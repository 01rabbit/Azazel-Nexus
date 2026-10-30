"""Write one operator-readable snapshot, the way auditd writes its own (#211).

A temp file in the snapshot's own leaf, `0640`, renamed over the snapshot:
a reader sees the old file or the new one, never half of either. Temp files a
killed predecessor left (`.status-*`) are swept once. A body larger than the
reader's limit is not written (the reader would refuse it anyway). Nothing
here raises: a snapshot is optional, so its failure is logged once until a
write succeeds again, and the daemon keeps serving.

The leaf is installer-owned (`install.sh`, `2750 <daemon>:azazel-operator`)
and the unit lists it as an optional writable path, so a node upgraded
without re-running install.sh still starts the daemon; status then shows the
snapshot as unavailable.

**The UI's copy (ADR-0007).** A writer given `ui_path` also puts the same
bytes into the read-only UI's leaf (`run/ui-read/<leaf>`, `2750
<daemon>:azui`), right after the operator snapshot, by the same temp file and
rename. The copy is byte-identical, so the UI reads it with the same strict
reader and judges its freshness from the same `written_at`. A copy that
cannot be written (an older install without the leaf, a full disk) is logged
once and never fails the daemon or the operator snapshot. The previous copy is
removed when that is possible, so the UI says absent rather than showing the
last good copy; otherwise that copy ages out on its own `written_at` (the one
the operator snapshot had then) and is never shown fresh past its limit.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, Optional

__all__ = ["SnapshotWriter", "UiCopy"]


def _stderr(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _replace(path: Path, body: bytes, mode: int) -> None:
    """`body` into `path` by a temp file in its own directory and a rename."""

    name = None
    try:
        fd, name = tempfile.mkstemp(dir=path.parent, prefix=".status-")
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
            os.fchmod(stream.fileno(), mode)
        os.replace(name, path)
        name = None
    finally:
        if name is not None:
            try:
                os.unlink(name)
            except OSError:
                pass


def _sweep(directory: Path) -> bool:
    """Remove `.status-*` temp files a killed predecessor left. Never raises."""

    try:
        for leftover in directory.glob(".status-*"):
            try:
                if leftover.is_file() and not leftover.is_symlink():
                    leftover.unlink()
            except OSError:
                pass
        return True
    except OSError:
        return False


class UiCopy:
    """The read-only UI's byte-identical copy of one snapshot (ADR-0007).

    `write(body)` puts `body` at `path`, `0640`, in the UI's leaf, whose
    setgid group is `azui`. Never raises; the first failure is logged once
    until a write succeeds again. `path=None` writes nothing.
    """

    def __init__(self, path: Optional[Path], *, name: str,
                 warn: Callable[[str], None] = _stderr) -> None:
        self.path = path
        self.name = name
        self.warn = warn
        self._swept = False
        self._failing = False
        # One write or removal at a time (R389b §3): the intake can write its
        # status from the worker and from shutdown at once, and a failure's
        # removal must not interleave with another thread's replace. The
        # outcome is the last call's: its copy, or none -- never an older
        # copy left looking current.
        self._lock = threading.Lock()

    def write(self, body: bytes) -> bool:
        if self.path is None:
            return False
        with self._lock:
            return self._write(body)

    def _write(self, body: bytes) -> bool:
        try:
            if not self._swept:
                self._swept = _sweep(self.path.parent)
            _replace(self.path, body, 0o640)
            self._failing = False
            return True
        except Exception as exc:  # noqa: BLE001 - the UI's copy is optional
            # The copy left by the last good write would still look fresh
            # until its own stale limit while the operator snapshot moves on
            # (R389 §3): remove it, so the UI says absent at once. Best effort;
            # where even that fails the copy ages out on its `written_at`.
            try:
                os.unlink(self.path)
            except OSError:
                pass
            if not self._failing:
                self._failing = True
                try:
                    self.warn(
                        f"{self.name}: cannot write the read-only UI's copy of its status "
                        f"snapshot ({type(exc).__name__}); it continues, the operator "
                        "snapshot is unaffected, and the UI shows this snapshot as absent. "
                        "Re-run install.sh to create the ui-read leaf (docs/operations.md)")
                except Exception:  # noqa: BLE001 - the log is optional too
                    pass
            return False


class SnapshotWriter:
    """Rewrites `path` from `build()` at most every `interval_s` on `tick()`.

    With `ui_path`, each snapshot written is also copied, byte for byte, into
    the read-only UI's leaf (`UiCopy`).
    """

    def __init__(self, path: Optional[Path], build: Callable[[], dict], *, limit: int,
                 interval_s: float, name: str,
                 warn: Callable[[str], None] = _stderr,
                 monotonic: Callable[[], float] = time.monotonic,
                 ui_path: Optional[Path] = None) -> None:
        self.path = path
        self.ui = UiCopy(ui_path, name=name, warn=warn)
        self.build = build
        self.limit = limit
        self.interval_s = interval_s
        self.name = name
        self.warn = warn
        self.monotonic = monotonic
        self._written: Optional[float] = None
        self._swept = False
        self._failing = False

    def tick(self) -> None:
        """Write when due. Never raises."""

        try:
            if self._written is None or self.monotonic() - self._written >= self.interval_s:
                self.write()
        except Exception:  # noqa: BLE001 - housekeeping must not stop serving
            return

    def write(self) -> bool:
        """Replace the snapshot now. `True` when it was written. Never raises."""

        if self.path is None:
            return False
        self._written = self.monotonic()
        if not self._swept:
            self._sweep()
        name = None
        try:
            body = json.dumps(self.build(), sort_keys=True, separators=(",", ":"),
                              allow_nan=False).encode() + b"\n"
            if len(body) > self.limit:
                raise ValueError("snapshot over its reader's limit")
            fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".status-")
            with os.fdopen(fd, "wb") as stream:
                stream.write(body)
                os.fchmod(stream.fileno(), 0o640)
            os.replace(name, self.path)
            name = None
            self._failing = False
        except Exception as exc:  # noqa: BLE001 - the snapshot is optional
            if not self._failing:
                self._failing = True
                self._warn(
                    f"{self.name}: cannot write its status snapshot ({type(exc).__name__}); "
                    "it continues and `azazel-nexus status` shows this snapshot as "
                    "unavailable. Re-run install.sh, then systemctl daemon-reload and "
                    "restart the unit (docs/operations.md)")
            return False
        finally:
            if name is not None:
                try:
                    os.unlink(name)
                except OSError:
                    pass
        # Only a snapshot the operator leaf holds is copied: the two never
        # say different things, and the UI's copy is never the newer one.
        self.ui.write(body)
        return True

    def _warn(self, message: str) -> None:
        """Log through `warn`; a logger that fails does not stop the daemon."""

        try:
            self.warn(message)
        except Exception:  # noqa: BLE001 - the snapshot is optional, and so is its log
            pass

    def _sweep(self) -> None:
        """Remove `.status-*` temp files a killed predecessor left. Never raises."""

        try:
            for leftover in self.path.parent.glob(".status-*"):
                try:
                    if leftover.is_file() and not leftover.is_symlink():
                        leftover.unlink()
                except OSError:
                    pass
            self._swept = True
        except OSError:
            pass
