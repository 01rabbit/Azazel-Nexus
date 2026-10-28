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
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Optional

__all__ = ["SnapshotWriter"]


def _stderr(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


class SnapshotWriter:
    """Rewrites `path` from `build()` at most every `interval_s` on `tick()`."""

    def __init__(self, path: Optional[Path], build: Callable[[], dict], *, limit: int,
                 interval_s: float, name: str,
                 warn: Callable[[str], None] = _stderr,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        self.path = path
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
            return True
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
