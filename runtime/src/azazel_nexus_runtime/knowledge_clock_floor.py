"""The Knowledge Lite wall-clock floor: raise-only, kept by `az-knowledge-lited`.

`knowledge-lited` evaluates each dated row's `agg_next_expiry` against its own
`query_as_of`, which is the wall clock. A wall clock that moves backwards --
an RTC reset, a hostile or mistaken time step -- would make rows that had
already expired look current again. This floor is
the latest wall-clock instant the daemon has already observed; an observation
earlier than it is a regression, and the daemon then serves nothing dated or
static, with the existing fixed reason `state_untrusted`.

Why not `bootstrap_clock`: that is an administrator-confirmed UTC anchor in the
root-only `/etc/azazel/bootstrap`, bound to one boot and only present in the
administrator-managed source mode. `azknowledge` cannot read it, and granting
that read would widen a root-only trust directory for a reader that needs
only a monotonic lower bound. This floor follows the shape of the existing
raise-only floors (`edge_issuer_floor`, the Lite watermark) instead, in the
daemon's own private state leaf `/var/lib/azazel/state/knowledge` (installer:
`0700 azknowledge:root`), which the unit already lists in `ReadWritePaths`.
No new write permission is added.

*Raise-only.* Nothing here lowers the stored instant, and there is no reset
verb. Recovery from a clock that once ran ahead is an administrator removing
the file after correcting the clock (documented in
`docs/knowledge-lite-consumer.md`).

*Fail-closed.* A floor that exists and is not exactly one canonical record in a
protected regular file -- or a store that cannot be opened or written -- is
`FloorUnavailable`. The caller then serves nothing. Only a file that does not
exist (`ENOENT`) is absent: first start, or after an administrator's removal.

*Bounded writes.* The in-process floor is exact. The persisted copy holds
whole seconds and is raised whenever an observation reaches a later second
than it holds -- so at most one write per second, and before the reply that
observed that second is returned. It is never later than an instant actually
observed. After a crash and restart the only regression not detected is one
back into the same wall-clock second as the latest observation (under one
second); expiries Knowledge writes carry whole seconds.

*No ceiling.* A clock that jumps forward raises the floor with it; nothing
here bounds a jump (for example by signed material's own time). That is an
owner decision. The floor also only moves when a request is answered: a
clock moved back while nobody asked is detected only against the last
answered instant.

This is local trust: `azknowledge` or root can delete the file. It protects
against a clock moved backwards, not against the node's administrator. A
removed floor is not silent: the next creation is reported (`created`), with
cause `absent_after_use` when this process had already kept a floor or the
leaf already holds other state.

*Not a defence against snapshot restore.* A VM or disk snapshot restored to an
earlier point rolls this file back with everything else in the same state
tree; the floor then agrees with the restored clock. Rows that expired after
the snapshot was taken can be served again. Only an anchor outside the
restored storage (for example signed material's own time) could detect that.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

__all__ = ["FILENAME", "PERSIST_STEP_S", "SCHEMA", "ClockFloor", "FloorUnavailable"]

SCHEMA = "azazel-nexus/knowledge-clock-floor/v1"
FILENAME = "clock-floor.json"
PERSIST_STEP_S = 1
_PARTIAL = ".clock-floor.json.partial"
_LIMIT = 256
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class FloorUnavailable(Exception):
    """The floor cannot be established; nothing time-bound may be served."""


def _instant(text: object) -> datetime:
    if type(text) is not str or not text.endswith("Z"):
        raise FloorUnavailable("floor instant refused")
    try:
        moment = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError:
        raise FloorUnavailable("floor instant refused") from None
    return moment.astimezone(UTC)


def _text(moment: datetime) -> str:
    # Seconds only, truncated: the stored floor never exceeds what was seen.
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def encode_floor(moment: datetime) -> bytes:
    return json.dumps({"floor_utc": _text(moment), "schema": SCHEMA},
                      sort_keys=True, separators=(",", ":")).encode() + b"\n"


def decode_floor(raw: bytes) -> datetime:
    try:
        document = json.loads(raw.decode("utf-8"))
        if type(document) is not dict or set(document) != {"floor_utc", "schema"}:
            raise ValueError
        if document["schema"] != SCHEMA:
            raise ValueError
        moment = _instant(document["floor_utc"])
    except (ValueError, UnicodeDecodeError, FloorUnavailable):
        raise FloorUnavailable("floor record refused") from None
    if encode_floor(moment) != raw:
        raise FloorUnavailable("floor record not canonical")
    return moment


class ClockFloor:
    """One daemon's floor in one private directory it owns."""

    def __init__(self, directory: Path, *, owner: int | None = None) -> None:
        self.directory = Path(directory)
        self.owner = os.geteuid() if owner is None else owner
        self._seen: datetime | None = None
        #: Set by `admit` when it created the file: `initial` or
        #: `absent_after_use`; otherwise None. Read by the caller for audit.
        self.created: str | None = None

    def admit(self, query_as_of: str) -> bool:
        """True if `query_as_of` is not behind the floor (and the floor is raised).

        False is a regression. `FloorUnavailable` means the floor could not be
        read or kept; the caller treats both as "serve nothing".
        """
        self.created = None
        now = _instant(query_as_of)
        stored = self._read()
        floor = max((m for m in (stored, self._seen) if m is not None), default=None)
        if floor is not None and now < floor:
            return False
        self._seen = now
        # Persist before answering whenever this reaches a later whole second.
        if stored is None or now.replace(microsecond=0) - stored >= timedelta(seconds=PERSIST_STEP_S):
            cause = None
            if stored is None:
                cause = "absent_after_use" if (self._seen_before or self._other_state()) else "initial"
            self._write(now)
            self.created = cause
        self._seen_before = True
        return True

    _seen_before = False

    def _other_state(self) -> bool:
        """Whether the leaf already holds anything besides a stale partial."""
        directory = self._open_directory()
        try:
            return any(name != _PARTIAL for name in os.listdir(directory))
        except OSError:
            raise FloorUnavailable("floor directory unreadable") from None
        finally:
            os.close(directory)

    # -- storage -----------------------------------------------------------

    def _protected(self, fd: int, *, directory: bool) -> os.stat_result:
        info = os.fstat(fd)
        kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if (not kind or info.st_uid != self.owner or info.st_mode & 0o022
                or (not directory and info.st_nlink != 1)):
            raise FloorUnavailable("floor storage protection refused")
        return info

    def _open_directory(self) -> int:
        try:
            fd = os.open(self.directory, _DIR_FLAGS)
        except OSError:
            raise FloorUnavailable("floor directory unavailable") from None
        try:
            self._protected(fd, directory=True)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _read(self) -> datetime | None:
        directory = self._open_directory()
        try:
            try:
                fd = os.open(FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | os.O_CLOEXEC, dir_fd=directory)
            except FileNotFoundError:
                return None
            except OSError:
                raise FloorUnavailable("floor unreadable") from None
            try:
                before = self._protected(fd, directory=False)
                if not 0 < before.st_size <= _LIMIT:
                    raise FloorUnavailable("floor size refused")
                raw = os.read(fd, _LIMIT + 1)
                if len(raw) != before.st_size:
                    raise FloorUnavailable("floor changed while read")
            except OSError:
                raise FloorUnavailable("floor unreadable") from None
            finally:
                os.close(fd)
            return decode_floor(raw)
        finally:
            os.close(directory)

    def _write(self, moment: datetime) -> None:
        raw = encode_floor(moment)
        directory = self._open_directory()
        try:
            try:
                os.unlink(_PARTIAL, dir_fd=directory)
            except FileNotFoundError:
                pass
            fd = os.open(_PARTIAL, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | os.O_CLOEXEC, 0o600, dir_fd=directory)
            try:
                os.fchmod(fd, 0o600)
                if os.write(fd, raw) != len(raw):
                    raise OSError("short floor write")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(_PARTIAL, FILENAME, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        except OSError:
            raise FloorUnavailable("floor could not be kept") from None
        finally:
            os.close(directory)
        if self._read() != moment.replace(microsecond=0):
            raise FloorUnavailable("floor read-back differs")
