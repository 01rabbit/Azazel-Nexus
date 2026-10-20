"""The activation anti-replay and clock floor: read, initialize, raise (#206).

`docs/activation-observe-baseline.md` §3.5. One root-owned file,
`/var/lib/azazel/state/activation/high-water.json`, holds the highest
`security_epoch`, `approval_seq` and `generation` a pass has accepted and the
`time_floor` the OS clock may not fall below (less the policy skew).

Since phase P4 the activation pass reads it before its decision and raises it
after recording the decision, through `activation_pass`.

Three properties, each a refusal rather than a convention:

*Raise-only.* An update with any value below the stored one is refused as a
whole. Nothing here lowers a floor, and there is no reset.

*Absent is not zero.* The reader returns `None` only when the file does not
exist; a malformed, oversized, linked, mis-owned or changing file is refused.
A node that already has an activation ledger but no high-water file is a
refusal the caller can ask for (`require_high_water_for_pass`): deleting the
file must not reopen replay.

*Bounded above.* Initializing or raising takes the caller's `now` (the same
clock read the pass uses) and the policy skew, and refuses a `time_floor`
beyond `now + skew`. A single pass with a fast clock therefore cannot push the
floor so far ahead that the node refuses forever; recovering from a floor
that is already too far ahead is the explicit administrator procedure in the
design document (§7), never code here.

*Crash-safe.* A write goes to a private temporary file, is fsynced, renamed
over the old file and the directory is fsynced. A crash leaves either the old
or the new floor, never a mixture; a stale temporary file is never read.

This is local trust, not authenticated time or a tamper-proof record: root
can still replace the file.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
import fcntl
import json
import os
import stat

from azazel_nexus.activation_policy import MAX_CLOCK_SKEW_SECONDS
from azazel_nexus.bootstrap_approval import parse_bootstrap_time

__all__ = [
    "HighWater",
    "HighWaterCommitUncertain",
    "HighWaterRefused",
    "activation_ledger_present",
    "decode_high_water",
    "encode_high_water",
    "initialize_high_water",
    "raise_high_water",
    "read_high_water",
    "require_high_water_for_pass",
]

SCHEMA = "azazel-nexus/activation-high-water/v1"
_STATE = ("var", "lib", "azazel", "state")
_LEAF = "activation"
_FILE = "high-water.json"
_PARTIAL = ".high-water.json.partial"
_LEDGER = "activation.jsonl"
_LIMIT = 4096
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
#: The owner every component and the file must have. Private test seam only.
_OWNER = 0


class HighWaterRefused(Exception):
    """The high-water state is unavailable, malformed, or would move backwards."""


class HighWaterCommitUncertain(HighWaterRefused):
    """The new file was renamed into place but its durability is unconfirmed.

    Do not retry blindly: read the file back. Not permission to proceed.
    """


def _count(value) -> bool:
    return type(value) is int and 0 <= value < 2**63


@dataclass(frozen=True)
class HighWater:
    security_epoch: int
    approval_seq: int
    generation: int
    time_floor: str

    def __post_init__(self):
        if not all(_count(v) for v in (self.security_epoch, self.approval_seq, self.generation)):
            raise HighWaterRefused("high-water counters must be bounded non-negative integers")
        try:
            parse_bootstrap_time(self.time_floor)
        except Exception:
            raise HighWaterRefused("high-water time floor must be whole-second UTC") from None

    def lower_than(self, other: "HighWater") -> list[str]:
        """The fields of `self` that are below `other`'s."""
        lower = [name for name in ("security_epoch", "approval_seq", "generation")
                 if getattr(self, name) < getattr(other, name)]
        if parse_bootstrap_time(self.time_floor) < parse_bootstrap_time(other.time_floor):
            lower.append("time_floor")
        return lower


def encode_high_water(value: HighWater) -> bytes:
    if type(value) is not HighWater:
        raise HighWaterRefused("high-water record required")
    return json.dumps({
        "schema": SCHEMA, "security_epoch": value.security_epoch,
        "approval_seq": value.approval_seq, "generation": value.generation,
        "time_floor": value.time_floor,
    }, sort_keys=True, separators=(",", ":")).encode()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise HighWaterRefused("duplicate high-water field")
        result[key] = value
    return result


def decode_high_water(raw: bytes) -> HighWater:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= _LIMIT:
            raise HighWaterRefused("high-water size refused")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
        if (type(document) is not dict
                or set(document) != {"schema", "security_epoch", "approval_seq",
                                     "generation", "time_floor"}
                or document.pop("schema") != SCHEMA):
            raise HighWaterRefused("high-water fields refused")
        value = HighWater(**document)
        if encode_high_water(value) != raw:
            raise HighWaterRefused("high-water record is not canonical")
        return value
    except Exception:
        raise HighWaterRefused("high-water record refused") from None


def _protected(fd: int, *, owner: int, directory: bool, private: bool) -> os.stat_result:
    info = os.fstat(fd)
    kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    mask = 0o077 if private else 0o022
    if (not kind or info.st_uid != owner or info.st_mode & mask
            or (not directory and info.st_nlink != 1)):
        raise HighWaterRefused("high-water storage protection refused")
    return info


@contextmanager
def _state_directory():
    """Open `/var/lib/azazel/state` without following any symlink."""
    fd = os.open("/", _DIR_FLAGS)
    try:
        for component in _STATE:
            _protected(fd, owner=_OWNER, directory=True, private=False)
            child = os.open(component, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        _protected(fd, owner=_OWNER, directory=True, private=False)
        yield fd
    finally:
        os.close(fd)


def _open_leaf(state_fd: int, *, create: bool) -> int | None:
    try:
        fd = os.open(_LEAF, _DIR_FLAGS, dir_fd=state_fd)
    except FileNotFoundError:
        if not create:
            return None
        os.mkdir(_LEAF, 0o700, dir_fd=state_fd)
        os.fsync(state_fd)
        fd = os.open(_LEAF, _DIR_FLAGS, dir_fd=state_fd)
    try:
        _protected(fd, owner=_OWNER, directory=True, private=True)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _lock(fd: int, mode: int) -> None:
    try:
        fcntl.flock(fd, mode | fcntl.LOCK_NB)
    except OSError:
        raise HighWaterRefused("high-water store is busy") from None


def _read_at(leaf_fd: int) -> HighWater | None:
    """`None` only for a missing file; everything else is a value or a refusal."""
    try:
        fd = os.open(_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=leaf_fd)
    except FileNotFoundError:
        return None
    try:
        before = _protected(fd, owner=_OWNER, directory=False, private=True)
        if not 0 < before.st_size <= _LIMIT:
            raise HighWaterRefused("high-water size refused")
        chunks = bytearray()
        while len(chunks) <= _LIMIT:
            part = os.read(fd, _LIMIT + 1 - len(chunks))
            if not part:
                break
            chunks.extend(part)
        after = _protected(fd, owner=_OWNER, directory=False, private=True)
        named = os.stat(_FILE, dir_fd=leaf_fd, follow_symlinks=False)
        stamp = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        if (stamp != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino)
                or len(chunks) != before.st_size):
            raise HighWaterRefused("high-water file changed while reading")
        return decode_high_water(bytes(chunks))
    finally:
        os.close(fd)


def _ledger_present_at(state_fd: int) -> bool:
    try:
        os.stat(_LEDGER, dir_fd=state_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True  # Any entry, of any type, counts: a node with history.


def _write_at(leaf_fd: int, value: HighWater) -> HighWater:
    """Temporary file, fsync, rename, directory fsync, read back."""
    data = encode_high_water(value)
    try:
        stale = os.stat(_PARTIAL, dir_fd=leaf_fd, follow_symlinks=False)
    except FileNotFoundError:
        stale = None
    if stale is not None:
        if not stat.S_ISREG(stale.st_mode):
            raise HighWaterRefused("high-water partial entry is not a regular file")
        os.unlink(_PARTIAL, dir_fd=leaf_fd)
    fd = os.open(_PARTIAL, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=leaf_fd)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(_PARTIAL, _FILE, src_dir_fd=leaf_fd, dst_dir_fd=leaf_fd)
    try:
        os.fsync(leaf_fd)
        if _read_at(leaf_fd) != value:
            raise HighWaterRefused("high-water read-back differs")
    except Exception:
        raise HighWaterCommitUncertain("high-water renamed; durability unconfirmed") from None
    return value


def _within_clock(value: HighWater, now: str, skew_seconds: int) -> None:
    if type(value) is not HighWater:
        raise HighWaterRefused("high-water record required")
    if (type(skew_seconds) is not int
            or not 0 <= skew_seconds <= MAX_CLOCK_SKEW_SECONDS):
        raise HighWaterRefused("bounded clock skew required")
    try:
        instant = parse_bootstrap_time(now)
    except Exception:
        raise HighWaterRefused("current time must be whole-second UTC") from None
    if parse_bootstrap_time(value.time_floor) > instant + timedelta(seconds=skew_seconds):
        raise HighWaterRefused("high-water time floor ahead of the current clock")


def _initialize_at(state_fd: int, value: HighWater) -> HighWater:
    leaf = _open_leaf(state_fd, create=True)
    try:
        _lock(leaf, fcntl.LOCK_EX)
        if _read_at(leaf) is not None:
            raise HighWaterRefused("high-water already initialized; only raising is possible")
        return _write_at(leaf, value)
    finally:
        os.close(leaf)


def _raise_at(state_fd: int, value: HighWater) -> HighWater:
    leaf = _open_leaf(state_fd, create=False)
    if leaf is None:
        raise HighWaterRefused("high-water absent; it is initialized, never raised from nothing")
    try:
        _lock(leaf, fcntl.LOCK_EX)
        current = _read_at(leaf)
        if current is None:
            raise HighWaterRefused("high-water absent; it is initialized, never raised from nothing")
        if value.lower_than(current):
            raise HighWaterRefused("high-water never moves backwards")
        if value == current:
            return current
        return _write_at(leaf, value)
    finally:
        os.close(leaf)


def _guard(operation):
    try:
        with _state_directory() as state_fd:
            return operation(state_fd)
    except HighWaterRefused:
        raise
    except Exception:
        raise HighWaterRefused("activation high-water store unavailable") from None


def _read_state(state_fd: int) -> HighWater | None:
    leaf = _open_leaf(state_fd, create=False)
    if leaf is None:
        return None
    try:
        _lock(leaf, fcntl.LOCK_SH)
        return _read_at(leaf)
    finally:
        os.close(leaf)


def read_high_water() -> HighWater | None:
    """The stored floor, or `None` when no high-water file exists at all."""
    return _guard(_read_state)


def activation_ledger_present() -> bool:
    """Whether `/var/lib/azazel/state/activation.jsonl` exists (any type)."""
    return _guard(_ledger_present_at)


def require_high_water_for_pass() -> HighWater | None:
    """The floor a pass checks against; refuses absence on a node with history.

    `None` means a fresh node: no ledger and no file. That is still not a
    grant -- §3.5 initializes the floor only through the operator's install.
    """
    def check(state_fd):
        value = _read_state(state_fd)
        if value is None and _ledger_present_at(state_fd):
            raise HighWaterRefused("high-water absent on a node with an activation ledger")
        return value
    return _guard(check)


def initialize_high_water(value: HighWater, *, now: str, skew_seconds: int) -> HighWater:
    """Create the first floor; refuses when one already exists or is ahead of `now + skew`."""
    _within_clock(value, now, skew_seconds)
    return _guard(lambda state_fd: _initialize_at(state_fd, value))


def raise_high_water(value: HighWater, *, now: str, skew_seconds: int) -> HighWater:
    """Replace the floor with one at or above it in every field, or refuse.

    `time_floor` must also be at most `now + skew_seconds`, with `now` from the
    same clock read the caller checked against the stored floor.
    """
    _within_clock(value, now, skew_seconds)
    return _guard(lambda state_fd: _raise_at(state_fd, value))
