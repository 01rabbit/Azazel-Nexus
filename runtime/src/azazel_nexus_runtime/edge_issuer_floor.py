"""The Edge package rollback floor: raise-only, after an authenticated activation.

`azazel_nexus.edge_issuer` reads `/var/lib/azazel/state/edge-issuer/floor.json`
on every inspection and refuses a package below it, a replayed manifest at its
version, and a revocation list older than the sequence it holds. This module
is the only writer, and it writes in one situation: the activation controller
has enabled `azazel-edge-core.service` (grant markers written, nothing rolled
back) and the pass record was appended -- so a grant withdrawn because its
record failed never raises it -- for a package whose issuer was
authenticated, whose digest was verified, which no revocation names and which
is at or above the floor.

The same four properties as `activation_high_water`, each a refusal:

*Raise-only.* A value below the stored one in any field -- a lower version,
the same version with another digest, a lower revocation sequence, or the same
sequence naming another list -- is refused as a whole. Nothing lowers it and there is no reset here.

*Fail-closed.* A floor that exists and is not exactly one canonical record is
refused, by the reader (the package with it) and here (no raise over it).

*Crash-safe.* Private temporary file, fsync, rename, directory fsync, read
back. A crash leaves the old or the new floor, never a mixture.

*Fixed path.* Traversed from `/` without following a link, every component
root-owned and not group or other writable. The leaf and file are readable by
everyone (`0755`/`0644`) so that `status` can show the floor; they hold a
version, a digest and a counter, nothing secret.

Not raised: an unauthenticated activation (every node with no issuer anchor,
which is every node today) never moves the floor. Failing to raise grants
nothing and withdraws nothing -- the package was already admitted on its
own checks -- so the caller records the label and continues.

This is local trust: root can delete the file, which reopens rollback to the
pinned version. It protects against a rewritten package directory and a
replayed older package or manifest, not against the node's administrator.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
import stat

from azazel_nexus.edge_issuer import (
    FLOOR_FILENAME,
    EdgeFloor,
    IssuerRefused,
    IssuerVerification,
    decode_floor,
    encode_floor,
)

__all__ = [
    "EdgeFloorCommitUncertain",
    "EdgeFloorRefused",
    "raise_edge_floor",
    "raise_floor_after_grant",
    "read_edge_floor",
]

_STATE = ("var", "lib", "azazel", "state")
_LEAF = "edge-issuer"
_PARTIAL = ".floor.json.partial"
_LIMIT = 4096
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
#: The owner every component and the file must have. Private test seam only.
_OWNER = 0


class EdgeFloorRefused(Exception):
    """The floor is unavailable, malformed, or would move backwards."""


class EdgeFloorCommitUncertain(EdgeFloorRefused):
    """Renamed into place, durability unconfirmed. Read it back; not a success."""


def _protected(fd: int, *, directory: bool) -> os.stat_result:
    info = os.fstat(fd)
    kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not kind or info.st_uid != _OWNER or info.st_mode & 0o022
            or (not directory and info.st_nlink != 1)):
        raise EdgeFloorRefused("edge floor storage protection refused")
    return info


@contextmanager
def _state_directory():
    """Open `/var/lib/azazel/state` without following any symlink."""
    fd = os.open("/", _DIR_FLAGS)
    try:
        for component in _STATE:
            _protected(fd, directory=True)
            child = os.open(component, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        _protected(fd, directory=True)
        yield fd
    finally:
        os.close(fd)


def _open_leaf(state_fd: int, *, create: bool) -> int | None:
    try:
        fd = os.open(_LEAF, _DIR_FLAGS, dir_fd=state_fd)
    except FileNotFoundError:
        if not create:
            return None
        os.mkdir(_LEAF, 0o755, dir_fd=state_fd)
        fd = os.open(_LEAF, _DIR_FLAGS, dir_fd=state_fd)
        # Explicit, so that a umask of 077 cannot leave the floor unreadable
        # to the operator who runs `status`.
        os.fchmod(fd, 0o755)
        os.fsync(state_fd)
    try:
        _protected(fd, directory=True)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _lock(fd: int, mode: int) -> None:
    try:
        fcntl.flock(fd, mode | fcntl.LOCK_NB)
    except OSError:
        raise EdgeFloorRefused("edge floor store is busy") from None


def _read_at(leaf_fd: int) -> EdgeFloor | None:
    """`None` only for a missing file; everything else is a value or a refusal."""
    try:
        fd = os.open(FLOOR_FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=leaf_fd)
    except FileNotFoundError:
        return None
    try:
        before = _protected(fd, directory=False)
        if not 0 < before.st_size <= _LIMIT:
            raise EdgeFloorRefused("edge floor size refused")
        chunks = bytearray()
        while len(chunks) <= _LIMIT:
            part = os.read(fd, _LIMIT + 1 - len(chunks))
            if not part:
                break
            chunks.extend(part)
        after = _protected(fd, directory=False)
        named = os.stat(FLOOR_FILENAME, dir_fd=leaf_fd, follow_symlinks=False)
        stamp = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        if (stamp != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino)
                or len(chunks) != before.st_size):
            raise EdgeFloorRefused("edge floor changed while reading")
        try:
            return decode_floor(bytes(chunks))
        except IssuerRefused:
            raise EdgeFloorRefused("edge floor record refused") from None
    finally:
        os.close(fd)


def _write_at(leaf_fd: int, value: EdgeFloor) -> EdgeFloor:
    """Temporary file, fsync, rename, directory fsync, read back."""
    data = encode_floor(value)
    try:
        stale = os.stat(_PARTIAL, dir_fd=leaf_fd, follow_symlinks=False)
    except FileNotFoundError:
        stale = None
    if stale is not None:
        if not stat.S_ISREG(stale.st_mode):
            raise EdgeFloorRefused("edge floor partial entry is not a regular file")
        os.unlink(_PARTIAL, dir_fd=leaf_fd)
    fd = os.open(_PARTIAL, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o644, dir_fd=leaf_fd)
    try:
        os.fchmod(fd, 0o644)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(_PARTIAL, FLOOR_FILENAME, src_dir_fd=leaf_fd, dst_dir_fd=leaf_fd)
    try:
        os.fsync(leaf_fd)
        if _read_at(leaf_fd) != value:
            raise EdgeFloorRefused("edge floor read-back differs")
    except Exception:
        raise EdgeFloorCommitUncertain("edge floor renamed; durability unconfirmed") from None
    return value


def _raise_at(state_fd: int, value: EdgeFloor) -> EdgeFloor:
    leaf = _open_leaf(state_fd, create=True)
    try:
        _lock(leaf, fcntl.LOCK_EX)
        current = _read_at(leaf)
        if current is not None:
            if value.lower_than(current):
                raise EdgeFloorRefused("the edge floor never moves backwards")
            if value == current:
                return current
        return _write_at(leaf, value)
    finally:
        os.close(leaf)


def _read_state(state_fd: int) -> EdgeFloor | None:
    leaf = _open_leaf(state_fd, create=False)
    if leaf is None:
        return None
    try:
        _lock(leaf, fcntl.LOCK_SH)
        return _read_at(leaf)
    finally:
        os.close(leaf)


def _guard(operation):
    try:
        with _state_directory() as state_fd:
            return operation(state_fd)
    except EdgeFloorRefused:
        raise
    except Exception:
        raise EdgeFloorRefused("edge floor store unavailable") from None


def read_edge_floor() -> EdgeFloor | None:
    """The stored floor, or `None` when there is none at all."""
    return _guard(_read_state)


def raise_edge_floor(value: EdgeFloor) -> EdgeFloor:
    """Create the floor, or replace it with one at or above it in every field."""
    if type(value) is not EdgeFloor:
        raise EdgeFloorRefused("an edge floor record is required")
    return _guard(lambda state_fd: _raise_at(state_fd, value))


def raise_floor_after_grant(
    issuer: IssuerVerification | None, *, launched_digest: str | None,
) -> str:
    """Raise the floor for a granted edge-core, when every condition holds. A label.

    The caller has already granted `azazel-edge-core.service` and written its
    marker. Raised only when the installed package's issuer is authenticated,
    its digest verified, no revocation names it, the floor held, and the digest
    is the one the activation evidence was bound to (`launched_digest`).
    Never raises: `not_authenticated`, `not_eligible`, `raised`, `held`,
    `refused` or `uncertain`.
    """

    if type(issuer) is not IssuerVerification or not issuer.issuer_authenticated:
        return "not_authenticated"
    if (not issuer.digest_verified
            or issuer.revoked != "none"
            or issuer.revocation_status not in ("none", "in_force")
            or issuer.floor_status not in ("absent", "held")
            or issuer.version is None or issuer.package_digest is None
            or type(launched_digest) is not str
            or issuer.package_digest != launched_digest):
        return "not_eligible"
    try:
        value = EdgeFloor(
            version=issuer.version, package_digest=issuer.package_digest,
            revocation_sequence=issuer.revocation_sequence or 0,
            revocation_digest=(issuer.revocation_digest or "")
            if issuer.revocation_sequence else "",
        )
    except IssuerRefused:
        return "not_eligible"
    try:
        before = read_edge_floor()
        stored = raise_edge_floor(value)
    except EdgeFloorCommitUncertain:
        return "uncertain"
    except EdgeFloorRefused:
        return "refused"
    return "held" if before == stored else "raised"
