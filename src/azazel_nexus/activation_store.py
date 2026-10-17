"""Read one protected, signed activation approval from its fixed location.

This module supplies a verified lease to a caller. It does not produce the
expected activation context, establish trusted time, or grant activation.
"""

from contextlib import contextmanager
import fcntl
import os
import stat

from .activation import ActivationLease
from .activation_approval import (
    ActivationContext,
    verify_activation_approval,
)
from .operator_store import _protected
from .operator_trust import MAX_APPROVAL_BYTES, ApprovalRefused

_COMPONENTS = ("etc", "azazel", "activation")
_MAX_SIGNATURE_BYTES = 64


def _private_directory(fd: int, *, owner: int) -> None:
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner
            or info.st_mode & 0o077):
        raise ApprovalRefused("activation approval directory is not private")


def _read_file_at(directory_fd: int, name: str, *, owner: int, limit: int) -> bytes:
    fd = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=directory_fd,
    )
    try:
        before = _protected(fd, owner=owner, directory=False)
        if before.st_mode & 0o077 or not 0 < before.st_size <= limit:
            raise ApprovalRefused("activation approval file permissions or size refused")
        chunks = bytearray()
        while len(chunks) <= limit:
            part = os.read(fd, min(8192, limit + 1 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
        after = _protected(fd, owner=owner, directory=False)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(chunks) != before.st_size:
            raise ApprovalRefused("activation approval file changed while reading")
        return bytes(chunks)
    finally:
        os.close(fd)


def _read_at(directory_fd: int, *, owner: int) -> tuple[bytes, bytes]:
    """Private descriptor seam for ordinary temporary-file tests."""
    _private_directory(directory_fd, owner=owner)
    payload = _read_file_at(
        directory_fd, "approval.json", owner=owner, limit=MAX_APPROVAL_BYTES
    )
    signature = _read_file_at(
        directory_fd, "approval.sig", owner=owner, limit=_MAX_SIGNATURE_BYTES
    )
    if len(signature) != _MAX_SIGNATURE_BYTES:
        raise ApprovalRefused("activation approval signature size refused")
    return payload, signature


@contextmanager
def _approval_directory():
    """Traverse only /etc/azazel/activation without following symlinks."""
    fd = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open("/", flags)
        for component in _COMPONENTS:
            _protected(fd, owner=0, directory=True)
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        _private_directory(fd, owner=0)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except (OSError, BlockingIOError):
            raise ApprovalRefused("activation approval store is busy") from None
        yield fd
    except ApprovalRefused:
        raise
    except (OSError, AttributeError) as exc:
        raise ApprovalRefused("protected activation approval unavailable") from exc
    finally:
        if fd is not None:
            os.close(fd)


def load_activation_approval(
    *, expected: ActivationContext, operator: str, now: str,
    max_lease_seconds: int,
) -> ActivationLease:
    """Load and verify the fixed approval against independently supplied inputs."""
    try:
        if type(expected) is not ActivationContext:
            raise ApprovalRefused("independent activation context required")
        with _approval_directory() as directory_fd:
            payload, signature = _read_at(directory_fd, owner=0)
            trust = _load_trust()
            lease = verify_activation_approval(
                trust=trust, expected=expected, operator=operator,
                payload=payload, signature=signature, now=now,
                max_lease_seconds=max_lease_seconds,
            )
            original = os.fstat(directory_fd)
            with _approval_directory() as current_fd:
                current = os.fstat(current_fd)
                if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
                    raise ApprovalRefused("activation approval directory changed")
                if _read_at(current_fd, owner=0) != (payload, signature):
                    raise ApprovalRefused("activation approval changed during verification")
            if _load_trust() != trust:
                raise ApprovalRefused("operator trust changed during verification")
            return lease
    except Exception:
        raise ApprovalRefused("protected activation approval refused") from None


def _load_trust():
    # Import at call time so tests can replace the fresh protected reader.
    from .operator_store import load_operator_trust

    return load_operator_trust()
