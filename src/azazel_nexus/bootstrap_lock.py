"""One protected bootstrap supervisor transaction across the whole lifetime.

This serializes cooperating controllers, not hostile root or service processes.
It is neither admission nor a lifetime/reboot fence. The protected state
directory must already exist; creating the empty lock does not initialize a
deadline. Lock files are never removed after release (unlink would split locks).
"""

import fcntl
import os
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass

from .activation_store import _private_directory
from .bootstrap_deadline_store import _open_directory
from .operator_store import _protected
from .operator_trust import ApprovalRefused

_NAME = "supervisor.lock"
_FLAGS = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


@dataclass(frozen=True, slots=True)
class BootstrapTransactionGuard:
    """Trusted in-process capability, not a boundary against arbitrary code.

    The runtime composition passes this only between trusted components. The
    filesystem lock and identity checks, not this Python type, enforce the
    cooperating-process serialization boundary.
    """

    _check: Callable[[], None]

    def __post_init__(self):
        if not callable(self._check):
            raise ApprovalRefused("bootstrap transaction check required")

    def __call__(self):
        self._check()


def _identity(info):
    return info.st_dev, info.st_ino


def _directory(fd: int, *, owner: int):
    _private_directory(fd, owner=owner)
    return os.fstat(fd)


def _lock_file(fd: int, *, owner: int):
    info = _protected(fd, owner=owner, directory=False)
    if info.st_mode & 0o077 or info.st_size != 0:
        raise ApprovalRefused("bootstrap transaction lock is not private and empty")
    return info


def _best_effort_recheck(check):
    """Preserve the in-flight failure if the final ownership check also refuses."""
    try:
        check()
    except ApprovalRefused:
        return False
    return True


@contextmanager
def _transaction_at(directory_fd: int, *, owner: int, reopen):
    """Descriptor-only seam for regular-file tests; caller owns directory_fd."""
    directory = _directory(directory_fd, owner=owner)
    lock_fd = os.open(_NAME, _FLAGS | os.O_CREAT, 0o600, dir_fd=directory_fd)
    active = False
    process = os.getpid()
    try:
        original = _lock_file(lock_fd, owner=owner)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        active = True

        def check():
            try:
                if not active or os.getpid() != process:
                    raise ApprovalRefused("bootstrap transaction no longer owned")
                held_directory = _directory(directory_fd, owner=owner)
                held_file = _lock_file(lock_fd, owner=owner)
                current_fd = reopen()
                try:
                    current_directory = _directory(current_fd, owner=owner)
                    candidate_fd = os.open(_NAME, _FLAGS, dir_fd=current_fd)
                    try:
                        current_file = _lock_file(candidate_fd, owner=owner)
                    finally:
                        os.close(candidate_fd)
                finally:
                    os.close(current_fd)
                if not (
                    _identity(directory)
                    == _identity(held_directory)
                    == _identity(current_directory)
                    and _identity(original)
                    == _identity(held_file)
                    == _identity(current_file)
                ):
                    raise ApprovalRefused("bootstrap transaction identity changed")
            except (OSError, ApprovalRefused, TypeError, ValueError, AttributeError):
                raise ApprovalRefused("bootstrap transaction lock refused") from None

        check()
        guard = BootstrapTransactionGuard(check)
        try:
            yield guard
        except BaseException:
            # Do not erase a containment failure or interrupt already in flight.
            # The original failure is sufficient to refuse this transaction.
            _best_effort_recheck(check)
            raise
        else:
            check()  # Still held until the supervisor has finished narrowing.
    finally:
        active = False
        os.close(lock_fd)  # Also releases flock; never unlink the inode.


@contextmanager
def bootstrap_transaction():
    """Fixed-path root-owned lock; no public path/owner override or fallback."""
    fd = None
    entered = False
    try:
        fd = _open_directory()
        with _transaction_at(fd, owner=0, reopen=_open_directory) as check:
            entered = True
            yield check
    except Exception:
        if entered:
            raise  # Preserve the supervisor's containment/domain failure.
        raise ApprovalRefused("protected bootstrap transaction unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)
