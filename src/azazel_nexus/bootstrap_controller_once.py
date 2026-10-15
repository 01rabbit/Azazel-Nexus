"""Retained one-use controller barrier for a selected bootstrap attempt.

PID 1 checks the matching negative ConditionPathExists before a fresh
controller execution. Claim before any helper grant/start, retain on every
failure, and never remove it during this boot. This is not grant approval.
"""

from contextlib import contextmanager
import os
import stat

from .activation_store import _private_directory
from .bootstrap_lock import BootstrapTransactionGuard
from .operator_store import _protected
from .operator_trust import ApprovalRefused

_NAME = "controller-used"
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
            info.st_mode, info.st_nlink, info.st_size)


def _marker(fd, owner):
    info = _protected(fd, owner=owner, directory=False)
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 0:
        raise ApprovalRefused("controller barrier metadata refused")
    return _identity(info)


def _open_directory():
    run = os.open("/run", _DIRECTORY)
    try:
        _protected(run, owner=0, directory=True)
        directory = os.open("azazel-nexus-bootstrap", _DIRECTORY, dir_fd=run)
        try:
            _private_directory(directory, owner=0)
        except BaseException:
            os.close(directory)
            raise
        return directory
    finally:
        os.close(run)


@contextmanager
def _controller_once_at(directory_fd, *, owner, reopen, guard):
    """Ordinary-file seam; creation consumes the attempt even on failure."""
    if type(guard) is not BootstrapTransactionGuard or not callable(reopen):
        raise ApprovalRefused("held controller transaction required")
    marker = None
    active = True
    process = os.getpid()
    try:
        guard()
        _private_directory(directory_fd, owner=owner)
        original_directory = os.fstat(directory_fd)
        marker = os.open(_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
        original_marker = _marker(marker, owner)
        os.fsync(marker)
        os.fsync(directory_fd)

        def check_retained():
            if not active or os.getpid() != process:
                raise ApprovalRefused("controller barrier no longer retained")
            guard()
            _private_directory(directory_fd, owner=owner)
            if _marker(marker, owner) != original_marker:
                raise ApprovalRefused("controller barrier changed")
            current = reopen()
            try:
                _private_directory(current, owner=owner)
                held = os.fstat(directory_fd)
                named = os.fstat(current)
                if ((original_directory.st_dev, original_directory.st_ino)
                        != (held.st_dev, held.st_ino)
                        or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)):
                    raise ApprovalRefused("controller barrier directory replaced")
                candidate = os.open(_NAME, _READ, dir_fd=current)
                try:
                    if _marker(candidate, owner) != original_marker:
                        raise ApprovalRefused("controller barrier identity changed")
                finally:
                    os.close(candidate)
            finally:
                os.close(current)
            guard()

        def check():
            try:
                check_retained()
            except (OSError, ValueError, TypeError) as error:
                raise ApprovalRefused("controller barrier unavailable") from error

        check()
        checked = BootstrapTransactionGuard(check)
        yield checked
        check()
    except (OSError, ValueError, TypeError) as error:
        raise ApprovalRefused("controller barrier unavailable") from error
    finally:
        active = False
        if marker is not None:
            os.close(marker)
        # No unlink: retrying this boot must remain impossible after failure.


@contextmanager
def bootstrap_controller_once(guard):
    """Fixed protected /run path, retained for the selected runtime lifetime."""
    fd = _open_directory()
    try:
        with _controller_once_at(fd, owner=0, reopen=_open_directory, guard=guard) as check:
            yield check
    finally:
        os.close(fd)
