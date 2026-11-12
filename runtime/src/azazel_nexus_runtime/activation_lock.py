"""The pass lock: one activation evaluation at a time (design: stop contract).

`/run/azazel-activation/pass.lock` is a root-owned ``0600`` regular file
under the same protected directory as the grant markers. The main pass
(`az-activated`) and the periodic recheck (`az-activation-recheck`) both
change the markers, the manager's unit state and the activation ledger, so
they take this lock first and keep it while they do.

* The main pass waits a bounded time for it (it must finish, or narrow).
* The recheck never waits: if it cannot take the lock it changes nothing.

The lock is an ``flock`` on a file opened with ``O_NOFOLLOW``. The file is
checked after opening (regular, owned by root, mode ``0600``, one link); a
foreign or loosened file is refused rather than used.
"""

from __future__ import annotations

import fcntl
import os
import stat
import time
from pathlib import Path
from typing import Callable

from . import activation_markers

__all__ = ["PassLock", "PassLockBusy", "PassLockRefused", "acquire_pass_lock"]

LOCK_NAME = "pass.lock"
_POLL_SECONDS = 0.05


class PassLockBusy(Exception):
    """Another evaluation holds the lock."""


class PassLockRefused(Exception):
    """The lock file or its directory is missing, foreign or loosened."""


class PassLock:
    """A held lock. Closing the descriptor (or exiting) releases it."""

    def __init__(self, fd: int) -> None:
        self._fd: int | None = fd

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            os.close(fd)

    def __enter__(self) -> "PassLock":
        return self

    def __exit__(self, *_exc) -> None:
        self.release()


def _open_lock(root: Path) -> int:
    parent = activation_markers._open_parent(root)
    if parent is None:
        raise PassLockRefused("pass lock directory unavailable")
    try:
        fd = os.open(
            LOCK_NAME,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=parent)
    except OSError:
        raise PassLockRefused("pass lock file could not be opened") from None
    finally:
        os.close(parent)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != activation_markers._OWNER
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise PassLockRefused("pass lock file protection refused")
    except BaseException:
        os.close(fd)
        raise
    return fd


def acquire_pass_lock(
    root: Path = Path("/"), *, wait_seconds: float = 0.0,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> PassLock:
    """Take the lock, waiting at most `wait_seconds` (0: do not wait).

    Raises `PassLockBusy` when another holder keeps it for that long and
    `PassLockRefused` when the file is not what it must be.
    """
    fd = _open_lock(root)
    give_up = clock() + max(0.0, wait_seconds)
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return PassLock(fd)
        except BlockingIOError:
            if clock() >= give_up:
                os.close(fd)
                raise PassLockBusy("pass lock is held") from None
            sleep(_POLL_SECONDS)
        except BaseException:
            os.close(fd)
            raise
