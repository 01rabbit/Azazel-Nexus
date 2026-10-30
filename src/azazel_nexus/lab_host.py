"""A persistent host contamination marker, never an authorization input.

Deliberately absolute: AZAZEL_ROOT must not hide a marked host. A dangling
symlink or an unreadable marker also refuses; removing it grants nothing.

`marker_lock` is the one host-wide lock that serializes writing the marker
with every Mission Pack publication (owner-decisions H7), whatever state root
a Pack uses. It is a fixed path on ``/run`` (tmpfs, independent of ``/data``
and of a read-only root), created empty and private by its first root user
and never removed (unlinking would split it). It serializes cooperating
writers; it is not an authorization input either. Order: this lock first,
then a Mission Pack state-root lock; the marker writer takes nothing else.
"""
import fcntl
import os
import stat
import time
from contextlib import contextmanager
from pathlib import Path

LAB_HOST_MARKER = Path("/etc/azazel-lab/LAB-HOST")
LAB_HOST_LOCK = Path("/run/azazel-lab-host.lock")


class MarkerLockBusy(Exception):
    """Another marker writer or Mission Pack writer holds the host lock."""


def is_lab_host() -> bool:
    try:
        LAB_HOST_MARKER.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def refuse_lab_host(error_type=ValueError) -> None:
    if is_lab_host():
        raise error_type("LAB_HOST_MARKER")


@contextmanager
def marker_lock(*, wait_seconds: float = 0.0):
    """Hold the host-wide marker lock; ``wait_seconds`` bounds the wait (a
    Mission Pack writer never waits), then `MarkerLockBusy`."""
    fd = os.open(LAB_HOST_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size != 0):
            raise OSError("the lab host lock is not a private empty regular file")
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise MarkerLockBusy("lab host lock held") from None
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)
