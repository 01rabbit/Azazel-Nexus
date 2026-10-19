"""Protect store directories independently of the operator's umask."""

import os
import stat
from pathlib import Path


def store_directory(path: Path, mode: int = 0o750) -> bool:
    """Remove write access regardless of umask, preserving inherited setgid.

    Store writers must protect both admitted artifacts and anti-rollback state.
    The fd binds inspection and tightening to the same directory, not a link.
    """

    # Every directory this creates gets `mode`, not only the last one:
    # `mkdir(parents=True)` would leave the ancestors to the umask.
    for directory in reversed((path, *path.parents)):
        if not os.path.lexists(directory):
            directory.mkdir(mode=mode, exist_ok=True)
    # Check and change the directory that was opened, never a path that could
    # be swapped for a symlink in between.
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_mode & 0o022:
            os.fchmod(fd, stat.S_IMODE(info.st_mode) & ~0o022)
            return True
        return False
    finally:
        os.close(fd)



def fsync_directory(path: Path) -> None:
    """Make a rename in `path` durable before anything that depends on it."""

    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
