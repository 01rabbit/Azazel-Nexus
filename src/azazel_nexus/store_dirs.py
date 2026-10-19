"""Protect store directories independently of the operator's umask."""

import os
import stat
from pathlib import Path


def store_directory(path: Path, mode: int = 0o750) -> bool:
    """Remove write access regardless of umask, preserving inherited setgid.

    Store writers must protect both admitted artifacts and anti-rollback state.
    The fd binds inspection and tightening to the same directory, not a link.
    """

    path.mkdir(mode=mode, parents=True, exist_ok=True)
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

