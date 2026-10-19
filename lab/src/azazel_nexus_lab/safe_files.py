"""Descriptor-only access to the two existing lab break/recovery files."""
from __future__ import annotations

import os
import pwd
import stat
from contextlib import contextmanager

from .refusal import LabRefused

FILES = {
    "knowledge-trust": ("var/lib/azazel/lite-trust/trust.json", None),
    "audit-tamper": ("var/lib/azazel/state/mio/route.jsonl", "azmioentry"),
}


def expected_owner(target):
    account = FILES[target][1]
    return 0 if account is None else pwd.getpwnam(account).pw_uid


@contextmanager
def lab_file(root, target, *, write=False):
    """Refuse links in every component and validate before any mutation.

    Files must already exist. Never create or truncate by an unchecked path in
    a directory writable by a daemon. Keep the checked inode open for the I/O.
    """
    relative, _ = FILES[target]
    directory_fd = file_fd = None
    try:
        if not root.is_absolute() or ".." in root.parts:
            raise LabRefused("LAB: unsafe lab file root")
        directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for part in (*root.parts[1:], *relative.split("/")[:-1]):
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(relative.split("/")[-1],
                          (os.O_RDWR if write else os.O_RDONLY)
                          | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                          dir_fd=directory_fd)
        info = os.fstat(file_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_owner(target)
                or info.st_nlink != 1):
            raise LabRefused("LAB: unsafe lab file owner, type or link count")
        stream = os.fdopen(file_fd, "r+b" if write else "rb")
        file_fd = None
        with stream:
            yield stream
    except OSError:
        raise LabRefused("LAB: unsafe or unavailable lab file") from None
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)
