"""This boot's id, read the protected way (#206 P5, #196 §14, #276 F3).

A leaf: it imports nothing from this package. The decoy (`az-decoyd`) and
the decoy network helper (`az-decoy-netd`) read the boot id through it, so
that what they load from the library stays a handful of modules
(`tests/unit/test_decoy_import_closure.py` pins the closures). Before #276
they read it through `edge_package`, which pulled in about forty.

`edge_package` uses this module too (and re-raises a refusal as its own
`EdgePackageRefused`), so there is one reader and one validator.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

__all__ = ["BOOT_ID_PATH", "BootIdRefused", "is_boot_id", "read_current_boot_id"]

#: The kernel's identifier for the current boot. Fixed; tests inject another
#: one.
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")

#: The most this reads from the boot id file: 36 characters and a newline.
_BOOT_ID_MAX_BYTES = 64
_BOOT_ID_HEX = "0123456789abcdef"


class BootIdRefused(Exception):
    """This boot's id could not be read the protected way."""


def is_boot_id(value: object) -> bool:
    """A canonical lowercase UUID, as the kernel writes it. Nothing else."""

    if type(value) is not str or len(value) != 36:
        return False
    for index, char in enumerate(value):
        if index in (8, 13, 18, 23):
            if char != "-":
                return False
        elif char not in _BOOT_ID_HEX:
            return False
    return True


def read_current_boot_id(
    path: Path = BOOT_ID_PATH, *, owner_uid: int | None = None,
) -> str:
    """This boot's id, read the protected way, or `BootIdRefused`.

    No symlink is followed, the file must be a regular one (procfs reports the
    sysctl as one) owned by root and writable by nobody else, the read is
    bounded, and the value must be a canonical lowercase UUID. Anything else
    refuses.

    `owner_uid` exists for unit tests of these checks against a file the test
    owns. No production caller passes it, and no flag reaches it.
    """

    trusted = (0,) if owner_uid is None else (0, owner_uid)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode)
                    or info.st_uid not in trusted
                    or info.st_mode & 0o022):
                raise BootIdRefused("the boot id has unsafe ownership or mode")
            raw = stream.read(_BOOT_ID_MAX_BYTES + 1)
    except OSError as exc:
        raise BootIdRefused(f"the boot id could not be read: {exc}") from exc
    if len(raw) > _BOOT_ID_MAX_BYTES:
        raise BootIdRefused("the boot id is longer than a boot id")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise BootIdRefused("the boot id is not ASCII") from exc
    text = text.removesuffix("\n")
    if not is_boot_id(text):
        raise BootIdRefused("the boot id is not a canonical boot id")
    return text
