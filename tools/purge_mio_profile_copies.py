#!/usr/bin/env python3
"""Remove raw-identity proposal copies left in /etc/azazel/mio-profile (#244).

Earlier releases published the expected and signed commissioning proposal there
in plain bytes. They carry raw identity (board serial, storage serials,
permanent MACs) that inventory confidentiality §3 allows only in the encrypted
commissioning record, and entryd no longer reads them. The reviewed signature
(`commissioning-proposal.sig`) holds no identity and is kept.

Only the two fixed names are touched, only as ordinary files, only inside the
given directory: the directory is opened without following a symlink, every
operation is relative to that descriptor, and a symlink, directory or other
object at a fixed name is refused (nothing removed) for administrator
inspection. Nothing here grants, verifies or activates anything.
"""
from __future__ import annotations

import fcntl
import os
import stat
import sys
from pathlib import Path

LEGACY_COPIES = ("commissioning-proposal.expected.json", "commissioning-proposal.json")


class PurgeRefused(Exception):
    """A fixed name holds something other than an ordinary file."""


def purge(directory: Path) -> list[str]:
    """Unlink the fixed legacy copies in ``directory``; return the names removed."""
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise PurgeRefused("profile directory refused (symlink or not a directory)") from exc
    try:
        # The same lock proposal review holds while publishing the signature.
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        present = []
        for name in LEGACY_COPIES:
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode):
                raise PurgeRefused(f"{name} is not an ordinary file; inspect it")
            present.append(name)
        for name in present:
            # unlink never follows a symlink and acts only on this directory.
            os.unlink(name, dir_fd=fd)
        if present:
            os.fsync(fd)
        return present
    finally:
        os.close(fd)


def main(argv: list[str]) -> int:
    if len(argv) != 1 or not argv[0].endswith("/etc/azazel/mio-profile"):
        print("usage: purge_mio_profile_copies.py [DESTDIR]/etc/azazel/mio-profile", file=sys.stderr)
        return 2
    try:
        removed = purge(Path(argv[0]))
    except (PurgeRefused, OSError) as exc:
        print(f"refusing to remove legacy M.I.O. proposal copies: {exc}", file=sys.stderr)
        return 1
    for name in removed:
        print(f"removed legacy raw-identity copy from the M.I.O. profile directory: {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
