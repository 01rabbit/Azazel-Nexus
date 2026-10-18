"""Fixed root pre-start observation; only a host HMAC crosses to locald."""
from __future__ import annotations

import grp
import os
import re
import stat
import sys

from azazel_nexus import model_admission as admission

from .hil_readiness import run_identity

DIRECTORY = "/run/azazel-mio-identity"
NAME = "node-identity"


def _directory():
    fd = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (info.st_uid != 0 or info.st_gid != grp.getgrnam("azmio").gr_gid
                or stat.S_IMODE(info.st_mode) != 0o750):
            raise ValueError("identity directory protection refused")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_identity():
    directory = _directory()
    try:
        fd = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=directory)
    finally:
        os.close(directory)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_gid != grp.getgrnam("azmio").gr_gid
                or stat.S_IMODE(info.st_mode) != 0o640 or info.st_nlink != 1
                or info.st_size != 77):
            raise ValueError("identity protection refused")
        raw = os.read(fd, 78)
        if not re.fullmatch(rb"hmac-sha256:[0-9a-f]{64}\n", raw):
            raise ValueError("identity digest refused")
        return {"host_digest": raw.decode("ascii").strip()}
    finally:
        os.close(fd)


def main():
    """No arguments or environment inputs; refresh on every service start."""
    if sys.argv[1:] or os.geteuid() != 0:
        raise SystemExit("root identity observer takes no arguments")
    directory = _directory()
    temporary = NAME + ".new"
    try:
        # A failed observation cannot leave a usable previous start's digest.
        for name in (NAME, temporary):
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
        try:
            raw = (run_identity()["host_digest"] + "\n").encode("ascii")
            if not re.fullmatch(rb"hmac-sha256:[0-9a-f]{64}\n", raw):
                raise ValueError("identity digest refused")
        except (OSError, ValueError, KeyError, UnicodeError):
            # Enabling admission makes unavailable identity a visible start failure.
            return 1 if admission.LOCAL_MODEL_ADMISSION_ENABLED else 0
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            os.fchown(fd, 0, grp.getgrnam("azmio").gr_gid)
            if os.write(fd, raw) != len(raw):
                raise OSError("short identity write")
            os.fchmod(fd, 0o640)
        finally:
            os.close(fd)
        os.replace(temporary, NAME, src_dir_fd=directory, dst_dir_fd=directory)
    finally:
        os.close(directory)
    return 0
