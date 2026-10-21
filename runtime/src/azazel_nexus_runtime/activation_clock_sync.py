"""Whether the OS clock was synchronized in this boot (#251 M-1). Read-only.

Used by the activation pass's `trusted_clock` producer only when the
activation policy says `"require_clock_synchronized":true`
(`docs/activation-observe-baseline.md` §10.1). The one source is
systemd-timesyncd's marker `/run/systemd/timesync/synchronized`, which
timesyncd touches on each successful synchronization ("to assist
systemd-time-wait-sync and other applications", timesyncd(8)). It was
chosen over the two other read-only sources because the controller can read
it without any new permission:

* `adjtimex(2)` (`STA_UNSYNC`) is in systemd's `@clock` group, which the
  controller's `SystemCallFilter=@system-service` does not allow; a blocked
  call kills the process. Python has no binding for it either.
* timedated's `NTPSynchronized` lives on another bus name. The controller's
  D-Bus session sends only to the admitted owner of `org.freedesktop.systemd1`,
  and asking timedated would bus-activate a service: a start, not a read.

The marker lives under `/run` (a tmpfs, so it names this boot; a
soft-reboot keeps both `/run` and the running clock). Under
`ProtectSystem=strict` `/run` stays readable. Its limits are stated rather
than solved: only timesyncd writes it, so a node that keeps time with
chrony or another daemon never has it and refuses every pass while the
policy requires synchronization; it proves that a synchronization happened
in this boot, not that the clock is still synchronized, nor that the time
source was authenticated.

This module opens nothing for writing, creates nothing and never follows a
symbolic link. Anything other than a regular marker in a real directory,
neither of them group- or world-writable, is a refusal (timesyncd's are
`0644` in a `0755` directory; the owner is not checked).
"""

from __future__ import annotations

import os
import stat

__all__ = ["TIMESYNC_SYNCHRONIZED", "ClockNotSynchronized", "require_clock_synchronized"]

#: The fixed marker path; never taken from configuration or the environment.
TIMESYNC_SYNCHRONIZED = "/run/systemd/timesync/synchronized"
_WRITABLE = stat.S_IWGRP | stat.S_IWOTH


class ClockNotSynchronized(Exception):
    """No proof that the clock was synchronized in this boot (fixed text)."""


def require_clock_synchronized(path: str = TIMESYNC_SYNCHRONIZED) -> bool:
    """Return True when the timesyncd marker proves a synchronization; else raise.

    `path` is a seam for tests; production uses the fixed path. Each
    directory component is opened with `O_NOFOLLOW`, the marker is
    `lstat`ed relative to its directory, and only a regular file whose
    directory and itself are neither group- nor world-writable counts.
    """
    try:
        if type(path) is not str or not path.startswith("/"):
            raise ClockNotSynchronized()
        parts = path.split("/")[1:]
        if len(parts) < 2 or any(part in ("", ".", "..") for part in parts):
            raise ClockNotSynchronized()
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for name in parts[:-1]:
                child = os.open(name, flags, dir_fd=fd)
                os.close(fd)
                fd = child
            directory = os.fstat(fd)
            if not stat.S_ISDIR(directory.st_mode) or directory.st_mode & _WRITABLE:
                raise ClockNotSynchronized()
            marker = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        finally:
            os.close(fd)
        if not stat.S_ISREG(marker.st_mode) or marker.st_mode & _WRITABLE:
            raise ClockNotSynchronized()
        return True
    except Exception:  # noqa: BLE001 - absent or unreadable is unproven, never synchronized
        raise ClockNotSynchronized("clock synchronization not proven") from None
