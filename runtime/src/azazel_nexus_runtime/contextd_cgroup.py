"""Whether the Knowledge Context broker's cgroup is empty (stop contract).

`ActiveState` only says what systemd believes about the unit. A unit can end
`failed` while processes are still in its cgroup (a process that survives the
final SIGKILL, for example in uninterruptible sleep). This module reads one
fixed file, `cgroup.events`, of the broker's one fixed cgroup and answers with
exactly one of three values:

- `empty`: the cgroup has no process (`populated 0`), or systemd has removed it;
- `populated`: `populated 1`;
- `unknown`: anything that cannot be established. `unknown` is never `empty`.

The path is a constant (cgroup v2, `system.slice`, the broker's unit name). It
is trusted only when (a) the mount that holds the directory this module opened
at `/sys/fs/cgroup` (its `mnt_id` in `/proc/self/fdinfo`) has a `/proc/self/mountinfo`
line that is `cgroup2`, with mount root `/`, mount point `/sys/fs/cgroup` and
the device of that directory, and (b) the reader's own `/proc/self/cgroup` is exactly one
line `0::/system.slice/<name>.service`, which shows that systemd's cgroup root
is this namespace's root. Otherwise (a container with the host cgroup
namespace, cgroup v1, an unreadable file) the constant path may name a
different cgroup, and the answer is `unknown`.

The path is walked one component at a time with `openat`, `O_NOFOLLOW` and
`O_DIRECTORY` from `/` (`sys`, `fs`, `cgroup`, then the broker's two names). `system.slice` must exist. Only the last directory (the
broker's own) may be absent, and that counts as `empty` only when the unit is
`inactive` or `failed` (systemd removes the cgroup of a stopped unit) and the
mount line, the device and the reader's own cgroup read again afterwards are
unchanged (the same re-check follows a `populated 0`); every other case is `unknown`. Every descriptor opened is closed.

Nothing is written, nothing is signalled, no other cgroup is read, and no D-Bus
property is used. Opening is `O_NOFOLLOW`; every directory on the path must be a
real directory.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

__all__ = ["CGROUP_EMPTY", "CGROUP_POPULATED", "CGROUP_UNKNOWN", "read_contextd_cgroup"]

CGROUP_EMPTY = "empty"
CGROUP_POPULATED = "populated"
CGROUP_UNKNOWN = "unknown"

_CGROUP_MOUNT = "/sys/fs/cgroup"
_TO_CGROUP = ("sys", "fs", "cgroup")
_BROKER_CGROUP = ("system.slice", "azazel-knowledge-contextd.service")
_SELF_LINE = re.compile(r"0::/system\.slice/[A-Za-z0-9_.@-]+\.service")
_STOPPED = ("inactive", "failed")
_READ_LIMIT = 65536
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _read_all(fd: int) -> str:
    data = os.read(fd, _READ_LIMIT + 1)
    if len(data) > _READ_LIMIT:
        raise OSError("too long")
    return data.decode("ascii")


def _read_file(root: Path, *parts: str) -> str:
    fd = os.open(root.joinpath(*parts), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return _read_all(fd)
    finally:
        os.close(fd)


#: Where an operator's login shell or a service may sit; anything else (for
#: example `/docker/<id>/...` under a shared host cgroup namespace) may mean the
#: constant path names another hierarchy.
_OPERATOR_TOP = ("init.scope", "user.slice", "system.slice")


def _own_cgroup_confirms_root_operator(root: Path, cgroup_fd: int) -> bool:
    """CLI mode: the reader's own cgroup is `/` or below a systemd top-level
    slice/scope, and that directory exists under the opened mount."""
    text = _read_file(root, "proc", "self", "cgroup")
    if not text.endswith("\n"):
        return False
    lines = text[:-1].split("\n")
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        return False
    parts = [part for part in lines[0][4:].split("/") if part]
    if any(part in (".", "..") for part in parts):
        return False
    if parts and parts[0] not in _OPERATOR_TOP:
        return False
    fd = os.dup(cgroup_fd)
    try:
        for part in parts:
            child = os.open(part, _DIR, dir_fd=fd)
            os.close(fd)
            fd = child
    except OSError:
        return False
    finally:
        os.close(fd)
    return True


def _own_cgroup_confirms_root(root: Path) -> bool:
    """The reader sits at `/system.slice/<name>.service`: systemd's root is ours."""
    text = _read_file(root, "proc", "self", "cgroup")
    if not text.endswith("\n"):
        return False
    lines = text[:-1].split("\n")
    return len(lines) == 1 and _SELF_LINE.fullmatch(lines[0]) is not None


def _mount_id(fd: int):
    """The mount ID of the mount that holds the open directory `fd`, or None."""
    with open(f"/proc/self/fdinfo/{fd}", "rb") as handle:
        for line in handle.read(_READ_LIMIT).decode("ascii", "replace").split("\n"):
            if line.startswith("mnt_id:"):
                value = line.split(":", 1)[1].strip()
                return value if value.isdigit() else None
    return None


def _trust(root: Path, cgroup_fd: int, caller: str = "service"):
    """The identity of the trusted cgroup root, or None if it is not trusted.

    The mount that holds the opened `/sys/fs/cgroup` directory (its `mnt_id`, from
    `/proc/self/fdinfo`) must have a `/proc/self/mountinfo` line that is `cgroup2`,
    has mount root `/`, mount point `/sys/fs/cgroup` and the device of that
    directory; and the reader's own cgroup must be `0::/system.slice/<name>.service`.
    """
    device = os.fstat(cgroup_fd).st_dev
    mount_id = _mount_id(cgroup_fd)
    if mount_id is None:
        return None
    found = None
    for line in _read_file(root, "proc", "self", "mountinfo").split("\n"):
        left, sep, right = line.partition(" - ")
        fields = left.split(" ")
        if sep and len(fields) >= 5 and fields[0] == mount_id:
            found = (fields, right.split(" ", 1)[0])
            break
    if found is None:
        return None
    fields, fstype = found
    if (fstype != "cgroup2" or fields[3] != "/" or fields[4] != _CGROUP_MOUNT
            or fields[2] != f"{os.major(device)}:{os.minor(device)}"):
        return None
    if caller == "operator":
        if not _own_cgroup_confirms_root_operator(root, cgroup_fd):
            return None
    elif not _own_cgroup_confirms_root(root):
        return None
    return (device, mount_id, tuple(fields), _read_file(root, "proc", "self", "cgroup"))


def read_contextd_cgroup(active_state: str, *, root: Path = Path("/"),
                         caller: str = "service") -> str:
    """`empty`, `populated` or `unknown` for the broker's cgroup; never raises.

    `active_state` is the broker's `ActiveState` read from systemd just before.
    `root` is `/` in production and a stand-in tree in tests. `caller` is
    `service` (the pass, the recheck: own cgroup must be a system.slice
    service) or `operator` (the egress CLI run by root from a login shell: own
    cgroup `/` or under init.scope, user.slice or system.slice, existing under
    the verified cgroup2 mount). Every other value is `unknown`; the mount
    binding is identical in both modes.
    """
    if caller not in ("service", "operator"):
        return CGROUP_UNKNOWN
    opened: list[int] = []

    def trust(fd: int):
        return _trust(root, fd) if caller == "service" else _trust(root, fd, caller)

    try:
        fd = os.open(root, _DIR)
        opened.append(fd)
        for part in _TO_CGROUP:
            fd = os.open(part, _DIR, dir_fd=fd)
            opened.append(fd)
        trusted = trust(fd)
        if trusted is None:
            return CGROUP_UNKNOWN
        for index, part in enumerate(_BROKER_CGROUP):
            try:
                fd = os.open(part, _DIR, dir_fd=fd)
            except FileNotFoundError:
                last = index == len(_BROKER_CGROUP) - 1
                if not (last and active_state in _STOPPED):
                    return CGROUP_UNKNOWN
                # Absence is believed only if nothing under it changed meanwhile.
                again = trust(opened[3])
                return CGROUP_EMPTY if again == trusted else CGROUP_UNKNOWN
            opened.append(fd)
        events = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=fd)
        opened.append(events)
        text = _read_all(events)
        values = [line.split(" ") for line in text.split("\n") if line.startswith("populated ")]
        if len(values) != 1 or len(values[0]) != 2:
            return CGROUP_UNKNOWN
        answer = {"0": CGROUP_EMPTY, "1": CGROUP_POPULATED}.get(values[0][1], CGROUP_UNKNOWN)
        if answer == CGROUP_EMPTY and trust(opened[3]) != trusted:
            return CGROUP_UNKNOWN  # the mount or the reader's cgroup changed while reading
        return answer
    except (OSError, UnicodeDecodeError):
        return CGROUP_UNKNOWN
    finally:
        for each in opened:
            try:
                os.close(each)
            except OSError:
                pass
