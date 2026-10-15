"""Read-only bounded cgroup-v2 observations beneath a trusted root descriptor.

Composition must independently establish that the descriptor is the host's
admitted cgroup-v2 hierarchy, not a caller-supplied regular filesystem. This
module has no production opener. Ordinary-file fixtures test the parser and
traversal only. Absence/emptiness is not proof of no process migration or of a
continuing fence; admitted unit hardening and same-owner observations surround it.
"""

import os
import posixpath
import re
import stat

from .units import UnitOperationFailed

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_LIMIT = 4096


def _components(path):
    if (type(path) is not str or not path.startswith("/")
            or path == "/" or path.startswith("//") or len(path) > 4096
            or posixpath.normpath(path) != path):
        raise UnitOperationFailed("bootstrap cgroup path refused")
    components = path[1:].split("/")
    if len(components) > 32 or any(
        not re.fullmatch(r"[A-Za-z0-9_.:@\\-]{1,255}", part)
        or part in {".", ".."} for part in components
    ):
        raise UnitOperationFailed("bootstrap cgroup path refused")
    return components


def _directory(fd, owner_uid):
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid
            or info.st_mode & 0o022):
        raise UnitOperationFailed("bootstrap cgroup directory refused")
    return info


def _events(raw):
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise UnitOperationFailed("bootstrap cgroup events malformed") from None
    values = {}
    for line in text.splitlines():
        fields = line.split(" ")
        if (len(fields) != 2 or not re.fullmatch(r"[a-z_]+", fields[0])
                or not re.fullmatch(r"[0-9]+", fields[1]) or fields[0] in values):
            raise UnitOperationFailed("bootstrap cgroup events malformed")
        values[fields[0]] = fields[1]
    if values.get("populated") != "0":
        raise UnitOperationFailed("bootstrap cgroup emptiness unconfirmed")


def validate_cgroup_root(root_fd, owner_uid):
    """Check descriptor shape/ownership only; this does not admit a mount."""
    if type(root_fd) is not int or type(owner_uid) is not int or owner_uid < 0:
        raise UnitOperationFailed("trusted cgroup root descriptor required")
    try:
        return _directory(root_fd, owner_uid)
    except OSError:
        raise UnitOperationFailed("bootstrap cgroup root unavailable") from None


def observe_cgroup_at(root_fd: int, path: str, *, owner_uid: int):
    """Observe an empty subtree or missing final leaf, never write or kill."""
    validate_cgroup_root(root_fd, owner_uid)
    parts = _components(path)
    current = None
    try:
        current = os.dup(root_fd)
        for index, part in enumerate(parts):
            parent = _directory(current, owner_uid)
            try:
                child = os.open(part, _DIR_FLAGS, dir_fd=current)
            except FileNotFoundError:
                if index == len(parts) - 1:
                    return ("absent", parent.st_dev, parent.st_ino)
                raise
            os.close(current)
            current = child
        info = _directory(current, owner_uid)
        fd = os.open("cgroup.events", _FILE_FLAGS, dir_fd=current)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner_uid
                    or before.st_nlink != 1 or before.st_mode & 0o022):
                raise UnitOperationFailed("bootstrap cgroup events file refused")
            raw = bytearray()
            while len(raw) <= _LIMIT:
                chunk = os.read(fd, _LIMIT + 1 - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) > _LIMIT:
                raise UnitOperationFailed("bootstrap cgroup events exceed budget")
            _events(bytes(raw))
            named = os.stat("cgroup.events", dir_fd=current, follow_symlinks=False)
            after = os.fstat(fd)
            def stamp(item):
                return (item.st_dev, item.st_ino, item.st_mode,
                        item.st_uid, item.st_nlink, item.st_mtime_ns,
                        item.st_ctime_ns)
            if stamp(before) != stamp(after) or stamp(after) != stamp(named):
                raise UnitOperationFailed("bootstrap cgroup events changed")
        finally:
            os.close(fd)
        return ("empty", info.st_dev, info.st_ino)
    except OSError:
        raise UnitOperationFailed("bootstrap cgroup observation unavailable") from None
    finally:
        if current is not None:
            os.close(current)
