"""Read-only fixed-path cgroup2 mount admission for trusted composition.

No mount, namespace, process, or cgroup mutation. This checks the current
process view and requires the controller to sit at its fixed unit path relative
to its own cgroup-namespace root (exact /proc/self/cgroup match); PID 1 is never
opened. This is not a proof against a private cgroup namespace whose root
already mimics that path (e.g. a container); containerised deployment is
unsupported. It does not authenticate PID 1 as the selected D-Bus manager or
prove the unit's no-escape hardening.
The libc boundary is reviewed for Linux LP64 amd64/arm64. Other ABIs refuse.
"""

from contextlib import contextmanager
import ctypes
import os
import platform
import re
import stat
import sys

from .bootstrap_cgroup import validate_cgroup_root
from .units import UnitOperationFailed

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_MOUNT = "/sys/fs/cgroup"
_CGROUP2_MAGIC = 0x63677270
_PROC_MAGIC = 0x9FA0
_NSFS_MAGIC = 0x6E736673
_LIMIT = 1024 * 1024
# The kernel prints this path relative to the reader's cgroup-namespace root.
# systemd places the controller at this path and RestrictNamespaces=yes stops
# the unit creating a namespace, so an exact match means the namespace root is
# the hierarchy root systemd used. A capability-less root cannot open
# /proc/1/ns (ptrace check), so PID 1 equivalence is not observable here.
CONTROLLER_GROUP = "/system.slice/azazel-activated.service"
_CONTROLLER_CGROUP = f"0::{CONTROLLER_GROUP}\n".encode("ascii")


def _filesystem_type(fd):
    if (sys.platform != "linux" or ctypes.sizeof(ctypes.c_long) != 8
            or platform.machine() not in {"x86_64", "aarch64"}):
        raise UnitOperationFailed("cgroup mount ABI not admitted")
    # Linux LP64 statfs begins with a native long f_type. An aligned oversized
    # buffer avoids relying on the layout of fields we do not inspect.
    buffer = (ctypes.c_long * 64)()
    function = ctypes.CDLL(None, use_errno=True).fstatfs
    function.argtypes = [ctypes.c_int, ctypes.c_void_p]
    function.restype = ctypes.c_int
    if function(fd, ctypes.byref(buffer)) != 0:
        raise UnitOperationFailed("cgroup filesystem observation unavailable")
    return buffer[0]


def _text(raw, limit):
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise ValueError
    return raw.decode("ascii")


def _mount_record(mountinfo, fdinfo, device, inode):
    """Pure bounded decoding; only trusted kernel procfs data admits a mount."""
    try:
        if type(device) is not int or device < 0 or type(inode) is not int or inode < 1:
            raise ValueError
        fields = {}
        for line in _text(fdinfo, 4096).splitlines():
            key, value = line.split(":", 1)
            if key in fields:
                raise ValueError
            fields[key] = value.strip()
        for key in ("mnt_id", "ino"):
            if not re.fullmatch(r"[1-9][0-9]{0,19}", fields[key]):
                raise ValueError
        wanted = int(fields["mnt_id"])
        if int(fields["ino"]) != inode:
            raise ValueError
        records, selected = {}, []
        for line in _text(mountinfo, _LIMIT).splitlines():
            pre, post = line.split(" - ")
            left, right = pre.split(" "), post.split(" ")
            if len(left) < 6 or len(right) != 3 or any(not item for item in left + right):
                raise ValueError
            if not all(re.fullmatch(r"[1-9][0-9]{0,19}", item) for item in left[:2]):
                raise ValueError
            number = int(left[0])
            if number in records:
                raise ValueError
            records[number] = (left, right)
            if left[4] == _MOUNT:
                selected.append(number)
            if left[4].startswith(_MOUNT + "/"):
                raise ValueError
        if selected != [wanted]:
            raise ValueError
        left, right = records[wanted]
        if (left[2] != f"{os.major(device)}:{os.minor(device)}"
                or left[3] != "/" or right[0] != "cgroup2"):
            raise ValueError
        return wanted
    except (ValueError, KeyError, UnicodeError, TypeError, OverflowError):
        raise UnitOperationFailed("cgroup mount record refused") from None


def _read_proc(path, limit):
    fd = os.open(path, _READ_FLAGS)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode) or _filesystem_type(fd) != _PROC_MAGIC:
            raise UnitOperationFailed("kernel procfs source required")
        raw = bytearray()
        while len(raw) <= limit:
            part = os.read(fd, limit + 1 - len(raw))
            if not part:
                break
            raw.extend(part)
        if not 0 < len(raw) <= limit:
            raise UnitOperationFailed("kernel procfs source exceeds bound")
        return bytes(raw)
    finally:
        os.close(fd)


def _namespaces():
    parent = os.open("/proc/self/ns", _DIR_FLAGS)
    try:
        if _filesystem_type(parent) != _PROC_MAGIC:
            raise UnitOperationFailed("kernel namespace source required")
        before = os.stat("cgroup", dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISLNK(before.st_mode):
            raise UnitOperationFailed("kernel namespace link required")
        # Following this kernel magic link is deliberate. Validate its
        # nsfs target, not a caller's matching symlink text.
        fd = os.open("cgroup", os.O_RDONLY | os.O_CLOEXEC, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if _filesystem_type(fd) != _NSFS_MAGIC:
                raise UnitOperationFailed("kernel namespace descriptor required")
            middle = os.stat("cgroup", dir_fd=parent, follow_symlinks=False)
            if (before.st_dev, before.st_ino) != (middle.st_dev, middle.st_ino):
                raise UnitOperationFailed("kernel namespace link changed")
            if _read_proc("/proc/self/cgroup", 4096) != _CONTROLLER_CGROUP:
                raise UnitOperationFailed("cgroup namespace root is not host root")
            after = os.stat("cgroup", dir_fd=parent, follow_symlinks=False)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise UnitOperationFailed("kernel namespace link changed")
            return ((info.st_dev, info.st_ino),)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _open_fixed_root():
    current = os.open("/", _DIR_FLAGS)
    try:
        for component in ("sys", "fs", "cgroup"):
            validate_cgroup_root(current, 0)
            child = os.open(component, _DIR_FLAGS, dir_fd=current)
            os.close(current)
            current = child
        validate_cgroup_root(current, 0)
        if _filesystem_type(current) != _CGROUP2_MAGIC:
            raise UnitOperationFailed("fixed cgroup path is not cgroup2")
        return current
    except BaseException:
        os.close(current)
        raise


def _snapshot(fd):
    info = validate_cgroup_root(fd, 0)
    if _filesystem_type(fd) != _CGROUP2_MAGIC:
        raise UnitOperationFailed("held cgroup filesystem changed")
    namespaces = _namespaces()
    before = _read_proc(f"/proc/self/fdinfo/{fd}", 4096)
    mount = _mount_record(_read_proc("/proc/self/mountinfo", _LIMIT), before,
                          info.st_dev, info.st_ino)
    if before != _read_proc(f"/proc/self/fdinfo/{fd}", 4096) or _namespaces() != namespaces:
        raise UnitOperationFailed("cgroup mount observation changed")
    current = _open_fixed_root()
    try:
        named = os.fstat(current)
        current_mount = _mount_record(
            _read_proc("/proc/self/mountinfo", _LIMIT),
            _read_proc(f"/proc/self/fdinfo/{current}", 4096), named.st_dev, named.st_ino,
        )
        if (named.st_dev, named.st_ino, current_mount) != (info.st_dev, info.st_ino, mount):
            raise UnitOperationFailed("cgroup mount path binding changed")
    finally:
        os.close(current)
    if _namespaces() != namespaces:
        raise UnitOperationFailed("cgroup namespace changed during binding check")
    return (info.st_dev, info.st_ino, mount, namespaces)


class BootstrapCgroupMount:
    """Context-owned root; consumers borrow it only while this context lives."""

    def __init__(self, fd):
        self._fd = fd
        self._identity = _snapshot(fd)

    def check(self):
        try:
            if self._fd is None or _snapshot(self._fd) != self._identity:
                raise UnitOperationFailed("cgroup mount identity changed")
        except OSError:
            raise UnitOperationFailed("cgroup mount unavailable") from None

    def fileno(self):
        self.check()
        return self._fd


@contextmanager
def open_bootstrap_cgroup_mount():
    """Fixed read-only opener; no path, namespace or device selection API."""
    fd, handle = None, None
    try:
        fd = _open_fixed_root()
        handle = BootstrapCgroupMount(fd)
        handle.check()
        yield handle
    except OSError:
        raise UnitOperationFailed("fixed cgroup mount admission unavailable") from None
    finally:
        if handle is not None:
            handle._fd = None
        if fd is not None:
            os.close(fd)
