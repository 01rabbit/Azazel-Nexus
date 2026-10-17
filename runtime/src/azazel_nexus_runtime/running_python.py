"""Read-only current interpreter binding, not start or import authority.

The procfs/kernel and Debian native substrate are trusted. This observes the
kernel executable's current bytes, not historical page contents, every mapped
library, or resistance to arbitrary in-process/privileged modification.
"""

from dataclasses import dataclass
from hashlib import sha256
import os
import stat
import sys

from azazel_nexus.installed_manifest import InstalledFile
from azazel_nexus.operator_trust import ApprovalRefused

from .bootstrap_cgroup_mount import _filesystem_type, _PROC_MAGIC
from .python_profile import BASE_INTERPRETER, pyvenv_config_path
from .startup_wrapper import validate_import_paths


_MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


@dataclass(frozen=True)
class PythonState:
    platform: str
    implementation: str
    cache_tag: str
    version: tuple
    abiflags: str
    executable: str
    base_executable: str
    prefixes: tuple
    flags: tuple
    import_paths: tuple
    dont_write_bytecode: bool
    byteorder: str
    maxsize: int


@dataclass(frozen=True)
class RunningExecutable:
    identity: tuple
    sha256: str


@dataclass(frozen=True)
class RunningPython:
    state: PythonState
    executable: RunningExecutable
    pid: int


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _protected_executable(identity, *, owner):
    if (type(identity) is not tuple or len(identity) != 9
            or any(type(value) is not int for value in identity)
            or identity[0] < 0 or identity[1] <= 0
            or not stat.S_ISREG(identity[2]) or stat.S_IMODE(identity[2]) != 0o755
            or identity[3] != owner or identity[5] != 1
            or not 0 < identity[6] <= _MAX_EXECUTABLE_BYTES):
        raise ApprovalRefused("current executable metadata refused")


def _fingerprint_fd(fd, *, owner=0):
    """Private regular-file test seam; production opens only its own proc exe."""
    before = _identity(os.fstat(fd))
    _protected_executable(before, owner=owner)
    hashes = []
    for _ in range(2):
        os.lseek(fd, 0, os.SEEK_SET)
        digest = sha256()
        total = 0
        while True:
            part = os.read(fd, min(65536, before[6] + 1 - total))
            if not part:
                break
            total += len(part)
            if total > before[6]:
                raise ApprovalRefused("current executable exceeds declared size")
            digest.update(part)
        if total != before[6] or _identity(os.fstat(fd)) != before:
            raise ApprovalRefused("current executable changed during measurement")
        hashes.append(digest.hexdigest())
    if hashes[0] != hashes[1]:
        raise ApprovalRefused("current executable content observations differ")
    return RunningExecutable(before, hashes[0])


def _python_state():
    return PythonState(
        sys.platform, sys.implementation.name, sys.implementation.cache_tag,
        tuple(sys.version_info), getattr(sys, "abiflags", None), sys.executable,
        getattr(sys, "_base_executable", None),
        (sys.prefix, sys.exec_prefix, sys.base_prefix, sys.base_exec_prefix),
        (sys.flags.isolated, sys.flags.no_site, sys.flags.ignore_environment,
         sys.flags.safe_path, getattr(sys.flags, "gil", None)),
        tuple(sys.path), sys.dont_write_bytecode, sys.byteorder, sys.maxsize,
    )


def observe_running_python() -> RunningPython:
    """No caller selects an executable, PID, path or alternate observation."""
    try:
        if sys.platform != "linux":
            raise ValueError("Linux current interpreter observation required")
        pid, before = os.getpid(), _python_state()
        proc = os.open("/proc", _DIR)
        try:
            if _filesystem_type(proc) != _PROC_MAGIC:
                raise ValueError("kernel procfs required")
            process = os.open(str(pid), _DIR, dir_fd=proc)
            try:
                if _filesystem_type(process) != _PROC_MAGIC:
                    raise ValueError("kernel process directory required")
                # Following this one magic link is intentional: directory
                # traversal itself is no-follow and verified as procfs.
                named = _identity(os.stat("exe", dir_fd=process))
                fd = os.open("exe", os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK,
                             dir_fd=process)
                try:
                    executable = _fingerprint_fd(fd)
                    if (executable.identity != named
                            or _identity(os.stat("exe", dir_fd=process)) != named):
                        raise ValueError("kernel executable binding changed")
                finally:
                    os.close(fd)
            finally:
                os.close(process)
        finally:
            os.close(proc)
        if os.getpid() != pid or _python_state() != before:
            raise ValueError("current Python observation changed")
        return RunningPython(before, executable, pid)
    except Exception:
        raise ApprovalRefused("current Python observation refused") from None


def validate_running_python(
    observation: RunningPython, *, interpreter: str, import_paths: tuple[str, ...],
    version: tuple[int, int, int], expected_file: InstalledFile,
) -> None:
    """Validate fixed observations against independent pins, not supplied trust."""
    try:
        pyvenv_config_path(interpreter)
        if (type(import_paths) is not tuple
                or validate_import_paths(import_paths) != import_paths
                or type(version) is not tuple or len(version) != 3
                or any(type(value) is not int for value in version)
                or version[:2] != (3, 13) or not 0 <= version[2] <= 9999
                or type(expected_file) is not InstalledFile
                or expected_file.mode != 0o755
                or not 0 < expected_file.size <= _MAX_EXECUTABLE_BYTES
                or type(observation) is not RunningPython
                or type(observation.pid) is not int or observation.pid <= 0
                or type(observation.state) is not PythonState
                or type(observation.executable) is not RunningExecutable):
            raise ValueError("fixed interpreter observations required")
        expected = PythonState(
            "linux", "cpython", "cpython-313", (*version, "final", 0), "",
            interpreter, "/" + BASE_INTERPRETER, ("/usr",) * 4,
            (1, 1, 1, True, 1), import_paths, True, "little", (1 << 63) - 1,
        )
        state = observation.state
        if (state != expected or type(state.version) is not tuple
                or tuple(type(v) for v in state.version) != (int, int, int, str, int)
                or type(state.flags) is not tuple
                or tuple(type(v) for v in state.flags) != (int, int, int, bool, int)
                or type(state.prefixes) is not tuple or type(state.import_paths) is not tuple
                or type(state.dont_write_bytecode) is not bool or type(state.maxsize) is not int):
            raise ValueError("unsupported current Python state")
        executable = observation.executable
        _protected_executable(executable.identity, owner=0)
        if (executable.identity[6] != expected_file.size
                or type(executable.sha256) is not str
                or executable.sha256 != expected_file.sha256):
            raise ValueError("current interpreter differs from independent pin")
    except Exception:
        raise ApprovalRefused("current Python binding refused") from None
