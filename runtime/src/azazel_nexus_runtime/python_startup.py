"""Protected absence of a bounded conventional CPython startup override set.

Current repeated absence is not historical startup proof, a filesystem freeze,
complete stdlib/import coverage or native-loader integrity. No file is opened
for content and no path is supplied by a runtime requester.
"""

from dataclasses import dataclass
import errno
import os
import stat

from azazel_nexus.operator_trust import ApprovalRefused

from .python_profile import BASE_INTERPRETER, pyvenv_config_path


_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


@dataclass(frozen=True)
class StartupAbsence:
    paths: tuple
    observations: tuple


def startup_absence_paths(interpreter: str) -> tuple[str, ...]:
    pyvenv_config_path(interpreter)
    paths = tuple(sorted({
        interpreter.removeprefix("/") + "._pth",
        BASE_INTERPRETER + "._pth",
        "usr/bin/pybuilddir.txt", "usr/bin/Modules/Setup.local",
        "usr/lib/python313.zip",
    }))
    if any(len(path.split("/")) > 32 for path in paths):
        raise ApprovalRefused("bounded Python startup paths required")
    return paths


def _stamp(info, *, owner):
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner
            or info.st_mode & 0o022):
        raise ApprovalRefused("Python startup ancestor not protected")
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)


def _missing(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except OSError as error:
        if error.errno == errno.ENOENT:
            return
        raise
    raise ApprovalRefused("Python startup override exists")


def _snapshot_at(root_fd, paths, *, owner):
    results = []
    known = {}
    for path in paths:
        chain = [("", os.dup(root_fd))]
        stamps = []
        missing_index = None
        try:
            stamps.append(_stamp(os.fstat(chain[0][1]), owner=owner))
            parts = path.split("/")
            for index, part in enumerate(parts):
                parent = chain[-1][1]
                try:
                    named = os.stat(part, dir_fd=parent, follow_symlinks=False)
                except OSError as error:
                    if error.errno != errno.ENOENT:
                        raise
                    missing_index = index
                    _missing(parent, part)
                    break
                if index == len(parts) - 1:
                    raise ApprovalRefused("Python startup override exists")
                expected = _stamp(named, owner=owner)
                child = os.open(part, _DIR, dir_fd=parent)
                chain.append((part, child))
                current = _stamp(os.fstat(child), owner=owner)
                if current != expected:
                    raise ApprovalRefused("Python startup ancestor changed")
                stamps.append(current)
            if missing_index is None:
                raise ApprovalRefused("Python startup absence not observed")
            _missing(chain[-1][1], parts[missing_index])
            for index in reversed(range(len(chain))):
                name, fd = chain[index]
                current = _stamp(os.fstat(fd), owner=owner)
                if current != stamps[index]:
                    raise ApprovalRefused("Python startup ancestor changed")
                if index and _stamp(os.stat(
                    name, dir_fd=chain[index - 1][1], follow_symlinks=False,
                ), owner=owner) != current:
                    raise ApprovalRefused("Python startup named ancestor changed")
                prefix = "/".join(parts[:index])
                if prefix in known and known[prefix] != current:
                    raise ApprovalRefused("Python startup shared ancestor changed")
                known[prefix] = current
            results.append((path, missing_index, tuple(stamps)))
        finally:
            for _name, fd in reversed(chain):
                os.close(fd)
    return tuple(results)


def _observe_at(root_fd, interpreter, *, owner):
    """Private ordinary-tree seam; production always opens its fixed root."""
    paths = startup_absence_paths(interpreter)
    first = _snapshot_at(root_fd, paths, owner=owner)
    if _snapshot_at(root_fd, paths, owner=owner) != first:
        raise ApprovalRefused("Python startup absence changed")
    return StartupAbsence(paths, first)


def observe_python_startup_absence(interpreter: str) -> StartupAbsence:
    """Interpreter comes only from already-pinned canonical wrapper bytes."""
    try:
        root = os.open("/", _DIR)
        try:
            before = _stamp(os.fstat(root), owner=0)
            result = _observe_at(root, interpreter, owner=0)
            if (_stamp(os.fstat(root), owner=0) != before
                    or _stamp(os.stat("/", follow_symlinks=False), owner=0) != before):
                raise ValueError("Python startup root changed")
            return result
        finally:
            os.close(root)
    except Exception:
        raise ApprovalRefused("protected Python startup absence refused") from None
