"""Owned fixed directory handles and retained optional-leaf absence.

No directory is created. Missing mutable overlay/mask directories refuse.
Optional absence is a checked path observation, never a fabricated fd or
permission to ignore a directory that subsequently appears. Private root seams
are for ordinary-directory tests, not user-selected runtime paths.
"""

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import stat

from azazel_nexus.operator_trust import ApprovalRefused

_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_PATHS = {
    "overlay": "/run/systemd/system.control",
    "masks": "/etc/systemd/system",
    "higher_priority": "/etc/systemd/system.control",
    "transient": "/run/systemd/transient",
    "generator_early": "/run/systemd/generator.early",
}
_OPTIONAL = frozenset({"higher_priority", "transient", "generator_early"})


def _stamp(fd, owner_uid):
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid
            or info.st_mode & 0o022):
        raise ApprovalRefused("unsafe bootstrap directory")
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode


class _RetainedPath:
    def __init__(self, root, chain, owner_uid, leaf, missing):
        self.root = root
        self.chain = tuple(chain)
        self.owner_uid = owner_uid
        self.leaf = leaf
        self.missing = missing
        self.closed = False
        self.forbidden = ()
        self.stamps = tuple(_stamp(fd, owner_uid) for _, fd in self.chain)
        self.path = root.joinpath(*(name for name, _ in self.chain[1:]))
        if missing:
            self.path /= leaf

    def check(self):
        if self.closed:
            raise ApprovalRefused("bootstrap directory lifetime ended")
        try:
            if self.root.resolve(strict=True) != self.root:
                raise ApprovalRefused("bootstrap root path changed")
            named = self.root.stat(follow_symlinks=False)
            if (named.st_dev, named.st_ino) != self.stamps[0][:2]:
                raise ApprovalRefused("bootstrap root identity changed")
            for index, (name, fd) in enumerate(self.chain):
                if _stamp(fd, self.owner_uid) != self.stamps[index]:
                    raise ApprovalRefused("bootstrap directory identity changed")
                if index:
                    named = os.stat(name, dir_fd=self.chain[index - 1][1],
                                    follow_symlinks=False)
                    if (named.st_dev, named.st_ino, named.st_uid, named.st_mode) != self.stamps[index]:
                        raise ApprovalRefused("bootstrap named directory changed")
            if self.missing:
                try:
                    os.stat(self.leaf, dir_fd=self.chain[-1][1], follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ApprovalRefused("optional bootstrap directory appeared")
            else:
                for name in self.forbidden:
                    try:
                        os.stat(name, dir_fd=self.chain[-1][1], follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    raise ApprovalRefused("higher-priority bootstrap input exists")
        except OSError:
            raise ApprovalRefused("bootstrap directory observation unavailable") from None


class PresentBootstrapDirectory:
    """Borrowed fd with named-chain validation at each fd-consuming operation."""

    def __init__(self, retained):
        if type(retained) is not _RetainedPath or retained.missing:
            raise ApprovalRefused("retained present directory required")
        self._retained = retained
        self._checks = (retained,)

    def __index__(self):
        for observation in self._checks:
            observation.check()
        return self._retained.chain[-1][1]

    def fileno(self):
        return self.__index__()


class AbsentBootstrapDirectory:
    """Borrowed absence witness; cannot be used as an operating-system fd."""

    def __init__(self, retained):
        if type(retained) is not _RetainedPath or not retained.missing:
            raise ApprovalRefused("retained absent directory required")
        self._retained = retained
        self._checks = (retained,)

    def check(self):
        for observation in self._checks:
            observation.check()

    def stamp(self, owner_uid):
        if owner_uid != self._retained.owner_uid:
            raise ApprovalRefused("absence owner differs")
        self.check()
        return ("absent", str(self._retained.path), self._retained.stamps)

    def bind(self, path):
        if Path(path) != self._retained.path:
            raise ApprovalRefused("absence path differs")
        self.check()


@contextmanager
def _directory_under(root, relative, *, owner_uid, optional):
    root = Path(root)
    parts = Path(relative).parts
    if (not root.is_absolute() or not parts or Path(relative).is_absolute()
            or any(part in {".", ".."} for part in parts)):
        raise ApprovalRefused("fixed bootstrap directory path required")
    chain = []
    retained = None
    try:
        chain.append(("", os.open(root, _FLAGS)))
        _stamp(chain[0][1], owner_uid)
        missing = False
        for index, part in enumerate(parts):
            try:
                fd = os.open(part, _FLAGS, dir_fd=chain[-1][1])
            except FileNotFoundError:
                if not optional or index != len(parts) - 1:
                    raise ApprovalRefused("required bootstrap directory missing") from None
                missing = True
                break
            chain.append((part, fd))
            _stamp(fd, owner_uid)
        retained = _RetainedPath(root, chain, owner_uid, parts[-1], missing)
        retained.check()
        yield retained, (AbsentBootstrapDirectory(retained) if missing
                         else PresentBootstrapDirectory(retained))
    except OSError:
        raise ApprovalRefused("bootstrap directory open refused") from None
    finally:
        if retained is not None:
            retained.closed = True
        for _, fd in reversed(chain):
            os.close(fd)


def bind_directory_path(path, fd):
    if type(fd) is AbsentBootstrapDirectory:
        fd.bind(path)
        return
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ApprovalRefused("bootstrap directory path refused")
    named, opened = path.stat(follow_symlinks=False), os.fstat(fd)
    if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
        raise ApprovalRefused("bootstrap directory descriptor binding changed")


@dataclass(frozen=True)
class BootstrapOverlayDirectories:
    """Context-owned handles; consumers borrow them until the context exits."""

    arguments: dict
    retained: tuple
    owner_uid: int

    def check(self):
        for path in self.retained:
            path.check()

    def closed_files(self, *, journal_store, guard):
        from .bootstrap_close_files import BootstrapClosedOverlayFiles
        self.check()
        keys = ("overlay", "masks", "higher_priority")
        args = {key + suffix: self.arguments[key + suffix]
                for key in keys for suffix in ("_fd", "_path")}
        return BootstrapClosedOverlayFiles(**args, owner_uid=self.owner_uid,
                                           journal_store=journal_store, guard=guard)

    def withdrawal_files(self, *, journal_store, guard):
        from .bootstrap_withdrawal import BootstrapWithdrawalFiles
        self.check()
        return BootstrapWithdrawalFiles(**self.arguments, owner_uid=self.owner_uid,
                                         journal_store=journal_store, guard=guard)


@contextmanager
def _overlay_directories_under(root, *, owner_uid):
    """Private ordinary-directory composition test seam."""
    root = Path(root)
    with ExitStack() as stack:
        args, retained = {}, []
        for key, path in _PATHS.items():
            observation, handle = stack.enter_context(_directory_under(
                root, path[1:], owner_uid=owner_uid, optional=key in _OPTIONAL,
            ))
            retained.append(observation)
            if key in _OPTIONAL:
                observation.forbidden = tuple(
                    unit + suffix for unit in
                    ("azazel-auditd.service", "azazel-commissiond.service")
                    for suffix in ("", ".d")
                )
            args[key + "_fd"], args[key + "_path"] = handle, str(root / path[1:])
        for key in _PATHS:
            args[key + "_fd"]._checks = tuple(retained)
        result = BootstrapOverlayDirectories(args, tuple(retained), owner_uid)
        result.check()
        yield result


@contextmanager
def open_bootstrap_overlay_directories():
    """Read-only fixed production paths; no fallback, mkdir or CLI input."""
    with _overlay_directories_under(Path("/"), owner_uid=0) as directories:
        yield directories
