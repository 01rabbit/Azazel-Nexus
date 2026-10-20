"""The scoped units' installed files, and nothing that would change them (#206).

`docs/activation-observe-baseline.md` §3.2: the observe-baseline generation
hashes each scoped unit file as installed in `/usr/lib/systemd/system`. That
hash only describes what systemd loads if no other file contributes to the
unit, so measuring is paired with a refusal of every override systemd's
reviewed Debian 13 search path would apply (the path pinned in
`bootstrap_systemd_profile`):

* a file of the same name in any other search-path directory (`/etc`,
  `/run`, `/usr/local`, control, transient, attached and generator
  directories) -- except a symbolic link whose target is exactly
  `/dev/null`, which is a mask: the governed state of a unit before its
  grant, and one that only withholds;
* any entry in a drop-in directory for the unit: `<unit>.d/`, the prefix
  forms systemd applies to dashed names (`azazel-.service.d/`,
  `azazel-edge-.service.d/`, ...), and the global `service.d/`, in every
  search-path directory including the vendor one. An empty drop-in
  directory is accepted; anything that is not a directory is refused.

`generation-publish`, `request` and `install` call this, and phase P4's pass
calls the same functions on every boot. Read-only: nothing is created,
removed or followed, and refusals carry fixed labels only. This is a check
of the files systemd would read, not of what a running manager has loaded.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat

from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST

from .bootstrap_systemd_profile import _DEBIAN13_V257_UNIT_PATH

__all__ = [
    "UNIT_DIRECTORY",
    "UnitFilesRefused",
    "UnitOverrideRefused",
    "drop_in_directory_names",
    "measure_scoped_unit_files",
    "require_no_unit_overrides",
]

UNIT_DIRECTORY = "/usr/lib/systemd/system"
_SEARCH_PATH = _DEBIAN13_V257_UNIT_PATH
_MASK_TARGET = "/dev/null"
_UNIT_LIMIT = 1 << 20
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
#: Private test seams: the root every fixed path is resolved under and the
#: owner every component must have. Production is `/` and root.
_ROOT = Path("/")
_OWNER = 0

if UNIT_DIRECTORY not in _SEARCH_PATH:  # pragma: no cover - import-time invariant
    raise RuntimeError("the measured unit directory must be on the reviewed search path")


class UnitFilesRefused(Exception):
    """A scoped unit file is missing, unprotected, linked or changed."""


class UnitOverrideRefused(UnitFilesRefused):
    """Another file would change what systemd loads for a scoped unit."""


def _scope(units) -> tuple[str, ...]:
    names = tuple(units)
    if (not names or any(type(name) is not str for name in names)
            or len(set(names)) != len(names)
            or not set(names) <= set(ACTIVATION_UNIT_ALLOWLIST)):
        raise UnitFilesRefused("unit scope refused")
    return names


def drop_in_directory_names(unit: str) -> tuple[str, ...]:
    """Every drop-in directory name systemd consults for `unit`.

    `a-b-c.service` -> `a-b-c.service.d`, `a-.service.d`, `a-b-.service.d`
    and `service.d`.
    """
    stem, _, suffix = unit.rpartition(".")
    parts = stem.split("-")
    names = [unit + ".d"]
    names.extend("-".join(parts[:index]) + "-." + suffix + ".d" for index in range(1, len(parts)))
    names.append(suffix + ".d")
    return tuple(names)


def _directory_ok(fd: int) -> None:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != _OWNER or info.st_mode & 0o022:
        raise UnitFilesRefused("unit directory protection refused")


def _open(path: str, *, required: bool) -> int | None:
    """Walk an absolute fixed path below the root without following links.

    A missing component is `None` unless `required`; a link, a foreign owner
    or a writable component refuses.
    """
    fd = os.open(_ROOT, _DIR)
    try:
        for component in path.strip("/").split("/"):
            _directory_ok(fd)
            try:
                child = os.open(component, _DIR, dir_fd=fd)
            except FileNotFoundError:
                if required:
                    raise UnitFilesRefused("unit directory missing") from None
                os.close(fd)
                return None
            os.close(fd)
            fd = child
        _directory_ok(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _entry(directory_fd: int, name: str):
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _same_name_is_absent_or_mask(directory_fd: int, unit: str) -> None:
    info = _entry(directory_fd, unit)
    if info is None:
        return
    if stat.S_ISLNK(info.st_mode) and os.readlink(unit, dir_fd=directory_fd) == _MASK_TARGET:
        return
    raise UnitOverrideRefused("scoped unit overridden by another unit file")


def _drop_in_is_absent_or_empty(directory_fd: int, name: str) -> None:
    info = _entry(directory_fd, name)
    if info is None:
        return
    if not stat.S_ISDIR(info.st_mode):
        raise UnitOverrideRefused("drop-in entry is not a plain directory")
    fd = os.open(name, _DIR, dir_fd=directory_fd)
    try:
        if os.listdir(fd):
            raise UnitOverrideRefused("scoped unit has a drop-in")
    finally:
        os.close(fd)


def require_no_unit_overrides(units) -> None:
    """Refuse if anything but the vendor unit file would shape a scoped unit."""
    try:
        scope = _scope(units)
        for directory in _SEARCH_PATH:
            fd = _open(directory, required=directory == UNIT_DIRECTORY)
            if fd is None:
                continue
            try:
                for unit in scope:
                    if directory != UNIT_DIRECTORY:
                        _same_name_is_absent_or_mask(fd, unit)
                    for name in drop_in_directory_names(unit):
                        _drop_in_is_absent_or_empty(fd, name)
            finally:
                os.close(fd)
    except UnitFilesRefused:
        raise
    except Exception:  # noqa: BLE001 - unreadable is refused, never "no override"
        raise UnitFilesRefused("unit override check could not complete") from None


def _read(directory_fd: int, unit: str) -> bytes:
    fd = os.open(unit, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != _OWNER or before.st_mode & 0o022
                or not 0 < before.st_size <= _UNIT_LIMIT):
            raise UnitFilesRefused("unit file protection refused")
        data = bytearray()
        while len(data) <= _UNIT_LIMIT:
            part = os.read(fd, min(65536, _UNIT_LIMIT + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        after = os.fstat(fd)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                    after.st_ctime_ns) or len(data) != before.st_size):
            raise UnitFilesRefused("unit file changed while reading")
        return bytes(data)
    finally:
        os.close(fd)


def measure_scoped_unit_files(units) -> dict[str, bytes]:
    """The vendor unit file bytes of each scoped unit, bracketed by override checks.

    Refuses (`UnitOverrideRefused`) when an override or drop-in exists before
    or after the read, and (`UnitFilesRefused`) when a file is missing,
    linked, not root-owned, group/other writable, multiply linked or changing.
    """
    scope = _scope(units)
    require_no_unit_overrides(scope)
    try:
        fd = _open(UNIT_DIRECTORY, required=True)
        try:
            measured = {unit: _read(fd, unit) for unit in scope}
        finally:
            os.close(fd)
    except UnitFilesRefused:
        raise
    except Exception:  # noqa: BLE001 - redacted: labels only
        raise UnitFilesRefused("unit files unavailable") from None
    require_no_unit_overrides(scope)
    return measured
