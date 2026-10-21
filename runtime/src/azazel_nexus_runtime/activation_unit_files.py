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

The bytes are also checked against what the grant marker relies on
(#251 H-1): every measured unit must carry, in `[Unit]` and exactly as
`hardening.render_unit` writes them, `ConditionPathExists=` on its grant
marker, `Requires=azazel-activated.service` and
`After=azazel-activated.service`; and its `Condition*=`, `Assert*=` and
`ExecCondition=` assignments must be exactly the rendered unit's, so none is
added, removed or reset by an empty assignment. A unit file that fails this
is refused like a changed one (`UnitContentRefused`).

`generation-publish`, `request` and `install` call this, and phase P4's pass
calls the same functions on every boot. Read-only: nothing is created,
removed or followed, and refusals carry fixed labels only. This is a check
of the files systemd would read, not of what a running manager has loaded
(`activation_loaded_units` checks that, in the pass).
"""

from __future__ import annotations

import os
from pathlib import Path
import stat

from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST

from .activation_markers import grant_marker_path
from .bootstrap_systemd_profile import _DEBIAN13_V257_UNIT_PATH

__all__ = [
    "CONTROLLER_UNIT",
    "UNIT_DIRECTORY",
    "UnitContentRefused",
    "UnitFilesRefused",
    "UnitOverrideRefused",
    "drop_in_directory_names",
    "measure_scoped_unit_files",
    "rendered_unit",
    "require_governed_unit_content",
    "require_grantable_unit_files",
    "require_no_unit_overrides",
    "required_unit_lines",
]

UNIT_DIRECTORY = "/usr/lib/systemd/system"
#: The controller every grant-marker unit requires and is ordered after.
CONTROLLER_UNIT = "azazel-activated.service"
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


class UnitContentRefused(UnitFilesRefused):
    """A scoped unit file lacks the grant-marker lines or changes a start guard."""


def _is_guard(key: str) -> bool:
    """A directive that gates or guards a start.

    Their set must equal the rendered unit's. An added one could only
    narrow, but an empty assignment resets the whole list, so any difference
    is refused rather than interpreted.
    """
    return key.startswith(("Condition", "Assert")) or key == "ExecCondition"


def _directives(text: str) -> list[tuple[str, str, str, str]]:
    """`(section, key, value, raw line)` for every assignment.

    Deliberately narrower than systemd's parser: a continued line (trailing
    backslash), a line that is neither blank, a comment, a section header
    nor an assignment, and an assignment before any section are refused
    rather than interpreted. The rendered units contain none of these.
    """
    section = None
    result = []
    for raw in text.split("\n"):
        # Only space and tab: `_decode` admits no other whitespace, so
        # Python and systemd cannot disagree on where a line starts.
        line = raw.strip(" \t")
        if line.endswith("\\"):
            raise UnitContentRefused("unit file line continuation refused")
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        key, separator, value = line.partition("=")
        if not separator or section is None or not key.strip():
            raise UnitContentRefused("unit file syntax refused")
        result.append((section, key.strip(), value.strip(), raw))
    return result


def _decode(data: bytes) -> str:
    """Printable ASCII, tab and newline only.

    Anything else -- a BOM, NUL, CR, another ASCII control character, or any
    non-ASCII character, Unicode whitespace included -- is refused, so that
    no character is read one way here and another way by systemd. The
    rendered units are plain ASCII.
    """
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise UnitContentRefused("unit file encoding refused") from None
    if any(not (" " <= char <= "~" or char in "\t\n") for char in text):
        raise UnitContentRefused("unit file encoding refused")
    return text


def rendered_unit(unit: str) -> str:
    """`hardening.render_unit` for one governed unit: the expected file."""
    from .hardening import PROFILES, render_unit

    for profile in PROFILES:
        if profile.unit == unit:
            return render_unit(profile)
    raise UnitContentRefused("unit has no rendered declaration")


def _guards(directives) -> list[tuple[str, str, str]]:
    return sorted((section, key, value) for section, key, value, _ in directives
                  if _is_guard(key))


def required_unit_lines(unit: str) -> tuple[str, str, str]:
    """The three `[Unit]` lines the grant marker's safety depends on (§5)."""
    return (f"ConditionPathExists={grant_marker_path(unit)}",
            f"Requires={CONTROLLER_UNIT}", f"After={CONTROLLER_UNIT}")


def require_governed_unit_content(unit: str, data: bytes) -> None:
    """Refuse a scoped unit file that would not wait for this boot's grant.

    Required, each as an exact line in `[Unit]`: `ConditionPathExists=` on
    the unit's grant marker, `Requires=` and `After=` on the controller. The
    `Condition*=`, `Assert*=` and `ExecCondition=` assignments, in every
    section, must be exactly those of `hardening.render_unit` for the unit,
    and no `[Unit]` assignment may be empty (a reset). Fixed labels only.
    """
    if (type(unit) is not str or unit not in ACTIVATION_UNIT_ALLOWLIST
            or type(data) is not bytes):
        raise UnitContentRefused("unit scope refused")
    directives = _directives(_decode(data))
    expected = _directives(rendered_unit(unit))
    unit_lines = {raw for section, _, _, raw in directives if section == "Unit"}
    if not set(required_unit_lines(unit)) <= unit_lines:
        raise UnitContentRefused("unit file lacks the grant-marker lines")
    if any(section == "Unit" and not value for section, _, value, _ in directives):
        raise UnitContentRefused("unit file resets a [Unit] setting")
    if _guards(directives) != _guards(expected):
        raise UnitContentRefused("unit file start guards differ from the declaration")


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
    or after the read, (`UnitContentRefused`) when a file lacks the
    grant-marker lines or its start guards differ from the declaration, and
    (`UnitFilesRefused`) when a file is missing, linked, not root-owned,
    group/other writable, multiply linked or changing.
    """
    scope = _scope(units)
    require_no_unit_overrides(scope)
    try:
        fd = _open(UNIT_DIRECTORY, required=True)
        try:
            measured = {unit: _read(fd, unit) for unit in scope}
        finally:
            os.close(fd)
        for unit, data in measured.items():
            require_governed_unit_content(unit, data)
    except UnitFilesRefused:
        raise
    except Exception:  # noqa: BLE001 - redacted: labels only
        raise UnitFilesRefused("unit files unavailable") from None
    require_no_unit_overrides(scope)
    return measured


def require_grantable_unit_files(units) -> None:
    """The same checks over every grantable unit, policy or not (#251 H-1).

    A unit outside this pass's policy is never granted, but if it is enabled
    with a start job queued, READY would release it unless it waits for its
    marker. So every grantable unit's vendor file must pass
    `require_governed_unit_content` and have no override or drop-in. A
    vendor file that does not exist is accepted for a unit outside the
    policy scope: systemd has no definition to start (the scope itself is
    measured by `measure_scoped_unit_files`, where a missing file refuses).
    """
    scope = _scope(units)
    require_no_unit_overrides(scope)
    try:
        fd = _open(UNIT_DIRECTORY, required=True)
        try:
            for unit in scope:
                if _entry(fd, unit) is None:
                    continue
                require_governed_unit_content(unit, _read(fd, unit))
        finally:
            os.close(fd)
    except UnitFilesRefused:
        raise
    except Exception:  # noqa: BLE001 - redacted: labels only
        raise UnitFilesRefused("unit files unavailable") from None
    require_no_unit_overrides(scope)
