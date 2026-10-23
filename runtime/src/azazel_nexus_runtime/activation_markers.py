"""Per-boot grant markers: absence withholds, presence grants nothing (#206 P4).

`docs/activation-observe-baseline.md` §5. Masking at the boot pass cannot stop
a start job that systemd queued before the pass ran (VM-confirmed), so every
governed loop unit carries
``ConditionPathExists=/run/azazel-activation/granted/<unit>``. The controller
creates that file only for the units **this** pass granted, after recording
the decision; a unit without its marker is skipped by PID 1
(``unmet condition check``) instead of started.

Why not ``/run/azazel/activation``: ``/run/azazel`` is where units' nested
``RuntimeDirectory=`` leaves (``azazel/mio``, ``azazel/remote``,
``azazel/fetch``) live, and systemd chowns a runtime directory to the
starting unit's account (recursively) and removes it when that unit stops.
When ``/run/azazel`` itself was the shared ``RuntimeDirectory=`` of the
controller and several loop units, a loop daemon would have come to own the
markers and the controller's own exit would have deleted them (that exit
also removed the directory under the loop units' feet: #206 P6, so no unit
declares the bare name any more). Markers stay out of any runtime-directory
tree regardless. ``/run/azazel-activation`` is a separate
root-owned ``0755`` directory created by ``systemd-tmpfiles``
(``packaging/tmpfiles.d/azazel-nexus-bootstrap.conf``), like the M.I.O.
identity handoff, and no unit names it as a runtime directory.

A marker is an empty root-owned ``0644`` file in a root-owned ``0755``
``granted/`` directory that each pass removes first (before any decision)
and recreates only when it grants something. It grants nothing by itself:
the unit must still be unmasked and enabled by the pass, ``/run`` is cleared
at every kernel boot (a soft-reboot keeps it, so the selected bootstrap path
removes the markers too: #251 L-7), and the controller still never starts a
unit.

**The scope files** (#196 G6, `docs/deception-exposure-wiring.md` §5.3).
Beside `granted/`, a pass that granted the Deception Lite exposure tier
writes `decoy-scope.json` (the rendered scope file, the network helper's and
the verify unit's credential) and `decoy-scope.digest` (`sha256:<hex>` and a
newline, the decoy's credential, owner decision Q-D = D2), each root `0600`,
written to a temporary name, fsynced, renamed, the directory fsynced, then
read back. `reset_grant_markers` removes both (and their temporary names)
**before** it removes `granted/`, so a failure while removing the markers
never leaves a scope file behind; a directory or other non-regular object at
any of those names refuses. A pass that withholds the tier therefore leaves
no scope file, and a unit started later in the boot fails at its
`LoadCredential=` (closed).

This module uses the standard library only, so importing it cannot keep
the controller from its mandatory narrowing.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Iterable

__all__ = [
    "DECOY_SCOPE_DIGEST_NAME",
    "DECOY_SCOPE_NAME",
    "EXPOSURE_UNITS",
    "GRANTABLE_UNITS",
    "GRANT_MARKER_DIRECTORY",
    "GrantMarkerRefused",
    "grant_marker_path",
    "read_scope_files",
    "reset_grant_markers",
    "reset_scope_files",
    "write_grant_markers",
    "write_scope_files",
]

#: The only units a pass may grant and mark: the five SUPPORTING loop units
#: (§6.2, phase P4), `azazel-edge-core.service` (EDGE_BASELINE, phase P5),
#: which the library still grants only on launchable, boot-bound Edge
#: evidence, and the three Deception Lite exposure units (DECEPTION_EXPOSURE,
#: #196). The single source for the pass's scope check, its tripwire, this
#: writer and the unit-content and loaded-unit checks (#253).
#:
#: The three exposure units are granted only together, on a verified v3
#: approval and the pass's exposure evidence with every stage held (#196 G6);
#: the pass's tripwire narrows everything for any other exposure grant. #253
#: checks their files and loaded definitions on every pass, granted or not.
GRANTABLE_UNITS = frozenset({
    "azazel-decoy-netd.service",
    "azazel-decoy-nsd.service",
    "azazel-decoyd.service",
    "azazel-edge-core.service",
    "azazel-edge-intaked.service",
    "azazel-edge-probed.service",
    "azazel-incident-explaind.service",
    "azazel-knowledge-lited.service",
    "azazel-mio-entryd.service",
})

#: The Deception Lite exposure units (#196 §10, review n1), marked together
#: or not at all. The same names as `activation.DECEPTION_EXPOSURE_UNITS` (a
#: test compares them); restated because this module imports nothing from
#: the library. systemd counts a unit skipped for a missing marker as a
#: success for the unit that `Requires=` it, so a marker set holding the
#: decoy without the helper, or the helper without the namespace unit, would
#: let a dependent start on a dependency that never ran.
EXPOSURE_UNITS = frozenset({
    "azazel-decoy-netd.service",
    "azazel-decoy-nsd.service",
    "azazel-decoyd.service",
})

#: The fixed marker directory; `hardening.py` renders the same path into
#: each governed loop unit's `ConditionPathExists=`.
GRANT_MARKER_DIRECTORY = "/run/azazel-activation/granted"
_PARENT = ("run", "azazel-activation")
_LEAF = "granted"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_UNIT_LIMIT = 255
#: The owner of the marker directories and files. Private test seam only.
_OWNER = 0

#: The scope files (wiring §5.3), beside `granted/`; `hardening.py` renders
#: `/run/azazel-activation/<name>` into the `LoadCredential=` lines.
DECOY_SCOPE_NAME = "decoy-scope.json"
DECOY_SCOPE_DIGEST_NAME = "decoy-scope.digest"
_SCOPE_NAMES = (DECOY_SCOPE_NAME, DECOY_SCOPE_DIGEST_NAME)
_SCOPE_LIMIT = 4096


class GrantMarkerRefused(Exception):
    """The marker directory is missing, foreign, or holds unexpected entries."""


def grant_marker_path(unit: str) -> str:
    """The `ConditionPathExists=` value for one governed unit."""
    _check_unit(unit)
    return f"{GRANT_MARKER_DIRECTORY}/{unit}"


def _check_unit(unit) -> str:
    if (type(unit) is not str or not 0 < len(unit) <= _UNIT_LIMIT
            or not unit.endswith(".service") or "/" in unit or unit.startswith(".")
            or not all(char.isalnum() or char in "-_.@" for char in unit)):
        raise GrantMarkerRefused("grant marker unit name refused")
    return unit


def _protected_directory(fd: int) -> None:
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != _OWNER
            or info.st_mode & 0o022):
        raise GrantMarkerRefused("grant marker directory protection refused")


def _open_parent(root: Path) -> int | None:
    """`<root>/run/azazel-activation`, without following links; None if absent."""
    try:
        fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except FileNotFoundError:
        return None  # a relocated root that does not exist holds no marker
    try:
        for component in _PARENT:
            try:
                child = os.open(component, _DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                return None
            os.close(fd)
            fd = child
        _protected_directory(fd)
        result, fd = fd, None
        return result
    finally:
        if fd is not None:
            os.close(fd)


def _remove_scope_files_at(parent: int) -> None:
    """Remove the scope files and their temporary names; refuse a non-regular one."""
    failure = None
    for name in _SCOPE_NAMES:
        for entry in (name, f"{name}.tmp"):
            try:
                info = os.stat(entry, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode):
                # Left as it is, and refused after the others are removed.
                failure = GrantMarkerRefused("unexpected object at a decoy scope file name")
                continue
            os.unlink(entry, dir_fd=parent)
    if failure is not None:
        raise failure


def reset_scope_files(root: Path = Path("/")) -> None:
    """Remove the scope files (and temporary names) only (wiring §5.3).

    A missing parent means none can exist. A non-regular object at any of
    the names refuses, after every regular one has been removed.
    """
    parent = _open_parent(root)
    if parent is None:
        return
    try:
        _remove_scope_files_at(parent)
    finally:
        os.close(parent)


def reset_grant_markers(root: Path = Path("/")) -> None:
    """Remove the scope files, then every marker and the `granted/` directory.

    Called before any decision. The scope files go first (wiring §5.3), so a
    failure while removing the markers never leaves one behind. A missing
    parent means no marker can exist. Anything unexpected inside `granted/`
    (a directory), or a non-regular object at a scope file's name, refuses
    rather than being guessed at; the caller treats a refusal as a pass that
    must not proceed.
    """
    parent = _open_parent(root)
    if parent is None:
        return
    try:
        # The scope files first; a refusal there still lets the markers go,
        # and is raised after them.
        try:
            _remove_scope_files_at(parent)
            scope_failure = None
        except GrantMarkerRefused as exc:
            scope_failure = exc
        _remove_markers_at(parent)
        if scope_failure is not None:
            raise scope_failure
    finally:
        os.close(parent)


def _remove_markers_at(parent: int) -> None:
    try:
        info = os.stat(_LEAF, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(info.st_mode):
        os.unlink(_LEAF, dir_fd=parent)
        return
    leaf = os.open(_LEAF, _DIR_FLAGS, dir_fd=parent)
    try:
        for entry in os.scandir(leaf):
            if entry.is_dir(follow_symlinks=False):
                raise GrantMarkerRefused("unexpected directory among grant markers")
            os.unlink(entry.name, dir_fd=leaf)
    finally:
        os.close(leaf)
    os.rmdir(_LEAF, dir_fd=parent)


def write_grant_markers(units: Iterable[str], root: Path = Path("/")) -> tuple[str, ...]:
    """Create `granted/` fresh and one empty marker per unit; nothing else.

    Refuses when the parent directory is absent or foreign, or when
    `granted/` already exists (the pass removes it first, so an existing one
    was created by something else in between).
    """
    names = sorted({_check_unit(unit) for unit in units})
    if not names:
        return ()
    if not set(names) <= GRANTABLE_UNITS:
        raise GrantMarkerRefused("grant marker for a unit no pass grants")
    if set(names) & EXPOSURE_UNITS and not EXPOSURE_UNITS <= set(names):
        raise GrantMarkerRefused(
            "grant markers for part of the Deception Lite exposure tier")
    parent = _open_parent(root)
    if parent is None:
        raise GrantMarkerRefused("grant marker directory unavailable")
    try:
        os.mkdir(_LEAF, 0o755, dir_fd=parent)
        leaf = os.open(_LEAF, _DIR_FLAGS, dir_fd=parent)
        try:
            os.fchmod(leaf, 0o755)
            _protected_directory(leaf)
            for name in names:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                             | os.O_CLOEXEC, 0o644, dir_fd=leaf)
                try:
                    os.fchmod(fd, 0o644)
                finally:
                    os.close(fd)
            present = sorted(entry.name for entry in os.scandir(leaf))
            if present != names:
                raise GrantMarkerRefused("grant markers differ from this pass's grants")
        finally:
            os.close(leaf)
    finally:
        os.close(parent)
    return tuple(names)


def write_scope_files(scope_file: bytes, scope_digest: str,
                      root: Path = Path("/")) -> None:
    """Write `decoy-scope.json` then `decoy-scope.digest`, root `0600` (wiring §5.3).

    The parent must exist, be root's and not group or other writable. Each
    file is created as `<name>.tmp` (`O_EXCL`, no link followed), set to
    `0600` whatever the umask, written, fsynced and renamed; then the
    directory is fsynced. The digest file holds `scope_digest` and a newline.
    Raises on any failure; the caller narrows.
    """
    if (type(scope_file) is not bytes or not 0 < len(scope_file) <= _SCOPE_LIMIT
            or type(scope_digest) is not str or len(scope_digest) != 71
            or not scope_digest.startswith("sha256:")
            or not all(char in "0123456789abcdef" for char in scope_digest[7:])):
        raise GrantMarkerRefused("decoy scope files refused")
    parent = _open_parent(root)
    if parent is None:
        raise GrantMarkerRefused("grant marker directory unavailable")
    try:
        for name, data in ((DECOY_SCOPE_NAME, scope_file),
                           (DECOY_SCOPE_DIGEST_NAME, (scope_digest + "\n").encode("ascii"))):
            temporary = f"{name}.tmp"
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | os.O_CLOEXEC, 0o600, dir_fd=parent)
            try:
                os.fchmod(fd, 0o600)
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def _read_scope_at(parent: int, name: str) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=parent)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != _OWNER
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 0 < info.st_size <= _SCOPE_LIMIT):
            raise GrantMarkerRefused("decoy scope file protection refused")
        data = b""
        while len(data) <= _SCOPE_LIMIT:
            chunk = os.read(fd, _SCOPE_LIMIT + 1 - len(data))
            if not chunk:
                break
            data += chunk
        if len(data) != info.st_size:
            raise GrantMarkerRefused("decoy scope file changed while reading")
        return data
    finally:
        os.close(fd)


def read_scope_files(root: Path = Path("/")) -> tuple[bytes, bytes]:
    """`(decoy-scope.json, decoy-scope.digest)` as written: regular, one link,
    root's, `0600`, bounded, no link followed. Raises otherwise."""
    parent = _open_parent(root)
    if parent is None:
        raise GrantMarkerRefused("grant marker directory unavailable")
    try:
        return (_read_scope_at(parent, DECOY_SCOPE_NAME),
                _read_scope_at(parent, DECOY_SCOPE_DIGEST_NAME))
    finally:
        os.close(parent)
