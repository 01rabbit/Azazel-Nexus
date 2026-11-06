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

This module uses the standard library only, so importing it cannot keep
the controller from its mandatory narrowing.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Iterable

__all__ = [
    "EXPOSURE_UNITS",
    "GRANTABLE_UNITS",
    "NON_GRANTABLE_MARKER_UNITS",
    "MARKER_GUARDED_UNITS",
    "GRANT_MARKER_DIRECTORY",
    "GrantMarkerRefused",
    "grant_marker_path",
    "reset_grant_markers",
    "write_grant_markers",
]

#: The only units a pass may grant and mark: the SUPPORTING loop units
#: (§6.2, phase P4; the loop's audit writer `azazel-auditd-loop.service`
#: since ADR 0008), `azazel-edge-core.service` (EDGE_BASELINE, phase P5),
#: which the library still grants only on launchable, boot-bound Edge
#: evidence, and the three Deception Lite exposure units (DECEPTION_EXPOSURE,
#: #196). The single source for the pass's scope check, its tripwire, this
#: writer and the unit-content and loaded-unit checks (#253).
#:
#: The three exposure units are here so that #253 checks their files and
#: loaded definitions on every pass (a queued start must wait for its
#: marker), not so that a pass can grant them: no activation policy may name
#: them (`activation_policy.ACTIVATION_UNIT_ALLOWLIST`), the library withholds
#: their tier in this build (`isolation_evidence_absent`), and the pass's
#: tripwire narrows everything if any of them is ever granted.
GRANTABLE_UNITS = frozenset({
    "azazel-auditd-loop.service",
    "azazel-decoy-netd.service",
    "azazel-decoy-nsd.service",
    "azazel-decoyd.service",
    "azazel-edge-core.service",
    "azazel-edge-intaked.service",
    "azazel-edge-probed.service",
    "azazel-incident-explaind.service",
    "azazel-knowledge-lited.service",
    "azazel-mio-entryd.service",
    "azazel-mio-referenced.service",
})

#: Unit files in this set remain guarded by per-boot grant markers so that a
#: queued/manual systemd start cannot bypass the activation controller. They
#: are deliberately outside GRANTABLE_UNITS and the activation policy until
#: the dedicated Knowledge commissioning loader and policy review exist.
NON_GRANTABLE_MARKER_UNITS = frozenset({
    # The unit needs the start guard but no pass may mint this marker until
    # the dedicated commissioning loader and policy review exist.
    "azazel-knowledge-contextd.service",
})

#: Units whose files and loaded systemd definitions must be checked for the
#: per-boot marker guard. This includes units the pass can never grant.
MARKER_GUARDED_UNITS = GRANTABLE_UNITS | NON_GRANTABLE_MARKER_UNITS

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


def reset_grant_markers(root: Path = Path("/")) -> None:
    """Remove every marker and the `granted/` directory; called before any decision.

    A missing parent means no marker can exist. Anything unexpected inside
    `granted/` (a directory) refuses rather than being guessed at; the
    caller treats a refusal as a pass that must not proceed.
    """
    parent = _open_parent(root)
    if parent is None:
        return
    try:
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
    finally:
        os.close(parent)


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
