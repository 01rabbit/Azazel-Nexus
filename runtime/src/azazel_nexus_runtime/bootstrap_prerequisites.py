"""Read-only observation of external prerequisites for the fixed bootstrap pair.

This describes a repeated systemd projection. It is not a start permission,
readiness proof, provenance claim, or a substitute for the enclosing guard.
"""

from dataclasses import dataclass
from hashlib import sha256
import json
import re

from .bootstrap_loaded_policy import LoadedBootstrapPolicy
from .bootstrap_loaded import _dependency_policy
from .bootstrap_masked import _observe_profile
from .bootstrap_stop import BootstrapStopJobs, _validate_expected_owner
from .bootstrap_systemd_profile import bootstrap_systemd_profile_digest
from .systemd_bus import (
    PROPERTIES_INTERFACE,
    UNIT_INTERFACE,
    _unit_object_path,
)
from .units import UNIT_NAMES, UnitKey, UnitOperationFailed

_PAIR = (UnitKey.AUDITD, UnitKey.COMMISSIOND)
_RELATIONS = ("Requires", "Wants", "BindsTo", "Requisite")
_EXCLUDED = frozenset({
    UNIT_NAMES[UnitKey.AUDITD],
    UNIT_NAMES[UnitKey.COMMISSIOND],
    "azazel-activated.service",
})


@dataclass(frozen=True)
class BootstrapPrerequisiteObservation:
    """Immutable repeated observation; carries no permission or readiness claim."""

    owner: str
    policy_digest: str
    units: tuple[str, ...]
    fingerprint: str
    conflicts: tuple[str, ...] = ()


def _prerequisite_names(policy):
    if type(policy) is not LoadedBootstrapPolicy:
        raise ValueError("protected loaded bootstrap policy required")
    units = policy.units
    if set(units) != set(_PAIR):
        raise ValueError("exact protected helper policy required")
    names = set()
    conflicts = set()
    for unit in _PAIR:
        dependencies = units[unit].dependencies
        _dependency_policy(unit, dependencies)
        for relation in _RELATIONS:
            names.update(dependencies[relation])
        for relation in ("Conflicts", "ConflictedBy"):
            conflicts.update(dependencies[relation])
    if conflicts.intersection(names | _EXCLUDED):
        raise ValueError("bootstrap conflicting prerequisite policy refused")
    names.difference_update(_EXCLUDED)
    combined = names | conflicts
    if len(combined) > 64 or any(
        type(name) is not str or not 0 < len(name) <= 256
        or "/" in name or any(char.isspace() for char in name)
        for name in combined
    ):
        raise ValueError("external prerequisite unit set refused")
    return tuple(sorted(names)), tuple(sorted(conflicts))


def _property(properties, key, signature, expected_type):
    if type(properties) is not dict or len(properties) > 2048 or any(
        type(name) is not str for name in properties
    ):
        raise UnitOperationFailed("prerequisite unit properties refused")
    variant = properties.get(key)
    if getattr(variant, "signature", None) != signature:
        raise UnitOperationFailed("prerequisite property signature refused")
    value = getattr(variant, "value", None)
    if type(value) is not expected_type:
        raise UnitOperationFailed("prerequisite property value refused")
    return value


class BootstrapPrerequisiteInspector:
    """Single-use, bounded two-snapshot check of policy-derived external units."""

    def __init__(self, *, bus, message_factory, message_type, timeout_seconds,
                 expected_owner, policy):
        self._owner = _validate_expected_owner(expected_owner)
        if self._owner is None:
            raise ValueError("enclosing systemd unique owner required")
        if type(policy) is not LoadedBootstrapPolicy:
            raise ValueError("protected loaded bootstrap policy required")
        if (type(policy.digest) is not str
                or re.fullmatch(r"sha256:[0-9a-f]{64}", policy.digest) is None):
            raise ValueError("protected policy digest required")
        if (type(policy.systemd_profile_digest) is not str
                or re.fullmatch(
                    r"sha256:[0-9a-f]{64}", policy.systemd_profile_digest
                ) is None):
            raise ValueError("protected systemd profile digest required")
        self._policy = policy
        self._names, self._conflicts = _prerequisite_names(policy)
        self._reader = BootstrapStopJobs(
            bus=bus, message_factory=message_factory, message_type=message_type,
            timeout_seconds=timeout_seconds, expected_owner=self._owner,
        )
        self._used = False

    async def inspect(self) -> BootstrapPrerequisiteObservation:
        if self._used:
            raise UnitOperationFailed("prerequisite inspection requires fresh session")
        self._used = True
        reader = self._reader

        async def snapshot():
            projected = []
            for name in (*self._names, *self._conflicts):
                expected_state = "inactive" if name in self._conflicts else "active"
                path = _unit_object_path(name)
                if await reader._call("GetUnit", "s", [name], "o") != [path]:
                    raise UnitOperationFailed("prerequisite unit object changed")
                body = await reader._call(
                    "GetAll", "s", [UNIT_INTERFACE], "a{sv}",
                    path=path, interface=PROPERTIES_INTERFACE,
                )
                if len(body) != 1:
                    raise UnitOperationFailed("prerequisite unit properties missing")
                props = body[0]
                names = _property(props, "Names", "as", list)
                if (not 1 <= len(names) <= 256
                        or any(type(alias) is not str or not 0 < len(alias) <= 256
                               or "/" in alias or any(char.isspace() for char in alias)
                               for alias in names)
                        or len(set(names)) != len(names) or name not in names):
                    raise UnitOperationFailed("prerequisite unit aliases refused")
                if (_property(props, "Id", "s", str) != name
                        or _property(props, "Following", "s", str) != ""
                        or _property(props, "LoadState", "s", str) != "loaded"
                        or _property(props, "ActiveState", "s", str) != expected_state
                        or _property(props, "NeedDaemonReload", "b", bool) is not False):
                    raise UnitOperationFailed("prerequisite unit state refused")
                job = _property(props, "Job", "(uo)", list)
                if (len(job) != 2 or type(job[0]) is not int or job[0] != 0
                        or type(job[1]) is not str or job[1] != "/"):
                    raise UnitOperationFailed("prerequisite unit job is not idle")
                projected.append((
                    name, path, tuple(sorted(names)), "loaded", expected_state, (0, "/"),
                ))
            return tuple(projected)

        async def operation():
            owner = await reader._owner()
            if owner != self._owner:
                raise UnitOperationFailed("enclosing systemd owner changed")
            reader._manager_owner = owner
            profile = await _observe_profile(reader)
            if bootstrap_systemd_profile_digest(profile) != self._policy.systemd_profile_digest:
                raise UnitOperationFailed("prerequisite systemd profile changed")
            before = await snapshot()

            if (await reader._owner() != owner
                    or await _observe_profile(reader) != profile):
                raise UnitOperationFailed("prerequisite owner/profile changed between snapshots")
            after = await snapshot()
            if before != after:
                raise UnitOperationFailed("prerequisite observation changed")
            final_profile = await _observe_profile(reader)
            if final_profile != profile or await reader._owner() != owner:
                raise UnitOperationFailed("prerequisite observation changed")

            raw = json.dumps(
                {"owner": owner, "policy": self._policy.digest,
                 "units": after}, sort_keys=True, separators=(",", ":"),
            ).encode()
            return BootstrapPrerequisiteObservation(
                owner, self._policy.digest, self._names,
                "sha256:" + sha256(raw).hexdigest(),
                self._conflicts,
            )

        return await reader._bounded(operation())
