"""Read-only observation of the masked auditd/commissiond bootstrap pair.

The observation describes two matching systemd property snapshots. It is not
a start fence, provenance proof, daemon-reload completion, job-quiescence
proof, or evidence of inactivity or empty cgroups. A masked unit may still be
active; masking is not stopping.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import posixpath

from .bootstrap_stop import BootstrapStopJobs, _validate_expected_owner
from .bootstrap_systemd_profile import observe_bootstrap_systemd_profile
from .systemd_bus import UNIT_INTERFACE, PROPERTIES_INTERFACE, _unit_object_path
from .systemd_bus import MANAGER_INTERFACE, MANAGER_PATH
from .units import UNIT_NAMES, UnitKey, UnitOperationFailed

_PAIR = (UnitKey.AUDITD, UnitKey.COMMISSIOND)


@dataclass(frozen=True)
class MaskedBootstrapPair:
    """Immutable identity and fragment-path fingerprint for the fixed pair."""

    owner: str
    fragments: tuple[tuple[UnitKey, str], ...]
    fingerprint: str


def _variant_value(properties, key: str, signature: str, value_type: type):
    variant = properties.get(key)
    if (variant is None or getattr(variant, "signature", None) != signature
            or not hasattr(variant, "value")):
        raise UnitOperationFailed("masked bootstrap property type refused")
    value = variant.value
    if type(value) is not value_type:
        raise UnitOperationFailed("masked bootstrap property value refused")
    return value


def _fragment_path(value) -> str:
    if (type(value) is not str or not value or len(value) > 4096
            or not value.startswith("/") or value == "/" or value.startswith("//")
            or any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in value)
            or posixpath.normpath(value) != value):
        raise UnitOperationFailed("masked bootstrap fragment path refused")
    return value


def _unit_snapshot(unit: UnitKey, properties: dict) -> tuple[UnitKey, str]:
    name = UNIT_NAMES[unit]
    if type(properties) is not dict or len(properties) > 2048:
        raise UnitOperationFailed("masked bootstrap property collection refused")
    if any(type(key) is not str for key in properties):
        raise UnitOperationFailed("masked bootstrap property key refused")
    if _variant_value(properties, "Id", "s", str) != name:
        raise UnitOperationFailed("masked bootstrap unit identity refused")
    names = _variant_value(properties, "Names", "as", list)
    if len(names) != 1 or type(names[0]) is not str or names[0] != name:
        raise UnitOperationFailed("masked bootstrap unit aliases refused")
    if _variant_value(properties, "Following", "s", str) != "":
        raise UnitOperationFailed("masked bootstrap unit alias refused")
    if _variant_value(properties, "LoadState", "s", str) != "masked":
        raise UnitOperationFailed("bootstrap unit is not masked")
    if _variant_value(properties, "NeedDaemonReload", "b", bool) is not False:
        raise UnitOperationFailed("masked bootstrap daemon reload is pending")
    fragment = _variant_value(properties, "FragmentPath", "s", str)
    return unit, _fragment_path(fragment)


async def _observe_profile(reader):
    """Read the compatibility tuple through an already owner-pinned reader."""
    body = await reader._call(
        "GetAll", "s", [MANAGER_INTERFACE], "a{sv}",
        path=MANAGER_PATH, interface=PROPERTIES_INTERFACE,
    )
    if (len(body) != 1 or type(body[0]) is not dict
            or len(body[0]) > 2048
            or any(type(key) is not str for key in body[0])):
        raise UnitOperationFailed("systemd profile properties refused")
    version = _variant_value(body[0], "Version", "s", str)
    unit_path = _variant_value(body[0], "UnitPath", "as", list)
    if any(type(path) is not str for path in unit_path):
        raise UnitOperationFailed("systemd profile path types refused")
    return observe_bootstrap_systemd_profile(version=version, unit_path=unit_path)


class BootstrapMaskedPairInspector:
    """One bounded, read-only, single-use two-snapshot inspection.

    Only GetNameOwner, GetUnit and Properties.GetAll are sent. Matching
    snapshots establish a repeated observation, not atomicity with a later
    start, provenance, reload completion, job quiescence, inactivity, or
    cgroup emptiness. Trusted composition may carry expected_owner from an
    enclosing transaction; a newly discovered owner cannot replace that pin.
    """

    def __init__(self, *, bus, message_factory, message_type, timeout_seconds,
                 expected_owner=None):
        self._expected_owner = _validate_expected_owner(expected_owner)
        self._reader = BootstrapStopJobs(
            bus=bus, message_factory=message_factory, message_type=message_type,
            timeout_seconds=timeout_seconds,
        )
        self._used = False

    async def inspect(self) -> MaskedBootstrapPair:
        if self._used:
            raise UnitOperationFailed("masked pair inspection requires fresh session")
        self._used = True
        reader = self._reader
        units = tuple((unit, UNIT_NAMES[unit], _unit_object_path(UNIT_NAMES[unit]))
                      for unit in _PAIR)

        async def snapshot() -> tuple[tuple[UnitKey, str], ...]:
            fragments = []
            for unit, name, path in units:
                if await reader._call("GetUnit", "s", [name], "o") != [path]:
                    raise UnitOperationFailed("masked bootstrap object changed")
                body = await reader._call(
                    "GetAll", "s", [UNIT_INTERFACE], "a{sv}",
                    path=path, interface=PROPERTIES_INTERFACE,
                )
                if len(body) != 1:
                    raise UnitOperationFailed("masked bootstrap properties missing")
                # Copy primitive strings into a tuple before any further await.
                fragments.append(_unit_snapshot(unit, body[0]))
            return tuple(fragments)

        async def operation() -> MaskedBootstrapPair:
            owner = await reader._owner()
            if self._expected_owner is not None and owner != self._expected_owner:
                raise UnitOperationFailed("enclosing systemd owner changed")
            reader._manager_owner = owner
            observed_profile = await _observe_profile(reader)
            if await reader._owner() != owner:
                raise UnitOperationFailed("systemd owner changed during profile inspection")
            before = await snapshot()
            after = await snapshot()
            final_profile = await _observe_profile(reader)
            if (before != after or final_profile != observed_profile
                    or await reader._owner() != owner):
                raise UnitOperationFailed("masked bootstrap pair changed during inspection")
            encoded = json.dumps(
                {"owner": owner, "fragments": [[unit.value, path]
                                                for unit, path in after]},
                sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
            return MaskedBootstrapPair(
                owner=owner,
                fragments=after,
                fingerprint="sha256:" + hashlib.sha256(encoded).hexdigest(),
            )

        try:
            return await reader._bounded(operation())
        except Exception:
            reader._usable = False
            raise UnitOperationFailed("masked bootstrap observation refused") from None
