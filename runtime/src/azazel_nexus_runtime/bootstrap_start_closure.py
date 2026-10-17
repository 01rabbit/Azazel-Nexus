"""Bounded transitive START-graph rejection, not transaction authorization.

Read effective dependencies, including implicit ones, from fixed roots. Device
follower groups are discovered read-only by shared SysFSPath. Stop propagation
and mount executable effects remain separate admission obligations.
"""

from dataclasses import dataclass
from hashlib import sha256
import json

from .bootstrap_loaded_policy import _ACTIVATION_CHANNELS
from .bootstrap_masked import _observe_profile
from .bootstrap_stop import BootstrapStopJobs, _validate_expected_owner
from .bootstrap_systemd_profile import bootstrap_systemd_profile_digest
from .systemd_bus import PROPERTIES_INTERFACE, UNIT_INTERFACE, _unit_object_path
from .units import UnitOperationFailed

_ROOTS = ("azazel-activated.service", "azazel-auditd.service", "azazel-commissiond.service")
_FORWARD = ("Requires", "Wants", "BindsTo")
_RELATIONS = (*_FORWARD, *sorted(_ACTIVATION_CHANNELS))
_MAX_NODES = 64
_MAX_EDGES = 1024
_MAX_DEVICES = 512
_DEVICE = "org.freedesktop.systemd1.Device"


@dataclass(frozen=True)
class BootstrapStartClosureObservation:
    owner: str
    profile_digest: str
    units: tuple[str, ...]
    fingerprint: str


def _value(properties, key, signature, kind):
    if (type(properties) is not dict or len(properties) > 2048
            or any(type(name) is not str for name in properties)):
        raise UnitOperationFailed("start closure property collection refused")
    variant = properties.get(key)
    value = getattr(variant, "value", None)
    if getattr(variant, "signature", None) != signature or type(value) is not kind:
        raise UnitOperationFailed("start closure property refused")
    return value


def _name(name):
    if (type(name) is not str or not 0 < len(name) <= 256 or not name.isascii()
            or any(char.isspace() or ord(char) < 33 or ord(char) == 127 or char == "/"
                   for char in name)):
        raise UnitOperationFailed("start closure unit name refused")
    if name not in _ROOTS and not name.endswith((".target", ".mount", ".slice", ".device")):
        raise UnitOperationFailed("start closure external activation refused")
    return name


def _names(properties, key):
    names = _value(properties, key, "as", list)
    if (len(names) > 256 or any(
            type(name) is not str or not 0 < len(name) <= 256 or not name.isascii()
            or any(char.isspace() or ord(char) < 33 or ord(char) == 127 or char == "/"
                   for char in name) for name in names)
            or len(set(names)) != len(names)):
        raise UnitOperationFailed("start closure dependency array refused")
    return tuple(sorted(names))


async def _device_inventory(reader):
    reply = await reader._call(
        "ListUnitsByPatterns", "asas", [[], ["*.device"]], "a(ssssssouso)",
    )
    if len(reply) != 1 or type(reply[0]) is not list or len(reply[0]) > _MAX_DEVICES:
        raise UnitOperationFailed("device closure inventory bound or shape refused")
    detached = []
    seen = set()
    paths = set()
    for row in reply[0]:
        if (type(row) is not list or len(row) != 10
                or any(type(row[index]) is not str for index in (*range(7), 8, 9))
                or type(row[7]) is not int or not 0 <= row[7] < 2**32
                or any(len(row[index]) > (4096 if index == 1 else 1024)
                       for index in (*range(7), 8, 9))):
            raise UnitOperationFailed("device closure inventory row refused")
        name, _description, load, state, substate, following, path, job, kind, job_path = row
        _name(name)
        if (not name.endswith(".device") or name in seen or path in paths
                or path != _unit_object_path(name)
                or (job == 0 and (kind != "" or job_path != "/"))
                or (job != 0 and (not kind or job_path != f"/org/freedesktop/systemd1/job/{job}"))):
            raise UnitOperationFailed("device closure inventory identity refused")
        if following:
            _name(following)
            if not following.endswith(".device") or following == name:
                raise UnitOperationFailed("device closure following identity refused")
        seen.add(name)
        paths.add(path)
        detached.append((name, load, state, substate, following, path, job, kind, job_path))
    observed = []
    for row in sorted(detached):
        name, _load, _state, _substate, following, path, *_job = row
        if await reader._call("GetUnit", "s", [name], "o") != [path]:
            raise UnitOperationFailed("device closure inventory object changed")
        props = await reader._call(
            "GetAll", "s", [_DEVICE], "a{sv}",
            path=path, interface=PROPERTIES_INTERFACE,
        )
        if len(props) != 1:
            raise UnitOperationFailed("device closure properties missing")
        sysfs = _value(props[0], "SysFSPath", "s", str)
        if sysfs and (len(sysfs) > 4096 or not sysfs.isascii()
                      or not sysfs.startswith("/sys/")
                      or any(part in {"", ".", ".."} for part in sysfs[1:].split("/"))
                      or any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in sysfs)):
            raise UnitOperationFailed("device closure sysfs identity refused")
        observed.append((*row, sysfs))
    by_name = {row[0]: row for row in observed}
    for row in observed:
        following = row[4]
        if following:
            leader = by_name.get(following)
            if leader is None or not row[-1] or leader[-1] != row[-1] or leader[4]:
                raise UnitOperationFailed("device closure following group refused")
    return tuple(observed)


class BootstrapStartClosureInspector:
    """Read two complete graphs; no mutation, start, job or learned pin.

    LoadUnit is never used in the masked/closed phases and never for external
    units (activated, targets, mounts, slices, devices keep GetUnit). Only when
    the caller opts in with `load_roots`, and only for the published pair
    (azazel-auditd.service / azazel-commissiond.service) after publication and
    Reload, LoadUnit replaces GetUnit as that root's lookup in every snapshot,
    because systemd does not load the unreferenced pair on its own. It is never
    StartUnit and creates no job. By default no LoadUnit is issued.
    """

    def __init__(self, *, bus, message_factory, message_type, timeout_seconds,
                 expected_owner, systemd_profile_digest, load_roots=frozenset()):
        if (type(load_roots) is not frozenset
                or not load_roots <= {"azazel-auditd.service",
                                      "azazel-commissiond.service"}):
            raise ValueError("load_roots may only name the published pair")
        self._load_roots = load_roots
        self._owner = _validate_expected_owner(expected_owner)
        if self._owner is None:
            raise ValueError("retained systemd owner required")
        if (type(systemd_profile_digest) is not str
                or len(systemd_profile_digest) != 71
                or not systemd_profile_digest.startswith("sha256:")
                or any(char not in "0123456789abcdef" for char in systemd_profile_digest[7:])):
            raise ValueError("independent systemd profile digest required")
        self._profile_digest = systemd_profile_digest
        self._reader = BootstrapStopJobs(
            bus=bus, message_factory=message_factory, message_type=message_type,
            timeout_seconds=timeout_seconds, expected_owner=self._owner,
        )
        self._used = False

    async def inspect(self):
        if self._used:
            raise UnitOperationFailed("start closure requires a fresh observation")
        self._used = True
        reader = self._reader

        async def snapshot():
            pending = list(_ROOTS)
            discovered = set(_ROOTS)
            rows = []
            edges = 0
            inventory = None
            while pending:
                name = pending.pop(0)
                path = _unit_object_path(name)
                if name in self._load_roots:
                    await reader._load_pair_unit(name, path)
                elif await reader._call("GetUnit", "s", [name], "o") != [path]:
                    raise UnitOperationFailed("start closure object changed")
                reply = await reader._call(
                    "GetAll", "s", [UNIT_INTERFACE], "a{sv}",
                    path=path, interface=PROPERTIES_INTERFACE,
                )
                if len(reply) != 1:
                    raise UnitOperationFailed("start closure properties missing")
                props = reply[0]
                following = _value(props, "Following", "s", str)
                if not name.endswith(".device") and following:
                    raise UnitOperationFailed("start closure following identity refused")
                aliases = _names(props, "Names")
                if (name not in aliases
                        or any(not alias or len(alias) > 256 or not alias.isascii()
                               or "/" in alias or any(char.isspace() for char in alias)
                               for alias in aliases)
                        or _value(props, "Id", "s", str) != name
                        or _value(props, "LoadState", "s", str) != "loaded"
                        or _value(props, "NeedDaemonReload", "b", bool) is not False):
                    raise UnitOperationFailed("start closure identity differs")
                state = _value(props, "ActiveState", "s", str)
                job = _value(props, "Job", "(uo)", list)
                if (len(job) != 2 or type(job[0]) is not int
                        or not 0 <= job[0] < 2**32 or type(job[1]) is not str
                        or job[1] != (f"/org/freedesktop/systemd1/job/{job[0]}" if job[0] else "/")):
                    raise UnitOperationFailed("start closure job malformed")
                if name in _ROOTS:
                    if (state not in {"inactive", "activating", "active"}
                            or _value(props, "DefaultDependencies", "b", bool) is not False):
                        raise UnitOperationFailed("start closure root policy differs")
                elif state != "active" or job != [0, "/"]:
                    raise UnitOperationFailed("start closure infrastructure not active and idle")
                job = tuple(job)
                relations = tuple((key, _names(props, key)) for key in _RELATIONS)
                if name.endswith(".device"):
                    if inventory is None:
                        inventory = await _device_inventory(reader)
                    records = {row[0]: row for row in inventory}
                    device = records.get(name)
                    if device is None or not device[-1] or following != device[4]:
                        raise UnitOperationFailed("device closure required group unavailable")
                    if (device[1:3] != ("loaded", state)
                            or device[6] != job[0] or device[8] != job[1]):
                        raise UnitOperationFailed("device closure listed state changed")
                    for sibling in inventory:
                        if sibling[-1] == device[-1] and sibling[0] not in discovered:
                            if len(discovered) >= _MAX_NODES:
                                raise UnitOperationFailed("start closure unit bound exceeded")
                            discovered.add(sibling[0])
                            pending.append(sibling[0])
                for key, names in relations:
                    if key in _ACTIVATION_CHANNELS and names:
                        raise UnitOperationFailed("start closure activation channel refused")
                    edges += len(names)
                    if edges > _MAX_EDGES:
                        raise UnitOperationFailed("start closure edge bound exceeded")
                    for child in names:
                        _name(child)
                        if child not in discovered:
                            if len(discovered) >= _MAX_NODES:
                                raise UnitOperationFailed("start closure unit bound exceeded")
                            discovered.add(child)
                            pending.append(child)
                # Detach every accepted primitive before the next bus await.
                rows.append((name, path, aliases, state, tuple(job), relations, following))
            if inventory is not None:
                if await _device_inventory(reader) != inventory:
                    raise UnitOperationFailed("device closure inventory changed")
                # Inventory contains private device identity; retain it only in
                # the transient comparison/hash input, never in the public result.
                return tuple(sorted(rows)), inventory
            return tuple(sorted(rows)), ()

        async def operation():
            if await reader._owner() != self._owner:
                raise UnitOperationFailed("start closure manager owner changed")
            reader._manager_owner = self._owner
            profile = await _observe_profile(reader)
            if bootstrap_systemd_profile_digest(profile) != self._profile_digest:
                raise UnitOperationFailed("start closure systemd profile differs")
            before = await snapshot()
            if (await reader._owner() != self._owner
                    or await _observe_profile(reader) != profile):
                raise UnitOperationFailed("start closure manager changed")
            after = await snapshot()
            if (before != after or await _observe_profile(reader) != profile
                    or await reader._owner() != self._owner):
                raise UnitOperationFailed("start closure graph changed")
            raw = json.dumps(after, separators=(",", ":"), ensure_ascii=True).encode()
            return BootstrapStartClosureObservation(
                self._owner, self._profile_digest, tuple(row[0] for row in after[0]),
                "sha256:" + sha256(raw).hexdigest(),
            )

        return await reader._bounded(operation())
