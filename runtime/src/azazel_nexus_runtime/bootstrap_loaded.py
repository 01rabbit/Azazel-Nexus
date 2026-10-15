"""Read-only loaded-unit observations for the bootstrap overlay prototype.

This is NOT semantic admission, complete hardening verification or a start token.
The independent expected dependency graph, file/package measurements, deadline,
health and persistent/volatile fence proofs remain composition prerequisites.
"""

from dataclasses import dataclass
import hashlib
import json

from .bootstrap_stop import BootstrapStopJobs
from .hardening import PROFILES
from .launch_environment import BOOTSTRAP_UNSET_ENVIRONMENT
from .systemd_bus import PROPERTIES_INTERFACE, UNIT_INTERFACE, _unit_object_path
from .units import UNIT_NAMES, UnitKey, UnitOperationFailed

_SERVICE = "org.freedesktop.systemd1.Service"
_CONTROLLER = "azazel-activated.service"
_PAIR = (UnitKey.AUDITD, UnitKey.COMMISSIOND)
_DEPENDENCIES = (
    "After", "Before", "Requires", "Wants", "BindsTo", "Requisite", "Upholds",
    "PartOf", "Conflicts", "ConflictedBy", "OnFailure", "OnSuccess", "Triggers",
    "TriggeredBy", "PropagatesStopTo", "StopPropagatedFrom", "JoinsNamespaceOf",
    "RequiredBy", "RequisiteOf", "WantedBy", "BoundBy", "UpheldBy", "ConsistsOf",
    "OnSuccessOf", "OnFailureOf", "PropagatesReloadTo", "ReloadPropagatedFrom",
)
_COMMANDS = (
    "ExecConditionEx", "ExecStartPreEx", "ExecStartPostEx", "ExecReloadEx",
    "ExecStopEx", "ExecStopPostEx",
)
_EXEC_SIGNATURE = "a(sasasttttuii)"
_TIMERS = ("TimeoutStartUSec", "TimeoutStopUSec", "RuntimeMaxUSec", "WatchdogUSec")
_SERVICE_EXPECTED = {
    "Type": ("s", "notify"), "NotifyAccess": ("s", "main"),
    "Restart": ("s", "no"), "RemainAfterExit": ("b", False),
    "KillMode": ("s", "control-group"), "SendSIGKILL": ("b", True),
    "TimeoutStartFailureMode": ("s", "kill"),
    "TimeoutStopFailureMode": ("s", "kill"),
    "FinalKillSignal": ("i", 9),
    "KillSignal": ("i", 15),
    "ExitType": ("s", "main"), "DynamicUser": ("b", False),
    "Group": ("s", ""), "Environment": ("as", []),
    "EnvironmentFiles": ("a(sb)", []), "PassEnvironment": ("as", []),
    "UnsetEnvironment": ("as", list(BOOTSTRAP_UNSET_ENVIRONMENT)),
    "PAMName": ("s", ""), "SupplementaryGroups": ("as", []),
    "RootDirectory": ("s", ""), "RootImage": ("s", ""),
}


@dataclass(frozen=True)
class LoadedBootstrapUnit:
    """Fingerprint of the checked property projection, not the entire unit."""

    unit: UnitKey
    owner: str
    fingerprint: str


def _value(properties, key, signature):
    variant = properties.get(key)
    if getattr(variant, "signature", None) != signature:
        raise UnitOperationFailed("loaded bootstrap property unavailable")
    return variant.value


def _expected(properties, key, signature, value):
    observed = _value(properties, key, signature)
    if type(observed) is not type(value) or observed != value:
        raise UnitOperationFailed("loaded bootstrap property mismatch")
    return observed


def _dependency_policy(unit, value):
    if type(value) is not dict or set(value) != set(_DEPENDENCIES):
        raise UnitOperationFailed("independent complete dependency projection required")
    frozen = {}
    for key, names in value.items():
        allowed = {_CONTROLLER}
        if unit is UnitKey.COMMISSIOND and key in {"After", "Requires", "BindsTo"}:
            allowed.add(UNIT_NAMES[UnitKey.AUDITD])
        if unit is UnitKey.AUDITD and key in {"Before", "RequiredBy", "BoundBy"}:
            allowed.add(UNIT_NAMES[UnitKey.COMMISSIOND])
        if type(names) is not frozenset or len(names) > 256 or any(
            type(name) is not str or not 0 < len(name) <= 256
            or "/" in name or any(char.isspace() for char in name)
            or (name.startswith("azazel-") and name not in allowed)
            for name in names
        ):
            raise UnitOperationFailed("bootstrap dependency policy refused")
        frozen[key] = sorted(names)
    required = {_CONTROLLER}
    if unit is UnitKey.COMMISSIOND:
        required.add(UNIT_NAMES[UnitKey.AUDITD])
    if (frozen["BindsTo"] != sorted(required)
            or not required.issubset(frozen["After"])
            or not required.issubset(frozen["Requires"])):
        raise UnitOperationFailed("controller/audit lifetime dependencies required")
    positive = set().union(*(value[key] for key in ("Requires", "Wants", "BindsTo")))
    if not positive.issubset(value["After"]):
        raise UnitOperationFailed("bootstrap positive dependencies must be ordered before helper")
    return frozen


def _service_policy(settings):
    if type(settings) is not dict or set(settings) != {*_TIMERS, "SetLoginEnvironment"}:
        raise UnitOperationFailed("independent service timing/environment policy required")
    expected = {}
    for key in _TIMERS:
        value = settings[key]
        if type(value) is not int or not 0 <= value < 2**64:
            raise UnitOperationFailed("service timer policy malformed")
        ceiling = {"TimeoutStartUSec": 30_000_000, "TimeoutStopUSec": 10_000_000}.get(key)
        if ceiling is not None and not 0 < value <= ceiling:
            raise UnitOperationFailed("finite bounded service start/stop policy required")
        expected[key] = ("t", value)
    if type(settings["SetLoginEnvironment"]) is not bool or settings["SetLoginEnvironment"] is not False:
        raise UnitOperationFailed("login environment policy malformed")
    expected["SetLoginEnvironment"] = ("b", settings["SetLoginEnvironment"])
    return expected


def _projection(unit, unit_properties, service_properties, dependencies, service_settings):
    name = UNIT_NAMES[unit]
    profile = next(item for item in PROFILES if item.unit == name)
    unit_expected = {
        "Id": ("s", name), "Names": ("as", [name]),
        "Following": ("s", ""), "LoadState": ("s", "loaded"),
        "DefaultDependencies": ("b", False),
        "FragmentPath": ("s", f"/run/systemd/system.control/{name}"),
        "SourcePath": ("s", ""), "DropInPaths": ("as", []),
        "NeedDaemonReload": ("b", False),
    }
    values = {
        key: _expected(unit_properties, key, *spec)
        for key, spec in unit_expected.items()
    }
    for key, names in dependencies.items():
        observed = _value(unit_properties, key, "as")
        if (type(observed) is not list or len(observed) > 256
                or any(type(item) is not str for item in observed)
                or len(set(observed)) != len(observed) or sorted(observed) != names):
            raise UnitOperationFailed("loaded bootstrap dependencies differ")
        values[key] = sorted(observed)
    service_expected = dict(_SERVICE_EXPECTED)
    service_expected.update(service_settings)
    service_expected["User"] = ("s", profile.account)
    service_expected.update({key: (_EXEC_SIGNATURE, []) for key in _COMMANDS})
    service = {
        key: _expected(service_properties, key, *spec)
        for key, spec in service_expected.items()
    }
    commands = _value(service_properties, "ExecStartEx", _EXEC_SIGNATURE)
    if type(commands) is not list or len(commands) != 1:
        raise UnitOperationFailed("single fixed bootstrap command required")
    command = commands[0]
    if (type(command) is not list or len(command) != 10
            or type(command[0]) is not str or command[0] != profile.executable
            or command[1] != [profile.executable] or type(command[1]) is not list
            or type(command[2]) is not list or command[2] != []):
        raise UnitOperationFailed("bootstrap executable, arguments or flags changed")
    for index, value in enumerate(command[3:], start=3):
        lower, upper = (0, 2**64) if index < 7 else (
            (0, 2**32) if index == 7 else (-2**31, 2**31)
        )
        if type(value) is not int or not lower <= value < upper:
            raise UnitOperationFailed("bootstrap execution metadata malformed")
    service["ExecStartEx"] = commands
    # Capture bytes now; do not retain mutable Variant values across awaits.
    return json.dumps({"unit": values, "service": service},
                      sort_keys=True, separators=(",", ":")).encode()


class BootstrapLoadedUnitInspector:
    """One observation on an already-owned dedicated system-bus connection.

    Only GetNameOwner, GetUnit and Properties.GetAll are issued; with the
    opt-in `load_first` (published pair after Reload, pinned owner) every
    snapshot uses LoadUnit instead of GetUnit as the lookup (no job, no start). Two identical
    projected snapshots and stable owner/path are required; this is not atomic
    with a later Start and does not validate the transitive graph or bytes on
    disk. Expected edges must come from independent semantic admission, not
    copied from the observed properties or an untrusted candidate.
    """

    def __init__(self, *, bus, message_factory, message_type, timeout_seconds,
                 expected_service_settings, expected_owner=None, load_first=False):
        if type(load_first) is not bool or (load_first and expected_owner is None):
            raise ValueError("load_first requires a bool flag and a pinned owner")
        self._load_first = load_first
        # Snapshot independent values before any awaits; never learn policy
        # from the manager's observed values. Start/stop pins must be positive
        # and within the shipped ceiling. This is not proof that a native kill
        # completed, nor a suspend-inclusive approval lifetime bound.
        self._service_settings = _service_policy(expected_service_settings)
        self._reader = BootstrapStopJobs(
            bus=bus, message_factory=message_factory, message_type=message_type,
            timeout_seconds=timeout_seconds,
            expected_owner=expected_owner,
        )
        self._used = False

    async def inspect(self, unit: UnitKey, *, expected_dependencies):
        if type(unit) is not UnitKey or unit not in _PAIR:
            raise UnitOperationFailed("loaded-unit inspection outside exact pair")
        dependencies = _dependency_policy(unit, expected_dependencies)
        if self._used:
            raise UnitOperationFailed("loaded-unit inspection requires fresh session")
        self._used = True
        reader = self._reader
        name, path = UNIT_NAMES[unit], _unit_object_path(UNIT_NAMES[unit])

        async def snapshot():
            if self._load_first:
                await reader._load_pair_unit(name, path)
            elif await reader._call("GetUnit", "s", [name], "o") != [path]:
                raise UnitOperationFailed("loaded bootstrap object changed")
            result = []
            for interface in (UNIT_INTERFACE, _SERVICE):
                body = await reader._call("GetAll", "s", [interface], "a{sv}",
                                          path=path, interface=PROPERTIES_INTERFACE)
                if (len(body) != 1 or type(body[0]) is not dict or len(body[0]) > 2048
                        or any(type(key) is not str for key in body[0])):
                    raise UnitOperationFailed("loaded property collection refused")
                result.append(body[0])
            return _projection(unit, *result, dependencies, self._service_settings)

        async def operation():
            owner = await reader._owner()
            if reader._expected_owner is not None and owner != reader._expected_owner:
                raise UnitOperationFailed("enclosing systemd owner changed before loaded inspection")
            reader._manager_owner = owner
            before = await snapshot()
            if await reader._owner() != owner:
                raise UnitOperationFailed("systemd owner changed during inspection")
            after = await snapshot()
            if before != after or await reader._owner() != owner:
                raise UnitOperationFailed("loaded unit changed during inspection")
            return LoadedBootstrapUnit(unit, owner, "sha256:" + hashlib.sha256(after).hexdigest())

        try:
            return await reader._bounded(operation())
        except Exception:
            reader._usable = False
            raise UnitOperationFailed("loaded bootstrap observation refused") from None
