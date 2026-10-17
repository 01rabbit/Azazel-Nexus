"""Two-snapshot systemd identity observation for the bootstrap controller."""

from dataclasses import dataclass
from hashlib import sha256
import json
import re

from .bootstrap_loaded import _COMMANDS, _EXEC_SIGNATURE
from .bootstrap_masked import _observe_profile
from .bootstrap_stop import BootstrapStopJobs, _validate_expected_owner
from .bootstrap_systemd_profile import bootstrap_systemd_profile_digest
from .hardening import PROFILES
from .launch_environment import BOOTSTRAP_UNSET_ENVIRONMENT
from .systemd_bus import (
    PROPERTIES_INTERFACE,
    UNIT_INTERFACE,
    _unit_object_path,
)
from .units import UnitOperationFailed

_UNIT = "azazel-activated.service"
_SERVICE = "org.freedesktop.systemd1.Service"
_CONTROLLER_PROFILE = next(profile for profile in PROFILES if profile.unit == _UNIT)
_CONTROL_GROUP = "/system.slice/azazel-activated.service"
#: CAP_DAC_READ_SEARCH is capability number 2, so the exact bounding mask is
#: 1 << 2. Derived from the generated profile's declaration, never "any".
_CAPABILITY_NUMBERS = {"CAP_DAC_READ_SEARCH": 2}
_BOUNDING_MASK = 0
for _name in _CONTROLLER_PROFILE.capability_bounding_set:
    _BOUNDING_MASK |= 1 << _CAPABILITY_NUMBERS[_name]
if _BOUNDING_MASK != 0x4:
    raise RuntimeError("controller bounding set must be exactly CAP_DAC_READ_SEARCH")
if _CONTROLLER_PROFILE.supplementary_groups != ("azazel-operator",):
    raise RuntimeError("controller supplementary group must be exactly azazel-operator")
_ONCE_PATH = "/run/azazel-nexus-bootstrap/controller-used"
_SERVICE_VALUES = {
    "ControlPID": ("u", 0),
    "User": ("s", "root"),
    "Type": ("s", "notify"),
    "NotifyAccess": ("s", "main"),
    "Restart": ("s", "no"),
    "KillMode": ("s", "control-group"),
    "SendSIGKILL": ("b", True),
    "ExitType": ("s", "main"),
    "RemainAfterExit": ("b", False),
    "WatchdogUSec": ("t", 30_000_000),
    "WatchdogSignal": ("i", 9),
    "TimeoutStartUSec": ("t", 30_000_000),
    "TimeoutStopUSec": ("t", 10_000_000),
    "TimeoutStartFailureMode": ("s", "kill"),
    "TimeoutStopFailureMode": ("s", "kill"),
    "FinalKillSignal": ("i", 9),
    "KillSignal": ("i", 15),
    "Environment": ("as", []),
    "EnvironmentFiles": ("a(sb)", []),
    "PassEnvironment": ("as", []),
    "UnsetEnvironment": ("as", list(BOOTSTRAP_UNSET_ENVIRONMENT)),
    "SetLoginEnvironment": ("b", False),
    "PAMName": ("s", ""),
    "SupplementaryGroups": ("as", ["azazel-operator"]),
    "CapabilityBoundingSet": ("t", _BOUNDING_MASK),
    "AmbientCapabilities": ("t", 0),
}


class BootstrapControllerNotReady(UnitOperationFailed):
    """Identity checked, but READY acknowledgement is not yet stable."""


@dataclass(frozen=True)
class BootstrapControllerIdentity:
    pid: int
    invocation_id: bytes
    control_group: str = _CONTROL_GROUP

    def __post_init__(self):
        if type(self.pid) is not int or not 0 < self.pid < 2**32:
            raise ValueError("controller PID must be a positive uint32")
        if (type(self.invocation_id) is not bytes or len(self.invocation_id) != 16
                or not any(self.invocation_id)):
            raise ValueError("controller invocation ID must be 16 nonzero bytes")
        if type(self.control_group) is not str or self.control_group != _CONTROL_GROUP:
            raise ValueError("fixed controller cgroup required")


@dataclass(frozen=True)
class BootstrapControllerObservation:
    identity: BootstrapControllerIdentity
    owner: str
    phase: str
    fingerprint: str


def _value(properties, key, signature, expected_type):
    if (type(properties) is not dict or len(properties) > 2048
            or any(type(name) is not str for name in properties)):
        raise UnitOperationFailed("controller property collection refused")
    variant = properties.get(key)
    if getattr(variant, "signature", None) != signature:
        raise UnitOperationFailed("controller property signature refused")
    value = getattr(variant, "value", None)
    if type(value) is not expected_type:
        raise UnitOperationFailed("controller property value refused")
    return value


def _unit_projection(properties, identity, phase):
    conditions = _value(properties, "Conditions", "a(sbbsi)", list)
    if (len(conditions) != 1 or type(conditions[0]) is not list
            or len(conditions[0]) != 5
            or any(type(value) is not kind for value, kind in zip(
                conditions[0], (str, bool, bool, str, int), strict=True))
            or conditions[0][:4] != ["ConditionPathExists", False, True, _ONCE_PATH]
            or conditions[0][4] not in (0, 1)
            or _value(properties, "ConditionResult", "b", bool) is not True):
        raise UnitOperationFailed("controller one-use start condition refused")
    allowed_states = {("activating", "start")}
    if phase == "ready":
        allowed_states.add(("active", "running"))
    values = {
        "Id": _value(properties, "Id", "s", str),
        "Names": _value(properties, "Names", "as", list),
        "Following": _value(properties, "Following", "s", str),
        "LoadState": _value(properties, "LoadState", "s", str),
        "DefaultDependencies": _value(properties, "DefaultDependencies", "b", bool),
        "NeedDaemonReload": _value(properties, "NeedDaemonReload", "b", bool),
        "InvocationID": _value(properties, "InvocationID", "ay", bytes),
        "ActiveState": _value(properties, "ActiveState", "s", str),
        "SubState": _value(properties, "SubState", "s", str),
        "Job": _value(properties, "Job", "(uo)", list),
    }
    names = values["Names"]
    if (not 1 <= len(names) <= 256
            or any(type(name) is not str or not 0 < len(name) <= 256
                   or "/" in name or any(char.isspace() for char in name)
                   for name in names)
            or len(set(names)) != len(names) or _UNIT not in names
            or values["Id"] != _UNIT
            or values["Following"] != "" or values["LoadState"] != "loaded"
            or values["DefaultDependencies"] is not False
            or values["NeedDaemonReload"] is not False
            or values["InvocationID"] != identity.invocation_id
            or (values["ActiveState"], values["SubState"]) not in allowed_states):
        raise UnitOperationFailed("controller unit phase or identity refused")
    job = values["Job"]
    if values["ActiveState"] == "activating" or (len(job) == 2 and job[0] != 0):
        if (len(job) != 2 or type(job[0]) is not int
                or not 0 < job[0] < 2**32 or type(job[1]) is not str
                or job[1] != f"/org/freedesktop/systemd1/job/{job[0]}"):
            raise UnitOperationFailed("controller start job identity refused")
    elif (len(job) != 2 or type(job[0]) is not int or job[0] != 0
          or type(job[1]) is not str or job[1] != "/"):
        raise UnitOperationFailed("controller job is not idle")
    values["Names"] = sorted(names)
    values["InvocationID"] = values["InvocationID"].hex()
    values["Job"] = [job[0], job[1]]
    # The per-condition state is 0 after any daemon-reload and 1 before one;
    # it is not part of the identity, so it is not projected.
    values["Conditions"] = [list(conditions[0][:4])]
    values["ConditionResult"] = True
    return values


def _service_projection(properties, identity):
    expected = dict(_SERVICE_VALUES)
    expected.update({"MainPID": ("u", identity.pid),
                     "ControlGroup": ("s", identity.control_group)})
    values = {}
    for key, (signature, value) in expected.items():
        observed = _value(properties, key, signature, type(value))
        if observed != value:
            raise UnitOperationFailed("controller service identity differs")
        # These arrays contain only fixed strings (or are required empty).
        # Detach now, before a later awaited reply can mutate their source.
        values[key] = observed.copy() if type(observed) is list else observed

    commands = _value(properties, "ExecStartEx", _EXEC_SIGNATURE, list)
    if type(commands) is not list or len(commands) != 1:
        raise UnitOperationFailed("controller fixed ExecStartEx required")
    command = commands[0]
    executable = _CONTROLLER_PROFILE.executable
    if (type(command) is not list or len(command) != 10
            or type(command[0]) is not str or command[0] != executable
            or type(command[1]) is not list or len(command[1]) != 1
            or type(command[1][0]) is not str or command[1][0] != executable
            or type(command[2]) is not list or command[2] != []):
        raise UnitOperationFailed("controller executable or arguments changed")
    for index, value in enumerate(command[3:], start=3):
        lower, upper = (0, 2**64) if index < 7 else (
            (0, 2**32) if index == 7 else (-2**31, 2**31)
        )
        if type(value) is not int or not lower <= value < upper:
            raise UnitOperationFailed("controller execution metadata malformed")
    values["ExecStartEx"] = [[executable, [executable], [], *command[3:]]]

    for key in _COMMANDS:
        signature = _EXEC_SIGNATURE
        if _value(properties, key, signature, list) != []:
            raise UnitOperationFailed("additional controller command refused")
        values[key] = []
    return values


class BootstrapControllerInspector:
    """Bounded, single-use repeated controller identity/phase observation."""

    def __init__(self, *, bus, message_factory, message_type, timeout_seconds,
                 expected_owner, systemd_profile_digest, identity, phase):
        self._owner = _validate_expected_owner(expected_owner)
        if self._owner is None:
            raise ValueError("enclosing systemd unique owner required")
        if (type(systemd_profile_digest) is not str
                or re.fullmatch(r"sha256:[0-9a-f]{64}", systemd_profile_digest) is None):
            raise ValueError("pinned systemd profile digest required")
        if type(identity) is not BootstrapControllerIdentity:
            raise ValueError("frozen controller identity required")
        if type(phase) is not str or phase not in {"pre-ready", "ready"}:
            raise ValueError("fixed controller observation phase required")
        self._profile_digest = systemd_profile_digest
        self._identity = identity
        self._phase = phase
        self._reader = BootstrapStopJobs(
            bus=bus, message_factory=message_factory, message_type=message_type,
            timeout_seconds=timeout_seconds, expected_owner=self._owner,
        )
        self._used = False

    async def inspect(self) -> BootstrapControllerObservation:
        if self._used:
            raise UnitOperationFailed("controller inspection requires a fresh session")
        self._used = True
        reader = self._reader
        path = _unit_object_path(_UNIT)

        async def snapshot():
            if await reader._call("GetUnit", "s", [_UNIT], "o") != [path]:
                raise UnitOperationFailed("controller unit object changed")
            unit_body = await reader._call(
                "GetAll", "s", [UNIT_INTERFACE], "a{sv}",
                path=path, interface=PROPERTIES_INTERFACE,
            )
            if len(unit_body) != 1:
                raise UnitOperationFailed("controller unit property reply shape refused")
            # Validate and detach Unit values before awaiting Service; a fake
            # or transport may retain and mutate the original reply object.
            unit = _unit_projection(unit_body[0], self._identity, self._phase)
            service_body = await reader._call(
                "GetAll", "s", [_SERVICE], "a{sv}",
                path=path, interface=PROPERTIES_INTERFACE,
            )
            if len(service_body) != 1:
                raise UnitOperationFailed("controller service property reply shape refused")
            service = _service_projection(service_body[0], self._identity)
            return {"unit": unit, "service": service}

        async def operation():
            owner = await reader._owner()
            if owner != self._owner:
                raise UnitOperationFailed("enclosing systemd owner changed")
            reader._manager_owner = owner
            profile = await _observe_profile(reader)
            if bootstrap_systemd_profile_digest(profile) != self._profile_digest:
                raise UnitOperationFailed("controller systemd profile changed")
            before = await snapshot()
            if (await reader._owner() != owner
                    or await _observe_profile(reader) != profile):
                raise UnitOperationFailed("controller owner/profile changed between snapshots")
            after = await snapshot()
            pending = self._phase == "ready" and any(
                sample["unit"]["ActiveState"] != "active" or sample["unit"]["Job"] != [0, "/"]
                for sample in (before, after)
            )
            if before != after:
                def stable(sample):
                    return {"service": sample["service"], "unit": {
                        key: value for key, value in sample["unit"].items()
                        if key not in {"ActiveState", "SubState", "Job"}
                    }}
                if not pending or stable(before) != stable(after):
                    raise UnitOperationFailed("controller identity changed between snapshots")
            final_profile = await _observe_profile(reader)
            if (final_profile != profile or await reader._owner() != owner):
                raise UnitOperationFailed("controller final owner/profile changed")
            if pending:
                raise BootstrapControllerNotReady("controller READY acknowledgement pending")
            encoded = json.dumps(
                {"owner": owner, "phase": self._phase, "identity": {
                    "pid": self._identity.pid,
                    "invocation_id": self._identity.invocation_id.hex(),
                    "control_group": self._identity.control_group,
                }, "snapshot": after}, sort_keys=True, separators=(",", ":"),
            ).encode()
            return BootstrapControllerObservation(
                self._identity, owner, self._phase,
                "sha256:" + sha256(encoded).hexdigest(),
            )

        return await reader._bounded(operation())
