"""Owner-pinned systemd identity observation for the fixed commission service.

This is a bounded identity observation only. It is not commission readiness,
complete unit hardening, or permission to start or use the service.
"""

from dataclasses import dataclass
import re

from .bootstrap_masked import _observe_profile
from .bootstrap_stop import BootstrapStopJobs, _validate_expected_owner
from .bootstrap_systemd_profile import bootstrap_systemd_profile_digest
from .systemd_bus import PROPERTIES_INTERFACE, UNIT_INTERFACE, _unit_object_path
from .units import UnitOperationFailed

_UNIT = "azazel-commissiond.service"
_SERVICE = "org.freedesktop.systemd1.Service"
_CONTROL_GROUP = "/system.slice/azazel-commissiond.service"
_OWNER_PATTERN = re.compile(r":[0-9]+\.[0-9]+\Z")
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class CommissionServiceIdentity:
    """A fixed commissiond identity observed under retained owner/profile pins."""

    owner: str
    profile_digest: str
    pid: int
    invocation_id: bytes

    def __post_init__(self):
        if type(self.owner) is not str or _OWNER_PATTERN.fullmatch(self.owner) is None:
            raise ValueError("exact systemd unique owner required")
        if (type(self.profile_digest) is not str
                or _DIGEST_PATTERN.fullmatch(self.profile_digest) is None):
            raise ValueError("pinned systemd profile digest required")
        if type(self.pid) is not int or not 0 < self.pid < 2**32:
            raise ValueError("commission service PID must be a positive uint32")
        if (type(self.invocation_id) is not bytes or len(self.invocation_id) != 16
                or not any(self.invocation_id)):
            raise ValueError("commission invocation ID must be 16 nonzero bytes")


def _property(properties, key, signature, expected_type):
    if (type(properties) is not dict or len(properties) > 2048
            or any(type(name) is not str for name in properties)):
        raise UnitOperationFailed("commission identity property collection refused")
    variant = properties.get(key)
    if getattr(variant, "signature", None) != signature:
        raise UnitOperationFailed("commission identity property signature refused")
    value = getattr(variant, "value", None)
    if type(value) is not expected_type:
        raise UnitOperationFailed("commission identity property value refused")
    return value


def _unit_projection(properties):
    values = {
        "Id": _property(properties, "Id", "s", str),
        "Names": _property(properties, "Names", "as", list),
        "Following": _property(properties, "Following", "s", str),
        "LoadState": _property(properties, "LoadState", "s", str),
        "ActiveState": _property(properties, "ActiveState", "s", str),
        "SubState": _property(properties, "SubState", "s", str),
        "NeedDaemonReload": _property(properties, "NeedDaemonReload", "b", bool),
        "InvocationID": _property(properties, "InvocationID", "ay", bytes),
        "Job": _property(properties, "Job", "(uo)", list),
    }
    names = values["Names"]
    invocation_id = values["InvocationID"]
    job = values["Job"]
    if (values["Id"] != _UNIT
            or not 1 <= len(names) <= 256
            or any(type(name) is not str or not 0 < len(name) <= 256
                   or "/" in name or any(char.isspace() for char in name)
                   for name in names)
            or len(set(names)) != len(names) or _UNIT not in names
            or values["Following"] != ""
            or values["LoadState"] != "loaded"
            or values["ActiveState"] != "active"
            or values["SubState"] != "running"
            or values["NeedDaemonReload"] is not False
            or len(invocation_id) != 16 or not any(invocation_id)
            or len(job) != 2 or type(job[0]) is not int or job[0] != 0
            or type(job[1]) is not str or job[1] != "/"):
        raise UnitOperationFailed("commission unit state or identity refused")
    return {
        "Id": _UNIT,
        "Names": tuple(sorted(names)),
        "Following": "",
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "NeedDaemonReload": False,
        "InvocationID": bytes(invocation_id),
        "Job": (0, "/"),
    }, values["InvocationID"]


def _service_projection(properties):
    expected = {
        "MainPID": ("u", int),
        "ControlPID": ("u", int),
        "ControlGroup": ("s", str),
        "User": ("s", str),
        "Type": ("s", str),
        "NotifyAccess": ("s", str),
        "Restart": ("s", str),
    }
    values = {
        key: _property(properties, key, signature, value_type)
        for key, (signature, value_type) in expected.items()
    }
    pid = values["MainPID"]
    if (not 0 < pid < 2**32 or values["ControlPID"] != 0
            or values["ControlGroup"] != _CONTROL_GROUP
            or values["User"] != "azcommission"
            or values["Type"] != "notify"
            or values["NotifyAccess"] != "main"
            or values["Restart"] != "no"):
        raise UnitOperationFailed("commission service identity differs")
    return {
        "MainPID": pid,
        "ControlPID": 0,
        "ControlGroup": _CONTROL_GROUP,
        "User": "azcommission",
        "Type": "notify",
        "NotifyAccess": "main",
        "Restart": "no",
    }, pid


class BootstrapCommissionIdentityInspector:
    """Single-use, bounded repeated observation of the fixed commissiond identity."""

    def __init__(self, *, bus, message_factory, message_type, timeout_seconds,
                 expected_owner, systemd_profile_digest):
        owner = _validate_expected_owner(expected_owner)
        if owner is None:
            raise ValueError("enclosing systemd unique owner required")
        if (type(systemd_profile_digest) is not str
                or _DIGEST_PATTERN.fullmatch(systemd_profile_digest) is None):
            raise ValueError("pinned systemd profile digest required")
        self._owner = owner
        self._profile_digest = systemd_profile_digest
        self._reader = BootstrapStopJobs(
            bus=bus, message_factory=message_factory,
            message_type=message_type, timeout_seconds=timeout_seconds,
            expected_owner=owner,
        )
        self._used = False

    async def inspect(self) -> CommissionServiceIdentity:
        if self._used:
            raise UnitOperationFailed("commission identity inspection requires fresh session")
        self._used = True
        reader = self._reader
        path = _unit_object_path(_UNIT)

        async def snapshot():
            if await reader._call("GetUnit", "s", [_UNIT], "o") != [path]:
                raise UnitOperationFailed("commission unit object changed")
            unit_body = await reader._call(
                "GetAll", "s", [UNIT_INTERFACE], "a{sv}",
                path=path, interface=PROPERTIES_INTERFACE,
            )
            if len(unit_body) != 1:
                raise UnitOperationFailed("commission unit property reply refused")
            unit, invocation_id = _unit_projection(unit_body[0])

            service_body = await reader._call(
                "GetAll", "s", [_SERVICE], "a{sv}",
                path=path, interface=PROPERTIES_INTERFACE,
            )
            if len(service_body) != 1:
                raise UnitOperationFailed("commission service property reply refused")
            service, pid = _service_projection(service_body[0])
            return {"unit": unit, "service": service}, pid, invocation_id

        async def operation():
            owner = await reader._owner()
            if owner != self._owner:
                raise UnitOperationFailed("enclosing systemd owner changed")
            reader._manager_owner = owner
            profile = await _observe_profile(reader)
            if bootstrap_systemd_profile_digest(profile) != self._profile_digest:
                raise UnitOperationFailed("commission systemd profile changed")

            before = await snapshot()
            if (await reader._owner() != owner
                    or await _observe_profile(reader) != profile):
                raise UnitOperationFailed("commission owner/profile changed between snapshots")
            after = await snapshot()
            if before != after:
                raise UnitOperationFailed("commission identity changed between snapshots")
            if (await _observe_profile(reader) != profile
                    or await reader._owner() != owner):
                raise UnitOperationFailed("commission final owner/profile changed")
            return CommissionServiceIdentity(
                owner=owner,
                profile_digest=self._profile_digest,
                pid=after[1],
                invocation_id=after[2],
            )

        return await reader._bounded(operation())
