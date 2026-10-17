"""Read-only credential admission of the fixed systemd system-bus owner.

Credentials are reported by the trusted fixed system bus, not self-reported
by a service. PID 1/UID 0 matches the cgroup namespace comparison's subject;
this does not attest the systemd executable, host OS, closure or hardware.
"""

from dataclasses import dataclass

from .bootstrap_stop import BootstrapStopJobs
from .units import UnitOperationFailed

_DBUS = "org.freedesktop.DBus"


@dataclass(frozen=True)
class BootstrapManagerIdentity:
    owner: str
    pid: int
    uid: int


async def inspect_bootstrap_manager_identity(*, bus, message_factory, message_type,
                                             timeout_seconds):
    reader = BootstrapStopJobs(bus=bus, message_factory=message_factory,
                               message_type=message_type, timeout_seconds=timeout_seconds)

    async def operation():
        owner = await reader._owner()

        async def credential(member, expected):
            result = await reader._call(
                member, "s", [owner], "u", destination=_DBUS,
                interface=_DBUS, path="/org/freedesktop/DBus",
            )
            if len(result) != 1 or type(result[0]) is not int or result[0] != expected:
                raise UnitOperationFailed("systemd manager credential refused")
            if await reader._owner() != owner:
                raise UnitOperationFailed("systemd manager owner changed during admission")

        await credential("GetConnectionUnixProcessID", 1)
        await credential("GetConnectionUnixUser", 0)
        return BootstrapManagerIdentity(owner=owner, pid=1, uid=0)

    try:
        return await reader._bounded(operation())
    except Exception:
        raise UnitOperationFailed("systemd manager identity admission refused") from None
