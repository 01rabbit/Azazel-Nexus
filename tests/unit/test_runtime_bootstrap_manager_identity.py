import asyncio
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_manager_identity import (
    inspect_bootstrap_manager_identity,
)
from azazel_nexus_runtime.bootstrap_stop import BootstrapStopJobs
from azazel_nexus_runtime.units import UnitOperationFailed


DBUS = "org.freedesktop.DBus"
DBUS_PATH = "/org/freedesktop/DBus"
OWNER = ":1.40"


class FakeBus:
    METHOD_RETURN = 1
    ERROR = 3

    def __init__(self, *, faults=None, owner=OWNER):
        self.faults = faults or {}
        self.owner = owner
        self.owner_reads = 0
        self.calls = []

    async def call(self, message):
        self.calls.append(message)
        assert message.destination == DBUS
        assert message.path == DBUS_PATH
        assert message.interface == DBUS
        member = message.member
        fault = self.faults.get(member)
        if fault == "timeout":
            await asyncio.Event().wait()
        if member == "GetNameOwner":
            self.owner_reads += 1
            owner = self.owner
            if self.faults.get("ownerdrift") and self.owner_reads > 1:
                owner = ":1.41"
            return self.reply(message, "s", [owner], sender=DBUS)
        if member == "GetConnectionUnixProcessID":
            value = 2 if fault == "wrongpid" else 1
        elif member == "GetConnectionUnixUser":
            value = 1 if fault == "wronguid" else 0
        else:
            raise AssertionError(f"unexpected D-Bus method: {member}")
        if fault == "bool":
            value = True
        if fault == "shape":
            return self.reply(message, "u", [], sender=DBUS)
        if fault == "missingcreds":
            return self.reply(message, "", [], sender=DBUS)
        if fault == "error":
            return self.reply(message, "u", [value], sender=DBUS, message_type=self.ERROR)
        sender = ":1.99" if fault == "wrongsender" else DBUS
        return self.reply(message, "u", [value], sender=sender)

    @staticmethod
    def reply(message, signature, body, *, sender, message_type=METHOD_RETURN):
        return SimpleNamespace(
            message_type=message_type,
            sender=sender,
            signature=signature,
            body=body,
        )


def message_factory(**values):
    return SimpleNamespace(**values)


MESSAGE_TYPE = SimpleNamespace(METHOD_RETURN=FakeBus.METHOD_RETURN)


def inspect(bus, timeout=5.0):
    return asyncio.run(inspect_bootstrap_manager_identity(
        bus=bus,
        message_factory=message_factory,
        message_type=MESSAGE_TYPE,
        timeout_seconds=timeout,
    ))


def test_pid1_uid0_manager_identity_is_admitted():
    bus = FakeBus()
    identity = inspect(bus)
    assert (identity.owner, identity.pid, identity.uid) == (OWNER, 1, 0)
    assert [call.member for call in bus.calls] == [
        "GetNameOwner",
        "GetConnectionUnixProcessID",
        "GetNameOwner",
        "GetConnectionUnixUser",
        "GetNameOwner",
    ]
    assert bus.calls[1].body == [OWNER]
    assert bus.calls[3].body == [OWNER]


@pytest.mark.parametrize("fault", [
    "wrongpid", "wronguid", "bool", "shape", "wrongsender", "error", "missingcreds",
])
def test_untrusted_or_malformed_manager_credentials_are_refused(fault):
    member = ("GetConnectionUnixUser" if fault == "wronguid"
              else "GetConnectionUnixProcessID")
    with pytest.raises(UnitOperationFailed):
        inspect(FakeBus(faults={member: fault}))


def test_owner_drift_during_credential_admission_is_refused():
    bus = FakeBus(faults={"ownerdrift": True})
    with pytest.raises(UnitOperationFailed):
        inspect(bus)
    assert [call.member for call in bus.calls] == [
        "GetNameOwner", "GetConnectionUnixProcessID", "GetNameOwner",
    ]


def test_credential_timeout_is_refused_within_budget():
    bus = FakeBus(faults={"GetConnectionUnixProcessID": "timeout"})
    with pytest.raises(UnitOperationFailed):
        inspect(bus, timeout=0.01)


def test_inherited_bus_owner_pin_rejects_change_without_reader_expected_owner():
    bus = FakeBus(owner=":1.41")
    bus._azazel_systemd_owner = OWNER
    reader = BootstrapStopJobs(
        bus=bus,
        message_factory=message_factory,
        message_type=MESSAGE_TYPE,
        timeout_seconds=5.0,
        expected_owner=None,
    )

    async def scenario():
        await reader._bounded(reader._owner())

    with pytest.raises(UnitOperationFailed):
        asyncio.run(scenario())
    assert reader._expected_owner is None
