"""Synthetic system-bus observations for fixed commissiond identity."""

import asyncio
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_commission_identity import (
    BootstrapCommissionIdentityInspector, CommissionServiceIdentity,
)
from azazel_nexus_runtime.bootstrap_systemd_profile import (
    bootstrap_systemd_profile_digest, observe_bootstrap_systemd_profile,
)
from azazel_nexus_runtime.systemd_bus import (
    MANAGER_INTERFACE, MANAGER_PATH, PROPERTIES_INTERFACE, UNIT_INTERFACE,
)
from azazel_nexus_runtime.units import UnitOperationFailed
from test_runtime_bootstrap_masked import (
    OWNER, PROFILE_PATHS, PROFILE_VERSION, Variant, _object_path, _reply,
)

UNIT = "azazel-commissiond.service"
SERVICE = "org.freedesktop.systemd1.Service"
INVOCATION_ID = bytes(range(1, 17))
PROFILE = observe_bootstrap_systemd_profile(version=PROFILE_VERSION,
                                            unit_path=PROFILE_PATHS)
PROFILE_DIGEST = bootstrap_systemd_profile_digest(PROFILE)


class FakeBus:
    def __init__(self, *, pids=None, invocation_ids=None, owner_drift_at=None,
                 profile_drift_at=None, fault=None, user="azcommission"):
        self.pids = pids or [4321, 4321]
        self.invocation_ids = invocation_ids or [INVOCATION_ID, INVOCATION_ID]
        self.owner_drift_at = owner_drift_at
        self.profile_drift_at = profile_drift_at
        self.fault = fault
        self.user = user
        self.calls = []
        self.owner_calls = self.profile_calls = self.unit_calls = self.service_calls = 0

    async def call(self, message):
        self.calls.append(message)
        if message.destination == "org.freedesktop.DBus":
            self.owner_calls += 1
            owner = (":1.99" if self.owner_drift_at is not None
                     and self.owner_calls >= self.owner_drift_at else OWNER)
            return _reply("s", owner, sender="org.freedesktop.DBus")
        if message.member == "GetUnit":
            assert message.interface == MANAGER_INTERFACE
            return _reply("o", _object_path(UNIT), sender=OWNER)
        if message.body == [MANAGER_INTERFACE]:
            assert message.path == MANAGER_PATH
            assert message.interface == PROPERTIES_INTERFACE
            self.profile_calls += 1
            version = ("257.13-2~deb13u1" if self.profile_drift_at is not None
                       and self.profile_calls >= self.profile_drift_at else PROFILE_VERSION)
            return _reply("a{sv}", {
                "Version": Variant("s", version),
                "UnitPath": Variant("as", list(PROFILE_PATHS)),
            }, sender=OWNER)
        if message.body == [UNIT_INTERFACE]:
            assert message.interface == PROPERTIES_INTERFACE
            self.unit_calls += 1
            return _reply("a{sv}", {
                "Id": Variant("s", UNIT), "Names": Variant("as", [UNIT]),
                "Following": Variant("s", ""), "LoadState": Variant("s", "loaded"),
                "ActiveState": Variant("s", "active"), "SubState": Variant("s", "running"),
                "NeedDaemonReload": Variant("b", False),
                "InvocationID": Variant("ay", self.invocation_ids[self.unit_calls - 1]),
                "Job": Variant("(uo)", [0, "/"]),
            }, sender=OWNER)
        assert message.body == [SERVICE]
        assert message.interface == PROPERTIES_INTERFACE
        self.service_calls += 1
        values = {
            "MainPID": Variant("u", self.pids[self.service_calls - 1]),
            "ControlPID": Variant("u", 0),
            "ControlGroup": Variant("s", "/system.slice/azazel-commissiond.service"),
            "User": Variant("s", "root" if self.fault == "user" else self.user),
            "Type": Variant("s", "notify"), "NotifyAccess": Variant("s", "main"),
            "Restart": Variant("s", "no"),
        }
        return _reply("a{sv}", values, sender=OWNER)


def _inspector(bus, **changes):
    options = {
        "bus": bus, "message_factory": lambda **values: SimpleNamespace(**values),
        "message_type": SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        "timeout_seconds": 0.2, "expected_owner": OWNER,
        "systemd_profile_digest": PROFILE_DIGEST,
    }
    options.update(changes)
    return BootstrapCommissionIdentityInspector(**options)


def test_matching_snapshots_capture_fixed_frozen_commission_identity():
    async def scenario():
        bus = FakeBus()
        identity = await _inspector(bus).inspect()
        assert identity == CommissionServiceIdentity(
            OWNER, PROFILE_DIGEST, 4321, INVOCATION_ID,
        )
        with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
            identity.pid = 5
        assert bus.owner_calls == bus.profile_calls == 3
        assert bus.unit_calls == bus.service_calls == 2

    asyncio.run(scenario())


@pytest.mark.parametrize("bus", [
    FakeBus(fault="user"), FakeBus(user="azaudit"),
    FakeBus(pids=[4321, 4322]),
    FakeBus(invocation_ids=[INVOCATION_ID, b"z" * 16]),
    FakeBus(owner_drift_at=2), FakeBus(profile_drift_at=2),
])
def test_changed_or_wrong_fixed_service_identity_is_refused(bus):
    async def scenario():
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()

    asyncio.run(scenario())


@pytest.mark.parametrize("args", [
    (None, PROFILE_DIGEST, 4321, INVOCATION_ID),
    (OWNER, "sha256:bad", 4321, INVOCATION_ID),
    (OWNER, PROFILE_DIGEST, True, INVOCATION_ID),
    (OWNER, PROFILE_DIGEST, 4321, bytes(16)),
])
def test_commission_identity_value_validates_exact_fields(args):
    with pytest.raises(ValueError):
        CommissionServiceIdentity(*args)


def test_inspector_is_single_use_and_rejects_unpinned_inputs():
    bus = FakeBus()
    with pytest.raises(ValueError):
        _inspector(bus, expected_owner=None)
    async def scenario():
        inspector = _inspector(bus)
        await inspector.inspect()
        calls = len(bus.calls)
        with pytest.raises(UnitOperationFailed, match="fresh session"):
            await inspector.inspect()
        assert len(bus.calls) == calls
    asyncio.run(scenario())
