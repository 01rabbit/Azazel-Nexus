"""Owner/profile-pinned identity observations for the fixed audit service."""

import asyncio
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_audit_identity import (
    AuditServiceIdentity,
    BootstrapAuditIdentityInspector,
)
from azazel_nexus_runtime.bootstrap_systemd_profile import (
    bootstrap_systemd_profile_digest,
    observe_bootstrap_systemd_profile,
)
from azazel_nexus_runtime.systemd_bus import (
    MANAGER_INTERFACE,
    MANAGER_PATH,
    PROPERTIES_INTERFACE,
    UNIT_INTERFACE,
)
from azazel_nexus_runtime.units import UnitOperationFailed
from test_runtime_bootstrap_masked import (
    OWNER,
    PROFILE_PATHS,
    PROFILE_VERSION,
    Variant,
    _object_path,
    _reply,
)


UNIT = "azazel-auditd.service"
SERVICE = "org.freedesktop.systemd1.Service"
CONTROL_GROUP = "/system.slice/azazel-auditd.service"
INVOCATION_ID = bytes(range(1, 17))
PID = 4321
PROFILE = observe_bootstrap_systemd_profile(
    version=PROFILE_VERSION, unit_path=PROFILE_PATHS,
)
PROFILE_DIGEST = bootstrap_systemd_profile_digest(PROFILE)


class FakeBus:
    def __init__(self, *, owner_drift_at=None, profile_drift_at=None,
                 initial_owner=OWNER, fault=None, aliases=None,
                 mutate_unit_during_service=False, unit_state="active",
                 pids=None, invocation_ids=None):
        self.owner_drift_at = owner_drift_at
        self.profile_drift_at = profile_drift_at
        self.initial_owner = initial_owner
        self.fault = fault
        self.aliases = [UNIT] if aliases is None else aliases
        self.mutate_unit_during_service = mutate_unit_during_service
        self.unit_state = unit_state
        self.pids = [PID, PID] if pids is None else pids
        self.invocation_ids = ([INVOCATION_ID, INVOCATION_ID]
                               if invocation_ids is None else invocation_ids)
        self.calls = []
        self.owner_calls = 0
        self.profile_calls = 0
        self.unit_calls = 0
        self.service_calls = 0
        self.retained_unit_properties = None
        self.retained_unit_replies = []

    async def call(self, message):
        self.calls.append(message)
        if message.destination == "org.freedesktop.DBus":
            assert message.member == "GetNameOwner"
            self.owner_calls += 1
            if self.initial_owner != OWNER and self.owner_calls == 1:
                owner = self.initial_owner
            elif (self.owner_drift_at is not None
                  and self.owner_calls >= self.owner_drift_at):
                owner = ":1.99"
            else:
                owner = OWNER
            return _reply("s", owner, sender="org.freedesktop.DBus")

        assert message.destination == OWNER
        if message.member == "GetUnit":
            assert message.interface == MANAGER_INTERFACE
            return _reply("o", _object_path(message.body[0]), sender=OWNER)

        assert message.member == "GetAll"
        assert message.interface == PROPERTIES_INTERFACE
        if message.body == [MANAGER_INTERFACE]:
            assert message.path == MANAGER_PATH
            self.profile_calls += 1
            version = PROFILE_VERSION
            if (self.profile_drift_at is not None
                    and self.profile_calls >= self.profile_drift_at):
                version = "257.13-2~deb13u1"
            return _reply("a{sv}", {
                "Version": Variant("s", version),
                "UnitPath": Variant("as", list(PROFILE_PATHS)),
            }, sender=OWNER)

        assert message.path == _object_path(UNIT)
        if message.body == [UNIT_INTERFACE]:
            self.unit_calls += 1
            unit = {
                "Id": Variant("s", UNIT),
                "Names": Variant("as", list(self.aliases)),
                "Following": Variant("s", ""),
                "LoadState": Variant("s", "loaded"),
                "ActiveState": Variant("s", self.unit_state),
                "SubState": Variant("s", "running"),
                "NeedDaemonReload": Variant("b", False),
                "InvocationID": Variant(
                    "ay", self.invocation_ids[self.unit_calls - 1]
                ),
                "Job": Variant("(uo)", [0, "/"]),
            }
            if self.fault == "wrong-id":
                unit["Id"] = Variant("s", "other.service")
            elif self.fault == "following":
                unit["Following"] = Variant("s", "another.service")
            elif self.fault == "unloaded":
                unit["LoadState"] = Variant("s", "not-found")
            elif self.fault == "stale-reload":
                unit["NeedDaemonReload"] = Variant("b", True)
            elif self.fault == "wrong-substate":
                unit["SubState"] = Variant("s", "dead")
            elif self.fault == "job":
                unit["Job"] = Variant("(uo)", [7, "/org/freedesktop/systemd1/job/7"])
            elif self.fault == "wrong-invocation-type":
                unit["InvocationID"] = Variant("s", INVOCATION_ID.hex())
            if self.fault == "zero-invocation":
                unit["InvocationID"] = Variant("ay", bytes(16))
            self.retained_unit_properties = unit
            self.retained_unit_replies.append(unit)
            return _reply("a{sv}", unit, sender=OWNER)

        assert message.body == [SERVICE]
        self.service_calls += 1
        if self.mutate_unit_during_service and self.service_calls == 1:
            self.retained_unit_replies[0]["ActiveState"] = Variant("s", "inactive")
        pid = self.pids[self.service_calls - 1]
        service = {
            "MainPID": Variant("u", pid),
            "ControlPID": Variant("u", 0),
            "ControlGroup": Variant("s", CONTROL_GROUP),
            "User": Variant("s", "azaudit"),
            "Type": Variant("s", "notify"),
            "NotifyAccess": Variant("s", "main"),
            "Restart": Variant("s", "no"),
        }
        if self.fault == "wrong-pid-type":
            service["MainPID"] = Variant("s", str(pid))
        elif self.fault == "wrong-control-group":
            service["ControlGroup"] = Variant("s", "/system.slice/other.service")
        elif self.fault == "wrong-control-pid":
            service["ControlPID"] = Variant("u", 7)
        elif self.fault == "wrong-user":
            service["User"] = Variant("s", "root")
        elif self.fault == "wrong-type":
            service["Type"] = Variant("s", "simple")
        elif self.fault == "wrong-restart":
            service["Restart"] = Variant("s", "always")
        return _reply("a{sv}", service, sender=OWNER)


def _inspector(bus, **changes):
    options = {
        "bus": bus,
        "message_factory": lambda **values: SimpleNamespace(**values),
        "message_type": SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        "timeout_seconds": 5.0,
        "expected_owner": OWNER,
        "systemd_profile_digest": PROFILE_DIGEST,
    }
    options.update(changes)
    return BootstrapAuditIdentityInspector(**options)


def test_matching_two_snapshots_return_frozen_fixed_service_identity():
    async def scenario():
        bus = FakeBus(aliases=["z-audit-alias.service", UNIT, "a-audit-alias.service"])
        identity = await _inspector(bus).inspect()
        assert identity == AuditServiceIdentity(
            OWNER, PROFILE_DIGEST, PID, INVOCATION_ID
        )
        with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
            identity.pid = 1
        assert bus.owner_calls == bus.profile_calls == 3
        assert bus.unit_calls == bus.service_calls == 2
        assert {call.member for call in bus.calls} <= {"GetNameOwner", "GetUnit", "GetAll"}
        assert all(call.member != "GetAll" or call.body in (
            [MANAGER_INTERFACE], [UNIT_INTERFACE], [SERVICE],
        ) for call in bus.calls)

    asyncio.run(scenario())


@pytest.mark.parametrize("identity_args", [
    (None, PROFILE_DIGEST, PID, INVOCATION_ID),
    ("org.freedesktop.systemd1", PROFILE_DIGEST, PID, INVOCATION_ID),
    (OWNER, "sha256:bad", PID, INVOCATION_ID),
    (OWNER, PROFILE_DIGEST, 0, INVOCATION_ID),
    (OWNER, PROFILE_DIGEST, 2**32, INVOCATION_ID),
    (OWNER, PROFILE_DIGEST, True, INVOCATION_ID),
    (OWNER, PROFILE_DIGEST, PID, b""),
    (OWNER, PROFILE_DIGEST, PID, bytes(16)),
    (OWNER, PROFILE_DIGEST, PID, b"x" * 15),
    (OWNER, PROFILE_DIGEST, PID, bytearray(INVOCATION_ID)),
])
def test_identity_value_requires_exact_owner_digest_pid_and_invocation(identity_args):
    with pytest.raises(ValueError):
        AuditServiceIdentity(*identity_args)


@pytest.mark.parametrize("fault", [
    "wrong-pid-type", "wrong-control-group", "wrong-control-pid",
    "wrong-user", "wrong-type", "wrong-restart", "wrong-invocation-type",
    "zero-invocation", "wrong-id", "following", "unloaded", "stale-reload",
    "wrong-substate", "job",
])
def test_malformed_service_or_unit_identity_is_refused(fault):
    async def scenario():
        bus = FakeBus(fault=fault)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()

    asyncio.run(scenario())


@pytest.mark.parametrize("state", ["inactive", "activating", "failed"])
def test_audit_unit_must_be_loaded_active_and_running(state):
    async def scenario():
        with pytest.raises(UnitOperationFailed):
            await _inspector(FakeBus(unit_state=state)).inspect()

    asyncio.run(scenario())


@pytest.mark.parametrize("aliases", [
    [], ["audit-alias.service"], [UNIT, UNIT], [UNIT, 7],
    [UNIT, "bad/audit-alias.service"], [UNIT, "x" * 257],
])
def test_audit_aliases_must_be_bounded_unique_and_include_canonical_name(aliases):
    async def scenario():
        with pytest.raises(UnitOperationFailed):
            await _inspector(FakeBus(aliases=aliases)).inspect()

    asyncio.run(scenario())


@pytest.mark.parametrize("pids", [[0, PID], [2**32, PID], [PID, PID + 1]])
def test_invalid_or_changed_service_pid_is_refused(pids):
    async def scenario():
        with pytest.raises(UnitOperationFailed):
            await _inspector(FakeBus(pids=pids)).inspect()

    asyncio.run(scenario())


def test_changed_invocation_id_between_snapshots_is_refused():
    async def scenario():
        with pytest.raises(UnitOperationFailed, match="changed between snapshots"):
            await _inspector(FakeBus(
                invocation_ids=[INVOCATION_ID, b"z" * 16],
            )).inspect()

    asyncio.run(scenario())


@pytest.mark.parametrize("fault", ["owner", "profile"])
@pytest.mark.parametrize("stage", ["between", "final"])
def test_owner_or_profile_drift_between_or_after_snapshots_refuses(fault, stage):
    async def scenario():
        count = 2 if stage == "between" else 3
        bus = FakeBus(
            owner_drift_at=count if fault == "owner" else None,
            profile_drift_at=count if fault == "profile" else None,
        )
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()

    asyncio.run(scenario())


def test_initial_owner_or_profile_mismatch_refuses_without_unit_reads():
    async def scenario():
        wrong_owner = FakeBus(initial_owner=":1.77")
        with pytest.raises(UnitOperationFailed):
            await _inspector(wrong_owner).inspect()
        assert wrong_owner.unit_calls == 0

        changed_profile = FakeBus(profile_drift_at=1)
        with pytest.raises(UnitOperationFailed):
            await _inspector(changed_profile).inspect()
        assert changed_profile.unit_calls == 0

    asyncio.run(scenario())


def test_unit_projection_is_detached_before_service_reply_mutates_retained_reply():
    async def scenario():
        baseline = await _inspector(FakeBus()).inspect()
        bus = FakeBus(mutate_unit_during_service=True)
        result = await _inspector(bus).inspect()
        assert result == baseline
        assert bus.retained_unit_replies[0]["ActiveState"].value == "inactive"

    asyncio.run(scenario())


def test_initially_invalid_unit_state_is_not_laundered_by_service_reply():
    async def scenario():
        bus = FakeBus(unit_state="inactive", mutate_unit_during_service=True)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()
        assert bus.service_calls == 0
        assert bus.retained_unit_properties["ActiveState"].value == "inactive"

    asyncio.run(scenario())


def test_inspection_is_single_use_and_constructor_pins_owner_profile():
    bus = FakeBus()
    for changes in (
        {"expected_owner": None},
        {"systemd_profile_digest": "sha256:bad"},
    ):
        with pytest.raises(ValueError):
            _inspector(bus, **changes)
    assert not bus.calls

    async def scenario():
        inspector = _inspector(bus)
        result = await inspector.inspect()
        assert result.owner == OWNER and result.profile_digest == PROFILE_DIGEST
        count = len(bus.calls)
        with pytest.raises(UnitOperationFailed, match="fresh session"):
            await inspector.inspect()
        assert len(bus.calls) == count

    asyncio.run(scenario())
