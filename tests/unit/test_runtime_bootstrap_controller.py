"""Owner-pinned controller identity and phase snapshots using a fake bus."""

import asyncio
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_controller import (
    BootstrapControllerIdentity,
    BootstrapControllerInspector,
)
from azazel_nexus_runtime.bootstrap_loaded import _COMMANDS, _EXEC_SIGNATURE
from azazel_nexus_runtime.bootstrap_systemd_profile import (
    bootstrap_systemd_profile_digest,
    observe_bootstrap_systemd_profile,
)
from azazel_nexus_runtime.hardening import PROFILES
from azazel_nexus_runtime.launch_environment import BOOTSTRAP_UNSET_ENVIRONMENT
from azazel_nexus_runtime.systemd_bus import (
    MANAGER_INTERFACE,
    MANAGER_PATH,
    PROPERTIES_INTERFACE,
    UNIT_INTERFACE,
)
from azazel_nexus_runtime.units import UnitOperationFailed
from test_runtime_bootstrap_loaded import OWNER, Variant, _object_path, _reply
from test_runtime_bootstrap_masked import PROFILE_PATHS, PROFILE_VERSION


UNIT = "azazel-activated.service"
CONTROL_GROUP = "/system.slice/azazel-activated.service"
INVOCATION_ID = bytes(range(1, 17))
IDENTITY = BootstrapControllerIdentity(4321, INVOCATION_ID)
PROFILE = observe_bootstrap_systemd_profile(
    version=PROFILE_VERSION, unit_path=PROFILE_PATHS,
)
PROFILE_DIGEST = bootstrap_systemd_profile_digest(PROFILE)
EXECUTABLE = next(profile.executable for profile in PROFILES if profile.unit == UNIT)


class FakeBus:
    def __init__(self, *, phase="ready", mutate=None, owner_drift_at=None,
                 profile_drift_at=None, wrong_path=False, aliases=None,
                 reorder_aliases=False, unit_active_state=None,
                 mutate_unit_during_service=False,
                 unit_state_on_service="inactive",
                 mutate_exec_on_next_getunit=False):
        self.phase = phase
        self.mutate = mutate
        self.owner_drift_at = owner_drift_at
        self.profile_drift_at = profile_drift_at
        self.wrong_path = wrong_path
        self.aliases = aliases
        self.reorder_aliases = reorder_aliases
        self.unit_active_state = unit_active_state
        self.mutate_unit_during_service = mutate_unit_during_service
        self.unit_state_on_service = unit_state_on_service
        self.mutate_exec_on_next_getunit = mutate_exec_on_next_getunit
        self.retained_unit_properties = None
        self.retained_service_properties = None
        self.retained_service_replies = []
        self.owner_calls = 0
        self.profile_calls = 0
        self.unit_calls = 0
        self.service_calls = 0
        self.calls = []

    async def call(self, message):
        self.calls.append(message)
        if message.destination == "org.freedesktop.DBus":
            assert message.member == "GetNameOwner"
            self.owner_calls += 1
            owner = ":1.99" if (
                self.owner_drift_at is not None
                and self.owner_calls >= self.owner_drift_at
            ) else OWNER
            return _reply("s", owner, sender="org.freedesktop.DBus")

        assert message.destination == OWNER
        if (message.member == "GetAll" and message.path == MANAGER_PATH
                and message.interface == PROPERTIES_INTERFACE):
            assert message.body == [MANAGER_INTERFACE]
            self.profile_calls += 1
            version = (
                "257.13-2~deb13u1"
                if self.profile_drift_at is not None
                and self.profile_calls >= self.profile_drift_at
                else PROFILE_VERSION
            )
            return _reply("a{sv}", {
                "Version": Variant("s", version),
                "UnitPath": Variant("as", list(PROFILE_PATHS)),
            })

        if message.member == "GetUnit":
            assert message.body == [UNIT]
            if (self.mutate_exec_on_next_getunit and self.service_calls == 1
                    and self.retained_service_replies):
                command = self.retained_service_replies[0]["ExecStartEx"].value[0]
                command[0] = "/usr/bin/changed-after-validation"
            path = _object_path(UNIT)
            if self.wrong_path:
                path += "_wrong"
            return _reply("o", path)

        assert message.member == "GetAll"
        assert message.path == _object_path(UNIT)
        assert message.interface == PROPERTIES_INTERFACE
        if message.body == [UNIT_INTERFACE]:
            self.unit_calls += 1
            properties = self._unit_properties()
            self.retained_unit_properties = properties
            count = self.unit_calls
        else:
            assert message.body == ["org.freedesktop.systemd1.Service"]
            self.service_calls += 1
            if (self.mutate_unit_during_service
                    and self.retained_unit_properties is not None):
                self.retained_unit_properties["ActiveState"] = Variant(
                    "s", self.unit_state_on_service
                )
            properties = self._service_properties()
            self.retained_service_properties = properties
            self.retained_service_replies.append(properties)
            count = self.service_calls
        if self.mutate is not None:
            properties = self.mutate(message.body[0], count, properties)
        return _reply("a{sv}", properties)

    def _unit_properties(self):
        pre_ready = self.phase == "pre-ready"
        names = [UNIT] if self.aliases is None else list(self.aliases)
        if self.reorder_aliases and self.unit_calls == 2:
            names.reverse()
        return {
            "Id": Variant("s", UNIT),
            "Names": Variant("as", names),
            "Following": Variant("s", ""),
            "LoadState": Variant("s", "loaded"),
            "DefaultDependencies": Variant("b", False),
            "Requires": Variant("as", []),
            "Wants": Variant("as", []),
            "BindsTo": Variant("as", []),
            "Requisite": Variant("as", []),
            "Upholds": Variant("as", []),
            "UpheldBy": Variant("as", []),
            "OnFailure": Variant("as", []),
            "OnSuccess": Variant("as", []),
            "OnFailureOf": Variant("as", []),
            "OnSuccessOf": Variant("as", []),
            "Triggers": Variant("as", []),
            "TriggeredBy": Variant("as", []),
            "NeedDaemonReload": Variant("b", False),
            "Conditions": Variant("a(sbbsi)", [[
                "ConditionPathExists", False, True,
                "/run/azazel-nexus-bootstrap/controller-used", 1,
            ]]),
            "ConditionResult": Variant("b", True),
            "InvocationID": Variant("ay", INVOCATION_ID),
            "ActiveState": Variant(
                "s", self.unit_active_state or ("activating" if pre_ready else "active")
            ),
            "SubState": Variant("s", "start" if pre_ready else "running"),
            "Job": Variant(
                "(uo)", [7, "/org/freedesktop/systemd1/job/7"]
                if pre_ready else [0, "/"],
            ),
        }

    def _service_properties(self):
        command = [EXECUTABLE, [EXECUTABLE], [], 0, 0, 0, 0, 0, 0, 0]
        properties = {
            "MainPID": Variant("u", IDENTITY.pid),
            "ControlPID": Variant("u", 0),
            "ControlGroup": Variant("s", CONTROL_GROUP),
            "User": Variant("s", "root"),
            "Type": Variant("s", "notify"),
            "NotifyAccess": Variant("s", "main"),
            "Restart": Variant("s", "no"),
            "KillMode": Variant("s", "control-group"),
            "SendSIGKILL": Variant("b", True),
            "ExitType": Variant("s", "main"),
            "RemainAfterExit": Variant("b", False),
            "WatchdogUSec": Variant("t", 30_000_000),
            "WatchdogSignal": Variant("i", 9),
            "TimeoutStartUSec": Variant("t", 30_000_000),
            "TimeoutStopUSec": Variant("t", 10_000_000),
            "TimeoutStartFailureMode": Variant("s", "kill"),
            "TimeoutStopFailureMode": Variant("s", "kill"),
            "FinalKillSignal": Variant("i", 9),
            "KillSignal": Variant("i", 15),
            "Environment": Variant("as", []),
            "EnvironmentFiles": Variant("a(sb)", []),
            "PassEnvironment": Variant("as", []),
            "UnsetEnvironment": Variant("as", list(BOOTSTRAP_UNSET_ENVIRONMENT)),
            "SetLoginEnvironment": Variant("b", False),
            "PAMName": Variant("s", ""),
            "SupplementaryGroups": Variant("as", ["azazel-operator"]),
            "CapabilityBoundingSet": Variant("t", 0x4),
            "AmbientCapabilities": Variant("t", 0),
            "ExecStartEx": Variant(_EXEC_SIGNATURE, [command]),
        }
        properties.update({key: Variant(_EXEC_SIGNATURE, []) for key in _COMMANDS})
        return properties


def _inspector(bus, *, phase="ready", identity=IDENTITY, owner=OWNER,
               profile_digest=PROFILE_DIGEST):
    return BootstrapControllerInspector(
        bus=bus,
        message_factory=lambda **fields: SimpleNamespace(**fields),
        message_type=SimpleNamespace(METHOD_RETURN=1, SIGNAL=4),
        timeout_seconds=0.2,
        expected_owner=owner,
        systemd_profile_digest=profile_digest,
        identity=identity,
        phase=phase,
    )


@pytest.mark.parametrize("phase", ["pre-ready", "ready"])
def test_matching_phase_returns_two_snapshot_identity_without_mutation(phase):
    async def scenario():
        bus = FakeBus(phase=phase)
        result = await _inspector(bus, phase=phase).inspect()
        assert result.identity == IDENTITY
        assert result.owner == OWNER and result.phase == phase
        assert result.fingerprint.startswith("sha256:")
        assert bus.unit_calls == bus.service_calls == 2
        assert bus.owner_calls == 3 and bus.profile_calls == 3
        assert all(call.member in {"GetNameOwner", "GetAll", "GetUnit"}
                   for call in bus.calls)

    asyncio.run(scenario())


@pytest.mark.parametrize("pid", [0, -1, 2**32, True])
def test_identity_requires_exact_positive_uint32_pid(pid):
    with pytest.raises(ValueError, match="PID"):
        BootstrapControllerIdentity(pid, INVOCATION_ID)


@pytest.mark.parametrize("invocation", [b"", bytes(16), b"x" * 15, b"x" * 17, bytearray(b"x" * 16)])
def test_identity_requires_nonzero_exactly_sixteen_bytes(invocation):
    with pytest.raises(ValueError, match="invocation"):
        BootstrapControllerIdentity(123, invocation)


def test_identity_requires_fixed_control_group():
    with pytest.raises(ValueError, match="cgroup"):
        BootstrapControllerIdentity(123, INVOCATION_ID, "/other.slice/controller.service")


@pytest.mark.parametrize("phase", ["pre-ready", "ready"])
@pytest.mark.parametrize("key,signature,value", [
    ("WatchdogUSec", "t", 0), ("WatchdogUSec", "t", 60_000_000),
    ("WatchdogUSec", "s", "30000000"), ("WatchdogSignal", "i", 6),
])
def test_controller_requires_fixed_watchdog_before_and_after_ready(phase, key, signature, value):
    def mutate(interface, _count, props):
        if interface == "org.freedesktop.systemd1.Service":
            props[key] = Variant(signature, value)
        return props

    with pytest.raises(UnitOperationFailed):
        asyncio.run(_inspector(FakeBus(phase=phase, mutate=mutate), phase=phase).inspect())


@pytest.mark.parametrize("phase", ["pre-ready", "ready"])
@pytest.mark.parametrize("fault", [
    "missing", "extra", "wrong-path", "positive", "trigger",
    "boolean-result", "wrong-signature", "failed-result",
])
def test_controller_requires_native_one_use_condition(phase, fault):
    def mutate(interface, _count, props):
        if interface != UNIT_INTERFACE:
            return props
        conditions = props["Conditions"].value
        if fault == "missing":
            del props["Conditions"]
        elif fault == "extra":
            conditions.append(list(conditions[0]))
        elif fault == "wrong-path":
            conditions[0][3] = "/tmp/elsewhere"
        elif fault == "positive":
            conditions[0][2] = False
        elif fault == "trigger":
            conditions[0][1] = True
        elif fault == "boolean-result":
            conditions[0][4] = True
        elif fault == "wrong-signature":
            props["Conditions"] = Variant("as", conditions)
        else:
            props["ConditionResult"] = Variant("b", False)
        return props

    with pytest.raises(UnitOperationFailed):
        asyncio.run(_inspector(FakeBus(phase=phase, mutate=mutate), phase=phase).inspect())


_CONTROLLER_BOUND_PROPERTIES = {
    "TimeoutStartUSec": ("t", 30_000_000),
    "TimeoutStopUSec": ("t", 10_000_000),
    "TimeoutStartFailureMode": ("s", "kill"),
    "TimeoutStopFailureMode": ("s", "kill"),
    "FinalKillSignal": ("i", 9),
    "KillSignal": ("i", 15),
}


def _controller_property_faults():
    faults = []
    for key, (signature, expected) in _CONTROLLER_BOUND_PROPERTIES.items():
        faults.append((key, "missing", None, None))
        faults.append((key, "signature", "s" if signature != "s" else "i", expected))
        wrong_type = True if signature in {"b", "t", "i"} else 7
        faults.append((key, "type", signature, wrong_type))
        if signature == "t":
            faults.extend([
                (key, "value", signature, expected - 1),
                (key, "infinity", signature, float("inf")),
                (key, "zero", signature, 0),
                (key, "over-cap", signature, expected + 1),
            ])
        else:
            faults.append((key, "value", signature,
                           "terminate" if signature == "s" else expected + 1))
    return faults


@pytest.mark.parametrize("phase", ["pre-ready", "ready"])
@pytest.mark.parametrize("key,fault,signature,value", _controller_property_faults())
def test_controller_bounds_timeout_and_kill_properties_in_both_phases(
    phase, key, fault, signature, value,
):
    def mutate(interface, _count, properties):
        if interface == "org.freedesktop.systemd1.Service":
            if fault == "missing":
                properties.pop(key)
            else:
                properties[key] = Variant(signature, value)
        return properties

    with pytest.raises(UnitOperationFailed):
        asyncio.run(_inspector(
            FakeBus(phase=phase, mutate=mutate), phase=phase,
        ).inspect())


@pytest.mark.parametrize("phase", ["pre-ready", "ready"])
@pytest.mark.parametrize("key,signature,value", [
    # Exactly CAP_DAC_READ_SEARCH (bit 2): empty, wider, or different refuses.
    ("CapabilityBoundingSet", "t", 0),
    ("CapabilityBoundingSet", "t", 0x4 | 0x2),       # + CAP_DAC_OVERRIDE
    ("CapabilityBoundingSet", "t", 0x4 | (1 << 12)),  # + CAP_NET_ADMIN
    ("CapabilityBoundingSet", "t", 0x2),
    ("CapabilityBoundingSet", "t", 2**64 - 1),
    ("CapabilityBoundingSet", "s", "CAP_DAC_READ_SEARCH"),
    ("AmbientCapabilities", "t", 0x4),
    ("AmbientCapabilities", "t", 1),
    ("SupplementaryGroups", "as", []),
    ("SupplementaryGroups", "as", ["wheel"]),
    ("SupplementaryGroups", "as", ["azazel-operator", "wheel"]),
    ("SupplementaryGroups", "as", ["azazel-operator", "azazel-operator"]),
    ("SupplementaryGroups", "as", ["azazel-audit"]),
])
def test_controller_requires_exact_capability_bound_and_group(
    phase, key, signature, value,
):
    def mutate(interface, _count, properties):
        if interface == "org.freedesktop.systemd1.Service":
            properties[key] = Variant(signature, value)
        return properties

    with pytest.raises(UnitOperationFailed):
        asyncio.run(_inspector(
            FakeBus(phase=phase, mutate=mutate), phase=phase,
        ).inspect())


@pytest.mark.parametrize("phase", ["pre-ready", "ready"])
@pytest.mark.parametrize("key", [
    "CapabilityBoundingSet", "AmbientCapabilities", "SupplementaryGroups",
])
def test_controller_refuses_missing_capability_or_group_property(phase, key):
    def mutate(interface, _count, properties):
        if interface == "org.freedesktop.systemd1.Service":
            properties.pop(key)
        return properties

    with pytest.raises(UnitOperationFailed):
        asyncio.run(_inspector(
            FakeBus(phase=phase, mutate=mutate), phase=phase,
        ).inspect())


@pytest.mark.parametrize("fault", [
    "pid", "invocation", "control-group", "active-state", "sub-state",
    "job", "exec", "extra-command", "property-type", "unit-path",
    "invocation-type",
    "wrong-control-group-interface",
])
def test_mismatched_controller_projection_refuses(fault):
    async def scenario():
        def mutate(interface, count, props):
            if interface == UNIT_INTERFACE:
                if fault == "invocation":
                    props["InvocationID"] = Variant("ay", b"z" * 16)
                elif fault == "invocation-type":
                    props["InvocationID"] = Variant("s", INVOCATION_ID.hex())
                elif fault == "active-state":
                    props["ActiveState"] = Variant("s", "inactive")
                elif fault == "sub-state":
                    props["SubState"] = Variant("s", "dead")
                elif fault == "job":
                    props["Job"] = Variant(
                        "(uo)", [7, "/org/freedesktop/systemd1/job/7"]
                    )
                elif fault == "wrong-control-group-interface":
                    props["ControlGroup"] = Variant("s", CONTROL_GROUP)
            else:
                if fault == "pid":
                    props["MainPID"] = Variant("u", IDENTITY.pid + 1)
                elif fault == "control-group":
                    props["ControlGroup"] = Variant("s", "/system.slice/other.service")
                elif fault == "wrong-control-group-interface":
                    props.pop("ControlGroup")
                elif fault == "exec":
                    props["ExecStartEx"].value[0][0] = "/usr/bin/other"
                elif fault == "extra-command":
                    props[_COMMANDS[0]] = Variant(_EXEC_SIGNATURE, [["unexpected"]])
                elif fault == "property-type":
                    props["MainPID"] = Variant("s", str(IDENTITY.pid))
            return props

        bus = FakeBus(phase="ready", mutate=mutate,
                      wrong_path=fault == "unit-path")
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()
        assert bus.calls

    asyncio.run(scenario())


@pytest.mark.parametrize("phase", ["pre-ready", "ready"])
@pytest.mark.parametrize("fault", ["missing", "true", "wrong-signature", "wrong-type"])
def test_controller_requires_explicit_default_dependencies_false(phase, fault):
    def mutate(interface, _count, props):
        if interface != UNIT_INTERFACE:
            return props
        if fault == "missing":
            props.pop("DefaultDependencies")
        elif fault == "true":
            props["DefaultDependencies"] = Variant("b", True)
        elif fault == "wrong-signature":
            props["DefaultDependencies"] = Variant("s", "no")
        else:
            props["DefaultDependencies"] = Variant("b", 0)
        return props

    with pytest.raises(UnitOperationFailed):
        asyncio.run(_inspector(
            FakeBus(phase=phase, mutate=mutate), phase=phase,
        ).inspect())


@pytest.mark.parametrize("phase,fault", [
    ("pre-ready", "active-state"), ("pre-ready", "job"),
    ("ready", "job"),
])
def test_job_and_active_substate_must_match_requested_phase(phase, fault):
    async def scenario():
        def mutate(interface, _count, props):
            if interface == UNIT_INTERFACE and fault == "active-state":
                props["ActiveState"] = Variant("s", "active")
            elif interface == UNIT_INTERFACE and fault == "job":
                props["Job"] = Variant(
                    "(uo)", [0, "/"] if phase == "pre-ready" else
                    [7, "/org/freedesktop/systemd1/job/7"],
                )
            return props

        with pytest.raises(UnitOperationFailed):
            await _inspector(FakeBus(phase=phase, mutate=mutate), phase=phase).inspect()

    asyncio.run(scenario())


def test_controller_alias_order_is_normalized_across_both_snapshots():
    async def scenario():
        aliases = ["z-alias.service", UNIT, "a-alias.service"]
        result = await _inspector(FakeBus(
            aliases=aliases, reorder_aliases=True,
        )).inspect()
        assert result.identity == IDENTITY

    asyncio.run(scenario())


@pytest.mark.parametrize("aliases", [
    [], ["alias.service"], [UNIT, UNIT], [UNIT, 7],
    [UNIT, "bad/alias.service"], [UNIT, "x" * 257],
])
def test_controller_alias_lists_are_bounded_unique_and_canonical(aliases):
    async def scenario():
        with pytest.raises(UnitOperationFailed):
            await _inspector(FakeBus(aliases=aliases)).inspect()

    asyncio.run(scenario())


def test_valid_nonzero_exec_metadata_remains_well_typed():
    async def scenario():
        def mutate(interface, _count, props):
            if interface == "org.freedesktop.systemd1.Service":
                props["ExecStartEx"].value[0][3] = 1
            return props

        result = await _inspector(FakeBus(mutate=mutate)).inspect()
        assert result.identity == IDENTITY

    asyncio.run(scenario())


def test_unit_projection_is_frozen_before_service_reply_can_mutate_it():
    async def scenario():
        baseline = await _inspector(FakeBus()).inspect()
        bus = FakeBus(
            mutate_unit_during_service=True, unit_state_on_service="inactive",
        )
        result = await _inspector(bus).inspect()
        assert result.fingerprint == baseline.fingerprint
        assert bus.retained_unit_properties["ActiveState"].value == "inactive"

    asyncio.run(scenario())


def test_initially_invalid_unit_projection_cannot_be_laundered_by_later_reply():
    async def scenario():
        bus = FakeBus(
            unit_active_state="inactive", mutate_unit_during_service=True,
            unit_state_on_service="active",
        )
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()
        assert bus.service_calls == 0
        assert bus.retained_unit_properties["ActiveState"].value == "inactive"

    asyncio.run(scenario())


def test_exec_projection_is_detached_before_later_getunit_can_mutate_reply():
    async def scenario():
        baseline = await _inspector(FakeBus()).inspect()
        bus = FakeBus(mutate_exec_on_next_getunit=True)
        result = await _inspector(bus).inspect()
        assert result.fingerprint == baseline.fingerprint
        assert (bus.retained_service_replies[0]["ExecStartEx"].value[0][0]
                == "/usr/bin/changed-after-validation")

    asyncio.run(scenario())


@pytest.mark.parametrize("key", [
    "Environment", "EnvironmentFiles", "PassEnvironment", "UnsetEnvironment",
])
def test_environment_projection_detaches_reply_arrays_before_later_await(key):
    class MutatingBus(FakeBus):
        async def call(self, message):
            if (message.member == "GetUnit" and self.service_calls == 1
                    and self.retained_service_replies):
                self.retained_service_replies[0][key].value[:] = ["synthetic-late-mutation"]
            return await super().call(message)

    baseline = asyncio.run(_inspector(FakeBus()).inspect())
    bus = MutatingBus()
    observed = asyncio.run(_inspector(bus).inspect())
    assert observed == baseline
    assert bus.retained_service_replies[0][key].value == ["synthetic-late-mutation"]


@pytest.mark.parametrize("fault", ["owner", "profile"])
def test_owner_or_profile_drift_between_snapshots_refuses(fault):
    async def scenario():
        bus = FakeBus(
            owner_drift_at=2 if fault == "owner" else None,
            profile_drift_at=2 if fault == "profile" else None,
        )
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()

    asyncio.run(scenario())


def test_controller_inspection_is_single_use():
    async def scenario():
        bus = FakeBus()
        inspector = _inspector(bus)
        await inspector.inspect()
        count = len(bus.calls)
        with pytest.raises(UnitOperationFailed, match="fresh session"):
            await inspector.inspect()
        assert len(bus.calls) == count

    asyncio.run(scenario())


def test_inspector_rejects_bad_owner_digest_identity_and_phase_before_calls():
    bus = FakeBus()
    for changes in (
        {"owner": None},
        {"profile_digest": "sha256:bad"},
        {"identity": object()},
        {"phase": "starting"},
    ):
        with pytest.raises(ValueError):
            _inspector(bus, **changes)
    assert not bus.calls


def _condition_state_mutator(state):
    def mutate(interface, _count, props):
        if interface == UNIT_INTERFACE:
            props["Conditions"].value[0][4] = state
        return props
    return mutate


@pytest.mark.parametrize("phase", ["pre-ready", "ready"])
@pytest.mark.parametrize("state", [0, 1])
def test_controller_accepts_condition_state_untested_or_passed(phase, state):
    bus = FakeBus(phase=phase, mutate=_condition_state_mutator(state))
    asyncio.run(_inspector(bus, phase=phase).inspect())


@pytest.mark.parametrize("phase", ["pre-ready", "ready"])
@pytest.mark.parametrize("state", [-1, -2, 2, 3])
def test_controller_refuses_other_condition_states(phase, state):
    bus = FakeBus(phase=phase, mutate=_condition_state_mutator(state))
    with pytest.raises(UnitOperationFailed):
        asyncio.run(_inspector(bus, phase=phase).inspect())


def test_condition_state_is_not_projected():
    from azazel_nexus_runtime.bootstrap_controller import _unit_projection

    snapshots = []
    for state in (1, 0):
        props = FakeBus(phase="pre-ready")._unit_properties()
        props["Conditions"].value[0][4] = state
        snapshots.append(_unit_projection(props, IDENTITY, "pre-ready"))
    assert snapshots[0] == snapshots[1]
    assert snapshots[0]["Conditions"] == [[
        "ConditionPathExists", False, True,
        "/run/azazel-nexus-bootstrap/controller-used"]]
