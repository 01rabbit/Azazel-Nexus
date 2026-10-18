"""Read-only external prerequisite inspection for the fixed bootstrap pair."""

import asyncio
from dataclasses import replace
import hashlib
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_loaded_policy import decode_loaded_bootstrap_policy
from azazel_nexus_runtime.bootstrap_prerequisites import (
    BootstrapPrerequisiteInspector,
)
from azazel_nexus_runtime.bootstrap_systemd_profile import (
    bootstrap_systemd_profile_digest,
    observe_bootstrap_systemd_profile,
)
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.systemd_bus import (
    MANAGER_INTERFACE,
    MANAGER_PATH,
    PROPERTIES_INTERFACE,
    UNIT_INTERFACE,
)
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed
from test_runtime_bootstrap_loaded import OWNER, Variant, _object_path, _reply
from test_runtime_bootstrap_loaded_policy import (
    _document, _pinned, _raw, SETTINGS,
)
from test_runtime_bootstrap_masked import PROFILE_PATHS, PROFILE_VERSION


PROFILE = observe_bootstrap_systemd_profile(
    version=PROFILE_VERSION, unit_path=PROFILE_PATHS,
)
PROFILE_DIGEST = bootstrap_systemd_profile_digest(PROFILE)
EXTERNAL = ("basic.target", "local-fs.target")


def _policy(names=EXTERNAL, *, conflicts=(), conflict_relation="Conflicts",
            conflict_unit=UnitKey.AUDITD):
    document = _document()
    document["systemd_profile_digest"] = PROFILE_DIGEST
    units = document["units"]
    audit_dependencies = units[UNIT_NAMES[UnitKey.AUDITD]]["dependencies"]
    audit_dependencies["Wants"] = sorted(names)
    audit_dependencies["After"] = sorted(
        set(audit_dependencies["After"]) | set(names)
    )
    units[UNIT_NAMES[conflict_unit]]["dependencies"][conflict_relation] = sorted(conflicts)
    for record in units.values():
        record["service_settings"] = {
            **SETTINGS,
            "TimeoutStartUSec": 101,
            "TimeoutStopUSec": 202,
            "RuntimeMaxUSec": 303,
            "WatchdogUSec": 404,
        }
    raw = _raw(document)
    return decode_loaded_bootstrap_policy(
        raw,
        prestart_policy=replace(
            _pinned(raw, profile_digest=PROFILE_DIGEST),
            loaded_policy_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        ),
    )


class FakeBus:
    def __init__(self, *, names=EXTERNAL, state="active", job=(0, "/"),
                 mutate=None, owner_drift_at=None, profile_drift_at=None,
                 owner_drift_after_profile_at=None, aliases=None, missing=None,
                 states=None, jobs=None):
        self.names = tuple(sorted(names))
        self.state = state
        self.job = job
        self.mutate = mutate
        self.owner_drift_at = owner_drift_at
        self.profile_drift_at = profile_drift_at
        self.owner_drift_after_profile_at = owner_drift_after_profile_at
        self.owner_changed = False
        self.aliases = aliases
        self.missing = missing
        self.states = {} if states is None else states
        self.jobs = {} if jobs is None else jobs
        self.calls = []
        self.owner_calls = 0
        self.profile_calls = 0
        self.property_calls = 0

    async def call(self, message):
        self.calls.append(message)
        if message.destination == "org.freedesktop.DBus":
            assert message.member == "GetNameOwner"
            self.owner_calls += 1
            owner = ":1.99" if (
                self.owner_changed or (self.owner_drift_at is not None
                                       and self.owner_calls >= self.owner_drift_at)
            ) else OWNER
            return _reply("s", owner, sender="org.freedesktop.DBus")

        assert message.destination == OWNER
        if (message.member == "GetAll" and message.path == MANAGER_PATH
                and message.interface == PROPERTIES_INTERFACE):
            assert message.body == [MANAGER_INTERFACE]
            self.profile_calls += 1
            if self.profile_calls == self.owner_drift_after_profile_at:
                self.owner_changed = True
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
            assert message.interface == MANAGER_INTERFACE
            name = message.body[0]
            path = _object_path(name)
            if name == self.missing:
                path += "_missing"
            return _reply("o", path)

        assert message.member == "GetAll"
        assert message.interface == PROPERTIES_INTERFACE
        assert message.body == [UNIT_INTERFACE]
        name = next(name for name in self.names
                    if message.path == _object_path(name))
        self.property_calls += 1
        values = {
            "Id": Variant("s", name),
            "Names": Variant("as", [name] if self.aliases is None else self.aliases(name)),
            "Following": Variant("s", ""),
            "LoadState": Variant("s", "loaded"),
            "ActiveState": Variant("s", self.states.get(name, self.state)),
            "Job": Variant("(uo)", list(self.jobs.get(name, self.job))),
            "NeedDaemonReload": Variant("b", False),
        }
        if self.mutate is not None:
            values = self.mutate(self.property_calls, name, values)
        return _reply("a{sv}", values)


def _client(bus, policy=None, *, owner=OWNER, timeout=5.0):
    return BootstrapPrerequisiteInspector(
        bus=bus,
        message_factory=lambda **fields: SimpleNamespace(**fields),
        message_type=SimpleNamespace(METHOD_RETURN=1, SIGNAL=4),
        timeout_seconds=timeout,
        expected_owner=owner,
        policy=_policy() if policy is None else policy,
    )


def test_active_external_prerequisites_are_observed_twice_read_only():
    async def scenario():
        bus = FakeBus()
        policy = _policy()
        result = await _client(bus, policy).inspect()
        assert result.owner == OWNER
        assert result.policy_digest == policy.digest
        assert result.units == EXTERNAL
        assert result.fingerprint.startswith("sha256:")
        assert bus.property_calls == 2 * len(EXTERNAL)
        assert bus.profile_calls == 3
        assert bus.owner_calls == 3
        assert all(call.member not in {
            "StartUnit", "StopUnit", "RestartUnit", "EnableUnitFiles",
            "UnmaskUnitFiles", "Reload",
        } for call in bus.calls)

    asyncio.run(scenario())


def test_loaded_conflict_target_is_observed_inactive_and_returned_separately():
    async def scenario():
        conflicts = ("rescue.target",)
        policy = _policy(conflicts=conflicts)
        bus = FakeBus(names=(*EXTERNAL, *conflicts), state="active",
                      states={"rescue.target": "inactive"})

        result = await _client(bus, policy).inspect()

        assert result.units == EXTERNAL
        assert result.conflicts == conflicts
        requests = [call.body[0] for call in bus.calls if call.member == "GetUnit"]
        assert requests == [*EXTERNAL, *conflicts, *EXTERNAL, *conflicts]

    asyncio.run(scenario())


def test_literal_shutdown_target_is_accepted_when_loaded_inactive():
    async def scenario():
        policy = _policy(conflicts=("shutdown.target",))
        bus = FakeBus(names=(*EXTERNAL, "shutdown.target"),
                      states={"shutdown.target": "inactive"})

        result = await _client(bus, policy).inspect()

        assert result.units == EXTERNAL
        assert result.conflicts == ("shutdown.target",)

    asyncio.run(scenario())


@pytest.mark.parametrize("fault", ["active", "pending-job"])
def test_active_or_pending_conflict_target_refuses(fault):
    async def scenario():
        conflicts = ("rescue.target",)
        policy = _policy(conflicts=conflicts)
        states = {"rescue.target": "active"} if fault == "active" else {}
        jobs = ({"rescue.target": (9, "/org/freedesktop/systemd1/job/9")}
                if fault == "pending-job" else {})
        bus = FakeBus(
            names=(*EXTERNAL, *conflicts), state="active", states=states, jobs=jobs,
        )

        with pytest.raises(UnitOperationFailed):
            await _client(bus, policy).inspect()
        assert bus.calls

    asyncio.run(scenario())


def test_conflictedby_inverse_only_is_included_in_inactive_observation():
    async def scenario():
        inverse = ("maintenance.target",)
        policy = _policy(conflicts=inverse, conflict_relation="ConflictedBy")
        bus = FakeBus(names=(*EXTERNAL, *inverse), state="active",
                      states={"maintenance.target": "inactive"})

        result = await _client(bus, policy).inspect()

        assert result.conflicts == inverse
        assert [call.body[0] for call in bus.calls if call.member == "GetUnit"] == [
            *EXTERNAL, *inverse, *EXTERNAL, *inverse,
        ]

    asyncio.run(scenario())


def test_positive_conflict_overlap_across_helpers_refuses_before_bus_io():
    bus = FakeBus(names=())
    # The shared target remains a positive Wants edge of auditd and is a
    # Conflicts edge of commissiond: the combined policy must reject it.
    policy = _policy(
        names=("shared.target",), conflicts=("shared.target",),
        conflict_unit=UnitKey.COMMISSIOND,
    )

    with pytest.raises((ValueError, ApprovalRefused)):
        _client(bus, policy)
    assert bus.calls == []


@pytest.mark.parametrize("forbidden", [
    "azazel-activated.service", UNIT_NAMES[UnitKey.AUDITD],
    UNIT_NAMES[UnitKey.COMMISSIOND],
])
def test_conflict_with_controller_or_protected_pair_refuses_before_bus_io(forbidden):
    bus = FakeBus(names=())
    with pytest.raises((ValueError, ApprovalRefused)):
        policy = _policy(names=(), conflicts=(forbidden,))
        _client(bus, policy)
    assert bus.calls == []


def test_positive_and_conflict_combined_bound_is_sixty_four():
    positives = tuple(f"positive-{index:02d}.target" for index in range(32))
    conflicts = tuple(f"conflict-{index:02d}.target" for index in range(33))
    policy = _policy(names=positives, conflicts=conflicts)
    bus = FakeBus(names=(*positives, *conflicts))

    with pytest.raises(ValueError, match="prerequisite"):
        _client(bus, policy)
    assert bus.calls == []


def test_positive_and_conflict_combined_bound_accepts_exactly_sixty_four():
    positives = tuple(f"positive-{index:02d}.target" for index in range(32))
    conflicts = tuple(f"conflict-{index:02d}.target" for index in range(32))
    policy = _policy(names=positives, conflicts=conflicts)
    bus = FakeBus(names=(*positives, *conflicts),
                  states={name: "inactive" for name in conflicts})

    async def scenario():
        observed = await _client(bus, policy).inspect()
        assert observed.units == positives
        assert observed.conflicts == conflicts

    asyncio.run(scenario())


def test_conflict_projection_drift_between_snapshots_refuses():
    async def scenario():
        conflicts = ("rescue.target",)
        policy = _policy(names=(), conflicts=conflicts)

        def mutate(count, _name, props):
            if count == 2:
                props["Names"] = Variant("as", ["rescue.target", "rescue-alias.target"])
            return props

        bus = FakeBus(names=conflicts, states={"rescue.target": "inactive"}, mutate=mutate)
        with pytest.raises(UnitOperationFailed, match="changed"):
            await _client(bus, policy).inspect()
        assert bus.property_calls == 2

    asyncio.run(scenario())


def test_empty_external_set_still_pins_owner_and_profile():
    async def scenario():
        bus = FakeBus(names=())
        result = await _client(bus, _policy(names=())).inspect()
        assert result.units == ()
        assert bus.owner_calls == 3 and bus.profile_calls == 3
        assert not any(call.member == "GetUnit" for call in bus.calls)

    asyncio.run(scenario())


def test_prerequisite_paths_escape_underscores_and_leading_digits():
    async def scenario():
        names = ("1example.service", "foo_bar.service")
        bus = FakeBus(names=names)
        observed = await _client(bus, _policy(names=names)).inspect()
        assert observed.units == names
        assert {call.path for call in bus.calls if call.member == "GetAll"
                and call.body == [UNIT_INTERFACE]} == {
            "/org/freedesktop/systemd1/unit/_31example_2eservice",
            "/org/freedesktop/systemd1/unit/foo_5fbar_2eservice",
        }

    asyncio.run(scenario())


def test_stable_aliases_are_sorted_in_projection_not_requested_as_units():
    async def scenario():
        policy = _policy()
        def aliases(name):
            return ["z-alias.service", name, "a-alias.service"]

        first_bus = FakeBus(aliases=aliases)
        second_bus = FakeBus(aliases=lambda name: list(reversed(aliases(name))))
        first = await _client(first_bus, policy).inspect()
        second = await _client(second_bus, policy).inspect()
        assert first.fingerprint == second.fingerprint
        requested = [call.body[0] for call in first_bus.calls
                     if call.member == "GetUnit"]
        assert requested == [name for _ in range(2) for name in EXTERNAL]

    asyncio.run(scenario())


@pytest.mark.parametrize("fault", [
    "inactive", "job-running", "job-malformed", "alias", "missing",
    "mutation", "owner-drift", "profile-drift", "owner-during-final-profile",
    "duplicate-alias", "missing-canonical-alias", "alias-type", "alias-drift",
])
def test_prerequisite_drift_and_nonready_projection_refuse(fault):
    async def scenario():
        mutate = None
        state, job, missing = "active", (0, "/"), None
        owner_drift_at = profile_drift_at = owner_after_profile_at = None
        aliases = None
        if fault == "inactive":
            state = "inactive"
        elif fault == "job-running":
            job = (9, "/org/freedesktop/systemd1/job/9")
        elif fault == "job-malformed":
            job = (True, "/")
        elif fault == "alias":
            def mutate(_count, _name, props):
                return {**props, "Names": Variant("as", ["alias.target"])}
        elif fault == "missing":
            missing = EXTERNAL[0]
        elif fault == "mutation":
            def mutate(count, name, props):
                if count == 3:
                    props["NeedDaemonReload"] = Variant("b", True)
                return props
        elif fault == "owner-drift":
            owner_drift_at = 2
        elif fault == "profile-drift":
            profile_drift_at = 2
        elif fault == "owner-during-final-profile":
            owner_after_profile_at = 3
        elif fault == "duplicate-alias":
            def aliases(name):
                return [name, name]
        elif fault == "missing-canonical-alias":
            def aliases(_name):
                return ["alias.service"]
        elif fault == "alias-type":
            def aliases(name):
                return [name, 7]
        elif fault == "alias-drift":
            def aliases(name):
                return [name, "alias-one.service"]

            def mutate(count, _name, props):
                if count == 3:
                    props["Names"] = Variant("as", [
                        props["Names"].value[0], "alias-two.service",
                    ])
                return props

        bus = FakeBus(
            state=state, job=job, missing=missing, mutate=mutate,
            owner_drift_at=owner_drift_at, profile_drift_at=profile_drift_at,
            owner_drift_after_profile_at=owner_after_profile_at,
            aliases=aliases,
        )
        with pytest.raises(UnitOperationFailed):
            await _client(bus).inspect()
        assert bus.calls

    asyncio.run(scenario())


def test_prerequisite_inspector_is_single_use_even_after_success():
    async def scenario():
        bus = FakeBus()
        inspector = _client(bus)
        await inspector.inspect()
        count = len(bus.calls)
        with pytest.raises(UnitOperationFailed, match="fresh session"):
            await inspector.inspect()
        assert len(bus.calls) == count

    asyncio.run(scenario())


def test_constructor_requires_enclosing_owner_and_fixed_policy():
    bus = FakeBus()
    with pytest.raises(ValueError, match="owner"):
        _client(bus, owner=None)
    with pytest.raises(ValueError, match="policy"):
        _client(bus, policy=object())
    malformed_profile = replace(_policy(), systemd_profile_digest="sha256:not-a-digest")
    with pytest.raises(ValueError, match="profile digest"):
        _client(bus, policy=malformed_profile)
    assert not bus.calls


def test_external_prerequisite_bound_refuses_over_sixty_four_names():
    names = tuple(f"external-{index:02d}.target" for index in range(65))
    with pytest.raises(ValueError, match="prerequisite"):
        _client(FakeBus(names=names), _policy(names=names))
