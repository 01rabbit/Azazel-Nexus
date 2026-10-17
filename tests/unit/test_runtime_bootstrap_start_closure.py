"""Read-only bounded dependency-closure inspection for bootstrap starts."""

import asyncio
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_start_closure import (
    BootstrapStartClosureInspector,
)
from azazel_nexus_runtime.bootstrap_loaded_policy import _ACTIVATION_CHANNELS
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
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed
from test_runtime_bootstrap_loaded import OWNER, Variant, _object_path, _reply
from test_runtime_bootstrap_masked import PROFILE_PATHS, PROFILE_VERSION


CONTROLLER = "azazel-activated.service"
AUDIT = UNIT_NAMES[UnitKey.AUDITD]
COMMISSION = UNIT_NAMES[UnitKey.COMMISSIOND]
ROOTS = (CONTROLLER, AUDIT, COMMISSION)
PROFILE = observe_bootstrap_systemd_profile(
    version=PROFILE_VERSION, unit_path=PROFILE_PATHS,
)
PROFILE_DIGEST = bootstrap_systemd_profile_digest(PROFILE)
_UNIT = "org.freedesktop.systemd1.Unit"
_DEPENDENCIES = (
    "After", "Before", "Requires", "Wants", "BindsTo", "Requisite", "Upholds",
    "PartOf", "Conflicts", "ConflictedBy", "OnFailure", "OnSuccess", "Triggers",
    "TriggeredBy", "PropagatesStopTo", "StopPropagatedFrom", "JoinsNamespaceOf",
    "RequiredBy", "RequisiteOf", "WantedBy", "BoundBy", "UpheldBy", "ConsistsOf",
    "OnSuccessOf", "OnFailureOf", "PropagatesReloadTo", "ReloadPropagatedFrom",
)


def _base_graph():
    return {
        CONTROLLER: {},
        AUDIT: {"Requisite": [CONTROLLER]},
        COMMISSION: {"Requisite": [CONTROLLER], "Requires": [AUDIT]},
    }


class FakeBus:
    def __init__(self, *, graph=None, mutate=None, owner_drift_at=None,
                 profile_drift_at=None, states=None, jobs=None):
        self.graph = _base_graph() if graph is None else graph
        self.mutate = mutate
        self.owner_drift_at = owner_drift_at
        self.profile_drift_at = profile_drift_at
        self.states = {} if states is None else states
        self.jobs = {} if jobs is None else jobs
        self.calls = []
        self.property_reads = {}
        self.profile_reads = 0
        self.owner_reads = 0

    async def call(self, message):
        self.calls.append(message)
        if message.destination == "org.freedesktop.DBus":
            assert message.member == "GetNameOwner"
            self.owner_reads += 1
            owner = ":1.99" if (
                self.owner_drift_at is not None
                and self.owner_reads >= self.owner_drift_at
            ) else OWNER
            return _reply("s", owner, sender="org.freedesktop.DBus")

        assert message.destination == OWNER
        if (message.member == "GetAll" and message.path == MANAGER_PATH
                and message.interface == PROPERTIES_INTERFACE):
            assert message.body == [MANAGER_INTERFACE]
            self.profile_reads += 1
            version = (
                "257.13-2~deb13u1"
                if self.profile_drift_at is not None
                and self.profile_reads >= self.profile_drift_at
                else PROFILE_VERSION
            )
            return _reply("a{sv}", {
                "Version": Variant("s", version),
                "UnitPath": Variant("as", list(PROFILE_PATHS)),
            })

        if message.member == "GetUnit":
            name = message.body[0]
            if name not in self.graph:
                raise AssertionError(f"unexpected closure unit {name}")
            return _reply("o", _object_path(name))

        assert message.member == "GetAll"
        assert message.interface == PROPERTIES_INTERFACE
        assert message.body == [UNIT_INTERFACE]
        name = next(name for name in self.graph if message.path == _object_path(name))
        count = self.property_reads.get(name, 0) + 1
        self.property_reads[name] = count
        state = self.states.get(name, "active")
        job = self.jobs.get(name, [0, "/"])
        properties = {
            "Id": Variant("s", name),
            "Names": Variant("as", [name]),
            "Following": Variant("s", ""),
            "LoadState": Variant("s", "loaded"),
            "NeedDaemonReload": Variant("b", False),
            "DefaultDependencies": Variant("b", False) if name in ROOTS else Variant("b", True),
            "ActiveState": Variant("s", state),
            "Job": Variant("(uo)", list(job)),
        }
        properties.update({key: Variant("as", []) for key in _DEPENDENCIES})
        for relation, names in self.graph[name].items():
            properties[relation] = Variant("as", list(names))
        if self.mutate is not None:
            properties = self.mutate(name, count, properties)
        return _reply("a{sv}", properties)


def _inspector(bus, *, owner=OWNER, digest=PROFILE_DIGEST):
    return BootstrapStartClosureInspector(
        bus=bus,
        message_factory=lambda **fields: SimpleNamespace(**fields),
        message_type=SimpleNamespace(METHOD_RETURN=1, SIGNAL=4),
        timeout_seconds=0.2,
        expected_owner=owner,
        systemd_profile_digest=digest,
    )


def test_inspects_fixed_roots_and_recursive_graph_twice_read_only():
    async def scenario():
        bus = FakeBus()
        observation = await _inspector(bus).inspect()

        assert observation.owner == OWNER
        assert observation.profile_digest == PROFILE_DIGEST
        assert observation.units == tuple(sorted(ROOTS))
        assert observation.fingerprint.startswith("sha256:")
        assert [call.member for call in bus.calls].count("GetUnit") == 2 * len(ROOTS)
        assert {call.member for call in bus.calls} <= {"GetNameOwner", "GetAll", "GetUnit"}
        assert all(call.member != "GetAll" or call.body != ["org.freedesktop.systemd1.Service"]
                   for call in bus.calls)

    asyncio.run(scenario())


def test_cycles_are_bounded_by_seen_units_and_return_sorted_closure():
    async def scenario():
        graph = _base_graph()
        graph[CONTROLLER]["Wants"] = ["basic.target"]
        graph["basic.target"] = {"Wants": [CONTROLLER]}
        bus = FakeBus(graph=graph)

        observation = await _inspector(bus).inspect()

        assert observation.units == tuple(sorted(graph))
        assert len([call for call in bus.calls if call.member == "GetUnit"]) == 2 * len(graph)

    asyncio.run(scenario())


@pytest.mark.parametrize("relation", sorted(_ACTIVATION_CHANNELS))
def test_unsupported_activation_effect_relations_refuse(relation):
    async def scenario():
        graph = _base_graph()
        graph[AUDIT][relation] = ["helper.service"]
        bus = FakeBus(graph=graph)

        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()
        assert not any(call.member == "GetUnit" and call.body == ["helper.service"]
                       for call in bus.calls)

    asyncio.run(scenario())


@pytest.mark.parametrize("suffix", [
    "service", "socket", "timer", "path", "automount", "swap", "scope",
])
def test_external_effect_units_of_disallowed_types_refuse(suffix):
    async def scenario():
        graph = _base_graph()
        name = f"external.{suffix}"
        graph[CONTROLLER]["Wants"] = [name]
        graph[name] = {}
        bus = FakeBus(graph=graph)

        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()

    asyncio.run(scenario())


@pytest.mark.parametrize("suffix", ["target", "mount", "slice"])
def test_external_nonservice_unit_types_are_allowed(suffix):
    async def scenario():
        graph = _base_graph()
        name = f"external.{suffix}"
        graph[CONTROLLER]["Wants"] = [name]
        graph[name] = {}
        bus = FakeBus(graph=graph)

        observation = await _inspector(bus).inspect()
        assert name in observation.units

    asyncio.run(scenario())


@pytest.mark.parametrize("root", ROOTS)
@pytest.mark.parametrize("fault", ["missing-default", "default-true", "default-signature", "default-type"])
def test_roots_require_default_dependencies_disabled(root, fault):
    async def scenario():
        graph = _base_graph()

        def mutate(name, _count, props):
            if name == root:
                if fault == "missing-default":
                    props.pop("DefaultDependencies")
                elif fault == "default-true":
                    props["DefaultDependencies"] = Variant("b", True)
                elif fault == "default-signature":
                    props["DefaultDependencies"] = Variant("s", "no")
                else:
                    props["DefaultDependencies"] = Variant("b", 0)
            return props

        with pytest.raises(UnitOperationFailed):
            await _inspector(FakeBus(graph=graph, mutate=mutate)).inspect()

    asyncio.run(scenario())


@pytest.mark.parametrize("fault", ["wrong-id", "missing-canonical-alias", "following", "not-loaded", "reload"])
def test_unit_identity_and_loaded_state_are_pinned(fault):
    async def scenario():
        graph = _base_graph()
        graph[CONTROLLER]["Wants"] = ["basic.target"]
        graph["basic.target"] = {}

        def mutate(name, _count, props):
            if name == "basic.target":
                if fault == "wrong-id":
                    props["Id"] = Variant("s", "other.target")
                elif fault == "missing-canonical-alias":
                    props["Names"] = Variant("as", ["other.target"])
                elif fault == "following":
                    props["Following"] = Variant("s", "other.target")
                elif fault == "not-loaded":
                    props["LoadState"] = Variant("s", "not-found")
                else:
                    props["NeedDaemonReload"] = Variant("b", True)
            return props

        with pytest.raises(UnitOperationFailed):
            await _inspector(FakeBus(graph=graph, mutate=mutate)).inspect()

    asyncio.run(scenario())


@pytest.mark.parametrize("state", ["inactive", "activating", "active"])
def test_root_states_are_allowed_and_controller_start_job_is_validated(state):
    async def scenario():
        job = [0, "/"] if state != "activating" else [17, "/org/freedesktop/systemd1/job/17"]
        bus = FakeBus(states={CONTROLLER: state}, jobs={CONTROLLER: job})

        observation = await _inspector(bus).inspect()
        assert observation.owner == OWNER

    asyncio.run(scenario())


@pytest.mark.parametrize("bad", ["inactive", "failed"])
def test_external_dependency_must_be_active(bad):
    async def scenario():
        graph = _base_graph()
        graph[CONTROLLER]["Wants"] = ["basic.target"]
        graph["basic.target"] = {}
        bus = FakeBus(graph=graph, states={"basic.target": bad})
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()

    asyncio.run(scenario())


@pytest.mark.parametrize("job", [[7, "/org/freedesktop/systemd1/job/7"], [0, "/"]])
def test_external_dependency_must_be_idle(job):
    async def scenario():
        graph = _base_graph()
        graph[CONTROLLER]["Wants"] = ["basic.target"]
        graph["basic.target"] = {}
        bus = FakeBus(graph=graph, jobs={"basic.target": job})
        if job == [0, "/"]:
            await _inspector(bus).inspect()
        else:
            with pytest.raises(UnitOperationFailed):
                await _inspector(bus).inspect()

    asyncio.run(scenario())


@pytest.mark.parametrize("fault", ["owner", "profile", "snapshot"])
def test_owner_profile_and_graph_must_remain_stable(fault):
    async def scenario():
        if fault == "owner":
            bus = FakeBus(owner_drift_at=2)
        elif fault == "profile":
            bus = FakeBus(profile_drift_at=2)
        else:
            def mutate(name, count, props):
                if name == "basic.target" and count == 2:
                    props["ActiveState"] = Variant("s", "inactive")
                return props
            graph = _base_graph()
            graph[CONTROLLER]["Wants"] = ["basic.target", "network.target"]
            graph["basic.target"] = {}
            graph["network.target"] = {}
            original_mutate = mutate

            def mutate_edge(name, count, props):
                props = original_mutate(name, count, props)
                if name == AUDIT and count == 2:
                    props["Wants"] = Variant("as", ["network.target"])
                return props

            bus = FakeBus(graph=graph, mutate=mutate_edge)

        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()

    asyncio.run(scenario())


def test_inspector_is_single_use():
    async def scenario():
        bus = FakeBus()
        inspector = _inspector(bus)
        await inspector.inspect()
        call_count = len(bus.calls)
        with pytest.raises(UnitOperationFailed):
            await inspector.inspect()
        assert len(bus.calls) == call_count

    asyncio.run(scenario())


@pytest.mark.parametrize(("external_count", "accepted"), [(61, True), (62, False)])
def test_total_discovered_unit_bound(external_count, accepted):
    async def scenario():
        names = [f"node-{index:02d}.target" for index in range(external_count)]
        graph = {
            CONTROLLER: {"Wants": names},
            AUDIT: {"Requisite": [CONTROLLER]},
            COMMISSION: {"Requisite": [CONTROLLER], "Requires": [AUDIT]},
            **{name: {} for name in names},
        }
        bus = FakeBus(graph=graph)
        if accepted:
            observation = await _inspector(bus).inspect()
            assert len(observation.units) == 64
        else:
            with pytest.raises(UnitOperationFailed):
                await _inspector(bus).inspect()

    asyncio.run(scenario())


def test_dependency_list_over_256_refuses():
    async def scenario():
        names = [f"node-{index:03d}.target" for index in range(257)]
        graph = _base_graph()
        graph[CONTROLLER]["Wants"] = names
        graph.update({name: {} for name in names})
        with pytest.raises(UnitOperationFailed):
            await _inspector(FakeBus(graph=graph)).inspect()

    asyncio.run(scenario())


def test_total_edge_bound_is_enforced_on_complete_walk():
    async def scenario():
        names = [f"node-{index:02d}.target" for index in range(61)]
        all_names = [*ROOTS, *names]
        graph = {
            name: {relation: all_names for relation in ("Requires", "Wants", "BindsTo")}
            for name in all_names
        }
        with pytest.raises(UnitOperationFailed):
            await _inspector(FakeBus(graph=graph)).inspect()

    asyncio.run(scenario())


@pytest.mark.parametrize("root", ROOTS)
def test_root_may_be_active_with_a_well_formed_pending_job(root):
    async def scenario():
        job = [23, "/org/freedesktop/systemd1/job/23"]
        observation = await _inspector(
            FakeBus(jobs={root: job})
        ).inspect()
        assert root in observation.units

    asyncio.run(scenario())
