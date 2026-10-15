"""Device-follower inventory coverage for the bootstrap start closure."""

import asyncio
from copy import deepcopy
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.units import UnitOperationFailed
from azazel_nexus_runtime.bootstrap_start_closure import BootstrapStartClosureInspector
from test_runtime_bootstrap_loaded import OWNER, Variant, _object_path, _reply
from test_runtime_bootstrap_start_closure import (
    CONTROLLER, PROFILE_DIGEST, ROOTS, FakeBus as GraphFakeBus, _base_graph, _inspector,
)


DEVICE_INTERFACE = "org.freedesktop.systemd1.Device"
MANAGER_INTERFACE = "org.freedesktop.systemd1.Manager"
MANAGER_PATH = "/org/freedesktop/systemd1"
PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties"
DEVICE_SIGNATURE = "a(ssssssouso)"
DEVICE_NAMES = ("disk-primary.device", "disk-alias.device")
SYSFS = "/sys/devices/virtual/block/dm-0"
_MISSING = object()


def _device_row(name, *, following="", sysfs=SYSFS, state="active", job=0,
                kind="", job_path="/"):
    return [
        name, f"device {name}", "loaded", state, "plugged", following,
        _object_path(name), job, kind, job_path,
    ]


class DeviceFakeBus(GraphFakeBus):
    """Existing graph fake plus only ListUnitsByPatterns/Device properties."""

    def __init__(self, *, graph=None, mutate=None, inventories=None,
                 sysfs_paths=None):
        super().__init__(graph=graph, mutate=mutate)
        self.inventories = inventories or [[
            _device_row(DEVICE_NAMES[0]),
            _device_row(DEVICE_NAMES[1], following=DEVICE_NAMES[0]),
        ]]
        self.sysfs_paths = sysfs_paths or {name: SYSFS for name in DEVICE_NAMES}
        self.inventory_reads = 0
        self.device_property_reads = []
        self.device_rows = {
            row[0]: row for inventory in self.inventories for row in inventory
            if type(row) is list and len(row) == 10 and type(row[0]) is str
        }
        self.device_followings = {
            row[0]: row[5] for row in self.device_rows.values()
        }
        original_mutate = self.mutate

        def mutate_device_unit(name, count, properties):
            if original_mutate is not None:
                properties = original_mutate(name, count, properties)
            if name in self.device_followings:
                properties["Following"] = Variant("s", self.device_followings[name])
            return properties

        self.mutate = mutate_device_unit

    async def call(self, message):
        if message.member == "ListUnitsByPatterns":
            self.calls.append(message)
            assert message.destination == OWNER
            assert message.path == MANAGER_PATH
            assert message.interface == MANAGER_INTERFACE
            assert message.signature == "asas"
            assert message.body == [[], ["*.device"]]
            self.inventory_reads += 1
            index = min(self.inventory_reads - 1, len(self.inventories) - 1)
            return _reply(DEVICE_SIGNATURE, deepcopy(self.inventories[index]))

        if (message.member == "GetAll" and message.body == [DEVICE_INTERFACE]
                and message.interface == PROPERTIES_INTERFACE):
            self.calls.append(message)
            assert message.destination == OWNER
            name = next((unit for unit in self.device_rows
                         if message.path == _object_path(unit)), None)
            assert name is not None
            self.device_property_reads.append(name)
            sysfs = self.sysfs_paths.get(name, "")
            if type(sysfs) is list:
                sysfs = sysfs[min(self.device_property_reads.count(name) - 1, len(sysfs) - 1)]
            props = {} if sysfs is _MISSING else {
                "SysFSPath": sysfs if type(sysfs) is Variant else Variant("s", sysfs),
            }
            return _reply("a{sv}", props)

        if message.member == "GetUnit" and message.body[0] in self.device_rows:
            self.calls.append(message)
            name = message.body[0]
            assert message.signature == "s"
            return _reply("o", _object_path(name))

        return await super().call(message)


def _graph(*, include_alias=True, hidden_service=False):
    graph = _base_graph()
    graph[CONTROLLER]["Wants"] = [DEVICE_NAMES[0]]
    graph[DEVICE_NAMES[0]] = {}
    if include_alias:
        graph[DEVICE_NAMES[1]] = {"Wants": ["disk-ready.target"]}
        graph["disk-ready.target"] = {}
    else:
        graph[DEVICE_NAMES[1]] = {}
    if hidden_service:
        graph[DEVICE_NAMES[1]] = {"Wants": ["hidden-helper.service"]}
    return graph


def _slow_inventory_inspector(bus):
    return BootstrapStartClosureInspector(
        bus=bus,
        message_factory=lambda **fields: SimpleNamespace(**fields),
        message_type=SimpleNamespace(METHOD_RETURN=1, SIGNAL=4),
        timeout_seconds=5.0,
        expected_owner=OWNER,
        systemd_profile_digest=PROFILE_DIGEST,
    )


def test_same_sysfs_followers_join_graph_and_both_forward_graphs_are_walked():
    async def scenario():
        graph = _graph()
        bus = DeviceFakeBus(graph=graph)

        observation = await _inspector(bus).inspect()

        assert observation.units == tuple(sorted({*ROOTS, *DEVICE_NAMES, "disk-ready.target"}))
        assert bus.inventory_reads == 4
        assert bus.device_property_reads.count(DEVICE_NAMES[0]) == 4
        assert bus.device_property_reads.count(DEVICE_NAMES[1]) == 4
        assert all(call.member in {
            "GetNameOwner", "GetAll", "GetUnit", "ListUnitsByPatterns",
        } for call in bus.calls)
        assert all(call.body != ["org.freedesktop.systemd1.Service"] for call in bus.calls)
        assert SYSFS not in repr(observation)

    asyncio.run(scenario())


def test_hidden_sibling_wants_service_refuses():
    async def scenario():
        bus = DeviceFakeBus(graph=_graph(hidden_service=True))
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()
        assert bus.inventory_reads >= 1

    asyncio.run(scenario())


@pytest.mark.parametrize("fault", ["changed-sysfs", "removed-sibling", "changed-following"])
def test_repeated_inventory_drift_refuses(fault):
    async def scenario():
        first = [
            _device_row(DEVICE_NAMES[0]),
            _device_row(DEVICE_NAMES[1], following=DEVICE_NAMES[0]),
        ]
        second = deepcopy(first)
        if fault == "removed-sibling":
            second.pop()
        elif fault == "changed-following":
            second[1][5] = ""
        bus = DeviceFakeBus(
            graph=_graph(), inventories=[first, second],
            sysfs_paths={
                DEVICE_NAMES[0]: SYSFS,
                DEVICE_NAMES[1]: [SYSFS, "/sys/devices/virtual/block/dm-1"]
                if fault == "changed-sysfs" else SYSFS,
            },
        )
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()

    asyncio.run(scenario())


@pytest.mark.parametrize("fault", ["row-shape", "duplicate-name", "duplicate-path", "bad-job-path"])
def test_malformed_inventory_records_refuse(fault):
    async def scenario():
        records = [
            _device_row(DEVICE_NAMES[0]),
            _device_row(DEVICE_NAMES[1], following=DEVICE_NAMES[0]),
        ]
        if fault == "row-shape":
            records[0].pop()
        elif fault == "duplicate-name":
            records[1][0] = records[0][0]
        elif fault == "duplicate-path":
            records[1][6] = records[0][6]
        else:
            records[0][7:10] = [7, "start", "/wrong/job/path"]
        bus = DeviceFakeBus(graph=_graph(), inventories=[records])

        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()

    asyncio.run(scenario())


@pytest.mark.parametrize("sysfs", ["", "relative", "/sys/../dev", "/sys/devices/has space", "/sys/devices/é"])
def test_reachable_device_requires_canonical_sysfs_path(sysfs):
    async def scenario():
        bus = DeviceFakeBus(graph=_graph(), sysfs_paths={DEVICE_NAMES[0]: sysfs})
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()

    asyncio.run(scenario())


@pytest.mark.parametrize("sysfs", [
    _MISSING, Variant("u", 1), Variant("s", 42),
])
def test_reachable_device_requires_exact_sysfs_property(sysfs):
    async def scenario():
        bus = DeviceFakeBus(graph=_graph(), sysfs_paths={DEVICE_NAMES[0]: sysfs})
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()

    asyncio.run(scenario())


def test_unrelated_inventory_device_may_have_empty_sysfs_path():
    async def scenario():
        unrelated = "unused.device"
        graph = _graph(include_alias=False)
        records = [
            _device_row(DEVICE_NAMES[0]),
            _device_row(DEVICE_NAMES[1], following=DEVICE_NAMES[0]),
            _device_row(unrelated, sysfs=""),
        ]
        bus = DeviceFakeBus(
            graph=graph, inventories=[records],
            sysfs_paths={DEVICE_NAMES[0]: SYSFS, DEVICE_NAMES[1]: SYSFS, unrelated: ""},
        )

        observation = await _inspector(bus).inspect()
        assert unrelated not in observation.units

    asyncio.run(scenario())


@pytest.mark.parametrize("fault", ["wrong-unit-following", "follower-job"])
def test_reachable_following_group_requires_all_matching_active_idle_units(fault):
    async def scenario():
        graph = _graph()
        records = [
            _device_row(DEVICE_NAMES[0]),
            _device_row(DEVICE_NAMES[1], following=DEVICE_NAMES[0]),
        ]
        bus = DeviceFakeBus(graph=graph, inventories=[records])
        if fault == "wrong-unit-following":
            bus.device_followings[DEVICE_NAMES[1]] = ""
        elif fault == "follower-job":
            bus.jobs[DEVICE_NAMES[1]] = [9, "/org/freedesktop/systemd1/job/9"]

        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()

    asyncio.run(scenario())


def test_same_sysfs_follower_group_cannot_exceed_graph_node_bound():
    async def scenario():
        names = [f"storage-{index:02d}.device" for index in range(65)]
        leader = names[0]
        graph = _base_graph()
        graph[CONTROLLER]["Wants"] = [leader]
        graph.update({name: {} for name in names})
        records = [_device_row(leader)] + [
            _device_row(name, following=leader) for name in names[1:]
        ]
        bus = DeviceFakeBus(
            graph=graph, inventories=[records],
            sysfs_paths={name: SYSFS for name in names},
        )

        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()

    asyncio.run(scenario())


@pytest.mark.parametrize("count,accepted", [(512, True), (513, False)])
def test_device_inventory_bound(count, accepted):
    async def scenario():
        names = [f"unrelated-{index:03d}.device" for index in range(count)]
        records = [
            _device_row(name, sysfs="") for name in names
        ]
        records[0] = _device_row(DEVICE_NAMES[0])
        graph = _graph(include_alias=False)
        bus = DeviceFakeBus(
            graph=graph, inventories=[records],
            sysfs_paths={DEVICE_NAMES[0]: SYSFS},
        )

        if accepted:
            observation = await _slow_inventory_inspector(bus).inspect()
            assert DEVICE_NAMES[0] in observation.units
            assert bus.inventory_reads == 4
        else:
            with pytest.raises(UnitOperationFailed):
                await _inspector(bus).inspect()
            assert bus.device_property_reads == []

    asyncio.run(scenario())


@pytest.mark.parametrize("following", ["missing.device", "disk-primary.device", "disk-outside.device"])
def test_following_must_be_nonself_same_sysfs_inventory_member(following):
    async def scenario():
        records = [
            _device_row(DEVICE_NAMES[0], following=following),
            _device_row(DEVICE_NAMES[1], following=DEVICE_NAMES[0]),
        ]
        if following == "disk-outside.device":
            records[0][5] = following
            records[1][5] = ""
        bus = DeviceFakeBus(graph=_graph(), inventories=[records])
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus).inspect()

    asyncio.run(scenario())
