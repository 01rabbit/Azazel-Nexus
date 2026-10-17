"""Synthetic stopped-pair inspection tests; no host cgroups are read."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_stopped import (
    BootstrapStoppedPairInspector,
    StoppedBootstrapPair,
)
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed
from test_runtime_bootstrap_masked import (
    FakeBus as MaskedFakeBus,
    OWNER,
    PAIR,
    Variant,
    _object_path,
)


OWNER_UID = os.getuid()


class StoppedFakeBus(MaskedFakeBus):
    """Masked inspector fixture extended with stopped-service properties."""

    def __init__(self, *, active=None, pids=None, control_groups=None, **kwargs):
        super().__init__(**kwargs)
        self.active = {unit: "inactive" for unit in PAIR}
        self.active.update(active or {})
        self.pids = {unit: (0, 0) for unit in PAIR}
        self.pids.update(pids or {})
        self.control_groups = {
            unit: "/system.slice/" + UNIT_NAMES[unit] for unit in PAIR
        }
        self.control_groups.update(control_groups or {})

    async def call(self, message):
        if (message.member == "GetAll"
                and message.body == ["org.freedesktop.systemd1.Service"]):
            self.calls.append(message)
            assert message.destination == OWNER
            unit = next(key for key in PAIR
                        if message.path == _object_path(UNIT_NAMES[key]))
            main_pid, control_pid = self.pids[unit]
            props = {
                "MainPID": Variant("u", main_pid),
                "ControlPID": Variant("u", control_pid),
                "ControlGroup": Variant("s", self.control_groups[unit]),
            }
            return SimpleNamespace(
                message_type=1, signature="a{sv}", body=[props], sender=OWNER
            )
        return await super().call(message)


def _private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, exist_ok=True)
    path.chmod(0o700)
    return path


def _cgroup(root: Path, unit: UnitKey, events=b"populated 0\nfrozen 0\n"):
    parent = _private_dir(root / "system.slice")
    leaf = _private_dir(parent / UNIT_NAMES[unit])
    file = leaf / "cgroup.events"
    file.write_bytes(events)
    file.chmod(0o600)
    return leaf


@pytest.fixture
def cgroup_root(tmp_path):
    root = _private_dir(tmp_path / "cgroup")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        yield root, fd
    finally:
        os.close(fd)


def _inspector(bus, root_fd, *, check_closed=None, expected_owner=OWNER):
    async def closed():
        return None

    return BootstrapStoppedPairInspector(
        bus=bus,
        message_factory=lambda **fields: SimpleNamespace(**fields),
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        timeout_seconds=0.2,
        cgroup_root_fd=root_fd,
        owner_uid=OWNER_UID,
        expected_owner=expected_owner,
        check_closed=check_closed or closed,
    )


def test_returns_stopped_pair_for_two_inactive_pids_zero_empty_cgroups(cgroup_root):
    async def run():
        root, root_fd = cgroup_root
        leaves = {unit: _cgroup(root, unit) for unit in PAIR}
        bus = StoppedFakeBus()

        result = await _inspector(bus, root_fd).inspect()

        assert isinstance(result, StoppedBootstrapPair)
        assert result.owner == OWNER
        assert tuple(row[0] for row in result.cgroups) == PAIR
        assert all(row[2][0] == "empty" for row in result.cgroups)
        assert all(leaf.is_dir() for leaf in leaves.values())

    asyncio.run(run())


def test_accepts_cleared_controlgroup_only_when_expected_leaf_is_absent(cgroup_root):
    async def run():
        root, root_fd = cgroup_root
        _private_dir(root / "system.slice")
        bus = StoppedFakeBus(
            control_groups={unit: "" for unit in PAIR}
        )

        result = await _inspector(bus, root_fd).inspect()

        assert all(row[1] == "" and row[2][0] == "absent"
                   for row in result.cgroups)

    asyncio.run(run())


@pytest.mark.parametrize("failure", ["populated", "main-pid", "control-pid", "active", "path"])
def test_refuses_populated_pid_active_or_misattributed_cgroup(cgroup_root, failure):
    async def run():
        root, root_fd = cgroup_root
        for unit in PAIR:
            _cgroup(root, unit, b"populated 1\nfrozen 0\n" if failure == "populated"
                    and unit == UnitKey.AUDITD else b"populated 0\nfrozen 0\n")
        options = {}
        if failure == "main-pid":
            options["pids"] = {UnitKey.AUDITD: (41, 0)}
        elif failure == "control-pid":
            options["pids"] = {UnitKey.COMMISSIOND: (0, 7)}
        elif failure == "active":
            options["active"] = {UnitKey.AUDITD: "failed"}
        elif failure == "path":
            options["control_groups"] = {
                UnitKey.COMMISSIOND: "/system.slice/other.service"
            }
        with pytest.raises(UnitOperationFailed):
            await _inspector(StoppedFakeBus(**options), root_fd).inspect()

    asyncio.run(run())


def test_refuses_owner_drift_and_wrong_expected_owner(cgroup_root):
    async def run():
        _root, root_fd = cgroup_root
        for unit in PAIR:
            _cgroup(_root, unit)
        with pytest.raises(UnitOperationFailed):
            await _inspector(StoppedFakeBus(owner_changes=True), root_fd).inspect()
        with pytest.raises(ValueError):
            _inspector(StoppedFakeBus(), root_fd, expected_owner=None)

    asyncio.run(run())


def test_guard_refusal_prevents_observation_and_bus_unit_queries(cgroup_root):
    async def run():
        _root, root_fd = cgroup_root
        calls = 0

        async def refused():
            nonlocal calls
            calls += 1
            return False

        bus = StoppedFakeBus()
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus, root_fd, check_closed=refused).inspect()
        assert calls == 1
        assert not any(call.member == "GetUnit" for call in bus.calls)

    asyncio.run(run())


def test_refuses_single_use_reinspection_without_more_bus_calls(cgroup_root):
    async def run():
        root, root_fd = cgroup_root
        for unit in PAIR:
            _cgroup(root, unit)
        bus = StoppedFakeBus()
        inspector = _inspector(bus, root_fd)
        await inspector.inspect()
        before = len(bus.calls)
        with pytest.raises(UnitOperationFailed):
            await inspector.inspect()
        assert len(bus.calls) == before

    asyncio.run(run())


def test_refuses_profile_drift_during_stopped_observation(cgroup_root):
    async def run():
        root, root_fd = cgroup_root
        for unit in PAIR:
            _cgroup(root, unit)
        bus = StoppedFakeBus(profile_drift=True)
        with pytest.raises(UnitOperationFailed):
            await _inspector(bus, root_fd).inspect()
        assert bus.profile_calls >= 2

    asyncio.run(run())
