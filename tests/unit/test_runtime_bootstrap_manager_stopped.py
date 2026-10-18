"""Integrated manager tests for closing and stopping the owned bootstrap pair."""

import asyncio
import os
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.systemd_bus import (
    MANAGER_INTERFACE,
    MANAGER_PATH,
    _unit_object_path,
)
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed
from test_runtime_bootstrap_close_files import _files
from test_runtime_bootstrap_close_sequence import FakeBus as CloseSequenceFakeBus
from test_runtime_bootstrap_close_sequence import Message
from test_runtime_bootstrap_overlay_files import PAIR, _environment, _publish


OWNER = ":1.42"
SERVICE_INTERFACE = "org.freedesktop.systemd1.Service"
PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties"


class Variant:
    def __init__(self, signature, value):
        self.signature = signature
        self.value = value


class StoppedManagerFakeBus(CloseSequenceFakeBus):
    """Close-sequence fake with the stop JobRemoved and stopped-unit protocol."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.handlers = []
        self.events = []
        self.job_id = 73
        self.job_path = f"/org/freedesktop/systemd1/job/{self.job_id}"
        self.disconnected = False

    def add_message_handler(self, handler):
        self.events.append("handler-add")
        self.handlers.append(handler)

    def remove_message_handler(self, handler):
        self.events.append("handler-remove")
        self.handlers.remove(handler)

    def disconnect(self):
        self.disconnected = True

    def _signal_job_removed(self, unit_name):
        signal = Message(
            message_type=4,
            signature="uoss",
            body=[self.job_id, self.job_path, unit_name, "done"],
            sender=OWNER,
            path=MANAGER_PATH,
            interface=MANAGER_INTERFACE,
            member="JobRemoved",
        )
        for handler in tuple(self.handlers):
            handler(signal)

    async def call(self, message):
        if message.member in {
            "AddMatch", "Subscribe", "Unsubscribe", "RemoveMatch", "StopUnit"
        }:
            self.calls.append(message)
            self.events.append(message.member)
            if message.member in {"AddMatch", "RemoveMatch"}:
                assert message.destination == "org.freedesktop.DBus"
            else:
                assert message.destination == OWNER
            if message.member == "StopUnit":
                assert message.body[1] == "fail"
                self._signal_job_removed(message.body[0])
                return SimpleNamespace(
                    message_type=1, signature="o", body=[self.job_path], sender=OWNER
                )
            return SimpleNamespace(
                message_type=1, signature="", body=[], sender=message.destination
            )

        if (message.member == "GetAll" and message.body == [SERVICE_INTERFACE]
                and message.interface == PROPERTIES_INTERFACE):
            self.calls.append(message)
            self.events.append(message.member)
            unit_name = next(
                name for name in UNIT_NAMES.values()
                if message.path == _unit_object_path(name)
            )
            return SimpleNamespace(
                message_type=1,
                signature="a{sv}",
                body=[{
                    "MainPID": Variant("u", 0),
                    "ControlPID": Variant("u", 0),
                    "ControlGroup": Variant("s", "/system.slice/" + unit_name),
                }],
                sender=OWNER,
            )

        if message.member == "Get" and message.interface == PROPERTIES_INTERFACE:
            self.calls.append(message)
            self.events.append(message.member)
            assert message.body == ["org.freedesktop.systemd1.Unit", "ActiveState"]
            return SimpleNamespace(
                message_type=1,
                signature="v",
                body=[Variant("s", "inactive")],
                sender=OWNER,
            )

        return await super().call(message)


class Session:
    def __init__(self, bus):
        self._bus = bus
        self._loop = asyncio.new_event_loop()
        self._message_factory = Message
        self._message_type = SimpleNamespace(ERROR=3, METHOD_RETURN=1, SIGNAL=4)
        self.closed = False

    def close(self):
        self._bus.disconnect()
        if not self._loop.is_closed():
            self._loop.close()
        self.closed = True


def _private_dir(path):
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _cgroup_root(tmp_path, *, populated_unit=None):
    root = _private_dir(tmp_path / "cgroup-root")
    system_slice = _private_dir(root / "system.slice")
    for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND):
        name = UNIT_NAMES[unit]
        leaf = _private_dir(system_slice / name)
        events = leaf / "cgroup.events"
        events.write_text(
            "populated " + ("1" if name == populated_unit else "0") + "\n",
            encoding="ascii",
        )
        events.chmod(0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    return root, fd


def _manager(env, bus):
    session = Session(bus)
    manager = BootstrapNarrowingManager(
        job_timeout_seconds=5.0,
        session_factory=lambda: session,
        closed_overlay_files=_files(env),
    )
    return manager, session


def _report_overlay_fragments(env):
    def mutate(_call_number, name, properties):
        properties["FragmentPath"] = Variant(
            "s", str(env["overlay_path"] / name)
        )
        properties["ActiveState"] = Variant("s", "inactive")
        return properties

    return mutate


def test_stop_closed_pair_closes_reloads_drains_then_stops_reverse_and_observes(
    tmp_path,
):
    with _environment(tmp_path) as env:
        _publish(env)
        bus = StoppedManagerFakeBus(
            snapshots=[[], [], [], []], mutate=_report_overlay_fragments(env)
        )
        manager, session = _manager(env, bus)
        overlay_identity = {
            unit: ((env["overlay_path"] / unit).stat().st_dev,
                   (env["overlay_path"] / unit).stat().st_ino)
            for unit in PAIR
        }
        _root, root_fd = _cgroup_root(tmp_path)
        try:
            result = manager.stop_closed_pair(
                cgroup_root_fd=root_fd, owner_uid=os.getuid()
            )
        finally:
            os.close(root_fd)

        members = [call.member for call in bus.calls]
        stops = [call.body[0] for call in bus.calls if call.member == "StopUnit"]
        assert stops == [UNIT_NAMES[UnitKey.COMMISSIOND], UNIT_NAMES[UnitKey.AUDITD]]
        assert members.index("Reload") < members.index("StopUnit")
        assert members.count("StopUnit") == 2
        assert members.count("AddMatch") == members.count("Subscribe") == 2
        assert members.count("Unsubscribe") == members.count("RemoveMatch") == 2
        assert not bus.handlers
        assert bus.events.count("handler-remove") == 2
        assert result.owner == OWNER
        assert len(result.cgroups) == 2
        assert all(row[2][0] == "empty" for row in result.cgroups)
        assert all((env["overlay_path"] / unit).exists() for unit in PAIR)
        assert {
            unit: ((env["overlay_path"] / unit).stat().st_dev,
                   (env["overlay_path"] / unit).stat().st_ino)
            for unit in PAIR
        } == overlay_identity
        assert env["store"].load().phase == "closing"
        assert session.closed and session._loop.is_closed() and bus.disconnected


def test_populated_cgroup_refuses_stopped_pair_result(tmp_path):
    with _environment(tmp_path) as env:
        _publish(env)
        bus = StoppedManagerFakeBus(
            snapshots=[[], [], [], []],
            mutate=_report_overlay_fragments(env),
        )
        manager, _session = _manager(env, bus)
        _root, root_fd = _cgroup_root(
            tmp_path, populated_unit=UNIT_NAMES[UnitKey.COMMISSIOND]
        )
        try:
            with pytest.raises(UnitOperationFailed):
                manager.stop_closed_pair(cgroup_root_fd=root_fd, owner_uid=os.getuid())
        finally:
            os.close(root_fd)


def test_owner_drift_during_closed_pair_stop_refuses(tmp_path):
    with _environment(tmp_path) as env:
        _publish(env)
        bus = StoppedManagerFakeBus(
            snapshots=[[], [], [], []],
            mutate=_report_overlay_fragments(env),
            drift_after_reload=True,
        )
        manager, _session = _manager(env, bus)
        _root, root_fd = _cgroup_root(tmp_path)
        try:
            with pytest.raises(UnitOperationFailed):
                manager.stop_closed_pair(cgroup_root_fd=root_fd, owner_uid=os.getuid())
        finally:
            os.close(root_fd)


def test_stop_closed_pair_without_owned_closure_refuses_before_session_creation(
    tmp_path,
):
    session_calls = []

    def make_session():
        session_calls.append(True)
        raise AssertionError("session must not be opened without owned closure")

    manager = BootstrapNarrowingManager(
        job_timeout_seconds=0.5, session_factory=make_session
    )
    _root, root_fd = _cgroup_root(tmp_path)
    try:
        with pytest.raises(UnitOperationFailed):
            manager.stop_closed_pair(cgroup_root_fd=root_fd, owner_uid=os.getuid())
    finally:
        os.close(root_fd)
    assert session_calls == []


@pytest.mark.parametrize("invalid", ["root_fd", "owner_uid"])
def test_invalid_cgroup_authority_refuses_before_session_or_overlay_close(
    tmp_path, invalid
):
    with _environment(tmp_path) as env:
        _publish(env)
        overlay_before = {
            unit: (env["overlay_path"] / unit).read_bytes() for unit in PAIR
        }
        session_calls = []

        def make_session():
            session_calls.append(True)
            raise AssertionError("invalid cgroup authority must preflight before bus")

        manager = BootstrapNarrowingManager(
            job_timeout_seconds=0.5,
            session_factory=make_session,
            closed_overlay_files=_files(env),
        )
        if invalid == "root_fd":
            invalid_path = tmp_path / "not-a-directory"
            invalid_path.write_text("ordinary file", encoding="ascii")
            root_fd = os.open(invalid_path, os.O_RDONLY | os.O_CLOEXEC)
            owner_uid = os.getuid()
        else:
            _root, root_fd = _cgroup_root(tmp_path)
            owner_uid = os.getuid() + 1
        try:
            with pytest.raises(UnitOperationFailed):
                manager.stop_closed_pair(
                    cgroup_root_fd=root_fd, owner_uid=owner_uid
                )
        finally:
            os.close(root_fd)

        assert session_calls == []
        assert {
            unit: (env["overlay_path"] / unit).read_bytes() for unit in PAIR
        } == overlay_before
