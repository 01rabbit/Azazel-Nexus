import asyncio
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_manager import (
    BootstrapNarrowingManager, _PrototypeBootstrapManager,
)
from azazel_nexus_runtime.systemd_bus import _unit_object_path

CONTROLLER = "azazel-activated.service"
HELPER = "azazel-auditd.service"
BOOT_OWNER = ":1.9"
READ_ONLY = {"GetNameOwner", "ListJobs", "GetUnit", "Get"}


@dataclass
class Reply:
    message_type: int
    signature: str
    body: list
    sender: str | None = None


def row(job, unit, kind):
    return [job, unit, kind, "waiting", f"/org/freedesktop/systemd1/job/{job}",
            _unit_object_path(unit)]


class FakeBus:
    METHOD_RETURN = 1
    OWNER = ":1.9"

    def __init__(self, rows=(), state="active", fail=None, bad=None):
        self.rows, self.state, self.fail, self.bad = list(rows), state, fail, bad
        self.members = []
        self.messages = []
        self.disconnected = False

    def disconnect(self):
        self.disconnected = True

    async def call(self, message):
        self.members.append(message.member)
        self.messages.append(message)
        if message.member == self.fail:
            raise OSError("bus error")
        if message.member == "GetNameOwner":
            reply = Reply(1, "s", [self.OWNER], "org.freedesktop.DBus")
        elif message.member == "ListJobs":
            reply = Reply(1, "a(usssoo)", [self.rows], self.OWNER)
        elif message.member == "GetUnit":
            reply = Reply(1, "o", [_unit_object_path(message.body[0])], self.OWNER)
        elif message.member == "Get":
            reply = Reply(1, "v", [SimpleNamespace(signature="s", value=self.state)],
                          self.OWNER)
        else:
            raise AssertionError(f"unexpected call {message.member}")
        if message.member == self.bad:
            reply.body = [] if message.member != "Get" else [object()]
        return reply


class FakeSession:
    def __init__(self, bus):
        self._loop = asyncio.new_event_loop()
        self._bus = bus
        self._message_factory = lambda **values: SimpleNamespace(**values)
        self._message_type = SimpleNamespace(METHOD_RETURN=1)

    def close(self):
        self._bus.disconnect()
        self._loop.close()


def observe(bus, cls=BootstrapNarrowingManager, bound=True):
    manager = cls(job_timeout_seconds=0.05, session_factory=lambda: FakeSession(bus))
    if bound:
        manager._controller_binding = ("identity", BOOT_OWNER, "digest")
    result = manager.controller_stop_observed()
    assert set(bus.members) <= READ_ONLY
    assert bus.disconnected
    return result


@pytest.mark.parametrize("cls", [BootstrapNarrowingManager, _PrototypeBootstrapManager])
def test_pending_stop_job_on_controller_is_observed(cls):
    bus = FakeBus([row(5, HELPER, "stop"), row(6, CONTROLLER, "stop")])
    assert observe(bus, cls) is True


def test_deactivating_controller_is_observed():
    assert observe(FakeBus(state="deactivating")) is True


def test_stop_job_on_helper_only_is_not_observed():
    assert observe(FakeBus([row(5, HELPER, "stop")])) is False


@pytest.mark.parametrize("kind", ["start", "restart", "reload", "try-restart"])
def test_non_stop_controller_job_is_not_observed(kind):
    assert observe(FakeBus([row(7, CONTROLLER, kind)])) is False


@pytest.mark.parametrize("state", ["active", "activating", "inactive", "failed"])
def test_other_controller_states_are_not_observed(state):
    assert observe(FakeBus(state=state)) is False


@pytest.mark.parametrize("member", ["GetNameOwner", "ListJobs", "GetUnit", "Get"])
def test_bus_error_is_not_observed(member):
    assert observe(FakeBus(state="deactivating", fail=member)) is False


@pytest.mark.parametrize("member", ["ListJobs", "Get"])
def test_malformed_reply_is_not_observed(member):
    assert observe(FakeBus(state="deactivating", bad=member)) is False


def test_malformed_row_is_not_observed():
    assert observe(FakeBus([[1, CONTROLLER]])) is False


def test_timeout_is_not_observed():
    class Hang(FakeBus):
        async def call(self, message):
            if message.member == "ListJobs":
                await asyncio.Future()
            return await super().call(message)

    assert observe(Hang()) is False


def test_restart_job_with_deactivating_is_not_observed():
    assert observe(FakeBus([row(7, CONTROLLER, "restart")], state="deactivating")) is False
    assert observe(FakeBus([row(7, CONTROLLER, "start")], state="deactivating")) is False


def test_stop_plus_other_controller_job_is_not_observed():
    bus = FakeBus([row(6, CONTROLLER, "stop"), row(7, CONTROLLER, "start")])
    assert observe(bus) is False


def test_no_binding_is_not_observed():
    bus = FakeBus([row(6, CONTROLLER, "stop")])
    manager = BootstrapNarrowingManager(
        job_timeout_seconds=0.05, session_factory=lambda: FakeSession(bus))
    assert manager.controller_stop_observed() is False
    assert bus.members == []


def test_owner_mismatch_is_not_observed():
    bus = FakeBus([row(6, CONTROLLER, "stop")])
    manager = BootstrapNarrowingManager(
        job_timeout_seconds=0.05, session_factory=lambda: FakeSession(bus))
    manager._controller_binding = ("identity", ":1.77", "digest")
    assert manager.controller_stop_observed() is False
    assert "ListJobs" not in bus.members


def test_wrong_controller_row_unit_path_is_not_observed():
    bad = row(6, CONTROLLER, "stop")
    bad[5] = _unit_object_path(HELPER)
    assert observe(FakeBus([bad])) is False


def test_stop_job_skips_unit_property_reads():
    bus = FakeBus([row(6, CONTROLLER, "stop")])
    assert observe(bus) is True
    assert bus.members == ["GetNameOwner", "ListJobs"]


def test_deactivating_reads_exact_controller_property():
    bus = FakeBus(state="deactivating")
    assert observe(bus) is True
    assert bus.members == ["GetNameOwner", "ListJobs", "GetUnit", "Get"]
    path = _unit_object_path(CONTROLLER)
    get_unit, get = bus.messages[2], bus.messages[3]
    assert get_unit.body == [CONTROLLER]
    assert get.path == path
    assert get.interface == "org.freedesktop.DBus.Properties"
    assert get.body == ["org.freedesktop.systemd1.Unit", "ActiveState"]
    assert get.destination == BOOT_OWNER


def test_no_such_unit_error_is_not_observed():
    class Absent(FakeBus):
        async def call(self, message):
            if message.member == "GetUnit":
                self.members.append("GetUnit")
                return Reply(3, "s", ["no such unit"], self.OWNER)
            return await super().call(message)

    assert observe(Absent()) is False
