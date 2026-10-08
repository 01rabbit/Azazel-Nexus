from __future__ import annotations

import asyncio
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from azazel_nexus.activation import CORE_UNITS
from azazel_nexus_runtime.activated import _run_once, main
from azazel_nexus_runtime.systemd_bus import (
    MANAGER_INTERFACE,
    PROPERTIES_INTERFACE,
    UNIT_INTERFACE,
    SystemdBusSession,
    SystemdUnitCalls,
)
from azazel_nexus_runtime.units import (
    DbusUnitManager,
    UnitOperationFailed,
    UnitState,
)


@dataclass
class Reply:
    signature: str
    body: list


@dataclass
class Variant:
    value: object


class _LoopStub:
    def run_until_complete(self, awaitable):
        return asyncio.run(awaitable)

    def is_closed(self):
        return False

    def close(self):
        pass


class _MessageStub:
    def __init__(self, **values):
        self.__dict__.update(values)


class _BusStub:
    def __init__(self, reply):
        self.reply = reply
        self.messages = []

    async def call(self, message):
        self.messages.append(message)
        return self.reply

    def disconnect(self):
        pass


def test_mask_enable_and_state_use_exact_systemd_manager_signatures():
    calls = []

    def exchange(interface, member, signature, body, **kwargs):
        calls.append((interface, member, signature, body, kwargs))
        if member == "GetUnitFileState":
            return Reply("s", ["masked"])
        if member in {"MaskUnitFiles", "UnmaskUnitFiles"}:
            return Reply("a(sss)", [[]])
        if member == "EnableUnitFiles":
            return Reply("ba(sss)", [True, []])
        raise AssertionError(member)

    service = "azazel-auditd.service"
    client = SystemdUnitCalls(exchange)
    assert client("GetUnitFileState", service) == "masked"
    client("MaskUnitFiles", service)
    client("UnmaskUnitFiles", service)
    client("EnableUnitFiles", service)
    assert calls == [
        (MANAGER_INTERFACE, "GetUnitFileState", "s", [service], {}),
        (MANAGER_INTERFACE, "MaskUnitFiles", "asbb", [[service], False, False], {}),
        (MANAGER_INTERFACE, "UnmaskUnitFiles", "asb", [[service], False], {}),
        (MANAGER_INTERFACE, "EnableUnitFiles", "asbb", [[service], False, False], {}),
    ]


def test_active_state_resolves_only_the_expected_unit_object_and_property():
    calls = []
    unit = "azazel-auditd.service"
    object_path = "/org/freedesktop/systemd1/unit/azazel_2dauditd_2eservice"

    def exchange(interface, member, signature, body, **kwargs):
        calls.append((interface, member, signature, body, kwargs))
        if member == "GetUnit":
            return Reply("o", [object_path])
        return Reply("v", [Variant("active")])

    assert SystemdUnitCalls(exchange)("GetActiveState", unit) is True
    assert calls == [
        (MANAGER_INTERFACE, "GetUnit", "s", [unit], {}),
        (
            PROPERTIES_INTERFACE,
            "Get",
            "ss",
            [UNIT_INTERFACE, "ActiveState"],
            {"path": object_path},
        ),
    ]


@pytest.mark.parametrize("state", ["maintenance", "refreshing"])
def test_valid_nonactive_systemd_states_are_not_misread_as_protocol_errors(state):
    unit = "azazel-auditd.service"
    object_path = "/org/freedesktop/systemd1/unit/azazel_2dauditd_2eservice"

    def exchange(interface, member, signature, body, **kwargs):
        if member == "GetUnit":
            return Reply("o", [object_path])
        return Reply("v", [Variant(state)])

    assert SystemdUnitCalls(exchange)("GetActiveState", unit) is False


def test_invalid_unit_file_state_remains_nonenabled():
    manager = DbusUnitManager(call=lambda _method, _unit: "invalid")
    assert manager.state("azazel-auditd.service") is UnitState.DISABLED


@pytest.mark.parametrize(
    ("member", "reply"),
    [
        ("GetUnitFileState", Reply("o", ["/invalid"])),
        ("MaskUnitFiles", Reply("s", ["masked"])),
        ("EnableUnitFiles", Reply("ba(sss)", ["yes", []])),
    ],
)
def test_invalid_systemd_replies_fail_closed(member, reply):
    client = SystemdUnitCalls(lambda *_args, **_kwargs: reply)
    with pytest.raises(UnitOperationFailed):
        client(member, "azazel-auditd.service")


def test_unknown_unit_and_manager_method_never_reach_the_bus():
    calls = []
    client = SystemdUnitCalls(lambda *args, **kwargs: calls.append((args, kwargs)))
    with pytest.raises(UnitOperationFailed):
        client("MaskUnitFiles", "sshd.service")
    with pytest.raises(UnitOperationFailed):
        client("StartUnit", "azazel-auditd.service")
    assert calls == []


def test_bus_session_constructs_only_a_fixed_system_manager_message():
    reply = SimpleNamespace(message_type=1, signature="s", body=["masked"])
    bus = _BusStub(reply)
    session = SystemdBusSession(
        bus=bus,
        loop=_LoopStub(),
        previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=_MessageStub,
    )
    assert session("GetUnitFileState", "azazel-auditd.service") == "masked"
    message = bus.messages[0]
    assert message.destination == "org.freedesktop.systemd1"
    assert message.path == "/org/freedesktop/systemd1"
    assert message.interface == MANAGER_INTERFACE
    assert message.member == "GetUnitFileState"
    assert message.signature == "s"
    assert message.body == ["azazel-auditd.service"]


def test_bus_session_translates_dbus_errors_without_accepting_the_reply():
    reply = SimpleNamespace(message_type=3, signature="s", body=["details withheld"])
    session = SystemdBusSession(
        bus=_BusStub(reply),
        loop=_LoopStub(),
        previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=_MessageStub,
    )
    with pytest.raises(UnitOperationFailed, match="returned an error"):
        session("GetUnitFileState", "azazel-auditd.service")


def test_connect_constructs_and_runs_dbus_next_on_the_same_loop(monkeypatch):
    import dbus_next.aio

    observed = {}

    class LoopBoundBus:
        def __init__(self, *, bus_type):
            observed["constructed_loop"] = asyncio.get_event_loop()
            observed["bus_type"] = bus_type

        async def connect(self):
            observed["connected_loop"] = asyncio.get_running_loop()

        def disconnect(self):
            observed["disconnected"] = True

    try:
        previous_loop = asyncio.get_event_loop()
    except RuntimeError:
        previous_loop = None
    monkeypatch.setattr(dbus_next.aio, "MessageBus", LoopBoundBus)

    session = SystemdBusSession.connect()
    owned_loop = observed["constructed_loop"]
    assert owned_loop is observed["connected_loop"]
    assert session._loop is owned_loop
    assert observed["bus_type"].name == "SYSTEM"

    session.close()
    assert observed["disconnected"] is True
    assert owned_loop.is_closed()
    try:
        restored_loop = asyncio.get_event_loop()
    except RuntimeError:
        restored_loop = None
    assert restored_loop is previous_loop


def test_production_composition_records_a_real_fail_closed_decision(tmp_path):
    states = {definition.name: "enabled" for definition in CORE_UNITS}
    calls = []

    def call(method, unit):
        calls.append((method, unit))
        if method == "MaskUnitFiles":
            states[unit] = "masked"
        elif method == "GetUnitFileState":
            return states[unit]
        else:
            raise AssertionError(f"unexpected widening or start operation: {method}")

    manager = DbusUnitManager(call=call)
    outcome = _run_once(
        manager=manager,
        root=tmp_path,
        now="2026-09-28T00:00:00Z",
        actor="azazel-activated",
    )
    assert outcome.granted == ()
    assert len(outcome.withheld) == len(CORE_UNITS)
    assert [method for method, _unit in calls] == [
        method
        for _definition in CORE_UNITS
        for method in ("MaskUnitFiles", "GetUnitFileState")
    ]
    assert all(states[definition.name] == "masked" for definition in CORE_UNITS)

    from azazel_nexus.audit import AuditLedger

    events = [
        entry.event
        for entry in AuditLedger(tmp_path / "var/lib/azazel/state/activation.jsonl")
    ]
    assert events[0]["event_type"] == "activation.refused"
    assert events[0]["reason"].startswith("no_generation:")


def test_entrypoint_rejects_arguments_instead_of_accepting_runtime_overrides():
    assert main(["--unit", "sshd.service"]) == 2


def test_entrypoint_checks_arguments_from_the_wrapper_invocation(monkeypatch):
    monkeypatch.setattr("sys.argv", ["az-activated", "sshd.service"])
    assert main() == 2
