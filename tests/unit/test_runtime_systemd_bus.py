from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime.activated import _run_once, main
from azazel_nexus_runtime.bootstrap_systemd_profile import (
    _DEBIAN13_V257_UNIT_PATH,
)
from azazel_nexus_runtime.systemd_bus import (
    MANAGER_INTERFACE,
    PROPERTIES_INTERFACE,
    UNIT_INTERFACE,
    EdgeUnitStateReader,
    SystemdBusSession,
    SystemdUnitCalls,
    _Reply,
    _unit_object_path,
)
from azazel_nexus_runtime.units import (
    DbusUnitManager,
    UnitOperationFailed,
    UnitState,
)

from azazel_nexus.activation import CORE_UNITS


@pytest.mark.parametrize("name,label", [
    ("foo_bar.service", "foo_5fbar_2eservice"),
    ("1example.service", "_31example_2eservice"),
    ("a1.service", "a1_2eservice"),
    ("_.mount", "_5f_2emount"),
    ("", "_"),
    ("é.service", "_c3_a9_2eservice"),
])
def test_unit_bus_label_matches_independent_systemd_vectors(name, label):
    assert _unit_object_path(name) == "/org/freedesktop/systemd1/unit/" + label


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
        (MANAGER_INTERFACE, "GetUnit", "s", [unit], {"allow_no_such_unit": True}),
        (
            PROPERTIES_INTERFACE,
            "Get",
            "ss",
            [UNIT_INTERFACE, "ActiveState"],
            {"path": object_path},
        ),
    ]


def test_bootstrap_profile_reads_only_pinned_manager_properties():
    calls = []

    def exchange(interface, member, signature, body, **kwargs):
        calls.append((interface, member, signature, body, kwargs))
        if body == ["org.freedesktop.systemd1.Manager", "Version"]:
            return Reply("v", [SimpleNamespace(signature="s", value="257.13-1~deb13u1")])
        if body == ["org.freedesktop.systemd1.Manager", "UnitPath"]:
            return Reply("v", [SimpleNamespace(signature="as", value=list(_DEBIAN13_V257_UNIT_PATH))])
        raise AssertionError(body)

    observed = SystemdUnitCalls(exchange).bootstrap_profile()

    assert observed.name == "systemd-257.13-deb13-path-v1"
    assert calls == [
        (PROPERTIES_INTERFACE, "Get", "ss",
         ["org.freedesktop.systemd1.Manager", "Version"],
         {"path": "/org/freedesktop/systemd1"}),
        (PROPERTIES_INTERFACE, "Get", "ss",
         ["org.freedesktop.systemd1.Manager", "UnitPath"],
         {"path": "/org/freedesktop/systemd1"}),
    ]


def test_bootstrap_profile_refuses_unknown_manager_path():
    def exchange(_interface, _member, _signature, body, **_kwargs):
        if body[1] == "Version":
            return Reply("v", [SimpleNamespace(signature="s", value="257.13-1~deb13u1")])
        return Reply("v", [SimpleNamespace(signature="as", value=["/tmp/systemd"] )])

    with pytest.raises(UnitOperationFailed):
        SystemdUnitCalls(exchange).bootstrap_profile()


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
    owner = ":1.42"
    reply = SimpleNamespace(message_type=1, signature="s", body=["masked"], sender=owner)
    bus = _BusStub(reply)
    bus._azazel_systemd_owner = owner
    session = SystemdBusSession(
        bus=bus,
        loop=_LoopStub(),
        previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=_MessageStub,
    )
    assert session("GetUnitFileState", "azazel-auditd.service") == "masked"
    message = bus.messages[0]
    assert message.destination == owner
    assert message.path == "/org/freedesktop/systemd1"
    assert message.interface == MANAGER_INTERFACE
    assert message.member == "GetUnitFileState"
    assert message.signature == "s"
    assert message.body == ["azazel-auditd.service"]


def test_bus_session_allows_only_manager_version_and_unitpath_reads():
    messages = []

    class ReadProfileBus:
        def __init__(self):
            self.replies = [
                SimpleNamespace(message_type=1, signature="v", body=[SimpleNamespace(
                    signature="s", value="257.13-1~deb13u1")]),
                SimpleNamespace(message_type=1, signature="v", body=[SimpleNamespace(
                    signature="as", value=list(_DEBIAN13_V257_UNIT_PATH))]),
            ]

        async def call(self, message):
            messages.append(message)
            return self.replies.pop(0)

        def disconnect(self):
            pass

    session = SystemdBusSession(
        bus=ReadProfileBus(), loop=_LoopStub(), previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=_MessageStub,
    )
    assert session.bootstrap_profile().name == "systemd-257.13-deb13-path-v1"
    assert [(message.interface, message.member, message.signature, message.body, message.path)
            for message in messages] == [
        (PROPERTIES_INTERFACE, "Get", "ss",
         ["org.freedesktop.systemd1.Manager", "Version"], "/org/freedesktop/systemd1"),
        (PROPERTIES_INTERFACE, "Get", "ss",
         ["org.freedesktop.systemd1.Manager", "UnitPath"], "/org/freedesktop/systemd1"),
    ]


def test_bus_session_rejects_unhashable_manager_property_before_bus_call():
    bus = _BusStub(SimpleNamespace(message_type=1, signature="v", body=[]))
    session = SystemdBusSession(
        bus=bus, loop=_LoopStub(), previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=_MessageStub,
    )
    with pytest.raises(UnitOperationFailed):
        session._exchange(
            PROPERTIES_INTERFACE, "Get", "ss",
            ["org.freedesktop.systemd1.Manager", []],
            path="/org/freedesktop/systemd1",
        )
    assert bus.messages == []


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
    monkeypatch.setattr("azazel_nexus_runtime.systemd_bus.require_supported_dbus_next", lambda: None)
    observed = {}
    owner = ":1.42"
    message_type = SimpleNamespace(ERROR=3, METHOD_RETURN=1)

    class LoopBoundBus:
        def __init__(self, *, bus_address):
            observed["constructed_loop"] = asyncio.get_event_loop()
            observed["bus_address"] = bus_address

        async def connect(self):
            observed["connected_loop"] = asyncio.get_running_loop()

        async def call(self, message):
            observed.setdefault("identity_messages", []).append(message)
            if message.member == "GetNameOwner":
                return SimpleNamespace(
                    message_type=1, signature="s", body=[owner], sender="org.freedesktop.DBus"
                )
            credential = {"GetConnectionUnixProcessID": 1, "GetConnectionUnixUser": 0}
            return SimpleNamespace(
                message_type=1, signature="u", body=[credential[message.member]],
                sender="org.freedesktop.DBus",
            )

        def disconnect(self):
            observed["disconnected"] = True

    try:
        previous_loop = asyncio.get_event_loop()
    except RuntimeError:
        previous_loop = None
    monkeypatch.setitem(
        sys.modules, "dbus_next",
        SimpleNamespace(Message=_MessageStub, MessageType=message_type),
    )
    monkeypatch.setitem(sys.modules, "dbus_next.aio", SimpleNamespace(MessageBus=LoopBoundBus))
    monkeypatch.setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/tmp/hostile-bus")

    session = SystemdBusSession.connect()
    owned_loop = observed["constructed_loop"]
    assert owned_loop is observed["connected_loop"]
    assert session._loop is owned_loop
    assert observed["bus_address"] == "unix:path=/run/dbus/system_bus_socket"
    assert session._bus._azazel_systemd_owner == owner
    assert [message.member for message in observed["identity_messages"]] == [
        "GetNameOwner", "GetConnectionUnixProcessID", "GetNameOwner",
        "GetConnectionUnixUser", "GetNameOwner",
    ]
    assert all(message.destination == "org.freedesktop.DBus"
               for message in observed["identity_messages"])

    session.close()
    assert observed["disconnected"] is True
    assert owned_loop.is_closed()
    try:
        restored_loop = asyncio.get_event_loop()
    except RuntimeError:
        restored_loop = None
    assert restored_loop is previous_loop


def test_bus_session_pins_manager_destination_and_refuses_foreign_sender():
    owner = ":1.42"
    bus = _BusStub(SimpleNamespace(
        message_type=1, signature="s", body=["masked"], sender=":1.99"
    ))
    bus._azazel_systemd_owner = owner
    session = SystemdBusSession(
        bus=bus, loop=_LoopStub(), previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=_MessageStub,
    )
    with pytest.raises(UnitOperationFailed, match="owner refused"):
        session("GetUnitFileState", "azazel-auditd.service")
    assert bus.messages[0].destination == owner


def test_production_composition_records_a_real_fail_closed_decision(tmp_path):
    states = {definition.name: "enabled" for definition in CORE_UNITS}
    calls = []

    def call(method, unit):
        calls.append((method, unit))
        if method == "MaskUnitFiles":
            states[unit] = "masked"
        elif method == "GetUnitFileState":
            return states[unit]
        elif method == "GetInactiveState":
            return True  # Explicit process observation, separate from masks.
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
    # Preflight narrows before evidence collection; the refusing decision then
    # independently verifies every mask. Neither pass may unmask/start a unit.
    assert calls == [
        (method, definition.name)
        for _pass in range(2)
        for definition in CORE_UNITS
        for method in ("MaskUnitFiles", "GetUnitFileState", "GetInactiveState")
    ]
    assert all(states[definition.name] == "masked" for definition in CORE_UNITS)

    from azazel_nexus.audit import AuditLedger

    events = [
        entry.event
        for entry in AuditLedger(tmp_path / "var/lib/azazel/state/activation.jsonl")
    ]
    assert events[0]["event_type"] == "activation.evidence_preflight_masked"
    assert events[0]["remask_failures"] == []
    assert events[1]["event_type"] == "activation.refused"
    assert events[1]["reason"].startswith("no_generation:")


def test_entrypoint_rejects_arguments_instead_of_accepting_runtime_overrides():
    assert main(["--unit", "sshd.service"]) == 2


def test_entrypoint_checks_arguments_from_the_wrapper_invocation(monkeypatch):
    monkeypatch.setattr("sys.argv", ["az-activated", "sshd.service"])
    assert main() == 2


# -- the probe's read-only view (#72, #195) --------------------------------

_EDGE = "azazel-edge-core.service"
_EDGE_PATH = "/org/freedesktop/systemd1/unit/azazel_2dedge_2dcore_2eservice"
_RUNNING = {"LoadState": "loaded", "ActiveState": "active", "SubState": "running"}


def _edge_exchange(state, calls):
    def exchange(interface, member, signature, body, **kwargs):
        calls.append((interface, member, signature, body, kwargs))
        if member == "GetUnit":
            if state is None:
                return _Reply("", [], no_such_unit=True)
            return _Reply("o", [_EDGE_PATH])
        return _Reply("v", [SimpleNamespace(signature="s", value=state[body[1]])])

    return exchange


def _edge_reader(state, calls):
    session = SimpleNamespace(_exchange=_edge_exchange(state, calls), close=lambda: None)
    return EdgeUnitStateReader(connect=lambda: session)


def test_edge_reader_reads_three_properties_of_the_fixed_unit_object():
    calls = []
    assert _edge_reader(_RUNNING, calls)("GetUnitProperties", _EDGE) == _RUNNING
    assert calls == [
        (MANAGER_INTERFACE, "GetUnit", "s", [_EDGE], {"allow_no_such_unit": True}),
        *[(PROPERTIES_INTERFACE, "Get", "ss", [UNIT_INTERFACE, name], {"path": _EDGE_PATH})
          for name in ("LoadState", "ActiveState", "SubState")],
    ]


def test_edge_reader_reports_no_unit_object_as_inactive():
    calls = []
    assert _edge_reader(None, calls)("GetUnitProperties", _EDGE) == {
        "LoadState": "not-loaded", "ActiveState": "inactive", "SubState": "dead",
    }
    assert [call[1] for call in calls] == ["GetUnit"]


@pytest.mark.parametrize("method, unit", [
    ("GetUnitProperties", "azazel-auditd.service"),
    ("GetUnitProperties", "sshd.service"),
    ("MaskUnitFiles", _EDGE),
    ("UnmaskUnitFiles", _EDGE),
    ("EnableUnitFiles", _EDGE),
    ("StartUnit", _EDGE),
    ("GetUnitFileState", _EDGE),
])
def test_edge_reader_refuses_anything_but_its_one_read_before_connecting(method, unit):
    connected = []
    reader = EdgeUnitStateReader(connect=lambda: connected.append(1))
    with pytest.raises(UnitOperationFailed):
        reader(method, unit)
    assert connected == []


def test_edge_reader_holds_no_control_verb():
    reader = _edge_reader(_RUNNING, [])
    reader("GetUnitProperties", _EDGE)
    assert not hasattr(reader, "calls") and not hasattr(reader, "__dict__")
    for member, signature in (("MaskUnitFiles", "asbb"), ("UnmaskUnitFiles", "asb"),
                              ("EnableUnitFiles", "asbb"), ("GetUnitFileState", "s")):
        with pytest.raises(UnitOperationFailed, match="non-read"):
            reader._exchange(MANAGER_INTERFACE, member, signature, [[_EDGE], False, False])


@pytest.mark.parametrize("state", [
    {**_RUNNING, "ActiveState": "running"},
    {**_RUNNING, "LoadState": "whatever"},
    {**_RUNNING, "SubState": "Running; rm"},
    {**_RUNNING, "SubState": ""},
])
def test_edge_reader_refuses_unknown_property_values(state):
    with pytest.raises(UnitOperationFailed):
        _edge_reader(state, [])("GetUnitProperties", _EDGE)


def test_edge_reader_refuses_a_non_string_variant():
    def wrong_type(interface, member, signature, body, **kwargs):
        if member == "GetUnit":
            return _Reply("o", [_EDGE_PATH])
        return _Reply("v", [SimpleNamespace(signature="u", value=1)])

    session = SimpleNamespace(_exchange=wrong_type, close=lambda: None)
    with pytest.raises(UnitOperationFailed, match="invalid"):
        EdgeUnitStateReader(connect=lambda: session)("GetUnitProperties", _EDGE)


def test_edge_reader_refuses_a_foreign_unit_object():
    session = SimpleNamespace(
        _exchange=lambda *a, **k: _Reply("o", [_unit_object_path("sshd.service")]),
        close=lambda: None,
    )
    with pytest.raises(UnitOperationFailed, match="invalid unit object"):
        EdgeUnitStateReader(connect=lambda: session)("GetUnitProperties", _EDGE)


def test_edge_reader_connects_once_lazily_and_close_never_raises():
    connects = []

    def boom():
        raise RuntimeError("disconnect failed")

    session = SimpleNamespace(_exchange=_edge_exchange(_RUNNING, []), close=boom)
    reader = EdgeUnitStateReader(connect=lambda: connects.append(1) or session)
    assert connects == []
    reader("GetUnitProperties", _EDGE)
    reader("GetUnitProperties", _EDGE)
    assert connects == [1]
    reader.close()
    reader.close()
    with pytest.raises(UnitOperationFailed, match="closed"):
        reader("GetUnitProperties", _EDGE)


def test_edge_reader_propagates_a_connect_failure():
    def refuse():
        raise UnitOperationFailed("could not connect to the system D-Bus service manager")

    reader = EdgeUnitStateReader(connect=refuse)
    with pytest.raises(UnitOperationFailed, match="could not connect"):
        reader("GetUnitProperties", _EDGE)
    reader.close()


def _session_for_allowlist():
    bus = _BusStub(SimpleNamespace(message_type=1, signature="v", body=[]))
    session = SystemdBusSession(
        bus=bus, loop=_LoopStub(), previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=_MessageStub,
    )
    return session, bus


@pytest.mark.parametrize("name", ["LoadState", "ActiveState", "SubState"])
def test_bus_allowlist_admits_the_edge_state_properties(name):
    session, bus = _session_for_allowlist()
    session._exchange(PROPERTIES_INTERFACE, "Get", "ss", [UNIT_INTERFACE, name], path=_EDGE_PATH)
    assert bus.messages[0].path == _EDGE_PATH
    assert bus.messages[0].body == [UNIT_INTERFACE, name]


@pytest.mark.parametrize("path, body", [
    # SubState/LoadState are admitted on the Edge object and the packaged
    # services the unit-state observer reads (U2), and nowhere else.
    (_unit_object_path("systemd-journald.service"), [UNIT_INTERFACE, "SubState"]),
    (_unit_object_path("systemd-journald.service"), [UNIT_INTERFACE, "LoadState"]),
    (_unit_object_path("azazel-units-observe.timer"), [UNIT_INTERFACE, "SubState"]),
    (_unit_object_path("azazel-auditd.service"), [UNIT_INTERFACE, "ExecStart"]),
    (_unit_object_path("sshd.service"), [UNIT_INTERFACE, "SubState"]),
    (_EDGE_PATH, [UNIT_INTERFACE, "ExecStart"]),
    (_EDGE_PATH, [UNIT_INTERFACE, "MainPID"]),
    (_EDGE_PATH, ["org.freedesktop.systemd1.Service", "SubState"]),
    (_EDGE_PATH, [UNIT_INTERFACE, ["SubState"]]),
    (_EDGE_PATH, [UNIT_INTERFACE, "SubState", "extra"]),
])
def test_bus_allowlist_still_refuses_other_properties_and_paths(path, body):
    session, bus = _session_for_allowlist()
    with pytest.raises(UnitOperationFailed):
        session._exchange(PROPERTIES_INTERFACE, "Get", "ss", body, path=path)
    assert bus.messages == []


# -- the pass's loaded-unit reads (#251 H-1) ---------------------------------

_INTAKE = "azazel-edge-intaked.service"
_MARKER_CONDITION = ["ConditionPathExists", False, False,
                     f"/run/azazel-activation/granted/{_INTAKE}", 0]
_LOADED = {
    "Id": ("s", _INTAKE),
    "LoadState": ("s", "loaded"),
    "FragmentPath": ("s", f"/usr/lib/systemd/system/{_INTAKE}"),
    "DropInPaths": ("as", []),
    "Conditions": ("a(sbbsi)", [_MARKER_CONDITION]),
    "Asserts": ("a(sbbsi)", []),
    "Requires": ("as", ["azazel-activated.service", "system.slice"]),
    "After": ("as", ["azazel-activated.service", "basic.target"]),
    # Present in the reply and not kept.
    "ActiveState": ("s", "inactive"),
}


def _loaded_exchange(calls, values=None, *, not_loaded=False, drop=()):
    values = {name: value for name, value in dict(_LOADED, **(values or {})).items()
              if name not in drop}

    def exchange(interface, member, signature, body, **kwargs):
        calls.append((interface, member, signature, list(body), kwargs))
        if member == "GetUnit":
            if not_loaded:
                return _Reply("", [], no_such_unit=True)
            return _Reply("o", [_unit_object_path(body[0])])
        return _Reply("a{sv}", [{name: SimpleNamespace(signature=kind, value=value)
                                 for name, (kind, value) in values.items()}])
    return exchange


def test_loaded_unit_reads_only_fixed_properties_of_a_grantable_unit():
    calls = []
    loaded = SystemdUnitCalls(_loaded_exchange(calls)).loaded_unit(_INTAKE)
    assert loaded == {
        "Id": _INTAKE, "LoadState": "loaded",
        "FragmentPath": f"/usr/lib/systemd/system/{_INTAKE}", "DropInPaths": [],
        "Conditions": [tuple(_MARKER_CONDITION)], "Asserts": [],
        "Requires": ["azazel-activated.service", "system.slice"],
        "After": ["azazel-activated.service", "basic.target"],
    }
    path = _unit_object_path(_INTAKE)
    assert calls == [
        (MANAGER_INTERFACE, "GetUnit", "s", [_INTAKE], {"allow_no_such_unit": True}),
        (PROPERTIES_INTERFACE, "GetAll", "s", [UNIT_INTERFACE], {"path": path}),
    ]


def test_loaded_unit_reports_a_unit_the_manager_does_not_hold_as_none():
    calls = []
    assert SystemdUnitCalls(_loaded_exchange(calls, not_loaded=True)).loaded_unit(_INTAKE) is None
    assert len(calls) == 1


@pytest.mark.parametrize("unit", ["azazel-watchdog.service", "azazel-auditd.service",
                                  "sshd.service"])
def test_loaded_unit_refuses_a_unit_outside_the_grantable_set_before_the_bus(unit):
    calls = []
    with pytest.raises(UnitOperationFailed):
        SystemdUnitCalls(_loaded_exchange(calls)).loaded_unit(unit)
    assert calls == []


@pytest.mark.parametrize("values", [
    {"Id": ("as", [_INTAKE])},
    {"FragmentPath": ("s", 7)},
    {"DropInPaths": ("as", [1])},
    {"Conditions": ("a(sbbsi)", [["ConditionPathExists", 0, False, "/x", 0]])},
    {"Conditions": ("a(sbbsi)", [["ConditionPathExists", False, False, "/x"]])},
    {"Asserts": ("as", [])},
    {"Requires": ("s", "azazel-activated.service")},
    {"After": ("as", [None])},
])
def test_loaded_unit_refuses_malformed_properties(values):
    with pytest.raises(UnitOperationFailed):
        SystemdUnitCalls(_loaded_exchange([], values)).loaded_unit(_INTAKE)


@pytest.mark.parametrize("name", ["Conditions", "Requires", "After", "FragmentPath"])
def test_loaded_unit_refuses_a_reply_without_a_kept_property(name):
    with pytest.raises(UnitOperationFailed):
        SystemdUnitCalls(_loaded_exchange([], drop=(name,))).loaded_unit(_INTAKE)


def test_loaded_unit_refuses_a_reply_of_another_shape():
    def exchange(interface, member, signature, body, **kwargs):
        if member == "GetUnit":
            return _Reply("o", [_unit_object_path(body[0])])
        return _Reply("a{sv}", [[("Id", SimpleNamespace(signature="s", value=_INTAKE))]])
    with pytest.raises(UnitOperationFailed):
        SystemdUnitCalls(exchange).loaded_unit(_INTAKE)


def test_bus_session_allows_loaded_unit_reads_only_on_grantable_unit_objects():
    bus = _BusStub(SimpleNamespace(message_type=1, signature="v", body=[]))
    session = SystemdBusSession(
        bus=bus, loop=_LoopStub(), previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=_MessageStub,
    )
    for path, name in (
        (_unit_object_path(_INTAKE), "FragmentPath"),
        (_unit_object_path(_INTAKE), "Conditions"),
        (_unit_object_path(_INTAKE), "ExecStart"),
    ):
        with pytest.raises(UnitOperationFailed):
            session._exchange(PROPERTIES_INTERFACE, "Get", "ss", [UNIT_INTERFACE, name],
                              path=path)
    for path, body, signature in (
        (_unit_object_path("azazel-auditd.service"), [UNIT_INTERFACE], "s"),
        (_unit_object_path("azazel-watchdog.service"), [UNIT_INTERFACE], "s"),
        (_unit_object_path("sshd.service"), [UNIT_INTERFACE], "s"),
        ("/org/freedesktop/systemd1", [MANAGER_INTERFACE], "s"),
        (_unit_object_path(_INTAKE), ["org.freedesktop.systemd1.Service"], "s"),
        (_unit_object_path(_INTAKE), [UNIT_INTERFACE, "Id"], "ss"),
    ):
        with pytest.raises(UnitOperationFailed):
            session._exchange(PROPERTIES_INTERFACE, "GetAll", signature, body, path=path)
    assert bus.messages == []


def test_bus_session_sends_getall_of_the_unit_interface_for_a_grantable_unit():
    reply = SimpleNamespace(message_type=1, signature="a{sv}", body=[{}])
    bus = _BusStub(reply)
    session = SystemdBusSession(
        bus=bus, loop=_LoopStub(), previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=_MessageStub,
    )
    path = _unit_object_path(_INTAKE)
    session._exchange(PROPERTIES_INTERFACE, "GetAll", "s", [UNIT_INTERFACE], path=path)
    message = bus.messages[0]
    assert (message.path, message.interface, message.member, message.signature,
            message.body) == (path, PROPERTIES_INTERFACE, "GetAll", "s", [UNIT_INTERFACE])
