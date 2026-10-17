"""A masked governed unit that systemd has not loaded reads as inactive."""

from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import activated
from azazel_nexus_runtime.systemd_bus import (
    MANAGER_INTERFACE,
    SystemdBusSession,
    SystemdUnitCalls,
    _Reply as Reply,
)
from azazel_nexus_runtime.units import DbusUnitManager, UnitOperationFailed
from test_runtime_systemd_bus import Variant, _BusStub, _LoopStub, _MessageStub

from azazel_nexus.activation import CORE_UNITS, UnitState
from azazel_nexus.audit import AuditLedger

NO_SUCH_UNIT = "org.freedesktop.systemd1.NoSuchUnit"
UNIT = "azazel-auditd.service"
PATH = "/org/freedesktop/systemd1/unit/azazel_2dauditd_2eservice"
NOW = "2026-10-13T00:00:00Z"


def _calls(file_state, calls=None):
    def exchange(interface, member, signature, body, **kwargs):
        if calls is not None:
            calls.append(member)
        if member == "GetUnit":
            return Reply("", [], no_such_unit=True)
        if member == "GetUnitFileState":
            return Reply("s", [file_state])
        raise AssertionError(member)

    return SystemdUnitCalls(exchange)


def _session(reply):
    return SystemdBusSession(
        bus=_BusStub(reply), loop=_LoopStub(), previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=_MessageStub,
    )


def test_not_loaded_and_masked_is_inactive_and_not_active():
    calls = []
    assert _calls("masked", calls)("GetInactiveState", UNIT) is True
    assert _calls("masked")("GetActiveState", UNIT) is False
    assert calls == ["GetUnit", "GetUnitFileState", "GetUnit"]


@pytest.mark.parametrize("method", ["GetActiveState", "GetInactiveState"])
def test_unit_loaded_between_first_read_and_recheck_is_refused(method):
    seen = {"get_unit": 0}

    def exchange(interface, member, signature, body, **kwargs):
        if member == "GetUnit":
            seen["get_unit"] += 1
            if seen["get_unit"] == 1:
                return Reply("", [], no_such_unit=True)
            return Reply("o", [PATH])
        if member == "GetUnitFileState":
            return Reply("s", ["masked"])
        raise AssertionError(member)

    with pytest.raises(UnitOperationFailed, match="loaded during observation"):
        SystemdUnitCalls(exchange)(method, UNIT)


@pytest.mark.parametrize("state", [
    "enabled", "disabled", "static", "masked-runtime", "linked", "bad", "",
])
@pytest.mark.parametrize("method", ["GetActiveState", "GetInactiveState"])
def test_not_loaded_but_not_masked_is_refused(state, method):
    with pytest.raises(UnitOperationFailed):
        _calls(state)(method, UNIT)


def test_not_loaded_with_malformed_file_state_reply_is_refused():
    def exchange(interface, member, signature, body, **kwargs):
        if member == "GetUnit":
            return Reply("", [], no_such_unit=True)
        return Reply("u", [1])

    with pytest.raises(UnitOperationFailed):
        SystemdUnitCalls(exchange)("GetInactiveState", UNIT)


def test_loaded_unit_path_is_unchanged():
    def exchange(interface, member, signature, body, **kwargs):
        if member == "GetUnit":
            return Reply("o", [PATH])
        return Reply("v", [Variant("inactive")])

    assert SystemdUnitCalls(exchange)("GetInactiveState", UNIT) is True
    assert SystemdUnitCalls(exchange)("GetActiveState", UNIT) is False


def test_session_returns_distinguishable_outcome_only_for_exact_name():
    reply = SimpleNamespace(message_type=3, signature="s", body=["x"], error_name=NO_SUCH_UNIT)
    outcome = _session(reply)._exchange(
        MANAGER_INTERFACE, "GetUnit", "s", [UNIT], allow_no_such_unit=True)
    assert outcome.no_such_unit is True


def test_session_refuses_no_such_unit_without_opt_in():
    reply = SimpleNamespace(message_type=3, signature="s", body=["x"], error_name=NO_SUCH_UNIT)
    with pytest.raises(UnitOperationFailed, match="returned an error"):
        _session(reply)._exchange(MANAGER_INTERFACE, "GetUnit", "s", [UNIT])
    with pytest.raises(UnitOperationFailed, match="returned an error"):
        _session(reply)("GetUnitFileState", UNIT)


@pytest.mark.parametrize("name", [
    "org.freedesktop.DBus.Error.AccessDenied",
    "org.freedesktop.systemd1.NoSuchUnit.Other",
    "org.freedesktop.systemd1.NoSuchUnits",
    "org.freedesktop.systemd1.nosuchunit",
    "org.freedesktop.systemd1.Failed",
    "", None, 7, b"org.freedesktop.systemd1.NoSuchUnit",
])
def test_session_refuses_any_other_error_name(name):
    reply = SimpleNamespace(message_type=3, signature="s", body=["x"], error_name=name)
    with pytest.raises(UnitOperationFailed):
        _session(reply)._exchange(
            MANAGER_INTERFACE, "GetUnit", "s", [UNIT], allow_no_such_unit=True)


def test_session_refuses_error_reply_with_no_error_name_attribute():
    reply = SimpleNamespace(message_type=3, signature="s", body=["x"])
    with pytest.raises(UnitOperationFailed):
        _session(reply)._exchange(
            MANAGER_INTERFACE, "GetUnit", "s", [UNIT], allow_no_such_unit=True)


def test_session_checks_owner_on_no_such_unit_reply():
    reply = SimpleNamespace(message_type=3, signature="s", body=["x"],
                            error_name=NO_SUCH_UNIT, sender=":1.99")
    session = _session(reply)
    session._admitted_owner = ":1.42"
    with pytest.raises(UnitOperationFailed, match="owner refused"):
        session._exchange(MANAGER_INTERFACE, "GetUnit", "s", [UNIT], allow_no_such_unit=True)


def test_session_other_errors_still_refused_through_the_public_call():
    reply = SimpleNamespace(message_type=3, signature="s", body=["x"],
                            error_name="org.freedesktop.DBus.Error.AccessDenied")
    with pytest.raises(UnitOperationFailed):
        _session(reply)("GetInactiveState", UNIT)


def test_activation_pass_with_masked_unloaded_units_is_safe_not_rollback_failed(tmp_path):
    """Models the real host: masked units are never loaded, GetUnit says so."""

    names = {d.name for d in CORE_UNITS}
    masked = set(names)

    def exchange(interface, member, signature, body, **kwargs):
        unit = body[0] if member != "MaskUnitFiles" else body[0][0]
        assert unit in names
        if member == "GetUnit":
            return Reply("", [], no_such_unit=True)
        if member == "GetUnitFileState":
            return Reply("s", ["masked" if unit in masked else "enabled"])
        if member == "MaskUnitFiles":
            masked.add(unit)
            return Reply("a(sss)", [[]])
        raise AssertionError(member)

    manager = DbusUnitManager(SystemdUnitCalls(exchange))
    outcome = activated._run_once(manager=manager, root=tmp_path, now=NOW, actor="test")
    assert outcome.granted == ()
    assert all(manager.state(n) is UnitState.MASKED for n in names)
    assert list(AuditLedger(tmp_path / "var/lib/azazel/state/activation.jsonl"))
