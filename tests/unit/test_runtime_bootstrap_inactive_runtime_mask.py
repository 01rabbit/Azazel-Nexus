"""Inactivity of the owned pair under a fence whose overlay masks are empty files.

After a pair publication `close_starts` truncates the owned overlay files in
/run/systemd/system.control, so systemd reports ``masked-runtime`` for the
unloaded helpers. The generic unit client accepts only ``masked``; under a
confirmed fence the manager must observe against the attested fragment.
"""

import asyncio
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.bootstrap_masked import MaskedBootstrapPair
from azazel_nexus_runtime.bootstrap_stop import BootstrapStopJobs
from azazel_nexus_runtime.systemd_bus import SystemdUnitCalls, _Reply, _unit_object_path
from azazel_nexus_runtime.units import UNIT_NAMES, DbusUnitManager, UnitKey, UnitOperationFailed

OWNER = ":1.42"
NO_SUCH_UNIT = "org.freedesktop.systemd1.NoSuchUnit"
RUNTIME_DIR = "/run/systemd/system.control/"
ETC_DIR = "/etc/systemd/system/"
UNIT = UnitKey.AUDITD
NAME = UNIT_NAMES[UNIT]
PATH = _unit_object_path(NAME)
TYPES = SimpleNamespace(ERROR=3, METHOD_RETURN=1, SIGNAL=4)


class Message:
    def __init__(self, *, destination, path, interface, member, signature, body):
        self.destination = destination
        self.path = path
        self.interface = interface
        self.member = member
        self.signature = signature
        self.body = body


class Variant:
    def __init__(self, signature, value):
        self.signature = signature
        self.value = value


def _ok(signature, body, sender=OWNER):
    return SimpleNamespace(message_type=1, signature=signature, body=body, sender=sender)


def _no_such_unit(sender=OWNER):
    return SimpleNamespace(
        message_type=3, signature="s", body=["no unit"], sender=sender,
        error_name=NO_SUCH_UNIT,
    )


class ScriptBus:
    """Scripted fake: GetUnit replies come from a list (last one repeats)."""

    def __init__(self, *, get_unit, file_state="masked-runtime", owner=OWNER,
                 active=None):
        self.get_unit = list(get_unit)
        self.file_state = file_state
        self.owner = owner
        self.active = active
        self.calls = []
        self.disconnected = False

    def disconnect(self):
        self.disconnected = True

    async def call(self, message):
        self.calls.append(message.member)
        if message.member == "GetNameOwner":
            return _ok("s", [self.owner], sender="org.freedesktop.DBus")
        if message.member == "GetUnit":
            reply = self.get_unit.pop(0) if len(self.get_unit) > 1 else self.get_unit[0]
            return _no_such_unit() if reply == "nosuch" else _ok("o", [reply])
        if message.member == "GetUnitFileState":
            return _ok("s", [self.file_state])
        if message.member == "Get":
            return _ok("v", [self.active])
        raise AssertionError(message.member)


def _client(bus, *, expected_owner=OWNER):
    return BootstrapStopJobs(
        bus=bus, message_factory=Message, message_type=TYPES,
        timeout_seconds=5.0, expected_owner=expected_owner,
    )


def _observe(bus, fragment, *, unit=UNIT, expected_owner=OWNER, client=None):
    client = client or _client(bus, expected_owner=expected_owner)
    return asyncio.run(client.observe_inactive(unit, fragment=fragment))


def _unloaded(state, **kwargs):
    return ScriptBus(get_unit=["nosuch", "nosuch"], file_state=state, **kwargs)


RUNTIME_FRAGMENT = RUNTIME_DIR + NAME
ETC_FRAGMENT = ETC_DIR + NAME


@pytest.mark.parametrize("fragment,state", [
    (RUNTIME_FRAGMENT, "masked-runtime"),
    (ETC_FRAGMENT, "masked"),
])
def test_unloaded_unit_with_matching_mask_is_inactive(fragment, state):
    bus = _unloaded(state)
    assert _observe(bus, fragment) is True
    assert bus.calls == [
        "GetNameOwner", "GetUnit", "GetUnitFileState", "GetUnit",
    ]


@pytest.mark.parametrize("fragment,state", [
    (RUNTIME_FRAGMENT, "masked"),
    (ETC_FRAGMENT, "masked-runtime"),
    ("/usr/lib/systemd/system/" + NAME, "masked"),
    ("/usr/lib/systemd/system/" + NAME, "masked-runtime"),
    (RUNTIME_FRAGMENT, "enabled"),
    (RUNTIME_FRAGMENT, "static"),
    (ETC_FRAGMENT, "enabled"),
    (ETC_FRAGMENT, "static"),
])
def test_unloaded_unit_with_mismatching_mask_is_refused(fragment, state):
    with pytest.raises(UnitOperationFailed):
        _observe(_unloaded(state), fragment)


def test_unit_loaded_between_the_two_reads_is_refused():
    bus = ScriptBus(get_unit=["nosuch", PATH], file_state="masked-runtime")
    with pytest.raises(UnitOperationFailed):
        _observe(bus, RUNTIME_FRAGMENT)


def test_owner_mismatch_is_refused():
    with pytest.raises(UnitOperationFailed):
        _observe(_unloaded("masked-runtime", owner=":1.99"), RUNTIME_FRAGMENT)


def test_missing_expected_owner_is_refused():
    with pytest.raises(UnitOperationFailed):
        _observe(_unloaded("masked-runtime"), RUNTIME_FRAGMENT, expected_owner=None)


@pytest.mark.parametrize("unit", [UnitKey.WATCHDOG, UnitKey.EDGE_PROBE, "auditd", NAME, None])
def test_unit_outside_pair_or_not_a_unitkey_is_refused(unit):
    bus = _unloaded("masked-runtime")
    with pytest.raises(UnitOperationFailed):
        _observe(bus, RUNTIME_FRAGMENT, unit=unit)
    assert bus.calls == []


@pytest.mark.parametrize("fragment", [None, b"/run/systemd/system.control/x", 7, ["x"]])
def test_non_str_fragment_is_refused(fragment):
    bus = _unloaded("masked-runtime")
    with pytest.raises(UnitOperationFailed):
        _observe(bus, fragment)
    assert bus.calls == []


def test_client_cannot_be_reused_after_a_call():
    bus = _unloaded("masked-runtime")
    client = _client(bus)
    assert _observe(bus, RUNTIME_FRAGMENT, client=client) is True
    with pytest.raises(UnitOperationFailed):
        _observe(bus, RUNTIME_FRAGMENT, client=client)


def test_concurrent_use_is_busy():
    bus = _unloaded("masked-runtime")
    client = _client(bus)

    async def both():
        first = asyncio.ensure_future(
            client.observe_inactive(UNIT, fragment=RUNTIME_FRAGMENT))
        await asyncio.sleep(0)
        with pytest.raises(UnitOperationFailed, match="already in progress"):
            await client.observe_inactive(UNIT, fragment=RUNTIME_FRAGMENT)
        return await first

    assert asyncio.run(both()) is True


@pytest.mark.parametrize("active,expected", [("inactive", True), ("active", False)])
def test_loaded_unit_reports_active_state(active, expected):
    bus = ScriptBus(get_unit=[PATH], active=Variant("s", active))
    assert _observe(bus, RUNTIME_FRAGMENT) is expected
    assert "GetUnitFileState" not in bus.calls


@pytest.mark.parametrize("variant", [
    Variant("u", "inactive"), Variant("s", 3), Variant("s", None), None,
])
def test_loaded_unit_with_malformed_active_state_is_refused(variant):
    bus = ScriptBus(get_unit=[PATH], active=variant)
    with pytest.raises(UnitOperationFailed):
        _observe(bus, RUNTIME_FRAGMENT)


def test_loaded_unit_at_wrong_object_path_is_refused():
    bus = ScriptBus(get_unit=["/org/freedesktop/systemd1/unit/other"],
                    active=Variant("s", "inactive"))
    with pytest.raises(UnitOperationFailed):
        _observe(bus, RUNTIME_FRAGMENT)


# --- manager level -----------------------------------------------------------

class ManagerSession:
    """Owned-loop session; also callable as the generic (method, unit) client."""

    def __init__(self, bus):
        self._bus = bus
        self._loop = asyncio.new_event_loop()
        self._message_factory = Message
        self._message_type = TYPES
        self.closed = False
        self.generic_calls = []
        self._generic = SystemdUnitCalls(self._exchange)

    def _exchange(self, interface, member, signature, body, **kwargs):
        self.generic_calls.append(member)
        if member == "GetUnit":
            return _Reply("", [], no_such_unit=True)
        if member == "GetUnitFileState":
            return _Reply("s", [self._bus.file_state])
        raise AssertionError(member)

    def __call__(self, method, unit):
        return self._generic(method, unit)

    def close(self):
        if not self._loop.is_closed():
            self._loop.close()
        self.closed = True


def _manager(session):
    return BootstrapNarrowingManager(
        job_timeout_seconds=5.0, session_factory=lambda: session)


def _fence(directory=RUNTIME_DIR):
    return MaskedBootstrapPair(
        owner=OWNER,
        fragments=tuple((u, directory + UNIT_NAMES[u])
                        for u in (UnitKey.AUDITD, UnitKey.COMMISSIOND)),
        fingerprint="f" * 64,
        not_loaded=(UnitKey.AUDITD, UnitKey.COMMISSIOND),
    )


def test_manager_with_fence_confirms_runtime_masked_unit_inactive():
    bus = _unloaded("masked-runtime")
    session = ManagerSession(bus)
    manager = _manager(session)
    manager._closed_observation = _fence()
    assert manager.is_inactive(UNIT) is True
    assert session.generic_calls == []
    assert session.closed


def test_manager_with_fence_still_refuses_mismatched_mask():
    session = ManagerSession(_unloaded("masked"))
    manager = _manager(session)
    manager._closed_observation = _fence()
    with pytest.raises(UnitOperationFailed):
        manager.is_inactive(UNIT)


def test_manager_with_fence_pins_the_fence_owner():
    session = ManagerSession(_unloaded("masked-runtime", owner=":1.7"))
    manager = _manager(session)
    manager._closed_observation = _fence()
    with pytest.raises(UnitOperationFailed):
        manager.is_inactive(UNIT)


def test_manager_without_fence_uses_generic_path_and_refuses_masked_runtime():
    session = ManagerSession(_unloaded("masked-runtime"))
    manager = _manager(session)
    assert manager._closed_observation is None
    with pytest.raises(UnitOperationFailed, match="not masked"):
        manager.is_inactive(UNIT)
    assert session.generic_calls == ["GetUnit", "GetUnitFileState"]
    assert session._bus.calls == []


def test_manager_without_fence_generic_path_accepts_plain_masked():
    session = ManagerSession(_unloaded("masked"))
    manager = _manager(session)
    assert manager.is_inactive(UNIT) is True
    assert session._bus.calls == []


def test_generic_client_unchanged_refuses_masked_runtime():
    session = ManagerSession(_unloaded("masked-runtime"))
    with pytest.raises(UnitOperationFailed):
        DbusUnitManager(session).is_inactive(NAME)
