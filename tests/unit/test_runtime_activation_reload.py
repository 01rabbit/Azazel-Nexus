"""F2/F1 (docs/activation-observe-baseline.md): Manager.Reload ends every batch.

A mask, unmask or enable changes unit files; a manager that loaded a unit
earlier keeps acting on its loaded definition until it is reloaded. So each
batch of such changes is followed by one Reload, and after the grant's Reload
the guarded units' loaded definitions are verified again before any marker is
written or READY is sent.

The ordering test reads `RecordingUnitManager.timeline` and fails if any
Reload is missing (the negative tests remove a Reload and expect the checker
to refuse the result).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from azazel_nexus.activation import CORE_UNITS, UnitState
from azazel_nexus_runtime import activated
from azazel_nexus_runtime.activation_loaded_units import verify_loaded_units
from azazel_nexus_runtime.systemd_bus import (
    MANAGER_INTERFACE, SystemdBusSession, SystemdUnitCalls, _Reply,
)
from azazel_nexus_runtime.units import (
    DbusUnitManager, RecordingUnitManager, UnitOperationFailed,
)

from test_runtime_activation_pass import NOW, SCOPE, world  # noqa: F401 - fixture

MUTATIONS = {"mask", "unmask_and_enable"}


def check_reload_after_every_batch(timeline) -> None:
    """Every maximal run of mask/unmask_and_enable is followed by a reload."""
    pending = False
    for operation, _unit in timeline:
        if operation in MUTATIONS:
            pending = True
        elif operation == "reload":
            pending = False
        else:  # pragma: no cover - the recording manager has no other verb
            raise AssertionError(operation)
    assert not pending, "unit file changes were left without a Manager.Reload"


def reload_positions(timeline):
    return [index for index, (operation, _) in enumerate(timeline) if operation == "reload"]


# -- the order of a granting pass ------------------------------------------------


def assert_granting_pass_shape(timeline) -> None:
    """Preflight masks, one reload, the grant batch, one reload."""
    check_reload_after_every_batch(timeline)
    count = len(CORE_UNITS)
    assert [op for op, _ in timeline[:count]] == ["mask"] * count
    assert timeline[count] == ("reload", ""), "no reload after the preflight masks"
    rest = timeline[count + 1:]
    assert sorted(unit for op, unit in rest if op == "unmask_and_enable") == sorted(SCOPE)
    assert rest[-1] == ("reload", ""), "no reload after the grants"
    assert all(op != "reload" for op, _ in rest[:-1])
    assert len(reload_positions(timeline)) == 2


def skip_reload(manager, which: int) -> None:
    """The mutation: the `which`-th reload (0-based) is silently not made."""
    original = manager.reload
    seen = {"count": -1}

    def reload():
        seen["count"] += 1
        if seen["count"] != which:
            original()

    manager.reload = reload


def test_a_granting_pass_reloads_after_the_preflight_masks_and_after_the_grants(world):
    world.manager.timeline.clear()  # the fixture's setup widened everything first
    outcome = world.run()
    assert sorted(outcome.granted) == list(SCOPE)
    assert_granting_pass_shape(world.manager.timeline)


def test_removing_the_preflight_reload_is_caught(world):
    world.manager.timeline.clear()
    skip_reload(world.manager, 0)
    world.run()
    with pytest.raises(AssertionError, match="no reload after the preflight masks"):
        assert_granting_pass_shape(world.manager.timeline)


def test_removing_the_grant_reload_is_caught(world):
    world.manager.timeline.clear()
    skip_reload(world.manager, 1)
    world.run()
    with pytest.raises(AssertionError, match="without a Manager.Reload|no reload after the grants"):
        assert_granting_pass_shape(world.manager.timeline)


def test_the_checker_itself_refuses_a_missing_reload():
    with pytest.raises(AssertionError):
        check_reload_after_every_batch([("mask", "a"), ("unmask_and_enable", "b")])
    check_reload_after_every_batch([("mask", "a"), ("reload", ""),
                                    ("unmask_and_enable", "b"), ("reload", "")])


# -- failure is fail-closed -------------------------------------------------------


def test_a_failed_reload_after_the_grants_leaves_nothing_granted(world):
    world.manager = RecordingUnitManager(
        (d.name for d in CORE_UNITS), fail_reload=True)
    with pytest.raises(Exception):
        world.run()
    assert all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert world.markers() is None
    assert world.raised == []


def test_a_failed_preflight_reload_stops_the_pass_before_any_grant(world):
    manager = RecordingUnitManager((d.name for d in CORE_UNITS), fail_reload=True)
    world.manager = manager
    with pytest.raises(Exception):
        world.run()
    assert not any(op == "unmask_and_enable" for op, _ in manager.timeline)
    assert world.markers() is None


def test_an_emergency_narrowing_reloads_after_its_masks(world):
    manager = world.manager
    manager.timeline.clear()
    with pytest.raises(RuntimeError):
        activated._emergency_narrow(manager, world.root, "synthetic")
    assert manager.timeline[-1] == ("reload", "")
    check_reload_after_every_batch(manager.timeline)


def test_an_emergency_narrowing_reports_a_failed_reload(world):
    manager = RecordingUnitManager((d.name for d in CORE_UNITS), fail_reload=True)
    with pytest.raises(RuntimeError, match="manager reload"):
        activated._emergency_narrow(manager, world.root, "synthetic")


# -- the grantable units are verified again after the reload -----------------------


def test_the_loaded_units_are_verified_again_after_the_grant_reload(world):
    log = []
    manager = world.manager
    original_reload = manager.reload

    def reload():
        log.append("reload")
        original_reload()

    manager.reload = reload

    def loaded_units(units):
        log.append("loaded_units")
        verify_loaded_units(world.systemd, units)

    outcome = world.run(loaded_units=loaded_units)
    assert sorted(outcome.granted) == list(SCOPE)
    # collection, then (preflight reload before it) the grant reload, then the
    # second verification, with nothing between the grant reload and it.
    assert log == ["reload", "loaded_units", "reload", "loaded_units"]


def test_a_unit_that_fails_verification_after_the_reload_is_not_granted(world):
    seen = {"count": 0}

    def loaded_units(units):
        seen["count"] += 1
        if seen["count"] == 2:  # only the check after the grant's Reload fails
            raise UnitOperationFailed("loaded definition changed by the reload")
        verify_loaded_units(world.systemd, units)

    with pytest.raises(RuntimeError, match="not verified as loaded after the manager reload"):
        world.run(loaded_units=loaded_units)
    assert seen["count"] == 2
    assert all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert world.markers() is None
    assert world.raised == []  # the floors are raised only after the verification
    assert any(e["event_type"] == "activation.grant_unverified_after_reload"
               for e in world.events())


def test_no_verification_after_the_reload_is_required_when_nothing_is_granted(world):
    world.healthy = False
    seen = {"count": 0}

    def loaded_units(units):
        seen["count"] += 1
        verify_loaded_units(world.systemd, units)

    outcome = world.run(loaded_units=loaded_units)
    assert outcome.granted == ()
    assert seen["count"] == 1


# -- the D-Bus layer -----------------------------------------------------------------


def test_reload_is_one_argument_less_manager_call():
    calls = []

    def exchange(interface, member, signature, body, **kwargs):
        calls.append((interface, member, signature, body, kwargs))
        return _Reply("", [])

    SystemdUnitCalls(exchange).reload()
    assert calls == [(MANAGER_INTERFACE, "Reload", "", [], {})]


@pytest.mark.parametrize("reply", [_Reply("s", ["x"]), _Reply("", ["x"]), _Reply("u", [1])])
def test_a_reload_reply_with_content_is_refused(reply):
    with pytest.raises(UnitOperationFailed):
        SystemdUnitCalls(lambda *a, **k: reply).reload()


def test_the_session_sends_reload_with_an_empty_signature_and_body():
    class Bus:
        def __init__(self):
            self.messages = []

        async def call(self, message):
            self.messages.append(message)
            return SimpleNamespace(message_type=1, signature="", body=[])

        def disconnect(self):
            pass

    class Loop:
        def run_until_complete(self, awaitable):
            import asyncio
            return asyncio.run(awaitable)

        def is_closed(self):
            return False

    class Message:
        def __init__(self, **values):
            self.__dict__.update(values)

    bus = Bus()
    session = SystemdBusSession(
        bus=bus, loop=Loop(), previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1), message_factory=Message)
    session.reload()
    [message] = bus.messages
    assert (message.interface, message.member, message.signature, message.body,
            message.path) == (MANAGER_INTERFACE, "Reload", "", [], "/org/freedesktop/systemd1")


def test_the_exchange_refuses_a_reload_with_an_argument_before_the_bus():
    class Bus:
        messages = []

        async def call(self, message):  # pragma: no cover - must not be reached
            self.messages.append(message)

    session = SystemdBusSession(
        bus=Bus(), loop=SimpleNamespace(), previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=lambda **values: SimpleNamespace(**values))
    with pytest.raises(UnitOperationFailed):
        session._exchange(MANAGER_INTERFACE, "Reload", "s", ["azazel-auditd.service"])
    with pytest.raises(UnitOperationFailed):
        session._exchange(MANAGER_INTERFACE, "Reload", "", ["x"])
    assert Bus.messages == []


def test_the_unit_manager_reloads_through_the_session_and_not_through_call():
    reloads = []

    class Adapter:
        def __call__(self, method, unit):  # pragma: no cover - reload never goes here
            raise AssertionError(method)

        def reload(self):
            reloads.append(1)

    DbusUnitManager(call=Adapter()).reload()
    assert reloads == [1]


def test_an_adapter_without_reload_cannot_confirm_a_batch():
    with pytest.raises(UnitOperationFailed, match="cannot reload"):
        DbusUnitManager(call=lambda method, unit: None).reload()


def test_the_base_manager_does_not_pretend_to_reload():
    from azazel_nexus_runtime.units import UnitManager
    with pytest.raises(NotImplementedError):
        UnitManager().reload()
