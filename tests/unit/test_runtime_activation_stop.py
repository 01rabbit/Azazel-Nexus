"""The fixed stop of the Knowledge Context broker (stop contract, main pass).

Covers the D-Bus layer (`StopUnit` with constant body, the `Job` read, the
authority type), the pass lock, `withdraw_contextd`, and the main pass:
preflight withdrawal of a running broker, replacement of a queued job for a
broker that is not granted, the 45 s budget and the 60 s start timeout.

Negative checks: removing the StopUnit, the marker removal or the reload makes
the scenario's own check fail (`test_*_is_caught`).
"""

from __future__ import annotations

import fcntl
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_nexus.activation import CORE_UNITS, UnitState
from azazel_nexus_runtime import activated, activation_lock, activation_markers
from azazel_nexus_runtime.activation_lock import (
    PassLockBusy, PassLockRefused, acquire_pass_lock,
)
from azazel_nexus_runtime.activation_withdraw import (
    STOP_WAIT_SECONDS, WithdrawalUnconfirmed, clear_contextd_job, withdraw_contextd,
)
from azazel_nexus_runtime.systemd_bus import (
    MANAGER_INTERFACE, PROPERTIES_INTERFACE, UNIT_INTERFACE, SystemdBusSession,
    SystemdUnitCalls, _Reply, _unit_object_path,
)
from azazel_nexus_runtime.units import (
    CONTEXTD_UNIT, ContextdStopAuthority, DbusUnitManager, UnitOperationFailed,
)
from azazel_nexus.audit import AuditLedger

from stop_helpers import (
    CTX, JOB, NO_JOB, ContextdModel, FakeClock, ModelManager, authority,
    failing_authority,
)
from test_runtime_activation_contextd import CTX_SCOPE, ctx_world  # noqa: F401 - fixture
from test_runtime_activation_pass import NOW, SCOPE

ROOT_DIRECTORY = Path(__file__).resolve().parents[2]


# -- the authority type and the D-Bus layer --------------------------------------


@pytest.mark.parametrize("unit", ["azazel-auditd.service", "sshd.service", "",
                                  "azazel-knowledge-contextd.service ", None, 7])
def test_the_authority_refuses_any_other_unit_before_calling_anything(unit):
    called = []
    guard = ContextdStopAuthority(stop=lambda: called.append("stop"),
                                  job=lambda u: called.append("job"),
                                  state=lambda u: called.append("state"),
                                  file_state=lambda u: called.append("file_state"))
    with pytest.raises(UnitOperationFailed, match="outside its scope"):
        guard.stop(unit)
    with pytest.raises(UnitOperationFailed, match="outside its scope"):
        guard.job(unit)
    with pytest.raises(UnitOperationFailed, match="outside its scope"):
        guard.active_state(unit)
    with pytest.raises(UnitOperationFailed, match="outside its scope"):
        guard.file_state(unit)
    assert called == []


def test_an_authority_needs_all_four_verbs_of_the_session():
    with pytest.raises(UnitOperationFailed, match="four verbs"):
        ContextdStopAuthority.from_session(object())
    with pytest.raises(UnitOperationFailed, match="four verbs"):
        ContextdStopAuthority(stop=None, job=lambda unit: NO_JOB,
                              state=lambda unit: "inactive", file_state=lambda unit: "masked")


@pytest.mark.parametrize("answer", [None, (1,), "x", (1, 2), ("1", "/"), [1, "/", 3]])
def test_the_authority_refuses_a_malformed_job_answer(answer):
    guard = ContextdStopAuthority(stop=lambda: "/x", job=lambda unit: answer,
                                  state=lambda unit: "inactive",
                                  file_state=lambda unit: "masked")
    with pytest.raises(UnitOperationFailed, match="invalid job"):
        guard.job(CTX)


def test_the_unit_manager_adapter_has_no_stop_verb():
    # The stop authority is a separate type: the manager adapter handed to the
    # watchdog and the pass has no way to stop anything.
    assert not hasattr(DbusUnitManager, "stop")
    assert not hasattr(DbusUnitManager, "stop_contextd")
    assert "StopUnit" not in DbusUnitManager.METHODS


def test_stop_unit_is_one_constant_body_in_replace_mode():
    calls = []

    def exchange(interface, member, signature, body, **kwargs):
        calls.append((interface, member, signature, body, kwargs))
        return _Reply("o", ["/org/freedesktop/systemd1/job/812"])

    assert SystemdUnitCalls(exchange).stop_contextd() == "/org/freedesktop/systemd1/job/812"
    assert calls == [(MANAGER_INTERFACE, "StopUnit", "ss", [CTX, "replace"], {})]


@pytest.mark.parametrize("reply", [
    _Reply("o", ["/org/freedesktop/systemd1/unit/azazel_2dauditd_2eservice"]),
    _Reply("o", ["/"]), _Reply("o", ["/org/freedesktop/systemd1/job/0"]),
    _Reply("o", ["/org/freedesktop/systemd1/job/"]),
    _Reply("o", ["/org/freedesktop/systemd1/job/1/../2"]),
    _Reply("o", ["job/1"]), _Reply("s", ["/org/freedesktop/systemd1/job/1"]),
    _Reply("o", []), _Reply("o", ["/org/freedesktop/systemd1/job/1", "x"]),
    _Reply("o", [7]),
])
def test_a_stop_reply_that_is_not_a_job_path_is_refused(reply):
    with pytest.raises(UnitOperationFailed):
        SystemdUnitCalls(lambda *a, **k: reply).stop_contextd()


def test_a_unit_name_never_reaches_stop_unit_through_the_method_table():
    calls = []
    client = SystemdUnitCalls(lambda *a, **k: calls.append(a))
    for unit in (CTX, "azazel-auditd.service"):
        with pytest.raises(UnitOperationFailed):
            client("StopUnit", unit)
    with pytest.raises(UnitOperationFailed):
        client("StartUnit", CTX)
    assert calls == []


class _Bus:
    def __init__(self, replies):
        self.replies = list(replies)
        self.messages = []

    async def call(self, message):
        self.messages.append(message)
        return self.replies.pop(0)

    def disconnect(self):
        pass


class _Loop:
    def run_until_complete(self, awaitable):
        import asyncio
        return asyncio.run(awaitable)

    def is_closed(self):
        return False


def _session(replies):
    bus = _Bus(replies)
    session = SystemdBusSession(
        bus=bus, loop=_Loop(), previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=lambda **values: SimpleNamespace(**values))
    return session, bus


def _ok(signature, body):
    return SimpleNamespace(message_type=1, signature=signature, body=body)


def test_the_session_refuses_stop_unit_with_another_unit_or_mode_before_the_bus():
    session, bus = _session([])
    for body in ([CTX, "fail"], ["azazel-auditd.service", "replace"],
                 [CTX, "replace", "x"], [CTX], ["sshd.service", "replace"]):
        with pytest.raises(UnitOperationFailed):
            session._exchange(MANAGER_INTERFACE, "StopUnit", "ss", body)
    with pytest.raises(UnitOperationFailed):
        session._exchange(MANAGER_INTERFACE, "StopUnit", "s", [CTX])
    assert bus.messages == []


def test_the_session_sends_exactly_one_stop_message():
    session, bus = _session([_ok("o", ["/org/freedesktop/systemd1/job/3"])])
    assert session.stop_contextd() == "/org/freedesktop/systemd1/job/3"
    [message] = bus.messages
    assert (message.interface, message.member, message.signature, message.body,
            message.path) == (MANAGER_INTERFACE, "StopUnit", "ss", [CTX, "replace"],
                              "/org/freedesktop/systemd1")


def test_the_job_property_is_read_for_the_broker_alone():
    path = _unit_object_path(CTX)
    session, bus = _session([
        _ok("o", [path]),
        _ok("v", [SimpleNamespace(signature="(uo)", value=[5, "/org/freedesktop/systemd1/job/5"])]),
    ])
    assert session.unit_job(CTX) == (5, "/org/freedesktop/systemd1/job/5")
    get = bus.messages[1]
    assert (get.interface, get.member, get.body, get.path) == (
        PROPERTIES_INTERFACE, "Get", [UNIT_INTERFACE, "Job"], path)
    other, other_bus = _session([])
    with pytest.raises(UnitOperationFailed):
        other.unit_job("azazel-auditd.service")
    # The Job property of any other unit's object is refused before the bus.
    with pytest.raises(UnitOperationFailed):
        other._exchange(PROPERTIES_INTERFACE, "Get", "ss", [UNIT_INTERFACE, "Job"],
                        path=_unit_object_path("azazel-auditd.service"))
    assert other_bus.messages == []


def test_no_unit_object_means_no_job():
    session, _bus = _session([SimpleNamespace(
        message_type=3, signature="s", body=["x"],
        error_name="org.freedesktop.systemd1.NoSuchUnit")])
    assert session.unit_job(CTX) == (0, "/")


@pytest.mark.parametrize("variant", [
    SimpleNamespace(signature="(uo)", value=[0, "/org/freedesktop/systemd1/job/1"]),
    SimpleNamespace(signature="(uo)", value=[2, "/org/freedesktop/systemd1/job/3"]),
    SimpleNamespace(signature="(uo)", value=[2, "/"]),
    SimpleNamespace(signature="(uo)", value=[-1, "/"]),
    SimpleNamespace(signature="(uo)", value=[1]),
    SimpleNamespace(signature="(uo)", value=["1", "/org/freedesktop/systemd1/job/1"]),
    SimpleNamespace(signature="(us)", value=[0, "/"]),
    SimpleNamespace(signature="u", value=0),
])
def test_a_malformed_job_property_is_refused(variant):
    session, _bus = _session([_ok("o", [_unit_object_path(CTX)]), _ok("v", [variant])])
    with pytest.raises(UnitOperationFailed):
        session.unit_job(CTX)


def test_the_job_of_the_idle_broker_reads_as_none():
    session, _bus = _session([
        _ok("o", [_unit_object_path(CTX)]),
        _ok("v", [SimpleNamespace(signature="(uo)", value=[0, "/"])])])
    assert session.unit_job(CTX) == NO_JOB


# -- the pass lock -------------------------------------------------------------------


@pytest.fixture
def lock_root(tmp_path, monkeypatch):
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    parent = tmp_path / "run" / "azazel-activation"
    parent.mkdir(parents=True)
    parent.chmod(0o755)
    return tmp_path


def test_the_lock_is_created_private_and_released_on_exit(lock_root):
    with acquire_pass_lock(lock_root):
        info = (lock_root / "run/azazel-activation/pass.lock").lstat()
        assert info.st_mode & 0o777 == 0o600 and info.st_nlink == 1
        with pytest.raises(PassLockBusy):
            acquire_pass_lock(lock_root)
    with acquire_pass_lock(lock_root):
        pass


def test_a_busy_lock_is_waited_for_only_within_the_bound(lock_root):
    clock = FakeClock()
    with acquire_pass_lock(lock_root):
        with pytest.raises(PassLockBusy):
            acquire_pass_lock(lock_root, wait_seconds=5.0, clock=clock, sleep=clock.sleep)
    assert 5.0 <= clock.now - 1000.0 < 5.2


def test_the_wait_ends_as_soon_as_the_holder_lets_go(lock_root):
    clock = FakeClock()
    holder = acquire_pass_lock(lock_root)
    polls = []

    def sleep(seconds):
        polls.append(seconds)
        holder.release()
        clock.sleep(seconds)

    with acquire_pass_lock(lock_root, wait_seconds=5.0, clock=clock, sleep=sleep):
        pass
    assert len(polls) == 1


@pytest.mark.parametrize("damage", ["mode", "symlink", "link-count", "directory"])
def test_a_lock_file_that_is_not_what_it_must_be_is_refused(lock_root, damage):
    lock = lock_root / "run/azazel-activation/pass.lock"
    if damage == "mode":
        lock.write_text("")
        lock.chmod(0o666)
    elif damage == "symlink":
        (lock_root / "elsewhere").write_text("")
        lock.symlink_to(lock_root / "elsewhere")
    elif damage == "link-count":
        lock.write_text("")
        lock.chmod(0o600)
        os.link(lock, lock_root / "second")
    else:
        lock.mkdir()
    with pytest.raises(PassLockRefused):
        acquire_pass_lock(lock_root)


def test_a_lock_owned_by_another_user_is_refused(lock_root, monkeypatch):
    lock = lock_root / "run/azazel-activation/pass.lock"
    lock.write_text("")
    lock.chmod(0o600)
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid() + 1)
    monkeypatch.setattr(activation_markers, "_protected_directory", lambda fd: None)
    with pytest.raises(PassLockRefused):
        acquire_pass_lock(lock_root)


def test_a_missing_or_loose_directory_refuses_the_lock(tmp_path, monkeypatch):
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    with pytest.raises(PassLockRefused):
        acquire_pass_lock(tmp_path)
    parent = tmp_path / "run" / "azazel-activation"
    parent.mkdir(parents=True)
    parent.chmod(0o777)
    with pytest.raises(Exception):
        acquire_pass_lock(tmp_path)


# -- the marker removal -------------------------------------------------------------


def _markers(root: Path, *units):
    directory = root / "run/azazel-activation/granted"
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o755)
    for unit in units:
        (directory / unit).write_text("")
        (directory / unit).chmod(0o644)
    return directory


def test_only_the_broker_marker_is_removed(lock_root):
    directory = _markers(lock_root, CTX, "azazel-mio-entryd.service")
    activation_markers.remove_contextd_marker(lock_root)
    assert sorted(p.name for p in directory.iterdir()) == ["azazel-mio-entryd.service"]
    activation_markers.remove_contextd_marker(lock_root)  # already absent


def test_a_missing_marker_directory_is_nothing_to_remove(lock_root, tmp_path):
    activation_markers.remove_contextd_marker(lock_root)
    activation_markers.remove_contextd_marker(tmp_path / "nowhere")


def test_a_directory_in_place_of_the_marker_is_refused(lock_root):
    directory = _markers(lock_root)
    (directory / CTX).mkdir()
    with pytest.raises(Exception):
        activation_markers.remove_contextd_marker(lock_root)


def test_the_marker_unit_name_matches_the_unit_table():
    assert activation_markers.CONTEXTD_MARKER_UNIT == CONTEXTD_UNIT


# -- withdraw_contextd ---------------------------------------------------------------


@pytest.fixture
def stage(lock_root):
    """A root with the broker's marker, another marker, a ledger and a clock."""
    directory = _markers(lock_root, CTX, "azazel-mio-entryd.service")
    clock = FakeClock()
    model = ContextdModel(clock, running=True)
    manager = ModelManager(model, enabled=[d.name for d in CORE_UNITS])
    ledger_path = lock_root / "var/lib/azazel/state/activation.jsonl"
    return SimpleNamespace(root=lock_root, directory=directory, clock=clock, model=model,
                           manager=manager, ledger=AuditLedger(ledger_path),
                           authority=authority(model), ledger_path=ledger_path)


def _withdraw(stage, *, deadline=None, reason="recheck", authority_=None):
    return withdraw_contextd(fresh=None, 
        reason=reason, manager=stage.manager, authority=authority_ or stage.authority,
        root=stage.root, ledger=stage.ledger, now=NOW, actor="test",
        invocation_id="f" * 32, deadline=deadline, clock=stage.clock, sleep=stage.clock.sleep)


def events(stage):
    return [e.event for e in AuditLedger(stage.ledger_path)] if stage.ledger_path.exists() else []


def assert_withdrawal_order(timeline, marker_gone_at_mask):
    """marker removed before the mask, mask before reload, reload before stop."""
    assert marker_gone_at_mask, "the mask was sent while the marker still existed"
    operations = [op for op, unit in timeline if unit in (CTX, "")]
    assert {"mask", "reload", "stop"} <= set(operations), "a step of the withdrawal is missing"
    assert operations.index("mask") < operations.index("reload") < operations.index("stop")


def _watch_marker(stage):
    seen = []
    marker = stage.directory / CTX
    stage.manager.on_mask = lambda unit: seen.append(not marker.exists()) if unit == CTX else None
    return seen


def test_a_running_broker_is_withdrawn_in_order_and_recorded(stage):
    seen = _watch_marker(stage)
    timings = _withdraw(stage)
    assert_withdrawal_order(stage.manager.timeline, all(seen) and bool(seen))
    assert stage.model.stops == 1 and stage.model.running is False
    assert stage.manager.state(CTX) is UnitState.MASKED
    # only the broker's marker is gone
    assert sorted(p.name for p in stage.directory.iterdir()) == ["azazel-mio-entryd.service"]
    [event] = [e for e in events(stage) if e["event_type"] == "activation.grant_withdrawn"]
    assert event["unit"] == CTX and event["reason"] == "recheck" and event["stopped"] is True
    assert event["invocation_id"] == "f" * 32
    assert event["t_marker_ms"] <= event["t_reload_ms"] <= event["t_stop_ms"] <= event["t_inactive_ms"]
    assert timings["t_inactive_ms"] - timings["t_stop_ms"] >= 1000  # the stop took a second


def test_a_broker_that_is_already_quiet_is_not_stopped(stage):
    stage.model.running = False
    timings = _withdraw(stage)
    assert stage.model.stops == 0
    assert timings["t_stop_ms"] is None
    [event] = [e for e in events(stage) if e["event_type"] == "activation.grant_withdrawn"]
    assert event["stopped"] is False
    assert stage.manager.state(CTX) is UnitState.MASKED
    assert not (stage.directory / CTX).exists()


def test_a_broker_waiting_on_a_job_is_stopped_with_replace(stage):
    stage.model.running = False
    stage.model.job = JOB
    _withdraw(stage)
    assert stage.model.stops == 1 and stage.model.job == NO_JOB


def test_the_stop_wait_is_bounded_by_twenty_seconds(stage):
    stage.model.stop_works = False
    started = stage.clock()
    with pytest.raises(WithdrawalUnconfirmed):
        _withdraw(stage)
    waited = stage.clock() - started
    assert STOP_WAIT_SECONDS <= waited < STOP_WAIT_SECONDS + 0.2
    [event] = [e for e in events(stage) if e["event_type"] == "activation.withdrawal_unconfirmed"]
    assert event["stage"] == "inactive" and event["why"] == "TimeoutError"
    # left masked, marker gone, never unmasked again
    assert stage.manager.state(CTX) is UnitState.MASKED
    assert not (stage.directory / CTX).exists()
    assert not any(op == "unmask_and_enable" for op, _ in stage.manager.timeline)


def test_the_stop_wait_is_also_bounded_by_the_overall_deadline(stage):
    stage.model.stop_works = False
    started = stage.clock()
    with pytest.raises(WithdrawalUnconfirmed):
        _withdraw(stage, deadline=started + 3.0)
    assert 3.0 <= stage.clock() - started < 3.2


@pytest.mark.parametrize("failing", ["mask", "reload", "stop"])
def test_a_step_that_fails_leaves_the_broker_masked_and_unconfirmed(stage, failing):
    if failing == "mask":
        stage.manager.mask = lambda unit: (_ for _ in ()).throw(
            UnitOperationFailed("systemd did not report the governed unit as masked"))
    elif failing == "reload":
        stage.manager._fail_reload = True
    else:
        def refuse():
            raise UnitOperationFailed("systemd D-Bus call did not complete")

        stage.authority = ContextdStopAuthority(
            stop=refuse, job=stage.model.current_job, state=stage.model.active_state,
            file_state=stage.model.file_state_of)
    with pytest.raises(WithdrawalUnconfirmed):
        _withdraw(stage)
    [event] = [e for e in events(stage) if e["event_type"] == "activation.withdrawal_unconfirmed"]
    assert event["stage"] == {"mask": "mask", "reload": "reload", "stop": "stop"}[failing]
    assert not (stage.directory / CTX).exists()


def test_an_unwritable_ledger_changes_neither_the_outcome_nor_the_state(stage, monkeypatch):
    def unavailable(self, event, *args, **kwargs):
        raise OSError("synthetic")

    monkeypatch.setattr(AuditLedger, "append", unavailable)
    _withdraw(stage)
    assert stage.model.running is False and stage.manager.state(CTX) is UnitState.MASKED
    stage.model.running = True
    stage.model.stop_works = False
    with pytest.raises(WithdrawalUnconfirmed):
        _withdraw(stage)


def test_no_unit_but_the_broker_is_masked_stopped_or_touched(stage):
    _withdraw(stage)
    assert {unit for op, unit in stage.manager.timeline if unit} == {CTX}


# negative checks: each removal is caught by the scenario's own assertions.


def test_removing_the_stop_unit_is_caught(stage, monkeypatch):
    monkeypatch.setattr(ContextdStopAuthority, "stop", lambda self, unit: "/job/none")
    with pytest.raises(WithdrawalUnconfirmed):
        _withdraw(stage)  # the broker never becomes inactive
    assert stage.model.running is True


def test_removing_the_marker_removal_is_caught(stage, monkeypatch):
    from azazel_nexus_runtime import activation_withdraw
    monkeypatch.setattr(activation_withdraw, "remove_contextd_marker", lambda root: None)
    seen = _watch_marker(stage)
    _withdraw(stage)
    with pytest.raises(AssertionError, match="marker still existed"):
        assert_withdrawal_order(stage.manager.timeline, all(seen) and bool(seen))


def test_removing_the_reload_is_caught(stage):
    stage.manager.reload = lambda: None
    seen = _watch_marker(stage)
    _withdraw(stage)
    with pytest.raises(AssertionError, match="step of the withdrawal is missing"):
        assert_withdrawal_order(stage.manager.timeline, all(seen) and bool(seen))


# -- replacing a queued job ------------------------------------------------------------


def _job_stage(stage, **model_kwargs):
    stage.model.running = False
    stage.model.job = JOB
    for key, value in model_kwargs.items():
        setattr(stage.model, key, value)
    return stage


def test_a_queued_job_is_replaced_and_recorded(stage):
    _job_stage(stage)
    assert clear_contextd_job(authority=stage.authority, ledger=stage.ledger, now=NOW,
                              actor="test", reason="withheld", invocation_id="1" * 32,
                              clock=stage.clock, sleep=stage.clock.sleep) is True
    assert stage.model.job == NO_JOB
    assert [e["event_type"] for e in events(stage)] == ["activation.queued_job_replaced"]


def test_no_job_means_no_stop(stage):
    stage.model.running = False
    assert clear_contextd_job(authority=stage.authority, ledger=stage.ledger, now=NOW,
                              actor="test", reason="withheld", invocation_id="1" * 32,
                              clock=stage.clock, sleep=stage.clock.sleep) is False
    assert stage.model.stops == 0


def test_a_job_that_does_not_clear_is_unconfirmed(stage):
    _job_stage(stage, stop_works=False)
    with pytest.raises(WithdrawalUnconfirmed):
        clear_contextd_job(authority=stage.authority, ledger=stage.ledger, now=NOW,
                           actor="test", reason="withheld", invocation_id="1" * 32,
                           clock=stage.clock, sleep=stage.clock.sleep)
    assert events(stage)[-1]["event_type"] == "activation.withdrawal_unconfirmed"


# -- the main pass ---------------------------------------------------------------------


@pytest.fixture
def main_pass(ctx_world):
    """The pass over the contextd-scoped world with a model of the broker."""
    clock = FakeClock()
    model = ContextdModel(clock)
    manager = ModelManager(model, enabled=[d.name for d in CORE_UNITS])
    ctx_world.manager = manager

    def run(**extra):
        return activated._run_once(
            manager=manager, root=ctx_world.root, now=NOW, actor="test",
            producers=ctx_world.producers(), stop_authority=authority(model),
            clock=clock, sleep=clock.sleep, invocation_id="a" * 32, **extra)

    return SimpleNamespace(world=ctx_world, clock=clock, model=model, manager=manager, run=run)


def test_a_running_broker_is_stopped_at_preflight_and_the_pass_completes(main_pass):
    main_pass.model.running = True
    outcome = main_pass.run()
    timeline = main_pass.manager.timeline
    assert main_pass.model.stops == 1
    # stopped before the preflight masks were confirmed and before any grant
    assert [op for op, _ in timeline].index("stop") < [op for op, _ in timeline].index(
        "unmask_and_enable")
    assert sorted(outcome.granted) == list(CTX_SCOPE)
    assert CTX in main_pass.world.markers()
    kinds = [e["event_type"] for e in main_pass.world.events()]
    assert "activation.grant_withdrawn" in kinds
    withdrawn = next(e for e in main_pass.world.events()
                     if e["event_type"] == "activation.grant_withdrawn")
    assert withdrawn["reason"] == "preflight" and withdrawn["invocation_id"] == "a" * 32


def test_a_broker_that_will_not_stop_ends_the_pass_with_everything_masked(main_pass):
    main_pass.model.running = True
    main_pass.model.stop_works = False
    with pytest.raises(RuntimeError, match="could not be withdrawn at preflight"):
        main_pass.run()
    assert main_pass.world.markers() is None
    assert all(main_pass.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert main_pass.world.raised == []
    assert not any(op == "unmask_and_enable" for op, _ in main_pass.manager.timeline)


def test_a_waiting_start_job_at_preflight_is_not_stopped(main_pass):
    main_pass.model.job = JOB  # inactive, with a start job queued
    outcome = main_pass.run()
    assert CTX in outcome.granted
    assert main_pass.model.stops == 0


def test_a_queued_job_for_a_broker_the_pass_withholds_is_replaced(main_pass):
    main_pass.world.sign(units=SCOPE)  # the approval no longer names the broker
    main_pass.model.job = JOB
    outcome = main_pass.run()
    assert CTX not in outcome.granted
    assert main_pass.model.stops == 1 and main_pass.model.job == NO_JOB
    assert any(e["event_type"] == "activation.queued_job_replaced"
               for e in main_pass.world.events())
    assert CTX not in (main_pass.world.markers() or [])


def test_a_queued_job_that_cannot_be_replaced_ends_the_pass_masked(main_pass):
    main_pass.world.sign(units=SCOPE)
    main_pass.model.job = JOB
    main_pass.model.stop_works = False
    with pytest.raises(RuntimeError, match="could not be replaced"):
        main_pass.run()
    assert main_pass.world.markers() is None
    assert all(main_pass.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)


def test_a_granted_broker_with_no_job_is_never_stopped(main_pass):
    outcome = main_pass.run()
    assert CTX in outcome.granted and main_pass.model.stops == 0


def test_without_an_authority_a_running_broker_is_still_a_containment_failure(main_pass):
    main_pass.model.running = True
    with pytest.raises(activated.RollbackFailed):
        activated._run_once(
            manager=main_pass.manager, root=main_pass.world.root, now=NOW, actor="test",
            producers=main_pass.world.producers())


# -- the lock around the pass --------------------------------------------------------------


def _locked(main_pass, **extra):
    return activated._locked_pass(
        manager=main_pass.manager, root=main_pass.world.root, now=NOW, actor="test",
        stop_authority=authority(main_pass.model), invocation_id="b" * 32,
        clock=main_pass.clock, sleep=main_pass.clock.sleep,
        producers=main_pass.world.producers(), **extra)


def test_the_pass_holds_the_lock_until_after_ready_and_its_barrier(main_pass, monkeypatch):
    from azazel_nexus_runtime import systemd_notify
    held = []

    def probe():
        try:
            acquire_pass_lock(main_pass.world.root)
        except PassLockBusy:
            held.append(True)
        else:
            held.append(False)

    monkeypatch.setattr(systemd_notify, "notify_ready", probe)
    monkeypatch.setattr(systemd_notify, "notify_barrier", probe)
    outcome = _locked(main_pass)
    assert CTX in outcome.granted
    assert held == [True, True]
    with acquire_pass_lock(main_pass.world.root):  # released afterwards
        pass


def test_a_pass_that_cannot_take_the_lock_changes_nothing_and_fails(main_pass, monkeypatch):
    """The holder owns the state: a loser removes no marker, masks nothing, reloads
    nothing, writes no ledger record, sends no READY, and exits non-zero."""
    from azazel_nexus_runtime import systemd_notify
    sent = []
    monkeypatch.setattr(systemd_notify, "notify_ready", lambda: sent.append("ready"))
    monkeypatch.setattr(systemd_notify, "notify_barrier", lambda: sent.append("barrier"))
    called = []
    monkeypatch.setattr(activated, "_run_once", lambda **kw: called.append(kw))
    first = main_pass.manager
    for unit in (CTX, "azazel-mio-entryd.service"):
        first.unmask_and_enable(unit)
    _markers(main_pass.world.root, CTX)
    first.timeline.clear()
    states = {d.name: first.state(d.name) for d in CORE_UNITS}
    ledger = main_pass.world.ledger_path
    ledger_before = ledger.read_bytes() if ledger.exists() else None
    with acquire_pass_lock(main_pass.world.root):
        started = main_pass.clock()
        with pytest.raises(RuntimeError, match="nothing was changed"):
            _locked(main_pass)
        waited = main_pass.clock() - started
    assert called == [] and sent == []
    wait = activated.PASS_LOCK_WAIT_SECONDS
    assert wait <= waited < wait + 0.2  # a bounded wait, then give up
    assert main_pass.world.markers() == [CTX]  # the holder's marker is intact
    assert {d.name: first.state(d.name) for d in CORE_UNITS} == states
    assert first.timeline == []  # no mask, no reload, no stop
    assert (ledger.read_bytes() if ledger.exists() else None) == ledger_before


def test_the_budget_is_below_the_start_timeout_of_the_unit():
    rendered = (ROOT_DIRECTORY / "packaging/systemd/azazel-activated.service").read_text()
    [timeout] = re.findall(r"^TimeoutStartSec=(\d+)s$", rendered, re.M)
    assert timeout == "60"
    # the lock wait is inside the budget; READY and its barrier get the rest
    assert activated.PASS_LOCK_WAIT_SECONDS < activated.MAIN_PASS_BUDGET_SECONDS
    assert activated.MAIN_PASS_BUDGET_SECONDS + 7 <= int(timeout)
    assert STOP_WAIT_SECONDS < activated.MAIN_PASS_BUDGET_SECONDS


def test_the_pass_budget_caps_the_broker_stop(main_pass):
    """With little budget left, the stop wait ends early and the pass narrows."""
    main_pass.model.running = True
    main_pass.model.stop_works = False
    started = main_pass.clock()
    with pytest.raises(RuntimeError, match="could not be withdrawn at preflight"):
        main_pass.run(deadline=started + 2.0)
    # the phases ended at 2 s; the narrowing's own withdrawal may spend the reserve
    assert main_pass.clock() - started < 2.5 + activated._AFTER_PHASES


def test_the_main_pass_wiring_is_the_locked_pass():
    source = (ROOT_DIRECTORY / "runtime/src/azazel_nexus_runtime/activated.py").read_text()
    main_source = source[source.index("def main("):source.index("def _notify_ready_or_withdraw")]
    assert "_locked_pass(" in main_source and "ContextdStopAuthority.from_session(session)" in main_source
    # one StopUnit target in the whole package, and it is constant
    bus = (ROOT_DIRECTORY / "runtime/src/azazel_nexus_runtime/systemd_bus.py").read_text()
    assert len(re.findall(r'"StopUnit"', bus)) >= 1
    assert '"StartUnit"' not in bus and "'StartUnit'" not in bus
