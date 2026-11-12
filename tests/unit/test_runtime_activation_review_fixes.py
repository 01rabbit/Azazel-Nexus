"""Fixes from the review of the stop contract (Codex 1-6, Sonnet S1-S4, N1-N3).

One file, one section per finding, so each can be traced to its test.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from types import SimpleNamespace

import pytest

from azazel_nexus.activation import CORE_UNITS, UnitState
from azazel_nexus.audit import AuditLedger
from azazel_nexus_runtime import (
    activated, activation_markers, activation_recheck, activation_retire,
    activation_withdraw,
)
from azazel_nexus_runtime import activation_budget
from azazel_nexus_runtime.activation_budget import (
    PassBudgetExpired, bind_remaining, check_budget,
)
from azazel_nexus_runtime.activation_lock import acquire_pass_lock
from azazel_nexus_runtime.activation_retire import (
    ACCEPTED, PENDING, RetireRefused, read_accepted_grant, resume_pending_retirement,
    retire_if_revoked, retirement_pending, write_accepted_grant,
)
from azazel_nexus_runtime.activation_withdraw import (
    WithdrawalUnconfirmed, contextd_is_quiet, contextd_is_running, withdraw_contextd,
)
from azazel_nexus_runtime.systemd_bus import SystemdUnitCalls, _Reply
from azazel_nexus_runtime.units import ContextdStopAuthority, UnitOperationFailed

from stop_helpers import (
    CTX, JOB, NO_JOB, ContextdModel, FakeClock, ModelManager, authority,
)
from test_runtime_activation_contextd import CTX_SCOPE, ctx_world  # noqa: F401 - fixture
from test_runtime_activation_pass import NOW, SCOPE
from test_runtime_activation_recheck import (  # noqa: F401 - fixture
    LATER, events_after, granted, markers, recheck, withdrawn,
)
from test_runtime_activation_retire import leaf, revoked_trust, tools


@pytest.fixture
def stage(granted):
    """A node a real pass granted, the broker running (see `granted`)."""
    return granted


@pytest.fixture
def fresh(ctx_world):
    """The contextd world with a modelled broker, before any pass."""
    clock = FakeClock()
    model = ContextdModel(clock)
    manager = ModelManager(model, enabled=[d.name for d in CORE_UNITS])
    ctx_world.manager = manager
    return SimpleNamespace(world=ctx_world, clock=clock, model=model, manager=manager)


def locked(fresh, *, budget_seconds=45.0, producers=None, authority_=None):
    return activated._locked_pass(
        manager=fresh.manager, root=fresh.world.root, now=NOW, actor="test",
        stop_authority=authority_ or authority(fresh.model), invocation_id="b" * 32,
        clock=fresh.clock, sleep=fresh.clock.sleep,
        producers=producers or fresh.world.producers(), budget_seconds=budget_seconds)


@pytest.fixture(autouse=True)
def ready_ok(monkeypatch):
    from azazel_nexus_runtime import systemd_notify
    monkeypatch.setattr(systemd_notify, "notify_ready", lambda: None)
    monkeypatch.setattr(systemd_notify, "notify_barrier", lambda: None)


def all_masked_and_unmarked(fresh) -> bool:
    return (fresh.world.markers() is None
            and all(fresh.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS))


# -- Codex 1 (04): a cooperative budget, no asynchronous interruption ---------------------------


def test_the_budget_is_cooperative_and_no_code_arms_a_timer():
    import inspect
    clock = FakeClock()
    check_budget(clock() + 1, clock)
    with pytest.raises(PassBudgetExpired):
        check_budget(clock(), clock)
    assert not issubclass(PassBudgetExpired, Exception)
    assert not hasattr(activation_budget, "alarm_budget")
    for module in (activation_budget, activated, activation_recheck):
        code = inspect.getsource(module)
        for word in ("setitimer", "SIGALRM", "signal.alarm", "import signal"):
            assert word not in code, (module.__name__, word)


def test_a_slow_collection_between_phases_ends_in_narrowing(fresh):
    """The clock passes the phase deadline inside a producer: the next check narrows."""
    def slow():
        fresh.clock.sleep(100)
        return fresh.world.evidence

    with pytest.raises(RuntimeError, match="used its whole time budget"):
        locked(fresh, producers=fresh.world.producers(commissioning_evidence=slow))
    assert all_masked_and_unmarked(fresh)
    assert any(e["event_type"] == "activation.pass_budget_expired" for e in fresh.world.events())
    assert fresh.manager.timeline[-1] == ("reload", "")


def test_a_slow_manager_call_ends_the_phases_and_the_pass_narrows(fresh):
    original = fresh.manager.reload
    state = {"first": True}

    def reload():
        if state.pop("first", False):
            fresh.clock.sleep(100)  # one call that took the whole budget
        original()

    fresh.manager.reload = reload
    with pytest.raises(RuntimeError, match="used its whole time budget"):
        locked(fresh)
    assert all_masked_and_unmarked(fresh)


def test_the_phases_end_a_reserve_before_the_budget(fresh):
    """A pass that finishes its phases after budget - reserve is narrowed."""
    def at_the_edge():
        fresh.clock.sleep(activated.MAIN_PASS_BUDGET_SECONDS
                          - activated.MAIN_PASS_RESERVE_SECONDS + 1)
        return fresh.world.evidence

    with pytest.raises(RuntimeError, match="used its whole time budget"):
        locked(fresh, producers=fresh.world.producers(commissioning_evidence=at_the_edge))
    assert all_masked_and_unmarked(fresh)


def test_the_narrowing_is_bound_to_the_end_of_the_whole_budget(fresh):
    given = []
    fresh.manager.call = SimpleNamespace(set_remaining=given.append)
    with pytest.raises(RuntimeError, match="used its whole time budget"):
        locked(fresh, producers=fresh.world.producers(
            commissioning_evidence=lambda: (fresh.clock.sleep(100), fresh.world.evidence)[1]))
    # first bound to the end of the phases, last to the end of the whole budget
    first, last = given[0], given[-1]
    assert last() - first() == pytest.approx(activated.MAIN_PASS_RESERVE_SECONDS)


def test_a_pass_whose_budget_ended_before_ready_does_not_send_it(fresh, monkeypatch):
    from azazel_nexus_runtime import systemd_notify
    sent = []
    monkeypatch.setattr(systemd_notify, "notify_ready", lambda: sent.append("ready"))
    real = activated._run_once

    def late(**kwargs):
        outcome = real(**kwargs)
        fresh.clock.sleep(100)
        return outcome

    monkeypatch.setattr(activated, "_run_once", late)
    with pytest.raises(RuntimeError, match="used its whole time budget"):
        locked(fresh)
    assert sent == [] and all_masked_and_unmarked(fresh)


def test_a_pass_inside_its_budget_is_unaffected(fresh):
    assert CTX in locked(fresh).granted


def test_without_the_phase_checks_the_slow_pass_would_complete(fresh, monkeypatch):
    """Negative check: with the checks removed the scenario above is not caught."""
    monkeypatch.setattr(activated, "check_budget", lambda deadline, clock: None)

    def slow():
        fresh.clock.sleep(100)
        return fresh.world.evidence

    outcome = locked(fresh, producers=fresh.world.producers(commissioning_evidence=slow))
    assert CTX in outcome.granted  # granted after 100 s on a 45 s budget


def test_the_budget_starts_before_the_bus_connects(fresh):
    """`started` is taken by main before connect: time already spent counts."""
    started = fresh.clock() - 40.0  # the connect took 40 s
    with pytest.raises(RuntimeError, match="used its whole time budget"):
        activated._locked_pass(
            manager=fresh.manager, root=fresh.world.root, now=NOW, actor="test",
            stop_authority=authority(fresh.model), invocation_id="b" * 32,
            clock=fresh.clock, sleep=fresh.clock.sleep, producers=fresh.world.producers(),
            started=started)
    assert all_masked_and_unmarked(fresh)


def test_bind_remaining_gives_a_session_its_time_and_leaves_recording_managers_alone():
    clock = FakeClock()
    given = []
    manager = SimpleNamespace(call=SimpleNamespace(set_remaining=given.append))
    bind_remaining(manager, clock() + 5, clock)
    assert given[0]() == 5
    clock.sleep(2)
    assert given[0]() == 3
    bind_remaining(SimpleNamespace(), clock() + 1, clock)  # no session: nothing to do


# -- the bus session: per-call limits, cancelled and drained -------------------------------------


class _Bus:
    def __init__(self, hang=False):
        self.hang = hang
        self.messages = []

    async def call(self, message):
        import asyncio
        self.messages.append(message)
        if self.hang:
            await asyncio.sleep(30)
        return SimpleNamespace(message_type=1, signature="s", body=["masked"], sender=None)

    def disconnect(self):
        pass


def _session(bus):
    import asyncio
    from azazel_nexus_runtime.systemd_bus import SystemdBusSession
    loop = asyncio.new_event_loop()
    session = SystemdBusSession(
        bus=bus, loop=loop, previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=lambda **values: SimpleNamespace(**values))
    return session, loop


def test_a_call_is_limited_to_the_time_that_is_left():
    bus = _Bus(hang=True)
    session, _ = _session(bus)
    session.set_remaining(lambda: 0.3)
    started = time.monotonic()
    with pytest.raises(UnitOperationFailed, match="did not complete"):
        session("GetUnitFileState", "azazel-auditd.service")
    assert time.monotonic() - started < 2.0  # not the 10 s bound


def test_a_call_after_the_deadline_is_not_sent():
    bus = _Bus()
    session, _ = _session(bus)
    session.set_remaining(lambda: 0.0)
    with pytest.raises(UnitOperationFailed, match="time budget ended"):
        session("GetUnitFileState", "azazel-auditd.service")
    assert bus.messages == []


def test_a_session_whose_call_timed_out_is_finished_and_refuses_every_call():
    import asyncio
    bus = _Bus(hang=True)
    session, loop = _session(bus)
    session.set_remaining(lambda: 0.2)
    with pytest.raises(UnitOperationFailed):
        session("GetUnitFileState", "azazel-auditd.service")
    assert session.broken is True
    assert [t for t in asyncio.all_tasks(loop) if not t.done()] == []
    sent = len(bus.messages)
    bus.hang = False
    session.set_remaining(lambda: 5.0)
    for call in (lambda: session("GetUnitFileState", "azazel-auditd.service"),
                 session.reload, lambda: session.unit_job(CTX)):
        with pytest.raises(UnitOperationFailed, match="finished"):
            call()
    assert len(bus.messages) == sent  # nothing more was sent on it


def test_the_cleanup_of_a_session_that_timed_out_is_bounded_by_the_time_left():
    bus = _Bus(hang=True)
    session, _ = _session(bus)
    left = [0.2]
    session.set_remaining(lambda: left[0])
    started = time.monotonic()
    with pytest.raises(UnitOperationFailed):
        session("GetUnitFileState", "azazel-auditd.service")
    assert time.monotonic() - started < 1.0  # not a fixed second, still less ten


def test_a_session_without_a_deadline_keeps_the_ten_second_bound():
    bus = _Bus()
    session, _ = _session(bus)
    assert session("GetUnitFileState", "azazel-auditd.service") == "masked"


def test_connecting_counts_against_the_budget():
    from azazel_nexus_runtime.systemd_bus import SystemdBusSession
    with pytest.raises(UnitOperationFailed):
        SystemdBusSession.connect(lambda: 0.0)


# -- Codex 2: the finalizer reaches masked ---------------------------------------------------


def _flaky_mask(manager, failures):
    real = manager.mask
    state = {"left": failures}

    def mask(unit):
        if unit == CTX and state["left"] > 0:
            state["left"] -= 1
            raise UnitOperationFailed("systemd D-Bus call did not complete")
        real(unit)

    manager.mask = mask


def test_a_mask_that_failed_once_is_masked_by_the_finalizer(stage):
    _flaky_mask(stage.manager, 1)
    stage.model.running = True
    with pytest.raises(WithdrawalUnconfirmed):
        withdraw_contextd(
            reason="t", manager=stage.manager, authority=authority(stage.model),
            root=stage.world.root, ledger=AuditLedger(stage.world.ledger_path), now=NOW,
            actor="t", invocation_id="1" * 32, clock=stage.clock, sleep=stage.clock.sleep)
    assert stage.manager.state(CTX) is UnitState.MASKED  # asserted final state
    assert stage.model.file_state == "masked"
    assert stage.model.stops == 1  # and a stop was sent
    event = stage.world.events()[-1]
    assert event["event_type"] == "activation.withdrawal_unconfirmed"
    assert event["final_masked"] is True and event["final_quiet"] is False  # stop sent, not settled
    assert CTX not in (stage.world.markers() or [])


def test_a_mask_that_never_works_is_recorded_as_not_masked(stage):
    _flaky_mask(stage.manager, 10)
    with pytest.raises(WithdrawalUnconfirmed):
        withdraw_contextd(
            reason="t", manager=stage.manager, authority=authority(stage.model),
            root=stage.world.root, ledger=AuditLedger(stage.world.ledger_path), now=NOW,
            actor="t", invocation_id="1" * 32, clock=stage.clock, sleep=stage.clock.sleep)
    event = stage.world.events()[-1]
    assert event["final_masked"] is False
    assert stage.manager.state(CTX) is UnitState.ENABLED  # honest, not claimed
    assert stage.model.stops == 1  # the broker is still stopped by the finalizer


def test_removing_the_finalizer_is_caught(stage, monkeypatch):
    monkeypatch.setattr(activation_withdraw, "_contain",
                        lambda **kw: {"final_masked": False, "final_quiet": False})
    _flaky_mask(stage.manager, 1)
    with pytest.raises(WithdrawalUnconfirmed):
        withdraw_contextd(
            reason="t", manager=stage.manager, authority=authority(stage.model),
            root=stage.world.root, ledger=AuditLedger(stage.world.ledger_path), now=NOW,
            actor="t", invocation_id="1" * 32, clock=stage.clock, sleep=stage.clock.sleep)
    assert stage.manager.state(CTX) is not UnitState.MASKED  # the scenario's assertion fails


# -- Codex 3: short writes ------------------------------------------------------------------------


def _state_dir(world):
    (world.root / "var/lib/azazel/state").mkdir(parents=True, exist_ok=True)
    (world.root / "var/lib/azazel/state").chmod(0o700)


def test_a_short_write_is_completed_before_the_rename(ctx_world, monkeypatch):
    _state_dir(ctx_world)
    real = os.write
    sizes = []

    def short(fd, data):
        sizes.append(len(data))
        return real(fd, bytes(data)[:3])

    monkeypatch.setattr(activation_retire.os, "write", short)
    write_accepted_grant(ctx_world.root, operator="operator-a", approval_seq=5,
                         approval_id="approval-1", payload_sha256="a" * 64, units=[CTX])
    assert len(sizes) > 3
    record = read_accepted_grant(ctx_world.root)
    assert record["units"] == [CTX] and record["payload_sha256"] == "a" * 64


def test_a_write_that_makes_no_progress_leaves_no_record(ctx_world, monkeypatch):
    _state_dir(ctx_world)
    monkeypatch.setattr(activation_retire.os, "write", lambda fd, data: 0)
    with pytest.raises(RetireRefused):
        write_accepted_grant(ctx_world.root, operator="operator-a", approval_seq=5,
                             approval_id="approval-1", payload_sha256="a" * 64, units=[CTX])
    assert not (leaf(ctx_world) / ACCEPTED).exists()


# -- Codex 4: an existing record is validated before admission ----------------------------------------


@pytest.mark.parametrize("change", [
    {"payload_sha256": "A" * 64}, {"payload_sha256": "a" * 63}, {"payload_sha256": ""},
    {"units": []}, {"units": [CTX, CTX]}, {"units": [CTX, "azazel-ui.service"]},
    {"operator": "Operator A"}, {"approval_id": ""}, {"approval_seq": 2**63 - 1},
])
def test_a_record_that_is_not_exactly_what_a_grant_writes_is_refused(ctx_world, change):
    _state_dir(ctx_world)
    fields = dict(operator="operator-a", approval_seq=5, approval_id="approval-1",
                  payload_sha256="a" * 64, units=[CTX]) | change
    with pytest.raises(RetireRefused):
        write_accepted_grant(ctx_world.root, **fields)


def test_a_malformed_accepted_record_withholds_the_grant_and_is_not_overwritten(fresh):
    path = leaf(fresh.world)
    path.mkdir(parents=True, mode=0o700)
    bad = path / ACCEPTED
    bad.write_text('{"schema":"x"}')
    bad.chmod(0o600)
    before = bad.read_bytes()
    for unit in CORE_UNITS:
        fresh.manager.mask(unit.name)
    outcome = activated._run_once(
        manager=fresh.manager, root=fresh.world.root, now=NOW, actor="test",
        producers=fresh.world.producers())
    assert outcome.granted == () and fresh.world.markers() is None
    assert bad.read_bytes() == before


def test_a_valid_accepted_record_does_not_block_a_new_grant(fresh):
    fresh.world.run()
    for unit in CORE_UNITS:
        fresh.manager.mask(unit.name)
    assert CTX in fresh.world.run().granted


# -- Codex 5: a classified retirement is resumed without trust ------------------------------------------


def _production_tools(world, monkeypatch, *, trust_fails=True):
    from azazel_nexus import operator_store
    from azazel_nexus_runtime import activation_high_water

    def broken():
        raise RuntimeError("synthetic")

    if trust_fails:
        monkeypatch.setattr(operator_store, "load_operator_trust", broken)
    raise_floor = world.producers().raise_high_water
    monkeypatch.setattr(activation_high_water, "read_high_water", lambda: world.high_water)
    monkeypatch.setattr(activation_high_water, "raise_high_water", raise_floor)
    return activation_recheck.production_retirement()


def test_a_pending_retirement_is_resumed_when_the_trust_cannot_be_loaded(stage, monkeypatch):
    world = stage.world
    with pytest.raises(RetireRefused):
        retire_if_revoked(**tools(world, revoked_trust(world), fail_raise=True))
    assert retirement_pending(world.root)
    record = json.loads((leaf(world) / PENDING).read_text())
    assert record["skew_seconds"] == 300 and record["target_seq"] == 6
    retire = _production_tools(world, monkeypatch)  # the trust loader raises
    assert retire(root=world.root, now=NOW) == "resumed"
    assert world.high_water.approval_seq == 6 and not retirement_pending(world.root)


def test_without_a_pending_file_a_failing_trust_loader_retires_nothing(stage, monkeypatch):
    retire = _production_tools(stage.world, monkeypatch)
    assert retire(root=stage.world.root, now=NOW) == "none"
    assert stage.world.high_water.approval_seq == 5


def test_resume_needs_no_trust_and_refuses_a_pending_record_without_its_skew(stage):
    world = stage.world
    with pytest.raises(RetireRefused):
        retire_if_revoked(**tools(world, revoked_trust(world), fail_raise=True))
    path = leaf(world) / PENDING
    document = json.loads(path.read_text())
    del document["skew_seconds"]
    path.write_text(json.dumps(document))
    kwargs = tools(world, None)
    with pytest.raises(RetireRefused):
        resume_pending_retirement(root=world.root, read_floor=kwargs["read_floor"],
                                  raise_floor=kwargs["raise_floor"], now=NOW)


# -- Codex 6: the exact unit-file state -----------------------------------------------------------------


def test_the_session_reports_the_exact_file_state_and_only_for_the_broker():
    calls = []

    def exchange(interface, member, signature, body, **kwargs):
        calls.append(member)
        return _Reply("s", ["masked-runtime"])

    client = SystemdUnitCalls(exchange)
    assert client.contextd_file_state(CTX) == "masked-runtime"
    with pytest.raises(UnitOperationFailed):
        client.contextd_file_state("azazel-auditd.service")
    with pytest.raises(UnitOperationFailed):
        client.contextd_active_state("azazel-auditd.service")
    assert calls == ["GetUnitFileState"]


def test_a_boot_ephemeral_mask_is_not_a_masked_broker(granted):
    stage = granted
    stage.model.file_state_of = lambda unit: "masked-runtime"
    guard = ContextdStopAuthority(
        stop=stage.model.stop, job=stage.model.current_job,
        state=stage.model.active_state, file_state=lambda unit: "masked-runtime")
    # it triggers the recheck ...
    assert "not_masked" in activation_recheck.contextd_triggers(
        stage.manager, guard, stage.world.root)
    # ... and a withdrawal that only reaches it is not confirmed
    stage.world.healthy = False
    with pytest.raises(WithdrawalUnconfirmed):
        withdraw_contextd(
            reason="t", manager=stage.manager, authority=guard, root=stage.world.root,
            ledger=AuditLedger(stage.world.ledger_path), now=NOW, actor="t",
            invocation_id="1" * 32, clock=stage.clock, sleep=stage.clock.sleep)
    assert stage.world.events()[-1]["stage"] == "verify_mask"


# -- S1: failed after a kill ------------------------------------------------------------------------------


def test_a_broker_left_failed_by_a_kill_is_quiet_for_the_withdrawal(granted):
    stage = granted
    stage.model.ends_failed = True
    stage.world.healthy = False
    assert recheck(stage) == 0
    event = [e for e in events_after(stage) if e["event_type"] == "activation.grant_withdrawn"][0]
    assert event["quiet_state"] == "failed" and event["stopped"] is True
    assert stage.model.failed is True
    # The already-withdrawn shape (failed, no job, exactly masked, no marker) is
    # left alone from now on: no trigger and no new record every period.
    assert activation_recheck.contextd_triggers(
        stage.manager, authority(stage.model), stage.world.root) == ()
    before = stage.world.ledger_path.read_bytes()
    assert recheck(stage) == 0
    assert stage.world.ledger_path.read_bytes() == before
    assert stage.model.stops == 1


def test_failed_with_a_job_is_not_quiet_and_failed_is_not_running():
    clock = FakeClock()
    model = ContextdModel(clock)
    model.failed = True
    guard = authority(model)
    assert contextd_is_quiet(guard)  # for the withdrawal confirmation only
    assert contextd_is_running(guard)  # preflight and recheck use exact `inactive`
    model.job = JOB
    assert not contextd_is_quiet(guard)


def test_the_generic_inactivity_check_still_refuses_failed():
    clock = FakeClock()
    model = ContextdModel(clock)
    model.failed = True
    manager = ModelManager(model)
    assert manager.is_inactive(CTX) is False  # nothing else treats failed as inactive


def test_a_broker_that_never_quiets_is_still_unconfirmed(granted, monkeypatch):
    monkeypatch.setattr(activation_withdraw, "QUIET_STATES", ("inactive",))
    stage = granted
    stage.model.ends_failed = True
    stage.world.healthy = False
    assert recheck(stage) == 1  # without S1's acceptance the withdrawal is unconfirmed


@pytest.mark.parametrize("state,expected", [("failed", "failed"), ("active", "active")])
def test_the_session_reads_the_exact_active_state(state, expected):
    from types import SimpleNamespace as NS
    from azazel_nexus_runtime.systemd_bus import _unit_object_path

    def exchange(interface, member, signature, body, **kwargs):
        if member == "GetUnit":
            return _Reply("o", [_unit_object_path(CTX)])
        return _Reply("v", [NS(signature="s", value=state)])

    assert SystemdUnitCalls(exchange).contextd_active_state(CTX) == expected


def test_a_broker_the_manager_does_not_hold_is_inactive_and_garbage_is_refused():
    def none(interface, member, signature, body, **kwargs):
        return _Reply("", [], no_such_unit=True)

    assert SystemdUnitCalls(none).contextd_active_state(CTX) == "inactive"
    from types import SimpleNamespace as NS
    from azazel_nexus_runtime.systemd_bus import _unit_object_path

    def odd(interface, member, signature, body, **kwargs):
        if member == "GetUnit":
            return _Reply("o", [_unit_object_path(CTX)])
        return _Reply("v", [NS(signature="s", value="exploded")])

    with pytest.raises(UnitOperationFailed):
        SystemdUnitCalls(odd).contextd_active_state(CTX)


# -- S2 and S3: lock hold time and the recheck budget ---------------------------------------------------------


def test_the_budgets_fit_the_unit_timeouts_and_the_lock_wait():
    # a recheck's bus work and finalizer hold the lock for less than the main pass waits
    assert activation_recheck.RECHECK_BUDGET_SECONDS < activated.PASS_LOCK_WAIT_SECONDS
    # the time-bounded part (bus work and finalizer) plus the record's reserve < the main wait
    assert activation_recheck.RECHECK_BUDGET_SECONDS + 2 <= 20 < activated.PASS_LOCK_WAIT_SECONDS
    assert activation_recheck.RECHECK_BUDGET_SECONDS + 15 <= 40  # TimeoutStartSec=40s
    work = (activation_recheck.RECHECK_BUDGET_SECONDS
            - activation_recheck.RECHECK_RECORD_SECONDS
            - activation_recheck.RECHECK_FINALIZER_SECONDS)
    assert 0 < activation_recheck.RECHECK_COLLECT_SECONDS < work
    # the main pass: phases + reserve = budget, and budget + margin <= TimeoutStartSec=60s
    assert activated.PASS_LOCK_WAIT_SECONDS < (
        activated.MAIN_PASS_BUDGET_SECONDS - activated.MAIN_PASS_RESERVE_SECONDS)
    assert activated.MAIN_PASS_BUDGET_SECONDS + 15 <= 60
    for name, seconds in (("azazel-activation-recheck.service", 40),
                          ("azazel-activated.service", 60)):
        path = "packaging/systemd/" + name
        if os.path.exists(path):
            assert f"TimeoutStartSec={seconds}s" in open(path).read()


class SlowSession:
    """Every call takes `cost` seconds of fake time, limited by the remaining time
    the way the real session limits it (a call that outlasts it fails)."""

    def __init__(self, clock, cost):
        self.clock, self.cost = clock, cost
        self.remaining = None

    def set_remaining(self, remaining):
        self.remaining = remaining

    def spend(self):
        left = self.remaining() if self.remaining else 10.0
        if left <= 0:
            raise UnitOperationFailed("the time budget ended before a call")
        self.clock.sleep(min(self.cost, 10.0, left))
        if self.cost > left:
            raise UnitOperationFailed("systemd D-Bus call did not complete")


def _slow(granted, cost):
    stage = granted
    session = SlowSession(stage.clock, cost)
    manager = stage.manager
    manager.call = session
    for name in ("mask", "reload"):
        real = getattr(manager, name)

        def call(*args, _real=real):
            session.spend()
            return _real(*args)

        setattr(manager, name, call)

    def slow(method):
        def call(*args):
            session.spend()
            return method(*args)
        return call

    guard = ContextdStopAuthority(
        stop=slow(stage.model.stop), job=slow(stage.model.current_job),
        state=slow(stage.model.active_state), file_state=slow(stage.model.file_state_of))
    return stage, guard


@pytest.mark.parametrize("cost", [0.5, 3.0, 7.0, 9.5])
def test_the_recheck_never_holds_the_lock_longer_than_its_budget(granted, cost):
    stage, guard = _slow(granted, cost)
    stage.world.healthy = False
    started = stage.clock()
    code = activation_recheck.run_recheck(
        manager=stage.manager, authority=guard, root=stage.world.root, now=NOW,
        producers=stage.world.producers(), invocation_id="c" * 32,
        clock=stage.clock, sleep=stage.clock.sleep)
    held = stage.clock() - started
    assert held <= activation_recheck.RECHECK_BUDGET_SECONDS + 1e-6
    assert held < activated.PASS_LOCK_WAIT_SECONDS
    assert code in (0, 1)
    kinds = [e["event_type"] for e in events_after(stage)]
    assert kinds and kinds[-1] in ("activation.grant_withdrawn",
                                   "activation.withdrawal_unconfirmed"), kinds
    assert CTX not in (stage.world.markers() or [])  # the marker is removed first


def test_a_recheck_whose_budget_ends_mid_withdrawal_is_unconfirmed_and_recorded(granted):
    stage, guard = _slow(granted, 9.5)
    stage.world.healthy = False
    code = activation_recheck.run_recheck(
        manager=stage.manager, authority=guard, root=stage.world.root, now=NOW,
        producers=stage.world.producers(), invocation_id="c" * 32,
        clock=stage.clock, sleep=stage.clock.sleep)
    assert code == 1
    assert events_after(stage)[-1]["event_type"] == "activation.withdrawal_unconfirmed"
    assert CTX not in (stage.world.markers() or [])


def test_a_recheck_that_cannot_stop_the_broker_ends_inside_its_budget(granted):
    stage = granted
    stage.model.stop_works = False
    stage.world.healthy = False
    started = stage.clock()
    assert recheck(stage) == 1
    assert stage.clock() - started <= activation_recheck.RECHECK_BUDGET_SECONDS + 1e-6
    assert events_after(stage)[-1]["event_type"] == "activation.withdrawal_unconfirmed"


def test_a_collection_that_does_not_finish_is_a_withhold_and_the_withdrawal_still_runs(granted):
    stage = granted

    def slow():
        stage.clock.sleep(activation_recheck.RECHECK_COLLECT_SECONDS + 1)
        return stage.world.evidence

    code = activation_recheck.run_recheck(
        manager=stage.manager, authority=authority(stage.model), root=stage.world.root,
        now=NOW, producers=stage.world.producers(commissioning_evidence=slow),
        invocation_id="c" * 32, clock=stage.clock, sleep=stage.clock.sleep)
    assert code == 1 and withdrawn(stage)


def test_a_pass_that_gets_the_lock_within_its_wait_runs(fresh):
    holder = acquire_pass_lock(fresh.world.root)
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        fresh.clock.sleep(seconds)
        if fresh.clock() - 1000.0 >= 10:  # the recheck finishes after 10 s
            holder.release()

    outcome = activated._locked_pass(
        manager=fresh.manager, root=fresh.world.root, now=NOW, actor="test",
        stop_authority=authority(fresh.model), invocation_id="b" * 32,
        clock=fresh.clock, sleep=sleep, producers=fresh.world.producers())
    assert CTX in outcome.granted and sum(sleeps) >= 10


# -- S4: a pending or failed retirement withholds ----------------------------------------------------------------


def test_the_verdict_withholds_while_a_retirement_is_blocked(ctx_world):
    from azazel_nexus.audit import AuditLedger as L
    from azazel_nexus_runtime.activation_pass import collect_pass_inputs
    inputs = collect_pass_inputs(producers=ctx_world.producers(), generations=ctx_world.store,
                                 ledger=L(ctx_world.ledger_path), now=NOW)
    assert activation_recheck.contextd_verdict(inputs, NOW).granted is True
    blocked = activation_recheck.contextd_verdict(inputs, NOW, retirement_blocked=True)
    assert blocked.granted is False and blocked.label == "retirement_pending"


def test_a_failed_retirement_withdraws_even_though_the_inputs_still_verify(granted):
    stage = granted
    world = stage.world
    trust = revoked_trust(world)  # not given to the verifier: it still accepts the approval
    code = activation_recheck.run_recheck(
        manager=stage.manager, authority=authority(stage.model), root=world.root, now=NOW,
        producers=world.producers(), invocation_id="c" * 32,
        retirement=lambda **kw: retire_if_revoked(**tools(world, trust, fail_raise=True)),
        clock=stage.clock, sleep=stage.clock.sleep)
    assert code == 1 and withdrawn(stage)
    assert retirement_pending(world.root)


def test_a_pending_retirement_withdraws_on_the_next_recheck(granted):
    stage = granted
    world = stage.world
    with pytest.raises(RetireRefused):
        retire_if_revoked(**tools(world, revoked_trust(world), fail_raise=True))
    assert recheck(stage) == 0 and withdrawn(stage)


# -- N1, N2 -------------------------------------------------------------------------------------------------------


def test_a_job_read_that_fails_once_is_read_again(stage):
    stage.model.running = False
    stage.model.job = JOB
    real = stage.model.current_job
    state = {"first": True}

    def flaky(unit):
        if state.pop("first", False):
            raise UnitOperationFailed("systemd returned an invalid unit object")
        return real(unit)

    guard = ContextdStopAuthority(stop=stage.model.stop, job=flaky,
                                  state=stage.model.active_state,
                                  file_state=stage.model.file_state_of)
    withdraw_contextd(
        reason="t", manager=stage.manager, authority=guard, root=stage.world.root,
        ledger=AuditLedger(stage.world.ledger_path), now=NOW, actor="t",
        invocation_id="1" * 32, clock=stage.clock, sleep=stage.clock.sleep)
    assert stage.model.stops == 1


def test_a_missing_activation_directory_is_nothing_to_do_without_a_broker(tmp_path, monkeypatch):
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    clock = FakeClock()
    model = ContextdModel(clock)
    manager = ModelManager(model)
    kwargs = dict(manager=manager, authority=authority(model), root=tmp_path, now=NOW,
                  producers=None, invocation_id="c" * 32, clock=clock, sleep=clock.sleep)
    assert activation_recheck.run_recheck(**kwargs) == 0
    model.running = True
    assert activation_recheck.run_recheck(**kwargs) == 1


# -- Codex 4 (04): strict parsing of the records ----------------------------------------------------


def _valid_record(world, **change):
    _state_dir(world)
    write_accepted_grant(world.root, operator="operator-a", approval_seq=5,
                         approval_id="approval-1", payload_sha256="a" * 64, units=[CTX])
    path = leaf(world) / ACCEPTED
    document = json.loads(path.read_text())
    document.update(change)
    return path, document


def _put(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


def _canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def test_the_record_the_writer_produces_is_accepted_byte_for_byte(ctx_world):
    path, document = _valid_record(ctx_world)
    assert path.read_bytes() == _canonical(document)
    assert read_accepted_grant(ctx_world.root)["approval_id"] == "approval-1"


def test_a_duplicate_key_is_refused(ctx_world):
    path, document = _valid_record(ctx_world)
    raw = _canonical(document).decode()
    _put(path, (raw[:-1] + ',"operator":"operator-b"}').encode())
    with pytest.raises(RetireRefused):
        read_accepted_grant(ctx_world.root)


@pytest.mark.parametrize("spell", ["spaces", "newline", "reordered", "escaped", "number"])
def test_bytes_other_than_the_writers_are_refused(ctx_world, spell):
    path, document = _valid_record(ctx_world)
    canonical = _canonical(document)
    if spell == "spaces":
        raw = json.dumps(document, sort_keys=True).encode()
    elif spell == "newline":
        raw = canonical + b"\n"
    elif spell == "reordered":
        raw = json.dumps(document, sort_keys=False, separators=(",", ":")).encode()
        raw = json.dumps(dict(reversed(list(document.items()))),
                         separators=(",", ":")).encode()
    elif spell == "escaped":
        raw = canonical.replace(b"approval-1", b"approval\\u002d1")
    else:
        raw = canonical.replace(b'"approval_seq":5', b'"approval_seq":5.0')
    assert raw != canonical
    _put(path, raw)
    with pytest.raises(RetireRefused):
        read_accepted_grant(ctx_world.root)


@pytest.mark.parametrize("approval_id", ["APPROVAL", "-approval", "a" * 65, "approval 1",
                                         "approval/1", "", "ａpproval"])
def test_an_approval_id_the_v2_schema_forbids_is_refused(ctx_world, approval_id):
    _state_dir(ctx_world)
    with pytest.raises(RetireRefused):
        write_accepted_grant(ctx_world.root, operator="operator-a", approval_seq=5,
                             approval_id=approval_id, payload_sha256="a" * 64, units=[CTX])
    path, document = _valid_record(ctx_world)
    document["approval_id"] = approval_id
    _put(path, _canonical(document))
    with pytest.raises(RetireRefused):
        read_accepted_grant(ctx_world.root)


def test_the_approval_id_grammar_is_the_v2_one():
    from azazel_nexus import activation_approval_v2 as v2
    assert activation_retire._APPROVAL_ID is v2._APPROVAL_ID


@pytest.mark.parametrize("seq", [True, 5.0, "5", None])
def test_an_approval_sequence_that_is_not_an_exact_int_is_refused(ctx_world, seq):
    path, document = _valid_record(ctx_world)
    document["approval_seq"] = seq
    _put(path, _canonical(document))
    with pytest.raises(RetireRefused):
        read_accepted_grant(ctx_world.root)
    with pytest.raises(RetireRefused):
        write_accepted_grant(ctx_world.root, operator="operator-a", approval_seq=seq,
                             approval_id="approval-1", payload_sha256="a" * 64, units=[CTX])


def _pending(world, **change):
    path, document = _valid_record(world)
    document.update(target_seq=6, skew_seconds=300)
    document.update(change)
    target = leaf(world) / PENDING
    _put(target, _canonical(document))
    return target


@pytest.mark.parametrize("change", [
    {"approval_seq": 0, "target_seq": True},  # True == 0 + 1
    {"target_seq": 6.0}, {"target_seq": "6"}, {"target_seq": 2**63},
    {"approval_seq": 2**63 - 1, "target_seq": 2**63},  # past the overflow bound
    {"target_seq": 5}, {"skew_seconds": True}, {"skew_seconds": -1},
])
def test_a_pending_record_must_have_exact_integers_inside_the_bound(ctx_world, change):
    _pending(ctx_world, **change)
    kwargs = tools(ctx_world, None)
    with pytest.raises(RetireRefused):
        resume_pending_retirement(root=ctx_world.root, read_floor=kwargs["read_floor"],
                                  raise_floor=kwargs["raise_floor"], now=NOW)


def test_a_pending_record_with_a_duplicate_key_is_refused(ctx_world):
    target = _pending(ctx_world)
    raw = target.read_bytes().decode()
    _put(target, (raw[:-1] + ',"target_seq":6}').encode())
    kwargs = tools(ctx_world, None)
    with pytest.raises(RetireRefused):
        resume_pending_retirement(root=ctx_world.root, read_floor=kwargs["read_floor"],
                                  raise_floor=kwargs["raise_floor"], now=NOW)


def test_the_valid_pending_record_resumes(ctx_world):
    _pending(ctx_world)
    kwargs = tools(ctx_world, None)
    assert resume_pending_retirement(
        root=ctx_world.root, read_floor=kwargs["read_floor"],
        raise_floor=kwargs["raise_floor"], now=NOW) == "resumed"
    assert ctx_world.high_water.approval_seq == 6


# -- the recovery procedure is documented in order -----------------------------------------------------


@pytest.mark.parametrize("document", ["docs/knowledge-context-consumer.md",
                                      "docs/activation-observe-baseline.md"])
def test_the_recovery_order_is_documented(document):
    text = open(document, encoding="utf-8").read()
    first = text.index("`systemctl start azazel-activated.service`")
    second = text.index("Confirm that the pass granted it", first)
    third = text.index("`systemctl start azazel-knowledge-contextd.service`", second)
    assert first < second < third
    assert "is refused" in text and "masked" in text and "pulls in no pass" in text


# -- Codex 1 (05): every narrowing path runs under the final deadline ------------------------------------


class BoundModelManager(ModelManager):
    """A modelled manager whose calls fail once the session's remaining time is gone."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._left = None
        self.call = SimpleNamespace(set_remaining=self._set, broken=False)
        self.refused = 0

    def _set(self, remaining):
        self._left = remaining

    def _check(self):
        if self._left is not None and self._left() <= 0:
            self.refused += 1
            raise UnitOperationFailed("the time budget ended before a call")

    def mask(self, unit):
        self._check()
        super().mask(unit)

    def reload(self):
        self._check()
        super().reload()

    def is_inactive(self, unit):
        self._check()
        return super().is_inactive(unit)


@pytest.fixture
def bound(ctx_world):
    clock = FakeClock()
    model = ContextdModel(clock)
    manager = BoundModelManager(model, enabled=[d.name for d in CORE_UNITS])
    ctx_world.manager = manager
    return SimpleNamespace(world=ctx_world, clock=clock, model=model, manager=manager,
                           begin=clock())


def _locked_bound(bound, *, started=None, producers=None, fresh_manager=None):
    return activated._locked_pass(
        manager=bound.manager, root=bound.world.root, now=NOW, actor="test",
        stop_authority=authority(bound.model), invocation_id="b" * 32,
        clock=bound.clock, sleep=bound.clock.sleep,
        producers=producers or bound.world.producers(), started=started,
        fresh_manager=fresh_manager)


def _narrowed_after_the_phases(bound):
    elapsed = bound.clock() - bound.begin
    work = activated.MAIN_PASS_BUDGET_SECONDS - activated.MAIN_PASS_RESERVE_SECONDS
    assert elapsed >= work, elapsed  # the narrowing happened after second 37
    assert bound.manager.refused == 0, "a narrowing call was refused for lack of time"
    assert bound.world.markers() is None
    assert all(bound.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert bound.manager.timeline[-1] == ("reload", "")


def test_the_lock_failure_changes_nothing_even_after_second_37(bound):
    holder = acquire_pass_lock(bound.world.root)
    started = bound.clock() - 30.0  # 30 s were spent before the lock was asked for
    bound.manager.timeline.clear()
    with pytest.raises(RuntimeError, match="nothing was changed"):
        _locked_bound(bound, started=started)
    holder.release()
    assert bound.clock() - started >= 37.0
    assert bound.manager.timeline == [] and bound.manager.refused == 0
    assert all(bound.manager.state(d.name) is UnitState.ENABLED for d in CORE_UNITS)


def test_a_failed_ready_narrows_after_second_37(bound, monkeypatch):
    from azazel_nexus_runtime import systemd_notify

    def late_failure():
        bound.clock.sleep(38.0 - (bound.clock() - bound.begin))
        raise UnitOperationFailed("systemd notification refused")

    monkeypatch.setattr(systemd_notify, "notify_ready", late_failure)
    with pytest.raises(RuntimeError, match="readiness notification unavailable"):
        _locked_bound(bound)
    _narrowed_after_the_phases(bound)


def test_an_expired_budget_narrows_after_second_37(bound):
    def slow():
        bound.clock.sleep(38.0)
        return bound.world.evidence

    with pytest.raises(RuntimeError, match="used its whole time budget"):
        _locked_bound(bound, producers=bound.world.producers(commissioning_evidence=slow))
    _narrowed_after_the_phases(bound)


def test_an_emergency_narrowing_inside_the_pass_runs_after_second_37(bound, monkeypatch):
    def late_marker_failure(units, root):
        bound.clock.sleep(38.0)
        raise OSError("synthetic")

    monkeypatch.setattr(activated, "write_grant_markers", late_marker_failure)
    with pytest.raises(RuntimeError, match="markers could not be written"):
        _locked_bound(bound)
    _narrowed_after_the_phases(bound)


def test_a_narrowing_that_stays_bound_to_the_phase_deadline_is_caught(bound, monkeypatch):
    """Negative check: without the rebinding every path above is refused."""
    monkeypatch.setattr(activated, "bind_remaining", lambda *a, **k: None)
    real = activated.bind_remaining

    def slow():
        bound.clock.sleep(38.0)
        return bound.world.evidence

    # bound once to the phases by the test, as _locked_pass does, then never moved
    bound.manager._set(lambda: bound.begin + 37.0 - bound.clock())
    with pytest.raises(RuntimeError):
        _locked_bound(bound, producers=bound.world.producers(commissioning_evidence=slow))
    assert bound.manager.refused > 0
    assert real is not None


# -- a finished session is replaced for the narrowing ---------------------------------------------------------


def _fresh(bound):
    model = ContextdModel(bound.clock)
    other = BoundModelManager(model, enabled=[d.name for d in CORE_UNITS])
    used = []

    @contextlib.contextmanager
    def factory():
        used.append("fresh")
        yield other, authority(model)

    return other, used, factory


def test_a_poisoned_session_narrows_on_a_fresh_one_on_every_path(bound, monkeypatch):
    bound.manager.call.broken = True  # a call on this session timed out
    other, used, factory = _fresh(bound)

    # the pass fails on the finished session: its own rollback is refused
    def refused(**kwargs):
        raise activated.RollbackFailed("synthetic: refused on a finished session")

    monkeypatch.setattr(activated, "_run_once", refused)
    with pytest.raises(RuntimeError, match="bus session finished"):
        _locked_bound(bound, fresh_manager=factory)
    assert used == ["fresh"]
    assert all(other.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert not any(op in ("mask", "reload") for op, _ in bound.manager.timeline)


def test_a_lock_failure_on_a_poisoned_session_changes_nothing_anywhere(bound):
    bound.manager.call.broken = True
    other, used, factory = _fresh(bound)
    holder = acquire_pass_lock(bound.world.root)
    bound.manager.timeline.clear()
    with pytest.raises(RuntimeError, match="nothing was changed"):
        _locked_bound(bound, started=bound.clock() - 30.0, fresh_manager=factory)
    holder.release()
    assert used == []  # no fresh session is even opened
    assert bound.manager.timeline == [] and other.timeline == []


def test_a_failed_ready_on_a_poisoned_session_narrows_on_a_fresh_one(bound, monkeypatch):
    from azazel_nexus_runtime import systemd_notify
    other, used, factory = _fresh(bound)

    def fail():
        bound.manager.call.broken = True
        raise UnitOperationFailed("systemd notification refused")

    monkeypatch.setattr(systemd_notify, "notify_ready", fail)
    with pytest.raises(RuntimeError, match="readiness notification unavailable"):
        _locked_bound(bound, fresh_manager=factory)
    assert used == ["fresh"]
    assert all(other.state(d.name) is UnitState.MASKED for d in CORE_UNITS)


def test_a_fresh_session_that_cannot_connect_falls_back_to_the_old_one(bound, monkeypatch):
    from azazel_nexus_runtime import systemd_notify
    bound.manager.call.broken = True

    @contextlib.contextmanager
    def failing():
        raise UnitOperationFailed("could not connect to the system D-Bus service manager")
        yield

    monkeypatch.setattr(systemd_notify, "notify_ready",
                        lambda: (_ for _ in ()).throw(UnitOperationFailed("refused")))
    with pytest.raises(RuntimeError, match="readiness notification unavailable"):
        _locked_bound(bound, fresh_manager=failing)


def test_the_connection_cleanup_is_charged_to_the_deadline():
    import inspect
    from azazel_nexus_runtime.systemd_bus import SystemdBusSession
    source = inspect.getsource(SystemdBusSession.connect)
    cleanup = source[source.index("pending = asyncio.all_tasks(loop)"):]
    assert "timeout=_BUS_TIMEOUT_SECONDS" not in cleanup  # no uncharged fixed ten seconds
    assert "remaining()" in cleanup


# -- Codex 3 (05): the recheck's lock hold is provably below the main wait ----------------------------------------


@pytest.mark.parametrize("cost,ledger_cost", [(0.5, 0.0), (3.0, 1.5), (7.0, 1.9), (9.5, 30.0)])
def test_the_recheck_bus_work_and_finalizer_end_within_twenty_seconds_whatever_the_ledger_does(
        granted, monkeypatch, cost, ledger_cost):
    """What is time-bounded under the lock is the bus work and the containment
    finalizer: they are over by the time the first record is appended. The append
    itself (local file I/O) is not bounded, here a 30 s stall."""
    stage, guard = _slow(granted, cost)
    stage.world.healthy = False
    real_append = AuditLedger.append
    started = stage.clock()
    reached = []

    def slow_append(self, event, *args, **kwargs):
        reached.append(stage.clock() - started)  # bus work and finalizer are over here
        stage.clock.sleep(ledger_cost)
        return real_append(self, event, *args, **kwargs)

    monkeypatch.setattr(AuditLedger, "append", slow_append)
    activation_recheck.run_recheck(
        manager=stage.manager, authority=guard, root=stage.world.root, now=NOW,
        producers=stage.world.producers(), invocation_id="c" * 32,
        clock=stage.clock, sleep=stage.clock.sleep)
    assert reached and all(at <= 20.0 for at in reached), reached
    assert all(at < activated.PASS_LOCK_WAIT_SECONDS for at in reached)


def test_the_poll_sleep_never_oversleeps_the_deadline(granted):
    stage = granted
    stage.model.stop_works = False
    stage.world.healthy = False
    sleeps = []
    real_sleep = stage.clock.sleep

    def recording_sleep(seconds):
        sleeps.append((seconds, deadline_left()))
        real_sleep(seconds)

    final = stage.clock() + activation_recheck.RECHECK_BUDGET_SECONDS \
        - activation_recheck.RECHECK_RECORD_SECONDS
    work = final - activation_recheck.RECHECK_FINALIZER_SECONDS

    def deadline_left():
        return work - stage.clock()

    activation_recheck.run_recheck(
        manager=stage.manager, authority=authority(stage.model), root=stage.world.root,
        now=NOW, producers=stage.world.producers(), invocation_id="c" * 32,
        clock=stage.clock, sleep=recording_sleep)
    assert sleeps and all(seconds <= left + 1e-9 for seconds, left in sleeps), sleeps
    assert stage.clock() <= final + 1e-9 + 0.1


def test_the_budget_constants_leave_the_record_its_reserve():
    total = activation_recheck.RECHECK_BUDGET_SECONDS
    assert total == 18.0 and activation_recheck.RECHECK_RECORD_SECONDS == 2.0
    assert total + activation_recheck.RECHECK_RECORD_SECONDS <= 20.0 < activated.PASS_LOCK_WAIT_SECONDS


@pytest.mark.parametrize("document", ["docs/knowledge-context-consumer.md",
                                      "docs/activation-observe-baseline.md"])
def test_the_recovery_text_states_the_second_pass_and_the_fallback(document):
    text = " ".join(open(document, encoding="utf-8").read().split())
    assert "The second pass is designed to keep the broker's queued start job" in text
    assert "(unmask, enable, reload, marker" in text
    assert "only once the same-boot procedure has been run on a clone (unit 45 S1)" in text
    assert "the supported recovery is a reboot after the grant" in text
    assert "placeholder" not in text and "is masked again" not in text
    assert "MASKED broker is refused" in text and "UNMASKED, granted broker is different" in text


# -- the recheck records inside the lock, in order, and never swallows a failure ------------------------------


def _watch_locked_appends(monkeypatch, stage):
    """Each append must find the pass lock HELD by the recheck."""
    seen = []
    real = AuditLedger.append

    def append(self, event, *args, **kwargs):
        try:
            free = acquire_pass_lock(stage.world.root)
        except Exception:
            held = True
        else:
            free.release()
            held = False
        seen.append((event["event_type"], held))
        return real(self, event, *args, **kwargs)

    monkeypatch.setattr(AuditLedger, "append", append)
    return seen


def test_a_withdrawal_is_recorded_while_the_lock_is_held(granted, monkeypatch):
    stage = granted
    stage.world.healthy = False
    seen = _watch_locked_appends(monkeypatch, stage)
    assert recheck(stage) == 0
    assert seen == [("activation.grant_withdrawn", True)]


def test_an_unconfirmed_withdrawal_is_recorded_while_the_lock_is_held(granted, monkeypatch):
    stage = granted
    stage.model.stop_works = False
    stage.world.healthy = False
    seen = _watch_locked_appends(monkeypatch, stage)
    assert recheck(stage) == 1
    assert seen == [("activation.withdrawal_unconfirmed", True)]


def test_retirement_and_withdrawal_records_are_in_transition_order_under_the_lock(
        granted, monkeypatch):
    stage = granted
    stage.world.healthy = False
    seen = _watch_locked_appends(monkeypatch, stage)
    code = activation_recheck.run_recheck(
        manager=stage.manager, authority=authority(stage.model), root=stage.world.root,
        now=NOW, producers=stage.world.producers(), invocation_id="c" * 32,
        retirement=lambda **kw: "retired", clock=stage.clock, sleep=stage.clock.sleep)
    assert code == 0
    assert seen == [("activation.approval_retired", True), ("activation.grant_withdrawn", True)]
    kinds = [e["event_type"] for e in events_after(stage)]
    assert kinds == ["activation.approval_retired", "activation.grant_withdrawn"]


@pytest.mark.parametrize("path", ["withdrawn", "unconfirmed", "retired"])
def test_a_record_that_cannot_be_appended_makes_the_exit_non_zero(granted, monkeypatch, path):
    stage = granted
    if path == "unconfirmed":
        stage.model.stop_works = False
    if path != "retired":
        stage.world.healthy = False

    def failing(self, event, *args, **kwargs):
        raise OSError("synthetic: the ledger is unwritable")

    monkeypatch.setattr(AuditLedger, "append", failing)
    retirement = (lambda **kw: "retired") if path == "retired" else None
    code = activation_recheck.run_recheck(
        manager=stage.manager, authority=authority(stage.model), root=stage.world.root,
        now=NOW, producers=stage.world.producers(), invocation_id="c" * 32,
        retirement=retirement, clock=stage.clock, sleep=stage.clock.sleep)
    assert code == 1
    if path == "withdrawn":
        assert withdrawn(stage)  # the state was changed; only the record is missing


def test_a_failing_retirement_record_alone_is_reported(granted, monkeypatch):
    stage = granted

    def failing(self, event, *args, **kwargs):
        raise OSError("synthetic")

    monkeypatch.setattr(AuditLedger, "append", failing)
    code = activation_recheck.run_recheck(
        manager=stage.manager, authority=authority(stage.model), root=stage.world.root,
        now=NOW, producers=stage.world.producers(), invocation_id="c" * 32,
        retirement=lambda **kw: "retired", clock=stage.clock, sleep=stage.clock.sleep)
    assert code == 1 and CTX in markers(stage)  # a grant that still holds is left alone


def test_a_record_appended_outside_the_lock_would_be_caught(granted, monkeypatch):
    """Negative check: handing the record back instead of appending is visible."""
    stage = granted
    stage.world.healthy = False
    real = activation_recheck.withdraw_contextd

    def deferring(**kwargs):
        kept = []
        kwargs["sink"] = kept.append  # the mutation: do not append under the lock
        try:
            return real(**kwargs)
        finally:
            stage.deferred = kept

    monkeypatch.setattr(activation_recheck, "withdraw_contextd", deferring)
    seen = _watch_locked_appends(monkeypatch, stage)
    recheck(stage)
    assert seen == []  # nothing was appended under the lock: the scenario above fails


def test_a_torn_tail_makes_the_next_append_refuse_and_nothing_repairs_it(tmp_path):
    """What a recheck killed during an append can leave: audit.py repairs only a write that
    failed in-process (`_withdraw`, src/azazel_nexus/audit.py:346-363); a killed process leaves
    a torn last line, `head()` (audit.py:138-190) cannot parse it and `append` refuses."""
    from azazel_nexus.audit import AuditChainBroken
    path = tmp_path / "activation.jsonl"
    ledger = AuditLedger(path)
    ledger.append({"event_type": "a"})
    with path.open("ab") as handle:
        handle.write(b'{"sequence":2,"previous_hash":"x')  # killed mid-line
    with pytest.raises(AuditChainBroken):
        ledger.append({"event_type": "b"})
    with pytest.raises(AuditChainBroken):
        ledger.append({"event_type": "b"})  # still refused: nothing repaired it


def test_the_ledger_append_has_no_lock_of_its_own():
    import inspect
    from azazel_nexus import audit
    source = inspect.getsource(audit.AuditLedger.append)
    assert "flock" not in source and "lockf" not in source  # only pass.lock serializes writers


# -- Codex 08: every ledger append is made while pass.lock is held -------------------------------------------------


def _watch_main_appends(monkeypatch, root):
    seen = []
    real = AuditLedger.append

    def append(self, event, *args, **kwargs):
        try:
            free = acquire_pass_lock(root)
        except Exception:
            held = True
        else:
            free.release()
            held = False
        seen.append((event["event_type"], held))
        return real(self, event, *args, **kwargs)

    monkeypatch.setattr(AuditLedger, "append", append)
    return seen


def test_the_budget_expired_record_is_appended_while_the_lock_is_held(fresh, monkeypatch):
    seen = _watch_main_appends(monkeypatch, fresh.world.root)

    def slow():
        fresh.clock.sleep(100)
        return fresh.world.evidence

    with pytest.raises(RuntimeError, match="used its whole time budget"):
        locked(fresh, producers=fresh.world.producers(commissioning_evidence=slow))
    expired = [held for kind, held in seen if kind == "activation.pass_budget_expired"]
    assert expired == [True]
    assert all(held for _, held in seen), seen  # every append of the pass was under the lock
    assert all_masked_and_unmarked(fresh)


def test_a_new_holder_cannot_race_the_budget_record(fresh, monkeypatch):
    """The lock is still held while the narrowing that follows the record runs."""
    held_during_narrow = []
    real = activated._emergency_narrow

    def watching(manager, root, message, **options):
        try:
            other = acquire_pass_lock(root)
        except Exception:
            held_during_narrow.append(True)
        else:
            other.release()
            held_during_narrow.append(False)
        return real(manager, root, message, **options)

    monkeypatch.setattr(activated, "_emergency_narrow", watching)

    def slow():
        fresh.clock.sleep(100)
        return fresh.world.evidence

    with pytest.raises(RuntimeError):
        locked(fresh, producers=fresh.world.producers(commissioning_evidence=slow))
    assert held_during_narrow and all(held_during_narrow)


def test_a_pass_that_never_held_the_lock_writes_no_ledger_record_and_changes_nothing(fresh, capsys):
    holder = acquire_pass_lock(fresh.world.root)
    before = fresh.world.ledger_path.exists() and fresh.world.ledger_path.read_bytes()
    fresh.manager.timeline.clear()
    with pytest.raises(RuntimeError, match="nothing was changed"):
        activated._locked_pass(
            manager=fresh.manager, root=fresh.world.root, now=NOW, actor="test",
            stop_authority=authority(fresh.model), invocation_id="b" * 32,
            clock=fresh.clock, sleep=fresh.clock.sleep, producers=fresh.world.producers(),
            started=fresh.clock() - 30.0)
    holder.release()
    after = fresh.world.ledger_path.exists() and fresh.world.ledger_path.read_bytes()
    assert after == before  # nothing was appended without the lock
    assert activated.NO_LOCK_NO_RECORD_MESSAGE in capsys.readouterr().err
    assert fresh.manager.timeline == []  # nothing was masked, reloaded or stopped


def test_the_ledger_appends_of_the_controller_and_the_recheck_are_all_under_the_lock():
    """Every call site (listed in IMPL-REPORT section 12) is inside the lock's region."""
    import inspect
    source = inspect.getsource(activated._locked_pass)
    outer = source.index("\n    except PassBudgetExpired:")
    locked_region = source[source.index("with lock:"):outer]
    assert "pass_budget_expired" in locked_region  # the record is inside `with lock`
    assert "pass_budget_expired" not in source[:source.index("with lock:")]
    tail = source[outer:]
    assert ".append(" not in tail  # outside the lock nothing is appended


# -- S1 on a real host: a queued start job of the broker survives the preflight --------------------------------------


class QueuedManager(ModelManager):
    """systemd as the clone showed it: masking the broker and reloading FAILS its
    queued start job ("Failed to start"). A job left alone runs after READY, if the
    broker's marker exists (its Condition), and is skipped otherwise."""

    def reload(self):
        super().reload()
        if self.model.file_state == "masked" and self.model.job != NO_JOB:
            self.model.job = NO_JOB
            self.model.start_job_failed = True

    def release_after_ready(self, root):
        model = self.model
        if model.job != NO_JOB and model.file_state != "masked":
            marker = root / "run/azazel-activation/granted" / CTX
            if marker.exists():
                model.running = True
            model.job = NO_JOB


@pytest.fixture
def queued(ctx_world, monkeypatch):
    from azazel_nexus_runtime import systemd_notify
    clock = FakeClock()
    model = ContextdModel(clock, job=JOB)
    model.start_job_failed = False
    manager = QueuedManager(model, enabled=[d.name for d in CORE_UNITS])
    ctx_world.manager = manager
    model.job = JOB  # an enabled broker with a start job waiting for the controller
    monkeypatch.setattr(systemd_notify, "notify_ready",
                        lambda: manager.release_after_ready(ctx_world.root))
    monkeypatch.setattr(systemd_notify, "notify_barrier", lambda: None)
    return SimpleNamespace(world=ctx_world, clock=clock, model=model, manager=manager)


def _pass(queued, **kwargs):
    return activated._locked_pass(
        manager=queued.manager, root=queued.world.root, now=NOW, actor="test",
        stop_authority=authority(queued.model), invocation_id="b" * 32,
        clock=queued.clock, sleep=queued.clock.sleep,
        producers=kwargs.pop("producers", None) or queued.world.producers(), **kwargs)


def test_a_queued_start_is_kept_on_grant_and_runs_after_ready(queued):
    outcome = _pass(queued)
    assert CTX in outcome.granted
    assert queued.model.start_job_failed is False
    assert queued.model.running is True  # the job ran, with the marker in place
    assert CTX in queued.world.markers()
    assert queued.manager.state(CTX) is UnitState.ENABLED


def test_the_old_preflight_fails_the_queued_start(queued, monkeypatch):
    """Negative check: masking the broker at preflight fails its job (the S1 finding)."""
    monkeypatch.setattr(activated, "contextd_start_is_queued", lambda authority_: False)
    outcome = _pass(queued)
    assert CTX in outcome.granted  # re-granted ...
    assert queued.model.start_job_failed is True  # ... but its start job had failed
    assert queued.model.running is False  # granted, unmasked, marker, inactive


def test_a_queued_start_is_replaced_when_the_broker_is_withheld(queued):
    queued.world.sign(units=SCOPE)  # the approval no longer names the broker
    outcome = _pass(queued)
    assert CTX not in outcome.granted
    assert queued.model.job == NO_JOB and queued.model.running is False
    assert queued.manager.state(CTX) is UnitState.MASKED
    assert CTX not in (queued.world.markers() or [])


def test_a_queued_start_is_replaced_when_the_budget_ends(queued):
    def slow():
        queued.clock.sleep(38.0)
        return queued.world.evidence

    with pytest.raises(RuntimeError, match="used its whole time budget"):
        _pass(queued, producers=queued.world.producers(commissioning_evidence=slow))
    assert queued.model.job == NO_JOB and queued.model.running is False
    assert queued.manager.state(CTX) is UnitState.MASKED
    assert queued.world.markers() is None


def test_a_queued_start_is_replaced_when_the_pass_narrows_for_another_reason(queued, monkeypatch):
    def fail_marker_write(units, root):
        raise OSError("synthetic")

    monkeypatch.setattr(activated, "write_grant_markers", fail_marker_write)
    with pytest.raises(RuntimeError, match="markers could not be written"):
        _pass(queued)
    assert queued.model.job == NO_JOB and queued.model.running is False
    assert queued.manager.state(CTX) is UnitState.MASKED


def test_a_pass_that_lost_the_lock_leaves_the_queued_job_and_the_state_alone(queued):
    holder = acquire_pass_lock(queued.world.root)
    before = (queued.world.ledger_path.read_bytes()
              if queued.world.ledger_path.exists() else None)
    with pytest.raises(RuntimeError, match="nothing was changed"):
        _pass(queued, started=queued.clock() - 30.0)
    holder.release()
    after = (queued.world.ledger_path.read_bytes()
             if queued.world.ledger_path.exists() else None)
    assert after == before
    assert queued.model.job == JOB and queued.manager.state(CTX) is UnitState.ENABLED
    assert queued.model.start_job_failed is False


def test_a_running_broker_is_still_stopped_at_preflight(queued):
    queued.model.running = True
    queued.model.job = NO_JOB
    outcome = _pass(queued)
    assert queued.model.stops == 1 and CTX in outcome.granted


# -- B: `failed` is consistent --------------------------------------------------------------------------------------


@pytest.mark.parametrize("shape,triggers", [
    ("withdrawn", False), ("unmasked", True), ("job", True), ("marker", True),
])
def test_only_the_already_withdrawn_failed_shape_is_left_alone(granted, shape, triggers):
    stage = granted
    from azazel_nexus_runtime.activation_markers import remove_contextd_marker
    remove_contextd_marker(stage.world.root)
    stage.manager.mask(CTX)
    stage.model.running = False
    stage.model.failed = True
    stage.model.stopped_at = None
    if shape == "unmasked":
        stage.manager.unmask_and_enable(CTX)
    elif shape == "job":
        stage.model.job = JOB
    elif shape == "marker":
        (stage.world.root / "run/azazel-activation/granted" / CTX).write_text("")
    found = activation_recheck.contextd_triggers(
        stage.manager, authority(stage.model), stage.world.root)
    assert bool(found) is triggers, found


def test_a_failed_masked_broker_without_job_or_marker_is_accepted_by_the_preflight(fresh):
    fresh.model.failed = True
    fresh.manager.mask(CTX)  # exactly masked, no marker, no job
    outcome = activated._run_once(
        manager=fresh.manager, root=fresh.world.root, now=NOW, actor="test",
        producers=fresh.world.producers(), stop_authority=authority(fresh.model),
        clock=fresh.clock, sleep=fresh.clock.sleep, invocation_id="a" * 32)
    assert outcome is not None  # no containment failure
    assert not any(e["event_type"] == "activation.rollback_failed"
                   for e in fresh.world.events())


def test_without_the_authority_a_failed_broker_is_still_a_containment_failure(fresh):
    fresh.model.failed = True
    fresh.manager.mask(CTX)
    with pytest.raises(activated.RollbackFailed):
        activated._run_once(
            manager=fresh.manager, root=fresh.world.root, now=NOW, actor="test",
            producers=fresh.world.producers())


def test_a_failed_broker_that_is_not_masked_is_withdrawn_at_preflight(fresh):
    fresh.model.failed = True  # still enabled
    fresh.world.sign(units=SCOPE)  # and not granted again
    outcome = activated._run_once(
        manager=fresh.manager, root=fresh.world.root, now=NOW, actor="test",
        producers=fresh.world.producers(), stop_authority=authority(fresh.model),
        clock=fresh.clock, sleep=fresh.clock.sleep, invocation_id="a" * 32)
    assert CTX not in outcome.granted
    assert fresh.manager.state(CTX) is UnitState.MASKED
    assert any(e["event_type"] == "activation.grant_withdrawn" for e in fresh.world.events())


# -- Codex 10: READY may have released the held start job --------------------------------------------------------------


def _ready_releases_then(queued, monkeypatch, failing):
    from azazel_nexus_runtime import systemd_notify

    def ready():
        queued.manager.release_after_ready(queued.world.root)  # READY=1 ran the held job
        if failing == "ready":
            raise UnitOperationFailed("systemd notification refused")

    def barrier():
        if failing == "barrier":
            raise UnitOperationFailed("systemd notification barrier refused")
        if failing == "barrier_timeout":
            raise UnitOperationFailed("systemd notification barrier timed out")

    monkeypatch.setattr(systemd_notify, "notify_ready", ready)
    monkeypatch.setattr(systemd_notify, "notify_barrier", barrier)


@pytest.mark.parametrize("failing", ["ready", "barrier", "barrier_timeout"])
def test_a_failed_ready_or_barrier_stops_a_broker_the_ready_already_started(
        queued, monkeypatch, failing):
    _ready_releases_then(queued, monkeypatch, failing)
    with pytest.raises(RuntimeError, match="readiness notification unavailable"):
        _pass(queued)
    assert queued.model.stops >= 1  # the broker that started was stopped ...
    model = queued.model
    assert model.running is True or model.stopped_at is not None
    queued.clock.sleep(2.0)  # ... and settles
    assert model.inactive() and model.job == NO_JOB
    assert queued.manager.state(CTX) is UnitState.MASKED
    assert model.file_state == "masked"
    assert queued.world.markers() is None
    events = queued.world.events()
    kinds = [e["event_type"] for e in events]
    assert "activation.readiness_unconfirmed" in kinds
    withdrawn_events = [e for e in events if e["event_type"] == "activation.grant_withdrawn"]
    assert len(withdrawn_events) == 1 and withdrawn_events[0]["reason"] == "narrowed"
    assert withdrawn_events[0]["stopped"] is True


def test_the_job_clear_alone_would_have_left_the_started_broker_running(queued, monkeypatch):
    """Negative check: with only the job clear (the earlier behaviour) the broker runs on."""
    _ready_releases_then(queued, monkeypatch, "barrier")
    real = activated.withdraw_contextd

    def job_clear_only(**kwargs):
        from azazel_nexus_runtime.activation_withdraw import clear_contextd_job
        return clear_contextd_job(
            authority=kwargs["authority"], ledger=kwargs["ledger"], now=kwargs["now"],
            actor=kwargs["actor"], reason="narrowed", invocation_id=kwargs["invocation_id"],
            sink=kwargs.get("sink"), clock=kwargs["clock"], sleep=kwargs["sleep"])

    monkeypatch.setattr(activated, "withdraw_contextd", job_clear_only)
    with pytest.raises(RuntimeError, match="readiness notification unavailable"):
        _pass(queued)
    assert queued.model.running is True  # started by READY and never stopped
    assert real is not None


# -- Codex 11: a loser leaves the holder's transaction alone; the fresh session brings its authority --------------


def test_a_loser_does_not_touch_a_marker_the_holder_publishes_meanwhile(fresh, monkeypatch):
    """The holder publishes its marker while the loser waits for the lock: the loser's
    give-up must leave marker, units and ledger as the holder left them."""
    holder = acquire_pass_lock(fresh.world.root)
    published = []

    def sleep(seconds):
        fresh.clock.sleep(seconds)
        if not published:  # the holder's marker publication, mid-wait
            activation_markers_dir = fresh.world.root / "run/azazel-activation/granted"
            activation_markers_dir.mkdir(exist_ok=True)
            activation_markers_dir.chmod(0o755)
            marker = activation_markers_dir / CTX
            marker.write_text("")
            marker.chmod(0o644)
            published.append(marker)

    ledger = fresh.world.ledger_path
    fresh.manager.timeline.clear()
    with pytest.raises(RuntimeError, match="nothing was changed"):
        activated._locked_pass(
            manager=fresh.manager, root=fresh.world.root, now=NOW, actor="loser",
            stop_authority=authority(fresh.model), invocation_id="b" * 32,
            clock=fresh.clock, sleep=sleep, producers=fresh.world.producers(),
            started=fresh.clock() - 30.0)
    holder.release()
    assert published and published[0].exists()  # the holder's marker survived
    assert fresh.manager.timeline == []
    assert not ledger.exists() or all(e["actor"] != "loser" for e in fresh.world.events())


def test_nothing_in_the_pass_mutates_before_the_lock_is_taken():
    import inspect
    source = inspect.getsource(activated._locked_pass)
    # from the start of the acquisition to the `with lock:` block
    before = source[source.index("bind_remaining(manager, work, clock)"):source.index("with lock:")]
    for word in ("reset_grant_markers", "_emergency_narrow", "_narrow_final", "narrow(",
                 ".mask(", "reload(", "stop(", ".append(", "notify_"):
        assert word not in before, word
    assert "not_the_holder(" in before  # the loser only reports


class _ScriptedBus:
    """A system bus that answers the broker's reads and stop, statefully."""

    def __init__(self, name, active=False):
        self.name = name
        self.active = active
        self.messages = []
        self.masked = set()

    async def call(self, message):
        from azazel_nexus_runtime.systemd_bus import _unit_object_path
        self.messages.append((message.member, list(message.body)))
        member = message.member
        reply = lambda signature, body: SimpleNamespace(  # noqa: E731
            message_type=1, signature=signature, body=body, sender=None)
        if member == "GetUnit":
            return reply("o", [_unit_object_path(message.body[0])])
        if member == "Get":
            prop = message.body[1]
            if prop == "ActiveState":
                is_ctx = message.path == _unit_object_path(CTX)
                return reply("v", [SimpleNamespace(
                    signature="s", value="active" if (is_ctx and self.active) else "inactive")])
            if prop == "Job":
                return reply("v", [SimpleNamespace(signature="(uo)", value=[0, "/"])])
        if member == "GetUnitFileState":
            return reply("s", ["masked" if message.body[0] in self.masked else "enabled"])
        if member == "MaskUnitFiles":
            self.masked.update(message.body[0])
            return reply("a(sss)", [[]])
        if member == "StopUnit":
            self.active = False
            return reply("o", ["/org/freedesktop/systemd1/job/7"])
        if member == "Reload":
            return reply("", [])
        raise AssertionError(member)

    def disconnect(self):
        pass


def _real_session(bus):
    import asyncio
    from azazel_nexus_runtime.systemd_bus import SystemdBusSession
    return SystemdBusSession(
        bus=bus, loop=asyncio.new_event_loop(), previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=lambda **values: SimpleNamespace(**values))


def test_the_fresh_session_narrowing_uses_the_authority_of_the_fresh_session(
        fresh, monkeypatch):
    """The authority is genuinely bound to a poisoned session (a real
    SystemdBusSession whose call timed out), so every read and stop on it is refused;
    the narrowing must stop the running broker through the fresh session's authority."""
    from azazel_nexus_runtime.units import ContextdStopAuthority, DbusUnitManager
    old_bus = _ScriptedBus("old", active=True)
    old_session = _real_session(old_bus)
    old_session.set_remaining(lambda: 0.2)

    async def hang(message):  # the call that times out and poisons the session
        import asyncio
        await asyncio.sleep(30)

    old_bus.call, real_call = hang, old_bus.call
    with pytest.raises(UnitOperationFailed):
        old_session("GetUnitFileState", CTX)
    assert old_session.broken is True
    old_authority = ContextdStopAuthority.from_session(old_session)
    with pytest.raises(UnitOperationFailed, match="finished"):
        old_authority.active_state(CTX)  # genuinely refused, not a fake that ignores poisoning
    with pytest.raises(UnitOperationFailed, match="finished"):
        old_authority.stop(CTX)
    old_bus.call = real_call
    sent_to_old = len(old_bus.messages)

    new_bus = _ScriptedBus("new", active=True)
    new_session = _real_session(new_bus)

    @contextlib.contextmanager
    def factory():
        yield DbusUnitManager(call=new_session), ContextdStopAuthority.from_session(new_session)

    marker_dir = fresh.world.root / "run/azazel-activation/granted"
    marker_dir.mkdir(exist_ok=True)
    marker_dir.chmod(0o755)
    (marker_dir / CTX).write_text("")
    (marker_dir / CTX).chmod(0o644)
    aids = activated._contextd_aids(
        fresh.world.root, now=NOW, actor="t", invocation_id="1" * 32,
        until=fresh.clock() + 8.0, clock=fresh.clock, sleep=fresh.clock.sleep, record=True)
    with pytest.raises(RuntimeError, match="used its whole"):
        activated._narrow_final(
            DbusUnitManager(call=old_session), fresh.world.root, "used its whole",
            until=fresh.clock() + 8.0, clock=fresh.clock, fresh_manager=factory,
            authority=old_authority, aids=aids)
    members = [m for m, _ in new_bus.messages]
    assert "StopUnit" in members and "MaskUnitFiles" in members  # the broker was stopped
    assert new_bus.active is False and CTX in new_bus.masked
    assert len(old_bus.messages) == sent_to_old  # nothing more went to the poisoned session
    assert not (marker_dir / CTX).exists()
    event = [e for e in fresh.world.events() if e["event_type"] == "activation.grant_withdrawn"]
    assert len(event) == 1 and event[0]["stopped"] is True


def test_with_the_old_authority_the_fresh_narrowing_would_not_stop_the_broker(fresh):
    """Negative check: refreshing only the manager leaves the stop refused."""
    from azazel_nexus_runtime.units import ContextdStopAuthority, DbusUnitManager
    old_session = _real_session(_ScriptedBus("old", active=True))
    old_session.broken = True  # finished
    old_authority = ContextdStopAuthority.from_session(old_session)
    new_bus = _ScriptedBus("new", active=True)
    new_session = _real_session(new_bus)

    @contextlib.contextmanager
    def factory():
        yield DbusUnitManager(call=new_session), old_authority  # the mutation

    aids = activated._contextd_aids(
        fresh.world.root, now=NOW, actor="t", invocation_id="1" * 32,
        until=fresh.clock() + 8.0, clock=fresh.clock, sleep=fresh.clock.sleep, record=True)
    with pytest.raises(RuntimeError):
        activated._narrow_final(
            DbusUnitManager(call=old_session), fresh.world.root, "x",
            until=fresh.clock() + 8.0, clock=fresh.clock, fresh_manager=factory,
            authority=old_authority, aids=aids)
    assert new_bus.active is True  # still running: the scenario above is not met
