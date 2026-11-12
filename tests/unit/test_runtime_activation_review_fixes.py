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
    # `failed` is quiet for the confirmation only: a later recheck still sees a
    # trigger and withdraws it again (idempotent; no StopUnit is needed)
    assert "not_inactive" in activation_recheck.contextd_triggers(
        stage.manager, authority(stage.model), stage.world.root)
    stops = stage.model.stops
    assert recheck(stage) == 0
    assert stage.model.stops == stops


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
    # a recheck holds the lock for less than the main pass waits for it
    assert activation_recheck.RECHECK_BUDGET_SECONDS < activated.PASS_LOCK_WAIT_SECONDS
    # budget + the record's overshoot (bounded below at 2 s) < the main wait
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


def test_the_lock_failure_narrows_after_second_37(bound):
    holder = acquire_pass_lock(bound.world.root)
    started = bound.clock() - 30.0  # 30 s were spent before the lock was asked for
    with pytest.raises(RuntimeError, match="pass lock could not be taken"):
        _locked_bound(bound, started=started)
    holder.release()
    bound.begin = started
    _narrowed_after_the_phases(bound)


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
        yield other

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


def test_a_lock_failure_on_a_poisoned_session_narrows_on_a_fresh_one(bound):
    bound.manager.call.broken = True
    other, used, factory = _fresh(bound)
    holder = acquire_pass_lock(bound.world.root)
    with pytest.raises(RuntimeError, match="pass lock could not be taken"):
        _locked_bound(bound, started=bound.clock() - 30.0, fresh_manager=factory)
    holder.release()
    assert used == ["fresh"] and other.refused == 0
    assert all(other.state(d.name) is UnitState.MASKED for d in CORE_UNITS)


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


def test_a_fresh_session_that_cannot_connect_falls_back_to_the_old_one(bound):
    bound.manager.call.broken = True

    @contextlib.contextmanager
    def failing():
        raise UnitOperationFailed("could not connect to the system D-Bus service manager")
        yield

    holder = acquire_pass_lock(bound.world.root)
    with pytest.raises(RuntimeError, match="pass lock could not be taken"):
        _locked_bound(bound, started=bound.clock() - 30.0, fresh_manager=failing)
    holder.release()


def test_the_connection_cleanup_is_charged_to_the_deadline():
    import inspect
    from azazel_nexus_runtime.systemd_bus import SystemdBusSession
    source = inspect.getsource(SystemdBusSession.connect)
    cleanup = source[source.index("pending = asyncio.all_tasks(loop)"):]
    assert "timeout=_BUS_TIMEOUT_SECONDS" not in cleanup  # no uncharged fixed ten seconds
    assert "remaining()" in cleanup


# -- Codex 3 (05): the recheck's lock hold is provably below the main wait ----------------------------------------


@pytest.mark.parametrize("cost,ledger_cost", [(0.5, 0.0), (3.0, 1.5), (7.0, 1.9), (9.5, 1.9)])
def test_the_recheck_holds_the_lock_at_most_twenty_seconds_with_slow_manager_and_ledger(
        granted, monkeypatch, cost, ledger_cost):
    stage, guard = _slow(granted, cost)
    stage.world.healthy = False
    real_append = AuditLedger.append

    def slow_append(self, event, *args, **kwargs):
        stage.clock.sleep(ledger_cost)  # a local fsync, bounded by the record reserve
        return real_append(self, event, *args, **kwargs)

    monkeypatch.setattr(AuditLedger, "append", slow_append)
    started = stage.clock()
    activation_recheck.run_recheck(
        manager=stage.manager, authority=guard, root=stage.world.root, now=NOW,
        producers=stage.world.producers(), invocation_id="c" * 32,
        clock=stage.clock, sleep=stage.clock.sleep)
    held = stage.clock() - started
    assert held <= 20.0, held
    assert held < activated.PASS_LOCK_WAIT_SECONDS


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
    assert "That second pass is the designed behaviour, not a failure" in text
    assert "queued start job for the broker is preserved" in text
    assert "(unmask, enable, reload, marker written)" in text
    assert "to be confirmed on the clone, unit 45 S1" in text
    assert "the supported recovery is a reboot after the grant" in text
    assert "may re-mask" not in text and "is masked again" not in text


# -- the recheck appends to the ledger only after it has released the lock ---------------------------------------


def _watch_appends(monkeypatch, stage, *, cost):
    """Every append must find the pass lock free; each takes `cost` seconds of fake time."""
    seen = []
    real = AuditLedger.append
    started = stage.clock()

    def append(self, event, *args, **kwargs):
        try:
            free = acquire_pass_lock(stage.world.root)
        except Exception:  # held: the record is being written under the lock
            free = None
        else:
            free.release()
        seen.append((event["event_type"], free is not None, stage.clock() - started))
        stage.clock.sleep(cost)
        return real(self, event, *args, **kwargs)

    monkeypatch.setattr(AuditLedger, "append", append)
    return seen


def test_a_withdrawal_is_recorded_after_the_lock_is_released(granted, monkeypatch):
    stage = granted
    stage.world.healthy = False
    seen = _watch_appends(monkeypatch, stage, cost=30.0)  # a ledger that stalls for 30 s
    assert recheck(stage) == 0
    kinds = [kind for kind, free, _ in seen if kind == "activation.grant_withdrawn"]
    assert kinds == ["activation.grant_withdrawn"]
    assert all(free for _, free, _ in seen), seen
    # the lock was released inside the bound, before the 30 s append began
    assert all(at <= 20.0 for _, _, at in seen), seen


def test_an_unconfirmed_withdrawal_is_recorded_after_the_lock_is_released(granted, monkeypatch):
    stage = granted
    stage.model.stop_works = False
    stage.world.healthy = False
    seen = _watch_appends(monkeypatch, stage, cost=30.0)
    assert recheck(stage) == 1
    assert [k for k, _, _ in seen] == ["activation.withdrawal_unconfirmed"]
    assert all(free for _, free, _ in seen) and all(at <= 20.0 for _, _, at in seen)


def test_a_retirement_record_is_written_after_the_lock_is_released(granted, monkeypatch):
    stage = granted
    seen = _watch_appends(monkeypatch, stage, cost=30.0)
    code = activation_recheck.run_recheck(
        manager=stage.manager, authority=authority(stage.model), root=stage.world.root,
        now=NOW, producers=stage.world.producers(), invocation_id="c" * 32,
        retirement=lambda **kw: "retired", clock=stage.clock, sleep=stage.clock.sleep)
    assert code == 0
    assert [k for k, _, _ in seen] == ["activation.approval_retired"]
    assert all(free for _, free, _ in seen)


def test_a_slow_ledger_does_not_change_the_state_or_the_exit_status(granted, monkeypatch):
    stage = granted
    stage.world.healthy = False

    def failing(self, event, *args, **kwargs):
        raise OSError("synthetic: the ledger is unwritable")

    monkeypatch.setattr(AuditLedger, "append", failing)
    assert recheck(stage) == 0 and withdrawn(stage)


def test_with_a_sink_nothing_is_appended_by_the_withdrawal_or_the_job_clear(granted, monkeypatch):
    stage = granted
    appended = []
    monkeypatch.setattr(AuditLedger, "append", lambda self, event, *a, **k: appended.append(event))
    sink = []
    withdraw_contextd(
        reason="t", manager=stage.manager, authority=authority(stage.model),
        root=stage.world.root, ledger=AuditLedger(stage.world.ledger_path), now=NOW,
        actor="t", invocation_id="1" * 32, sink=sink.append,
        clock=stage.clock, sleep=stage.clock.sleep)
    stage.model.job = JOB
    stage.model.running = False
    stage.model.stopped_at = None  # the earlier stop has settled; this is a new queued job
    activation_withdraw.clear_contextd_job(
        authority=authority(stage.model), ledger=AuditLedger(stage.world.ledger_path),
        now=NOW, actor="t", reason="withheld", invocation_id="1" * 32, sink=sink.append,
        clock=stage.clock, sleep=stage.clock.sleep)
    assert appended == []
    assert [e["event_type"] for e in sink] == [
        "activation.grant_withdrawn", "activation.queued_job_replaced"]
    # the unconfirmed record travels the same way
    stage.model.running = True
    stage.model.stopped_at = None
    stage.model.stop_works = False
    with pytest.raises(WithdrawalUnconfirmed):
        withdraw_contextd(
            reason="t", manager=stage.manager, authority=authority(stage.model),
            root=stage.world.root, ledger=AuditLedger(stage.world.ledger_path), now=NOW,
            actor="t", invocation_id="1" * 32, sink=sink.append,
            clock=stage.clock, sleep=stage.clock.sleep)
    assert appended == [] and sink[-1]["event_type"] == "activation.withdrawal_unconfirmed"


def test_without_a_sink_the_main_pass_still_records_inline(granted):
    stage = granted
    stage.world.healthy = False
    withdraw_contextd(
        reason="t", manager=stage.manager, authority=authority(stage.model),
        root=stage.world.root, ledger=AuditLedger(stage.world.ledger_path), now=NOW,
        actor="t", invocation_id="1" * 32, clock=stage.clock, sleep=stage.clock.sleep)
    assert stage.world.events()[-1]["event_type"] == "activation.grant_withdrawn"


def test_an_append_under_the_lock_would_be_caught(granted, monkeypatch):
    """Negative check: if the recheck recorded inline, the watcher sees a held lock."""
    stage = granted
    stage.world.healthy = False
    real = activation_recheck.withdraw_contextd

    def inline(**kwargs):
        kwargs.pop("sink", None)  # the mutation: record while the lock is held
        return real(**kwargs)

    monkeypatch.setattr(activation_recheck, "withdraw_contextd", inline)
    seen = _watch_appends(monkeypatch, stage, cost=0.0)
    recheck(stage)
    assert any(not free for _, free, _ in seen)
