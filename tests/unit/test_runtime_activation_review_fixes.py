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
from azazel_nexus_runtime.activation_budget import (
    PassBudgetExpired, alarm_budget, check_budget,
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


# -- Codex 1: the budget holds in every phase --------------------------------------------


def test_the_budget_helpers():
    clock = FakeClock()
    check_budget(clock() + 1, clock)
    with pytest.raises(PassBudgetExpired):
        check_budget(clock(), clock)
    assert not issubclass(PassBudgetExpired, Exception)  # no broad handler swallows it
    started = time.monotonic()
    with pytest.raises(PassBudgetExpired):
        with alarm_budget(0.1):
            time.sleep(2)
    assert time.monotonic() - started < 1.0


def test_a_slow_collection_between_phases_ends_in_narrowing(fresh):
    """The clock passes the deadline inside a producer: the next phase check narrows."""
    def slow():
        fresh.clock.sleep(100)
        return fresh.world.evidence

    with pytest.raises(RuntimeError, match="used its whole time budget"):
        locked(fresh, producers=fresh.world.producers(commissioning_evidence=slow))
    assert all_masked_and_unmarked(fresh)
    assert any(e["event_type"] == "activation.pass_budget_expired" for e in fresh.world.events())
    assert fresh.manager.timeline[-1] == ("reload", "")


def test_a_producer_that_does_not_return_is_abandoned_by_the_alarm(fresh):
    def hangs():
        time.sleep(5)
        return fresh.world.evidence

    started = time.monotonic()
    with pytest.raises(RuntimeError, match="used its whole time budget"):
        locked(fresh, budget_seconds=0.3,
               producers=fresh.world.producers(commissioning_evidence=hangs))
    assert time.monotonic() - started < 2.0
    assert all_masked_and_unmarked(fresh)


def test_a_slow_manager_call_is_abandoned_by_the_alarm(fresh):
    original = fresh.manager.reload
    slow = {"first": True}

    def reload():
        if slow.pop("first", False):
            time.sleep(5)
        original()

    fresh.manager.reload = reload
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="used its whole time budget"):
        locked(fresh, budget_seconds=0.3)
    assert time.monotonic() - started < 2.0
    assert all_masked_and_unmarked(fresh)


@pytest.mark.parametrize("which", ["ready", "barrier"])
def test_a_slow_ready_or_barrier_is_abandoned_and_narrowed(fresh, monkeypatch, which):
    from azazel_nexus_runtime import systemd_notify

    def slow():
        time.sleep(5)

    monkeypatch.setattr(systemd_notify, "notify_ready" if which == "ready" else "notify_barrier",
                        slow)
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="used its whole time budget"):
        locked(fresh, budget_seconds=0.5)
    assert time.monotonic() - started < 3.0
    assert all_masked_and_unmarked(fresh)


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


def test_without_the_alarm_and_the_checks_the_slow_pass_would_complete(fresh, monkeypatch):
    """Negative check: with the enforcement removed the scenario above is not caught."""
    monkeypatch.setattr(activated, "alarm_budget", lambda seconds: contextlib.nullcontext())
    monkeypatch.setattr(activated, "check_budget", lambda deadline, clock: None)

    def slow():
        fresh.clock.sleep(100)
        return fresh.world.evidence

    outcome = locked(fresh, producers=fresh.world.producers(commissioning_evidence=slow))
    assert CTX in outcome.granted  # granted after 100 s on a 45 s budget


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
    # and the next recheck does not withdraw it again
    stage.manager.timeline.clear()
    assert recheck(stage) == 0
    assert stage.manager.timeline == []


def test_failed_with_a_job_is_not_quiet_and_failed_is_not_running():
    clock = FakeClock()
    model = ContextdModel(clock)
    model.failed = True
    guard = authority(model)
    assert contextd_is_quiet(guard) and not contextd_is_running(guard)
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
    assert activation_recheck.RECHECK_BUDGET_SECONDS + 5 <= 40  # TimeoutStartSec=40s
    assert activation_recheck.RECHECK_COLLECT_SECONDS < activation_recheck.RECHECK_BUDGET_SECONDS
    assert activated.PASS_LOCK_WAIT_SECONDS < activated.MAIN_PASS_BUDGET_SECONDS
    assert activated.MAIN_PASS_BUDGET_SECONDS + 15 <= 60  # TimeoutStartSec=60s
    unit = open("packaging/systemd/azazel-activation-recheck.service").read() \
        if os.path.exists("packaging/systemd/azazel-activation-recheck.service") else None
    if unit is not None:
        assert "TimeoutStartSec=40s" in unit


def test_a_recheck_that_cannot_stop_the_broker_ends_inside_its_budget(granted):
    stage = granted
    stage.model.stop_works = False
    stage.world.healthy = False
    started = stage.clock()
    assert recheck(stage) == 1
    held = stage.clock() - started
    assert held <= activation_recheck.RECHECK_BUDGET_SECONDS + 0.2
    last = events_after(stage)[-1]
    assert last["event_type"] == "activation.withdrawal_unconfirmed"  # recorded before any kill


def test_a_collection_that_does_not_finish_is_a_withhold_and_the_withdrawal_still_runs(granted):
    stage = granted

    def hangs():
        time.sleep(5)

    started = time.monotonic()
    code = activation_recheck.run_recheck(
        manager=stage.manager, authority=authority(stage.model), root=stage.world.root,
        now=NOW, producers=stage.world.producers(commissioning_evidence=hangs),
        invocation_id="c" * 32, clock=stage.clock, sleep=stage.clock.sleep,
        collect_seconds=0.3)
    assert time.monotonic() - started < 2.0
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
