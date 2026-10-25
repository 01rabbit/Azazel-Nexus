"""Main-loop watchdog renewals remain behind READY and admission checks."""

import pytest

from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap as bootstrap_module
from azazel_nexus_runtime.units import UnitKey
from test_runtime_bootstrap import Harness, evidence as bootstrap_evidence


@pytest.fixture
def evidence():
    # Reuse the canonical synthetic approval fixture from its owning module.
    return bootstrap_evidence.__wrapped__(None)


def test_start_checkpoints_and_steady_poll_renew_only_after_ready(evidence):
    observations = []
    order = []
    harness_ref = {}

    def watchdog():
        supervisor = harness_ref["h"].supervisor
        assert supervisor._controller_ready_confirmed
        assert supervisor._previous is not None
        observations.append(supervisor._last_elapsed)
        order.append("watchdog")

    h = Harness(evidence, controller_watchdog=watchdog)
    harness_ref["h"] = h
    h.supervisor.controller_ready = lambda: order.append("ready")
    h.supervisor.wait = lambda seconds: (
        order.append("wait"), setattr(h, "stop", True)
    )

    assert h.supervisor.run().state == "stopped"
    assert order[0] == "ready"
    assert order[-2:] == ["watchdog", "wait"]
    assert len(observations) >= 7  # three checks per start plus steady poll
    assert [unit for op, unit in h.manager.calls if op == "start_and_wait"] == [
        UnitKey.AUDITD, UnitKey.COMMISSIOND,
    ]


def test_cancellation_before_ready_never_renews_watchdog(evidence):
    calls = []
    h = Harness(evidence, controller_watchdog=lambda: calls.append(True))
    h.stop = True

    assert h.supervisor.run().state == "stopped"
    assert calls == []
    assert not any(op == "start_and_wait" for op, _ in h.manager.calls)


def test_steady_poll_wait_is_capped_at_ten_seconds(evidence):
    waits = []
    h = Harness(evidence)
    h.supervisor.poll_seconds = 60.0

    def wait(seconds):
        waits.append(seconds)
        h.stop = True

    h.supervisor.wait = wait
    assert h.supervisor.run().state == "stopped"
    assert waits == [10.0]


def test_slow_steady_watchdog_notification_reduces_remaining_wait(evidence):
    now = [100_000_000_000]
    waits = []
    h_ref = {}
    deadline = evidence[0].deadline_boottime_ns

    def watchdog():
        h = h_ref["h"]
        if h.grant_journal.phase == "commissiond_ready":
            # Simulate a notifier consuming three seconds, leaving four
            # seconds in the immutable deadline. No wall clock sleep occurs.
            now[0] = deadline - 7 * 1_000_000_000
            now[0] += 3 * 1_000_000_000

    h = Harness(evidence, clock=lambda: now[0], controller_watchdog=watchdog)
    h_ref["h"] = h
    h.supervisor.poll_seconds = 60.0

    def wait(seconds):
        waits.append(seconds)
        h.stop = True

    h.supervisor.wait = wait
    assert h.supervisor.run().state == "stopped"
    assert waits == pytest.approx([4.0])


@pytest.mark.parametrize("outcome", ["non-none", "exception"])
def test_unconfirmed_or_failing_watchdog_contains_pair(evidence, outcome):
    calls = []

    def watchdog():
        calls.append(True)
        if outcome == "exception":
            raise RuntimeError("watchdog notification failed")
        return False

    h = Harness(evidence, controller_watchdog=watchdog)
    expected = ApprovalRefused if outcome == "non-none" else RuntimeError
    with pytest.raises(expected):
        h.supervisor.run()

    assert calls == [True]
    assert all(h.manager.inactive.values())
    assert all(h.manager.masked.values())
    assert not h.supervisor._controller_ready_confirmed


@pytest.mark.parametrize("interruption", ["cancel", "expire"])
def test_slow_watchdog_notification_cannot_hide_cancellation_or_expiry(
    evidence, interruption,
):
    now = [100_000_000_000]
    h_ref = {}
    calls = []

    def watchdog():
        calls.append(True)
        if interruption == "cancel":
            h_ref["h"].stop = True
        else:
            now[0] = evidence[0].deadline_boottime_ns

    h = Harness(evidence, clock=lambda: now[0], controller_watchdog=watchdog)
    h_ref["h"] = h
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()

    assert calls == [True]
    assert all(h.manager.inactive.values())
    assert all(h.manager.masked.values())
    assert not h.supervisor._controller_ready_confirmed


@pytest.mark.parametrize("interruption", ["cancel", "expire"])
@pytest.mark.parametrize("guard_call", ["before-notify", "after-notify"])
def test_watchdog_guard_resamples_after_transaction_validation(
    evidence, interruption, guard_call,
):
    """Direct internal checkpoint exercise; this is not process evidence."""
    now = [100_000_000_000]
    notifications = []
    guard_calls = []
    h = Harness(evidence, clock=lambda: now[0],
                controller_watchdog=lambda: notifications.append(True))
    supervisor = h.supervisor
    supervisor._controller_ready_confirmed = True
    supervisor._previous = h.deadline
    supervisor._last_elapsed = now[0]

    def transaction_guard():
        guard_calls.append(True)
        target = 1 if guard_call == "before-notify" else 2
        if len(guard_calls) == target:
            if interruption == "cancel":
                h.stop = True
            else:
                now[0] = h.deadline.deadline_boottime_ns

    supervisor._check_transaction = transaction_guard
    continuation = []
    with pytest.raises(ApprovalRefused):
        supervisor._heartbeat()
        continuation.append(True)

    assert continuation == []
    assert len(guard_calls) == (1 if guard_call == "before-notify" else 2)
    assert len(notifications) == (0 if guard_call == "before-notify" else 1)


# --- Post-READY ping spacing (Nexus#324 VM watchdog kill) -----------------
# Synthetic step accounting with fake callbacks; this is not PID 1 evidence.

# Blocking steps counted in the post-READY startup sequence: a full _check(),
# a helper readiness read (_ready), a live audit head read outside _check
# (verify_startup / observe), a grant-journal fsync and an audit append.
# Reads nested inside a counted step belong to that step.
_BLOCKING = ("check", "ready-read", "audit-read", "fsync", "append")


def _instrumented(evidence, monkeypatch, fail_at=None, receipt_override=None):
    """Log each blocking step after it returns, and each WATCHDOG=1 ping.

    ``fail_at`` refuses the n-th top-level blocking step after READY (0-based).
    """
    log = []
    state = {"ready": False, "post_ready_steps": 0, "depth": 0}

    def wrap(kind, original):
        def step(*args, **kwargs):
            if state["depth"]:
                return original(*args, **kwargs)
            index = None
            if state["ready"]:
                index = state["post_ready_steps"]
                state["post_ready_steps"] += 1
            if fail_at is not None and index == fail_at:
                log.append(kind + "-failed")
                raise ApprovalRefused(f"synthetic {kind} refusal")
            state["depth"] += 1
            try:
                result = original(*args, **kwargs)
            finally:
                state["depth"] -= 1
            if kind == "append" and receipt_override is not None:
                result = receipt_override(args, result)
            log.append(kind)
            return result
        return step

    class LoggedLiveAuditHead(bootstrap_module.BootstrapLiveAuditHead):
        def verify_startup(self):
            return wrap("audit-read", super().verify_startup)()

        def observe(self):
            return wrap("audit-read", super().observe)()

    monkeypatch.setattr(
        bootstrap_module, "BootstrapLiveAuditHead", LoggedLiveAuditHead
    )
    h = Harness(evidence)
    supervisor = h.supervisor
    supervisor._check = wrap("check", supervisor._check)
    supervisor._ready = wrap("ready-read", supervisor._ready)
    supervisor._advance_grant = wrap("fsync", supervisor._advance_grant)
    supervisor._record = wrap("append", supervisor._record)

    def ready():
        state["ready"] = True
        log.append("ready")

    def wait(seconds):
        log.append("wait")
        h.stop = True

    supervisor.controller_ready = ready
    supervisor.controller_watchdog = lambda: log.append("ping")
    supervisor.wait = wait
    return h, log, state


def _startup_segments(log):
    """Blocking-step counts between consecutive pings, READY .. first wait."""
    first = log.index("ping")
    end = log.index("wait")
    segments, count = [], 0
    for entry in log[first + 1:end]:
        if entry == "ping":
            segments.append(count)
            count = 0
        elif entry in _BLOCKING:
            count += 1
    return segments, count


def test_post_ready_startup_has_at_most_one_blocking_step_between_pings(
    evidence, monkeypatch,
):
    h, log, _ = _instrumented(evidence, monkeypatch)
    assert h.supervisor.run().state == "stopped"

    assert log.index("ready") < log.index("ping")
    segments, trailing = _startup_segments(log)
    assert segments and max(segments) <= 1, segments
    assert trailing == 0, "a blocking step precedes the steady wait without a ping"
    # The two helper starts, the grant journal and the audit intents all
    # happen inside the measured window.
    window = log[log.index("ping"):log.index("wait")]
    assert window.count("fsync") == 5
    assert window.count("append") == 6
    assert window.count("audit-read") == 2  # verify_startup + grant-intent observe
    assert window.count("ready-read") >= 6
    assert [unit for op, unit in h.manager.calls if op == "start_and_wait"] == [
        UnitKey.AUDITD, UnitKey.COMMISSIOND,
    ]


def test_every_post_ready_ping_directly_follows_a_completed_step(
    evidence, monkeypatch,
):
    h, log, _ = _instrumented(evidence, monkeypatch)
    assert h.supervisor.run().state == "stopped"

    pings = [i for i, entry in enumerate(log) if entry == "ping"]
    assert log[pings[0] - 1] in {"ready", *_BLOCKING}
    for index in pings[1:]:
        assert log[index - 1] in _BLOCKING, log[index - 3:index + 1]


def test_no_ping_after_any_failed_post_ready_step(evidence, monkeypatch):
    h, log, state = _instrumented(evidence, monkeypatch)
    assert h.supervisor.run().state == "stopped"
    steps_before_wait = sum(
        1 for entry in log[log.index("ready"):log.index("wait")]
        if entry in _BLOCKING
    )
    assert steps_before_wait >= 30
    failed_kinds = set()

    for fail_at in range(steps_before_wait):
        h, log, _ = _instrumented(evidence, monkeypatch, fail_at=fail_at)
        with pytest.raises(ApprovalRefused):
            h.supervisor.run()
        failed = next(i for i, e in enumerate(log) if e.endswith("-failed"))
        failed_kinds.add(log[failed])
        assert "ping" not in log[failed:], (fail_at, log[failed - 1])
        assert all(h.manager.inactive.values())
        assert all(h.manager.masked.values())
    assert failed_kinds == {kind + "-failed" for kind in _BLOCKING}


def test_unconfirmed_audit_receipt_is_not_renewed(evidence, monkeypatch):
    def drop_controller_ready_receipt(args, result):
        return None if args[0] == "bootstrap.controller_ready_intent" else result

    h, log, _ = _instrumented(
        evidence, monkeypatch, receipt_override=drop_controller_ready_receipt
    )
    h.supervisor.run()

    appends = [i for i, e in enumerate(log) if e == "append"]
    events = [e["event_type"] for e in h.events]
    dropped = appends[events.index("bootstrap.controller_ready_intent")]
    assert log[dropped + 1] != "ping"
