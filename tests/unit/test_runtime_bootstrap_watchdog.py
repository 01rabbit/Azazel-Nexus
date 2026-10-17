"""Main-loop watchdog renewals remain behind READY and admission checks."""

import pytest

from azazel_nexus.operator_trust import ApprovalRefused
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
