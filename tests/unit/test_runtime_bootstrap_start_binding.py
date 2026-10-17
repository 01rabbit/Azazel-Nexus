"""Start-boundary transaction tests using the in-memory supervisor harness."""

from dataclasses import fields, replace

import pytest

pytest_plugins = ("test_runtime_bootstrap",)

from azazel_nexus.operator_trust import ApprovalRefused  # noqa: E402
from azazel_nexus.bootstrap_grant_transaction import advance_transaction  # noqa: E402
from azazel_nexus_runtime.bootstrap_audit import AuditObservation  # noqa: E402
from azazel_nexus_runtime.units import UnitKey  # noqa: E402


def _intercept_start(harness, callback):
    original = harness.manager.start_and_wait

    def start(unit, *, transaction, check_start):
        return callback(original, unit, transaction, check_start)

    harness.manager.start_and_wait = start


def _assert_no_readiness_advanced(harness, units):
    ready_events = {
        event.get("unit_key")
        for event in harness.events
        if event.get("event_type") == "bootstrap.ready"
    }
    assert not (ready_events & {unit.value for unit in units})
    assert not any(
        operation == "is_ready" and unit in units
        for operation, unit in harness.manager.calls
    )


@pytest.mark.parametrize("substitution", ["wrong-unit", "wrong-phase", "grant"])
def test_audit_start_rejects_unit_phase_or_grant_substitution(evidence, substitution):
    from test_runtime_bootstrap import Harness

    harness = Harness(evidence)

    def intercept(original, unit, transaction, check_start):
        if unit is UnitKey.AUDITD:
            if substitution == "wrong-unit":
                harness.supervisor._start_checkpoint(UnitKey.COMMISSIOND, transaction)
            elif substitution == "wrong-phase":
                wrong = advance_transaction(transaction, "auditd_ready")
                harness.supervisor._start_checkpoint(unit, wrong)
            else:
                wrong = replace(transaction, grant_id="f" * 32)
                harness.supervisor._start_checkpoint(unit, wrong)
        return original(unit, transaction=transaction, check_start=check_start)

    _intercept_start(harness, intercept)
    with pytest.raises(ApprovalRefused):
        harness.supervisor.run()

    assert ("start_and_wait", UnitKey.AUDITD) not in harness.manager.calls
    assert ("start_and_wait", UnitKey.COMMISSIOND) not in harness.manager.calls
    _assert_no_readiness_advanced(harness, (UnitKey.AUDITD, UnitKey.COMMISSIOND))


def test_commission_start_rejects_missing_audit_receipt(evidence):
    from test_runtime_bootstrap import Harness

    harness = Harness(evidence)

    def intercept(original, unit, transaction, check_start):
        if unit is UnitKey.COMMISSIOND:
            # Defensive malformed-object fixture: the normal constructor forbids
            # this state, so this checks rejection of an invalid transaction value.
            missing_receipt = object.__new__(type(transaction))
            for item in fields(transaction):
                object.__setattr__(
                    missing_receipt, item.name, getattr(transaction, item.name)
                )
            object.__setattr__(missing_receipt, "audit_receipt_digest", None)
            harness.supervisor._start_checkpoint(unit, missing_receipt)
        return original(unit, transaction=transaction, check_start=check_start)

    _intercept_start(harness, intercept)
    with pytest.raises(ApprovalRefused):
        harness.supervisor.run()

    assert ("start_and_wait", UnitKey.AUDITD) in harness.manager.calls
    assert ("start_and_wait", UnitKey.COMMISSIOND) not in harness.manager.calls
    _assert_no_readiness_advanced(harness, (UnitKey.COMMISSIOND,))


@pytest.mark.parametrize("invalid_unit", ["auditd", "commissiond", None])
def test_start_checkpoint_rejects_non_unit_key_before_manager_call(evidence, invalid_unit):
    from test_runtime_bootstrap import Harness

    harness = Harness(evidence)

    def intercept(original, unit, transaction, check_start):
        if unit is UnitKey.AUDITD:
            harness.supervisor._start_checkpoint(invalid_unit, transaction)
        return original(unit, transaction=transaction, check_start=check_start)

    _intercept_start(harness, intercept)
    with pytest.raises(ApprovalRefused):
        harness.supervisor.run()

    assert ("start_and_wait", UnitKey.AUDITD) not in harness.manager.calls
    _assert_no_readiness_advanced(harness, (UnitKey.AUDITD, UnitKey.COMMISSIOND))


@pytest.mark.parametrize("result", [True, False])
def test_non_none_manager_start_result_is_refused(evidence, result):
    from test_runtime_bootstrap import Harness

    harness = Harness(evidence)

    def return_unconfirmed(_original, _unit, _transaction, check_start):
        assert check_start() is None
        return result

    _intercept_start(harness, return_unconfirmed)
    with pytest.raises(ApprovalRefused, match="completion unconfirmed"):
        harness.supervisor.run()

    assert ("start_and_wait", UnitKey.AUDITD) not in harness.manager.calls
    _assert_no_readiness_advanced(harness, (UnitKey.AUDITD, UnitKey.COMMISSIOND))


@pytest.mark.parametrize("unit,failure", [
    (UnitKey.AUDITD, "cancel"),
    (UnitKey.AUDITD, "expiry"),
    (UnitKey.COMMISSIOND, "cancel"),
    (UnitKey.COMMISSIOND, "expiry"),
])
def test_start_refuses_cancellation_or_expiry_during_store_read(evidence, unit, failure):
    from test_runtime_bootstrap import Harness

    harness = Harness(evidence)
    original_load = harness.grant_store.load_optional
    triggered = []

    def load_during_start_read(*, boot_id):
        observed = original_load(boot_id=boot_id)
        expected_phase = (
            "auditd_start_intent"
            if unit is UnitKey.AUDITD
            else "commissiond_start_intent"
        )
        if observed is not None and observed.phase == expected_phase and not triggered:
            triggered.append(expected_phase)
            if failure == "cancel":
                harness.stop = True
            else:
                harness.supervisor.boottime_ns = (
                    lambda: harness.deadline.deadline_boottime_ns
                )
        return observed

    harness.grant_store.load_optional = load_during_start_read
    with pytest.raises(ApprovalRefused):
        harness.supervisor.run()

    assert triggered == [
        "auditd_start_intent"
        if unit is UnitKey.AUDITD
        else "commissiond_start_intent"
    ]
    assert ("start_and_wait", unit) not in harness.manager.calls
    _assert_no_readiness_advanced(harness, (unit,))
    if unit is UnitKey.COMMISSIOND:
        assert ("start_and_wait", UnitKey.AUDITD) in harness.manager.calls


def test_post_manager_store_drift_blocks_readiness(evidence):
    from test_runtime_bootstrap import Harness

    harness = Harness(evidence)

    def intercept(original, unit, transaction, check_start):
        result = original(unit, transaction=transaction, check_start=check_start)
        if unit is UnitKey.AUDITD:
            harness.grant_store.journal = replace(
                harness.grant_store.journal, grant_id="e" * 32
            )
        return result

    _intercept_start(harness, intercept)
    with pytest.raises(ApprovalRefused):
        harness.supervisor.run()

    assert ("start_and_wait", UnitKey.AUDITD) in harness.manager.calls
    assert ("start_and_wait", UnitKey.COMMISSIOND) not in harness.manager.calls
    _assert_no_readiness_advanced(harness, (UnitKey.AUDITD, UnitKey.COMMISSIOND))


@pytest.mark.parametrize("failure", ["cancel", "expiry"])
def test_post_manager_cancellation_or_expiry_blocks_readiness(evidence, failure):
    from test_runtime_bootstrap import Harness

    harness = Harness(evidence)

    def change_after_manager(original, unit, transaction, check_start):
        result = original(unit, transaction=transaction, check_start=check_start)
        if unit is UnitKey.AUDITD:
            if failure == "cancel":
                harness.stop = True
            else:
                harness.supervisor.boottime_ns = (
                    lambda: harness.deadline.deadline_boottime_ns
                )
        return result

    _intercept_start(harness, change_after_manager)
    with pytest.raises(ApprovalRefused):
        harness.supervisor.run()

    assert ("start_and_wait", UnitKey.AUDITD) in harness.manager.calls
    assert ("start_and_wait", UnitKey.COMMISSIOND) not in harness.manager.calls
    _assert_no_readiness_advanced(harness, (UnitKey.AUDITD, UnitKey.COMMISSIOND))


def test_audit_extension_failure_after_start_blocks_readiness_and_commission(evidence):
    from test_runtime_bootstrap import Harness

    harness = Harness(evidence)
    after_submission = []

    def fail_extension_during_handoff(_context, previous):
        if harness.manager.inactive[UnitKey.AUDITD] is False:
            after_submission.append(previous.sequence)
            raise ApprovalRefused("audit extension refused during writer handoff")
        return previous

    harness.supervisor.audit_continuation = fail_extension_during_handoff
    with pytest.raises(ApprovalRefused, match="audit extension refused"):
        harness.supervisor.run()

    assert after_submission
    assert ("start_and_wait", UnitKey.AUDITD) in harness.manager.calls
    assert ("start_and_wait", UnitKey.COMMISSIOND) not in harness.manager.calls
    _assert_no_readiness_advanced(harness, (UnitKey.AUDITD, UnitKey.COMMISSIOND))


def test_handoff_extension_cannot_replace_original_live_startup_anchor(evidence):
    from test_runtime_bootstrap import Harness

    harness = Harness(evidence)
    extensions = []

    def accepted_extension(_context, previous):
        if harness.manager.inactive[UnitKey.AUDITD] is False:
            extensions.append(previous.sequence)
            return AuditObservation(2, "b" * 64, 1, 200)
        return previous

    class AdvancedLiveHead:
        def observe_head(self):
            assert harness.grant_journal.phase == "auditd_start_intent"
            return 2, "b" * 64

    harness.supervisor.audit_continuation = accepted_extension
    harness.supervisor.audit_head_reader = AdvancedLiveHead()
    with pytest.raises(ApprovalRefused, match="startup head differs"):
        harness.supervisor.run()

    assert extensions
    assert ("start_and_wait", UnitKey.AUDITD) in harness.manager.calls
    assert ("start_and_wait", UnitKey.COMMISSIOND) not in harness.manager.calls
    assert not any(event.get("event_type") == "bootstrap.ready" for event in harness.events)
    assert not any(
        operation == "is_ready" and unit is UnitKey.COMMISSIOND
        for operation, unit in harness.manager.calls
    )


def test_commission_start_requires_fresh_audit_readiness(evidence):
    from test_runtime_bootstrap import Harness

    harness = Harness(evidence)
    original = harness.manager.start_and_wait

    def without_audit_readiness(unit, *, transaction, check_start):
        if unit is UnitKey.COMMISSIOND:
            harness.manager.ready = False
        return original(unit, transaction=transaction, check_start=check_start)

    harness.manager.start_and_wait = without_audit_readiness
    with pytest.raises(ApprovalRefused):
        harness.supervisor.run()

    assert ("start_and_wait", UnitKey.COMMISSIOND) not in harness.manager.calls
    _assert_no_readiness_advanced(harness, (UnitKey.COMMISSIOND,))
