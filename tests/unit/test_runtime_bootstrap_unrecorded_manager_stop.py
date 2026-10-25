"""Nexus#339: a systemd stop that ended supervision before the close was recorded.

The failing boot keeps ``recovery_required`` and only labels the evidence; a
later boot may retire that boot's closed overlay journal for exactly that label.
Every other pair (generic recovery evidence, mismatched identity, other failure
types, unproven stop or chain) keeps manual recovery.
"""

# ruff: noqa: F811 - the imported ``evidence`` fixture is used by parameter name.

from dataclasses import replace
from hashlib import sha256
import json

import pytest

from azazel_nexus.audit import AuditUnavailable
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.bootstrap import BootstrapContainmentFailed
from azazel_nexus_runtime.bootstrap_audit import AuditObservation
from azazel_nexus_runtime.bootstrap_recovery_evidence import (
    MANAGER_STOP_SUPERVISION_FAILURES,
    UNRECORDED_MANAGER_STOP,
    unrecorded_manager_stop_digest,
    unrecorded_manager_stop_failure,
)
from azazel_nexus_runtime.units import UnitOperationFailed

from test_runtime_bootstrap import evidence  # noqa: F401,F811
from test_runtime_bootstrap_journal_retire import NEW_BOOT, OLD_BOOT, _entries, _stage
from test_runtime_bootstrap_journal_retire_callsite import (
    _abandoned_grant,
    _fenced,
    _grant_for,
    _manager,
    _spy_writes,
)
from test_runtime_bootstrap_operator_stop import (
    StopObservingManager,
    _event_types,
    _fail_stopping,
    _harness,
)
from test_runtime_bootstrap_overlay_withdraw import _withdraw_environment


def _label(grant, failure):
    """Independent recomputation of the v2 recovery label (schema pinned here)."""
    raw = json.dumps(
        {
            "schema": "azazel-nexus/bootstrap-recovery-evidence/v2",
            "reason": "manager-stop-close-unrecorded",
            "boot_id": grant.boot_id,
            "grant_id": grant.grant_id,
            "context_digest": grant.context_digest,
            "approval_digest": grant.approval_digest,
            "generation": grant.generation,
            "generation_digest": grant.generation_digest,
            "unit_payload_digests": [list(row) for row in grant.unit_payload_digests],
            "audit_receipt_digest": grant.audit_receipt_digest,
            "supervision_failure": failure,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return "sha256:" + sha256(raw).hexdigest()


def _generic(grant, failure_type="AuditUnavailable"):
    raw = json.dumps(
        {
            "schema": "azazel-nexus/bootstrap-recovery-evidence/v1",
            "grant_id": grant.grant_id,
            "phase": "closing",
            "failure_type": failure_type,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return "sha256:" + sha256(raw).hexdigest()


# --- failing boot: the supervisor labels, never closes ----------------------


def _stop_window_failure(evidence, cause, *, observed=True, manager=None,
                         record_error=None, tip=None):
    """Supervision fails with ``cause`` while the helpers are being stopped."""
    manager = manager if manager is not None else StopObservingManager(observed)
    h = _harness(evidence, manager, tip=tip)
    _fail_stopping(h, record_error)

    def wait(seconds):
        h.waits.append(seconds)
        raise cause

    h.supervisor.wait = wait
    return h


@pytest.mark.parametrize("cause", [
    UnitOperationFailed("loaded bootstrap observation refused"),
    AuditUnavailable("verified audit head unavailable"),
])
def test_helper_observation_failure_under_manager_stop_is_labelled(evidence, cause):
    h = _stop_window_failure(evidence, cause)
    with pytest.raises(ApprovalRefused, match="not fully recorded"):
        h.supervisor.run()
    grant = h.grant_journal
    assert grant.phase == "recovery_required"  # never closed in the failing boot
    assert grant.close_evidence_digest is None
    assert grant.recovery_evidence_digest == _label(grant, type(cause).__name__)
    assert grant.recovery_evidence_digest != _generic(grant)
    assert unrecorded_manager_stop_failure(grant) == type(cause).__name__
    assert h.manager.observe_calls == 1
    assert all(h.manager.inactive.values()) and all(h.manager.masked.values())
    assert "bootstrap.stopped" not in _event_types(h)


def _assert_generic(h):
    grant = h.grant_journal
    assert grant.phase == "recovery_required"
    assert unrecorded_manager_stop_failure(grant) is None
    assert grant.recovery_evidence_digest not in {
        _label(grant, name) for name in MANAGER_STOP_SUPERVISION_FAILURES}


class _SubclassFailure(UnitOperationFailed):
    pass


def _same_name(base, name):
    """A different class that only borrows an admitted type name."""
    return type(name, (base,), {})


@pytest.mark.parametrize("cause", [
    RuntimeError("boom"),
    ApprovalRefused("bootstrap elapsed deadline expired"),
    BootstrapContainmentFailed("x"),
    _SubclassFailure("loaded bootstrap observation refused"),
    # Exact types only: neither a subclass nor a look-alike name qualifies.
    _same_name(UnitOperationFailed, "UnitOperationFailed")("x"),
    _same_name(AuditUnavailable, "AuditUnavailable")("x"),
    _same_name(RuntimeError, "UnitOperationFailed")("x"),
    _same_name(ApprovalRefused, "AuditUnavailable")("x"),
])
def test_other_supervision_failures_are_not_labelled(evidence, cause):
    h = _stop_window_failure(evidence, cause)
    with pytest.raises(ApprovalRefused, match="not fully recorded"):
        h.supervisor.run()
    _assert_generic(h)


def test_no_manager_stop_observed_is_not_labelled(evidence):
    h = _stop_window_failure(evidence, UnitOperationFailed("x"), observed=False)
    with pytest.raises(ApprovalRefused, match="not fully recorded"):
        h.supervisor.run()
    _assert_generic(h)
    assert h.manager.observe_calls == 1


@pytest.mark.parametrize("kind", ["raises", "non-bool"])
def test_unreadable_stop_observation_is_not_labelled(evidence, kind):
    manager = StopObservingManager(True)
    if kind == "raises":
        manager.observe_error = RuntimeError("bus error")
    else:
        manager.controller_stop_observed = lambda: 1
    h = _stop_window_failure(evidence, UnitOperationFailed("x"), manager=manager)
    with pytest.raises(ApprovalRefused, match="not fully recorded"):
        h.supervisor.run()
    _assert_generic(h)


def test_stopping_record_error_other_than_audit_unavailable_is_not_labelled(evidence):
    h = _stop_window_failure(evidence, UnitOperationFailed("x"),
                             record_error=RuntimeError("other"))
    with pytest.raises(ApprovalRefused, match="not fully recorded"):
        h.supervisor.run()
    _assert_generic(h)
    assert h.manager.observe_calls == 0


@pytest.mark.parametrize("defect", ["behind", "same-seq-other-digest", "raises"])
def test_broken_chain_after_containment_is_not_labelled(evidence, defect):
    def tip(head):
        if defect == "behind":
            return AuditObservation(1, "a" * 64, 1, 100)
        if defect == "same-seq-other-digest":
            return AuditObservation(head.sequence, "e" * 64, 1, 100)
        raise ApprovalRefused("chain broken")

    h = _stop_window_failure(evidence, UnitOperationFailed("x"), tip=tip)
    with pytest.raises(ApprovalRefused, match="not fully recorded"):
        h.supervisor.run()
    _assert_generic(h)


def test_missing_receipt_is_not_labelled(evidence):
    h = _stop_window_failure(evidence, UnitOperationFailed("x"))
    _fail_stopping(h, before=lambda: setattr(h.supervisor, "_last_receipt", None))
    with pytest.raises(ApprovalRefused, match="not fully recorded"):
        h.supervisor.run()
    _assert_generic(h)


def test_containment_failure_is_not_labelled(evidence):
    manager = StopObservingManager(True)
    manager.stop_failure_after_open = True
    h = _stop_window_failure(evidence, UnitOperationFailed("x"), manager=manager)
    with pytest.raises(BootstrapContainmentFailed):
        h.supervisor.run()
    _assert_generic(h)


def test_close_intent_failure_is_not_labelled(evidence):
    h = _stop_window_failure(evidence, UnitOperationFailed("x"))
    store = h.grant_store
    original = store.advance

    def advance(expected, action, *, evidence_digest=None):
        if action == "closing":
            raise ApprovalRefused("store down")
        return original(expected, action, evidence_digest=evidence_digest)

    store.advance = advance
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()
    assert h.grant_journal.phase == "recovery_required"
    assert unrecorded_manager_stop_failure(h.grant_journal) is None
    assert h.manager.observe_calls == 0


def test_eligible_manager_stop_still_closes_unlabelled(evidence):
    h = _harness(evidence)
    _fail_stopping(h)  # SIGTERM path: the ordinary absent-manager-stop close
    result = h.supervisor.run()
    assert result.stopping_record == "absent-manager-stop"
    assert h.grant_journal.phase == "closed"
    assert h.grant_journal.recovery_evidence_digest is None


def test_label_helpers_refuse_other_inputs(evidence):
    h = _stop_window_failure(evidence, UnitOperationFailed("x"))
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()
    grant = h.grant_journal
    with pytest.raises(ValueError):
        unrecorded_manager_stop_digest(grant, "RuntimeError")
    with pytest.raises(ValueError):
        unrecorded_manager_stop_digest(object(), "UnitOperationFailed")
    assert unrecorded_manager_stop_failure(None) is None
    assert unrecorded_manager_stop_failure(replace(
        grant, recovery_evidence_digest=_label(grant, "RuntimeError"))) is None


# --- next boot: retire the earlier boot's closed journal for that label only --


def _labelled(closed, failure="UnitOperationFailed", **identity):
    grant = _abandoned_grant(closed, "recovery_required")
    grant = replace(grant, audit_receipt_digest="sha256:" + "b" * 64, **identity)
    return replace(grant, recovery_evidence_digest=_label(grant, failure))


@pytest.mark.parametrize("failure", list(MANAGER_STOP_SUPERVISION_FAILURES))
def test_closed_journal_with_labelled_recovery_grant_is_retired(tmp_path, failure):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        manager, grants = _manager(env, {OLD_BOOT: _labelled(closed, failure)})
        seen = []
        manager._retirement_record = lambda event: seen.append(
            (event, env["store"].load_optional())) or True
        manager._retire_prior_boot_journal(env["store"], env["guard"])
        (event, still_there), = seen
        assert still_there == closed  # the record precedes the unlink
        assert env["store"].load_optional() is None
        assert _entries(env) == []
        assert grants.loads == [OLD_BOOT]
        assert event["event_type"] == "activation.overlay_journal_retiring"
        assert (event["phase"], event["grant_phase"]) == ("closed", "recovery_required")
        assert event["recovery_reason"] == UNRECORDED_MANAGER_STOP
        assert event["supervision_failure"] == failure
        assert (event["boot_id"], event["current_boot_id"]) == (OLD_BOOT, NEW_BOOT)


def test_closed_grant_event_has_no_recovery_reason(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        manager, _ = _manager(env, {OLD_BOOT: _grant_for(closed)})
        seen = []
        manager._retirement_record = lambda event: seen.append(event) or True
        manager._retire_prior_boot_journal(env["store"], env["guard"])
        (event,) = seen
        assert "recovery_reason" not in event and "supervision_failure" not in event


def _refused(env, grant, closed):
    manager, _ = _manager(env, {OLD_BOOT: grant})
    calls = _spy_writes(env)
    with pytest.raises(ApprovalRefused):
        manager._retire_prior_boot_journal(env["store"], env["guard"])
    assert calls == [] and manager.records == []
    assert env["store"].load() == closed
    assert _entries(env) == ["overlay-journal.json"]


@pytest.mark.parametrize("case", [
    "generic-v1", "generic-v1-unit", "arbitrary", "other-failure-name",
    "label-of-other-grant", "label-of-other-context", "label-of-other-receipt",
    "label-of-other-approval",
])
def test_closed_journal_with_other_recovery_evidence_still_refuses(tmp_path, case):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        grant = _labelled(closed)
        other = {
            "generic-v1": _generic(grant),
            "generic-v1-unit": _generic(grant, "UnitOperationFailed"),
            "arbitrary": "sha256:" + "a" * 64,
            "other-failure-name": _label(grant, "RuntimeError"),
            "label-of-other-grant": _label(replace(grant, grant_id="1" * 32),
                                           "UnitOperationFailed"),
            "label-of-other-context": _label(replace(
                grant, context_digest="sha256:" + "9" * 64), "UnitOperationFailed"),
            "label-of-other-receipt": _label(replace(
                grant, audit_receipt_digest="sha256:" + "8" * 64), "UnitOperationFailed"),
            "label-of-other-approval": _label(replace(
                grant, approval_digest="sha256:" + "7" * 64), "UnitOperationFailed"),
        }[case]
        _refused(env, replace(grant, recovery_evidence_digest=other), closed)


@pytest.mark.parametrize("case", ["grant_id", "context", "payload", "boot"])
def test_labelled_grant_with_mismatched_identity_refuses(tmp_path, case):
    """The label is self-consistent, but the grant is not this journal's grant."""
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        identity = {
            "grant_id": {"grant_id": "1" * 32},
            "context": {"context_digest": "sha256:" + "9" * 64},
            "payload": {"unit_payload_digests": tuple(
                (unit, "0" * 64) for unit, _ in closed.intent.payload_digests)},
            "boot": {"boot_id": NEW_BOOT},
        }[case]
        grant = _labelled(closed, **identity)
        assert unrecorded_manager_stop_failure(grant) == "UnitOperationFailed"
        _refused(env, grant, closed)


def test_same_boot_labelled_journal_is_never_retired(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        closed = _stage(env, "closed")
        manager, grants = _manager(env, {OLD_BOOT: _labelled(closed)}, boot=OLD_BOOT)
        calls = _spy_writes(env)
        manager._retire_prior_boot_journal(env["store"], env["guard"])
        assert calls == [] and grants.loads == [] and manager.records == []
        assert env["store"].load() == closed


@pytest.mark.parametrize("phase", ["published", "closing", "withdrawing"])
def test_label_does_not_change_abandoned_journal_handling(tmp_path, phase):
    """Unfenced abandoned journals still refuse; fenced ones carry no reason."""
    with _withdraw_environment(tmp_path) as env:
        journal = _stage(env, phase)
        manager, _ = _manager(env, {OLD_BOOT: _labelled(journal)})
        calls = _spy_writes(env)
        with pytest.raises(Exception):
            manager._retire_prior_boot_journal(env["store"], env["guard"])
        assert calls == [] and env["store"].load() == journal
        _fenced(manager)
        manager._retire_prior_boot_journal(env["store"], env["guard"])
        (event,) = manager.records
        assert event["grant_phase"] == "recovery_required"
        assert "recovery_reason" not in event
