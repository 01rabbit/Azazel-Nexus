"""Operator-stop Option C: a missing stopping record is accepted only with proof."""

# ruff: noqa: F811 - the imported ``evidence`` fixture is used by parameter name.

from hashlib import sha256
import json

import pytest

from azazel_nexus.audit import AuditUnavailable
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.bootstrap import BootstrapContainmentFailed
from azazel_nexus_runtime.bootstrap_audit import AuditObservation
from azazel_nexus_runtime.units import UnitKey
from azazel_nexus_runtime.bootstrap import _receipt_digest

from test_runtime_bootstrap import Harness, RecordingManager, evidence  # noqa: F401,F811


class StopObservingManager(RecordingManager):
    def __init__(self, observed=True, **kwargs):
        super().__init__(**kwargs)
        self.observed = observed
        self.observe_calls = 0
        self.observe_error = None

    def controller_stop_observed(self):
        self.observe_calls += 1
        if self.observe_error is not None:
            raise self.observe_error
        return self.observed


TIP_DIGEST = "c" * 64


def _harness(evidence, manager=None, *, tip=None):
    """Harness whose stopped-writer continuation reports an on-disk tip.

    ``tip(head)`` maps the last verified live head to the post-containment
    observation (default: extends it by one record).
    """
    holder = {}

    def continuation(_context, previous):
        h = holder["h"]
        if h.supervisor._live_audit is None:
            return previous
        head = h.supervisor._audit_head
        if tip is not None:
            return tip(head)
        return AuditObservation(head.sequence + 1, TIP_DIGEST, 1, 200)

    h = Harness(
        evidence,
        manager=manager if manager is not None else StopObservingManager(True),
        audit_continuation=continuation,
    )
    holder["h"] = h
    return h


def _fail_stopping(h, error=None, before=None):
    original = h.record
    error = AuditUnavailable("auditd unavailable") if error is None else error

    def record(event):
        if event["event_type"] == "bootstrap.stopping":
            h.events.append(event)
            if before is not None:
                before()
            raise error
        return original(event)

    h.supervisor.record = record
    return original


def _event_types(h):
    return [e["event_type"] for e in h.events]


def _capture_contain(h):
    contained = []
    real = h.supervisor._contain

    def contain():
        contained.append(real())
        return contained[-1]

    h.supervisor._contain = contain
    return contained


def _v2_digest(h, containment, post):
    journal = h.grant_journal
    head = h.supervisor._audit_head
    receipt = h.supervisor._last_receipt
    raw = json.dumps(
        {
            "schema": "azazel-nexus/bootstrap-close-evidence/v2",
            "stopping_record": "absent-manager-stop",
            "boot_id": journal.boot_id,
            "grant_id": journal.grant_id,
            "last_head_sequence": head.sequence,
            "last_head_digest": head.digest,
            "last_receipt": _receipt_digest(receipt),
            "post_containment_sequence": post.sequence,
            "post_containment_digest": post.digest,
            "containment": containment,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return "sha256:" + sha256(raw).hexdigest()


def _run_waived(evidence, tip_digest=TIP_DIGEST):
    h = _harness(
        evidence,
        tip=lambda head: AuditObservation(head.sequence + 1, tip_digest, 1, 200),
    )
    _fail_stopping(h)
    contained = _capture_contain(h)
    result = h.supervisor.run()
    head = h.supervisor._audit_head
    post = AuditObservation(head.sequence + 1, tip_digest, 1, 200)
    return h, result, _v2_digest(h, contained[-1], post)


def test_manager_stop_after_helpers_closes_with_v2_digest(evidence):
    h, result, expected = _run_waived(evidence)
    assert result.state == "stopped"
    assert result.stopping_record == "absent-manager-stop"
    assert h.manager.observe_calls == 1
    journal = h.grant_journal
    assert journal.phase == "closed"
    assert journal.close_evidence_digest == expected
    assert "bootstrap.stopped" not in _event_types(h)
    assert all(h.manager.inactive.values()) and all(h.manager.masked.values())
    assert not any(t == ("store.advance", "recovery_required") for t in h.timeline)


def test_digest_binds_post_containment_tip(evidence):
    h1, _, expected1 = _run_waived(evidence, "c" * 64)
    h2, _, expected2 = _run_waived(evidence, "d" * 64)
    assert h1.grant_journal.close_evidence_digest == expected1
    assert h2.grant_journal.close_evidence_digest == expected2
    # Same recomputation recipe, different tip: the digests must differ even
    # though the random grant ids differ, so also re-derive with swapped tips.
    head = h1.supervisor._audit_head
    swapped = _v2_digest(
        h1, "sha256:" + "0" * 64, AuditObservation(head.sequence + 1, "d" * 64, 1, 200)
    )
    other = _v2_digest(
        h1, "sha256:" + "0" * 64, AuditObservation(head.sequence + 1, "c" * 64, 1, 200)
    )
    assert swapped != other


@pytest.mark.parametrize("defect", [
    "behind", "same-seq-other-digest", "raises", "wrong-type", "no-stopped-head",
])
def test_broken_chain_after_containment_is_recovery_required(evidence, defect):
    def tip(head):
        if defect == "behind":
            return AuditObservation(1, "a" * 64, 1, 100)
        if defect == "same-seq-other-digest":
            return AuditObservation(head.sequence, "e" * 64, 1, 100)
        if defect == "raises":
            raise ApprovalRefused("chain broken")
        return None

    h = _harness(evidence, tip=tip)
    if defect == "no-stopped-head":
        h = _harness(evidence)
        _fail_stopping(
            h, before=lambda: setattr(h.supervisor, "_stopped_audit_head", None)
        )
    else:
        _fail_stopping(h)
    with pytest.raises(ApprovalRefused, match="not fully recorded"):
        h.supervisor.run()
    assert h.grant_journal.phase == "recovery_required"


def test_readiness_lost_during_stop_window_closes_when_proof_holds(evidence):
    manager = StopObservingManager(True)
    h = _harness(evidence, manager)
    _fail_stopping(h)

    def wait(seconds):
        h.waits.append(seconds)
        manager.ready = False  # helper stopped by systemd; SIGTERM not yet delivered

    h.supervisor.wait = wait
    result = h.supervisor.run()
    assert result.stopping_record == "absent-manager-stop"
    assert h.grant_journal.phase == "closed"
    assert "bootstrap.stopped" not in _event_types(h)


def test_readiness_lost_without_stop_observation_is_not_swallowed(evidence):
    manager = StopObservingManager(False)
    h = _harness(evidence, manager)
    _fail_stopping(h)

    def wait(seconds):
        h.waits.append(seconds)
        manager.ready = False

    h.supervisor.wait = wait
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()
    assert h.grant_journal.phase == "recovery_required"


def test_no_stop_observed_keeps_recovery_required(evidence):
    h = _harness(evidence, StopObservingManager(False))
    _fail_stopping(h)
    with pytest.raises(ApprovalRefused, match="not fully recorded"):
        h.supervisor.run()
    assert h.grant_journal.phase == "recovery_required"


@pytest.mark.parametrize("kind", ["missing", "raises", "non-bool"])
def test_unreadable_stop_observation_fails_closed(evidence, kind):
    if kind == "missing":
        manager = RecordingManager()
    else:
        manager = StopObservingManager(True)
        if kind == "raises":
            manager.observe_error = RuntimeError("bus error")
        else:
            manager.controller_stop_observed = lambda: 1
    h = _harness(evidence, manager)
    _fail_stopping(h)
    with pytest.raises(ApprovalRefused, match="not fully recorded"):
        h.supervisor.run()
    assert h.grant_journal.phase == "recovery_required"


def test_containment_failure_with_observed_stop_is_recovery_required(evidence):
    manager = StopObservingManager(True)
    manager.stop_failure_after_open = True
    h = _harness(evidence, manager)
    _fail_stopping(h)
    with pytest.raises(BootstrapContainmentFailed):
        h.supervisor.run()
    assert h.grant_journal.phase == "recovery_required"


def test_helper_still_active_at_confirm_is_containment_failure(evidence):
    manager = StopObservingManager(True)
    manager.inactive_false_after_open.add(UnitKey.AUDITD)
    h = _harness(evidence, manager)
    _fail_stopping(h)
    with pytest.raises(BootstrapContainmentFailed):
        h.supervisor.run()
    assert h.grant_journal.phase == "recovery_required"


def test_non_audit_unavailable_error_is_not_waived(evidence):
    h = _harness(evidence)
    _fail_stopping(h, RuntimeError("other"))
    with pytest.raises(ApprovalRefused, match="not fully recorded"):
        h.supervisor.run()
    assert h.grant_journal.phase == "recovery_required"


def test_stop_before_first_record_is_ordinary_close(evidence):
    h = _harness(evidence)
    h.stop = True
    result = h.supervisor.run()  # nothing live: no stopping record attempted
    assert result.stopping_record == "recorded"


@pytest.mark.parametrize("attr", ["_last_receipt", "_audit_head"])
def test_missing_head_or_receipt_makes_waiver_ineligible(evidence, attr):
    h = _harness(evidence)
    _fail_stopping(h, before=lambda: setattr(h.supervisor, attr, None))
    with pytest.raises(ApprovalRefused, match="not fully recorded"):
        h.supervisor.run()
    assert h.grant_journal.phase == "recovery_required"
    assert "bootstrap.stopped" not in _event_types(h)


@pytest.mark.parametrize("cause", [
    ApprovalRefused("bootstrap deadline expired"),
    RuntimeError("boom"),
])
def test_other_supervision_failure_with_stop_observed_stays_recovery(evidence, cause):
    h = _harness(evidence)
    _fail_stopping(h)

    def wait(seconds):
        h.waits.append(seconds)
        raise cause

    h.supervisor.wait = wait
    with pytest.raises(ApprovalRefused, match="not fully recorded"):
        h.supervisor.run()
    assert h.grant_journal.phase == "recovery_required"


def test_final_closed_advance_failure_is_recovery_required(evidence):
    h = _harness(evidence)
    _fail_stopping(h)
    store = h.grant_store
    original = store.advance

    def advance(expected, action, *, evidence_digest=None):
        if action == "closed":
            raise ApprovalRefused("store down")
        return original(expected, action, evidence_digest=evidence_digest)

    store.advance = advance
    with pytest.raises(ApprovalRefused, match="store down"):
        h.supervisor.run()
    assert h.grant_journal.phase == "recovery_required"


def test_stopping_record_state_is_constrained():
    from azazel_nexus_runtime.bootstrap import BootstrapResult

    BootstrapResult(stopping_record="absent-manager-stop")
    with pytest.raises(ValueError):
        BootstrapResult(stopping_record="whatever")


def test_close_error_is_not_waived(evidence):
    h = _harness(evidence)
    _fail_stopping(h)
    store = h.grant_store
    original = store.advance

    def advance(expected, action, *, evidence_digest=None):
        if action == "closing":
            raise ApprovalRefused("store down")
        return original(expected, action, evidence_digest=evidence_digest)

    store.advance = advance
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()
    assert h.grant_journal.phase != "closed"


def test_sigterm_clean_path_unchanged(evidence):
    manager = StopObservingManager(True)
    h = _harness(evidence, manager)
    result = h.supervisor.run()
    assert result.stopping_record == "recorded"
    assert h.events[-1]["event_type"] == "bootstrap.stopping"
    assert manager.observe_calls == 0
    assert h.grant_journal.phase == "closed"
    assert "bootstrap.stopped" not in _event_types(h)


@pytest.mark.parametrize("stopping,text", [
    ("absent-manager-stop",
     "stopped by manager after helpers; stopping record unavailable"),
    ("recorded", "stopped after confirmed containment"),
])
def test_activated_prints_distinct_message_for_manager_stop(monkeypatch, capsys, stopping, text, private_os):
    from pathlib import Path

    from azazel_nexus import bootstrap_selection_optional as selection_store
    from azazel_nexus_runtime import activated, bootstrap_entrypoint, runtime_paths
    private_os(activated)
    from azazel_nexus_runtime.bootstrap import BootstrapResult

    monkeypatch.setattr(activated.os, "geteuid", lambda: 0)
    monkeypatch.setenv("INVOCATION_ID", "a" * 32)
    monkeypatch.setattr(runtime_paths, "ROOT", Path("/"))
    monkeypatch.setattr(Path, "is_dir", lambda path: path == Path("/run/systemd/system"))
    monkeypatch.setattr(selection_store, "load_optional_bootstrap_selection", lambda: object())
    monkeypatch.setattr(
        bootstrap_entrypoint, "run_selected_bootstrap",
        lambda _selected, *, narrow: BootstrapResult(stopping_record=stopping),
    )
    assert activated.main([]) == 0
    assert text in capsys.readouterr().out
