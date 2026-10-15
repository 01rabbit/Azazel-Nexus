"""Controller transaction tests using only injected in-memory dependencies."""

from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import os
import json

import pytest
from nacl.signing import SigningKey

from azazel_nexus.bootstrap_approval import (
    BootstrapApprovalPolicy,
    BootstrapContext,
    bootstrap_payload,
    verify_bootstrap_approval,
)
from azazel_nexus.bootstrap_deadline import begin_deadline
from azazel_nexus.bootstrap_generation import VerifiedBootstrapGeneration
from azazel_nexus.bootstrap_grant_store import GrantTransactionStore
from azazel_nexus.bootstrap_grant_transaction import GrantTransaction, advance_transaction
from azazel_nexus.bootstrap_lock import _transaction_at
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
    approval_message,
)
from azazel_nexus_runtime.bootstrap_audit import AuditObservation
from azazel_nexus_runtime.bootstrap import (
    BootstrapContainmentFailed,
    BootstrapSupervisor,
)
from azazel_nexus_runtime.bootstrap_audit_client import AuditAppendReceipt
from azazel_nexus_runtime.units import UnitKey

NS = 1_000_000_000
START = "2026-10-13T00:00:00Z"
DIGEST = "sha256:" + "a" * 64


def _owned_grant_transaction():
    return GrantTransaction(
        boot_id="11111111-1111-1111-1111-111111111111",
        context_digest=DIGEST,
        approval_digest=DIGEST,
        generation=1,
        generation_digest=DIGEST,
        grant_id="0123456789abcdef0123456789abcdef",
        unit_payload_digests=(
            ("azazel-auditd.service", "a" * 64),
            ("azazel-commissiond.service", "b" * 64),
        ),
        phase="pair_grant_opened",
    )


@pytest.fixture
def evidence(request):
    start, expires = getattr(request, "param", (START, "2026-10-13T00:05:00Z"))
    key = SigningKey.generate()
    policy = BootstrapApprovalPolicy(frozenset({"operator-a"}), 300)
    context = BootstrapContext(
        approval_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        node_digest=DIGEST,
        boot_id="11111111-1111-1111-1111-111111111111",
        generation=1,
        generation_digest=DIGEST,
        package_digest=DIGEST,
        unit_closure_digest=DIGEST,
        policy_digest=DIGEST,
        approval_policy_digest=policy.digest(),
        security_epoch=7,
        revocation_digest=DIGEST,
    )
    payload = bootstrap_payload(
        context=context,
        operator="operator-a",
        granted_at=start,
        expires_at=expires,
    )
    signature = key.sign(
        approval_message(ApprovalPurpose.SUPPORTING_BOOTSTRAP, payload)
    ).signature
    approval = verify_bootstrap_approval(
        trust=OperatorTrust({"operator-a": bytes(key.verify_key)}),
        expected=context,
        policy=policy,
        operator="operator-a",
        payload=payload,
        signature=signature,
        now=start,
    )
    deadline = begin_deadline(
        approval,
        boot_id=context.boot_id,
        now=start,
        boottime_ns=100 * NS,
        clock_trusted=True,
    )
    generation = VerifiedBootstrapGeneration(1, DIGEST, START)
    return deadline, generation


class RecordingManager:
    def __init__(self, *, fail=(), inactive=None, ready=True):
        self.calls = []
        self.fail = set(fail)
        self.inactive = {unit: True for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND)}
        self.masked = {unit: True for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND)}
        self.mask_observation = {}
        self.inactive_observation = {}
        self.inactive_observation_sequence = {}
        self.inactive_false_after_open = set()
        if inactive:
            self.inactive.update(inactive)
        self.ready = ready
        self.close_starts_result = None
        self.close_starts_error = None
        self.open_pair_result = None
        self.open_pair_error = None
        self.open_pair_before_publish = None
        self.open_pair_after_publish = None
        self.withdraw_pair_result = None
        self.withdraw_pair_error = None
        self.confirm_empty_pair_result = None
        self.confirm_empty_pair_error = None
        self.confirm_empty_pair_results = []
        self.confirm_empty_pair_errors = []
        self.pair_open = False
        self.stop_result = None
        self.stop_failure_after_open = False

    def open_pair(self, transaction, *, approval, check_publish):
        self.calls.append(("open_pair", transaction))
        assert approval is not None
        if self.open_pair_before_publish is not None:
            self.open_pair_before_publish(transaction, approval)
        assert check_publish() is None
        # Model even a partial/uncertain grant: cleanup must explicitly withdraw it.
        self.pair_open = True
        for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND):
            self.masked[unit] = False
        if self.open_pair_error is not None:
            raise self.open_pair_error
        if self.open_pair_after_publish is not None:
            self.open_pair_after_publish(transaction, approval)
        return self.open_pair_result

    def withdraw_pair(self, transaction):
        self.calls.append(("withdraw_pair", transaction))
        if not self.pair_open:
            return None
        if self.withdraw_pair_error is not None:
            raise self.withdraw_pair_error
        if self.withdraw_pair_result is not None:
            return self.withdraw_pair_result
        self.pair_open = False
        return None

    def confirm_empty_pair(self):
        self.calls.append(("confirm_empty_pair", None))
        if self.confirm_empty_pair_errors:
            error = self.confirm_empty_pair_errors.pop(0)
            if error is not None:
                raise error
        elif self.confirm_empty_pair_error is not None:
            raise self.confirm_empty_pair_error
        if self.confirm_empty_pair_results:
            return self.confirm_empty_pair_results.pop(0)
        return self.confirm_empty_pair_result

    def close_starts(self):
        self.calls.append(("close_starts", None))
        if self.close_starts_error is not None:
            raise self.close_starts_error
        return self.close_starts_result

    def _call(self, op, unit):
        self.calls.append((op, unit))
        if (op, unit) in self.fail:
            raise RuntimeError(f"{op} failed")
        if (
            op == "stop_and_wait"
            and self.pair_open
            and self.stop_failure_after_open
        ):
            raise RuntimeError("stop failed after grant")
        if op == "start_and_wait":
            self.inactive[unit] = False
        elif op == "stop_and_wait":
            self.inactive[unit] = True
        elif op == "mask":
            self.masked[unit] = True
        if op == "stop_and_wait" and self.pair_open:
            return self.stop_result

    def confirm_controller_ready(self, transaction, *, check_ready, notify):
        assert transaction.phase == "pair_grant_opened"
        assert check_ready() is None
        assert notify() is None
        assert check_ready() is None

    def start_and_wait(self, unit, *, transaction, check_start):
        assert transaction.phase == (
            "auditd_start_intent" if unit is UnitKey.AUDITD else "commissiond_start_intent"
        )
        assert check_start() is None
        self._call("start_and_wait", unit)

    def stop_and_wait(self, unit):
        return self._call("stop_and_wait", unit)

    def mask(self, unit):
        self._call("mask", unit)

    def is_inactive(self, unit):
        self.calls.append(("is_inactive", unit))
        if self.pair_open and unit in self.inactive_false_after_open:
            return False
        sequence = self.inactive_observation_sequence.get(unit)
        if sequence:
            return sequence.pop(0)
        return self.inactive_observation.get(unit, self.inactive[unit])

    def is_masked(self, unit):
        self.calls.append(("is_masked", unit))
        return self.mask_observation.get(unit, self.masked[unit])

    def is_ready(self, unit):
        self.calls.append(("is_ready", unit))
        return self.ready


class RecordingDeadlineGuard:
    def __init__(self, timeline):
        self.timeline = timeline
        self.deadlines = []
        self.releases = 0

    def __call__(self, deadline):
        self.deadlines.append(deadline)
        self.timeline.append(("deadline_guard", deadline))

    def release_after_stop(self):
        self.releases += 1
        self.timeline.append(("deadline_release", None))


class Harness:
    def __init__(self, evidence, **options):
        self.deadline, self.generation = evidence
        self.manager = options.pop("manager", RecordingManager())
        self.events = []
        self.waits = []
        self.narrowed = []
        self.stop = False
        self.refresh_value = self.deadline
        self.refresh_error = None
        self.admit_error = None
        self.record_error = None
        self.lock_error = None
        self.clock = options.pop("clock", lambda: 100 * NS)
        self._lock_depth = 0
        self.grant_journal = None
        self.timeline = []
        self.deadline_guard = options.pop(
            "deadline_guard", RecordingDeadlineGuard(self.timeline),
        )
        self.load_optional_hook = None

        class Store:
            def __init__(inner):
                inner.journal = None

            def create(inner, journal):
                assert inner.journal is None
                inner.journal = journal
                self.grant_journal = journal
                self.timeline.append(("store.create", journal.phase))

            def load_optional(inner, *, boot_id):
                assert boot_id == self.deadline.approval.context.boot_id
                self.timeline.append(("store.load_optional", boot_id))
                observed = inner.journal
                if self.load_optional_hook is not None and observed is not None:
                    hook = self.load_optional_hook
                    self.load_optional_hook = None
                    hook(observed)
                return observed

            def advance(inner, expected, action, *, evidence_digest=None):
                assert inner.journal == expected
                updated = advance_transaction(
                    expected, action, evidence_digest=evidence_digest
                )
                inner.journal = updated
                self.grant_journal = updated
                self.timeline.append(("store.advance", updated.phase))
                return updated

        self.grant_store = Store()

        @contextmanager
        def grant_store_factory(_guard):
            yield self.grant_store

        class HeadReader:
            def observe_head(inner):
                if not self.events:
                    return 1, "a" * 64
                return (
                    len(self.events) + 1,
                    sha256(repr(self.events[-1]).encode()).hexdigest(),
                )

        self.supervisor = BootstrapSupervisor(
            manager=self.manager,
            refresh=self.refresh,
            admit_generation=self.admit,
            deadline_guard=self.deadline_guard,
            record=self.record,
            controller_ready=lambda: None,
            controller_watchdog=options.pop("controller_watchdog", lambda: None),
            transaction=self.transaction,
            emergency_narrow=lambda: self.narrowed.append(True),
            stopped=lambda: self.stop,
            wait=self.wait,
            poll_seconds=2.0,
            boottime_ns=self.clock,
            prestart=options.pop("prestart", lambda _context: AuditObservation(1, "a" * 64, 1, 100)),
            audit_continuation=options.pop("audit_continuation", lambda _context, previous: previous),
            audit_head_reader=options.pop("audit_head_reader", HeadReader()),
            grant_store_factory=options.pop("grant_store_factory", grant_store_factory),
            boot_id_reader=options.pop(
                "boot_id_reader", lambda: self.deadline.approval.context.boot_id
            ),
            initial_admission=options.pop("initial_admission", None),
        )

    def refresh(self):
        if self.refresh_error:
            raise self.refresh_error
        return self.refresh_value

    def admit(self, context):
        self.timeline.append(("admit_generation", context))
        if self.admit_error:
            raise self.admit_error
        return self.generation

    def record(self, event):
        self.events.append(event)
        self.timeline.append((event["event_type"], event.get("unit_key")))
        if self.record_error:
            raise self.record_error
        return AuditAppendReceipt(
            len(self.events) + 1, sha256(repr(event).encode()).hexdigest()
        )

    def wait(self, seconds):
        self.waits.append(seconds)
        self.stop = True

    @contextmanager
    def transaction(self):
        if self.lock_error:
            raise self.lock_error
        self._lock_depth += 1
        try:
            yield lambda: None
        finally:
            self._lock_depth -= 1


def test_default_prestart_runs_once_under_lock_before_audit_records_and_widening(evidence, monkeypatch):
    from azazel_nexus_runtime import bootstrap

    h = Harness(evidence, prestart=None)
    calls = []

    def inspect(*, expected, manager):
        assert expected == h.deadline.approval.context
        assert manager is h.manager
        assert h._lock_depth == 1
        assert not h.events
        assert not any(op in {"open_pair", "start_and_wait"} for op, _ in h.manager.calls)
        calls.append(expected)
        return AuditObservation(1, "a" * 64, 1, 100)

    monkeypatch.setattr(bootstrap, "inspect_bootstrap_prestart", inspect)
    assert h.supervisor.run().state == "stopped"
    assert len(calls) == 1
    assert h.waits  # Periodic checks occurred without repeating stopped-writer preflight.


@pytest.mark.parametrize("result", [None, True, {}])
def test_invalid_prestart_result_never_releases_controller_or_helpers(evidence, result):
    h = Harness(evidence, prestart=lambda _: result)
    h.supervisor.controller_ready = lambda: pytest.fail("controller barrier released")
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()
    assert not any(op in {"open_pair", "start_and_wait"} for op, _ in h.manager.calls)


def test_default_continuation_advances_only_verified_head(evidence, monkeypatch):
    from azazel_nexus_runtime import bootstrap

    observed = []

    def continuing(*, expected, previous):
        observed.append(previous.sequence)
        return AuditObservation(previous.sequence + 1, "b" * 64, 1, 200)

    monkeypatch.setattr(bootstrap, "check_bootstrap_audit_extension", continuing)
    h = Harness(evidence, audit_continuation=None)
    assert h.supervisor.run().state == "stopped"
    assert observed == list(range(1, len(observed) + 1))
    assert len(observed) > 2


def test_continuation_failure_after_start_contains_helpers_without_advancing_head(evidence):
    h = Harness(evidence)

    class Reader:
        calls = 0

        def observe_head(self):
            self.calls += 1
            if self.calls > 1:
                raise OSError("audit writer head unavailable")
            return 1, "a" * 64

    h.supervisor.audit_head_reader = Reader()
    with pytest.raises(ApprovalRefused, match="audit live head"):
        h.supervisor.run()
    assert h.supervisor._audit_head.sequence == 1
    assert all(h.manager.is_masked(unit) and h.manager.is_inactive(unit)
               for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND))


def test_audit_intent_precedes_commission_and_scope_is_exact_pair(evidence):
    h = Harness(evidence)
    result = h.supervisor.run()
    assert result.state == "stopped"
    starts = [unit for op, unit in h.manager.calls if op == "start_and_wait"]
    assert starts == [UnitKey.AUDITD, UnitKey.COMMISSIOND]
    commission_start = h.manager.calls.index(("start_and_wait", UnitKey.COMMISSIOND))
    assert any(
        e["event_type"] == "bootstrap.ready" and e["unit_key"] == "auditd"
        for e in h.events[:]
    )
    assert h.events[0]["event_type"] == "bootstrap.grant_intent"
    assert h.events[1]["event_type"] == "bootstrap.controller_ready_intent"
    audit_ready = next(
        i
        for i, event in enumerate(h.events)
        if event["event_type"] == "bootstrap.ready" and event["unit_key"] == "auditd"
    )
    commission_intent = next(
        i
        for i, event in enumerate(h.events)
        if event["event_type"] == "bootstrap.start_intent"
        and event["unit_key"] == "commissiond"
    )
    assert audit_ready < commission_intent
    for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND):
        assert ("stop_and_wait", unit) in h.manager.calls
        assert h.manager.calls.count(("mask", unit)) >= 2
        assert ("is_masked", unit) in h.manager.calls
    assert all(
        unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND)
        for _, unit in h.manager.calls
        if isinstance(unit, UnitKey)
    )
    assert commission_start > h.manager.calls.index(("start_and_wait", UnitKey.AUDITD))


@pytest.mark.parametrize("failure", ["refusal", "exception"])
def test_admission_failure_contains_pair(failure, evidence):
    h = Harness(evidence)
    if failure == "refusal":
        h.admit_error = ApprovalRefused("ordinary generation admission refused")
        expected = ApprovalRefused
    else:
        h.refresh_error = RuntimeError("refresh exploded")
        expected = RuntimeError
    with pytest.raises(expected):
        h.supervisor.run()
    assert h.manager.calls.count(("mask", UnitKey.AUDITD)) >= 2
    assert h.manager.calls.count(("mask", UnitKey.COMMISSIOND)) >= 2
    assert h.manager.inactive == {UnitKey.AUDITD: True, UnitKey.COMMISSIOND: True}


@pytest.mark.parametrize("failure", ["open", "start", "readiness", "audit"])
def test_partial_transaction_failures_always_stop_and_remask(failure, evidence):
    manager = RecordingManager()
    h = Harness(evidence, manager=manager)
    if failure == "open":
        manager.open_pair_error = RuntimeError("pair grant failed")
    if failure == "start":
        manager.fail.add(("start_and_wait", UnitKey.AUDITD))
    if failure == "readiness":
        manager.ready = False
    if failure == "audit":
        h.record_error = OSError("audit unavailable")
    with pytest.raises((ApprovalRefused, OSError, RuntimeError)):
        h.supervisor.run()
    assert ("stop_and_wait", UnitKey.COMMISSIOND) in manager.calls
    assert ("stop_and_wait", UnitKey.AUDITD) in manager.calls
    assert manager.calls.count(("mask", UnitKey.AUDITD)) >= 2
    assert manager.calls.count(("mask", UnitKey.COMMISSIOND)) >= 2


@pytest.mark.parametrize("failure", ["exception", "non-none"])
def test_pair_open_failure_is_withdrawn_during_cleanup(failure, evidence):
    manager = RecordingManager()
    h = Harness(evidence, manager=manager)
    if failure == "exception":
        manager.open_pair_error = RuntimeError("pair open uncertain")
        expected = RuntimeError
    else:
        manager.open_pair_result = False
        expected = ApprovalRefused

    with pytest.raises(expected):
        h.supervisor.run()

    assert sum(op == "open_pair" for op, _ in manager.calls) == 1
    assert sum(op == "withdraw_pair" for op, _ in manager.calls) >= 1
    assert not manager.pair_open
    for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND):
        assert ("mask", unit) in manager.calls
        assert ("stop_and_wait", unit) in manager.calls


@pytest.mark.parametrize("mutation", ["deleted", "tampered"])
def test_publication_checkpoint_rejects_changed_saved_grant_before_open(
    mutation, evidence,
):
    h = Harness(evidence)
    manager = h.manager

    # Install a check wrapper that restores the protected fake after it has
    # returned the mutated/deleted snapshot to the checkpoint.
    def checked_open(transaction, *, approval, check_publish):
        original = h.grant_store.journal
        h.grant_store.journal = (
            None if mutation == "deleted"
            else replace(transaction, approval_digest="sha256:" + "b" * 64)
        )
        try:
            check_publish()
        except ApprovalRefused:
            h.grant_store.journal = original
            raise
        pytest.fail("mutated saved grant passed the publication checkpoint")

    manager.open_pair = checked_open
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()

    assert not manager.pair_open
    assert ("start_and_wait", UnitKey.AUDITD) not in manager.calls
    assert not any(
        op == "store.advance" and phase == "pair_grant_opened"
        for op, phase in h.timeline
    )


@pytest.mark.parametrize("mutation", ["cancel-during-open", "stale-generation", "approval-change"])
def test_publication_checkpoint_rechecks_live_inputs_before_open(mutation, evidence):
    h = Harness(evidence)

    def alter_before_publish(_transaction, _approval):
        if mutation == "cancel-during-open":
            h.stop = True
        elif mutation == "stale-generation":
            h.generation = VerifiedBootstrapGeneration(2, "sha256:" + "b" * 64, START)
        else:
            context = replace(
                h.deadline.approval.context,
                revocation_digest="sha256:" + "b" * 64,
            )
            approval = replace(h.deadline.approval, context=context)
            h.refresh_value = replace(h.deadline, approval=approval)

    h.manager.open_pair_before_publish = alter_before_publish
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()

    assert not h.manager.pair_open
    assert not any(
        op == "store.advance" and phase == "pair_grant_opened"
        for op, phase in h.timeline
    )


@pytest.mark.parametrize("during_read", ["cancel", "expire"])
def test_publication_checkpoint_rechecks_after_matching_grant_read(
    during_read, evidence,
):
    h = Harness(evidence)

    def mutate_after_matching_read(transaction):
        assert transaction == h.supervisor._grant_transaction
        if during_read == "cancel":
            h.stop = True
        else:
            h.supervisor.boottime_ns = lambda: h.deadline.deadline_boottime_ns

    h.load_optional_hook = mutate_after_matching_read
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()

    assert not h.manager.pair_open
    assert not any(
        op == "store.advance" and phase == "pair_grant_opened"
        for op, phase in h.timeline
    )


def test_failed_postpublication_checkpoint_never_records_grant_opened(evidence):
    h = Harness(evidence)
    h.manager.open_pair_after_publish = lambda _transaction, _approval: setattr(
        h, "stop", True
    )

    with pytest.raises(ApprovalRefused):
        h.supervisor.run()

    assert not h.manager.pair_open
    assert not any(
        op == "store.advance" and phase == "pair_grant_opened"
        for op, phase in h.timeline
    )


@pytest.mark.parametrize("failure", ["stop-exception", "stop-non-none", "inactive"])
def test_pair_grant_retained_until_stops_are_confirmed(failure, evidence):
    manager = RecordingManager()
    h = Harness(evidence, manager=manager)
    if failure == "stop-exception":
        manager.stop_failure_after_open = True
    elif failure == "stop-non-none":
        manager.stop_result = False
    else:
        manager.inactive_false_after_open.add(UnitKey.COMMISSIOND)

    with pytest.raises(BootstrapContainmentFailed):
        h.supervisor.run()

    # The initial containment has no grant to withdraw. Once opened, retain it
    # if any stop result or inactive observation is unconfirmed.
    assert sum(op == "open_pair" for op, _ in manager.calls) == 1
    # No owned grant is withdrawn when its stop/inactive state is uncertain.
    assert not any(op == "withdraw_pair" for op, _ in manager.calls)
    assert manager.pair_open
    for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND):
        assert manager.calls.count(("mask", unit)) >= 2
        assert ("is_masked", unit) in manager.calls


@pytest.mark.parametrize("failure", ["exception", "non-none"])
def test_pair_grant_retained_when_cgroup_empty_check_fails(failure, evidence):
    manager = RecordingManager()
    h = Harness(evidence, manager=manager)
    manager.pair_open = True
    h.supervisor._grant_transaction = _owned_grant_transaction()
    if failure == "exception":
        manager.confirm_empty_pair_errors = [RuntimeError("cgroup not empty")]
    else:
        manager.confirm_empty_pair_results = [False]

    with pytest.raises(BootstrapContainmentFailed):
        h.supervisor._contain()

    assert manager.pair_open
    assert not any(op == "withdraw_pair" for op, _ in manager.calls)
    assert manager.calls.count(("confirm_empty_pair", None)) == 1
    assert len(h.narrowed) >= 1


@pytest.mark.parametrize("failure", ["exception", "non-none"])
def test_final_cgroup_recheck_failure_prevents_successful_containment(
    failure, evidence,
):
    manager = RecordingManager()
    manager.pair_open = True
    h = Harness(evidence, manager=manager)
    h.supervisor._grant_transaction = _owned_grant_transaction()
    manager.confirm_empty_pair_results = [
        None, False if failure == "non-none" else None
    ]
    if failure == "exception":
        manager.confirm_empty_pair_errors = [None, RuntimeError("final cgroup check failed")]
    with pytest.raises(BootstrapContainmentFailed):
        h.supervisor._contain()

    assert not manager.pair_open
    assert sum(op == "withdraw_pair" for op, _ in manager.calls) == 1
    assert manager.calls.count(("confirm_empty_pair", None)) == 2
    assert len(h.narrowed) >= 1


@pytest.mark.parametrize("failure", ["exception", "non-none"])
def test_pair_withdrawal_failure_remasks_and_reports_containment(failure, evidence):
    manager = RecordingManager()
    h = Harness(evidence, manager=manager)
    if failure == "exception":
        manager.withdraw_pair_error = RuntimeError("withdrawal uncertain")
    else:
        manager.withdraw_pair_result = False

    with pytest.raises(BootstrapContainmentFailed):
        h.supervisor.run()

    assert manager.pair_open
    withdrawals = [entry for entry in manager.calls if entry[0] == "withdraw_pair"]
    assert len(withdrawals) == 1
    assert withdrawals[0][1].grant_id == h.supervisor._grant_transaction.grant_id
    cleanup = manager.calls
    withdrawal = max(
        index for index, entry in enumerate(cleanup)
        if entry[0] == "withdraw_pair"
    )
    cleanup_fence = max(
        index for index, entry in enumerate(cleanup[:withdrawal])
        if entry == ("close_starts", None)
    )
    last_stop = max(
        index for index, entry in enumerate(cleanup)
        if entry[0] == "stop_and_wait"
    )
    pre_withdraw_masks = [
        index for index, entry in enumerate(cleanup)
        if index > cleanup_fence and index < withdrawal and entry[0] == "mask"
    ]
    assert len(pre_withdraw_masks) >= 2
    assert cleanup_fence < min(pre_withdraw_masks) < last_stop < withdrawal
    assert all(
        cleanup.index(("mask", unit), withdrawal) > withdrawal
        for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND)
    )
    assert last_stop < withdrawal
    cgroup_check = cleanup.index(("confirm_empty_pair", None), last_stop + 1)
    assert last_stop < cgroup_check < withdrawal
    for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND):
        assert any(
            entry == ("is_inactive", unit)
            for entry in cleanup[last_stop + 1 : withdrawal]
        )
        assert ("is_inactive", unit) in cleanup[withdrawal + 1 :]
        assert ("is_masked", unit) in cleanup[withdrawal + 1 :]
    assert len(h.narrowed) >= 1


def test_containment_digest_commits_to_v2_cgroup_empty_pair_evidence(evidence):
    h = Harness(evidence)

    observed = h.supervisor._contain()

    expected_evidence = json.dumps(
        {
            "schema": "azazel-nexus/bootstrap-containment-evidence/v2",
            "start_fence": "confirmed",
            "stopped": ["auditd", "commissiond"],
            "inactive": ["auditd", "commissiond"],
            "cgroup_empty_pair": ["auditd", "commissiond"],
            "masked_operations": ["auditd", "commissiond"],
            "masked_observations": ["auditd", "commissiond"],
            "grant_withdrawal": "not-owned",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    assert observed == "sha256:" + sha256(expected_evidence).hexdigest()
    assert ("confirm_empty_pair", None) in h.manager.calls


def test_missing_deadline_and_changed_deadline_refuse(evidence):
    h = Harness(evidence)
    h.refresh_value = None
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()
    h = Harness(evidence)
    h.refresh_value = replace(
        h.deadline,
        admitted_boottime_ns=101 * NS,
        deadline_boottime_ns=401 * NS,
        last_boottime_ns=101 * NS,
    )
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()


def test_kernel_deadline_guard_precedes_admission_and_widening(evidence):
    h = Harness(evidence)
    original_open_pair = h.manager.open_pair
    original_start = h.manager.start_and_wait
    original_ready = h.manager.confirm_controller_ready

    def open_pair(*args, **kwargs):
        h.timeline.append(("open_pair", None))
        return original_open_pair(*args, **kwargs)

    def start_and_wait(*args, **kwargs):
        h.timeline.append(("start_and_wait", None))
        return original_start(*args, **kwargs)

    def confirm_controller_ready(*args, **kwargs):
        h.timeline.append(("confirm_controller_ready", None))
        return original_ready(*args, **kwargs)

    h.manager.open_pair = open_pair
    h.manager.start_and_wait = start_and_wait
    h.manager.confirm_controller_ready = confirm_controller_ready
    h.supervisor.controller_ready = lambda: h.timeline.append(("controller_ready", None))
    h.supervisor.run()

    first_guard = next(i for i, event in enumerate(h.timeline)
                       if event[0] == "deadline_guard")
    first_admission = next(i for i, event in enumerate(h.timeline)
                           if event[0] == "admit_generation")
    for operation in (
        "open_pair", "confirm_controller_ready", "controller_ready", "start_and_wait",
    ):
        first_operation = next(
            i for i, event in enumerate(h.timeline) if event[0] == operation
        )
        assert first_guard < first_operation
    assert first_guard < first_admission
    assert h.deadline_guard.deadlines
    assert all(deadline == h.deadline for deadline in h.deadline_guard.deadlines)
    assert h.deadline_guard.releases == 1


def test_kernel_deadline_guard_requires_exact_none_before_admission(evidence):
    class UnconfirmedGuard(RecordingDeadlineGuard):
        def __call__(self, deadline):
            super().__call__(deadline)
            return True

    h = Harness(evidence)
    guard = UnconfirmedGuard(h.timeline)
    h.supervisor.deadline_guard = guard
    with pytest.raises(ApprovalRefused, match="kernel deadline unconfirmed"):
        h.supervisor.run()
    assert not any(event[0] == "admit_generation" for event in h.timeline)
    assert not any(call[0] == "open_pair" for call in h.manager.calls)
    assert guard.releases == 1


def test_kernel_guard_rejects_refresh_extension_before_rebinding(evidence):
    class ChangingDeadlineGuard(RecordingDeadlineGuard):
        def __init__(self, timeline, owner):
            super().__init__(timeline)
            self.owner = owner

        def __call__(self, deadline):
            super().__call__(deadline)
            if len(self.deadlines) == 1:
                self.owner.refresh_value = replace(
                    self.owner.deadline,
                    admitted_boottime_ns=101 * NS,
                    deadline_boottime_ns=401 * NS,
                    last_boottime_ns=101 * NS,
                )

    h = Harness(evidence)
    guard = ChangingDeadlineGuard(h.timeline, h)
    h.supervisor.deadline_guard = guard

    with pytest.raises(ApprovalRefused, match="cannot be renewed"):
        h.supervisor.run()

    assert guard.deadlines == [h.deadline]
    assert guard.releases == 1  # only after the failure path contained helpers


def test_kernel_guard_is_not_released_while_supervision_is_running(evidence):
    h = Harness(evidence)
    original_wait = h.wait

    def wait(seconds):
        assert h.deadline_guard.releases == 0
        original_wait(seconds)

    h.supervisor.wait = wait
    h.supervisor.run()
    assert h.deadline_guard.releases == 1


def test_kernel_deadline_guard_is_not_released_when_cleanup_fails(evidence):
    h = Harness(evidence)
    original_record = h.record

    def record(event):
        receipt = original_record(event)
        if event["event_type"] == "bootstrap.stopping":
            h.manager.stop_failure_after_open = True
        return receipt

    h.supervisor.record = record
    with pytest.raises(BootstrapContainmentFailed):
        h.supervisor.run()
    assert h.deadline_guard.deadlines
    assert h.deadline_guard.releases == 0


def test_initial_containment_block_does_not_arm_or_release_kernel_guard(evidence):
    h = Harness(evidence)
    h.manager.inactive_observation[UnitKey.AUDITD] = False

    with pytest.raises(BootstrapContainmentFailed):
        h.supervisor.run()

    assert h.deadline_guard.deadlines == []
    assert h.deadline_guard.releases == 0


def test_ordinary_generation_refusal_and_generation_mismatch_contain(evidence):
    h = Harness(evidence)
    h.admit_error = ApprovalRefused("ordinary generation admission refused")
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()
    h = Harness(evidence)
    h.generation = VerifiedBootstrapGeneration(2, DIGEST, START)
    with pytest.raises(ApprovalRefused, match="independently admitted"):
        h.supervisor.run()


@pytest.mark.parametrize("failed", ["mask", "stop", "inactive", "masked"])
def test_unconfirmed_containment_emergency_narrows_and_raises(failed, evidence):
    manager = RecordingManager()
    if failed == "mask":
        manager.fail.add(("mask", UnitKey.AUDITD))
    if failed == "stop":
        manager.fail.add(("stop_and_wait", UnitKey.AUDITD))
    if failed == "inactive":
        manager.inactive_observation[UnitKey.AUDITD] = False
    if failed == "masked":
        manager.mask_observation[UnitKey.AUDITD] = False
    h = Harness(evidence, manager=manager)
    with pytest.raises(BootstrapContainmentFailed):
        h.supervisor.run()
    assert len(h.narrowed) >= 1


@pytest.mark.parametrize("failure", ["missing", "exception", "non-none"])
def test_start_fence_failure_masks_but_never_stops_or_withdraws_pair(
    failure, evidence, monkeypatch,
):
    manager = RecordingManager()
    if failure == "missing":
        monkeypatch.delattr(RecordingManager, "close_starts")
    elif failure == "exception":
        manager.close_starts_error = RuntimeError("start fence failed")
    else:
        manager.close_starts_result = False
    h = Harness(evidence, manager=manager)

    with pytest.raises(BootstrapContainmentFailed):
        h.supervisor.run()

    for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND):
        assert ("mask", unit) in manager.calls
        assert ("stop_and_wait", unit) not in manager.calls
    assert not any(op == "withdraw_pair" for op, _ in manager.calls)
    assert len(h.narrowed) >= 1
    if failure != "missing":
        assert manager.calls[0] == ("close_starts", None)


def test_active_pair_is_left_running_when_start_fence_cannot_be_established(evidence):
    manager = RecordingManager()
    manager.close_starts_error = RuntimeError("start fence unavailable")
    manager.inactive_observation[UnitKey.AUDITD] = False
    h = Harness(evidence, manager=manager)

    with pytest.raises(BootstrapContainmentFailed):
        h.supervisor.run()

    assert all(op != "stop_and_wait" for op, _unit in manager.calls)
    assert all(op != "withdraw_pair" for op, _unit in manager.calls)
    assert all(op == "mask" or op == "close_starts" or op in {
        "is_inactive", "is_masked"
    } for op, _unit in manager.calls)
    assert len(h.narrowed) >= 1


def test_lock_failure_has_no_side_effects(evidence):
    h = Harness(evidence)
    h.lock_error = RuntimeError("lock unavailable")
    with pytest.raises(RuntimeError):
        h.supervisor.run()
    assert h.manager.calls == []
    assert h.events == []
    assert h.narrowed == []


def test_consumed_supervisor_cannot_restart(evidence):
    h = Harness(evidence)
    h.stop = True
    h.supervisor.run()
    before = list(h.manager.calls)
    with pytest.raises(ApprovalRefused, match="cannot restart"):
        h.supervisor.run()
    assert h.manager.calls == before
    assert not h.events


def test_controller_notification_follows_containment_admission_and_audit(evidence):
    h = Harness(evidence)
    observations = []

    def ready():
        assert h._lock_depth == 1
        assert h.supervisor._previous == h.deadline
        assert h.manager.pair_open
        assert all(h.manager.inactive.values())
        assert not h.events
        observations.append(True)

    h.supervisor.controller_ready = ready
    h.supervisor.run()
    assert observations == [True]
    assert [unit for op, unit in h.manager.calls if op == "start_and_wait"] == [
        UnitKey.AUDITD, UnitKey.COMMISSIOND
    ]


@pytest.mark.parametrize("failure", ["containment", "admission", "audit", "cancelled"])
def test_controller_never_notifies_before_prerequisites(evidence, failure):
    h = Harness(evidence)
    notified = []
    h.supervisor.controller_ready = lambda: notified.append(True)
    if failure == "containment":
        h.manager.inactive_observation[UnitKey.AUDITD] = False
    elif failure == "admission":
        h.admit_error = ApprovalRefused("not admitted")
    elif failure == "audit":
        h.record_error = RuntimeError("ledger unavailable")
    else:
        h.stop = True
    if failure == "cancelled":
        h.supervisor.run()
    else:
        with pytest.raises((BootstrapContainmentFailed, ApprovalRefused, RuntimeError)):
            h.supervisor.run()
    if failure == "audit":
        # The controller must notify systemd before its After= helpers can
        # start; the audit append is therefore post-notification. Failure
        # still closes the grant and contains both helpers.
        assert notified == [True]
        assert all(h.manager.inactive.values()) and all(h.manager.masked.values())
    else:
        assert notified == []
        assert not any(op == "open_pair" for op, _ in h.manager.calls)


@pytest.mark.parametrize("failure", ["send", "expiry", "cancelled"])
def test_controller_notification_failure_or_changed_inputs_prevent_widening(evidence, failure):
    h = Harness(evidence)

    def ready():
        if failure == "send":
            raise RuntimeError("notification failed")
        if failure == "expiry":
            h.refresh_error = ApprovalRefused("expired while notifying")
        else:
            h.stop = True

    h.supervisor.controller_ready = ready
    if failure == "cancelled":
        with pytest.raises(ApprovalRefused, match="controller READY cancelled"):
            h.supervisor.run()
    else:
        with pytest.raises((ApprovalRefused, RuntimeError)):
            h.supervisor.run()
    assert any(op == "open_pair" for op, _ in h.manager.calls)
    assert all(h.manager.masked.values()) and all(h.manager.inactive.values())
    assert h.manager.calls.count(("stop_and_wait", UnitKey.AUDITD)) == 2
    assert not any(op == "start_and_wait" for op, _ in h.manager.calls)


@pytest.mark.parametrize("at", ["before", "audit_ready", "poll"])
def test_cancellation_records_stopped_only_after_confirmed_cleanup(evidence, at):
    h = Harness(evidence)
    if at == "before":
        h.stop = True
    original = h.record

    def record(event):
        if event["event_type"] == "bootstrap.ready" and at == "audit_ready":
            h.stop = True
        return original(event)

    h.supervisor.record = record
    h.supervisor.run()
    if at == "before":
        assert not h.events
    else:
        assert h.events[-1]["event_type"] == "bootstrap.stopping"
    assert all(h.manager.inactive.values()) and all(h.manager.masked.values())
    starts = sum(op == "start_and_wait" for op, _ in h.manager.calls)
    assert starts == {"before": 0, "audit_ready": 1, "poll": 2}[at]


def test_poll_is_capped_at_watchdog_cadence_and_remaining_deadline(evidence):
    h = Harness(evidence)
    h.supervisor.poll_seconds = 500.0
    h.supervisor.boottime_ns = lambda: 100 * NS
    h.supervisor.run()
    assert h.waits == [10.0]


def test_elapsed_clock_high_water_rollback_refuses_and_contains(evidence):
    manager = RecordingManager()
    h = Harness(evidence, manager=manager)

    clock_calls = []

    def elapsed():
        clock_calls.append(None)
        return (101 if len(clock_calls) == 1 else 100) * NS

    h.supervisor.boottime_ns = elapsed
    with pytest.raises(ApprovalRefused, match="moved backward"):
        h.supervisor.run()
    assert ("stop_and_wait", UnitKey.AUDITD) in manager.calls
    assert ("mask", UnitKey.COMMISSIOND) in manager.calls


def test_intent_and_audit_readiness_precede_commission_start(evidence):
    h = Harness(evidence)
    timeline = h.timeline
    operation = h.manager._call

    def call(op, unit):
        assert h._lock_depth == 1
        timeline.append((op, unit.value))
        operation(op, unit)

    h.manager._call = call
    controller_ready = h.supervisor.controller_ready

    def notify_controller():
        timeline.append(("controller_ready", None))
        return controller_ready()

    h.supervisor.controller_ready = notify_controller
    open_pair = h.manager.open_pair

    def open_grant(transaction, *, approval, check_publish):
        assert transaction.phase == "pair_grant_intent"
        timeline.append(("open_pair", transaction.phase))
        return open_pair(
            transaction, approval=approval, check_publish=check_publish
        )

    h.manager.open_pair = open_grant
    def record(event):
        h.events.append(event)
        timeline.append((event["event_type"], event.get("unit_key")))
        return AuditAppendReceipt(
            len(h.events) + 1, sha256(repr(event).encode()).hexdigest()
        )

    h.supervisor.record = record
    h.supervisor.run()
    assert timeline.index(("store.advance", "pair_grant_intent")) < timeline.index(
        ("open_pair", "pair_grant_intent")
    )
    assert timeline.index(("store.advance", "pair_grant_opened")) < timeline.index(
        ("controller_ready", None)
    )
    assert timeline.index(("controller_ready", None)) < timeline.index(
        ("store.advance", "auditd_start_intent")
    )
    assert timeline.index(("store.advance", "auditd_start_intent")) < timeline.index(
        ("start_and_wait", "auditd")
    )
    assert timeline.index(("bootstrap.grant_intent", None)) < timeline.index(
        ("store.advance", "audit_intent_recorded")
    )
    assert timeline.index(("store.advance", "audit_intent_recorded")) < timeline.index(
        ("bootstrap.start_intent", "commissiond")
    )
    assert timeline.index(("bootstrap.ready", "auditd")) < timeline.index(
        ("bootstrap.start_intent", "commissiond")
    )
    assert timeline.index(("bootstrap.start_intent", "commissiond")) < timeline.index(
        ("start_and_wait", "commissiond")
    )
    grant_event = next(event for event in h.events
                       if event["event_type"] == "bootstrap.grant_intent")
    assert h.grant_journal.phase == "closed"
    grant_hash = sha256(repr(grant_event).encode()).hexdigest()
    expected_receipt = json.dumps(
        {
            "schema": "azazel-nexus/bootstrap-audit-receipt/v1",
            "sequence": h.events.index(grant_event) + 2,
            "event_hash": grant_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    assert h.grant_journal.audit_receipt_digest == (
        "sha256:" + sha256(expected_receipt).hexdigest()
    )
    assert h.grant_journal.close_evidence_digest.startswith("sha256:")
    containment_evidence = json.dumps(
        {
            "schema": "azazel-nexus/bootstrap-containment-evidence/v2",
            "start_fence": "confirmed",
            "stopped": ["auditd", "commissiond"],
            "inactive": ["auditd", "commissiond"],
            "cgroup_empty_pair": ["auditd", "commissiond"],
            "masked_operations": ["auditd", "commissiond"],
            "masked_observations": ["auditd", "commissiond"],
            "grant_withdrawal": "confirmed",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    assert h.grant_journal.close_evidence_digest == (
        "sha256:" + sha256(containment_evidence).hexdigest()
    )


@pytest.mark.parametrize(
    "failed_phase, expected_notification",
    [("pair_grant_opened", False), ("auditd_start_intent", True)],
)
def test_failed_grant_advance_prevents_gated_notification_or_start(
    evidence, failed_phase, expected_notification,
):
    h = Harness(evidence)
    notifications = []
    h.supervisor.controller_ready = lambda: notifications.append(True)
    advance = h.grant_store.advance

    def fail_selected_advance(expected, action, *, evidence_digest=None):
        if action == failed_phase:
            raise RuntimeError(f"simulated {failed_phase} persistence failure")
        return advance(expected, action, evidence_digest=evidence_digest)

    h.grant_store.advance = fail_selected_advance
    with pytest.raises(RuntimeError, match="persistence failure"):
        h.supervisor.run()

    assert notifications == ([True] if expected_notification else [])
    assert ("start_and_wait", UnitKey.AUDITD) not in h.manager.calls
    assert ("start_and_wait", UnitKey.COMMISSIOND) not in h.manager.calls
    assert h.manager.pair_open is False
    assert all(h.manager.is_masked(unit) and h.manager.is_inactive(unit)
               for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND))
    assert h.grant_journal.phase == "closed"


@pytest.mark.parametrize("failure", ["expiry", "cancelled", "audit-lost", "admission"])
def test_commission_start_rechecks_after_persisting_intent(evidence, failure):
    h = Harness(evidence)
    advance = h.grant_store.advance

    def changed_during_write(expected, action, *, evidence_digest=None):
        result = advance(expected, action, evidence_digest=evidence_digest)
        if action == "commissiond_start_intent":
            if failure == "expiry":
                h.supervisor.boottime_ns = lambda: h.deadline.deadline_boottime_ns
            elif failure == "cancelled":
                h.stop = True
            elif failure == "audit-lost":
                h.manager.ready = False
            else:
                h.admit_error = ApprovalRefused("admission withdrawn")
        return result

    h.grant_store.advance = changed_during_write
    if failure == "cancelled":
        h.supervisor.run()
    else:
        with pytest.raises(ApprovalRefused):
            h.supervisor.run()
    assert ("start_and_wait", UnitKey.AUDITD) in h.manager.calls
    assert ("start_and_wait", UnitKey.COMMISSIOND) not in h.manager.calls
    assert not h.manager.pair_open
    assert all(h.manager.masked.values()) and all(h.manager.inactive.values())


@pytest.mark.parametrize("evidence", [
    ("2026-10-12T23:59:59Z", "2026-10-13T00:04:59Z"),
], indirect=True)
def test_historical_intents_cross_midnight_without_reordering_disk_chain(evidence, tmp_path):
    from azazel_nexus_runtime.auditd import SegmentedLedger

    ledger = SegmentedLedger(tmp_path / "ledger")
    seed = ledger.append({"seed": True}, day="2026-10-12")

    class HeadReader:
        def observe_head(self):
            return ledger.head()

    h = Harness(
        evidence,
        prestart=lambda _context: AuditObservation(seed.sequence, seed.event_hash, 1, 100),
        audit_head_reader=HeadReader(),
    )
    open_pair = h.manager.open_pair

    def crossing_midnight(transaction, *, approval, check_publish):
        result = open_pair(
            transaction, approval=approval, check_publish=check_publish
        )
        h.refresh_value = replace(h.deadline, last_utc="2026-10-13T00:00:01Z",
                                  last_boottime_ns=102 * NS)
        h.supervisor.boottime_ns = lambda: 102 * NS
        return result

    def record(event):
        entry = ledger.append(event, day=event["occurred_at"][:10])
        h.events.append(event)
        return AuditAppendReceipt(entry.sequence, entry.event_hash)

    h.manager.open_pair = crossing_midnight
    h.supervisor.record = record
    h.supervisor.run()
    assert [event["event_type"] for event in h.events[:2]] == [
        "bootstrap.grant_intent", "bootstrap.controller_ready_intent",
    ]
    assert [event["occurred_at"][:10] for event in h.events[:2]] == [
        "2026-10-12", "2026-10-13",
    ]
    ledger.verify()
    assert ledger.head()[0] == len(h.events) + 1


def test_missing_grant_append_receipt_never_starts_commissiond(evidence):
    h = Harness(evidence)

    def no_receipt(event):
        h.events.append(event)
        if event["event_type"] == "bootstrap.grant_intent":
            return None
        return AuditAppendReceipt(
            len(h.events) + 1, sha256(repr(event).encode()).hexdigest()
        )

    h.supervisor.record = no_receipt
    with pytest.raises(ApprovalRefused, match="receipt required"):
        h.supervisor.run()
    assert ("start_and_wait", UnitKey.COMMISSIOND) not in h.manager.calls
    assert all(h.manager.inactive.values()) and all(h.manager.masked.values())
    assert h.grant_journal.phase == "closed"


def test_grant_receipt_must_match_auditd_live_head(evidence):
    h = Harness(evidence)

    class MismatchedHead:
        calls = 0

        def observe_head(self):
            self.calls += 1
            if self.calls == 1:
                return 1, "a" * 64
            return 3, "f" * 64

    h.supervisor.audit_head_reader = MismatchedHead()
    with pytest.raises(ApprovalRefused, match="differs from live writer head"):
        h.supervisor.run()
    assert ("start_and_wait", UnitKey.COMMISSIOND) not in h.manager.calls
    assert all(h.manager.inactive.values()) and all(h.manager.masked.values())
    assert h.grant_journal.phase == "closed"


def test_supervisor_persists_complete_lifecycle_in_ordinary_directory(evidence, tmp_path):
    h = Harness(evidence)
    directory = tmp_path / "protected-test-state"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

    def open_directory():
        return os.open(directory, flags)

    def reload_phase():
        fd = open_directory()
        store = GrantTransactionStore(
            fd, owner_uid=os.getuid(), reopen=open_directory
        )
        os.close(fd)
        try:
            return store.load(
                boot_id=h.deadline.approval.context.boot_id
            ).phase
        finally:
            store.close()

    @contextmanager
    def file_store(_guard):
        fd = open_directory()
        store = GrantTransactionStore(
            fd, owner_uid=os.getuid(), reopen=open_directory
        )
        os.close(fd)
        try:
            yield store
        finally:
            store.close()

    observed = []
    h.supervisor.controller_ready = lambda: observed.append(
        ("controller_ready", reload_phase())
    )
    start = h.manager.start_and_wait

    def checked_start(unit, **kwargs):
        observed.append((f"{unit.value}_start", reload_phase()))
        return start(unit, **kwargs)

    h.manager.start_and_wait = checked_start
    h.supervisor.grant_store_factory = file_store
    assert h.supervisor.run().state == "stopped"
    assert observed == [
        ("controller_ready", "pair_grant_opened"),
        ("auditd_start", "auditd_start_intent"),
        ("commissiond_start", "commissiond_start_intent"),
    ]
    fd = open_directory()
    stored = GrantTransactionStore(
        fd, owner_uid=os.getuid(), reopen=open_directory
    )
    os.close(fd)
    try:
        journal = stored.load(boot_id=h.deadline.approval.context.boot_id)
        assert journal == h.supervisor._grant_transaction
        assert journal.phase == "closed"
    finally:
        stored.close()


@pytest.mark.parametrize(
    "phase",
    [
        "prepared", "pair_grant_intent", "pair_grant_opened",
        "auditd_start_intent", "auditd_ready", "audit_intent_recorded",
        "commissiond_start_intent", "commissiond_ready", "closing",
        "closed", "recovery_required",
    ],
)
def test_fresh_supervisor_refuses_to_replay_retained_crash_phase(
    evidence, tmp_path, phase,
):
    directory = tmp_path / phase
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

    def open_directory():
        return os.open(directory, flags)

    fd = open_directory()
    store = GrantTransactionStore(fd, owner_uid=os.getuid(), reopen=open_directory)
    os.close(fd)
    source = Harness(evidence)
    journal = source.supervisor.grant_transaction_factory(
        source.deadline, source.generation
    )
    actions = (
        ("pair_grant_intent", None),
        ("pair_grant_opened", None),
        ("auditd_start_intent", None),
        ("auditd_ready", None),
        ("audit_intent_recorded", DIGEST),
        ("commissiond_start_intent", None),
        ("commissiond_ready", None),
        ("closing", DIGEST),
        ("closed", "sha256:" + "b" * 64),
    )
    try:
        store.create(journal)
        if phase == "recovery_required":
            journal = store.advance(
                journal, "recovery_required", evidence_digest=DIGEST
            )
        elif phase != "prepared":
            for action, evidence_digest in actions:
                journal = store.advance(
                    journal, action, evidence_digest=evidence_digest
                )
                if journal.phase == phase:
                    break
        assert journal.phase == phase
    finally:
        store.close()

    h = Harness(evidence)

    @contextmanager
    def file_store(_guard):
        fd = open_directory()
        current = GrantTransactionStore(
            fd, owner_uid=os.getuid(), reopen=open_directory
        )
        os.close(fd)
        try:
            yield current
        finally:
            current.close()

    if phase not in {"prepared", "closed"}:
        h.manager.pair_open = True
        h.manager.inactive = {
            UnitKey.AUDITD: False,
            UnitKey.COMMISSIOND: False,
        }
        h.manager.masked = {
            UnitKey.AUDITD: False,
            UnitKey.COMMISSIOND: False,
        }
    h.supervisor.grant_store_factory = file_store
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()
    assert not any(op in {"open_pair", "start_and_wait"}
                   for op, _ in h.manager.calls)
    assert not h.events
    assert not h.manager.pair_open
    assert all(h.manager.inactive.values()) and all(h.manager.masked.values())
    withdrawals = [entry[1] for entry in h.manager.calls
                   if entry[0] == "withdraw_pair"]
    if phase == "closed":
        assert not withdrawals
    else:
        assert [item.grant_id for item in withdrawals] == [journal.grant_id]

    fd = open_directory()
    current = GrantTransactionStore(fd, owner_uid=os.getuid(), reopen=open_directory)
    os.close(fd)
    try:
        retained = current.load(boot_id=journal.boot_id)
        assert retained == h.supervisor._grant_transaction
        assert retained.phase == (
            phase if phase in {"closed", "recovery_required"}
            else "recovery_required"
        )
    finally:
        current.close()


def test_interrupted_pair_grant_is_contained_by_fresh_supervisor(evidence, tmp_path):
    class SimulatedProcessCrash(BaseException):
        pass

    directory = tmp_path / "interrupted-pair-grant"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

    def open_directory():
        return os.open(directory, flags)

    @contextmanager
    def file_store(_guard):
        fd = open_directory()
        store = GrantTransactionStore(
            fd, owner_uid=os.getuid(), reopen=open_directory
        )
        os.close(fd)
        try:
            yield store
        finally:
            store.close()

    manager = RecordingManager()
    manager.open_pair_error = SimulatedProcessCrash()
    h = Harness(evidence, manager=manager, grant_store_factory=file_store)

    def process_gone():
        raise SimulatedProcessCrash()

    h.supervisor._finish_transaction = process_gone
    with pytest.raises(SimulatedProcessCrash):
        h.supervisor.run()
    assert manager.pair_open

    fd = open_directory()
    store = GrantTransactionStore(fd, owner_uid=os.getuid(), reopen=open_directory)
    os.close(fd)
    try:
        interrupted = store.load(
            boot_id=h.deadline.approval.context.boot_id
        )
        assert interrupted.phase == "pair_grant_intent"
    finally:
        store.close()

    recovered_manager = RecordingManager(inactive={
        UnitKey.AUDITD: False,
        UnitKey.COMMISSIOND: False,
    })
    recovered_manager.pair_open = True
    recovered_manager.masked = {
        UnitKey.AUDITD: False,
        UnitKey.COMMISSIOND: False,
    }
    recovered = Harness(
        evidence,
        manager=recovered_manager,
        grant_store_factory=file_store,
    )
    with pytest.raises(ApprovalRefused, match="manual review"):
        recovered.supervisor.run()
    assert not recovered_manager.pair_open
    assert all(recovered_manager.inactive.values())
    assert all(recovered_manager.masked.values())
    assert sum(op == "withdraw_pair" for op, _ in recovered_manager.calls) == 1
    assert not any(op in {"open_pair", "start_and_wait"}
                   for op, _ in recovered_manager.calls)

    fd = open_directory()
    store = GrantTransactionStore(fd, owner_uid=os.getuid(), reopen=open_directory)
    os.close(fd)
    try:
        recovered_journal = store.load(
            boot_id=h.deadline.approval.context.boot_id
        )
        assert recovered_journal.grant_id == interrupted.grant_id
        assert recovered_journal.phase == "recovery_required"
    finally:
        store.close()


@pytest.mark.parametrize(
    "change",
    [
        "renew",
        "boot",
        "revocation",
        "utc_rollback",
        "expiry",
        "helper_loss",
        "phase_end",
    ],
)
def test_running_session_change_narrows_without_restart(change, evidence):
    h = Harness(evidence)

    def wait(_seconds):
        assert [unit for op, unit in h.manager.calls if op == "start_and_wait"] == [
            UnitKey.AUDITD,
            UnitKey.COMMISSIOND,
        ]
        if change == "renew":
            h.refresh_value = replace(
                h.deadline,
                admitted_boottime_ns=101 * NS,
                deadline_boottime_ns=401 * NS,
                last_boottime_ns=101 * NS,
            )
        elif change in ("boot", "revocation"):
            context = replace(
                h.deadline.approval.context,
                **(
                    {"boot_id": "22222222-2222-2222-2222-222222222222"}
                    if change == "boot"
                    else {"revocation_digest": "sha256:" + "b" * 64}
                ),
            )
            h.refresh_value = replace(
                h.deadline, approval=replace(h.deadline.approval, context=context)
            )
        elif change == "utc_rollback":
            h.refresh_error = ApprovalRefused("fresh trusted UTC moved backward")
        elif change == "expiry":
            h.supervisor.boottime_ns = lambda: h.deadline.deadline_boottime_ns
        elif change == "helper_loss":
            h.manager.ready = False
        else:
            h.stop = True

    h.supervisor.wait = wait
    if change == "phase_end":
        assert h.supervisor.run().state == "stopped"
    else:
        with pytest.raises(ApprovalRefused):
            h.supervisor.run()
    assert all(h.manager.inactive.values()) and all(h.manager.masked.values())
    assert sum(op == "start_and_wait" for op, _ in h.manager.calls) == 2


def test_partial_commission_start_that_changes_state_then_raises_is_contained(evidence):
    h = Harness(evidence)
    start = h.manager.start_and_wait

    def partial(unit, **kwargs):
        start(unit, **kwargs)
        if unit is UnitKey.COMMISSIOND:
            raise RuntimeError("job reply lost after process start")

    h.manager.start_and_wait = partial
    with pytest.raises(RuntimeError):
        h.supervisor.run()
    assert all(h.manager.inactive.values()) and all(h.manager.masked.values())


def test_audit_failure_after_start_and_keyboard_interrupt_still_contain(evidence):
    for error in (OSError("audit failed"), KeyboardInterrupt()):
        h = Harness(evidence)

        def record(event):
            if event["event_type"] == "bootstrap.ready":
                raise error
            return h.record(event)

        h.supervisor.record = record
        with pytest.raises(type(error)):
            h.supervisor.run()
        assert all(h.manager.inactive.values()) and all(h.manager.masked.values())


def test_real_file_lock_covers_start_wait_and_cleanup(evidence, tmp_path):
    directory = tmp_path / "bootstrap"
    directory.mkdir(mode=0o700)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(directory, flags)
    try:
        h = Harness(evidence)

        def transaction():
            return _transaction_at(
                fd, owner=os.getuid(), reopen=lambda: os.open(directory, flags)
            )

        h.supervisor.transaction = transaction
        observed = []
        operation = h.manager._call

        def call(op, unit):
            with pytest.raises(BlockingIOError):
                with transaction():
                    pytest.fail("second controller obtained a held lock")
            observed.append(op)
            operation(op, unit)

        h.manager._call = call

        def wait(seconds):
            with pytest.raises(BlockingIOError):
                with transaction():
                    pytest.fail("lifetime lock released during wait")
            h.stop = True

        h.supervisor.wait = wait
        assert h.supervisor.run().state == "stopped"
        assert "start_and_wait" in observed and "stop_and_wait" in observed
        with transaction() as check:
            check()
    finally:
        os.close(fd)


def test_lost_lock_identity_prevents_second_start_but_not_cleanup(evidence, tmp_path):
    directory = tmp_path / "bootstrap"
    directory.mkdir(mode=0o700)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(directory, flags)
    try:
        h = Harness(evidence)
        h.supervisor.transaction = lambda: _transaction_at(
            fd, owner=os.getuid(), reopen=lambda: os.open(directory, flags)
        )

        def record(event):
            if event["event_type"] == "bootstrap.ready":
                (directory / "supervisor.lock").rename(directory / "displaced.lock")
                (directory / "supervisor.lock").touch(mode=0o600)
            return h.record(event)

        h.supervisor.record = record
        with pytest.raises(ApprovalRefused, match="transaction lock refused"):
            h.supervisor.run()
        assert [unit for op, unit in h.manager.calls if op == "start_and_wait"] == [
            UnitKey.AUDITD
        ]
        assert all(h.manager.inactive.values()) and all(h.manager.masked.values())
        assert (directory / "displaced.lock").exists()
    finally:
        os.close(fd)
