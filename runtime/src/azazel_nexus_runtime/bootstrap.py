"""Two-helper supervision owned by the activation controller.

This is the controller transaction, not a deployed systemd backend. All input,
locking, job and health adapters are trusted runtime composition dependencies,
not caller-provided RPC values. No real adapter is installed yet: production
activation remains refusing until protected producers and lifetime/boot fencing
exist. Tests use ordinary files and recording managers only.
"""

from contextlib import AbstractContextManager
from dataclasses import dataclass
from hashlib import sha256
import json
import math
from typing import Callable, Protocol

from azazel_nexus.bootstrap_approval import BootstrapContext
from azazel_nexus.bootstrap_deadline import (
    BootstrapDeadline,
    read_boottime_ns,
    revalidate_deadline,
)
from azazel_nexus.bootstrap_generation import VerifiedBootstrapGeneration
from azazel_nexus.bootstrap_grant_transaction import GrantTransaction
from azazel_nexus.bootstrap_grant_store import grant_transaction_store_in_transaction
from azazel_nexus.bootstrap_lock import bootstrap_transaction
from azazel_nexus.hil_preflight import read_boot_id
from azazel_nexus.operator_trust import ApprovalRefused

from .units import UnitKey
from .bootstrap_audit import AuditObservation
from .bootstrap_audit_client import AuditAppendReceipt, BootstrapAuditClient
from .bootstrap_audit_live import BootstrapLiveAuditHead
from .bootstrap_overlay_files import new_overlay_intent
from .bootstrap_prestart import inspect_bootstrap_prestart, check_bootstrap_audit_extension

_ORDER = (UnitKey.AUDITD, UnitKey.COMMISSIOND)


def _new_grant_transaction(deadline, generation) -> GrantTransaction:
    """Bind the crash record to the verified admission and fixed unit bytes."""
    if (type(deadline) is not BootstrapDeadline
            or type(generation) is not VerifiedBootstrapGeneration):
        raise ApprovalRefused("verified bootstrap admission required")
    approval = deadline.approval
    intent = new_overlay_intent(approval)
    return GrantTransaction(
        boot_id=approval.context.boot_id,
        context_digest="sha256:" + intent.context_digest,
        approval_digest=approval.payload_digest,
        generation=generation.number,
        generation_digest=generation.digest,
        grant_id=intent.grant_id,
        unit_payload_digests=intent.payload_digests,
    )


def _transaction_matches(transaction, deadline, generation) -> bool:
    if (type(transaction) is not GrantTransaction
            or type(deadline) is not BootstrapDeadline
            or type(generation) is not VerifiedBootstrapGeneration):
        return False
    try:
        expected = _new_grant_transaction(deadline, generation)
        return (
            transaction.boot_id == expected.boot_id
            and transaction.context_digest == expected.context_digest
            and transaction.approval_digest == expected.approval_digest
            and transaction.generation == expected.generation
            and transaction.generation_digest == expected.generation_digest
            and transaction.unit_payload_digests == expected.unit_payload_digests
            and type(transaction.grant_id) is str
            and len(transaction.grant_id) == 32
        )
    except Exception:
        return False


def _receipt_digest(receipt: AuditAppendReceipt) -> str:
    if type(receipt) is not AuditAppendReceipt:
        raise ApprovalRefused("auditd grant-intent receipt required")
    raw = json.dumps(
        {
            "schema": "azazel-nexus/bootstrap-audit-receipt/v1",
            "sequence": receipt.sequence,
            "event_hash": receipt.event_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return "sha256:" + sha256(raw).hexdigest()


class BootstrapContainmentFailed(RuntimeError):
    """Stopping/masking could not be positively confirmed; never success."""


class BootstrapManager(Protocol):
    """Private reviewed backend contract; no arbitrary name/path/command API.

    Job operations MUST be bounded, cancel/fence timed-out jobs, and observe
    completion. Masks do not stop a process. No enable/persistent grant is
    requested here. A deployed backend needs reviewed persistent-mask and
    controller-death/reboot fencing; an unmask alone cannot supply these.
    """

    def close_starts(self) -> None:
        """Revoke pair starts and fence pending/late jobs before any stop.

        Return only after the deployment fence is effective. This must be
        idempotent, including before the first grant. A later reviewed grant
        transaction, never a mask or observation, may reopen admission.
        """
        ...

    def open_pair(self, transaction: GrantTransaction, *, approval, check_publish) -> None:
        """Admit one owned pair grant after fresh checks; never start a unit.

        A deployment implementation must verify the complete loaded closure,
        preserve persistent/reboot masks and bind its fence to this lifetime.
        The exact grant id and unit digests must match the durable transaction.
        Partial failure remains owned and must be recoverable by containment.
        Invoke check_publish before each publication mutation and around loaded
        inspection; it must return None, not a cached approval flag.
        """
        ...

    def withdraw_pair(self, transaction: GrantTransaction) -> None:
        """Withdraw only this lifecycle's grant after fenced, confirmed stops.

        Must be idempotent before any grant, reject unknown ownership, and
        verify the restored loaded mask state. The durable transaction is the
        ownership selector after a controller restart; never remove another
        grant.
        """
        ...
    def start_and_wait(self, unit: UnitKey, *, transaction: GrantTransaction,
                       check_start: Callable[[], None]) -> None:
        """Start only the captured phase-bound intent under fresh checkpoints.

        Invoke check_start at each start boundary; it must return None. It is
        synchronous and may use owned D-Bus sessions, so must not be invoked
        inside a running asyncio loop. Job/owner/deadline fencing remains a
        backend obligation; the callback alone does not authorize deployment.
        """
        ...
    def confirm_controller_ready(self, transaction: GrantTransaction, *,
                                 check_ready, notify) -> None:
        """Notify once, then confirm the retained controller under a deadline."""
        ...
    def confirm_empty_pair(self) -> None:
        """Fresh same-owner inactive/zero-PID/cgroup proof under the closed fence.

        A missing source, changed identity or populated subtree must refuse.
        This is required before owned withdrawal and again before success.
        """
        ...
    def stop_and_wait(self, unit: UnitKey) -> None: ...
    def mask(self, unit: UnitKey) -> None: ...
    def is_masked(self, unit: UnitKey) -> bool: ...
    def is_inactive(self, unit: UnitKey) -> bool: ...
    def is_ready(self, unit: UnitKey) -> bool: ...


@dataclass(frozen=True)
class BootstrapResult:
    """Only returned after both helpers were positively contained."""

    state: str = "stopped"


class BootstrapSupervisor:
    """One nonrenewable session. Refusal raises only after narrowing.

    ``refresh`` must reverify signature/current independent context and durably
    advance the existing deadline store; it MUST NOT initialize missing state.
    ``admit_generation`` repeatedly checks semantic admission, protected policy,
    installed closure and phase-appropriate continuing health. It MUST NOT
    compare the initial stopped-writer audit head after audit records advance.
    ``prestart`` owns that initial-head check once, before controller records or
    READY. The separate ``audit_continuation`` inspector verifies extensions of
    the last verified head; initial preflight alone is not continuing assurance.
    The generation shape verifier alone is insufficient.
    ``transaction`` serializes the entire lifetime across processes and yields
    a canonical-path identity recheck. The default is the protected fixed-path
    lock, not a no-op. Other required dependencies have no permissive defaults
    or CLI switches.
    """

    def __init__(
        self,
        *,
        manager: BootstrapManager,
        refresh: Callable[[], BootstrapDeadline],
        admit_generation: Callable[[BootstrapContext], VerifiedBootstrapGeneration],
        deadline_guard,
        record: Callable[[dict], object],
        controller_ready: Callable[[], None],
        controller_watchdog: Callable[[], None] | None = None,
        transaction: Callable[[], AbstractContextManager] = bootstrap_transaction,
        emergency_narrow: Callable[[], None],
        stopped: Callable[[], bool],
        wait: Callable[[float], None],
        poll_seconds: float,
        boottime_ns: Callable[[], int] = read_boottime_ns,
        prestart: Callable[[BootstrapContext], AuditObservation] | None = None,
        audit_continuation: Callable[[BootstrapContext, AuditObservation], AuditObservation] | None = None,
        audit_head_reader=None,
        grant_store_factory=grant_transaction_store_in_transaction,
        grant_transaction_factory=None,
        boot_id_reader: Callable[[], str] = read_boot_id,
    ) -> None:
        if (
            type(poll_seconds) not in (int, float)
            or not math.isfinite(poll_seconds)
            or poll_seconds <= 0
        ):
            raise ValueError("explicit positive finite supervision interval required")
        self.manager = manager
        self.refresh = refresh
        self.admit_generation = admit_generation
        if (not callable(deadline_guard)
                or not callable(getattr(deadline_guard, "release_after_stop", None))):
            raise ValueError("required bootstrap kernel deadline guard")
        self.deadline_guard = deadline_guard
        self.record = record
        self.audit_head_reader = (
            audit_head_reader if audit_head_reader is not None else
            record if type(record) is BootstrapAuditClient else BootstrapAuditClient()
        )
        self.grant_store_factory = grant_store_factory
        self.grant_transaction_factory = (
            grant_transaction_factory or _new_grant_transaction
        )
        self.boot_id_reader = boot_id_reader
        self.controller_ready = controller_ready
        if controller_watchdog is None:
            from .systemd_notify import notify_watchdog
            controller_watchdog = notify_watchdog
        if not callable(controller_watchdog):
            raise ValueError("fixed controller watchdog callback required")
        self.controller_watchdog = controller_watchdog
        self._controller_ready_confirmed = False
        self.transaction = transaction
        self.emergency_narrow = emergency_narrow
        self.stopped = stopped
        self.wait = wait
        self.poll_seconds = poll_seconds
        self.boottime_ns = boottime_ns
        # Production default is the real protected-policy/capacity/audit path.
        # Overrides are trusted composition/test seams, never request inputs.
        self.prestart = prestart if prestart is not None else (
            lambda context: inspect_bootstrap_prestart(expected=context, manager=self.manager)
        )
        if not callable(self.prestart):
            raise ValueError("bootstrap prestart inspector required")
        self.audit_continuation = audit_continuation if audit_continuation is not None else (
            lambda context, previous: check_bootstrap_audit_extension(expected=context, previous=previous)
        )
        if not callable(self.audit_continuation):
            raise ValueError("bootstrap audit continuation inspector required")
        if (not callable(getattr(self.audit_head_reader, "observe_head", None))
                or not callable(self.grant_store_factory)
                or not callable(self.grant_transaction_factory)
                or not callable(self.boot_id_reader)):
            raise ValueError("protected grant store, transaction factory and audit reader required")
        self._audit_head: AuditObservation | object | None = None
        self._stopped_audit_head: AuditObservation | None = None
        self._live_audit: BootstrapLiveAuditHead | None = None
        self._grant_store = None
        self._grant_transaction: GrantTransaction | None = None
        self._previous: BootstrapDeadline | None = None
        self._last_elapsed: int | None = None
        self._used = False
        self._check_transaction: Callable[[], None] | None = None

    def _check(self) -> BootstrapDeadline:
        if self._check_transaction is None:
            raise ApprovalRefused("bootstrap transaction not held")
        self._check_transaction()
        current = self.refresh()
        if type(current) is not BootstrapDeadline:
            raise ApprovalRefused("durably retained bootstrap deadline required")
        if self._previous is not None:
            previous = self._previous
            if (
                current.admitted_at,
                current.admitted_boottime_ns,
                current.deadline_boottime_ns,
            ) != (
                previous.admitted_at,
                previous.admitted_boottime_ns,
                previous.deadline_boottime_ns,
            ):
                raise ApprovalRefused("bootstrap admission cannot be renewed")
            revalidate_deadline(
                previous,
                approval=current.approval,
                boot_id=current.approval.context.boot_id,
                now=current.last_utc,
                boottime_ns=current.last_boottime_ns,
                clock_trusted=True,
            )
        if self.deadline_guard(current) is not None:
            raise ApprovalRefused("bootstrap kernel deadline unconfirmed")
        generation = self.admit_generation(current.approval.context)
        if type(generation) is not VerifiedBootstrapGeneration or (
            generation.number,
            generation.digest,
        ) != (
            current.approval.context.generation,
            current.approval.context.generation_digest,
        ):
            raise ApprovalRefused(
                "independently admitted bootstrap generation required"
            )
        self._admitted_generation = generation
        next_head = self._audit_head
        if self._audit_head is not None and self._live_audit is None:
            next_head = self.audit_continuation(current.approval.context, self._audit_head)
            if (type(next_head) is not AuditObservation
                    or next_head.sequence < self._audit_head.sequence
                    or (next_head.sequence == self._audit_head.sequence
                        and next_head.digest != self._audit_head.digest)):
                raise ApprovalRefused("bootstrap audit continuation invalid")
        elif self._live_audit is not None:
            next_head = self._live_audit.observe()
        elapsed = self.boottime_ns()
        if (
            type(elapsed) is not int
            or not current.last_boottime_ns <= elapsed < current.deadline_boottime_ns
        ):
            raise ApprovalRefused("bootstrap elapsed clock invalid or expired")
        if self._last_elapsed is not None and elapsed < self._last_elapsed:
            raise ApprovalRefused("bootstrap elapsed clock moved backward")
        self._last_elapsed = elapsed
        self._previous = current
        self._check_transaction()
        self._audit_head = next_head
        return current

    def _record(
        self, event: str, unit: UnitKey | None = None, *, occurred_at: str | None = None
    ):
        assert self._previous is not None
        record = {
            "event_type": event,
            "approval_digest": self._previous.approval.payload_digest,
            "generation": self._previous.approval.context.generation,
            "occurred_at": self._previous.last_utc if occurred_at is None else occurred_at,
        }
        if unit is not None:
            record["unit_key"] = unit.value
        return self.record(record)

    def _contain(self) -> str:
        # Masks alone cannot fence queued jobs or a higher-priority override.
        # Require the deployment fence first, then best-effort reverse stops.
        # Every unit/operation is attempted even if a prior one failed.
        failures = []
        stopped_units = []
        masked_units = []
        inactive_units = []
        confirmed_masks = []
        grant_withdrawal = "not-owned"
        fenced = False
        try:
            if self.manager.close_starts() is not None:
                failures.append("start-fence")
            else:
                fenced = True
        except Exception:
            failures.append("start-fence")
        stopped = fenced
        for unit in _ORDER:
            try:
                if self.manager.mask(unit) is not None:
                    raise BootstrapContainmentFailed("invalid mask completion")
                masked_units.append(unit.value)
            except Exception:
                failures.append(unit)
                stopped = False
        if fenced:
            for unit in reversed(_ORDER):
                try:
                    if self.manager.stop_and_wait(unit) is not None:
                        raise BootstrapContainmentFailed("invalid stop completion")
                    stopped_units.append(unit.value)
                except Exception:
                    failures.append(unit)
                    stopped = False
        for unit in _ORDER:
            try:
                if self.manager.is_inactive(unit) is not True:
                    stopped = False
                else:
                    inactive_units.append(unit.value)
            except Exception:
                stopped = False
        if fenced and stopped:
            try:
                if self.manager.confirm_empty_pair() is not None:
                    raise BootstrapContainmentFailed("invalid empty-pair completion")
            except Exception:
                stopped = False
                failures.append("cgroup-containment")
        if (fenced and stopped
                and type(self._grant_transaction) is GrantTransaction
                and self._grant_transaction.phase != "closed"):
            try:
                if self.manager.withdraw_pair(self._grant_transaction) is not None:
                    failures.append("withdrawal")
                else:
                    grant_withdrawal = "confirmed"
            except Exception:
                failures.append("withdrawal")
        elif not fenced or not stopped:
            if "grant-retained" not in failures:
                failures.append("grant-retained")
        for unit in _ORDER:
            try:
                if self.manager.mask(unit) is not None:
                    failures.append(unit)
            except Exception:
                failures.append(unit)
        for unit in _ORDER:
            try:
                if self.manager.is_inactive(unit) is not True:
                    failures.append(unit)
                elif unit.value not in inactive_units:
                    inactive_units.append(unit.value)
            except Exception:
                failures.append(unit)
            try:
                if self.manager.is_masked(unit) is not True:
                    failures.append(unit)
                else:
                    confirmed_masks.append(unit.value)
            except Exception:
                failures.append(unit)
        if fenced and stopped:
            try:
                if self.manager.confirm_empty_pair() is not None:
                    raise BootstrapContainmentFailed("invalid final empty-pair completion")
            except Exception:
                failures.append("final-cgroup-containment")
        if failures:
            try:
                self.emergency_narrow()
            except Exception:
                pass  # Never replace a containment failure with success.
            raise BootstrapContainmentFailed(
                "bootstrap pair containment unconfirmed"
            ) from None
        evidence = json.dumps(
            {
                "schema": "azazel-nexus/bootstrap-containment-evidence/v2",
                "start_fence": "confirmed",
                "stopped": sorted(set(stopped_units)),
                "inactive": sorted(set(inactive_units)),
                "cgroup_empty_pair": sorted(unit.value for unit in _ORDER),
                "masked_operations": sorted(set(masked_units)),
                "masked_observations": sorted(set(confirmed_masks)),
                "grant_withdrawal": grant_withdrawal,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return "sha256:" + sha256(evidence).hexdigest()

    def _advance_grant(self, action: str, *, evidence_digest: str | None = None):
        current = self._grant_transaction
        if type(current) is not GrantTransaction or self._grant_store is None:
            raise ApprovalRefused("durable bootstrap transaction unavailable")
        updated = self._grant_store.advance(
            current, action, evidence_digest=evidence_digest
        )
        if type(updated) is not GrantTransaction:
            raise ApprovalRefused("durable bootstrap transaction update unconfirmed")
        self._grant_transaction = updated
        return updated

    def _close_intent_digest(self) -> str:
        journal = self._grant_transaction
        if type(journal) is not GrantTransaction:
            raise ApprovalRefused("durable bootstrap transaction unavailable")
        raw = json.dumps(
            {
                "schema": "azazel-nexus/bootstrap-close-intent/v1",
                "boot_id": journal.boot_id,
                "grant_id": journal.grant_id,
                "phase": journal.phase,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return "sha256:" + sha256(raw).hexdigest()

    def _recovery_digest(self, failure: BaseException) -> str:
        journal = self._grant_transaction
        raw = json.dumps(
            {
                "schema": "azazel-nexus/bootstrap-recovery-evidence/v1",
                "grant_id": journal.grant_id if type(journal) is GrantTransaction else "none",
                "phase": journal.phase if type(journal) is GrantTransaction else "none",
                "failure_type": type(failure).__name__,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return "sha256:" + sha256(raw).hexdigest()

    def _mark_recovery(self, failure: BaseException) -> None:
        journal = self._grant_transaction
        if (type(journal) is GrantTransaction and self._grant_store is not None
                and journal.phase not in {"closed", "recovery_required"}):
            try:
                self._advance_grant(
                    "recovery_required",
                    evidence_digest=self._recovery_digest(failure),
                )
            except Exception:
                pass  # Retain the original containment/store failure.

    def _finish_transaction(self) -> None:
        self._controller_ready_confirmed = False
        journal = self._grant_transaction
        if type(journal) is not GrantTransaction:
            self._contain()
            return

        close_error = None
        if journal.phase not in {"closing", "closed", "recovery_required"}:
            try:
                journal = self._advance_grant(
                    "closing", evidence_digest=self._close_intent_digest()
                )
            except Exception as exc:
                close_error = exc

        audit_error = None
        if self._live_audit is not None:
            try:
                self._record("bootstrap.stopping")
            except Exception as exc:
                audit_error = exc

        try:
            close_evidence = self._contain()
        except BaseException as exc:
            self._mark_recovery(exc)
            raise

        failure = close_error or audit_error
        if failure is not None:
            self._mark_recovery(failure)
            raise ApprovalRefused("bootstrap transaction close was not fully recorded") from None
        if journal.phase == "recovery_required":
            raise ApprovalRefused("bootstrap transaction requires recovery")
        try:
            self._advance_grant("closed", evidence_digest=close_evidence)
        except Exception as exc:
            self._mark_recovery(exc)
            raise

    def _cancelled(self) -> bool:
        value = self.stopped()
        if type(value) is not bool:
            raise ApprovalRefused("invalid supervision stop observation")
        return value

    def _ready(self, units: tuple[UnitKey, ...]) -> None:
        for unit in units:
            if self.manager.is_ready(unit) is not True:
                raise ApprovalRefused("bootstrap helper readiness lost")

    def _publication_checkpoint(self, transaction: GrantTransaction) -> BootstrapDeadline:
        """Revalidate the exact retained intent, admission and cancellation.

        This does not reuse the pre-publication absent-overlay observation:
        file ownership, manager owner and phase-aware fences are backend duties.
        """
        return self._intent_checkpoint(transaction, "pair_grant_intent", "publication")

    def _intent_checkpoint(self, transaction, phase, operation):
        current = self._check()
        if self._cancelled():
            raise ApprovalRefused(f"bootstrap {operation} cancelled")
        if (type(transaction) is not GrantTransaction
                or transaction.phase != phase
                or self._grant_transaction != transaction
                or self._grant_store is None
                or not _transaction_matches(transaction, current, self._admitted_generation)
                or self._grant_store.load_optional(boot_id=transaction.boot_id) != transaction):
            raise ApprovalRefused(f"retained {operation} intent changed")
        # The protected-store read is synchronous: expiry/cancellation may
        # occur while it is in progress even if the returned bytes match.
        if self._cancelled():
            raise ApprovalRefused(f"bootstrap {operation} cancelled")
        elapsed = self.boottime_ns()
        if (type(elapsed) is not int or self._last_elapsed is None
                or not self._last_elapsed <= elapsed < current.deadline_boottime_ns):
            raise ApprovalRefused(f"bootstrap {operation} elapsed clock invalid or expired")
        self._last_elapsed = elapsed
        self._check_transaction()
        return current

    def _start_checkpoint(self, unit: UnitKey,
                          transaction: GrantTransaction) -> BootstrapDeadline:
        """Bind one start to its retained intent, not merely a unit name."""
        if type(unit) is not UnitKey or unit not in _ORDER:
            raise ApprovalRefused("bootstrap start unit refused")
        phase = ("auditd_start_intent" if unit is UnitKey.AUDITD
                 else "commissiond_start_intent")
        current = self._check()
        if self._cancelled():
            raise ApprovalRefused("bootstrap start cancelled")
        if (type(transaction) is not GrantTransaction or transaction.phase != phase
                or self._grant_transaction != transaction
                or self._grant_store is None
                or (unit is UnitKey.COMMISSIOND
                    and transaction.audit_receipt_digest is None)
                or not _transaction_matches(transaction, current, self._admitted_generation)
                or self._grant_store.load_optional(boot_id=transaction.boot_id) != transaction):
            raise ApprovalRefused("retained start intent changed")
        if unit is UnitKey.COMMISSIOND:
            self._ready((UnitKey.AUDITD,))
        # Neither a matching store read nor readiness extends the deadline.
        if self._cancelled():
            raise ApprovalRefused("bootstrap start cancelled")
        elapsed = self.boottime_ns()
        if (type(elapsed) is not int or self._last_elapsed is None
                or not self._last_elapsed <= elapsed < current.deadline_boottime_ns):
            raise ApprovalRefused("bootstrap start elapsed clock invalid or expired")
        self._last_elapsed = elapsed
        self._check_transaction()
        return current

    def _start_helper(self, unit: UnitKey) -> None:
        transaction = self._grant_transaction

        def check_start():
            self._start_checkpoint(unit, transaction)
            self._heartbeat()

        check_start()
        if self.manager.start_and_wait(
            unit, transaction=transaction, check_start=check_start,
        ) is not None:
            raise ApprovalRefused("bootstrap start completion unconfirmed")
        check_start()

    def _supervise(self) -> None:
        initial = self._check()
        if self._cancelled():
            return
        # Run before any controller record can advance the expected audit head,
        # and only while both helpers are initially contained. Never rerun this
        # stopped-writer check after auditd legitimately starts appending.
        initial_head = self.prestart(initial.approval.context)
        if type(initial_head) is not AuditObservation:
            raise ApprovalRefused("bootstrap prestart observation required")
        self._audit_head = initial_head
        self._stopped_audit_head = initial_head
        self._check()
        if self._cancelled():
            return

        generation = getattr(self, "_admitted_generation", None)
        transaction = self.grant_transaction_factory(initial, generation)
        if not _transaction_matches(transaction, initial, generation):
            raise ApprovalRefused("bootstrap transaction identity differs from admission")
        self._grant_store.create(transaction)
        self._grant_transaction = transaction

        grant_intent_at = self._previous.last_utc
        self._advance_grant("pair_grant_intent")
        if self._cancelled():
            return
        publication_transaction = self._grant_transaction
        publication = self._publication_checkpoint(publication_transaction)

        def check_publish():
            self._publication_checkpoint(publication_transaction)

        if self.manager.open_pair(
            publication_transaction, approval=publication.approval,
            check_publish=check_publish,
        ) is not None:
            raise ApprovalRefused("bootstrap pair grant completion unconfirmed")
        check_publish()
        self._advance_grant("pair_grant_opened")
        self._check()
        if self._cancelled():
            return

        # systemd orders both notify helpers After this controller. READY is
        # therefore released only after all prestart checks and the durable
        # pair-grant intent, but before submitting the first helper job.
        controller_ready_at = self._previous.last_utc
        ready_transaction = self._grant_transaction

        def check_ready():
            self._intent_checkpoint(ready_transaction, "pair_grant_opened", "controller READY")

        check_ready()
        if self.manager.confirm_controller_ready(
            ready_transaction, check_ready=check_ready, notify=self.controller_ready,
        ) is not None:
            raise ApprovalRefused("controller READY completion unconfirmed")
        check_ready()
        self._controller_ready_confirmed = True
        self._check()
        if self._cancelled():
            return

        auditd_start_at = self._previous.last_utc
        self._advance_grant("auditd_start_intent")
        self._check()
        if self._cancelled():
            return
        self._start_helper(UnitKey.AUDITD)
        self._ready((UnitKey.AUDITD,))

        if self._stopped_audit_head is None:
            raise ApprovalRefused("stopped audit head unavailable")
        live_audit = BootstrapLiveAuditHead(
            self._stopped_audit_head, self.audit_head_reader
        )
        self._audit_head = live_audit.verify_startup()
        self._live_audit = live_audit
        self._advance_grant("auditd_ready")

        # Replay historical intents in occurrence order. Audit segments are
        # date-ordered, so emitting READY before the earlier grant can otherwise
        # append a successor into yesterday's segment across midnight.
        receipt = self._record("bootstrap.grant_intent", occurred_at=grant_intent_at)
        if type(receipt) is not AuditAppendReceipt:
            raise ApprovalRefused("auditd grant-intent receipt required")
        live_head = self._live_audit.observe()
        if (live_head.sequence, live_head.digest) != (
            receipt.sequence, receipt.event_hash
        ):
            raise ApprovalRefused(
                "auditd grant-intent receipt differs from live writer head"
            )
        self._audit_head = live_head
        self._advance_grant(
            "audit_intent_recorded",
            evidence_digest=_receipt_digest(receipt),
        )
        self._record(
            "bootstrap.controller_ready_intent", occurred_at=controller_ready_at
        )
        self._record(
            "bootstrap.start_intent", UnitKey.AUDITD, occurred_at=auditd_start_at
        )
        self._record("bootstrap.ready", UnitKey.AUDITD)

        if self._cancelled():
            return
        self._check()
        self._ready((UnitKey.AUDITD,))
        commissiond_start_at = self._previous.last_utc
        self._record("bootstrap.start_intent", UnitKey.COMMISSIOND,
                     occurred_at=commissiond_start_at)
        self._check()
        if self._cancelled():
            return
        self._advance_grant("commissiond_start_intent")
        # Durable storage can take time. Revalidate after it, not only before
        # it; persistence does not extend admission or suppress cancellation.
        self._check()
        self._ready((UnitKey.AUDITD,))
        if self._cancelled():
            return
        self._start_helper(UnitKey.COMMISSIOND)
        self._check()
        self._ready(_ORDER)
        self._advance_grant("commissiond_ready")
        self._record("bootstrap.ready", UnitKey.COMMISSIOND)
        while not self._cancelled():
            current = self._check()
            self._ready(_ORDER)
            elapsed = self.boottime_ns()
            if type(elapsed) is not int or elapsed < self._last_elapsed:
                raise ApprovalRefused("bootstrap elapsed clock moved backward")
            self._last_elapsed = elapsed
            remaining = (current.deadline_boottime_ns - elapsed) / 1_000_000_000
            if remaining <= 0:
                raise ApprovalRefused("bootstrap elapsed deadline expired")
            self._check_transaction()
            self._heartbeat()
            # Charge notifier time to the immutable budget; keep healthy idle
            # polling below the fixed 30-second system-manager watchdog.
            remaining = (self._previous.deadline_boottime_ns - self._last_elapsed) / 1_000_000_000
            self.wait(min(self.poll_seconds, 10.0, remaining))

    def _heartbeat(self):
        """Renew only from validated main-loop progress, never a background task."""
        def check():
            def sample():
                if (not self._controller_ready_confirmed or self._cancelled()
                        or self._previous is None):
                    raise ApprovalRefused("controller watchdog progress not admitted")
                elapsed = self.boottime_ns()
                if (type(elapsed) is not int or self._last_elapsed is None
                        or not self._last_elapsed <= elapsed < self._previous.deadline_boottime_ns):
                    raise ApprovalRefused("controller watchdog elapsed deadline refused")
                self._last_elapsed = elapsed

            sample()
            self._check_transaction()
            sample()  # the synchronous guard can consume time or observe cancellation

        check()
        if self.controller_watchdog() is not None:
            raise ApprovalRefused("controller watchdog notification unconfirmed")
        check()  # a slow notifier cannot extend admission or hide cancellation

    def run(self) -> BootstrapResult:
        if self._used:
            raise ApprovalRefused(
                "bootstrap supervisor cannot restart a consumed session"
            )
        self._used = True
        # A failed lock acquisition must not stop another controller's session.
        with self.transaction() as check_transaction:
            if not callable(check_transaction):
                raise ApprovalRefused("bootstrap transaction validator required")
            self._check_transaction = check_transaction
            with self.grant_store_factory(check_transaction) as store:
                if not all(callable(getattr(store, name, None))
                           for name in ("load_optional", "create", "advance")):
                    raise ApprovalRefused("protected bootstrap grant store required")
                self._grant_store = store
                try:
                    existing = store.load_optional(boot_id=self.boot_id_reader())
                except BaseException:
                    # The record may be ambiguous, but narrowing still runs.
                    try:
                        self._contain()
                    except BaseException:
                        self._contain()
                        raise
                    raise
                if existing is not None:
                    self._grant_transaction = existing
                    try:
                        self._contain()
                    except BaseException as exc:
                        self._mark_recovery(exc)
                        try:
                            self._contain()
                        except BaseException:
                            raise
                        raise
                    if existing.phase not in {"closed", "recovery_required"}:
                        self._mark_recovery(
                            ApprovalRefused("interrupted bootstrap transaction")
                        )
                    raise ApprovalRefused(
                        "existing bootstrap transaction requires manual review"
                    )
                try:
                    self._contain()
                except BaseException:
                    # Retry narrowing once; never continue after an unconfirmed
                    # initial fence or stop observation.
                    self._contain()
                    raise
                try:
                    self._supervise()
                except BaseException:
                    self._finish_transaction()
                    self._release_deadline_guard()
                    raise
                self._finish_transaction()
                self._release_deadline_guard()
                return BootstrapResult()

    def _release_deadline_guard(self) -> None:
        if self.deadline_guard.release_after_stop() is not None:
            raise ApprovalRefused("bootstrap kernel deadline release unconfirmed")
