"""Recovery evidence for a manager stop whose close could not be recorded.

Nexus#324/#339: on reboot systemd stops the helper pair before the controller.
If the supervision loop wakes inside that window, the helper observation fails
(``UnitOperationFailed`` from the loaded-unit recheck, or ``AuditUnavailable``
from the audit head read) instead of reporting lost readiness, so the
absent-manager-stop close (``bootstrap.BootstrapSupervisor._finish_transaction``)
does not apply and the grant stays ``recovery_required`` with a closed overlay
journal.

This module only labels that one shape. The controller of the failing boot
writes the label as the grant's recovery evidence digest, and only after the
same proof the absent-manager-stop close needs: close intent recorded, the
stopping record refused with ``AuditUnavailable``, systemd observed stopping
the controller, containment confirmed and the stopped-writer audit chain
intact. The grant stays ``recovery_required``; nothing in that boot turns into
success. A later boot's prior-journal retirement may then remove the closed
journal of that earlier boot (``bootstrap_manager._retire_prior_boot_journal``)
and records the reason in the activation ledger.

It is not an approval, grant, selection or unit operation. Any other recovery
evidence (the generic ``bootstrap-recovery-evidence/v1`` digest, containment
failures, chain defects, supervision failures of other types) keeps manual
recovery.
"""

from __future__ import annotations

from hashlib import sha256
import json

from azazel_nexus.bootstrap_grant_transaction import GrantTransaction

UNRECORDED_MANAGER_STOP = "manager-stop-close-unrecorded"
# Exact supervision failure type names admitted for the label: the two helper
# observations that fail, rather than report lost readiness, while systemd
# stops the pair ahead of the controller.
MANAGER_STOP_SUPERVISION_FAILURES = ("UnitOperationFailed", "AuditUnavailable")


def unrecorded_manager_stop_digest(transaction: GrantTransaction, supervision_failure: str) -> str:
    """Deterministic label over the grant identity and the failure type name."""
    if (type(transaction) is not GrantTransaction
            or type(supervision_failure) is not str
            or supervision_failure not in MANAGER_STOP_SUPERVISION_FAILURES):
        raise ValueError("unrecorded manager stop evidence refused")
    raw = json.dumps(
        {
            "schema": "azazel-nexus/bootstrap-recovery-evidence/v2",
            "reason": UNRECORDED_MANAGER_STOP,
            "boot_id": transaction.boot_id,
            "grant_id": transaction.grant_id,
            "context_digest": transaction.context_digest,
            "approval_digest": transaction.approval_digest,
            "generation": transaction.generation,
            "generation_digest": transaction.generation_digest,
            "unit_payload_digests": [list(row) for row in transaction.unit_payload_digests],
            "audit_receipt_digest": transaction.audit_receipt_digest,
            "supervision_failure": supervision_failure,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return "sha256:" + sha256(raw).hexdigest()


def unrecorded_manager_stop_failure(transaction: object) -> str | None:
    """Return the supervision failure name if ``transaction`` carries the label.

    Only a ``recovery_required`` grant whose recovery evidence digest equals
    the label recomputed from its own identity qualifies; anything else is None.
    """
    if (type(transaction) is not GrantTransaction
            or transaction.phase != "recovery_required"
            or type(transaction.recovery_evidence_digest) is not str):
        return None
    for name in MANAGER_STOP_SUPERVISION_FAILURES:
        if transaction.recovery_evidence_digest == unrecorded_manager_stop_digest(
                transaction, name):
            return name
    return None
