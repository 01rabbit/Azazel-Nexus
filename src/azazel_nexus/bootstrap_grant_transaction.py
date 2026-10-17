"""Pure crash-recovery record for the exact two-helper bootstrap grant.

This is a transaction state description only. It does not authorize a grant,
prove a systemd operation/readiness observation, or replace auditd's chain.
The companion protected store persists this state; the systemd adapter remains
a separate composition obligation.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import re
import uuid

from .operator_trust import ApprovalRefused

SCHEMA = "azazel-nexus/bootstrap-grant-transaction/v2"
PAIR = ("azazel-auditd.service", "azazel-commissiond.service")
MAX_BYTES = 4096
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_BARE_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_GRANT_ID = re.compile(r"[0-9a-f]{32}\Z")
_PHASES = (
    "prepared",
    "pair_grant_intent",
    "pair_grant_opened",
    "auditd_start_intent",
    "auditd_ready",
    "audit_intent_recorded",
    "commissiond_start_intent",
    "commissiond_ready",
    "closing",
    "closed",
    "recovery_required",
)


@dataclass(frozen=True, slots=True)
class GrantTransaction:
    """Immutable phase description, not authorization, grant or readiness proof."""

    boot_id: str
    context_digest: str
    approval_digest: str
    generation: int
    generation_digest: str
    grant_id: str
    unit_payload_digests: tuple[tuple[str, str], ...]
    phase: str = "prepared"
    audit_receipt_digest: str | None = None
    close_intent_digest: str | None = None
    close_evidence_digest: str | None = None
    recovery_evidence_digest: str | None = None

    def __post_init__(self) -> None:
        try:
            if (type(self.boot_id) is not str
                    or str(uuid.UUID(self.boot_id)) != self.boot_id
                    or type(self.context_digest) is not str
                    or not _DIGEST.fullmatch(self.context_digest)
                    or type(self.approval_digest) is not str
                    or not _DIGEST.fullmatch(self.approval_digest)
                    or type(self.generation) is not int
                    or self.generation < 1
                    or type(self.generation_digest) is not str
                    or not _DIGEST.fullmatch(self.generation_digest)
                    or type(self.grant_id) is not str
                    or not _GRANT_ID.fullmatch(self.grant_id)
                    or type(self.unit_payload_digests) is not tuple
                    or len(self.unit_payload_digests) != len(PAIR)
                    or tuple(row[0] for row in self.unit_payload_digests) != PAIR
                    or any(type(row) is not tuple or len(row) != 2
                           or type(row[1]) is not str
                           or not _BARE_DIGEST.fullmatch(row[1])
                           for row in self.unit_payload_digests)
                    or type(self.phase) is not str or self.phase not in _PHASES):
                raise ValueError
            for value in (self.audit_receipt_digest, self.close_evidence_digest,
                          self.recovery_evidence_digest):
                if value is not None and (type(value) is not str
                                          or not _DIGEST.fullmatch(value)):
                    raise ValueError
            if ((self.phase in {"prepared", "pair_grant_intent", "pair_grant_opened",
                                "auditd_start_intent", "auditd_ready"}
                 and self.audit_receipt_digest is not None)
                    or (self.phase in {"audit_intent_recorded", "commissiond_start_intent",
                                       "commissiond_ready"}
                        and self.audit_receipt_digest is None)
                    or (self.phase not in {"closing", "closed"}
                        and self.close_intent_digest is not None)
                    or (self.phase not in {"closing", "closed"}
                        and self.close_evidence_digest is not None)
                    or (self.phase in {"closing", "closed"}
                        and self.close_intent_digest is None)
                    or (self.phase == "closing" and self.close_evidence_digest is not None)
                    or (self.phase == "closed" and self.close_evidence_digest is None)
                    or (self.phase != "recovery_required"
                        and self.recovery_evidence_digest is not None)
                    or (self.phase == "recovery_required"
                        and self.recovery_evidence_digest is None)):
                raise ValueError
        except (ValueError, TypeError, AttributeError, IndexError):
            raise ApprovalRefused("bootstrap grant transaction refused") from None


def advance_transaction(
    journal: GrantTransaction,
    action: str,
    *,
    evidence_digest: str | None = None,
) -> GrantTransaction:
    """Apply exactly the next typed state transition; never infer OS facts."""
    if type(journal) is not GrantTransaction or type(action) is not str:
        raise ApprovalRefused("bootstrap grant transaction transition refused")
    transitions = {
        "prepared": {"pair_grant_intent": "pair_grant_intent"},
        "pair_grant_intent": {"pair_grant_opened": "pair_grant_opened"},
        "pair_grant_opened": {"auditd_start_intent": "auditd_start_intent"},
        "auditd_start_intent": {"auditd_ready": "auditd_ready"},
        "auditd_ready": {"audit_intent_recorded": "audit_intent_recorded"},
        "audit_intent_recorded": {"commissiond_start_intent": "commissiond_start_intent"},
        "commissiond_start_intent": {"commissiond_ready": "commissiond_ready"},
        "commissiond_ready": {"closing": "closing"},
        "closing": {"closed": "closed"},
    }
    if action == "recovery_required":
        if journal.phase in {"closed", "recovery_required"}:
            raise ApprovalRefused("bootstrap grant transaction transition refused")
        if type(evidence_digest) is not str or not _DIGEST.fullmatch(evidence_digest):
            raise ApprovalRefused("bootstrap recovery evidence digest required")
        return replace(journal, phase="recovery_required",
                       audit_receipt_digest=journal.audit_receipt_digest,
                       close_intent_digest=None,
                       close_evidence_digest=None,
                       recovery_evidence_digest=evidence_digest)
    if action == "closing" and journal.phase not in {"closed", "recovery_required", "closing"}:
        if type(evidence_digest) is not str or not _DIGEST.fullmatch(evidence_digest):
            raise ApprovalRefused("bootstrap close intent digest required")
        return replace(journal, phase="closing", close_intent_digest=evidence_digest)
    if action not in transitions.get(journal.phase, {}):
        raise ApprovalRefused("bootstrap grant transaction transition refused")
    expected_phase = transitions[journal.phase][action]
    if action == "audit_intent_recorded":
        if type(evidence_digest) is not str or not _DIGEST.fullmatch(evidence_digest):
            raise ApprovalRefused("bootstrap audit receipt digest required")
    elif action == "closed":
        if type(evidence_digest) is not str or not _DIGEST.fullmatch(evidence_digest):
            raise ApprovalRefused("bootstrap close evidence digest required")
    elif evidence_digest is not None:
        raise ApprovalRefused("unexpected bootstrap transition evidence")
    changes = {"phase": expected_phase}
    if action == "audit_intent_recorded":
        changes["audit_receipt_digest"] = evidence_digest
    elif action == "closed":
        changes["close_evidence_digest"] = evidence_digest
    return replace(journal, **changes)


def encode_transaction(journal: GrantTransaction) -> bytes:
    """Canonical bounded encoding for the protected per-boot store."""
    if type(journal) is not GrantTransaction:
        raise ApprovalRefused("bootstrap grant transaction refused")
    value = {
        "schema": SCHEMA,
        "boot_id": journal.boot_id,
        "context_digest": journal.context_digest,
        "approval_digest": journal.approval_digest,
        "generation": journal.generation,
        "generation_digest": journal.generation_digest,
        "grant_id": journal.grant_id,
        "unit_payload_digests": [list(row) for row in journal.unit_payload_digests],
        "phase": journal.phase,
        "audit_receipt_digest": journal.audit_receipt_digest,
        "close_intent_digest": journal.close_intent_digest,
        "close_evidence_digest": journal.close_evidence_digest,
        "recovery_evidence_digest": journal.recovery_evidence_digest,
    }
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(raw) > MAX_BYTES:
        raise ApprovalRefused("bootstrap grant transaction exceeds bound")
    return raw


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate field")
        value[key] = item
    return value


def decode_transaction(raw: bytes) -> GrantTransaction:
    """Decode only the exact canonical schema; reject ambiguous JSON."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
        raise ApprovalRefused("bootstrap grant transaction encoding refused")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
        expected = {
            "schema", "boot_id", "context_digest", "approval_digest", "generation",
            "generation_digest", "grant_id", "unit_payload_digests", "phase",
            "audit_receipt_digest", "close_intent_digest", "close_evidence_digest",
            "recovery_evidence_digest",
        }
        if type(value) is not dict or set(value) != expected or value["schema"] != SCHEMA:
            raise ValueError
        rows = value["unit_payload_digests"]
        if type(rows) is not list:
            raise ValueError
        journal = GrantTransaction(
            boot_id=value["boot_id"], context_digest=value["context_digest"],
            approval_digest=value["approval_digest"], generation=value["generation"],
            generation_digest=value["generation_digest"], grant_id=value["grant_id"],
            unit_payload_digests=tuple(tuple(row) for row in rows), phase=value["phase"],
            audit_receipt_digest=value["audit_receipt_digest"],
            close_intent_digest=value["close_intent_digest"],
            close_evidence_digest=value["close_evidence_digest"],
            recovery_evidence_digest=value["recovery_evidence_digest"],
        )
        if encode_transaction(journal) != raw:
            raise ValueError
        return journal
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ApprovalRefused("bootstrap grant transaction encoding refused") from None
