"""Pure crash-recovery state description; it performs no host operations."""

from dataclasses import FrozenInstanceError

import pytest

from azazel_nexus.bootstrap_grant_transaction import (
    PAIR,
    GrantTransaction,
    advance_transaction,
    decode_transaction,
    encode_transaction,
)
from azazel_nexus.operator_trust import ApprovalRefused

_HEX = "a" * 64
_DIGEST = "sha256:" + _HEX


def _transaction():
    return GrantTransaction(
        boot_id="22222222-2222-4222-8222-222222222222",
        context_digest=_DIGEST,
        approval_digest="sha256:" + "b" * 64,
        generation=7,
        generation_digest="sha256:" + "c" * 64,
        grant_id="0123456789abcdef0123456789abcdef",
        unit_payload_digests=tuple((unit, _HEX) for unit in PAIR),
    )


def _advance_to(journal, phase):
    steps = (
        ("pair_grant_intent", None),
        ("pair_grant_opened", None),
        ("auditd_start_intent", None),
        ("auditd_ready", None),
        ("audit_intent_recorded", _DIGEST),
        ("commissiond_start_intent", None),
        ("commissiond_ready", None),
        ("closing", _DIGEST),
        ("closed", "sha256:" + "d" * 64),
    )
    for action, evidence in steps:
        journal = advance_transaction(journal, action, evidence_digest=evidence)
        if journal.phase == phase:
            return journal
    assert journal.phase == phase


def test_transaction_has_fixed_exact_pair_and_starts_as_non_authorizing_intent():
    journal = _transaction()
    assert journal.phase == "prepared"
    assert tuple(name for name, _ in journal.unit_payload_digests) == PAIR
    assert "authorization" in GrantTransaction.__doc__
    assert "grant" in GrantTransaction.__doc__


def test_expected_audit_first_sequence_and_receipt_binding():
    journal = _transaction()
    journal = advance_transaction(journal, "pair_grant_intent")
    journal = advance_transaction(journal, "pair_grant_opened")
    journal = advance_transaction(journal, "auditd_start_intent")
    journal = advance_transaction(journal, "auditd_ready")
    with pytest.raises(ApprovalRefused):
        advance_transaction(journal, "audit_intent_recorded")
    receipt = "sha256:" + "d" * 64
    journal = advance_transaction(
        journal, "audit_intent_recorded", evidence_digest=receipt
    )
    assert journal.phase == "audit_intent_recorded"
    assert journal.audit_receipt_digest == receipt
    journal = advance_transaction(journal, "commissiond_start_intent")
    journal = advance_transaction(journal, "commissiond_ready")
    assert journal.phase == "commissiond_ready"


@pytest.mark.parametrize("action", [
    "pair_grant_intent", "pair_grant_opened", "auditd_start_intent",
    "auditd_ready", "audit_intent_recorded", "commissiond_start_intent",
    "commissiond_ready", "closed",
])
def test_skipped_or_out_of_order_stage_refuses(action):
    with pytest.raises(ApprovalRefused):
        advance_transaction(_transaction(), action, evidence_digest=_DIGEST)


def test_replay_and_mutated_identity_refuse():
    journal = advance_transaction(_transaction(), "pair_grant_intent")
    with pytest.raises(ApprovalRefused):
        advance_transaction(journal, "pair_grant_intent")
    with pytest.raises(FrozenInstanceError):
        journal.context_digest = "sha256:" + "e" * 64


def test_recovery_required_is_terminal_and_never_regrants():
    journal = advance_transaction(
        _transaction(), "recovery_required", evidence_digest=_DIGEST
    )
    assert journal.phase == "recovery_required"
    with pytest.raises(ApprovalRefused):
        advance_transaction(journal, "pair_grant_opened")
    with pytest.raises(ApprovalRefused):
        advance_transaction(journal, "recovery_required", evidence_digest=_DIGEST)


def test_close_requires_evidence_and_is_terminal():
    journal = _advance_to(_transaction(), "commissiond_ready")
    with pytest.raises(ApprovalRefused):
        advance_transaction(journal, "closing")
    journal = advance_transaction(journal, "closing", evidence_digest=_DIGEST)
    assert journal.close_intent_digest == _DIGEST
    with pytest.raises(ApprovalRefused):
        advance_transaction(journal, "closed")
    journal = advance_transaction(
        journal, "closed", evidence_digest="sha256:" + "d" * 64
    )
    with pytest.raises(ApprovalRefused):
        advance_transaction(journal, "recovery_required", evidence_digest=_DIGEST)


def test_canonical_round_trip_all_phases_and_unknown_or_duplicate_fields_refuse():
    journal = _advance_to(_transaction(), "audit_intent_recorded")
    raw = encode_transaction(journal)
    assert decode_transaction(raw) == journal
    with pytest.raises(ApprovalRefused):
        decode_transaction(raw[:-1] + b" ")
    duplicate = raw[:-1] + b',"phase":"audit_intent_recorded"}'
    with pytest.raises(ApprovalRefused):
        decode_transaction(duplicate)
    with pytest.raises(ApprovalRefused):
        decode_transaction(raw.replace(b'"phase":', b'"unknown":1,"phase":'))
