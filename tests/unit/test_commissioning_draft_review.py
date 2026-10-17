"""Ephemeral signatures and synthetic inventory, not measured admission."""

from dataclasses import replace
import json

import pytest
from nacl.signing import SigningKey

from azazel_nexus.commissioning import Proposal, confirm_roles
from azazel_nexus.commissioning_draft import DraftRefused, _decode_draft, draft_bytes, verify_draft_review
from azazel_nexus.inventory import InterfaceReadout
from azazel_nexus.operator_trust import ApprovalPurpose, OperatorTrust, approval_message


@pytest.fixture
def review():
    key = SigningKey.generate()
    readout = InterfaceReadout("synthetic0", {"mac": "02:00:00:00:00:01", "bus_path": "synthetic"})
    proposal = Proposal(commissionable=(readout,))
    record = confirm_roles(proposal, ((readout, "observation"),), operator="operator-a",
                           at="2026-10-13T00:00:00Z", profiles_present=("hardware",))
    payload = draft_bytes(record)
    args = dict(payload=payload, operator="operator-a", current=proposal,
                trust=OperatorTrust({"operator-a": bytes(key.verify_key)}),
                signature=key.sign(approval_message(ApprovalPurpose.COMMISSIONING, payload)).signature)
    return key, args


def test_signature_and_current_binding_are_checked_without_returning_admission(review):
    _, args = review
    assert verify_draft_review(**args) is None


@pytest.mark.parametrize("change", ["missing", "changed", "ambiguous"])
def test_changed_inventory_is_refused(review, change):
    _, args = review
    original = args["current"].commissionable[0]
    readouts = {
        "missing": (),
        "changed": (replace(original, fields={"mac": "02:00:00:00:00:02"}),),
        "ambiguous": (original, original),
    }[change]
    with pytest.raises(DraftRefused):
        verify_draft_review(**(args | {"current": Proposal(commissionable=readouts)}))


@pytest.mark.parametrize("change", ["operator", "time", "digest", "extra", "duplicate", "profile", "role"])
def test_valid_signature_does_not_fix_invalid_draft_semantics(review, change):
    key, args = review
    document = json.loads(args["payload"])
    if change == "operator":
        document["record"]["roles"][0]["confirmed_by"] = "operator-b"
    elif change == "time":
        document["record"]["created_at"] = "invalid"
    elif change == "digest":
        document["record"]["digest"] = "sha256:" + "f" * 64
    elif change == "extra":
        document["record"]["measured"] = True
    elif change == "profile":
        document["record"]["profiles_present"] = [True]
    elif change == "role":
        document["record"]["roles"][0]["role"] = []
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if change == "duplicate":
        payload = b'{"status":"unsigned-draft",' + payload[1:]
    signature = key.sign(approval_message(ApprovalPurpose.COMMISSIONING, payload)).signature
    with pytest.raises(DraftRefused):
        verify_draft_review(**(args | dict(payload=payload, signature=signature)))


def test_activation_signature_cannot_review_commissioning(review):
    key, args = review
    signature = key.sign(approval_message(ApprovalPurpose.ACTIVATION, args["payload"])).signature
    with pytest.raises(DraftRefused):
        verify_draft_review(**(args | {"signature": signature}))


def test_revoked_operator_cannot_review_a_draft(review):
    _, args = review
    trust = OperatorTrust(args["trust"].public_keys, frozenset({"operator-a"}))
    with pytest.raises(DraftRefused):
        verify_draft_review(**(args | {"trust": trust}))


@pytest.mark.parametrize("changes", [{"confirmed_by": "operator-b"},
                                     {"confirmed_at": "2026-10-12T00:00:00Z"}])
def test_correct_digest_and_signature_cannot_substitute_confirming_operator_or_time(review, changes):
    key, args = review
    original = _decode_draft(args["payload"])
    altered = replace(original, roles=(replace(original.roles[0], **changes),))
    payload = draft_bytes(altered)
    signature = key.sign(approval_message(ApprovalPurpose.COMMISSIONING, payload)).signature
    with pytest.raises(DraftRefused, match="identity or time mismatch"):
        verify_draft_review(**(args | dict(payload=payload, signature=signature)))


def test_all_skip_review_is_not_an_entire_inventory_unchanged_claim(review):
    key, args = review
    record = replace(_decode_draft(args["payload"]), roles=())
    payload = draft_bytes(record)
    signature = key.sign(approval_message(ApprovalPurpose.COMMISSIONING, payload)).signature
    different = Proposal(commissionable=(InterfaceReadout("other", {"mac": "02:00:00:00:00:02"}),))
    assert verify_draft_review(**(args | dict(payload=payload, signature=signature,
                                             current=different))) is None
