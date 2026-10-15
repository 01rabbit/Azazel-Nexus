"""Ephemeral test keys only; no node enrollment or activation."""

import pytest
from nacl.signing import SigningKey

from azazel_nexus.operator_trust import (
    MAX_APPROVAL_BYTES,
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
    approval_message,
)


@pytest.fixture
def approval():
    key = SigningKey.generate()
    purpose = ApprovalPurpose.COMMISSIONING
    payload = b"synthetic record bytes"
    signature = key.sign(approval_message(purpose, payload)).signature
    trust = OperatorTrust({"operator-a": bytes(key.verify_key)})
    return key, trust, dict(
        operator="operator-a", purpose=purpose, payload=payload, signature=signature
    )


def test_enrolled_operator_signature_is_verified_without_an_authorization(approval):
    _, trust, args = approval
    assert trust.verify(**args) is None


@pytest.mark.parametrize("change", [
    {"operator": "unknown"},
    {"purpose": ApprovalPurpose.ACTIVATION},
    {"payload": b"changed record"},
    {"signature": b"invalid"},
    {"signature": bytearray(64)},
    {"purpose": "commissioning"},
    {"payload": b""},
    {"payload": b"x" * (MAX_APPROVAL_BYTES + 1)},
])
def test_changed_or_malformed_input_is_refused(approval, change):
    _, trust, args = approval
    with pytest.raises(ApprovalRefused):
        trust.verify(**(args | change))


def test_wrong_key_is_refused(approval):
    _, _, args = approval
    trust = OperatorTrust({"operator-a": bytes(SigningKey.generate().verify_key)})
    with pytest.raises(ApprovalRefused):
        trust.verify(**args)


def test_revocation_and_missing_enrollment_refuse_previously_signed_input(approval):
    key, _, args = approval
    for trust in (
        OperatorTrust({}),
        OperatorTrust({"operator-a": bytes(key.verify_key)}, frozenset({"operator-a"})),
    ):
        with pytest.raises(ApprovalRefused):
            trust.verify(**args)


def test_trust_snapshot_cannot_be_changed_through_callers_mapping(approval):
    key, _, args = approval
    keys = {"operator-a": bytes(key.verify_key)}
    trust = OperatorTrust(keys)
    keys.clear()
    assert trust.verify(**args) is None
    with pytest.raises(TypeError):
        trust.public_keys["operator-b"] = bytes(key.verify_key)


def test_operator_alias_cannot_duplicate_a_key(approval):
    key, _, _ = approval
    public = bytes(key.verify_key)
    with pytest.raises(ApprovalRefused):
        OperatorTrust({"operator-a": public, "operator-b": public})


@pytest.mark.parametrize("keys", [{"Bad/name": b"x" * 32}, {"operator-a": b""},
                                  {"operator-a": bytes(32)}])
def test_invalid_trust_material_is_refused(keys):
    with pytest.raises(ApprovalRefused):
        OperatorTrust(keys)
