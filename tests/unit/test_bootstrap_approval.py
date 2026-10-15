"""Pure bootstrap approval verification; synthetic keys and evidence only."""

from dataclasses import replace
import json

import pytest
from nacl.signing import SigningKey

from azazel_nexus.activation import (
    ActivationController,
    ActivationLease,
    CORE_UNITS,
    RecordingUnitController,
)
from azazel_nexus.audit import AuditLedger
from azazel_nexus.bootstrap_approval import (
    BOOTSTRAP_UNITS,
    BootstrapApprovalPolicy,
    BootstrapContext,
    VerifiedBootstrapApproval,
    bootstrap_payload,
    verify_bootstrap_approval,
)
from azazel_nexus.generation import GenerationStore
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
    approval_message,
)

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
START = "2026-10-13T00:00:00Z"
END = "2026-10-13T00:05:00Z"
OPERATOR = "operator-a"


@pytest.fixture
def signed():
    key = SigningKey.generate()
    policy = BootstrapApprovalPolicy(frozenset({OPERATOR}), 300)
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
        context=context, operator=OPERATOR, granted_at=START, expires_at=END
    )
    signature = key.sign(approval_message(ApprovalPurpose.SUPPORTING_BOOTSTRAP, payload)).signature
    return key, policy, context, dict(
        trust=OperatorTrust({OPERATOR: bytes(key.verify_key)}), expected=context,
        policy=policy, operator=OPERATOR, payload=payload, signature=signature, now=START,
    )


def _resign(key, payload, purpose=ApprovalPurpose.SUPPORTING_BOOTSTRAP):
    return key.sign(approval_message(purpose, payload)).signature


def test_valid_signature_returns_distinct_bootstrap_evidence(signed):
    _, _, context, args = signed
    evidence = verify_bootstrap_approval(**args)
    assert type(evidence) is VerifiedBootstrapApproval
    assert evidence.context == context
    assert evidence.operator == OPERATOR
    assert evidence.granted_at == START
    assert evidence.expires_at == END
    assert evidence.payload_digest.startswith("sha256:")
    assert BOOTSTRAP_UNITS == ("azazel-auditd.service", "azazel-commissiond.service")
    assert not isinstance(evidence, ActivationLease)


@pytest.mark.parametrize("field,value", [
    ("approval_id", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
    ("node_digest", OTHER_DIGEST),
    ("boot_id", "22222222-2222-2222-2222-222222222222"),
    ("generation", 2),
    ("generation_digest", OTHER_DIGEST),
    ("package_digest", OTHER_DIGEST),
    ("unit_closure_digest", OTHER_DIGEST),
    ("policy_digest", OTHER_DIGEST),
    ("approval_policy_digest", OTHER_DIGEST),
    ("security_epoch", 8),
    ("revocation_digest", OTHER_DIGEST),
])
def test_every_changed_expected_context_field_refuses(signed, field, value):
    key, _, context, args = signed
    changed = replace(context, **{field: value})
    payload = bootstrap_payload(
        context=context, operator=OPERATOR, granted_at=START, expires_at=END
    )
    with pytest.raises(ApprovalRefused):
        verify_bootstrap_approval(**(args | {
            "expected": changed, "payload": payload, "signature": _resign(key, payload),
        }))


@pytest.mark.parametrize("field,value", [
    ("generation", True), ("security_epoch", True),
    ("approval_id", "not-a-uuid"), ("boot_id", "not-a-uuid"),
    ("node_digest", "bad-digest"), ("generation_digest", "bad-digest"),
    ("package_digest", "bad-digest"), ("unit_closure_digest", "bad-digest"),
    ("policy_digest", "bad-digest"), ("approval_policy_digest", "bad-digest"),
    ("revocation_digest", "bad-digest"),
])
def test_context_constructor_rejects_malformed_types_and_identifiers(signed, field, value):
    _, _, context, _ = signed
    with pytest.raises(ApprovalRefused):
        replace(context, **{field: value})


@pytest.mark.parametrize("operators,max_seconds", [
    ({OPERATOR}, 300), (frozenset(), 300), (frozenset({OPERATOR}), True),
    (frozenset({OPERATOR}), 0),
])
def test_policy_constructor_requires_immutable_nonempty_operators_and_positive_integer_duration(
    operators, max_seconds,
):
    with pytest.raises(ApprovalRefused):
        BootstrapApprovalPolicy(operators, max_seconds)


@pytest.mark.parametrize("kind", ["whitespace", "duplicate", "extra", "missing", "schema",
                                    "purpose", "units_extra", "units_duplicate", "units_reordered",
                                    "wrong_context", "boolean_generation", "malformed_json", "null", "array"])
def test_signed_noncanonical_or_wrong_shape_document_refuses(signed, kind):
    key, _, _, args = signed
    doc = json.loads(args["payload"])
    if kind == "extra":
        doc["healthy"] = True
    elif kind == "missing":
        del doc["units"]
    elif kind == "schema":
        doc["schema"] = "other/v1"
    elif kind == "purpose":
        doc["purpose"] = ApprovalPurpose.ACTIVATION.value
    elif kind == "units_extra":
        doc["units"] = ["azazel-auditd.service", "azazel-fetchd.service"]
    elif kind == "units_duplicate":
        doc["units"] = ["azazel-auditd.service", "azazel-auditd.service"]
    elif kind == "units_reordered":
        doc["units"] = list(reversed(doc["units"]))
    elif kind == "wrong_context":
        doc["context"]["generation_digest"] = OTHER_DIGEST
    elif kind == "boolean_generation":
        doc["context"]["generation"] = True
    payload = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    if kind == "malformed_json":
        payload = b'{"'
    elif kind == "null":
        payload = b"null"
    elif kind == "array":
        payload = b"[]"
    elif kind == "whitespace":
        payload += b"\n"
    elif kind == "duplicate":
        payload = b'{"operator":"operator-a",' + payload[1:]
    with pytest.raises(ApprovalRefused):
        verify_bootstrap_approval(**(args | {"payload": payload, "signature": _resign(key, payload)}))


def test_revoked_and_wrong_key_refuse(signed):
    key, _, _, args = signed
    revoked = OperatorTrust({OPERATOR: bytes(key.verify_key)}, frozenset({OPERATOR}))
    with pytest.raises(ApprovalRefused):
        verify_bootstrap_approval(**(args | {"trust": revoked}))
    other = OperatorTrust({OPERATOR: bytes(SigningKey.generate().verify_key)})
    with pytest.raises(ApprovalRefused):
        verify_bootstrap_approval(**(args | {"trust": other}))


def test_purpose_transcripts_are_separated_both_directions(signed):
    key, _, _, args = signed
    activation_signature = _resign(key, args["payload"], ApprovalPurpose.ACTIVATION)
    with pytest.raises(ApprovalRefused):
        verify_bootstrap_approval(**(args | {"signature": activation_signature}))

    # An activation verifier must not accept a bootstrap-purpose signature.
    from azazel_nexus.activation_approval import (
        ActivationContext, approval_payload, verify_activation_approval,
    )

    activation_context = ActivationContext(
        DIGEST, "11111111-1111-1111-1111-111111111111", 1,
        DIGEST, DIGEST, DIGEST, DIGEST, DIGEST, 0,
    )
    payload = approval_payload(
        context=activation_context, operator=OPERATOR,
        granted_at=START, expires_at=END,
    )
    bootstrap_signature = _resign(key, payload)
    with pytest.raises(ApprovalRefused):
        verify_activation_approval(
            trust=args["trust"], expected=activation_context, operator=OPERATOR,
            payload=payload, signature=bootstrap_signature, now=START,
            max_lease_seconds=300,
        )


@pytest.mark.parametrize("purpose", [
    ApprovalPurpose.COMMISSIONING,
    ApprovalPurpose.COMMISSIONING_PROPOSAL,
])
def test_commissioning_purposes_cannot_authorize_bootstrap(signed, purpose):
    key, _, _, args = signed
    signature = _resign(key, args["payload"], purpose)
    with pytest.raises(ApprovalRefused):
        verify_bootstrap_approval(**(args | {"signature": signature}))


def test_enrollment_without_bootstrap_policy_does_not_authorize(signed):
    _, _, _, args = signed
    with pytest.raises(ApprovalRefused):
        verify_bootstrap_approval(**(args | {
            "policy": BootstrapApprovalPolicy(frozenset({"operator-b"}), 300),
        }))


def test_policy_digest_and_duration_and_expiry_are_enforced(signed):
    key, policy, context, args = signed
    with pytest.raises(ApprovalRefused):
        verify_bootstrap_approval(**(args | {
            "expected": replace(context, approval_policy_digest=OTHER_DIGEST),
        }))

    longer_policy = BootstrapApprovalPolicy(frozenset({OPERATOR}), 240)
    longer_context = replace(context, approval_policy_digest=longer_policy.digest())
    longer_payload = bootstrap_payload(
        context=longer_context, operator=OPERATOR, granted_at=START,
        expires_at="2026-10-13T00:04:01Z",
    )
    with pytest.raises(ApprovalRefused):
        verify_bootstrap_approval(**(args | {
            "policy": longer_policy, "expected": longer_context,
            "payload": longer_payload, "signature": _resign(key, longer_payload),
        }))
    for now in ("2026-10-12T23:59:59Z", END, "2026-10-13T00:00:00+00:00"):
        with pytest.raises(ApprovalRefused):
            verify_bootstrap_approval(**(args | {"now": now}))


def test_normal_activation_controller_rejects_verified_bootstrap_evidence(tmp_path, signed):
    _, _, _, args = signed
    evidence = verify_bootstrap_approval(**args)
    store = GenerationStore(tmp_path / "generations")
    store.create({"config": b"operational"}, created_at=START, commissioning_digest=DIGEST)
    units = RecordingUnitController(d.name for d in CORE_UNITS)
    controller = ActivationController(
        units=units, generations=store, ledger=AuditLedger(tmp_path / "audit.jsonl"),
    )
    outcome = controller.activate(now=START, actor=OPERATOR, lease=evidence)
    assert outcome.granted == ()
    assert all(v.reason.startswith("invalid_lease_type") for v in outcome.verdicts)
    assert all(operation == "mask" for operation, _ in units.calls)
