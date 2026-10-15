"""Review exported commissioning proposals against retained local expectations."""

import json

import pytest
from nacl.signing import SigningKey

from azazel_nexus.commissioning_approval import (
    commissioning_proposal_payload,
    verify_retained_commissioning_proposal,
)
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    MAX_APPROVAL_BYTES,
    OperatorTrust,
    approval_message,
)

_UNSET = object()

pytest.importorskip("azazel_fabric")
from azazel_fabric.provisioning_contracts import HardwareInventory, ResourceProfile, TopologyProfile  # noqa: E402
from azazel_fabric.testing.provisioning import (  # noqa: E402
    golden_hardware_inventory,
    golden_resource_profile,
    golden_topology_profile,
)


@pytest.fixture
def context():
    return dict(
        inventory=HardwareInventory.model_validate(golden_hardware_inventory()),
        resource_profile=ResourceProfile.model_validate(golden_resource_profile()),
        topology_profile=TopologyProfile.model_validate(golden_topology_profile()),
        record_id="record-synthetic",
        operator="operator-a",
        confirmed_at="2026-10-13T00:00:00Z",
    )


def _review(context, *, candidate=None, expected=_UNSET, key=None, operator=None, node_id=None,
            trust=None, signature=None):
    key = key or SigningKey.generate()
    expected = commissioning_proposal_payload(**context) if expected is _UNSET else expected
    candidate = expected if candidate is None else candidate
    if signature is None:
        signature = key.sign(
            approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL, candidate)
        ).signature
    return verify_retained_commissioning_proposal(
        trust=trust or OperatorTrust({context["operator"]: bytes(key.verify_key)}),
        payload=candidate,
        signature=signature,
        expected_payload=expected,
        operator=context["operator"] if operator is None else operator,
        node_id=context["inventory"].node_id if node_id is None else node_id,
    )


def _document(payload):
    return json.loads(payload)


def _canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def test_retained_proposal_review_accepts_full_canonical_proposal_and_returns_none(context):
    assert _review(context) is None


def test_changed_candidate_signed_by_enrolled_key_does_not_match_retained_expectation(context):
    expected = commissioning_proposal_payload(**context)
    candidate_context = dict(context)
    candidate_context["record_id"] = "record-other"
    candidate = commissioning_proposal_payload(**candidate_context)
    key = SigningKey.generate()

    with pytest.raises(ApprovalRefused):
        _review(context, candidate=candidate, expected=expected, key=key)


def test_legitimately_changed_retained_expectation_and_matching_candidate_can_verify(context):
    changed_context = dict(context)
    changed_context["record_id"] = "record-revised"
    revised = commissioning_proposal_payload(**changed_context)
    key = SigningKey.generate()

    # This demonstrates the trust boundary: protection/provenance of expected bytes
    # is the caller's responsibility; a matching changed expectation is not root-proof.
    assert _review(context, candidate=revised, expected=revised, key=key) is None


@pytest.mark.parametrize("field", ["operator", "node_id"])
def test_retained_expectations_must_match_requested_operator_and_current_node(context, field):
    wrong = "operator-b" if field == "operator" else "different-node"
    kwargs = {field: wrong}
    with pytest.raises(ApprovalRefused):
        _review(context, **kwargs)


def test_revoked_operator_cannot_review_retained_proposal(context):
    key = SigningKey.generate()
    trust = OperatorTrust({"operator-a": bytes(key.verify_key)}, frozenset({"operator-a"}))
    with pytest.raises(ApprovalRefused):
        _review(context, key=key, trust=trust)


def test_wrong_enrolled_key_cannot_review_retained_proposal(context):
    key = SigningKey.generate()
    trust = OperatorTrust({"operator-a": bytes(SigningKey.generate().verify_key)})
    with pytest.raises(ApprovalRefused):
        _review(context, key=key, trust=trust)


@pytest.mark.parametrize(
    "expected",
    [b"", b"x" * (MAX_APPROVAL_BYTES + 1), bytearray(b"not-bytes"), "not-bytes", None],
)
def test_empty_oversized_or_nonbytes_retained_expectations_are_refused(context, expected):
    # Keep the signature input valid so refusal exercises the retained-input
    # verifier rather than the test helper's signing-transcript size check.
    candidate = commissioning_proposal_payload(**context)
    with pytest.raises(ApprovalRefused):
        _review(context, candidate=candidate, expected=expected)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload + b" ",  # noncanonical JSON whitespace
        lambda payload: payload.replace(b'"operator":"operator-a"',
                                        b'"operator":"operator-a","operator":"operator-a"'),
        lambda payload: _canonical({**_document(payload), "unknown": True}),
        lambda payload: b"{malformed",
        lambda payload: _canonical({**_document(payload), "schema": "azazel-nexus/commissioning-proposal/v999"}),
    ],
    ids=["noncanonical", "duplicate-field", "unknown-field", "malformed", "schema-change"],
)
def test_noncanonical_or_invalid_retained_document_is_refused(context, mutate):
    expected = mutate(commissioning_proposal_payload(**context))
    with pytest.raises(ApprovalRefused):
        _review(context, expected=expected)


@pytest.mark.parametrize("change", ["future-resource", "inconsistent-resource-node", "inconsistent-topology-digest"])
def test_future_or_inconsistent_retained_profiles_are_refused(context, change):
    document = _document(commissioning_proposal_payload(**context))
    if change == "future-resource":
        document["resource"]["measured_at"] = "2099-01-01T00:00:00Z"
    elif change == "inconsistent-resource-node":
        document["resource"]["node_id"] = "different-node"
    else:
        document["topology"]["hardware_inventory_digest"] = "sha256:" + "f" * 64
    expected = _canonical(document)

    with pytest.raises(ApprovalRefused):
        _review(context, expected=expected)
