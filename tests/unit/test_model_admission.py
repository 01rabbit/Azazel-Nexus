"""Only ephemeral test keys; these tests are not hardware evidence."""
from dataclasses import replace

import pytest
from admission_helpers import END, NOW, evidence, inputs

from azazel_nexus import model_admission as admission
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
    approval_message,
)


def test_minted_immutable_evidence_has_no_boolean_approval():
    value = evidence()
    assert admission.is_verified(value)
    assert not hasattr(value, "approved")
    with pytest.raises(TypeError):
        value.context.bindings["model"]["role"] = "generative"
    with pytest.raises(ApprovalRefused):
        replace(value, _seal=object())
    assert not admission.is_verified(object())
    assert not admission.is_verified(object.__new__(admission.VerifiedModelAdmission))


@pytest.mark.parametrize("now,symbol", [(END, "EXPIRED"), ("2026-10-17T23:59:59Z", "NOT_YET_VALID")])
def test_exclusive_time_window(now, symbol):
    kwargs, _, _ = inputs()
    kwargs["now"] = now
    with pytest.raises(ApprovalRefused, match=symbol):
        admission.verify_local_model_admission(**kwargs)


def test_wrong_purpose_tamper_and_revoked_keys_refuse():
    kwargs, signer, _ = inputs()
    for purpose in (ApprovalPurpose.ACTIVATION, ApprovalPurpose.SUPPORTING_BOOTSTRAP):
        kwargs["signature"] = signer.sign(approval_message(purpose, kwargs["payload"])).signature
        with pytest.raises(ApprovalRefused, match="SIGNATURE_REFUSED"):
            admission.verify_local_model_admission(**kwargs)
    kwargs["trust"] = OperatorTrust(kwargs["trust"].public_keys, frozenset({"approver"}))
    with pytest.raises(ApprovalRefused, match="SIGNATURE_REFUSED"):
        admission.verify_local_model_admission(**kwargs)


@pytest.mark.parametrize("section,symbol", [
    ("approval_key", "KEY_ROTATED"), ("node", "NODE_MISMATCH"),
    ("catalog", "CATALOG_MISMATCH"), ("model", "CATALOG_MISMATCH"),
    ("generation", "GENERATION_MISMATCH"), ("runtime", "RUNTIME_MISMATCH"),
    ("settings", "SETTINGS_MISMATCH"), ("compatibility", "TUPLE_MISMATCH"),
    ("reserve", "RESERVE_MISMATCH"), ("runtime_evidence", "RUNTIME_EVIDENCE_MISSING"),
    ("resources", "RESOURCE_FIT"),
])
def test_each_binding_is_independently_checked(section, symbol):
    kwargs, signer, _ = inputs()
    doc = admission.decode(kwargs["payload"])
    key = next(iter(doc[section]))
    value = doc[section][key]
    doc[section][key] = value + 1 if type(value) is int else value + "x"
    kwargs["payload"] = admission.canonical(doc)
    kwargs["signature"] = signer.sign(approval_message(
        ApprovalPurpose.LOCAL_MODEL_ADMISSION, kwargs["payload"])).signature
    with pytest.raises(ApprovalRefused, match=symbol):
        admission.verify_local_model_admission(**kwargs)


@pytest.mark.parametrize("alter", ["bool", "extra", "duplicate", "whitespace", "role"])
def test_canonical_types_exact_fields_and_role(alter):
    kwargs, signer, _ = inputs()
    doc = admission.decode(kwargs["payload"])
    if alter == "bool":
        doc["generation"]["number"] = True
    if alter == "extra":
        doc["model"]["extra"] = "refuse"
    if alter == "role":
        doc["model"]["role"] = "generative"
    payload = admission.canonical(doc)
    if alter == "duplicate":
        payload = payload.replace(b'"schema":', b'"schema":"duplicate","schema":', 1)
    if alter == "whitespace":
        payload += b"\n"
    kwargs["payload"] = payload
    kwargs["signature"] = signer.sign(approval_message(ApprovalPurpose.LOCAL_MODEL_ADMISSION, payload)).signature
    with pytest.raises(ApprovalRefused):
        admission.verify_local_model_admission(**kwargs)


def test_validity_hard_cap_policy_shortening_and_bool_refusal():
    for seconds in (True, 0, 604801):
        with pytest.raises(ApprovalRefused):
            admission.AdmissionPolicy(frozenset({"approver"}), seconds, ("embedding",))
    kwargs, _, _ = inputs()
    kwargs["policy"] = replace(kwargs["policy"], max_seconds=3600)
    with pytest.raises(ApprovalRefused, match="VALIDITY_EXCEEDS_POLICY"):
        admission.verify_local_model_admission(**kwargs)
    with pytest.raises(ApprovalRefused, match="VALIDITY_EXCEEDS_POLICY"):
        admission.admission_payload(context=kwargs["expected"], operator="approver",
                                    approval_id=admission.decode(kwargs["payload"])["approval_id"],
                                    issued_at=NOW, expires_at="2026-10-26T00:00:00Z")


def test_attester_cannot_be_approver_and_must_remain_enrolled():
    kwargs, _, _ = inputs()
    context = kwargs["expected"].as_document()
    context["reserve"]["attestation_key_fingerprint"] = context["approval_key"]["fingerprint"]
    kwargs["expected"] = admission.AdmissionContext(context)
    with pytest.raises(ApprovalRefused, match="ATTESTER_IS_APPROVER"):
        admission.verify_local_model_admission(**kwargs)
    kwargs, _, _ = inputs()
    kwargs["trust"] = OperatorTrust(kwargs["trust"].public_keys, frozenset({"attester"}))
    with pytest.raises(ApprovalRefused, match="RESERVE_UNATTESTED"):
        admission.verify_local_model_admission(**kwargs)


def test_key_rotation_and_epoch_binding():
    kwargs, _, _ = inputs()
    context = kwargs["expected"].as_document()
    context["approval_key"]["fingerprint"] = "sha256:" + "0" * 64
    kwargs["expected"] = admission.AdmissionContext(context)
    with pytest.raises(ApprovalRefused, match="KEY_ROTATED"):
        admission.verify_local_model_admission(**kwargs)


def test_epoch_and_resource_caps_are_not_booleans_or_unbounded():
    kwargs, signer, _ = inputs()
    doc = admission.decode(kwargs["payload"])
    doc["approval_key"]["security_epoch"] += 1
    kwargs["payload"] = admission.canonical(doc)
    kwargs["signature"] = signer.sign(approval_message(
        ApprovalPurpose.LOCAL_MODEL_ADMISSION, kwargs["payload"])).signature
    with pytest.raises(ApprovalRefused, match="EPOCH_MISMATCH"):
        admission.verify_local_model_admission(**kwargs)
    for need in (0, 3841, True):
        context = kwargs["expected"].as_document()
        context["resources"]["memory_need_mib"] = need
        with pytest.raises(ApprovalRefused):
            admission.AdmissionContext(context)
