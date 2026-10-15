"""Full linked proposals with ephemeral keys, not live commissioning admission."""

import json

import pytest
from nacl.signing import SigningKey

from azazel_nexus.commissioning_approval import commissioning_proposal_payload, verify_commissioning_proposal
from azazel_nexus.fabric_boundary import CommissioningRecordUnavailable
from azazel_nexus.operator_trust import ApprovalPurpose, ApprovalRefused, OperatorTrust, approval_message

pytest.importorskip("azazel_fabric")
from azazel_fabric.provisioning_contracts import HardwareInventory, ResourceProfile, TopologyProfile
from azazel_fabric.testing.provisioning import golden_hardware_inventory, golden_resource_profile, golden_topology_profile


@pytest.fixture
def context():
    return dict(inventory=HardwareInventory.model_validate(golden_hardware_inventory()),
        resource_profile=ResourceProfile.model_validate(golden_resource_profile()),
        topology_profile=TopologyProfile.model_validate(golden_topology_profile()),
        record_id="record-synthetic", operator="operator-a", confirmed_at="2026-10-13T00:00:00Z")


def _signed(context):
    key = SigningKey.generate()
    payload = commissioning_proposal_payload(**context)
    return key, dict(payload=payload, trust=OperatorTrust({"operator-a": bytes(key.verify_key)}),
        signature=key.sign(approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL, payload)).signature)


def test_full_proposal_signature_authenticates_linkage_but_returns_no_grant(context):
    _, signed = _signed(context)
    document = json.loads(signed["payload"])
    assert document["status"] == "unsigned-proposal"
    assert document["confirmation_is"] == "proposed-until-full-signature-verified"
    assert document["record"]["authority"] == "descriptive_only"
    assert document["inventory"]["node_id"] == document["record"]["node_id"]
    assert verify_commissioning_proposal(**signed, **context) is None


@pytest.mark.parametrize("purpose", [ApprovalPurpose.COMMISSIONING, ApprovalPurpose.ACTIVATION])
def test_draft_or_activation_signature_cannot_approve_full_proposal(context, purpose):
    key, signed = _signed(context)
    signed["signature"] = key.sign(approval_message(purpose, signed["payload"])).signature
    with pytest.raises(ApprovalRefused):
        verify_commissioning_proposal(**signed, **context)


@pytest.mark.parametrize("change", ["hardware", "resource-node", "topology-node", "resource-inventory",
    "assignment-node", "assignment-selector", "assignment-inventory", "unassigned-overlap", "unassigned-omission", "future"])
def test_inconsistent_linked_profiles_refused(context, change):
    resource, topology = context["resource_profile"], context["topology_profile"]
    if change == "hardware":
        context["inventory"] = context["inventory"].model_copy(update={"node_id": "different"})
    elif change == "resource-node":
        context["resource_profile"] = resource.model_copy(update={"node_id": "different"})
    elif change == "topology-node":
        context["topology_profile"] = topology.model_copy(update={"node_id": "different"})
    elif change == "resource-inventory":
        context["resource_profile"] = resource.model_copy(update={"hardware_inventory_digest": "sha256:" + "f" * 64})
    elif change in {"assignment-node", "assignment-selector", "assignment-inventory"}:
        assignment = topology.commissioned_assignments[0]
        update = {"node_id": "different"} if change == "assignment-node" else {
            "selector": assignment.selector.model_copy(update={"bus_path": "absent"})}
        if change == "assignment-inventory":
            update = {"inventory_digest": "sha256:" + "f" * 64}
        context["topology_profile"] = topology.model_copy(update={"commissioned_assignments":
            (assignment.model_copy(update=update), *topology.commissioned_assignments[1:])})
    elif change == "unassigned-overlap":
        context["topology_profile"] = topology.model_copy(update={"unassigned_interface_keys":
            tuple(item.interface_key for item in context["inventory"].interfaces)})
    elif change == "unassigned-omission":
        context["topology_profile"] = topology.model_copy(update={"commissioned_assignments": (), "unassigned_interface_keys": ()})
    else:
        context["confirmed_at"] = "2000-01-01T00:00:00Z"
    with pytest.raises(CommissioningRecordUnavailable):
        commissioning_proposal_payload(**context)


@pytest.mark.parametrize("change", [
    "capture-unknown-interface",
    "capture-duplicate-interface",
    "capture-future-observation",
    "isolation-future-observation",
    "isolation-duplicate-property",
])
def test_invalid_topology_evidence_refused(context, change):
    topology = context["topology_profile"]
    if change.startswith("capture-"):
        capture = topology.capture_support[0]
        if change == "capture-unknown-interface":
            capture = capture.model_copy(update={"interface_key": "if-absent"})
            capture_support = (capture, *topology.capture_support[1:])
        elif change == "capture-duplicate-interface":
            capture_support = (*topology.capture_support, capture.model_copy())
        else:
            capture = capture.model_copy(update={"observed_at": capture.observed_at.replace(year=2099)})
            capture_support = (capture, *topology.capture_support[1:])
        context["topology_profile"] = topology.model_copy(update={"capture_support": capture_support})
    elif change == "isolation-future-observation":
        original = topology.isolation_properties[0]
        property_ = original.model_copy(update={"observed_at": original.observed_at.replace(year=2099)})
        context["topology_profile"] = topology.model_copy(update={"isolation_properties":
            (property_, *topology.isolation_properties[1:])})
    else:
        property_ = topology.isolation_properties[0]
        duplicate = topology.isolation_properties[1].model_copy(update={"property_id": property_.property_id})
        context["topology_profile"] = topology.model_copy(update={"isolation_properties":
            (property_, duplicate, *topology.isolation_properties[2:])})
    with pytest.raises(CommissioningRecordUnavailable):
        commissioning_proposal_payload(**context)


def test_changed_expected_measurement_refuses_old_signature(context):
    _, signed = _signed(context)
    context["resource_profile"] = context["resource_profile"].model_copy(update={"usable_storage_mib": 1})
    with pytest.raises(ApprovalRefused):
        verify_commissioning_proposal(**signed, **context)


def test_even_valid_signature_over_noncanonical_bytes_is_refused(context):
    key, signed = _signed(context)
    signed["payload"] = json.dumps(json.loads(signed["payload"]), indent=2).encode()
    signed["signature"] = key.sign(approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL, signed["payload"])).signature
    with pytest.raises(ApprovalRefused):
        verify_commissioning_proposal(**signed, **context)


def test_revoked_operator_cannot_approve_full_record(context):
    _, signed = _signed(context)
    signed["trust"] = OperatorTrust(signed["trust"].public_keys, frozenset({"operator-a"}))
    with pytest.raises(ApprovalRefused):
        verify_commissioning_proposal(**signed, **context)


def test_complete_proposal_cannot_silently_truncate_to_fit_signature_bound(context, monkeypatch):
    from azazel_nexus import commissioning_approval

    size = len(commissioning_proposal_payload(**context))
    monkeypatch.setattr(commissioning_approval, "MAX_APPROVAL_BYTES", size - 1)
    with pytest.raises(ApprovalRefused, match="size bound"):
        commissioning_proposal_payload(**context)


def test_wrong_enrolled_key_refuses_full_proposal(context):
    _, signed = _signed(context)
    signed["trust"] = OperatorTrust({"operator-a": bytes(SigningKey.generate().verify_key)})
    with pytest.raises(ApprovalRefused):
        verify_commissioning_proposal(**signed, **context)
