"""Ephemeral operator keys and synthetic snapshots; no network or admission."""

from dataclasses import replace

import pytest
from nacl.signing import SigningKey

from azazel_nexus import fabric_boundary as boundary
from azazel_nexus.commissioning import confirm_roles, propose
from azazel_nexus.commissioning_draft import draft_bytes
from azazel_nexus.inventory import InterfaceReadout
from azazel_nexus.operator_trust import ApprovalPurpose, OperatorTrust, approval_message

pytest.importorskip("azazel_fabric")
from azazel_fabric.provisioning_contracts import COMPOSITE_IDENTITY_FIELDS, HardwareInventory, content_digest
from azazel_fabric.testing.provisioning import golden_hardware_inventory


@pytest.fixture
def inputs():
    inventory = HardwareInventory.model_validate(golden_hardware_inventory())
    readouts = tuple(InterfaceReadout(item.kernel_name_observed,
        {field: getattr(item, field) for field in COMPOSITE_IDENTITY_FIELDS},
        driver_version=item.driver_version) for item in inventory.interfaces)
    proposal = propose(readouts)
    projected = boundary.project_inventory(readouts)
    inventory = inventory.model_copy(update={"interfaces": projected.identities})
    inventory = inventory.model_copy(update={"inventory_digest": content_digest(inventory, digest_field="inventory_digest")})
    key = SigningKey.generate()
    record = confirm_roles(proposal, ((readouts[0], "observation"),), operator="operator-a",
                           at="2026-10-13T00:00:00Z", profiles_present=())
    payload = draft_bytes(record)
    signature = key.sign(approval_message(ApprovalPurpose.COMMISSIONING, payload)).signature
    args = dict(payload=payload, signature=signature, operator="operator-a",
                trust=OperatorTrust({"operator-a": bytes(key.verify_key)}), current=proposal,
                inventory=inventory, profile_id="topology-synthetic", observed_at="2026-10-13T00:01:00Z")
    return key, record, args


def test_reviewed_roles_project_without_invented_operational_evidence(inputs):
    _, _, args = inputs
    profile = boundary.project_reviewed_topology(**args)
    assert len(profile.commissioned_assignments) == 1
    assigned = profile.commissioned_assignments[0]
    assert assigned.role == "observation"
    assert assigned.node_id == profile.node_id == args["inventory"].node_id
    assert assigned.inventory_digest == profile.hardware_inventory_digest == args["inventory"].inventory_digest
    assert assigned.confirmation.method == "signed_site_approval"
    assert assigned.confirmation.operator_ref == "operator-a"
    assert assigned.confirmation.confirmed_at != profile.observed_at
    assert profile.management_reachability == "unknown"
    assert not profile.capture_support and not profile.isolation_properties
    assert len(profile.unassigned_interface_keys) == 1
    assert profile.authority == "descriptive_only"
    assert "signature-covers-draft-only-not-this-profile" in profile.limitations


@pytest.mark.parametrize("change", ["unsigned", "revoked", "wrong-purpose", "changed-payload", "wrong-operator"])
def test_invalid_operator_evidence_refused(inputs, change):
    key, _, args = inputs
    if change == "unsigned":
        args["signature"] = b""
    elif change == "revoked":
        args["trust"] = OperatorTrust(args["trust"].public_keys, frozenset({"operator-a"}))
    elif change == "wrong-purpose":
        args["signature"] = key.sign(approval_message(ApprovalPurpose.ACTIVATION, args["payload"])).signature
    elif change == "changed-payload":
        args["payload"] += b" "
    else:
        args["operator"] = "operator-b"
    with pytest.raises(boundary.CommissioningRecordUnavailable):
        boundary.project_reviewed_topology(**args)


@pytest.mark.parametrize("change", ["extra", "distinct-extra", "missing", "rename", "driver-version", "refused", "digest"])
def test_snapshot_mismatch_refused_including_unassigned_interfaces(inputs, change):
    _, _, args = inputs
    current = args["current"]
    one, two = current.commissionable
    if change == "extra":
        args["current"] = replace(current, commissionable=(one, two, replace(two, kernel_name="extra")))
    elif change == "distinct-extra":
        third = replace(two, kernel_name="third", fields=dict(two.fields) | {
            "bus_path": "pci-0000:04:00.0", "permanent_mac": "02:00:00:00:00:0c"})
        args["current"] = replace(current, commissionable=(one, two, third))
    elif change == "missing":
        args["current"] = replace(current, commissionable=(one,))
    elif change == "rename":
        args["current"] = replace(current, commissionable=(one, replace(two, kernel_name="renamed")))
    elif change == "driver-version":
        args["current"] = replace(current, commissionable=(one, replace(two, driver_version="changed")))
    elif change == "refused":
        args["current"] = replace(current, refused=(("unresolved", ("incomplete",)),))
    else:
        args["inventory"] = args["inventory"].model_copy(update={"node_id": "another-node"})
    with pytest.raises(boundary.CommissioningRecordUnavailable):
        boundary.project_reviewed_topology(**args)


def test_all_skip_leaves_every_interface_unassigned(inputs):
    key, record, args = inputs
    args["payload"] = draft_bytes(replace(record, roles=()))
    args["signature"] = key.sign(approval_message(ApprovalPurpose.COMMISSIONING, args["payload"])).signature
    profile = boundary.project_reviewed_topology(**args)
    assert not profile.commissioned_assignments
    assert set(profile.unassigned_interface_keys) == {item.interface_key for item in args["inventory"].interfaces}


def test_enumeration_order_does_not_change_role_bindings(inputs):
    _, _, args = inputs
    before = boundary.project_reviewed_topology(**args)
    args["current"] = replace(args["current"], commissionable=tuple(reversed(args["current"].commissionable)))
    assert boundary.project_reviewed_topology(**args) == before


def test_missing_fabric_refuses(inputs, monkeypatch):
    _, _, args = inputs
    monkeypatch.setattr(boundary, "_import_fabric", lambda: (None, "absent"))
    with pytest.raises(boundary.CommissioningRecordUnavailable):
        boundary.project_reviewed_topology(**args)
