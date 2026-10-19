"""Ephemeral signatures and private credential files, never production state."""

import json
from types import SimpleNamespace

import pytest
from nacl.signing import SigningKey

from azazel_nexus import commissioning_draft
from azazel_nexus.commissioning_approval import commissioning_proposal_payload
from azazel_nexus.mio_profile import MioProfile
from azazel_nexus.operator_trust import ApprovalPurpose, MAX_APPROVAL_BYTES, OperatorTrust, approval_message
from azazel_nexus_runtime import mio_commissioning, mio_entryd


@pytest.fixture
def credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(commissioning_draft, "_MIO_CREDENTIALS", tmp_path)
    monkeypatch.setattr(mio_commissioning, "load_declared_node",
                        lambda: SimpleNamespace(node_id="node-synthetic"))
    key = SigningKey.generate()
    monkeypatch.setattr(mio_commissioning, "load_operator_trust",
                        lambda: OperatorTrust({"operator-a": bytes(key.verify_key)}))

    def save(payload, *, signature=None):
        values = (payload, payload, signature if signature is not None else key.sign(
            approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL, payload)).signature)
        for name, value in zip(("commissioning-proposal.expected.json",
                                "commissioning-proposal.json", "commissioning-proposal.sig"), values):
            path = tmp_path / ("mio-commissioning_" + name)
            if path.exists():
                path.chmod(0o600)
            path.write_bytes(value)
            path.chmod(0o400)

    return SimpleNamespace(save=save, key=key, directory=tmp_path)


@pytest.fixture
def context():
    pytest.importorskip("azazel_fabric")
    from azazel_fabric.provisioning_contracts import HardwareInventory, ResourceProfile, TopologyProfile
    from azazel_fabric.testing.provisioning import (
        golden_hardware_inventory, golden_resource_profile, golden_topology_profile,
    )
    inventory = HardwareInventory.model_validate(golden_hardware_inventory())
    return dict(inventory=inventory,
                resource_profile=ResourceProfile.model_validate(golden_resource_profile()),
                topology_profile=TopologyProfile.model_validate(golden_topology_profile()),
                record_id="record-synthetic", operator="operator-a",
                confirmed_at="2026-10-13T00:00:00Z")


def _node(monkeypatch, context):
    monkeypatch.setattr(mio_commissioning, "load_declared_node",
                        lambda: SimpleNamespace(node_id=context["inventory"].node_id))


@pytest.mark.parametrize("selection,expected", [
    (None, MioProfile.CORE), ("CORE", MioProfile.CORE),
    ("LITE", MioProfile.LOCAL_ONLY), ("FULL", MioProfile.FASTEST_PERMITTED),
])
def test_signed_ceiling_uses_operator_choice_not_resource_capacity(
    credentials, context, monkeypatch, selection, expected
):
    _node(monkeypatch, context)
    credentials.save(commissioning_proposal_payload(**context, mio_profile=selection))
    assert mio_entryd.commissioned_profile() is expected


@pytest.mark.parametrize("failure", [
    "unsigned", "tampered", "changed-both", "wrong-purpose", "revoked", "wrong-node",
    "unknown-profile", "missing-profile", "future-schema", "noncanonical", "lab-host",
])
def test_unverified_selection_is_core(credentials, context, monkeypatch, failure):
    _node(monkeypatch, context)
    payload = commissioning_proposal_payload(**context, mio_profile="FULL")
    credentials.save(payload)
    if failure == "unsigned":
        (credentials.directory / "mio-commissioning_commissioning-proposal.sig").unlink()
    elif failure in {"tampered", "changed-both"}:
        names = ["commissioning-proposal.json"]
        if failure == "changed-both":
            names.append("commissioning-proposal.expected.json")
        for name in names:
            path = credentials.directory / ("mio-commissioning_" + name)
            path.chmod(0o600)
            path.write_bytes(payload.replace(b'"mio_profile":"FULL"', b'"mio_profile":"LITE"'))
    elif failure == "wrong-purpose":
        credentials.save(payload, signature=credentials.key.sign(
            approval_message(ApprovalPurpose.COMMISSIONING, payload)).signature)
    elif failure == "revoked":
        monkeypatch.setattr(mio_commissioning, "load_operator_trust", lambda: OperatorTrust(
            {"operator-a": bytes(credentials.key.verify_key)}, frozenset({"operator-a"})))
    elif failure == "wrong-node":
        monkeypatch.setattr(mio_commissioning, "load_declared_node",
                            lambda: SimpleNamespace(node_id="other-node"))
    elif failure == "lab-host":
        monkeypatch.setattr("azazel_nexus.lab_host.is_lab_host", lambda: True)
    else:
        document = json.loads(payload)
        if failure == "unknown-profile":
            document["mio_profile"] = "standard"
        elif failure == "missing-profile":
            del document["mio_profile"]
        elif failure == "future-schema":
            document["schema"] = "azazel-nexus/commissioning-proposal/v999"
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        if failure == "noncanonical":
            payload += b" "
        credentials.save(payload)
    assert mio_entryd.commissioned_profile() is MioProfile.CORE


@pytest.mark.parametrize("raw", [None, b"{malformed", b'[]', b'{"operator":[]}'])
def test_missing_or_malformed_credentials_are_core(credentials, raw):
    if raw is not None:
        credentials.save(raw)
    assert mio_entryd.commissioned_profile() is MioProfile.CORE


@pytest.mark.parametrize("failure", ["permissions", "symlink", "hardlink", "oversized", "unreadable"])
def test_credential_storage_failure_is_core(credentials, context, failure, monkeypatch):
    _node(monkeypatch, context)
    credentials.save(commissioning_proposal_payload(**context, mio_profile="FULL"))
    path = credentials.directory / "mio-commissioning_commissioning-proposal.expected.json"
    if failure == "permissions":
        path.chmod(0o444)
    elif failure == "symlink":
        content = path.read_bytes()
        path.unlink()
        target = credentials.directory / "other"
        target.write_bytes(content)
        path.symlink_to(target)
    elif failure == "hardlink":
        (credentials.directory / "other").hardlink_to(path)
    elif failure == "oversized":
        path.chmod(0o600)
        path.write_bytes(b"x" * (MAX_APPROVAL_BYTES + 1))
    else:
        def refused():
            raise PermissionError("synthetic refusal")
        monkeypatch.setattr(mio_commissioning, "read_mio_profile_review_inputs", refused)
    assert mio_entryd.commissioned_profile() is MioProfile.CORE


@pytest.mark.parametrize("changed", ["node", "trust", "inputs"])
def test_protected_state_change_during_verification_is_core(
    credentials, context, monkeypatch, changed
):
    _node(monkeypatch, context)
    credentials.save(commissioning_proposal_payload(**context, mio_profile="FULL"))
    name = {"node": "load_declared_node", "trust": "load_operator_trust", "inputs": "read_mio_profile_review_inputs"}[changed]
    actual = getattr(mio_commissioning, name)
    values = iter((actual(), None))
    monkeypatch.setattr(mio_commissioning, name, lambda: next(values))
    assert mio_entryd.commissioned_profile() is MioProfile.CORE


def test_environment_cannot_supply_missing_credentials(credentials, context, monkeypatch, tmp_path):
    _node(monkeypatch, context)
    credentials.save(commissioning_proposal_payload(**context, mio_profile="FULL"))
    alternate = tmp_path / "alternate"
    alternate.mkdir()
    for path in credentials.directory.glob("mio-commissioning_*"):
        path.rename(alternate / path.name)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(alternate))
    monkeypatch.setenv("AZAZEL_ROOT", str(alternate))
    assert mio_entryd.commissioned_profile() is MioProfile.CORE
