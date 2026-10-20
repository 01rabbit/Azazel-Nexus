"""Ephemeral signatures and private credential files, never production state."""

import json
from types import SimpleNamespace

import pytest
from nacl.signing import SigningKey

from azazel_nexus import commissioning_draft
from azazel_nexus.commissioning_approval import commissioning_proposal_payload
from azazel_nexus.mio_profile import MioProfile
from azazel_nexus.operator_trust import ApprovalPurpose, MAX_APPROVAL_BYTES, approval_message
from azazel_nexus_runtime import mio_commissioning, mio_entryd


@pytest.fixture
def credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(commissioning_draft, "_MIO_CREDENTIALS", tmp_path)
    monkeypatch.setattr(mio_commissioning, "_cache_key", None)
    key = SigningKey.generate()
    (tmp_path / "mio-node").write_bytes(b"node_id: node-synthetic\n")
    (tmp_path / "mio-trust").write_text(json.dumps({
        "schema": "azazel-nexus/operator-trust/v1",
        "keys": {"operator-a": bytes(key.verify_key).hex()}, "revoked": []}))
    for name in ("mio-node", "mio-trust"):
        (tmp_path / name).chmod(0o400)

    def save(payload, *, signature=None):
        values = (payload, payload, signature if signature is not None else key.sign(
            approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL, payload)).signature)
        for name, value in zip(("commissioning-proposal.expected.json",
                                "commissioning-proposal.json", "commissioning-proposal.sig"), values):
            path = tmp_path / ("mio-profile_" + name)
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
    path = commissioning_draft._MIO_CREDENTIALS / "mio-node"
    path.chmod(0o600)
    path.write_text("node_id: " + context["inventory"].node_id + "\n")
    path.chmod(0o400)


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
        (credentials.directory / "mio-profile_commissioning-proposal.sig").unlink()
    elif failure in {"tampered", "changed-both"}:
        names = ["commissioning-proposal.json"]
        if failure == "changed-both":
            names.append("commissioning-proposal.expected.json")
        for name in names:
            path = credentials.directory / ("mio-profile_" + name)
            path.chmod(0o600)
            path.write_bytes(payload.replace(b'"mio_profile":"FULL"', b'"mio_profile":"LITE"'))
    elif failure == "wrong-purpose":
        credentials.save(payload, signature=credentials.key.sign(
            approval_message(ApprovalPurpose.COMMISSIONING, payload)).signature)
    elif failure == "revoked":
        path = credentials.directory / "mio-trust"
        path.chmod(0o600)
        document = json.loads(path.read_bytes())
        document["revoked"] = ["operator-a"]
        path.write_text(json.dumps(document))
        path.chmod(0o400)
    elif failure == "wrong-node":
        path = credentials.directory / "mio-node"
        path.chmod(0o600)
        path.write_bytes(b"node_id: other-node\n")
        path.chmod(0o400)
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
    path = credentials.directory / "mio-profile_commissioning-proposal.expected.json"
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
        monkeypatch.setattr(mio_commissioning, "read_mio_verification_inputs", refused)
    assert mio_entryd.commissioned_profile() is MioProfile.CORE


@pytest.mark.parametrize("changed", range(5))
def test_protected_state_change_during_verification_is_core(
    credentials, context, monkeypatch, changed
):
    _node(monkeypatch, context)
    credentials.save(commissioning_proposal_payload(**context, mio_profile="FULL"))
    actual = mio_commissioning.read_mio_verification_inputs()
    altered = list(actual)
    altered[changed] += b" "
    values = iter((actual, tuple(altered)))
    monkeypatch.setattr(mio_commissioning, "read_mio_verification_inputs", lambda: next(values))
    assert mio_entryd.commissioned_profile() is MioProfile.CORE


def test_environment_cannot_supply_missing_credentials(credentials, context, monkeypatch, tmp_path):
    _node(monkeypatch, context)
    credentials.save(commissioning_proposal_payload(**context, mio_profile="FULL"))
    alternate = tmp_path / "alternate"
    alternate.mkdir()
    for path in credentials.directory.glob("mio-profile_*"):
        path.rename(alternate / path.name)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(alternate))
    monkeypatch.setenv("AZAZEL_ROOT", str(alternate))
    assert mio_entryd.commissioned_profile() is MioProfile.CORE


@pytest.mark.parametrize("changed", range(5))
def test_cache_reuses_only_identical_input_bytes(credentials, monkeypatch, changed):
    # Exercise caching without requiring the optional Fabric extra.
    inputs = [b'{"operator":"operator-a","schema":"azazel-nexus/commissioning-proposal/v2","mio_profile":"FULL"}',
              b"payload", b"s" * 64, b"trust", b"node"]
    monkeypatch.setattr(mio_commissioning, "read_mio_verification_inputs", lambda: tuple(inputs))
    monkeypatch.setattr(mio_commissioning, "operator_trust_bytes", lambda raw: object())
    monkeypatch.setattr(mio_commissioning, "declared_node_bytes", lambda raw: SimpleNamespace(node_id="synthetic"))
    calls = []
    monkeypatch.setattr(mio_commissioning, "verify_retained_commissioning_proposal", lambda **kw: calls.append(kw))
    assert mio_commissioning.commissioned_profile() is MioProfile.FASTEST_PERMITTED
    assert mio_commissioning.commissioned_profile() is MioProfile.FASTEST_PERMITTED
    assert len(calls) == 1
    inputs[changed] += b" "
    assert mio_commissioning.commissioned_profile() is MioProfile.FASTEST_PERMITTED
    assert len(calls) == 2


@pytest.mark.parametrize("stage", ["read_mio_verification_inputs", "declared_node_bytes",
                                   "operator_trust_bytes", "verify_retained_commissioning_proposal"])
def test_unexpected_exception_is_core(credentials, monkeypatch, stage):
    inputs = (b'{"operator":"operator-a"}', b"payload", b"s" * 64, b"trust", b"node")
    monkeypatch.setattr(mio_commissioning, "read_mio_verification_inputs", lambda: inputs)
    monkeypatch.setattr(mio_commissioning, "declared_node_bytes", lambda raw: SimpleNamespace(node_id="synthetic"))
    monkeypatch.setattr(mio_commissioning, "operator_trust_bytes", lambda raw: object())
    def unexpected(*args, **kwargs):
        raise RuntimeError("synthetic unexpected failure")
    monkeypatch.setattr(mio_commissioning, stage, unexpected)
    assert mio_commissioning.commissioned_profile() is MioProfile.CORE


@pytest.mark.parametrize("name", ["mio-node", "mio-trust"])
def test_missing_verification_credential_is_core(credentials, name):
    credentials.save(b"synthetic")
    (credentials.directory / name).unlink()
    assert mio_commissioning.commissioned_profile() is MioProfile.CORE


def test_lab_marker_still_narrows_a_cached_ceiling(credentials, monkeypatch):
    monkeypatch.setattr(mio_commissioning, "read_mio_verification_inputs", lambda: (b"same",) * 5)
    import hashlib
    monkeypatch.setattr(mio_commissioning, "_cache_key", (hashlib.sha256(b"same").digest(),) * 5)
    monkeypatch.setattr(mio_commissioning, "_cache_result", MioProfile.FASTEST_PERMITTED)
    monkeypatch.setattr("azazel_nexus.lab_host.is_lab_host", lambda: True)
    assert mio_commissioning.commissioned_profile() is MioProfile.CORE


def test_changed_revocation_bytes_narrow_cached_verified_profile(credentials, context, monkeypatch):
    _node(monkeypatch, context)
    credentials.save(commissioning_proposal_payload(**context, mio_profile="FULL"))
    assert mio_commissioning.commissioned_profile() is MioProfile.FASTEST_PERMITTED
    path = credentials.directory / "mio-trust"
    path.chmod(0o600)
    document = json.loads(path.read_bytes())
    document["revoked"] = ["operator-a"]
    path.write_text(json.dumps(document))
    path.chmod(0o400)
    assert mio_commissioning.commissioned_profile() is MioProfile.CORE
    assert mio_commissioning.commissioned_profile() is MioProfile.CORE


def test_absent_optional_fabric_is_core(credentials, context, monkeypatch):
    _node(monkeypatch, context)
    credentials.save(commissioning_proposal_payload(**context, mio_profile="FULL"))
    monkeypatch.setattr("azazel_nexus.fabric_boundary._import_fabric", lambda: (None, "unavailable"))
    assert mio_commissioning.commissioned_profile() is MioProfile.CORE


@pytest.mark.parametrize("name", ["mio-trust", "mio-node"])
def test_the_unit_fallback_value_is_core_without_verifying(credentials, monkeypatch, name):
    # What systemd supplies when the source file is missing (SetCredential).
    inputs = [b'{"operator":"operator-a"}', b"payload", b"s" * 64, b"trust", b"node"]
    inputs[3 if name == "mio-trust" else 4] = mio_commissioning.MISSING_CREDENTIAL
    monkeypatch.setattr(mio_commissioning, "read_mio_verification_inputs", lambda: tuple(inputs))
    monkeypatch.setattr(mio_commissioning, "verify_retained_commissioning_proposal",
                        lambda **kw: pytest.fail("fallback reached verification"))
    assert mio_commissioning.commissioned_profile() is MioProfile.CORE


@pytest.mark.parametrize("uid,mode,accepted", [
    (0, 0o100440, True),        # systemd 257: root:root 0440 + ACL for the unit user
    ("self", 0o100400, True),   # older systemd: copy chowned to the unit user
    (0, 0o100444, False),       # readable by others
    (0, 0o100640, False),       # writable
    ("other", 0o100440, False), # neither root nor this process
])
def test_systemd_credential_ownership_is_accepted_as_systemd_presents_it(uid, mode, accepted):
    import os

    info = SimpleNamespace(st_uid=os.geteuid() if uid == "self" else 0 if uid == 0 else os.geteuid() + 1,
                           st_mode=mode)
    assert commissioning_draft._credential_owner_ok(info) is accepted
    # Ordinary private drafts keep the strict owner-only rule.
    assert commissioning_draft._private_owner_ok(info) is (uid == "self" and mode == 0o100400)


@pytest.mark.parametrize("index", [0, 1])
def test_a_locked_commissioning_volume_is_core_without_verifying(credentials, monkeypatch, index):
    # systemd supplies the fallback for a proposal file missing at unit start,
    # which is what a locked volume (an empty mount point) looks like (#244).
    inputs = [b'{"operator":"operator-a"}', b'{"operator":"operator-a"}', b"s" * 64,
              b"trust", b"node"]
    inputs[index] = mio_commissioning.MISSING_CREDENTIAL
    monkeypatch.setattr(mio_commissioning, "read_mio_verification_inputs", lambda: tuple(inputs))
    monkeypatch.setattr(mio_commissioning, "verify_retained_commissioning_proposal",
                        lambda **kw: pytest.fail("fallback reached verification"))
    assert mio_commissioning.commissioned_profile() is MioProfile.CORE


@pytest.mark.parametrize("names", [
    ("commissioning-proposal.expected.json", "commissioning-proposal.json"),
    ("commissioning-proposal.sig",),
])
def test_unit_fallback_files_for_the_proposal_are_core(credentials, context, monkeypatch, names):
    _node(monkeypatch, context)
    credentials.save(commissioning_proposal_payload(**context, mio_profile="FULL"))
    assert mio_commissioning.commissioned_profile() is MioProfile.FASTEST_PERMITTED
    for name in names:
        path = credentials.directory / ("mio-profile_" + name)
        path.chmod(0o600)
        path.write_bytes(mio_commissioning.MISSING_CREDENTIAL)
        path.chmod(0o400)
    assert mio_commissioning.commissioned_profile() is MioProfile.CORE
