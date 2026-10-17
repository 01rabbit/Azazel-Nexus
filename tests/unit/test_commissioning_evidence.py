"""Complete retained commissioning evidence and its protected binding key."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from azazel_nexus import commissioning_evidence
from azazel_nexus.commissioning_approval import commissioning_proposal_payload
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
    approval_message,
)

pytest.importorskip("azazel_fabric")
from azazel_fabric.provisioning_contracts import (  # noqa: E402
    HardwareInventory,
    ResourceProfile,
    TopologyProfile,
    content_digest,
)
from azazel_fabric.testing.provisioning import (  # noqa: E402
    golden_hardware_inventory,
    golden_resource_profile,
    golden_topology_profile,
)


@pytest.fixture
def context():
    return {
        "inventory": HardwareInventory.model_validate(golden_hardware_inventory()),
        "resource_profile": ResourceProfile.model_validate(golden_resource_profile()),
        "topology_profile": TopologyProfile.model_validate(golden_topology_profile()),
        "record_id": "record-synthetic",
        "operator": "operator-a",
        "confirmed_at": "2026-10-13T00:00:00Z",
    }


@pytest.fixture
def signed(context):
    key = SigningKey.generate()
    payload = commissioning_proposal_payload(**context)
    signature = key.sign(
        approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL, payload)
    ).signature
    return {
        "key": key,
        "payload": payload,
        "signature": signature,
        "trust": OperatorTrust({"operator-a": bytes(key.verify_key)}),
    }


def _current_inventory(inventory, *, inventory_id="inv-current-2", collected_at=None):
    if collected_at is None:
        collected_at = datetime(2026, 10, 14, tzinfo=timezone.utc)
    current = inventory.model_copy(
        update={"inventory_id": inventory_id, "collected_at": collected_at}
    )
    normalized = HardwareInventory.model_validate(current.model_dump(mode="json"))
    return normalized.model_copy(
        update={
            "inventory_digest": content_digest(
                normalized, digest_field="inventory_digest"
            )
        }
    )


def _verify(context, signed, *, current=None, **overrides):
    return commissioning_evidence.verify_commissioning_evidence(
        trust=overrides.pop("trust", signed["trust"]),
        expected_payload=overrides.pop(
            "expected_payload", commissioning_proposal_payload(**context)
        ),
        payload=overrides.pop("payload", signed["payload"]),
        signature=overrides.pop("signature", signed["signature"]),
        node_id=overrides.pop("node_id", context["inventory"].node_id),
        current_inventory=overrides.pop(
            "current_inventory", current or context["inventory"]
        ),
        protection_key=overrides.pop("protection_key", b"p" * 32),
        **overrides,
    )


def test_complete_signed_proposal_is_retained_and_repr_hides_evidence(context, signed):
    current = _current_inventory(context["inventory"])

    evidence = _verify(context, signed, current=current)

    assert evidence.payload == signed["payload"]
    assert evidence.signature == signed["signature"]
    assert evidence.current_inventory == json.dumps(
        current.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    rendered = repr(evidence)
    assert signed["payload"].decode() not in rendered
    assert signed["signature"].hex() not in rendered
    assert evidence.current_inventory.decode() not in rendered
    assert evidence.binding not in rendered


def test_metadata_only_new_current_snapshot_preserves_hmac_binding(context, signed):
    first = _verify(context, signed, current=context["inventory"])
    second_current = _current_inventory(
        context["inventory"],
        inventory_id="inv-current-new-id",
        collected_at=datetime(2026, 10, 15, tzinfo=timezone.utc),
    )

    second = _verify(context, signed, current=second_current)

    assert first.binding == second.binding
    assert first.current_inventory != second.current_inventory


def test_protection_key_changes_the_binding(context, signed):
    first = _verify(context, signed, protection_key=b"a" * 32)
    second = _verify(context, signed, protection_key=b"b" * 32)

    assert first.binding != second.binding


def test_changed_resource_payload_with_its_own_valid_signature_changes_binding(
    context, signed
):
    revised = dict(context)
    revised["resource_profile"] = context["resource_profile"].model_copy(
        update={
            "usable_storage_mib": context["resource_profile"].usable_storage_mib + 1
        }
    )
    changed_payload = commissioning_proposal_payload(**revised)
    changed_signature = (
        signed["key"]
        .sign(approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL, changed_payload))
        .signature
    )

    original = _verify(context, signed)
    changed = _verify(
        revised,
        {**signed, "payload": changed_payload, "signature": changed_signature},
    )

    assert changed.payload == changed_payload
    assert changed.binding != original.binding


@pytest.mark.parametrize(
    "failure", ["candidate", "wrong-key", "signature", "purpose", "node"]
)
def test_unretained_or_misattributed_approval_is_refused(context, signed, failure):
    kwargs = {}
    if failure == "candidate":
        revised = dict(context)
        revised["record_id"] = "record-other-synthetic"
        kwargs["payload"] = commissioning_proposal_payload(**revised)
        kwargs["signature"] = (
            signed["key"]
            .sign(
                approval_message(
                    ApprovalPurpose.COMMISSIONING_PROPOSAL, kwargs["payload"]
                )
            )
            .signature
        )
    elif failure == "wrong-key":
        kwargs["trust"] = OperatorTrust(
            {"operator-a": bytes(SigningKey.generate().verify_key)}
        )
    elif failure == "signature":
        kwargs["signature"] = (
            bytes([signed["signature"][0] ^ 1]) + signed["signature"][1:]
        )
    elif failure == "purpose":
        kwargs["signature"] = (
            signed["key"]
            .sign(approval_message(ApprovalPurpose.COMMISSIONING, signed["payload"]))
            .signature
        )
    else:
        kwargs["node_id"] = "node-other"

    with pytest.raises(ApprovalRefused):
        _verify(context, signed, **kwargs)


def test_changed_current_hardware_with_valid_digest_is_refused(context, signed):
    altered = context["inventory"].model_copy(
        update={
            "platform": context["inventory"].platform.model_copy(
                update={"vendor": "Synthetic Different Vendor"}
            )
        }
    )
    current = _current_inventory(altered)

    with pytest.raises(ApprovalRefused):
        _verify(context, signed, current=current)


def test_read_key_at_accepts_private_regular_key_in_private_directory(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    key = b"k" * 32
    key_path = directory / "commissioning.key"
    key_path.write_bytes(key)
    key_path.chmod(0o600)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert (
            commissioning_evidence._read_key_at(directory_fd, owner=os.geteuid()) == key
        )
    finally:
        os.close(directory_fd)


def _read_key(directory: Path, *, owner=None):
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return commissioning_evidence._read_key_at(
            directory_fd, owner=os.geteuid() if owner is None else owner
        )
    finally:
        os.close(directory_fd)


@pytest.mark.parametrize(
    "case",
    [
        "wrong-owner",
        "directory-mode",
        "file-mode",
        "symlink",
        "hardlink",
        "fifo",
        "short",
        "oversized",
    ],
)
def test_read_key_at_refuses_unprotected_or_unbounded_key_files(tmp_path, case):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "commissioning.key"
    path.write_bytes(b"k" * 32)
    path.chmod(0o600)
    owner = os.geteuid()
    if case == "wrong-owner":
        owner += 1
    elif case == "directory-mode":
        directory.chmod(0o750)
    elif case == "file-mode":
        path.chmod(0o640)
    elif case == "symlink":
        path.unlink()
        path.symlink_to(directory / "target")
    elif case == "hardlink":
        os.link(path, directory / "second-link")
    elif case == "fifo":
        path.unlink()
        os.mkfifo(path, 0o600)
    elif case == "short":
        path.write_bytes(b"k" * 31)
    else:
        path.write_bytes(b"k" * 4097)

    expected_error = (
        (ApprovalRefused, OSError) if case == "symlink" else ApprovalRefused
    )
    with pytest.raises(expected_error):
        _read_key(directory, owner=owner)


def test_read_key_at_refuses_a_file_changed_during_read(tmp_path, monkeypatch):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "commissioning.key"
    path.write_bytes(b"k" * 32)
    path.chmod(0o600)
    original_read = os.read
    changed = False

    def read_then_change(fd, size):
        nonlocal changed
        data = original_read(fd, size)
        if not changed:
            changed = True
            with path.open("ab") as stream:
                stream.write(b"x")
        return data

    monkeypatch.setattr(commissioning_evidence.os, "read", read_then_change)

    with pytest.raises(ApprovalRefused):
        _read_key(directory)
