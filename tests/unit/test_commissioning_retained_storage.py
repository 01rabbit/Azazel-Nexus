"""Protected retained proposal inputs, exercised with synthetic records only."""

import fcntl
import os
from pathlib import Path

import pytest

from azazel_nexus import commissioning_draft
from azazel_nexus.commissioning_approval import commissioning_proposal_payload
from azazel_nexus.fabric_boundary import CommissioningRecordUnavailable
from azazel_nexus.commissioning_draft import DraftRefused

pytest.importorskip("azazel_fabric")
from azazel_fabric.provisioning_contracts import HardwareInventory, ResourceProfile, TopologyProfile
from azazel_fabric.testing.provisioning import (
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
def protected_dir(tmp_path, monkeypatch):
    directory = tmp_path / "commissioning"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(commissioning_draft, "COMMISSIONING_DIR", directory)
    profile_dir = tmp_path / "mio-profile"
    profile_dir.mkdir(mode=0o700)
    monkeypatch.setattr(commissioning_draft, "MIO_PROFILE_DIR", profile_dir)
    monkeypatch.setattr(commissioning_draft, "PROTECTION_KEY", tmp_path / "test-key")
    monkeypatch.setattr(commissioning_draft, "luks_backed", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(commissioning_draft, "read_protection_key", lambda _path: b"synthetic-key")
    return directory


def _proposal_files(directory: Path) -> tuple[Path, Path, Path]:
    return tuple(directory / name for name in commissioning_draft._PROPOSAL_FILES)


def _write_private(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def _retain_with_signature(context, directory):
    commissioning_draft.retain_proposal_context(**context)
    expected, payload, signature = _proposal_files(directory)
    _write_private(signature, b"s" * 64)
    return expected, payload, signature


def test_retention_writes_canonical_equal_copies_and_reads_manual_signature(context, protected_dir):
    expected_bytes = commissioning_proposal_payload(**context)

    commissioning_draft.retain_proposal_context(**context)

    expected, payload, signature = _proposal_files(protected_dir)
    assert expected.read_bytes() == expected_bytes
    assert payload.read_bytes() == expected_bytes
    assert expected.stat().st_mode & 0o777 == 0o600
    assert payload.stat().st_mode & 0o777 == 0o600
    assert not signature.exists()
    # The raw-identity proposal stays in encrypted storage only (#244).
    assert list(commissioning_draft.MIO_PROFILE_DIR.iterdir()) == []

    _write_private(signature, b"x" * 64)
    assert commissioning_draft.read_proposal_review_inputs() == (
        expected_bytes,
        expected_bytes,
        b"x" * 64,
    )


@pytest.mark.parametrize("missing_index", [0, 1, 2])
def test_reader_requires_all_three_inputs(context, protected_dir, missing_index):
    files = _retain_with_signature(context, protected_dir)
    files[missing_index].unlink()

    with pytest.raises(DraftRefused):
        commissioning_draft.read_proposal_review_inputs()


def test_reader_refuses_short_signature(context, protected_dir):
    files = _retain_with_signature(context, protected_dir)
    signature = files[2]
    _write_private(signature, b"s" * 63)

    with pytest.raises(DraftRefused):
        commissioning_draft.read_proposal_review_inputs()


def test_reader_refuses_while_directory_flock_is_held(context, protected_dir):
    _retain_with_signature(context, protected_dir)
    directory_fd = os.open(protected_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(DraftRefused):
            commissioning_draft.read_proposal_review_inputs()
    finally:
        os.close(directory_fd)


def test_reader_refuses_mismatched_retained_copies(context, protected_dir):
    expected, payload, signature = _retain_with_signature(context, protected_dir)
    _write_private(payload, expected.read_bytes() + b" ")

    with pytest.raises(DraftRefused):
        commissioning_draft.read_proposal_review_inputs()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "permissions", "fifo", "oversized"])
def test_reader_refuses_untrusted_or_unbounded_input(context, protected_dir, monkeypatch, kind):
    expected, payload, signature = _retain_with_signature(context, protected_dir)
    target = payload
    if kind == "symlink":
        target.unlink()
        target.symlink_to(expected)
    elif kind == "hardlink":
        target.unlink()
        os.link(expected, target)
    elif kind == "permissions":
        target.chmod(0o640)
    elif kind == "fifo":
        target.unlink()
        os.mkfifo(target, 0o600)
    else:
        monkeypatch.setattr(commissioning_draft, "MAX_APPROVAL_BYTES", 4)
        _write_private(target, b"x" * 5)

    with pytest.raises(DraftRefused):
        commissioning_draft.read_proposal_review_inputs()


def test_reader_refuses_insecure_directory_permissions(context, protected_dir):
    _retain_with_signature(context, protected_dir)
    protected_dir.chmod(0o770)

    with pytest.raises(DraftRefused):
        commissioning_draft.read_proposal_review_inputs()


def test_existing_legacy_export_is_not_migrated(context, protected_dir):
    legacy_payload = commissioning_proposal_payload(**context)
    commissioning_draft.export_proposal(legacy_payload)

    with pytest.raises(DraftRefused):
        commissioning_draft.read_proposal_review_inputs()
    with pytest.raises(DraftRefused):
        commissioning_draft.retain_proposal_context(**context)

    expected, payload, signature = _proposal_files(protected_dir)
    assert not expected.exists()
    assert payload.read_bytes() == legacy_payload
    assert not signature.exists()


@pytest.mark.parametrize("existing_index", [0, 1, 2])
def test_retention_refuses_each_preexisting_proposal_path_unchanged(
    context, protected_dir, existing_index
):
    files = _proposal_files(protected_dir)
    _write_private(files[existing_index], b"preexisting synthetic state")
    before = {path.name: path.read_bytes() for path in protected_dir.iterdir()}

    with pytest.raises(DraftRefused):
        commissioning_draft.retain_proposal_context(**context)

    assert {path.name: path.read_bytes() for path in protected_dir.iterdir()} == before


def test_partial_write_failure_is_left_for_inspection_and_retry_does_not_overwrite(
    context, protected_dir, monkeypatch
):
    create_private = commissioning_draft._create_private_at
    expected, payload, signature = _proposal_files(protected_dir)

    def fail_on_second(directory_fd, filename, content):
        if filename == payload.name:
            raise OSError("synthetic second-file failure")
        create_private(directory_fd, filename, content)

    monkeypatch.setattr(commissioning_draft, "_create_private_at", fail_on_second)
    with pytest.raises(DraftRefused):
        commissioning_draft.retain_proposal_context(**context)
    retained_bytes = expected.read_bytes()
    assert retained_bytes == commissioning_proposal_payload(**context)
    assert not payload.exists()
    assert not signature.exists()

    monkeypatch.setattr(commissioning_draft, "_create_private_at", create_private)
    with pytest.raises(DraftRefused):
        commissioning_draft.retain_proposal_context(**context)
    assert expected.read_bytes() == retained_bytes
    assert not payload.exists()
    assert not signature.exists()


def test_retention_refuses_while_directory_flock_is_held(context, protected_dir):
    directory_fd = os.open(protected_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(DraftRefused):
            commissioning_draft.retain_proposal_context(**context)
    finally:
        os.close(directory_fd)

    assert not any(path.exists() for path in _proposal_files(protected_dir))


def test_invalid_context_creates_no_proposal_files(context, protected_dir):
    context["confirmed_at"] = "2000-01-01T00:00:00Z"

    with pytest.raises(CommissioningRecordUnavailable):
        commissioning_draft.retain_proposal_context(**context)

    assert not any(path.exists() for path in _proposal_files(protected_dir))


@pytest.mark.parametrize("field", ["inventory", "resource_profile", "topology_profile"])
def test_retention_cannot_substitute_candidate_bytes_for_local_models(context, protected_dir, field):
    context[field] = commissioning_proposal_payload(**context)
    with pytest.raises(CommissioningRecordUnavailable):
        commissioning_draft.retain_proposal_context(**context)
    assert list(protected_dir.iterdir()) == []


def _raw_identity_values(context) -> set[str]:
    """Every serial, model name and permanent MAC in the synthetic inventory."""
    inventory = context["inventory"].model_dump(mode="json")
    values = {inventory["platform"]["board_serial"]}
    for device in inventory["storage_devices"]:
        values |= {device["serial"], device["model_name"]}
    for interface in inventory["interfaces"]:
        values |= {interface["permanent_mac"], interface["serial"]}
    return {value for value in values if value}


def test_no_raw_identity_reaches_the_unencrypted_profile_directory(context, protected_dir):
    """Retention and a successful publication leave only the 64-byte signature."""
    commissioning_draft.retain_proposal_context(**context)
    expected, payload, signature = _proposal_files(protected_dir)
    identity = _raw_identity_values(context)
    assert identity, "the synthetic inventory must carry identity for this test to mean anything"
    assert all(value.encode() in payload.read_bytes() for value in identity)
    _write_private(signature, b"s" * 64)
    commissioning_draft.publish_mio_profile_signature(*commissioning_draft.read_proposal_review_inputs())
    profile = commissioning_draft.MIO_PROFILE_DIR
    assert [p.name for p in profile.iterdir()] == ["commissioning-proposal.sig"]
    published = (profile / "commissioning-proposal.sig").read_bytes()
    assert published == b"s" * 64
    assert not any(value.encode() in published for value in identity)
    # The encrypted originals are untouched and still what entryd will load.
    assert expected.read_bytes() == payload.read_bytes() == commissioning_proposal_payload(**context)
