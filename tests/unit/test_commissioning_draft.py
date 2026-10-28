"""Private unsigned export tests; no real inventory or operator credentials."""

import json
import os
import stat

import pytest

from azazel_nexus import commissioning_draft
from azazel_nexus.commissioning import CommissioningRecord, ConfirmedRole
from azazel_nexus.commissioning_draft import (
    DraftRefused, draft_bytes, export_draft, read_draft_review_inputs,
)


@pytest.fixture(autouse=True)
def protected_synthetic_store(tmp_path, monkeypatch):
    monkeypatch.setattr(commissioning_draft, "COMMISSIONING_DIR", tmp_path)
    monkeypatch.setattr(commissioning_draft, "luks_backed", lambda *a, **kw: True)
    monkeypatch.setattr(commissioning_draft, "read_protection_key", lambda path: b"synthetic-test-only")


@pytest.fixture
def record():
    return CommissioningRecord(roles=(), profiles_present=("hardware",),
                               created_at="2026-10-13T00:00:00Z")


def test_export_is_explicitly_unsigned_without_invented_generation(record, tmp_path):
    tmp_path.chmod(0o700)
    output = tmp_path / "commissioning-draft.json"
    export_draft(record, output)
    raw = output.read_bytes()
    assert raw == draft_bytes(record)
    document = json.loads(raw)
    assert document["status"] == "unsigned-draft"
    assert document["record"]["digest"] == record.digest()
    assert "generation" not in document["record"]
    assert document["profiles_are"] == "operator-assertions-not-measurements"
    assert output.stat().st_mode & 0o777 == 0o600


def test_existing_file_is_never_overwritten(record, tmp_path):
    output = tmp_path / "commissioning-draft.json"
    output.write_bytes(b"existing user data")
    with pytest.raises(DraftRefused):
        export_draft(record, output)
    assert output.read_bytes() == b"existing user data"


def test_symlink_target_is_not_modified(record, tmp_path):
    target = tmp_path / "saved"
    target.write_bytes(b"existing")
    output = tmp_path / "commissioning-draft.json"
    output.symlink_to(target)
    with pytest.raises(DraftRefused):
        export_draft(record, output)
    assert target.read_bytes() == b"existing"


def test_symlink_parent_is_not_followed(record, tmp_path, monkeypatch):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(private, target_is_directory=True)
    monkeypatch.setattr(commissioning_draft, "COMMISSIONING_DIR", alias)
    with pytest.raises(DraftRefused):
        export_draft(record, alias / "commissioning-draft.json")
    assert list(private.iterdir()) == []


@pytest.mark.parametrize("mode", [0o720, 0o770, 0o701, 0o702, 0o704, 0o707, 0o777])
def test_shared_directory_is_refused(record, tmp_path, mode):
    tmp_path.chmod(mode)
    with pytest.raises(DraftRefused):
        export_draft(record, tmp_path / "commissioning-draft.json")
    assert list(tmp_path.iterdir()) == []


def test_installer_directory_mode_preserves_private_payload(record, tmp_path):
    tmp_path.chmod(0o750)
    path = tmp_path / "commissioning-draft.json"
    export_draft(record, path)
    assert path.stat().st_mode & 0o777 == 0o600
    signature = tmp_path / "commissioning-draft.sig"
    signature.write_bytes(b"s" * 64)
    signature.chmod(0o600)
    payload, read_signature = commissioning_draft.read_draft_review_inputs()
    assert payload == path.read_bytes()
    assert read_signature == b"s" * 64


def test_foreign_owner_is_refused(record, tmp_path, monkeypatch, private_os):
    private_os(commissioning_draft)
    monkeypatch.setattr(commissioning_draft.os, "geteuid", lambda: tmp_path.stat().st_uid + 1)
    with pytest.raises(DraftRefused):
        export_draft(record, tmp_path / "commissioning-draft.json")


def test_bounded_payload_is_checked_before_creating_file(tmp_path):
    huge = CommissioningRecord(roles=(), profiles_present=("x" * 70000,), created_at="synthetic")
    with pytest.raises(DraftRefused):
        export_draft(huge, tmp_path / "commissioning-draft.json")
    assert list(tmp_path.iterdir()) == []


def test_failed_write_reports_failure_and_leaves_only_private_incomplete_file(record, tmp_path, monkeypatch, private_os):
    private_os(commissioning_draft)
    monkeypatch.setattr(commissioning_draft.os, "write", lambda *args: 0)
    output = tmp_path / "commissioning-draft.json"
    with pytest.raises(DraftRefused, match="inspect destination"):
        export_draft(record, output)
    assert output.stat().st_mode & 0o777 == 0o600
    assert output.read_bytes() == b""


@pytest.mark.parametrize("missing", ["encryption", "key"])
def test_role_bearing_draft_never_reaches_unprotected_storage(tmp_path, monkeypatch, missing):
    if missing == "encryption":
        monkeypatch.setattr(commissioning_draft, "luks_backed", lambda *a, **kw: False)
    else:
        monkeypatch.setattr(commissioning_draft, "read_protection_key", lambda path: None)
    record = CommissioningRecord(
        roles=(ConfirmedRole(composite=(("mac", "02:00:00:00:00:01"),),
                             role="observation", confirmed_by="synthetic",
                             confirmed_at="2026-10-13T00:00:00Z"),),
        profiles_present=(), created_at="2026-10-13T00:00:00Z",
    )
    with pytest.raises(DraftRefused):
        export_draft(record, tmp_path / "commissioning-draft.json")
    assert list(tmp_path.iterdir()) == []


def test_an_arbitrary_private_destination_is_refused(record, tmp_path):
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    with pytest.raises(DraftRefused):
        export_draft(record, other / "commissioning-draft.json")
    assert list(other.iterdir()) == []


def test_protected_reader_returns_only_fixed_draft_and_signature(record, tmp_path):
    export_draft(record, tmp_path / "commissioning-draft.json")
    signature = tmp_path / "commissioning-draft.sig"
    signature.write_bytes(b"s" * 64)
    signature.chmod(0o600)
    assert read_draft_review_inputs() == (draft_bytes(record), b"s" * 64)


@pytest.mark.parametrize("fault", ["missing", "short", "oversized", "symlink", "hardlink", "public"])
def test_unprotected_or_invalid_signature_input_is_refused(record, tmp_path, fault):
    export_draft(record, tmp_path / "commissioning-draft.json")
    signature = tmp_path / "commissioning-draft.sig"
    if fault != "missing":
        signature.write_bytes(b"s" * ({"short": 63, "oversized": 65}.get(fault, 64)))
        signature.chmod(0o600)
    if fault == "symlink":
        signature.rename(tmp_path / "saved")
        signature.symlink_to(tmp_path / "saved")
    elif fault == "hardlink":
        os.link(signature, tmp_path / "alias")
    elif fault == "public":
        signature.chmod(0o644)
    with pytest.raises(DraftRefused):
        read_draft_review_inputs()


def test_review_reader_checks_encryption_before_reading_any_payload(record, tmp_path, monkeypatch):
    export_draft(record, tmp_path / "commissioning-draft.json")
    monkeypatch.setattr(commissioning_draft, "luks_backed", lambda *a, **kw: False)
    def forbidden(*args, **kwargs):
        raise AssertionError("unprotected payload read")
    monkeypatch.setattr(commissioning_draft, "_read_private", forbidden)
    with pytest.raises(DraftRefused, match="encrypted"):
        read_draft_review_inputs()


def test_review_reader_checks_key_before_reading_any_payload(record, tmp_path, monkeypatch):
    export_draft(record, tmp_path / "commissioning-draft.json")
    monkeypatch.setattr(commissioning_draft, "read_protection_key", lambda path: None)
    def forbidden(*args, **kwargs):
        raise AssertionError("unprotected payload read")
    monkeypatch.setattr(commissioning_draft, "_read_private", forbidden)
    with pytest.raises(DraftRefused, match="key"):
        read_draft_review_inputs()


def test_changed_draft_is_refused_during_read(record, tmp_path, monkeypatch, private_os):
    private_os(commissioning_draft)
    path = tmp_path / "commissioning-draft.json"
    export_draft(record, path)
    original = os.read
    changed = False
    def changed_read(fd, size):
        nonlocal changed
        result = original(fd, size)
        if not changed:
            changed = True
            path.write_bytes(b"changed")
        return result
    monkeypatch.setattr(commissioning_draft.os, "read", changed_read)
    with pytest.raises(DraftRefused, match="changed while reading"):
        read_draft_review_inputs()


def test_nonregular_input_metadata_is_refused_without_reading(record, tmp_path, monkeypatch, private_os):
    # Ordinary file only: simulate FIFO metadata, never create/open a real FIFO.
    private_os(commissioning_draft)
    export_draft(record, tmp_path / "commissioning-draft.json")
    original = os.fstat
    def fifo_metadata(fd):
        info = original(fd)
        if stat.S_ISREG(info.st_mode):
            values = list(info)
            values[0] = stat.S_IFIFO | 0o600
            return os.stat_result(values)
        return info
    def forbidden(*args):
        raise AssertionError("nonregular input was read")
    monkeypatch.setattr(commissioning_draft.os, "fstat", fifo_metadata)
    monkeypatch.setattr(commissioning_draft.os, "read", forbidden)
    with pytest.raises(DraftRefused, match="private draft input refused"):
        read_draft_review_inputs()
