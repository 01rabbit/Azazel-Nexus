"""Protected storage tests for an externally prepared commissioning proposal."""

import os

import pytest

from azazel_nexus import commissioning_draft
from azazel_nexus.commissioning_draft import DraftRefused, export_proposal
from azazel_nexus.operator_trust import MAX_APPROVAL_BYTES


@pytest.fixture(autouse=True)
def protected_synthetic_store(tmp_path, monkeypatch):
    monkeypatch.setattr(commissioning_draft, "COMMISSIONING_DIR", tmp_path)
    monkeypatch.setattr(commissioning_draft, "luks_backed", lambda *a, **kw: True)
    monkeypatch.setattr(
        commissioning_draft, "read_protection_key", lambda path: b"synthetic-test-only"
    )


def test_proposal_roundtrips_as_private_fixed_file(tmp_path):
    payload = b'{"schema":"synthetic-proposal"}'

    export_proposal(payload)

    output = tmp_path / "commissioning-proposal.json"
    assert output.read_bytes() == payload
    assert output.stat().st_mode & 0o777 == 0o600
    assert output.stat().st_nlink == 1


def test_existing_proposal_file_is_never_overwritten(tmp_path):
    output = tmp_path / "commissioning-proposal.json"
    output.write_bytes(b"existing user data")

    with pytest.raises(DraftRefused):
        export_proposal(b"new proposal")

    assert output.read_bytes() == b"existing user data"


def test_proposal_symlink_is_refused_without_modifying_target(tmp_path):
    target = tmp_path / "saved"
    target.write_bytes(b"existing")
    (tmp_path / "commissioning-proposal.json").symlink_to(target)

    with pytest.raises(DraftRefused):
        export_proposal(b"new proposal")

    assert target.read_bytes() == b"existing"


@pytest.mark.parametrize(
    "payload",
    [b"", bytearray(b"not exact bytes"), "not bytes", b"x" * (MAX_APPROVAL_BYTES + 1)],
)
def test_invalid_or_oversized_payload_creates_no_file(tmp_path, payload):
    with pytest.raises(DraftRefused):
        export_proposal(payload)

    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("protection", ["encryption", "key"])
def test_protection_failure_creates_no_proposal(tmp_path, monkeypatch, protection):
    if protection == "encryption":
        monkeypatch.setattr(commissioning_draft, "luks_backed", lambda *a, **kw: False)
    else:
        monkeypatch.setattr(commissioning_draft, "read_protection_key", lambda path: None)

    with pytest.raises(DraftRefused):
        export_proposal(b"proposal")

    assert list(tmp_path.iterdir()) == []


def test_partial_write_failure_leaves_private_file_and_retry_refuses(
    tmp_path, monkeypatch, private_os
):
    private_os(commissioning_draft)
    payload = b"proposal payload that requires multiple writes"
    output = tmp_path / "commissioning-proposal.json"
    original_write = os.write
    calls = 0

    def partial_then_fail(fd, data):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_write(fd, data[:5])
        raise OSError("synthetic write failure")

    monkeypatch.setattr(commissioning_draft.os, "write", partial_then_fail)
    with pytest.raises(DraftRefused):
        export_proposal(payload)

    assert output.read_bytes() == payload[:5]
    assert output.stat().st_mode & 0o777 == 0o600

    monkeypatch.setattr(commissioning_draft.os, "write", original_write)
    with pytest.raises(DraftRefused):
        export_proposal(payload)
    assert output.read_bytes() == payload[:5]


def test_no_progress_write_leaves_private_file_and_retry_refuses(tmp_path, monkeypatch, private_os):
    private_os(commissioning_draft)
    output = tmp_path / "commissioning-proposal.json"
    monkeypatch.setattr(commissioning_draft.os, "write", lambda *args: 0)

    with pytest.raises(DraftRefused):
        export_proposal(b"proposal")

    assert output.read_bytes() == b""
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(DraftRefused):
        export_proposal(b"proposal")
    assert output.read_bytes() == b""


def test_fsync_failure_leaves_private_file_and_retry_refuses(tmp_path, monkeypatch, private_os):
    private_os(commissioning_draft)
    payload = b"proposal"
    output = tmp_path / "commissioning-proposal.json"

    def failed_fsync(fd):
        raise OSError("synthetic fsync failure")

    with monkeypatch.context() as patcher:
        patcher.setattr(commissioning_draft.os, "fsync", failed_fsync)
        with pytest.raises(DraftRefused):
            export_proposal(payload)

    assert output.read_bytes() == payload
    assert output.stat().st_mode & 0o777 == 0o600

    with pytest.raises(DraftRefused):
        export_proposal(payload)
    assert output.read_bytes() == payload


def test_proposal_export_requires_owned_protected_directory(tmp_path, monkeypatch, private_os):
    private_os(commissioning_draft)
    monkeypatch.setattr(commissioning_draft.os, "geteuid", lambda: tmp_path.stat().st_uid + 1)

    with pytest.raises(DraftRefused):
        export_proposal(b"proposal")

    assert list(tmp_path.iterdir()) == []
