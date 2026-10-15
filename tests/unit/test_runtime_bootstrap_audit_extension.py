"""Existing audit extensions must preserve an independently pinned prefix."""

import os

import pytest

from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_audit
from test_runtime_bootstrap_audit import _chain  # noqa: F401


def inspect(directory, expected_head, *, allow_extension=True):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return bootstrap_audit._inspect_at(
            fd, owner=os.getuid(), expected_head=expected_head,
            max_total_bytes=65536, max_segments=8,
            allow_extension=allow_extension,
        )
    finally:
        os.close(fd)


def test_valid_next_day_extension_succeeds_only_when_explicitly_allowed(tmp_path):
    ledger = _chain(tmp_path / "audit", days=("2026-10-12",))
    old_head = ledger.head()
    ledger.append({"kind": "test", "day": "2026-10-13"}, day="2026-10-13")
    for segment in ledger.segments():
        segment.chmod(0o600)

    observed = inspect(ledger.root, old_head, allow_extension=True)

    assert (observed.sequence, observed.digest) == ledger.head()
    assert observed.sequence == old_head[0] + 1
    with pytest.raises(ApprovalRefused):
        inspect(ledger.root, old_head, allow_extension=False)


def test_unchanged_audit_chain_is_accepted_as_extension(tmp_path):
    ledger = _chain(tmp_path / "audit", days=("2026-10-12", "2026-10-13"))

    observed = inspect(ledger.root, ledger.head(), allow_extension=True)

    assert (observed.sequence, observed.digest) == ledger.head()


def test_truncation_before_pinned_anchor_is_refused(tmp_path):
    ledger = _chain(tmp_path / "audit", days=("2026-10-12", "2026-10-13"))
    old_head = ledger.head()
    second_segment = ledger.segments()[-1]
    second_segment.write_bytes(b"")

    with pytest.raises(ApprovalRefused):
        inspect(ledger.root, old_head, allow_extension=True)


def test_different_valid_chain_with_replaced_anchor_is_refused(tmp_path):
    original = _chain(tmp_path / "original", days=("2026-10-12", "2026-10-13"))
    changed = _chain(tmp_path / "changed", days=("2026-10-12", "2026-10-14"))
    assert changed.head()[0] == original.head()[0]
    assert changed.head()[1] != original.head()[1]

    with pytest.raises(ApprovalRefused):
        inspect(changed.root, original.head(), allow_extension=True)


def test_segment_replacement_between_snapshots_refuses(tmp_path, monkeypatch):
    ledger = _chain(tmp_path / "audit", days=("2026-10-12", "2026-10-13"))
    original_head = ledger.head()
    snapshot = bootstrap_audit._snapshot
    calls = []

    def replace_after_first_snapshot(*args, **kwargs):
        result = snapshot(*args, **kwargs)
        calls.append(None)
        if len(calls) == 1:
            segment = ledger.segments()[0]
            replacement = ledger.root / "replacement.jsonl"
            replacement.write_bytes(segment.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(segment)
        return result

    monkeypatch.setattr(bootstrap_audit, "_snapshot", replace_after_first_snapshot)

    with pytest.raises(ApprovalRefused):
        inspect(ledger.root, original_head, allow_extension=True)
    assert len(calls) == 2


def test_extension_flag_requires_exact_boolean_true(tmp_path):
    ledger = _chain(tmp_path / "audit", days=("2026-10-12",))
    fd = os.open(ledger.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(ApprovalRefused):
            bootstrap_audit._inspect_at(
                fd, owner=os.getuid(), expected_head=ledger.head(),
                max_total_bytes=65536, max_segments=8, allow_extension=1,
            )
    finally:
        os.close(fd)


def test_public_extension_inspector_uses_only_redirected_ordinary_directory(
    tmp_path, monkeypatch,
):
    ledger = _chain(tmp_path / "audit", days=("2026-10-12",))
    owner = os.getuid()
    opened = []
    monkeypatch.setattr(
        bootstrap_audit.pwd, "getpwnam",
        lambda name: type("Account", (), {"pw_uid": owner})(),
    )

    def open_ordinary_directory(actual_owner):
        assert actual_owner == owner
        opened.append(actual_owner)
        return os.open(ledger.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    monkeypatch.setattr(bootstrap_audit, "_open_ledger", open_ordinary_directory)

    observed = bootstrap_audit.inspect_audit_extension(
        expected_head=ledger.head(), max_total_bytes=65536, max_segments=8,
    )

    assert (observed.sequence, observed.digest) == ledger.head()
    assert opened == [owner, owner]
