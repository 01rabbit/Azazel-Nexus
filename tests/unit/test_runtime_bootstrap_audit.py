"""Read-only continuity checks for existing runtime audit segments."""

import json
import os
from pathlib import Path

import pytest

from azazel_nexus.audit import GENESIS_HASH, AuditLedger
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.auditd import SegmentedLedger
from azazel_nexus_runtime import bootstrap_audit
from azazel_nexus_runtime.bootstrap_audit import AuditObservation, _inspect_at

OWNER = os.getuid()
DAY1 = "2026-10-12"
DAY2 = "2026-10-13"


def _chain(directory: Path, *, days=(DAY1, DAY2)):
    directory.mkdir()
    directory.chmod(0o700)
    ledger = SegmentedLedger(directory)
    for day in days:
        ledger.append({"kind": "test", "day": day}, day=day)
    for path in ledger.segments():
        path.chmod(0o600)
    ledger.verify()
    return ledger


def _head(ledger):
    return ledger.head()


def _observe(directory: Path, expected_head=None, *, max_total_bytes=65536, max_segments=8):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return _inspect_at(
            fd,
            owner=OWNER,
            expected_head=expected_head,
            max_total_bytes=max_total_bytes,
            max_segments=max_segments,
        )
    finally:
        os.close(fd)


def _records(directory: Path):
    paths = sorted(directory.glob("*.jsonl"))
    return paths, [path.read_text(encoding="utf-8").splitlines() for path in paths]


def _write_records(paths, records):
    for path, lines in zip(paths, records):
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_authentic_multi_day_chain_returns_observation(tmp_path):
    ledger = _chain(tmp_path / "audit")
    result = _observe(ledger.root, _head(ledger))
    assert result == AuditObservation(*_head(ledger), 2, sum(
        path.stat().st_size for path in ledger.segments()
    ))
    assert result.assurance == "LOCAL_CONTINUITY_ONLY"


def test_observation_cannot_be_constructed_with_an_anchored_assurance_flag():
    with pytest.raises(TypeError):
        AuditObservation(1, "a" * 64, 1, 100, assurance="ROLLBACK_ANCHORED")


def test_blank_lines_inside_a_valid_segment_are_ignored(tmp_path):
    ledger = _chain(tmp_path / "audit", days=(DAY1,))
    expected = _head(ledger)
    segment = ledger.segments()[0]
    segment.write_bytes(segment.read_bytes() + b"\n  \n\n")
    observation = _observe(ledger.root, expected)
    assert (observation.sequence, observation.digest) == expected


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32"])
def test_non_utf8_ledger_is_refused(tmp_path, encoding):
    ledger = _chain(tmp_path / "audit", days=(DAY1,))
    expected = _head(ledger)
    segment = ledger.segments()[0]
    segment.write_bytes(segment.read_text().encode(encoding))
    with pytest.raises(ApprovalRefused):
        _observe(ledger.root, expected)


def test_replacement_between_snapshots_refuses_even_with_identical_bytes(tmp_path, monkeypatch):
    ledger = _chain(tmp_path / "audit", days=(DAY1,))
    expected = _head(ledger)
    original = bootstrap_audit._snapshot
    calls = 0

    def replace_after_snapshot(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 1:
            segment = ledger.segments()[0]
            replacement = ledger.root / "replacement"
            replacement.write_bytes(segment.read_bytes())
            replacement.chmod(0o600)
            assert replacement.stat().st_ino != segment.stat().st_ino
            replacement.replace(segment)
        return result

    monkeypatch.setattr(bootstrap_audit, "_snapshot", replace_after_snapshot)
    with pytest.raises(ApprovalRefused):
        _observe(ledger.root, expected)
    assert calls == 2


def test_wrong_head_and_genesis_or_missing_history_are_refused(tmp_path):
    ledger = _chain(tmp_path / "audit")
    with pytest.raises(ApprovalRefused):
        _observe(ledger.root, (1, "a" * 64))
    with pytest.raises(ApprovalRefused):
        _observe(ledger.root, (0, GENESIS_HASH))
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ApprovalRefused):
        _observe(empty, (1, "a" * 64))


def test_truncated_record_and_broken_chain_are_refused(tmp_path):
    ledger = _chain(tmp_path / "audit")
    expected = _head(ledger)
    first = ledger.segments()[0]
    first.write_bytes(first.read_bytes().rstrip(b"\n"))
    with pytest.raises(ApprovalRefused):
        _observe(ledger.root, expected)

    ledger = _chain(tmp_path / "other")
    expected = _head(ledger)
    paths, records = _records(ledger.root)
    record = json.loads(records[1][0])
    record["previous_hash"] = "f" * 64
    records[1][0] = json.dumps(record, separators=(",", ":"))
    _write_records(paths, records)
    with pytest.raises(ApprovalRefused):
        _observe(ledger.root, expected)


@pytest.mark.parametrize("mutation", ["duplicate", "bool_sequence"])
def test_duplicate_fields_and_boolean_sequence_are_refused(tmp_path, mutation):
    ledger = _chain(tmp_path / "audit", days=(DAY1,))
    expected = _head(ledger)
    path = ledger.segments()[0]
    record = json.loads(path.read_text(encoding="utf-8"))
    if mutation == "duplicate":
        line = path.read_text(encoding="utf-8").strip()
        line = line[:-1] + ',"sequence":1}'
    else:
        record["sequence"] = True
        line = json.dumps(record, separators=(",", ":"))
    path.write_text(line + "\n", encoding="utf-8")
    with pytest.raises(ApprovalRefused):
        _observe(ledger.root, expected)


@pytest.mark.parametrize("name", ["notes.txt", "2026-02-30.jsonl"])
def test_foreign_entry_and_impossible_date_are_refused(tmp_path, name):
    ledger = _chain(tmp_path / "audit", days=(DAY1,))
    expected = _head(ledger)
    (ledger.root / name).write_text("x\n", encoding="utf-8")
    with pytest.raises(ApprovalRefused):
        _observe(ledger.root, expected)


def test_symlink_and_hardlink_segments_are_refused(tmp_path):
    ledger = _chain(tmp_path / "audit", days=(DAY1,))
    segment = ledger.segments()[0]
    original = tmp_path / "original.jsonl"
    segment.rename(original)
    segment.symlink_to(original)
    with pytest.raises(ApprovalRefused):
        _observe(ledger.root, _head(ledger))
    segment.unlink()
    os.link(original, segment)
    with pytest.raises(ApprovalRefused):
        _observe(ledger.root, _head(ledger))


@pytest.mark.parametrize("target", ["directory", "file"])
def test_group_or_other_writable_permissions_are_refused(tmp_path, target):
    ledger = _chain(tmp_path / "audit", days=(DAY1,))
    path = ledger.root if target == "directory" else ledger.segments()[0]
    original_mode = path.stat().st_mode & 0o777
    path.chmod(original_mode | 0o020)
    try:
        with pytest.raises(ApprovalRefused):
            _observe(ledger.root, _head(ledger))
    finally:
        path.chmod(original_mode)


@pytest.mark.parametrize("kwargs", [
    {"max_total_bytes": 1},
    {"max_segments": 1},
])
def test_byte_and_segment_limits_are_enforced(tmp_path, kwargs):
    ledger = _chain(tmp_path / "audit")
    with pytest.raises(ApprovalRefused):
        _observe(ledger.root, _head(ledger), **kwargs)


def test_empty_segment_and_invalid_expected_heads_are_refused(tmp_path):
    ledger = _chain(tmp_path / "audit", days=(DAY1,))
    expected = _head(ledger)
    with pytest.raises(ApprovalRefused):
        AuditLedger(ledger.root / f"{DAY2}.jsonl").path.write_bytes(b"")
        _observe(ledger.root, expected)

    with pytest.raises(ApprovalRefused):
        _observe(ledger.root, (True, expected[1]))
    with pytest.raises(ApprovalRefused):
        _observe(ledger.root, (1, "A" * 64))


@pytest.mark.usefixtures("audit_owner_is_this_account")
def test_public_inspector_opens_existing_ledger_and_ignores_root_override(
    tmp_path, monkeypatch
):
    ledger = _chain(tmp_path / "audit")
    calls = []

    def open_ledger(owner):
        calls.append(owner)
        return os.open(ledger.root, os.O_RDONLY | os.O_DIRECTORY)

    monkeypatch.setattr(bootstrap_audit.pwd, "getpwnam", lambda _name: type("Account", (), {"pw_uid": OWNER})())
    monkeypatch.setattr(bootstrap_audit, "_open_ledger", open_ledger)
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path / "different-root"))
    result = bootstrap_audit.inspect_existing_audit(
        expected_head=_head(ledger), max_total_bytes=65536, max_segments=8
    )
    assert result.sequence == 2
    assert calls == [OWNER, OWNER]
    assert not (tmp_path / "different-root").exists()


def test_public_inspector_refuses_an_audit_account_with_uid_0_as_root(tmp_path, monkeypatch):
    # The counterpart of the test above: as root, this account's uid is 0,
    # and an azaudit with uid 0 is refused before any ledger is opened (the
    # public refusal is generic, so "no ledger opened" is what pins the cause).
    if os.geteuid() != 0:
        pytest.skip("not running as root: the stand-in azaudit uid is not 0")
    ledger = _chain(tmp_path / "audit")
    calls = []

    def open_ledger(owner):
        calls.append(owner)
        return os.open(ledger.root, os.O_RDONLY | os.O_DIRECTORY)

    monkeypatch.setattr(bootstrap_audit.pwd, "getpwnam", lambda _name: type("Account", (), {"pw_uid": OWNER})())
    monkeypatch.setattr(bootstrap_audit, "_open_ledger", open_ledger)
    with pytest.raises(ApprovalRefused, match="continuity refused"):
        bootstrap_audit.inspect_existing_audit(
            expected_head=_head(ledger), max_total_bytes=65536, max_segments=8
        )
    assert calls == []


@pytest.mark.parametrize("failure", ["account", "path"])
def test_public_inspector_refuses_missing_account_or_path_without_creation(
    tmp_path, monkeypatch, failure
):
    missing = tmp_path / "not-created"
    if failure == "account":
        def missing_account(_name):
            raise KeyError("azaudit")

        monkeypatch.setattr(bootstrap_audit.pwd, "getpwnam", missing_account)
    else:
        monkeypatch.setattr(
            bootstrap_audit.pwd, "getpwnam",
            lambda _name: type("Account", (), {"pw_uid": OWNER})(),
        )

        def missing_path(_owner):
            return os.open(missing, os.O_RDONLY | os.O_DIRECTORY)

        monkeypatch.setattr(bootstrap_audit, "_open_ledger", missing_path)
    with pytest.raises(ApprovalRefused):
        bootstrap_audit.inspect_existing_audit(
            expected_head=(1, "a" * 64), max_total_bytes=65536, max_segments=8
        )
    assert not missing.exists()


def test_public_inspector_rejects_reopened_different_directory(tmp_path, monkeypatch):
    first = _chain(tmp_path / "audit-one")
    second = _chain(tmp_path / "audit-two")
    roots = iter((first.root, second.root))
    monkeypatch.setattr(
        bootstrap_audit.pwd, "getpwnam",
        lambda _name: type("Account", (), {"pw_uid": OWNER})(),
    )

    def open_different(_owner):
        return os.open(next(roots), os.O_RDONLY | os.O_DIRECTORY)

    monkeypatch.setattr(bootstrap_audit, "_open_ledger", open_different)
    with pytest.raises(ApprovalRefused):
        bootstrap_audit.inspect_existing_audit(
            expected_head=_head(first), max_total_bytes=65536, max_segments=8
        )
