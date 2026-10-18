"""First-install genesis reader, extension-from-genesis and observation invariant."""

import os
from pathlib import Path

import time

import pytest

from azazel_nexus.audit import GENESIS_HASH
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_audit
from azazel_nexus_runtime.bootstrap_audit import (
    AuditObservation, _inspect_at, _inspect_genesis_at, inspect_existing_audit,
    inspect_first_install_audit,
)
from test_runtime_bootstrap_audit import OWNER, DAY1, _chain, _observe

GENESIS = (0, GENESIS_HASH)


def _empty(path: Path, mode=0o700):
    path.mkdir()
    path.chmod(mode)
    return path


def _genesis(directory, *, owner=OWNER):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return _inspect_genesis_at(fd, owner=owner, max_total_bytes=65536, max_segments=8)
    finally:
        os.close(fd)


def test_empty_protected_directory_returns_genesis_observation(tmp_path):
    result = _genesis(_empty(tmp_path / "audit"))
    assert result == AuditObservation(0, GENESIS_HASH, 0, 0)
    assert result.assurance == "LOCAL_CONTINUITY_ONLY"


def test_genesis_reader_takes_no_expected_head():
    with pytest.raises(TypeError):
        inspect_first_install_audit(expected_head=GENESIS, max_total_bytes=1, max_segments=1)


def test_valid_segment_is_refused(tmp_path):
    ledger = _chain(tmp_path / "audit", days=(DAY1,))
    with pytest.raises(ApprovalRefused):
        _genesis(ledger.root)


@pytest.mark.parametrize("kind", ["file", "tmp", "dot", "dir", "empty-segment"])
def test_any_entry_is_refused(tmp_path, kind):
    root = _empty(tmp_path / "audit")
    if kind == "file":
        (root / "stray").write_bytes(b"x")
    elif kind == "tmp":
        (root / f"{DAY1}.jsonl.tmp").write_bytes(b"")
    elif kind == "dot":
        (root / ".hidden").write_bytes(b"")
    elif kind == "dir":
        (root / "sub").mkdir()
    else:
        (root / f"{DAY1}.jsonl").write_bytes(b"")
    with pytest.raises(ApprovalRefused):
        _genesis(root)


@pytest.mark.parametrize("mode", [0o777, 0o770, 0o720, 0o755, 0o750, 0o500, 0o600])
def test_unprotected_or_non_0700_directory_is_refused(tmp_path, mode):
    root = _empty(tmp_path / "audit", mode)
    try:
        with pytest.raises(ApprovalRefused):
            _genesis(root)
    finally:
        root.chmod(0o700)


def test_wrong_owner_is_refused(tmp_path):
    root = _empty(tmp_path / "audit")
    with pytest.raises(ApprovalRefused):
        _genesis(root, owner=OWNER + 1)


def test_changed_between_snapshots_is_refused(tmp_path, monkeypatch):
    root = _empty(tmp_path / "audit")
    real = bootstrap_audit._scan_entries
    calls = []

    def scan(fd):
        calls.append(None)
        result = real(fd)
        if len(calls) == 1:
            (root / "late").write_bytes(b"x")
        return result

    monkeypatch.setattr(bootstrap_audit, "_scan_entries", scan)
    with pytest.raises(ApprovalRefused):
        _genesis(root)


def _public(monkeypatch, directory):
    monkeypatch.setattr(bootstrap_audit.pwd, "getpwnam",
                        lambda _n: type("A", (), {"pw_uid": OWNER})())
    monkeypatch.setattr(bootstrap_audit, "_open_ledger",
                        lambda owner: os.open(directory, os.O_RDONLY | os.O_DIRECTORY))


def test_public_genesis_inspector_ignores_root_override_and_creates_nothing(tmp_path, monkeypatch):
    root = _empty(tmp_path / "audit")
    _public(monkeypatch, root)
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path / "different"))
    result = inspect_first_install_audit(max_total_bytes=65536, max_segments=8)
    assert result == AuditObservation(0, GENESIS_HASH, 0, 0)
    assert not (tmp_path / "different").exists()
    assert list(root.iterdir()) == []


def test_public_genesis_inspector_refuses_nonempty(tmp_path, monkeypatch):
    ledger = _chain(tmp_path / "audit", days=(DAY1,))
    _public(monkeypatch, ledger.root)
    with pytest.raises(ApprovalRefused):
        inspect_first_install_audit(max_total_bytes=65536, max_segments=8)


def test_absent_directory_refused_without_creation(tmp_path, monkeypatch):
    monkeypatch.setattr(bootstrap_audit.pwd, "getpwnam",
                        lambda _n: type("A", (), {"pw_uid": OWNER})())
    # Real _open_ledger starts at "/" and refuses the absent canonical path.
    before = set(os.listdir("/"))
    with pytest.raises(ApprovalRefused):
        inspect_first_install_audit(max_total_bytes=65536, max_segments=8)
    assert set(os.listdir("/")) == before


def test_symlink_directory_refused_by_real_opener(tmp_path):
    target = _empty(tmp_path / "real")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        os.open(link, bootstrap_audit._FLAGS)


def test_missing_account_refused(monkeypatch):
    def missing(_n):
        raise KeyError("azaudit")

    monkeypatch.setattr(bootstrap_audit.pwd, "getpwnam", missing)
    with pytest.raises(ApprovalRefused):
        inspect_first_install_audit(max_total_bytes=65536, max_segments=8)


def test_public_existing_inspector_still_refuses_genesis_pair(tmp_path, monkeypatch):
    root = _empty(tmp_path / "audit")
    _public(monkeypatch, root)
    with pytest.raises(ApprovalRefused):
        inspect_existing_audit(expected_head=GENESIS, max_total_bytes=65536, max_segments=8)


def test_private_existing_reader_refuses_genesis_without_extension(tmp_path):
    root = _empty(tmp_path / "audit")
    with pytest.raises(ApprovalRefused):
        _observe(root, GENESIS)
    ledger = _chain(tmp_path / "chain")
    with pytest.raises(ApprovalRefused):
        _observe(ledger.root, GENESIS)


def _extend(directory, head):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return _inspect_at(fd, owner=OWNER, expected_head=head, max_total_bytes=65536,
                           max_segments=8, allow_extension=True)
    finally:
        os.close(fd)


def test_extension_from_genesis_accepts_empty_dir(tmp_path):
    assert _extend(_empty(tmp_path / "audit"), GENESIS) == AuditObservation(0, GENESIS_HASH, 0, 0)


def test_extension_from_genesis_accepts_valid_chain(tmp_path):
    ledger = _chain(tmp_path / "audit", days=(DAY1,))
    result = _extend(ledger.root, GENESIS)
    assert (result.sequence, result.digest) == ledger.head()
    assert result.sequence == 1


def test_extension_from_genesis_refuses_broken_chain_and_empty_segment(tmp_path):
    ledger = _chain(tmp_path / "audit", days=(DAY1,))
    segment = ledger.segments()[0]
    data = segment.read_bytes()
    segment.write_bytes(data.replace(b'"sequence":1', b'"sequence":2', 1))
    with pytest.raises(ApprovalRefused):
        _extend(ledger.root, GENESIS)
    segment.write_bytes(b"")
    with pytest.raises(ApprovalRefused):
        _extend(ledger.root, GENESIS)


@pytest.mark.parametrize("head", [(0, "a" * 64), (1, GENESIS_HASH), (-1, GENESIS_HASH)])
def test_extension_refuses_non_exact_genesis_pairs(tmp_path, head):
    with pytest.raises(ApprovalRefused):
        _extend(_empty(tmp_path / "audit"), head)


def test_nonempty_extension_still_requires_a_nonempty_dir_for_positive_head(tmp_path):
    with pytest.raises(ApprovalRefused):
        _extend(_empty(tmp_path / "audit"), (1, "a" * 64))


@pytest.mark.parametrize("args", [
    (0, "a" * 64, 0, 0), (3, GENESIS_HASH, 1, 10), (0, GENESIS_HASH, 1, 0),
    (0, GENESIS_HASH, 0, 5),
])
def test_observation_invariant(args):
    with pytest.raises(ValueError):
        AuditObservation(*args)


def test_observation_allows_genesis_and_positive():
    AuditObservation(0, GENESIS_HASH, 0, 0)
    AuditObservation(1, "a" * 64, 1, 10)


@pytest.mark.parametrize("args", [
    (False, GENESIS_HASH, 0, 0), (0, GENESIS_HASH, False, 0), (0, GENESIS_HASH, 0, False),
    (True, "a" * 64, 1, 10), (1, "a" * 64, True, 10), (1, "a" * 64, 1, True),
])
def test_observation_refuses_bool_integers(args):
    with pytest.raises(ValueError):
        AuditObservation(*args)


def test_genesis_refuses_stamp_change_between_scans_without_lasting_entry(tmp_path, monkeypatch):
    root = _empty(tmp_path / "audit")
    real = bootstrap_audit._scan_entries
    calls = []

    def scan(fd):
        result = real(fd)
        calls.append(1)
        if len(calls) == 1:  # entry created and removed after the first scan
            # Directory stamps advance on the kernel's coarse clock (a few ms on
            # Linux): a create+unlink inside the same tick as the stamps the first
            # scan saw is invisible to any stamp comparison. Step past one tick so
            # this exercises the refusal logic; the granularity limit itself is a
            # documented residual of stamp-based change detection.
            time.sleep(0.05)
            (root / "transient").write_bytes(b"")
            (root / "transient").unlink()
        return result

    monkeypatch.setattr(bootstrap_audit, "_scan_entries", scan)
    with pytest.raises(ApprovalRefused):
        _genesis(root)
    assert len(calls) == 1 and not list(root.iterdir())


def test_genesis_refuses_final_recheck_identity_difference(tmp_path, monkeypatch):
    root = _empty(tmp_path / "audit")
    real = bootstrap_audit._protected
    calls = []

    def protected(fd, **kwargs):
        info = real(fd, **kwargs)
        calls.append(1)
        if len(calls) == 3:  # only the final re-check differs
            return _Stat(info, st_ctime_ns=info.st_ctime_ns + 1)
        return info

    monkeypatch.setattr(bootstrap_audit, "_protected", protected)
    with pytest.raises(ApprovalRefused):
        _genesis(root)
    assert len(calls) == 3


class _Stat:
    def __init__(self, info, **override):
        self._info, self._override = info, override

    def __getattr__(self, name):
        return self._override.get(name, getattr(self._info, name))
