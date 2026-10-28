"""Ordinary-directory tests for boot-bound bootstrap transaction persistence."""

import os
from pathlib import Path
import stat

import pytest

from azazel_nexus.bootstrap_grant_store import (
    GrantTransactionDurabilityUncertain,
    GrantTransactionStore,
)
import azazel_nexus.bootstrap_grant_store as grant_store
from azazel_nexus.bootstrap_grant_transaction import (
    PAIR,
    GrantTransaction,
)
from azazel_nexus.operator_trust import ApprovalRefused

BOOT = "22222222-2222-4222-8222-222222222222"
DIGEST = "sha256:" + "a" * 64


def _journal():
    return GrantTransaction(
        boot_id=BOOT,
        context_digest=DIGEST,
        approval_digest="sha256:" + "b" * 64,
        generation=3,
        generation_digest="sha256:" + "c" * 64,
        grant_id="d" * 32,
        unit_payload_digests=tuple((unit, "e" * 64) for unit in PAIR),
    )


def _store(path: Path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)

    def open_directory():
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)

    fd = open_directory()
    store = GrantTransactionStore(fd, owner_uid=os.getuid(), reopen=open_directory)
    os.close(fd)
    return store


def test_create_load_and_compare_advance_are_boot_bound(tmp_path):
    store = _store(tmp_path / "state")
    try:
        assert store.load_optional(boot_id=BOOT) is None
        prepared = _journal()
        store.create(prepared)
        assert store.load_optional(boot_id=BOOT) == prepared
        assert store.load(boot_id=BOOT) == prepared

        granted = store.advance(prepared, "pair_grant_intent")
        assert granted.phase == "pair_grant_intent"
        assert store.load(boot_id=BOOT) == granted
        with pytest.raises(ApprovalRefused, match="compare-and-swap"):
            store.advance(prepared, "pair_grant_intent")
    finally:
        store.close()


def test_duplicate_create_wrong_boot_and_unknown_boot_refuse(tmp_path):
    store = _store(tmp_path / "state")
    try:
        journal = _journal()
        store.create(journal)
        with pytest.raises(ApprovalRefused, match="already exists"):
            store.create(journal)
        with pytest.raises(ApprovalRefused, match="boot identity"):
            store.load(boot_id="not-a-boot-id")
        with pytest.raises(ApprovalRefused):
            store.load(boot_id="33333333-3333-4333-8333-333333333333")
    finally:
        store.close()


def test_interrupted_transaction_marker_refuses_without_repair(tmp_path):
    directory = tmp_path / "state"
    store = _store(directory)
    pending = directory / f".grant-{BOOT}.json.pending"
    pending.write_bytes(b"operator recovery required\n")
    os.chmod(pending, 0o600)
    try:
        with pytest.raises(ApprovalRefused, match="unfinished"):
            store.load(boot_id=BOOT)
        assert pending.exists()
    finally:
        store.close()


def test_symlinked_transaction_is_refused(tmp_path):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    target = tmp_path / "outside.json"
    target.write_bytes(b"not a transaction")
    (directory / f"grant-{BOOT}.json").symlink_to(target)
    store = _store(directory)
    try:
        with pytest.raises(ApprovalRefused):
            store.load(boot_id=BOOT)
    finally:
        store.close()


def test_replaced_state_directory_is_refused(tmp_path):
    path = tmp_path / "state"
    store = _store(path)
    moved = tmp_path / "old-state"
    path.rename(moved)
    path.mkdir(mode=0o700)
    try:
        with pytest.raises(ApprovalRefused, match="directory changed"):
            store.load(boot_id=BOOT)
    finally:
        store.close()


def test_noncanonical_boot_id_cannot_become_a_filename(tmp_path):
    store = _store(tmp_path / "state")
    try:
        with pytest.raises(ApprovalRefused, match="canonical"):
            store.load(boot_id="../22222222-2222-4222-8222-222222222222")
    finally:
        store.close()


def test_directory_fsync_failure_leaves_refusing_pending_marker(tmp_path, monkeypatch, private_os):
    private_os(grant_store)
    directory = tmp_path / "state"
    store = _store(directory)
    original_fsync = grant_store.os.fsync

    def fail_directory_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("simulated directory durability failure")
        return original_fsync(fd)

    monkeypatch.setattr(grant_store.os, "fsync", fail_directory_fsync)
    try:
        with pytest.raises(GrantTransactionDurabilityUncertain):
            store.create(_journal())
        assert (directory / f".grant-{BOOT}.json.pending").exists()
        with pytest.raises(ApprovalRefused, match="unfinished"):
            store.load(boot_id=BOOT)
    finally:
        store.close()


def test_transaction_name_is_synced_before_pending_marker_is_removed(
    tmp_path, monkeypatch, private_os
):
    private_os(grant_store)
    directory = tmp_path / "state"
    store = _store(directory)
    original_fsync = grant_store.os.fsync
    directory_syncs = 0

    def fail_after_transaction_name_sync(fd):
        nonlocal directory_syncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_syncs += 1
            if directory_syncs == 2:
                assert (directory / f"grant-{BOOT}.json").exists()
                assert (directory / f".grant-{BOOT}.json.pending").exists()
                raise OSError("simulated directory durability failure")
        return original_fsync(fd)

    monkeypatch.setattr(grant_store.os, "fsync", fail_after_transaction_name_sync)
    try:
        with pytest.raises(GrantTransactionDurabilityUncertain):
            store.create(_journal())
        assert (directory / f"grant-{BOOT}.json").exists()
        assert (directory / f".grant-{BOOT}.json.pending").exists()
        with pytest.raises(ApprovalRefused, match="unfinished"):
            store.load_optional(boot_id=BOOT)
    finally:
        store.close()


@pytest.mark.parametrize("failed_sync", [1, 2, 3])
def test_advance_directory_sync_boundaries_fail_closed_or_reopen_durable_state(
    tmp_path, monkeypatch, failed_sync, private_os
):
    private_os(grant_store)
    directory = tmp_path / "state"
    store = _store(directory)
    prepared = _journal()
    store.create(prepared)
    original_fsync = grant_store.os.fsync
    directory_syncs = 0

    def fail_selected_directory_sync(fd):
        nonlocal directory_syncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_syncs += 1
            if directory_syncs == failed_sync:
                raise OSError("simulated transaction advance crash boundary")
        return original_fsync(fd)

    monkeypatch.setattr(grant_store.os, "fsync", fail_selected_directory_sync)
    try:
        with pytest.raises(GrantTransactionDurabilityUncertain):
            store.advance(prepared, "pair_grant_intent")
    finally:
        store.close()

    reopened = _store(directory)
    try:
        if failed_sync < 3:
            with pytest.raises(ApprovalRefused, match="unfinished"):
                reopened.load_optional(boot_id=BOOT)
        else:
            assert reopened.load(boot_id=BOOT).phase == "pair_grant_intent"
    finally:
        reopened.close()
