"""Generation creation is staged completely before its numbered directory appears."""

from __future__ import annotations

import fcntl
import json
import os
import stat

import pytest

from azazel_nexus import generation as generation_module
from azazel_nexus.generation import (
    GenerationCommitUncertain,
    GenerationRefused,
    GenerationStore,
    tree_digest,
)

T0 = "2026-10-13T00:00:00Z"
T1 = "2026-10-13T00:01:00Z"
CD = "sha256:" + "a" * 64
BINDING = "hmac-sha256:" + "b" * 64


@pytest.fixture
def store(tmp_path) -> GenerationStore:
    root = tmp_path / "generations"
    root.mkdir(mode=0o700)
    return GenerationStore(root)


def _seed(store: GenerationStore) -> dict[str, bytes]:
    files = {"stable.conf": b"stable generation\n"}
    store.create(files, created_at=T0, commissioning_digest=CD)
    return files


def _numbered_directories(store: GenerationStore) -> tuple[str, ...]:
    return tuple(
        sorted(
            child.name
            for child in store.root.iterdir()
            if child.is_dir() and child.name.isdigit()
        )
    )


def _assert_failed_generation_not_visible(store: GenerationStore, old_tree: dict[str, bytes]) -> None:
    assert store.numbers() == (1,)
    assert store.current().number == 1
    assert store.read_tree(1) == old_tree
    assert _numbered_directories(store) == ("1",)
    staging = list(store.root.glob(".staging-*"))
    assert staging, "failed staging tree should remain for diagnosis"
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o700 for path in staging)
    assert all(stat.S_IMODE((path / "tree").stat().st_mode) == 0o700 for path in staging)


def test_write_failure_mid_tree_keeps_partial_generation_hidden(store, monkeypatch):
    old_tree = _seed(store)
    real_write_private = generation_module._write_private

    def fail_on_second_file(path, data):
        if path.name == "second.conf":
            raise OSError("synthetic staged file write failure")
        return real_write_private(path, data)

    monkeypatch.setattr(generation_module, "_write_private", fail_on_second_file)
    with pytest.raises(GenerationRefused, match="staging failed"):
        store.create(
            {"first.conf": b"complete first file\n", "second.conf": b"fails\n"},
            created_at=T1,
            commissioning_digest=CD,
        )

    _assert_failed_generation_not_visible(store, old_tree)


def test_metadata_write_failure_keeps_complete_tree_hidden(store, monkeypatch):
    old_tree = _seed(store)
    real_write_private = generation_module._write_private

    def fail_on_generation_metadata(path, data):
        if path.name == "generation.json":
            raise OSError("synthetic metadata write failure")
        return real_write_private(path, data)

    monkeypatch.setattr(generation_module, "_write_private", fail_on_generation_metadata)
    with pytest.raises(GenerationRefused, match="staging failed"):
        store.create(
            {"candidate.conf": b"complete tree\n"},
            created_at=T1,
            commissioning_digest=CD,
        )

    _assert_failed_generation_not_visible(store, old_tree)


def test_promotion_rename_failure_keeps_completed_generation_hidden(store, monkeypatch):
    old_tree = _seed(store)
    from pathlib import Path

    real_rename = Path.rename

    def fail_staging_rename(path, target):
        if path.name.startswith(".staging-") and Path(target).name.isdigit():
            raise OSError("synthetic generation rename failure")
        return real_rename(path, target)

    monkeypatch.setattr(Path, "rename", fail_staging_rename)
    with pytest.raises(GenerationRefused, match="staging failed"):
        store.create(
            {"candidate.conf": b"complete tree\n"},
            created_at=T1,
            commissioning_digest=CD,
        )

    _assert_failed_generation_not_visible(store, old_tree)


def test_root_fsync_failure_reports_published_generation_as_uncertain(store, monkeypatch):
    old_tree = _seed(store)
    real_fsync = os.fsync
    root_info = store.root.stat()

    def fail_root_directory_fsync(descriptor):
        info = os.fstat(descriptor)
        if (info.st_dev, info.st_ino) == (root_info.st_dev, root_info.st_ino):
            raise OSError("synthetic post-publication root fsync failure")
        return real_fsync(descriptor)

    monkeypatch.setattr(generation_module.os, "fsync", fail_root_directory_fsync)
    with pytest.raises(GenerationCommitUncertain) as uncertain:
        store.create(
            {"candidate.conf": b"complete published tree\n"},
            created_at=T1,
            commissioning_digest=CD,
            commissioning_evidence_binding=BINDING,
        )

    assert uncertain.value.number == 2
    assert store.numbers() == (1, 2)
    assert store.current().number == 2
    assert store.read_tree(2) == {"candidate.conf": b"complete published tree\n"}
    assert store.verify(2).commissioning_evidence_binding == BINDING
    assert store.read_tree(1) == old_tree
    assert not list(store.root.glob(".staging-*"))


def test_success_promotes_complete_tree_metadata_and_evidence_binding(store):
    old_tree = _seed(store)
    files = {"nested/policy.conf": b"policy bytes\n", "service.conf": b"service bytes\n"}

    generation = store.create(
        files,
        created_at=T1,
        commissioning_digest=CD,
        commissioning_evidence_binding=BINDING,
    )

    assert generation.number == 2
    assert generation.supersedes == 1
    assert generation.digest == tree_digest(files)
    assert store.read_tree(2) == files
    assert store.verify(2).commissioning_evidence_binding == BINDING
    assert store.read(2).commissioning_digest == CD
    assert store.read_tree(1) == old_tree
    assert store.numbers() == (1, 2)

    generation_dir = store.root / "2"
    tree_dir = generation_dir / "tree"
    metadata = generation_dir / "generation.json"
    assert stat.S_IMODE(generation_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(tree_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(metadata.stat().st_mode) == 0o600
    assert not list(store.root.glob(".staging-*"))
    assert json.loads(metadata.read_text(encoding="utf-8"))["commissioning_evidence_binding"] == BINDING


def test_create_refuses_while_generation_directory_flock_is_held(store):
    descriptor = os.open(store.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(GenerationRefused):
            store.create(
                {"candidate.conf": b"must not stage\n"},
                created_at=T0,
                commissioning_digest=CD,
            )
        assert store.numbers() == ()
        assert not list(store.root.glob(".staging-*"))
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@pytest.mark.parametrize("path", ["a//b.conf", "./a.conf", "a/./b.conf", "a/"])
def test_noncanonical_path_aliases_are_refused_before_staging(store, path):
    with pytest.raises(GenerationRefused, match="not a path inside"):
        store.create(
            {path: b"invalid path\n"},
            created_at=T0,
            commissioning_digest=CD,
        )

    assert store.numbers() == ()
    assert not list(store.root.glob(".staging-*"))


def test_mutable_file_contents_are_refused_before_staging(store):
    with pytest.raises(GenerationRefused, match="immutable bytes"):
        store.create(
            {"candidate.conf": bytearray(b"mutable\n")},
            created_at=T0,
            commissioning_digest=CD,
        )

    assert store.numbers() == ()
    assert not list(store.root.glob(".staging-*"))


def test_store_root_creation_syncs_each_new_directory_entry(tmp_path, monkeypatch):
    grandparent = tmp_path / "new-grandparent"
    parent = grandparent / "new-parent"
    store = GenerationStore(parent / "generations")
    real_sync_directory = generation_module._sync_directory
    synced = []

    def record_sync(path):
        synced.append(path)
        return real_sync_directory(path)

    monkeypatch.setattr(generation_module, "_sync_directory", record_sync)
    store.create({"config": b"ready\n"}, created_at=T0, commissioning_digest=CD)

    assert synced[:3] == [tmp_path, grandparent, parent]


@pytest.mark.parametrize(
    "entry,kind",
    [
        ("01", "directory"),
        ("0", "directory"),
        ("١", "directory"),
        ("2", "symlink"),
        ("2", "file"),
    ],
)
def test_numbers_refuses_ambiguous_numeric_entries_before_creation(store, entry, kind):
    target = store.root / entry
    if kind == "directory":
        target.mkdir()
    elif kind == "symlink":
        destination = store.root / "ordinary-target"
        destination.mkdir()
        target.symlink_to(destination, target_is_directory=True)
    else:
        target.write_bytes(b"not a generation directory\n")
    before = {path.name for path in store.root.iterdir()}

    with pytest.raises(GenerationRefused, match="noncanonical generation entry"):
        store.create(
            {"candidate.conf": b"must not be published\n"},
            created_at=T0,
            commissioning_digest=CD,
        )

    assert {path.name for path in store.root.iterdir()} == before
    assert not list(store.root.glob(".staging-*"))


def test_rollback_refuses_if_another_generation_advances_before_publication(store, monkeypatch):
    store.create({"config": b"generation one\n"}, created_at=T0, commissioning_digest=CD)
    store.create({"config": b"generation two\n"}, created_at=T1, commissioning_digest=CD)
    real_create = store.create
    injected = False

    def advance_then_create(files, **kwargs):
        nonlocal injected
        if not injected and kwargs.get("rolled_back_from") is not None:
            injected = True
            real_create(
                {"config": b"concurrent generation three\n"},
                created_at="2026-10-13T00:02:00Z",
                commissioning_digest=CD,
            )
        return real_create(files, **kwargs)

    monkeypatch.setattr(store, "create", advance_then_create)
    with pytest.raises(GenerationRefused, match="current generation changed"):
        store.roll_back_to(
            1,
            created_at="2026-10-13T00:03:00Z",
            reason="rollback raced with another writer",
            actor="operator",
        )

    assert store.numbers() == (1, 2, 3)
    assert store.current().number == 3
    assert store.read_tree(1) == {"config": b"generation one\n"}
    assert store.read_tree(2) == {"config": b"generation two\n"}
    assert store.read_tree(3) == {"config": b"concurrent generation three\n"}


def test_explicit_latest_allows_rollback_from_an_earlier_active_generation(store):
    files = _seed(store)
    staged = store.create({"config": b"staged\n"}, created_at=T1, commissioning_digest=CD)

    restored = store.create(
        files, created_at=T1, commissioning_digest=CD,
        rolled_back_from=1, rollback_reason="restore active selection", actor="operator",
        expected_latest_generation=staged.number,
    )

    assert restored.number == 3
    assert store.verify(3).rolled_back_from == 1
    assert restored.supersedes == staged.number
    assert store.read_tree(3) == files


def test_explicit_latest_refuses_when_store_advances_before_publication(store):
    files = _seed(store)
    expected = store.current().number
    concurrent = store.create({"config": b"concurrent\n"}, created_at=T1, commissioning_digest=CD)
    before = set(store.root.iterdir())

    with pytest.raises(GenerationRefused, match="current generation changed"):
        store.create(
            files, created_at=T1, commissioning_digest=CD,
            rolled_back_from=1, rollback_reason="restore active selection", actor="operator",
            expected_latest_generation=expected,
        )

    assert set(store.root.iterdir()) == before
    assert store.numbers() == (1, 2)
    assert store.verify(2) == concurrent
    assert store.read_tree(1) == files


def test_default_rollback_still_requires_latest_stored_generation(store):
    files = _seed(store)
    latest = store.create({"config": b"latest\n"}, created_at=T1, commissioning_digest=CD)

    with pytest.raises(GenerationRefused, match="current generation changed"):
        store.create(
            files, created_at=T1, commissioning_digest=CD,
            rolled_back_from=1, rollback_reason="stale source", actor="operator",
        )
    assert store.numbers() == (1, 2)

    restored = store.create(
        files, created_at=T1, commissioning_digest=CD,
        rolled_back_from=latest.number, rollback_reason="restore previous tree", actor="operator",
    )
    assert store.verify(3).rolled_back_from == latest.number
    assert restored.supersedes == latest.number
    assert store.read_tree(3) == files
