"""Exact selected-directory membership on ordinary synthetic trees only."""

from hashlib import sha256
import os
import shutil

import pytest

from azazel_nexus import installed_files as measured
from azazel_nexus.installed_manifest import (
    InstalledDirectory, InstalledFile, InstalledManifest, encode_installed_manifest,
)
from azazel_nexus.operator_trust import ApprovalRefused


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "root"
    site = root / "opt/env/site"
    package = site / "pkg"
    package.mkdir(parents=True)
    (site / "empty").mkdir()
    leaf = package / "module.py"
    payload = b"synthetic module; never executed\n"
    leaf.write_bytes(payload)
    leaf.chmod(0o644)
    for directory in (root, root / "opt", root / "opt/env", site, package, site / "empty"):
        directory.chmod(0o755)
    manifest = InstalledManifest(
        (InstalledFile("opt/env/site/pkg/module.py", 0o644, len(payload),
                       sha256(payload).hexdigest()),),
        tuple(InstalledDirectory(path) for path in (
            "opt/env/site", "opt/env/site/empty", "opt/env/site/pkg",
        )), version=2,
    )
    raw = encode_installed_manifest(manifest)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield root, site, leaf, fd, raw, "sha256:" + sha256(raw).hexdigest()
    finally:
        os.close(fd)


def inspect(tree):
    return measured._measure_at(tree[3], tree[4], expected_digest=tree[5], owner=os.getuid())


def test_exact_nested_and_empty_directory_membership_matches(tree):
    result = inspect(tree)
    assert result.directory_count == 3
    assert result.file_count == 1
    assert result.total_bytes == tree[2].stat().st_size


@pytest.mark.parametrize("kind", ["file", "directory", "symlink"])
def test_unlisted_child_refuses_without_following_it(tree, kind):
    child = tree[1] / "unexpected"
    if kind == "file":
        child.write_bytes(b"unlisted")
    elif kind == "directory":
        child.mkdir()
    else:
        child.symlink_to("/not-an-admitted-target")
    with pytest.raises(ApprovalRefused):
        inspect(tree)


def test_declared_empty_directory_must_remain_empty(tree):
    (tree[1] / "empty/unlisted").write_bytes(b"extra")
    with pytest.raises(ApprovalRefused):
        inspect(tree)


@pytest.mark.parametrize("kind", ["mode", "symlink", "missing"])
def test_unsafe_declared_directory_refuses(tree, kind):
    empty = tree[1] / "empty"
    if kind == "mode":
        empty.chmod(0o777)
    elif kind == "missing":
        empty.rmdir()
    else:
        empty.rmdir()
        outside = tree[0] / "outside"
        outside.mkdir()
        empty.symlink_to(outside, target_is_directory=True)
    with pytest.raises((ApprovalRefused, OSError)):
        inspect(tree)


def test_membership_added_during_file_hashing_refuses(tree, monkeypatch, private_os):
    private_os(measured)
    original = measured.os.read
    changed = []

    def read(fd, count):
        if not changed:
            changed.append(True)
            (tree[1] / "injected.py").write_bytes(b"not approved")
        return original(fd, count)

    monkeypatch.setattr(measured.os, "read", read)
    with pytest.raises(ApprovalRefused):
        inspect(tree)
    assert changed == [True]


def test_identical_directory_replacement_between_snapshots_refuses(tree, monkeypatch):
    original = measured._snapshot_at
    calls = []

    def snapshot(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append(True)
        if len(calls) == 1:
            retained = tree[0] / "retained-site"
            tree[1].rename(retained)
            shutil.copytree(retained, tree[1])
        return result

    monkeypatch.setattr(measured, "_snapshot_at", snapshot)
    with pytest.raises(ApprovalRefused):
        inspect(tree)
    assert len(calls) == 2


def test_directory_enumeration_stops_at_first_unknown_child(tree, monkeypatch, private_os):
    private_os(measured)
    consumed = []

    class Entry:
        name = "unknown"

    class Entries:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            for _ in range(10000):
                consumed.append(True)
                yield Entry()

    monkeypatch.setattr(measured.os, "scandir", lambda _fd: Entries())
    with pytest.raises(ApprovalRefused):
        inspect(tree)
    assert len(consumed) == 1


def test_wrong_manifest_pin_refuses_before_directory_enumeration(tree, monkeypatch, private_os):
    private_os(measured)
    monkeypatch.setattr(measured.os, "scandir", lambda _fd: pytest.fail("enumerated"))
    with pytest.raises(ApprovalRefused):
        measured._measure_at(tree[3], tree[4], expected_digest="sha256:" + "0" * 64,
                             owner=os.getuid())
