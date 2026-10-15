"""Read-only installed measurements use only ordinary synthetic temporary trees."""

from hashlib import sha256
import json
import os

import pytest

from azazel_nexus import installed_files as measured
from azazel_nexus.operator_trust import ApprovalRefused


@pytest.fixture
def selection(tmp_path):
    root = tmp_path / "root"
    leaf = root / "usr/libexec/azazel/helper"
    leaf.parent.mkdir(parents=True, mode=0o755)
    for directory in (root, root / "usr", root / "usr/libexec", leaf.parent):
        directory.chmod(0o755)
    payload = b"synthetic, never executed\n"
    leaf.write_bytes(payload)
    leaf.chmod(0o755)
    raw = json.dumps({"schema": "azazel-nexus/selected-installed-files/v1", "files": [
        {"path": "usr/libexec/azazel/helper", "mode": 0o755, "size": len(payload),
         "sha256": sha256(payload).hexdigest()},
    ]}, sort_keys=True, separators=(",", ":")).encode()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield root, leaf, raw, "sha256:" + sha256(raw).hexdigest(), fd
    finally:
        os.close(fd)


def inspect(selection):
    _root, _leaf, raw, pin, fd = selection
    return measured._measure_at(fd, raw, expected_digest=pin, owner=os.getuid())


def test_exact_regular_file_selection_matches_without_execution(selection):
    result = inspect(selection)
    assert result.manifest_digest == selection[3]
    assert result.file_count == 1
    assert result.total_bytes == selection[1].stat().st_size


@pytest.mark.parametrize("change", ["bytes", "mode", "size", "missing", "symlink", "hardlink", "directory", "ancestor-mode", "ancestor-symlink"])
def test_changed_or_unsafe_selection_refuses(selection, change):
    root, leaf, _raw, _pin, _fd = selection
    if change == "bytes":
        leaf.write_bytes(b"X" * leaf.stat().st_size)
    elif change == "mode":
        leaf.chmod(0o644)
    elif change == "size":
        leaf.write_bytes(b"short")
    elif change == "ancestor-mode":
        leaf.parent.chmod(0o777)
    elif change == "hardlink":
        os.link(leaf, root / "another-link")
    elif change == "ancestor-symlink":
        original = root / "usr/libexec"
        original.rename(root / "relocated")
        original.symlink_to(root / "relocated", target_is_directory=True)
    else:
        leaf.unlink()
        if change == "symlink":
            leaf.symlink_to(root / "missing-target")
        elif change == "directory":
            leaf.mkdir()
    with pytest.raises((ApprovalRefused, OSError)):
        inspect(selection)


def test_wrong_pin_refuses_before_any_tree_read(selection, monkeypatch):
    _root, _leaf, raw, _pin, fd = selection
    monkeypatch.setattr(measured, "_snapshot_at", lambda *a, **kw: pytest.fail("tree read"))
    with pytest.raises(ApprovalRefused):
        measured._measure_at(fd, raw, expected_digest="sha256:" + "0" * 64, owner=os.getuid())


def test_identical_byte_replacement_between_snapshots_refuses(selection, monkeypatch):
    _root, leaf, _raw, _pin, _fd = selection
    original = measured._snapshot_at
    calls = []

    def snapshot(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append(None)
        if len(calls) == 1:
            replacement = leaf.parent / "replacement"
            replacement.write_bytes(leaf.read_bytes())
            replacement.chmod(0o755)
            replacement.replace(leaf)
        return result

    monkeypatch.setattr(measured, "_snapshot_at", snapshot)
    with pytest.raises(ApprovalRefused):
        inspect(selection)


def test_unlisted_files_are_explicitly_outside_selection(selection):
    root, _leaf, _raw, _pin, _fd = selection
    (root / "usr/unlisted").write_bytes(b"not a full closure claim")
    assert inspect(selection).file_count == 1
