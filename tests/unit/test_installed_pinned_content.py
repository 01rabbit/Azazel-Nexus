"""Pinned selected-file byte reads stay bounded and stable on ordinary trees."""

from hashlib import sha256
import os

import pytest

from azazel_nexus import installed_files
from azazel_nexus.installed_manifest import (
    InstalledDirectory, InstalledFile, InstalledManifest,
    encode_installed_manifest,
)
from azazel_nexus.operator_trust import ApprovalRefused


@pytest.fixture
def pinned_tree(tmp_path):
    root = tmp_path / "installed"
    files = {
        "opt/env/bin/python": b"synthetic interpreter bytes\n",
        "opt/env/site/az-activated": b"wrapper bytes\n",
        "opt/env/site/unrequested": b"not returned\n",
        "opt/env/site/large": b"x" * 65537,
    }
    directories = ("opt/env", "opt/env/bin", "opt/env/site")
    for relative, payload in files.items():
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(0o755)
    for relative in (root, root / "opt", *(root / p for p in directories)):
        relative.mkdir(parents=True, exist_ok=True)
        relative.chmod(0o755)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    entries = tuple(sorted((
        InstalledFile(path, 0o755, len(payload), sha256(payload).hexdigest())
        for path, payload in files.items()
    ), key=lambda entry: entry.path))
    manifest = InstalledManifest(
        entries, tuple(InstalledDirectory(path) for path in directories), 2,
    )
    raw = encode_installed_manifest(manifest)
    pin = "sha256:" + sha256(raw).hexdigest()
    try:
        yield root, root_fd, files, directories, raw, pin, os.getuid()
    finally:
        os.close(root_fd)


def _read(tree, paths=("opt/env/bin/python",)):
    _root, root_fd, _files, _directories, raw, pin, owner = tree
    return installed_files._read_pinned_at(
        root_fd, raw, expected_digest=pin, paths=paths, owner=owner,
    )


def test_pinned_read_returns_only_requested_exact_bytes(pinned_tree):
    assert _read(pinned_tree, ("opt/env/bin/python", "opt/env/site/az-activated")) == (
        b"synthetic interpreter bytes\n", b"wrapper bytes\n",
    )


@pytest.mark.parametrize("paths", [
    (),
    ("opt/env/site/az-activated", "opt/env/bin/python"),
    ("opt/env/bin/python", "opt/env/bin/python"),
    ("opt/env/site/not-in-manifest",),
    ("usr/share/missing",),
    ("opt/env/bin/python", "opt/env/site/az-activated",
     "opt/env/site/large", "opt/env/site/unrequested"),
])
def test_invalid_or_unpinned_path_selection_refuses(pinned_tree, paths):
    with pytest.raises(ApprovalRefused):
        _read(pinned_tree, paths)


def test_wrong_manifest_pin_refuses_before_read(pinned_tree, monkeypatch):
    _root, root_fd, _files, _directories, raw, _pin, owner = pinned_tree

    def forbidden(*_args, **_kwargs):
        pytest.fail("bad pin reached the filesystem snapshot")

    monkeypatch.setattr(installed_files, "_snapshot_at", forbidden)
    with pytest.raises(ApprovalRefused):
        installed_files._read_pinned_at(
            root_fd, raw, expected_digest="sha256:" + "0" * 64,
            paths=("opt/env/bin/python",), owner=owner,
        )


def test_reader_does_not_open_unrequested_or_unlisted_files(pinned_tree, monkeypatch):
    root, root_fd, _files, _directories, raw, pin, owner = pinned_tree
    unexpected = root / "opt/env/bin/unlisted"
    unexpected.write_bytes(b"must not be opened")
    unexpected.chmod(0o755)
    real_open = installed_files.os.open

    def watched_open(path, flags, *args, **kwargs):
        if path in {"unlisted", "unrequested", "large"}:
            pytest.fail("unrequested file was opened")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(installed_files.os, "open", watched_open)
    assert installed_files._read_pinned_at(
        root_fd, raw, expected_digest=pin,
        paths=("opt/env/bin/python",), owner=owner,
    ) == (b"synthetic interpreter bytes\n",)


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_unsafe_selected_file_links_refuse(pinned_tree, kind):
    root, _root_fd, _files, _directories, _raw, _pin, _owner = pinned_tree
    selected = root / "opt/env/bin/python"
    if kind == "symlink":
        selected.unlink()
        selected.symlink_to("/etc/passwd")
    else:
        os.link(selected, root / "outside-hardlink")

    with pytest.raises(ApprovalRefused):
        _read(pinned_tree)


def test_identical_replacement_between_snapshots_refuses(pinned_tree, monkeypatch):
    root, _root_fd, _files, _directories, _raw, _pin, _owner = pinned_tree
    selected = root / "opt/env/bin/python"
    original_snapshot = installed_files._snapshot_at
    calls = []

    def replace_after_first(root_fd, manifest, *, owner, contents=None):
        result = original_snapshot(root_fd, manifest, owner=owner, contents=contents)
        calls.append(None)
        if len(calls) == 1:
            replacement = selected.with_name("replacement")
            replacement.write_bytes(selected.read_bytes())
            replacement.chmod(0o755)
            replacement.replace(selected)
        return result

    monkeypatch.setattr(installed_files, "_snapshot_at", replace_after_first)
    with pytest.raises(ApprovalRefused):
        _read(pinned_tree)
    assert len(calls) >= 2


def test_pinned_file_size_limit_is_enforced(pinned_tree, monkeypatch):
    del monkeypatch
    with pytest.raises(ApprovalRefused):
        _read(pinned_tree, ("opt/env/site/large",))


def test_public_reader_uses_only_fixed_root_descriptor(monkeypatch, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    observed = []
    content = b"exact bytes"
    raw = encode_installed_manifest(InstalledManifest((InstalledFile(
        "opt/env/bin/python", 0o755, len(content), sha256(content).hexdigest(),
    ),)))
    expected_digest = "sha256:" + sha256(raw).hexdigest()
    selected = ("opt/env/bin/python",)

    def fixed_open(path, flags, *args, **kwargs):
        assert path == "/"
        assert flags & os.O_DIRECTORY
        return os.dup(root_fd)

    def read_at(fd, actual_raw, *, expected_digest, paths, owner):
        observed.append((os.fstat(fd).st_ino, actual_raw, expected_digest, paths, owner))
        return (b"exact bytes",)

    monkeypatch.setattr(installed_files.os, "open", fixed_open)
    monkeypatch.setattr(installed_files, "_read_pinned_at", read_at)
    try:
        assert installed_files.read_pinned_installed_files(
            raw, expected_digest=expected_digest, paths=selected,
        ) == (b"exact bytes",)
        assert observed == [(
            os.fstat(root_fd).st_ino, raw, expected_digest,
            selected, 0,
        )]
    finally:
        os.close(root_fd)
