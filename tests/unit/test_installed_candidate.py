"""Explicit installed-candidate observation tests on ordinary temporary files."""

from hashlib import sha256
import os

import pytest

from azazel_nexus import installed_candidate as candidate
from azazel_nexus import installed_files
from azazel_nexus.installed_files import _measure_at
from azazel_nexus.installed_manifest import decode_installed_manifest
from azazel_nexus.operator_trust import ApprovalRefused


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "root"
    paths = ("opt/azazel/helper", "usr/lib/azazel/module.py")
    for path in paths:
        leaf = root.joinpath(*path.split("/"))
        leaf.parent.mkdir(parents=True, exist_ok=True)
        leaf.write_bytes(("synthetic:" + path + "\n").encode())
        leaf.chmod(0o755 if path.startswith("opt/") else 0o644)
    for directory in (root, root / "opt", root / "opt/azazel", root / "usr",
                      root / "usr/lib", root / "usr/lib/azazel"):
        directory.chmod(0o755)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield root, fd, paths, os.getuid()
    finally:
        os.close(fd)


def observe(tree, paths=None):
    _root, fd, selected, owner = tree
    return candidate._candidate_at(fd, selected if paths is None else paths, owner=owner)


def test_candidate_matches_existing_selected_measurement_and_is_deterministic(tree):
    raw = observe(tree)
    assert observe(tree) == raw
    pin = "sha256:" + sha256(raw).hexdigest()
    measured = _measure_at(tree[1], raw, expected_digest=pin, owner=tree[3])
    manifest = decode_installed_manifest(raw, expected_digest=pin)
    assert measured.file_count == len(tree[2])
    assert measured.total_bytes == sum(entry.size for entry in manifest.files)


def test_v2_candidate_measures_only_explicit_directory_membership(tree):
    directories = (
        "opt/azazel", "usr/lib", "usr/lib/azazel",
    )
    raw = candidate._candidate_at(
        tree[1], tree[2], owner=tree[3], directories=directories,
    )
    pin = "sha256:" + sha256(raw).hexdigest()
    manifest = decode_installed_manifest(raw, expected_digest=pin)
    measured = _measure_at(tree[1], raw, expected_digest=pin, owner=tree[3])

    assert manifest.version == 2
    assert tuple(entry.path for entry in manifest.directories) == directories
    assert measured.file_count == len(tree[2])
    assert measured.directory_count == len(directories)


def test_v3_candidate_records_explicit_link_without_opening_it(tree, monkeypatch, private_os):
    root, fd, paths, owner = tree
    link_path = "opt/azazel/helper-alias"
    link = root / link_path
    link.symlink_to("/usr/lib/azazel/module.py")
    original_open = candidate.os.open

    def no_follow_open(path, flags, *args, **kwargs):
        if path == link.name:
            pytest.fail("candidate opened the symlink leaf")
        return original_open(path, flags, *args, **kwargs)

    # The candidate and the measurement it delegates to both open entries.
    for module in (candidate, installed_files):
        private_os(module)
        monkeypatch.setattr(module.os, "open", no_follow_open)
    directories = ("opt/azazel", "usr/lib", "usr/lib/azazel")
    raw = candidate._candidate_at(
        fd, paths, owner=owner, directories=directories, links=(link_path,),
    )
    pin = "sha256:" + sha256(raw).hexdigest()
    manifest = decode_installed_manifest(raw, expected_digest=pin)
    measured = _measure_at(fd, raw, expected_digest=pin, owner=owner)

    assert manifest.version == 3
    assert manifest.links[0].path == link_path
    assert manifest.links[0].target == "/usr/lib/azazel/module.py"
    assert measured.link_count == 1


def test_candidate_refuses_link_target_not_explicitly_selected(tree):
    root, fd, paths, owner = tree
    link_path = "opt/azazel/helper-alias"
    (root / link_path).symlink_to("unlisted-target")

    with pytest.raises(ApprovalRefused):
        candidate._candidate_at(fd, paths, owner=owner, links=(link_path,))


def test_candidate_refuses_link_cycle(tree):
    root, fd, paths, owner = tree
    first = root / "opt/azazel/link-a"
    second = root / "opt/azazel/link-b"
    first.symlink_to("link-b")
    second.symlink_to("link-a")

    with pytest.raises(ApprovalRefused):
        candidate._candidate_at(
            fd, paths, owner=owner,
            links=("opt/azazel/link-a", "opt/azazel/link-b"),
        )


@pytest.mark.parametrize("kind", ["regular-leaf", "unsafe-target"])
def test_candidate_refuses_nonlink_leaf_or_invalid_link_text(tree, kind):
    root, fd, paths, owner = tree
    link_path = "opt/azazel/helper-alias"
    link = root / link_path
    if kind == "regular-leaf":
        link.write_bytes(b"not a symlink")
        link.chmod(0o644)
    else:
        link.symlink_to("../module.py")

    with pytest.raises(ApprovalRefused):
        candidate._candidate_at(fd, paths, owner=owner, links=(link_path,))


def test_v2_candidate_refuses_unlisted_child_in_selected_directory(tree):
    root, fd, paths, owner = tree
    extra = root / "opt/azazel/unlisted"
    extra.write_bytes(b"unlisted")
    extra.chmod(0o644)

    with pytest.raises(ApprovalRefused):
        candidate._candidate_at(
            fd, paths, owner=owner,
            directories=("opt/azazel", "usr/lib", "usr/lib/azazel"),
        )


@pytest.mark.parametrize("directories", [
    ("usr/lib/azazel", "usr/lib"),
    ("usr/lib", "usr/lib"),
    ("usr/../etc",),
])
def test_invalid_directory_selection_refuses_before_any_open(tree, monkeypatch, directories, private_os):
    def forbidden_open(*_args, **_kwargs):
        pytest.fail("invalid directory selection reached filesystem open")

    # The guard covers the measurement helpers the candidate delegates to.
    for module in (candidate, installed_files):
        private_os(module)
        monkeypatch.setattr(module.os, "open", forbidden_open)
    with pytest.raises(ApprovalRefused):
        candidate._candidate_at(tree[1], tree[2], owner=tree[3], directories=directories)


@pytest.mark.parametrize("paths", [
    ("usr/a", "opt/a"),
    ("usr/a", "usr/a"),
    ("etc/passwd",),
    ("usr/../etc/passwd",),
    ("/usr/bin/python",),
    ("usr//a",),
    ("usr/a\\b",),
])
def test_invalid_or_unsafe_selection_refuses_before_any_open(tree, monkeypatch, paths, private_os):
    def forbidden_open(*_args, **_kwargs):
        pytest.fail("invalid selection reached filesystem open")

    # The guard covers the measurement helpers the candidate delegates to.
    for module in (candidate, installed_files):
        private_os(module)
        monkeypatch.setattr(module.os, "open", forbidden_open)
    with pytest.raises(ApprovalRefused):
        observe(tree, paths)


@pytest.mark.parametrize("kind", ["symlink", "directory", "hardlink", "mode"])
def test_unsafe_candidate_entries_are_refused_before_opening_leaf(tree, monkeypatch, kind, private_os):
    root, _fd, paths, _owner = tree
    target = root / paths[0]
    if kind == "symlink":
        target.unlink()
        target.symlink_to("missing")
    elif kind == "directory":
        target.unlink()
        target.mkdir()
    elif kind == "hardlink":
        os.link(target, root / "opt/azazel/second-link")
    else:
        target.chmod(0o600)

    original_open = candidate.os.open
    leaf_opens = []

    def checked_open(path, flags, *args, **kwargs):
        if path == target.name:
            leaf_opens.append(path)
            pytest.fail("unsafe leaf was opened")
        return original_open(path, flags, *args, **kwargs)

    # The guard covers the measurement helpers the candidate delegates to.
    for module in (candidate, installed_files):
        private_os(module)
        monkeypatch.setattr(module.os, "open", checked_open)
    with pytest.raises(ApprovalRefused):
        observe(tree)
    assert leaf_opens == []


@pytest.mark.parametrize("mutation", ["bytes", "identical-replacement"])
def test_change_between_candidate_read_and_selected_snapshot_refuses(
    tree, monkeypatch, mutation
):
    root, _fd, paths, _owner = tree
    leaf = root / paths[0]
    original_snapshot = candidate._snapshot_at
    calls = []

    def changed_snapshot(root_fd, manifest, *, owner):
        calls.append(None)
        if mutation == "bytes":
            leaf.write_bytes(b"changed synthetic bytes\n")
        else:
            replacement = leaf.with_name("replacement")
            replacement.write_bytes(leaf.read_bytes())
            replacement.chmod(0o755)
            replacement.replace(leaf)
        return original_snapshot(root_fd, manifest, owner=owner)

    monkeypatch.setattr(candidate, "_snapshot_at", changed_snapshot)
    with pytest.raises(ApprovalRefused):
        observe(tree)
    assert calls == [None]


def test_file_size_limit_rejects_before_read(tree, monkeypatch, private_os):
    _root, _fd, _paths, _owner = tree
    monkeypatch.setattr(candidate, "_MAX_FILE_SIZE", 4)

    def forbidden_read(*_args):
        pytest.fail("oversized file was read")

    # The guard covers the measurement helpers the candidate delegates to.
    for module in (candidate, installed_files):
        private_os(module)
        monkeypatch.setattr(module.os, "read", forbidden_read)
    with pytest.raises(ApprovalRefused):
        observe(tree)


def test_file_count_limit_rejects_selection_before_tree_walk(tree, monkeypatch, private_os):
    monkeypatch.setattr(candidate, "_MAX_FILES", 1)

    def forbidden_open(*_args, **_kwargs):
        pytest.fail("over-count selection reached filesystem")

    # The guard covers the measurement helpers the candidate delegates to.
    for module in (candidate, installed_files):
        private_os(module)
        monkeypatch.setattr(module.os, "open", forbidden_open)
    with pytest.raises(ApprovalRefused):
        observe(tree)


@pytest.mark.parametrize("payload", [b"", b"grown" * 100])
def test_growth_or_truncation_during_read_refuses(tree, monkeypatch, payload, private_os):
    private_os(candidate)
    leaf = tree[0] / tree[2][0]
    original_read = candidate.os.read
    changed = False

    def mutate_before_read(fd, count):
        nonlocal changed
        if not changed:
            changed = True
            leaf.write_bytes(payload)
        return original_read(fd, count)

    monkeypatch.setattr(candidate.os, "read", mutate_before_read)
    with pytest.raises(ApprovalRefused):
        observe(tree)


def test_second_pass_failure_closes_owned_descriptors_but_not_caller_root(tree, monkeypatch, private_os):
    private_os(candidate)
    allocated = []
    original_open, original_dup = candidate.os.open, candidate.os.dup

    def record_open(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        allocated.append(fd)
        return fd

    def record_dup(fd):
        result = original_dup(fd)
        allocated.append(result)
        return result

    def refuse(*_args, **_kwargs):
        raise ApprovalRefused("synthetic second-pass refusal")

    monkeypatch.setattr(candidate.os, "open", record_open)
    monkeypatch.setattr(candidate.os, "dup", record_dup)
    monkeypatch.setattr(candidate, "_snapshot_at", refuse)
    with pytest.raises(ApprovalRefused):
        observe(tree)
    assert allocated
    for fd in set(allocated):
        with pytest.raises(OSError):
            os.fstat(fd)
    os.fstat(tree[1])
