"""Synthetic filesystem contract tests for bounded cgroup observations."""

import os
import stat

import pytest

from azazel_nexus_runtime import bootstrap_cgroup
from azazel_nexus_runtime.units import UnitOperationFailed


OWNER = os.getuid()


def _private_dir(path):
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


@pytest.fixture
def cgroup_root(tmp_path):
    root = _private_dir(tmp_path / "root")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        yield root, fd
    finally:
        os.close(fd)


def _leaf(root, relative="group"):
    path = root
    for component in relative.split("/"):
        path = _private_dir(path / component)
    return path


def _events(leaf, data=b"populated 0\nfrozen 0\n"):
    path = leaf / "cgroup.events"
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def _observe(root_fd, path):
    return bootstrap_cgroup.observe_cgroup_at(root_fd, path, owner_uid=OWNER)


def test_empty_leaf_returns_directory_identity_and_allows_frozen_zero(cgroup_root):
    root, root_fd = cgroup_root
    leaf = _leaf(root)
    _events(leaf)

    result = _observe(root_fd, "/group")

    info = leaf.stat()
    assert result == ("empty", info.st_dev, info.st_ino)


def test_populated_leaf_is_refused(cgroup_root):
    root, root_fd = cgroup_root
    _events(_leaf(root), b"populated 1\nfrozen 0\n")

    with pytest.raises(UnitOperationFailed):
        _observe(root_fd, "/group")


@pytest.mark.parametrize(
    "contents",
    [
        b"",
        b"frozen 0\n",
        b"populated\n",
        b"populated nope\n",
        b"populated 0\npopulated 0\n",
        b"populated 0\nnot-valid 0\n",
        b"populated 0\npopulated 1\n",
    ],
)
def test_malformed_duplicate_or_missing_populated_is_refused(cgroup_root, contents):
    root, root_fd = cgroup_root
    _events(_leaf(root), contents)

    with pytest.raises(UnitOperationFailed):
        _observe(root_fd, "/group")


def test_oversized_events_file_is_refused(cgroup_root):
    root, root_fd = cgroup_root
    _events(_leaf(root), b"populated 0\n" + b"x" * 4096)

    with pytest.raises(UnitOperationFailed):
        _observe(root_fd, "/group")


@pytest.mark.parametrize(
    "path", ["/", "", "group", "//group", "/group/..", "/group/.", "/a//b", "/a/../b"]
)
def test_invalid_absolute_or_non_normalized_paths_are_refused(cgroup_root, path):
    _, root_fd = cgroup_root

    with pytest.raises(UnitOperationFailed):
        _observe(root_fd, path)


def test_missing_final_leaf_is_absent_but_missing_intermediate_is_refused(cgroup_root):
    root, root_fd = cgroup_root
    _leaf(root, "existing")

    parent_info = (root / "existing").stat()
    assert _observe(root_fd, "/existing/missing") == (
        "absent",
        parent_info.st_dev,
        parent_info.st_ino,
    )
    with pytest.raises(UnitOperationFailed):
        _observe(root_fd, "/missing/leaf")


def test_symlink_leaf_is_refused(cgroup_root):
    root, root_fd = cgroup_root
    target = _leaf(root, "target")
    _events(target)
    (root / "link").symlink_to(target, target_is_directory=True)

    with pytest.raises(UnitOperationFailed):
        _observe(root_fd, "/link")


@pytest.mark.parametrize("kind", ["symlink", "fifo", "hardlink", "wrong_mode"])
def test_untrusted_events_file_is_refused(cgroup_root, kind):
    root, root_fd = cgroup_root
    leaf = _leaf(root)
    events = _events(leaf)
    if kind == "symlink":
        events.unlink()
        (leaf / "cgroup.events").symlink_to(root / "source")
        (root / "source").write_bytes(b"populated 0\n")
        (root / "source").chmod(0o600)
    elif kind == "fifo":
        events.unlink()
        os.mkfifo(events, 0o600)
    elif kind == "hardlink":
        os.link(events, root / "alias")
    else:
        events.chmod(0o620)

    with pytest.raises(UnitOperationFailed):
        _observe(root_fd, "/group")


def test_observation_closes_internal_descriptors_and_preserves_root_fd(
    cgroup_root, monkeypatch, private_os
):
    private_os(bootstrap_cgroup)
    root, root_fd = cgroup_root
    _events(_leaf(root))
    opened = []
    closed = []
    real_open = os.open
    real_close = os.close

    def tracked_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def tracked_close(fd):
        closed.append(fd)
        return real_close(fd)

    monkeypatch.setattr(bootstrap_cgroup.os, "open", tracked_open)
    monkeypatch.setattr(bootstrap_cgroup.os, "close", tracked_close)

    assert _observe(root_fd, "/group")[0] == "empty"

    assert opened
    assert set(opened) <= set(closed)
    assert root_fd not in closed
    assert stat.S_ISDIR(os.fstat(root_fd).st_mode)
