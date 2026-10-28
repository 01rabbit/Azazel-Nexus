"""Fixed-node configuration parser/storage seams; no real host enrollment."""

import os

import pytest

from azazel_nexus_runtime import node_config as config


def test_declared_label_preserved_without_consuming_role_or_resource_claims():
    node = config._decode(b"node_id: Node-A\nresource_profile: standard\nroles:\n  management: {required: true}\n")
    assert node.node_id == "Node-A"
    assert "Node-A" not in repr(node)
    assert not hasattr(node, "roles")


@pytest.mark.parametrize("raw", [b"", b"[]", b"{}", b"node_id: 12", b"node_id: true",
    b"node_id: null", b"node_id: ' padded '", b"node_id: ''", b"node_id: a\nnode_id: b",
    b"node_id: a\n---\nnode_id: b", b"node_id: &node a", b"node_id: *node",
    b"node_id: !!str a", b"node_id: a\nroles: {x: 1, x: 2}", b"node_id: a\nroles: {1: 2}",
    b"node_id: a\nroles: {<<: {x: 1}}", b"node_id: 'a\x00b'", b"node_id: \xff",
    b"node_id: " + b"a" * 129, b"node_id: a\nvalues: " + b"[" * 33 + b"]" * 33])
def test_ambiguous_or_unsupported_yaml_refused_without_raw_detail(raw):
    with pytest.raises(config.NodeConfigUnavailable) as error:
        config._decode(raw)
    assert str(error.value) in {"ambiguous node configuration", "node configuration refused"}


@pytest.fixture
def directory(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "node.yaml"
    path.write_bytes(b"node_id: private-synthetic\n")
    path.chmod(0o600)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield tmp_path, path, fd
    finally:
        os.close(fd)


def test_private_regular_file_read(directory):
    _, _, fd = directory
    assert config._read_at(fd, owner=os.geteuid()).node_id == "private-synthetic"


@pytest.mark.parametrize("change", ["writable-file", "writable-directory", "symlink", "hardlink", "oversize", "wrong-owner"])
def test_unsafe_storage_refused(directory, change):
    root, path, fd = directory
    owner = os.geteuid()
    if change == "writable-file":
        path.chmod(0o622)
    elif change == "writable-directory":
        root.chmod(0o722)
    elif change == "symlink":
        path.rename(root / "original")
        path.symlink_to(root / "original")
    elif change == "hardlink":
        os.link(path, root / "alias")
    elif change == "oversize":
        path.write_bytes(b"x" * 65537)
    else:
        owner += 1
    with pytest.raises((config.NodeConfigUnavailable, OSError)):
        config._read_at(fd, owner=owner)


def test_public_reader_redacts_filesystem_failure(monkeypatch, private_os):
    private_os(config)
    def fail(*a, **k):
        raise OSError("private-path")
    monkeypatch.setattr(config.os, "open", fail)
    with pytest.raises(config.NodeConfigUnavailable) as error:
        config.load_declared_node()
    assert "private" not in str(error.value)
