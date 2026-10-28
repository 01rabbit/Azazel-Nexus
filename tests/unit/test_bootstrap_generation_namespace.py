"""Separate bootstrap and operational generation namespaces, temp-only."""

import os
from pathlib import Path

import pytest

from azazel_nexus.bootstrap_generation_publish import (
    publication_digest,
    publish_bootstrap_generation,
)
from azazel_nexus.bootstrap_generation_store import (
    load_bootstrap_generation,
)
from azazel_nexus.generation import GenerationRefused, GenerationStore
from test_bootstrap_generation import _bootstrap_metadata, _config, _context

NOW = "2026-10-13T00:00:00Z"
COMM_DIGEST = "sha256:" + "a" * 64


def test_fixed_bootstrap_namespace_is_separate_and_publisher_preserves_normal_store(
    tmp_path, monkeypatch, private_os,
):
    import azazel_nexus.activation_store as activation_store
    import azazel_nexus.bootstrap_generation_publish as publisher
    import azazel_nexus.bootstrap_generation_store as reader
    import azazel_nexus.operator_store as operator_store

    root = tmp_path / "system-root"
    (root / "var/lib/azazel/generations").mkdir(parents=True, mode=0o700)
    bootstrap_root = root / "var/lib/azazel/bootstrap-generations"
    bootstrap_root.mkdir(mode=0o700)
    normal_root = root / "var/lib/azazel/generations"
    for directory in (
        root, root / "var", root / "var/lib", root / "var/lib/azazel",
        normal_root, bootstrap_root,
    ):
        directory.chmod(0o700)

    normal = GenerationStore(normal_root)
    original = normal.create(
        {"node.yaml": b"preexisting ordinary generation\n"},
        created_at=NOW, commissioning_digest=COMM_DIGEST,
    )
    original_bytes = (normal_root / str(original.number) / "tree/node.yaml").read_bytes()
    assert normal.numbers() == (original.number,)
    assert normal.current() == original

    context = _context({"bootstrap.json": _config()})
    metadata = _bootstrap_metadata(context)
    config = _config()
    uid = os.getuid()
    open_original = os.open

    def map_root_open(path, flags, *args, **kwargs):
        if path == "/" and "dir_fd" not in kwargs:
            path = root
        return open_original(path, flags, *args, **kwargs)

    # Every module that opens "/" during publication sees the mapped root.
    for module in (reader, publisher, activation_store):
        private_os(module)
        monkeypatch.setattr(module.os, "open", map_root_open)

    protected_original = operator_store._protected

    def protected_for_test(fd, *, owner, directory):
        return protected_original(fd, owner=uid, directory=directory)

    monkeypatch.setattr(reader, "_protected", protected_for_test)

    private_original = activation_store._private_directory

    def private_for_test(fd, *, owner):
        return private_original(fd, owner=uid)

    monkeypatch.setattr(reader, "_private_directory", private_for_test)
    monkeypatch.setattr(publisher, "_private_directory", private_for_test)

    protected_file_original = activation_store._protected

    def protected_file_for_test(fd, *, owner, directory):
        return protected_file_original(fd, owner=uid, directory=directory)

    monkeypatch.setattr(activation_store, "_protected", protected_file_for_test)

    publish_original = publisher._publish_at

    def publish_for_test(fd, **kwargs):
        kwargs["owner"] = uid
        return publish_original(fd, **kwargs)

    monkeypatch.setattr(publisher, "_publish_at", publish_for_test)

    load_original = reader._load_at

    def load_for_test(fd, *, owner, expected):
        return load_original(fd, owner=uid, expected=expected)

    monkeypatch.setattr(reader, "_load_at", load_for_test)

    # Exercise the actual fixed traversal, with only its root descriptor mapped
    # into the private test tree. The installed declaration names this sibling.
    assert reader._COMPONENTS == ("var", "lib", "azazel", "bootstrap-generations")
    installer = Path(__file__).parents[2] / "packaging" / "install.sh"
    install_text = installer.read_text(encoding="utf-8")
    assert "make_dir 0700 root /var/lib/azazel/generations" in install_text
    assert "make_dir 0700 root /var/lib/azazel/bootstrap-generations" in install_text

    published = publish_bootstrap_generation(
        metadata=metadata,
        config=config,
        expected=context,
        confirmed_digest=publication_digest(metadata=metadata, config=config),
        confirmed_publish=True,
    )
    assert published.number == 7
    assert load_bootstrap_generation(expected=context) == published

    assert normal.numbers() == (original.number,)
    assert normal.current() == original
    assert (normal_root / str(original.number) / "tree/node.yaml").read_bytes() == original_bytes
    assert not (normal_root / "7").exists()
    with pytest.raises(GenerationRefused):
        normal.read(7)


def test_normal_generation_reader_still_rejects_bootstrap_variant(tmp_path):
    store = GenerationStore(tmp_path / "ordinary")
    store.root.mkdir(mode=0o700)
    config = _config()
    context = _context({"bootstrap.json": config}, generation=1)
    directory = store.root / "1"
    (directory / "tree").mkdir(parents=True, mode=0o700)
    (directory / "generation.json").write_bytes(_bootstrap_metadata(context))
    (directory / "tree" / "bootstrap.json").write_bytes(config)

    with pytest.raises(GenerationRefused):
        store.read(1)
