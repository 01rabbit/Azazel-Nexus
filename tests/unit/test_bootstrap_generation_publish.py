"""Explicit bootstrap-generation publication on private temporary storage."""

from contextlib import contextmanager
import os
from pathlib import Path

import pytest

from azazel_nexus.bootstrap_generation_publish import (
    BootstrapGenerationDurabilityUncertain,
    _publish_at,
    publication_digest,
    publish_bootstrap_generation,
)
from azazel_nexus.bootstrap_generation_store import _load_at
from azazel_nexus.generation import GenerationRefused, GenerationStore
from test_bootstrap_generation import _bootstrap_metadata, _config, _context


def _inputs():
    config = _config()
    files = {"bootstrap.json": config}
    context = _context(files)
    return context, _bootstrap_metadata(context), config


@pytest.fixture
def store(tmp_path):
    root = tmp_path / "generations"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root


def _load(root: Path, context):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return _load_at(fd, owner=os.getuid(), expected=context)
    finally:
        os.close(fd)


def _publish_at_root(root, *, context, metadata, config, confirmed_digest=None,
                     confirmed_publish=True, recheck=lambda: None):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return _publish_at(
            fd, metadata=metadata, config=config, expected=context, owner=os.getuid(),
            confirmed_digest=(confirmed_digest if confirmed_digest is not None else
                             publication_digest(metadata=metadata, config=config)),
            confirmed_publish=confirmed_publish, recheck=recheck,
        )
    finally:
        os.close(fd)


def _public_publisher(monkeypatch, root):
    import azazel_nexus.bootstrap_generation_publish as publisher

    @contextmanager
    def directory():
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(
        publisher, "_generation_directory", directory,
    )
    original_publish = publisher._publish_at

    def publish_for_test(fd, **kwargs):
        kwargs["owner"] = os.getuid()
        return original_publish(fd, **kwargs)

    monkeypatch.setattr(publisher, "_publish_at", publish_for_test)


def test_public_publish_roundtrips_through_bootstrap_reader_but_not_normal_reader(
    store, monkeypatch,
):
    context, metadata, config = _inputs()
    _public_publisher(monkeypatch, store)

    published = publish_bootstrap_generation(
        metadata=metadata, config=config, expected=context,
        confirmed_digest=publication_digest(metadata=metadata, config=config),
        confirmed_publish=True,
    )

    assert published == _load(store, context)
    assert (store / str(context.generation) / "generation.json").read_bytes() == metadata
    assert (store / str(context.generation) / "tree" / "bootstrap.json").read_bytes() == config
    assert not (store / f".bootstrap-{context.generation}.pending").exists()
    with pytest.raises(GenerationRefused):
        GenerationStore(store).read(context.generation)


@pytest.mark.parametrize("case", ["confirmation", "digest", "context"])
def test_publication_requires_exact_consent_digest_and_independent_context(
    store, monkeypatch, case,
):
    context, metadata, config = _inputs()
    digest = publication_digest(metadata=metadata, config=config)
    if case == "confirmation":
        confirmed, accepted, expected = digest, False, context
    elif case == "digest":
        confirmed, accepted, expected = "sha256:" + "0" * 64, True, context
    else:
        confirmed, accepted = digest, True
        expected = _context(generation=8)

    with pytest.raises(GenerationRefused):
        _publish_at_root(
            store, context=expected, metadata=metadata, config=config,
            confirmed_digest=confirmed, confirmed_publish=accepted,
        )
    assert list(store.iterdir()) == []


@pytest.mark.parametrize("target_kind", ["directory", "symlink", "pending"])
def test_existing_target_or_pending_marker_is_never_replaced(store, target_kind):
    context, metadata, config = _inputs()
    target = store / str(context.generation)
    pending = store / f".bootstrap-{context.generation}.pending"
    if target_kind == "directory":
        target.mkdir(mode=0o700)
    elif target_kind == "symlink":
        target.symlink_to(store / "nonexistent")
    else:
        pending.write_bytes(b"administrator state\n")
        pending.chmod(0o600)

    with pytest.raises(GenerationRefused):
        _publish_at_root(store, context=context, metadata=metadata, config=config)
    if target_kind == "directory":
        assert list(target.iterdir()) == []
    elif target_kind == "symlink":
        assert target.is_symlink()
    else:
        assert pending.read_bytes() == b"administrator state\n"
    assert not target.is_dir() or target_kind == "directory"


def test_reader_refuses_generation_when_interrupted_publication_marker_exists(store):
    context, metadata, config = _inputs()
    _publish_at_root(store, context=context, metadata=metadata, config=config)
    marker = store / f".bootstrap-{context.generation}.pending"
    marker.write_bytes(b"bootstrap generation publication pending\n")
    marker.chmod(0o600)

    with pytest.raises(GenerationRefused):
        _load(store, context)


def test_reader_refuses_marker_appearing_during_verification(store, monkeypatch):
    import azazel_nexus.bootstrap_generation_store as reader

    context, metadata, config = _inputs()
    _publish_at_root(store, context=context, metadata=metadata, config=config)
    original = reader.verify_bootstrap_generation

    def interrupted(**kwargs):
        result = original(**kwargs)
        marker = store / f".bootstrap-{context.generation}.pending"
        marker.symlink_to(store / "missing-marker-target")
        return result

    monkeypatch.setattr(reader, "verify_bootstrap_generation", interrupted)
    with pytest.raises(GenerationRefused):
        _load(store, context)


def test_unrelated_number_pending_does_not_select_or_block_current_generation(store):
    context, metadata, config = _inputs()
    _publish_at_root(store, context=context, metadata=metadata, config=config)
    (store / ".bootstrap-999.pending").write_bytes(b"unrelated incomplete generation")
    assert _load(store, context).number == context.generation


@pytest.mark.parametrize("revalidate", [False, lambda: True])
def test_public_selection_revalidation_requires_callable_and_exact_none(store, monkeypatch, revalidate):
    context, metadata, config = _inputs()
    _public_publisher(monkeypatch, store)
    with pytest.raises(GenerationRefused):
        publish_bootstrap_generation(
            metadata=metadata, config=config, expected=context,
            confirmed_digest=publication_digest(metadata=metadata, config=config),
            confirmed_publish=True, revalidate_selection=revalidate,
        )
    assert list(store.iterdir()) == []


def test_pending_marker_and_reader_block_remain_after_injected_fsync_failure(
    store, monkeypatch, private_os,
):
    import azazel_nexus.bootstrap_generation_publish as publisher
    private_os(publisher)

    context, metadata, config = _inputs()
    original_fsync = publisher.os.fsync
    count = 0

    def fail_root_sync(fd):
        nonlocal count
        count += 1
        if count == 2:  # pending file has been written; fail its directory sync
            raise OSError("injected sync failure")
        return original_fsync(fd)

    monkeypatch.setattr(publisher.os, "fsync", fail_root_sync)
    with pytest.raises(OSError, match="injected sync failure"):
        _publish_at_root(store, context=context, metadata=metadata, config=config)

    assert (store / f".bootstrap-{context.generation}.pending").exists()
    with pytest.raises(GenerationRefused):
        _load(store, context)


def test_readback_failure_retains_pending_marker_and_blocks_reader(store, monkeypatch):
    import azazel_nexus.bootstrap_generation_publish as publisher

    context, metadata, config = _inputs()
    monkeypatch.setattr(
        publisher, "_snapshot",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("injected readback failure")),
    )

    with pytest.raises(OSError, match="injected readback failure"):
        _publish_at_root(store, context=context, metadata=metadata, config=config)

    assert (store / f".bootstrap-{context.generation}.pending").exists()
    with pytest.raises(GenerationRefused):
        _load(store, context)


def test_mutation_during_final_recheck_retains_marker_and_blocks_reader(store):
    context, metadata, config = _inputs()
    checks = 0

    def mutate_on_final_recheck():
        nonlocal checks
        checks += 1
        if checks == 2:
            target = store / str(context.generation) / "tree" / "bootstrap.json"
            target.write_bytes(config + b" ")
            target.chmod(0o600)

    with pytest.raises(GenerationRefused):
        _publish_at_root(
            store, context=context, metadata=metadata, config=config,
            recheck=mutate_on_final_recheck,
        )

    assert checks == 2
    assert (store / f".bootstrap-{context.generation}.pending").exists()
    with pytest.raises(GenerationRefused):
        _load(store, context)


def test_final_directory_fsync_failure_is_reported_as_durability_uncertain(store, monkeypatch, private_os):
    import azazel_nexus.bootstrap_generation_publish as publisher
    private_os(publisher)

    context, metadata, config = _inputs()
    original_fsync = publisher.os.fsync
    root_info = store.stat()
    root_syncs = 0

    def fail_final_root_sync(fd):
        nonlocal root_syncs
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (root_info.st_dev, root_info.st_ino):
            root_syncs += 1
            if root_syncs == 3:
                raise OSError("injected final directory sync failure")
        return original_fsync(fd)

    monkeypatch.setattr(publisher.os, "fsync", fail_final_root_sync)
    with pytest.raises(BootstrapGenerationDurabilityUncertain):
        _publish_at_root(store, context=context, metadata=metadata, config=config)

    assert not (store / f".bootstrap-{context.generation}.pending").exists()
    assert _load(store, context).number == context.generation
