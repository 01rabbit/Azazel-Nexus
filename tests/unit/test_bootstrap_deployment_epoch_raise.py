"""Raise-only replacement of the deployment declaration (#251, design §11).

Ordinary private files under a temporary directory; only the fixed directory
and its owner are redirected.
"""

from contextlib import contextmanager
import dataclasses
import hashlib
import os

import pytest

from azazel_nexus import bootstrap_deployment_store as store
from azazel_nexus.bootstrap_deployment import encode_bootstrap_deployment
from azazel_nexus.operator_trust import ApprovalRefused
from test_bootstrap_deployment_store import declaration


@pytest.fixture
def local(tmp_path, monkeypatch):
    root = tmp_path / "bootstrap"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    path = root / "deployment.json"
    path.write_bytes(encode_bootstrap_deployment(declaration()))
    path.chmod(0o600)

    @contextmanager
    def directory():
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(store, "_bootstrap_directory", directory)
    for name in ("_raise_epoch_at", "_recover_at", "_read_at"):
        original = getattr(store, name)

        def local_owner(*args, _operation=original, **kwargs):
            return _operation(*args, **(kwargs | {"owner": os.getuid()}))

        monkeypatch.setattr(store, name, local_owner)
    return root, path


def test_raise_replaces_only_the_epoch(local):
    root, path = local
    store.raise_bootstrap_deployment_epoch(declaration(), 4)
    assert store.load_bootstrap_deployment() == dataclasses.replace(declaration(),
                                                                    security_epoch=4)
    assert sorted(p.name for p in root.iterdir()) == ["deployment.json"]
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("to_epoch", [3, 2, 0, 2**64])
def test_raise_never_lowers_or_repeats(local, to_epoch):
    _, path = local
    before = path.read_bytes()
    with pytest.raises(ApprovalRefused):
        store.raise_bootstrap_deployment_epoch(declaration(), to_epoch)
    assert path.read_bytes() == before


def test_raise_is_compare_and_swap(local):
    _, path = local
    before = path.read_bytes()
    stale = dataclasses.replace(declaration(), security_epoch=2)
    with pytest.raises(ApprovalRefused):
        store.raise_bootstrap_deployment_epoch(stale, 4)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ApprovalRefused):  # another field may not change with it
            store._raise_epoch_at(fd, before, encode_bootstrap_deployment(dataclasses.replace(
                declaration(), security_epoch=4, policy_digest="sha256:" + "e" * 64)))
    finally:
        os.close(fd)
    assert path.read_bytes() == before


def test_pending_publication_refuses(local):
    root, path = local
    (root / "deployment.pending").write_bytes(store._PENDING_BYTES)
    (root / "deployment.pending").chmod(0o600)
    with pytest.raises(ApprovalRefused):
        store.raise_bootstrap_deployment_epoch(declaration(), 4)
    assert store.decode_bootstrap_deployment(path.read_bytes()) == declaration()


def test_interrupted_raise_blocks_readers_until_explicit_recovery(local, monkeypatch):
    root, _ = local
    raised = dataclasses.replace(declaration(), security_epoch=4)

    def fail(*args, **kwargs):
        raise OSError("injected interruption")

    monkeypatch.setattr(store.os, "replace", fail)
    with pytest.raises(ApprovalRefused):
        store.raise_bootstrap_deployment_epoch(declaration(), 4)
    monkeypatch.undo()
    with pytest.raises(ApprovalRefused):  # pending: every reader refuses
        store.load_bootstrap_deployment()
    with pytest.raises(ApprovalRefused):  # and a second raise does too
        store.raise_bootstrap_deployment_epoch(declaration(), 4)
    assert (root / ".deployment.json.next").exists()


def test_recovery_after_interruption_then_raise_again(local, monkeypatch):
    root, _ = local
    original = store.os.replace

    def fail(*args, **kwargs):
        raise OSError("injected interruption")

    monkeypatch.setattr(store.os, "replace", fail)
    with pytest.raises(ApprovalRefused):
        store.raise_bootstrap_deployment_epoch(declaration(), 4)
    monkeypatch.setattr(store.os, "replace", original)
    raw = encode_bootstrap_deployment(declaration())
    store.recover_bootstrap_deployment(raw, confirmed_sha256=hashlib.sha256(raw).hexdigest(),
                                       confirmed_recovery=True)
    assert store.load_bootstrap_deployment() == declaration()
    store.raise_bootstrap_deployment_epoch(declaration(), 4)  # the stale .next is cleared
    assert store.load_bootstrap_deployment().security_epoch == 4
    assert sorted(p.name for p in root.iterdir()) == ["deployment.json"]
