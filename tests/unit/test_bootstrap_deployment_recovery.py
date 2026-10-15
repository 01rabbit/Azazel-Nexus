"""Recovery never synthesizes or overwrites declaration bytes."""

import hashlib
import os

import pytest

from azazel_nexus import bootstrap_deployment_store as store
from azazel_nexus.bootstrap_deployment import encode_bootstrap_deployment
from test_bootstrap_deployment_store import declaration


@pytest.fixture
def retained(tmp_path):
    tmp_path.chmod(0o700)
    raw = encode_bootstrap_deployment(declaration())
    for name, data in (("deployment.json", raw), ("deployment.pending", store._PENDING_BYTES)):
        path = tmp_path / name
        path.write_bytes(data)
        path.chmod(0o600)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield tmp_path, fd, raw
    finally:
        os.close(fd)


def recover(fd, raw):
    store._recover_at(fd, raw, owner=os.getuid(), confirmed_sha256=hashlib.sha256(raw).hexdigest(),
                      confirmed_recovery=True)


def test_recovery_only_removes_marker_and_preserves_declaration_inode(retained):
    root, fd, raw = retained
    before = (root / "deployment.json").stat().st_ino
    recover(fd, raw)
    assert store._read_at(fd, owner=os.getuid()) == raw
    assert (root / "deployment.json").stat().st_ino == before
    assert not (root / "deployment.pending").exists()


@pytest.mark.parametrize("case", ["partial", "different", "missing", "marker", "symlink", "hardlink"])
def test_unrecognized_state_is_not_repaired(retained, case):
    root, fd, raw = retained
    path = root / "deployment.json"
    if case == "partial":
        path.write_bytes(raw[:10])
    elif case == "different":
        path.write_bytes(raw.replace(b"operator-a", b"operator-b"))
    elif case == "missing":
        path.unlink()
    elif case == "marker":
        (root / "deployment.pending").write_bytes(b"unknown")
    elif case == "symlink":
        path.rename(root / "other")
        path.symlink_to(root / "other")
    else:
        os.link(path, root / "other")
    before = {p.name: (p.lstat().st_ino, p.read_bytes()) for p in root.iterdir()}
    with pytest.raises((OSError, store.ApprovalRefused)):
        recover(fd, raw)
    assert {p.name: (p.lstat().st_ino, p.read_bytes()) for p in root.iterdir()} == before


@pytest.mark.parametrize("position", [1, 2, 3])
def test_recovery_fsync_failure_is_not_success(retained, monkeypatch, position):
    root, fd, raw = retained
    original = store.os.fsync
    calls = 0

    def fail(target):
        nonlocal calls
        calls += 1
        if calls == position:
            raise OSError("injected")
        original(target)

    monkeypatch.setattr(store.os, "fsync", fail)
    expected = OSError if position < 3 else store.DeploymentDurabilityUncertain
    with pytest.raises(expected):
        recover(fd, raw)
    assert (root / "deployment.json").read_bytes() == raw
    assert (root / "deployment.pending").exists() == (position < 3)
