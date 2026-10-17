from contextlib import contextmanager
import os

import pytest

from azazel_nexus import bootstrap_deployment_store as store
from azazel_nexus.bootstrap_deployment import (
    BootstrapDeployment, declared_node_digest, encode_bootstrap_deployment,
)
from azazel_nexus.operator_trust import ApprovalRefused


def declaration():
    return BootstrapDeployment(declared_node_digest("node-a"), 3,
                               "sha256:" + "a" * 64, "sha256:" + "b" * 64,
                               "sha256:" + "c" * 64, "operator-a")


@pytest.fixture
def protected(tmp_path, monkeypatch):
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

    original = store._read_at
    monkeypatch.setattr(store, "_bootstrap_directory", directory)
    monkeypatch.setattr(store, "_read_at", lambda fd, *, owner: original(fd, owner=os.getuid()))
    return root, path


def test_read_uses_deployment_not_candidate(protected):
    root, _ = protected
    (root / "approval.json").write_bytes(b"not the deployment")
    assert store.load_bootstrap_deployment() == declaration()


@pytest.mark.parametrize("case", ["absent", "nonprivate", "symlink", "hardlink", "oversized"])
def test_unsafe_deployment_refuses_without_creation(protected, case):
    root, path = protected
    if case == "absent":
        path.unlink()
    elif case == "nonprivate":
        path.chmod(0o640)
    elif case == "oversized":
        path.write_bytes(b"x" * 4097)
    else:
        other = root / "other"
        if case == "hardlink":
            os.link(path, other)
        else:
            path.rename(other)
            path.symlink_to(other)
    with pytest.raises(ApprovalRefused):
        store.load_bootstrap_deployment()
    if case == "absent":
        assert not path.exists()


def test_mutation_during_decode_refuses(protected, monkeypatch):
    _, path = protected
    original = store.decode_bootstrap_deployment

    def mutate(raw):
        result = original(raw)
        path.write_bytes(raw + b"\n")
        return result

    monkeypatch.setattr(store, "decode_bootstrap_deployment", mutate)
    with pytest.raises(ApprovalRefused):
        store.load_bootstrap_deployment()
