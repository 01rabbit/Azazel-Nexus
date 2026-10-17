"""Read policy expectations from a protected administrator pin, without context."""

from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import os

import pytest

from azazel_nexus import bootstrap_prestart_store as store
from azazel_nexus.bootstrap_prestart_policy import decode_pinned_prestart_policy, encode_prestart_policy
from azazel_nexus.operator_trust import ApprovalRefused
from test_bootstrap_deployment_store import declaration
from test_bootstrap_prestart_policy import policy


@pytest.fixture(params=[None, "sha256:" + "b" * 64], ids=["v3", "v4"])
def declared_policy(tmp_path, monkeypatch, request):
    root = tmp_path / "bootstrap"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    value = policy(loaded_policy_digest=request.param)
    raw = encode_prestart_policy(value)
    deployment = replace(declaration(), policy_digest="sha256:" + sha256(raw).hexdigest())
    path = root / "admission.json"
    path.write_bytes(raw)
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
    return deployment, value, raw, path


def test_policy_loader_derives_expectations_without_candidate_context(declared_policy):
    deployment, value, raw, _path = declared_policy
    assert decode_pinned_prestart_policy(raw, expected_digest=deployment.policy_digest) == value
    assert store.load_declared_prestart_policy(deployment=deployment) == value


@pytest.mark.parametrize("case", ["wrong-pin", "noncanonical", "mode", "missing", "untyped"])
def test_declared_policy_refuses_unpinned_or_unprotected_record(declared_policy, case):
    deployment, _value, raw, path = declared_policy
    if case == "wrong-pin":
        deployment = replace(deployment, policy_digest="sha256:" + "0" * 64)
    elif case == "noncanonical":
        path.write_bytes(raw + b"\n")
        deployment = replace(deployment, policy_digest="sha256:" + sha256(raw + b"\n").hexdigest())
    elif case == "mode":
        path.chmod(0o644)
    elif case == "missing":
        path.unlink()
    else:
        deployment = None
    with pytest.raises(ApprovalRefused):
        store.load_declared_prestart_policy(deployment=deployment)
