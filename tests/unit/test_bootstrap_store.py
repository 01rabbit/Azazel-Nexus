"""Protected bootstrap reader tests use temporary files and ephemeral keys only."""

from contextlib import contextmanager
import inspect
import hashlib
import json
import os

import pytest
from nacl.signing import SigningKey

from azazel_nexus import bootstrap_store
from azazel_nexus.bootstrap_approval import (
    BOOTSTRAP_UNITS,
    BootstrapApprovalPolicy,
    BootstrapContext,
    bootstrap_payload,
)
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
    approval_message,
)

DIGEST = "sha256:" + "a" * 64
START = "2026-10-13T00:00:00Z"
END = "2026-10-13T00:05:00Z"
OPERATOR = "operator-a"


@pytest.fixture
def store(tmp_path, monkeypatch):
    key = SigningKey.generate()
    policy = BootstrapApprovalPolicy(frozenset({OPERATOR}), 300)
    context = BootstrapContext(
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", DIGEST,
        "11111111-1111-1111-1111-111111111111", 1, DIGEST, DIGEST,
        DIGEST, DIGEST, policy.digest(), 7, DIGEST,
    )
    policy_raw = json.dumps({
        "schema": "azazel-nexus/bootstrap-approval-policy/v1",
        "operators": [OPERATOR], "max_seconds": 300, "units": BOOTSTRAP_UNITS,
    }, sort_keys=True, separators=(",", ":")).encode()
    payload = bootstrap_payload(
        context=context, operator=OPERATOR, granted_at=START, expires_at=END,
    )
    signature = key.sign(
        approval_message(ApprovalPurpose.SUPPORTING_BOOTSTRAP, payload)
    ).signature
    directory = tmp_path / "bootstrap"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    for name, data in (("policy.json", policy_raw), ("approval.json", payload),
                       ("approval.sig", signature)):
        path = directory / name
        path.write_bytes(data)
        path.chmod(0o600)
    trust = OperatorTrust({OPERATOR: bytes(key.verify_key)})

    @contextmanager
    def directory_reader():
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(bootstrap_store, "_bootstrap_directory", directory_reader)
    read_at = bootstrap_store._read_at
    monkeypatch.setattr(
        bootstrap_store, "_read_at",
        lambda fd, *, owner: read_at(fd, owner=os.getuid() if owner == 0 else owner),
    )
    monkeypatch.setattr(bootstrap_store, "_load_trust", lambda: trust)
    return directory, key, policy, context, payload, signature, trust, policy_raw


def _load(context):
    return bootstrap_store.load_bootstrap_approval(
        expected=context, operator=OPERATOR, now=START,
    )


def test_public_reader_returns_verified_bootstrap_proof(store):
    _, _, _, context, payload, _, _, _ = store
    proof = _load(context)
    assert proof.context == context
    assert proof.operator == OPERATOR
    assert proof.payload_digest == "sha256:" + hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize("fault", ["duplicate", "extra", "units", "operator_order", "duration", "schema"])
def test_noncanonical_or_out_of_scope_policy_is_redacted(store, fault):
    directory, _, _, context, *_ = store
    policy = json.loads((directory / "policy.json").read_bytes())
    if fault == "duplicate":
        raw = b'{"max_seconds":300,"operators":["operator-a","operator-a"],"schema":"azazel-nexus/bootstrap-approval-policy/v1","units":["azazel-auditd.service","azazel-commissiond.service"]}'
    else:
        if fault == "extra":
            policy["extra"] = True
        elif fault == "units":
            policy["units"] = ["azazel-auditd.service"]
        elif fault == "operator_order":
            policy["operators"] = ["operator-b", "operator-a"]
        elif fault == "duration":
            policy["max_seconds"] = True
        else:
            policy["schema"] = "other/v1"
        raw = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    (directory / "policy.json").write_bytes(raw)
    with pytest.raises(ApprovalRefused) as error:
        _load(context)
    assert str(error.value) == "protected bootstrap approval refused"


def test_wrong_key_and_revoked_operator_refuse(store, monkeypatch):
    _, _, _, context, _, _, trust, _ = store
    monkeypatch.setattr(bootstrap_store, "_load_trust", lambda: OperatorTrust(
        {OPERATOR: bytes(SigningKey.generate().verify_key)}
    ))
    with pytest.raises(ApprovalRefused):
        _load(context)
    revoked = OperatorTrust(trust.public_keys, frozenset({OPERATOR}))
    monkeypatch.setattr(bootstrap_store, "_load_trust", lambda: revoked)
    with pytest.raises(ApprovalRefused):
        _load(context)


@pytest.mark.parametrize("change", ["policy", "payload", "trust"])
def test_inputs_changed_during_read_are_refused(store, monkeypatch, change):
    directory, _, _, context, _, _, trust, _ = store
    if change == "trust":
        other = OperatorTrust({OPERATOR: bytes(SigningKey.generate().verify_key)})
        values = iter((trust, other))
        monkeypatch.setattr(bootstrap_store, "_load_trust", lambda: next(values))
    else:
        original = bootstrap_store._read_at
        count = 0

        def changing(fd, *, owner):
            nonlocal count
            result = original(fd, owner=os.getuid())
            count += 1
            if count == 1:
                name = "policy.json" if change == "policy" else "approval.json"
                (directory / name).write_bytes(b"changed")
            return result

        monkeypatch.setattr(bootstrap_store, "_read_at", changing)
    with pytest.raises(ApprovalRefused):
        _load(context)


def test_replaced_directory_during_read_is_refused(store, monkeypatch, tmp_path):
    directory, _, _, context, _, _, _, _ = store
    replacement = tmp_path / "replacement"
    replacement.mkdir(mode=0o700)
    for name in ("policy.json", "approval.json", "approval.sig"):
        (replacement / name).write_bytes((directory / name).read_bytes())
        (replacement / name).chmod(0o600)
    selected = iter((directory, replacement))

    @contextmanager
    def changing_directory():
        fd = os.open(next(selected), os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(bootstrap_store, "_bootstrap_directory", changing_directory)
    with pytest.raises(ApprovalRefused):
        _load(context)


@pytest.mark.parametrize("fault", ["directory_mode", "file_mode", "symlink", "hardlink", "size", "wrong_owner", "type", "missing"])
def test_private_descriptor_reader_rejects_bad_storage(store, fault):
    directory, *_ = store
    target = directory / "policy.json"
    owner = os.getuid()
    if fault == "directory_mode":
        directory.chmod(0o750)
    elif fault == "file_mode":
        target.chmod(0o640)
    elif fault == "symlink":
        target.rename(directory / "saved.json")
        target.symlink_to(directory / "saved.json")
    elif fault == "hardlink":
        os.link(target, directory / "alias.json")
    elif fault == "size":
        target.write_bytes(b"x" * (bootstrap_store.MAX_APPROVAL_BYTES + 1))
    elif fault == "wrong_owner":
        owner += 1
    elif fault == "type":
        target.unlink()
        target.mkdir()
    else:
        target.unlink()
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises((ApprovalRefused, OSError)):
            bootstrap_store._read_at(fd, owner=owner)
    finally:
        os.close(fd)


def test_public_api_has_no_path_or_owner_override():
    assert tuple(inspect.signature(bootstrap_store.load_bootstrap_approval).parameters) == (
        "expected", "operator", "now",
    )
    with pytest.raises(TypeError):
        bootstrap_store.load_bootstrap_approval(
            expected=None, operator=OPERATOR, now=START, path="/tmp/approval",
        )


def test_public_refusal_redacts_paths_and_raw_errors(store, monkeypatch):
    _, _, _, context, *_ = store
    calls = []
    @contextmanager
    def unavailable():
        calls.append("opened")
        raise OSError("/private/secret/path")
        yield

    monkeypatch.setattr(bootstrap_store, "_bootstrap_directory", unavailable)
    with pytest.raises(ApprovalRefused) as error:
        bootstrap_store.load_bootstrap_approval(expected=context, operator=OPERATOR, now=START)
    assert str(error.value) == "protected bootstrap approval refused"
    assert calls == ["opened"]
