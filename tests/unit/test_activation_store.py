"""Protected approval reader tests use temporary files and ephemeral keys only."""

from contextlib import contextmanager
from dataclasses import replace
import fcntl
import inspect
import os

import pytest
from nacl.signing import SigningKey

from azazel_nexus import activation_store
from azazel_nexus.activation_approval import ActivationContext, approval_payload
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
    approval_message,
)

DIGEST = "sha256:" + "a" * 64
START = "2026-10-13T00:00:00Z"
END = "2026-10-13T00:10:00Z"


@pytest.fixture
def approval(tmp_path, monkeypatch):
    key = SigningKey.generate()
    context = ActivationContext(
        DIGEST, "11111111-1111-1111-1111-111111111111", 7,
        DIGEST, DIGEST, DIGEST, DIGEST, DIGEST, 3,
    )
    payload = approval_payload(
        context=context, operator="operator-a", granted_at=START, expires_at=END
    )
    signature = key.sign(
        approval_message(ApprovalPurpose.ACTIVATION, payload)
    ).signature
    directory = tmp_path / "activation"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    (directory / "approval.json").write_bytes(payload)
    (directory / "approval.json").chmod(0o600)
    (directory / "approval.sig").write_bytes(signature)
    (directory / "approval.sig").chmod(0o600)
    trust = OperatorTrust({"operator-a": bytes(key.verify_key)})

    @contextmanager
    def directory_reader():
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(activation_store, "_approval_directory", directory_reader)
    read_at = activation_store._read_at
    monkeypatch.setattr(
        activation_store, "_read_at",
        lambda fd, *, owner: read_at(
            fd, owner=os.getuid() if owner == 0 else owner
        ),
    )
    monkeypatch.setattr(activation_store, "_load_trust", lambda: trust)
    return directory, key, context, payload, signature, trust


def _load(context):
    return activation_store.load_activation_approval(
        expected=context, operator="operator-a", now=START,
        max_lease_seconds=600,
    )


def _resign(key, payload, purpose=ApprovalPurpose.ACTIVATION):
    return key.sign(approval_message(purpose, payload)).signature


def test_public_reader_returns_bound_lease_from_real_verifier(approval):
    _, _, context, _, _, _ = approval
    lease = _load(context)
    assert lease.granted_by == "operator-a"
    assert lease.generation_number == context.generation
    assert lease.generation_digest == context.generation_digest
    assert lease.commissioning_digest == context.commissioning_digest
    assert lease.valid_at(START)
    assert not lease.valid_at(END)


@pytest.mark.parametrize("fault", ["signature", "context", "operator", "purpose", "time", "cap"])
def test_invalid_approval_refused_with_redacted_error(approval, monkeypatch, fault):
    directory, key, context, payload, signature, trust = approval
    if fault == "signature":
        (directory / "approval.sig").write_bytes(b"x" * 64)
    elif fault == "context":
        context = replace(context, generation=8)
    elif fault == "operator":
        monkeypatch.setattr(activation_store, "_load_trust", lambda: trust)
        with pytest.raises(ApprovalRefused):
            activation_store.load_activation_approval(
                expected=context, operator="operator-b", now=START,
                max_lease_seconds=600,
            )
        return
    elif fault == "purpose":
        (directory / "approval.sig").write_bytes(
            _resign(key, payload, ApprovalPurpose.COMMISSIONING)
        )
    elif fault == "time":
        with pytest.raises(ApprovalRefused):
            activation_store.load_activation_approval(
                expected=context, operator="operator-a", now=END,
                max_lease_seconds=600,
            )
        return
    else:
        with pytest.raises(ApprovalRefused):
            activation_store.load_activation_approval(
                expected=context, operator="operator-a", now=START,
                max_lease_seconds=599,
            )
        return
    with pytest.raises(ApprovalRefused) as error:
        _load(context)
    assert str(error.value) == "protected activation approval refused"


def test_changed_protected_pair_is_refused(approval, monkeypatch):
    directory, _, context, _, _, _ = approval
    original = activation_store._read_at
    count = 0

    def changing(fd, *, owner):
        nonlocal count
        result = original(fd, owner=os.getuid())
        count += 1
        if count == 1:
            (directory / "approval.json").write_bytes(b"changed")
        return result

    monkeypatch.setattr(activation_store, "_read_at", changing)
    with pytest.raises(ApprovalRefused):
        _load(context)


def test_replaced_approval_directory_is_refused_even_with_same_pair(approval, monkeypatch):
    directory, _, context, _, _, _ = approval
    replacement = directory.with_name("replacement")
    replacement.mkdir(mode=0o700)
    replacement.chmod(0o700)
    for name in ("approval.json", "approval.sig"):
        (replacement / name).write_bytes((directory / name).read_bytes())
        (replacement / name).chmod(0o600)
    directories = iter((directory, replacement))

    @contextmanager
    def replaced_directory_reader():
        selected = next(directories)
        fd = os.open(selected, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(
        activation_store, "_approval_directory", replaced_directory_reader
    )
    with pytest.raises(ApprovalRefused) as error:
        _load(context)
    assert str(error.value) == "protected activation approval refused"


def test_changed_trust_is_refused(approval, monkeypatch):
    _, _, context, _, _, trust = approval
    other = OperatorTrust({"operator-a": bytes(SigningKey.generate().verify_key)})
    values = iter((trust, other))
    monkeypatch.setattr(activation_store, "_load_trust", lambda: next(values))
    with pytest.raises(ApprovalRefused):
        _load(context)


@pytest.mark.parametrize("change", ["directory-mode", "file-mode", "symlink", "hardlink", "size", "wrong-owner"])
def test_private_descriptor_reader_rejects_unprotected_storage(approval, change):
    directory, _, _, _, _, _ = approval
    target = directory / "approval.json"
    owner = os.getuid()
    if change == "directory-mode":
        directory.chmod(0o750)
    elif change == "file-mode":
        target.chmod(0o640)
    elif change == "symlink":
        target.rename(directory / "saved.json")
        target.symlink_to(directory / "saved.json")
    elif change == "hardlink":
        os.link(target, directory / "alias.json")
    elif change == "size":
        target.write_bytes(b"x" * (activation_store.MAX_APPROVAL_BYTES + 1))
    else:
        owner += 1
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises((ApprovalRefused, OSError)):
            activation_store._read_at(fd, owner=owner)
    finally:
        os.close(fd)


def test_public_api_has_no_path_or_owner_overrides():
    with pytest.raises(TypeError):
        activation_store.load_activation_approval(
            expected=None, operator="operator-a", now=START,
            max_lease_seconds=600, path="/tmp/approval",
        )


def test_wrong_expected_type_refuses_before_opening_directory(monkeypatch):
    opened = False

    @contextmanager
    def directory_reader():
        nonlocal opened
        opened = True
        raise OSError("sensitive path detail")
        yield

    monkeypatch.setattr(activation_store, "_approval_directory", directory_reader)
    with pytest.raises(ApprovalRefused) as error:
        activation_store.load_activation_approval(
            expected=None, operator="operator-a", now=START,
            max_lease_seconds=600,
        )
    assert not opened
    assert str(error.value) == "protected activation approval refused"


def test_malformed_signed_payload_error_is_redacted(approval):
    directory, key, context, _, _, _ = approval
    malformed = b"not-json: /private/path"
    (directory / "approval.json").write_bytes(malformed)
    (directory / "approval.sig").write_bytes(_resign(key, malformed))
    with pytest.raises(ApprovalRefused) as error:
        _load(context)
    assert str(error.value) == "protected activation approval refused"


def test_private_descriptor_reader_checks_file_owner(approval):
    directory, *_ = approval
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ApprovalRefused):
            activation_store._read_file_at(
                fd, "approval.json", owner=os.getuid() + 1,
                limit=activation_store.MAX_APPROVAL_BYTES,
            )
    finally:
        os.close(fd)


def _synthetic_approval_root(monkeypatch, tmp_path):
    root = tmp_path / "synthetic-root"
    activation = root / "etc" / "azazel" / "activation"
    activation.mkdir(parents=True, mode=0o700)
    for directory in (root, root / "etc", root / "etc" / "azazel", activation):
        directory.chmod(0o700)

    real_open = os.open
    real_protected = activation_store._protected
    real_private_directory = activation_store._private_directory
    opened = []

    def rooted_open(path, flags, *args, **kwargs):
        if path == "/":
            path = root
        elif isinstance(path, str):
            opened.append(path)
        return real_open(path, flags, *args, **kwargs)

    def current_owner_protected(fd, *, owner, directory):
        return real_protected(
            fd, owner=os.getuid() if owner == 0 else owner, directory=directory
        )

    def current_owner_private(fd, *, owner):
        return real_private_directory(fd, owner=os.getuid() if owner == 0 else owner)

    monkeypatch.setattr(activation_store.os, "open", rooted_open)
    monkeypatch.setattr(activation_store, "_protected", current_owner_protected)
    monkeypatch.setattr(activation_store, "_private_directory", current_owner_private)
    return root, activation, opened


def test_real_approval_directory_uses_fixed_components_and_allows_nested_shared_lock(
    monkeypatch, tmp_path,
):
    _, activation, opened = _synthetic_approval_root(monkeypatch, tmp_path)
    with activation_store._approval_directory() as first_fd:
        first = os.fstat(first_fd)
        with activation_store._approval_directory() as second_fd:
            second = os.fstat(second_fd)
            assert (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)
    assert opened == ["etc", "azazel", "activation"] * 2
    assert tuple(inspect.signature(activation_store.load_activation_approval).parameters) == (
        "expected", "operator", "now", "max_lease_seconds"
    )
    assert activation.is_dir()


def test_real_approval_directory_refuses_symlink_ancestor(monkeypatch, tmp_path):
    root, _, _ = _synthetic_approval_root(monkeypatch, tmp_path)
    etc = root / "etc"
    moved = root / "etc-real"
    etc.rename(moved)
    etc.symlink_to(moved, target_is_directory=True)
    with pytest.raises(ApprovalRefused):
        with activation_store._approval_directory():
            pytest.fail("symlinked ancestor was accepted")


def test_real_approval_directory_refuses_contended_nonblocking_lock(
    monkeypatch, tmp_path,
):
    _, activation, _ = _synthetic_approval_root(monkeypatch, tmp_path)
    held_fd = os.open(activation, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(held_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ApprovalRefused):
            with activation_store._approval_directory():
                pytest.fail("shared lock unexpectedly bypassed exclusive holder")
    finally:
        os.close(held_fd)
