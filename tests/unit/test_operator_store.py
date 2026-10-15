"""Ordinary temporary files only; no real enrollment or privileged writes."""

import json
import os

import pytest
from nacl.signing import SigningKey

from azazel_nexus import operator_store
from azazel_nexus.operator_store import _decode, _read_at, load_operator_trust
from azazel_nexus.operator_trust import ApprovalRefused


@pytest.fixture
def store(tmp_path):
    public = bytes(SigningKey.generate().verify_key).hex()
    document = {"schema": "azazel-nexus/operator-trust/v1",
                "keys": {"operator-a": public}, "revoked": []}
    path = tmp_path / "operators.json"
    path.write_text(json.dumps(document))
    path.chmod(0o600)
    tmp_path.chmod(0o700)
    return path, document


def _read(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return _read_at(fd, owner=os.getuid())
    finally:
        os.close(fd)


def test_read_and_reload_revocations(store):
    path, document = store
    assert "operator-a" in _read(path.parent).public_keys
    document["revoked"] = ["operator-a"]
    path.write_text(json.dumps(document))
    assert _read(path.parent).revoked == frozenset({"operator-a"})


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
def test_writable_trust_file_is_refused(store, mode):
    path, _ = store
    path.chmod(mode)
    with pytest.raises(ApprovalRefused):
        _read(path.parent)


def test_writable_parent_is_refused(store):
    path, _ = store
    path.parent.chmod(0o770)
    with pytest.raises(ApprovalRefused):
        _read(path.parent)


def test_wrong_owner_is_refused(store):
    path, _ = store
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ApprovalRefused):
            _read_at(fd, owner=os.getuid() + 1)
    finally:
        os.close(fd)


def test_symlink_is_not_followed(store):
    path, _ = store
    target = path.with_name("saved.json")
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(OSError):
        _read(path.parent)


def test_hardlink_is_refused(store):
    path, _ = store
    os.link(path, path.with_name("alias.json"))
    with pytest.raises(ApprovalRefused):
        _read(path.parent)


def test_directory_instead_of_file_is_refused(store):
    path, _ = store
    path.unlink()
    path.mkdir()
    with pytest.raises(ApprovalRefused):
        _read(path.parent)


@pytest.mark.parametrize("raw", [b"", b"x" * 65537, b"{}", b"[]", b"\xff",
                                 b'{"schema":1,"schema":2}', b"[" * 2000])
def test_invalid_or_oversized_file_is_refused(store, raw):
    path, _ = store
    path.write_bytes(raw)
    with pytest.raises(ApprovalRefused):
        _read(path.parent)


@pytest.mark.parametrize("changes", [
    {"extra": True}, {"keys": []}, {"keys": {"operator-a": 12}},
    {"revoked": [True]}, {"revoked": ["operator-a", "operator-a"]},
])
def test_unknown_fields_and_malformed_values_are_refused(store, changes):
    _, document = store
    with pytest.raises(ApprovalRefused):
        _decode(json.dumps(document | changes).encode())


def test_public_loader_has_no_path_or_owner_override():
    with pytest.raises(TypeError):
        load_operator_trust(path="/tmp/untrusted", owner=os.getuid())


def test_public_loader_sanitizes_open_failures(monkeypatch):
    def denied(*args, **kwargs):
        raise OSError("sensitive path")
    monkeypatch.setattr(os, "open", denied)
    with pytest.raises(ApprovalRefused, match="store unavailable"):
        load_operator_trust()


def test_file_changed_during_read_is_refused(store, monkeypatch):
    path, _ = store
    original = os.read
    changed = False

    def changing_read(fd, count):
        nonlocal changed
        result = original(fd, count)
        if not changed:
            changed = True
            path.write_text("{}")
        return result

    monkeypatch.setattr(os, "read", changing_read)
    with pytest.raises(ApprovalRefused, match="changed while reading"):
        _read(path.parent)


@pytest.mark.parametrize("fault", ["none", "symlink", "writable"])
def test_public_directory_traversal_on_synthetic_root(store, monkeypatch, fault):
    path, _ = store
    root = path.parent
    etc = root / "etc"
    trusted = etc / "azazel" / "operator-trust"
    trusted.mkdir(parents=True, mode=0o700)
    etc.chmod(0o700)
    (etc / "azazel").chmod(0o700)
    path.rename(trusted / "operators.json")
    if fault == "symlink":
        etc.rename(root / "other")
        etc.symlink_to(root / "other", target_is_directory=True)
    elif fault == "writable":
        etc.chmod(0o777)
    original_open = os.open
    original_protected = operator_store._protected

    def rooted_open(name, flags, **kwargs):
        return original_open(root if name == "/" else name, flags, **kwargs)

    def user_owned(fd, *, owner, directory):
        # Only the synthetic test root maps the expected root owner to this
        # test account. The public API has no such override.
        assert owner == 0
        return original_protected(fd, owner=os.getuid(), directory=directory)

    monkeypatch.setattr(os, "open", rooted_open)
    monkeypatch.setattr(operator_store, "_protected", user_owned)
    if fault == "none":
        assert "operator-a" in load_operator_trust().public_keys
    else:
        with pytest.raises(ApprovalRefused):
            load_operator_trust()
