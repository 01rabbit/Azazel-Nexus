"""Enrollment transaction tests use only unprivileged ordinary temp files."""

import fcntl
import os
from types import SimpleNamespace

import pytest
from nacl.signing import SigningKey

from azazel_nexus import operator_enrollment as enrollment
from azazel_nexus.operator_store import _read_at
from azazel_nexus.operator_trust import ApprovalRefused


@pytest.fixture
def transaction(tmp_path):
    tmp_path.chmod(0o700)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    public = bytes(SigningKey.generate().verify_key).hex()
    args = dict(owner=os.getuid(), action="enroll", operator="operator-a",
                public_key_hex=public, confirmation=enrollment.public_key_fingerprint(public))
    try:
        yield tmp_path, fd, args
    finally:
        os.close(fd)


def test_enroll_readback_and_revoke_without_erasing_identity(transaction):
    path, fd, args = transaction
    enrollment._update_at(fd, **args)
    trust = _read_at(fd, owner=os.getuid())
    assert trust.public_keys["operator-a"].hex() == args["public_key_hex"]
    assert (path / "operators.json").stat().st_mode & 0o777 == 0o600
    enrollment._update_at(fd, **(args | {"action": "revoke"}))
    trust = _read_at(fd, owner=os.getuid())
    assert "operator-a" in trust.revoked
    assert "operator-a" in trust.public_keys
    assert len(list(path.iterdir())) == 1


@pytest.mark.parametrize("changes", [
    {"confirmation": "sha256:wrong"}, {"operator": "../bad"},
    {"public_key_hex": "not-a-key"}, {"action": "replace"}, {"action": "revoke"},
])
def test_invalid_change_does_not_create_store(transaction, changes):
    path, fd, args = transaction
    with pytest.raises(ApprovalRefused):
        enrollment._update_at(fd, **(args | changes))
    assert list(path.iterdir()) == []


def test_no_silent_replacement_or_reenrollment_after_revocation(transaction):
    path, fd, args = transaction
    enrollment._update_at(fd, **args)
    before = (path / "operators.json").read_bytes()
    with pytest.raises(ApprovalRefused):
        enrollment._update_at(fd, **args)
    assert (path / "operators.json").read_bytes() == before
    enrollment._update_at(fd, **(args | {"action": "revoke"}))
    with pytest.raises(ApprovalRefused):
        enrollment._update_at(fd, **args)


def test_alias_cannot_restore_revoked_key(transaction):
    _, fd, args = transaction
    enrollment._update_at(fd, **args)
    enrollment._update_at(fd, **(args | {"action": "revoke"}))
    with pytest.raises(ApprovalRefused):
        enrollment._update_at(fd, **(args | {"operator": "operator-b"}))


def test_concurrent_writer_is_refused(transaction):
    path, fd, args = transaction
    other = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            enrollment._update_at(fd, **args)
    finally:
        os.close(other)


def test_write_failure_preserves_old_store_and_cleans_owned_temporary(transaction, monkeypatch):
    path, fd, args = transaction
    enrollment._update_at(fd, **args)
    before = (path / "operators.json").read_bytes()
    monkeypatch.setattr(os, "write", lambda *a: 0)
    with pytest.raises(OSError):
        enrollment._update_at(fd, **(args | {"action": "revoke"}))
    assert (path / "operators.json").read_bytes() == before
    assert len(list(path.iterdir())) == 1


def test_rootless_public_update_does_not_open_storage(transaction, monkeypatch):
    _, _, args = transaction
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(ApprovalRefused, match="administrator"):
        enrollment.update_operator(**{k: v for k, v in args.items() if k != "owner"})


def test_cli_requires_interactive_administrator(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert enrollment.main(["enroll", "operator-a"]) == 1


def test_temporary_name_collision_does_not_remove_existing_file(transaction, monkeypatch):
    path, fd, args = transaction
    sentinel = path / ".operators-collision"
    sentinel.write_bytes(b"owned by another operation")
    monkeypatch.setattr(enrollment.uuid, "uuid4", lambda: SimpleNamespace(hex="collision"))
    with pytest.raises(FileExistsError):
        enrollment._update_at(fd, **args)
    assert sentinel.read_bytes() == b"owned by another operation"


def test_postrename_failure_does_not_rollback_revocation(transaction, monkeypatch):
    _, fd, args = transaction
    enrollment._update_at(fd, **args)
    original = os.fsync

    def fail_directory_fsync(target):
        if target == fd:
            raise OSError("simulated durability failure")
        original(target)

    monkeypatch.setattr(os, "fsync", fail_directory_fsync)
    with pytest.raises(OSError):
        enrollment._update_at(fd, **(args | {"action": "revoke"}))
    assert "operator-a" in _read_at(fd, owner=os.getuid()).revoked


@pytest.mark.parametrize("consent,expected", [("ENROLL operator-a", 0), ("yes", 1)])
def test_cli_separates_fingerprint_and_action_confirmation(transaction, monkeypatch, consent, expected):
    _, _, args = transaction
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(enrollment.sys.stdin, "isatty", lambda: True)
    answers = iter((args["public_key_hex"], args["confirmation"], consent))
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    calls = []
    monkeypatch.setattr(enrollment, "update_operator", lambda **kwargs: calls.append(kwargs))
    assert enrollment.main(["enroll", "operator-a"]) == expected
    assert len(calls) == (1 if expected == 0 else 0)
    if calls:
        assert calls[0]["confirmation"] == args["confirmation"]


def test_enrollment_reserves_space_for_revoking_every_accepted_key(transaction, monkeypatch):
    path, fd, args = transaction
    monkeypatch.setattr(enrollment, "_MAX_STORE_BYTES", 400)
    accepted = []
    for index in range(10):
        public = bytes(SigningKey.generate().verify_key).hex()
        attempt = args | dict(operator=f"operator-{index}", public_key_hex=public,
                             confirmation=enrollment.public_key_fingerprint(public))
        before = (path / "operators.json").read_bytes() if accepted else None
        try:
            enrollment._update_at(fd, **attempt)
        except ApprovalRefused as exc:
            assert "reserve" in str(exc)
            candidate = enrollment._updated(
                _read_at(fd, owner=os.getuid()),
                **{key: value for key, value in attempt.items() if key != "owner"},
            )
            assert len(enrollment._encoded(candidate)) <= 400
            assert len(enrollment._encoded(candidate, reserve_revocations=True)) > 400
            assert (path / "operators.json").read_bytes() == before
            break
        accepted.append(attempt)
    else:
        pytest.fail("fixture never reached the bounded store's capacity")
    assert len(accepted) >= 2
    for attempt in accepted:
        enrollment._update_at(fd, **(attempt | {"action": "revoke"}))
    trust = _read_at(fd, owner=os.getuid())
    assert trust.revoked == frozenset(attempt["operator"] for attempt in accepted)
    assert (path / "operators.json").stat().st_size <= 400
