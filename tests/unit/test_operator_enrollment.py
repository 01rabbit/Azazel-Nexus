"""Enrollment transaction tests use only unprivileged ordinary temp files."""

import fcntl
import os
import shutil
import stat
import sys
import tempfile
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


def _reader_group(monkeypatch, gid):
    def lookup(name):
        if name != enrollment.READER_GROUP:
            raise KeyError(name)
        if gid is None:
            raise KeyError(name)
        return SimpleNamespace(gr_gid=gid)
    monkeypatch.setattr(enrollment.grp, "getgrnam", lookup)


def test_reader_group_present_writes_group_readable_store(transaction, monkeypatch):
    path, fd, args = transaction
    # The caller's own primary group stands in for azmission-read; the test
    # owner seam stands in for root. Real cross-user access is covered below.
    gid = os.getgid()
    _reader_group(monkeypatch, gid)
    created = []
    original_open = os.open

    def observe(name, flags, *rest, **kwargs):
        result = original_open(name, flags, *rest, **kwargs)
        if str(name).startswith(".operators-"):
            created.append(result)
        return result
    original_fchmod = os.fchmod
    temporary_modes = []

    def record(target, mode):
        if target in created:
            temporary_modes.append(mode)
        original_fchmod(target, mode)
    monkeypatch.setattr(os, "open", observe)
    monkeypatch.setattr(os, "fchmod", record)
    enrollment._update_at(fd, **args)
    monkeypatch.undo()
    info = (path / "operators.json").stat()
    assert stat.S_IMODE(info.st_mode) == 0o640 and info.st_gid == gid
    assert info.st_uid == args["owner"]
    directory = path.stat()
    assert stat.S_IMODE(directory.st_mode) == 0o750 and directory.st_gid == gid
    assert temporary_modes == [0o640]
    assert _read_at(fd, owner=os.getuid()).public_keys["operator-a"].hex() == args["public_key_hex"]
    # Revocation keeps the reader modes on the replacement file.
    _reader_group(monkeypatch, gid)
    enrollment._update_at(fd, **(args | {"action": "revoke"}))
    assert stat.S_IMODE((path / "operators.json").stat().st_mode) == 0o640
    assert len(list(path.iterdir())) == 1


def test_reader_group_absent_keeps_private_modes(transaction, monkeypatch):
    path, fd, args = transaction
    _reader_group(monkeypatch, None)
    calls = []
    monkeypatch.setattr(os, "fchown", lambda *a: calls.append(a))
    enrollment._update_at(fd, **args)
    assert calls == []
    assert stat.S_IMODE((path / "operators.json").stat().st_mode) == 0o600
    assert stat.S_IMODE(path.stat().st_mode) == 0o700


def test_store_owned_by_another_group_is_not_handed_to_readers(transaction, monkeypatch):
    """Matches provisioning: a deliberately assigned foreign group is kept private."""
    path, fd, args = transaction
    if os.getgid() == 0:
        pytest.skip("needs a non-root primary group to stand in for a foreign group")
    os.fchown(fd, -1, os.getgid())
    current = path.stat().st_gid
    _reader_group(monkeypatch, current + 4242)
    calls = []
    monkeypatch.setattr(os, "fchown", lambda *a: calls.append(a))
    enrollment._update_at(fd, **args)
    assert calls == []
    assert stat.S_IMODE((path / "operators.json").stat().st_mode) == 0o600
    assert stat.S_IMODE(path.stat().st_mode) == 0o700


def test_refused_change_does_not_alter_directory_modes(transaction, monkeypatch):
    path, fd, args = transaction
    _reader_group(monkeypatch, os.getgid())
    with pytest.raises(ApprovalRefused):
        enrollment._update_at(fd, **(args | {"confirmation": "sha256:wrong"}))
    assert stat.S_IMODE(path.stat().st_mode) == 0o700


def test_reader_group_never_makes_writable_directory_acceptable(transaction, monkeypatch):
    path, fd, args = transaction
    path.chmod(0o770)
    _reader_group(monkeypatch, os.getgid())
    with pytest.raises(ApprovalRefused):
        enrollment._update_at(fd, **args)
    assert stat.S_IMODE(path.stat().st_mode) == 0o770
    assert list(path.iterdir()) == []


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0 or sys.platform != "linux",
                    reason="real cross-user group read needs Linux root")
def test_non_owner_group_member_can_load_store_written_as_root(monkeypatch):
    # Root-owned store, reader runs as an unprivileged uid with only the
    # reader group, mirroring azmio + SupplementaryGroups=azmission-read.
    reader_uid, reader_gid = 65534, 65533
    base = tempfile.mkdtemp(prefix="azotr-root-")
    try:
        os.chmod(base, 0o755)
        trust = os.path.join(base, "operator-trust")
        os.mkdir(trust, 0o700)
        public = bytes(SigningKey.generate().verify_key).hex()
        args = {"owner": 0, "action": "enroll", "operator": "operator-a", "public_key_hex": public,
                "confirmation": enrollment.public_key_fingerprint(public)}
        for gid, readable in ((None, False), (reader_gid, True)):
            _reader_group(monkeypatch, gid)
            fd = os.open(trust, os.O_RDONLY | os.O_DIRECTORY)
            try:
                if gid is not None:
                    os.unlink("operators.json", dir_fd=fd)
                enrollment._update_at(fd, **args)
            finally:
                os.close(fd)
            child = os.fork()
            if child == 0:  # pragma: no cover - exercised in the child
                code = 1
                try:
                    os.setgroups([reader_gid])
                    os.setgid(reader_gid)
                    os.setuid(reader_uid)
                    directory = os.open(trust, os.O_RDONLY | os.O_DIRECTORY)
                    loaded = _read_at(directory, owner=0)
                    code = 0 if loaded.public_keys["operator-a"].hex() == public else 2
                except PermissionError:
                    code = 3
                finally:
                    os._exit(code)
            _, status = os.waitpid(child, 0)
            assert os.waitstatus_to_exitcode(status) == (0 if readable else 3)
    finally:
        shutil.rmtree(base)
