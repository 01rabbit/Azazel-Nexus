"""Retained bootstrap deadline storage; descriptor-only temporary fixtures."""

from contextlib import contextmanager
import fcntl
import inspect
import json
import os

import pytest
from nacl.signing import SigningKey

from azazel_nexus import bootstrap_deadline_store as store
from azazel_nexus.bootstrap_approval import (
    BootstrapApprovalPolicy,
    BootstrapContext,
    bootstrap_payload,
    verify_bootstrap_approval,
)
from azazel_nexus.bootstrap_deadline import begin_deadline
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
    approval_message,
)

DIGEST = "sha256:" + "a" * 64
START = "2026-10-13T00:00:00Z"
BOOT_ID = "11111111-1111-1111-1111-111111111111"
OTHER_BOOT = "22222222-2222-2222-2222-222222222222"
NS = 1_000_000_000
OPERATOR = "operator-a"


@pytest.fixture
def state_store(tmp_path, monkeypatch):
    key = SigningKey.generate()
    policy = BootstrapApprovalPolicy(frozenset({OPERATOR}), 300)
    context = BootstrapContext(
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", DIGEST, BOOT_ID, 1,
        DIGEST, DIGEST, DIGEST, DIGEST, policy.digest(), 7, DIGEST,
    )
    payload = bootstrap_payload(
        context=context, operator=OPERATOR, granted_at=START,
        expires_at="2026-10-13T00:05:00Z",
    )
    signature = key.sign(
        approval_message(ApprovalPurpose.SUPPORTING_BOOTSTRAP, payload)
    ).signature
    trust = OperatorTrust({OPERATOR: bytes(key.verify_key)})
    verified = verify_bootstrap_approval(
        trust=trust, expected=context, policy=policy, operator=OPERATOR,
        payload=payload, signature=signature, now=START,
    )
    directory = tmp_path / "deadline-state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)

    @contextmanager
    def opened_directory():
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(store, "_state_directory", opened_directory)
    owner = os.getuid()
    private_directory = store._private_directory
    monkeypatch.setattr(
        store, "_private_directory",
        lambda fd, *, owner: private_directory(fd, owner=os.getuid()),
    )
    read_file = store._read_file_at
    monkeypatch.setattr(
        store, "_read_file_at",
        lambda fd, name, *, owner, limit: read_file(
            fd, name, owner=os.getuid(), limit=limit
        ),
    )
    initial = begin_deadline(
        verified, boot_id=BOOT_ID, now=START, boottime_ns=100 * NS,
        clock_trusted=True,
    )
    return directory, verified, initial, owner


@contextmanager
def _fd(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        yield fd
    finally:
        os.close(fd)


def _retain(directory, state, owner):
    with _fd(directory) as fd:
        return store._retain_initial_at(fd, state, owner=owner)


def _advance(directory, approval, owner, *, now="2026-10-13T00:00:10Z",
             boottime_ns=110 * NS, boot_id=BOOT_ID):
    with _fd(directory) as fd:
        return store._advance_at(
            fd, owner=owner, approval=approval, boot_id=boot_id, now=now,
            boottime_ns=boottime_ns, clock_trusted=True,
        )


def test_initialize_restart_and_successive_highwater_preserve_deadline(state_store):
    directory, approval, initial, owner = state_store
    _retain(directory, initial, owner)
    restarted = _advance(directory, approval, owner)
    later = _advance(
        directory, approval, owner, now="2026-10-13T00:00:20Z",
        boottime_ns=120 * NS,
    )
    assert restarted.deadline_boottime_ns == initial.deadline_boottime_ns
    assert later.deadline_boottime_ns == initial.deadline_boottime_ns
    assert later.admitted_boottime_ns == 100 * NS
    assert later.last_utc == "2026-10-13T00:00:20Z"
    assert later.last_boottime_ns == 120 * NS
    assert sorted(path.name for path in directory.iterdir()) == [
        "checkpoint.json", "initial.json",
    ]


def test_repeated_initialize_refuses_without_overwriting(state_store):
    directory, _, initial, owner = state_store
    _retain(directory, initial, owner)
    before = {name: (directory / name).read_bytes() for name in ("initial.json", "checkpoint.json")}
    with pytest.raises(ApprovalRefused):
        _retain(directory, initial, owner)
    assert {name: (directory / name).read_bytes() for name in before} == before


@pytest.mark.parametrize("missing", ["initial.json", "checkpoint.json"])
def test_missing_record_is_never_reset_or_reinitialized(state_store, missing):
    directory, approval, initial, owner = state_store
    _retain(directory, initial, owner)
    (directory / missing).unlink()
    with pytest.raises((ApprovalRefused, FileNotFoundError)):
        _advance(directory, approval, owner)
    with pytest.raises(ApprovalRefused):
        _retain(directory, initial, owner)
    assert missing not in {path.name for path in directory.iterdir()}


@pytest.mark.parametrize("record", ["initial.json", "checkpoint.json"])
@pytest.mark.parametrize("raw", [b"{", b"{}", b"\xff"])
def test_corrupt_records_refuse_without_reset(state_store, record, raw):
    directory, approval, initial, owner = state_store
    _retain(directory, initial, owner)
    (directory / record).write_bytes(raw)
    with pytest.raises((ApprovalRefused, ValueError)):
        _advance(directory, approval, owner)
    with pytest.raises(ApprovalRefused):
        _retain(directory, initial, owner)
    assert (directory / record).read_bytes() == raw


def test_noncanonical_and_duplicate_record_json_refuse(state_store):
    directory, approval, initial, owner = state_store
    _retain(directory, initial, owner)
    record = directory / "checkpoint.json"
    document = json.loads(record.read_bytes())
    noncanonical = json.dumps(document, sort_keys=True, indent=2).encode()
    record.write_bytes(noncanonical)
    with pytest.raises((ApprovalRefused, OSError)):
        _advance(directory, approval, owner)
    duplicate = b'{"schema":"x","schema":"y"}'
    record.write_bytes(duplicate)
    with pytest.raises(ApprovalRefused):
        _advance(directory, approval, owner)


@pytest.mark.parametrize("failure", ["initial-write", "initial-file-fsync", "initial-dir-fsync"])
def test_interrupted_initial_transaction_stays_pending(state_store, monkeypatch, failure):
    directory, _, initial, owner = state_store
    if failure == "initial-write":
        original = store.os.write
        calls = 0

        def partial(fd, data):
            nonlocal calls
            calls += 1
            if calls == 2:
                return original(fd, data[:3])
            if calls == 3:
                raise OSError("injected partial initial write")
            return original(fd, data)

        monkeypatch.setattr(store.os, "write", partial)
    elif failure == "initial-file-fsync":
        original = store.os.fsync
        calls = 0

        def failed_file(fd):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError("injected initial file fsync")
            return original(fd)

        monkeypatch.setattr(store.os, "fsync", failed_file)
    else:
        original = store.os.fsync
        calls = 0

        def failed_directory(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected initial directory fsync")
            return original(fd)

        monkeypatch.setattr(store.os, "fsync", failed_directory)
    with pytest.raises(OSError):
        _retain(directory, initial, owner)
    assert (directory / "transaction.pending").exists()
    monkeypatch.undo()
    with pytest.raises(ApprovalRefused):
        _retain(directory, initial, owner)


@pytest.mark.parametrize("failure", ["next-file-fsync", "checkpoint-replace", "prepublish-read", "published-read"])
def test_interrupted_checkpoint_transaction_stays_pending(state_store, monkeypatch, failure):
    directory, approval, initial, owner = state_store
    _retain(directory, initial, owner)
    if failure == "next-file-fsync":
        original = store.os.fsync
        calls = 0

        def failed_next(fd):
            nonlocal calls
            calls += 1
            # pending-file fsync, directory fsync, next-file fsync
            if calls == 3:
                raise OSError("injected next fsync")
            return original(fd)

        monkeypatch.setattr(store.os, "fsync", failed_next)
    elif failure == "checkpoint-replace":
        monkeypatch.setattr(store.os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("replace")))
    else:
        original = store._read_file_at
        calls = 0

        def fail_checkpoint_read(fd, name, *, owner, limit):
            nonlocal calls
            if name == "checkpoint.json":
                calls += 1
                if calls == (2 if failure == "prepublish-read" else 3):
                    raise OSError("injected checkpoint verification failure")
            return original(fd, name, owner=os.getuid(), limit=limit)

        monkeypatch.setattr(store, "_read_file_at", fail_checkpoint_read)
    with pytest.raises(OSError):
        _advance(directory, approval, owner)
    assert (directory / "transaction.pending").exists()
    monkeypatch.undo()
    with pytest.raises(ApprovalRefused):
        _advance(directory, approval, owner, now="2026-10-13T00:00:11Z", boottime_ns=111 * NS)


def test_final_directory_fsync_failure_may_leave_published_checkpoint(state_store, monkeypatch):
    directory, approval, initial, owner = state_store
    _retain(directory, initial, owner)
    original = store.os.fsync
    calls = 0

    def fail_final_directory(fd):
        nonlocal calls
        calls += 1
        # pending file + directory, next file, pre-unlink dir, post-unlink dir.
        if calls == 5:
            raise OSError("injected post-unlink directory fsync")
        return original(fd)

    monkeypatch.setattr(store.os, "fsync", fail_final_directory)
    with pytest.raises(OSError):
        _advance(directory, approval, owner)
    monkeypatch.undo()
    assert not (directory / "transaction.pending").exists()
    recovered = _advance(
        directory, approval, owner, now="2026-10-13T00:00:11Z", boottime_ns=111 * NS
    )
    assert recovered.deadline_boottime_ns == initial.deadline_boottime_ns


@pytest.mark.parametrize("name", ["initial.json", "checkpoint.json"])
@pytest.mark.parametrize("protection", ["symlink", "mode", "hardlink"])
def test_protected_record_checks_reject_link_or_unsafe_mode(state_store, name, protection):
    directory, approval, initial, owner = state_store
    _retain(directory, initial, owner)
    path = directory / name
    if protection == "symlink":
        path.rename(directory / "saved-record")
        path.symlink_to(directory / "saved-record")
    elif protection == "mode":
        path.chmod(0o640)
    else:
        os.link(path, directory / "record-alias")
    with pytest.raises((ApprovalRefused, OSError)):
        _advance(directory, approval, owner)


def test_descriptor_lock_is_exclusive_and_nonblocking(state_store):
    directory, _, _, owner = state_store
    with _fd(directory) as first, _fd(directory) as second:
        fcntl.flock(first, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with pytest.raises(BlockingIOError):
                with store._locked(second, owner=owner):
                    pass
        finally:
            fcntl.flock(first, fcntl.LOCK_UN)


def test_changed_approval_boot_and_time_refuse_without_checkpoint_change(state_store):
    directory, approval, initial, owner = state_store
    _retain(directory, initial, owner)
    with pytest.raises(ApprovalRefused):
        _advance(directory, approval, owner, boot_id=OTHER_BOOT)
    _advance(directory, approval, owner)
    before = (directory / "checkpoint.json").read_bytes()
    with pytest.raises(ApprovalRefused):
        _advance(directory, approval, owner, now="2026-10-13T00:00:05Z", boottime_ns=109 * NS)
    # A fresh proof with a changed signed context is rejected by full proof equality.
    from dataclasses import replace
    changed_context = replace(approval.context, generation=2)
    # Construct a valid, independently signed proof for the changed context.
    key = SigningKey.generate()
    policy = BootstrapApprovalPolicy(frozenset({OPERATOR}), 300)
    changed_context = replace(changed_context, approval_policy_digest=policy.digest())
    changed_payload = bootstrap_payload(
        context=changed_context, operator=OPERATOR, granted_at=START,
        expires_at="2026-10-13T00:05:00Z",
    )
    changed = verify_bootstrap_approval(
        trust=OperatorTrust({OPERATOR: bytes(key.verify_key)}), expected=changed_context,
        policy=policy, operator=OPERATOR, payload=changed_payload,
        signature=key.sign(approval_message(ApprovalPurpose.SUPPORTING_BOOTSTRAP, changed_payload)).signature,
        now=START,
    )
    with pytest.raises(ApprovalRefused):
        _advance(directory, changed, owner)
    assert (directory / "checkpoint.json").read_bytes() == before


def test_public_api_has_no_path_override():
    with pytest.raises(TypeError):
        store.advance_deadline(
            approval=None, boot_id=BOOT_ID, now=START, boottime_ns=1,
            clock_trusted=True, path="/tmp/override",
        )
    assert "path" not in inspect.signature(store.retain_initial_deadline).parameters


@pytest.mark.parametrize("name", ["transaction.pending", "checkpoint.next"])
def test_orphan_transaction_state_never_allows_initialization(state_store, name):
    directory, approval, initial, owner = state_store
    marker = directory / name
    marker.write_bytes(b"interrupted")
    with pytest.raises(ApprovalRefused, match="unfinished"):
        _retain(directory, initial, owner)
    with pytest.raises(ApprovalRefused, match="unfinished"):
        _advance(directory, approval, owner)
    assert marker.read_bytes() == b"interrupted"
    assert not (directory / "initial.json").exists()


def test_rebased_checkpoint_cannot_replace_original_deadline(state_store):
    from dataclasses import replace

    directory, approval, initial, owner = state_store
    _retain(directory, initial, owner)
    # Internally consistent but rebased admission cannot override initial.json.
    forged = replace(initial, admitted_boottime_ns=200 * NS,
                     last_boottime_ns=200 * NS, deadline_boottime_ns=500 * NS)
    (directory / "checkpoint.json").write_bytes(store._encode(forged))
    with pytest.raises(ApprovalRefused, match="original bootstrap deadline changed"):
        _advance(directory, approval, owner, boottime_ns=210 * NS)


def test_public_reader_writer_flow_and_missing_state_redaction(state_store):
    directory, approval, initial, _owner = state_store
    assert store.retain_initial_deadline(initial) == initial
    advanced = store.advance_deadline(approval=approval, boot_id=BOOT_ID,
                                      now="2026-10-13T00:00:10Z",
                                      boottime_ns=110 * NS, clock_trusted=True)
    assert advanced.deadline_boottime_ns == initial.deadline_boottime_ns
    (directory / "checkpoint.json").unlink()
    with pytest.raises(ApprovalRefused, match="^protected bootstrap state refused$"):
        store.advance_deadline(approval=approval, boot_id=BOOT_ID, now=START,
                               boottime_ns=120 * NS, clock_trusted=True)


@pytest.mark.parametrize("present", [
    ("initial.json",), ("checkpoint.json",), ("transaction.pending",),
    ("checkpoint.next",), ("initial.json", "checkpoint.json"),
])
def test_first_admission_retain_refuses_when_any_state_exists(state_store, present):
    directory, approval, initial, owner = state_store
    for name in present:
        (directory / name).write_bytes(b"pre-existing")
    before = {name: (directory / name).read_bytes() for name in present}
    with pytest.raises(ApprovalRefused):
        _retain(directory, initial, owner)
    assert {path.name for path in directory.iterdir()} == set(present)
    assert {name: (directory / name).read_bytes() for name in present} == before
    with pytest.raises((ApprovalRefused, FileNotFoundError)):
        _advance(directory, approval, owner)


def test_first_admission_state_then_advance_uses_same_admitted_fields(state_store):
    directory, approval, initial, owner = state_store
    retained = _retain(directory, initial, owner)
    advanced = _advance(directory, approval, owner)
    assert (advanced.admitted_at, advanced.admitted_boottime_ns,
            advanced.deadline_boottime_ns) == (
        retained.admitted_at, retained.admitted_boottime_ns,
        retained.deadline_boottime_ns)
