"""Earlier boots' retained deadline and grant records move to archive/ (Nexus#324).

Ordinary private directories and the store's descriptor seams only; the test
uid stands in for root. Every missing condition must refuse (deadline) or skip
(grant) with every file left as it was, and a ledger record that is not
confirmed must change nothing.
"""

from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from azazel_nexus import bootstrap_deadline_store as store
from azazel_nexus import bootstrap_grant_store as grant_store
from azazel_nexus.audit import AuditLedger
from azazel_nexus.bootstrap_approval import (
    BootstrapApprovalPolicy,
    BootstrapContext,
    bootstrap_payload,
    verify_bootstrap_approval,
)
from azazel_nexus.bootstrap_deadline import begin_deadline
from azazel_nexus.bootstrap_grant_store import GrantTransactionStore
from azazel_nexus.bootstrap_grant_transaction import (
    PAIR,
    GrantTransaction,
    encode_transaction,
)
from azazel_nexus.bootstrap_lock import BootstrapTransactionGuard
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
    approval_message,
)

DIGEST = "sha256:" + "a" * 64
START = "2026-10-13T00:00:00Z"
CURRENT = "11111111-1111-4111-8111-111111111111"
PRIOR = "22222222-2222-4222-8222-22222222abcd"
THIRD = "33333333-3333-4333-8333-333333333333"
NS = 1_000_000_000
OPERATOR = "operator-a"


def _approval(boot_id, key=None, granted_at=START, expires_at="2026-10-13T00:05:00Z"):
    key = key or SigningKey.generate()
    policy = BootstrapApprovalPolicy(frozenset({OPERATOR}), 300)
    context = BootstrapContext(
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", DIGEST, boot_id, 1,
        DIGEST, DIGEST, DIGEST, DIGEST, policy.digest(), 7, DIGEST,
    )
    payload = bootstrap_payload(context=context, operator=OPERATOR,
                                granted_at=granted_at, expires_at=expires_at)
    signature = key.sign(
        approval_message(ApprovalPurpose.SUPPORTING_BOOTSTRAP, payload)).signature
    return verify_bootstrap_approval(
        trust=OperatorTrust({OPERATOR: bytes(key.verify_key)}), expected=context,
        policy=policy, operator=OPERATOR, payload=payload, signature=signature,
        now=granted_at,
    )


def _state(boot_id, **kw):
    return begin_deadline(_approval(boot_id, **kw), boot_id=boot_id, now=START,
                          boottime_ns=100 * NS, clock_trusted=True)


@pytest.fixture
def seams(monkeypatch):
    uid = os.getuid()
    private, read_file = store._private_directory, store._read_file_at
    monkeypatch.setattr(store, "_private_directory",
                        lambda fd, *, owner: private(fd, owner=uid))
    monkeypatch.setattr(store, "_read_file_at",
                        lambda fd, name, *, owner, limit: read_file(
                            fd, name, owner=uid, limit=limit))
    return uid


@pytest.fixture
def deadline_dir(tmp_path, seams):
    directory = tmp_path / "bootstrap"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory


@contextmanager
def _fd(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        yield fd
    finally:
        os.close(fd)


def _snapshot(directory: Path):
    return {str(p.relative_to(directory)): (p.read_bytes() if p.is_file() else None)
            for p in sorted(directory.rglob("*"))}


def _place(directory, initial_raw, checkpoint_raw=None):
    for name, raw in (("initial.json", initial_raw),
                      ("checkpoint.json", checkpoint_raw or initial_raw)):
        if raw is None:
            continue
        (directory / name).write_bytes(raw)
        os.chmod(directory / name, 0o600)


class Recorder:
    def __init__(self, result=True):
        self.calls, self.result = [], result

    def __call__(self, summary):
        self.calls.append(summary)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def _retain(directory, state, record):
    with _fd(directory) as fd:
        return store._retain_initial_at(fd, state, owner=os.getuid(),
                                        record_deadline_retirement=record)


def _forge(state, **changes):
    document = json.loads(store._encode(state))
    document.update(changes)
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


# --- A: retained deadline of an earlier boot --------------------------------

def test_prior_boot_deadline_is_recorded_archived_then_created(deadline_dir):
    prior_raw = store._encode(_state(PRIOR))
    _place(deadline_dir, prior_raw)
    current = _state(CURRENT)
    record = Recorder()

    assert _retain(deadline_dir, current, record) == current

    assert record.calls == [{
        "boot_id": PRIOR,
        "approval_digest": json.loads(prior_raw)["approval_digest"],
        "initial_sha256": hashlib.sha256(prior_raw).hexdigest(),
        "checkpoint_sha256": hashlib.sha256(prior_raw).hexdigest(),
        "current_boot_id": CURRENT,
    }]
    raw = store._encode(current)
    assert _snapshot(deadline_dir) == {
        "archive": None,
        f"archive/checkpoint-{PRIOR}.json": prior_raw,
        f"archive/initial-{PRIOR}.json": prior_raw,
        "checkpoint.json": raw,
        "initial.json": raw,
    }
    assert (deadline_dir / "archive").stat().st_mode & 0o777 == 0o700
    # The current boot's record is then never extended or replaced.
    with pytest.raises(ApprovalRefused, match="already initialized"):
        _retain(deadline_dir, _state(CURRENT), Recorder())


@pytest.mark.parametrize("result", [
    False, None, 1, "True", ApprovalRefused("ledger refused"), OSError("disk"),
])
def test_unconfirmed_ledger_record_changes_nothing(deadline_dir, result):
    _place(deadline_dir, store._encode(_state(PRIOR)))
    before = _snapshot(deadline_dir)
    record = Recorder(result)
    with pytest.raises((ApprovalRefused, OSError)):
        _retain(deadline_dir, _state(CURRENT), record)
    assert len(record.calls) == 1
    # Only the empty private archive, prepared before any record or marker.
    assert _snapshot(deadline_dir) == {**before, "archive": None}
    assert not any((deadline_dir / "archive").iterdir())
    assert not (deadline_dir / "transaction.pending").exists()


def test_archive_mkdir_failure_leaves_no_marker_and_no_record(deadline_dir, monkeypatch):
    _place(deadline_dir, store._encode(_state(PRIOR)))
    before = _snapshot(deadline_dir)
    real_mkdir = os.mkdir

    def mkdir(*_a, **_kw):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(store.os, "mkdir", mkdir)
    record = Recorder()
    with pytest.raises(OSError):
        _retain(deadline_dir, _state(CURRENT), record)
    assert record.calls == [] and _snapshot(deadline_dir) == before
    assert not (deadline_dir / "transaction.pending").exists()
    # The failure was preventable, not an unfinished transaction: once the
    # archive can be created, the same next-boot admission proceeds.
    monkeypatch.setattr(store.os, "mkdir", real_mkdir)
    current = _state(CURRENT)
    assert _retain(deadline_dir, current, record) == current
    assert len(record.calls) == 1


def test_without_a_record_seam_existing_state_refuses_as_before(deadline_dir):
    _place(deadline_dir, store._encode(_state(PRIOR)))
    before = _snapshot(deadline_dir)
    with pytest.raises(ApprovalRefused, match="already initialized"):
        _retain(deadline_dir, _state(CURRENT), None)
    assert _snapshot(deadline_dir) == before


def test_same_boot_record_refuses_even_with_another_approval(deadline_dir):
    # A soft reboot keeps the kernel boot id: a new approval never renews it.
    _place(deadline_dir, store._encode(_state(CURRENT)))
    before = _snapshot(deadline_dir)
    record = Recorder()
    with pytest.raises(ApprovalRefused, match="already initialized"):
        _retain(deadline_dir, _state(CURRENT), record)
    assert record.calls == [] and _snapshot(deadline_dir) == before


def test_same_approval_digest_refuses(deadline_dir):
    current = _state(CURRENT)
    _place(deadline_dir, _forge(_state(PRIOR),
                                approval_digest=current.approval.payload_digest))
    before = _snapshot(deadline_dir)
    record = Recorder()
    with pytest.raises(ApprovalRefused, match="same approval"):
        _retain(deadline_dir, current, record)
    assert record.calls == [] and _snapshot(deadline_dir) == before


@pytest.mark.parametrize("name", ["transaction.pending", "checkpoint.next"])
def test_unfinished_transaction_refuses(deadline_dir, name):
    _place(deadline_dir, store._encode(_state(PRIOR)))
    (deadline_dir / name).write_bytes(b"interrupted")
    before = _snapshot(deadline_dir)
    record = Recorder()
    with pytest.raises(ApprovalRefused, match="unfinished"):
        _retain(deadline_dir, _state(CURRENT), record)
    assert record.calls == [] and _snapshot(deadline_dir) == before


@pytest.mark.parametrize("missing", ["initial.json", "checkpoint.json"])
def test_incomplete_prior_record_refuses(deadline_dir, missing):
    _place(deadline_dir, store._encode(_state(PRIOR)))
    (deadline_dir / missing).unlink()
    before = _snapshot(deadline_dir)
    record = Recorder()
    with pytest.raises(ApprovalRefused, match="incomplete"):
        _retain(deadline_dir, _state(CURRENT), record)
    assert record.calls == [] and _snapshot(deadline_dir) == before


@pytest.mark.parametrize("checkpoint", [
    lambda: store._encode(_state(THIRD)),  # other boot
    lambda: store._encode(_state(PRIOR, expires_at="2026-10-13T00:04:00Z")),  # other approval
])
def test_records_of_different_identities_refuse(deadline_dir, checkpoint):
    _place(deadline_dir, store._encode(_state(PRIOR)), checkpoint())
    before = _snapshot(deadline_dir)
    record = Recorder()
    with pytest.raises(ApprovalRefused, match="differ"):
        _retain(deadline_dir, _state(CURRENT), record)
    assert record.calls == [] and _snapshot(deadline_dir) == before


@pytest.mark.parametrize("which", ["initial.json", "checkpoint.json", "both"])
@pytest.mark.parametrize("corrupt", [
    lambda raw: raw + b"\n",
    lambda raw: raw.replace(b",", b", ", 1),
    lambda raw: b"[]",
    lambda raw: b"\xff",
    lambda raw: raw.replace(b'"schema":"azazel-nexus/bootstrap-deadline/v1"',
                            b'"schema":"azazel-nexus/bootstrap-deadline/v2"'),
    lambda raw: _forge_raw(raw, boot_id=PRIOR.upper()),
    lambda raw: _forge_raw(raw, boot_id="not-a-boot"),
    lambda raw: _forge_raw(raw, approval_digest="sha256:" + "z" * 64),
    lambda raw: _forge_raw(raw, admitted_boottime_ns=-1),
    lambda raw: _forge_raw(raw, last_utc=7),
    lambda raw: _forge_raw(raw, extra=1),
])
def test_non_canonical_prior_record_refuses(deadline_dir, which, corrupt):
    raw = store._encode(_state(PRIOR))
    _place(deadline_dir, raw)
    for name in (("initial.json", "checkpoint.json") if which == "both" else (which,)):
        (deadline_dir / name).write_bytes(corrupt(raw))
    before = _snapshot(deadline_dir)
    record = Recorder()
    with pytest.raises(ApprovalRefused):
        _retain(deadline_dir, _state(CURRENT), record)
    assert record.calls == [] and _snapshot(deadline_dir) == before


def _forge_raw(raw, **changes):
    document = json.loads(raw)
    document.update(changes)
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def test_unprotected_prior_record_refuses(deadline_dir):
    _place(deadline_dir, store._encode(_state(PRIOR)))
    os.chmod(deadline_dir / "checkpoint.json", 0o644)
    before = _snapshot(deadline_dir)
    record = Recorder()
    with pytest.raises(ApprovalRefused):
        _retain(deadline_dir, _state(CURRENT), record)
    assert record.calls == [] and _snapshot(deadline_dir) == before


@pytest.mark.parametrize("arrange", ["target", "mode", "symlink"])
def test_unusable_archive_refuses_before_any_record(deadline_dir, tmp_path, arrange):
    _place(deadline_dir, store._encode(_state(PRIOR)))
    if arrange == "symlink":
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir(mode=0o700)
        (deadline_dir / "archive").symlink_to(elsewhere)
    else:
        (deadline_dir / "archive").mkdir(mode=0o700)
        if arrange == "mode":
            os.chmod(deadline_dir / "archive", 0o755)
        else:
            (deadline_dir / "archive" / f"checkpoint-{PRIOR}.json").write_bytes(b"older")
    before = _snapshot(deadline_dir)
    record = Recorder()
    with pytest.raises((ApprovalRefused, OSError)):
        _retain(deadline_dir, _state(CURRENT), record)
    assert record.calls == [] and _snapshot(deadline_dir) == before


def test_interrupted_archive_leaves_the_unfinished_marker(deadline_dir, monkeypatch):
    prior_raw = store._encode(_state(PRIOR))
    _place(deadline_dir, prior_raw)
    calls = []
    real = os.rename

    def rename(*args, **kw):
        calls.append(args)
        if len(calls) == 2:
            raise OSError("power lost")
        return real(*args, **kw)

    monkeypatch.setattr(store.os, "rename", rename)
    with pytest.raises(OSError):
        _retain(deadline_dir, _state(CURRENT), Recorder())
    monkeypatch.setattr(store.os, "rename", real)
    assert (deadline_dir / "transaction.pending").exists()
    assert (deadline_dir / "checkpoint.json").read_bytes() == prior_raw
    # A later boot never treats the half-moved pair as an earlier boot's.
    record = Recorder()
    with pytest.raises(ApprovalRefused, match="unfinished"):
        _retain(deadline_dir, _state(THIRD), record)
    assert record.calls == []


def test_archived_then_created_state_advances_like_a_first_admission(deadline_dir):
    _place(deadline_dir, store._encode(_state(PRIOR)))
    current = _state(CURRENT)
    _retain(deadline_dir, current, Recorder())
    with _fd(deadline_dir) as fd:
        advanced = store._advance_at(
            fd, owner=os.getuid(), approval=current.approval, boot_id=CURRENT,
            now="2026-10-13T00:00:10Z", boottime_ns=110 * NS, clock_trusted=True)
    assert advanced.deadline_boottime_ns == current.deadline_boottime_ns


def test_public_retain_refusal_reason_reaches_the_journal_label(deadline_dir, monkeypatch):
    from azazel_nexus_runtime import activated

    _place(deadline_dir, store._encode(_state(CURRENT)))

    @contextmanager
    def opened():
        with _fd(deadline_dir) as fd:
            yield fd

    monkeypatch.setattr(store, "_state_directory", opened)
    with pytest.raises(ApprovalRefused) as exc:
        try:
            store.retain_initial_deadline(_state(CURRENT), record_deadline_retirement=Recorder())
        except Exception:
            # The same wrapper as ProtectedBootstrapInitialAdmission.retain.
            raise ApprovalRefused("protected bootstrap runtime inputs refused") from None
    assert activated._failure_label(exc.value) == (
        "ApprovalRefused: protected bootstrap runtime inputs refused"
        " <- protected bootstrap state refused"
        " <- bootstrap deadline was already initialized")


def test_runtime_deadline_record_appends_one_confirmed_ledger_entry(tmp_path, monkeypatch):
    from azazel_nexus_runtime import activated, bootstrap_inputs

    ledger = AuditLedger(tmp_path / "activation.jsonl")
    monkeypatch.setattr(activated, "_activation_ledger", lambda _root: ledger)
    summary = {"boot_id": PRIOR, "approval_digest": DIGEST, "initial_sha256": "1" * 64,
               "checkpoint_sha256": "2" * 64, "current_boot_id": CURRENT}
    assert bootstrap_inputs._record_deadline_retirement(summary) is True
    (entry,) = list(ledger)
    event = dict(entry.event)
    assert event.pop("occurred_at").endswith("Z")
    assert event == {"event_type": "activation.bootstrap_deadline_retiring",
                     "actor": "azazel-activated", **summary}

    class Unconfirmed:
        def append(self, _event):
            return object()

    monkeypatch.setattr(activated, "_activation_ledger", lambda _root: Unconfirmed())
    assert bootstrap_inputs._record_deadline_retirement(summary) is False


# --- D: grant records of earlier boots ---------------------------------------

def _grant(boot_id, phase="closed"):
    journal = GrantTransaction(
        boot_id=boot_id, context_digest=DIGEST, approval_digest="sha256:" + "b" * 64,
        generation=3, generation_digest="sha256:" + "c" * 64, grant_id="d" * 32,
        unit_payload_digests=tuple((unit, "e" * 64) for unit in PAIR),
    )
    for action in {"prepared": (), "pair_grant_intent": ("pair_grant_intent",),
                   "closed": ("closing", "closed")}[phase]:
        from azazel_nexus.bootstrap_grant_transaction import advance_transaction
        journal = advance_transaction(
            journal, action,
            evidence_digest=None if action == "pair_grant_intent" else "sha256:" + "f" * 64)
    return journal


@pytest.fixture
def grant_dir(tmp_path, seams):
    directory = tmp_path / "bootstrap"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory


def _write_grant(directory, boot_id, raw=None, mode=0o600, name=None):
    path = directory / (name or f"grant-{boot_id}.json")
    path.write_bytes(raw if raw is not None else encode_transaction(_grant(boot_id)))
    os.chmod(path, mode)
    return path


@contextmanager
def _grants(directory):
    def reopen():
        return os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)

    fd = reopen()
    try:
        opened = GrantTransactionStore(fd, owner_uid=os.getuid(), reopen=reopen)
    finally:
        os.close(fd)
    try:
        yield opened
    finally:
        opened.close()


def _archive(directory, record, *, current=CURRENT, referenced=None):
    with _grants(directory) as grants:
        return grants.archive_prior(current_boot_id=current,
                                    referenced_boot_id=referenced, record=record)


def test_prior_grants_are_recorded_then_moved_never_deleted(grant_dir):
    raws = {boot: _write_grant(grant_dir, boot).read_bytes() for boot in (PRIOR, THIRD)}
    current = _write_grant(grant_dir, CURRENT).read_bytes()
    record = Recorder()
    assert _archive(grant_dir, record) == (PRIOR, THIRD)
    assert record.calls == [{"current_boot_id": CURRENT, "grants": [
        {"boot_id": boot, "phase": "closed", "sha256": hashlib.sha256(raws[boot]).hexdigest()}
        for boot in (PRIOR, THIRD)]}]
    assert _snapshot(grant_dir) == {
        "archive": None,
        f"archive/grant-{PRIOR}.json": raws[PRIOR],
        f"archive/grant-{THIRD}.json": raws[THIRD],
        f"grant-{CURRENT}.json": current,
    }
    # Nothing left to move: no second record, no change.
    again = Recorder()
    assert _archive(grant_dir, again) == () and again.calls == []
    # This boot's record still works through the ordinary store.
    with _grants(grant_dir) as grants:
        assert grants.load(boot_id=CURRENT).boot_id == CURRENT


def test_archived_boot_can_create_its_record_as_before(grant_dir):
    _write_grant(grant_dir, PRIOR)
    _archive(grant_dir, Recorder(), current=CURRENT)
    with _grants(grant_dir) as grants:
        assert grants.load_optional(boot_id=PRIOR) is None
        grants.create(_grant(THIRD, "prepared"))
        assert grants.load(boot_id=THIRD).phase == "prepared"


@pytest.mark.parametrize("arrange", [
    "current", "referenced", "pending", "next", "boot_mismatch", "undecodable",
    "mode", "uppercase_name", "archived_already",
])
def test_unprovable_grant_is_left_in_place(grant_dir, arrange):
    boot = PRIOR
    referenced = None
    if arrange == "current":
        boot = CURRENT
    elif arrange == "referenced":
        referenced = PRIOR
    if arrange == "boot_mismatch":
        _write_grant(grant_dir, PRIOR, raw=encode_transaction(_grant(THIRD)))
    elif arrange == "undecodable":
        _write_grant(grant_dir, PRIOR, raw=b"{}")
    elif arrange == "mode":
        _write_grant(grant_dir, PRIOR, mode=0o644)
    elif arrange == "uppercase_name":
        _write_grant(grant_dir, PRIOR, name=f"grant-{PRIOR.upper()}.json")
    else:
        _write_grant(grant_dir, boot)
    if arrange in ("pending", "next"):
        marker = grant_dir / f".grant-{PRIOR}.json.{arrange}"
        marker.write_bytes(b"x")
        os.chmod(marker, 0o600)
    if arrange == "archived_already":
        (grant_dir / "archive").mkdir(mode=0o700)
        (grant_dir / "archive" / f"grant-{PRIOR}.json").write_bytes(b"older")
    before = _snapshot(grant_dir)
    record = Recorder()
    assert _archive(grant_dir, record, referenced=referenced) == ()
    assert record.calls == [] and _snapshot(grant_dir) == before


@pytest.mark.parametrize("result", [False, None, 1, ApprovalRefused("x"), OSError("disk")])
def test_unconfirmed_grant_record_changes_nothing(grant_dir, result):
    _write_grant(grant_dir, PRIOR)
    before = _snapshot(grant_dir)
    record = Recorder(result)
    with pytest.raises(ApprovalRefused):
        _archive(grant_dir, record)
    assert len(record.calls) == 1 and _snapshot(grant_dir) == before


def test_grant_archive_requires_canonical_boots_and_a_record(grant_dir):
    _write_grant(grant_dir, PRIOR)
    before = _snapshot(grant_dir)
    for kw in ({"current": "x"}, {"referenced": PRIOR.upper()}):
        with pytest.raises(ApprovalRefused):
            _archive(grant_dir, Recorder(), **kw)
    with pytest.raises(ApprovalRefused):
        _archive(grant_dir, None)
    assert _snapshot(grant_dir) == before


# --- D: the manager after READY ----------------------------------------------

class _JournalStore:
    def __init__(self, boot_id):
        self.boot_id = boot_id

    def load_optional(self):
        if self.boot_id is None:
            return None
        return type("J", (), {"intent": type("I", (), {"boot_id": self.boot_id})()})()


def _archiving_manager(grant_dir, *, journal_boot, kernel_boot=CURRENT):
    from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager

    manager = BootstrapNarrowingManager(job_timeout_seconds=5.0)
    guard = BootstrapTransactionGuard(lambda: None)
    manager._publication_inputs = (object(), _JournalStore(journal_boot), guard)
    manager._boot_id_reader = lambda: kernel_boot

    @contextmanager
    def opener(held):
        assert held is guard
        with _grants(grant_dir) as grants:
            yield grants

    manager._grant_store_opener = opener
    manager._grant_archive_record = Recorder()
    return manager


@pytest.mark.parametrize("journal_boot", [None, CURRENT, PRIOR])
def test_manager_moves_only_grants_no_journal_names(grant_dir, journal_boot):
    for boot in (PRIOR, THIRD, CURRENT):
        _write_grant(grant_dir, boot)
    manager = _archiving_manager(grant_dir, journal_boot=journal_boot)
    manager._archive_prior_boot_grants(_grant(CURRENT, "pair_grant_intent"))
    left = {p.name for p in grant_dir.iterdir() if p.is_file()}
    expected = {f"grant-{CURRENT}.json"} | (
        {f"grant-{PRIOR}.json"} if journal_boot == PRIOR else set())
    assert left == expected


def test_manager_moves_nothing_when_kernel_boot_differs_from_grant(grant_dir, capsys):
    _write_grant(grant_dir, PRIOR)
    before = _snapshot(grant_dir)
    manager = _archiving_manager(grant_dir, journal_boot=None, kernel_boot=THIRD)
    manager._grant_archive_failure = lambda *_a: pytest.fail("not a failure")
    manager._archive_prior_boot_grants(_grant(CURRENT, "pair_grant_intent"))
    assert manager._grant_archive_record.calls == [] and _snapshot(grant_dir) == before
    assert "kernel boot differs" in capsys.readouterr().err


@pytest.mark.parametrize("failure", ["record", "store", "journal"])
def test_manager_archive_failure_is_reported_and_never_raised(grant_dir, capsys, failure):
    _write_grant(grant_dir, PRIOR)
    before = _snapshot(grant_dir)
    manager = _archiving_manager(grant_dir, journal_boot=None)
    notes = []
    manager._grant_archive_failure = lambda boot, reason: notes.append((boot, reason))
    if failure == "record":
        manager._grant_archive_record = Recorder(OSError("ledger disk"))
    elif failure == "store":
        manager._grant_store_opener = lambda _g: (_ for _ in ()).throw(
            ApprovalRefused("bootstrap transaction store busy"))
    else:
        manager._publication_inputs[1].load_optional = lambda: (_ for _ in ()).throw(
            ApprovalRefused("bootstrap optional journal observation refused"))
    manager._archive_prior_boot_grants(_grant(CURRENT, "pair_grant_intent"))
    assert _snapshot(grant_dir) == before
    assert len(notes) == 1 and notes[0][0] == CURRENT
    assert notes[0][1].startswith("ApprovalRefused")
    err = capsys.readouterr().err
    assert "left prior boot grant records in place" in err and "ledger disk" not in err
    # Idempotent: the next attempt (the next boot) moves what is left.
    retry = _archiving_manager(grant_dir, journal_boot=None)
    retry._archive_prior_boot_grants(_grant(CURRENT, "pair_grant_intent"))
    assert len(retry._grant_archive_record.calls) == 1
    assert not (grant_dir / f"grant-{PRIOR}.json").exists()
    assert (grant_dir / "archive" / f"grant-{PRIOR}.json").exists()


def test_manager_failure_note_failure_is_still_not_raised(grant_dir, capsys):
    _write_grant(grant_dir, PRIOR)
    manager = _archiving_manager(grant_dir, journal_boot=None)
    manager._grant_archive_record = Recorder(False)
    manager._grant_archive_failure = lambda *_a: (_ for _ in ()).throw(OSError("x"))
    manager._archive_prior_boot_grants(_grant(CURRENT, "pair_grant_intent"))
    assert "could not record the skipped grant archive" in capsys.readouterr().err
    assert (grant_dir / f"grant-{PRIOR}.json").exists()


def test_manager_archive_lets_base_exceptions_through(grant_dir):
    manager = _archiving_manager(grant_dir, journal_boot=None)
    manager._grant_archive_failure = lambda *_a: pytest.fail("not an Exception")

    def interrupted():
        raise KeyboardInterrupt

    manager._boot_id_reader = interrupted
    with pytest.raises(KeyboardInterrupt):
        manager._archive_prior_boot_grants(_grant(CURRENT, "pair_grant_intent"))


def test_manager_without_publication_composition_does_nothing(grant_dir):
    from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager

    _write_grant(grant_dir, PRIOR)
    before = _snapshot(grant_dir)
    manager = BootstrapNarrowingManager(job_timeout_seconds=5.0)
    manager._grant_store_opener = lambda _g: pytest.fail("no store without composition")
    manager._archive_prior_boot_grants(_grant(CURRENT, "pair_grant_intent"))
    assert _snapshot(grant_dir) == before


def test_runtime_grant_record_appends_one_confirmed_ledger_entry(tmp_path, monkeypatch):
    from azazel_nexus_runtime import activated, bootstrap_manager
    from azazel_nexus_runtime.units import UnitOperationFailed

    ledger = AuditLedger(tmp_path / "activation.jsonl")
    monkeypatch.setattr(activated, "_activation_ledger", lambda _root: ledger)
    summary = {"current_boot_id": CURRENT,
               "grants": [{"boot_id": PRIOR, "phase": "closed", "sha256": "1" * 64}]}
    assert bootstrap_manager._append_grant_archive_record(summary) is True
    (entry,) = list(ledger)
    event = dict(entry.event)
    assert event.pop("occurred_at").endswith("Z")
    assert event == {"event_type": "activation.bootstrap_grants_archiving",
                     "actor": "azazel-activated", **summary}

    class Unconfirmed:
        def append(self, _event):
            return None

    monkeypatch.setattr(activated, "_activation_ledger", lambda _root: Unconfirmed())
    with pytest.raises(UnitOperationFailed, match="record unconfirmed"):
        bootstrap_manager._append_grant_archive_record(summary)


def test_grant_archive_runs_after_ready_notification(monkeypatch):
    from test_runtime_bootstrap_controller_ready import (
        DelayedReadyBus, _manager, _transaction)

    bus = DelayedReadyBus(ready_after=1)
    manager, _sessions = _manager(bus, monkeypatch)
    order = []
    monkeypatch.setattr(manager, "_archive_prior_boot_grants",
                        lambda grant: order.append(("archive", grant.phase,
                                                    manager._controller_ready_confirmed)))
    manager.confirm_controller_ready(
        _transaction("pair_grant_opened"), check_ready=lambda: None,
        notify=lambda: order.append(("notify",)),
    )
    assert order == [("notify",), ("archive", "pair_grant_intent", True)]


def test_grant_archive_failure_never_leaves_confirm_controller_ready(monkeypatch, capsys):
    from test_runtime_bootstrap_controller_ready import (
        DelayedReadyBus, _manager, _transaction)

    bus = DelayedReadyBus(ready_after=1)
    manager, _sessions = _manager(bus, monkeypatch)
    notes = []

    def broken(_grant):
        raise OSError("archive disk")

    monkeypatch.setattr(manager, "_archive_prior_boot_grants_once", broken)
    manager._grant_archive_failure = lambda boot, reason: notes.append((boot, reason))
    assert manager.confirm_controller_ready(
        _transaction("pair_grant_opened"), check_ready=lambda: None,
        notify=lambda: None,
    ) is None
    assert manager._controller_ready_confirmed
    assert notes == [(_transaction().boot_id, "OSError")]
    assert "left prior boot grant records in place" in capsys.readouterr().err


def test_real_grant_and_journal_stores_move_only_unreferenced_prior_grants(
        tmp_path, seams, monkeypatch):
    """The production store composition, over private tmp directories."""
    from azazel_nexus import bootstrap_lock
    from azazel_nexus import bootstrap_overlay_journal as overlay_journal
    from azazel_nexus.bootstrap_overlay_journal import OverlayIntent, new_overlay_journal
    from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager

    uid = os.getuid()
    dirs = {}
    for name in ("lock", "journal", "bootstrap"):
        dirs[name] = tmp_path / name
        dirs[name].mkdir(mode=0o700)
        dirs[name].chmod(0o700)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    for boot in (PRIOR, THIRD, CURRENT):
        _write_grant(dirs["bootstrap"], boot)

    @contextmanager
    def state_directory():
        fd = os.open(dirs["bootstrap"], flags)
        try:
            yield fd
        finally:
            os.close(fd)

    real_open = grant_store.os.open

    def fixed_open(path, *args, **kw):
        if path == "/var/lib/azazel/state/bootstrap":
            path = dirs["bootstrap"]
        return real_open(path, *args, **kw)

    monkeypatch.setattr(grant_store, "_state_directory", state_directory)
    monkeypatch.setattr(grant_store, "_OWNER", uid)
    monkeypatch.setattr(grant_store.os, "open", fixed_open)
    lock_fd, journal_fd = os.open(dirs["lock"], flags), os.open(dirs["journal"], flags)
    try:
        with bootstrap_lock._transaction_at(
            lock_fd, owner=uid, reopen=lambda: os.open(dirs["lock"], flags),
        ) as guard, overlay_journal._overlay_store_under_guard(
            guard, journal_fd, owner_uid=uid,
            reopen=lambda: os.open(dirs["journal"], flags),
        ) as journal_store:
            # The retained journal still names PRIOR: its grant must stay.
            journal_store.create(new_overlay_journal(OverlayIntent(
                boot_id=PRIOR, context_digest="c" * 64, grant_id="d" * 32,
                payload_digests=tuple((unit, "e" * 64) for unit in PAIR))))
            manager = BootstrapNarrowingManager(job_timeout_seconds=5.0)
            manager._publication_inputs = (object(), journal_store, guard)
            manager._boot_id_reader = lambda: CURRENT
            manager._grant_archive_record = Recorder()
            assert manager._grant_store_opener is grant_store.grant_transaction_store_in_transaction
            manager._archive_prior_boot_grants(_grant(CURRENT, "pair_grant_intent"))
    finally:
        os.close(lock_fd)
        os.close(journal_fd)
    assert [row["boot_id"] for row in manager._grant_archive_record.calls[0]["grants"]] == [THIRD]
    assert sorted(p.name for p in dirs["bootstrap"].iterdir() if p.is_file()) == [
        f"grant-{CURRENT}.json", f"grant-{PRIOR}.json"]
    assert [p.name for p in (dirs["bootstrap"] / "archive").iterdir()] == [f"grant-{THIRD}.json"]


def test_runtime_grant_archive_failure_note_is_a_ledger_entry(tmp_path, monkeypatch):
    from azazel_nexus_runtime import activated, bootstrap_manager

    ledger = AuditLedger(tmp_path / "activation.jsonl")
    monkeypatch.setattr(activated, "_activation_ledger", lambda _root: ledger)
    bootstrap_manager._append_grant_archive_failure(CURRENT, "ApprovalRefused")
    (entry,) = list(ledger)
    event = dict(entry.event)
    assert event.pop("occurred_at").endswith("Z")
    assert event == {"event_type": "activation.bootstrap_grants_archive_failed",
                     "current_boot_id": CURRENT, "reason": "ApprovalRefused",
                     "actor": "azazel-activated"}
