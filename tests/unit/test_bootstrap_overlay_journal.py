import os
import uuid
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

import azazel_nexus.bootstrap_overlay_journal as overlay_journal
from azazel_nexus import bootstrap_lock
from azazel_nexus.bootstrap_overlay_journal import (
    OverlayIntent,
    OverlayJournal,
    OverlayStopEvidence,
    advance_overlay,
    decode_overlay_journal,
    encode_overlay_journal,
    new_overlay_journal,
)
from azazel_nexus.operator_trust import ApprovalRefused

AUDITD = "azazel-auditd.service"
COMMISSIOND = "azazel-commissiond.service"
PAIR = (AUDITD, COMMISSIOND)
PAYLOADS = ((AUDITD, "a" * 64), (COMMISSIOND, "b" * 64))


def intent():
    return OverlayIntent(
        boot_id=str(uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")),
        context_digest="c" * 64,
        grant_id="d" * 32,
        payload_digests=PAYLOADS,
    )


def created(journal, unit, device=1, inode=10):
    if journal.owned_files and inode == 10:
        inode = 11
    return advance_overlay(
        journal, "create-file", unit=unit, device=device, inode=inode
    )


def published():
    partial = created(new_overlay_journal(intent()), COMMISSIOND, inode=20)
    return created(partial, AUDITD, inode=21)


def good_evidence():
    return OverlayStopEvidence(
        start_fence_closed=True,
        stopped_pair=PAIR,
        inactive_pair=PAIR,
        withdrawn_pair=PAIR,
        persistent_masks_restored=True,
        loaded_masks_confirmed=True,
    )


@pytest.fixture
def journal_store(tmp_path):
    directory = tmp_path / "journal"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory_fd = os.open(directory, flags)

    def reopen():
        return os.open(directory, flags)

    store = overlay_journal.OverlayJournalStore(
        directory_fd, owner_uid=os.getuid(), reopen=reopen
    )
    try:
        yield store, directory, directory_fd
    finally:
        close = getattr(store, "close", None)
        if callable(close):
            close()
        os.close(directory_fd)


def _record_file(directory):
    candidates = [path for path in directory.iterdir()
                  if not path.name.startswith(".overlay-journal.")]
    assert len(candidates) == 1
    return candidates[0]


def _bootstrap_tree(root: Path):
    root.mkdir()
    root.chmod(0o755)
    current = root
    for component in overlay_journal._OVERLAY_COMPONENTS:
        current = current / component
        current.mkdir(mode=0o755)
        current.chmod(0o755)
    current.chmod(0o700)
    return current


def test_fixed_overlay_directory_traversal_opens_the_protected_leaf(tmp_path):
    leaf = _bootstrap_tree(tmp_path / "root")
    root_fd = os.open(tmp_path / "root", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = overlay_journal._open_overlay_directory_at(root_fd, owner_uid=os.getuid())
        try:
            opened, expected = os.fstat(fd), leaf.stat()
            assert (opened.st_dev, opened.st_ino) == (expected.st_dev, expected.st_ino)
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)


def test_fixed_overlay_directory_traversal_refuses_wrong_owner_expectation(tmp_path):
    _bootstrap_tree(tmp_path / "root")
    root_fd = os.open(tmp_path / "root", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(ApprovalRefused):
            overlay_journal._open_overlay_directory_at(
                root_fd, owner_uid=os.getuid() + 1
            )
    finally:
        os.close(root_fd)


@pytest.mark.parametrize("unsafe", ["symlink", "writable_parent", "loose_leaf"])
def test_fixed_overlay_directory_traversal_fails_closed_on_unsafe_path(
    tmp_path, unsafe
):
    leaf = _bootstrap_tree(tmp_path / "root")
    if unsafe == "symlink":
        real_leaf = leaf.with_name("real-bootstrap")
        leaf.rename(real_leaf)
        leaf.symlink_to(real_leaf, target_is_directory=True)
    elif unsafe == "writable_parent":
        leaf.parent.chmod(0o777)
    else:
        leaf.chmod(0o750)
    root_fd = os.open(tmp_path / "root", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(ApprovalRefused):
            overlay_journal._open_overlay_directory_at(
                root_fd, owner_uid=os.getuid()
            )
    finally:
        os.close(root_fd)


def test_intent_records_exact_boot_context_grant_and_two_payload_digests():
    value = intent()
    assert value.boot_id == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert value.context_digest == "c" * 64
    assert value.grant_id == "d" * 32
    assert value.payload_digests == PAYLOADS
    assert new_overlay_journal(value) == OverlayJournal(value, "intent")


@pytest.mark.parametrize(
    "changes",
    [
        {"boot_id": "not-a-uuid"},
        {"context_digest": "x" * 64},
        {"grant_id": "d" * 31},
        {"payload_digests": ((AUDITD, "a" * 64),)},
        {"payload_digests": ((AUDITD, "a" * 64), ("other.service", "b" * 64))},
        {"payload_digests": ((AUDITD, "A" * 64), (COMMISSIOND, "b" * 64))},
    ],
)
def test_malformed_intent_is_refused(changes):
    values = {
        "boot_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "context_digest": "c" * 64,
        "grant_id": "d" * 32,
        "payload_digests": PAYLOADS,
    }
    values.update(changes)
    with pytest.raises(ApprovalRefused):
        OverlayIntent(**values)


def test_candidate_files_must_be_created_once_for_exact_pair_and_publish_after_both():
    initial = new_overlay_journal(intent())
    partial = created(initial, COMMISSIOND)
    assert partial.phase == "partial"
    assert tuple(row[0] for row in partial.owned_files) == (COMMISSIOND,)

    complete = created(partial, AUDITD)
    assert complete.phase == "published"
    assert tuple(row[0] for row in complete.owned_files) == PAIR
    assert {row[0]: row[3] for row in complete.owned_files} == dict(PAYLOADS)


def test_synthetic_regular_candidate_files_supply_only_recorded_identity(tmp_path):
    overlay = tmp_path / "run/systemd/system.control"
    overlay.mkdir(parents=True)
    files = {}
    for index, unit in enumerate(PAIR, start=1):
        path = overlay / unit
        path.write_bytes(bytes([index]))
        info = path.stat(follow_symlinks=False)
        files[unit] = (info.st_dev, info.st_ino)

    journal = new_overlay_journal(intent())
    journal = created(journal, PAIR[0], *files[PAIR[0]])
    journal = created(journal, PAIR[1], *files[PAIR[1]])
    assert journal.phase == "published"
    assert tuple((item[1], item[2]) for item in journal.owned_files) == tuple(
        files[unit] for unit in PAIR
    )
    # Journal transitions record filesystem identity; they do not publish a
    # service grant or perform any systemd operation.
    assert all((overlay / unit).is_file() for unit in PAIR)


@pytest.mark.parametrize(
    "call",
    [
        lambda journal: advance_overlay(
            advance_overlay(journal, "close-starts"), "close-starts"
        ),
        lambda journal: advance_overlay(
            journal, "create-file", unit="other.service", device=1, inode=1
        ),
        lambda journal: advance_overlay(
            journal, "create-file", unit=AUDITD, device=1, inode=True
        ),
        lambda journal: advance_overlay(
            created(journal, AUDITD), "create-file", unit=AUDITD, device=1, inode=11
        ),
        lambda journal: advance_overlay(
            journal, "create-file", unit=AUDITD, device=True, inode=10
        ),
    ],
)
def test_invalid_creation_order_or_identity_is_refused(call):
    with pytest.raises(ApprovalRefused):
        call(new_overlay_journal(intent()))


def test_partial_record_cannot_claim_published_but_can_record_narrowing_intent():
    first = created(new_overlay_journal(intent()), AUDITD)
    with pytest.raises(ApprovalRefused):
        OverlayJournal(intent(), "published", first.owned_files)
    closing = advance_overlay(first, "close-starts")
    assert closing.phase == "closing"
    assert closing.owned_files == first.owned_files
    assert decode_overlay_journal(encode_overlay_journal(closing)) == closing


def test_empty_intent_can_record_narrowing_without_claiming_file_ownership():
    closing = advance_overlay(new_overlay_journal(intent()), "close-starts")
    assert closing.phase == "closing"
    assert closing.owned_files == ()
    assert decode_overlay_journal(encode_overlay_journal(closing)) == closing


def test_two_candidate_names_cannot_claim_one_device_inode_pair():
    with pytest.raises(ApprovalRefused):
        OverlayJournal(
            intent(), "published",
            ((AUDITD, 1, 10, "a" * 64), (COMMISSIOND, 1, 10, "b" * 64)),
        )


def test_published_is_file_phase_only_and_transitions_to_closing_not_permission():
    journal = published()
    assert journal.phase == "published"
    closing = advance_overlay(journal, "close-starts")
    assert closing.phase == "closing"
    assert closing.owned_files == journal.owned_files
    assert not hasattr(closing, "authorized")


def test_withdrawal_requires_closing_and_exact_typed_evidence():
    journal = advance_overlay(published(), "close-starts")
    with pytest.raises(ApprovalRefused):
        advance_overlay(published(), "withdraw", evidence=good_evidence())
    with pytest.raises(ApprovalRefused):
        advance_overlay(journal, "withdraw", evidence=None)
    # Closing the files is not yet authorization to forget their ownership.
    with pytest.raises(ApprovalRefused):
        advance_overlay(journal, "withdraw", evidence=good_evidence())
    withdrawing = advance_overlay(journal, "begin-withdrawal")
    assert withdrawing.phase == "withdrawing"
    assert withdrawing.owned_files == journal.owned_files
    closed = advance_overlay(withdrawing, "withdraw", evidence=good_evidence())
    assert closed.phase == "closed"
    assert closed.owned_files == ()


@pytest.mark.parametrize("journal", [
    new_overlay_journal(intent()),
    created(new_overlay_journal(intent()), AUDITD),
    published(),
    advance_overlay(
        advance_overlay(published(), "close-starts"), "begin-withdrawal"
    ),
    advance_overlay(
        advance_overlay(
            advance_overlay(published(), "close-starts"), "begin-withdrawal"
        ),
        "withdraw",
        evidence=good_evidence(),
    ),
])
def test_begin_withdrawal_requires_closing_phase(journal):
    with pytest.raises(ApprovalRefused):
        advance_overlay(journal, "begin-withdrawal")


def test_closing_cannot_finalize_without_withdrawal_intent():
    closing = advance_overlay(published(), "close-starts")
    with pytest.raises(ApprovalRefused):
        advance_overlay(closing, "withdraw", evidence=good_evidence())


@pytest.mark.parametrize("journal,owned_count", [
    (advance_overlay(
        advance_overlay(new_overlay_journal(intent()), "close-starts"),
        "begin-withdrawal",
    ), 0),
    (advance_overlay(
        advance_overlay(
            created(new_overlay_journal(intent()), AUDITD), "close-starts"
        ),
        "begin-withdrawal",
    ), 1),
    (advance_overlay(
        advance_overlay(published(), "close-starts"), "begin-withdrawal"
    ), 2),
])
def test_withdrawing_codec_retains_zero_one_or_two_owned_files(journal, owned_count):
    raw = encode_overlay_journal(journal)
    assert decode_overlay_journal(raw) == journal
    assert journal.phase == "withdrawing"
    assert len(journal.owned_files) == owned_count


@pytest.mark.parametrize(
    "changes",
    [
        {"start_fence_closed": False},
        {"start_fence_closed": 1},
        {"stopped_pair": (AUDITD,)},
        {"inactive_pair": (AUDITD, AUDITD)},
        {"withdrawn_pair": (COMMISSIOND, AUDITD)},
        {"persistent_masks_restored": False},
        {"persistent_masks_restored": 1},
        {"loaded_masks_confirmed": False},
        {"loaded_masks_confirmed": 1},
    ],
)
def test_incomplete_or_malformed_stop_evidence_is_refused(changes):
    journal = advance_overlay(
        advance_overlay(published(), "close-starts"), "begin-withdrawal"
    )
    with pytest.raises(ApprovalRefused):
        evidence = replace(good_evidence(), **changes)
        advance_overlay(journal, "withdraw", evidence=evidence)


def test_unknown_actions_and_reopening_closed_journal_are_refused():
    with pytest.raises(ApprovalRefused):
        advance_overlay(new_overlay_journal(intent()), "publish")
    closed = advance_overlay(
        advance_overlay(
            advance_overlay(published(), "close-starts"), "begin-withdrawal"
        ),
        "withdraw",
        evidence=good_evidence(),
    )
    with pytest.raises(ApprovalRefused):
        advance_overlay(closed, "create-file", unit=AUDITD, device=1, inode=99)


@pytest.mark.parametrize("journal", [
    new_overlay_journal(intent()),
    created(new_overlay_journal(intent()), AUDITD),
    published(),
    advance_overlay(published(), "close-starts"),
    advance_overlay(
        advance_overlay(published(), "close-starts"), "begin-withdrawal"
    ),
    advance_overlay(
        advance_overlay(
            advance_overlay(published(), "close-starts"), "begin-withdrawal"
        ),
        "withdraw",
        evidence=good_evidence(),
    ),
])
def test_journal_codec_roundtrips_every_phase_canonically(journal):
    raw = encode_overlay_journal(journal)
    assert raw.endswith(b"\n")
    assert decode_overlay_journal(raw) == journal


@pytest.mark.parametrize("raw", [
    b"",
    b"{}\n",
    b"{}",
    b'{"schema":"wrong","schema":"duplicate"}\n',
    b" " * 4097,
    encode_overlay_journal(new_overlay_journal(intent())).replace(
        b'"phase":"intent"', b'"phase":"published"'
    ),
    encode_overlay_journal(new_overlay_journal(intent())).replace(
        b'"phase":"intent"', b'"phase":"bogus"'
    ),
    encode_overlay_journal(published()).replace(b'"inode":21', b'"inode":20'),
    encode_overlay_journal(published()).replace(b'"inode":21', b'"inode":18446744073709551616'),
])
def test_journal_decoder_rejects_ambiguous_noncanonical_or_overbound_state(raw):
    with pytest.raises(ApprovalRefused):
        decode_overlay_journal(raw)


def test_store_create_load_replace_and_remove_cas(journal_store):
    store, directory, _directory_fd = journal_store
    initial = new_overlay_journal(intent())
    partial = created(initial, AUDITD)

    store.create(initial)
    assert store.load() == initial
    with pytest.raises(ApprovalRefused):
        store.create(initial)

    store.replace(initial, partial)
    assert store.load() == partial
    with pytest.raises(ApprovalRefused):
        store.replace(initial, published())
    assert store.load() == partial

    with pytest.raises(ApprovalRefused):
        store.remove(initial)
    assert store.load() == partial
    store.remove(partial)
    with pytest.raises(ApprovalRefused):
        store.load()
    assert list(directory.iterdir()) == []


def test_create_write_failure_reports_uncertain_and_does_not_adopt_partial_file(
    journal_store, monkeypatch
):
    store, directory, _directory_fd = journal_store

    def fail_write(_fd, _raw):
        raise OSError("injected create write failure")

    monkeypatch.setattr(overlay_journal, "_write_all", fail_write)
    with pytest.raises(overlay_journal.OverlayJournalDurabilityUncertain):
        store.create(new_overlay_journal(intent()))
    assert len(list(directory.iterdir())) == 1
    with pytest.raises(ApprovalRefused):
        store.load()


def test_create_file_fsync_failure_reports_uncertain(journal_store, monkeypatch, private_os):
    private_os(overlay_journal)
    store, _directory, _directory_fd = journal_store

    def fail_fsync(_fd):
        raise OSError("injected create fsync failure")

    monkeypatch.setattr(overlay_journal.os, "fsync", fail_fsync)
    with pytest.raises(overlay_journal.OverlayJournalDurabilityUncertain):
        store.create(new_overlay_journal(intent()))


@pytest.mark.parametrize("mutation", ["symlink", "hardlink", "mode", "bytes"])
def test_store_load_refuses_unsafe_or_noncanonical_record(journal_store, tmp_path, mutation):
    store, directory, _directory_fd = journal_store
    store.create(new_overlay_journal(intent()))
    record = _record_file(directory)
    if mutation == "symlink":
        original = record.read_bytes()
        record.unlink()
        target = tmp_path / "external"
        target.write_bytes(original)
        record.symlink_to(target)
    elif mutation == "hardlink":
        os.link(record, tmp_path / "linked-journal")
    elif mutation == "mode":
        record.chmod(0o644)
    else:
        record.write_bytes(record.read_bytes().replace(b'"phase":"intent"', b'"phase": "intent"'))

    with pytest.raises(ApprovalRefused):
        store.load()


def test_store_load_refuses_missing_record_and_unexpected_directory_entry(journal_store):
    store, directory, _directory_fd = journal_store
    with pytest.raises(ApprovalRefused):
        store.load()
    store.create(new_overlay_journal(intent()))
    foreign = directory / "foreign"
    foreign.write_bytes(b"keep")
    with pytest.raises(ApprovalRefused):
        store.load()
    assert foreign.read_bytes() == b"keep"


def test_store_rejects_wrong_directory_owner_or_mode(tmp_path):
    directory = tmp_path / "unsafe-journal"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(directory, flags)

    def reopen():
        return os.open(directory, flags)

    try:
        wrong_owner = overlay_journal.OverlayJournalStore(
            fd, owner_uid=os.getuid() + 1, reopen=reopen
        )
        with pytest.raises(ApprovalRefused):
            wrong_owner.create(new_overlay_journal(intent()))
        if hasattr(wrong_owner, "close"):
            wrong_owner.close()

        directory.chmod(0o755)
        wrong_mode = overlay_journal.OverlayJournalStore(
            fd, owner_uid=os.getuid(), reopen=reopen
        )
        with pytest.raises(ApprovalRefused):
            wrong_mode.load()
        if hasattr(wrong_mode, "close"):
            wrong_mode.close()
    finally:
        os.close(fd)


def test_store_refuses_reopened_path_with_replaced_directory_identity(tmp_path):
    original = tmp_path / "original"
    replacement = tmp_path / "replacement"
    original.mkdir(mode=0o700)
    replacement.mkdir(mode=0o700)
    original.chmod(0o700)
    replacement.chmod(0o700)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    original_fd = os.open(original, flags)
    store = overlay_journal.OverlayJournalStore(
        original_fd, owner_uid=os.getuid(), reopen=lambda: os.open(replacement, flags)
    )
    try:
        with pytest.raises(ApprovalRefused):
            store.load()
    finally:
        store.close()
        os.close(original_fd)


def test_store_reuses_the_already_held_bootstrap_transaction_guard(tmp_path):
    lock_directory = tmp_path / "lock"
    journal_directory = tmp_path / "overlay-journal"
    lock_directory.mkdir(mode=0o700)
    journal_directory.mkdir(mode=0o700)
    lock_directory.chmod(0o700)
    journal_directory.chmod(0o700)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    lock_fd = os.open(lock_directory, flags)
    journal_fd = os.open(journal_directory, flags)

    def reopen_lock():
        return os.open(lock_directory, flags)

    def reopen_journal():
        return os.open(journal_directory, flags)

    try:
        with bootstrap_lock._transaction_at(
            lock_fd, owner=os.getuid(), reopen=reopen_lock
        ) as guard, overlay_journal._overlay_store_under_guard(
            guard, journal_fd, owner_uid=os.getuid(), reopen=reopen_journal
        ) as store:
            with pytest.raises(FrozenInstanceError):
                guard._check = lambda: None
            journal = new_overlay_journal(intent())
            store.create(journal)
            assert store.load() == journal
        with pytest.raises(ApprovalRefused):
            guard()
        assert (lock_directory / "supervisor.lock").is_file()
    finally:
        os.close(journal_fd)
        os.close(lock_fd)


def _open_guard_test_directories(tmp_path):
    lock_directory = tmp_path / "lock"
    journal_directory = tmp_path / "overlay-journal"
    lock_directory.mkdir(mode=0o700)
    journal_directory.mkdir(mode=0o700)
    lock_directory.chmod(0o700)
    journal_directory.chmod(0o700)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    return (
        lock_directory,
        journal_directory,
        flags,
        os.open(lock_directory, flags),
        os.open(journal_directory, flags),
    )


def test_expired_transaction_guard_cannot_open_the_overlay_store(tmp_path):
    lock_directory, journal_directory, flags, lock_fd, journal_fd = (
        _open_guard_test_directories(tmp_path)
    )
    try:
        with bootstrap_lock._transaction_at(
            lock_fd, owner=os.getuid(), reopen=lambda: os.open(lock_directory, flags)
        ) as guard:
            pass
        with pytest.raises(ApprovalRefused), overlay_journal._overlay_store_under_guard(
            guard, journal_fd, owner_uid=os.getuid(),
            reopen=lambda: os.open(journal_directory, flags),
        ):
            pytest.fail("expired guard opened a journal store")
    finally:
        os.close(journal_fd)
        os.close(lock_fd)


def test_expired_guard_at_store_exit_closes_store_descriptor(tmp_path):
    lock_directory, journal_directory, flags, lock_fd, journal_fd = (
        _open_guard_test_directories(tmp_path)
    )
    transaction = bootstrap_lock._transaction_at(
        lock_fd, owner=os.getuid(), reopen=lambda: os.open(lock_directory, flags)
    )
    store_context = None
    store = None
    try:
        guard = transaction.__enter__()
        store_context = overlay_journal._overlay_store_under_guard(
            guard, journal_fd, owner_uid=os.getuid(),
            reopen=lambda: os.open(journal_directory, flags),
        )
        store = store_context.__enter__()
        transaction.__exit__(None, None, None)
        with pytest.raises(ApprovalRefused):
            store_context.__exit__(None, None, None)
        assert store._directory_fd is None
    finally:
        if store is not None and store._directory_fd is not None:
            store.close()
        os.close(journal_fd)
        os.close(lock_fd)


def test_expired_guard_at_store_exit_preserves_inflight_exception(tmp_path):
    lock_directory, journal_directory, flags, lock_fd, journal_fd = (
        _open_guard_test_directories(tmp_path)
    )
    transaction = bootstrap_lock._transaction_at(
        lock_fd, owner=os.getuid(), reopen=lambda: os.open(lock_directory, flags)
    )
    store_context = None
    store = None
    try:
        guard = transaction.__enter__()
        store_context = overlay_journal._overlay_store_under_guard(
            guard, journal_fd, owner_uid=os.getuid(),
            reopen=lambda: os.open(journal_directory, flags),
        )
        store = store_context.__enter__()
        transaction.__exit__(None, None, None)
        original = RuntimeError("operation failed before guard expired")
        assert store_context.__exit__(
            RuntimeError, original, original.__traceback__
        ) is False
        assert store._directory_fd is None
    finally:
        if store is not None and store._directory_fd is not None:
            store.close()
        os.close(journal_fd)
        os.close(lock_fd)


def test_replace_write_failure_keeps_old_record(journal_store, monkeypatch, private_os):
    private_os(overlay_journal)
    store, _directory, _directory_fd = journal_store
    initial = new_overlay_journal(intent())
    next_journal = created(initial, AUDITD)
    store.create(initial)
    real_write = overlay_journal.os.write

    def fail_write(_fd, _raw):
        raise OSError("injected short write")

    monkeypatch.setattr(overlay_journal.os, "write", fail_write)
    with pytest.raises(ApprovalRefused):
        store.replace(initial, next_journal)
    monkeypatch.setattr(overlay_journal.os, "write", real_write)
    assert store.load() == initial


def test_replace_directory_fsync_uncertainty_reports_new_visible_state(
    journal_store, monkeypatch, private_os
):
    private_os(overlay_journal)
    store, _directory, _directory_fd = journal_store
    initial = new_overlay_journal(intent())
    next_journal = created(initial, AUDITD)
    store.create(initial)
    real_fsync = overlay_journal.os.fsync
    calls = 0

    def fail_after_replace(fd):
        nonlocal calls
        calls += 1
        # Temp-file fsync succeeds; directory fsync after rename is uncertain.
        if calls == 2:
            raise OSError("injected directory fsync failure")
        return real_fsync(fd)

    monkeypatch.setattr(overlay_journal.os, "fsync", fail_after_replace)
    with pytest.raises(ApprovalRefused) as error:
        store.replace(initial, next_journal)
    assert "uncertain" in type(error.value).__name__.lower()
    monkeypatch.setattr(overlay_journal.os, "fsync", real_fsync)
    assert store.load() == next_journal


def test_replace_post_rename_read_failure_reports_uncertain(journal_store, monkeypatch):
    store, _directory, _directory_fd = journal_store
    initial = new_overlay_journal(intent())
    next_journal = created(initial, AUDITD)
    store.create(initial)
    read_current = store._read_current
    calls = 0

    def fail_after_rename():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ApprovalRefused("injected readback refusal")
        return read_current()

    monkeypatch.setattr(store, "_read_current", fail_after_rename)
    with pytest.raises(overlay_journal.OverlayJournalDurabilityUncertain):
        store.replace(initial, next_journal)
    monkeypatch.setattr(store, "_read_current", read_current)
    assert store.load() == next_journal


def test_replace_temp_close_failure_is_uncertain_without_double_close(
    journal_store, monkeypatch, private_os
):
    private_os(overlay_journal)
    store, _directory, _directory_fd = journal_store
    initial = new_overlay_journal(intent())
    next_journal = created(initial, AUDITD)
    store.create(initial)
    real_open = overlay_journal.os.open
    real_close = overlay_journal.os.close
    temp_fd = None
    close_attempts = 0

    def capture_open(path, *args, **kwargs):
        nonlocal temp_fd
        fd = real_open(path, *args, **kwargs)
        if isinstance(path, str) and path.startswith(".overlay-journal."):
            temp_fd = fd
        return fd

    def fail_once(fd):
        nonlocal close_attempts
        if fd == temp_fd:
            close_attempts += 1
            real_close(fd)
            raise OSError("injected close error after descriptor release")
        return real_close(fd)

    monkeypatch.setattr(overlay_journal.os, "open", capture_open)
    monkeypatch.setattr(overlay_journal.os, "close", fail_once)
    with pytest.raises(overlay_journal.OverlayJournalDurabilityUncertain):
        store.replace(initial, next_journal)
    assert close_attempts == 1
    monkeypatch.setattr(overlay_journal.os, "open", real_open)
    monkeypatch.setattr(overlay_journal.os, "close", real_close)
    assert store.load() == next_journal


def test_remove_directory_fsync_uncertainty_reports_absent_state(journal_store, monkeypatch, private_os):
    private_os(overlay_journal)
    store, _directory, _directory_fd = journal_store
    current = new_overlay_journal(intent())
    store.create(current)
    real_fsync = overlay_journal.os.fsync

    def fail_directory(fd):
        raise OSError("injected directory fsync failure")

    monkeypatch.setattr(overlay_journal.os, "fsync", fail_directory)
    with pytest.raises(ApprovalRefused) as error:
        store.remove(current)
    assert "uncertain" in type(error.value).__name__.lower()
    monkeypatch.setattr(overlay_journal.os, "fsync", real_fsync)
    with pytest.raises(ApprovalRefused):
        store.load()


def test_remove_post_unlink_directory_recheck_reports_uncertain(journal_store, monkeypatch):
    store, _directory, _directory_fd = journal_store
    current = new_overlay_journal(intent())
    store.create(current)
    check_directory = store._check_directory
    calls = 0

    def fail_after_unlink():
        nonlocal calls
        calls += 1
        if calls == 4:
            raise ApprovalRefused("injected post-unlink recheck failure")
        return check_directory()

    monkeypatch.setattr(store, "_check_directory", fail_after_unlink)
    with pytest.raises(overlay_journal.OverlayJournalDurabilityUncertain):
        store.remove(current)
    with pytest.raises(ApprovalRefused):
        store.load()


def test_load_optional_returns_none_without_creating_a_journal(journal_store):
    store, directory, _directory_fd = journal_store

    assert store.load_optional() is None
    assert list(directory.iterdir()) == []


def test_load_optional_returns_existing_valid_record(journal_store):
    store, _directory, _directory_fd = journal_store
    current = new_overlay_journal(intent())
    store.create(current)

    assert store.load_optional() == current


@pytest.mark.parametrize("kind", ["empty", "malformed", "symlink", "dangling", "fifo", "mode"])
def test_load_optional_refuses_invalid_journal_entries(journal_store, tmp_path, kind):
    store, directory, _directory_fd = journal_store
    record = directory / overlay_journal._JOURNAL_NAME
    if kind == "empty":
        record.write_bytes(b"")
        record.chmod(0o600)
    elif kind == "malformed":
        record.write_bytes(b"not a journal")
        record.chmod(0o600)
    elif kind in {"symlink", "dangling"}:
        target = tmp_path / "journal-target"
        if kind == "symlink":
            target.write_bytes(encode_overlay_journal(new_overlay_journal(intent())))
        record.symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(record, 0o600)
    elif kind == "mode":
        store.create(new_overlay_journal(intent()))
        record.chmod(0o644)

    with pytest.raises(ApprovalRefused):
        store.load_optional()


def test_load_optional_refuses_unexpected_directory_entry(journal_store):
    store, directory, _directory_fd = journal_store
    foreign = directory / "unexpected"
    foreign.write_bytes(b"leave intact")

    with pytest.raises(ApprovalRefused):
        store.load_optional()
    assert foreign.read_bytes() == b"leave intact"


def test_load_optional_refuses_closed_store(journal_store):
    store, _directory, _directory_fd = journal_store
    store.close()

    with pytest.raises(ApprovalRefused):
        store.load_optional()


def test_load_optional_does_not_treat_lstat_permission_error_as_absence(
    journal_store, monkeypatch, private_os
):
    private_os(overlay_journal)
    store, _directory, _directory_fd = journal_store
    real_stat = overlay_journal.os.stat

    def denied_stat(path, *args, **kwargs):
        if path == overlay_journal._JOURNAL_NAME and kwargs.get("dir_fd") == store._directory_fd:
            raise PermissionError("injected journal lstat denial")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(overlay_journal.os, "stat", denied_stat)
    with pytest.raises(ApprovalRefused):
        store.load_optional()


def test_load_optional_refuses_journal_appearing_between_absence_checks(
    journal_store, monkeypatch, private_os
):
    private_os(overlay_journal)
    store, directory, _directory_fd = journal_store
    real_stat = overlay_journal.os.stat
    first_absence = True

    def appearing_stat(path, *args, **kwargs):
        nonlocal first_absence
        if path == overlay_journal._JOURNAL_NAME and kwargs.get("dir_fd") == store._directory_fd:
            if first_absence:
                first_absence = False
                raise FileNotFoundError(path)
            (directory / path).write_bytes(
                encode_overlay_journal(new_overlay_journal(intent()))
            )
            (directory / path).chmod(0o600)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(overlay_journal.os, "stat", appearing_stat)
    with pytest.raises(ApprovalRefused, match="appeared"):
        store.load_optional()


@pytest.mark.parametrize("phase", ["published", "closing", "withdrawing"])
def test_reboot_reset_closes_published_closing_and_withdrawing(phase):
    journal = published()
    if phase != "published":
        journal = advance_overlay(journal, "close-starts")
    if phase == "withdrawing":
        journal = advance_overlay(journal, "begin-withdrawal")

    closed = advance_overlay(journal, "reboot-reset")

    assert closed == OverlayJournal(journal.intent, "closed")
    assert closed.owned_files == ()
    assert decode_overlay_journal(encode_overlay_journal(closed)) == closed


@pytest.mark.parametrize("phase", ["intent", "partial", "closed"])
def test_reboot_reset_refused_outside_owned_phases(phase):
    journal = new_overlay_journal(intent())
    if phase == "partial":
        journal = created(journal, COMMISSIOND, inode=20)
    if phase == "closed":
        journal = OverlayJournal(intent(), "closed")
    with pytest.raises(ApprovalRefused, match="reboot reset refused"):
        advance_overlay(journal, "reboot-reset")
