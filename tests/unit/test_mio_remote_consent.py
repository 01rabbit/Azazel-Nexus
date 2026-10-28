"""The remote opt-in store: generations, fail-closed reads, restart, send gate.

Temporary directories only; the send gate is exercised with real `flock`
between threads. Mock evidence for the store; no systemd, no transport.
"""

from __future__ import annotations

import fcntl
import os
import threading

import pytest

from azazel_nexus.mio_profile import NO_OPT_IN, PREREQUISITES, RemotePrerequisite
from azazel_nexus_runtime import mio_remote_consent as mc
from azazel_nexus_runtime.mio_remote_consent import (
    ConsentRecord,
    ConsentRefused,
    ConsentStore,
    decode_record,
    encode_record,
)

OPERATOR = "uid:1001"


@pytest.fixture
def directory(tmp_path):
    state = tmp_path / "mio"
    state.mkdir()
    state.chmod(0o700)
    return state


def _store(directory, **kw) -> ConsentStore:
    return ConsentStore(directory, owner=os.geteuid(), clock=lambda: "2026-10-28T00:00:00Z", **kw)


def _grant_all(store: ConsentStore) -> ConsentRecord:
    record = None
    for prerequisite in PREREQUISITES:
        record = store.set_prerequisite(prerequisite, operator=OPERATOR)
    return record


def _record_path(directory):
    return directory / mc.LEAF / mc.RECORD_FILENAME


# -- reading --------------------------------------------------------------


def test_no_record_is_no_opt_in_and_creates_nothing(directory):
    reading = _store(directory).reading()
    assert reading.opt_in is NO_OPT_IN and reading.generation == 0
    assert reading.status == "absent" and not reading.permits
    assert not (directory / mc.LEAF).exists()


def test_an_absent_state_directory_is_unavailable(tmp_path):
    reading = _store(tmp_path / "missing").reading()
    assert reading.generation is None and reading.opt_in is NO_OPT_IN


def test_each_prerequisite_is_explicit_and_each_change_is_a_generation(directory):
    store = _store(directory)
    generations = []
    for index, prerequisite in enumerate(PREREQUISITES):
        record = store.set_prerequisite(prerequisite, operator=OPERATOR)
        generations.append(record.generation)
        reading = store.reading()
        assert reading.permits is (index == len(PREREQUISITES) - 1)
    assert generations == [1, 2, 3, 4]
    reading = store.reading()
    assert reading.status == "granted" and reading.opt_in.active()
    assert reading.generation == 4


def test_setting_the_same_prerequisite_again_still_moves_the_generation(directory):
    store = _store(directory)
    store.set_prerequisite(RemotePrerequisite.REMOTE_USE, operator=OPERATOR)
    again = store.set_prerequisite(RemotePrerequisite.REMOTE_USE, operator=OPERATOR)
    assert again.generation == 2 and again.granted == ("remote use",)


def test_withdrawal_moves_the_generation_and_stops_permitting(directory):
    store = _store(directory)
    _grant_all(store)
    record, drained = store.withdraw("privacy_review", operator="uid:1002")
    assert drained is True
    assert record.generation == 5
    reading = store.reading()
    assert reading.status == "withdrawn" and not reading.permits
    assert reading.opt_in.withdrawn.operator == "uid:1002"
    assert reading.opt_in.withdrawn.reason == "privacy_review"
    # The prerequisites set before stay on record for an audit reader.
    assert reading.opt_in.complete


def test_a_regrant_starts_from_nothing_and_never_reuses_a_generation(directory):
    store = _store(directory)
    _grant_all(store)
    store.withdraw("operator_request", operator=OPERATOR)
    record = store.set_prerequisite(RemotePrerequisite.REMOTE_USE, operator=OPERATOR)
    assert record.generation == 6 and record.granted == ("remote use",)
    assert not store.reading().permits
    record = _grant_all(store)
    assert record.generation == 10 and store.reading().permits


def test_an_unknown_withdrawal_reason_or_prerequisite_is_refused(directory):
    store = _store(directory)
    with pytest.raises(ConsentRefused):
        store.withdraw("because", operator=OPERATOR)
    with pytest.raises(ConsentRefused):
        store.set_prerequisite("remote use", operator=OPERATOR)
    assert store.reading().status == "absent"


# -- restart --------------------------------------------------------------


def test_a_withdrawal_survives_a_restart(directory):
    _grant_all(_store(directory))
    _store(directory).withdraw("incident_response", operator=OPERATOR)
    restarted = _store(directory)
    reading = restarted.reading()
    assert reading.status == "withdrawn" and not reading.permits
    assert reading.generation == 5


def test_a_stale_partial_file_from_a_crash_is_never_read(directory):
    store = _store(directory)
    _grant_all(store)
    store.withdraw("operator_request", operator=OPERATOR)
    granted = encode_record(ConsentRecord(generation=99, granted=tuple(
        p.value for p in PREREQUISITES), operator=OPERATOR, at="2026-10-28T00:00:00Z"))
    partial = directory / mc.LEAF / ".opt-in.json.partial"
    partial.write_bytes(granted)
    partial.chmod(0o600)
    assert _store(directory).reading().status == "withdrawn"


def test_the_record_is_private_and_canonical(directory):
    store = _store(directory)
    record = _grant_all(store)
    path = _record_path(directory)
    assert path.stat().st_mode & 0o777 == 0o600
    assert (directory / mc.LEAF).stat().st_mode & 0o777 == 0o700
    assert decode_record(path.read_bytes()) == record


# -- fail-closed ----------------------------------------------------------


def _corrupt(directory, data: bytes):
    path = _record_path(directory)
    path.write_bytes(data)
    path.chmod(0o600)


@pytest.mark.parametrize("data", [
    b"", b"{", b"[]", b"x" * 5000,
    b'{"schema":"azazel-nexus/mio-remote-opt-in/v1"}',
])
def test_a_malformed_record_reads_as_no_opt_in(directory, data):
    store = _store(directory)
    _grant_all(store)
    _corrupt(directory, data)
    reading = _store(directory).reading()
    assert reading.opt_in is NO_OPT_IN and reading.generation is None
    assert not reading.permits


def test_a_non_canonical_record_reads_as_no_opt_in(directory):
    store = _store(directory)
    _grant_all(store)
    raw = _record_path(directory).read_bytes()
    _corrupt(directory, raw.replace(b",", b", ", 1))
    assert _store(directory).reading().generation is None


def test_a_record_with_an_unknown_field_or_generation_zero_is_refused():
    good = ConsentRecord(generation=1, granted=("remote use",), operator=OPERATOR,
                         at="2026-10-28T00:00:00Z")
    raw = encode_record(good)
    assert decode_record(raw) == good
    with pytest.raises(ConsentRefused):
        decode_record(raw.replace(b'"generation":1', b'"generation":0'))
    with pytest.raises(ConsentRefused):
        decode_record(raw.replace(b'"generation":1', b'"generation":true'))
    with pytest.raises(ConsentRefused):
        decode_record(raw[:-1] + b',"zz":1}')


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660])
def test_a_record_readable_or_writable_by_others_is_refused(directory, mode):
    store = _store(directory)
    _grant_all(store)
    _record_path(directory).chmod(mode)
    assert _store(directory).reading().generation is None


def test_a_record_owned_by_another_account_is_refused(directory):
    store = _store(directory)
    _grant_all(store)
    other = ConsentStore(directory, owner=os.geteuid() + 1)
    assert other.reading().generation is None


def test_a_linked_record_or_leaf_is_refused(directory, tmp_path):
    store = _store(directory)
    _grant_all(store)
    path = _record_path(directory)
    elsewhere = tmp_path / "elsewhere.json"
    os.replace(path, elsewhere)
    path.symlink_to(elsewhere)
    assert _store(directory).reading().generation is None

    other = tmp_path / "other"
    other.mkdir()
    other.chmod(0o700)
    (other / mc.LEAF).symlink_to(directory / mc.LEAF)
    assert _store(other).reading().generation is None


def test_a_group_writable_state_directory_is_refused(directory):
    _grant_all(_store(directory))
    directory.chmod(0o770)
    assert _store(directory).reading().generation is None


def test_a_rolled_back_record_is_refused_while_the_process_runs(directory):
    store = _store(directory)
    _grant_all(store)
    granted = _record_path(directory).read_bytes()
    store.withdraw("operator_request", operator=OPERATOR)
    assert store.reading().status == "withdrawn"
    # An older copy put back under the running daemon.
    _corrupt(directory, granted)
    reading = store.reading()
    assert reading.generation is None and not reading.permits
    # So is a deleted one.
    _record_path(directory).unlink()
    assert store.reading().generation is None


def test_a_grant_over_a_rolled_back_record_is_refused(directory):
    store = _store(directory)
    _grant_all(store)
    granted = _record_path(directory).read_bytes()
    store.withdraw("operator_request", operator=OPERATOR)
    _corrupt(directory, granted)
    with pytest.raises(ConsentRefused):
        store.set_prerequisite(RemotePrerequisite.REMOTE_USE, operator=OPERATOR)


def test_a_withdrawal_over_a_rolled_back_record_is_written_above_it(directory):
    store = _store(directory)
    _grant_all(store)
    granted = _record_path(directory).read_bytes()
    store.withdraw("operator_request", operator=OPERATOR)  # generation 5
    _corrupt(directory, granted)  # generation 4, granted
    record, _ = store.withdraw("incident_response", operator=OPERATOR)
    assert record.generation == 6
    assert store.reading().status == "withdrawn"


def test_no_write_over_a_record_that_cannot_be_read(directory):
    store = _store(directory)
    _grant_all(store)
    _corrupt(directory, b"{")
    with pytest.raises(ConsentRefused):
        store.withdraw("operator_request", operator=OPERATOR)
    with pytest.raises(ConsentRefused):
        store.set_prerequisite(RemotePrerequisite.REMOTE_USE, operator=OPERATOR)
    assert _record_path(directory).read_bytes() == b"{"


# -- the send gate --------------------------------------------------------


def test_the_gate_yields_the_reading_in_force(directory):
    store = _store(directory)
    with store.send_gate() as reading:
        assert reading.status == "absent"
    record = _grant_all(store)
    with store.send_gate() as reading:
        assert reading.permits and reading.generation == record.generation


def test_a_gate_held_exclusively_is_a_refusal_not_a_wait(directory):
    store = _store(directory)
    _grant_all(store)
    fd = os.open(directory / mc.LEAF / mc.GATE_FILENAME, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with store.send_gate() as reading:
            assert reading.generation is None and not reading.permits
    finally:
        os.close(fd)


def test_a_withdrawal_waits_for_a_sender_inside_the_gate(directory):
    store = _store(directory)
    _grant_all(store)
    entered, release = threading.Event(), threading.Event()
    returned = []

    def sender():
        with _store(directory).send_gate() as reading:
            assert reading.permits
            entered.set()
            release.wait(10)

    def withdraw():
        returned.append(_store(directory).withdraw("operator_request", operator=OPERATOR))

    send = threading.Thread(target=sender)
    send.start()
    assert entered.wait(5)
    take = threading.Thread(target=withdraw)
    take.start()
    take.join(0.3)
    # Committed (a fresh reader already sees it) but not confirmed.
    assert take.is_alive() and returned == []
    assert _store(directory).reading().status == "withdrawn"
    release.set()
    send.join(5)
    take.join(5)
    assert returned and returned[0][1] is True


def test_a_drain_that_expires_leaves_the_withdrawal_in_force(directory):
    store = _store(directory, drain_timeout_s=0.05)
    _grant_all(store)
    fd = os.open(directory / mc.LEAF / mc.GATE_FILENAME, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        record, drained = store.withdraw("operator_request", operator=OPERATOR)
    finally:
        os.close(fd)
    assert drained is False
    assert store.reading().status == "withdrawn"
    assert record.generation == 5


def test_the_store_does_not_reach_knowledge():
    """Consent to an online AI is not Knowledge peer authorisation."""
    import inspect

    source = inspect.getsource(mc)
    code = source.split('"""', 2)[2]
    assert "knowledge" not in code.lower()


# -- the generation ceiling ------------------------------------------------


def test_at_the_generation_ceiling_a_grant_is_refused_and_a_withdrawal_still_works(
        directory, monkeypatch):
    monkeypatch.setattr(mc, "_MAX_GENERATION", 4)
    store = _store(directory)
    record = _grant_all(store)
    assert record.generation == 4 and store.reading().permits
    with pytest.raises(ConsentRefused):
        store.set_prerequisite(RemotePrerequisite.REMOTE_USE, operator=OPERATOR)
    record, drained = store.withdraw("incident_response", operator=OPERATOR)
    assert drained is True and record.generation == 4
    reading = store.reading()
    assert reading.status == "withdrawn" and not reading.permits
    # Not a rollback for this process, nor for a restarted one.
    assert _store(directory).reading().status == "withdrawn"
    # A second withdrawal at the ceiling also stands; a grant stays refused.
    assert store.withdraw("operator_request", operator=OPERATOR)[0].generation == 4
    with pytest.raises(ConsentRefused):
        store.set_prerequisite(RemotePrerequisite.REMOTE_USE, operator=OPERATOR)
    assert store.reading().status == "withdrawn"
