"""Explicit clock recovery only completes an exact retained pending record."""

from hashlib import sha256
import os

import pytest

from azazel_nexus import bootstrap_clock_store as store
from azazel_nexus.operator_trust import ApprovalRefused

pytest_plugins = ("test_bootstrap_clock_publication",)

PENDING = b"administrator time publication pending\n"


def _stage_pending(root, raw, *, marker=PENDING, record=None):
    pending = root / "time.pending"
    pending.write_bytes(marker)
    pending.chmod(0o600)
    path = root / "time.json"
    if record is not None:
        path.write_bytes(record)
        path.chmod(0o600)
    else:
        path.write_bytes(raw)
        path.chmod(0o600)
    return pending, path


def test_public_recovery_completes_exact_pending_record_with_shared_readers(
    public_environment,
):
    context, anchor, raw, _policy, root = public_environment
    pending, path = _stage_pending(root, raw)

    store.recover_administrator_time(
        raw, expected=context, confirmed_sha256=sha256(raw).hexdigest(),
        confirmed_recovery=True,
    )

    assert not pending.exists()
    assert path.read_bytes() == raw
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert store._read_at(fd, owner=os.getuid()) == raw
    finally:
        os.close(fd)


@pytest.mark.parametrize("failure", ["expired", "wrong-boot", "false-confirmation"])
def test_public_recovery_refuses_current_state_or_confirmation_without_changes(
    public_environment, monkeypatch, failure,
):
    context, anchor, raw, _policy, root = public_environment
    pending, path = _stage_pending(root, raw)
    if failure == "expired":
        monkeypatch.setattr(store, "read_boottime_ns", lambda: anchor.expires_boottime_ns)
    elif failure == "wrong-boot":
        monkeypatch.setattr(
            store, "read_boot_id", lambda: "33333333-3333-4333-8333-333333333333",
        )

    with pytest.raises(ApprovalRefused):
        store.recover_administrator_time(
            raw, expected=context, confirmed_sha256=sha256(raw).hexdigest(),
            confirmed_recovery=False if failure == "false-confirmation" else True,
        )

    assert pending.read_bytes() == PENDING
    assert path.read_bytes() == raw


@pytest.mark.parametrize("case", [
    "unknown-marker", "truncated-marker", "truncated-record", "missing-record",
    "different-record", "wrong-digest", "false-confirmation", "truthy-confirmation",
])
def test_private_recovery_refuses_incomplete_or_unconfirmed_retained_bytes_unchanged(
    public_environment, case,
):
    _context, _anchor, raw, _policy, root = public_environment
    marker_value = PENDING
    record = raw
    digest = sha256(raw).hexdigest()
    confirmation = True
    if case == "unknown-marker":
        marker_value = b"review required\n"
    elif case == "truncated-marker":
        marker_value = PENDING[:-1]
    elif case == "truncated-record":
        record = raw[:-1]
    elif case == "missing-record":
        marker_value = PENDING
        record = None
    elif case == "different-record":
        record = raw[:-1] + b" "
    elif case == "wrong-digest":
        digest = "0" * 64
    elif case == "false-confirmation":
        confirmation = False
    else:
        confirmation = 1
    pending, path = _stage_pending(root, raw, marker=marker_value, record=record)
    if record is None:
        path.unlink()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises((ApprovalRefused, OSError)):
            store._recover_at(
                fd, raw, owner=os.getuid(), confirmed_sha256=digest,
                confirmed_recovery=confirmation, validate_current=lambda: None,
            )
    finally:
        os.close(fd)

    assert pending.read_bytes() == marker_value
    if record is None:
        assert not path.exists()
    else:
        assert path.read_bytes() == record


def test_second_validation_record_change_refuses_and_retains_pending(public_environment):
    _context, _anchor, raw, _policy, root = public_environment
    pending, path = _stage_pending(root, raw)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    validations = []

    def mutate_on_second_validation():
        validations.append(None)
        if len(validations) == 2:
            path.write_bytes(raw + b" ")
            path.chmod(0o600)

    try:
        with pytest.raises(ApprovalRefused):
            store._recover_at(
                fd, raw, owner=os.getuid(), confirmed_sha256=sha256(raw).hexdigest(),
                confirmed_recovery=True, validate_current=mutate_on_second_validation,
            )
    finally:
        os.close(fd)

    assert len(validations) == 2
    assert pending.read_bytes() == PENDING
    assert path.read_bytes() == raw + b" "


def test_final_recovery_fsync_failure_reports_uncertainty_after_marker_removal(
    public_environment, monkeypatch,
):
    _context, _anchor, raw, _policy, root = public_environment
    pending, path = _stage_pending(root, raw)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    original_fsync = store.os.fsync
    calls = []

    def fail_final_sync(descriptor):
        calls.append(descriptor)
        if len(calls) == 3:
            raise OSError("injected final recovery sync failure")
        return original_fsync(descriptor)

    monkeypatch.setattr(store.os, "fsync", fail_final_sync)
    try:
        with pytest.raises(store.TimeDurabilityUncertain):
            store._recover_at(
                fd, raw, owner=os.getuid(), confirmed_sha256=sha256(raw).hexdigest(),
                confirmed_recovery=True, validate_current=lambda: None,
            )
    finally:
        os.close(fd)

    assert len(calls) == 3
    assert not pending.exists()
    assert path.read_bytes() == raw


@pytest.mark.parametrize("failed_call", [1, 2])
def test_prepublication_recovery_fsync_failure_keeps_reader_blocked(
    public_environment, monkeypatch, failed_call,
):
    context, _anchor, raw, _policy, root = public_environment
    pending, path = _stage_pending(root, raw)
    original = store.os.fsync
    calls = []

    def fail_sync(fd):
        calls.append(fd)
        if len(calls) == failed_call:
            raise OSError("injected prepublication sync failure")
        original(fd)

    monkeypatch.setattr(store.os, "fsync", fail_sync)
    with pytest.raises(ApprovalRefused) as caught:
        store.recover_administrator_time(
            raw, expected=context, confirmed_sha256=sha256(raw).hexdigest(),
            confirmed_recovery=True,
        )
    assert not isinstance(caught.value, store.TimeDurabilityUncertain)
    assert pending.read_bytes() == PENDING
    assert path.read_bytes() == raw
    with pytest.raises(ApprovalRefused):
        store.load_administrator_time_window(expected=context)
