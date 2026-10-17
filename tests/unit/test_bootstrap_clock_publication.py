"""Administrator clock publication transaction tests use ordinary temporary files."""

from contextlib import contextmanager
from hashlib import sha256
import fcntl
import os
import stat
from types import SimpleNamespace

import pytest

from azazel_nexus import activation_store
from azazel_nexus import bootstrap_clock_store as store
from azazel_nexus.bootstrap_clock import (
    AdministratorClockLimits,
    AdministratorTimeAnchor,
    encode_administrator_anchor,
)
from azazel_nexus.operator_trust import ApprovalRefused
from test_bootstrap_generation import _context

NS = 1_000_000_000
START = 5 * NS


def make_anchor(context):
    return AdministratorTimeAnchor(
        context.node_digest, context.policy_digest, context.boot_id,
        "2026-10-13T12:00:00Z", "2026-10-13T12:00:10Z",
        START, 20 * NS,
    )


@pytest.fixture
def ordinary_store(tmp_path):
    root = tmp_path / "bootstrap"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield root, fd, os.getuid()
    finally:
        os.close(fd)


@pytest.fixture
def public_environment(tmp_path, monkeypatch):
    root = tmp_path / "administrator-bootstrap"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    context = _context()
    anchor = make_anchor(context)
    raw = encode_administrator_anchor(anchor)
    limits = AdministratorClockLimits(20 * NS, 20 * NS, 0)
    policy = SimpleNamespace(clock_limits=lambda: limits)

    @contextmanager
    def directory():
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            yield fd
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def load_policy(*, expected):
        assert expected == context
        # Model the protected pre-start policy reader taking a shared lock
        # while inspecting the same ordinary temporary directory.
        with directory():
            return policy

    def private_directory(fd, *, owner):
        info = os.fstat(fd)
        assert stat.S_ISDIR(info.st_mode)
        assert info.st_uid == os.getuid()
        assert info.st_mode & 0o077 == 0
        assert type(owner) is int

    def read_file(fd, name, *, owner, limit):
        return activation_store._read_file_at(fd, name, owner=os.getuid(), limit=limit)

    monkeypatch.setattr(store, "_bootstrap_directory", directory)
    monkeypatch.setattr(store, "_private_directory", private_directory)
    monkeypatch.setattr(store, "_read_file_at", read_file)
    monkeypatch.setattr(store, "load_bootstrap_prestart_policy", load_policy)
    monkeypatch.setattr(store, "read_boot_id", lambda: context.boot_id)
    monkeypatch.setattr(store, "read_boottime_ns", lambda: START + NS)
    return context, anchor, raw, policy, root


def test_initialize_at_publishes_after_exact_digest_and_true_confirmation(
    ordinary_store,
):
    root, fd, owner = ordinary_store
    context = _context()
    raw = encode_administrator_anchor(make_anchor(context))
    validations = []

    store._initialize_at(
        fd, raw, owner=owner, confirmed_sha256=sha256(raw).hexdigest(),
        confirmed_initialize=True, validate_current=lambda: validations.append(True),
    )

    assert (root / "time.json").read_bytes() == raw
    assert (root / "time.json").stat().st_mode & 0o777 == 0o600
    assert not (root / "time.pending").exists()
    assert store._read_at(fd, owner=owner) == raw
    assert validations == [True, True]


@pytest.mark.parametrize(("digest", "confirmation"), [
    ("0" * 64, True),
    (None, 1),
    (None, "yes"),
    (None, False),
])
def test_initialize_at_requires_separate_exact_digest_and_true_confirmation(
    ordinary_store, digest, confirmation,
):
    root, fd, owner = ordinary_store
    raw = encode_administrator_anchor(make_anchor(_context()))
    validations = []

    with pytest.raises(ApprovalRefused):
        store._initialize_at(
            fd, raw, owner=owner, confirmed_sha256=digest or sha256(raw).hexdigest(),
            confirmed_initialize=confirmation, validate_current=lambda: validations.append(True),
        )

    assert list(root.iterdir()) == []
    assert validations == []


@pytest.mark.parametrize("existing", ["time.json", "time.pending"])
def test_initialize_at_refuses_existing_or_pending_state_without_overwrite(
    ordinary_store, existing,
):
    root, fd, owner = ordinary_store
    path = root / existing
    path.write_bytes(b"preserve existing state")
    path.chmod(0o600)
    raw = encode_administrator_anchor(make_anchor(_context()))

    with pytest.raises(ApprovalRefused):
        store._initialize_at(
            fd, raw, owner=owner, confirmed_sha256=sha256(raw).hexdigest(),
            confirmed_initialize=True, validate_current=lambda: None,
        )

    assert path.read_bytes() == b"preserve existing state"
    assert list(root.iterdir()) == [path]


def test_interrupted_validation_retains_pending_reader_refuses_and_retry_refuses(
    ordinary_store,
):
    root, fd, owner = ordinary_store
    raw = encode_administrator_anchor(make_anchor(_context()))
    validations = []

    def fail_after_publication():
        validations.append(None)
        if len(validations) == 2:
            raise ApprovalRefused("injected current-state change")

    with pytest.raises(ApprovalRefused, match="injected"):
        store._initialize_at(
            fd, raw, owner=owner, confirmed_sha256=sha256(raw).hexdigest(),
            confirmed_initialize=True, validate_current=fail_after_publication,
        )

    assert (root / "time.pending").read_bytes() == b"administrator time publication pending\n"
    assert (root / "time.json").read_bytes() == raw
    with pytest.raises(ApprovalRefused):
        store._read_at(fd, owner=owner)
    with pytest.raises(ApprovalRefused):
        store._initialize_at(
            fd, raw, owner=owner, confirmed_sha256=sha256(raw).hexdigest(),
            confirmed_initialize=True, validate_current=lambda: None,
        )


def test_public_initializer_publishes_and_reader_loads_same_anchor(public_environment):
    context, anchor, raw, _policy, root = public_environment

    store.initialize_administrator_time(
        raw, expected=context, confirmed_sha256=sha256(raw).hexdigest(),
        confirmed_initialize=True,
    )

    assert (root / "time.json").read_bytes() == raw
    assert not (root / "time.pending").exists()
    loaded = store.decode_administrator_anchor((root / "time.json").read_bytes())
    assert loaded == anchor
    window = store.load_administrator_time_window(expected=context)
    assert window.boot_id == context.boot_id
    assert window.observed_boottime_ns == START + NS


@pytest.mark.parametrize("failure", ["expired", "wrong-boot"])
def test_public_initializer_refuses_expired_or_wrong_boot_anchor_without_writes(
    public_environment, monkeypatch, failure,
):
    context, anchor, raw, _policy, root = public_environment
    if failure == "expired":
        monkeypatch.setattr(store, "read_boottime_ns", lambda: anchor.expires_boottime_ns)
    else:
        monkeypatch.setattr(
            store, "read_boot_id", lambda: "33333333-3333-4333-8333-333333333333",
        )

    with pytest.raises(ApprovalRefused):
        store.initialize_administrator_time(
            raw, expected=context, confirmed_sha256=sha256(raw).hexdigest(),
            confirmed_initialize=True,
        )
    assert list(root.iterdir()) == []


def test_second_validation_record_mutation_refuses_and_retains_pending(
    public_environment, monkeypatch,
):
    context, _anchor, raw, _policy, root = public_environment
    ticks = []

    def mutate_during_second_validation():
        ticks.append(None)
        if len(ticks) == 2:
            path = root / "time.json"
            path.write_bytes(raw + b" ")
            path.chmod(0o600)
        return START + NS

    monkeypatch.setattr(store, "read_boottime_ns", mutate_during_second_validation)

    with pytest.raises(ApprovalRefused):
        store.initialize_administrator_time(
            raw, expected=context, confirmed_sha256=sha256(raw).hexdigest(),
            confirmed_initialize=True,
        )

    assert (root / "time.pending").read_bytes() == b"administrator time publication pending\n"
    assert (root / "time.json").read_bytes() == raw + b" "
    assert len(ticks) == 2


def test_public_initializer_refuses_boottime_regression_and_retains_pending(
    public_environment, monkeypatch,
):
    context, _anchor, raw, _policy, root = public_environment
    ticks = iter((START + 2 * NS, START + NS))
    monkeypatch.setattr(store, "read_boottime_ns", lambda: next(ticks))

    with pytest.raises(ApprovalRefused):
        store.initialize_administrator_time(
            raw, expected=context, confirmed_sha256=sha256(raw).hexdigest(),
            confirmed_initialize=True,
        )

    assert (root / "time.pending").read_bytes() == b"administrator time publication pending\n"
    assert (root / "time.json").read_bytes() == raw


def test_final_directory_fsync_failure_reports_uncertain_durability(ordinary_store, monkeypatch):
    root, fd, owner = ordinary_store
    raw = encode_administrator_anchor(make_anchor(_context()))
    original_fsync = store.os.fsync
    calls = []

    def fail_final_sync(descriptor):
        calls.append(descriptor)
        if len(calls) == 5:
            raise OSError("injected final directory sync failure")
        return original_fsync(descriptor)

    monkeypatch.setattr(store.os, "fsync", fail_final_sync)

    with pytest.raises(store.TimeDurabilityUncertain):
        store._initialize_at(
            fd, raw, owner=owner, confirmed_sha256=sha256(raw).hexdigest(),
            confirmed_initialize=True, validate_current=lambda: None,
        )

    assert len(calls) == 5
    assert (root / "time.json").read_bytes() == raw
    assert not (root / "time.pending").exists()
