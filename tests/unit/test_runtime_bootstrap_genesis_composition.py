"""Genesis prestart composition, live head, client and receipt boundaries."""

from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import os
import socket
import threading

import pytest

from azazel_nexus import bootstrap_prestart_store as store
from azazel_nexus.audit import GENESIS_HASH, AuditUnavailable
from azazel_nexus.bootstrap_prestart_policy import (
    BootstrapPrestartPolicy, FirstInstallGenesis, encode_prestart_policy,
)
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_audit, bootstrap_prestart
from azazel_nexus_runtime.bootstrap_audit import AuditObservation
from azazel_nexus_runtime.bootstrap_audit_client import AuditAppendReceipt, BootstrapAuditClient
from azazel_nexus_runtime.bootstrap_audit_live import BootstrapLiveAuditHead, WriterHead
from azazel_nexus_runtime.transport import send_frame
from test_bootstrap_generation import _context
from test_runtime_bootstrap_audit import OWNER, DAY1, _chain
from test_runtime_bootstrap_audit_client import _read_request
from test_runtime_bootstrap_prestart_audit import ReadOnlyManager

GENESIS = AuditObservation(0, GENESIS_HASH, 0, 0)
HASH = "b" * 64


def _policy(context, *, genesis=True, **changes):
    values = dict(
        package_digest=context.package_digest, unit_closure_digest=context.unit_closure_digest,
        systemd_profile_digest="sha256:" + "a" * 64, min_usable_memory_mib=1024,
        min_online_logical_cpus=2, min_mission_available_mib=512, bootstrap_bytes=100,
        bootstrap_inodes=10, audit_bytes=200, audit_inodes=20,
        audit_sequence=0 if genesis else 1, audit_head=GENESIS_HASH if genesis else "a" * 64,
        max_audit_bytes=10000, max_audit_segments=10, max_anchor_lifetime_ns=60_000_000_000,
        max_uncertainty_ns=2_000_000_000, drift_ppb=1000, loaded_policy_digest="sha256:" + "b" * 64,
        first_install_genesis=FirstInstallGenesis(
            context.node_digest, "33333333-3333-4333-8333-333333333333") if genesis else None,
    )
    values.update(changes)
    return BootstrapPrestartPolicy(**values)


def _install(tmp_path, monkeypatch, *, genesis=True):
    context = _context()
    raw = encode_prestart_policy(_policy(context, genesis=genesis))
    context = replace(context, policy_digest="sha256:" + sha256(raw).hexdigest())
    tmp_path.chmod(0o700)
    path = tmp_path / "admission.json"
    path.write_bytes(raw)
    path.chmod(0o600)

    @contextmanager
    def directory():
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(store, "_bootstrap_directory", directory)
    reader = store._read_at
    monkeypatch.setattr(store, "_read_at", lambda fd, *, owner: reader(fd, owner=os.getuid()))
    return context


def _ledger(monkeypatch, directory):
    monkeypatch.setattr(bootstrap_audit.pwd, "getpwnam",
                        lambda _n: type("A", (), {"pw_uid": OWNER})())
    monkeypatch.setattr(bootstrap_audit, "_open_ledger",
                        lambda owner: os.open(directory, os.O_RDONLY | os.O_DIRECTORY))


@pytest.fixture
def genesis_ctx(tmp_path_factory, monkeypatch):
    return _install(tmp_path_factory.mktemp("adm"), monkeypatch)


def test_genesis_policy_with_empty_dir_returns_genesis_and_checks_helpers(
    genesis_ctx, tmp_path, monkeypatch,
):
    root = tmp_path / "audit"
    root.mkdir()
    root.chmod(0o700)
    _ledger(monkeypatch, root)
    manager = ReadOnlyManager()
    assert bootstrap_prestart.check_bootstrap_existing_audit(
        expected=genesis_ctx, manager=manager) == GENESIS
    assert len(manager.reads) == 8


def test_genesis_policy_with_history_refused(genesis_ctx, tmp_path, monkeypatch):
    ledger = _chain(tmp_path / "audit", days=(DAY1,))
    _ledger(monkeypatch, ledger.root)
    with pytest.raises(ApprovalRefused):
        bootstrap_prestart.check_bootstrap_existing_audit(
            expected=genesis_ctx, manager=ReadOnlyManager())


def test_existing_history_policy_with_empty_dir_refused(tmp_path, monkeypatch):
    (tmp_path / "adm").mkdir()
    context = _install(tmp_path / "adm", monkeypatch, genesis=False)
    root = tmp_path / "audit"
    root.mkdir()
    root.chmod(0o700)
    _ledger(monkeypatch, root)
    with pytest.raises(ApprovalRefused):
        bootstrap_prestart.check_bootstrap_existing_audit(
            expected=context, manager=ReadOnlyManager())


def test_genesis_does_not_use_existing_reader(genesis_ctx, monkeypatch):
    monkeypatch.setattr(bootstrap_prestart, "inspect_existing_audit",
                        lambda **_k: pytest.fail("existing reader used"))
    monkeypatch.setattr(bootstrap_prestart, "inspect_first_install_audit",
                        lambda **k: GENESIS if k == {"max_total_bytes": 10000, "max_segments": 10}
                        else pytest.fail("unexpected arguments"))
    assert bootstrap_prestart.check_bootstrap_existing_audit(
        expected=genesis_ctx, manager=ReadOnlyManager()) == GENESIS


@pytest.mark.parametrize("observed", [
    AuditObservation(1, "a" * 64, 1, 10),
    None,
])
def test_genesis_observation_must_be_exact_genesis(genesis_ctx, monkeypatch, observed):
    monkeypatch.setattr(bootstrap_prestart, "inspect_first_install_audit", lambda **_k: observed)
    with pytest.raises(ApprovalRefused):
        bootstrap_prestart.check_bootstrap_existing_audit(
            expected=genesis_ctx, manager=ReadOnlyManager())


@pytest.mark.parametrize("check", ["masked", "inactive"])
def test_helpers_not_stopped_refused_before_inspection(genesis_ctx, monkeypatch, check):
    monkeypatch.setattr(bootstrap_prestart, "inspect_first_install_audit",
                        lambda **_k: pytest.fail("must not inspect"))
    with pytest.raises(ApprovalRefused):
        bootstrap_prestart.check_bootstrap_existing_audit(
            expected=genesis_ctx, manager=ReadOnlyManager(**{check: [False] * 4}))


def test_policy_change_during_observation_refused(genesis_ctx, monkeypatch):
    original = bootstrap_prestart.load_bootstrap_prestart_policy
    calls = []

    def changing(*, expected):
        policy = original(expected=expected)
        calls.append(None)
        return policy if len(calls) == 1 else replace(policy, max_audit_bytes=policy.max_audit_bytes + 1)

    monkeypatch.setattr(bootstrap_prestart, "load_bootstrap_prestart_policy", changing)
    monkeypatch.setattr(bootstrap_prestart, "inspect_first_install_audit", lambda **_k: GENESIS)
    with pytest.raises(ApprovalRefused):
        bootstrap_prestart.check_bootstrap_existing_audit(
            expected=genesis_ctx, manager=ReadOnlyManager())


def test_extension_from_genesis_with_genesis_policy_succeeds(genesis_ctx, tmp_path, monkeypatch):
    root = tmp_path / "audit"
    root.mkdir()
    root.chmod(0o700)
    _ledger(monkeypatch, root)
    assert bootstrap_prestart.check_bootstrap_audit_extension(
        expected=genesis_ctx, previous=GENESIS) == GENESIS


def test_extension_to_first_record_succeeds(genesis_ctx, tmp_path, monkeypatch):
    ledger = _chain(tmp_path / "audit", days=(DAY1,))
    _ledger(monkeypatch, ledger.root)
    result = bootstrap_prestart.check_bootstrap_audit_extension(
        expected=genesis_ctx, previous=GENESIS)
    assert (result.sequence, result.digest) == ledger.head()


def test_extension_genesis_previous_refused_for_existing_history_policy(tmp_path, monkeypatch):
    (tmp_path / "adm").mkdir()
    context = _install(tmp_path / "adm", monkeypatch, genesis=False)
    with pytest.raises(ApprovalRefused):
        bootstrap_prestart.check_bootstrap_audit_extension(expected=context, previous=GENESIS)


def test_forged_previous_cannot_be_constructed():
    with pytest.raises(ValueError):
        AuditObservation(0, "a" * 64, 0, 0)


# Live head.

def test_writer_head_accepts_exact_genesis_only():
    assert WriterHead(0, GENESIS_HASH).sequence == 0
    for bad in ((0, "a" * 64), (1, GENESIS_HASH), (-1, GENESIS_HASH), (False, GENESIS_HASH)):
        with pytest.raises(ValueError):
            WriterHead(*bad)


class _Reader:
    def __init__(self, *values):
        self.values = iter(values)

    def observe_head(self):
        return next(self.values)


def test_startup_genesis_then_advance_to_first_record():
    adapter = BootstrapLiveAuditHead(GENESIS, _Reader(
        (0, GENESIS_HASH), (0, GENESIS_HASH), (1, HASH)))
    assert adapter.verify_startup() == WriterHead(0, GENESIS_HASH)
    assert adapter.observe() == WriterHead(0, GENESIS_HASH)
    assert adapter.observe() == WriterHead(1, HASH)


def test_regression_to_genesis_refused():
    adapter = BootstrapLiveAuditHead(AuditObservation(1, HASH, 1, 10), _Reader(
        (1, HASH), (0, GENESIS_HASH)))
    adapter.verify_startup()
    with pytest.raises(ApprovalRefused):
        adapter.observe()


def test_nonzero_live_head_against_genesis_stopped_refused_at_startup():
    adapter = BootstrapLiveAuditHead(GENESIS, _Reader((1, HASH)))
    with pytest.raises(ApprovalRefused, match="startup head differs"):
        adapter.verify_startup()


def test_genesis_live_head_against_positive_stopped_refused_at_startup():
    adapter = BootstrapLiveAuditHead(AuditObservation(1, HASH, 1, 10), _Reader((0, GENESIS_HASH)))
    with pytest.raises(ApprovalRefused, match="startup head differs"):
        adapter.verify_startup()


# Client.

def _observe_with(result):
    client_socket, server_socket = socket.socketpair()

    def serve():
        try:
            _read_request(server_socket)
            send_frame(server_socket, {"ok": True, "result": result})
        finally:
            server_socket.close()

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        return BootstrapAuditClient(socket_factory=lambda: client_socket).observe_head()
    finally:
        thread.join(timeout=1)


def test_client_observes_exact_genesis():
    assert _observe_with({"verified": True, "head_sequence": 0, "head_hash": GENESIS_HASH}) == (
        0, GENESIS_HASH)


@pytest.mark.parametrize("sequence,digest", [
    (0, HASH), (1, GENESIS_HASH), (-1, GENESIS_HASH), (False, GENESIS_HASH),
])
def test_client_refuses_other_sequence_zero_pairs(sequence, digest):
    with pytest.raises(AuditUnavailable):
        _observe_with({"verified": True, "head_sequence": sequence, "head_hash": digest})


def test_append_receipt_stays_positive():
    with pytest.raises(ValueError):
        AuditAppendReceipt(0, GENESIS_HASH)
    assert AuditAppendReceipt(1, HASH).sequence == 1
