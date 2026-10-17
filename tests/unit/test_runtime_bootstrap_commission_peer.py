"""Synthetic peer proof tests for the fixed commission socket binding."""

from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
import time

import pytest

from azazel_nexus_runtime import bootstrap_commission_peer as peer_module
from azazel_nexus_runtime.bootstrap_audit_identity import AuditServiceIdentity
from azazel_nexus_runtime.bootstrap_audit_peer import AuditPeerBinding
from azazel_nexus_runtime.bootstrap_commission_identity import CommissionServiceIdentity
from azazel_nexus_runtime.bootstrap_commission_peer import (
    CommissionPeerBinding, _CommissionSocketPath,
)
from azazel_nexus_runtime.units import UnitOperationFailed

IDENTITY = CommissionServiceIdentity(
    owner=":1.42", profile_digest="sha256:" + "34" * 32,
    pid=4321, invocation_id=b"i" * 16,
)
AUDIT_IDENTITY = AuditServiceIdentity(
    owner=IDENTITY.owner, profile_digest=IDENTITY.profile_digest,
    pid=IDENTITY.pid, invocation_id=IDENTITY.invocation_id,
)
ACCOUNTS = (220, 221, 222)


class FakePath:
    def __init__(self):
        self.checks = 0

    def check(self):
        self.checks += 1


def _install_peer_evidence(monkeypatch, *, credentials=None, cgroup=True,
                           namespaces=("pid", "cgroup")):
    path = FakePath()
    monkeypatch.setattr(peer_module, "_account", lambda: ACCOUNTS)
    monkeypatch.setattr(peer_module, "_namespaces", lambda: namespaces)
    monkeypatch.setattr(
        peer_module, "_read_proc",
        lambda _path, _limit: (
            b"0::/system.slice/azazel-commissiond.service\n" if cgroup
            else b"0::/system.slice/azazel-auditd.service\n"
        ),
    )
    monkeypatch.setattr(peer_module, "peer_credentials",
                        lambda _connection: credentials or (IDENTITY.pid, ACCOUNTS[0], ACCOUNTS[1]))

    @contextmanager
    def open_path(_accounts):
        yield path

    monkeypatch.setattr(peer_module, "_open_commission_path", open_path)
    return path


def test_binding_proof_checks_commission_peer_and_fixed_socket_path(monkeypatch):
    path = _install_peer_evidence(monkeypatch)
    binding = CommissionPeerBinding(IDENTITY, lambda: IDENTITY)
    with binding.proof(time.monotonic() + 5) as proof:
        assert proof.path == "/var/lib/azazel/run/commission/commission.sock"
        proof.check(object())
    assert path.checks == 2


@pytest.mark.parametrize("credentials", [
    (IDENTITY.pid + 1, ACCOUNTS[0], ACCOUNTS[1]),
    (IDENTITY.pid, ACCOUNTS[0] + 1, ACCOUNTS[1]),
    (IDENTITY.pid, ACCOUNTS[0], ACCOUNTS[1] + 1),
])
def test_wrong_peer_credentials_are_refused_before_request_evidence(monkeypatch, credentials):
    _install_peer_evidence(monkeypatch, credentials=credentials)
    binding = CommissionPeerBinding(IDENTITY, lambda: IDENTITY)
    with binding.proof(time.monotonic() + 5) as proof:
        with pytest.raises(UnitOperationFailed, match="peer identity"):
            proof.check(object())


def test_wrong_service_cgroup_and_namespace_drift_are_refused(monkeypatch):
    _install_peer_evidence(monkeypatch, cgroup=False)
    binding = CommissionPeerBinding(IDENTITY, lambda: IDENTITY)
    with binding.proof(time.monotonic() + 5) as proof:
        with pytest.raises(UnitOperationFailed, match="cgroup"):
            proof.check(object())

    _install_peer_evidence(monkeypatch)
    changing = iter([("pid", "cgroup"), ("pid", "mount")])
    monkeypatch.setattr(peer_module, "_namespaces", lambda: next(changing))
    with CommissionPeerBinding(IDENTITY, lambda: IDENTITY).proof(
            time.monotonic() + 5) as proof:
        with pytest.raises(UnitOperationFailed, match="binding changed"):
            proof.check(object())


def test_pre_and_post_revalidation_require_exact_commission_identity(monkeypatch):
    _install_peer_evidence(monkeypatch)
    other = CommissionServiceIdentity(
        IDENTITY.owner, IDENTITY.profile_digest, IDENTITY.pid + 1,
        IDENTITY.invocation_id,
    )
    with pytest.raises(UnitOperationFailed, match="identity changed"):
        with CommissionPeerBinding(IDENTITY, lambda: other).proof(time.monotonic() + 5):
            pass

    validations = iter([IDENTITY, other])
    with CommissionPeerBinding(IDENTITY, lambda: next(validations)).proof(
            time.monotonic() + 5) as proof:
        with pytest.raises(UnitOperationFailed, match="identity changed"):
            proof.check(object())


def test_audit_identity_and_binding_cannot_be_used_as_commission_binding():
    with pytest.raises(ValueError, match="commission identity"):
        CommissionPeerBinding(AUDIT_IDENTITY, lambda: AUDIT_IDENTITY)
    with pytest.raises(ValueError, match="audit identity"):
        AuditPeerBinding(IDENTITY, lambda: IDENTITY)


def test_path_guard_rejects_regular_file_leaf_without_opening_socket():
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        (directory / "commission.sock").write_bytes(b"synthetic regular file")
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            expected = peer_module._directory_stamp(os.fstat(fd))
            with pytest.raises(UnitOperationFailed, match="socket declaration"):
                _CommissionSocketPath([(fd, ".", fd, expected)], ACCOUNTS)
        finally:
            os.close(fd)
