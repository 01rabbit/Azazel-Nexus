"""Injected peer evidence tests for the real bootstrap audit exchange.

These tests exercise proof ordering and request suppression. Their injected
factory and mocked kernel observations are trusted test seams, not production
peer authentication evidence.
"""

from contextlib import contextmanager
import json
import struct

import pytest

from azazel_nexus.audit import AuditUnavailable
from azazel_nexus_runtime import bootstrap_audit_client as audit_client_module
from azazel_nexus_runtime import bootstrap_audit_peer as peer_module
from azazel_nexus_runtime.bootstrap_audit_client import BootstrapAuditClient
from azazel_nexus_runtime.bootstrap_audit_identity import AuditServiceIdentity
from azazel_nexus_runtime.bootstrap_audit_peer import AuditPeerBinding

from test_runtime_bootstrap_audit_client import (
    DeadlineSocket,
    FakeClock,
    HASH,
    _append_event,
)

HEADER = struct.Struct("!I")
UID = 210
PRIMARY_GID = 211
OPERATOR_GID = 212
PID = 3210
IDENTITY = AuditServiceIdentity(
    owner=":1.42",
    profile_digest="sha256:" + "34" * 32,
    pid=PID,
    invocation_id=b"i" * 16,
)


class FakePath:
    def __init__(self, *, replace_on_check=None):
        self.checks = 0
        self.replace_on_check = replace_on_check

    def check(self):
        self.checks += 1
        if self.checks == self.replace_on_check:
            raise peer_module.UnitOperationFailed("audit socket identity changed")


def _success_frame(operation):
    result = ({"verified": True, "head_sequence": 7, "head_hash": HASH}
              if operation == "observe" else {"sequence": 7, "event_hash": HASH})
    return HEADER.pack(len(raw := json.dumps(
        {"ok": True, "result": result}, separators=(",", ":")
    ).encode())) + raw


def _install_peer_evidence(monkeypatch, *, credentials=None, cgroup=None,
                           replace_path_on_check=None, accounts=None):
    path = FakePath(replace_on_check=replace_path_on_check)
    observed_accounts = accounts or (UID, PRIMARY_GID, OPERATOR_GID)
    monkeypatch.setattr(peer_module, "_account", lambda: observed_accounts)
    monkeypatch.setattr(peer_module, "_namespaces", lambda: ("pid", "cgroup"))
    monkeypatch.setattr(
        peer_module, "_read_proc",
        lambda _path, _limit: (b"0::/wrong\n" if cgroup is False
                               else b"0::/system.slice/azazel-auditd.service\n"),
    )
    monkeypatch.setattr(
        peer_module, "peer_credentials",
        lambda _connection: credentials or (PID, UID, PRIMARY_GID),
    )

    @contextmanager
    def open_path(_accounts):
        yield path

    monkeypatch.setattr(peer_module, "_open_audit_path", open_path)
    return path


@pytest.mark.parametrize("operation", ["observe", "append"])
def test_real_client_peer_proof_allows_observe_and_append(monkeypatch, operation):
    clock = FakeClock()
    monkeypatch.setattr(audit_client_module.time, "monotonic", clock.monotonic)
    _install_peer_evidence(monkeypatch)
    calls = []
    binding = AuditPeerBinding(IDENTITY, lambda: IDENTITY)
    connection = DeadlineSocket(clock, _success_frame(operation))
    client = BootstrapAuditClient(
        socket_factory=lambda: (calls.append("factory") or connection),
        binding_source=lambda: binding,
    )

    if operation == "observe":
        assert client.observe_head() == (7, HASH)
    else:
        receipt = client(_append_event())
        assert (receipt.sequence, receipt.event_hash) == (7, HASH)

    assert calls == ["factory"]
    assert [event[0] for event in connection.events].count("sendall") == 1
    assert connection.closed


@pytest.mark.parametrize("credentials", [
    (PID + 1, UID, PRIMARY_GID),
    (PID, UID + 1, PRIMARY_GID),
    (PID, UID, PRIMARY_GID + 1),
])
def test_wrong_pid_uid_or_primary_gid_sends_no_request(monkeypatch, credentials):
    clock = FakeClock()
    monkeypatch.setattr(audit_client_module.time, "monotonic", clock.monotonic)
    _install_peer_evidence(monkeypatch, credentials=credentials)
    connection = DeadlineSocket(clock)
    client = BootstrapAuditClient(
        socket_factory=lambda: connection,
        binding_source=lambda: AuditPeerBinding(IDENTITY, lambda: IDENTITY),
    )

    with pytest.raises(AuditUnavailable):
        client.observe_head()

    assert not any(event[0] in {"sendall", "shutdown"} for event in connection.events)
    assert connection.closed


def test_operator_socket_gid_is_not_accepted_as_primary_gid(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(audit_client_module.time, "monotonic", clock.monotonic)
    _install_peer_evidence(
        monkeypatch, credentials=(PID, UID, OPERATOR_GID),
    )
    connection = DeadlineSocket(clock)
    client = BootstrapAuditClient(
        socket_factory=lambda: connection,
        binding_source=lambda: AuditPeerBinding(IDENTITY, lambda: IDENTITY),
    )

    with pytest.raises(AuditUnavailable):
        client(_append_event())

    assert not any(event[0] == "sendall" for event in connection.events)


def test_fixed_cgroup_mismatch_sends_no_request(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(audit_client_module.time, "monotonic", clock.monotonic)
    _install_peer_evidence(monkeypatch, cgroup=False)
    connection = DeadlineSocket(clock)
    client = BootstrapAuditClient(
        socket_factory=lambda: connection,
        binding_source=lambda: AuditPeerBinding(IDENTITY, lambda: IDENTITY),
    )

    with pytest.raises(AuditUnavailable):
        client.observe_head()

    assert not any(event[0] == "sendall" for event in connection.events)


def test_path_guard_detected_replacement_sends_no_request(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(audit_client_module.time, "monotonic", clock.monotonic)
    path = _install_peer_evidence(monkeypatch, replace_path_on_check=1)
    connection = DeadlineSocket(clock)
    client = BootstrapAuditClient(
        socket_factory=lambda: connection,
        binding_source=lambda: AuditPeerBinding(IDENTITY, lambda: IDENTITY),
    )

    with pytest.raises(AuditUnavailable):
        client.observe_head()

    assert path.checks == 1
    assert not any(event[0] == "sendall" for event in connection.events)


def test_invocation_identity_drift_after_response_fails_exchange(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(audit_client_module.time, "monotonic", clock.monotonic)
    _install_peer_evidence(monkeypatch)
    changed = AuditServiceIdentity(
        owner=IDENTITY.owner,
        profile_digest=IDENTITY.profile_digest,
        pid=IDENTITY.pid,
        invocation_id=b"j" * 16,
    )
    validations = []

    def revalidate():
        validations.append(True)
        return IDENTITY if len(validations) < 3 else changed

    connection = DeadlineSocket(clock, _success_frame("observe"))
    client = BootstrapAuditClient(
        socket_factory=lambda: connection,
        binding_source=lambda: AuditPeerBinding(IDENTITY, revalidate),
    )

    with pytest.raises(AuditUnavailable):
        client.observe_head()

    assert len(validations) >= 3
    assert sum(event[0] == "sendall" for event in connection.events) == 1
    assert connection.closed


@pytest.mark.parametrize("operation", ["observe", "append"])
@pytest.mark.parametrize("when", ["before", "after"])
def test_expired_peer_authentication_budget_prevents_later_request_io(
    monkeypatch, operation, when,
):
    clock = FakeClock()
    monkeypatch.setattr(audit_client_module.time, "monotonic", clock.monotonic)
    _install_peer_evidence(monkeypatch)
    connection = DeadlineSocket(
        clock,
        _success_frame(operation) if when == "after" else b"",
    )
    validations = []

    def revalidate():
        validations.append(True)
        if when == "before" or len(validations) >= 3:
            clock.now += 1.1
        return IDENTITY

    client = BootstrapAuditClient(
        socket_factory=lambda: connection,
        binding_source=lambda: AuditPeerBinding(IDENTITY, revalidate),
        timeout_seconds=1.0,
    )
    with pytest.raises(AuditUnavailable):
        client.observe_head() if operation == "observe" else client(_append_event())

    if when == "before":
        assert not any(event[0] in {"sendall", "shutdown", "recv"}
                       for event in connection.events)
    else:
        assert sum(event[0] == "sendall" for event in connection.events) == 1
    if when == "after":
        assert connection.closed


def test_missing_production_binding_refuses_before_opening_socket(monkeypatch):
    calls = []
    monkeypatch.setattr(
        BootstrapAuditClient, "_connect",
        staticmethod(lambda *_args, **_kwargs: calls.append("opened")),
    )
    client = BootstrapAuditClient()

    with pytest.raises(AuditUnavailable):
        client.observe_head()

    assert calls == []


def test_injected_factory_without_binding_is_only_a_trusted_test_seam():
    """Client docs explicitly limit factory injection; this is not auth evidence."""
    clock = FakeClock()
    connection = DeadlineSocket(clock, _success_frame("observe"))
    client = BootstrapAuditClient(socket_factory=lambda: connection)

    assert client.observe_head() == (7, HASH)
    assert sum(event[0] == "sendall" for event in connection.events) == 1


@pytest.mark.parametrize("when", ["before-send", "after-response"])
@pytest.mark.parametrize("operation", ["observe", "append"])
def test_socket_replacement_during_identity_revalidation_is_detected(
    monkeypatch, when, operation,
):
    clock = FakeClock()
    monkeypatch.setattr(audit_client_module.time, "monotonic", clock.monotonic)
    path = _install_peer_evidence(monkeypatch)
    validations = []

    def revalidate():
        validations.append(True)
        if len(validations) == (2 if when == "before-send" else 3):
            path.replace_on_check = path.checks + 1
        return IDENTITY

    connection = DeadlineSocket(clock, _success_frame(operation))
    client = BootstrapAuditClient(
        socket_factory=lambda: connection,
        binding_source=lambda: AuditPeerBinding(IDENTITY, revalidate),
    )
    with pytest.raises(AuditUnavailable):
        client.observe_head() if operation == "observe" else client(_append_event())
    assert path.checks == path.replace_on_check
    assert sum(event[0] == "sendall" for event in connection.events) == (
        0 if when == "before-send" else 1
    )
    assert connection.closed
