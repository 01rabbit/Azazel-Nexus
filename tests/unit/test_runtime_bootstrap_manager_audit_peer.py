"""Manager identity capture and real client wiring, using synthetic peers."""

import pytest

from azazel_nexus.audit import AuditUnavailable
from azazel_nexus_runtime.bootstrap import BootstrapSupervisor
from azazel_nexus_runtime.bootstrap_audit_client import BootstrapAuditClient
from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.units import UnitOperationFailed
from test_runtime_bootstrap_audit_client import DeadlineSocket, FakeClock, HASH, _append_event
from test_runtime_bootstrap_audit_identity import FakeBus, OWNER, PROFILE_DIGEST, PID
from test_runtime_bootstrap_audit_peer import (
    UID, PRIMARY_GID, _install_peer_evidence, _success_frame,
)
from test_runtime_bootstrap_manager import FakeSystemdBusSession


def _manager(*, changed_pid=False):
    sessions = []

    def factory():
        bus = FakeBus(pids=[PID + 1, PID + 1] if changed_pid and sessions else None)
        bus.disconnected = False
        bus.disconnect = lambda: setattr(bus, "disconnected", True)
        session = FakeSystemdBusSession(bus=bus)
        sessions.append(session)
        return session

    return BootstrapNarrowingManager(job_timeout_seconds=0.2, session_factory=factory), sessions


def _capture(manager, check=lambda: None):
    manager._capture_audit_peer_binding(
        expected_owner=OWNER, systemd_profile_digest=PROFILE_DIGEST, check_start=check,
    )


def test_client_created_before_capture_refuses_without_opening_a_session():
    manager, sessions = _manager()
    client = manager._bootstrap_audit_client()
    with pytest.raises(AuditUnavailable):
        client.observe_head()
    assert sessions == []


@pytest.mark.parametrize("operation", ["observe", "append"])
def test_retained_manager_binding_authenticates_real_client_exchange(monkeypatch, operation):
    manager, sessions = _manager()
    _capture(manager)
    client = manager._bootstrap_audit_client()
    _install_peer_evidence(monkeypatch, credentials=(PID, UID, PRIMARY_GID))
    connection = DeadlineSocket(FakeClock(), _success_frame(operation))
    paths = []

    def connect(_deadline, *, path):
        paths.append(path)
        return connection

    monkeypatch.setattr(BootstrapAuditClient, "_connect", staticmethod(connect))
    if operation == "observe":
        assert client.observe_head() == (7, HASH)
    else:
        assert client(_append_event()).event_hash == HASH
    assert paths == ["/var/lib/azazel/run/audit/audit.sock"]
    assert len(sessions) == 4  # capture + begin/pre-send/final identity checks
    assert all(s.closed and s._bus.disconnected and s._loop.is_closed() for s in sessions)
    assert connection.closed


def test_revalidation_does_not_adopt_replacement_audit_pid(monkeypatch):
    manager, sessions = _manager(changed_pid=True)
    _capture(manager)
    binding = manager._audit_binding_source()
    opened = []
    monkeypatch.setattr(BootstrapAuditClient, "_connect", staticmethod(
        lambda *_args, **_kwargs: opened.append(True)
    ))
    with pytest.raises(AuditUnavailable):
        manager._bootstrap_audit_client().observe_head()
    assert manager._audit_binding_source() is binding
    assert binding.identity.pid == PID
    assert opened == [] and len(sessions) == 2
    assert all(s.closed for s in sessions)


@pytest.mark.parametrize("when", [1, 2])
def test_failed_capture_checkpoint_never_publishes_binding(when):
    manager, sessions = _manager()
    calls = []

    def check():
        calls.append(True)
        return False if len(calls) == when else None

    with pytest.raises(UnitOperationFailed):
        _capture(manager, check)
    with pytest.raises(UnitOperationFailed):
        manager._audit_binding_source()
    assert len(sessions) == when - 1
    assert all(s.closed for s in sessions)


def test_supervisor_default_head_reader_is_its_same_audit_client():
    manager, sessions = _manager()
    client = manager._bootstrap_audit_client()

    class FakeDeadlineGuard:
        def __call__(self, _deadline):
            return None

        def release_after_stop(self):
            return None

    supervisor = BootstrapSupervisor(
        manager=manager, refresh=lambda: None, admit_generation=lambda _: None,
        deadline_guard=FakeDeadlineGuard(),
        record=client, controller_ready=lambda: None, emergency_narrow=lambda: None,
        stopped=lambda: True, wait=lambda _: None, poll_seconds=0.2,
    )
    assert supervisor.record is client and supervisor.audit_head_reader is client
    assert sessions == []


def test_closure_invalidates_existing_client_even_if_fencing_fails(monkeypatch):
    manager, sessions = _manager()
    _capture(manager)
    client = manager._bootstrap_audit_client()
    opened = []
    monkeypatch.setattr(BootstrapAuditClient, "_connect", staticmethod(
        lambda *_args, **_kwargs: opened.append(True)
    ))
    # No owned fence was supplied; close must invalidate before refusing it.
    with pytest.raises(UnitOperationFailed):
        manager.close_starts()
    captured_sessions = len(sessions)
    with pytest.raises(AuditUnavailable):
        client.observe_head()
    assert opened == [] and len(sessions) == captured_sessions
    with pytest.raises(UnitOperationFailed, match="binding unavailable"):
        manager._audit_binding_source()


def test_closure_invalidates_commission_client_before_fencing(monkeypatch):
    from azazel_nexus_runtime.bootstrap_commission_client import BootstrapCommissionClient
    from azazel_nexus_runtime.bootstrap_commission_peer import CommissionPeerBinding
    from test_runtime_bootstrap_commission_peer import IDENTITY

    manager, sessions = _manager()
    manager._commission_peer_binding = CommissionPeerBinding(IDENTITY, lambda: IDENTITY)
    client = manager._authenticated_commission_client
    opened = []
    monkeypatch.setattr(BootstrapCommissionClient, "_connect", staticmethod(
        lambda *_args, **_kwargs: opened.append(True)
    ))
    with pytest.raises(UnitOperationFailed):
        manager.close_starts()
    with pytest.raises(UnitOperationFailed, match="inventory unavailable"):
        client.observe_inventory()
    assert opened == [] and sessions == []
