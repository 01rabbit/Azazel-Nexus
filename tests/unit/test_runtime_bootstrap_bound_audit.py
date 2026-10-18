"""Bound audit start composition over owned fake system-bus sessions."""

from dataclasses import replace

import pytest

from azazel_nexus.bootstrap_grant_transaction import advance_transaction
from azazel_nexus_runtime import bootstrap_manager as manager_module
from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.bootstrap_audit_client import BootstrapAuditClient
from azazel_nexus_runtime.units import UnitOperationFailed
from test_runtime_bootstrap_audit_client import DeadlineSocket, FakeClock, HASH
from test_runtime_bootstrap_audit_identity import FakeBus as IdentityBus
from test_runtime_bootstrap_audit_peer import (
    PRIMARY_GID, UID, _install_peer_evidence, _success_frame,
)
from test_runtime_bootstrap_controller_ready import (
    ReadyThenStartBus, _reply, _transaction,
)
from test_runtime_bootstrap_manager import FakeSystemdBusSession
from test_runtime_bootstrap_controller import OWNER, PROFILE_DIGEST


def _harness(monkeypatch, *, start_bus=None, identity_buses=None,
             manager_type=BootstrapNarrowingManager, job_timeout_seconds=5.0):
    monkeypatch.setattr(manager_module, "current_bootstrap_controller_identity",
                        lambda: object())
    start_bus = start_bus or ReadyThenStartBus()
    identity_buses = list(identity_buses or [IdentityBus() for _ in range(5)])
    buses = [start_bus, *identity_buses]
    sessions = []

    def factory():
        bus = buses[len(sessions)]
        session = FakeSystemdBusSession(bus=bus)
        sessions.append(session)
        bus.disconnected = False
        bus.disconnect = lambda: setattr(bus, "disconnected", True)
        return session

    manager = manager_type(job_timeout_seconds=job_timeout_seconds, session_factory=factory)
    # Model the exact retained publication/READY context required by the private
    # composition; no publication or controller service is exercised here.
    manager._controller_binding = (object(), OWNER, PROFILE_DIGEST)
    manager._controller_grant = _transaction("pair_grant_intent")
    manager._publication_check = lambda: None
    manager._controller_ready_confirmed = True
    publication = advance_transaction(
        advance_transaction(manager._controller_grant, "pair_grant_opened"),
        "auditd_start_intent",
    )
    return manager, sessions, start_bus, publication


def _assert_unbound(manager):
    with pytest.raises(UnitOperationFailed, match="binding unavailable"):
        manager._audit_binding_source()


def test_bound_start_captures_identity_and_real_client_observes(monkeypatch):
    manager, sessions, start_bus, transaction = _harness(monkeypatch)
    manager._start_bound_audit(transaction, check_start=lambda: None)

    assert start_bus.started
    assert sum(call.member == "StartUnit" for call in start_bus.calls) == 1
    assert len(sessions) == 2  # owned start, then real identity inspector
    assert all(s.closed and s._loop.is_closed() for s in sessions)

    _install_peer_evidence(monkeypatch, credentials=(4321, UID, PRIMARY_GID))
    clock = FakeClock()
    connection = DeadlineSocket(clock, _success_frame("observe"))
    monkeypatch.setattr(BootstrapAuditClient, "_connect",
                        staticmethod(lambda *_args, **_kwargs: connection))
    assert manager._bootstrap_audit_client().observe_head() == (7, HASH)
    assert connection.closed
    assert len(sessions) == 5  # capture + three identity revalidations
    assert all(s.closed and s._bus.disconnected and s._loop.is_closed()
               for s in sessions)


def test_wrong_transaction_refuses_before_opening_a_bus(monkeypatch):
    manager, sessions, bus, transaction = _harness(monkeypatch)
    wrong = replace(transaction, grant_id="fedcba9876543210fedcba9876543210")
    with pytest.raises(UnitOperationFailed, match="differs from publication"):
        manager._start_bound_audit(wrong, check_start=lambda: None)
    assert sessions == [] and bus.calls == [] and not bus.started
    _assert_unbound(manager)


@pytest.mark.parametrize("publication", ["missing", "refused"])
def test_retained_publication_is_required_before_audit_start(
    monkeypatch, publication,
):
    manager, sessions, bus, transaction = _harness(monkeypatch)
    manager._publication_check = None if publication == "missing" else lambda: False
    trusted_checks = []

    with pytest.raises(UnitOperationFailed, match="publication admission"):
        manager._start_bound_audit(
            transaction, check_start=lambda: trusted_checks.append(True)
        )

    assert trusted_checks == []
    assert sessions == [] and bus.calls == [] and not bus.started
    _assert_unbound(manager)


@pytest.mark.parametrize("failure", ["start", "cleanup", "capture"])
def test_failed_start_cleanup_or_capture_never_publishes_binding(monkeypatch, failure):
    start_bus = ReadyThenStartBus()
    identity_buses = [IdentityBus(fault="wrong-user") if failure == "capture"
                      else IdentityBus()]
    # The "start" job never completes, so it refuses only at the job deadline.
    manager, sessions, _, transaction = _harness(
        monkeypatch, start_bus=start_bus, identity_buses=identity_buses,
        job_timeout_seconds=0.1 if failure == "start" else 5.0,
    )
    if failure == "start":
        original_call = start_bus.call

        async def failed_start(message):
            if message.member == "StartUnit":
                start_bus.calls.append(message)
                return _reply("o", "/org/freedesktop/systemd1/job/999")
            return await original_call(message)

        start_bus.call = failed_start
    elif failure == "cleanup":
        original_factory = manager._factory

        def cleanup_failure_factory():
            session = original_factory()
            close = session.close

            def fail_close():
                close()
                raise RuntimeError("close")

            session.close = fail_close
            return session

        manager._factory = cleanup_failure_factory
    with pytest.raises(UnitOperationFailed):
        manager._start_bound_audit(transaction, check_start=lambda: None)
    _assert_unbound(manager)
    assert all(session.closed and session._loop.is_closed() for session in sessions)


def test_publication_drift_at_submission_checkpoint_prevents_start(monkeypatch):
    manager, sessions, start_bus, transaction = _harness(monkeypatch)
    checks = []

    def publication_check():
        checks.append(True)
        # Initial composition and before-observation checks passed. Refuse at
        # the bridge's before-submission checkpoint, after signal subscription.
        if len(checks) == 5:
            raise UnitOperationFailed("publication changed before submission")

    manager._publication_check = publication_check
    with pytest.raises(UnitOperationFailed):
        manager._start_bound_audit(transaction, check_start=lambda: None)
    assert len(checks) == 5
    assert "Subscribe" in [call.member for call in start_bus.calls]
    assert "StartUnit" not in [call.member for call in start_bus.calls]
    assert not start_bus.started
    assert all(session.closed and session._loop.is_closed() for session in sessions)
    _assert_unbound(manager)


def test_admission_cancellation_after_start_prevents_capture(monkeypatch):
    manager, sessions, start_bus, transaction = _harness(monkeypatch)
    checks = []

    def cancel_after_job():
        checks.append(True)
        # The bridge checkpoints several times. Cancellation at the next
        # composition checkpoint occurs after the StartUnit job has completed.
        return False if start_bus.started and len(checks) >= 5 else None

    with pytest.raises(UnitOperationFailed, match="admission unconfirmed"):
        manager._start_bound_audit(transaction, check_start=cancel_after_job)
    assert start_bus.started
    assert len(sessions) == 1
    _assert_unbound(manager)
