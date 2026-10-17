"""Private protocol publication through actual owned files and synthetic systemd.

This exercises the real publication implementation, not native systemd or
deployment admission. The existing fixture supplies protected ordinary files,
an owned journal/guard and fake loaded-policy/manager observations.
"""

import pytest

from azazel_nexus.audit import AuditUnavailable
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.bootstrap_audit_client import BootstrapAuditClient
from azazel_nexus_runtime.bootstrap_manager import _PrototypeBootstrapManager
from azazel_nexus_runtime.units import UnitKey, UnitOperationFailed
from test_runtime_bootstrap_audit_client import DeadlineSocket, FakeClock
from test_runtime_bootstrap_audit_peer import (
    PRIMARY_GID, UID, _install_peer_evidence, _success_frame,
)
from test_runtime_bootstrap_bound_audit import _harness
from test_runtime_bootstrap_manager_publication import (
    _check_publish, _manager_fixture, _transaction,
)
from test_runtime_bootstrap_overlay_files import _environment


def test_protocol_publication_retains_actual_files_and_journal(tmp_path, monkeypatch):
    with _environment(tmp_path) as env:
        manager, sessions, bus, approval, *_ = _manager_fixture(
            env, monkeypatch, manager_type=_PrototypeBootstrapManager,
        )
        transaction = _transaction(approval)
        checkpoints = []
        assert manager.open_pair(
            transaction, approval=approval, check_publish=_check_publish(checkpoints),
        ) is None
        assert env["store"].load().phase == "published"
        assert manager._controller_grant is transaction
        assert manager._controller_binding is not None
        assert manager._publication_check is not None
        manager._check_retained_publication()
        assert checkpoints and bus.reload_count == 1
        assert all(session.closed for session in sessions)
        assert not any(call.member == "StartUnit" for call in bus.calls)


def test_protocol_audit_start_and_readiness_use_actual_peer_client(monkeypatch):
    manager, sessions, bus, transaction = _harness(
        monkeypatch, manager_type=_PrototypeBootstrapManager,
    )
    # Retained publication/READY context is supplied by this fixture, while
    # actual start-job, identity and authenticated peer code execute below.
    with pytest.raises(AuditUnavailable):
        manager.is_ready(UnitKey.AUDITD)
    assert sessions == []
    manager.start_and_wait(UnitKey.AUDITD, transaction=transaction, check_start=lambda: None)
    _install_peer_evidence(monkeypatch, credentials=(4321, UID, PRIMARY_GID))
    connection = DeadlineSocket(FakeClock(), _success_frame("observe"))
    monkeypatch.setattr(BootstrapAuditClient, "_connect",
                        staticmethod(lambda *_args, **_kwargs: connection))
    assert manager.is_ready(UnitKey.AUDITD) is True
    assert connection.closed and bus.started
    assert sum(call.member == "StartUnit" for call in bus.calls) == 1
    assert len(sessions) == 5
    assert all(session.closed for session in sessions)


def test_readiness_rejects_actual_publication_mutation_during_peer_exchange(
    tmp_path, monkeypatch,
):
    with _environment(tmp_path) as env:
        manager, sessions, _bus, approval, *_ = _manager_fixture(
            env, monkeypatch, manager_type=_PrototypeBootstrapManager,
        )
        manager.open_pair(
            _transaction(approval), approval=approval, check_publish=lambda: None,
        )
        peer_calls = []

        def peer(_unit):
            peer_calls.append(True)
            # A synthetic successful peer cannot authorize changed publication.
            (env["overlay_path"] / "azazel-auditd.service").unlink()
            return True

        monkeypatch.setattr(manager, "_bound_helper_ready", peer)
        with pytest.raises(ApprovalRefused, match="published pair file observation"):
            manager.is_ready(UnitKey.AUDITD)
        assert peer_calls == [True]
        assert all(session.closed for session in sessions)


@pytest.mark.parametrize("fault", ["reload-error", "owner-after-reload"])
def test_protocol_publication_failure_cannot_report_completion(tmp_path, monkeypatch, fault):
    with _environment(tmp_path) as env:
        manager, sessions, bus, approval, *_ = _manager_fixture(
            env, monkeypatch, fault=fault, manager_type=_PrototypeBootstrapManager,
        )
        with pytest.raises(UnitOperationFailed):
            manager.open_pair(
                _transaction(approval), approval=approval, check_publish=lambda: None,
            )
        assert bus.fault_reached
        assert manager._controller_grant is None
        assert manager._publication_check is None
        assert manager._closed_observation is None
        assert env["store"].load() is not None  # retain uncertain durable intent
        assert all(session.closed for session in sessions)
        assert not any(call.member == "StartUnit" for call in bus.calls)
