"""The supervisor-facing empty-pair gate always observes fresh state."""

import os

import pytest

from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed
from test_runtime_bootstrap_close_files import _files
from test_runtime_bootstrap_manager_stopped import (
    Session, StoppedManagerFakeBus, _cgroup_root, _report_overlay_fragments,
)
from test_runtime_bootstrap_overlay_files import _environment, _publish


def test_empty_pair_gate_rechecks_real_fixture_after_previous_success(tmp_path):
    with _environment(tmp_path) as env:
        _publish(env)
        root_path, root_fd = _cgroup_root(tmp_path)
        sessions = []

        def factory():
            bus = StoppedManagerFakeBus(mutate=_report_overlay_fragments(env))
            session = Session(bus)
            sessions.append(session)
            return session

        try:
            manager = BootstrapNarrowingManager(
                job_timeout_seconds=5.0, session_factory=factory,
                closed_overlay_files=_files(env), cgroup_root_fd=root_fd,
                cgroup_owner_uid=os.getuid(),
            )
            with pytest.raises(UnitOperationFailed):
                manager.confirm_empty_pair()
            assert not sessions
            manager.close_starts()
            assert manager.confirm_empty_pair() is None
            assert not any(call.member in {"Reload", "StopUnit", "CancelJob"}
                           for call in sessions[-1]._bus.calls)
            events = root_path / "system.slice" / UNIT_NAMES[UnitKey.AUDITD] / "cgroup.events"
            events.write_text("populated 1\n")
            with pytest.raises(UnitOperationFailed):
                manager.confirm_empty_pair()
            assert all(session.closed for session in sessions)
            assert env["store"].load().phase == "closing"
        finally:
            os.close(root_fd)


def test_missing_cgroup_backend_never_opens_bus_for_empty_confirmation():
    def forbidden():
        raise AssertionError("must refuse before bus connection")

    manager = BootstrapNarrowingManager(job_timeout_seconds=0.1, session_factory=forbidden)
    with pytest.raises(UnitOperationFailed):
        manager.confirm_empty_pair()


def test_closed_cgroup_descriptor_refuses_before_new_session(tmp_path):
    with _environment(tmp_path) as env:
        _publish(env)
        _path, root_fd = _cgroup_root(tmp_path)
        sessions = []

        def factory():
            session = Session(StoppedManagerFakeBus(mutate=_report_overlay_fragments(env)))
            sessions.append(session)
            return session

        manager = BootstrapNarrowingManager(
            job_timeout_seconds=5.0, session_factory=factory,
            closed_overlay_files=_files(env), cgroup_root_fd=root_fd,
            cgroup_owner_uid=os.getuid(),
        )
        try:
            manager.close_starts()
        finally:
            os.close(root_fd)
        count = len(sessions)
        with pytest.raises(UnitOperationFailed):
            manager.confirm_empty_pair()
        assert len(sessions) == count
