"""Manager integration for journal-owned mask withdrawal; synthetic only."""

import os
from types import SimpleNamespace

import pytest

from azazel_nexus.bootstrap_grant_transaction import GrantTransaction
from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, UnitOperationFailed
from azazel_nexus_runtime import bootstrap_withdraw_files
from test_runtime_bootstrap_manager_stopped import (
    Session,
    StoppedManagerFakeBus,
    _cgroup_root,
)
from test_runtime_bootstrap_overlay_withdraw import (
    _close,
    _withdraw_environment,
)
from test_runtime_bootstrap_overlay_files import PAIR


def _transaction(env, *, grant_id=None):
    intent = env["store"].load().intent
    return GrantTransaction(
        boot_id=intent.boot_id,
        context_digest="sha256:" + intent.context_digest,
        approval_digest="sha256:" + "b" * 64,
        generation=1,
        generation_digest="sha256:" + "c" * 64,
        grant_id=grant_id or intent.grant_id,
        unit_payload_digests=intent.payload_digests,
    )


def _manager(env, root_fd, buses, fault_state):
    from azazel_nexus_runtime.bootstrap_close_files import BootstrapClosedOverlayFiles
    from azazel_nexus_runtime.bootstrap_withdrawal import BootstrapWithdrawalFiles

    closed_files = BootstrapClosedOverlayFiles(
        overlay_fd=env["overlay_fd"], masks_fd=env["masks_fd"],
        higher_priority_fd=env["higher_fd"], overlay_path=env["overlay_path"],
        masks_path=env["masks_path"], higher_priority_path=env["higher_path"],
        journal_store=env["store"], guard=env["guard"], owner_uid=os.getuid(),
    )
    withdrawal_files = BootstrapWithdrawalFiles(
        overlay_fd=env["overlay_fd"], masks_fd=env["masks_fd"],
        higher_priority_fd=env["higher_fd"], transient_fd=env["transient_fd"],
        generator_early_fd=env["generator_early_fd"],
        overlay_path=env["overlay_path"], masks_path=env["masks_path"],
        higher_priority_path=env["higher_path"], transient_path=env["transient_path"],
        generator_early_path=env["generator_early_path"],
        journal_store=env["store"], guard=env["guard"], owner_uid=os.getuid(),
    )
    from azazel_nexus_runtime.bootstrap_systemd_profile import (
        _DEBIAN13_V257_UNIT_PATH,
        observe_bootstrap_systemd_profile,
    )
    sessions = []

    class FreshBus(StoppedManagerFakeBus):
        async def call(self, message):
            self.owner_changes = fault_state["owner_changes"]
            self.reload_error = fault_state["reload_error"]
            return await super().call(message)

    def session_factory():
        bus = FreshBus(mutate=_dynamic_overlay_fragments(env))
        buses.append(bus)
        session = Session(bus)
        session.bootstrap_profile = lambda: observe_bootstrap_systemd_profile(
            version="257.13-1~deb13u1", unit_path=list(_DEBIAN13_V257_UNIT_PATH),
        )
        sessions.append(session)
        return session

    manager = BootstrapNarrowingManager(
        job_timeout_seconds=5.0,
        session_factory=session_factory,
        closed_overlay_files=closed_files,
        withdrawal_files=withdrawal_files,
        cgroup_root_fd=root_fd,
        cgroup_owner_uid=os.getuid(),
    )
    return manager, sessions


def _dynamic_overlay_fragments(env):
    def mutate(_number, name, properties):
        path = env["overlay_path"] / name
        if path.exists():
            fragment = str(path)
        else:
            fragment = str(env["masks_path"] / name)
        properties["FragmentPath"] = SimpleNamespace(signature="s", value=fragment)
        properties["ActiveState"] = SimpleNamespace(signature="s", value="inactive")
        return properties

    return mutate


def test_manager_withdraws_real_closed_journal_then_confirms_empty_pair(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        buses = []
        fault_state = {"owner_changes": False, "reload_error": False}
        _root, root_fd = _cgroup_root(tmp_path)
        try:
            manager, sessions = _manager(env, root_fd, buses, fault_state)
            manager.close_starts()
            manager.withdraw_pair(_transaction(env))
            manager.confirm_empty_pair()
        finally:
            os.close(root_fd)

        assert env["store"].load().phase == "closed"
        assert all(not (env["overlay_path"] / name).exists() for name in PAIR)
        assert any(bus.reloaded for bus in buses)
        assert [call.body[0] for bus in buses for call in bus.calls
                if call.member == "StopUnit"] == [
            UNIT_NAMES[UnitKey.COMMISSIOND], UNIT_NAMES[UnitKey.AUDITD],
        ]
        assert all(
            call.member != "StartUnit" for bus in buses for call in bus.calls
        )
        assert len(sessions) >= 3
        assert len({id(bus) for bus in buses}) == len(buses)
        assert all(session.closed and session._loop.is_closed() for session in sessions)
        assert all(bus.disconnected for bus in buses)


def test_wrong_grant_refuses_before_withdrawal_session_or_unlink(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        buses = []
        fault_state = {"owner_changes": False, "reload_error": False}
        _root, root_fd = _cgroup_root(tmp_path)
        try:
            manager, _sessions = _manager(env, root_fd, buses, fault_state)
            manager.close_starts()
            before = len(buses)
            with pytest.raises(UnitOperationFailed):
                manager.withdraw_pair(_transaction(env, grant_id="f" * 32))
        finally:
            os.close(root_fd)

        assert len(buses) == before
        assert len({id(bus) for bus in buses}) == len(buses)
        assert env["store"].load().phase == "closing"
        assert all((env["overlay_path"] / name).exists() for name in PAIR)


def test_owner_drift_after_first_unlink_retains_withdrawing_journal(tmp_path, monkeypatch):
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        buses = []
        fault_state = {"owner_changes": False, "reload_error": False}
        _root, root_fd = _cgroup_root(tmp_path)
        try:
            manager, _sessions = _manager(env, root_fd, buses, fault_state)
            manager.close_starts()
            real_unlink = bootstrap_withdraw_files.os.unlink

            def unlink_then_drift(name, *, dir_fd=None):
                result = real_unlink(name, dir_fd=dir_fd)
                if dir_fd == env["overlay_fd"]:
                    fault_state["owner_changes"] = True
                return result

            monkeypatch.setattr(bootstrap_withdraw_files.os, "unlink", unlink_then_drift)
            with pytest.raises(UnitOperationFailed):
                manager.withdraw_pair(_transaction(env))
        finally:
            os.close(root_fd)

        assert env["store"].load().phase == "withdrawing"
        assert any(not (env["overlay_path"] / name).exists() for name in PAIR)
        assert all(not any(call.member == "StartUnit" for call in bus.calls)
                   for bus in buses)
        assert len({id(bus) for bus in buses}) == len(buses)
        assert all(bus.disconnected for bus in buses)


def test_postwithdraw_reload_failure_retains_withdrawing_journal(tmp_path, monkeypatch):
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        buses = []
        fault_state = {"owner_changes": False, "reload_error": False}
        _root, root_fd = _cgroup_root(tmp_path)
        try:
            manager, _sessions = _manager(env, root_fd, buses, fault_state)
            manager.close_starts()
            real_unlink = bootstrap_withdraw_files.os.unlink

            def unlink_then_break_reload(name, *, dir_fd=None):
                result = real_unlink(name, dir_fd=dir_fd)
                if dir_fd == env["overlay_fd"]:
                    fault_state["reload_error"] = True
                return result

            monkeypatch.setattr(bootstrap_withdraw_files.os, "unlink", unlink_then_break_reload)
            with pytest.raises(UnitOperationFailed):
                manager.withdraw_pair(_transaction(env))
        finally:
            os.close(root_fd)

        assert env["store"].load().phase == "withdrawing"
        assert any(not (env["overlay_path"] / name).exists() for name in PAIR)
        assert len({id(bus) for bus in buses}) == len(buses)
        assert all(bus.disconnected for bus in buses)


def test_fresh_manager_resumes_partial_withdrawal_and_completes_containment(
    tmp_path, monkeypatch,
):
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        buses = []
        fault_state = {"owner_changes": False, "reload_error": False}
        _root, root_fd = _cgroup_root(tmp_path)
        try:
            first_manager, first_sessions = _manager(env, root_fd, buses, fault_state)
            first_manager.close_starts()
            real_unlink = bootstrap_withdraw_files.os.unlink

            def unlink_then_drift(name, *, dir_fd=None):
                result = real_unlink(name, dir_fd=dir_fd)
                if dir_fd == env["overlay_fd"]:
                    fault_state["owner_changes"] = True
                return result

            monkeypatch.setattr(bootstrap_withdraw_files.os, "unlink", unlink_then_drift)
            with pytest.raises(UnitOperationFailed):
                first_manager.withdraw_pair(_transaction(env))
            assert env["store"].load().phase == "withdrawing"
            assert any(not (env["overlay_path"] / name).exists() for name in PAIR)

            monkeypatch.setattr(bootstrap_withdraw_files.os, "unlink", real_unlink)
            fault_state["owner_changes"] = False
            second_manager, second_sessions = _manager(env, root_fd, buses, fault_state)
            second_manager.close_starts()
            second_manager.withdraw_pair(_transaction(env))
            second_manager.confirm_empty_pair()
        finally:
            os.close(root_fd)

        assert env["store"].load().phase == "closed"
        assert all(not (env["overlay_path"] / name).exists() for name in PAIR)
        assert len(buses) == len({id(bus) for bus in buses})
        assert all(bus.disconnected for bus in buses)
        assert all(
            session.closed and session._loop.is_closed()
            for session in first_sessions + second_sessions
        )
        assert any(call.member == "StopUnit" for bus in buses for call in bus.calls)


def test_default_manager_still_refuses_withdrawal_without_backend():
    manager = BootstrapNarrowingManager(
        job_timeout_seconds=0.05,
        session_factory=lambda: pytest.fail("default refusal opened a session"),
    )
    transaction = GrantTransaction(
        boot_id="22222222-2222-4222-8222-222222222222",
        context_digest="sha256:" + "a" * 64,
        approval_digest="sha256:" + "b" * 64,
        generation=1,
        generation_digest="sha256:" + "c" * 64,
        grant_id="0123456789abcdef0123456789abcdef",
        unit_payload_digests=tuple((name, "d" * 64) for name in PAIR),
    )
    with pytest.raises(UnitOperationFailed, match="unavailable"):
        manager.withdraw_pair(transaction)


def test_fresh_manager_reobserves_already_closed_withdrawal(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        _close(env)
        buses = []
        fault_state = {"owner_changes": False, "reload_error": False}
        _root, root_fd = _cgroup_root(tmp_path)
        try:
            transaction = _transaction(env)
            for _attempt in range(2):
                manager, sessions = _manager(env, root_fd, buses, fault_state)
                manager.close_starts()
                manager.withdraw_pair(transaction)
                manager.confirm_empty_pair()
                assert env["store"].load().phase == "closed"
                assert all(session.closed for session in sessions)
        finally:
            os.close(root_fd)
        assert all(not (env["overlay_path"] / name).exists() for name in PAIR)
        assert all(bus.disconnected for bus in buses)
        assert len({id(bus) for bus in buses}) == len(buses)
