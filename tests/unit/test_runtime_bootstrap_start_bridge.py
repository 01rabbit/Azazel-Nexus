"""Synchronous/async checkpoint bridge tests for the private start adapter."""

import asyncio
import time

import pytest

from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.units import UnitKey, UnitOperationFailed


def _manager_with_bus(*, timeout=0.1, bus=None):
    from test_runtime_bootstrap_manager import FakeSystemdBusSession
    from test_runtime_bootstrap_start import FakeBus

    bus = bus or FakeBus()
    bus.disconnected = False
    bus.disconnect = lambda: setattr(bus, "disconnected", True)
    if bus.start_reply_hook is None:
        from test_runtime_bootstrap_start import _complete

        bus.start_reply_hook = lambda: _complete(bus, UnitKey.AUDITD)

    session = FakeSystemdBusSession()
    session._bus = bus
    sessions = []

    def factory():
        sessions.append(session)
        return session

    manager = BootstrapNarrowingManager(
        job_timeout_seconds=timeout, session_factory=factory
    )
    manager._controller_ready_confirmed = True  # synthetic prerequisite for job-only tests
    return manager, bus, session, sessions


def _assert_session_closed(bus, session):
    assert bus.disconnected
    assert session.closed
    assert session._loop.is_closed()
    assert not bus.handlers


def _record_pending_at_close(session):
    """Capture production teardown state, then clean up only for test hygiene."""
    pending_at_close = []
    original_close = session.close

    def close():
        pending = [
            task for task in asyncio.all_tasks(session._loop) if not task.done()
        ]
        pending_at_close.append(pending)
        # Finish test-owned stragglers after recording the state observed by
        # close, so the fixture itself never leaves a task on a closed loop.
        for task in pending:
            task.cancel()
        if pending:
            session._loop.run_until_complete(
                asyncio.wait(pending, timeout=0.2)
            )
        original_close()

    session.close = close
    return pending_at_close


def test_success_runs_three_sync_callbacks_on_one_owned_idle_session():
    manager, bus, session, sessions = _manager_with_bus()
    checkpoints = []

    def check_start():
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        asyncio.run(asyncio.sleep(0))
        checkpoints.append(len(checkpoints))
        return None

    assert manager._run_owned_start(
        UnitKey.AUDITD, expected_owner=":1.40", check_start=check_start
    ) is None

    assert checkpoints == [0, 1, 2]
    assert sessions == [session]
    members = [call.member for call in bus.calls]
    assert members.count("Subscribe") == 1
    assert members.count("StartUnit") == 1
    assert members.count("Unsubscribe") == 1
    _assert_session_closed(bus, session)


@pytest.mark.parametrize("failure", ["raise", "false", "expiry"])
def test_presubmission_checkpoint_refusal_or_expiry_never_submits_start(failure):
    manager, bus, session, _sessions = _manager_with_bus(timeout=0.04)
    calls = []

    def check_start():
        calls.append(None)
        if len(calls) == 2:
            if failure == "raise":
                raise RuntimeError("admission refused")
            if failure == "false":
                return False
            time.sleep(0.06)
        return None

    exception = RuntimeError if failure == "raise" else UnitOperationFailed
    with pytest.raises(exception):
        manager._run_owned_start(
            UnitKey.AUDITD, expected_owner=":1.40", check_start=check_start
        )

    assert len(calls) == 2
    assert not any(call.member == "StartUnit" for call in bus.calls)
    _assert_session_closed(bus, session)


def test_owner_drift_during_second_checkpoint_prevents_submission():
    manager, bus, session, _sessions = _manager_with_bus()
    calls = []

    def check_start():
        calls.append(None)
        if len(calls) == 2:
            bus.owner = ":1.41"
        return None

    with pytest.raises(UnitOperationFailed):
        manager._run_owned_start(
            UnitKey.AUDITD, expected_owner=":1.40", check_start=check_start
        )

    assert len(calls) == 2
    assert not any(call.member == "StartUnit" for call in bus.calls)
    _assert_session_closed(bus, session)


def test_fast_job_signal_before_start_reply_is_retained():
    manager, bus, session, _sessions = _manager_with_bus()
    checkpoints = []

    assert manager._run_owned_start(
        UnitKey.AUDITD,
        expected_owner=":1.40",
        check_start=lambda: checkpoints.append(True),
    ) is None
    assert len(checkpoints) == 3
    assert "StartUnit" in [call.member for call in bus.calls]
    _assert_session_closed(bus, session)


def test_postsubmission_checkpoint_failure_cleans_observer_and_session():
    manager, bus, session, _sessions = _manager_with_bus()
    calls = []

    def check_start():
        calls.append(None)
        if len(calls) == 3:
            raise RuntimeError("post-completion admission changed")

    with pytest.raises(RuntimeError, match="post-completion admission changed"):
        manager._run_owned_start(
            UnitKey.AUDITD, expected_owner=":1.40", check_start=check_start
        )

    assert len(calls) == 3
    assert "StartUnit" in [call.member for call in bus.calls]
    assert "Unsubscribe" in [call.member for call in bus.calls]
    assert "RemoveMatch" in [call.member for call in bus.calls]
    _assert_session_closed(bus, session)


def test_observer_cleanup_failure_is_reported_and_session_is_closed():
    manager, bus, session, _sessions = _manager_with_bus()
    bus.fail_unsubscribe = True

    with pytest.raises(UnitOperationFailed, match="completion unconfirmed"):
        manager._run_owned_start(
            UnitKey.AUDITD, expected_owner=":1.40", check_start=lambda: None
        )

    assert "StartUnit" in [call.member for call in bus.calls]
    _assert_session_closed(bus, session)


def test_cleanup_failure_does_not_replace_original_checkpoint_failure():
    manager, bus, session, _sessions = _manager_with_bus()
    bus.fail_unsubscribe = True
    checkpoints = []

    def refuse_after_completion():
        checkpoints.append(True)
        if len(checkpoints) == 3:
            raise RuntimeError("original admission refusal")

    with pytest.raises(RuntimeError, match="original admission refusal"):
        manager._run_owned_start(
            UnitKey.AUDITD, expected_owner=":1.40", check_start=refuse_after_completion,
        )
    assert len(checkpoints) == 3
    assert "Unsubscribe" in [call.member for call in bus.calls]
    _assert_session_closed(bus, session)


def test_late_cancellation_at_submission_checkpoint_cannot_start():
    manager, bus, session, _sessions = _manager_with_bus()
    calls = []

    def cancel_before_submit():
        calls.append(None)
        if len(calls) == 2:
            raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        manager._run_owned_start(
            UnitKey.AUDITD,
            expected_owner=":1.40",
            check_start=cancel_before_submit,
        )

    assert len(calls) == 2
    assert not any(call.member == "StartUnit" for call in bus.calls)
    _assert_session_closed(bus, session)


def test_public_start_api_still_refuses_without_opening_a_session():
    manager, bus, session, sessions = _manager_with_bus()

    with pytest.raises(UnitOperationFailed):
        manager.start_and_wait(
            UnitKey.AUDITD, transaction=object(), check_start=lambda: None
        )

    assert sessions == []
    assert bus.calls == []
    assert not session.closed
    session._loop.close()


def test_cancellation_resistant_late_subscribe_reply_never_reaches_start():
    manager, bus, session, _sessions = _manager_with_bus(timeout=0.04)
    original_call = bus.call
    late_replies = []

    async def cancellation_resistant_call(message):
        if message.member == "Subscribe":
            try:
                await asyncio.sleep(0.2)
            except asyncio.CancelledError:
                for _ in range(5):
                    try:
                        await asyncio.sleep(0.005)
                    except asyncio.CancelledError:
                        continue
                    break
                late_replies.append(message.member)
                return await original_call(message)
        return await original_call(message)

    bus.call = cancellation_resistant_call
    callbacks = []

    with pytest.raises(UnitOperationFailed):
        manager._run_owned_start(
            UnitKey.AUDITD,
            expected_owner=":1.40",
            check_start=lambda: callbacks.append(True),
        )

    assert callbacks == [True]
    assert late_replies == ["Subscribe"]
    assert not any(call.member == "StartUnit" for call in bus.calls)
    _assert_session_closed(bus, session)


def test_pre_submit_refusal_drains_unsubscribe_cleanup_descendants():
    manager, bus, session, _sessions = _manager_with_bus(timeout=0.04)
    pending_at_close = _record_pending_at_close(session)
    original_call = bus.call
    reached = {
        "unsubscribe_entered": False,
        "cleanup_child_started": False,
        "cleanup_child_cancelled": False,
        "grandchild_started": False,
    }

    async def hanging_unsubscribe(message):
        if message.member == "Unsubscribe":
            reached["unsubscribe_entered"] = True
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                async def cleanup_child():
                    reached["cleanup_child_started"] = True
                    try:
                        await asyncio.Future()
                    except asyncio.CancelledError:
                        reached["cleanup_child_cancelled"] = True
                        async def grandchild():
                            reached["grandchild_started"] = True
                            await asyncio.Future()

                        # Spawn after the manager's first task snapshot. The
                        # shared teardown pump must discover this descendant.
                        asyncio.get_running_loop().create_task(grandchild())
                        await asyncio.sleep(0)

                asyncio.get_running_loop().create_task(cleanup_child())
                return await original_call(message)
        return await original_call(message)

    bus.call = hanging_unsubscribe
    callbacks = []

    def refuse_before_submit():
        callbacks.append(None)
        return False if len(callbacks) == 2 else None

    with pytest.raises(UnitOperationFailed):
        manager._run_owned_start(
            UnitKey.AUDITD,
            expected_owner=":1.40",
            check_start=refuse_before_submit,
        )

    assert len(callbacks) == 2
    assert not any(call.member == "StartUnit" for call in bus.calls)
    assert reached == {
        "unsubscribe_entered": True,
        "cleanup_child_started": True,
        "cleanup_child_cancelled": True,
        "grandchild_started": True,
    }
    assert pending_at_close == [[]]
    _assert_session_closed(bus, session)


def test_owned_loop_refuses_success_when_cleanup_task_cannot_quiesce():
    manager, bus, session, _sessions = _manager_with_bus(timeout=0.03)
    pending_at_close = _record_pending_at_close(session)
    checks = []

    async def stubborn_cleanup():
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            # Exceed the owned teardown deadline after being cancelled.
            await asyncio.sleep(0.1)

    def leave_stubborn_cleanup_task():
        checks.append(None)
        if len(checks) == 3:
            session._loop.create_task(stubborn_cleanup())

    with pytest.raises(UnitOperationFailed, match="(quiesce|cleanup)"):
        manager._run_owned_start(
            UnitKey.AUDITD,
            expected_owner=":1.40",
            check_start=leave_stubborn_cleanup_task,
        )

    assert checks == [None, None, None]
    assert "StartUnit" in [call.member for call in bus.calls]
    assert len(pending_at_close) == 1
    # This records the still-pending task at close before fixture-only draining.
    assert pending_at_close[0]
    _assert_session_closed(bus, session)
