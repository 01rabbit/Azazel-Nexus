"""Fake-clock tests for the READY and helper-start checkpoint budgets.

Synchronous checkpoints are full verifications. Their time is not charged to
the per-operation async budget; one fixed total ceiling still bounds each step.
"""

import asyncio
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime import bootstrap_manager as manager_module
from azazel_nexus_runtime import bootstrap_start_bridge
from azazel_nexus_runtime.bootstrap_start_bridge import _StartCheckpointBridge
from azazel_nexus_runtime.units import UnitOperationFailed

from azazel_nexus.operator_trust import ApprovalRefused
from test_runtime_bootstrap import Harness, evidence as bootstrap_evidence
from test_runtime_bootstrap_controller_ready import (
    DelayedReadyBus,
    _manager,
    _transaction,
)

PHASES = ("before_observation", "before_submission", "after_completion")


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


def _ready_manager(monkeypatch, *, ready_after=1):
    clock = _Clock()
    manager, sessions = _manager(DelayedReadyBus(ready_after=ready_after), monkeypatch)
    monkeypatch.setattr(manager_module, "time", SimpleNamespace(monotonic=clock.monotonic))
    return manager, sessions, clock


def test_five_slow_sync_checkpoints_exceed_old_budget_but_confirm_ready(monkeypatch):
    manager, _sessions, clock = _ready_manager(monkeypatch)
    checks, notified = [], []

    def check_ready():
        checks.append(True)
        clock.now += 2.2  # 5 x 2.2 s = 11 s > the old shared 10 s window

    manager.confirm_controller_ready(
        _transaction(), check_ready=check_ready, notify=lambda: notified.append(True),
    )

    assert len(checks) >= 5
    assert notified == [True]
    assert manager._controller_ready_confirmed is True
    assert clock.now - 1000.0 > manager._timeout


def test_total_ceiling_fails_closed_after_single_notification(monkeypatch):
    manager, _sessions, clock = _ready_manager(monkeypatch)
    checks, notified = [], []

    def check_ready():
        checks.append(True)
        clock.now += manager_module.READY_TOTAL_SECONDS / 2 + 0.5

    with pytest.raises(UnitOperationFailed):
        manager.confirm_controller_ready(
            _transaction(), check_ready=check_ready, notify=lambda: notified.append(True),
        )

    assert notified == [True]
    assert len(checks) == 2
    assert manager._controller_ready_confirmed is False


def test_ceiling_is_fixed_code_constant_below_timeout_start_margin():
    assert manager_module.READY_TOTAL_SECONDS == 25.0 < 30.0


def test_each_inspect_keeps_its_own_async_budget_capped_by_remaining_ceiling(monkeypatch):
    manager, _sessions, clock = _ready_manager(monkeypatch)
    timeouts = []
    real = manager_module.BootstrapControllerInspector

    def spy(**kwargs):
        timeouts.append(kwargs["timeout_seconds"])
        return real(**kwargs)

    monkeypatch.setattr(manager_module, "BootstrapControllerInspector", spy)

    def check_ready():
        clock.now += 2.2

    manager.confirm_controller_ready(
        _transaction(), check_ready=check_ready, notify=lambda: None,
    )
    # Three sync checks ran before the inspect; it still has the full own budget.
    assert timeouts[0] == manager._timeout

    manager2, _sessions2, clock2 = _ready_manager(monkeypatch)
    timeouts.clear()
    state = []

    def near_ceiling():
        state.append(True)
        if len(state) == 3:
            clock2.now = 1000.0 + manager_module.READY_TOTAL_SECONDS - 0.25

    manager2.confirm_controller_ready(
        _transaction(), check_ready=near_ceiling, notify=lambda: None,
    )
    assert timeouts[0] == pytest.approx(0.25)


def test_retained_deadline_expiry_inside_check_ready_still_refuses(monkeypatch):
    manager, _sessions, _clock = _ready_manager(monkeypatch)
    checks = []

    def check_ready():
        checks.append(True)
        if len(checks) == 3:
            raise UnitOperationFailed("retained admission deadline expired")

    with pytest.raises(UnitOperationFailed):
        manager.confirm_controller_ready(
            _transaction(), check_ready=check_ready, notify=lambda: None,
        )

    assert len(checks) == 3
    assert manager._controller_ready_confirmed is False


class _FakeLoop(asyncio.SelectorEventLoop):
    def __init__(self):
        super().__init__()
        self.fake_now = 5000.0

    def time(self):
        return self.fake_now


def _bridge():
    loop = _FakeLoop()
    observer = SimpleNamespace(_usable=True)
    return loop, observer, _StartCheckpointBridge(loop, observer)


def _run(loop, observer, bridge, operation, check_start):
    try:
        return bridge.run(operation(), check_start)
    finally:
        loop.run_until_complete(asyncio.sleep(0))
        loop.close()


def test_three_slow_sync_phases_are_not_charged_to_the_async_budget():
    loop, observer, bridge = _bridge()

    async def operation():
        deadline = loop.time() + 10  # same shape as BootstrapStopJobs._bounded
        for phase in PHASES:
            await bridge.checkpoint(phase, deadline)
        assert loop.time() < deadline  # sync time was held back from the job clock

    def check_start():
        loop.fake_now += 4.0  # 3 x 4 s = 12 s > the 10 s job budget
        return None

    assert _run(loop, observer, bridge, operation, check_start) is None
    assert observer._usable is True
    assert "time" not in vars(loop)  # clock override removed after the job


def test_async_time_between_phases_is_still_charged():
    loop, observer, bridge = _bridge()

    async def operation():
        deadline = loop.time() + 10
        await bridge.checkpoint(PHASES[0], deadline)
        loop.fake_now += 11.0  # async-side time, not a synchronous check
        await bridge.checkpoint(PHASES[1], deadline)

    with pytest.raises(UnitOperationFailed):
        _run(loop, observer, bridge, operation, lambda: None)
    assert observer._usable is False


def test_sync_total_beyond_ceiling_fails_closed():
    loop, observer, bridge = _bridge()
    ceiling = bootstrap_start_bridge.START_SYNC_CEILING_SECONDS
    calls = []

    async def operation():
        deadline = loop.time() + 10
        for phase in PHASES:
            await bridge.checkpoint(phase, deadline)

    def check_start():
        calls.append(True)
        loop.fake_now += ceiling / 2 + 1.0
        return None

    with pytest.raises(UnitOperationFailed, match="ceiling"):
        _run(loop, observer, bridge, operation, check_start)
    assert len(calls) == 2
    assert observer._usable is False


def test_changed_deadline_is_still_refused():
    loop, observer, bridge = _bridge()

    async def operation():
        await bridge.checkpoint(PHASES[0], loop.time() + 10)
        await bridge.checkpoint(PHASES[1], loop.time() + 20)

    with pytest.raises(UnitOperationFailed):
        _run(loop, observer, bridge, operation, lambda: None)
    assert observer._usable is False


def test_override_removed_on_exception_paths():
    for failing in ("raise", "refuse"):
        loop, observer, bridge = _bridge()

        async def operation():
            await bridge.checkpoint(PHASES[0], loop.time() + 10)

        def check_start():
            loop.fake_now += 1.0
            if failing == "raise":
                raise RuntimeError("admission failed")
            return False

        with pytest.raises((RuntimeError, UnitOperationFailed)):
            _run(loop, observer, bridge, operation, check_start)
        assert "time" not in vars(loop)
        assert observer._usable is False


def test_timer_scheduled_before_a_pause_still_fires_after_it():
    loop, observer, bridge = _bridge()
    fired = []

    async def operation():
        loop.call_later(1.0, fired.append, True)
        deadline = loop.time() + 10
        for phase in PHASES:
            await bridge.checkpoint(phase, deadline)
        assert fired == []  # sync pauses did not advance the job clock
        loop.fake_now += 2.0
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert fired == [True]

    def check_start():
        loop.fake_now += 4.0
        return None

    assert _run(loop, observer, bridge, operation, check_start) is None


def test_ready_retry_sleep_is_clamped_to_remaining_ceiling(monkeypatch):
    manager, _sessions, clock = _ready_manager(monkeypatch, ready_after=3)
    sleeps = []
    real_sleep = asyncio.sleep

    async def spy(delay, *args, **kwargs):
        sleeps.append(delay)
        return await real_sleep(0, *args, **kwargs)

    monkeypatch.setattr(manager_module.asyncio, "sleep", spy)
    state = []

    def check_ready():
        state.append(True)
        if len(state) >= 4:
            clock.now = 1000.0 + manager_module.READY_TOTAL_SECONDS - 0.001

    try:
        manager.confirm_controller_ready(
            _transaction(), check_ready=check_ready, notify=lambda: None,
        )
    except UnitOperationFailed:
        pass
    assert all(0.0 <= delay <= 0.01 for delay in sleeps)


def test_heartbeat_is_emitted_right_after_ready_confirmation_before_next_check():
    h = Harness(bootstrap_evidence.__wrapped__(None))
    log = []
    supervisor = h.supervisor
    original_check = supervisor._check

    def check(*args, **kwargs):
        log.append(("check", supervisor._controller_ready_confirmed))
        return original_check(*args, **kwargs)

    supervisor._check = check
    supervisor.controller_watchdog = lambda: log.append(("watchdog", None))
    supervisor.wait = lambda seconds: setattr(h, "stop", True)

    assert supervisor.run().state == "stopped"
    first_watchdog = next(i for i, e in enumerate(log) if e[0] == "watchdog")
    first_post_ready_check = next(
        i for i, e in enumerate(log) if e == ("check", True)
    )
    assert first_watchdog < first_post_ready_check


def test_heartbeat_not_sent_when_cancelled_at_ready():
    h = Harness(bootstrap_evidence.__wrapped__(None))
    beats = []
    h.supervisor.controller_watchdog = lambda: beats.append(True)
    h.supervisor.controller_ready = lambda: setattr(h, "stop", True)
    try:
        h.supervisor.run()
    except ApprovalRefused:
        pass
    assert beats == []
