"""Bounded controller-ready confirmation uses only an owned fake bus."""

import asyncio
import time
from types import SimpleNamespace
import pytest

from azazel_nexus.bootstrap_grant_transaction import GrantTransaction, PAIR
from azazel_nexus_runtime import bootstrap_manager as manager_module
from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.units import UnitKey, UnitOperationFailed
from test_runtime_bootstrap_controller import (
    FakeBus as ControllerFakeBus,
    IDENTITY,
    OWNER,
    PROFILE_DIGEST,
    Variant,
    _object_path,
    _reply,
)
from test_runtime_bootstrap_manager import FakeSystemdBusSession


def _transaction(phase="pair_grant_opened"):
    return GrantTransaction(
        boot_id="22222222-2222-4222-8222-222222222222",
        context_digest="sha256:" + "a" * 64,
        approval_digest="sha256:" + "b" * 64,
        generation=1,
        generation_digest="sha256:" + "c" * 64,
        grant_id="0123456789abcdef0123456789abcdef",
        unit_payload_digests=tuple((name, "d" * 64) for name in PAIR),
        phase=phase,
    )


class DelayedReadyBus(ControllerFakeBus):
    def __init__(self, *, ready_after=2, **kwargs):
        super().__init__(phase="pre-ready", **kwargs)
        self.ready_after = ready_after

    async def call(self, message):
        result = await super().call(message)
        if (message.member == "GetAll"
                and message.body == ["org.freedesktop.systemd1.Service"]
                and self.service_calls >= 2 * self.ready_after):
            self.phase = "ready"
        return result


class ReadyThenStartBus(DelayedReadyBus):
    """One fake connection serves the controller observer and start bridge."""

    def __init__(self):
        super().__init__(ready_after=1)
        self.handlers = []
        self.started = False
        self.job = (73, "/org/freedesktop/systemd1/job/73")

    def add_message_handler(self, handler):
        self.handlers.append(handler)

    def remove_message_handler(self, handler):
        self.handlers.remove(handler)

    async def call(self, message):
        if message.member == "LoadUnit":  # fake: LoadUnit is the same lookup as GetUnit
            message.member = "GetUnit"
        if message.member == "GetNameOwner" or message.member == "GetAll":
            return await super().call(message)
        if message.member == "GetUnit":
            if message.body == ["azazel-activated.service"]:
                return await super().call(message)
            self.calls.append(message)
            return _reply("o", _object_path(message.body[0]), sender=OWNER)
        if message.member in {"AddMatch", "RemoveMatch", "Subscribe", "Unsubscribe"}:
            self.calls.append(message)
            return _reply("", sender=message.destination)
        if message.member == "Get" and message.interface == "org.freedesktop.DBus.Properties":
            self.calls.append(message)
            state = "active" if self.started else "inactive"
            return _reply("v", Variant("s", state), sender=OWNER)
        if message.member == "StartUnit":
            self.calls.append(message)
            self.started = True
            signal = SimpleNamespace(
                message_type=4,
                signature="uoss",
                sender=OWNER,
                path="/org/freedesktop/systemd1",
                interface="org.freedesktop.systemd1.Manager",
                member="JobRemoved",
                body=[self.job[0], self.job[1], message.body[0], "done"],
            )
            for handler in tuple(self.handlers):
                handler(signal)
            return _reply("o", self.job[1], sender=OWNER)
        raise AssertionError(f"unexpected start bridge call: {message.member}")


def _manager(bus, monkeypatch, *, timeout=5.0):
    monkeypatch.setattr(
        manager_module, "current_bootstrap_controller_identity", lambda: IDENTITY,
    )
    sessions = []

    def factory():
        session = FakeSystemdBusSession(bus=bus)
        sessions.append(session)
        return session

    manager = BootstrapNarrowingManager(
        job_timeout_seconds=timeout, session_factory=factory,
    )
    bus.disconnected = False
    bus.disconnect = lambda: setattr(bus, "disconnected", True)
    manager._controller_binding = (IDENTITY, OWNER, PROFILE_DIGEST)
    manager._controller_grant = _transaction("pair_grant_intent")
    return manager, sessions


def test_delayed_ready_is_confirmed_once_on_one_owned_session_without_start(monkeypatch):
    bus = DelayedReadyBus(ready_after=2)
    manager, sessions = _manager(bus, monkeypatch)
    checkpoints = []
    notifications = []

    def check_ready():
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        checkpoints.append(True)

    manager.confirm_controller_ready(
        _transaction("pair_grant_opened"), check_ready=check_ready,
        notify=lambda: notifications.append(True),
    )

    assert manager._controller_ready_confirmed
    assert notifications == [True]
    assert len(checkpoints) >= 2
    assert len(sessions) == 1
    assert bus.service_calls >= 4
    assert not any(call.member == "StartUnit" for call in bus.calls)
    assert bus.disconnected and sessions[0].closed and sessions[0]._loop.is_closed()


@pytest.mark.parametrize("change", ["owner", "pid"])
def test_identity_drift_during_ready_poll_refuses_without_start(change, monkeypatch):
    bus = DelayedReadyBus(ready_after=20)
    manager, sessions = _manager(bus, monkeypatch)
    notifications = []
    if change == "owner":
        bus.owner_drift_at = 4
    else:
        def mutate(interface, count, properties):
            if interface == "org.freedesktop.systemd1.Service" and count >= 3:
                properties["MainPID"] = Variant("u", IDENTITY.pid + 1)
            return properties
        bus.mutate = mutate

    with pytest.raises(UnitOperationFailed):
        manager.confirm_controller_ready(
            _transaction("pair_grant_opened"), check_ready=lambda: None,
            notify=lambda: notifications.append(True),
        )

    assert notifications == [True]
    assert not any(call.member == "StartUnit" for call in bus.calls)
    assert sessions[0].closed and sessions[0]._loop.is_closed()


def test_checkpoint_cancellation_stops_pending_readiness_poll(monkeypatch):
    bus = DelayedReadyBus(ready_after=20)
    manager, sessions = _manager(bus, monkeypatch)
    checks = []
    notifications = []

    def check_ready():
        checks.append(True)
        if len(checks) == 4:
            raise UnitOperationFailed("readiness admission cancelled")

    with pytest.raises(UnitOperationFailed, match="cancelled"):
        manager.confirm_controller_ready(
            _transaction("pair_grant_opened"), check_ready=check_ready,
            notify=lambda: notifications.append(True),
        )

    assert len(checks) == 4
    assert notifications == [True]
    assert not any(call.member == "StartUnit" for call in bus.calls)
    assert sessions[0].closed and sessions[0]._loop.is_closed()


def test_checkpoint_expiry_stops_pending_readiness_poll(monkeypatch):
    bus = DelayedReadyBus(ready_after=20)
    manager, sessions = _manager(bus, monkeypatch, timeout=0.1)
    # The READY step now has one total ceiling (not the per-inspect timeout).
    monkeypatch.setattr(manager_module, "READY_TOTAL_SECONDS", 0.1)
    checks = []

    def check_ready():
        checks.append(True)
        if len(checks) == 4:
            time.sleep(0.15)

    with pytest.raises(UnitOperationFailed):
        manager.confirm_controller_ready(
            _transaction("pair_grant_opened"), check_ready=check_ready, notify=lambda: None,
        )

    assert len(checks) == 4
    assert not any(call.member == "StartUnit" for call in bus.calls)
    assert sessions[0].closed and sessions[0]._loop.is_closed()


@pytest.mark.parametrize("phase", ["pair_grant_intent", "prepared"])
def test_wrong_transaction_phase_is_rejected_before_session_or_notification(phase, monkeypatch):
    bus = DelayedReadyBus()
    manager, sessions = _manager(bus, monkeypatch)
    notifications = []

    with pytest.raises(UnitOperationFailed):
        manager.confirm_controller_ready(
            _transaction(phase), check_ready=lambda: None,
            notify=lambda: notifications.append(True),
        )

    assert sessions == []
    assert bus.calls == []
    assert notifications == []


def test_start_bridge_refuses_before_controller_ready_without_session_or_start():
    bus = ReadyThenStartBus()
    factory_calls = []

    def factory():
        factory_calls.append(True)
        return FakeSystemdBusSession(bus=bus)

    manager = BootstrapNarrowingManager(
        job_timeout_seconds=0.5, session_factory=factory,
    )
    with pytest.raises(UnitOperationFailed, match="READY barrier"):
        manager._run_owned_start(
            UnitKey.AUDITD, expected_owner=OWNER, check_start=lambda: None,
        )

    assert factory_calls == []
    assert bus.calls == []
    assert not bus.started


def test_confirmed_controller_barrier_allows_private_real_start_bridge(monkeypatch):
    bus = ReadyThenStartBus()
    manager, sessions = _manager(bus, monkeypatch)
    manager.confirm_controller_ready(
        _transaction("pair_grant_opened"), check_ready=lambda: None,
        notify=lambda: None,
    )
    assert manager._controller_ready_confirmed

    manager._run_owned_start(
        UnitKey.AUDITD, expected_owner=OWNER, check_start=lambda: None,
    )

    assert bus.started
    assert sum(call.member == "StartUnit" for call in bus.calls) == 1
    assert len(sessions) == 2
    assert all(session.closed and session._loop.is_closed() for session in sessions)


@pytest.mark.parametrize("failure", ["exception", "non-none"])
def test_uncertain_notification_is_never_retried(failure, monkeypatch):
    bus = ReadyThenStartBus()
    manager, sessions = _manager(bus, monkeypatch)
    notifications = []

    def notify():
        notifications.append(True)
        if failure == "exception":
            raise RuntimeError("notification transport uncertain")
        return False

    expected = RuntimeError if failure == "exception" else UnitOperationFailed
    with pytest.raises(expected):
        manager.confirm_controller_ready(
            _transaction("pair_grant_opened"), check_ready=lambda: None, notify=notify,
        )
    with pytest.raises(UnitOperationFailed, match="READY context"):
        manager.confirm_controller_ready(
            _transaction("pair_grant_opened"), check_ready=lambda: None,
            notify=lambda: notifications.append(True),
        )

    assert notifications == [True]
    assert sessions == []
    assert bus.calls == []
    assert not manager._controller_ready_confirmed


def test_ready_confirmation_cleanup_failure_does_not_set_confirmed(monkeypatch):
    bus = ReadyThenStartBus()
    manager, sessions = _manager(bus, monkeypatch)

    def failed_disconnect():
        bus.disconnected = True
        raise OSError("synthetic disconnect failure")

    bus.disconnect = failed_disconnect
    with pytest.raises(UnitOperationFailed, match="session cleanup failed"):
        manager.confirm_controller_ready(
            _transaction("pair_grant_opened"), check_ready=lambda: None,
            notify=lambda: None,
        )

    assert sessions[0].closed and sessions[0]._loop.is_closed()
    assert not manager._controller_ready_confirmed
    assert any(call.member == "GetAll" for call in bus.calls)


def test_active_controller_with_job_pending_retries_until_idle(monkeypatch):
    observed_states = []

    def pending_job(interface, count, properties):
        if interface == "org.freedesktop.systemd1.Unit":
            observed_states.append((
                properties["ActiveState"].value,
                properties["SubState"].value,
                count,
            ))
            if count <= 2:
                properties["Job"] = Variant(
                    "(uo)", [91, "/org/freedesktop/systemd1/job/91"],
                )
        return properties

    bus = ReadyThenStartBus()
    bus.phase = "ready"
    bus.mutate = pending_job
    manager, sessions = _manager(bus, monkeypatch)
    manager.confirm_controller_ready(
        _transaction("pair_grant_opened"), check_ready=lambda: None,
        notify=lambda: None,
    )

    assert bus.unit_calls == 4
    assert bus.service_calls == 4
    assert observed_states == [("active", "running", count) for count in range(1, 5)]
    assert manager._controller_ready_confirmed
    assert len(sessions) == 1 and sessions[0].closed
    assert not any(call.member == "StartUnit" for call in bus.calls)
