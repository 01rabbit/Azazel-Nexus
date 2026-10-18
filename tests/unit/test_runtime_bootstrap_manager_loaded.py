"""Synchronous manager ownership tests for loaded bootstrap inspection."""

import asyncio

import pytest

import test_runtime_bootstrap_loaded as loaded_fixtures
from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.bootstrap_systemd_profile import (
    _DEBIAN13_V257_UNIT_PATH,
    SystemdBootstrapProfile,
    observe_bootstrap_systemd_profile,
)
from azazel_nexus_runtime.units import UnitKey, UnitOperationFailed
from test_runtime_bootstrap_manager import FakeSystemdBusSession


class TrackedBus(loaded_fixtures.FakeBus):
    def __init__(self, unit, *, hang_get_all=False):
        super().__init__(unit)
        self.disconnected = False
        self.hang_get_all = hang_get_all

    async def call(self, message):
        if self.hang_get_all and message.member == "GetAll":
            self.calls.append(message)
            await asyncio.Future()
        return await super().call(message)

    def disconnect(self):
        self.disconnected = True


def _session(unit=UnitKey.AUDITD, *, hang_get_all=False):
    bus = TrackedBus(unit, hang_get_all=hang_get_all)
    session = FakeSystemdBusSession(bus=bus)
    session.profile_calls = 0
    session.bootstrap_profile = lambda: _supported_profile(session)
    return session, bus


def _supported_profile(session):
    session.profile_calls += 1
    return observe_bootstrap_systemd_profile(
        version="257.13-1~deb13u1",
        unit_path=list(_DEBIAN13_V257_UNIT_PATH),
    )


def _manager_for(session, *, timeout=5.0):
    return BootstrapNarrowingManager(
        job_timeout_seconds=timeout, session_factory=lambda: session
    )


@pytest.mark.parametrize("unit", [UnitKey.AUDITD, UnitKey.COMMISSIOND])
def test_inspect_loaded_uses_real_inspector_and_closes_owned_loop(unit):
    session, bus = _session(unit)
    manager = _manager_for(session)

    result = manager.inspect_loaded(
        unit,
        expected_owner=loaded_fixtures.OWNER,
        expected_dependencies=loaded_fixtures._dependencies(unit),
        expected_service_settings=loaded_fixtures._service_settings(),
    )

    assert result.unit is unit
    assert result.owner == loaded_fixtures.OWNER
    assert result.fingerprint.startswith("sha256:")
    assert [call.member for call in bus.calls] == [
        "GetNameOwner", "GetUnit", "GetAll", "GetAll", "GetNameOwner",
        "GetUnit", "GetAll", "GetAll", "GetNameOwner",
    ]
    assert bus.disconnected
    assert session.closed
    assert session._loop.is_closed()
    assert session.profile_calls == 1


@pytest.mark.parametrize("unit", ["auditd", "azazel-auditd.service", None, 7])
def test_invalid_unit_is_rejected_before_session_factory(unit):
    factory_calls = []

    def factory():
        factory_calls.append(True)
        raise AssertionError("invalid unit reached session factory")

    manager = BootstrapNarrowingManager(
        job_timeout_seconds=0.05, session_factory=factory
    )
    with pytest.raises(UnitOperationFailed):
        manager.inspect_loaded(
            unit,
            expected_owner=loaded_fixtures.OWNER,
            expected_dependencies=loaded_fixtures._dependencies(),
            expected_service_settings=loaded_fixtures._service_settings(),
        )
    assert factory_calls == []


def test_invalid_expected_service_policy_still_closes_created_session():
    session, bus = _session()

    with pytest.raises(UnitOperationFailed):
        _manager_for(session).inspect_loaded(
            UnitKey.AUDITD,
            expected_owner=loaded_fixtures.OWNER,
            expected_dependencies=loaded_fixtures._dependencies(),
            expected_service_settings={},
        )

    assert bus.calls == []
    assert bus.disconnected
    assert session.closed
    assert session._loop.is_closed()


def test_unsupported_systemd_profile_refuses_before_inspecting_unit():
    session, bus = _session()

    def unsupported_profile():
        session.profile_calls += 1
        raise UnitOperationFailed("unsupported systemd version profile")

    session.bootstrap_profile = unsupported_profile
    with pytest.raises(UnitOperationFailed, match="unsupported systemd version"):
        _manager_for(session).inspect_loaded(
            UnitKey.AUDITD,
            expected_owner=loaded_fixtures.OWNER,
            expected_dependencies=loaded_fixtures._dependencies(),
            expected_service_settings=loaded_fixtures._service_settings(),
        )

    assert session.profile_calls == 1
    assert bus.calls == []
    assert bus.disconnected
    assert session.closed
    assert session._loop.is_closed()


def test_malformed_profile_result_refuses_before_inspecting_unit():
    session, bus = _session()
    session.bootstrap_profile = lambda: object()

    with pytest.raises(UnitOperationFailed, match="profile was not admitted"):
        _manager_for(session).inspect_loaded(
            UnitKey.AUDITD,
            expected_owner=loaded_fixtures.OWNER,
            expected_dependencies=loaded_fixtures._dependencies(),
            expected_service_settings=loaded_fixtures._service_settings(),
        )

    assert bus.calls == []
    assert bus.disconnected
    assert session.closed
    assert session._loop.is_closed()


def test_unreviewed_typed_profile_refuses_before_inspecting_unit():
    session, bus = _session()
    session.bootstrap_profile = lambda: SystemdBootstrapProfile(
        name="unreviewed-profile",
        version="257.13-1~deb13u1",
        unit_path=("/opt/vendor/systemd",),
    )

    with pytest.raises(UnitOperationFailed, match="unsupported systemd unit search path"):
        _manager_for(session).inspect_loaded(
            UnitKey.AUDITD,
            expected_owner=loaded_fixtures.OWNER,
            expected_dependencies=loaded_fixtures._dependencies(),
            expected_service_settings=loaded_fixtures._service_settings(),
        )

    assert bus.calls == []
    assert bus.disconnected
    assert session.closed
    assert session._loop.is_closed()


@pytest.mark.parametrize("failure", ["timeout", "error"])
def test_inspection_timeout_or_error_closes_owned_session(failure):
    if failure == "timeout":
        session, bus = _session(hang_get_all=True)
    else:
        session, bus = _session()

        async def fail_call(_message):
            raise RuntimeError("private transport detail")

        bus.call = fail_call

    with pytest.raises(UnitOperationFailed):
        _manager_for(session, timeout=0.01).inspect_loaded(
            UnitKey.AUDITD,
            expected_owner=loaded_fixtures.OWNER,
            expected_dependencies=loaded_fixtures._dependencies(),
            expected_service_settings=loaded_fixtures._service_settings(),
        )

    assert bus.disconnected
    assert session.closed
    assert session._loop.is_closed()


@pytest.mark.parametrize("method", ["start_and_wait", "unmask"])
def test_inspection_does_not_enable_widening_operations(method):
    factory_calls = []
    session, bus = _session()

    def factory():
        factory_calls.append(True)
        assert len(factory_calls) == 1, "widening reached session factory"
        return session

    manager = BootstrapNarrowingManager(
        job_timeout_seconds=5.0, session_factory=factory
    )
    manager.inspect_loaded(
        UnitKey.AUDITD,
        expected_owner=loaded_fixtures.OWNER,
        expected_dependencies=loaded_fixtures._dependencies(),
        expected_service_settings=loaded_fixtures._service_settings(),
    )
    observed_calls = len(bus.calls)
    with pytest.raises(UnitOperationFailed, match="widening refused"):
        kwargs = {"transaction": None, "check_start": lambda: None} if method == "start_and_wait" else {}
        getattr(manager, method)(UnitKey.AUDITD, **kwargs)
    assert factory_calls == [True]
    assert len(bus.calls) == observed_calls


def test_each_inspection_uses_a_fresh_session():
    sessions = []
    buses = []

    def factory():
        session, bus = _session()
        sessions.append(session)
        buses.append(bus)
        return session

    manager = BootstrapNarrowingManager(
        job_timeout_seconds=5.0, session_factory=factory
    )
    for _ in range(2):
        manager.inspect_loaded(
            UnitKey.AUDITD,
            expected_owner=loaded_fixtures.OWNER,
            expected_dependencies=loaded_fixtures._dependencies(),
            expected_service_settings=loaded_fixtures._service_settings(),
        )

    assert len(sessions) == 2
    assert sessions[0] is not sessions[1]
    assert all(session.closed and session._loop.is_closed() for session in sessions)
    assert all(bus.disconnected for bus in buses)


@pytest.mark.parametrize("expected_owner", [None, "", ":1", ":1.2.extra", 7, True])
def test_invalid_expected_owner_is_rejected_before_session_factory(expected_owner):
    factory_calls = []

    def factory():
        factory_calls.append(True)
        raise AssertionError("invalid owner reached session factory")

    manager = BootstrapNarrowingManager(
        job_timeout_seconds=0.05, session_factory=factory
    )
    with pytest.raises(ValueError):
        manager.inspect_loaded(
            UnitKey.AUDITD,
            expected_owner=expected_owner,
            expected_dependencies=loaded_fixtures._dependencies(),
            expected_service_settings=loaded_fixtures._service_settings(),
        )
    assert factory_calls == []


def test_mismatched_enclosing_owner_closes_and_discards_owned_session():
    session, bus = _session()
    bus.owner = ":1.99"  # Transport pin differs from the enclosing transaction.
    bus._azazel_systemd_owner = ":1.99"

    with pytest.raises(UnitOperationFailed):
        _manager_for(session).inspect_loaded(
            UnitKey.AUDITD,
            expected_owner=loaded_fixtures.OWNER,
            expected_dependencies=loaded_fixtures._dependencies(),
            expected_service_settings=loaded_fixtures._service_settings(),
        )

    assert [call.member for call in bus.calls] == ["GetNameOwner"]
    assert bus.disconnected
    assert session.closed
    assert session._loop.is_closed()
