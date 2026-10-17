"""Exact systemd owner pins for bootstrap observers and manager entry points."""

from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.bootstrap_job_drain import BootstrapJobDrain
from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.units import UnitOperationFailed
from test_runtime_bootstrap_job_drain import FakeBus as JobFakeBus
from test_runtime_bootstrap_job_drain import run
from test_runtime_bootstrap_manager import FakeSystemdBusSession
from test_runtime_bootstrap_masked import FakeBus as MaskedFakeBus
from test_runtime_bootstrap_masked import Message, OWNER as MASKED_OWNER, _inspector
from test_runtime_bootstrap_manager_masked import _manager as make_masked_manager


class StringSubclass(str):
    pass


INVALID_OWNERS = [
    "", ":", ":1", ":1.", ":.1", ":1.2.extra", "1:2.3", ":-1.2",
    ":1.-2", StringSubclass(":1.2"), 1, True, [], {},
]


def _pinned_inspector(bus, expected_owner):
    from azazel_nexus_runtime.bootstrap_masked import BootstrapMaskedPairInspector

    return BootstrapMaskedPairInspector(
        bus=bus,
        message_factory=Message,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        timeout_seconds=0.2,
        expected_owner=expected_owner,
    )


@pytest.mark.parametrize("expected_owner", INVALID_OWNERS)
@pytest.mark.parametrize("observer", ["masked", "drain"])
def test_observers_reject_invalid_expected_owner_before_bus_calls(observer, expected_owner):
    if observer == "masked":
        bus = MaskedFakeBus()
        with pytest.raises(ValueError):
            _pinned_inspector(bus, expected_owner)
    else:
        bus = JobFakeBus()
        with pytest.raises(ValueError):
            BootstrapJobDrain(
                bus=bus,
                message_factory=lambda **values: SimpleNamespace(**values),
                message_type=SimpleNamespace(METHOD_RETURN=JobFakeBus.METHOD_RETURN),
                timeout_seconds=0.1,
                check_closed=lambda: None,
                expected_owner=expected_owner,
            )
    assert bus.calls == []


def test_owner_mismatch_refuses_before_masked_observation_calls():
    bus = MaskedFakeBus()
    with pytest.raises(UnitOperationFailed):
        run(_pinned_inspector(bus, ":1.99").inspect())
    assert [call.member for call in bus.calls] == ["GetNameOwner"]


def test_owner_mismatch_refuses_before_job_list_or_cancellation():
    bus = JobFakeBus([[]])
    drain = BootstrapJobDrain(
        bus=bus,
        message_factory=lambda **values: SimpleNamespace(**values),
        message_type=SimpleNamespace(METHOD_RETURN=JobFakeBus.METHOD_RETURN),
        timeout_seconds=0.1,
        check_closed=_always_closed,
        expected_owner=":1.99",
    )
    with pytest.raises(UnitOperationFailed):
        run(drain.drain())
    assert [call.member for call in bus.calls] == ["GetNameOwner"]


def test_matching_owner_succeeds_for_both_observers_and_none_keeps_legacy_behavior():
    masked_bus = MaskedFakeBus()
    assert run(_pinned_inspector(masked_bus, MASKED_OWNER).inspect()).owner == MASKED_OWNER
    assert run(_inspector(MaskedFakeBus()).inspect()).owner == ":1.42"

    for expected_owner in (JobFakeBus.OWNER, None):
        bus = JobFakeBus([[], []])
        drain = BootstrapJobDrain(
            bus=bus,
            message_factory=lambda **values: SimpleNamespace(**values),
            message_type=SimpleNamespace(METHOD_RETURN=JobFakeBus.METHOD_RETURN),
            timeout_seconds=0.1,
            check_closed=lambda: _async_none(),
            expected_owner=expected_owner,
        )
        assert run(drain.drain()) is None
        assert [call.member for call in bus.calls].count("ListJobs") == 2


async def _async_none():
    return None


@pytest.mark.parametrize("entrypoint", ["masked", "drain"])
def test_manager_forwards_matching_and_mismatching_owner_pin(entrypoint):
    if entrypoint == "masked":
        class TrackedMaskedBus(MaskedFakeBus):
            def disconnect(self):
                self.disconnected = True

        matching_bus = TrackedMaskedBus()
        manager, session = make_masked_manager(matching_bus)
        # The shared fixture's owner is :1.42.
        assert manager.inspect_masked_pair(expected_owner=":1.42").owner == ":1.42"
        mismatch_bus = TrackedMaskedBus()
        manager, session = make_masked_manager(mismatch_bus)
        with pytest.raises(UnitOperationFailed):
            manager.inspect_masked_pair(expected_owner=":1.99")
        assert [call.member for call in mismatch_bus.calls] == ["GetNameOwner"]
    else:
        for expected_owner, should_succeed in ((JobFakeBus.OWNER, True), (":1.99", False)):
            bus = JobFakeBus([[], []])
            session = FakeSystemdBusSession(bus=bus)
            manager = BootstrapNarrowingManager(
                job_timeout_seconds=0.1, session_factory=lambda: session,
            )
            if should_succeed:
                assert manager.drain_pending_jobs(
                    check_closed=_always_closed, expected_owner=expected_owner,
                ) is None
            else:
                with pytest.raises(UnitOperationFailed):
                    manager.drain_pending_jobs(
                        check_closed=_always_closed, expected_owner=expected_owner,
                    )
                assert [call.member for call in bus.calls] == ["GetNameOwner"]
            assert session.closed and session._loop.is_closed()


async def _always_closed():
    return None


@pytest.mark.parametrize("entrypoint", ["masked", "drain"])
@pytest.mark.parametrize("expected_owner", INVALID_OWNERS)
def test_manager_rejects_invalid_owner_before_opening_session(entrypoint, expected_owner):
    factory_calls = []

    def forbidden_factory():
        factory_calls.append(True)
        raise AssertionError("session factory must not run for invalid owner")

    manager = BootstrapNarrowingManager(
        job_timeout_seconds=0.1, session_factory=forbidden_factory,
    )
    with pytest.raises(ValueError):
        if entrypoint == "masked":
            manager.inspect_masked_pair(expected_owner=expected_owner)
        else:
            manager.drain_pending_jobs(
                check_closed=_always_closed, expected_owner=expected_owner,
            )
    assert factory_calls == []
