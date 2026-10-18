"""Loaded-mask observations use the manager's owned, read-only session."""

import pytest

from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.bootstrap_systemd_profile import (
    _DEBIAN13_V257_UNIT_PATH,
    observe_bootstrap_systemd_profile,
)
from azazel_nexus_runtime.units import UnitKey, UnitOperationFailed
from test_runtime_bootstrap_manager import FakeSystemdBusSession
from test_runtime_bootstrap_masked import FakeBus, Variant


class TrackedBus(FakeBus):
    disconnected = False

    def disconnect(self):
        self.disconnected = True


def _manager(bus, timeout=5.0):
    session = FakeSystemdBusSession(bus=bus)
    session.bootstrap_profile = lambda: observe_bootstrap_systemd_profile(
        version="257.13-1~deb13u1", unit_path=list(_DEBIAN13_V257_UNIT_PATH),
    )
    return BootstrapNarrowingManager(
        job_timeout_seconds=timeout, session_factory=lambda: session,
    ), session


def test_manager_observes_both_loaded_masks_and_closes_owned_session():
    bus = TrackedBus()
    manager, session = _manager(bus)
    observed = manager.inspect_masked_pair()
    assert tuple(unit for unit, _path in observed.fragments) == (
        UnitKey.AUDITD, UnitKey.COMMISSIOND,
    )
    assert {message.member for message in bus.calls} == {
        "GetNameOwner", "GetUnit", "GetAll",
    }
    assert bus.disconnected and session.closed and session._loop.is_closed()


@pytest.mark.parametrize("failure", ["unmasked", "owner", "timeout", "profile"])
def test_manager_mask_observation_failure_still_cleans_up(failure):
    def mutate(_number, _name, properties):
        properties["LoadState"] = Variant("s", "loaded")
        return properties

    bus = TrackedBus(
        mutate=mutate if failure == "unmasked" else None,
        owner_changes=failure == "owner",
        hang_member="GetAll" if failure == "timeout" else None,
    )
    # Only the hanging GetAll case needs a short bound to reach its deadline.
    manager, session = _manager(bus, 0.05 if failure == "timeout" else 5.0)
    if failure == "profile":
        session.bootstrap_profile = lambda: None
    with pytest.raises(UnitOperationFailed):
        manager.inspect_masked_pair()
    if failure == "profile":
        assert bus.calls == []
    assert bus.disconnected and session.closed and session._loop.is_closed()
