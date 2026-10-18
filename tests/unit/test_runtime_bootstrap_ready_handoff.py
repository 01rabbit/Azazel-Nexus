"""Supervisor ordering with the real READY observer and owned start bridge.

Publication, admission and containment are synthetic; this is not live systemd.
"""

import pytest

from azazel_nexus_runtime.units import UnitKey, UnitOperationFailed
import test_runtime_bootstrap as supervisor_tests
from test_runtime_bootstrap import Harness
from test_runtime_bootstrap_controller import IDENTITY, OWNER, PROFILE_DIGEST
from test_runtime_bootstrap_controller_ready import ReadyThenStartBus, _manager

evidence = supervisor_tests.evidence


@pytest.mark.parametrize("failure", [None, "owner", "pending"])
def test_supervisor_requires_real_ready_before_audit_intent_and_start(
    evidence, monkeypatch, failure,
):
    bus = ReadyThenStartBus()
    real, sessions = _manager(bus, monkeypatch)
    if failure == "owner":
        bus.owner_drift_at = 4
    elif failure == "pending":
        bus.ready_after = 10000
    h = Harness(evidence)
    phases = []
    advance = h.supervisor._advance_grant

    def record_phase(phase, **kwargs):
        phases.append(phase)
        if phase == "auditd_start_intent":
            assert real._controller_ready_confirmed
        return advance(phase, **kwargs)

    monkeypatch.setattr(h.supervisor, "_advance_grant", record_phase)

    def bind_publication(transaction, approval):
        # Only publication is modelled. The READY observer and bridge are real.
        real._controller_binding = (IDENTITY, OWNER, PROFILE_DIGEST)
        real._controller_grant = transaction

    h.manager.open_pair_after_publish = bind_publication
    h.manager.confirm_controller_ready = real.confirm_controller_ready
    start = h.manager.start_and_wait

    def start_after_ready(unit, *, transaction, check_start):
        assert real._controller_ready_confirmed
        if unit is UnitKey.AUDITD:
            real._run_owned_start(unit, expected_owner=OWNER, check_start=check_start)
        return start(unit, transaction=transaction, check_start=check_start)

    h.manager.start_and_wait = start_after_ready
    if failure is None:
        h.supervisor.run()
        assert "auditd_start_intent" in phases
        assert bus.started
        assert sum(call.member == "StartUnit" for call in bus.calls) == 1
    else:
        with pytest.raises((UnitOperationFailed, TimeoutError)):
            h.supervisor.run()
        assert "auditd_start_intent" not in phases
        assert not bus.started
        assert not real._controller_ready_confirmed
        assert not any(op == "start_and_wait" for op, _ in h.manager.calls)
    assert all(h.manager.masked.values()) and all(h.manager.inactive.values())
    assert all(session.closed and session._loop.is_closed() for session in sessions)
