"""Capability observation, durable deduplication and audit-before-publication."""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime.mio_entryd import MioEntryService
from azazel_nexus_runtime.mio_capability import read_capability
from azazel_nexus_runtime.mio_router import MioRouter

from azazel_nexus import model_admission
from azazel_nexus.audit import AuditChainBroken, AuditUnavailable
from azazel_nexus.mio_profile import MioProfile


@pytest.fixture
def owner(tmp_path, monkeypatch):
    from azazel_nexus_runtime import mio_router
    monkeypatch.setattr(mio_router, "mio_state_dir", lambda: tmp_path)
    time = [1800000000.0]
    router = MioRouter(clock=lambda: datetime.fromtimestamp(time[0], UTC).isoformat())
    service = MioEntryService(router=router, profile_reader=lambda: MioProfile.CORE,
                              clock=lambda: time[0], wall_clock=lambda: time[0])
    service.local.observe = lambda: "local_unavailable"
    service.remote.observe = lambda: "remote_unavailable"
    return service, time


def transitions(service):
    return [item.event for item in service.router.ledger
            if item.event["event_type"] == "mio.capability.transition"]


def test_read_is_pure_and_unchanged_reconciliation_writes_nothing(owner):
    service, time = owner
    for _ in range(3):
        assert service.capability()["state"] == "CORE"
    assert not service.router.ledger.path.exists()
    service.reconcile_capability()
    before = service.router.ledger.path.read_bytes()
    for _ in range(3):
        time[0] += 10
        service.capability()
        service.reconcile_capability()
    assert service.router.ledger.path.read_bytes() == before
    assert transitions(service)[0]["from"] is None


def test_each_changed_reason_records_once_even_at_same_state(owner):
    service, time = owner
    service.reconcile_capability()
    service._profile_reader = lambda: MioProfile.FASTEST_PERMITTED
    service.local.observe = lambda: "local_not_admitted"
    time[0] += 10
    service.reconcile_capability()
    service.reconcile_capability()
    events = transitions(service)
    assert len(events) == 2
    assert events[1]["from"] == events[1]["to"] == "CORE"
    assert events[1]["reasons"] == {
        "profile": "FULL", "resource": "core_reserve_unmeasured",
        "trust": "not-checked", "topology": "no_verified_egress",
        "health": {"local": "not_admitted", "remote": "unavailable"},
    }
    assert model_admission.LOCAL_MODEL_ADMISSION_ENABLED is False


def test_restart_uses_last_transition_not_ledger_head(owner):
    service, time = owner
    service.reconcile_capability()
    service.router._record({"event_type": "mio.route.unrelated"})
    restarted = MioEntryService(router=service.router, profile_reader=lambda: MioProfile.CORE,
                                clock=lambda: time[0], wall_clock=lambda: time[0])
    restarted.local.observe = service.local.observe
    restarted.remote.observe = service.remote.observe
    time[0] += 10
    restarted.reconcile_capability()
    assert len(transitions(service)) == 1


def test_flapping_is_sampled_at_most_once_per_ten_seconds(owner):
    service, time = owner
    service.reconcile_capability()
    for i in range(9):
        service.local.observe = lambda: "local_not_admitted"
        time[0] += 1
        service.reconcile_capability()
    assert len(transitions(service)) == 1
    time[0] += 1
    service.reconcile_capability()
    assert len(transitions(service)) == 2


@pytest.mark.parametrize("profile", [None, {}, "FULL", MioProfile.FASTEST_PERMITTED])
def test_absent_malformed_inputs_are_core_with_independent_reasons(profile):
    reading = read_capability(profile, {}, None).as_dict()
    assert reading["state"] == "CORE"
    assert reading["reasons"]["health"] == {
        "local": "invalid_observation", "remote": "invalid_observation"}
    assert reading["reasons"]["resource"] == "core_reserve_unmeasured"
    assert reading["reasons"]["trust"] == "not-checked"
    assert reading["reasons"]["topology"] == "no_verified_egress"


def test_failed_read_does_not_mask_other_dimension(owner):
    service, _ = owner
    def broken():
        raise ValueError("private parser details")
    service._profile_reader = broken
    service.local.observe = broken
    reading = service.capability()
    assert reading["reasons"]["profile"] == "CORE"
    assert reading["reasons"]["health"]["local"] == "invalid_observation"
    assert reading["reasons"]["health"]["remote"] == "unavailable"


def test_audit_failure_never_advances_comparison_basis_or_dispatches(owner, monkeypatch):
    service, _ = owner
    original = service.router._record
    def fail(event):
        raise AuditUnavailable("full")
    monkeypatch.setattr(service.router, "_record", fail)
    with pytest.raises(AuditUnavailable):
        service.handle(SimpleNamespace(arguments={"deadline_ms": 1000,
                                                  "privacy_class": "P0-public"}))
    assert service._last_capability is None
    monkeypatch.setattr(service.router, "_record", original)
    service.reconcile_capability()
    assert len(transitions(service)) == 1


def test_broken_history_refused_on_restart(owner):
    service, time = owner
    service.reconcile_capability()
    raw = service.router.ledger.path.read_text().replace('"CORE"', '"FULL"')
    service.router.ledger.path.write_text(raw)
    with pytest.raises(AuditChainBroken):
        MioEntryService(router=service.router, clock=lambda: time[0], wall_clock=lambda: time[0])
