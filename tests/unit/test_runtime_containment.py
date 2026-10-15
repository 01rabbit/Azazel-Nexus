"""Synthetic observations only; no running systemd service is controlled."""

from types import SimpleNamespace

import pytest

from azazel_nexus.activation import CORE_UNITS, UnitState
from azazel_nexus.audit import AuditLedger
from azazel_nexus.generation import GenerationStore
from azazel_nexus_runtime.activated import (
    ActivationDaemon,
    ManagedUnitController,
    RollbackFailed,
    _run_once,
)
from azazel_nexus_runtime.systemd_bus import SystemdUnitCalls
from azazel_nexus_runtime.units import DbusUnitManager, RecordingUnitManager, UnitOperationFailed

NOW = "2026-10-13T00:00:00Z"
UNIT = "azazel-auditd.service"


@pytest.mark.parametrize("state", [
    "inactive", "active", "activating", "deactivating", "reloading",
    "failed", "maintenance", "refreshing", "unknown",
])
def test_only_positive_inactive_state_is_containment_evidence(state):
    def exchange(_interface, member, *_args, **_kwargs):
        if member == "GetUnit":
            return SimpleNamespace(signature="o", body=[
                "/org/freedesktop/systemd1/unit/azazel_2dauditd_2eservice"
            ])
        return SimpleNamespace(signature="v", body=[SimpleNamespace(value=state)])

    manager = DbusUnitManager(SystemdUnitCalls(exchange))
    if state == "unknown":
        with pytest.raises(UnitOperationFailed):
            manager.is_inactive(UNIT)
    else:
        assert manager.is_inactive(UNIT) is (state == "inactive")


@pytest.mark.parametrize("answer", [None, 0, 1, "inactive", [], {}])
def test_invalid_inactivity_reply_refuses(answer):
    with pytest.raises(UnitOperationFailed):
        DbusUnitManager(lambda *_: answer).is_inactive(UNIT)


class IndependentProcessState(RecordingUnitManager):
    """Mask changes file state, never our independent process observation."""

    def __init__(self, observation):
        super().__init__(d.name for d in CORE_UNITS)
        self.observation = observation

    def is_inactive(self, unit):
        if unit != UNIT:
            return True
        if self.observation == "error":
            raise UnitOperationFailed("state unavailable")
        return self.observation


@pytest.mark.parametrize("observation", [False, None, "error"])
@pytest.mark.parametrize("path", ["remask", "rollback", "narrow", "policy"])
def test_mask_without_inactivity_never_reports_containment(tmp_path, observation, path):
    manager = IndependentProcessState(observation)
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    daemon = ActivationDaemon(GenerationStore(tmp_path / "generations"), ledger, manager)
    units = ManagedUnitController(manager)
    if path == "remask":
        failures = daemon._remask_all(
            now=NOW, actor="test", event_type="test.remask", error_type="test"
        )
        assert failures == [f"{UNIT}: UnitOperationFailed"]
    elif path == "rollback":
        units.widened.append(UNIT)
        with pytest.raises(RollbackFailed):
            daemon._roll_back(units, now=NOW, actor="test", outcome=None)
        event = list(ledger)[0].event
        assert event["masked_again"] == []
        assert any(UNIT in item for item in event["could_not_mask"])
    elif path == "narrow":
        with pytest.raises(RollbackFailed):
            daemon._narrow_everything(now=NOW, actor="test", after=[UNIT])
        assert any(UNIT in item for item in list(ledger)[0].event["still_unreachable"])
    else:
        with pytest.raises(UnitOperationFailed):
            units._mask(UNIT)
    assert manager.state(UNIT) is UnitState.MASKED
    assert all(method == "mask" for method, _unit in manager.calls)


def test_positive_inactivity_allows_observed_narrowing(tmp_path):
    manager = IndependentProcessState(True)
    daemon = ActivationDaemon(
        GenerationStore(tmp_path / "generations"), AuditLedger(tmp_path / "audit.jsonl"), manager
    )
    assert daemon._remask_all(
        now=NOW, actor="test", event_type="test.remask", error_type="test"
    ) == []


def test_unexpected_grant_emergency_path_checks_inactivity(tmp_path, monkeypatch):
    manager = IndependentProcessState(True)

    def unexpected_grant(_self, **_kwargs):
        manager.observation = False
        return SimpleNamespace(granted=(UNIT,))

    monkeypatch.setattr(ActivationDaemon, "activate", unexpected_grant)
    with pytest.raises(RuntimeError, match=f"{UNIT}: UnitOperationFailed"):
        _run_once(manager=manager, root=tmp_path, now=NOW, actor="test")
    assert manager.state(UNIT) is UnitState.MASKED
    assert all(method == "mask" for method, _unit in manager.calls)
