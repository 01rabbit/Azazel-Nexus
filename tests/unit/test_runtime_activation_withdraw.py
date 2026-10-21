"""#251 L-2: a pass that cannot be recorded, or whose READY fails, leaves no grant.

Same fake manager, temporary root and in-memory key as
``test_runtime_activation_pass.py`` (whose ``world`` fixture is reused).
"""

from __future__ import annotations

import pytest

from azazel_nexus.activation import CORE_UNITS, UnitState
from azazel_nexus.audit import AuditLedger, AuditUnavailable
from azazel_nexus_runtime import activated, systemd_notify
from azazel_nexus_runtime.units import UnitOperationFailed

from test_runtime_activation_pass import NOW, SCOPE, world  # noqa: F401 - fixture


def _all_masked(world):
    return all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)


def _withdraw(world):
    activated._notify_ready_or_withdraw(world.manager, world.root, now=NOW, actor="test")


def test_an_unappendable_final_record_removes_markers_and_remasks(world, monkeypatch):
    original = AuditLedger.append

    def append(self, event, *args, **kwargs):
        if event.get("event_type") == "activation.inputs_incomplete":
            assert world.markers() == list(SCOPE)  # written, then withdrawn
            raise AuditUnavailable("synthetic")
        return original(self, event, *args, **kwargs)

    monkeypatch.setattr(AuditLedger, "append", append)
    with pytest.raises(RuntimeError, match="activation pass record could not be appended"):
        world.run()
    assert _all_masked(world)
    assert world.markers() is None


def test_a_failure_assembling_the_final_record_removes_markers_and_remasks(world, monkeypatch):
    """Not only the append: anything between the markers and the record withdraws."""
    from azazel_nexus_runtime.activation_pass import PassInputs

    def broken(self):
        raise ValueError("synthetic")

    monkeypatch.setattr(PassInputs, "missing", broken)
    with pytest.raises(RuntimeError, match="activation pass record could not be appended"):
        world.run()
    assert _all_masked(world)
    assert world.markers() is None
    assert all(e["event_type"] != "activation.inputs_incomplete" for e in world.events())


@pytest.mark.parametrize("failing", ["ready", "barrier"])
def test_a_failed_readiness_notification_withdraws_and_is_recorded(world, monkeypatch, failing):
    outcome = world.run()
    assert sorted(outcome.granted) == list(SCOPE)
    assert world.markers() == list(SCOPE)

    def refuse():
        raise UnitOperationFailed("systemd notification refused")

    monkeypatch.setattr(systemd_notify, "notify_ready",
                        refuse if failing == "ready" else lambda: None)
    monkeypatch.setattr(systemd_notify, "notify_barrier", refuse)
    with pytest.raises(RuntimeError, match="readiness notification unavailable"):
        _withdraw(world)
    assert _all_masked(world)
    assert world.markers() is None
    assert world.events()[-1] == {"event_type": "activation.readiness_unconfirmed",
                                  "occurred_at": NOW, "actor": "test"}
    from azazel_nexus_runtime.activation_cli import FLOOR_EVENTS
    assert "activation.readiness_unconfirmed" not in FLOOR_EVENTS  # no floor recorded


def test_an_unwritable_ledger_still_withdraws_after_a_failed_readiness(world, monkeypatch):
    world.run()
    before = world.events()

    def refuse(*_args, **_kwargs):
        raise UnitOperationFailed("systemd notification refused")

    def unavailable(self, event, *args, **kwargs):
        raise AuditUnavailable("synthetic")

    monkeypatch.setattr(systemd_notify, "notify_ready", refuse)
    monkeypatch.setattr(AuditLedger, "append", unavailable)
    with pytest.raises(RuntimeError, match="readiness notification unavailable"):
        _withdraw(world)
    monkeypatch.undo()
    assert world.events() == before
    assert _all_masked(world)
    assert world.markers() is None


def test_a_sent_readiness_notification_keeps_the_grants(world, monkeypatch):
    world.run()
    before = world.events()
    monkeypatch.setattr(systemd_notify, "notify_ready", lambda: None)
    monkeypatch.setattr(systemd_notify, "notify_barrier", lambda: None)
    _withdraw(world)
    assert world.markers() == list(SCOPE)
    assert world.events() == before
