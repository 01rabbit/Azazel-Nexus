"""#251 L-2: a pass that cannot be recorded, or whose READY fails, leaves no grant.

Same fake manager, temporary root and in-memory key as
``test_runtime_activation_pass.py`` (whose ``world`` fixture is reused).
"""

from __future__ import annotations

import json

import pytest

from azazel_nexus.activation import CORE_UNITS, UnitState
from azazel_nexus.audit import AuditChainBroken, AuditLedger, AuditUnavailable
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


# -- a tampered last record refuses the writer's append (#433) -----------------


def _flip_last_hash(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[-1])
    h = record["event_hash"]
    record["event_hash"] = h[:-1] + ("0" if h[-1] != "0" else "1")
    lines[-1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_a_pass_over_a_tampered_last_record_appends_nothing_and_grants_nothing(world):
    world.run()
    _flip_last_hash(world.ledger_path)
    before = world.ledger_path.read_bytes()

    # The refusal is the same AuditChainBroken a torn last line already gave.
    # The masks come before the record that cannot be written, so containment
    # has run by the time it surfaces.
    with pytest.raises(AuditChainBroken):
        world.run()

    assert world.ledger_path.read_bytes() == before
    assert _all_masked(world)
    assert world.markers() is None


def test_a_torn_last_line_gives_the_same_refusal_and_containment(world):
    """The pre-existing case the tampered-hash one is compared against."""
    world.run()
    with world.ledger_path.open("ab") as handle:
        handle.write(b'{"sequence": 99, "pre')
    before = world.ledger_path.read_bytes()

    with pytest.raises(AuditChainBroken):
        world.run()

    assert world.ledger_path.read_bytes() == before
    assert _all_masked(world)
    assert world.markers() is None


def test_a_tail_tamper_during_judgement_leaves_every_unit_masked_and_no_grant(world, monkeypatch):
    """#433: AuditChainBroken mid-loop narrows like AuditUnavailable does."""
    original = AuditLedger.append
    seen = {"granted": 0}

    def append(self, event, *args, **kwargs):
        if event.get("event_type") == "activation.unit_granted":
            seen["granted"] += 1
            if seen["granted"] == 2:
                _flip_last_hash(self.path)
        return original(self, event, *args, **kwargs)

    monkeypatch.setattr(AuditLedger, "append", append)
    with pytest.raises((AuditChainBroken, RuntimeError)):
        world.run()

    assert seen["granted"] >= 2
    assert _all_masked(world)
    assert world.markers() is None
