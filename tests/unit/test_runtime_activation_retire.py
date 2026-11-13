"""Approval retirement on an explicit operator revocation (stop contract).

A grant records the approval it was made under. Only a freshly loaded trust
snapshot that lists that approval's operator in `revoked` retires it: the
approval-sequence floor goes to approval_seq + 1, so the same approval is
refused for every unit it names. Expiry, health and evidence loss retire
nothing, and a retirement interrupted half way is resumed.
"""

from __future__ import annotations

import os
from dataclasses import replace
from types import SimpleNamespace

import pytest

from azazel_nexus.activation import CORE_UNITS, UnitState
from azazel_nexus.audit import AuditLedger
from azazel_nexus.operator_trust import OperatorTrust
from azazel_nexus_runtime import activated, activation_recheck, activation_retire
from azazel_nexus_runtime.activation_retire import (
    ACCEPTED, PENDING, RetireRefused, read_accepted_grant, retire_if_revoked,
    retirement_pending, write_accepted_grant,
)

from stop_helpers import CTX, ContextdModel, FakeClock, ModelManager, authority
from test_runtime_activation_contextd import CTX_SCOPE, ctx_world  # noqa: F401 - fixture
from test_runtime_activation_pass import NOW


def leaf(world):
    return world.root / "var/lib/azazel/state/activation"


@pytest.fixture
def stage(ctx_world):
    clock = FakeClock()
    model = ContextdModel(clock)
    manager = ModelManager(model, enabled=[d.name for d in CORE_UNITS])
    ctx_world.manager = manager
    outcome = activated._run_once(
        manager=manager, root=ctx_world.root, now=NOW, actor="test",
        producers=ctx_world.producers(), stop_authority=authority(model),
        clock=clock, sleep=clock.sleep)
    assert CTX in outcome.granted
    model.running = True
    manager.timeline.clear()
    return SimpleNamespace(world=ctx_world, clock=clock, model=model, manager=manager)


def revoked_trust(world, who="operator-a"):
    return OperatorTrust(dict(world.trust.public_keys), frozenset({who}))


def tools(world, trust, *, fail_raise=False):
    raise_floor = world.producers().raise_high_water

    def raising(value, *, now, skew_seconds):
        if fail_raise:
            raise RuntimeError("synthetic")
        return raise_floor(value, now=now, skew_seconds=skew_seconds)

    return dict(root=world.root, trust=trust, read_floor=lambda: world.high_water,
                raise_floor=raising, now=NOW, skew_seconds=300)


# -- the record of an accepted grant -------------------------------------------------------


def test_a_grant_records_the_approval_it_was_made_under_before_the_markers(ctx_world, monkeypatch):
    seen = []
    original = activated.write_grant_markers

    def watching(units, root):
        seen.append(read_accepted_grant(root))
        return original(units, root)

    monkeypatch.setattr(activated, "write_grant_markers", watching)
    outcome = ctx_world.run()
    [record] = seen
    assert record["operator"] == "operator-a" and record["approval_seq"] == 5
    assert record["approval_id"] == "approval-1"
    assert len(record["payload_sha256"]) == 64
    import hashlib
    assert record["payload_sha256"] == hashlib.sha256(ctx_world.payload).hexdigest()
    assert record["units"] == sorted(outcome.granted)
    info = (leaf(ctx_world) / ACCEPTED).stat()
    assert info.st_mode & 0o777 == 0o600 and info.st_nlink == 1


def test_a_grant_whose_record_cannot_be_written_is_withdrawn(ctx_world, monkeypatch):
    def refuse(*_a, **_k):
        raise RetireRefused("synthetic")

    monkeypatch.setattr(activated, "write_accepted_grant", refuse)
    with pytest.raises(RuntimeError, match="accepted approval could not be recorded"):
        ctx_world.run()
    assert ctx_world.markers() is None
    assert all(ctx_world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)


def test_records_that_are_loose_or_inconsistent_are_refused(ctx_world):
    ctx_world.run()
    path = leaf(ctx_world) / ACCEPTED
    path.chmod(0o644)
    with pytest.raises(RetireRefused):
        read_accepted_grant(ctx_world.root)
    path.chmod(0o600)
    path.write_text('{"schema":"x"}')
    with pytest.raises(RetireRefused):
        read_accepted_grant(ctx_world.root)
    path.write_text("not json")
    with pytest.raises(RetireRefused):
        read_accepted_grant(ctx_world.root)


def test_an_approval_sequence_that_cannot_be_advanced_is_refused(ctx_world):
    with pytest.raises(RetireRefused):
        write_accepted_grant(ctx_world.root, operator="operator-a", approval_seq=2**63 - 1,
                             approval_id="a", payload_sha256="0" * 64, units=[CTX])


# -- retirement ------------------------------------------------------------------------------


def test_an_explicitly_revoked_operator_retires_the_approval(stage):
    world = stage.world
    assert retire_if_revoked(**tools(world, revoked_trust(world))) == "retired"
    assert world.high_water.approval_seq == 6  # accepted 5 + 1
    assert world.high_water.security_epoch == 2 and world.high_water.generation == 1
    assert not (leaf(world) / ACCEPTED).exists() and not retirement_pending(world.root)
    # The same approval is refused afterwards for every unit it names.
    stage.model.running = False  # the next boot: nothing is running
    for unit in CORE_UNITS:
        stage.manager.mask(unit.name)
    outcome = world.run()
    assert outcome.granted == ()


def test_nothing_proves_a_revocation_but_an_explicit_entry(stage):
    world = stage.world
    # operator missing from the enrolled keys: refused by the verifier, not retired
    no_keys = OperatorTrust({}, frozenset())
    assert retire_if_revoked(**tools(world, no_keys)) == "none"
    # another operator revoked
    assert retire_if_revoked(**tools(world, revoked_trust(world, "operator-b"))) == "none"
    assert world.high_water.approval_seq == 5 and (leaf(world) / ACCEPTED).exists()


def test_the_production_wiring_retires_nothing_when_the_trust_store_fails(stage, monkeypatch):
    from azazel_nexus import operator_store

    def broken():
        raise RuntimeError("synthetic")

    monkeypatch.setattr(operator_store, "load_operator_trust", broken)
    assert activation_recheck.production_retirement()(root=stage.world.root, now=NOW) == "none"
    assert stage.world.high_water.approval_seq == 5


def test_an_interrupted_retirement_is_resumed_and_blocks_grants_meanwhile(stage):
    world = stage.world
    with pytest.raises(RetireRefused):
        retire_if_revoked(**tools(world, revoked_trust(world), fail_raise=True))
    assert retirement_pending(world.root) and world.high_water.approval_seq == 5
    assert (leaf(world) / PENDING).stat().st_mode & 0o777 == 0o600
    # the main pass grants nothing while a retirement is pending
    stage.model.running = False
    for unit in CORE_UNITS:
        stage.manager.mask(unit.name)
    assert world.run().granted == ()
    # the recheck resumes it, even when the trust no longer names the operator
    assert retire_if_revoked(**tools(world, OperatorTrust({}, frozenset()))) == "resumed"
    assert world.high_water.approval_seq == 6 and not retirement_pending(world.root)
    assert not (leaf(world) / ACCEPTED).exists()


def test_a_floor_that_is_not_confirmed_is_not_a_retirement(stage):
    world = stage.world
    kwargs = tools(world, revoked_trust(world))
    kwargs["raise_floor"] = lambda value, *, now, skew_seconds: value  # raises nothing
    with pytest.raises(RetireRefused, match="not confirmed"):
        retire_if_revoked(**kwargs)
    assert retirement_pending(world.root)


def test_a_floor_already_above_the_target_is_kept(stage):
    world = stage.world
    world.high_water = replace(world.high_water, approval_seq=9)
    assert retire_if_revoked(**tools(world, revoked_trust(world))) == "retired"
    assert world.high_water.approval_seq == 9


def test_without_a_record_there_is_nothing_to_retire(ctx_world):
    assert retire_if_revoked(**tools(ctx_world, revoked_trust(ctx_world))) == "none"


# -- what does not retire ----------------------------------------------------------------------


def test_expiry_or_lost_health_withdraws_but_retires_nothing(stage):
    world = stage.world
    world.healthy = False
    code = activation_recheck.run_recheck(
        manager=stage.manager, authority=authority(stage.model), root=world.root, now=NOW,
        producers=world.producers(), invocation_id="c" * 32,
        retirement=lambda **kw: retire_if_revoked(**tools(world, world.trust), **{}),
        clock=stage.clock, sleep=stage.clock.sleep)
    assert code == 0 and stage.manager.state(CTX) is UnitState.MASKED
    assert world.high_water.approval_seq == 5 and (leaf(world) / ACCEPTED).exists()
    # the condition returns: the same approval grants again
    world.healthy = True
    for unit in CORE_UNITS:
        stage.manager.mask(unit.name)
    assert CTX in world.run().granted


# -- inside the recheck -------------------------------------------------------------------------


def _recheck(stage, retirement):
    return activation_recheck.run_recheck(
        manager=stage.manager, authority=authority(stage.model), root=stage.world.root,
        now=NOW, producers=stage.world.producers(), invocation_id="c" * 32,
        retirement=retirement, clock=stage.clock, sleep=stage.clock.sleep)


def test_a_revoked_operator_is_withdrawn_and_retired_by_the_recheck(stage):
    world = stage.world
    trust = revoked_trust(world)
    world.trust = trust  # the verifier now refuses the operator too
    code = _recheck(stage, lambda **kw: retire_if_revoked(**tools(world, trust)))
    assert code == 0
    assert stage.manager.state(CTX) is UnitState.MASKED and stage.model.running is False
    assert world.high_water.approval_seq == 6
    kinds = [e["event_type"] for e in world.events()]
    assert "activation.grant_withdrawn" in kinds and "activation.approval_retired" in kinds


def test_a_retirement_that_fails_is_reported_and_the_withdrawal_still_happens(stage):
    world = stage.world
    world.healthy = False
    trust = revoked_trust(world)
    code = _recheck(stage, lambda **kw: retire_if_revoked(
        **tools(world, trust, fail_raise=True)))
    assert code == 1
    assert stage.manager.state(CTX) is UnitState.MASKED


def test_a_recheck_without_the_retirement_is_caught(stage):
    world = stage.world
    trust = revoked_trust(world)
    world.trust = trust
    _recheck(stage, lambda **kw: "none")  # the mutation: retirement dropped
    # The scenario above requires the floor to have moved to 6; it did not.
    assert world.high_water.approval_seq == 5
    assert (leaf(world) / ACCEPTED).exists()
