"""The P4 observe-baseline pass with a fake manager, a tmp root and ephemeral keys (#206).

`docs/activation-observe-baseline.md` §3.6 and §5. Every producer is an
in-memory fixture passed through `_run_once`'s test seam; the approval is
signed here with a key that exists only for the test, and verified by the
real v2 verifier against the context the pass collected.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from nacl.signing import SigningKey

from azazel_nexus.activation import CORE_UNITS, UnitState
from azazel_nexus.activation_approval_v2 import (
    ObserveBaselineContext,
    observe_baseline_payload,
    verify_observe_baseline_approval,
)
from azazel_nexus.activation_policy import ACTIVATION_POLICY_SCHEMA, decode_activation_policy
from azazel_nexus.audit import AuditLedger
from azazel_nexus.bootstrap_deployment import BootstrapDeployment, declared_node_digest
from azazel_nexus.commissioning_evidence import CommissioningEvidence
from azazel_nexus.generation import GenerationStore
from azazel_nexus.observe_baseline import build_observe_baseline, evidence_commissioning_digest
from azazel_nexus.operator_trust import ApprovalPurpose, ApprovalRefused, OperatorTrust, approval_message
from azazel_nexus_runtime import activated, activation_markers, activation_pass
from azazel_nexus_runtime.activation_high_water import HighWater, HighWaterRefused
from azazel_nexus_runtime.activation_pass import (
    ALWAYS_MISSING,
    PassProducers,
)
from azazel_nexus_runtime.node_config import DeclaredNode
from azazel_nexus_runtime.units import RecordingUnitManager

NOW = "2026-10-21T00:00:00Z"
DIGEST = "sha256:" + "d" * 64
SCOPE = (
    "azazel-edge-intaked.service",
    "azazel-edge-probed.service",
    "azazel-incident-explaind.service",
    "azazel-knowledge-lited.service",
    "azazel-mio-entryd.service",
)
NODE = "private-node-a"
EVIDENCE_PAYLOAD = b'{"private-commissioning-proposal":true}'


def make_policy(units=SCOPE, operators=("operator-a",), skew=300):
    raw = json.dumps({
        "schema": ACTIVATION_POLICY_SCHEMA, "operators": sorted(operators),
        "max_lease_seconds": 72 * 3600, "units": sorted(units),
        "state_floors": {"audit_bytes": 1, "audit_inodes": 1,
                         "bootstrap_bytes": 1, "bootstrap_inodes": 1},
        "resource_floors": {"min_mission_available_mib": 1, "min_online_logical_cpus": 1,
                            "min_usable_memory_mib": 1},
        "max_clock_skew_seconds": skew,
    }, sort_keys=True, separators=(",", ":")).encode()
    return decode_activation_policy(raw)


class World:
    """A commissioned, published, approved and healthy node in a tmp root."""

    def __init__(self, root: Path):
        self.root = root
        self.manager = RecordingUnitManager(d.name for d in CORE_UNITS)
        for definition in CORE_UNITS:  # the previous boot left everything wide
            self.manager.unmask_and_enable(definition.name)
        self.manager.calls.clear()
        self.key = SigningKey.generate()
        self.trust = OperatorTrust({"operator-a": bytes(self.key.verify_key)})
        self.evidence = CommissioningEvidence(
            EVIDENCE_PAYLOAD, b"\x01" * 64, b'{"inventory":1}', "hmac-sha256:" + "c" * 64)
        self.node = DeclaredNode(NODE)
        self.deployment = BootstrapDeployment(
            node_digest=declared_node_digest(NODE), security_epoch=2,
            revocation_digest=DIGEST, policy_digest=DIGEST,
            approval_policy_digest=DIGEST, operator="operator-a")
        self.policy = make_policy()
        self.high_water = HighWater(security_epoch=2, approval_seq=5, generation=1,
                                    time_floor="2026-10-20T00:00:00Z")
        self.unit_files = {unit: f"[Unit]\nDescription={unit}\n".encode() for unit in SCOPE}
        self.healthy = True
        self.raised: list[HighWater] = []
        self.store = GenerationStore(root / "var/lib/azazel/generations")
        self.generation = self.store.create(
            build_observe_baseline(units=list(self.policy.units), unit_files=self.unit_files),
            created_at="2026-10-20T00:00:00Z",
            commissioning_digest=evidence_commissioning_digest(self.evidence),
            commissioning_evidence_binding=self.evidence.binding,
        )
        (root / "run/azazel-activation").mkdir(parents=True, mode=0o755)
        os.chmod(root / "run/azazel-activation", 0o755)
        self.sign()

    def context(self, **overrides):
        values = dict(
            node_digest=declared_node_digest(NODE), generation=self.generation.number,
            generation_digest=self.generation.digest,
            commissioning_digest=evidence_commissioning_digest(self.evidence),
            commissioning_evidence_binding=self.evidence.binding,
            policy_digest=self.policy.policy_digest, security_epoch=2,
        ) | overrides
        return ObserveBaselineContext(**values)

    def sign(self, *, context=None, **overrides):
        fields = dict(approval_id="approval-1", operator="operator-a", approval_seq=5,
                      units=SCOPE, granted_at="2026-10-20T12:00:00Z",
                      expires_at="2026-10-22T00:00:00Z") | overrides
        self.payload = observe_baseline_payload(context=context or self.context(), **fields)
        self.signature = self.key.sign(
            approval_message(ApprovalPurpose.ACTIVATION, self.payload)).signature

    def producers(self, **replaced) -> PassProducers:
        def approval(**kwargs):
            return verify_observe_baseline_approval(
                trust=self.trust, payload=self.payload, signature=self.signature, **kwargs)

        def raise_high_water(value, *, now, skew_seconds):
            if value.lower_than(self.high_water):
                raise HighWaterRefused("high-water never moves backwards")
            self.raised.append(value)
            self.high_water = value
            return value

        def unit_files(units):
            return {unit: self.unit_files[unit] for unit in units}

        values = dict(
            commissioning_evidence=lambda: self.evidence,
            declared_node=lambda: self.node,
            deployment=lambda: self.deployment,
            policy=lambda: self.policy,
            high_water=lambda: self.high_water,
            unit_files=unit_files,
            approval=approval,
            health=lambda policy, ledger: (
                self.healthy, (("state_capacity", "ok" if self.healthy else "failed"),)),
            raise_high_water=raise_high_water,
        ) | replaced
        return PassProducers(**values)

    def run(self, **replaced):
        return activated._run_once(manager=self.manager, root=self.root, now=NOW,
                                   actor="test", producers=self.producers(**replaced))

    @property
    def ledger_path(self) -> Path:
        return self.root / "var/lib/azazel/state/activation.jsonl"

    def events(self):
        return [entry.event for entry in AuditLedger(self.ledger_path)]

    def inputs_event(self):
        return [e for e in self.events() if e["event_type"] == "activation.inputs_incomplete"][-1]

    def markers(self):
        directory = self.root / "run/azazel-activation/granted"
        return sorted(p.name for p in directory.iterdir()) if directory.exists() else None


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    monkeypatch.setattr(activated, "_collect_input_status", lambda _root: {})
    return World(tmp_path)


def _assert_refused(world, outcome, missing):
    assert outcome.granted == ()
    assert all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert world.markers() is None
    event = world.inputs_event()
    assert event["missing_producers"] == list(ALWAYS_MISSING) + list(missing)
    assert event["grant_markers"] == []
    assert world.raised == []
    text = world.ledger_path.read_text()
    assert NODE not in text and EVIDENCE_PAYLOAD.decode() not in text


# -- the regular path ----------------------------------------------------------


def test_complete_inputs_grant_only_the_scoped_units_and_only_they_get_markers(world):
    outcome = world.run()
    assert sorted(outcome.granted) == list(SCOPE)
    for definition in CORE_UNITS:
        expected = UnitState.ENABLED if definition.name in SCOPE else UnitState.MASKED
        assert world.manager.state(definition.name) is expected, definition.name
    assert world.markers() == list(SCOPE)
    granted_dir = world.root / "run/azazel-activation/granted"
    assert granted_dir.stat().st_mode & 0o777 == 0o755
    assert all((granted_dir / unit).stat().st_mode & 0o777 == 0o644 for unit in SCOPE)
    assert all((granted_dir / unit).read_bytes() == b"" for unit in SCOPE)
    event = world.inputs_event()
    assert event["missing_producers"] == list(ALWAYS_MISSING)
    assert event["grant_markers"] == list(SCOPE)
    assert set(event["observed_inputs"]["producers"].values()) == {"verified"}
    assert event["observed_inputs"]["high_water"] == "raised"
    # Edge-core, enforcement and the other supporting units stay masked.
    reasons = {v.unit: v.reason.split(":", 1)[0] for v in outcome.verdicts}
    assert reasons["azazel-edge-core.service"] == "outside_lease_scope"
    assert reasons["azazel-auditd.service"] == "outside_lease_scope"
    text = world.ledger_path.read_text()
    assert NODE not in text and EVIDENCE_PAYLOAD.decode() not in text


def test_a_narrower_approval_grants_and_marks_only_its_units(world):
    world.sign(units=SCOPE[:2])
    outcome = world.run()
    assert sorted(outcome.granted) == list(SCOPE[:2])
    assert world.markers() == list(SCOPE[:2])
    for unit in SCOPE[2:]:
        assert world.manager.state(unit) is UnitState.MASKED


def test_a_second_pass_replaces_markers_with_its_own_grants(world):
    world.run()
    world.sign(units=SCOPE[:1])
    world.run()
    assert world.markers() == list(SCOPE[:1])


# -- each producer, absent or failed, refuses -------------------------------


def _raises(message="private reader detail"):
    def reader(*_args, **_kwargs):
        raise ApprovalRefused(message)
    return reader


@pytest.mark.parametrize("replaced,missing", [
    ({"commissioning_evidence": _raises()}, ["authenticated_commissioning", "inventory_binding"]),
    ({"declared_node": _raises()}, ["node_identity"]),
    ({"deployment": _raises()}, ["node_identity"]),
    ({"policy": _raises()}, ["activation_policy"]),
    ({"high_water": lambda: None}, ["epoch_high_water"]),
    ({"high_water": _raises()}, ["epoch_high_water"]),
    ({"unit_files": _raises()}, ["operational_generation_publisher"]),
    ({"approval": _raises()}, ["activation_approval_loader"]),
    ({"health": _raises()}, ["node_health"]),
    ({"health": lambda policy, ledger: (False, (("watchdog_fences", "failed"),))},
     ["node_health"]),
], ids=["evidence", "declared-node", "deployment", "policy", "high-water-absent",
        "high-water-refused", "unit-file", "approval", "health-error", "unhealthy"])
def test_each_absent_or_failed_producer_refuses_and_is_named_alone(world, replaced, missing):
    outcome = world.run(**replaced)
    _assert_refused(world, outcome, missing)
    assert "private reader detail" not in world.ledger_path.read_text()


def test_no_generation_refuses_as_the_missing_publisher(world, tmp_path):
    world.store = GenerationStore(tmp_path / "elsewhere")
    import shutil
    shutil.rmtree(world.root / "var/lib/azazel/generations")
    outcome = world.run()
    _assert_refused(world, outcome, ["operational_generation_publisher"])


def test_a_declared_node_differing_from_the_deployment_refuses(world):
    world.node = DeclaredNode("private-node-b")
    _assert_refused(world, world.run(), ["node_identity"])


def test_edge_core_in_policy_scope_is_refused_before_p5(world):
    world.policy = make_policy(units=SCOPE + ("azazel-edge-core.service",))
    _assert_refused(world, world.run(), ["activation_policy"])


# -- epoch, clock, expiry, tampering, floors, revocation -------------------


def test_epoch_bump_refuses_an_approval_signed_for_the_old_epoch(world):
    world.deployment = replace(world.deployment, security_epoch=3)
    _assert_refused(world, world.run(), ["activation_approval_loader"])


def test_declared_epoch_below_the_floor_refuses(world):
    world.high_water = replace(world.high_water, security_epoch=3)
    _assert_refused(world, world.run(), ["epoch_high_water"])


def test_clock_rolled_back_beyond_the_skew_refuses(world):
    world.high_water = replace(world.high_water, time_floor="2026-10-21T00:05:01Z")
    _assert_refused(world, world.run(), ["trusted_clock"])


def test_clock_behind_the_floor_within_the_skew_passes_and_keeps_the_floor(world):
    world.high_water = replace(world.high_water, time_floor="2026-10-21T00:04:00Z")
    outcome = world.run()
    assert sorted(outcome.granted) == list(SCOPE)
    assert world.raised[-1].time_floor == "2026-10-21T00:04:00Z"


def test_expired_approval_refuses(world):
    world.sign(granted_at="2026-10-19T00:00:00Z", expires_at="2026-10-20T23:59:59Z")
    _assert_refused(world, world.run(), ["activation_approval_loader"])


def test_unit_file_changed_after_publish_refuses_the_generation(world):
    world.unit_files["azazel-mio-entryd.service"] += b"ExecStartPre=/bin/true\n"
    _assert_refused(world, world.run(), ["operational_generation_publisher"])


def test_generation_tree_altered_on_disk_refuses(world):
    tree = world.root / f"var/lib/azazel/generations/{world.generation.number}/tree/baseline.json"
    tree.chmod(0o600)
    tree.write_bytes(tree.read_bytes().replace(b"azazel-mio-entryd", b"azazel-mio-entryX"))
    _assert_refused(world, world.run(), ["operational_generation_publisher"])


def test_generation_bound_to_other_evidence_refuses(world):
    world.evidence = CommissioningEvidence(
        EVIDENCE_PAYLOAD, b"\x01" * 64, b'{"inventory":1}', "hmac-sha256:" + "e" * 64)
    _assert_refused(world, world.run(), ["operational_generation_publisher"])


def test_generation_below_the_floor_refuses(world):
    world.high_water = replace(world.high_water, generation=2)
    _assert_refused(world, world.run(), ["epoch_high_water"])


def test_sequence_below_the_floor_refuses(world):
    world.high_water = replace(world.high_water, approval_seq=6)
    _assert_refused(world, world.run(), ["activation_approval_loader"])


def test_revoked_operator_refuses(world):
    world.trust = OperatorTrust(dict(world.trust.public_keys), frozenset({"operator-a"}))
    _assert_refused(world, world.run(), ["activation_approval_loader"])


def test_operator_not_named_by_the_policy_refuses(world):
    world.policy = make_policy(operators=("operator-b",))
    world.sign()
    _assert_refused(world, world.run(), ["activation_approval_loader"])


# -- tripwire ------------------------------------------------------------------


def _extra_grant(monkeypatch, extra):
    original = activated.ActivationDaemon.activate

    def activate(self, **kwargs):
        outcome = original(self, **kwargs)
        return SimpleNamespace(granted=tuple(outcome.granted) + (extra,),
                               verdicts=outcome.verdicts, generation=outcome.generation)

    monkeypatch.setattr(activated.ActivationDaemon, "activate", activate)


@pytest.mark.parametrize("extra", ["azazel-watchdog.service", "azazel-edge-core.service"])
def test_a_grant_outside_the_lease_remasks_everything_and_raises(world, monkeypatch, extra):
    _extra_grant(monkeypatch, extra)
    with pytest.raises(RuntimeError, match="outside a verified lease"):
        world.run()
    assert all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert world.markers() is None
    assert world.raised == []


def test_a_grant_outside_a_narrower_lease_remasks_everything(world, monkeypatch):
    world.sign(units=SCOPE[:1])
    _extra_grant(monkeypatch, SCOPE[1])
    with pytest.raises(RuntimeError, match="outside a verified lease"):
        world.run()
    assert all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert world.markers() is None


def test_any_grant_without_lease_and_health_remasks_everything(world, monkeypatch):
    _extra_grant(monkeypatch, SCOPE[0])
    world.healthy = False
    with pytest.raises(RuntimeError, match="outside a verified lease"):
        world.run()
    assert all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)


# -- stale markers -------------------------------------------------------------


def test_stale_markers_are_removed_before_any_decision(world):
    stale = world.root / "run/azazel-activation/granted"
    stale.mkdir(mode=0o755)
    (stale / "azazel-mio-entryd.service").write_bytes(b"")
    (stale / "azazel-edge-core.service").write_bytes(b"")
    seen = []
    original = world.producers

    def producers(**replaced):
        made = original(**replaced)

        def evidence():
            seen.append(stale.exists())
            return world.evidence
        return replace(made, commissioning_evidence=evidence)

    world.producers = producers
    _assert_refused(world, world.run(policy=_raises()), ["activation_policy"])
    assert seen == [False]


def test_stale_markers_are_replaced_by_exactly_this_pass_grants(world):
    stale = world.root / "run/azazel-activation/granted"
    stale.mkdir(mode=0o755)
    (stale / "azazel-edge-core.service").write_bytes(b"")
    world.sign(units=SCOPE[:2])
    world.run()
    assert world.markers() == list(SCOPE[:2])


def test_unremovable_stale_markers_refuse_after_narrowing(world):
    stale = world.root / "run/azazel-activation/granted"
    (stale / "unexpected-directory").mkdir(parents=True)
    with pytest.raises(RuntimeError, match="stale activation grant markers"):
        world.run()
    assert all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert world.events()[-1]["event_type"] == "activation.grant_markers_unclean"


def test_missing_marker_directory_refuses_after_recording(world):
    import shutil
    shutil.rmtree(world.root / "run/azazel-activation")
    with pytest.raises(RuntimeError, match="grant markers could not be written"):
        world.run()
    assert all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert world.events()[-1]["event_type"] == "activation.grant_markers_unwritten"


def test_a_rolled_back_pass_writes_no_marker(world, monkeypatch):
    original = world.manager.unmask_and_enable

    def unmask_and_enable(unit):
        if unit == "azazel-mio-entryd.service":
            raise OSError("synthetic manager failure")
        original(unit)

    monkeypatch.setattr(world.manager, "unmask_and_enable", unmask_and_enable)
    world.run()
    assert world.markers() is None
    assert all(world.manager.state(unit) is UnitState.MASKED for unit in SCOPE)


# -- high water ----------------------------------------------------------------


def test_high_water_is_raised_after_the_decision_and_never_lowered(world):
    world.high_water = HighWater(security_epoch=1, approval_seq=4, generation=1,
                                 time_floor="2026-10-20T00:00:00Z")
    order = []
    original = world.producers

    def producers(**replaced):
        made = original(**replaced)
        inner = made.raise_high_water

        def raise_high_water(value, *, now, skew_seconds):
            order.append([e["event_type"] for e in world.events()])
            assert skew_seconds == 300
            return inner(value, now=now, skew_seconds=skew_seconds)
        return replace(made, raise_high_water=raise_high_water)

    world.producers = producers
    world.run()
    assert "activation.unit_granted" in order[0]
    assert world.raised == [HighWater(security_epoch=2, approval_seq=5,
                                      generation=world.generation.number, time_floor=NOW)]
    assert not world.raised[-1].lower_than(HighWater(1, 4, 1, "2026-10-20T00:00:00Z"))


def test_a_refused_pass_does_not_touch_the_high_water(world):
    world.run(approval=_raises())
    assert world.raised == []


def test_high_water_that_cannot_be_raised_remasks_and_writes_no_marker(world):
    with pytest.raises(RuntimeError, match="high water could not be raised"):
        world.run(raise_high_water=_raises())
    assert all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert world.markers() is None
    assert world.events()[-1]["event_type"] == "activation.high_water_unraised"


# -- the marker and unit-file readers ------------------------------------------


def test_markers_refuse_a_foreign_parent_and_an_existing_leaf(tmp_path, monkeypatch):
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    parent = tmp_path / "run/azazel-activation"
    parent.mkdir(parents=True)
    parent.chmod(0o777)
    with pytest.raises(activation_markers.GrantMarkerRefused):
        activation_markers.write_grant_markers([SCOPE[0]], tmp_path)
    parent.chmod(0o755)
    (parent / "granted").mkdir()
    with pytest.raises(FileExistsError):
        activation_markers.write_grant_markers([SCOPE[0]], tmp_path)
    activation_markers.reset_grant_markers(tmp_path)
    assert activation_markers.write_grant_markers([SCOPE[0]], tmp_path) == (SCOPE[0],)
    with pytest.raises(activation_markers.GrantMarkerRefused):
        activation_markers.write_grant_markers(["../escape.service"], tmp_path)


def test_commissioning_digest_is_the_signed_proposal_digest(world):
    assert evidence_commissioning_digest(world.evidence) == (
        "sha256:" + hashlib.sha256(EVIDENCE_PAYLOAD).hexdigest())


def test_a_missing_relocated_root_holds_no_marker_and_cannot_grant(tmp_path):
    missing = tmp_path / "absent-root"
    activation_markers.reset_grant_markers(missing)
    with pytest.raises(activation_markers.GrantMarkerRefused):
        activation_markers.write_grant_markers([SCOPE[0]], missing)


def test_raising_the_high_water_is_recorded_as_a_floor_event(world):
    world.run()
    events = world.events()
    raised = [e for e in events if e["event_type"] == "activation.high_water_raised"]
    assert len(raised) == 1
    assert raised[0]["high_water"] == {"security_epoch": 2, "approval_seq": 5,
                                       "generation": world.generation.number,
                                       "time_floor": NOW}
    from azazel_nexus_runtime.activation_cli import FLOOR_EVENTS
    assert "activation.high_water_raised" in FLOOR_EVENTS
    kinds = [e["event_type"] for e in events]
    assert kinds.index("activation.high_water_raised") > max(
        i for i, kind in enumerate(kinds) if kind == "activation.unit_granted")


def test_the_pass_scope_and_tripwire_share_one_unit_set():
    from azazel_nexus_runtime.activation_markers import GRANTABLE_UNITS
    assert activation_pass.P4_UNIT_SCOPE is GRANTABLE_UNITS
    assert GRANTABLE_UNITS == frozenset(SCOPE)
    import ast
    source = Path(activated.__file__).read_text()
    names = {node.id for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Name)}
    assert "GRANTABLE_UNITS" in names and "_P4_GRANTABLE" not in names


def test_markers_are_never_written_for_a_unit_this_phase_cannot_grant(tmp_path, monkeypatch):
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    (tmp_path / "run/azazel-activation").mkdir(parents=True, mode=0o755)
    for unit in ("azazel-edge-core.service", "azazel-watchdog.service",
                 "azazel-mio-locald.service"):
        with pytest.raises(activation_markers.GrantMarkerRefused):
            activation_markers.write_grant_markers([unit], tmp_path)
    assert not (tmp_path / "run/azazel-activation/granted").exists()


def test_emergency_narrowing_remasks_even_when_markers_cannot_be_removed(world, monkeypatch, capsys):
    def broken(_root):
        raise activation_markers.GrantMarkerRefused("synthetic")
    monkeypatch.setattr(activated, "reset_grant_markers", broken)
    with pytest.raises(RuntimeError, match="grant_markers: GrantMarkerRefused"):
        activated._emergency_narrow(world.manager, world.root, "synthetic emergency")
    assert all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert "could not remove grant markers" in capsys.readouterr().err


def test_a_verified_approval_raises_the_floors_even_when_every_unit_is_withheld(world, monkeypatch):
    """Documented: the floor follows the accepted approval, not the grant count."""
    original = activated.ActivationDaemon.activate

    def nothing_granted(self, **kwargs):
        return original(self, **(kwargs | {"lease": None}))

    monkeypatch.setattr(activated.ActivationDaemon, "activate", nothing_granted)
    outcome = world.run()
    assert outcome.granted == ()
    assert len(world.raised) == 1
    assert world.markers() is None
