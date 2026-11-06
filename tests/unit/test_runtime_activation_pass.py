"""The observe-baseline pass with a fake manager, a tmp root and ephemeral keys (#206).

`docs/activation-observe-baseline.md` §3.4, §3.6 and §5 (phases P4 and P5).
Every producer is an in-memory fixture passed through `_run_once`'s test
seam; the approval is signed here with a key that exists only for the test,
and verified by the real v2 verifier against the context the pass collected.
The Edge evidence is the real `edge_package` reader over a package, a probe
result and a boot id written under the tmp root.
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

from azazel_nexus import edge_package
from azazel_nexus.activation import CORE_UNITS, EdgeBaselineState, UnitState
from azazel_nexus.activation_approval_v2 import (
    ObserveBaselineApproval,
    ObserveBaselineContext,
    observe_baseline_payload,
    verify_observe_baseline_approval,
)
from azazel_nexus.activation_policy import ACTIVATION_POLICY_SCHEMA, decode_activation_policy
from azazel_nexus.audit import AuditLedger
from azazel_nexus.bootstrap_deployment import BootstrapDeployment, declared_node_digest
from azazel_nexus.commissioning_evidence import CommissioningEvidence
from azazel_nexus.edge_package import (
    PIN,
    PROBE_CONTRACT,
    PROBE_CONTRACT_V1,
    Evidence,
    ProbeResult,
    installed_baseline_state,
    installed_package_digest,
    measure_extracted_components,
)
from azazel_nexus.generation import GenerationStore
from azazel_nexus.observe_baseline import build_observe_baseline, evidence_commissioning_digest
from azazel_nexus.operator_trust import ApprovalPurpose, ApprovalRefused, OperatorTrust, approval_message
from azazel_nexus_runtime import activated, activation_markers, activation_pass
from azazel_nexus_runtime.activation_loaded_units import verify_loaded_units
from azazel_nexus_runtime.activation_high_water import HighWater, HighWaterRefused
from azazel_nexus_runtime.activation_pass import (
    ALWAYS_MISSING,
    EDGE_EVIDENCE,
    PassProducers,
)
from azazel_nexus_runtime.node_config import DeclaredNode
from azazel_nexus_runtime.units import RecordingUnitManager
from _edge_package_fixture import elf_stub, write_package

NOW = "2026-10-21T00:00:00Z"
DIGEST = "sha256:" + "d" * 64
SCOPE = (
    "azazel-edge-intaked.service",
    "azazel-edge-probed.service",
    "azazel-incident-explaind.service",
    "azazel-knowledge-lited.service",
    "azazel-mio-entryd.service",
)
EDGE = "azazel-edge-core.service"
#: The integrated loop's audit writer (ADR 0008).
AUDIT_LOOP = "azazel-auditd-loop.service"
EDGE_SCOPE = tuple(sorted(SCOPE + (EDGE,)))
#: The Deception Lite exposure units (#196 P1, (a)): grantable for the #253
#: checks, never nameable by a policy, always withheld by the library.
DECOY_UNITS = ("azazel-decoy-nsd.service", "azazel-decoy-netd.service",
               "azazel-decoyd.service")
NODE = "private-node-a"
EVIDENCE_PAYLOAD = b'{"private-commissioning-proposal":true}'
BOOT = "0f0e0d0c-0b0a-4908-8706-050403020100"
OTHER_BOOT = "11111111-2222-4333-8444-555555555555"
#: The edge-core unit file as rendered: observe-only Environment= lines.
EDGE_UNIT_FILE = (b"[Unit]\nDescription=azazel-edge-core.service\n[Service]\n"
                  b"Environment=AZAZEL_REDIRECT_POLICY_PATH=/opt/azazel/edge-core/config/"
                  b"redirect_policy.yaml\n")


def loaded_as_declared(unit):
    """What a manager reports for a unit loaded from its rendered vendor file."""
    return {
        "Id": unit, "LoadState": "loaded",
        "FragmentPath": f"/usr/lib/systemd/system/{unit}", "DropInPaths": [],
        "Conditions": [("ConditionPathExists", False, False,
                        f"/run/azazel-activation/granted/{unit}", 0)],
        # The Deception Lite exposure units assert AppArmor (#196 G3).
        "Asserts": ([("AssertSecurity", False, False, "apparmor", 0)]
                    if unit.startswith("azazel-decoy") else []),
        "Requires": ["azazel-activated.service", "system.slice", "sysinit.target"],
        "After": ["azazel-activated.service", "basic.target", "system.slice"],
    }


class FakeManagerReader:
    """The two reads the pass makes of the controller's D-Bus session."""

    def __init__(self):
        self.loaded = {}
        self.profile_error = None
        #: Profiles returned in turn (the last one repeats); errors raise.
        self.profiles = ["reviewed"]
        self.reads = []

    def bootstrap_profile(self):
        if self.profile_error is not None:
            raise self.profile_error
        value = self.profiles.pop(0) if len(self.profiles) > 1 else self.profiles[0]
        if isinstance(value, Exception):
            raise value
        return value

    def loaded_unit(self, unit):
        self.reads.append(unit)
        return self.loaded.get(unit, loaded_as_declared(unit))


def make_policy(units=SCOPE, operators=("operator-a",), skew=300, require_sync=None):
    extra = {} if require_sync is None else {"require_clock_synchronized": require_sync}
    raw = json.dumps(extra | {
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

    def __init__(self, root: Path, units=SCOPE):
        self.root = root
        self.units = tuple(units)
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
        self.policy = make_policy(units=self.units)
        self.high_water = HighWater(security_epoch=2, approval_seq=5, generation=1,
                                    time_floor="2026-10-20T00:00:00Z")
        self.unit_files = {unit: f"[Unit]\nDescription={unit}\n".encode()
                           for unit in SCOPE + (AUDIT_LOOP,)}
        self.unit_files[EDGE] = EDGE_UNIT_FILE
        self.healthy = True
        self.systemd = FakeManagerReader()
        self.raised: list[HighWater] = []
        # The installed Edge package, this boot's id and the preflight's
        # result: fresh, healthy, from this boot, not running (as at boot).
        self.edge_root = root / "opt/azazel/edge-core"
        self.probe_path = root / "var/lib/azazel/run/edge-probe/edge-probe.json"
        self.boot_path = root / "proc/boot_id"
        self.boot_path.parent.mkdir(parents=True)
        self.boot_path.write_text(BOOT + "\n")
        self.boot_path.chmod(0o444)
        self.package_digest, self.components = self.package()
        self.probe()
        self.store = GenerationStore(root / "var/lib/azazel/generations")
        self.generation = self.store.create(
            build_observe_baseline(
                units=list(self.policy.units),
                unit_files={unit: self.unit_files[unit] for unit in self.policy.units},
                package_digest=self.package_digest if EDGE in self.units else None,
                package_components=self.components if EDGE in self.units else None),
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

    def package(self, **contents):
        """The archive, its manifest and the extracted binary and redirect policy."""
        return write_package(self.edge_root, **contents)

    def probe(self, *, health=Evidence.PASSED, boot=BOOT, contract=PROBE_CONTRACT,
              observed_at="2026-10-20T23:59:00Z", digest=None):
        self.probe_path.parent.mkdir(parents=True, exist_ok=True)
        result = ProbeResult(
            contract=contract, observed_at=observed_at, ttl_seconds=300,
            package_version=PIN.version, package_digest=digest or self.package_digest,
            health=health, health_reason="az-edge-probed --health",
            running=Evidence.FAILED, running_reason="not started at boot",
            boot_id=boot if contract == PROBE_CONTRACT else None)
        self.probe_path.write_text(json.dumps(result.as_event()))
        self.probe_path.chmod(0o644)

    def sign(self, *, context=None, **overrides):
        fields = dict(approval_id="approval-1", operator="operator-a", approval_seq=5,
                      units=self.units, granted_at="2026-10-20T12:00:00Z",
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
            loaded_units=lambda units: verify_loaded_units(self.systemd, units),
            approval=approval,
            health=lambda policy, ledger: (
                self.healthy, (("state_capacity", "ok" if self.healthy else "failed"),)),
            raise_high_water=raise_high_water,
            edge_package_digest=lambda: installed_package_digest(package_root=self.edge_root),
            edge_state=lambda *, now: installed_baseline_state(
                now=now, package_root=self.edge_root, probe_path=self.probe_path,
                boot_id_path=self.boot_path),
            edge_components=lambda: measure_extracted_components(
                package_root=self.edge_root, owner_uid=os.getuid()),
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


def _owned_by_the_test(monkeypatch):
    """The real readers, trusting the test's uid as the probe writer and boot id owner."""
    read_probe, read_boot = edge_package.load_probe_result, edge_package.read_current_boot_id
    monkeypatch.setattr(edge_package, "load_probe_result",
                        lambda path: read_probe(path, owner_uid=os.geteuid()))
    monkeypatch.setattr(edge_package, "read_current_boot_id",
                        lambda path: read_boot(path, owner_uid=os.geteuid()))


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    monkeypatch.setattr(activated, "_collect_input_status", lambda _root: {})
    _owned_by_the_test(monkeypatch)
    return World(tmp_path)


@pytest.fixture
def edge_world(tmp_path, monkeypatch):
    """The same node with edge-core in the policy, the generation and the approval."""
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    monkeypatch.setattr(activated, "_collect_input_status", lambda _root: {})
    _owned_by_the_test(monkeypatch)
    return World(tmp_path, units=EDGE_SCOPE)


def _assert_refused(world, outcome, missing):
    assert outcome.granted == ()
    assert all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert world.markers() is None
    event = world.inputs_event()
    assert event["missing_producers"] == list(ALWAYS_MISSING) + [EDGE_EVIDENCE] + list(missing)
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
    assert event["missing_producers"] == list(ALWAYS_MISSING) + [EDGE_EVIDENCE]
    assert event["grant_markers"] == list(SCOPE)
    assert event["observed_inputs"]["edge_evidence"] == "not_in_scope"
    assert event["observed_inputs"]["edge_package_binding"] == "not_in_scope"
    assert set(event["observed_inputs"]["producers"].values()) == {"verified"}
    assert event["observed_inputs"]["high_water"] == "raised"
    # Edge-core, enforcement and the other supporting units stay masked.
    reasons = {v.unit: v.reason.split(":", 1)[0] for v in outcome.verdicts}
    assert reasons["azazel-edge-core.service"] == "outside_lease_scope"
    assert reasons["azazel-auditd.service"] == "outside_lease_scope"
    text = world.ledger_path.read_text()
    assert NODE not in text and EVIDENCE_PAYLOAD.decode() not in text


def test_the_loops_audit_writer_is_granted_and_marked_like_a_loop_unit(tmp_path, monkeypatch):
    """ADR 0008: a policy naming `azazel-auditd-loop.service` gets it from the
    ordinary pass, with its own marker; the bootstrap helper stays masked."""
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    monkeypatch.setattr(activated, "_collect_input_status", lambda _root: {})
    _owned_by_the_test(monkeypatch)
    world = World(tmp_path, units=tuple(sorted(SCOPE + (AUDIT_LOOP,))))
    outcome = world.run()
    assert AUDIT_LOOP in outcome.granted
    assert world.markers() == sorted(SCOPE + (AUDIT_LOOP,))
    assert world.manager.state(AUDIT_LOOP) is UnitState.ENABLED
    for helper in ("azazel-auditd.service", "azazel-commissiond.service"):
        assert world.manager.state(helper) is UnitState.MASKED
        reasons = {v.unit: v.reason.split(":", 1)[0] for v in outcome.verdicts}
        assert reasons[helper] == "outside_lease_scope"


def test_a_policy_cannot_name_the_bootstrap_helpers():
    for helper in ("azazel-auditd.service", "azazel-commissiond.service"):
        with pytest.raises(ApprovalRefused):
            make_policy(units=SCOPE + (helper,))


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
    ({"loaded_units": _raises()}, ["systemd_loaded_units"]),
    ({"approval": _raises()}, ["activation_approval_loader"]),
    ({"health": _raises()}, ["node_health"]),
    ({"health": lambda policy, ledger: (False, (("watchdog_fences", "failed"),))},
     ["node_health"]),
], ids=["evidence", "declared-node", "deployment", "policy", "high-water-absent",
        "high-water-refused", "unit-file", "loaded-units", "approval", "health-error", "unhealthy"])
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


def test_a_policy_naming_a_unit_outside_the_grantable_set_is_refused(world):
    """The policy's allowlist is the grantable set minus the Deception Lite
    exposure units (#196 P1), which no policy may name; nothing wider decodes."""
    from azazel_nexus.activation import DECEPTION_EXPOSURE_UNITS
    from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST
    assert frozenset(ACTIVATION_UNIT_ALLOWLIST) == (
        activation_pass.UNIT_SCOPE - frozenset(DECEPTION_EXPOSURE_UNITS))
    with pytest.raises(ApprovalRefused):
        make_policy(units=SCOPE + ("azazel-watchdog.service",))
    world.policy = SimpleNamespace(units=SCOPE + ("azazel-watchdog.service",))
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


# -- clock synchronization required by the policy (#251 M-1) -----------------


def _require_sync(world, value):
    """Re-sign against a policy carrying `require_clock_synchronized`."""
    world.policy = make_policy(units=world.units, require_sync=value)
    world.sign()


def _never_called():
    raise AssertionError("the synchronization reader was called")


@pytest.mark.parametrize("value", [None, False])
def test_default_policy_never_reads_synchronization_and_grants_as_before(world, value):
    if value is not None:
        _require_sync(world, value)
    outcome = world.run(clock_synchronized=_never_called)
    assert sorted(outcome.granted) == list(SCOPE)
    event = world.inputs_event()
    assert event["observed_inputs"]["producers"]["trusted_clock"] == "verified"
    assert "clock_synchronization" not in event["observed_inputs"]


def test_default_policy_without_a_reader_grants_as_before(world):
    outcome = world.run(clock_synchronized=None)
    assert sorted(outcome.granted) == list(SCOPE)


def test_required_and_synchronized_grants(world):
    _require_sync(world, True)
    calls = []
    outcome = world.run(clock_synchronized=lambda: calls.append(1) or True)
    assert sorted(outcome.granted) == list(SCOPE)
    assert calls == [1]
    assert world.inputs_event()["observed_inputs"]["clock_synchronization"] == "synchronized"


def _unsynchronized():
    raise OSError("no marker")


@pytest.mark.parametrize("reader", [None, _unsynchronized, lambda: False, lambda: 1,
                                    lambda: "true", lambda: None])
def test_required_and_unproven_refuses_trusted_clock(world, reader):
    _require_sync(world, True)
    _assert_refused(world, world.run(clock_synchronized=reader), ["trusted_clock"])
    event = world.inputs_event()
    assert event["observed_inputs"]["clock_synchronization"] == "not_proven"
    assert event["observed_inputs"]["producers"]["activation_approval_loader"] == "not_attempted"


def test_required_with_the_real_reader_and_no_marker_refuses(world, tmp_path):
    from azazel_nexus_runtime.activation_clock_sync import require_clock_synchronized
    _require_sync(world, True)
    missing = str(tmp_path / "timesync" / "synchronized")
    _assert_refused(world, world.run(
        clock_synchronized=lambda: require_clock_synchronized(missing)), ["trusted_clock"])


def test_required_with_the_real_reader_and_a_marker_grants(world, tmp_path):
    from azazel_nexus_runtime.activation_clock_sync import require_clock_synchronized
    _require_sync(world, True)
    # The reader follows no symlink at any component (macOS's /var is one).
    directory = Path(os.path.realpath(tmp_path)) / "timesync"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    (directory / "synchronized").write_bytes(b"")
    (directory / "synchronized").chmod(0o644)
    outcome = world.run(clock_synchronized=lambda: require_clock_synchronized(
        str(directory / "synchronized")))
    assert sorted(outcome.granted) == list(SCOPE)


def test_required_with_the_clock_below_the_floor_fails_before_reading(world):
    _require_sync(world, True)
    world.high_water = replace(world.high_water, time_floor="2026-10-21T00:05:01Z")
    _assert_refused(world, world.run(clock_synchronized=_never_called), ["trusted_clock"])
    assert "clock_synchronization" not in world.inputs_event()["observed_inputs"]


def test_approval_for_the_policy_without_the_field_does_not_verify_after_it_is_added(world):
    """The field is part of the signed policy: adding it changes the digest."""
    before = world.policy.policy_digest
    world.policy = make_policy(units=world.units, require_sync=True)
    assert world.policy.policy_digest != before
    _assert_refused(world, world.run(clock_synchronized=lambda: True),
                    ["activation_approval_loader"])


def test_expired_approval_refuses(world):
    world.sign(granted_at="2026-10-19T00:00:00Z", expires_at="2026-10-20T23:59:59Z")
    _assert_refused(world, world.run(), ["activation_approval_loader"])


def _sign_v3(world):
    """A v3 approval (#196 G6 prep) for exactly this pass's context and units."""
    from azazel_nexus.activation_approval_v3 import activation_approval_v3_payload

    world.payload = activation_approval_v3_payload(
        context=world.context(), approval_id="approval-1", operator="operator-a",
        approval_seq=5, units=world.units, granted_at="2026-10-20T12:00:00Z",
        expires_at="2026-10-22T00:00:00Z", exposure_scope_digest="sha256:" + "e" * 64,
        exposure_prefix_count=1, exposure_ingress_count=1)
    # v3's own purpose (wiring §5.1, Q-C), the only one its verifier accepts.
    world.signature = world.key.sign(
        approval_message(ApprovalPurpose.ACTIVATION_EXPOSURE, world.payload)).signature


def _assert_granted(world, outcome):
    assert sorted(outcome.granted) == list(SCOPE)
    assert world.markers() == list(SCOPE)


def test_a_v3_approval_is_not_accepted_by_the_pass(world):
    """The v3 decoder is not wired: the pass's v2 verifier refuses v3 bytes,
    while the same world with the same fields signed as v2 grants."""
    _sign_v3(world)
    _assert_refused(world, world.run(), ["activation_approval_loader"])
    world.sign()
    _assert_granted(world, world.run())


def test_the_pass_refuses_a_v3_result_even_from_its_approval_producer(world):
    """Wiring the v3 verifier in as the producer would still grant nothing:
    the v3 verifier accepts (asserted on the very call the pass made), and
    the pass refuses its result because it is not an `ObserveBaselineApproval`."""
    from azazel_nexus.activation_approval_v3 import (
        ActivationApprovalV3,
        verify_activation_approval_v3,
    )

    _sign_v3(world)
    calls = []

    def approval(**kwargs):
        result = verify_activation_approval_v3(
            trust=world.trust, payload=world.payload, signature=world.signature, **kwargs)
        calls.append((kwargs, result))
        return result

    _assert_refused(world, world.run(approval=approval), ["activation_approval_loader"])
    assert len(calls) == 1
    kwargs, result = calls[0]
    assert type(result) is ActivationApprovalV3
    assert result.lease.units == frozenset(SCOPE)
    # The same arguments, called again directly, give the same accepted result.
    assert type(approval(**kwargs)) is ActivationApprovalV3
    # Every other check the pass makes on the result holds, so the type is
    # what refused it ("approval result refused"): the same lease handed
    # over as an `ObserveBaselineApproval` grants.
    assert result.lease.generation_digest == world.generation.digest
    assert result.lease.generation_number == world.generation.number

    def as_v2(**kwargs):
        verified = approval(**kwargs)
        return ObserveBaselineApproval(
            lease=verified.lease, approval_id=verified.approval_id,
            approval_seq=verified.approval_seq, security_epoch=verified.security_epoch)

    _assert_granted(world, world.run(approval=as_v2))


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
    from azazel_nexus_runtime.activation_markers import (
        GRANTABLE_UNITS,
        MARKER_GUARDED_UNITS,
        NON_GRANTABLE_MARKER_UNITS,
    )
    assert activation_pass.UNIT_SCOPE is GRANTABLE_UNITS
    assert activation_pass.UNIT_CHECK_SCOPE is MARKER_GUARDED_UNITS
    assert activation_pass.UNIT_CHECK_SCOPE == GRANTABLE_UNITS | NON_GRANTABLE_MARKER_UNITS
    assert GRANTABLE_UNITS == frozenset(EDGE_SCOPE + DECOY_UNITS) | {
        "azazel-mio-referenced.service", "azazel-auditd-loop.service"}
    assert "azazel-knowledge-contextd.service" not in GRANTABLE_UNITS
    assert not hasattr(activation_pass, "P4_UNIT_SCOPE")
    import ast
    source = Path(activated.__file__).read_text()
    names = {node.id for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Name)}
    assert "GRANTABLE_UNITS" in names and "_P4_GRANTABLE" not in names


def test_markers_are_never_written_for_a_unit_this_phase_cannot_grant(tmp_path, monkeypatch):
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    (tmp_path / "run/azazel-activation").mkdir(parents=True, mode=0o755)
    for unit in ("azazel-watchdog.service", "azazel-mio-locald.service",
                 "azazel-auditd.service", "azazel-model-fetchd.service",
                 "azazel-knowledge-contextd.service"):
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


@pytest.mark.parametrize("failing", ["high_water", "markers"])
def test_a_failing_failure_record_never_skips_the_emergency_remask(world, monkeypatch, failing):
    original = activated.ActivationDaemon._record

    def record(self, event):
        if event["event_type"] in ("activation.high_water_unraised",
                                   "activation.grant_markers_unwritten"):
            raise ValueError("synthetic non-audit failure")
        return original(self, event)

    monkeypatch.setattr(activated.ActivationDaemon, "_record", record)
    replaced = {"raise_high_water": _raises()} if failing == "high_water" else {}
    if failing == "markers":
        import shutil
        shutil.rmtree(world.root / "run/azazel-activation")
    with pytest.raises(RuntimeError, match="emergency remask failures"):
        world.run(**replaced)
    assert all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert world.markers() is None


# -- edge-core in scope (P5) ------------------------------------------------------


def _reasons(outcome):
    return {v.unit: v.reason for v in outcome.verdicts}


def _supporting_granted(world, outcome):
    assert sorted(outcome.granted) == list(SCOPE)
    assert world.markers() == list(SCOPE)
    assert world.manager.state(EDGE) is UnitState.MASKED
    for unit in SCOPE:
        assert world.manager.state(unit) is UnitState.ENABLED
    assert len(world.raised) == 1


def test_edge_core_is_granted_and_marked_on_package_and_fresh_boot_health(edge_world):
    outcome = edge_world.run()
    assert sorted(outcome.granted) == list(EDGE_SCOPE)
    assert edge_world.markers() == list(EDGE_SCOPE)
    assert edge_world.manager.state(EDGE) is UnitState.ENABLED
    # Running is not required to launch, and readiness is not claimed.
    assert outcome.edge.launchable and not outcome.edge.running
    assert not outcome.edge_baseline_ready
    grant = next(e for e in edge_world.events()
                 if e["event_type"] == "activation.unit_granted" and e["unit"] == EDGE)
    assert grant["reason"].startswith("package-admitted:")
    event = edge_world.inputs_event()
    assert event["missing_producers"] == list(ALWAYS_MISSING)
    assert event["observed_inputs"]["edge_evidence"] == "launchable"
    assert event["observed_inputs"]["edge_package_binding"] == "bound"
    assert "edge_missing_for_launch" not in event["observed_inputs"]
    assert edge_world.package_digest not in edge_world.ledger_path.read_text().split(
        '"observed_inputs"', 1)[1]


def test_an_approval_without_edge_core_leaves_it_outside_the_lease(edge_world):
    edge_world.sign(units=SCOPE)
    outcome = edge_world.run()
    _supporting_granted(edge_world, outcome)
    assert _reasons(outcome)[EDGE].startswith("outside_lease_scope")


def _assert_edge_withheld(world, outcome, missing):
    _supporting_granted(world, outcome)
    reason = _reasons(outcome)[EDGE]
    assert reason.startswith("edge_not_ready: "), reason
    assert sorted(reason.split(": ", 1)[1].split(",")) == sorted(missing)
    event = world.inputs_event()
    assert event["missing_producers"] == list(ALWAYS_MISSING) + [EDGE_EVIDENCE]
    assert event["observed_inputs"]["edge_evidence"] == "not_launchable"
    assert sorted(event["observed_inputs"]["edge_missing_for_launch"]) == sorted(missing)
    assert set(event["observed_inputs"]["producers"].values()) == {"verified"}


@pytest.mark.parametrize("probe", [
    dict(boot=OTHER_BOOT),
    dict(contract=PROBE_CONTRACT_V1),
    dict(observed_at="2026-10-20T23:50:00Z"),
    dict(health=Evidence.FAILED),
    dict(health=Evidence.NOT_CHECKED),
], ids=["other-boot", "v1", "expired", "health-failed", "health-not-checked"])
def test_edge_core_is_withheld_on_stale_or_failed_health_and_supporting_proceed(edge_world, probe):
    edge_world.probe(**probe)
    outcome = edge_world.run()
    _assert_edge_withheld(edge_world, outcome, ["health_endpoint_healthy"])
    assert edge_world.inputs_event()["observed_inputs"]["edge_package_binding"] == "bound"


def test_a_failed_or_timed_out_preflight_withholds_edge_core_only(edge_world):
    """No result this boot (the preflight failed or timed out) is no health.

    It also names no probed package, which is never bound (L3).
    """
    edge_world.probe_path.unlink()
    _assert_edge_withheld(edge_world, edge_world.run(),
                          ["digest_matches", "health_endpoint_healthy"])


@pytest.mark.parametrize("name", ["bin/azazel-edge-core", "config/redirect_policy.yaml"])
def test_an_extracted_component_changed_after_publication_refuses_the_lease(edge_world, name):
    """The archive is intact, but the file the unit runs or reads is not the signed one."""
    path = edge_world.edge_root / name
    path.write_bytes(path.read_bytes() + b"# rewritten after extraction\n")
    assert installed_package_digest(package_root=edge_world.edge_root) == (
        edge_world.package_digest)
    _assert_refused(edge_world, edge_world.run(), ["operational_generation_publisher"])


@pytest.mark.parametrize("damage", ["absent", "symlink", "group-writable"])
def test_an_unreadable_extracted_component_withholds_edge_core_only(edge_world, damage):
    path = edge_world.edge_root / "bin/azazel-edge-core"
    if damage == "absent":
        path.unlink()
    elif damage == "symlink":
        target = edge_world.root / "elsewhere"
        target.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(target)
    else:
        path.chmod(0o775)
    outcome = edge_world.run()
    _supporting_granted(edge_world, outcome)
    assert _reasons(outcome)[EDGE] == "edge_not_ready: digest_matches"
    event = edge_world.inputs_event()
    assert event["observed_inputs"]["edge_package_binding"] == "package_refused"
    assert event["observed_inputs"]["edge_evidence"] == "not_launchable"


def test_an_unreadable_boot_id_withholds_edge_core_only(edge_world):
    edge_world.boot_path.unlink()
    _assert_edge_withheld(edge_world, edge_world.run(), ["health_endpoint_healthy"])


def test_an_edge_reader_that_raises_withholds_edge_core_only(edge_world):
    def broken(*, now):
        raise OSError("private reader detail")
    outcome = edge_world.run(edge_state=broken)
    _assert_edge_withheld(edge_world, outcome, ["package_present", "version_matches",
                                                "digest_matches", "health_endpoint_healthy"])
    assert "private reader detail" not in edge_world.ledger_path.read_text()


@pytest.mark.parametrize("damage", ["artifact", "manifest", "absent"])
def test_failing_package_checks_withhold_edge_core_and_supporting_proceed(edge_world, damage):
    if damage == "artifact":
        (edge_world.edge_root / PIN.artifact_name).write_bytes(b"tampered")
    elif damage == "manifest":
        manifest = edge_world.edge_root / PIN.manifest_name
        manifest.write_text(manifest.read_text().replace('"observe_only": true',
                                                         '"observe_only": false'))
    else:
        import shutil
        shutil.rmtree(edge_world.edge_root)
    outcome = edge_world.run()
    _supporting_granted(edge_world, outcome)
    assert _reasons(outcome)[EDGE].startswith("edge_not_ready: ")
    assert "digest_matches" in _reasons(outcome)[EDGE]
    event = edge_world.inputs_event()
    assert event["observed_inputs"]["edge_package_binding"] == "package_refused"
    assert event["observed_inputs"]["edge_evidence"] == "not_launchable"
    assert event["missing_producers"] == list(ALWAYS_MISSING) + [EDGE_EVIDENCE]


def test_a_package_digest_unreadable_by_the_pass_withholds_edge_core_only(edge_world):
    """The package checks pass for the reader but the pass got no digest."""
    def refused():
        raise edge_package.EdgePackageRefused("private reader detail")
    outcome = edge_world.run(edge_package_digest=refused)
    _assert_edge_withheld(edge_world, outcome, ["digest_matches"])
    assert edge_world.inputs_event()["observed_inputs"]["edge_package_binding"] == (
        "package_refused")


def test_an_installed_package_other_than_the_signed_one_refuses_the_lease(edge_world):
    """The operator's signature binds the package: another one is another baseline."""
    edge_world.package_digest, _ = edge_world.package(binary=elf_stub() + b"another edge-core")
    edge_world.probe()  # even a fresh, healthy probe of the new package
    _assert_refused(edge_world, edge_world.run(), ["operational_generation_publisher"])


def test_a_probe_of_another_package_than_the_signed_one_withholds_edge_core(edge_world):
    """The reader already refuses a probe of a package not on disk; the pass

    additionally requires the probe's digest to be the signed pin.
    """
    other = "sha256:" + "e" * 64

    def state(*, now):
        return EdgeBaselineState(True, True, True, True, False, observed_at=NOW,
                                 package_version=PIN.version, package_digest=other)
    _assert_edge_withheld(edge_world, edge_world.run(edge_state=state), ["digest_matches"])


def test_the_edge_core_unit_file_is_measured_with_its_environment_lines(edge_world):
    measured = []
    original = edge_world.producers

    def producers(**replaced):
        made = original(**replaced)

        def unit_files(units):
            files = made.unit_files(units)
            measured.append(dict(files))
            return files
        return replace(made, unit_files=unit_files)

    edge_world.producers = producers
    edge_world.run()
    assert measured and all(m[EDGE] == EDGE_UNIT_FILE for m in measured)
    assert b"Environment=" in EDGE_UNIT_FILE
    edge_world.raised.clear()
    edge_world.unit_files[EDGE] = EDGE_UNIT_FILE.replace(b"redirect_policy.yaml",
                                                         b"enforce_policy.yaml")
    _assert_refused(edge_world, edge_world.run(), ["operational_generation_publisher"])


def test_a_generation_without_the_package_pin_is_refused_for_an_edge_policy(edge_world):
    """A baseline published for the SUPPORTING scope does not admit edge-core."""
    edge_world.store.create(
        build_observe_baseline(units=list(SCOPE),
                               unit_files={u: edge_world.unit_files[u] for u in SCOPE}),
        created_at="2026-10-20T00:00:00Z",
        commissioning_digest=evidence_commissioning_digest(edge_world.evidence),
        commissioning_evidence_binding=edge_world.evidence.binding)
    _assert_refused(edge_world, edge_world.run(), ["operational_generation_publisher"])


def test_edge_evidence_never_supplies_a_lease_or_health(edge_world):
    edge_world.healthy = False
    _assert_refused(edge_world, edge_world.run(), ["node_health"])
    assert edge_world.manager.state(EDGE) is UnitState.MASKED


def test_edge_core_granted_without_launchable_evidence_trips_the_wire(edge_world, monkeypatch):
    original = activation_pass.collect_pass_inputs

    def forged(**kwargs):
        inputs = original(**kwargs)
        inputs.edge_package_binding = "package_refused"
        return inputs

    monkeypatch.setattr(activation_pass, "collect_pass_inputs", forged)
    with pytest.raises(RuntimeError, match="edge-core without launchable"):
        edge_world.run()
    assert all(edge_world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert edge_world.markers() is None


def test_the_production_pass_reads_edge_evidence_at_the_fixed_paths(monkeypatch):
    """The controller reads the preflight's result; it never runs or requires it."""
    seen = []
    monkeypatch.setattr(edge_package, "installed_baseline_state",
                        lambda **kwargs: seen.append(kwargs) or "state")
    producers = activation_pass.production_producers(commissioning_evidence=lambda: None)
    assert producers.edge_state(now=NOW) == "state"
    assert seen == [{"now": NOW}]
    assert producers.edge_package_digest is edge_package.installed_package_digest
    assert producers.edge_components is edge_package.measure_extracted_components
    source = Path(activation_pass.__file__).read_text()
    for forbidden in ("StartUnit", "subprocess", "HEALTH_ARGV", "azazel-edge-probe-preflight"):
        assert forbidden not in source


# -- what the running manager loaded (#251 H-1, M-3) -------------------------


def _loaded(unit, **changes):
    return loaded_as_declared(unit) | changes


ENTRYD = "azazel-mio-entryd.service"


@pytest.mark.parametrize("loaded", [
    _loaded(ENTRYD, Conditions=[]),
    _loaded(ENTRYD, Conditions=[("ConditionPathExists", False, False,
                                 "/run/azazel-activation/granted/azazel-mio-entryd.service", 0),
                                ("ConditionPathExists", True, False, "/", 1)]),
    _loaded(ENTRYD, Conditions=[("ConditionPathExists", False, True,
                                 "/run/azazel-activation/granted/azazel-mio-entryd.service", 0)]),
    _loaded(ENTRYD, Asserts=[("AssertPathExists", False, False, "/", 1)]),
    _loaded(ENTRYD, FragmentPath=f"/etc/systemd/system/{ENTRYD}"),
    _loaded(ENTRYD, DropInPaths=[f"/run/systemd/system/{ENTRYD}.d/override.conf"]),
    _loaded(ENTRYD, LoadState="bad-setting"),
    _loaded(ENTRYD, LoadState="not-found"),
    _loaded(ENTRYD, Id="azazel-mio-locald.service"),
    _loaded(ENTRYD, Conditions=None),
    "not a mapping",
], ids=["no-condition", "extra-condition", "negated-marker", "assert", "fragment-in-etc",
        "drop-in", "bad-setting", "not-found", "other-id", "malformed-conditions", "malformed"])
def test_a_loaded_unit_not_as_declared_refuses_everything(world, loaded):
    """A unit loaded earlier in the boot runs its loaded definition (H-1)."""
    world.systemd.loaded[ENTRYD] = loaded
    _assert_refused(world, world.run(), ["systemd_loaded_units"])


def test_an_unreviewed_manager_profile_refuses_everything(world):
    """M-3: Version and UnitPath are checked on the ordinary path too."""
    from azazel_nexus_runtime.units import UnitOperationFailed
    world.systemd.profile_error = UnitOperationFailed("unsupported systemd unit search path")
    _assert_refused(world, world.run(), ["systemd_loaded_units"])


def test_an_unreadable_loaded_unit_refuses_everything(world):
    def unreadable(unit):
        raise RuntimeError("private bus detail")
    world.systemd.loaded_unit = unreadable
    _assert_refused(world, world.run(), ["systemd_loaded_units"])
    assert "private bus detail" not in world.ledger_path.read_text()


@pytest.mark.parametrize("loaded", [None, _loaded(ENTRYD, LoadState="masked", Conditions=[])],
                         ids=["not-loaded", "masked"])
def test_a_unit_not_loaded_or_masked_in_the_manager_is_accepted(world, loaded):
    world.systemd.loaded[ENTRYD] = loaded
    assert sorted(world.run().granted) == list(SCOPE)


def test_the_loaded_check_reads_every_marker_guarded_unit_not_only_the_policy(world):
    world.run()
    assert world.systemd.reads == sorted(activation_pass.UNIT_CHECK_SCOPE)


def test_the_production_loaded_check_refuses_without_the_controller_session(monkeypatch):
    from azazel_nexus_runtime import activation_loaded_units
    checked = []
    monkeypatch.setattr(activation_loaded_units, "require_grantable_unit_files",
                        lambda units: checked.append(tuple(units)))
    producers = activation_pass.production_producers(commissioning_evidence=lambda: None)
    with pytest.raises(Exception, match="systemd manager reader required"):
        producers.loaded_units(list(SCOPE))
    reader = FakeManagerReader()
    producers = activation_pass.production_producers(commissioning_evidence=lambda: None,
                                                     systemd=reader)
    producers.loaded_units(list(SCOPE))
    assert reader.reads == list(SCOPE)
    assert checked == [tuple(SCOPE), tuple(SCOPE)]


def test_the_production_loaded_check_refuses_a_grantable_unit_file_first(monkeypatch):
    from azazel_nexus_runtime import activation_loaded_units
    from azazel_nexus_runtime.activation_unit_files import UnitContentRefused

    def refused(units):
        raise UnitContentRefused("unit file lacks the grant-marker lines")
    monkeypatch.setattr(activation_loaded_units, "require_grantable_unit_files", refused)
    reader = FakeManagerReader()
    producers = activation_pass.production_producers(commissioning_evidence=lambda: None,
                                                     systemd=reader)
    with pytest.raises(activation_loaded_units.LoadedUnitRefused):
        producers.loaded_units(list(SCOPE))
    assert reader.reads == []


@pytest.mark.parametrize("loaded", [
    _loaded(EDGE, Conditions=[]),
    _loaded(EDGE, DropInPaths=[f"/etc/systemd/system/{EDGE}.d/x.conf"]),
    _loaded(EDGE, Requires=["system.slice"]),
], ids=["no-condition", "drop-in", "no-requires"])
def test_a_grantable_unit_outside_the_policy_loaded_not_as_declared_refuses(world, loaded):
    """READY would release its queued start though this policy never names it."""
    assert EDGE not in world.policy.units
    world.systemd.loaded[EDGE] = loaded
    _assert_refused(world, world.run(), ["systemd_loaded_units"])


def test_non_grantable_context_broker_still_requires_its_loaded_start_guard(world):
    context = "azazel-knowledge-contextd.service"
    assert context not in activation_pass.UNIT_SCOPE
    assert context in activation_pass.UNIT_CHECK_SCOPE
    world.systemd.loaded[context] = _loaded(context, Conditions=[])
    _assert_refused(world, world.run(), ["systemd_loaded_units"])


def test_a_policy_narrower_than_the_grantable_set_grants_only_its_units(
        tmp_path, monkeypatch):
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    monkeypatch.setattr(activated, "_collect_input_status", lambda _root: {})
    _owned_by_the_test(monkeypatch)
    narrow = World(tmp_path, units=SCOPE[:2])
    outcome = narrow.run()
    assert sorted(outcome.granted) == list(SCOPE[:2])
    assert narrow.markers() == list(SCOPE[:2])
    assert narrow.systemd.reads == sorted(activation_pass.UNIT_CHECK_SCOPE)


@pytest.mark.parametrize("field", ["Requires", "After"])
def test_a_loaded_unit_not_waiting_for_the_controller_refuses(world, field):
    world.systemd.loaded[ENTRYD] = _loaded(ENTRYD, **{field: ["system.slice"]})
    _assert_refused(world, world.run(), ["systemd_loaded_units"])


def test_only_the_second_profile_read_failing_refuses_everything(world):
    """The read after the units detects a re-executed manager."""
    from azazel_nexus_runtime.units import UnitOperationFailed
    world.systemd.profiles = ["reviewed", UnitOperationFailed("unsupported systemd version")]
    _assert_refused(world, world.run(), ["systemd_loaded_units"])


def test_a_profile_changed_between_the_reads_refuses_everything(world):
    world.systemd.profiles = ["reviewed", "reviewed-but-another-version"]
    _assert_refused(world, world.run(), ["systemd_loaded_units"])


# -- the commissioning storage label (#242 §4 "Diagnostic only") ---------------

#: The real collection; the `world` fixtures replace it with an empty one.
_COLLECT = activated._collect_input_status


def _storage(kind):
    """`luks_backing` as the controller would see it: True, False, None or an error."""
    def reader(path, **_kwargs):
        assert path == Path("/etc/azazel/commissioning")
        if kind == "raises":
            raise RuntimeError("private /dev/mapper/azn-commissioning 254:3 detail")
        return {"luks": True, "plain": False, "unknown": None}[kind]
    return reader


def _pass_with_storage(tmp_path, monkeypatch, kind, **replaced):
    """One pass in a fresh world whose real input collection sees `kind`."""
    world = World(tmp_path / kind)
    monkeypatch.setattr(activated, "load_operator_trust", lambda: world.trust)
    monkeypatch.setattr(activated, "read_boot_id", lambda: BOOT)
    monkeypatch.setattr(activated, "load_declared_node", lambda: world.node)
    monkeypatch.setattr(activated, "luks_backing", _storage(kind))
    monkeypatch.setattr(activated, "_collect_input_status", lambda _root: _COLLECT(Path("/")))
    outcome = world.run(**replaced)
    states = {d.name: world.manager.state(d.name) for d in CORE_UNITS}
    events = world.events()
    labels = [e["observed_inputs"].pop("commissioning_storage", None) for e in events
              if e["event_type"] == "activation.inputs_incomplete"]
    decided = (outcome, states, list(world.manager.calls), world.markers(),
               list(world.raised), world.high_water, events)
    return decided, labels, world.ledger_path.read_text()


@pytest.mark.parametrize("replaced", [{}, {"commissioning_evidence": _raises()}],
                         ids=["granting", "commissioning-refused"])
def test_the_storage_label_never_changes_the_decision(tmp_path, monkeypatch, replaced):
    """Only the label differs: outcome, units, markers, floors and ledger do not."""
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    _owned_by_the_test(monkeypatch)
    results = {kind: _pass_with_storage(tmp_path, monkeypatch, kind, **replaced)
               for kind in ("luks", "plain", "unknown", "raises")}
    assert results["luks"][1] == ["luks_backed"]
    assert results["plain"][1] == ["not_luks_backed"]
    assert results["unknown"][1] == [None]  # undetermined: no key, no guess
    assert results["raises"][1] == [None]  # no third value and no reader text
    assert (results["luks"][0] == results["plain"][0] == results["unknown"][0]
            == results["raises"][0])
    outcome, *_, events = results["luks"][0]
    assert sorted(outcome.granted) == ([] if replaced else list(SCOPE))
    assert any(e["event_type"] == "activation.high_water_raised" for e in events) is not bool(
        replaced)
    for _, _, text in results.values():
        for leak in ("/etc/azazel", "/dev", "mapper", "254:3", "private"):
            assert leak not in text, leak



# -- Deception Lite exposure units (#196 P1) ---------------------------------


@pytest.mark.parametrize("unit", DECOY_UNITS)
def test_a_policy_naming_an_exposure_unit_is_refused_as_a_whole(world, unit):
    """Not in `ACTIVATION_UNIT_ALLOWLIST`: no lease can ever hold one."""
    with pytest.raises(ApprovalRefused):
        make_policy(units=tuple(sorted(SCOPE + (unit,))))
    world.policy = SimpleNamespace(units=tuple(sorted(SCOPE + (unit,))))
    _assert_refused(world, world.run(), ["activation_policy"])


def test_the_exposure_units_are_withheld_and_never_marked(world):
    outcome = world.run()
    assert sorted(outcome.granted) == list(SCOPE)
    for unit in DECOY_UNITS:
        assert unit in outcome.withheld
        assert world.manager.state(unit) is UnitState.MASKED
    assert not set(DECOY_UNITS) & set(world.markers())


@pytest.mark.parametrize("unit", DECOY_UNITS)
def test_the_exposure_units_are_checked_as_loaded_like_every_grantable_unit(world, unit):
    """#253: a queued start must wait for its marker though no policy names it."""
    world.systemd.loaded[unit] = _loaded(unit, Conditions=[])
    _assert_refused(world, world.run(), ["systemd_loaded_units"])
    assert unit in world.systemd.reads


@pytest.mark.parametrize("unit", DECOY_UNITS)
def test_the_exposure_units_loaded_as_declared_are_accepted_and_still_withheld(world, unit):
    world.systemd.loaded[unit] = _loaded(unit)
    outcome = world.run()
    assert sorted(outcome.granted) == list(SCOPE)
    assert unit in outcome.withheld


@pytest.mark.parametrize("forged_units", [
    (DECOY_UNITS[2],), (DECOY_UNITS[0],), (DECOY_UNITS[1],), DECOY_UNITS,
], ids=["decoy", "namespace", "helper", "all-three"])
def test_an_exposure_unit_granted_trips_the_wire(world, monkeypatch, forged_units):
    """Even a forged lease naming them and a library that granted them are
    narrowed: any one exposure unit, or all three together (#196 (a))."""
    from azazel_nexus.activation import ActivationOutcome, UnitVerdict

    original = activated.ActivationDaemon.activate

    def forged(self, **kwargs):
        outcome = original(self, **kwargs)
        lease = kwargs["lease"]
        if lease is not None:
            object.__setattr__(lease, "units", lease.units | set(forged_units))
        return ActivationOutcome(outcome.generation, outcome.verdicts + tuple(
            UnitVerdict(unit, True, "granted") for unit in forged_units), edge=outcome.edge)

    monkeypatch.setattr(activated.ActivationDaemon, "activate", forged)
    with pytest.raises(RuntimeError, match="Deception Lite exposure unit"):
        world.run()
    assert all(world.manager.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert world.markers() is None


def test_the_pass_checks_a_decoded_policy_against_the_narrower_scope(world):
    """Second layer (review m5): even a policy object that names an exposure
    unit -- forged past the decoder -- is refused by the pass itself."""
    assert activation_pass.POLICY_UNIT_SCOPE == (
        activation_pass.UNIT_SCOPE - frozenset(DECOY_UNITS))
    from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST
    assert activation_pass.POLICY_UNIT_SCOPE == frozenset(ACTIVATION_UNIT_ALLOWLIST)
    forged = make_policy()
    object.__setattr__(forged, "units", tuple(sorted(SCOPE + (DECOY_UNITS[1],))))
    world.policy = forged
    _assert_refused(world, world.run(), ["activation_policy"])


# -- Edge issuer authentication and the rollback floor ------------------------


@pytest.fixture
def floor_state(tmp_path, monkeypatch):
    """The floor writer against a temporary state directory owned by the test."""
    from contextlib import contextmanager

    from azazel_nexus_runtime import edge_issuer_floor

    directory = tmp_path / "floor-state"
    directory.mkdir(mode=0o711)
    directory.chmod(0o711)

    @contextmanager
    def state_directory():
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(edge_issuer_floor, "_state_directory", state_directory)
    monkeypatch.setattr(edge_issuer_floor, "_OWNER", os.getuid())
    return edge_issuer_floor


def _floor_events(world):
    return [e["edge_issuer_floor"] for e in world.events()
            if e["event_type"] == "activation.edge_issuer_floor"]


def test_a_grant_withdrawn_because_its_record_failed_never_raises_the_floor(
        edge_world, floor_state, monkeypatch):
    from azazel_nexus.audit import AuditUnavailable

    original = AuditLedger.append

    def append(self, event, *args, **kwargs):
        if event.get("event_type") == "activation.inputs_incomplete":
            raise AuditUnavailable("synthetic")
        return original(self, event, *args, **kwargs)

    monkeypatch.setattr(AuditLedger, "append", append)
    with pytest.raises(RuntimeError, match="activation pass record could not be appended"):
        edge_world.run(edge_issuer=lambda: _issuer(edge_world.package_digest))
    assert edge_world.markers() is None
    assert floor_state.read_edge_floor() is None


def test_a_floor_record_that_cannot_be_appended_withdraws_nothing(
        edge_world, floor_state, monkeypatch):
    from azazel_nexus.audit import AuditUnavailable

    original = AuditLedger.append

    def append(self, event, *args, **kwargs):
        if event.get("event_type") == "activation.edge_issuer_floor":
            raise AuditUnavailable("synthetic")
        return original(self, event, *args, **kwargs)

    monkeypatch.setattr(AuditLedger, "append", append)
    outcome = edge_world.run(edge_issuer=lambda: _issuer(edge_world.package_digest))
    assert EDGE in outcome.granted and EDGE in edge_world.markers()
    assert floor_state.read_edge_floor() is not None


def _issuer(digest, *, authenticated=True):
    from azazel_nexus.edge_issuer import IssuerVerification

    if not authenticated:
        return IssuerVerification(digest_verified=True, issuer_authenticated=False,
                                  issuer_status="not_configured")
    return IssuerVerification(
        digest_verified=True, issuer_authenticated=True, issuer_status="authenticated",
        issuer="edge-release", revocation_status="none", revoked="none",
        floor_status="absent", version=PIN.version, package_digest=digest)


def _ledger_shape(world):
    """Event types, and the recorded input keys, of one pass: what main records."""
    return ([e["event_type"] for e in world.events()],
            sorted(world.inputs_event()["observed_inputs"]))


def test_a_node_without_an_issuer_records_exactly_what_main_records(
        edge_world, floor_state, tmp_path):
    """Not configured and nothing noted: the ledger has main's shape, byte for byte in keys."""
    outcome = edge_world.run(edge_issuer=lambda: _issuer(None, authenticated=False))
    assert EDGE in outcome.granted
    observed = edge_world.inputs_event()["observed_inputs"]
    assert "edge_issuer" not in observed
    assert _floor_events(edge_world) == []
    assert floor_state.read_edge_floor() is None
    # The same node with no issuer producer at all -- the path main runs.
    main_like = World(tmp_path / "main-like", units=EDGE_SCOPE)
    main_like.run(edge_issuer=None)
    assert _ledger_shape(edge_world) == _ledger_shape(main_like)
    assert observed == main_like.inputs_event()["observed_inputs"]


def test_an_unconfigured_issuer_with_a_note_records_both_facts(edge_world, floor_state):
    from azazel_nexus.edge_issuer import IssuerVerification

    noted = IssuerVerification(digest_verified=True, issuer_authenticated=False,
                               issuer_status="not_configured",
                               notes=("revocations_present_without_anchor",))
    edge_world.run(edge_issuer=lambda: noted)
    observed = edge_world.inputs_event()["observed_inputs"]
    assert observed["edge_issuer"]["digest_verified"] is True
    assert observed["edge_issuer"]["issuer_authenticated"] is False
    assert observed["edge_issuer"]["notes"] == ["revocations_present_without_anchor"]


def test_a_floor_raise_that_raises_escapes_nothing(edge_world, floor_state, monkeypatch, capsys):
    def broken(*args, **kwargs):
        raise RuntimeError("synthetic")

    monkeypatch.setattr(floor_state, "raise_floor_after_grant", broken)
    outcome = edge_world.run(edge_issuer=lambda: _issuer(edge_world.package_digest))
    assert EDGE in outcome.granted and EDGE in edge_world.markers()
    assert _floor_events(edge_world) == ["failed"]
    assert "edge issuer floor failed" in capsys.readouterr().err


def test_an_unrecorded_floor_outcome_is_visible_in_the_journal(edge_world, floor_state,
                                                              monkeypatch, capsys):
    from azazel_nexus.audit import AuditUnavailable

    original = AuditLedger.append

    def append(self, event, *args, **kwargs):
        if event.get("event_type") == "activation.edge_issuer_floor":
            raise AuditUnavailable("synthetic")
        return original(self, event, *args, **kwargs)

    monkeypatch.setattr(AuditLedger, "append", append)
    edge_world.run(edge_issuer=lambda: _issuer(edge_world.package_digest))
    assert ("edge issuer floor raised; its ledger record was not appended"
            in capsys.readouterr().err)


def test_an_authenticated_edge_grant_raises_the_floor_after_the_marker(edge_world, floor_state):
    outcome = edge_world.run(edge_issuer=lambda: _issuer(edge_world.package_digest))
    assert EDGE in outcome.granted and EDGE in edge_world.markers()
    observed = edge_world.inputs_event()["observed_inputs"]
    assert observed["edge_issuer"]["issuer_authenticated"] is True
    assert _floor_events(edge_world) == ["raised"]
    # Raised after, and only after, the pass record that completes the grant.
    kinds = [e["event_type"] for e in edge_world.events()]
    assert kinds.index("activation.inputs_incomplete") < kinds.index(
        "activation.edge_issuer_floor")
    floor = floor_state.read_edge_floor()
    assert (floor.version, floor.package_digest) == (PIN.version, edge_world.package_digest)
    # Labels only: no digest reaches the recorded inputs.
    assert edge_world.package_digest not in json.dumps(observed)


def test_a_withheld_edge_core_never_raises_the_floor(edge_world, floor_state):
    def refused():
        raise edge_package.EdgePackageRefused("synthetic")
    outcome = edge_world.run(edge_package_digest=refused,
                             edge_issuer=lambda: _issuer(edge_world.package_digest))
    assert EDGE not in outcome.granted
    assert _floor_events(edge_world) == []
    assert floor_state.read_edge_floor() is None


def test_an_issuer_reader_that_raises_authenticates_nothing(edge_world, floor_state):
    def broken():
        raise OSError("unreadable")
    outcome = edge_world.run(edge_issuer=broken)
    assert EDGE in outcome.granted  # issuer authentication is not required to admit
    observed = edge_world.inputs_event()["observed_inputs"]
    assert "edge_issuer" not in observed
    assert _floor_events(edge_world) == []  # unauthenticated: the ledger is unchanged
    assert floor_state.read_edge_floor() is None


def test_the_production_pass_reads_the_issuer_at_the_fixed_paths():
    producers = activation_pass.production_producers(commissioning_evidence=lambda: None)
    assert producers.edge_issuer is edge_package.installed_issuer_verification
