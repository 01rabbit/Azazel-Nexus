"""Authenticated runtime commissioning input and fail-closed daemon wiring."""

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from nacl.signing import SigningKey

from azazel_nexus.commissioning import confirm_roles
from azazel_nexus.commissioning_approval import commissioning_proposal_payload
from azazel_nexus.commissioning_draft import draft_bytes
from azazel_nexus.fabric_boundary import (
    project_hardware_inventory,
    project_resource_profile,
    project_reviewed_topology,
)
from azazel_nexus.generation import GenerationStore
from azazel_nexus.inventory import InterfaceReadout
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
    approval_message,
)
from azazel_nexus.audit import AuditLedger
from azazel_nexus_runtime import activated, commissioning_input
from azazel_nexus_runtime.activated import RollbackFailed
from azazel_nexus_runtime.hardware_inventory import HardwareObservation
from azazel_nexus_runtime.netlink import NetlinkUnavailable
from azazel_nexus_runtime.units import RecordingUnitManager

pytest.importorskip("azazel_fabric")


NODE_ID = "node-synthetic-runtime"
OPERATOR = "operator-a"
AT = "2026-10-13T00:00:00Z"


@pytest.fixture
def evidence_inputs():
    """A complete linked proposal, real Fabric projections, and ephemeral keys."""
    readout = InterfaceReadout(
        "synthetic0",
        {
            "bus_path": "pci/synthetic",
            "permanent_mac": "02:00:00:00:00:01",
            "pci_id": "8086:15b8",
            "driver": "synthetic",
        },
        driver_version="synthetic-1",
    )
    observation = HardwareObservation(
        collected_at=AT,
        interfaces=(readout,),
        platform={
            "vendor": None,
            "product_name": None,
            "board_serial": None,
            "firmware_vendor": None,
            "firmware_version": None,
        },
        storage_devices=(
            {
                "bus_path": "pci/storage",
                "size_bytes": 4096,
                "removable": False,
                "rotational": False,
                "model_name": None,
                "serial": None,
            },
        ),
        limitations=(
            "read-only-snapshot-not-authenticated",
            "snapshot-not-atomic",
            "platform-fields-unavailable",
            "storage-optional-identity-unavailable",
        ),
    )
    inventory = project_hardware_inventory(
        readouts=observation.interfaces,
        platform=observation.platform,
        storage_devices=observation.storage_devices,
        limitations=observation.limitations,
        node_id=NODE_ID,
        inventory_id="inventory-synthetic-retained",
        collected_at=observation.collected_at,
    )
    proposal = observation.commissioning_proposal()
    record = confirm_roles(
        proposal,
        ((readout, "observation"),),
        operator=OPERATOR,
        at=AT,
        profiles_present=(),
    )
    draft_payload = draft_bytes(record)
    operator_key = SigningKey.generate()
    trust = OperatorTrust({OPERATOR: bytes(operator_key.verify_key)})
    draft_signature = operator_key.sign(
        approval_message(ApprovalPurpose.COMMISSIONING, draft_payload)
    ).signature
    resource_observation = {
        "schema": "azazel-nexus/resource-observation/v1",
        "observed_at": AT,
        "architecture": "arm64",
        "measurements": {
            "usable_memory_mib": 16095,
            "online_logical_cpus": 4,
            "mission_available_mib": 10000,
        },
        "unavailable": [],
        "limitations": [
            "gpu-unmeasured",
            "throughput-unmeasured",
            "thermal-power-unmeasured",
            "cgroup-limits-unmeasured",
            "storage-trust-unverified",
        ],
        "admission": "not-evaluated",
    }
    resource = project_resource_profile(
        observation=resource_observation,
        inventory=inventory,
        profile_id="resource-synthetic",
    )
    topology = project_reviewed_topology(
        payload=draft_payload,
        signature=draft_signature,
        operator=OPERATOR,
        trust=trust,
        current=proposal,
        inventory=inventory,
        profile_id="topology-synthetic",
        observed_at=AT,
    )
    context = {
        "inventory": inventory,
        "resource_profile": resource,
        "topology_profile": topology,
        "record_id": "record-synthetic-runtime",
        "operator": OPERATOR,
        "confirmed_at": AT,
    }
    retained = commissioning_proposal_payload(**context)
    full_signature = operator_key.sign(
        approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL, retained)
    ).signature
    return SimpleNamespace(
        node=SimpleNamespace(node_id=NODE_ID),
        observation=observation,
        inventory=inventory,
        trust=trust,
        operator_key=operator_key,
        binding_key=b"b" * 32,
        expected=retained,
        payload=retained,
        signature=full_signature,
        draft_payload=draft_payload,
    )


class StableAddresses:
    def __init__(self):
        self.reads = 0

    def __call__(self, _name):
        return "02:00:00:00:00:01"

    def unchanged(self):
        self.reads += 1
        return True


def _wire_loader(monkeypatch, inputs, *, initial=None, changes=None, observations=None):
    initial = initial or {}
    changes = changes or {}
    monkeypatch.setattr(
        commissioning_input,
        "load_declared_node",
        _sequence(initial.get("node", inputs.node), changes.get("node")),
    )
    monkeypatch.setattr(
        commissioning_input,
        "load_operator_trust",
        _sequence(initial.get("trust", inputs.trust), changes.get("trust")),
    )
    monkeypatch.setattr(
        commissioning_input,
        "load_commissioning_binding_key",
        _sequence(initial.get("key", inputs.binding_key), changes.get("key")),
    )
    retained_pair = (inputs.expected, inputs.payload, inputs.signature)
    monkeypatch.setattr(
        commissioning_input,
        "read_proposal_review_inputs",
        _sequence(initial.get("retained", retained_pair), changes.get("retained")),
    )
    collected = iter(observations or (inputs.observation, inputs.observation))
    monkeypatch.setattr(
        commissioning_input,
        "collect_hardware_observations",
        lambda *, permanent_mac_reader: next(collected),
    )
    addresses = StableAddresses()
    monkeypatch.setattr(commissioning_input, "_PermanentAddresses", lambda: addresses)
    return addresses


def _sequence(first, second=None):
    values = iter((first, first if second is None else second))
    return lambda: next(values)


def test_loader_verifies_and_returns_full_retained_proposal(evidence_inputs, monkeypatch):
    addresses = _wire_loader(monkeypatch, evidence_inputs)

    evidence = commissioning_input.load_commissioning_evidence()

    assert evidence.payload == evidence_inputs.payload
    assert evidence.signature == evidence_inputs.signature
    assert evidence.current_inventory
    current = json.loads(evidence.current_inventory)
    assert current["interfaces"][0]["permanent_mac"] == "02:00:00:00:00:01"
    assert current["storage_devices"][0]["size_bytes"] == 4096
    assert evidence.binding.startswith("hmac-sha256:")
    assert addresses.reads == 2
    rendered = repr(evidence)
    assert evidence.payload.decode() not in rendered
    assert evidence.signature.hex() not in rendered
    assert NODE_ID not in rendered


@pytest.mark.parametrize(
    "failure",
    [
        "revoked",
        "bad-key",
        "changed-trust",
        "changed-key",
        "changed-draft",
        "changed-node",
        "hardware",
        "netlink",
    ],
)
def test_loader_refuses_untrusted_or_changed_runtime_inputs(
    evidence_inputs, monkeypatch, failure
):
    changes = {}
    initial = {}
    observations = None
    if failure == "revoked":
        initial["trust"] = OperatorTrust(
            {OPERATOR: bytes(evidence_inputs.operator_key.verify_key)}, frozenset({OPERATOR})
        )
    elif failure == "bad-key":
        initial["trust"] = OperatorTrust(
            {OPERATOR: bytes(SigningKey.generate().verify_key)}
        )
    elif failure == "changed-trust":
        changes["trust"] = OperatorTrust(
            {OPERATOR: bytes(evidence_inputs.operator_key.verify_key)}, frozenset({OPERATOR})
        )
    elif failure == "changed-key":
        changes["key"] = b"c" * 32
    elif failure == "changed-draft":
        changes["retained"] = (
            evidence_inputs.expected,
            evidence_inputs.payload + b" ",
            evidence_inputs.signature,
        )
    elif failure == "changed-node":
        changes["node"] = SimpleNamespace(node_id="node-changed")
    elif failure == "hardware":
        altered = replace(
            evidence_inputs.observation,
            platform={**evidence_inputs.observation.platform, "vendor": "changed"},
        )
        observations = (altered, altered)

    _wire_loader(
        monkeypatch,
        evidence_inputs,
        initial=initial,
        changes=changes,
        observations=observations,
    )
    if failure == "netlink":
        class BrokenAddresses:
            def __init__(self):
                raise NetlinkUnavailable("synthetic private netlink detail")

        monkeypatch.setattr(commissioning_input, "_PermanentAddresses", BrokenAddresses)

    with pytest.raises(ApprovalRefused) as refused:
        commissioning_input.load_commissioning_evidence()

    assert "synthetic private" not in str(refused.value)
    assert NODE_ID not in str(refused.value)


def _temporary_run_once(monkeypatch, tmp_path, manager, loader):
    real_store = GenerationStore
    real_ledger = AuditLedger
    paths = {"generation": [], "ledger": []}

    def generation_store(_production_path):
        store_path = tmp_path / "generations"
        store_path.mkdir(parents=True, exist_ok=True)
        paths["generation"].append(store_path)
        store = real_store(store_path)
        if store.current() is None:
            store.create(
                {"synthetic.conf": b"synthetic=true\n"},
                created_at="2026-10-13T00:00:00Z",
                commissioning_digest="sha256:" + "1" * 64,
            )
        return store

    def audit_ledger(_production_path):
        path = tmp_path / "state" / "activation.jsonl"
        paths["ledger"].append(path)
        return real_ledger(path)

    monkeypatch.setattr(activated, "GenerationStore", generation_store)
    monkeypatch.setattr(activated, "AuditLedger", audit_ledger)
    monkeypatch.setattr(activated, "load_commissioning_evidence", loader)
    monkeypatch.setattr(activated, "_collect_input_status", lambda _root: {})
    return paths


def test_run_once_masks_before_loading_and_passes_evidence_to_real_decision(
    evidence_inputs, monkeypatch, tmp_path
):
    _wire_loader(monkeypatch, evidence_inputs)
    manager = RecordingUnitManager(item.name for item in activated.CORE_UNITS)
    loaded = []

    def load_after_preflight():
        assert manager.calls[: len(activated.CORE_UNITS)] == [
            ("mask", item.name) for item in activated.CORE_UNITS
        ]
        value = commissioning_input.load_commissioning_evidence()
        loaded.append(value)
        return value

    paths = _temporary_run_once(monkeypatch, tmp_path, manager, load_after_preflight)
    actual_activate = activated.ActivationDaemon.activate
    observed = {}

    def capture_activation(self, **kwargs):
        observed.update(kwargs)
        return actual_activate(self, **kwargs)

    monkeypatch.setattr(activated.ActivationDaemon, "activate", capture_activation)

    outcome = activated._run_once(
        manager=manager,
        root=Path("/"),
        now="2026-10-14T00:00:00Z",
        actor="azazel-activated",
    )

    assert observed["commissioning_evidence"] is loaded[0]
    assert observed["require_commissioning_evidence"] is True
    assert observed["lease"] is None
    assert observed["record"] is None
    assert observed["healthy"] is False
    assert outcome.granted == ()
    assert all(not verdict.granted for verdict in outcome.verdicts)
    assert paths["generation"] == [tmp_path / "generations"]
    assert paths["ledger"] == [tmp_path / "state" / "activation.jsonl"]
    log = paths["ledger"][0].read_text(encoding="utf-8")
    assert "verified_current_binding" in log
    assert evidence_inputs.payload.decode() not in log
    assert NODE_ID not in log


def test_run_once_attempts_every_preflight_mask_before_refusing_loader(
    monkeypatch, tmp_path
):
    manager = RecordingUnitManager(item.name for item in activated.CORE_UNITS)
    failing_unit = activated.CORE_UNITS[0].name

    def mask(unit):
        manager.calls.append(("mask", unit))
        if unit == failing_unit:
            raise OSError("synthetic mask failure")

    monkeypatch.setattr(manager, "mask", mask)
    loads = []
    paths = _temporary_run_once(
        monkeypatch,
        tmp_path,
        manager,
        lambda: loads.append("load"),
    )

    with pytest.raises(RollbackFailed):
        activated._run_once(
            manager=manager,
            root=Path("/"),
            now="2026-10-14T00:00:00Z",
            actor="azazel-activated",
        )

    first_mask_sweep = [("mask", item.name) for item in activated.CORE_UNITS]
    assert manager.calls == first_mask_sweep + first_mask_sweep
    assert loads == []
    assert paths["ledger"][0].exists()


def test_run_once_loader_exception_still_runs_refusing_decision_without_raw_log(
    monkeypatch, tmp_path
):
    manager = RecordingUnitManager(item.name for item in activated.CORE_UNITS)
    paths = _temporary_run_once(
        monkeypatch,
        tmp_path,
        manager,
        lambda: (_ for _ in ()).throw(RuntimeError("private synthetic detail")),
    )
    actual_activate = activated.ActivationDaemon.activate
    observed = {}

    def capture_activation(self, **kwargs):
        observed.update(kwargs)
        return actual_activate(self, **kwargs)

    monkeypatch.setattr(activated.ActivationDaemon, "activate", capture_activation)

    outcome = activated._run_once(
        manager=manager,
        root=Path("/"),
        now="2026-10-14T00:00:00Z",
        actor="azazel-activated",
    )

    assert observed["commissioning_evidence"] is None
    assert observed["require_commissioning_evidence"] is True
    assert observed["lease"] is None
    assert observed["healthy"] is False
    assert outcome.granted == ()
    log = paths["ledger"][0].read_text(encoding="utf-8")
    assert "unavailable" in log
    assert "private synthetic detail" not in log


def test_staged_run_once_never_loads_host_commissioning_evidence(monkeypatch, tmp_path):
    manager = RecordingUnitManager(item.name for item in activated.CORE_UNITS)
    loads = []
    paths = _temporary_run_once(
        monkeypatch,
        tmp_path,
        manager,
        lambda: loads.append("load"),
    )
    outcome = activated._run_once(
        manager=manager,
        root=tmp_path / "staged-root",
        now="2026-10-14T00:00:00Z",
        actor="azazel-activated",
    )

    assert loads == []
    assert outcome.granted == ()
    assert all(path.is_relative_to(tmp_path) for path in paths["generation"] + [p.parent for p in paths["ledger"]])
