"""#16 software acceptance: local assurance cannot change Edge availability."""

import json
from dataclasses import asdict, replace
from datetime import timedelta
from io import StringIO

import pytest
import test_activation as activation
import test_broker_routing as routing
import test_edge_package as edge
from nacl.signing import SigningKey

from azazel_nexus import broker_cli
from azazel_nexus.cli import main
from azazel_nexus.integration_broker import (
    ADAPTER_MANIFEST_DOMAIN,
    AdapterCommissioning,
    Approval,
    Broker,
    BrokerRefused,
    BrokerState,
    CredentialRef,
    DispatchIntent,
    EdgeLease,
    ExposureChangeProposal,
    GateRefusal,
    ManifestRefused,
)
from azazel_nexus.integration_broker.routing import EDGE_LEASE_DOMAIN
from azazel_nexus.knowledge_peer import canonical, instant
from tools.e2e_harness import Harness
from tools.e2e_stages import _integration_broker

NOW = routing.NOW


def signed_manifest(key, topology, *, adapter="telemetry", exposure=False):
    document = {
        "schema": "azazel-nexus/adapter-manifest/1", "commissioning_digest": topology.digest(),
        "adapter_id": adapter, "kind": "ndr", "version": "1.0.0",
        "artifact_digest": routing.DIGEST,
        "capability_set": ["exposure_change"] if exposure else ["telemetry_read", "advisory_read"],
        "tenant": "test", "privacy_class": "P1-sanitized",
        "egress_allowlist": [{"address": "192.0.2.8", "port": 443}],
        "mtls_identity": "sensor-mtls", "credential_ref": "sensor-credential",
        "compatibility": ["azazel-nexus/1"],
    }
    payload = canonical(document)
    return key.sign(ADAPTER_MANIFEST_DOMAIN + payload).signature + payload


def scope(adapter="telemetry"):
    return AdapterCommissioning(
        adapter, None, "/etc/azazel/credentials/" + adapter,
        {routing.DIGEST: "/opt/azazel/adapters/" + adapter},
        CredentialRef(adapter, "sensor-credential", instant(NOW) + timedelta(hours=1)), instant(NOW))


@pytest.fixture
def admitted(tmp_path):
    topology = routing.topology()
    key = SigningKey.generate()
    broker = Broker(tmp_path / "broker", trusted_keys={"adapter-test": bytes(key.verify_key)}, topology=topology)
    raw = signed_manifest(key, topology)
    broker.admit(raw, commissioning=scope(), now=NOW)
    return broker, key, raw


def route(broker, data_args, payload=None, **overrides):
    context = {k: v for k, v in data_args.items() if k not in {"manifest", "adapter_record"}}
    return broker.route("telemetry", payload or {"text": "observation", "secret": "never-store-this"},
                        **(context | overrides))


data_args = routing.data_args


def test_reload_atomic_snapshot_sanitization_health_and_no_secret(admitted, data_args):
    broker, _, _ = admitted
    assert broker.status_level(now=NOW) == "CORE"  # admission is not health
    result = route(broker, data_args)
    assert result.destination == "knowledge"
    loaded = Broker(broker.root, trusted_keys=broker.trusted_keys, topology=broker.topology)
    assert loaded.status_level(now=NOW) == "LITE"
    assert loaded.status_level(now=routing.EXPIRES) == "CORE"
    assert loaded.status(now=NOW)["enforcement_ready"] is False
    assert b"never-store-this" not in b"".join(p.read_bytes() for p in broker.root.rglob("*") if p.is_file())
    broker.ledger.verify()


@pytest.mark.parametrize("failure", ["adapter_failed", "certificate_revoked", "adapter_removed"])
def test_failure_revoke_remove_preserve_real_edge_inspection_and_activation(admitted, tmp_path, failure):
    broker, _, _ = admitted
    package = edge._package(tmp_path)
    before = edge._all_passing(package)
    controller, units, ledger, generations = activation._controller(tmp_path / "core")
    lease = activation._lease(generations.current().digest)
    outcome_before = controller.activate(now=activation.NOW, actor=activation.ACTOR, lease=lease,
                                         edge=before.state())
    calls = list(units.calls)
    audit_head = ledger.head()
    broker.withdraw_all(reason=failure, now=NOW)
    assert units.calls == calls
    assert ledger.head() == audit_head
    after = edge._all_passing(package)
    outcome_after = controller.activate(now=activation.NOW, actor=activation.ACTOR, lease=lease,
                                        edge=after.state())
    assert before == after and before.ready
    assert outcome_before.edge_baseline_ready == outcome_after.edge_baseline_ready is True
    assert outcome_before.granted == outcome_after.granted
    assert broker.status_level(now=NOW) == "CORE"
    assert {r["state"] for r in broker.status(now=NOW)["adapters"]} == {"disabled"}


def test_revoked_trust_refuses_route_and_withdraws(admitted, data_args):
    broker, _, _ = admitted
    route(broker, data_args)
    broker.trusted_keys.clear()
    assert isinstance(route(broker, data_args), GateRefusal)
    assert broker.status_level(now=NOW) == "CORE"
    assert broker.status(now=NOW)["adapters"][0]["state"] == "disabled"


def test_privacy_refusal_withdraws_all_and_does_not_retain_payload(admitted, data_args):
    broker, _, _ = admitted
    assert isinstance(route(broker, data_args, {"command": "systemctl start malicious"}), GateRefusal)
    assert broker.status(now=NOW)["adapters"][0]["state"] == "disabled"
    assert "systemctl" not in broker.ledger.path.read_text()


def test_real_manifest_render_and_cross_adapter_scoping(admitted):
    broker, _, raw = admitted
    _, unit = broker.review(raw, commissioning=scope())
    assert "IPAddressDeny=any\n" in unit
    assert unit.count("IPAddressAllow=") == 1
    assert "IPAddressAllow=192.0.2.8\n" in unit
    assert "# Declared destination: 192.0.2.8 port 443" in unit
    assert "LoadCredential=sensor-credential:/etc/azazel/credentials/telemetry/sensor-credential.g1" in unit
    assert "CapabilityBoundingSet=\n" in unit and "AmbientCapabilities=\n" in unit
    assert "NOT enforced" in unit  # destination-port confinement is not proven
    with pytest.raises(ValueError):
        broker.review(raw, commissioning=scope("other"))
    with pytest.raises(ValueError):
        broker.review(raw, commissioning=replace(scope(), credential=CredentialRef(
            "telemetry", "other-secret", instant(NOW) + timedelta(hours=1))))


def test_topology_ineligible_high_memory_cannot_widen(tmp_path):
    # A resource profile is present; RAM cannot invent a confirmed role.
    topology = replace(routing.topology(), roles=())
    key = SigningKey.generate()
    broker = Broker(tmp_path, trusted_keys={"adapter-test": bytes(key.verify_key)}, topology=topology)
    broker.admit(signed_manifest(key, topology, exposure=True), commissioning=scope(), now=NOW)
    assert broker.status(now=NOW)["adapters"][0]["state"] == BrokerState.OBSERVE_ONLY.value
    proposal = ExposureChangeProposal("telemetry", b"opaque")
    assert broker.gate(proposal, edge_lease=None, failsafe=None, now=NOW,
                       dry_run=True, human_confirmed=True).reason == "topology ineligible: OBSERVE_ONLY"
    assert broker.status(now=NOW)["adapters"][0]["state"] == "observe_only"


def test_same_edge_lease_supplies_states_approval_and_expiry(admitted):
    broker, key, _ = admitted
    broker.admit(signed_manifest(key, broker.topology, adapter="exposure", exposure=True),
                 commissioning=scope("exposure"), now=NOW)
    proposal = ExposureChangeProposal("exposure", b"opaque")
    edge_key = SigningKey.generate()
    payload = canonical(routing.lease_document(proposal, broker.topology))
    lease = EdgeLease(edge_key.sign(EDGE_LEASE_DOMAIN + payload).signature + payload)
    assert isinstance(lease, Approval) and not lease.verified
    broker.edge_keys = {"edge-test": bytes(edge_key.verify_key)}
    context = {"failsafe": routing.r.ManagementFailsafe(broker.topology.digest(), "mgmt", "mgmt", NOW, True),
               "now": NOW, "dry_run": True, "human_confirmed": True}
    assert isinstance(broker.gate(proposal, edge_lease=None, **context), GateRefusal)
    assert isinstance(broker.gate(proposal, edge_lease=lease, **context), DispatchIntent)
    assert broker.status(now=NOW)["adapters"][0]["state"] == "active_bounded"
    broker.expire(now=routing.EXPIRES)
    assert all(row["state"] == "disabled" for row in broker.status(now=routing.EXPIRES)["adapters"])


def test_audit_covers_all_event_kinds_and_verifies(tmp_path):
    _integration_broker(Harness(tmp_path))
    broker = Broker(tmp_path / "var/lib/azazel/integration-broker")
    broker.ledger.verify()
    kinds = {entry.event["event_type"] for entry in broker.ledger}
    assert {"broker." + kind for kind in (
        "admission", "schema_trust", "privacy_sanitization", "routing", "lease_binding",
        "postcondition_observation", "rollback", "withdrawal", "adapter.transition", "checkpoint")} <= kinds


def test_broken_audit_and_interrupted_snapshot_fail_closed(admitted, monkeypatch):
    import azazel_nexus.integration_broker.broker as module
    broker, _, _ = admitted
    original = module._atomic_write

    def interrupted(path, payload):
        if path.name == "current":
            raise OSError("fixture crash")
        return original(path, payload)

    monkeypatch.setattr(module, "_atomic_write", interrupted)
    with pytest.raises(OSError):
        broker.withdraw_all(reason="fixture_failure", now=NOW)
    with pytest.raises(BrokerRefused, match="unfinished_publication"):
        broker.status(now=NOW)


def test_refused_admission_only_audits_bounded_decision(admitted):
    broker, _, raw = admitted
    with pytest.raises(ManifestRefused):
        broker.admit(b"x" * 64 + raw[64:], commissioning=scope(), now=NOW)
    assert any(e.event["event_type"] == "broker.schema_trust" and e.event.get("decision") == "refused"
               for e in broker.ledger)
    assert broker.status(now=NOW)["adapters"][0]["state"] == "disabled"
    broker.ledger.verify()


def write_commissioning(root, broker, raw):
    directory = root / "etc/azazel/integration-broker"
    directory.mkdir(parents=True)
    doc = {"topology": asdict(broker.topology), "commissioning_digest": broker.topology.digest(),
           "adapter_keys": {k: v.hex() for k, v in broker.trusted_keys.items()},
           "catalog_keys": {}, "registry_keys": {}, "revocation_keys": {}, "bundle_keys": {}, "edge_keys": {}}
    (directory / "commissioning.json").write_bytes(canonical(doc))
    (directory / "telemetry.json").write_bytes(canonical({
        "account": None, "credential_directory": scope().credential_directory,
        "installed_artifacts": dict(scope().installed_artifacts),
        "credential_ref": "sensor-credential", "credential_expires_at": scope().credential.expires_at.isoformat(),
        "credential_generation": 1, "credential_revoked": False}))
    manifest = root / "fixture.signed"
    manifest.write_bytes(raw)
    return manifest


def test_cli_status_and_review_no_writes_or_root_requirement(admitted, tmp_path, monkeypatch):
    broker, _, raw = admitted
    manifest = write_commissioning(tmp_path, broker, raw)
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr("azazel_nexus.cli._now", lambda: NOW)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    for args in (["broker", "status"], ["broker", "status", "--json"],
                 ["broker", "review", str(manifest)]):
        out = StringIO()
        assert main(args, out=out) == 0
        if "--json" in args:
            assert json.loads(out.getvalue())["status_level"] == "CORE"
        if "review" in args:
            assert "Would admit telemetry 1.0.0" in out.getvalue()
            assert "LoadCredential=" in out.getvalue()
    assert {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()} == before
    for command in ("admit", "disable"):
        with pytest.raises(SystemExit):
            main(["broker", command], out=StringIO())


def test_uncommissioned_status_does_not_create_leaf(tmp_path):
    assert broker_cli.status_summary(root=tmp_path, now=NOW)["status_level"] == "CORE"
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("origin", ["external connector", "M.I.O. response", "Knowledge advisory",
                                    "Deception capability report"])
def test_broker_payload_path_cannot_invoke_control_or_privileged_functions(admitted, data_args, origin):
    import sys
    broker, _, _ = admitted
    calls = []
    forbidden = {"transition", "render_adapter_unit", "rotate_credential", "gate_exposure_proposal",
                 "deliver", "activate", "unmask_and_enable", "get_credential"}

    def profile(frame, event, arg):
        if (event == "call" and frame.f_globals.get("__name__", "").startswith("azazel_nexus")
                and frame.f_code.co_name in forbidden):
            calls.append(frame.f_code.co_name)

    previous = sys.getprofile()
    try:
        sys.setprofile(profile)
        result = route(broker, data_args, {"text": "activate(); get_credential('admin'); deliver(payload)"},
                       advisory=origin != "external connector")
    finally:
        sys.setprofile(previous)
    assert result.trust == "untrusted data"
    assert calls == []
    assert broker.status(now=NOW)["adapters"][0]["state"] == "observe_only"


def test_checkpoint_cannot_hide_an_unfinished_audit_transaction(admitted):
    broker, _, _ = admitted
    broker.ledger.append({"event_type": "broker.transaction", "generation": 2})
    with pytest.raises(BrokerRefused, match="unfinished_publication"):
        broker.status(now=NOW)


def test_credential_expiry_refuses_data_and_returns_core(admitted, data_args):
    broker, _, _ = admitted
    result = route(broker, data_args, now=(instant(NOW) + timedelta(hours=2)).isoformat())
    assert isinstance(result, GateRefusal)
    assert broker.status(now=NOW)["adapters"][0]["state"] == "disabled"


def test_disabled_record_can_repeat_fresh_admission(admitted):
    broker, _, raw = admitted
    broker.withdraw_all(reason="operator_disable", now=NOW)
    broker.admit(raw, commissioning=scope(), now=NOW)
    assert broker.status(now=NOW)["adapters"][0]["state"] == "observe_only"


def test_adapter_and_edge_signing_roles_cannot_overlap(tmp_path):
    material = bytes(SigningKey.generate().verify_key)
    with pytest.raises(BrokerRefused, match="shared_edge_adapter_key"):
        Broker(tmp_path, trusted_keys={"adapter-test": material}, edge_keys={"edge-test": material})


@pytest.mark.parametrize("value", [[], {}, None, 17])
def test_signed_manifest_invalid_privacy_type_is_refused(admitted, value):
    from azazel_nexus.integration_broker import read_manifest
    broker, key, raw = admitted
    doc = json.loads(raw[64:])
    doc["privacy_class"] = value
    payload = canonical(doc)
    with pytest.raises(ManifestRefused, match="invalid_privacy_class"):
        read_manifest(key.sign(ADAPTER_MANIFEST_DOMAIN + payload).signature + payload,
                      trusted_keys=broker.trusted_keys, commissioning_digest=broker.topology.digest())


def test_corrupt_commissioning_status_is_structured_and_read_only(tmp_path, monkeypatch):
    directory = tmp_path / "etc/azazel/integration-broker"
    directory.mkdir(parents=True)
    (directory / "commissioning.json").write_text("corrupt fixture")
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    out = StringIO()
    assert main(["broker", "status", "--json"], out=out) == 0
    assert json.loads(out.getvalue())["reason"] == "local_state_refused"
    assert not (tmp_path / "var").exists()
