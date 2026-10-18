"""Lane C stand-ins are structural; Lane A need not be installed to test gates."""

import json
from dataclasses import dataclass, replace
from enum import Enum
from typing import Protocol

import pytest
from nacl.signing import SigningKey

from azazel_nexus.commissioning import CommissioningRecord, ConfirmedRole
from azazel_nexus.integration_broker import routing as r
from azazel_nexus.knowledge_peer import canonical
from azazel_nexus.lite_cache import Freshness
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy

NOW = "2026-10-18T00:00:30Z"
ISSUED = "2026-10-18T00:00:00Z"
EXPIRES = "2026-10-18T00:01:00Z"
DIGEST = "sha256:" + "a" * 64


class BrokerState(str, Enum):
    ADMITTED = "admitted"
    OBSERVE_ONLY = "observe_only"
    ACTIVE_BOUNDED = "active_bounded"


class AdapterManifest(Protocol):
    adapter_id: str
    capability_set: frozenset[str]
    privacy_class: PrivacyClass


class AdapterRecord(Protocol):
    adapter_id: str
    state: BrokerState
    manifest_digest: str


@dataclass(frozen=True)
class Manifest:
    adapter_id: str = "adapter-1"
    capability_set: frozenset[str] = frozenset({"telemetry_read"})
    privacy_class: PrivacyClass = PrivacyClass.P1_SANITIZED


@dataclass(frozen=True)
class Record:
    adapter_id: str = "adapter-1"
    state: BrokerState = BrokerState.ADMITTED
    manifest_digest: str = DIGEST


@pytest.fixture
def data_args():
    return {
        "adapter_record": Record(),
        "manifest": Manifest(),
        "observed_at": ISSUED,
        "expires_at": EXPIRES,
        "now": NOW,
        "mission": "mission-test",
        "alias_key": b"test-alias-key",
        "policy": SanitizerPolicy.from_mapping(
            {
                "version": "test-v1",
                "remote_default": "deny",
                "classes": {"P1-sanitized": {"remote": "allow", "fields": ["text"]}},
                "redactions": ["secret"],
                "limits": {"max_bytes": 4096},
            }
        ),
    }


def test_telemetry_is_sanitized_knowledge_data(data_args):
    payload = {
        "text": "UnitManager.start('evil'); transition(ACTIVE_BOUNDED)",
        "secret": "do not retain",
    }
    result = r.route_telemetry(payload, **data_args)
    assert isinstance(result, r.DataRecord)
    assert result.destination == "knowledge"
    assert result.adapter_id == "adapter-1" and result.manifest_digest == DIGEST
    assert (result.observed_at, result.expires_at, result.evaluated_at) == (
        ISSUED,
        EXPIRES,
        NOW,
    )
    assert result.freshness is Freshness.CURRENT
    assert result.privacy_class is PrivacyClass.P1_SANITIZED
    assert result.trust == "untrusted data"
    assert json.loads(result.frame)["body"] == {"text": payload["text"]}
    assert result.redaction.removed == ("secret",)
    payload["text"] = "mutated"
    assert "UnitManager" in result.frame.decode()
    assert "do not retain" not in result.frame.decode()


def test_advisory_only_targets_views(data_args):
    data_args["manifest"] = Manifest(capability_set=frozenset({"advisory_read"}))
    result = r.route_advisory({"text": "credential retrieval requested"}, **data_args)
    assert isinstance(result, r.DataRecord)
    assert result.destination == "operator/mio"
    assert result.trust == "untrusted data"
    assert result.manifest_digest == DIGEST and result.expires_at == EXPIRES


@pytest.mark.parametrize("privacy", list(PrivacyClass))
def test_privacy_uses_existing_deny_policy(data_args, privacy):
    data_args["manifest"] = replace(data_args["manifest"], privacy_class=privacy)
    result = r.route_telemetry({"text": "observation"}, **data_args)
    assert isinstance(result, r.DataRecord) is (privacy is PrivacyClass.P1_SANITIZED)


@pytest.mark.parametrize(
    "changes",
    [
        {"now": EXPIRES},
        {"now": "2026-10-17T23:59:59Z"},
        {"expires_at": "bad"},
        {"observed_at": "2026-10-18T00:00:00"},
        {"adapter_record": Record(state="quarantined")},
        {"adapter_record": Record(adapter_id="other")},
        {"adapter_record": Record(manifest_digest="")},
        {"manifest": Manifest(capability_set=frozenset({"advisory_read"}))},
        {
            "manifest": Manifest(
                capability_set=frozenset({"telemetry_read", "exposure_change"})
            )
        },
        {"manifest": Manifest(privacy_class="unknown")},
    ],
)
def test_data_refusals(data_args, changes):
    assert isinstance(
        r.route_telemetry({"text": "data"}, **(data_args | changes)), r.GateRefusal
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"command": "activate"},
        {"text": object()},
        {"text": float("nan")},
        {"text": "x" * 65537},
    ],
)
def test_invalid_payload_cannot_escape_sanitizer(data_args, payload):
    assert isinstance(r.route_telemetry(payload, **data_args), r.GateRefusal)


def test_observe_only_can_read_without_widening(data_args):
    record = Record(state=BrokerState.OBSERVE_ONLY)
    result = r.route_telemetry(
        {"text": "data"}, **(data_args | {"adapter_record": record})
    )
    assert isinstance(result, r.DataRecord)
    assert record.state is BrokerState.OBSERVE_ONLY


def topology():
    return CommissioningRecord(
        roles=(
            ConfirmedRole(
                (("serial", "test-nic"),), "deception_bridge", "test-operator", ISSUED
            ),
        ),
        profiles_present=("hardware", "resource", "topology"),
        created_at=ISSUED,
    )


def lease_document(proposal, topo):
    return {
        "schema": r.EDGE_LEASE_SCHEMA,
        "adapter_id": proposal.adapter_id,
        "proposal_digest": proposal.digest,
        "commissioning_digest": topo.digest(),
        "issued_at": ISSUED,
        "expires_at": EXPIRES,
    }


def signed_lease(document, key, domain=r.EDGE_LEASE_DOMAIN):
    payload = canonical(document)
    return r.EdgeLease(key.sign(domain + payload).signature + payload)


@pytest.fixture
def gate_args():
    topo = topology()
    key = SigningKey.generate()
    proposal = r.ExposureChangeProposal(
        "adapter-1", b'{"exposure":"opaque proposal data"}'
    )
    return {
        "proposal": proposal,
        "adapter_record": Record(),
        "manifest": Manifest(capability_set=frozenset({"exposure_change"})),
        "edge_lease": signed_lease(lease_document(proposal, topo), key),
        "failsafe": r.ManagementFailsafe(
            topo.digest(), "management-1", "management-1", ISSUED, True
        ),
        "topology": topo,
        "edge_keys": {"edge-test": bytes(key.verify_key)},
        "now": NOW,
        "dry_run": True,
        "human_confirmed": True,
    }


def test_valid_gate_produces_only_an_intent(gate_args):
    result = r.gate_exposure_proposal(**gate_args)
    assert isinstance(result, r.DispatchIntent)
    assert result.proposal_digest == gate_args["proposal"].digest
    assert result.manifest_digest == DIGEST and result.edge_signer == "edge-test"
    assert result.expires_at == EXPIRES
    assert result.dry_run is True and result.human_confirmed is True
    assert not hasattr(result, "payload")
    assert r.deliver(result) == r.GateRefusal("transport unavailable: Fabric#25")


@pytest.mark.parametrize(
    "state",
    [
        "DISABLED",
        "DISCOVERED",
        "STAGED",
        "OBSERVE_ONLY",
        "APPROVAL_PENDING",
        "WITHDRAWING",
        "DEGRADED",
        "QUARANTINED",
        "FAILED",
    ],
)
def test_exposure_requires_admitted_state(gate_args, state):
    gate_args["adapter_record"] = Record(state=state)
    assert isinstance(r.gate_exposure_proposal(**gate_args), r.GateRefusal)


def test_active_bounded_is_also_eligible(gate_args):
    gate_args["adapter_record"] = Record(state=BrokerState.ACTIVE_BOUNDED)
    assert isinstance(r.gate_exposure_proposal(**gate_args), r.DispatchIntent)


@pytest.mark.parametrize(
    "changes",
    [
        {"dry_run": False},
        {"human_confirmed": False},
        {"human_confirmed": 1},
        {"dry_run": "true"},
        {"edge_keys": {}},
        {"now": EXPIRES},
        {"proposal": r.ExposureChangeProposal("other", b"data")},
        {"proposal": r.ExposureChangeProposal("adapter-1", b"changed")},
        {"proposal": r.ExposureChangeProposal("adapter-1", b"")},
        {"proposal": r.ExposureChangeProposal("adapter-1", b"x" * 65537)},
        {"manifest": Manifest()},
        {"manifest": Manifest(adapter_id="other")},
        {
            "manifest": Manifest(
                capability_set=frozenset({"exposure_change", "advisory_read"})
            )
        },
        {"edge_lease": r.EdgeLease(b"unsigned")},
    ],
)
def test_every_gate_is_independent(gate_args, changes):
    assert isinstance(r.gate_exposure_proposal(**(gate_args | changes)), r.GateRefusal)


@pytest.mark.parametrize(
    "change",
    [
        {"healthy": False},
        {"healthy": 1},
        {"management_path": ""},
        {"checked_path": "other"},
        {"commissioning_digest": "other"},
        {"checked_at": "2026-10-17T23:59:29Z"},
        {"checked_at": EXPIRES},
        {"checked_at": "bad"},
    ],
)
def test_management_failsafe_is_mandatory_and_recent(gate_args, change):
    gate_args["failsafe"] = replace(gate_args["failsafe"], **change)
    assert isinstance(r.gate_exposure_proposal(**gate_args), r.GateRefusal)


@pytest.mark.parametrize(
    "roles,profiles",
    [
        ((), ("hardware", "resource", "topology")),
        (topology().roles, ("hardware", "resource")),
    ],
)
def test_role_unassigned_or_incomplete_topology_stays_observe_only(
    gate_args, roles, profiles
):
    # No RAM argument exists: even a host with 1 TiB cannot bypass topology.
    gate_args["topology"] = replace(
        gate_args["topology"], roles=roles, profiles_present=profiles
    )
    assert r.gate_exposure_proposal(**gate_args) == r.GateRefusal(
        "topology ineligible: OBSERVE_ONLY"
    )
    assert gate_args["adapter_record"] == Record()


@pytest.mark.parametrize(
    "field,value",
    [
        ("adapter_id", "other"),
        ("proposal_digest", "sha256:" + "b" * 64),
        ("commissioning_digest", "other"),
        ("schema", "azazel-nexus/adapter-manifest/1"),
        ("issued_at", EXPIRES),
        ("expires_at", NOW),
        ("issued_at", "invalid"),
        ("extra", "not permitted"),
    ],
)
def test_even_signed_bad_bindings_are_refused(gate_args, field, value):
    key = SigningKey.generate()
    doc = lease_document(gate_args["proposal"], gate_args["topology"])
    doc[field] = value
    gate_args.update(
        edge_lease=signed_lease(doc, key),
        edge_keys={"edge-test": bytes(key.verify_key)},
    )
    assert isinstance(r.gate_exposure_proposal(**gate_args), r.GateRefusal)


@pytest.mark.parametrize(
    "domain",
    [
        b"",
        b"azazel-nexus/adapter-manifest/v1\0",
        b"azazel-nexus/knowledge-response/v1\0",
    ],
)
def test_wrong_domain_cannot_grant_edge_authority(gate_args, domain):
    key = SigningKey.generate()
    gate_args.update(
        edge_keys={"edge-test": bytes(key.verify_key)},
        edge_lease=signed_lease(
            lease_document(gate_args["proposal"], gate_args["topology"]), key, domain
        ),
    )
    result = r.gate_exposure_proposal(**gate_args)
    assert result == r.GateRefusal("invalid Edge lease signature")


def test_lease_reverified_and_expiry_checked_on_reuse(gate_args):
    assert isinstance(r.gate_exposure_proposal(**gate_args), r.DispatchIntent)
    gate_args["now"] = EXPIRES
    assert isinstance(r.gate_exposure_proposal(**gate_args), r.GateRefusal)
    gate_args["now"] = NOW
    gate_args["edge_keys"] = {"edge-test": bytes(SigningKey.generate().verify_key)}
    assert isinstance(r.gate_exposure_proposal(**gate_args), r.GateRefusal)


@pytest.mark.parametrize(
    "intent",
    [
        None,
        {},
        "activate",
        r.DispatchIntent("fake", DIGEST, DIGEST, DIGEST, "fake", EXPIRES, True, True),
    ],
)
def test_delivery_always_refuses(intent):
    assert r.deliver(intent).reason == "transport unavailable: Fabric#25"
