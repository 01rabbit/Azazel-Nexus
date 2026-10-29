"""The explanation ledger projected onto Fabric `mio_contracts` (P6).

`fabric_boundary.project_explanation` turns one explanation-ledger record into
a Fabric `ClaimSet`; `incident_explaind` keeps it in the ledger beside the
record when the pinned Fabric is present. The tests that need Fabric skip
without it (CI installs no Fabric); the reader-side checks and the absent-
Fabric path run everywhere.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import get_args

import pytest

from azazel_nexus import fabric_boundary
from azazel_nexus.audit import AuditLedger
from azazel_nexus.edge_intake import EvidenceRecord
from azazel_nexus.fabric_boundary import FABRIC_PIN, project_explanation
from azazel_nexus.incident_explain import (
    FABRIC_RECORD_FIELD,
    explanation_summary,
    read_record,
)
from azazel_nexus.lite_import import KnowledgeRef
from azazel_nexus.sanitizer import NEVER_REMOTE, PrivacyClass
from azazel_nexus_runtime import incident_explaind as daemon
from test_edge_intake import parsed
from test_incident_explain import transition

DIGEST = "sha256:" + "b" * 64
CONTRACT_DOC = Path(__file__).resolve().parents[2] / "docs" / "contract-ownership.md"

#: docs/contract-ownership.md §3.3: Nexus's privacy classes against Fabric's
#: `mio_contracts.PrivacyClass`. Held here, not in the product: nothing is sent
#: in Fabric's shape, so no product code maps one onto the other.
FABRIC_PRIVACY_CLASS = {
    "P0-public": "public",
    "P1-sanitized": "internal",
    "P2-mission": "sensitive",
    "P3-restricted": "restricted",
}


def _ref(technique="T1059", freshness="static", citation="MITRE ATT&CK technique"):
    return {"technique_id": technique, "name": "Command and Scripting Interpreter",
            "summary": "Check context", "claim_id": technique, "bundle_digest": DIGEST,
            "freshness": freshness, "source_kind": "knowledge_lite", "generation": 4,
            "trust_check": "verified", "as_of": "2026-10-18T00:00:00Z", "citation": citation}


def _record(refs=None):
    refs = [_ref()] if refs is None else refs
    return read_record({
        "incident_id": "inc-0123456789abcdef", "explained_at": 1790000000.0,
        "transition": "opened", "edge_would": "throttle",
        "policy_reason": "severity_elevated_throttle_reversible", "attack_type": "absent",
        "technique_ids": ["T1059", "T1059.001"],
        "mio": {"route": "unavailable", "outcome": "unavailable", "reason": "mio_unavailable",
                "text": None},
        "knowledge_refs": refs, "knowledge_state": "available" if refs else "skipped",
        "failure_codes": ["mio_unavailable"]})


def _stored(record):
    """The ledger form `as_ledger` writes, built by hand for Fabric-less readers."""
    claims = [{"claim_id": record["incident_id"] + ":edge", "source": "deterministic_core",
               "input_refs": [],
               "statement": f"Edge would {record['edge_would']}; "
                            f"policy_reason={record['policy_reason']}"}]
    claims += [{"claim_id": "knowledge:" + r["claim_id"], "source": "knowledge_advisory",
                "input_refs": [r["bundle_digest"]], "freshness": r["freshness"],
                "statement": r["name"] + (f": {r['summary']}" if r["summary"] else "")}
               for r in record["knowledge_refs"]]
    return {"fabric_version": "0.9.0rc5",
            "claim_set": {"authority": "descriptive_only", "trace_id": record["incident_id"],
                          "claims": claims}}


def _pinned_fabric():
    fabric = pytest.importorskip("azazel_fabric")
    if fabric.__version__ != FABRIC_PIN.lstrip("v"):
        pytest.skip("pinned Fabric required")
    return fabric


# -- without Fabric: the reader, and the explainer's fallback ----------------


def test_a_record_with_a_consistent_projection_reads():
    record = _record()
    stored = {**record, FABRIC_RECORD_FIELD: _stored(record)}
    assert read_record(stored)[FABRIC_RECORD_FIELD] == _stored(record)


@pytest.mark.parametrize("drift", [
    lambda f: f["claim_set"]["claims"][1]["input_refs"].__setitem__(0, "sha256:" + "c" * 64),
    lambda f: f["claim_set"]["claims"][1].__setitem__("freshness", "current"),
    lambda f: f["claim_set"]["claims"][1].__setitem__("statement", "Run this command"),
    lambda f: f["claim_set"]["claims"][0].__setitem__("statement", "Edge would isolate"),
    lambda f: f["claim_set"]["claims"][1].__setitem__("source", "local_model"),
    lambda f: f["claim_set"]["claims"].append(dict(f["claim_set"]["claims"][1])),
    lambda f: f["claim_set"]["claims"].pop(),
    lambda f: f["claim_set"]["claims"][0].__setitem__("source", "knowledge_advisory"),
    lambda f: f["claim_set"].__setitem__("trace_id", "inc-ffffffffffffffff"),
    lambda f: f["claim_set"].__setitem__("authority", "advisory_only"),
    lambda f: f.__setitem__("fabric_version", "main"),
    lambda f: f.__setitem__("extra", 1),
    lambda f: f["claim_set"].__setitem__("padding", "x" * (33 * 1024)),
])
def test_a_projection_that_drifted_from_its_record_is_refused(drift):
    record = _record()
    stored = _stored(record)
    drift(stored)
    with pytest.raises(ValueError):
        read_record({**record, FABRIC_RECORD_FIELD: stored})


def test_the_projection_is_never_summarised_for_display():
    record = _record()
    stored = {**record, FABRIC_RECORD_FIELD: _stored(record)}
    assert explanation_summary(stored) == explanation_summary(record)
    assert "claim_set" not in json.dumps(explanation_summary(stored))


def test_absent_fabric_leaves_the_record_exactly_as_it_was(monkeypatch):
    monkeypatch.setattr(fabric_boundary, "_import_fabric", lambda: (None, "unavailable"))
    record = _record()
    assert not project_explanation(record).available
    assert daemon.with_fabric_claims(record) == record


def test_a_failing_projection_never_costs_the_explanation(monkeypatch):
    def broken(_):
        raise RuntimeError("projection crashed")

    monkeypatch.setattr(daemon, "project_explanation", broken)
    record = _record()
    assert daemon.with_fabric_claims(record) == record


def test_the_writer_and_the_reader_name_claims_alike():
    from azazel_nexus import incident_explain

    assert fabric_boundary.EDGE_CLAIM_SUFFIX == incident_explain.EDGE_CLAIM_SUFFIX
    assert fabric_boundary.KNOWLEDGE_CLAIM_PREFIX == incident_explain.KNOWLEDGE_CLAIM_PREFIX


def test_privacy_classes_correspond_and_the_never_remote_sets_coincide():
    assert set(FABRIC_PRIVACY_CLASS) == {c.value for c in PrivacyClass}
    assert {FABRIC_PRIVACY_CLASS[c.value] for c in NEVER_REMOTE} == {"sensitive", "restricted"}
    assert len(set(FABRIC_PRIVACY_CLASS.values())) == len(FABRIC_PRIVACY_CLASS)
    table = CONTRACT_DOC.read_text(encoding="utf-8")
    for nexus, fabric in FABRIC_PRIVACY_CLASS.items():
        assert f"| `{nexus}` | `{fabric}` |" in table, nexus


# -- with the pinned Fabric ---------------------------------------------------


def test_privacy_classes_are_fabrics_own_words():
    _pinned_fabric()
    from azazel_fabric.mio_contracts import PrivacyClass as FabricPrivacy
    from azazel_fabric.mio_contracts.validation import NON_EGRESSIBLE_PRIVACY_CLASSES

    assert set(FABRIC_PRIVACY_CLASS.values()) == set(get_args(FabricPrivacy))
    assert {FABRIC_PRIVACY_CLASS[c.value] for c in NEVER_REMOTE} == NON_EGRESSIBLE_PRIVACY_CLASSES


def test_knowledge_refs_become_knowledge_advisory_claims():
    _pinned_fabric()
    from azazel_fabric.mio_contracts import ClaimSet

    record = _record([_ref(), _ref("T1059.001", "current", "")])
    projection = project_explanation(record)
    assert projection.available, projection.reason
    claims = projection.view.claim_set.claims
    assert [c.source for c in claims] == ["deterministic_core", "knowledge_advisory",
                                         "knowledge_advisory"]
    edge, static, current = claims
    assert edge.claim_id == "inc-0123456789abcdef:edge"
    assert edge.statement == "Edge would throttle; policy_reason=severity_elevated_throttle_reversible"
    assert edge.input_refs == () and "evidence_refs_not_carried" in edge.limitations
    assert (static.claim_id, static.input_refs, static.freshness) == ("knowledge:T1059", (DIGEST,), "static")
    assert current.freshness == "current"
    assert "citation=MITRE ATT&CK technique" in static.limitations
    assert not any(item.startswith("citation=") for item in current.limitations)
    assert projection.view.claim_set.authority == "descriptive_only"
    # The ledger form is Fabric's own dump and validates back unchanged.
    ledger = projection.view.as_ledger()
    assert ClaimSet.model_validate(ledger["claim_set"]) == projection.view.claim_set
    assert read_record({**record, FABRIC_RECORD_FIELD: ledger})


def test_edge_intake_evidence_becomes_evidence_refs_of_the_edge_claim():
    _pinned_fabric()
    evidence = EvidenceRecord.receive(parsed(), lambda: 0)
    projection = project_explanation(_record(), evidence=[evidence])
    assert projection.available, projection.reason
    edge = projection.view.claim_set.claims[0]
    assert edge.input_refs == (evidence.digest,)
    assert "evidence_refs_not_carried" not in edge.limitations
    (ref,) = projection.view.evidence_refs
    assert (ref.evidence_id, ref.source) == (evidence.digest, "edge-core")


def test_the_explainer_keeps_the_projection_in_its_ledger_only(tmp_path):
    _pinned_fabric()
    incidents = tmp_path / "incidents"
    incidents.mkdir()
    ref = KnowledgeRef(**_ref())
    e = daemon.Explainer(
        incidents=incidents, state=tmp_path / "state", status_path=tmp_path / "status.json",
        clock=lambda: 0, monotonic=lambda: 0,
        mio=lambda _: {"route": "deterministic handoff", "outcome": "answered",
                       "reason": "no admitted model", "ledger_seq": 1,
                       "reference_status": "unavailable"},
        knowledge=lambda _: (ref,))
    e.prepare()
    AuditLedger(incidents / "1970-01-01.jsonl").append(transition())
    e.poll()
    (line,) = [json.loads(x) for p in sorted(e.store.directory.glob("*.jsonl"))
               for x in p.read_text().splitlines()]
    stored = read_record(line)
    assert [c["source"] for c in stored[FABRIC_RECORD_FIELD]["claim_set"]["claims"]] == [
        "deterministic_core", "knowledge_advisory"]
    # Everything that leaves the ledger: status, recent rows and the
    # checkpoint (recent.json/cursor.json), and every event handed to audit.
    outside = [p for p in (tmp_path / "state").rglob("*")
               if p.is_file() and e.store.directory not in p.parents]
    shown = [p.read_text() for p in outside] + [e.status_path.read_text()]
    shown += [json.dumps(e.recent), json.dumps(list(e.audit_pending.queue))]
    assert outside and e.audit_pending.queue
    for text in shown:
        assert "claim_set" not in text and "deterministic_core" not in text


def _segment_explainer(tmp_path, segment_bytes):
    incidents = tmp_path / "incidents"
    incidents.mkdir(parents=True)
    ref = KnowledgeRef(**_ref())
    e = daemon.Explainer(
        incidents=incidents, state=tmp_path / "state", status_path=tmp_path / "status.json",
        clock=lambda: 0, monotonic=lambda: 0, store_limits={"segment_bytes": segment_bytes},
        mio=lambda _: {"route": "deterministic handoff", "outcome": "answered",
                       "reason": "no admitted model", "ledger_seq": 1,
                       "reference_status": "unavailable"},
        knowledge=lambda _: (ref,))
    e.prepare()
    AuditLedger(incidents / "1970-01-01.jsonl").append(transition())
    return e


def test_a_day_with_room_for_the_record_but_not_its_projection_keeps_the_explanation(tmp_path):
    _pinned_fabric()
    probe = _segment_explainer(tmp_path / "probe", 1024 * 1024)
    probe.poll()
    (line,) = [x for p in probe.store.directory.glob("*.jsonl") for x in p.read_bytes().splitlines()]
    projected = json.loads(line)
    plain = {k: v for k, v in projected.items() if k != FABRIC_RECORD_FIELD}
    from azazel_nexus.edge_intake import canonical
    plain_size, projected_size = len(canonical(plain)) + 1, len(line) + 1
    assert plain_size < projected_size
    e = _segment_explainer(tmp_path / "tight", (plain_size + projected_size) // 2)
    e.poll()
    (kept,) = [json.loads(x) for p in e.store.directory.glob("*.jsonl")
               for x in p.read_bytes().splitlines()]
    assert FABRIC_RECORD_FIELD not in kept and kept["knowledge_state"] == "available"
    assert not e.refused["explanation_segment_full"]


def test_a_reference_cited_twice_is_projected_once_and_says_so():
    _pinned_fabric()
    record = _record([_ref(), _ref()])
    projection = project_explanation(record)
    assert projection.available, projection.reason
    claims = projection.view.claim_set.claims
    assert [c.claim_id for c in claims] == ["inc-0123456789abcdef:edge", "knowledge:T1059"]
    assert "duplicate_knowledge_refs_merged" in claims[0].limitations
    assert read_record({**record, FABRIC_RECORD_FIELD: projection.view.as_ledger()})
