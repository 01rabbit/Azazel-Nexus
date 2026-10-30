"""Edge evidence pointers and M.I.O. provenance through the explanation path (S-18).

An incident transition names its first and latest Edge evidence records by
digest. Those pointers -- never the content -- travel through the durable
pending queue into the explanation record, and from there into Fabric's
`EvidenceRef`/`ClaimSet` view. When a pointer may not lead to a stored record
the record says why (`evidence_not_stored`, `evidence_retention_elapsed`),
which is never `evidence_refs_not_carried` (no pointer at all: a record or
pending entry from before them). A local answer's generation method and model
are recorded beside its `content_kind` and projected as a `Claim` with
`model_ref` (owner-decisions L23).

The tests that need Fabric skip without it; the 4th CI configuration
(`.[dev,fabric]`) runs them.
"""

from __future__ import annotations

import json

import pytest

from azazel_nexus.audit import AuditLedger
from azazel_nexus.edge_intake import IncidentTracker
from azazel_nexus.fabric_boundary import FABRIC_PIN, project_edge_evidence, project_explanation
from azazel_nexus.incident_explain import (
    EVIDENCE_RETENTION_DAYS,
    FABRIC_RECORD_FIELD,
    build_frame,
    explanation_summary,
    pending_entry,
    read_mio_reply,
    read_pending,
    read_record,
    record_evidence,
)
from azazel_nexus.local_advisory import build_options, delivered_document
from azazel_nexus_runtime import incident_explaind as daemon
from test_edge_intake import record as evidence_record

DAY = 86400
DIGEST = "sha256:" + "b" * 64


def _transition(tracker, evidence, event_type=None):
    """The last transition intake emits for `evidence`, as its ledger holds it."""
    out = tracker.add(evidence)
    t = dict(out[-1])
    kind = t.pop("transition")
    t["event_type"] = "edge.incident." + (event_type or kind)
    return t


def _incident(first_at=0.0, latest_at=None, *, severity=3, escalated=1, stored=True):
    """An opened transition and, with `latest_at`, its escalation, from real records."""
    tracker = IncidentTracker(lambda: first_at, monotonic=lambda: 0)
    first = evidence_record(first_at, ids=["T1059"], severity=severity)
    opened = _transition(tracker, first)
    if latest_at is None:
        return (first,), (opened,)
    tracker.clock = lambda: latest_at
    # Records in between kept it open (intake closes an idle one at 900 s).
    (item,) = tracker.incidents.values()
    item["last_seen"] = item["last_update"] = latest_at - 1
    latest = evidence_record(latest_at, ids=["T1059"], severity=escalated)
    out = tracker.add(latest, evidence_stored=stored)
    updated = dict(out[-1])
    updated.pop("transition")
    updated["event_type"] = "edge.incident.updated"
    return (first, latest), (opened, updated)


def _local(source, model_id="model-a1"):
    """An answered local reply whose delivery was made by `source`."""
    if source == "model":
        # A model's own text: the shared pipeline, with a model that answers.
        from types import SimpleNamespace

        from test_closed_choice import deliver

        answer = {"reason": 'Investigate "host-1" activity.', "check_1": "Review the logs.",
                  "check_2": "Review the account.", "check_3": "Review the source.",
                  "missing": "The event time is needed."}
        frame = {"request_id": "test", "privacy_class": "P2-mission",
                 "question": "SSH host-1 T1110.003",
                 "context": [{"kind": "auth_log", "text": "Password spray against host-1"}]}
        body, _ = deliver(frame, (.8,), SimpleNamespace(
            infer=lambda *_, **__: SimpleNamespace(text=json.dumps(answer))), model_id=model_id)
        assert body["explanation_source"] == "model"
    else:
        from test_incident_explain import transition

        frame = build_frame(transition(), 1)
        options = build_options(frame)
        body = delivered_document(frame, (), options,
                                  {"option_id": "other_suspicious", "kind": "other_suspicious"},
                                  list(options), None, model_id,
                                  retrieval="keyword" if source == "keyword" else "embedding",
                                  provenance=source)
    return {"route": "local", "outcome": "answered", "reason": "local", "ledger_seq": 1, **body}


def _record(**extra):
    base = {"incident_id": "inc-0123456789abcdef", "explained_at": 20 * DAY,
            "transition": "updated", "edge_would": "throttle",
            "policy_reason": "severity_elevated_throttle_reversible", "attack_type": "absent",
            "technique_ids": ["T1059"],
            "mio": {"route": "unavailable", "outcome": "unavailable", "reason": "mio_unavailable",
                    "text": None},
            "knowledge_refs": [], "knowledge_state": "skipped", "failure_codes": []}
    return {**base, **extra}


def _pinned_fabric():
    fabric = pytest.importorskip("azazel_fabric")
    if fabric.__version__ != FABRIC_PIN.lstrip("v"):
        pytest.skip("pinned Fabric required")
    return fabric


def _explainer(tmp_path, clock, mio=None, **kwargs):
    incidents = tmp_path / "incidents"
    incidents.mkdir(parents=True, exist_ok=True)
    e = daemon.Explainer(
        incidents=incidents, state=tmp_path / "state", status_path=tmp_path / "status.json",
        clock=clock, monotonic=lambda: 0, knowledge=lambda _: (),
        mio=mio or (lambda _: {"route": "deterministic handoff", "outcome": "answered",
                               "reason": "no admitted model", "ledger_seq": 1,
                               "reference_status": "unavailable"}), **kwargs)
    e.prepare()
    return e


def _append(e, t, day="1970-01-01"):
    AuditLedger(e.incidents / (day + ".jsonl")).append(t)


def _records(e):
    return [read_record(json.loads(line)) for p in sorted(e.store.directory.glob("*.jsonl"))
            for line in p.read_text().splitlines()]


def _pointers(evidence):
    return [(r.digest, r.received_at) for r in evidence]


def _cited(record):
    return [(r["evidence_id"], r["observed_at"]) for r in record["evidence"]["refs"]]


# -- the pointer and its carriage --------------------------------------------


def test_an_opening_names_one_record_and_an_escalation_names_both():
    (first,), (opened,) = _incident()
    assert pending_entry(opened)["evidence"] == {"refs": [
        {"evidence_id": first.digest, "role": "first_and_latest", "observed_at": first.received_at}],
        "gaps": []}
    (first, latest), (_, updated) = _incident(0.0, 100.0)
    assert first.digest != latest.digest
    assert pending_entry(updated)["evidence"]["refs"] == [
        {"evidence_id": first.digest, "role": "first", "observed_at": 0.0},
        {"evidence_id": latest.digest, "role": "latest", "observed_at": 100.0}]


def test_evidence_intake_did_not_store_is_said_of_the_whole_record():
    _, (_, updated) = _incident(0.0, 100.0, stored=False)
    assert updated["evidence_stored"] is False
    assert pending_entry(updated)["evidence"]["gaps"] == ["evidence_not_stored"]


def test_the_frame_never_carries_the_pointers():
    (first, latest), (_, updated) = _incident(0.0, 100.0)
    entry = pending_entry(updated)
    frame = build_frame(entry, 7)
    assert frame == build_frame(updated, 7)
    text = json.dumps(frame)
    assert first.digest not in text and latest.digest not in text
    assert first.digest.removeprefix("sha256:")[:16] not in text


def test_a_pending_entry_from_before_the_pointers_still_reads():
    _, (opened,) = _incident()
    entry = pending_entry(opened)
    legacy = {k: v for k, v in entry.items() if k != "evidence"}
    assert read_pending(legacy) == legacy
    assert read_pending(entry) == entry


@pytest.mark.parametrize("mutate", [
    lambda v: v["refs"].clear(),
    lambda v: v["refs"].append(dict(v["refs"][0])),
    lambda v: v["refs"][0].update(evidence_id="sha256:" + "B" * 64),
    lambda v: v["refs"][0].update(evidence_id="raw payload"),
    lambda v: v["refs"][0].update(role="latest"),
    lambda v: v["refs"][0].update(observed_at=-1),
    lambda v: v["refs"][0].update(content="GET /admin"),
    lambda v: v.update(gaps=["evidence_refs_not_carried"]),
    lambda v: v.update(gaps=["evidence_retention_elapsed"]),
    lambda v: v.update(gaps=["evidence_not_stored", "evidence_not_stored"]),
    lambda v: v.update(extra=1),
])
def test_a_malformed_pending_pointer_is_refused(mutate):
    _, (opened,) = _incident()
    entry = pending_entry(opened)
    mutate(entry["evidence"])
    with pytest.raises(ValueError):
        read_pending(entry)


# -- retention -----------------------------------------------------------------


def test_the_retention_rule_is_intakes():
    from azazel_nexus_runtime.edge_intaked import RETENTION_DAYS

    assert EVIDENCE_RETENTION_DAYS == RETENTION_DAYS


@pytest.mark.parametrize("age_days", range(12, 18))
def test_window_elapsed_exactly_when_intakes_age_rule_may_delete_the_day(tmp_path, age_days):
    """Intake's own `DailySegments.retain`, with its newest segment today."""
    from azazel_nexus_runtime.edge_intaked import EvidenceStore

    today = 40 * DAY + 3600
    observed = today - age_days * DAY + 7
    store = EvidenceStore(tmp_path, monotonic=lambda: 0)
    for instant in (observed, today):
        store.path_at(instant).write_bytes(b"{}\n")
    store.last_now = today
    store.retain()
    deleted = not store.path_at(observed).exists()
    state = record_evidence({"refs": [{"evidence_id": DIGEST, "role": "first_and_latest",
                                       "observed_at": observed}], "gaps": []}, today)
    assert (state["refs"][0]["retention"] == "window_elapsed") == deleted
    assert ("evidence_retention_elapsed" in state["gaps"]) == deleted


@pytest.mark.parametrize("mutate", [
    lambda e: e["refs"][0].update(retention="window_open"),
    lambda e: e["refs"][1].update(retention="window_elapsed"),
    lambda e: e.update(gaps=[]),
    lambda e: e.update(gaps=["evidence_retention_elapsed", "evidence_not_stored"]),
    lambda e: e["refs"][0].pop("retention"),
    lambda e: e.update(gaps=["evidence_refs_not_carried", "evidence_retention_elapsed"]),
])
def test_a_record_whose_retention_disagrees_with_its_instants_is_refused(mutate):
    evidence = record_evidence({"refs": [
        {"evidence_id": DIGEST, "role": "first", "observed_at": 1.0},
        {"evidence_id": "sha256:" + "c" * 64, "role": "latest", "observed_at": 19 * DAY}],
        "gaps": []}, 20 * DAY)
    assert [r["retention"] for r in evidence["refs"]] == ["window_elapsed", "window_open"]
    assert evidence["gaps"] == ["evidence_retention_elapsed"]
    assert read_record(_record(evidence=evidence))["evidence"] == evidence
    mutate(evidence)
    with pytest.raises(ValueError):
        read_record(_record(evidence=evidence))


# -- generation method (L23) ---------------------------------------------------


@pytest.mark.parametrize("source, method, model_ref", [
    ("model", "local_model_inference", "model-a1"),
    ("embedding", "embedding_matching", "model-a1"),
    ("keyword", "deterministic_keyword_matching", None),
])
def test_a_local_answer_records_how_it_was_made(source, method, model_ref):
    m = read_mio_reply(_local(source))
    # `content_kind` stays what every reader expects of an answered local reply.
    assert m["content_kind"] == "ai_advice"
    assert m["provenance"] == {"method": method, "model_ref": model_ref}
    record = read_record(_record(mio=m))
    assert record["mio"]["provenance"]["method"] == method
    # The display summary (and so recent.json) is the one before the field.
    legacy = {**record, "mio": {k: v for k, v in m.items() if k != "provenance"}}
    assert explanation_summary(record) == explanation_summary(legacy)


@pytest.mark.parametrize("source, change", [
    ("keyword", {"method": "local_model_inference", "model_ref": "model-a1"}),
    ("keyword", {"method": "embedding_matching", "model_ref": "model-a1"}),
    ("model", {"method": "deterministic_keyword_matching", "model_ref": None}),
    ("embedding", {"method": "local_model_inference", "model_ref": "model-a1"}),
    ("keyword", {"method": "deterministic_keyword_matching", "model_ref": "model-a1"}),
    ("model", {"method": "local_model_inference", "model_ref": None}),
    ("model", {"method": "local_model_inference", "model_ref": "a b"}),
    ("model", {"method": "remote_model", "model_ref": "model-a1"}),
    ("model", {"method": "local_model_inference"}),
])
def test_a_method_the_text_does_not_bear_out_is_refused(source, change):
    m = read_mio_reply(_local(source))
    with pytest.raises(ValueError):
        read_record(_record(mio={**m, "provenance": change}))


def test_only_a_local_answer_has_a_method():
    m = read_mio_reply(_local("keyword"))
    handoff = {"route": "unavailable", "outcome": "unavailable", "reason": "mio_unavailable",
               "text": None, "provenance": m["provenance"]}
    with pytest.raises(ValueError):
        read_record(_record(mio=handoff))


# -- the explainer, end to end (no Fabric needed) ------------------------------


def test_restart_resumes_pending_pointers_and_the_record_cites_intakes_records(tmp_path):
    (first, latest), (opened, updated) = _incident(0.0, 100.0)
    e = _explainer(tmp_path, lambda: 200.0)
    _append(e, opened)
    _append(e, updated)
    e.selection.attempts.extend([0] * 6)  # the rate budget holds both in pending
    e.poll()
    assert not _records(e) and len(e.selection.pending) == 2
    checkpoint = (e.state / "cursor.json").read_text()
    assert first.digest in checkpoint and latest.digest in checkpoint
    restarted = _explainer(tmp_path, lambda: 200.0)
    restarted.monotonic = lambda: 61
    restarted.poll()
    restarted.monotonic = lambda: 200
    restarted.poll()
    opened_record, escalated = _records(restarted)
    assert _cited(opened_record) == _pointers([first])
    assert _cited(escalated) == _pointers([first, latest])
    assert [r["role"] for r in escalated["evidence"]["refs"]] == ["first", "latest"]
    # The same evidence record is cited alike by both of the incident's records.
    assert opened_record["evidence"]["refs"][0]["evidence_id"] == escalated["evidence"]["refs"][0]["evidence_id"]
    # Nothing outside the ledger shows the pointers.
    for path in (tmp_path / "recent.json", tmp_path / "status.json"):
        text = path.read_text()
        assert first.digest not in text and "evidence_refs" not in text


def test_a_pending_entry_from_a_previous_release_is_explained_without_pointers(tmp_path):
    _, (opened,) = _incident()
    e = _explainer(tmp_path, lambda: 200.0)
    _append(e, opened)
    e.selection.attempts.extend([0] * 6)
    e.poll()
    path = e.state / "cursor.json"
    value = json.loads(path.read_bytes())
    value["pending"] = [[{k: v for k, v in t.items() if k != "evidence"}, s]
                        for t, s in value["pending"]]
    path.write_text(json.dumps(value))
    restarted = _explainer(tmp_path, lambda: 200.0)
    restarted.monotonic = lambda: 61
    restarted.poll()
    (record,) = _records(restarted)
    assert "evidence" not in record


def test_a_long_lived_incident_says_its_first_record_may_be_retired(tmp_path):
    """The first record is past intake's age window; the latest is not."""
    now = 30 * DAY
    (first, latest), (_, updated) = _incident(now - 16 * DAY, now - 60)
    e = _explainer(tmp_path, lambda: now)
    _append(e, updated, "1970-01-30")
    e.poll()
    (record,) = _records(e)
    assert _cited(record) == _pointers([first, latest])
    assert [r["retention"] for r in record["evidence"]["refs"]] == ["window_elapsed", "window_open"]
    assert record["evidence"]["gaps"] == ["evidence_retention_elapsed"]


def test_a_pending_entry_resumed_across_the_retention_window(tmp_path):
    """Explained a retention period after it was queued: the pointer says so."""
    _, (opened, updated) = _incident(0.0, 100.0)
    e = _explainer(tmp_path, lambda: 200.0)
    _append(e, opened)
    e.poll()
    _append(e, updated)
    e.selection.attempts.extend([0] * 6)
    e.poll()
    assert len(e.selection.pending) == 1
    restarted = _explainer(tmp_path, lambda: 16 * DAY)
    restarted.monotonic = lambda: 61
    restarted.poll()
    record = _records(restarted)[-1]
    assert record["transition"] == "updated"
    assert {r["retention"] for r in record["evidence"]["refs"]} == {"window_elapsed"}
    assert "evidence_retention_elapsed" in record["evidence"]["gaps"]


def test_evidence_not_stored_reaches_the_record(tmp_path):
    _, (opened, updated) = _incident(0.0, 100.0, stored=False)
    e = _explainer(tmp_path, lambda: 200.0)
    _append(e, opened)
    _append(e, updated)
    e.poll()
    e.monotonic = lambda: 61
    e.poll()
    first, second = _records(e)
    assert first["evidence"]["gaps"] == []
    assert second["evidence"]["gaps"] == ["evidence_not_stored"]


def test_records_rotate_with_the_day_and_keep_their_pointers(tmp_path):
    """Two explanation-ledger days (segment rotation); the same pointers."""
    (first, latest), (opened, updated) = _incident(DAY - 50, DAY + 50)
    clock = [DAY - 40]
    e = _explainer(tmp_path, lambda: clock[0])
    _append(e, opened, "1970-01-01")
    e.poll()
    clock[0] = DAY + 60
    _append(e, updated)
    e.monotonic = lambda: 61
    e.poll()
    days = sorted(p.name for p in e.store.directory.glob("*.jsonl"))
    assert days == ["1970-01-01.jsonl", "1970-01-02.jsonl"]
    one, two = _records(e)
    assert _cited(one) == _pointers([first]) and _cited(two) == _pointers([first, latest])


def test_a_local_answer_keeps_its_method_in_the_ledger_and_not_in_recent(tmp_path):
    e = _explainer(tmp_path, lambda: 200.0, mio=lambda _: _local("embedding"))
    _, (opened,) = _incident()
    _append(e, opened)
    e.poll()
    (record,) = _records(e)
    assert record["mio"]["provenance"] == {"method": "embedding_matching", "model_ref": "model-a1"}
    recent = (tmp_path / "recent.json").read_text()
    assert "model-a1" not in recent and "embedding_matching" not in recent


# -- with the pinned Fabric ----------------------------------------------------


def test_the_claim_set_cites_the_records_intake_stored(tmp_path):
    _pinned_fabric()
    (first, latest), (opened, updated) = _incident(0.0, 100.0)
    e = _explainer(tmp_path, lambda: 200.0, mio=lambda _: _local("model"))
    _append(e, opened)
    _append(e, updated)
    e.poll()
    e.monotonic = lambda: 61
    e.poll()
    for stored, evidence in zip(_records(e), ([first], [first, latest])):
        view = stored[FABRIC_RECORD_FIELD]
        edge, mio = view["claim_set"]["claims"][:2]
        assert edge["input_refs"] == [r.digest for r in evidence]
        assert "evidence_refs_not_carried" not in edge["limitations"]
        # Each pointer is Fabric's EvidenceRef of the record intake stored,
        # but for the trace: the incident's id, not Edge's own trace id.
        expected = [{**project_edge_evidence(r).view.model_dump(mode="json"),
                     "trace_id": stored["incident_id"]} for r in evidence]
        assert view["evidence_refs"] == expected
        assert (mio["source"], mio["model_ref"], mio["model_generation"]) == (
            "local_model", "model-a1", None)
        assert mio["input_refs"] == edge["input_refs"]
        assert "generation_method=local_model_inference" in mio["limitations"]
        assert "model_generation_not_delivered" in mio["limitations"]


@pytest.mark.parametrize("source, claim_source, model_ref", [
    ("model", "local_model", "model-a1"),
    ("embedding", "local_model", "model-a1"),
    ("keyword", "deterministic_core", None),
])
def test_each_method_projects_with_its_own_source(source, claim_source, model_ref):
    _pinned_fabric()
    from azazel_fabric.mio_contracts import ClaimSet

    record = read_record(_record(mio=read_mio_reply(_local(source))))
    projection = project_explanation(record)
    assert projection.available, projection.reason
    edge, mio = projection.view.claim_set.claims
    assert edge.limitations[1] == "evidence_refs_not_carried"
    assert (mio.claim_id, mio.source, mio.model_ref) == (
        "inc-0123456789abcdef:mio", claim_source, model_ref)
    ledger = projection.view.as_ledger()
    assert "evidence_refs" not in ledger
    assert ClaimSet.model_validate(ledger["claim_set"]) == projection.view.claim_set
    assert read_record({**record, FABRIC_RECORD_FIELD: ledger})


def _projected():
    (first, latest), (_, updated) = _incident(0.0, 100.0, stored=False)
    evidence = record_evidence(pending_entry(updated)["evidence"], 20 * DAY)
    record = read_record(_record(mio=read_mio_reply(_local("model")), evidence=evidence))
    projection = project_explanation(record)
    assert projection.available, projection.reason
    return record, projection.view.as_ledger()


def test_gaps_are_the_edge_claims_limitations():
    _pinned_fabric()
    record, ledger = _projected()
    edge = ledger["claim_set"]["claims"][0]
    assert edge["limitations"] == ["reported_by_edge_core_not_executed_by_nexus",
                                   "evidence_not_stored", "evidence_retention_elapsed"]
    assert read_record({**record, FABRIC_RECORD_FIELD: ledger})


@pytest.mark.parametrize("drift", [
    lambda f: f["evidence_refs"].pop(),
    lambda f: f["evidence_refs"][0].update(observed_at="1970-01-01T00:00:01Z"),
    lambda f: f["evidence_refs"][0].update(trace_id="trace-1"),
    lambda f: f.pop("evidence_refs"),
    lambda f: f["claim_set"]["claims"][0]["input_refs"].pop(),
    lambda f: f["claim_set"]["claims"][0]["limitations"].remove("evidence_not_stored"),
    lambda f: f["claim_set"]["claims"][0]["limitations"].__setitem__(1, "evidence_refs_not_carried"),
    lambda f: f["claim_set"]["claims"].pop(1),
    lambda f: f["claim_set"]["claims"][1].update(model_ref="model-b2"),
    lambda f: f["claim_set"]["claims"][1].update(source="deterministic_core"),
    lambda f: f["claim_set"]["claims"][1].update(model_generation="7"),
    lambda f: f["claim_set"]["claims"][1].update(input_refs=[]),
    lambda f: f["claim_set"]["claims"][1].update(statement="Run this command"),
])
def test_a_projection_that_lost_its_evidence_or_provenance_is_refused(drift):
    _pinned_fabric()
    record, ledger = _projected()
    drift(ledger)
    with pytest.raises(ValueError):
        read_record({**record, FABRIC_RECORD_FIELD: ledger})


def test_a_full_day_keeps_the_pointers_and_the_method_without_the_projection(tmp_path):
    """#380's fallback is unchanged: the plain record still carries both."""
    _pinned_fabric()
    from azazel_nexus.edge_intake import canonical

    _, (opened,) = _incident()

    def run(path, segment_bytes):
        e = _explainer(path, lambda: 200.0, mio=lambda _: _local("model"),
                       store_limits={"segment_bytes": segment_bytes})
        _append(e, opened)
        e.poll()
        return e, [x for p in e.store.directory.glob("*.jsonl") for x in p.read_bytes().splitlines()]

    _, (line,) = run(tmp_path / "probe", 1024 * 1024)
    projected = json.loads(line)
    plain = {k: v for k, v in projected.items() if k != FABRIC_RECORD_FIELD}
    plain_size, projected_size = len(canonical(plain)) + 1, len(line) + 1
    e, (kept,) = run(tmp_path / "tight", (plain_size + projected_size) // 2)
    kept = json.loads(kept)
    assert FABRIC_RECORD_FIELD not in kept
    assert kept["evidence"] == plain["evidence"] and kept["mio"]["provenance"]
    assert not e.refused["explanation_segment_full"]
    # A day too full for the record itself still refuses it, as before.
    e, lines = run(tmp_path / "full", plain_size - 1)
    assert not lines and e.refused["explanation_segment_full"] == 1
