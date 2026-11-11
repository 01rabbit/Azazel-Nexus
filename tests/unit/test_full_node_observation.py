"""Unit C: explaind candidates, retention table, replacement and the row trace (DESIGN-M5 2.4-2.6)."""
import json
import re

import pytest

from azazel_nexus.audit import AuditLedger
from azazel_nexus.incident_explain import (
    FULL_NODE_INCOMPLETE_CHECK, MIO_KNOWLEDGE_NOT_QUERIED_CHECK, adopt_full_node_reply, pending_entry, read_recent_incidents,
)
from azazel_nexus_runtime import incident_explaind as daemon
from test_incident_explain import _core_full_node_fast, transition
from test_incident_explaind import append, handoff, make, records

RULE = object()


def tx(kind="opened", severity=3, ids=("T1059", "T1059.001"), count=1, **kw):
    t = transition(severity, kind, **kw)
    t["technique_ids"] = list(ids)
    t["count"] = count
    if kind == "closed":
        t["reason"] = "idle"
    return t


def base_fast():
    return {"schema_version": "mio.assistance.v1", "trace_id": "mio-0123456789abcdef-1",
            "frame_id": "mio-0123456789abcdef-1:frame", "generation_method": "static_reference",
            "state": "dependency_unavailable", "observations": [], "hypotheses": [],
            "unknowns": ["Fast assessment unavailable"], "next_checks": [], "knowledge": [],
            "handoff": None, "reasoning_trace": [],
            "dependency_outcome": {"knowledge": "not_queried", "deception": "absent"},
            "full_node_context_status": "not_queried"}


def received(case="partial", **kw):
    fast = base_fast()
    full = _core_full_node_fast(case)
    fast.update(full_node_context_status="received",
                full_node_context_received_at="2026-11-06T00:00:10Z",
                fabric_knowledge_context_advisory=full["fabric_knowledge_context_advisory"],
                trace_id="mio-ffffffffffffffff-9", frame_id="mio-ffffffffffffffff-9:frame")
    fast["dependency_outcome"] = {"knowledge": "unavailable", "deception": "absent"}
    fast["unknowns"] = fast["unknowns"] + ["KNOWLEDGE_CONTEXT_" + case.upper()]
    fast["next_checks"] = [FULL_NODE_INCOMPLETE_CHECK]
    fast.update(kw)
    return fast


class Rig:
    def __init__(self, tmp_path, rule=True, observed=None, plain=False, **kw):
        self.rule = rule
        self.calls = []
        self.observed = observed or (lambda frame: received())
        self.advised = []

        def mio(frame):
            fast = base_fast()
            self.advised.append(frame)
            return {**handoff(), "fast_assistance": fast}

        def context(frame):
            self.calls.append(frame)
            return {"outcome": "context_observed", "fast_assistance": self.observed(frame)}

        if not plain:
            kw["observation_rule"] = lambda: RULE if self.rule else None
        self.e = make(tmp_path, mio=mio, context=context, **kw)

    def step(self, t, minute=None):
        append(self.e, t)
        if minute is not None:
            self.e.monotonic = lambda: minute * 61
        self.e.poll()

    @property
    def row(self):
        return self.e.recent[0]

    @property
    def trace(self):
        return self.row.get("full_node_trace")

    def current(self):
        return self.row["explanation"]["fast_assistance"]["full_node_context"]


@pytest.fixture
def rig(tmp_path):
    return Rig(tmp_path)


# ---- no rule: nothing changes -------------------------------------------------

def test_without_a_rule_nothing_about_full_node_is_written(tmp_path):
    outputs = []
    for name, kwargs in (("a", {"plain": True}), ("b", {"rule": False})):
        (tmp_path / name).mkdir(exist_ok=True)
        r = Rig(tmp_path / name, **kwargs)
        r.step(tx())
        r.step(tx("updated", 1, count=2), minute=1)
        r.step(tx("updated", 1, count=3), minute=2)
        assert r.calls == []
        raw = (tmp_path / name / "state" / "cursor.json").read_bytes()
        assert b"full_node_trace" not in raw and b"query_origin" not in raw
        assert b"full_node_context_origin" not in b"".join(
            p.read_bytes() for p in (tmp_path / name / "state").rglob("*.jsonl"))
        outputs.append((raw, [json.dumps(x, sort_keys=True) for x in records(r.e)]))
    assert outputs[0] == outputs[1]


# ---- candidates ---------------------------------------------------------------

def test_an_opened_transition_asks_once_and_records_the_origin(rig):
    rig.step(tx())
    assert len(rig.calls) == 1
    assert rig.calls[0]["privacy_class"] == "P3-restricted"
    fast = records(rig.e)[0]["mio"]["fast_assistance"]
    assert fast["full_node_context_origin"] == "observation_rule_v1"
    assert fast["full_node_context_status"] == "received"
    assert fast["trace_id"] == "mio-0123456789abcdef-1"            # advise side kept
    assert fast["frame_id"] == "mio-0123456789abcdef-1:frame"
    assert rig.current()["query_origin"] == "observation_rule_v1"
    tr = rig.trace
    assert tr["transition_query"] == "queried" and tr["observed_sequence"] == 1
    assert tr["last_attempt"] == {"attempted_at": "1970-01-01T00:00:00Z", "result": "received",
                                  "technique_ids": ["T1059", "T1059.001"]}
    assert tr["last_receipt"]["received_at"] == "2026-11-06T00:00:10Z"
    assert tr["last_receipt"]["outcome"] == "partial"
    assert read_recent_incidents(json.dumps({"schema": "azazel-nexus/recent-incidents/v1",
                                              "written_at": 0, "incidents": [rig.row]}).encode())


def test_the_same_pair_is_not_asked_again_and_the_receipt_is_kept(rig):
    rig.step(tx())
    receipt = json.loads(json.dumps(rig.trace["last_receipt"]))
    rig.step(tx("updated", 1, count=2), minute=1)
    assert len(rig.calls) == 1
    assert records(rig.e)[1]["mio"]["fast_assistance"]["full_node_context_origin"] == "observation_rule_v1_repeat"
    assert rig.trace["transition_query"] == "repeat"
    assert rig.trace["last_receipt"] == receipt
    assert rig.current()["full_node_context_status"] == "not_queried"
    assert rig.current()["query_origin"] == "observation_rule_v1_repeat"


def test_a_changed_set_including_the_eight_cap_replacement_asks_again(rig):
    eight = ["T1001", "T1002", "T1003", "T1004", "T1005", "T1006", "T1007", "T1059"]
    rig.step(tx(ids=eight))
    rig.step(tx("updated", 2, ids=["T1000"] + eight[:7], count=2), minute=1)
    assert len(rig.calls) == 2
    assert rig.trace["last_attempt"]["technique_ids"] == ["T1000"] + eight[:7]


def test_no_candidate_cases(rig, tmp_path):
    rig.step(tx(ids=()))
    assert rig.calls == []
    assert records(rig.e)[0]["mio"]["fast_assistance"]["full_node_context_origin"] == "none"
    assert rig.trace["transition_query"] == "no_candidate" and rig.trace["last_attempt"] is None
    # no projection: a sequence beyond the trace grammar
    (tmp_path / "x").mkdir()
    other = Rig(tmp_path / "x")
    other.e.explain(pending_entry(tx()), daemon.MIO_TRACE_SEQUENCE_MAX + 1)
    assert other.calls == []


def test_a_code_zero_set_and_a_closed_transition_are_not_candidates(rig):
    rig.step(tx(ids=()))
    rig.step(tx("closed", count=1), minute=1)
    assert rig.calls == [] and rig.trace["transition_query"] == "closed"


def test_the_pair_is_spent_whatever_the_result(tmp_path):
    def broken(frame):
        raise TimeoutError
    r = Rig(tmp_path, observed=broken)
    r.step(tx())
    assert len(r.calls) == 1
    assert r.trace["last_attempt"]["result"] == "unavailable" and r.trace["last_receipt"] is None
    assert records(r.e)[0]["mio"]["fast_assistance"]["full_node_context_status"] == "unavailable"
    assert r.current()["full_node_context_status"] == "unavailable"
    r.step(tx("updated", 1, count=2), minute=1)
    assert len(r.calls) == 1                                   # no retry


def test_the_table_is_per_incident_cleared_on_close_and_bounded(rig, monkeypatch):
    rig.step(tx())
    rig.step(tx("closed"), minute=1)
    assert rig.e._consumed == {}
    monkeypatch.setattr(daemon, "CONSUMED_PAIRS_MAX", 3)
    e = rig.e
    for n, ident in enumerate(("inc-" + f"{k:016x}" for k in range(1, 4))):
        e._spend(ident, ("T100%d" % n,))
        e._spend(ident, ("T200%d" % n,))
    total = sum(len(p) for p in e._consumed.values())
    assert total <= 3 and "inc-" + f"{1:016x}" not in e._consumed


def test_a_reply_that_breaks_the_replacement_rules_is_dropped(tmp_path):
    cases = {
        "state": lambda: received(state="complete"),
        "hypotheses": lambda: received(hypotheses=[{"x": 1}]),
        "other_unknown": lambda: received(unknowns=["Fast assessment unavailable", "KNOWLEDGE_CONTEXT_PARTIAL", "extra"]),
        "not_queried": lambda: base_fast(),
        "knowledge": lambda: received(knowledge=[{"x": 1}]),
    }
    for name, make_reply in cases.items():
        (tmp_path / name).mkdir()
        r = Rig(tmp_path / name, observed=lambda frame, f=make_reply: f())
        r.step(tx())
        assert len(r.calls) == 1, name
        fast = records(r.e)[0]["mio"]["fast_assistance"]
        assert fast["full_node_context_status"] == "unavailable", name
        assert "fabric_knowledge_context_advisory" not in fast, name
        assert r.trace["last_attempt"]["result"] == "unavailable" and r.trace["last_receipt"] is None, name


def test_received_without_an_advisory_is_received_not_adopted(tmp_path):
    def expired(frame):
        fast = received()
        del fast["fabric_knowledge_context_advisory"], fast["unknowns"][-1]
        fast["next_checks"] = []
        fast["dependency_outcome"] = {"knowledge": "expired", "deception": "absent"}
        return fast
    r = Rig(tmp_path, observed=expired)
    r.step(tx())
    assert r.trace["last_attempt"]["result"] == "received_not_adopted"
    assert r.trace["last_receipt"] is None


def test_adopt_keeps_the_advise_trace_and_takes_the_full_fields():
    advise, observed = base_fast(), received()
    adopted = adopt_full_node_reply(advise, observed)
    assert adopted["trace_id"] == advise["trace_id"] and adopted["frame_id"] == advise["frame_id"]
    assert adopted["full_node_context_status"] == "received"
    assert adopted["fabric_knowledge_context_advisory"] == observed["fabric_knowledge_context_advisory"]
    assert adopt_full_node_reply(advise, received(state="complete")) is None


# ---- row paths (DESIGN-M5 2.4) --------------------------------------------------

def test_unexplained_updates_and_escalation_and_close_move_the_word_only(rig):
    rig.step(tx())
    before = json.loads(json.dumps(rig.trace))
    append(rig.e, tx("updated", 3, count=2))
    rig.e.poll()
    assert rig.trace["transition_query"] == "not_explained" and rig.trace["observed_sequence"] == 2
    assert rig.trace["last_attempt"] == before["last_attempt"] and rig.trace["last_receipt"] == before["last_receipt"]
    assert rig.current()["full_node_context_status"] == "not_queried"
    assert "KNOWLEDGE_CONTEXT_PARTIAL" not in rig.row["explanation"]["fast_assistance"]["unknowns"]
    # escalation observed, explanation still queued: pending
    append(rig.e, tx("updated", 1, count=3))
    rig.e.ingest()
    assert rig.trace["transition_query"] == "pending" and rig.trace["observed_sequence"] == 3
    append(rig.e, tx("closed", 1, count=3))
    rig.e.ingest()
    assert rig.trace["transition_query"] == "closed" and rig.trace["last_receipt"] == before["last_receipt"]


def test_reset_closes_the_trace_and_converts_the_current_projection(rig):
    rig.step(tx())
    ledger = AuditLedger(rig.e.incidents / "1970-01-01.jsonl")
    ledger.append({"event_type": "edge.incident.reset", "at": 0, "reason": "intake_started"})
    receipt = json.loads(json.dumps(rig.trace["last_receipt"]))
    rig.e.poll()
    assert rig.row["state"] == "closed" and rig.trace["transition_query"] == "closed"
    assert rig.trace["last_receipt"] == receipt
    assert rig.current()["full_node_context_status"] == "not_queried" and "query_origin" not in rig.current()
    assert rig.e._consumed == {}


def test_explanation_unavailable_both_displaced_branches(rig):
    rig.step(tx())
    ident = rig.row["incident_id"]
    rig.row["explanation"]["state"] = "explained"
    shown = json.loads(json.dumps(rig.row))
    rig.e.explanation_unavailable(ident, "queue_full", displaced=True)
    assert rig.row == shown                                    # displaced over a shown explanation: untouched
    rig.row["explanation"]["state"] = "pending"
    rig.e.explanation_unavailable(ident, "queue_full", displaced=True)
    assert rig.row["explanation"]["state"] == "unavailable"
    assert rig.trace["transition_query"] == "not_explained"
    assert rig.trace["last_receipt"] == shown["full_node_trace"]["last_receipt"]


def test_slow_superseded_leaves_the_trace_alone(rig):
    rig.step(tx())
    rig.row["explanation"] = {**rig.row["explanation"], "slow_analysis": {"state": "queued", "usage": "unknown"}}
    rig.e.observe_transition(tx("updated", 3, count=2), sequence=2)
    assert rig.row["explanation"]["slow_analysis"] == {"state": "superseded", "usage": "unknown"}
    assert rig.trace["transition_query"] == "not_explained"


def test_a_failed_observation_leaves_the_row_untouched(rig, monkeypatch):
    rig.step(tx())
    before = json.dumps(rig.e.recent, sort_keys=True)

    def boom(*a, **k):
        raise ValueError("recent_refused")
    monkeypatch.setattr(daemon, "build_recent_incidents", boom)
    rig.e.observe_transition(tx("updated", 3, count=2), sequence=2)
    assert json.dumps(rig.e.recent, sort_keys=True) == before
    assert rig.e._latest_sequence[rig.row["incident_id"]] == 1


# ---- late explanations (DESIGN-M5 2.5, revision 3) -------------------------------

def test_a_late_explanation_updates_the_attempt_but_not_the_current_fields(rig):
    rig.step(tx())                                             # sequence 1, queried
    other = tx("updated", 1, ids=("T1059", "T1059.001", "T1110"), count=2)   # escalation, seq 2
    append(rig.e, other)
    rig.e.ingest()
    append(rig.e, tx("updated", 1, ids=("T1059", "T1059.001", "T1110"), count=3))   # ordinary, seq 3
    rig.e.ingest()
    assert rig.trace["transition_query"] == "not_explained" and rig.trace["observed_sequence"] == 3
    rig.e.monotonic = lambda: 61
    rig.e.poll()                                               # explains seq 2 late
    assert len(rig.calls) == 2
    assert rig.trace["transition_query"] == "not_explained"
    assert rig.trace["last_attempt"]["technique_ids"] == ["T1059", "T1059.001", "T1110"]
    assert rig.current()["full_node_context_status"] == "not_queried"
    assert "query_origin" not in rig.current()


def test_an_old_explanation_after_a_later_escalation_or_reopening(rig):
    rig.step(tx())
    entry = pending_entry(tx())
    append(rig.e, tx("closed"))
    append(rig.e, tx("opened", count=1))                       # same body reopened, seq 3
    rig.e.ingest()
    assert rig.trace["observed_sequence"] == 3 and rig.row["state"] == "open"
    rig.e.explain(entry, 1)                                    # stale: seq 1
    assert rig.trace["transition_query"] == "pending"
    assert rig.current()["full_node_context_status"] == "not_queried"
    assert rig.trace["observed_sequence"] == 3


def test_reset_between_escalation_and_its_explanation(rig):
    rig.step(tx())
    append(rig.e, tx("updated", 1, ids=("T1059", "T1110"), count=2))
    rig.e.ingest()
    AuditLedger(rig.e.incidents / "1970-01-01.jsonl").append(
        {"event_type": "edge.incident.reset", "at": 0, "reason": "intake_started"})
    rig.e.ingest()
    assert rig.row["state"] == "closed" and rig.trace["observed_sequence"] == 2
    rig.e.monotonic = lambda: 61
    rig.e.poll()                                               # the escalation is explained after the reset
    assert rig.trace["transition_query"] == "closed"
    assert rig.trace["last_attempt"]["technique_ids"] == ["T1059", "T1110"]
    assert rig.current()["full_node_context_status"] == "not_queried"


def test_without_trace_or_memory_the_latest_check_uses_state_count_and_first_seen(rig):
    rig.step(tx(ids=()))
    e, row = rig.e, rig.row
    del row["full_node_trace"]
    e._latest_sequence.clear()
    t = tx(ids=())
    assert e._is_latest(row, row["incident_id"], 1, t)
    assert not e._is_latest(row, row["incident_id"], 1, {**t, "count": 2})
    assert not e._is_latest(row, row["incident_id"], 1, {**t, "first_seen": t["first_seen"] + 5})
    row["state"] = "closed"
    assert not e._is_latest(row, row["incident_id"], 1, t)


# ---- first query after a later transition (review M1) --------------------------------

def _reset(e):
    AuditLedger(e.incidents / "1970-01-01.jsonl").append(
        {"event_type": "edge.incident.reset", "at": 0, "reason": "intake_started"})


@pytest.mark.parametrize("later,word", [
    ("updated", "not_explained"), ("escalation", "pending"),
    ("closed", "closed"), ("reset", "closed")])
def test_first_query_after_a_later_transition_still_leaves_the_receipt(rig, later, word):
    from azazel_nexus.incident_explain import full_node_reference_state
    append(rig.e, tx())
    rig.e.ingest()                                             # seq 1 queued, not yet explained
    if later == "updated":
        append(rig.e, tx("updated", 3, count=2))
    elif later == "escalation":
        append(rig.e, tx("updated", 1, ids=("T1059", "T1059.001"), count=2))
    elif later == "closed":
        append(rig.e, tx("closed"))
    if later != "reset":
        rig.e.ingest()
    else:
        _reset(rig.e)
        rig.e.ingest()
    assert rig.trace is None
    rig.e.monotonic = lambda: 61
    if later == "escalation":                                  # the queue would take the escalation first
        rig.e.explain(pending_entry(tx()), 1)
    else:
        rig.e.poll()                                           # explains seq 1, which is not the latest
    assert len(rig.calls) == 1
    t = rig.trace
    assert t["transition_query"] == word and t["observed_sequence"] == (1 if later == "reset" else 2)
    assert t["last_attempt"]["result"] == "received"
    assert t["last_receipt"]["received_at"] == "2026-11-06T00:00:10Z"
    assert rig.current()["full_node_context_status"] == "not_queried"
    assert "query_origin" not in rig.current()
    now = 1793923200 + 10
    assert full_node_reference_state(t, rig.row["technique_ids"], now) == "in_window"


def test_first_query_without_a_remembered_sequence_writes_no_trace(rig):
    append(rig.e, tx())
    rig.e.ingest()
    append(rig.e, tx("updated", 3, count=2))
    rig.e.ingest()
    rig.e._latest_sequence.clear()
    rig.e.monotonic = lambda: 61
    rig.e.poll()
    assert rig.trace is None and len(rig.calls) == 1


# ---- receipt time and outcomes (review M2) ----------------------------------------------

@pytest.mark.parametrize("case,has_time,expected", [
    ("complete", True, "received"), ("partial", True, "received"), ("stale", True, "received"),
    ("complete", False, "unavailable"), ("partial", False, "unavailable"),
    ("stale", False, "unavailable")])
def test_advisory_outcomes_with_and_without_the_receipt_time(tmp_path, case, has_time, expected):
    def observed(frame):
        fast = received(case)
        if not has_time:
            del fast["full_node_context_received_at"]
        return fast
    r = Rig(tmp_path, observed=observed)
    r.step(tx())
    assert r.trace["last_attempt"]["result"] == expected
    assert (r.trace["last_receipt"] is not None) == (expected == "received")


@pytest.mark.parametrize("outcome,status,expected", [
    ("rejected", "received", "received_not_adopted"), ("expired", "received", "received_not_adopted"),
    ("unavailable", "received", "received_not_adopted"), ("unavailable", "unavailable", "unavailable")])
def test_non_advisory_outcomes(rig, outcome, status, expected):
    rig.step(tx())
    summary = {"fast_assistance": {"full_node_context": {"outcome": outcome,
                                                          "full_node_context_status": status}}}
    row = json.loads(json.dumps(rig.row))
    attempt = {"word": "queried", "queried": True, "adopted": True,
               "received_at": "2026-11-06T00:00:10Z"}
    rig.e._settle_row(row, summary, tx(), 1, attempt, 100.0)
    assert row["full_node_trace"]["last_attempt"]["result"] == expected


# ---- the trace is never an input ----------------------------------------------------

def test_the_trace_does_not_change_decisions_requests_or_records(tmp_path):
    variants = [None,
                {"receipt_ids": ["T1059"], "expires": "2026-11-06T00:01:00Z"},
                {"receipt_ids": ["T1059", "T9999"], "expires": "2020-01-01T00:00:01Z"}]
    seen = []
    for n, variant in enumerate(variants):
        (tmp_path / str(n)).mkdir()
        r = Rig(tmp_path / str(n))
        r.step(tx(ids=("T1059",)))
        if variant:
            tr = r.trace
            tr["last_receipt"]["technique_ids"] = variant["receipt_ids"]
            tr["last_attempt"]["technique_ids"] = variant["receipt_ids"]
            tr["last_receipt"]["expires_at"] = variant["expires"]
            tr["last_receipt"]["generated_at"] = "2020-01-01T00:00:00Z"
        elif r.trace:
            del r.row["full_node_trace"]
        r.step(tx("updated", 1, ids=("T1059", "T1110"), count=2), minute=1)
        seen.append((len(r.calls), [json.dumps(c, sort_keys=True) for c in r.calls],
                     json.dumps(records(r.e)[1], sort_keys=True)))
    assert seen[0] == seen[1] == seen[2]


def test_a_checkpoint_restores_the_same_trace(rig, tmp_path):
    rig.step(tx())
    rig.step(tx("updated", 1, count=2), minute=1)
    before = json.loads(json.dumps(rig.e.recent))
    raw = (tmp_path / "state" / "cursor.json").read_bytes()
    again = make(tmp_path, mio=lambda _: handoff(), observation_rule=lambda: None)
    assert again.recent == before
    again.checkpoint()
    assert (tmp_path / "state" / "cursor.json").read_bytes() == raw


def test_the_advise_side_not_queried_check_may_be_replaced_by_the_incomplete_check():
    others = ["Fix the time window of the main complaint.", "Line up the other log timestamps."]
    advise = {**base_fast(), "next_checks": [MIO_KNOWLEDGE_NOT_QUERIED_CHECK, *others]}
    observed = received(next_checks=[FULL_NODE_INCOMPLETE_CHECK, *others])
    assert adopt_full_node_reply(advise, observed) is not None
    # the incomplete check may also be absent, but nothing else may differ, in text or in order
    assert adopt_full_node_reply(advise, received(next_checks=list(others))) is not None
    assert adopt_full_node_reply(advise, received(next_checks=[FULL_NODE_INCOMPLETE_CHECK, others[0] + "."] + others[1:])) is None
    assert adopt_full_node_reply(advise, received(next_checks=[FULL_NODE_INCOMPLETE_CHECK, others[1], others[0]])) is None
    assert adopt_full_node_reply(advise, received(next_checks=[FULL_NODE_INCOMPLETE_CHECK, *others, "extra"])) is None
    assert adopt_full_node_reply(advise, received(next_checks=[FULL_NODE_INCOMPLETE_CHECK, others[0]])) is None


@pytest.mark.parametrize("damage", [
    lambda f: f.update(unknowns="not a list"),
    lambda f: f.update(next_checks=["x" * 5000]),
    lambda f: f.update(full_node_context_status="bogus"),
    lambda f: f.update(extra_key=1),
    lambda f: f.update(reasoning_trace="bad"),
    lambda f: f.update(fabric_knowledge_context_advisory={"authority": "advisory_only"})])
def test_an_invalid_observe_reply_is_unavailable_and_keeps_the_advise_result(tmp_path, damage):
    def observed(frame):
        fast = received()
        damage(fast)
        return fast
    r = Rig(tmp_path, observed=observed)
    r.step(tx())
    assert len(r.calls) == 1
    assert r.trace["last_attempt"]["result"] == "unavailable" and r.trace["last_receipt"] is None
    assert r.current()["full_node_context_status"] == "unavailable"
    assert r.row["explanation"]["state"] != "unavailable" or r.row["explanation"]["failure_codes"] != ["mio_reply_refused"]
    assert "mio_reply_refused" not in r.row["explanation"]["failure_codes"]
