"""Unit D: recent-row `full_node_trace`, `query_origin`, reference words, rollback conversion."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from azazel_nexus.incident_explain import (
    FULL_NODE_LIMITATIONS, build_recent_incident, build_recent_incidents, explanation_summary,
    full_node_reference_state, read_recent_incidents, utc_seconds, without_current_full_node,
)
from test_incident_explain import _core_full_node_fast, _record, _t1110

RECEIPT = {"received_at": "2026-11-06T00:00:10Z", "outcome": "partial",
           "source_kind": "fabric_knowledge_context_response_v1",
           "claim_status": "source_reported_unverified", "trust": "unverified_advisory_only",
           "snapshot_state": "partial", "generated_at": "2026-11-06T00:00:00Z",
           "expires_at": "2026-11-06T00:01:00Z",
           "limitations": [FULL_NODE_LIMITATIONS[0]], "technique_ids": ["T1110"]}
ATTEMPT = {"attempted_at": "2026-11-06T00:00:11Z", "result": "received",
           "technique_ids": ["T1110"]}


def trace(**kw):
    value = {"transition_query": "queried", "last_attempt": dict(ATTEMPT),
             "last_receipt": dict(RECEIPT), "observed_sequence": 7}
    value.update(kw)
    return value


def row_with(tr=None, fast=None, origin=None):
    t = _t1110()
    fast = fast or _core_full_node_fast("partial")
    if origin:
        fast["full_node_context_origin"] = origin
    record = _record({"route": "unavailable", "outcome": "unavailable", "reason": "mio_unavailable",
                      "text": None, "fast_assistance": fast})
    record["technique_ids"] = ["T1110"]
    record["incident_id"] = t["incident_id"]
    row = build_recent_incident(t, record=record)
    if tr is not None:
        row["full_node_trace"] = tr
    return row


def read(row):
    value = {"schema": "azazel-nexus/recent-incidents/v1", "written_at": 1, "incidents": [row]}
    return read_recent_incidents(json.dumps(value).encode())


def test_rows_with_and_without_the_trace_read():
    assert read(row_with()) is not None
    assert read(row_with(trace())) is not None
    assert read(row_with(trace(last_attempt=None, last_receipt=None, transition_query="closed"))) is not None


def test_query_origin_is_optional_and_closed():
    plain = row_with()
    assert "query_origin" not in plain["explanation"]["fast_assistance"]["full_node_context"]
    for origin in ("observation_rule_v1", "observation_rule_v1_repeat", "none"):
        r = row_with(origin=origin)
        assert r["explanation"]["fast_assistance"]["full_node_context"]["query_origin"] == origin
        assert read(r) is not None
    bad = row_with(origin="observation_rule_v1")
    bad["explanation"]["fast_assistance"]["full_node_context"]["query_origin"] = "other"
    assert read(bad) is None


def test_conversion_drops_the_origin_and_matches_the_old_form():
    plain = row_with()
    with_origin = row_with(origin="observation_rule_v1")
    assert without_current_full_node(with_origin["explanation"])[
        "fast_assistance"]["full_node_context"].get("query_origin") is None
    assert "query_origin" not in without_current_full_node(
        with_origin["explanation"])["fast_assistance"]["full_node_context"]
    assert without_current_full_node(plain["explanation"]) == without_current_full_node(
        with_origin["explanation"])


@pytest.mark.parametrize("mutate", [
    lambda t: t.pop("observed_sequence"),
    lambda t: t.update(extra=1),
    lambda t: t.update(transition_query="other"),
    lambda t: t.update(observed_sequence=0),
    lambda t: t.update(observed_sequence=True),
    lambda t: t.update(last_attempt=None),                       # queried needs an attempt
    lambda t: t.update(last_receipt=None),                       # received needs a receipt
    lambda t: t["last_attempt"].update(result="maybe"),
    lambda t: t["last_attempt"].update(attempted_at="2026-11-06 00:00:11"),
    lambda t: t["last_attempt"].update(attempted_at="2026-13-06T00:00:11Z"),
    lambda t: t["last_attempt"].update(technique_ids=["T1110", "T1059"]),
    lambda t: t["last_attempt"].update(technique_ids=[]),
    lambda t: t["last_receipt"].update(technique_ids=["T1059"]),   # differs from the attempt
    lambda t: t["last_receipt"].update(outcome="complete"),         # snapshot_state mismatch
    lambda t: t["last_receipt"].update(outcome="rejected", snapshot_state="rejected"),
    lambda t: t["last_receipt"].update(received_at="yesterday"),
    lambda t: t["last_receipt"].update(received_at="2026-02-31T00:00:00Z"),
    lambda t: t["last_receipt"].update(expires_at="2026-11-05T00:00:00Z"),
    lambda t: t["last_receipt"].update(source_kind="x"),
    lambda t: t["last_receipt"].update(limitations=["free text"]),
    lambda t: t["last_receipt"].pop("trust"),
    lambda t: t["last_receipt"].update(subject="x"),
])
def test_a_bad_trace_refuses_the_whole_snapshot(mutate):
    t = trace()
    mutate(t)
    assert read(row_with(t)) is None


def test_reference_state_words():
    ids = ["T1110"]
    t = trace()
    inside = 1793923200 + 10  # 2026-11-06T00:00:10Z
    assert full_node_reference_state(None, ids, inside) == "not_recorded"
    assert full_node_reference_state(trace(last_receipt=None, last_attempt=None,
                                           transition_query="closed"), ids, inside) == "none"
    for bad in (None, float("nan"), float("inf"), -1, "x"):
        assert full_node_reference_state(t, ids, bad) == "unknown"
    assert full_node_reference_state(t, ids, inside) == "in_window"
    assert full_node_reference_state(t, ["T1059", "T1110"], inside) == "set_changed"
    expires = inside + 50
    assert full_node_reference_state(t, ids, expires - 1) == "in_window"
    assert full_node_reference_state(t, ids, expires) == "expired"
    assert full_node_reference_state(t, ["T1059"], expires + 1) == "expired"


def test_utc_seconds_truncates_and_refuses_bad_clocks():
    assert utc_seconds(0.9) == "1970-01-01T00:00:00Z"
    assert utc_seconds(1793923211.99) == "2026-11-06T00:00:11Z"
    for bad in (None, float("nan"), -1, "1"):
        with pytest.raises(ValueError):
            utc_seconds(bad)


def test_status_view_shows_one_word_not_the_trace():
    from azazel_nexus.status_view import _recent_extra
    for tr, now, word in ((None, 5.0, "not_recorded"), (trace(), None, "unknown"),
                          (trace(), 1793923210.0, "in_window"), (trace(), 1793923300.0, "expired")):
        value = build_recent_incidents([row_with(tr)], 1)
        snap = {}
        _recent_extra(value, snap, now, "ui")
        copy = snap["incidents"][0]
        assert copy["full_node_reference"] == word
        assert "full_node_trace" not in copy and "observed_sequence" not in json.dumps(snap)


@pytest.mark.parametrize("reader", ["operator", "root"])
def test_status_view_without_ui_reader_has_no_reference_key(reader):
    from azazel_nexus.status_view import _recent_extra
    snap = {}
    _recent_extra(build_recent_incidents([row_with(trace())], 1), snap, 1793923210.0, reader)
    assert "full_node_reference" not in snap["incidents"][0]
    snap = {}
    _recent_extra(build_recent_incidents([row_with(trace())], 1), snap, 1793923210.0)
    assert "full_node_reference" not in snap["incidents"][0]


def _maximal_guidance(incident_id):
    t = lambda k: ("Inspect the launch of the interpreter and check its parent " * 6)[:k].strip()
    return {"guidance_schema_version": "1.0.0", "content_kind": "deterministic_guidance",
            "generation_method": "deterministic_guidance", "model_calls": 0,
            "playbook_id": "p" * 60, "playbook_version": "v" * 90, "playbook_digest": "sha256:" + "a" * 64,
            "guidance_digest": "sha256:" + "b" * 64, "selection_mode": "s" * 90,
            "facts": [{"kind": "knowledge", "trust": "x" * 60, "text": t(280)}] * 8,
            "competing_explanations": [{"slot": "s" * 60, "role": "hostile", "prompt": t(280),
                                        "support": "unverified_candidate"}] * 4,
            "discriminating_material": [t(280)] * 8, "claim_boundaries": [t(280)] * 8,
            "unknown_groups": [{"text": t(280), "topic": "t" * 60, "sources": ["report"],
                                "merged": [t(280)] * 8}] * 8,
            "topics_addressed": [{"id": "i" * 60, "as_reported": t(280), "negative": False}] * 4,
            "weight_notes": [{"explanation": "e" * 60, "direction": "verification_priority_up",
                              "topic": "t" * 60, "as_reported": t(280)}] * 4,
            "next_checks": [{"id": "check-a", "tier": "required", "mode": "read_only_existing_authority", "text": t(240)},
                            {"id": "check-b", "tier": "required", "mode": "read_only_existing_authority", "text": t(240)},
                            {"id": "check-c", "tier": "optional_when_needed", "mode": "read_only_existing_authority", "text": t(240)},
                            {"id": "check-d", "tier": "optional_when_needed", "mode": "read_only_existing_authority", "text": t(240)}],
            "recommendation": {"recommended_action": "OBSERVE", "executable": False, "current_action": None,
                               "source": "deterministic_fixed"},
            "evidence_gaps": {"items": [{"marker": t(240), "question": t(240), "capability": t(240)}] * 4,
                              "reason": "r" * 90, "source": "deterministic"},
            "handoff": {"incident_id": incident_id, "privacy_class": "P3-restricted"}}


def _maximal_row(n):
    """A row with every optional field the reader accepts at its upper bound, plus a maximal trace."""
    from azazel_nexus.incident_explain import CITATION_FIELDS
    big = trace(last_receipt={**RECEIPT, "limitations": [FULL_NODE_LIMITATIONS[i] for i in (0, 2, 1)]})
    r = row_with(big, fast=_core_full_node_fast("partial"), origin="observation_rule_v1_repeat")
    r["incident_id"] = f"inc-{n:016x}"
    r["last_seen"] = r["last_seen"] + n
    text = lambda k: ("Inspect the launch of the interpreter and check its parent " * 5)[:k].strip()
    e = r["explanation"]
    e.update(state="explained", route="local", outcome="answered", content_kind="ai_advice",
             summary=text(279), knowledge_refs_omitted=8)
    ref = {"technique_id": "T1110", "name": "n" * 120, "claim_id": "T1110",
           "bundle_digest_short": "sha256:" + "a" * 12, "generation": 2**62, "freshness": "current",
           "as_of": "2026-11-06T00:00:00Z", "citation": "c" * 160, "citation_state": "shown"}
    e["knowledge_refs"] = [ref] * 8
    e["guidance"] = _maximal_guidance(r["incident_id"])
    f = e["fast_assistance"]
    f["unknowns"] = [text(240)] * 8
    f["next_checks"] = [text(240)] * 8
    f["knowledge"] = [{"technique_id": "T1110", "name": "n" * 120, "summary": "s" * 240,
                       "freshness": "current", "as_of": "2026-11-06T00:00:00Z", "citation": "c" * 160,
                       "revocation_status": "clear", "claim_status": "reported_unverified"}] * 8
    f["dependency_outcome"] = {"knowledge": "available", "deception": "absent"}
    e["slow_analysis"] = {"state": "complete", "usage": "known", "verification": "model_proposed_unverified",
                          "hypotheses": [text(240)] * 4, "unknowns": [text(240)] * 8,
                          "next_checks": [text(240)] * 8}
    return r


def _recent_bytes(rows):
    return len(json.dumps({"schema": "azazel-nexus/recent-incidents/v1", "written_at": 1,
                           "incidents": rows}).encode())


def test_the_trace_adds_under_one_kib_to_a_maximal_row():
    from azazel_nexus.incident_explain import RECENT_BYTES
    rows = [_maximal_row(n) for n in range(20)]
    assert read_recent_incidents(json.dumps({"schema": "azazel-nexus/recent-incidents/v1",
                                             "written_at": 1, "incidents": rows[:1]}).encode()) is not None
    bare = [{k: v for k, v in r.items() if k != "full_node_trace"} for r in rows]
    per_row = (_recent_bytes(rows) - _recent_bytes(bare)) / 20
    assert 0 < per_row < 1024
    print("one maximal row:", len(json.dumps(rows[0])), "twenty with trace:", _recent_bytes(rows),
          "without:", _recent_bytes(bare), "bound:", RECENT_BYTES)


@pytest.mark.xfail(strict=True, reason=(
    "FINDING (review M4): rows with every existing optional field at the reader's maximum "
    "(citations, guidance, slow_analysis, fast_assistance strings) are about 60 KiB each, so 20 of "
    "them exceed RECENT_BYTES (256 KiB) even without the trace; the product is unchanged."))
def test_twenty_maximal_rows_fit_in_the_bound():
    from azazel_nexus.incident_explain import RECENT_BYTES
    assert _recent_bytes([_maximal_row(n) for n in range(20)]) <= RECENT_BYTES


# ---- rollback conversion -------------------------------------------------

def _checkpoint(tmp_path, rows):
    from azazel_nexus_runtime import incident_explaind as d
    value = {"cursor": {"segment": None, "offset": 0, "sequence": 0, "last_hash": "0" * 64, "broken": False}, "pending": [], "recent": build_recent_incidents(rows, 0),
             "audit_severities": {}, "audit_forward_dropped": 0, "audit_forward_refused": 0,
             "explained_ids": {}, "explained": 0, "last_explained_at": None, "refused": {},
             "chain_broken": False, "mio_available": True, "knowledge_available": True}
    return value, d


def test_rollback_conversion_strips_only_trace_and_origin(tmp_path):
    from azazel_nexus_runtime import incident_explaind as d
    probe = Path(d.__file__)
    rows = [row_with(trace(), origin="observation_rule_v1"), row_with()]
    rows[1]["incident_id"] = "inc-" + "1" * 16
    rows[0]["last_seen"] += 1
    value, d = _checkpoint(tmp_path, rows)
    path = tmp_path / "cursor.json"
    path.write_bytes(d.canonical(value) + b"\n")
    original = path.read_bytes()
    assert d.checkpoint_for_release_before_full_node_trace(path) == 1
    out = path.read_text()
    assert "full_node_trace" not in out and "query_origin" not in out
    assert path.with_name("cursor.json.pre-rollback").read_bytes() == original
    # a second run is refused, an interrupted one (backup == current original) is not tested here
    with pytest.raises(ValueError, match="rollback_backup_exists"):
        d.checkpoint_for_release_before_full_node_trace(path)
    assert probe.exists()


def test_an_existing_backup_is_refused_even_when_identical(tmp_path):
    value, d = _checkpoint(tmp_path, [row_with(trace(), origin="observation_rule_v1")])
    path = tmp_path / "cursor.json"
    path.write_bytes(d.canonical(value) + b"\n")
    backup = path.with_name("cursor.json.pre-rollback")
    backup.write_bytes(path.read_bytes())                     # same bytes as the checkpoint
    original = path.read_bytes()
    with pytest.raises(ValueError, match="rollback_backup_exists"):
        d.checkpoint_for_release_before_full_node_trace(path)
    assert path.read_bytes() == original and backup.read_bytes() == original


def d_convert(path):
    from azazel_nexus_runtime import incident_explaind as d
    return d.checkpoint_for_release_before_full_node_trace(path)


def test_a_refused_checkpoint_is_not_rewritten_by_the_trace_conversion(tmp_path):
    from azazel_nexus_runtime import incident_explaind as d
    path = tmp_path / "cursor.json"
    path.write_bytes(b'{"cursor": "broken"}')
    with pytest.raises(ValueError):
        d.checkpoint_for_release_before_full_node_trace(path)
    assert not path.with_name("cursor.json.pre-rollback").exists()


OLD = os.environ.get("NEXUS_ROLLBACK_TARGET_SRC")


@pytest.mark.skipif(not OLD, reason="NEXUS_ROLLBACK_TARGET_SRC (a 74a6189 checkout) not set")
def test_the_converted_checkpoint_is_read_by_74a6189(tmp_path):
    """A real 74a6189 checkout reads the converted checkpoint (decode, recent reader, prepare())."""
    from test_incident_explaind import append, make
    old = Path(OLD)
    e = make(tmp_path)
    append(e)
    e.poll()
    # A ledger record carrying the D fields, as the new release writes them.
    fast = _core_full_node_fast("partial")
    fast["full_node_context_received_at"] = "2026-11-06T00:00:10Z"
    fast["full_node_context_origin"] = "observation_rule_v1"
    from azazel_nexus.incident_explain import read_record
    record = _record({"route": "unavailable", "outcome": "unavailable", "reason": "mio_unavailable",
                      "text": None, "fast_assistance": fast})
    record["incident_id"] = "inc-" + "2" * 16
    e.store.append_record(read_record(record))
    e.recent = [row_with(trace(), origin="observation_rule_v1")]
    e.checkpoint()
    path = tmp_path / "state" / "cursor.json"
    assert b"full_node_trace" in path.read_bytes() and b"query_origin" in path.read_bytes()
    script = (
        f"import sys; sys.path[:0] = ['{old}/src', '{old}/runtime/src']\n"
        "import pathlib\n"
        "from azazel_nexus_runtime import incident_explaind as d\n"
        "from azazel_nexus.incident_explain import read_recent_incidents\n"
        "base = pathlib.Path(sys.argv[1])\n"
        "print('FILE', d.__file__)\n"
        "raw = (base / 'state' / 'cursor.json').read_bytes()\n"
        "try:\n"
        "    v = d.decode_checkpoint(raw); print('DECODED', read_recent_incidents(d.canonical(v['recent'])) is not None)\n"
        "except Exception: print('REFUSED')\n"
        "x = d.Explainer(incidents=base / 'incidents', state=base / 'state', status_path=base / 'status2.json',\n"
        "                clock=lambda: 0, monotonic=lambda: 0, mio=lambda _: None, knowledge=lambda _: ())\n"
        "try:\n"
        "    x.prepare(); print('PREPARED')\n"
        "except Exception as exc: print('PREPARE_FAILED', exc)\n")
    run = lambda: subprocess.run([sys.executable, "-I", "-c", script, str(tmp_path)],
                                 capture_output=True, text=True).stdout
    before = run()
    assert str(old) in before and "REFUSED" in before and "PREPARE_FAILED" in before
    assert d_convert(path) == 1
    after = run()
    assert "DECODED True" in after and "PREPARED" in after, after
