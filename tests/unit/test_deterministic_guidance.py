"""Deterministic guidance (no model) through the explanation record, snapshot, view and handoff."""
from __future__ import annotations

import copy
import json
import sys

import pytest

from azazel_nexus import guidance_record as GR
from azazel_nexus.incident_explain import (
    build_recent_incidents, explanation_summary, read_record, read_recent_incidents)
from azazel_nexus_runtime import incident_explaind as daemon
from azazel_nexus_runtime.mio_deterministic_guidance import guidance_for_frame

from test_evidence_refs import _append, _explainer, _incident, _records

pytest.importorskip("azazel_mio.guidance")

REPORT = ("Synthetic 5m report: DNS timeouts 18/60 vs prior 0/60; existing TCP checks 60/60. "
          "One probe, one resolver; other sites unknown. Clock trust and affected population are unknown. "
          "Read-only checks; preserve essential communication.")
NEW = REPORT.replace("other sites unknown", "two other sites report no timeouts against the same resolver")
ADDRESS = "198.51.100.18"


def with_report(report):
    def make(frame):
        frame = copy.deepcopy(frame)
        frame["context"].append({"kind": "operator_report", "text": report})
        return guidance_for_frame(frame, withheld_values=[ADDRESS])
    return make


def explained(tmp_path, report=REPORT):
    (first,), (opened,) = _incident()
    e = _explainer(tmp_path, lambda: 200.0, guidance=with_report(report))
    _append(e, opened)
    e.poll()
    (rec,) = _records(e)
    return e, rec, first


def test_record_stores_guidance_and_it_binds_to_the_record(tmp_path):
    e, rec, first = explained(tmp_path)
    g = rec["guidance"]
    assert (g["content_kind"], g["model_calls"], g["generation_method"]) == ("deterministic_guidance", 0, "deterministic_guidance")
    assert g["handoff"]["incident_id"] == rec["incident_id"]
    assert g["handoff"]["evidence_refs"] == [first.digest]
    assert g["recommendation"]["recommended_action"] == "OBSERVE" and g["recommendation"]["executable"] is False
    assert any("18/60" in f["text"] for f in g["facts"])
    assert rec["mio"]["content_kind"] != "ai_advice"


def test_summary_snapshot_and_view(tmp_path):
    _, rec, _ = explained(tmp_path, NEW)
    summary = explanation_summary(rec)
    assert summary["guidance"]["content_kind"] == "deterministic_guidance"
    assert set(summary["guidance"]["handoff"]) == {"incident_id", "privacy_class"}
    v = GR.guidance_view(rec["guidance"])
    assert len(v["summary"]["required_checks"]) == 2
    assert any(w["direction"] == "確認の優先度が上がる" for w in v["summary"]["priority_changes"])
    assert any("報告ベース・未検証" in u["text"] for u in v["detail"]["all_unknowns"])
    assert v["detail"]["explanations"] and "未検証" in v["detail"]["explanations"][0]["support"]
    assert "モデル生成ではありません" in v["summary"]["notice"]
    md = GR.guidance_markdown(rec["guidance"])
    assert "model_calls 0" in md and rec["incident_id"] in md


def test_withheld_value_never_appears(tmp_path):
    _, rec, _ = explained(tmp_path, REPORT + f" Source {ADDRESS} was seen. Three hosts.")
    assert ADDRESS not in json.dumps(rec)
    bad = copy.deepcopy(rec["guidance"])
    bad["facts"][0]["text"] = f"seen {ADDRESS}"
    with pytest.raises(ValueError):
        GR.read_guidance(bad)


def test_unknown_kind_and_tampering_drop_the_guidance_only(tmp_path):
    _, rec, _ = explained(tmp_path)
    muts = (lambda g: g.update(content_kind="ai_advice"), lambda g: g.update(model_calls=1),
            lambda g: g["recommendation"].update(executable=True),
            lambda g: g["facts"][0].update(trust="verified"),
            lambda g: g.update(extra=1))
    for mutate in muts:
        bad = copy.deepcopy(rec)
        mutate(bad["guidance"])
        with pytest.raises(ValueError):
            GR.read_guidance(bad["guidance"])
        kept = read_record(bad)
        assert "guidance" not in kept and kept["mio"] == rec["mio"] and kept["incident_id"] == rec["incident_id"]


def test_binding_mismatch_drops_the_guidance_only(tmp_path):
    _, rec, _ = explained(tmp_path)
    for path, value in (("incident_id", "inc-" + "0" * 16), ("trace_id", "mio-x-1"), ("frame_id", "mio-x-1:frame"),
                        ("request_id", "inc-0000000000000000:1"), ("evidence_refs", ["sha256:" + "0" * 64])):
        bad = copy.deepcopy(rec)
        bad["guidance"]["handoff"][path] = value
        kept = read_record(bad)
        assert "guidance" not in kept and kept["mio"] == rec["mio"]


def test_recent_row_only_guidance_makes_json_and_markdown_handoff(tmp_path):
    from azazel_nexus import handoff as H
    _, rec, first = explained(tmp_path, NEW)
    row = {"explanation": {"guidance": explanation_summary(rec)["guidance"]}}
    block = H._guidance_block([], row)
    assert block["source"] == "recent_snapshot" and H.scan_package(block) == []
    md = GR.guidance_markdown(row["explanation"]["guidance"], H._md)
    assert "非表示" in md and "model_calls 0" in md and rec["incident_id"] in md and H.scan_markdown(md) == []
    assert first.digest not in md and first.digest not in json.dumps(block)


def test_old_records_without_guidance_still_read(tmp_path):
    e, rec, _ = explained(tmp_path)
    old = {k: v for k, v in rec.items() if k != "guidance"}
    assert read_record(old) == old
    assert "guidance" not in explanation_summary(old)


def test_a_guidance_failure_leaves_the_record_intact(tmp_path):
    (first,), (opened,) = _incident()
    def boom(frame): raise RuntimeError("x")
    e = _explainer(tmp_path, lambda: 200.0, guidance=boom)
    _append(e, opened)
    e.poll()
    (rec,) = _records(e)
    assert "guidance" not in rec and rec["mio"]["route"] == "deterministic handoff"
    # an unbound guidance is dropped, the rest kept
    e2 = _explainer(tmp_path / "b", lambda: 200.0, guidance=lambda f: dict(with_report(REPORT)(f), handoff={**with_report(REPORT)(f)["handoff"], "trace_id": "mio-z-1"}))
    _append(e2, opened)
    e2.poll()
    (rec2,) = _records(e2)
    assert "guidance" not in rec2 and rec2["mio"]["reason"] != "mio_reply_refused"


def test_recent_snapshot_accepts_guidance_and_refuses_unknown(tmp_path):
    _, rec, _ = explained(tmp_path)
    from azazel_nexus.incident_explain import build_recent_incident
    summary = explanation_summary(rec)
    assert read_recent_incidents  # reader exercised through the daemon snapshot below
    bad = copy.deepcopy(summary["guidance"])
    bad["content_kind"] = "model_output"
    with pytest.raises(ValueError):
        GR.read_guidance(bad, public=True)


def test_handoff_block_json_and_markdown_pass_the_leak_scan(tmp_path):
    from azazel_nexus import handoff as H
    e, rec, first = explained(tmp_path, NEW + f" Source {ADDRESS}.")
    block = H._guidance_block([rec], None)
    assert block["status"] == "available" and block["model_calls"] == 0 and block["source"] == "explanation_ledger"
    assert block["guidance"]["handoff"]["evidence_refs"] == [first.digest]
    md = GR.guidance_markdown(rec["guidance"], H._md)
    assert H.scan_markdown(md) == []
    assert H.scan_package(block) == []
    assert ADDRESS not in md and ADDRESS not in json.dumps(block)
    assert "モデル生成ではない" in md
    # without a record the block says so
    assert H._guidance_block([], None)["status"] == "unavailable"
    # the recent snapshot row carries the bounded projection, without evidence pointers
    row_guidance = explanation_summary(rec)["guidance"]
    assert first.digest not in json.dumps(row_guidance)
    row = {"explanation": {"guidance": row_guidance}}
    assert H._guidance_block([], row)["source"] == "recent_snapshot"


def test_daemon_recent_snapshot_row_validates(tmp_path):
    e, rec, _ = explained(tmp_path)
    snap = build_recent_incidents(e.recent, 200.0)
    assert read_recent_incidents(json.dumps(snap).encode()) == snap
    g = snap["incidents"][0]["explanation"]["guidance"]
    assert g["content_kind"] == "deterministic_guidance"
    snap["incidents"][0]["explanation"]["guidance"]["content_kind"] = "x"
    assert read_recent_incidents(json.dumps(snap).encode()) is None


def test_an_unlisted_address_in_the_report_is_scrubbed_not_fatal(tmp_path):
    _, rec, _ = explained(tmp_path, REPORT + " Peer 203.0.113.5 and 2001:db8::7 also timed out. Two sites.")
    blob = json.dumps(rec)
    assert "203.0.113.5" not in blob and "2001:db8::7" not in blob
    assert any("[withheld]" in f["text"] for f in rec["guidance"]["facts"])


def test_edge_fact_text_names_executed_action_not_edge_decision():
    # U36: the line carries the executed action (None = nothing ran); Edge's would decision is elsewhere.
    t = GR._fact_text({"kind": "edge_decision", "text": "Edge selected_action=None, result=not_executed, executed_count=0"})
    assert "None を選択" not in t and "Edge の判断:" not in t
    assert "実行した action: なし（結果 not_executed、実行件数 0）" in t and "Edge 欄" in t
    assert "実行した action: isolate" in GR._fact_text({"kind": "edge_decision", "text": "Edge selected_action=isolate, result=x, executed_count=1"})
