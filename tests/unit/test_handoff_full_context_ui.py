"""U39 E: `knowledge.full_node_context` for principal ui (DESIGN-M5 3.2, 3.3)."""

from __future__ import annotations

import hashlib
import json

import pytest

from azazel_nexus import handoff
from azazel_nexus.incident_explain import FULL_NODE_LIMITATIONS

from test_handoff_full_context_row import (
    BASE, FULL, GOLDEN_FULL_ROW, UI_HIDDEN, _files, _root, example, runtime_paths, shutil,
)

NOW = example.GENERATED
IDS = None


def _iso(epoch):
    return handoff._iso(epoch)


def _recent(root):
    return root / "var/lib/azazel/run/incident-explain-status/recent.json"


def _with_trace(tmp_path, name, trace, fast=None, tweak=None):
    root = _root(tmp_path, name, fast if fast is not None else {**BASE, "full_node_context": FULL})
    doc = json.loads(_recent(root).read_text())
    row = doc["incidents"][0]
    if trace is not None:
        row["full_node_trace"] = trace(row["technique_ids"]) if callable(trace) else trace
    if tweak:
        tweak(row)
    _recent(root).write_text(json.dumps(doc))
    for leaf in runtime_paths.UI_COPIES:
        src = runtime_paths.snapshot_path(leaf, root)
        if src.is_file():
            dst = runtime_paths.snapshot_path(leaf, root, reader="ui")
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(src, dst)
    return root


def _receipt(ids, expires="2026-10-29T06:00:00Z", **kw):
    r = {"received_at": "2026-10-29T03:15:30Z", "outcome": "complete",
         "source_kind": FULL["source_kind"], "claim_status": FULL["claim_status"],
         "trust": FULL["trust"], "snapshot_state": "complete",
         "generated_at": "2026-10-29T03:15:00Z", "expires_at": expires,
         "limitations": [FULL_NODE_LIMITATIONS[0]], "technique_ids": ids}
    r.update(kw)
    return r


def _trace(query, attempt=None, receipt=None):
    return {"transition_query": query, "last_attempt": attempt, "last_receipt": receipt,
            "observed_sequence": 7}


def _fn(tmp_path, monkeypatch, name, trace, **kw):
    root = _with_trace(tmp_path, name, trace, **kw)
    monkeypatch.setenv("AZAZEL_ROOT", str(root))
    pkg = handoff.build_package(example.INCIDENT, now=NOW, principal="ui", root=None)
    return pkg["knowledge"]["full_node_context"], pkg


def test_old_row_has_no_trace(tmp_path, monkeypatch):
    fn, _ = _fn(tmp_path, monkeypatch, "a", None)
    assert fn["reference_state"] == "not_recorded" and fn["transition_query"] == "not_recorded"
    assert fn["last_attempt"] is None and fn["last_receipt"] is None
    assert fn["full_node_context_status"] == "received" and fn["query_origin"] == "not_recorded"
    assert fn["limitations"][-1].startswith("The past reference is not an answer")


def test_trace_null_receipt_attempt(tmp_path, monkeypatch):
    fn, _ = _fn(tmp_path, monkeypatch, "b", lambda ids: _trace("not_explained"))
    assert fn["reference_state"] == "none" and fn["last_receipt"] is None


@pytest.mark.parametrize("case", ["received", "received_not_adopted", "unavailable"])
def test_attempt_results(tmp_path, monkeypatch, case):
    def trace(ids):
        attempt = {"attempted_at": "2026-10-29T03:15:31Z", "result": case, "technique_ids": ids}
        return _trace("queried", attempt, _receipt(ids))
    fn, _ = _fn(tmp_path, monkeypatch, "c" + case, trace)
    assert fn["last_attempt"]["result"] == case
    assert fn["last_receipt"]["received_in_current_transition"] is (case == "received")
    assert fn["last_receipt"]["technique_set_relation"] == "same"
    assert fn["reference_state"] == "in_window"
    assert fn["last_receipt"]["expired_at_generation"] is False


def test_expired_and_set_changed(tmp_path, monkeypatch):
    fn, _ = _fn(tmp_path, monkeypatch, "d", lambda ids: _trace("not_explained", None, _receipt(ids, "2026-10-29T04:00:00Z")))
    assert fn["reference_state"] == "expired" and fn["last_receipt"]["expired_at_generation"] is True
    fn, _ = _fn(tmp_path, monkeypatch, "e", lambda ids: _trace("not_explained", None, _receipt(["T9999"] if False else ids)),
                tweak=lambda row: row.update(technique_ids=sorted(set(row["technique_ids"]) | {"T1595"})))
    assert fn["reference_state"] == "set_changed" and fn["last_receipt"]["technique_set_relation"] == "changed"


@pytest.mark.parametrize("bad", [None, float("nan"), float("inf"), -1.0])
def test_no_judgement_time_is_unknown(bad):
    ids = ["T1046"]
    row = {"technique_ids": ids, "explanation": {"fast_assistance": {"full_node_context": {
        "full_node_context_status": "received", "outcome": "complete", "limitations": []}}},
        "full_node_trace": _trace("not_explained", None, _receipt(ids))}
    fn = handoff._full_node_context(row, {"recent_incidents_snapshot": (None, None)}, bad)
    assert fn["reference_state"] == "unknown" and fn["last_receipt"]["expired_at_generation"] is None


def test_out_of_range_value_refuses_generation(monkeypatch):
    snaps = {"recent_incidents_snapshot": (None, None)}
    row = {"technique_ids": ["T1046"], "explanation": {"fast_assistance": {"full_node_context": {
        "full_node_context_status": "bogus", "outcome": "unknown"}}}}
    with pytest.raises(handoff.HandoffRefused):
        handoff._full_node_context(row, snaps, NOW)
    row["explanation"]["fast_assistance"]["full_node_context"] = {"full_node_context_status": "received", "outcome": "complete"}
    row["full_node_trace"] = _trace("queried", None, _receipt(["T1046"], limitations=["producer prose"]))
    with pytest.raises(handoff.HandoffRefused):
        handoff._full_node_context(row, snaps, NOW)


@pytest.mark.parametrize("key,value", [
    ("source_kind", "other"), ("claim_status", "verified"), ("trust", "trusted"),
    ("snapshot_state", "stale"), ("outcome", "rejected"), ("outcome", "unavailable"),
    ("source_kind", 5), ("trust", None)])
def test_receipt_values_outside_the_fixed_ranges_refuse(key, value):
    ids = ["T1046"]
    node = {"full_node_context_status": "received", "outcome": "complete", "limitations": []}
    row = {"technique_ids": ids, "explanation": {"fast_assistance": {"full_node_context": node}},
           "full_node_trace": _trace("queried", None, _receipt(ids, **{key: value}))}
    with pytest.raises(handoff.HandoffRefused):
        handoff._full_node_context(row, {"recent_incidents_snapshot": (None, None)}, NOW)


def test_current_limitations_outside_the_fixed_texts_refuse_instead_of_dropping():
    node = {"full_node_context_status": "received", "outcome": "complete",
            "limitations": [FULL_NODE_LIMITATIONS[0], "producer prose"]}
    row = {"technique_ids": ["T1046"], "explanation": {"fast_assistance": {"full_node_context": node}}}
    with pytest.raises(handoff.HandoffRefused):
        handoff._full_node_context(row, {"recent_incidents_snapshot": (None, None)}, NOW)


def test_hidden_strings_and_internal_values_absent(tmp_path, monkeypatch):
    def tweak(row):
        row["explanation"]["fast_assistance"]["unknowns"] = ["SYNTH-SUBJECT-MARK request_id"]
    root = _with_trace(tmp_path, "g", lambda ids: _trace("not_explained", None, _receipt(ids)), tweak=tweak)
    files = _files(root, "ui", monkeypatch)
    for name, data in files.items():
        text = data.decode()
        assert "SYNTH-SUBJECT-MARK" not in text and "observed_sequence" not in text, name
        for mark in UI_HIDDEN:
            assert mark not in text, (name, mark)
    md = files["handoff.ja.md"].decode()
    for heading in ("今回の遷移", "最後の照会", "最後に受け取った参照"):
        assert heading in md
    manifest = json.loads(files["manifest.json"])
    assert {f["name"] for f in manifest["files"]} == {"handoff.json", "handoff.ja.md"}


@pytest.mark.parametrize("principal", ["root", "operator"])
def test_trace_does_not_change_root_or_operator_bytes(tmp_path, principal):
    base = _files(_root(tmp_path, "h", {**BASE, "full_node_context": FULL}), principal)
    with_trace = _files(_with_trace(tmp_path, "i", lambda ids: _trace(
        "queried", {"attempted_at": "2026-10-29T03:15:31Z", "result": "received", "technique_ids": ids},
        _receipt(ids))), principal)
    assert with_trace == base
    assert {k: hashlib.sha256(v).hexdigest() for k, v in with_trace.items()} == GOLDEN_FULL_ROW[principal]
