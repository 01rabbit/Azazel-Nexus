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


# ---- U51 B: the technique answer is its own axis in the handoff and the UI ----
# These build the row through the product reader (`read_recent_incidents` runs on the
# stored file) and the product `handoff.build_package`; the technique record comes from
# the real projector. Nothing here bypasses a reader; the stored row is a fixed file.

def _tk_record():
    from _technique_fixture import make_response
    from azazel_nexus.technique_knowledge import project_technique_response
    return project_technique_response(make_response(["T1110"]), ["T1110"])


def _tk_fast(record):
    from azazel_nexus.incident_explain import _full_node_projection
    return {**BASE, "full_node_context": _full_node_projection(
        None, "unavailable", "unavailable", technique_knowledge=record)}


def _tk_md(tmp_path, monkeypatch, name, now, trace):
    root = _with_trace(tmp_path, name, trace, fast=_tk_fast(_tk_record()))
    monkeypatch.setenv("AZAZEL_ROOT", str(root))
    pkg = handoff.build_package(example.INCIDENT, now=now, principal="ui", root=None)
    return pkg["knowledge"]["full_node_context"], handoff.encode_files(pkg)["handoff.ja.md"].decode()


def test_fabric_unavailable_is_not_read_as_a_failed_technique_query(tmp_path, monkeypatch):
    # The stored trace says "unavailable" (Fabric path only) while the ATT&CK query succeeded.
    attempt = lambda ids: _trace("queried", {"attempted_at": "2026-10-29T03:15:31Z",
                                             "result": "unavailable", "technique_ids": ids})
    fn, md = _tk_md(tmp_path, monkeypatch, "tk", NOW, attempt)
    assert fn["last_attempt"]["result"] == "unavailable"                 # stored value is untouched
    assert fn["technique_knowledge"]["transport"] == "received"
    assert fn["technique_knowledge"]["verification"] == "ok"
    assert "Fabric 助言の照会状態（ATT&CK 照会とは別）: `unavailable`" in md
    assert "最後の照会（Fabric 助言の経路のみ" in md
    assert "通信: `received`、検証: `ok`" in md
    assert "MIO が活用" not in md and "M.I.O. が活用" not in md
    assert "期限切れ" not in md.split("未検証の ATT&CK ラベル")[1].split("対応")[0]


def test_technique_expiry_is_judged_at_generation_time(tmp_path, monkeypatch):
    record = _tk_record()
    later = handoff._epoch(record["expires_at"]) + 60 if hasattr(handoff, "_epoch") else None
    if later is None:
        from datetime import datetime
        later = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00")).timestamp() + 60
    _, md = _tk_md(tmp_path, monkeypatch, "tk2", later, None)
    assert "（この資料の生成時点で期限切れ）" in md


def test_an_old_row_without_a_technique_record_reads_as_before(tmp_path, monkeypatch):
    fn, pkg = _fn(tmp_path, monkeypatch, "old", lambda ids: _trace(
        "queried", {"attempted_at": "2026-10-29T03:15:31Z", "result": "unavailable", "technique_ids": ids}))
    md = handoff.encode_files(pkg)["handoff.ja.md"].decode()
    assert "technique_knowledge" not in fn and "未検証の ATT&CK ラベル" not in md
    assert fn["last_attempt"]["result"] == "unavailable" and fn["last_receipt"] is None


def _lapse_line(md):
    return [l for l in md.split("未検証の ATT&CK ラベル")[1].splitlines() if l.startswith("- 基準時刻")][0]


def test_technique_expiry_boundary_is_never_shown_valid_after_it_lapsed(tmp_path, monkeypatch):
    expires = handoff._epoch(_tk_record()["expires_at"])
    for i, (now, lapsed) in enumerate([(expires - 1, False), (expires, True), (expires + 0.9, True)]):
        _, md = _tk_md(tmp_path, monkeypatch, f"tkb{i}", now, None)
        assert ("（この資料の生成時点で期限切れ）" in _lapse_line(md)) is lapsed, (now, lapsed)


def test_fractional_expiry_is_compared_as_time_not_text(tmp_path, monkeypatch):
    # judged_at is whole seconds; "...:00Z" >= "...:00.5Z" is False as text. Compared as
    # time with the expiry floored, an answer lapsing within the judged second is shown lapsed.
    root = _with_trace(tmp_path, "tkf", None, fast=_tk_fast(_tk_record()))
    monkeypatch.setenv("AZAZEL_ROOT", str(root))
    expires = handoff._epoch(_tk_record()["expires_at"])
    pkg = handoff.build_package(example.INCIDENT, now=expires - 5, principal="ui", root=None)
    tk = pkg["knowledge"]["full_node_context"]["technique_knowledge"]
    judged = pkg["knowledge"]["full_node_context"]["basis"]["judged_at"]
    tk["expires_at"] = judged[:-1] + ".5Z"
    assert "（この資料の生成時点で期限切れ）" in _lapse_line(handoff.encode_files(pkg)["handoff.ja.md"].decode())
    tk["expires_at"] = "not-a-time"
    assert "（期限を判定できません）" in _lapse_line(handoff.encode_files(pkg)["handoff.ja.md"].decode())


# ---- every official ATT&CK 20.1 name goes through the product handoff ----

def _official():
    path = __import__("pathlib").Path(__file__).parents[1] / "fixtures/attack-enterprise-20.1-extract.json"
    return json.loads(path.read_text())["techniques"]


def _md_for(tmp_path, monkeypatch, tag, tid, name, tactic):
    from _technique_fixture import make_response
    from azazel_nexus.incident_explain import _full_node_projection
    from azazel_nexus.technique_knowledge import project_technique_response
    resp = make_response([tid], content={tid: (name, tactic, "20.1")}, version="20.1")
    record = project_technique_response(resp, [tid])
    fast = {**BASE, "full_node_context": _full_node_projection(
        None, "unavailable", "unavailable", technique_knowledge=record)}
    root = _with_trace(tmp_path, tag, None, fast=fast)
    monkeypatch.setenv("AZAZEL_ROOT", str(root))
    pkg = handoff.build_package(example.INCIDENT, now=NOW, principal="ui", root=None)
    return record, pkg, handoff.encode_files(pkg)


def test_a_name_with_a_slash_is_shown_by_the_product_handoff(tmp_path, monkeypatch):
    record, pkg, files = _md_for(tmp_path, monkeypatch, "slash", "T1033", "System Owner/User Discovery", "discovery")
    md = files["handoff.ja.md"].decode()
    row = pkg["knowledge"]["full_node_context"]["technique_knowledge"]["techniques"][0]
    # The scanner is not relaxed: a name it would refuse is withheld, never shown or rejected whole.
    assert row["name"] is None and row["name_withheld"] is True and row["useful_content"] is True
    assert "System Owner" not in md and "名称は表示を控えました" in md
    assert "「該当知識なし」ではありません" in md and "対応 `found`、内容あり `True`" in md
    assert "T1033" in md and "未検証" in md
    assert "出典: " in md and "knowledge:attack-stix" in md


def test_all_official_20_1_names_pass_through_the_handoff(tmp_path, monkeypatch):
    bad = []
    for i, t in enumerate(_official()):
        try:
            _md_for(tmp_path, monkeypatch, f"o{i}", t["id"], t["name"], (t["tactics"] or ["discovery"])[0])
        except Exception as exc:  # noqa: BLE001 - collect, then assert
            bad.append((t["id"], t["name"], type(exc).__name__, str(exc)[:60]))
    assert not bad, bad[:20]
    # names that pass the scanner are still shown (only the refused ones are withheld)
    _, pkg, files = _md_for(tmp_path, monkeypatch, "plain", "T1110", "Brute Force", "credential-access")
    assert "Brute Force" in files["handoff.ja.md"].decode()


def test_a_withheld_name_does_not_take_a_safe_neighbour_with_it(tmp_path, monkeypatch):
    # Same package: one name the scanner refuses, one it accepts; a private path elsewhere is still refused.
    from _technique_fixture import make_response
    from azazel_nexus.incident_explain import _full_node_projection
    from azazel_nexus.technique_knowledge import project_technique_response
    ids = ["T1033", "T1110"]
    resp = make_response(ids, content={"T1033": ("System Owner/User Discovery", "discovery", "20.1"),
                                       "T1110": ("Brute Force", "credential-access", "20.1")}, version="20.1")
    record = project_technique_response(resp, ids)
    fast = {**BASE, "full_node_context": _full_node_projection(None, "unavailable", "unavailable",
                                                               technique_knowledge=record)}
    root = _with_trace(tmp_path, "nb", None, fast=fast)
    monkeypatch.setenv("AZAZEL_ROOT", str(root))
    pkg = handoff.build_package(example.INCIDENT, now=NOW, principal="ui", root=None)
    rows = {r["technique_id"]: r for r in pkg["knowledge"]["full_node_context"]["technique_knowledge"]["techniques"]}
    assert rows["T1033"]["name"] is None and rows["T1110"]["name"] == "Brute Force"
    md = handoff.encode_files(pkg)["handoff.ja.md"].decode()
    assert "Brute Force" in md
    # the exemption is for the technique name only: a private path in another field is still refused
    pkg["knowledge"]["full_node_context"]["technique_knowledge"]["provenance"] = {"x": "/home/someone/secret"}
    with pytest.raises(handoff.HandoffRefused):
        handoff.encode_files(pkg)
