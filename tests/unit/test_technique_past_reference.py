"""DESIGN-D53 v2: the ATT&CK technique answer kept as a past reference.

Rows come from the product daemon path (`Explainer`, the real `build_recent_incident`,
`_settle_row`, `_close_full_node`, `_shrink_to_fit`); the views come from the product
`status_view._recent_extra` and `handoff.build_package`. Nothing here replaces a product
function.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from azazel_nexus import handoff, technique_past_reference as past
from azazel_nexus.audit import AuditLedger
from azazel_nexus.incident_explain import (
    RECENT_BYTES, build_recent_incidents, read_recent_incidents,
)
from azazel_nexus.technique_knowledge import not_run_projection, project_technique_response
from azazel_nexus_runtime import incident_explaind as daemon

from _technique_fixture import make_response
from test_full_node_observation import Rig, _real_mio_like, _technique_record, tx
from test_full_node_trace import _checkpoint, row_with, trace as trace_value
from test_handoff_full_context_ui import _with_trace, example
from test_handoff_full_context_row import BASE
from test_incident_explaind import make

NOW = 1_800_000_000.0
KEY = "technique_past_reference"
A_IDS = ("T1059", "T1059.001")
B_IDS = ("T1059", "T1110")


def ids_of(frame):
    return sorted({c["text"] for c in frame["context"] if c["kind"] == "technique"})


def answering(tmp_path, failing=()):
    """An observation rule that answers every technique query with a verified record."""
    def observed(frame):
        ids = tuple(ids_of(frame))
        record = not_run_projection("received", "failed") if ids in failing else _technique_record(ids)
        return _real_mio_like(record)
    return Rig(tmp_path, observed=observed)


@pytest.fixture
def rig(tmp_path):
    return answering(tmp_path)


def view(row, now=NOW, state=None):
    return past.view(row[KEY], state or row["state"], now)


def recent_value(rows, written_at=NOW):
    return build_recent_incidents(copy.deepcopy(rows), written_at)


def ui_row(rows, now=NOW):
    """The product status projection (reader=ui) of the first row."""
    from azazel_nexus.status_view import _recent_extra
    snapshot = {}
    _recent_extra(recent_value(rows), snapshot, now, reader="ui")
    return snapshot["incidents"][0]


# ---- capture on the daemon path ---------------------------------------------------

def test_right_after_receipt_there_is_no_past_reference(rig):
    rig.step(tx())
    assert rig.current()["technique_knowledge"]["verification"] == "ok"
    assert KEY not in rig.row
    assert KEY not in ui_row(rig.e.recent)


def test_an_update_with_the_same_techniques_makes_the_answer_a_past_reference(rig):
    rig.step(tx(ids=A_IDS))
    first = copy.deepcopy(rig.current()["technique_knowledge"])
    attempted = rig.trace["last_attempt"]["attempted_at"]
    calls = len(rig.calls)
    rig.step(tx("updated", 3, ids=A_IDS, count=2), minute=1)
    assert len(rig.calls) == calls                                       # the same pair is not asked again
    ref = rig.row[KEY]
    assert ref["state"] == "retained" and ref["record"] == first
    assert ref["binding"] == {"incident_id": rig.row["incident_id"], "observed_sequence": 1,
                              "technique_ids": list(A_IDS), "attempted_at": attempted}
    assert "superseded_by" not in ref and "transition" not in ref["binding"]
    # the current projection no longer carries the answer, and the past one does not become it
    assert rig.current()["full_node_context_status"] == "not_queried"
    assert "technique_knowledge" not in rig.current()
    v = view(rig.row)
    assert (v["kind"], v["adoption"], v["adoption_reason"]) == ("past_before_update", "not_adoptable", "past_observation")
    assert v["revocation"] == "not_checked" and v["freshness"] == "expired"


def test_a_close_makes_a_closed_incident_past_reference(rig):
    rig.step(tx(ids=A_IDS))
    rig.step(tx("closed", 3, ids=A_IDS, count=1), minute=1)
    assert rig.row["state"] == "closed"
    v = view(rig.row)
    assert v["kind"] == "past_closed" and v["adoption_reason"] == "closed_incident"
    assert v["adoption"] == "not_adoptable"
    assert rig.row["full_node_trace"]["last_receipt"] is None            # the trace is unchanged


def test_a_new_answer_replaces_the_past_one_and_the_old_one_is_never_adopted_again(rig):
    rig.step(tx(ids=A_IDS))
    rig.step(tx("updated", 1, ids=B_IDS, count=2), minute=1)             # escalation: asks for B (sequence 2)
    assert rig.current()["technique_knowledge"]["techniques"][1]["technique_id"] == "T1110"
    assert rig.row[KEY]["binding"]["observed_sequence"] == 1 and rig.row[KEY]["binding"]["technique_ids"] == list(A_IDS)
    answer_b = copy.deepcopy(rig.current()["technique_knowledge"])
    rig.step(tx("updated", 1, ids=B_IDS, count=3), minute=2)             # repeat: B leaves the current projection
    ref = rig.row[KEY]
    assert ref["binding"]["observed_sequence"] == 2 and ref["record"] == answer_b
    assert "technique_knowledge" not in rig.current()                    # nothing is re-adopted
    # one reference per incident, never a history
    assert json.dumps(rig.row).count('"technique_ids":') >= 1 and sum(1 for k in rig.row if k == KEY) == 1


def test_a_failed_attempt_does_not_replace_a_verified_past_reference(tmp_path):
    rig = answering(tmp_path, failing={B_IDS})
    rig.step(tx(ids=A_IDS))
    rig.step(tx("updated", 3, ids=A_IDS, count=2), minute=1)
    kept = copy.deepcopy(rig.row[KEY])
    rig.step(tx("updated", 1, ids=B_IDS, count=3), minute=2)             # failed record is current
    assert rig.current()["technique_knowledge"]["verification"] == "failed"
    rig.step(tx("closed", 3, ids=B_IDS, count=3), minute=3)
    assert rig.row[KEY] == kept


def test_a_late_explanation_becomes_a_newer_past_reference_from_its_own_arguments(rig):
    rig.step(tx(ids=A_IDS))                                              # sequence 1, answer A current
    append_all(rig, tx("updated", 1, ids=B_IDS, count=2))                # escalation, sequence 2
    append_all(rig, tx("updated", 1, ids=B_IDS, count=3))                # ordinary, sequence 3
    assert rig.row[KEY]["binding"]["observed_sequence"] == 1             # A was moved when seq 2 arrived
    rig.e.monotonic = lambda: 61
    rig.e.poll()                                                         # explains sequence 2 late
    ref = rig.row[KEY]
    assert ref["binding"]["observed_sequence"] == 2
    assert ref["binding"]["technique_ids"] == list(B_IDS)
    assert ref["binding"]["attempted_at"] == rig.trace["last_attempt"]["attempted_at"]
    assert ref["record"]["techniques"][1]["technique_id"] == "T1110"
    assert "technique_knowledge" not in rig.current()                    # never shown as current


def append_all(rig, t):
    from test_incident_explaind import append
    append(rig.e, t)
    rig.e.ingest()


def test_reset_captures_before_it_removes(rig):
    rig.step(tx(ids=A_IDS))
    record = copy.deepcopy(rig.current()["technique_knowledge"])
    AuditLedger(rig.e.incidents / "1970-01-01.jsonl").append(
        {"event_type": "edge.incident.reset", "at": 0, "reason": "intake_started"})
    rig.e.ingest()
    assert rig.row["state"] == "closed" and rig.current()["full_node_context_status"] == "not_queried"
    assert rig.row[KEY]["record"] == record and view(rig.row)["kind"] == "past_closed"


def test_the_merge_rule_is_by_sequence_and_a_missing_binding_never_hides_an_answer():
    def cand(seq, ids=("T1059", "T1059.001")):
        row = {"incident_id": "inc-" + "a" * 16,
               "explanation": {"fast_assistance": {"full_node_context": {"technique_knowledge": _technique_record(ids)}}},
               "full_node_trace": {"transition_query": "queried", "observed_sequence": seq,
                                   "last_attempt": {"attempted_at": "2026-11-16T00:00:00Z", "result": "unavailable",
                                                    "technique_ids": list(ids)},
                                   "last_receipt": None}}
        return past.capture_from_row(row)

    one = past.merge(None, cand(5))
    assert one["binding"]["observed_sequence"] == 5
    assert past.merge(one, cand(4)) is one and past.merge(one, cand(5)) is one       # older and equal stay
    assert past.merge(one, cand(6))["binding"]["observed_sequence"] == 6
    assert past.merge(one, None) is one
    # a candidate whose binding cannot be made: stub when nothing is held, nothing when something is
    broken = cand(5)
    row = {"incident_id": "inc-" + "a" * 16,
           "explanation": {"fast_assistance": {"full_node_context": {"technique_knowledge": _technique_record()}}},
           "full_node_trace": {"transition_query": "not_explained", "observed_sequence": 3,
                               "last_attempt": None, "last_receipt": None}}
    lost = past.capture_from_row(row)
    assert lost == ("stub", {"version": past.VERSION, "state": "binding_missing"})
    assert past.merge(None, lost)["state"] == "binding_missing" and past.merge(one, lost) is one
    # a failed or unavailable record is never a candidate
    row["explanation"]["fast_assistance"]["full_node_context"]["technique_knowledge"] = not_run_projection("received", "failed")
    assert past.capture_from_row(row) is None and broken[0] == "retained"


# ---- restart ------------------------------------------------------------------------

def test_a_checkpoint_keeps_the_past_reference(rig, tmp_path):
    rig.step(tx(ids=A_IDS))
    rig.step(tx("updated", 3, ids=A_IDS, count=2), minute=1)
    before = json.loads(json.dumps(rig.e.recent))
    again = make(tmp_path, mio=lambda _: None, observation_rule=lambda: None)
    assert again.recent == before and again.recent[0][KEY]["state"] == "retained"
    assert view(again.recent[0]) == view(before[0])


# ---- size and shrink order ----------------------------------------------------------

def _worst_record():
    ids = [f"T10{n:02d}" for n in range(1, 9)]
    name = "\U0001d400" * 120                                              # letters outside the BMP: 12 bytes each, escaped
    tactics = ("collection,command-and-control,credential-access,defense-evasion,defense-impairment,"
               "discovery,execution,exfiltration,impact,initial-access,lateral-movement,persistence,"
               "privilege-escalation,reconnaissance,resource-development,stealth")
    response = make_response(ids, content={i: (name, tactics, "20.1") for i in ids}, version="20.1")
    return ids, project_technique_response(response, ids)


def _prior(incident_id, seq, ids, record):
    return {"incident_id": incident_id,
            "explanation": {"fast_assistance": {"full_node_context": {"technique_knowledge": record}}},
            "full_node_trace": {"transition_query": "queried", "observed_sequence": seq,
                                "last_attempt": {"attempted_at": "2026-11-16T00:00:00Z", "result": "unavailable",
                                                 "technique_ids": ids},
                                "last_receipt": None}}


def _window(tmp_path, states, pending_oldest=False):
    """A daemon whose 20-row window carries one worst-case past reference per row."""
    ids, record = _worst_record()
    e = make(tmp_path)
    rows = []
    for n, state in enumerate(states):
        row = row_with(trace_value(transition_query="not_explained", last_attempt=None, last_receipt=None))
        row["incident_id"] = f"inc-{n + 1:016x}"
        row["first_seen"] = row["last_seen"] = 1000 + n
        row["state"] = state
        row[KEY] = past.merge(None, past.capture_from_row(_prior(row["incident_id"], 1, ids, record)))
        rows.append(row)
    if pending_oldest:
        rows[0]["explanation"] = {"state": "pending", "route": "unavailable", "outcome": "unavailable",
                                  "summary": "", "knowledge_refs": [], "failure_codes": []}
    return e, rows, ids


def test_the_worst_case_exceeds_the_bound_and_the_daemon_still_keeps_it(tmp_path):
    states = ["open"] + ["closed"] * 9 + ["open"] * 10
    e, rows, _ = _window(tmp_path, states)
    sized = len(json.dumps(rows[0][KEY]))
    assert 15000 < sized < 16000 and sized * 20 > RECENT_BYTES            # 15,741 B each: 314,820 B for twenty
    e.recent = rows
    e._keep_window(None, now=NOW)
    value = build_recent_incidents(e._public_rows(), NOW)
    assert len(json.dumps(value).encode()) <= RECENT_BYTES
    assert e.refused["status_write_failed"] >= 1


def test_shrink_order_is_closed_oldest_first_then_open_oldest_first_and_explanations_are_untouched(tmp_path):
    states = ["open"] + ["closed"] * 9 + ["open"] * 10                      # the oldest row is open
    e, rows, _ = _window(tmp_path, states)
    explanations = {r["incident_id"]: json.dumps(r["explanation"], sort_keys=True) for r in rows}
    e.recent = rows
    e._keep_window(None, now=NOW)
    by_age = sorted(e.recent, key=lambda r: (r["last_seen"], r["first_seen"], r["incident_id"]))
    stubbed = [r for r in by_age if r[KEY]["state"] == "size_dropped"]
    kept = [r for r in by_age if r[KEY]["state"] == "retained"]
    assert stubbed and kept
    assert all(r["state"] == "closed" for r in stubbed) or all(r["state"] == "closed" for r in by_age if r[KEY]["state"] == "size_dropped")
    closed_old_first = [r for r in by_age if r["state"] == "closed"]
    assert [r["incident_id"] for r in stubbed] == [r["incident_id"] for r in closed_old_first[:len(stubbed)]]
    assert by_age[0]["state"] == "open" and by_age[0][KEY]["state"] == "retained"       # open rows come after closed ones
    assert all(json.dumps(r["explanation"], sort_keys=True) == explanations[r["incident_id"]] for r in e.recent)
    assert all(r["full_node_trace"] == next(x for x in rows if x["incident_id"] == r["incident_id"])["full_node_trace"] for r in e.recent)
    assert set(stubbed[0][KEY]) == {"version", "state"}


def test_open_rows_follow_once_the_closed_ones_are_gone_and_pending_rows_lose_only_their_reference(tmp_path):
    e, rows, _ = _window(tmp_path, ["open"] * 20, pending_oldest=True)
    e.recent = rows
    e._keep_window(None, now=NOW)
    by_age = sorted(e.recent, key=lambda r: (r["last_seen"], r["first_seen"], r["incident_id"]))
    stubbed = [r for r in by_age if r[KEY]["state"] == "size_dropped"]
    assert stubbed and by_age[0][KEY]["state"] == "size_dropped"            # the oldest, a pending row, is stubbed first
    assert by_age[0]["explanation"]["state"] == "pending"                   # its explanation is not reduced
    assert [r["incident_id"] for r in stubbed] == [r["incident_id"] for r in by_age[:len(stubbed)]]


def test_a_window_that_needs_no_shrink_keeps_every_reference(tmp_path):
    ids = ["T1059", "T1059.001"]
    e = make(tmp_path)
    rows = []
    for n in range(3):
        row = row_with(trace_value(transition_query="not_explained", last_attempt=None, last_receipt=None))
        row["incident_id"] = f"inc-{n + 1:016x}"
        row["first_seen"] = row["last_seen"] = 1000 + n
        row[KEY] = past.merge(None, past.capture_from_row(_prior(row["incident_id"], 1, ids, _technique_record())))
        rows.append(row)
    e.recent = rows
    e._keep_window(None, now=NOW)
    assert all(r[KEY]["state"] == "retained" for r in e.recent)


# ---- the strict reader --------------------------------------------------------------

def _stored(rig):
    rig.step(tx(ids=A_IDS))
    rig.step(tx("updated", 3, ids=A_IDS, count=2), minute=1)
    return json.loads(json.dumps(rig.e.recent[0]))


def _reads(row):
    return read_recent_incidents(json.dumps({"schema": "azazel-nexus/recent-incidents/v1", "written_at": NOW,
                                             "incidents": [row]}).encode()) is not None


def test_the_reader_accepts_the_stored_row_and_refuses_every_binding_that_does_not_match(rig):
    row = _stored(rig)
    assert _reads(row)
    cases = {
        "incident": lambda r: r[KEY]["binding"].update(incident_id="inc-" + "f" * 16),
        "ids": lambda r: r[KEY]["binding"].update(technique_ids=["T1110"]),
        "sequence": lambda r: r[KEY]["binding"].update(observed_sequence=2),
        "attempted": lambda r: r[KEY]["binding"].update(attempted_at="2026-11-16T00:00:01Z"),
        "digest": lambda r: r[KEY].update(capture_digest="sha256:" + "0" * 64),
        "record": lambda r: r[KEY]["record"].update(as_of="2026-11-12T00:00:01Z"),
        "transition": lambda r: r[KEY]["binding"].update(transition="updated"),
        "superseded_by": lambda r: r[KEY].update(superseded_by={"event": "closed"}),
        "missing_binding": lambda r: r[KEY].pop("binding"),
        "version": lambda r: r[KEY].update(version="technique-past-reference/2"),
        "state": lambda r: r[KEY].update(state="current"),
        "failed_record": lambda r: r[KEY].update(record=not_run_projection("received", "failed")),
    }
    for name, damage in cases.items():
        broken = copy.deepcopy(row)
        damage(broken)
        assert not _reads(broken), name


def test_stubs_are_closed_and_carry_nothing_else(rig):
    row = _stored(rig)
    for state in ("binding_missing", "size_dropped"):
        stub = copy.deepcopy(row)
        stub[KEY] = {"version": past.VERSION, "state": state}
        assert _reads(stub)
        for extra in ({"record": {}}, {"binding": {}}, {"capture_digest": "x"}):
            bad = copy.deepcopy(stub)
            bad[KEY].update(extra)
            assert not _reads(bad)
    bad = copy.deepcopy(row)
    bad[KEY] = {"version": past.VERSION, "state": "gone"}
    assert not _reads(bad)


def test_old_rows_without_the_key_still_read_and_show_nothing(rig):
    rig.step(tx(ids=A_IDS))
    row = json.loads(json.dumps(rig.e.recent[0]))
    assert KEY not in row and _reads(row)
    assert KEY not in ui_row([row])


# ---- API (status view) ---------------------------------------------------------------

def test_the_status_view_is_for_the_ui_reader_only_and_derives_its_words(rig):
    from azazel_nexus.status_view import _recent_extra
    rig.step(tx(ids=A_IDS))
    rig.step(tx("updated", 3, ids=A_IDS, count=2), minute=1)
    expires = datetime_epoch(rig.row[KEY]["record"]["expires_at"])
    for now, fresh in ((expires - 5, "fresh"), (expires, "expired"), (expires + 1, "expired")):
        api = ui_row(rig.e.recent, now)[KEY]
        assert api["freshness"] == fresh and api["adoption"] == "not_adoptable"
        assert api["revocation"] == "not_checked" and api["retained"] is True
        assert api["technique_knowledge"] == rig.row[KEY]["record"]
        assert api["binding"] == rig.row[KEY]["binding"]
    assert ui_row(rig.e.recent, None)[KEY]["freshness"] == "unjudgeable"
    for reader in ("operator", "root"):
        snapshot = {}
        _recent_extra(recent_value(rig.e.recent), snapshot, NOW, reader=reader)
        assert KEY not in snapshot["incidents"][0]


def datetime_epoch(text):
    from datetime import datetime
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def test_stub_projection_never_looks_like_an_answer(rig):
    row = _stored(rig)
    for state in ("binding_missing", "size_dropped"):
        row[KEY] = {"version": past.VERSION, "state": state}
        api = ui_row([row])[KEY]
        assert api == {"kind": "past_unavailable", "state": state, "retained": False, "adoption": "not_adoptable",
                       "adoption_reason": state, "freshness": None, "revocation": "not_checked"}


# ---- handoff (JSON and Markdown) ------------------------------------------------------

def _ui_package(tmp_path, monkeypatch, name, past_value, state="open", now=None, record=None):
    def tweak(row):
        row["state"] = state
        if past_value is not None:
            row[KEY] = past_value(row["incident_id"]) if callable(past_value) else past_value
    root = _with_trace(tmp_path, name, None, fast=BASE, tweak=tweak)
    monkeypatch.setenv("AZAZEL_ROOT", str(root))
    pkg = handoff.build_package(example.INCIDENT, now=now or example.GENERATED, principal="ui", root=None)
    return root, pkg, handoff.encode_files(pkg)["handoff.ja.md"].decode()


def _made(record=None, ids=None):
    record = record or _technique_record(("T1110",))
    ids = ids or [t["technique_id"] for t in record["techniques"]]
    return lambda incident_id: past.merge(None, past.capture_from_row(_prior(incident_id, 7, ids, record)))


def test_json_api_and_markdown_correspond(tmp_path, monkeypatch):
    record = _technique_record(("T1110",))
    root, pkg, md = _ui_package(tmp_path, monkeypatch, "h1", _made(record), now=datetime_epoch(record["as_of"]) + 1)
    fn = pkg["knowledge"]["full_node_context"]
    j = fn[KEY]
    assert j["kind"] == "past_before_update" and j["adoption"] == "not_adoptable" and j["freshness"] == "fresh"
    assert j["adoption_reason"] == "past_observation" and j["revocation"] == "not_checked"
    stored = json.loads((root / "var/lib/azazel/run/incident-explain-status/recent.json").read_text())["incidents"][0]
    api = ui_row([stored], datetime_epoch(record["as_of"]) + 1)[KEY]
    assert j == api                                                       # the same derived value, API and handoff JSON
    for needle in ("更新前の観測に対する過去参照", "現在の判断への採用: 不可", "この回答は現在より前の観測に対するものです",
                   "過去の参照を保持しています。今回の照会結果ではありません。", "期限内（取得時点の期限に基づく参考",
                   "台帳の遷移番号 #7、技術 T1110", "判定時刻 ", "照会時刻 " + j["binding"]["attempted_at"] + "（受領時刻ではありません）",
                   "knowledge:attack-stix", "knowledge:attack-coverage", "このリファレンスでは取消の有無を確認していません",
                   "ATT&CK の知識があることは、その事象が起きたことや原因を示しません",
                   "直近 20 件の窓から外れた incident の過去参照は残りません", "T1110", "対応 `found`"):
        assert needle in md, needle
    assert "取消されていません" not in md
    assert j["judged_at"] in md


def test_expired_closed_and_unjudgeable_words_in_the_handoff(tmp_path, monkeypatch):
    record = _technique_record(("T1110",))
    late = datetime_epoch(record["expires_at"]) + 10
    _, pkg, md = _ui_package(tmp_path, monkeypatch, "h2", _made(record), state="closed", now=late)
    j = pkg["knowledge"]["full_node_context"][KEY]
    assert j["kind"] == "past_closed" and j["freshness"] == "expired" and j["adoption"] == "not_adoptable"
    assert "終了済みインシデントの過去参照" in md and "期限切れ：現在の判断には使用できません" in md
    assert "期限内" not in md
    assert past.view(_made(record)("inc-" + "0" * 16), "open", float("nan"))["freshness"] == "unjudgeable"


@pytest.mark.parametrize("state,sentence", [
    ("binding_missing", "対応する観測との結び付きが記録されていないため、過去の参照は保持していません。"),
    ("size_dropped", "容量の上限のため、過去の参照は保持していません。")])
def test_stubs_in_the_handoff_say_only_that_nothing_is_kept(tmp_path, monkeypatch, state, sentence):
    _, pkg, md = _ui_package(tmp_path, monkeypatch, "s" + state, {"version": past.VERSION, "state": state})
    j = pkg["knowledge"]["full_node_context"][KEY]
    assert j == {"kind": "past_unavailable", "state": state, "retained": False, "adoption": "not_adoptable",
                 "adoption_reason": state, "freshness": None, "revocation": "not_checked"}
    section = md.split("ATT&CK ラベルの過去参照")[1].split("## 9.")[0]
    bullets = [l for l in section.splitlines() if l.startswith("- ")]
    assert bullets == ["- " + sentence + "今回の照会結果ではありません。現在の判断には使用できません。"]   # one line only
    for forbidden in ("対応 `", "内容あり", "期限の状態", "基準時刻", "出典:", "遷移", "過去の参照を保持しています",
                      "種別", "採用", "取消", "20 件"):
        assert forbidden not in section, forbidden


def test_a_row_without_a_past_reference_reads_as_before(tmp_path, monkeypatch):
    _, pkg, md = _ui_package(tmp_path, monkeypatch, "h0", None)
    assert KEY not in pkg["knowledge"]["full_node_context"] and "ATT&CK ラベルの過去参照" not in md


def test_the_handoff_withholds_a_name_on_a_copy_and_never_writes_it_back(tmp_path, monkeypatch):
    record = project_technique_response(
        make_response(["T1033"], content={"T1033": ("System Owner/User Discovery", "discovery", "20.1")}, version="20.1"),
        ["T1033"])
    assert record["techniques"][0]["name"] == "System Owner/User Discovery"
    root, pkg, md = _ui_package(tmp_path, monkeypatch, "w", _made(record))
    recent = root / "var/lib/azazel/run/incident-explain-status/recent.json"
    before = recent.read_bytes()
    row = pkg["knowledge"]["full_node_context"][KEY]["technique_knowledge"]["techniques"][0]
    assert row["name"] is None and row["name_withheld"] is True and row["useful_content"] is True
    assert "System Owner" not in md and "名称は表示を控えました" in md and "「該当知識なし」ではありません" in md
    handoff.build_package(example.INCIDENT, now=example.GENERATED, principal="ui", root=None)
    assert recent.read_bytes() == before                                   # the stored record is untouched
    stored = json.loads(before)["incidents"][0][KEY]["record"]["techniques"][0]
    assert stored["name"] == "System Owner/User Discovery" and stored["name_withheld"] is False
    # the screen view is not scanned that way: it still shows the stored name
    assert ui_row([json.loads(before)["incidents"][0]])[KEY]["technique_knowledge"]["techniques"][0]["name"] == stored["name"]


def test_a_word_screen_withheld_name_stays_withheld_in_the_past_reference(tmp_path, monkeypatch):
    record = project_technique_response(
        make_response(["T1110"], content={"T1110": ("Block Everything Now", "credential-access", "20.1")}, version="20.1"),
        ["T1110"])
    assert record["techniques"][0]["name"] is None and record["techniques"][0]["name_withheld"] is True
    _, pkg, md = _ui_package(tmp_path, monkeypatch, "ww", _made(record))
    row = pkg["knowledge"]["full_node_context"][KEY]["technique_knowledge"]["techniques"][0]
    assert row["name"] is None and "Block Everything" not in md


def test_other_principals_never_get_the_past_reference(tmp_path, monkeypatch):
    root = _with_trace(tmp_path, "pr", None, fast=BASE, tweak=lambda row: row.update({KEY: _made()(row["incident_id"])}))
    for principal in ("operator", "root"):
        pkg = handoff.build_package(example.INCIDENT, now=example.GENERATED, principal=principal, root=root)
        assert KEY not in json.dumps(pkg) and "過去参照" not in handoff.encode_files(pkg)["handoff.ja.md"].decode()


def test_an_invalid_binding_refuses_the_handoff(tmp_path, monkeypatch):
    def broken(incident_id):
        value = _made()(incident_id)
        value["capture_digest"] = "sha256:" + "1" * 64
        return value
    root = _with_trace(tmp_path, "bad", None, fast=BASE, tweak=lambda row: row.update({KEY: broken(row["incident_id"])}))
    monkeypatch.setenv("AZAZEL_ROOT", str(root))
    recent = root / "var/lib/azazel/run/incident-explain-status/recent.json"
    assert read_recent_incidents(recent.read_bytes()) is None            # the strict reader refuses the snapshot
    with pytest.raises(handoff.HandoffRefused):                           # so no row, and no package, is made
        handoff.build_package(example.INCIDENT, now=example.GENERATED, principal="ui", root=None)


# ---- the screen (static contract of app.js) -----------------------------------------

def test_the_screen_words():
    js = (Path(__file__).parents[2] / "runtime/src/azazel_nexus_runtime/ui_static/app.js").read_text()
    block = js[js.index("function pastReferenceBlock("):js.index("// ATT&CK technique labels (reference only)")]
    for needle in ("更新前の観測に対する過去参照", "終了済みインシデントの過去参照", "現在の観測に対する回答ではありません",
                   "現在の判断への採用", "不可", "この回答は現在より前の観測に対するものです", "このインシデントは終了済みです",
                   "期限切れ：現在の判断には使用できません", "期限を判定できません。現在の判断には使用できません",
                   "過去の参照を保持しています。今回の照会結果ではありません。",
                   "照会時刻（受領時刻ではありません）", "出典", "このリファレンスでは取消の有無を確認していません",
                   "ATT&CK の知識があることは、その事象が起きたことや原因を示しません",
                   "直近 20 件の窓から外れた incident の過去参照は残りません",
                   "対応する観測との結び付きが記録されていないため、過去の参照は保持していません。",
                   "容量の上限のため、過去の参照は保持していません。", "name_withheld"):
        assert needle in block, needle
    assert "innerHTML" not in block and "pastReferenceBlock(row.technique_past_reference)" in js
    assert "台帳の遷移番号" in block and "端末時計" in block
    assert "取消されていません" not in block


# ---- rollback conversions -------------------------------------------------------------

def _row_with_past(n=0):
    row = row_with(trace_value(), origin="observation_rule_v1")
    row["incident_id"] = f"inc-{n + 1:016x}"
    row[KEY] = past.merge(None, past.capture_from_row(_prior(row["incident_id"], 3, ["T1059", "T1059.001"], _technique_record())))
    return row


def _write(tmp_path, rows):
    value, d = _checkpoint(tmp_path, rows)
    path = tmp_path / "cursor.json"
    path.write_bytes(d.canonical(value) + b"\n")
    return path, d


def test_rollback_a_drops_only_the_past_reference_in_one_pass(tmp_path):
    path, d = _write(tmp_path, [_row_with_past()])
    original = path.read_bytes()
    assert d.checkpoint_for_release_before_past_reference(path) == 1
    out = path.read_text()
    assert KEY not in out and "full_node_trace" in out and "query_origin" in out
    assert path.with_name("cursor.json.pre-rollback").read_bytes() == original
    keys = {k for r in json.loads(out)["recent"]["incidents"] for k in r}
    assert keys <= daemon._ROW_KEYS_9FD28B9
    with pytest.raises(ValueError, match="rollback_backup_exists"):
        d.checkpoint_for_release_before_past_reference(path)


def test_rollback_a_resumes_an_interrupted_run_and_refuses_a_broken_checkpoint(tmp_path):
    path, d = _write(tmp_path, [_row_with_past()])
    path.with_name("cursor.json.pre-rollback").write_bytes(path.read_bytes())
    assert d.checkpoint_for_release_before_past_reference(path) == 1
    bad = tmp_path / "bad"
    bad.mkdir()
    broken = bad / "cursor.json"
    broken.write_bytes(b'{"cursor": "broken"}')
    with pytest.raises(ValueError):
        d.checkpoint_for_release_before_past_reference(broken)
    assert not broken.with_name("cursor.json.pre-rollback").exists()


def test_rollback_b_drops_all_four_in_one_pass_with_one_backup(tmp_path):
    row = _row_with_past()
    row["explanation"] = {**row["explanation"]}
    path, d = _write(tmp_path, [row, row_with()])
    original = path.read_bytes()
    assert d.checkpoint_for_release_before_full_node_trace(path) >= 1
    out = path.read_text()
    for gone in (KEY, "full_node_trace", "query_origin"):
        assert gone not in out
    assert path.with_name("cursor.json.pre-rollback").read_bytes() == original
    assert len(list(tmp_path.glob("cursor.json.pre-rollback*"))) == 1


def test_rollback_b_removes_a_current_technique_answer_too(rig, tmp_path):
    rig.step(tx(ids=A_IDS))
    rig.step(tx("updated", 1, ids=B_IDS, count=2), minute=1)
    assert "technique_knowledge" in rig.current() and KEY in rig.row
    rig.e.checkpoint()
    path = tmp_path / "state" / "cursor.json"
    assert b"technique_knowledge" in path.read_bytes()
    daemon.checkpoint_for_release_before_full_node_trace(path)
    out = path.read_text()
    assert KEY not in out and "technique_knowledge" not in out and "full_node_trace" not in out


def test_b_after_a_stops_and_b_alone_on_the_original_works(tmp_path):
    path, d = _write(tmp_path, [_row_with_past()])
    original = path.read_bytes()
    d.checkpoint_for_release_before_past_reference(path)
    converted = path.read_bytes()
    with pytest.raises(ValueError, match="rollback_backup_exists"):
        d.checkpoint_for_release_before_full_node_trace(path)
    assert path.read_bytes() == converted                                   # nothing was written
    backup = path.with_name("cursor.json.pre-rollback")
    assert backup.read_bytes() == original
    backup.replace(path)                                                    # the documented recovery
    d.checkpoint_for_release_before_full_node_trace(path)
    assert KEY not in path.read_text() and backup.read_bytes() == original


def test_a_checkpoint_without_the_new_key_converts_as_before(tmp_path):
    path, d = _write(tmp_path, [row_with(trace_value(), origin="observation_rule_v1")])
    assert d.checkpoint_for_release_before_past_reference(path) == 0
    path2 = tmp_path / "two"
    path2.mkdir()
    p2, d2 = _write(path2, [row_with(trace_value(), origin="observation_rule_v1")])
    assert d2.checkpoint_for_release_before_full_node_trace(p2) == 1


# ---- the current decision path never receives a past reference (spies on the real path) ----

def _spied(tmp_path, monkeypatch):
    rig = answering(tmp_path)
    seen = {"observe": [], "adopt": []}
    original_observe = rig.e._observe_full_node

    def observe(t, frame, sequence, mio):
        seen["observe"].append(json.dumps([t, frame, sequence, mio], sort_keys=True))
        return original_observe(t, frame, sequence, mio)

    original_adopt = daemon.adopt_full_node_reply

    def adopt(advise, observed):
        seen["adopt"].append(json.dumps([advise, observed], sort_keys=True))
        return original_adopt(advise, observed)

    rig.e._observe_full_node = observe                                   # delegating spies: the product runs
    monkeypatch.setattr(daemon, "adopt_full_node_reply", adopt)
    return rig, seen


def test_a_past_reference_never_reaches_observation_adoption_or_the_retention_table(tmp_path, monkeypatch):
    rig, seen = _spied(tmp_path, monkeypatch)
    rig.step(tx(ids=A_IDS))
    rig.step(tx("updated", 3, ids=A_IDS, count=2), minute=1)             # a repeat; a past reference now exists
    assert KEY in rig.row
    ident = rig.row["incident_id"]
    consumed = [tuple(p) for p in rig.e._consumed[ident]]
    queries = len(rig.calls)
    rig.step(tx("updated", 3, ids=A_IDS, count=3), minute=2)             # another repeat with the reference held
    assert len(rig.calls) == queries                                     # no new Full query
    assert [tuple(p) for p in rig.e._consumed[ident]] == consumed        # capture does not touch the table
    assert "technique_knowledge" not in rig.current()
    rig.step(tx("updated", 1, ids=B_IDS, count=4), minute=3)             # a new pair is asked with the reference held
    assert len(rig.calls) == queries + 1
    assert [tuple(p) for p in rig.e._consumed[ident]] == consumed + [("T1059", "T1110")]
    assert seen["observe"]
    for payload in (*seen["observe"], *seen["adopt"], *(json.dumps(f, sort_keys=True) for f in rig.calls + rig.advised)):
        assert KEY not in payload and "capture_digest" not in payload
    assert rig.current()["technique_knowledge"]["techniques"][1]["technique_id"] == "T1110"   # B is a new answer


def test_a_late_explanation_with_a_held_reference_does_not_read_it_either(tmp_path, monkeypatch):
    rig, seen = _spied(tmp_path, monkeypatch)
    rig.step(tx(ids=A_IDS))
    append_all(rig, tx("updated", 1, ids=B_IDS, count=2))
    assert KEY in rig.row
    rig.e.monotonic = lambda: 61
    rig.e.poll()
    assert seen["observe"]
    for payload in (*seen["observe"], *seen["adopt"], *(json.dumps(f, sort_keys=True) for f in rig.calls)):
        assert KEY not in payload and "capture_digest" not in payload


# ---- review findings: an answer the row still shows as current is captured before a late settle ----

def test_a_late_settle_captures_the_answer_the_row_still_shows_as_current(rig):
    from azazel_nexus.incident_explain import pending_entry
    ordinary = ("T1110", "T1566")
    rig.step(tx(ids=A_IDS))                                              # sequence 1: answer A
    append_all(rig, tx("updated", 3, ids=ordinary, count=2))             # sequence 2: not explained yet
    rig.step(tx("updated", 1, ids=B_IDS, count=3), minute=1)             # sequence 3 (escalation): answer B is current
    assert rig.current()["technique_knowledge"]["techniques"][1]["technique_id"] == "T1110"
    answer_b = copy.deepcopy(rig.current()["technique_knowledge"])
    rig.e.explain(pending_entry(tx("updated", 3, ids=ordinary, count=2)), 2)      # sequence 2 is explained late
    assert "technique_knowledge" not in rig.current()                    # the late explanation does not show it
    ref = rig.row[KEY]
    assert ref["binding"]["observed_sequence"] == 3 and ref["binding"]["technique_ids"] == list(B_IDS)
    assert ref["record"] == answer_b                                     # B was not lost; the older answer did not win


# ---- freshness is compared as each layer does ----

def _held(expires):
    record = copy.deepcopy(_technique_record(("T1110",)))
    record["expires_at"] = expires
    binding = {"incident_id": "inc-" + "a" * 16, "observed_sequence": 3, "technique_ids": ["T1110"],
               "attempted_at": "2026-11-16T00:00:00Z"}
    return {"version": past.VERSION, "state": "retained", "binding": binding, "record": record,
            "capture_digest": past.digest(binding, record)}


def test_status_keeps_the_fraction_and_the_handoff_floors():
    value = _held("2026-11-16T00:00:00.900000Z")
    value["record"]["as_of"] = "2026-11-15T00:00:00Z"
    base = datetime_epoch("2026-11-16T00:00:00Z")
    assert past.view(value, "open", base + 0.1)["freshness"] == "fresh"           # .100 against an expiry of .900
    assert past.view(value, "open", base + 0.9)["freshness"] == "expired"
    assert past.view(value, "open", base + 0.1, whole_seconds=True)["freshness"] == "expired"   # the handoff's rule
    assert past.view(value, "open", base - 1, whole_seconds=True)["freshness"] == "fresh"
    assert past.view(value, "open", base + 0.1)["judged_at"] == "2026-11-16T00:00:00Z"
    assert "judged_at" not in past.view({"version": past.VERSION, "state": "size_dropped"}, "open", base)


# ---- design section 11 items 2, 9, 16, 17 ----

def test_an_expired_current_answer_creates_no_past_reference(rig):
    rig.step(tx(ids=A_IDS))
    expires = datetime_epoch(rig.current()["technique_knowledge"]["expires_at"])
    assert KEY not in rig.row and KEY not in ui_row(rig.e.recent, expires + 600)


def test_without_a_checkpoint_a_restart_starts_empty(rig, tmp_path):
    rig.step(tx(ids=A_IDS))
    rig.step(tx("updated", 3, ids=A_IDS, count=2), minute=1)
    assert KEY in rig.row
    (tmp_path / "state" / "cursor.json").unlink()
    again = make(tmp_path, mio=lambda _: None, observation_rule=lambda: None)
    assert all(KEY not in row for row in again.recent)                   # nothing is rebuilt from the ledger


def test_an_incident_leaving_the_window_takes_its_reference_and_leaves_the_ledger(rig):
    from test_incident_explaind import records
    from test_incident_explain import transition
    rig.step(tx(ids=A_IDS))
    rig.step(tx("updated", 3, ids=A_IDS, count=2), minute=1)
    ident = rig.row["incident_id"]
    assert KEY in rig.row
    kept = len(records(rig.e))
    for n in range(20):
        other = transition(3, "opened", incident_id=f"inc-{0xb00 + n:016x}", first_seen=2000 + n, last_seen=2000 + n)
        rig.e.observe_transition(other, sequence=10 + n)
    assert ident not in [r["incident_id"] for r in rig.e.recent] and len(rig.e.recent) == 20
    assert len(records(rig.e)) == kept                                   # the ledger is not touched


def test_revocation_words_of_other_axes_never_enter_the_past_reference(rig):
    row = _stored(rig)
    api = ui_row([row])[KEY]
    assert set(api) == {"kind", "state", "retained", "adoption", "adoption_reason", "freshness", "judged_at",
                        "revocation", "binding", "technique_knowledge"}
    assert api["revocation"] == "not_checked" and "revocation_status" not in json.dumps(api)
    row["explanation"]["fast_assistance"] = {
        "state": "frame_ready", "unknowns": [], "next_checks": [],
        "dependency_outcome": {"knowledge": "available", "deception": "absent"},
        "knowledge": [{"technique_id": "T1110", "name": "Brute Force", "summary": "", "freshness": "current",
                       "as_of": "2026-11-12T00:00:00Z", "citation": "", "revocation_status": "revoked",
                       "claim_status": "reported_unverified"}]}
    assert not _reads(row)                                               # a revoked word is refused, not shown beside it


# ---- the screen, run: pastReferenceBlock on the product's own view ----

def _run_block(views):
    import shutil
    import subprocess
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    js = (Path(__file__).parents[2] / "runtime/src/azazel_nexus_runtime/ui_static/app.js").read_text()
    body = js[js.index("function pastReferenceBlock("):js.index("// ATT&CK technique labels (reference only)")]
    script = """
function el(tag, cls, t) { return { text: t === undefined || t === null ? "" : String(t), kids: [] }; }
function add(parent) { for (var i = 1; i < arguments.length; i++) { if (arguments[i]) { parent.kids.push(arguments[i]); } } return parent; }
function text(v) { return v === null || v === undefined ? "" : String(v); }
function kv(rows) { var n = el("dl"); rows.forEach(function (r) { n.kids.push(el("dt", null, r[0]), el("dd", null, Array.isArray(r[1]) ? r[1].join(", ") : r[1])); }); return n; }
function block(title) { var n = el("section"); n.kids.push(el("h3", null, title)); return n; }
""" + body + """
function flat(n) { return [n.text].concat((n.kids || []).map(flat)).join("\\n"); }
var views = JSON.parse(process.argv[1]);
console.log(JSON.stringify(views.map(function (v) { return flat(pastReferenceBlock(v)); })));
"""
    out = subprocess.run([node, "-e", script, json.dumps(views)], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def test_the_screen_renders_the_product_views(rig):
    row = _stored(rig)
    retained = ui_row([row], NOW)[KEY]
    stubs = []
    for state in ("binding_missing", "size_dropped"):
        row[KEY] = {"version": past.VERSION, "state": state}
        stubs.append(ui_row([row])[KEY])
    shown, *stub_texts = _run_block([retained, *stubs])
    for needle in ("更新前の観測に対する過去参照", "現在の判断への採用", "台帳の遷移番号 #1", "技術 T1059, T1059.001",
                   "期限切れ：現在の判断には使用できません", "端末時計", "照会時刻（受領時刻ではありません）",
                   "knowledge:attack-stix", "このリファレンスでは取消の有無を確認していません", "直近 20 件の窓から外れた"):
        assert needle in shown, needle
    sentences = ("対応する観測との結び付きが記録されていないため、過去の参照は保持していません。",
                 "容量の上限のため、過去の参照は保持していません。")
    for rendered, sentence in zip(stub_texts, sentences):
        assert sentence in rendered and "今回の照会結果ではありません" in rendered
        for forbidden in ("対応あり", "期限", "基準時刻", "出典", "T1059", "取消", "20 件", "採用"):
            assert forbidden not in rendered, forbidden


# ---- a real older checkout reads the converted checkpoint (NEXUS_ROLLBACK_TARGET_SRC method) ----

_OLD_SCRIPT = (
    "import sys; sys.path[:0] = [sys.argv[2] + '/src', sys.argv[2] + '/runtime/src']\n"
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


def _old_run(old, tmp_path):
    import subprocess
    import sys
    return subprocess.run([sys.executable, "-I", "-c", _OLD_SCRIPT, str(tmp_path), str(old)],
                          capture_output=True, text=True).stdout


def _checkpointed_with_a_reference(tmp_path):
    from test_incident_explaind import append
    e = make(tmp_path)
    append(e)
    e.poll()
    row = _row_with_past()
    e.recent = [row]
    e.checkpoint()
    path = tmp_path / "state" / "cursor.json"
    assert KEY.encode() in path.read_bytes()
    return path


@pytest.mark.skipif(not __import__("os").environ.get("NEXUS_ROLLBACK_TARGET_SRC_9FD28B9"),
                    reason="NEXUS_ROLLBACK_TARGET_SRC_9FD28B9 (a 9fd28b9 checkout) not set")
def test_conversion_a_is_read_by_a_real_9fd28b9(tmp_path):
    old = Path(__import__("os").environ["NEXUS_ROLLBACK_TARGET_SRC_9FD28B9"])
    path = _checkpointed_with_a_reference(tmp_path)
    before = _old_run(old, tmp_path)
    assert str(old) in before and "REFUSED" in before and "PREPARE_FAILED" in before     # the old release refuses the key
    assert daemon.checkpoint_for_release_before_past_reference(path) == 1
    after = _old_run(old, tmp_path)
    assert "DECODED True" in after and "PREPARED" in after, after
    assert b"full_node_trace" in path.read_bytes()                       # what 9fd28b9 reads is kept


@pytest.mark.skipif(not __import__("os").environ.get("NEXUS_ROLLBACK_TARGET_SRC"),
                    reason="NEXUS_ROLLBACK_TARGET_SRC (a 74a6189 checkout) not set")
def test_conversion_b_with_a_past_reference_is_read_by_a_real_74a6189(tmp_path):
    old = Path(__import__("os").environ["NEXUS_ROLLBACK_TARGET_SRC"])
    path = _checkpointed_with_a_reference(tmp_path)
    assert "REFUSED" in _old_run(old, tmp_path)
    assert daemon.checkpoint_for_release_before_full_node_trace(path) >= 1
    after = _old_run(old, tmp_path)
    assert "DECODED True" in after and "PREPARED" in after, after
    assert KEY.encode() not in path.read_bytes() and b"full_node_trace" not in path.read_bytes()
