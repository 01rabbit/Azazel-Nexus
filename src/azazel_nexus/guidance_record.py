"""Deterministic guidance as a stored, read and displayed record (no model involved).

M.I.O. (`azazel_mio.guidance`) produces the content; this module is the Nexus side: a strict
reader for the stored value (`content_kind == "deterministic_guidance"` only, any other value is
refused), the binding check against the explanation record, a bounded public projection for the
recent-incidents snapshot, and the Japanese display layer (ID -> text, English when unregistered).
"""
from __future__ import annotations

import re

from .edge_intake import _int, _shape, _text
from .guidance_display_ja import DISPLAY_JA

GUIDANCE_FIELD = "guidance"
GUIDANCE_CONTENT_KIND = "deterministic_guidance"
GUIDANCE_SCHEMA_VERSION = "1.0.0"
_TOP = ("guidance_schema_version", "content_kind", "generation_method", "model_calls", "playbook_id",
        "playbook_version", "playbook_digest", "guidance_digest", "selection_mode", "facts",
        "competing_explanations", "discriminating_material", "claim_boundaries", "unknown_groups",
        "topics_addressed", "weight_notes", "next_checks", "recommendation", "evidence_gaps", "handoff")
_ID = re.compile(r"[a-z][a-z0-9_:-]{1,95}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FACT_KINDS = {"supplied_report", "supplied_report_gap", "supplied_report_note", "edge_decision", "knowledge"}
_SOURCES = ("report", "frame", "frame_analysis", "knowledge")
_LIMITS = {"facts": 16, "competing_explanations": 4, "discriminating_material": 8, "claim_boundaries": 8,
           "unknown_groups": 16, "topics_addressed": 8, "weight_notes": 8, "next_checks": 4}
_PUBLIC_LIMITS = {"facts": 8, "unknown_groups": 8, "weight_notes": 4, "topics_addressed": 4}
TEXT_MAX = 280


def _refuse():
    raise ValueError("guidance_refused")


def _t(value, limit=TEXT_MAX):
    if type(value) is not str or len(value) > limit or not value.isprintable():
        _refuse()
    from .handoff import contains_network_address
    if contains_network_address(value):
        _refuse()


def _list(value, key, public):
    if type(value) is not list:
        _refuse()
    limit = (_PUBLIC_LIMITS if public else _LIMITS).get(key, _LIMITS[key])
    if len(value) > limit:
        _refuse()
    return value


def read_guidance(g, *, public=False):
    """Validate one guidance value; `public` is the bounded snapshot projection (no handoff sections)."""
    _shape(g, _TOP)
    if (g["content_kind"] != GUIDANCE_CONTENT_KIND or g["guidance_schema_version"] != GUIDANCE_SCHEMA_VERSION
            or g["generation_method"] != "deterministic_guidance" or g["model_calls"] != 0
            or type(g["model_calls"]) is not int):
        _refuse()
    for key in ("playbook_digest", "guidance_digest"):
        if type(g[key]) is not str or not _DIGEST.fullmatch(g[key]):
            _refuse()
    for key in ("playbook_id", "playbook_version", "selection_mode"):
        _t(g[key], 96)
    if type(g["playbook_id"]) is not str or not re.fullmatch(r"[a-z][a-z0-9-]{2,63}", g["playbook_id"]):
        _refuse()
    for f in _list(g["facts"], "facts", public):
        _shape(f, ("kind", "trust", "text"))
        if f["kind"] not in _FACT_KINDS:
            _refuse()
        _t(f["trust"], 64); _t(f["text"])
        # a supplied report is never labelled as verified
        if f["kind"].startswith("supplied_report") and f["trust"] != "untrusted_report":
            _refuse()
    for e in _list(g["competing_explanations"], "competing_explanations", public):
        _shape(e, ("slot", "role", "prompt", "support") + (() if public else ("evidence_refs",)))
        if e["support"] != "unverified_candidate" or e["role"] not in {"hostile", "benign", "unresolved"}:
            _refuse()
        _t(e["slot"], 64); _t(e["prompt"])
        for r in () if public else e["evidence_refs"]:
            if type(r) is not str or not _DIGEST.fullmatch(r):
                _refuse()
        if not public and (type(e["evidence_refs"]) is not list or len(e["evidence_refs"]) > 8):
            _refuse()
    for key in ("discriminating_material", "claim_boundaries"):
        for s in _list(g[key], key, public):
            _t(s)
    for grp in _list(g["unknown_groups"], "unknown_groups", public):
        _shape(grp, ("text", "topic", "sources", "merged"))
        _t(grp["text"])
        if grp["topic"] is not None:
            _t(grp["topic"], 64)
        if (type(grp["sources"]) is not list or not grp["sources"] or any(s not in _SOURCES for s in grp["sources"])
                or type(grp["merged"]) is not list or len(grp["merged"]) > 8):
            _refuse()
        for s in grp["merged"]:
            _t(s)
    for t in _list(g["topics_addressed"], "topics_addressed", public):
        _shape(t, ("id", "as_reported", "negative"))
        _t(t["id"], 64); _t(t["as_reported"])
        if type(t["negative"]) is not bool:
            _refuse()
    for w in _list(g["weight_notes"], "weight_notes", public):
        _shape(w, ("explanation", "direction", "topic", "as_reported"))
        if w["direction"] not in {"verification_priority_up", "verification_priority_down"}:
            _refuse()
        _t(w["explanation"], 64); _t(w["topic"], 64); _t(w["as_reported"])
    checks = _list(g["next_checks"], "next_checks", public)
    for i, c in enumerate(checks):
        _shape(c, ("id", "tier", "mode", "text"))
        if (c["mode"] != "read_only_existing_authority" or c["tier"] != ("required" if i < 2 else "optional_when_needed")
                or type(c["id"]) is not str or not _ID.fullmatch(c["id"])):
            _refuse()
        _t(c["text"], 240)
    if g["recommendation"] != {"recommended_action": "OBSERVE", "executable": False, "current_action": None,
                               "source": "deterministic_fixed"}:
        _refuse()
    gaps = g["evidence_gaps"]
    _shape(gaps, ("items", "reason", "source"))
    if type(gaps["items"]) is not list or len(gaps["items"]) > 4 or gaps["source"] != "deterministic":
        _refuse()
    _t(gaps["reason"], 96)
    for item in gaps["items"]:
        _shape(item, ("marker", "question", "capability"))
        for v in item.values():
            _t(v, 240)
    h = g["handoff"]
    # The snapshot keeps the incident only: request, trace, frame and evidence ids stay in the ledger.
    _shape(h, ("incident_id", "privacy_class") + (() if public else ("request_id", "trace_id", "frame_id", "evidence_refs", "sections")))
    for key in ("incident_id",) if public else ("incident_id", "request_id", "trace_id", "frame_id"):
        _t(h[key], 96)
    if not public and (type(h["evidence_refs"]) is not list or len(h["evidence_refs"]) > 8 or any(
            type(r) is not str or not _DIGEST.fullmatch(r) for r in h["evidence_refs"])):
        _refuse()
    if h["privacy_class"] != "P3-restricted":
        _refuse()
    if not public:
        _shape(h["sections"], ("report_basis", "competing_explanations", "missing_information", "safe_next_checks", "execution"))
        for key in ("report_basis", "competing_explanations", "missing_information", "safe_next_checks"):
            if type(h["sections"][key]) is not list or len(h["sections"][key]) > 20:
                _refuse()
            for s in h["sections"][key]:
                _t(s)
        if h["sections"]["execution"] != "none (current_action null)":
            _refuse()
    return g


def bind_guidance(g, *, incident_id, sequence=None, evidence_ids=None):
    """The guidance must describe the record it is stored with: incident, request, trace, frame, refs."""
    h = g["handoff"]
    if h["incident_id"] != incident_id:
        _refuse()
    if sequence is not None:
        trace = f"mio-{incident_id[4:]}-{sequence}"
        if (h["request_id"], h["trace_id"], h["frame_id"]) != (f"{incident_id}:{sequence}", trace, trace + ":frame"):
            _refuse()
    if evidence_ids is not None and sorted(set(h["evidence_refs"])) != sorted(set(evidence_ids)):
        _refuse()
    if any(e["evidence_refs"] != h["evidence_refs"] for e in g["competing_explanations"]):
        _refuse()
    return g


def public_guidance(g):
    """Bounded projection for the recent snapshot (the record keeps the full value)."""
    p = dict(g)
    for key, limit in _PUBLIC_LIMITS.items():
        p[key] = list(g[key][:limit])
    p["unknown_groups"] = [dict(x, merged=[]) for x in p["unknown_groups"]]
    h = dict(g["handoff"])
    h.pop("sections", None)
    # Evidence pointers stay in the ledger; the snapshot never shows them.
    h = {"incident_id": h["incident_id"], "privacy_class": h["privacy_class"]}
    p["competing_explanations"] = [{k: v for k, v in e.items() if k != "evidence_refs"} for e in g["competing_explanations"]]
    p["handoff"] = h
    return read_guidance(p, public=True)


# ---------------------------------------------------------------- display layer (Japanese)
_UNKNOWN_PREFIX = "Reported, not verified: "


def _ja_check(g, check):
    pid = g["playbook_id"]
    table = DISPLAY_JA["playbooks"].get(pid, {}).get("checks", {})
    m = re.fullmatch(re.escape(pid) + r":q(\d+)", check["id"])
    return table.get("q" + m.group(1)) if m else None


def _unknown_text(text):
    fixed = DISPLAY_JA["fixed_unknowns"].get(text)
    if fixed:
        return fixed
    if text.startswith(_UNKNOWN_PREFIX):
        return "報告ベース・未検証：" + text[len(_UNKNOWN_PREFIX):].replace(" (verification still required)", "（確認が必要）")
    return text


_EDGE_RE = re.compile(r"Edge selected_action=(\S+), result=(\S+), executed_count=(\d+)")


def _fact_text(f):
    m = _EDGE_RE.fullmatch(f["text"]) if f["kind"] == "edge_decision" else None
    if not m:
        return f["text"]
    ev = DISPLAY_JA["edge_values"]
    a, r = m.group(1).rstrip(","), m.group(2).rstrip(",")
    return f"Edge の判断: {ev.get(a, a)} を選択（結果 {ev.get(r, r)}、実行件数 {m.group(3)}）"


def guidance_view(g):
    """Summary and detail for the UI and the handoff, from a validated guidance value."""
    d = DISPLAY_JA
    pb = d["playbooks"].get(g["playbook_id"], {})
    labels = pb.get("slots", {})
    source_ja = d["sources"]
    checks = [{"id": c["id"], "tier": c["tier"], "text": _ja_check(g, c) or c["text"], "text_en": c["text"]}
              for c in g["next_checks"]]
    weights = [{"explanation": w["explanation"], "explanation_ja": labels.get(w["explanation"], w["explanation"]),
                "direction": d["directions"].get(w["direction"], w["direction"]),
                "topic": d["topics"].get(w["topic"], w["topic"]), "as_reported": w["as_reported"]}
               for w in g["weight_notes"]]
    weak = pb.get("weakening", [])
    weakening = weak if len(weak) == len(g["discriminating_material"]) else list(g["discriminating_material"])
    bounds = pb.get("boundaries", [])
    boundaries = bounds if len(bounds) == len(g["claim_boundaries"]) else list(g["claim_boundaries"])
    unknowns = [{"text": _unknown_text(u["text"]), "topic": d["topics"].get(u["topic"], u["topic"]) if u["topic"] else None,
                 "sources": [source_ja.get(s, s) for s in u["sources"]]} for u in g["unknown_groups"]]
    report_points = [{"kind": d["fact_kinds"].get(f["kind"], f["kind"]), "text": _fact_text(f), "trust": f["trust"]}
                     for f in g["facts"] if f["kind"] != "knowledge"]
    nc = d["nochange"]
    compare = any(u["text"].startswith(d["compare_unknown"]) for u in g["unknown_groups"])
    if weights:
        weight_status = None
    elif compare:
        weight_status = nc["compare"]
    else:
        weight_status = nc["no_effect"] if g["topics_addressed"] else nc["no_topic"]
    qid = pb.get("precondition_check")
    precondition = None
    if compare:
        ref = next((c for c in checks if c["id"].endswith(":" + str(qid))), None) if qid else None
        precondition = "比較条件（窓・時刻帯・集計）が揃っていません。" + (
            f"先に {ref['id']}（{ref['text']}）を確認してから比較する" if ref else "先に比較条件を確認してから比較する")
    summary = {
        "title": d["sections"]["summary"], "playbook": pb.get("label", g["playbook_id"]),
        "report_points": report_points[:6],
        "required_checks": [c for c in checks if c["tier"] == "required"],
        "key_unknowns": unknowns[:3], "priority_changes": weights,
        "recommendation": "経過観察（OBSERVE）。実行可能な推奨ではありません。",
        "notice": "モデル生成ではありません（決定論の案内）。報告は未検証です。",
        "weight_status": weight_status, "precondition": precondition,
        "edge_relation": "§2 の Edge 観測との関係: 未確認（この案内は供給された報告のみに基づく）",
    }
    detail = {
        "explanations": [{"slot": e["slot"], "label": labels.get(e["slot"], e["prompt"]), "role": e["role"],
                          "support": "報告 ref に基づく候補。内容的な支持は未検証",
                          "evidence_refs": e.get("evidence_refs", [])} for e in g["competing_explanations"]],
        "weakening": weakening, "claim_boundaries": boundaries,
        "optional_checks": [c for c in checks if c["tier"] != "required"],
        "all_unknowns": unknowns,
        "handoff": {k: v for k, v in g["handoff"].items() if k != "sections"},
        "provenance": {"playbook_id": g["playbook_id"], "playbook_version": g["playbook_version"],
                       "playbook_digest": g["playbook_digest"], "guidance_digest": g["guidance_digest"],
                       "guidance_schema_version": g["guidance_schema_version"],
                       "content_kind": g["content_kind"], "model_calls": g["model_calls"]},
    }
    return {"content_kind": g["content_kind"], "summary": summary, "detail": detail,
            "sections": {k: d["sections"][k] for k in d["sections"]}}


def guidance_markdown(g, esc=str):
    """Japanese Markdown block for the handoff; mirrors `guidance_view`."""
    v = guidance_view(g)
    s, dt = v["summary"], v["detail"]
    out = ["### 決定論の案内（モデル生成ではない）", "",
           f"- {s['recommendation']}", "", "#### " + v["sections"]["report_points"]]
    out += [f"- [{esc(p['kind'])}] {esc(p['text'])}" for p in s["report_points"]] or ["- なし"]
    if s["precondition"]:
        out += ["", "比較の前提: " + esc(s["precondition"])]
    out += ["", "#### " + v["sections"]["required_checks"]]
    out += [f"- {c['id']}: {esc(c['text'])}" for c in s["required_checks"]] or ["- なし"]
    out += ["", "#### " + v["sections"]["all_unknowns"]]
    out += [f"- {esc(u['text'])}（出典: {'・'.join(u['sources'])}）" for u in dt["all_unknowns"]] or ["- なし"]
    out += ["", "#### " + v["sections"]["weights"]]
    out += [f"- {w['explanation_ja']}: {w['direction']} — {esc(w['topic'])}" for w in s["priority_changes"]] or ["- " + s["weight_status"]]
    out += ["", "#### " + v["sections"]["explanations"]]
    out += [f"- {esc(e['label'])}" for e in dt["explanations"]]
    out += ["", "#### " + v["sections"]["optional_checks"]]
    out += [f"- {c['id']}: {esc(c['text'])}" for c in dt["optional_checks"]] or ["- なし"]
    h = dt["handoff"]
    pv = dt["provenance"]
    out += ["", "#### " + v["sections"]["handoff"],
            "- 運用で伝える ID: " + (f"incident_id `{h['incident_id']}`" if "incident_id" in h else "なし"),
            "- 診断用 ID: " + (" / ".join(f"{k} `{h[k]}`" for k in ("request_id", "trace_id", "frame_id") if k in h) or "なし") + ("" if "frame_id" in h else "（request・trace・frame は snapshot 由来のため非表示）"),
            "- 証拠 ref: " + (", ".join(h["evidence_refs"]) or "なし" if "evidence_refs" in h else "非表示（snapshot 由来の公開形）"), f"- privacy 区分: {h['privacy_class'].lower()}（伏せた値は再掲しない）",
            "", s["edge_relation"], "",
            f"詳細: 種別 {pv['content_kind']} / schema {pv['guidance_schema_version']} / playbook {g['playbook_id']} {pv['playbook_version']} / model_calls {pv['model_calls']}"]
    return "\n".join(out) + "\n"
