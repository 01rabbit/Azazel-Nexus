"""What the read-only UI sends to a browser, projected from the read model (U5).

**The normal screen answers four questions first (goal2 【5】A).** `summary`
is projected here, in Python, from the sections below and nothing else:

* `communication` -- is communication being kept? What the passive NOC
  observation saw of the default route and its link, and the Edge unit's
  state. Reachability is not measured, so the best word is `path_observed`
  (information), never "ok";
* `events` -- what is happening? Open incidents, from the explainer's recent
  list, only when the intake that feeds it is running;
* `response` -- what is being handled automatically? Edge's decisions as
  `would` (observe-only, not executed) and the execution result, which this
  node never accepts (`none`);
* `next` -- what does the person on duty do next? An ordered list of codes,
  each with the screen or the terminal command to go to.

Each answer carries a `basis` that keeps the kinds apart: `observed` (a
snapshot a daemon or observer wrote), `ai_inference` (an AI explanation),
`edge_decision` (Edge's would) and `execution_result`. A source that is
unknown, stale, absent, not enabled or not readable by this account makes
the answer say so; none is ever a healthy word.

The browser receives one JSON document, schema `azazel-nexus/ui-model/1`,
built here from:

* the status read model (`status_view`, schema `azazel-nexus/status-view/1`),
  which is already an allowlist of what strict readers checked. Only the
  sections the screens use are copied (`UI_SECTIONS`); the interface list
  is not (NOC belongs to its own section, and interface identity stays on
  the operator's terminal, inventory-confidentiality §6);
* the setup guide (`azazel-nexus setup --json`), copied field by field;
* the UI's own reading of which snapshot files this account may open
  (`access`), so that a section this account cannot read is shown as
  **permission denied** rather than as merely absent.

The operator snapshots (U2: `knowledge_status`, `mio_status`, `services`,
`storage`) and the NOC section (U3: `noc`) are screen sections like the
others. A section the read model does not carry (an older read model, or a
fixture saved before it existed) is listed under `pending` with
`section_absent_from_read_model`, and the page says "not collected" with
that code -- never a healthy word.

Nothing here decides anything: the document states that Edge decides and
enforces and that Edge's decisions reach this node as `would`, never as
executed (`authority`, copied from the read model).
"""

from __future__ import annotations

import json
from typing import Optional

__all__ = [
    "ACCESS_WORDS", "BASIS_KINDS", "NEXT_CODES", "OBSERVER_WORDS", "SCHEMA", "SETUP_FIELDS",
    "SUMMARY_WORDS", "UI_SECTIONS", "browser_json", "project",
]

SCHEMA = "azazel-nexus/ui-model/1"

#: The status read model's sections the screens render. Not `interfaces`.
UI_SECTIONS = (
    "profile", "mio", "capability", "enforcement", "external_modules",
    "knowledge_lite", "edge_core", "integration", "fabric", "edge_loop",
    "health", "next_actions",
    # The operator snapshots (U2) and the passive NOC observation (U3): what
    # an account that is not root reads in place of the root-only sources.
    "knowledge_status", "mio_status", "services", "storage", "noc",
    # The catalog, import, admission gates and confirmations (S-04), as the
    # versioned section `operator_view_source` builds.
    "operator_view",
)

SETUP_FIELDS = ("schema", "provider_admission", "hg05", "enforcement_readiness",
                "notice", "read_only")
SETUP_STEP_FIELDS = ("name", "status", "reason", "next_command")
SETUP_SCHEMA = "azazel-nexus/setup/1"

#: What the UI's account found when it tried each snapshot it reads.
ACCESS_WORDS = frozenset({"readable", "permission_denied", "absent", "not_regular",
                          "unreadable", "not_probed"})

#: Whether an observer's timer is enabled, read from the unit's wants link.
OBSERVER_WORDS = frozenset({"enabled", "not_enabled", "unknown"})

#: The words the four answers can carry. Only these; the page labels each.
SUMMARY_WORDS = frozenset({
    # communication
    "path_observed", "path_down_observed", "no_default_route_observed",
    # events
    "open_incidents", "no_open_incidents",
    # response
    "observe_only_no_execution",
    # next
    "action_needed", "monitoring_only",
    # any answer whose source is not usable
    "unknown", "stale", "permission_denied", "observer_not_enabled", "not_collected",
})

#: What a basis entry is. Kept apart on the page, never merged.
BASIS_KINDS = ("observed", "ai_inference", "edge_decision", "execution_result")

#: The next steps, in the order they are listed.
NEXT_CODES = (
    "read_model_unavailable", "check_uplink", "review_incidents_and_hand_off",
    "check_failed_units", "enable_observers", "check_unreadable_sources",
    "check_stale_sources", "continue_setup", "keep_monitoring",
)

OBSERVER_TIMERS = {"noc": "azazel-noc-observe.timer", "units": "azazel-units-observe.timer"}


def _copy(value):
    """A detached copy of a JSON value."""
    return json.loads(json.dumps(value, allow_nan=False))


def _setup(value) -> dict:
    if not isinstance(value, dict) or value.get("schema") != SETUP_SCHEMA:
        return {"status": "unavailable", "reason_code": "setup_guide_unavailable"}
    steps = value.get("steps")
    if not isinstance(steps, list):
        return {"status": "unavailable", "reason_code": "setup_guide_unavailable"}
    copied = {key: _copy(value[key]) for key in SETUP_FIELDS if key in value}
    copied["steps"] = [{key: _copy(step[key]) for key in SETUP_STEP_FIELDS if key in step}
                       for step in steps if isinstance(step, dict)]
    return {"status": "read", "reason_code": None, **copied}


def project(view, *, origin: dict, served_at: str, setup=None,
            setup_reason: Optional[str] = None, access: Optional[dict] = None,
            read_reason: Optional[str] = None, observers: Optional[dict] = None) -> dict:
    """The document the browser receives. Never raises on a bad `view`."""

    from .status_view import AUTHORITY, SCHEMA as VIEW_SCHEMA

    model = {
        "schema": SCHEMA,
        "origin": _copy(origin),
        "served_at": served_at,
        # Fixed, never derived: who decides, and that nothing executed here.
        "authority": dict(AUTHORITY),
        "access": {name: word if word in ACCESS_WORDS else "unreadable"
                   for name, word in sorted((access or {}).items())},
        "observers": {name: (observers or {}).get(name) if (observers or {}).get(name)
                      in OBSERVER_WORDS else "unknown" for name in OBSERVER_TIMERS},
        "sections": {},
        "pending": {},
    }
    if setup is not None:
        model["setup"] = _setup(setup)
    else:
        model["setup"] = {"status": "not_collected",
                          "reason_code": setup_reason or "setup_guide_not_collected"}
    sections = view.get("sections") if isinstance(view, dict) else None
    if (read_reason is not None or not isinstance(view, dict)
            or view.get("schema") != VIEW_SCHEMA or not isinstance(sections, dict)):
        model["read_model"] = {"status": "unavailable",
                               "reason_code": read_reason or "read_model_refused"}
        model.update(as_of=None, clock={"status": "unknown", "reason_code": "read_model_unavailable"},
                     lab_host=None)
        model["pending"] = {name: "read_model_unavailable" for name in UI_SECTIONS}
        model["summary"] = summarize(model)
        return model
    model["read_model"] = {"status": "read", "reason_code": None, "schema": VIEW_SCHEMA}
    model["as_of"] = view.get("as_of") if isinstance(view.get("as_of"), str) else None
    clock = view.get("clock")
    model["clock"] = _copy(clock) if isinstance(clock, dict) else {
        "status": "unknown", "reason_code": "clock_unknown"}
    model["lab_host"] = view.get("lab_host") is True
    model["snapshot_reader"] = view.get("snapshot_reader") if view.get(
        "snapshot_reader") in ("operator", "ui") else None
    for name in UI_SECTIONS:
        if name not in sections:
            model["pending"][name] = "section_absent_from_read_model"
        elif name == "operator_view":
            # A section with its own schema (M23, R389-05): only the version
            # this page knows, field by field; any other is not shown.
            copied = _operator_view(sections[name])
            if copied is None:
                model["pending"][name] = "section_version_unsupported"
            else:
                model["sections"][name] = copied
        else:
            model["sections"][name] = _copy(sections[name])
    model["summary"] = summarize(model)
    return model


# -- the operator view section (M23) --------------------------------------------

OPERATOR_VIEW_SCHEMA = "azazel-nexus/status-view/operator-view/1"
_OV_SCALARS = ("status", "reason_code", "admission_build_switch", "models_omitted",
               "status_sentence")
_OV_INPUTS = ("model_store", "core_reserve", "mio_entry_record", "remote_consent")
_OV_ROW = ("axis", "value", "reason", "reason_code", "model_id", "refused_by", "admitted",
           "nominal_gib", "profile", "is_this_node", "note")
_OV_ROW_LISTS = ("reason_codes", "entries")
_OV_OPERATION = ("confirmation", "available", "reason", "transition")


def _scalar(value) -> bool:
    return value is None or type(value) in (str, int, bool) or (
        type(value) is float and value == value)


def _strings(value) -> list:
    return [item for item in value if type(item) is str] if isinstance(value, list) else []


def _operator_view(section) -> Optional[dict]:
    """`operator-view/1`, copied field by field; `None` for any other version."""

    if not isinstance(section, dict) or section.get("schema") != OPERATOR_VIEW_SCHEMA:
        return None
    copied = {"schema": OPERATOR_VIEW_SCHEMA}
    for key in _OV_SCALARS:
        if key in section and _scalar(section[key]):
            copied[key] = section[key]
    inputs = _dict(section.get("inputs"))
    copied["inputs"] = {k: inputs[k] for k in _OV_INPUTS if type(inputs.get(k)) is str}
    copied["unread_inputs"] = _strings(section.get("unread_inputs"))
    provider = _dict(section.get("provider"))
    copied["provider"] = {"state": provider.get("state") if type(provider.get("state")) is str
                          else None, "reason_codes": _strings(provider.get("reason_codes"))}
    sections = []
    for part in section.get("sections") if isinstance(section.get("sections"), list) else ():
        part = _dict(part)
        rows = []
        for row in part.get("rows") if isinstance(part.get("rows"), list) else ():
            row = _dict(row)
            kept = {k: row[k] for k in _OV_ROW if k in row and _scalar(row[k])}
            kept.update({k: _strings(row[k]) for k in _OV_ROW_LISTS if k in row})
            rows.append(kept)
        sections.append({"key": part.get("key") if type(part.get("key")) is str else None,
                         "title": part.get("title") if type(part.get("title")) is str else None,
                         "rows": rows})
    copied["sections"] = sections
    copied["operations"] = [
        {k: op[k] for k in _OV_OPERATION if k in op and _scalar(op[k])}
        for op in (_dict(o) for o in (section.get("operations")
                                      if isinstance(section.get("operations"), list) else ()))]
    return copied


# -- the four answers ---------------------------------------------------------


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _unusable(section, access_word, observer=None):
    """`(word, reason)` when a snapshot section cannot answer; else `None`.

    Permission denied first (the account), then an observer that is not
    enabled, then absent/refused/stale/unknown as the section says.
    """

    section = _dict(section)
    if not section:
        return "not_collected", "section_absent_from_read_model"
    source = _dict(section.get("source"))
    if section.get("snapshot") is None:
        if access_word == "permission_denied":
            return "permission_denied", "access_permission_denied"
        if observer == "not_enabled":
            return "observer_not_enabled", "observer_timer_not_enabled"
        return "unknown", section.get("reason_code") or source.get("reason_code") or "not_collected"
    freshness = source.get("freshness")
    if freshness == "stale":
        return "stale", source.get("reason_code") or "snapshot_expired"
    if freshness != "fresh":
        return "unknown", source.get("reason_code") or "clock_unknown"
    return None


def _answer(word, reason, basis, **extra) -> dict:
    return {"status": word, "reason_code": reason, "basis": basis, **extra}


def _family_path(family) -> Optional[str]:
    """`usable`, `down` or `none` for one observed address family, else `None`."""

    family = _dict(family)
    if family.get("state") != "observed":
        return None
    main = _dict(_dict(family.get("value")).get("table_main"))
    if type(main.get("default_routes")) is not int:
        return None
    if main["default_routes"] <= 0:
        return "none"
    return "down" if main.get("linkdown") is True or main.get("dead") is True else "usable"


def _edge_unit(services) -> Optional[dict]:
    units = _dict(_dict(services).get("snapshot")).get("units")
    for unit in units if isinstance(units, list) else ():
        if _dict(unit).get("unit") == "azazel-edge-core.service":
            return {"kind": "observed", "code": "edge_unit_state",
                    "active_state": unit.get("active_state"), "status": unit.get("status")}
    return None


def _communication(model) -> dict:
    sections, access = model["sections"], model["access"]
    noc = sections.get("noc")
    basis = []
    edge = _edge_unit(sections.get("services"))
    if edge is not None and not _unusable(sections.get("services"), access.get("units_status")):
        basis.append(edge)
    basis.append({"kind": "observed", "code": "reachability_not_measured"})
    bad = _unusable(noc, access.get("noc_status"), model["observers"].get("noc"))
    if bad:
        return _answer(*bad, basis)
    snapshot = _dict(_dict(noc).get("snapshot"))
    if snapshot.get("collection") != "observed":
        return _answer("unknown", snapshot.get("reason_code") or "collection_failed", basis)
    uplink = _dict(snapshot.get("uplink"))
    paths = {name: _family_path(uplink.get(name)) for name in ("ipv4", "ipv6")}
    basis.insert(0, {"kind": "observed", "code": "default_route",
                     "families": {k: v for k, v in paths.items()},
                     "observed_at": snapshot.get("observed_at")})
    if "usable" in paths.values():
        return _answer("path_observed", None, basis)
    if "down" in paths.values():
        return _answer("path_down_observed", "default_route_link_down", basis)
    if set(paths.values()) == {"none"}:
        return _answer("no_default_route_observed", "no_default_route", basis)
    return _answer("unknown", "uplink_not_observed", basis)


def _loop_part(model, name, access_name):
    loop = _dict(model["sections"].get("edge_loop"))
    if not loop:
        return None, ("not_collected", "section_absent_from_read_model")
    if loop.get("status") != "read":
        return None, ("unknown", loop.get("reason_code") or "internal_error")
    part = _dict(loop.get(name))
    return part, _unusable(part, model["access"].get(access_name))


def _explainer_notes(model) -> list:
    """What makes the explainer's list incomplete or late, as basis entries."""

    explainer, bad = _loop_part(model, "explainer", "incident_explain_status")
    if bad:
        return [{"kind": "observed", "code": "explainer_not_usable", "reason_code": bad[1]}]
    snapshot = _dict(explainer.get("snapshot"))
    notes = []
    for flag in ("chain_broken", "storage_failed"):
        if snapshot.get(flag) is True:
            notes.append({"kind": "observed", "code": "explainer_" + flag})
    for counter in ("pending", "cursor_lag"):
        if type(snapshot.get(counter)) is int and snapshot[counter] > 0:
            notes.append({"kind": "observed", "code": "explainer_behind",
                          "counter": counter, "count": snapshot[counter]})
    return notes


def _events(model) -> dict:
    """Open incidents: the intake's count is the total; the list is a view.

    The intake owns the incident ledger and reports `open_incidents`; the
    explainer's recent list holds at most twenty rows and can lag, fail to
    store or break. So the total comes from the intake, the list's rows are
    counted separately, a disagreement is said, and "none" is said only when
    the intake is fresh, running (not degraded) and reports zero, and the list
    shows none open either (R389-02).
    """

    intake, intake_bad = _loop_part(model, "intake", "edge_intake_status")
    recent, recent_bad = _loop_part(model, "recent", "incident_recent")
    rows = [] if recent_bad else [
        row for row in _dict(recent.get("snapshot")).get("incidents") or ()
        if isinstance(row, dict)]
    open_rows = [row for row in rows if row.get("state") == "open"]
    ai = sum(1 for row in open_rows
             if _dict(row.get("explanation")).get("content_kind") == "ai_advice")
    latest = max((row.get("last_seen") for row in open_rows
                  if isinstance(row.get("last_seen"), (int, float))), default=None)
    # Severity: a smaller number is more severe (`incident_explain`,
    # Edge's `decide_defense`), so the most severe is the minimum (R389-03).
    severities = [row.get("most_severe") for row in open_rows
                  if type(row.get("most_severe")) is int]
    total = None
    if not intake_bad and intake.get("status") in ("running", "degraded"):
        count = _dict(intake.get("snapshot")).get("open_incidents")
        total = count if type(count) is int and count >= 0 else None
    basis = [{"kind": "observed", "code": "open_incidents_total", "count": total,
              "source": "intake"},
             {"kind": "observed", "code": "open_incidents_listed", "count": len(open_rows),
              "shown": len(rows), "latest": latest,
              "most_severe": min(severities) if severities else None,
              "reason_code": recent_bad[1] if recent_bad else None}]
    basis.extend(_explainer_notes(model))
    if ai:
        basis.append({"kind": "ai_inference", "code": "ai_explanations", "count": ai})
    if total is not None and len(open_rows) != total:
        basis.append({"kind": "observed", "code": "list_differs_from_intake",
                      "count": total, "listed": len(open_rows)})
    if (total or 0) > 0 or open_rows:
        count = max(total or 0, len(open_rows))
        # Which way they disagree is said, not assumed (R389b-02): fewer rows
        # than the count is a list that misses some; more is a list that has
        # not caught up with a closure (or a count that lags).
        reason = (None if total is not None and total == len(open_rows)
                  else "intake_not_evidenced_running" if total is None
                  else "incident_list_incomplete" if len(open_rows) < total
                  else "incident_list_ahead_of_intake")
        return _answer("open_incidents", reason, basis, count=count)
    if intake_bad:
        word, reason = intake_bad
        return _answer(word if word in ("permission_denied", "stale", "not_collected")
                       else "unknown", "intake_not_evidenced_running", basis, intake=reason)
    if intake.get("status") != "running" or total is None:
        # Degraded (storage failed) or no usable count: completeness unknown.
        return _answer("unknown", "incident_count_not_evidenced", basis,
                       intake=intake.get("reason_code"))
    if recent_bad:
        return _answer("unknown", "incident_list_unusable", basis)
    return _answer("no_open_incidents", None, basis, count=0)


def _response(model) -> dict:
    basis = [{"kind": "execution_result", "code": "none_accepted",
              "reason_code": "nexus_accepts_observe_only"}]
    recent, bad = _loop_part(model, "recent", "incident_recent")
    if bad:
        basis.insert(0, {"kind": "edge_decision", "code": "would_not_read",
                         "reason_code": bad[1]})
        return _answer("observe_only_no_execution", "nexus_accepts_observe_only", basis)
    would: dict = {}
    for row in _dict(recent.get("snapshot")).get("incidents") or ():
        decision = _dict(_dict(row).get("edge_decision"))
        if _dict(row).get("state") == "open" and decision.get("kind") == "would":
            action = decision.get("action")
            if isinstance(action, str):
                would[action] = would.get(action, 0) + 1
    basis.insert(0, {"kind": "edge_decision", "code": "would_not_executed",
                     "actions": dict(sorted(would.items()))})
    return _answer("observe_only_no_execution", "nexus_accepts_observe_only", basis)


def _sources(model):
    """`(unreadable, stale)` names among the snapshot sources the page reads."""

    sections, access = model["sections"], model["access"]
    loop = _dict(sections.get("edge_loop"))
    named = {
        "noc": (sections.get("noc"), "noc_status"),
        "services": (sections.get("services"), "units_status"),
        "knowledge_status": (sections.get("knowledge_status"), "knowledge_status"),
        "mio_status": (sections.get("mio_status"), "mio_status"),
        "intake": (loop.get("intake"), "edge_intake_status"),
        "explainer": (loop.get("explainer"), "incident_explain_status"),
        "recent": (loop.get("recent"), "incident_recent"),
    }
    unreadable, stale = [], []
    for name, (section, access_name) in named.items():
        if section is None:
            continue
        bad = _unusable(section, access.get(access_name))
        if bad and bad[0] == "permission_denied":
            unreadable.append(name)
        elif bad and bad[0] == "stale":
            stale.append(name)
    return unreadable, stale


def _next(model, answers) -> dict:
    items = []
    if model["read_model"]["status"] != "read":
        items.append({"code": "read_model_unavailable", "command": "azazel-nexus status"})
    if answers["communication"]["status"] in ("path_down_observed", "no_default_route_observed"):
        items.append({"code": "check_uplink", "screen": "noc"})
    if answers["events"]["status"] == "open_incidents":
        items.append({"code": "review_incidents_and_hand_off", "screen": "incidents"})
    services = _dict(model["sections"].get("services"))
    if services.get("reason_code") == "unit_failed":
        items.append({"code": "check_failed_units", "screen": "setup"})
    disabled = sorted(OBSERVER_TIMERS[name] for name, word in model["observers"].items()
                      if word == "not_enabled")
    if disabled:
        items.append({"code": "enable_observers",
                      "command": "sudo systemctl enable --now " + " ".join(disabled)})
    if model["read_model"]["status"] == "read":
        unreadable, stale = _sources(model)
        if unreadable:
            items.append({"code": "check_unreadable_sources", "sources": unreadable,
                          "command": "azazel-nexus status"})
        if stale:
            items.append({"code": "check_stale_sources", "sources": stale, "screen": "detail"})
    setup = model.get("setup") or {}
    pending = [step for step in setup.get("steps") or ()
               if isinstance(step, dict) and step.get("status") not in ("done", "not-applicable")]
    if pending:
        step = pending[0]
        items.append({"code": "continue_setup", "step": step.get("name"),
                      "command": step.get("next_command"), "screen": "setup"})
    if not items:
        items.append({"code": "keep_monitoring"})
    word = "monitoring_only" if items[0]["code"] == "keep_monitoring" else "action_needed"
    return _answer(word, None, [], items=items)


def summarize(model) -> dict:
    """The four answers of the normal screen (see the module docstring)."""

    answers = {}
    for name, build in (("communication", _communication), ("events", _events),
                        ("response", _response)):
        try:
            answers[name] = build(model)
        except Exception:  # noqa: BLE001 - an answer that cannot be built is unknown
            answers[name] = _answer("unknown", "internal_error", [])
    try:
        answers["next"] = _next(model, answers)
    except Exception:  # noqa: BLE001
        answers["next"] = _answer("unknown", "internal_error", [], items=[])
    return answers


def browser_json(value) -> bytes:
    """JSON safe to hand to a page: no `<`, `>`, `&` or line separators raw.

    The page parses it with `JSON.parse` and writes with `textContent`, so
    this is a second line: even a mistaken HTML sink would see no tag.
    """

    text = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True)
    for raw, escaped in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"),
                         (" ", "\\u2028"), (" ", "\\u2029")):
        text = text.replace(raw, escaped)
    return text.encode("utf-8")
