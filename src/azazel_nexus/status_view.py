"""`azazel-nexus status` as a read model, separate from its rendering (U1).

`build` turns what `status` has read into a `StatusView`:

* `view` -- the read model. A plain, JSON-serialisable dict, schema
  `azazel-nexus/status-view/1`, built **by allowlist**: every value is copied
  field by field from what a strict reader already checked (the snapshot
  readers in `edge_intake`, `incident_explain` and `audit_status`, the route
  ledger reader in `mio_status`, Knowledge Lite's `status_summary`) or from a
  fixed vocabulary in this package. Nothing is passed through whole, so a
  field added upstream does not reach the view until it is listed here.
* `terminal` -- free text that only the operator's own terminal may show:
  exception text, filesystem paths, interface descriptions (bus path and port
  label) and finding reasons that can carry either. The text rendering has
  always shown them and still does; the read model marks each one it leaves
  out under `withheld` instead of copying it.

`render_text` prints the existing `status` screen from the two, byte for byte
(the golden files in `tests/fixtures/status-view/` were written before this
module existed). `dumps` serialises `view` alone.

**Vocabulary that is fixed here, not inferred.** Every section carries a
`status` word and a `reason_code`; an unknown, unmeasured, refused or stale
input is said as such and never as a healthy word. Each section names its
`source` (the snapshot's schema, `written_at` and freshness where there is a
snapshot). Edge's decisions are `would` and not executed: Nexus's intake
refuses any Edge event that is not observe-only (`edge_intake`), so no
execution result can reach this node, and the view says so rather than
leaving the field empty.

`build` reads only what `status` has always read (the M.I.O. route ledger,
the broker's local state, the loop snapshots), each once and through its
existing reader. Nothing here opens a socket, starts a process or writes a
file, and nothing here decides anything.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, TextIO

__all__ = ["SCHEMA", "StatusView", "build", "dumps", "render_text"]

SCHEMA = "azazel-nexus/status-view/1"

#: Fixed statement of who decides; the view never derives authority.
AUTHORITY = {
    "decision_and_enforcement": "edge",
    "nexus": "observe_explain_advise",
    "edge_decisions": "would_not_executed",
    "execution_results": "not_accepted",
    "reason_code": "nexus_accepts_observe_only",
}

#: Snapshot freshness thresholds, the same as the text renderer's.
LOOP_STALE_S = 30
FUTURE_S = 5

# -- allowlists ------------------------------------------------------------
#
# The exact fields copied from each reader's output. A reader that grows a
# field does not widen the view: the field is added here, deliberately.

INTAKE_FIELDS = ("schema", "written_at", "last_accepted_at", "accepted", "processed",
                 "last_processed_at", "refused", "open_incidents", "queue_drops",
                 "storage_failed", "ledger_recovered")
EDGE_FORWARD_FIELDS = ("dropped", "failed", "sent", "since", "reported_at", "restarts")
DECOY_FIELDS = ("accepted", "last_accepted_at")
EXPLAINER_FIELDS = ("schema", "written_at", "last_explained_at", "explained", "refused",
                    "pending", "cursor_lag", "chain_broken", "recovery_hint", "storage_failed",
                    "mio_available", "knowledge_available", "audit_forward_dropped",
                    "audit_forward_refused")
RECENT_FIELDS = ("schema", "written_at")
INCIDENT_FIELDS = ("incident_id", "state", "first_seen", "last_seen", "count", "most_severe",
                   "edge_would", "policy_reason", "technique_ids", "evidence_stored")
EXPLANATION_FIELDS = ("state", "route", "outcome", "summary", "failure_codes",
                      "content_kind", "notice")
#: A citation as `read_recent_incidents` checks it today. Copied as is; a
#: citation field added later (provenance, time, digest) is added here too.
KNOWLEDGE_REF_FIELDS = ("technique_id", "name", "claim_id")
AUDIT_SOURCE_FIELDS = ("schema", "written_at")
MIO_FIELDS = ("ceiling", "state", "reasons", "source", "observed_at", "availability", "notice")
ISSUER_LABEL_FIELDS = ("digest_verified", "issuer_authenticated", "issuer_status",
                       "revocation_status", "revoked", "floor_status", "notes")
#: Health subjects whose detail is fixed text over checked values. Others
#: (`audit chain`, from the hidden `--ledger`) carry a path or exception text.
PUBLIC_HEALTH_SUBJECTS = frozenset({"systemd units", "audit"})

LAB_HOST_STEPS = (
    ("azazel-nexus commission", "commissioning"),
    ("azazel-nexus hil-preflight", "host-preflight"),
    ("azazel-nexus model-import-fetched", "model-import-fetched"),
)

_FABRIC_PROJECTED = re.compile(r"projected \(v([0-9]+\.[0-9]+\.[0-9]+(?:rc[0-9]+|a[0-9]+|b[0-9]+)?)\)")
_FABRIC_FIXED = {
    "not available (extra not installed)": "not_installed",
    "refused (projection_refused)": "refused",
}
_GENERATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")


@dataclass(frozen=True)
class StatusView:
    """The read model, and the terminal-only text kept beside it."""

    view: dict
    terminal: dict = field(default_factory=dict, repr=False)


def dumps(status: StatusView) -> str:
    """The read model as JSON. The terminal-only half is never serialised."""

    return json.dumps(status.view, ensure_ascii=False, sort_keys=True, indent=2,
                      allow_nan=False)


# -- building --------------------------------------------------------------


def _pick(value: dict, fields) -> dict:
    return {key: _plain(value[key]) for key in fields if key in value}


def _plain(value):
    """A detached copy of a checked JSON value (dicts, lists, scalars)."""
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite")
    return value


def _epoch(as_of: Optional[str]) -> Optional[float]:
    try:
        return datetime.fromisoformat(as_of).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _freshness(written_at, now, stale_after) -> tuple[str, Optional[str], Optional[int]]:
    """`(status, reason_code, age_s)` of one snapshot against the status clock."""
    if type(now) not in (int, float):
        return "unknown", "clock_unknown", None
    age = now - written_at
    if written_at > now + FUTURE_S:
        return "stale", "snapshot_dated_in_future", int(age)
    if age > stale_after:
        return "stale", "snapshot_expired", int(age)
    return "fresh", None, max(0, int(age))


def _snapshot_source(value, now, stale_after) -> dict:
    status, reason, age = _freshness(value["written_at"], now, stale_after)
    return {"kind": "snapshot", "schema": value["schema"], "written_at": value["written_at"],
            "freshness": status, "reason_code": reason, "age_s": age}


def _absent_source() -> dict:
    return {"kind": "snapshot", "schema": None, "written_at": None, "freshness": "unavailable",
            "reason_code": "snapshot_absent_or_refused", "age_s": None}


def _profile(report, terminal) -> dict:
    reading = report.profile.reading
    source = {"kind": "os_reading", "reader": "resource_profile.take_reading"}
    if reading is None:
        terminal["profile_reason"] = report.profile.reason
        return {"status": "not_measured", "reason_code": "profile_not_measured",
                "profile": None, "usable_mib": None, "source": source, "withheld": ["reason"]}
    return {"status": "measured", "reason_code": None, "profile": reading.profile.value,
            "usable_mib": reading.usable_mib, "source": source, "withheld": []}


def _mio(summary: dict) -> dict:
    reading = _pick(summary, MIO_FIELDS)
    if reading.get("state"):
        status, reason = "recorded", None
    elif summary.get("availability") == "unknown (no recorded capability transition)":
        status, reason = "unknown", "no_recorded_capability_transition"
    else:
        status, reason = "unknown", "route_ledger_unreadable_or_refused"
    return {"status": status, "reason_code": reason, "reading": reading,
            "source": {"kind": "route_ledger", "reader": "mio_status.status_summary",
                       "observed_at": reading.get("observed_at")}}


def _capability(report) -> dict:
    caps = report.capabilities
    return {"status": "reported", "reason_code": None, "state": caps.state.value,
            "retained": list(caps.retained), "lost": list(caps.lost),
            "source": {"kind": "fixed_component_set", "live_provider_assessment": False}}


def _enforcement(report, edge) -> dict:
    record = report.record
    return {
        "enforcement_ready": bool(report.enforcement_ready),
        "edge_baseline_ready": bool(edge is not None and edge.ready),
        "commissioning_record": "absent" if record is None else "present",
        "missing_profiles": [] if record is None else list(record.missing_profiles),
        "observe_only": None if record is None else bool(record.observe_only),
        "reason_code": None if report.enforcement_ready else (
            "no_commissioning_record" if record is None else "commissioning_incomplete"),
    }


def _interfaces(report, terminal) -> dict:
    from .hil_preflight import OPERATOR_SCREEN_FIELDS

    facts = terminal.setdefault("interface_facts", {})
    items = []
    for interface in report.interfaces:
        facts[interface.handle] = ", ".join(
            f"{k}={v}" for k, v in sorted(interface.description.items())
            if k in OPERATOR_SCREEN_FIELDS)
        items.append({
            "handle": interface.handle,
            "state": interface.role or ("unassigned" if interface.commissionable
                                        else "not commissionable"),
            "role": interface.role,
            "commissionable": bool(interface.commissionable),
            "blocked_by": list(interface.blocked_by),
            "withheld": ["description"],
        })
    return {"status": "read" if items else "none_read",
            "reason_code": None if items else "no_interfaces_read",
            "items": items, "source": {"kind": "sysfs_read", "reader": "inventory.read_interfaces"}}


def _modules(report) -> list:
    return [{"name": m.name, "state": m.state.value, "reason": m.reason,
             "working": bool(m.working)} for m in report.modules]


def _knowledge(reading: Optional[dict]) -> dict:
    from .functional_readiness import readiness_for

    if reading is None:
        return {"status": "not_collected", "reason_code": "not_collected"}
    readiness = readiness_for("knowledge_lite")
    generation = reading["generation"]
    withheld = []
    if not (generation is None or type(generation) is int
            or (type(generation) is str and _GENERATION.fullmatch(generation))):
        generation, withheld = None, ["generation"]
    return {
        "status": str(reading["state"]), "reason_code": str(reading["reason_code"]),
        "generation": generation, "freshness": str(reading["freshness"]),
        "readiness": {"functional": bool(readiness.functional),
                      "word": "functional" if readiness.functional else readiness.value,
                      "means": readiness.means, "does_not_mean": list(readiness.does_not_mean)},
        "cryptographic_implementation": {"status": "not_supported",
                                         "reason_code": "nexus_70_review_pending"},
        "source": {"kind": "store_read", "reader": "lite_import.status_summary",
                   "written_at": None, "trust": "commissioned_trust_root"},
        "withheld": withheld,
    }


def _edge(edge, probe_code: str, boot_code: str, terminal) -> dict:
    from .edge_package import (
        AUTHENTICATED_CAVEAT, NOT_AUTHENTICATED_CAVEAT, UNSIGNED_CAVEAT,
    )

    if edge is None:
        return {"status": "not_inspected", "reason_code": "not_inspected"}
    known_caveats = {UNSIGNED_CAVEAT, NOT_AUTHENTICATED_CAVEAT, AUTHENTICATED_CAVEAT}
    terminal["edge_root"] = edge.root
    terminal["edge_finding_reasons"] = [finding.reason for finding in edge.findings]
    terminal["edge_caveats"] = list(edge.caveats)
    issuer = None
    if edge.issuer is not None:
        labels = edge.issuer.labels()
        issuer = {**{key: _plain(labels[key]) for key in ISSUER_LABEL_FIELDS},
                  "issuer_reason": edge.issuer.issuer_reason,
                  "withheld": ["issuer", "revocation_sequence", "floor_version"]}
        terminal["edge_issuer"] = {"issuer": edge.issuer.issuer,
                                   "revocation_sequence": edge.issuer.revocation_sequence,
                                   "floor_version": edge.issuer.floor_version}
    return {
        "status": edge.presence.value,
        "reason_code": None if edge.ready else "checks_not_all_passed",
        "ready": bool(edge.ready),
        "root_configured": bool(edge.root),
        "findings": [{"check": f.check, "evidence": f.evidence.value,
                      "security": bool(f.security), "withheld": ["reason"]}
                     for f in edge.findings],
        "issuer": issuer,
        "caveats": [{"text": c if c in known_caveats else None,
                     "withheld": [] if c in known_caveats else ["text"]} for c in edge.caveats],
        "probe": {"result": probe_code, "boot_id": boot_code,
                  "observed_at": edge.probe.observed_at if edge.probe else None},
        "source": {"kind": "package_files_and_probe_result",
                   "reader": "edge_package.inspect", "probe_reader": "edge_package.load_probe_result"},
        "withheld": ["root"],
    }


def _integration(view, broker: Optional[dict]) -> dict:
    if view is None:
        return {"status": "not_collected", "reason_code": "not_collected"}
    return {
        "status": "reported", "reason_code": None,
        "rows": [{"axis": row.axis, "subject": row.subject, "value": row.value,
                  "defect": bool(row.defect), "reason": row.reason} for row in view.rows],
        "enforcement_capable": bool(view.enforcement_capable),
        "baseline_ready": bool(view.baseline_ready),
        "continues": list(view.continues),
        "broker": {"status_level": str(broker["status_level"]) if broker else None,
                   "informational": True, "core": "deterministic",
                   "transport": "unavailable", "transport_reason": "Fabric#25"},
    }


def _fabric(report) -> dict:
    from . import edge_loop_status

    try:
        result = edge_loop_status.fabric_status_result(report)
    except Exception:  # noqa: BLE001 - optional presentation cannot stop status
        return {"status": "internal_error", "reason_code": "internal_error", "version": None}
    match = _FABRIC_PROJECTED.fullmatch(result)
    if match:
        return {"status": "projected", "reason_code": None, "version": match.group(1)}
    if result in _FABRIC_FIXED:
        code = _FABRIC_FIXED[result]
        return {"status": code, "reason_code": ("fabric_extra_not_installed" if code == "not_installed"
                                                else "projection_refused"), "version": None}
    return {"status": "internal_error", "reason_code": "internal_error", "version": None}


def _component(value, now, stale_after, fields, extra=None) -> dict:
    if value is None:
        return {"status": "unavailable", "reason_code": "snapshot_absent_or_refused",
                "source": _absent_source(), "snapshot": None}
    source = _snapshot_source(value, now, stale_after)
    snapshot = _pick(value, fields)
    if extra:
        extra(value, snapshot)
    return {"status": "running" if source["freshness"] == "fresh" else "stale",
            "reason_code": source["reason_code"], "source": source, "snapshot": snapshot}


def _intake_extra(now):
    from .edge_intake import DECOY_REFUSAL_CODES
    from .edge_loop_status import FORWARD_STALE_S

    def extra(value, snapshot):
        refused = value["refused"]
        snapshot["refused"] = dict(refused)
        if "edge_forward" in value:
            forward = _pick(value["edge_forward"], EDGE_FORWARD_FIELDS)
            age = now - forward["reported_at"]
            snapshot["edge_forward"] = forward
            snapshot["edge_forward_freshness"] = {
                "status": "stale" if age > FORWARD_STALE_S or age < -FUTURE_S else "fresh",
                "reported_by": "edge", "age_s": int(age)}
        if "decoy" in value:
            snapshot["decoy"] = _pick(value["decoy"], DECOY_FIELDS)
        snapshot["decoy_status"] = {
            "listening": "decoy" in value, "observer": "nexus", "hardware_evidence": False,
            "refused": {k: v for k, v in refused.items() if k in DECOY_REFUSAL_CODES}}
    return extra


def _recent_extra(value, snapshot):
    rows = []
    for row in value["incidents"]:
        copy = _pick(row, INCIDENT_FIELDS)
        explanation = row["explanation"]
        copy["explanation"] = _pick(explanation, EXPLANATION_FIELDS)
        copy["explanation"]["knowledge_refs"] = [
            _pick(ref, KNOWLEDGE_REF_FIELDS) for ref in explanation["knowledge_refs"]]
        copy["edge_decision"] = {"kind": "would", "action": row["edge_would"],
                                 "executed": False, "decided_by": "edge"}
        copy["execution_result"] = {"status": "none",
                                    "reason_code": "nexus_accepts_observe_only"}
        rows.append(copy)
    snapshot["incidents"] = rows


def _edge_loop(now) -> dict:
    from . import edge_loop_status
    from .incident_explain import CONTENT_LABELS

    base = {"authority": dict(AUTHORITY), "evaluated_at": now}
    try:
        if type(now) not in (int, float):
            return {**base, "status": "unavailable", "reason_code": "clock_unknown"}
        raw = edge_loop_status.read_edge_loop()
        return {
            **base, "status": "read", "reason_code": None,
            "intake": _component(raw["intake"], now, LOOP_STALE_S, INTAKE_FIELDS,
                                 _intake_extra(now)),
            "explainer": _component(raw["explainer"], now, LOOP_STALE_S, EXPLAINER_FIELDS),
            "recent": _component(raw["recent"], now, LOOP_STALE_S, RECENT_FIELDS, _recent_extra),
            "content_labels": dict(CONTENT_LABELS),
        }
    except Exception:  # noqa: BLE001 - presentation only; status continues
        return {**base, "status": "unavailable", "reason_code": "internal_error"}


def _health(report, audit_seen, now, terminal) -> list:
    details = terminal.setdefault("health_details", {})
    entries = []
    for index, check in enumerate(report.health):
        public = check.subject in PUBLIC_HEALTH_SUBJECTS
        status = "unknown" if check.unknown else ("ok" if check.healthy else "failed")
        entry = {"subject": check.subject, "status": status,
                 "detail": check.detail if public else None,
                 "advisory": check.advisory if public else None,
                 "withheld": [] if public else ["detail", "advisory"]}
        if not public:
            details[index] = check.detail
        if check.subject == "systemd units":
            entry["reason_code"] = "service_manager_not_queried"
            entry["source"] = {"kind": "not_queried"}
        elif check.subject == "audit":
            entry["source"] = _audit_source(audit_seen, now)
            entry["reason_code"] = entry["source"]["reason_code"] or (
                "chain_not_verified_at_auditd_start" if status == "failed" else None)
        else:
            entry["reason_code"] = None if status == "ok" else "audit_chain_" + status
            entry["source"] = {"kind": "ledger_verify", "withheld": ["path"]}
        entries.append(entry)
    return entries


def _audit_source(audit_seen, now) -> dict:
    """Where the `audit` line came from: auditd's capacity snapshot (#211)."""
    from .audit_status import STATUS_STALE_S

    if not audit_seen:
        return {"kind": "snapshot", "schema": None, "written_at": None,
                "freshness": "unavailable", "reason_code": "internal_error", "age_s": None}
    value = audit_seen[-1]
    if value is None:
        return _absent_source()
    return _snapshot_source(_pick(value, AUDIT_SOURCE_FIELDS), now, STATUS_STALE_S)


def _next_actions(report, lab_host, terminal) -> list:
    summaries = terminal.setdefault("next_action_summaries", {})
    secrets = [text for text in (terminal.get("profile_reason"),
                                 *terminal.get("health_details", {}).values()) if text]
    actions = []
    for index, action in enumerate(report.next_actions):
        step = None
        if lab_host and action.command:
            step = next((name for command, name in LAB_HOST_STEPS
                         if command in action.command), None)
        withheld = any(text in action.summary for text in secrets)
        if withheld:
            summaries[index] = action.summary
        actions.append({"summary": None if withheld else action.summary,
                        "command": action.command,
                        "lab_host_unavailable_step": step,
                        "withheld": ["summary"] if withheld else []})
    return actions


def build(
    report,
    *,
    edge=None,
    knowledge: Optional[dict] = None,
    integration=None,
    as_of: str,
    wall_now: str,
    audit_seen: Optional[list] = None,
    probe: str = "not_read",
    boot_id: str = "not_read",
    preamble: str = "",
) -> StatusView:
    """Project what `status` read into the read model and its terminal half.

    `as_of` is the instant the screen is evaluated at (`--as-of`, or the wall
    clock the command line read); `wall_now` is the wall clock, which the
    integration broker has always been asked at. `audit_seen` is the list
    `cli._health_reports` appended auditd's snapshot to, so the `audit` line
    and its source come from one read. `probe` and `boot_id` are fixed codes
    for what reading the probe result and this boot's id came to; `preamble`
    is the text the command printed about them, which only a terminal shows.
    """

    from .lab_host import is_lab_host
    from .mio_status import status_summary as mio_summary

    terminal: dict = {"preamble": preamble}
    now = _epoch(as_of)
    lab_host = is_lab_host()
    broker = None
    if integration is not None:
        from .broker_cli import status_summary as broker_summary
        broker = broker_summary(now=wall_now)
    sections = {
        "profile": _profile(report, terminal),
        "mio": _mio(mio_summary()),
        "capability": _capability(report),
        "enforcement": _enforcement(report, edge),
        "interfaces": _interfaces(report, terminal),
        "external_modules": _modules(report),
        "knowledge_lite": _knowledge(knowledge),
        "edge_core": _edge(edge, probe, boot_id, terminal),
        "integration": _integration(integration, broker),
        "fabric": _fabric(report),
        "edge_loop": _edge_loop(now),
        "health": _health(report, audit_seen, now, terminal),
    }
    sections["next_actions"] = _next_actions(report, lab_host, terminal)
    view = {
        "schema": SCHEMA,
        "as_of": (datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z")
                  if now is not None else None),
        "clock": {"status": "known" if now is not None else "unknown",
                  "reason_code": None if now is not None else "clock_unknown"},
        "lab_host": bool(lab_host),
        "authority": dict(AUTHORITY),
        "sections": sections,
    }
    json.dumps(view, allow_nan=False)  # refuse a value JSON cannot carry, here
    return StatusView(view=view, terminal=terminal)


# -- the text an operator reads ----------------------------------------------


def render_text(status: StatusView, out: TextIO) -> None:
    """The `status` screen, from the read model and its terminal half."""

    terminal, s = status.terminal, status.view["sections"]
    out.write(terminal.get("preamble", ""))
    _text_profile(s["profile"], terminal, out)
    print(file=out)
    from .mio_status import describe
    print(describe(s["mio"]["reading"]), file=out)
    print(file=out)
    capability = s["capability"]
    print(f"CLI baseline capability state: {capability['state']} "
          "(fixed CORE component set; no live provider assessment)", file=out)
    print("    continuing: " + ", ".join(capability["retained"]), file=out)
    if capability["lost"]:
        print("    not available: " + ", ".join(capability["lost"]), file=out)
    print(file=out)
    enforcement = s["enforcement"]
    print("enforcement ready: " + ("yes" if enforcement["enforcement_ready"] else "no"), file=out)
    print("edge-baseline-ready: " + ("yes" if enforcement["edge_baseline_ready"] else "no"),
          file=out)
    if not enforcement["enforcement_ready"]:
        if enforcement["commissioning_record"] == "absent":
            print("    no commissioning record exists on this node", file=out)
        else:
            if enforcement["missing_profiles"]:
                print("    missing profiles: " + ", ".join(enforcement["missing_profiles"]),
                      file=out)
            if enforcement["observe_only"]:
                print("    no interface carries a confirmed role", file=out)
    print(file=out)
    print("interfaces:", file=out)
    _text_interfaces(s["interfaces"], terminal, out)
    print(file=out)
    print("external modules:", file=out)
    for module in s["external_modules"]:
        print(f"    {module['name']}: {module['state']} -- {module['reason']}", file=out)
    print(file=out)
    if s["knowledge_lite"]["status"] != "not_collected":
        _text_knowledge(s["knowledge_lite"], out)
        print(file=out)
    if s["edge_core"]["status"] != "not_inspected":
        _text_edge(s["edge_core"], terminal, out)
        print(file=out)
    if s["integration"]["status"] != "not_collected":
        _text_integration(s["integration"], out)
        print(file=out)
    _text_fabric(s["fabric"], out)
    _text_edge_loop(s["edge_loop"], out)
    print(file=out)
    _text_health(s["health"], terminal, out)
    print(file=out)
    print("next:", file=out)
    if not s["next_actions"]:
        print("    nothing is outstanding.", file=out)
    summaries = terminal.get("next_action_summaries", {})
    for index, action in enumerate(s["next_actions"]):
        if action["lab_host_unavailable_step"]:
            print(f"    {action['lab_host_unavailable_step']} step unavailable on a lab host "
                  "(LAB_HOST_MARKER); requires a non-lab deployment", file=out)
            continue
        summary = action["summary"] if action["summary"] is not None else summaries[index]
        print(f"    {summary}", file=out)
        if action["command"]:
            print(f"        {action['command']}", file=out)


def _text_profile(profile, terminal, out) -> None:
    if profile["status"] != "measured":
        print(f"resource profile: not measured -- {terminal['profile_reason']}", file=out)
        return
    print(f"resource profile: {profile['profile']} "
          f"(usable RAM {profile['usable_mib']} MiB, as the OS reports it)", file=out)
    print("    a profile is an upper bound. It grants no NIC role, no capture, "
          "no enforcement and no external connection.", file=out)


def _text_interfaces(section, terminal, out) -> None:
    if not section["items"]:
        print("No interfaces were read from this host.", file=out)
        return
    facts = terminal.get("interface_facts", {})
    for item in section["items"]:
        print(f"{item['handle']}  {item['state']}", file=out)
        print(f"    {facts[item['handle']]}", file=out)
        for reason in item["blocked_by"]:
            print(f"    blocked: {reason}", file=out)


def _text_knowledge(section, out) -> None:
    readiness = section["readiness"]
    print("Knowledge Lite: " + readiness["word"], file=out)
    print(f"    state: {section['status']}", file=out)
    print(f"    reason: {section['reason_code']}", file=out)
    print(f"    generation: {section['generation']}", file=out)
    print(f"    freshness: {section['freshness']}", file=out)
    print("    cryptographic implementation: not supported (Nexus#70 review pending)", file=out)
    print(f"    functional means: {readiness['means']}", file=out)
    for limit in readiness["does_not_mean"]:
        print(f"    it does not mean: {limit}", file=out)


def _text_edge(section, terminal, out) -> None:
    where = terminal.get("edge_root") or "no package root configured"
    print(f"edge core (local): {section['status']}  [{where}]", file=out)
    reasons = terminal.get("edge_finding_reasons", [])
    for finding, reason in zip(section["findings"], reasons):
        mark = "  SECURITY FINDING" if finding["security"] else ""
        print(f"    {finding['check']}: {finding['evidence']}{mark}", file=out)
        print(f"        {reason}", file=out)
    issuer = section["issuer"]
    if issuer is not None:
        private = terminal.get("edge_issuer", {})
        print("    digest_verified: " + ("yes" if issuer["digest_verified"] else "no"), file=out)
        named = f", issuer {private.get('issuer')}" if private.get("issuer") else ""
        print("    issuer_authenticated: "
              + ("yes" if issuer["issuer_authenticated"] else "no")
              + f" ({issuer['issuer_status']}{named})", file=out)
        print(f"        {issuer['issuer_reason']}", file=out)
        sequence = private.get("revocation_sequence")
        sequence = f", sequence {sequence}" if sequence is not None else ""
        print(f"    revocation: {issuer['revocation_status']}{sequence}"
              f" (revoked: {issuer['revoked']})", file=out)
        floor = private.get("floor_version")
        floor = f", floor {floor}" if floor else ""
        print(f"    rollback floor: {issuer['floor_status']}{floor}", file=out)
        if issuer["notes"]:
            print("    issuer notes (no effect on acceptance): "
                  + ", ".join(issuer["notes"]), file=out)
    for caveat in terminal.get("edge_caveats", []):
        print(f"    caveat: {caveat}", file=out)


def _text_integration(section, out) -> None:
    print("integration:", file=out)
    for row in section["rows"]:
        subject = f" [{row['subject']}]" if row["subject"] else ""
        marker = "  DEFECT" if row["defect"] else ""
        print(f"    {row['axis']}{subject}: {row['value']}{marker}", file=out)
        print(f"        {row['reason']}", file=out)
    print(file=out)
    print(f"enforcement capable: {'yes' if section['enforcement_capable'] else 'no'}", file=out)
    print(f"baseline ready: {'yes' if section['baseline_ready'] else 'no'}", file=out)
    print("continuing regardless: " + ", ".join(section["continues"]), file=out)
    print("Integration broker (informational): " + section["broker"]["status_level"]
          + "; Core deterministic; transport unavailable: Fabric#25", file=out)


def _text_fabric(section, out) -> None:
    status = section["status"]
    if status == "internal_error":
        print("fabric status view: unavailable (internal)", file=out)
    elif status == "projected":
        print(f"fabric status view: projected (v{section['version']})", file=out)
    elif status == "not_installed":
        print("fabric status view: not available (extra not installed)", file=out)
    else:
        print("fabric status view: refused (projection_refused)", file=out)


def _text_edge_loop(section, out) -> None:
    from .edge_loop_status import render_edge_loop

    if section["status"] != "read":
        print("edge loop: unavailable (internal)", file=out)
        return
    render_edge_loop(out, now=section["evaluated_at"], snapshots={
        name: section[name]["snapshot"] for name in ("intake", "explainer", "recent")})


def _text_health(entries, terminal, out) -> None:
    details = terminal.get("health_details", {})
    print("health:", file=out)
    for index, entry in enumerate(entries):
        mark = {"ok": "ok", "failed": "FAILED"}.get(entry["status"], "unknown")
        detail = entry["detail"] if entry["detail"] is not None else details[index]
        print(f"    {entry['subject']}: {mark} -- {detail}", file=out)
