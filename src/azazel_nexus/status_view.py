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
  label) and finding reasons that can carry either, and every fixed sentence
  that names a path (an install path, a document). The text rendering has
  always shown them and still does; the read model marks each one it leaves
  out under `withheld` and carries a code beside it.

Values are checked against their vocabulary again here, not only by the
readers: a code-keyed map (`refused`), a code list (`failure_codes`), the
M.I.O. reasons, Knowledge Lite's words. Anything outside refuses that part of
the view (`snapshot_refused_by_view`, `reading_refused`). An integer beyond
JavaScript's exact range is `too_large`, and an age beyond ten years is
`null` with `age_out_of_range`.

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

`build` reads what `status` has always read (the M.I.O. route ledger, the
broker's local state, the loop snapshots), each once and through its
existing reader, and the operator snapshots of U2 (`operator_snapshots`:
Knowledge Lite's and entryd's status, the packaged units' states, and the
free space under fixed labels) and of U3 (`noc_status`: the passive NOC
observation). Those five sections are in the read model only; the text
screen is unchanged. Nothing here opens a socket, starts a
process or writes a file, and nothing here decides anything.
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
#: The M.I.O. route ledger records transitions (and carries the last one into
#: each daily segment with its original time), so an unchanged reading ages
#: legitimately: how long it has been unchanged (`age_s`) is shown and never
#: judged. What is judged is whether entryd, the ledger's writer, is shown to
#: be alive (`liveness`). Its operator snapshot (`mio-status/v1`, rewritten
#: every minute from the serve loop) is the primary evidence, against its own
#: `MIO_STALE_S`; the route ledger's newest capability record (a transition,
#: or the carried record a day's first write opens a segment with) is the
#: secondary evidence, against this limit. Neither within its limit: stale.
#: Option 1 of the re-review, the default until the owner changes it (#358).
MIO_OBSERVATION_STALE_S = 2 * 86400
#: An age beyond this is not a clock skew but a value nobody can act on.
MAX_AGE_S = 10 * 365 * 86400
#: The largest integer a JavaScript reader holds exactly.
MAX_SAFE_INTEGER = 2**53 - 1
#: What a counter beyond `MAX_SAFE_INTEGER` is replaced with in the view.
TOO_LARGE = "too_large"

#: Every `reason_code` the view can carry. A code outside it is a defect.
REASON_CODES = frozenset({
    "nexus_accepts_observe_only", "profile_not_measured", "no_recorded_capability_transition",
    "route_ledger_unreadable_or_refused", "reading_refused", "observed_at_in_future",
    "liveness_evidence_expired", "liveness_evidence_in_future", "snapshot_reading_differs",
    "route_record_expired", "route_record_in_future", "operator_snapshot_present",
    "observed_at_unreadable", "clock_unknown",
    "no_commissioning_record", "commissioning_incomplete", "no_interfaces_read",
    "not_collected", "not_inspected", "checks_not_all_passed", "fabric_extra_not_installed",
    "projection_refused", "internal_error", "snapshot_absent_or_refused",
    "snapshot_dated_in_future", "snapshot_expired", "snapshot_refused_by_view",
    "chain_broken", "storage_failed", "service_manager_not_queried",
    "chain_not_verified_at_auditd_start", "audit_chain_failed", "audit_chain_unknown",
    "nexus_70_review_pending", "age_out_of_range", "audit_capacity_warning",
    # The operator snapshots (U2): their own words, beside Knowledge Lite's.
    "capability_record_uncertain", "unit_failed", "unit_state_unread",
    "no_location_measured", "status_unrecognised",
    # The NOC section (U3).
    "collection_failed", "active_check_not_performed", "role_evidence_not_provided",
    # The operator_view section (S-04, `operator_view_source`).
    "inputs_not_all_read", "not_read", "catalog_permission_denied", "catalog_refused",
    "catalog_absent", "catalog_unsigned", "catalog_invalid", "catalog_unreadable",
})
#: Knowledge Lite's closed status shape (`lite_import.status_summary`).
KNOWLEDGE_STATES = frozenset({"available", "stale", "unavailable", "quarantined"})
KNOWLEDGE_REASONS = KNOWLEDGE_STATES | frozenset({
    "trust_unreadable", "unverified", "no_bundle", "store_unreadable", "bundle_refused",
    "revoked", "state_untrusted"})
KNOWLEDGE_FRESHNESS = frozenset({"current", "stale", "absent"})
#: The verified bundle's display facts `knowledge.status` adds (#362), and
#: the names they carry in the view's `bundle`. All null unless a trusted
#: bundle was read.
KNOWLEDGE_BUNDLE_FIELDS = (("bundle_digest_short", "digest_short"),
                           ("signer_key_ids", "signer_key_ids"),
                           ("static_count", "static_count"),
                           ("current_count", "current_count"),
                           ("next_expiry", "next_expiry"))

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
                      "content_kind", "notice", "knowledge_refs_omitted", "guidance")
#: A citation as `read_recent_incidents` checks it: the three keys every row
#: has (a row written before #362 has only these), and the display fields
#: that say where it came from. Each is checked again here; a citation whose
#: dataset citation names a path is withheld (`withheld: ["citation"]`).
KNOWLEDGE_REF_FIELDS = ("technique_id", "name", "claim_id")
KNOWLEDGE_REF_DISPLAY_FIELDS = ("bundle_digest_short", "generation", "freshness", "as_of",
                                "citation", "citation_state")
AUDIT_CAPACITY_FIELDS = ("chain_verified", "chain_bytes", "segments", "filesystem_free_bytes",
                         "warning", "warning_reasons", "warn_chain_bytes", "warn_free_bytes",
                         "rate_limit_summaries_dropped")
ISSUER_LABEL_FIELDS = ("digest_verified", "issuer_authenticated", "issuer_status",
                       "revocation_status", "revoked", "floor_status", "notes")
MIO_REASON_KEYS = frozenset({"profile", "resource", "trust", "health", "topology"})

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
#: Fixed text that names a file or a path (an install path, a document) is
#: kept for the terminal; the view carries the code beside it instead.
_PATHISH = re.compile(r"(?:^|[\s(\[`'\"])(?:/|[\w.-]+/)[\w./-]*")
_INCIDENT_ID = re.compile(r"inc-[0-9a-f]{16}")
_DIGEST_SHORT = re.compile(r"sha256:[0-9a-f]{12}")
_UTC_SECONDS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", re.ASCII)


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


class _Refused(ValueError):
    """A value outside the vocabulary the view copies."""


def _require(condition) -> None:
    if not condition:
        raise _Refused("refused")


#: Closed vocabularies for the recent row's Full Node Context availability
#: (`local_advisory.read_fast_assistance` and `incident_explain` projection).
FULL_NODE_STATUS_WORDS = frozenset({"unknown", "not_queried", "received", "unavailable"})
KNOWLEDGE_DEPENDENCY_WORDS = frozenset({"available", "partial", "absent", "not_queried", "timeout",
                                        "expired", "rejected", "unavailable", "unknown"})


def _fast_assistance_availability(fast) -> dict:
    """Only the two closed words the UI needs to say why Knowledge was not used."""
    node = fast.get("full_node_context")
    status = node.get("full_node_context_status") if isinstance(node, dict) else None
    dependency = fast.get("dependency_outcome")
    knowledge = dependency.get("knowledge") if isinstance(dependency, dict) else None
    return {"full_node_context_status": status if status in FULL_NODE_STATUS_WORDS else "unknown",
            "knowledge_dependency": knowledge if knowledge in KNOWLEDGE_DEPENDENCY_WORDS else "unknown"}


def _pick(value: dict, fields) -> dict:
    return {key: _plain(value[key]) for key in fields if key in value}


def _plain(value):
    """A detached copy of a checked JSON value (dicts, lists, scalars).

    An integer a JavaScript reader cannot hold exactly becomes `too_large`
    rather than a different number.
    """
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if type(value) is int and abs(value) > MAX_SAFE_INTEGER:
        return TOO_LARGE
    if isinstance(value, float) and not math.isfinite(value):
        raise _Refused("non-finite")
    return value


def _free(terminal, key, text):
    """Fixed text for the view, unless it names a path; the terminal keeps it all."""
    terminal.setdefault("text", {})[key] = text
    if text is None or _PATHISH.search(str(text)):
        return None
    return text


def _text(terminal, key):
    return terminal["text"][key]


def _codes(mapping, allowed) -> dict:
    """A count per fixed code; any other key or value refuses the copy."""
    _require(type(mapping) is dict)
    for code, count in mapping.items():
        _require(code in allowed and type(count) is int and count >= 0)
    return _plain(mapping)


def _epoch(as_of: Optional[str]) -> Optional[float]:
    try:
        return datetime.fromisoformat(as_of).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _age(now, then) -> tuple[Optional[int], Optional[str]]:
    age = now - then
    if not math.isfinite(age) or abs(age) > MAX_AGE_S:
        return None, "age_out_of_range"
    return int(age), None


def _freshness(written_at, now, stale_after) -> tuple[str, Optional[str], Optional[int], Optional[str]]:
    """`(status, reason_code, age_s, age_reason)` of a snapshot against the status clock."""
    if type(now) not in (int, float):
        return "unknown", "clock_unknown", None, None
    age, age_reason = _age(now, written_at)
    if written_at > now + FUTURE_S:
        return "stale", "snapshot_dated_in_future", age, age_reason
    if now - written_at > stale_after:
        return "stale", "snapshot_expired", age, age_reason
    return "fresh", None, max(0, age), None


def _snapshot_source(value, now, stale_after) -> dict:
    status, reason, age, age_reason = _freshness(value["written_at"], now, stale_after)
    return {"kind": "snapshot", "schema": value["schema"], "written_at": value["written_at"],
            "freshness": status, "reason_code": reason, "age_s": age, "age_reason": age_reason}


def _absent_source() -> dict:
    return {"kind": "snapshot", "schema": None, "written_at": None, "freshness": "unavailable",
            "reason_code": "snapshot_absent_or_refused", "age_s": None, "age_reason": None}


def _profile(report, terminal) -> dict:
    reading = report.profile.reading
    source = {"kind": "os_reading", "reader": "resource_profile.take_reading"}
    if reading is None:
        terminal["profile_reason"] = report.profile.reason
        return {"status": "not_measured", "reason_code": "profile_not_measured",
                "profile": None, "usable_mib": None, "source": source, "withheld": ["reason"]}
    return {"status": "measured", "reason_code": None, "profile": reading.profile.value,
            "usable_mib": _plain(reading.usable_mib), "source": source, "withheld": []}


def _mio_reading(summary: dict) -> dict:
    """The route-ledger reading, checked against its own vocabulary, or refused."""
    from .capability import CapabilityState
    from .edge_package import Evidence
    from .mio_status import HEALTH_REASONS, NOTICE, RESOURCE_REASONS, TOPOLOGY_REASONS, UNKNOWN

    levels = {state.value for state in CapabilityState}
    _require(type(summary) is dict and summary.get("source") == "route-ledger"
             and summary.get("notice") == NOTICE)
    availability = summary.get("availability")
    if summary.get("state") is None:
        _require(summary.get("ceiling") is None and summary.get("observed_at") is None
                 and summary.get("reasons") == {}
                 and availability in (UNKNOWN, "unknown (no recorded capability transition)"))
    else:
        reasons = summary.get("reasons")
        _require(availability == "last recorded observation"
                 and summary["state"] in levels and summary.get("ceiling") in levels
                 and type(reasons) is dict and set(reasons) == MIO_REASON_KEYS
                 and reasons["profile"] in levels
                 and reasons["resource"] in RESOURCE_REASONS
                 and reasons["trust"] in {value.value for value in Evidence}
                 and reasons["topology"] in TOPOLOGY_REASONS
                 and type(reasons["health"]) is dict
                 and set(reasons["health"]) == {"local", "remote"}
                 and all(v in HEALTH_REASONS for v in reasons["health"].values())
                 and type(summary.get("observed_at")) is str)
    return {key: _plain(summary[key]) for key in
            ("ceiling", "state", "reasons", "source", "observed_at", "availability", "notice")}


def _mio(summary: dict, now, terminal, snapshot_section=None) -> dict:
    from .mio_status import NOTICE, UNKNOWN

    liveness = None
    age, age_reason = None, None
    try:
        reading = _mio_reading(summary)
    except (_Refused, KeyError, TypeError):
        reading = {"ceiling": None, "state": None, "reasons": {}, "source": "route-ledger",
                   "observed_at": None, "availability": UNKNOWN, "notice": NOTICE}
        status, reason = "unknown", "reading_refused"
    else:
        if reading["state"] is None:
            status, reason = "unknown", (
                "no_recorded_capability_transition"
                if reading["availability"] != UNKNOWN else "route_ledger_unreadable_or_refused")
        else:
            status, reason, age, age_reason, liveness = _mio_freshness(
                reading, summary.get("recorded_at"), now, snapshot_section)
    terminal["mio_reading"] = reading
    public = dict(reading)
    public["availability"] = _free(terminal, "mio.availability", reading["availability"])
    public["notice"] = _free(terminal, "mio.notice", reading["notice"])
    return {"status": status, "reason_code": reason, "reading": public,
            # How long the reading has been unchanged: information, never a verdict.
            "age_s": age, "age_reason": age_reason,
            "liveness": liveness if liveness is not None else {
                **_no_liveness(), "reason_code": reason},
            "source": {"kind": "route_ledger", "reader": "mio_status.status_summary",
                       "observed_at": reading["observed_at"]}}


def _no_liveness() -> dict:
    """Liveness when there is no recorded reading to vouch for: not judged."""
    return {"status": "unknown", "reason_code": "no_recorded_capability_transition",
            "evidence": None, "operator_snapshot": None, "route_ledger_record": None}


def _when(text) -> Optional[float]:
    """Epoch seconds of a zoned ISO time, or `None`."""
    try:
        when = datetime.fromisoformat(text)
        _require(when.tzinfo is not None)
        return when.timestamp()
    except (_Refused, ValueError, TypeError, OverflowError):
        return None


def _snapshot_evidence(reading, section, now) -> dict:
    """Whether entryd's operator snapshot vouches for *this* reading now.

    Counted only when it is fresh against `MIO_STALE_S`, holds a settled
    record, and that record is the reading the ledger gave: a snapshot of a
    different reading says entryd is alive, not that this reading is current.
    """
    from .operator_snapshots import MIO_STALE_S

    entry = {"status": "not_counted", "reason_code": "snapshot_absent_or_refused",
             "written_at": None, "age_s": None, "stale_after_s": MIO_STALE_S}
    if not isinstance(section, dict) or not isinstance(section.get("source"), dict):
        entry["reason_code"] = "internal_error"
        return entry
    snapshot, source = section.get("snapshot"), section["source"]
    if snapshot is None:
        entry["reason_code"] = source.get("reason_code") or "snapshot_absent_or_refused"
        return entry
    entry.update(written_at=source.get("written_at"), age_s=source.get("age_s"))
    if source.get("freshness") != "fresh":
        entry["reason_code"] = source.get("reason_code") or "snapshot_expired"
        return entry
    if not snapshot.get("recorded"):
        entry["reason_code"] = "no_recorded_capability_transition"
    elif snapshot.get("record_uncertain") is not False:
        entry["reason_code"] = "capability_record_uncertain"
    elif (snapshot.get("state"), snapshot.get("reasons")) != (reading["state"], reading["reasons"]) \
            or _when(snapshot.get("observed_at")) != _when(reading["observed_at"]):
        entry["reason_code"] = "snapshot_reading_differs"
    else:
        entry.update(status="counted", reason_code=None)
    return entry


def _utc(epoch) -> Optional[str]:
    try:
        return datetime.fromtimestamp(epoch, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _record_evidence(observed, recorded_at, now) -> dict:
    """Whether the route ledger's newest capability record is recent enough.

    Only consulted when entryd's snapshot cannot be read (`_mio_freshness`).
    The record's own write time (`recorded_at`: a carried record's day, a
    transition's observation) when the reader gave a zoned one no earlier
    than the observation; otherwise the observation time, which entryd also
    wrote. Never a time later than the ledger holds.
    """
    recorded = _when(recorded_at)
    if recorded is None or recorded < observed:
        recorded, recorded_at = observed, None
    age, _ = _age(now, recorded)
    entry = {"status": "counted", "reason_code": None,
             "recorded_at": _utc(recorded),
             "basis": "record_written" if recorded_at is not None else "observation",
             "age_s": age, "stale_after_s": MIO_OBSERVATION_STALE_S}
    if recorded > now + FUTURE_S:
        entry.update(status="not_counted", reason_code="route_record_in_future")
    elif now - recorded > MIO_OBSERVATION_STALE_S:
        entry.update(status="not_counted", reason_code="route_record_expired")
    return entry


def _mio_freshness(reading, recorded_at, now, snapshot_section):
    """`(status, reason, age_s, age_reason, liveness)` of a recorded reading.

    The order is the safe side's: an unknown clock, an unreadable or future
    observation, then any evidence dated in the future (a clock that went
    back), then evidence that entryd is alive. Nothing here is a green word:
    `recorded` says a reading exists and its writer is shown to be alive.
    """
    if type(now) not in (int, float):
        return "unknown", "clock_unknown", None, None, {
            **_no_liveness(), "reason_code": "clock_unknown"}
    then = _when(reading["observed_at"])
    if then is None:
        return "unknown", "observed_at_unreadable", None, None, {
            **_no_liveness(), "reason_code": "observed_at_unreadable"}
    age, age_reason = _age(now, then)
    if then > now + FUTURE_S:
        # A negative age is no period anybody can read: none is given.
        return "stale", "observed_at_in_future", None, age_reason, {
            **_no_liveness(), "reason_code": "observed_at_in_future"}
    age = None if age is None else max(0, age)
    snapshot = _snapshot_evidence(reading, snapshot_section, now)
    record = _record_evidence(then, recorded_at, now)
    liveness = {"status": "not_evidenced", "reason_code": None, "evidence": None,
                "operator_snapshot": snapshot, "route_ledger_record": record}
    in_future = (snapshot["reason_code"] == "snapshot_dated_in_future"
                 or record["reason_code"] == "route_record_in_future")
    # The ledger record is the fallback for a node whose snapshot cannot be
    # read (absent, refused, not built). When entryd's snapshot is there,
    # it alone speaks for the writer: an expired one is a stopped writer, and
    # a fresh one that does not count (no record, an uncertain record,
    # another reading) does not vouch for this reading -- a record up to two
    # days old must not keep a stopped or diverged entryd looking alive.
    if (isinstance(snapshot_section, dict) and snapshot_section.get("snapshot") is not None
            and record["status"] == "counted"):
        record.update(status="not_counted", reason_code="operator_snapshot_present")
    if in_future:
        liveness["reason_code"] = "liveness_evidence_in_future"
    elif snapshot["status"] == "counted" or record["status"] == "counted":
        liveness.update(status="evidenced", evidence=(
            "operator_snapshot" if snapshot["status"] == "counted" else "route_ledger_record"))
        return "recorded", None, age, age_reason, liveness
    else:
        liveness["reason_code"] = "liveness_evidence_expired"
    return "stale", liveness["reason_code"], age, age_reason, liveness


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


def _modules(report, terminal) -> list:
    entries = []
    for index, m in enumerate(report.modules):
        reason = _free(terminal, f"module.{index}", m.reason)
        entries.append({"name": m.name, "state": m.state.value, "reason": reason,
                        "working": bool(m.working),
                        "withheld": [] if reason is not None or m.reason is None else ["reason"]})
    return entries


def _knowledge(reading: Optional[dict], terminal) -> dict:
    from .functional_readiness import readiness_for

    if reading is None:
        return {"status": "not_collected", "reason_code": "not_collected"}
    readiness = readiness_for("knowledge_lite")
    generation = reading["generation"]
    withheld = []
    terminal["knowledge_words"] = (reading["state"], reading["reason_code"], reading["freshness"])
    words_known = (reading["state"] in KNOWLEDGE_STATES
                   and reading["reason_code"] in KNOWLEDGE_REASONS
                   and reading["freshness"] in KNOWLEDGE_FRESHNESS)
    if not words_known:
        # The integration view quotes these words in its knowledge rows.
        terminal.setdefault("untrusted", []).extend(
            str(word) for word in terminal["knowledge_words"])
    if not (generation is None or (type(generation) is int and 0 <= generation <= MAX_SAFE_INTEGER)
            or (type(generation) is str and _GENERATION.fullmatch(generation))):
        withheld.append("generation")
    terminal["knowledge_generation"] = generation
    means = _free(terminal, "knowledge.means", readiness.means)
    limits = [_free(terminal, f"knowledge.does_not_mean.{i}", text)
              for i, text in enumerate(readiness.does_not_mean)]
    terminal["knowledge_limits"] = len(limits)
    if means is None:
        withheld.append("readiness.means")
    if None in limits:
        withheld.append("readiness.does_not_mean")
    bundle = _knowledge_bundle(reading, words_known, withheld, terminal)
    return {
        "status": reading["state"] if words_known else "unknown",
        "reason_code": reading["reason_code"] if words_known else "reading_refused",
        "generation": None if "generation" in withheld or not words_known else generation,
        "freshness": reading["freshness"] if words_known else None,
        "bundle": bundle,
        "readiness": {"functional": bool(readiness.functional),
                      "word": "functional" if readiness.functional else readiness.value,
                      "means": means, "does_not_mean": limits},
        "cryptographic_implementation": {"status": "not_supported",
                                         "reason_code": "nexus_70_review_pending"},
        "source": {"kind": "store_read", "reader": "lite_import.status_summary",
                   "written_at": None, "trust": "commissioned_trust_root"},
        "withheld": withheld,
    }


def _knowledge_bundle(reading: dict, words_known: bool, withheld: list, terminal) -> Optional[dict]:
    """The verified bundle's display facts, each checked again; else `None`.

    A reading in the older four-key shape, or one that describes no bundle,
    has none. Facts beside a state that has no trusted bundle, or outside
    their shape, are withheld rather than copied. Signing key ids are the
    operator's own names for anchors; one that names a path is kept for the
    terminal only, like any other path.
    """
    raw = {name: reading.get(key) for key, name in KNOWLEDGE_BUNDLE_FIELDS}
    described = any(value is not None for value in raw.values())
    terminal["knowledge_bundle"] = described
    if not described:
        return None
    if not (words_known and reading["state"] in ("available", "stale")):
        withheld.extend(f"bundle.{name}" for _, name in KNOWLEDGE_BUNDLE_FIELDS)
        return None
    signers = raw["signer_key_ids"]
    checked = {
        "digest_short": type(raw["digest_short"]) is str
        and _DIGEST_SHORT.fullmatch(raw["digest_short"]) is not None,
        "signer_key_ids": type(signers) is list and len(signers) <= 8 and all(
            type(k) is str and 0 < len(k) <= 128 and k.isprintable() for k in signers),
        "static_count": type(raw["static_count"]) is int and raw["static_count"] >= 0,
        "current_count": type(raw["current_count"]) is int and raw["current_count"] >= 0,
        "next_expiry": raw["next_expiry"] is None or (
            type(raw["next_expiry"]) is str
            and _UTC_SECONDS.fullmatch(raw["next_expiry"]) is not None),
    }
    if checked["signer_key_ids"]:
        terminal["knowledge_signers"] = list(signers)
        if any(_PATHISH.search(k) for k in signers):
            checked["signer_key_ids"] = False
    bundle = {}
    for _, name in KNOWLEDGE_BUNDLE_FIELDS:
        bundle[name] = _plain(raw[name]) if checked[name] else None
        if not checked[name]:
            withheld.append(f"bundle.{name}")
    return bundle


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
        reason = _free(terminal, "edge.issuer_reason", edge.issuer.issuer_reason)
        issuer = {**{key: _plain(labels[key]) for key in ISSUER_LABEL_FIELDS},
                  "issuer_reason": reason,
                  "withheld": ["issuer", "revocation_sequence", "floor_version"]
                  + ([] if reason is not None else ["issuer_reason"])}
        terminal["edge_issuer"] = {"issuer": edge.issuer.issuer,
                                   "revocation_sequence": edge.issuer.revocation_sequence,
                                   "floor_version": edge.issuer.floor_version}
    caveats = []
    for c in edge.caveats:
        shown = c if c in known_caveats and not _PATHISH.search(c) else None
        caveats.append({"text": shown, "withheld": [] if shown is not None else ["text"]})
    return {
        "status": edge.presence.value,
        "reason_code": None if edge.ready else "checks_not_all_passed",
        "ready": bool(edge.ready),
        "root_configured": bool(edge.root),
        "findings": [{"check": f.check, "evidence": f.evidence.value,
                      "security": bool(f.security), "withheld": ["reason"]}
                     for f in edge.findings],
        "issuer": issuer,
        "caveats": caveats,
        "probe": {"result": probe_code, "boot_id": boot_code,
                  "observed_at": edge.probe.observed_at if edge.probe else None},
        "source": {"kind": "package_files_and_probe_result",
                   "reader": "edge_package.inspect", "probe_reader": "edge_package.load_probe_result"},
        "withheld": ["root"],
    }


def _integration(view, broker: Optional[dict], terminal) -> dict:
    if view is None:
        return {"status": "not_collected", "reason_code": "not_collected"}
    rows = []
    for index, row in enumerate(view.rows):
        reason = _free(terminal, f"integration.{index}", row.reason)
        if reason is not None and any(word in reason for word in terminal.get("untrusted", ())):
            reason = None
        rows.append({"axis": row.axis, "subject": row.subject, "value": row.value,
                     "defect": bool(row.defect), "reason": reason,
                     "withheld": [] if reason is not None else ["reason"]})
    level = str(broker["status_level"]) if broker else None
    return {
        "status": "reported", "reason_code": None,
        "rows": rows,
        "enforcement_capable": bool(view.enforcement_capable),
        "baseline_ready": bool(view.baseline_ready),
        "continues": list(view.continues),
        "broker": {"status_level": level if level in ("CORE", "LITE") else None,
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


def _component(value, now, stale_after, fields, *, schema, extra=None, flags=()) -> dict:
    """One loop snapshot: its source, its words, and its allowlisted copy.

    `flags` are the reader-checked booleans that make a running component
    `degraded`: listed in `conditions`, and the first is the reason code.
    """
    if value is None:
        return {"status": "unavailable", "reason_code": "snapshot_absent_or_refused",
                "conditions": [], "source": _absent_source(), "snapshot": None}
    try:
        _require(value["schema"] == schema)
        source = _snapshot_source(value, now, stale_after)
        snapshot = _pick(value, fields)
        if extra:
            extra(value, snapshot)
    except (_Refused, KeyError, TypeError, ValueError):
        return {"status": "unavailable", "reason_code": "snapshot_refused_by_view",
                "conditions": [], "source": {**_absent_source(),
                                             "reason_code": "snapshot_refused_by_view"},
                "snapshot": None}
    conditions = [flag for flag in flags if value.get(flag) is True]
    if source["freshness"] != "fresh":
        status, reason = ("unknown" if source["freshness"] == "unknown" else "stale",
                          source["reason_code"])
    elif conditions:
        status, reason = "degraded", conditions[0]
    else:
        status, reason = "running", None
    return {"status": status, "reason_code": reason, "conditions": conditions,
            "source": source, "snapshot": snapshot}


def _intake_extra(now):
    from .edge_intake import DECOY_REFUSAL_CODES, REFUSAL_CODES
    from .edge_loop_status import FORWARD_STALE_S

    def extra(value, snapshot):
        refused = _codes(value["refused"], REFUSAL_CODES)
        snapshot["refused"] = refused
        if "edge_forward" in value:
            forward = _pick(value["edge_forward"], EDGE_FORWARD_FIELDS)
            age, age_reason = _age(now, value["edge_forward"]["reported_at"])
            stale = age is None or age > FORWARD_STALE_S or age < -FUTURE_S
            snapshot["edge_forward"] = forward
            snapshot["edge_forward_freshness"] = {
                "status": "stale" if stale else "fresh", "reported_by": "edge",
                "age_s": age, "age_reason": age_reason}
        if "decoy" in value:
            snapshot["decoy"] = _pick(value["decoy"], DECOY_FIELDS)
        snapshot["decoy_status"] = {
            "listening": "decoy" in value, "observer": "nexus", "hardware_evidence": False,
            "refused": {k: v for k, v in refused.items() if k in DECOY_REFUSAL_CODES}}
    return extra


def _explainer_extra(value, snapshot):
    from .incident_explain import CODES, RECOVERY_HINT

    snapshot["refused"] = _codes(value["refused"], CODES)
    _require(value["recovery_hint"] in (None, RECOVERY_HINT))


def _recent_extra(value, snapshot, now=None):
    from .edge_intake import ACTIONS
    from .incident_explain import (
        CITATION_STATES, CODES, CONTENT_KINDS, LEGACY_HANDOFF, POLICY_REASONS, SHOWN_STATES,
        full_node_reference_state,
    )
    from .lite_import import TECHNIQUE_ID
    from .local_advisory import HANDOFF_NOTICE

    rows = []
    for row in value["incidents"]:
        _require(_INCIDENT_ID.fullmatch(row["incident_id"]) and row["state"] in ("open", "closed")
                 and row["edge_would"] in ACTIONS
                 and row["policy_reason"] in POLICY_REASONS | {"other"}
                 and all(TECHNIQUE_ID.fullmatch(t) for t in row["technique_ids"]))
        explanation = row["explanation"]
        _require(explanation["state"] in {"pending", "unavailable"} | SHOWN_STATES
                 and explanation["route"] in ("local", "deterministic handoff", "unavailable")
                 and explanation.get("content_kind", "none") in (*CONTENT_KINDS, LEGACY_HANDOFF)
                 and explanation.get("notice", HANDOFF_NOTICE["en"]) in HANDOFF_NOTICE.values()
                 and all(code in CODES for code in explanation["failure_codes"]))
        for ref in explanation["knowledge_refs"]:
            _require(TECHNIQUE_ID.fullmatch(ref["technique_id"])
                     and ref["claim_id"] == ref["technique_id"])
            if set(ref) != set(KNOWLEDGE_REF_FIELDS):
                _require(set(ref) == set(KNOWLEDGE_REF_FIELDS + KNOWLEDGE_REF_DISPLAY_FIELDS)
                         and type(ref["bundle_digest_short"]) is str
                         and _DIGEST_SHORT.fullmatch(ref["bundle_digest_short"])
                         and type(ref["generation"]) is int and ref["generation"] >= 0
                         and ref["freshness"] in ("static", "current")
                         and type(ref["as_of"]) is str and _UTC_SECONDS.fullmatch(ref["as_of"])
                         and ref["citation_state"] in CITATION_STATES
                         and type(ref["citation"]) is str and len(ref["citation"]) <= 160
                         and bool(ref["citation"]) == (ref["citation_state"] == "shown"))
        omitted = explanation.get("knowledge_refs_omitted", 1)
        _require(type(omitted) is int and 1 <= omitted <= 16)
        copy = _pick(row, INCIDENT_FIELDS)
        # One closed word from the stored trace (never the trace itself), judged at `as_of`.
        copy["full_node_reference"] = full_node_reference_state(
            row.get("full_node_trace"), row["technique_ids"], now)
        copy["explanation"] = _pick(explanation, EXPLANATION_FIELDS)
        if isinstance(explanation.get("fast_assistance"), dict):
            copy["explanation"]["fast_assistance"] = _fast_assistance_availability(
                explanation["fast_assistance"])
        if "guidance" in explanation:
            from .guidance_record import guidance_view, read_guidance
            read_guidance(explanation["guidance"], public=True)
            copy["explanation"]["guidance_view"] = _plain(guidance_view(explanation["guidance"]))
        if "slow_analysis" in explanation:
            # Re-run the strict recent reader before forwarding this bounded projection.
            from .incident_explain import read_recent_incidents
            _require(read_recent_incidents(json.dumps(value).encode()) == value)
            from .incident_explain import public_slow_analysis
            slow = public_slow_analysis(explanation["slow_analysis"], row["incident_id"], now)
            copy["explanation"]["slow_analysis"] = slow
        copy["explanation"]["knowledge_refs"] = [
            _knowledge_ref(ref) for ref in explanation["knowledge_refs"]]
        copy["edge_decision"] = {"kind": "would", "action": row["edge_would"],
                                 "executed": False, "decided_by": "edge"}
        copy["execution_result"] = {"status": "none",
                                    "reason_code": "nexus_accepts_observe_only"}
        rows.append(copy)
    snapshot["incidents"] = rows


def _knowledge_ref(ref: dict) -> dict:
    """One checked citation; a dataset citation that names a path is withheld.

    The text screen renders the loop from this copy, so the operator reads
    `declared, withheld` there too: the citation is producer text, not the
    operator's own path.
    """
    from .incident_explain import citation_names_a_path

    copy = _pick(ref, KNOWLEDGE_REF_FIELDS + KNOWLEDGE_REF_DISPLAY_FIELDS)
    if "citation" in copy:
        copy["withheld"] = []
        # The one rule the builder applies too (R389b-01): any separator.
        if _PATHISH.search(copy["citation"]) or citation_names_a_path(copy["citation"]):
            copy.update(citation="", citation_state="withheld", withheld=["citation"])
    return copy


def _edge_loop(now, reader: str = "operator") -> dict:
    from . import edge_loop_status
    from .edge_intake import STATUS_SCHEMA as INTAKE_SCHEMA
    from .incident_explain import CONTENT_LABELS, RECENT_SCHEMA

    base = {"authority": dict(AUTHORITY), "evaluated_at": now}
    try:
        if type(now) not in (int, float):
            return {**base, "status": "unavailable", "reason_code": "clock_unknown"}
        raw = (edge_loop_status.read_edge_loop() if reader == "operator"
               else edge_loop_status.read_edge_loop(reader))
        return {
            **base, "status": "read", "reason_code": None,
            "intake": _component(raw["intake"], now, LOOP_STALE_S, INTAKE_FIELDS,
                                 schema=INTAKE_SCHEMA, extra=_intake_extra(now),
                                 flags=("storage_failed",)),
            "explainer": _component(raw["explainer"], now, LOOP_STALE_S, EXPLAINER_FIELDS,
                                    schema="azazel-nexus/incident-explain-status/v1",
                                    extra=_explainer_extra,
                                    flags=("chain_broken", "storage_failed")),
            "recent": _component(raw["recent"], now, LOOP_STALE_S, RECENT_FIELDS,
                                 schema=RECENT_SCHEMA, extra=lambda value, snapshot: _recent_extra(value, snapshot, now)),
            "content_labels": dict(CONTENT_LABELS),
        }
    except Exception:  # noqa: BLE001 - presentation only; status continues
        return {**base, "status": "unavailable", "reason_code": "internal_error"}


def _health(report, audit_seen, now, terminal) -> list:
    entries = []
    for index, check in enumerate(report.health):
        status = "unknown" if check.unknown else ("ok" if check.healthy else "failed")
        # `audit chain` comes from the hidden `--ledger`: a path, or exception text.
        public = check.subject in ("systemd units", "audit")
        if not public:
            terminal.setdefault("private_texts", []).append(check.detail)
        detail = _free(terminal, f"health.{index}.detail", check.detail) if public else None
        advisory = _free(terminal, f"health.{index}.advisory", check.advisory) if public else None
        terminal["text"][f"health.{index}.detail"] = check.detail
        withheld = [name for name, shown, original in (
            ("detail", detail, check.detail), ("advisory", advisory, check.advisory))
            if shown is None and original is not None]
        entry = {"subject": check.subject, "status": status, "detail": detail,
                 "advisory": advisory, "advisory_code": None, "withheld": withheld}
        if check.subject == "systemd units":
            entry["reason_code"] = "service_manager_not_queried"
            entry["source"] = {"kind": "not_queried"}
        elif check.subject == "audit":
            try:
                entry["source"], capacity = _audit_source(audit_seen, now)
            except (_Refused, KeyError, TypeError, ValueError):
                # The view refused the snapshot this line was judged from, so
                # nothing it said is carried: not its word, not its sentences.
                entry["source"], capacity = ({**_absent_source(),
                                              "reason_code": "snapshot_refused_by_view"}, None)
                entry.update(status="unknown", detail=None, advisory=None,
                             withheld=[name for name, original in (
                                 ("detail", check.detail), ("advisory", check.advisory))
                                 if original is not None])
                check = None
            entry["capacity"] = capacity
            entry["reason_code"] = entry["source"]["reason_code"] or (
                "chain_not_verified_at_auditd_start" if status == "failed" else None)
            if check is not None and check.advisory:
                entry["advisory_code"] = "audit_capacity_warning"
        else:
            entry["reason_code"] = None if status == "ok" else "audit_chain_" + status
            entry["source"] = {"kind": "ledger_verify", "withheld": ["path"]}
        entries.append(entry)
    return entries


def _audit_source(audit_seen, now) -> tuple[dict, Optional[dict]]:
    """Where the `audit` line came from (auditd's snapshot, #211), and its sizes."""
    from .audit_status import STATUS_STALE_S, WARNING_REASONS

    if not audit_seen:
        return ({**_absent_source(), "reason_code": "internal_error"}, None)
    value = audit_seen[-1]
    if value is None:
        return _absent_source(), None
    capacity = _pick(value, AUDIT_CAPACITY_FIELDS)
    _require(all(code in WARNING_REASONS for code in value["warning_reasons"]))
    capacity["rate_limited_total"] = _plain(sum(value["rate_limited"].values()))
    return _snapshot_source(value, now, STATUS_STALE_S), capacity


# -- operator snapshots (U2) --------------------------------------------------
#
# Written by the daemons that own the facts, into operator-readable leaves,
# so that a non-root reader (this command, the UI) gets the same answer root
# would. `operator_snapshots` holds the strict readers; this copies fields.

#: Allowlists for the three snapshots, beside `schema` and `written_at`.
KNOWLEDGE_SNAPSHOT_FIELDS = ("state", "reason_code", "generation", "freshness")
MIO_SNAPSHOT_FIELDS = ("recorded", "state", "ceiling", "reasons", "observed_at",
                       "record_uncertain")
UNIT_FIELDS = ("unit", "status", "load_state", "active_state", "sub_state", "reason_code")
STORAGE_FIELDS = ("label", "status", "total_bytes", "free_bytes", "available_bytes",
                  "read_only", "same_filesystem_as", "reason_code")

#: `(statvfs, stat)` for the storage section; `None` is the host's own. A
#: test sets it so that every scenario measures the same filesystem.
_storage_probes = None


def _snapshot_section(path, reader, limit, now, stale_after, fields, *,
                      schema: str, writer: str, extra=None, leaf: str = "operator") -> dict:
    from .edge_loop_status import read_snapshot

    value = read_snapshot(path, reader, limit)
    section = _component(value, now, stale_after, ("schema", "written_at", *fields),
                         schema=schema, extra=extra)
    section["source"]["writer"] = writer
    # Which copy was read: the operator group's leaf or the UI's (ADR-0007).
    section["source"]["leaf"] = leaf
    # Freshness is its own item. `status` below never says `running`: a fresh
    # snapshot of a failed unit or of quarantined Knowledge is fresh news of
    # a problem, and each caller turns the snapshot into its own word.
    section["freshness"] = section["source"]["freshness"]
    return section


def _fresh(section) -> bool:
    return section["snapshot"] is not None and section["freshness"] == "fresh"


def _knowledge_status(now, reader: str = "operator") -> dict:
    from . import operator_snapshots as snap
    from .runtime_paths import knowledge_status_path

    section = _snapshot_section(
        knowledge_status_path(reader=reader), snap.read_knowledge_status, snap.KNOWLEDGE_BYTES, now,
        snap.KNOWLEDGE_STALE_S, KNOWLEDGE_SNAPSHOT_FIELDS, schema=snap.KNOWLEDGE_SCHEMA,
        writer="az-knowledge-lited", leaf=reader)
    # Knowledge Lite's own word decides: only `available` is available;
    # anything else is `degraded` with Knowledge Lite's reason code.
    snapshot = section["snapshot"]
    if _fresh(section):
        if snapshot["state"] == "available":
            section["status"], section["reason_code"] = "available", None
        else:
            section["status"], section["reason_code"] = "degraded", snapshot["reason_code"]
    # `freshness` (current/static/absent) was evaluated when the snapshot was
    # written, not now: a dated claim can expire between two writes.
    section["content_freshness_evaluated_at"] = (
        snapshot["written_at"] if snapshot is not None else None)
    section["cryptographic_implementation"] = {"status": "not_supported",
                                               "reason_code": "nexus_70_review_pending"}
    return section


def _mio_status(now, reader: str = "operator") -> dict:
    from . import operator_snapshots as snap
    from .mio_status import NOTICE
    from .runtime_paths import mio_status_path

    section = _snapshot_section(
        mio_status_path(reader=reader), snap.read_mio_status, snap.MIO_BYTES, now, snap.MIO_STALE_S,
        MIO_SNAPSHOT_FIELDS, schema=snap.MIO_SCHEMA, writer="az-mio-entryd", leaf=reader)
    snapshot = section["snapshot"]
    if _fresh(section):
        if not snapshot["recorded"]:
            section["status"], section["reason_code"] = "unknown", "no_recorded_capability_transition"
        elif snapshot["record_uncertain"]:
            section["status"], section["reason_code"] = "unknown", "capability_record_uncertain"
        else:
            # The mio section's own word: a recorded reading, not a grant.
            section["status"], section["reason_code"] = "recorded", None
    section["notice"] = NOTICE
    return section


def _services(now, reader: str = "operator") -> dict:
    from . import operator_snapshots as snap
    from .runtime_paths import units_status_path

    def extra(value, snapshot):
        snapshot["units"] = [_pick(unit, UNIT_FIELDS) for unit in value["units"]]

    section = _snapshot_section(
        units_status_path(reader=reader), snap.read_units_status, snap.UNITS_BYTES, now,
        snap.UNITS_STALE_S, (), schema=snap.UNITS_SCHEMA, writer="az-units-observe",
        extra=extra, leaf=reader)
    section["source"]["reader"] = "systemd_bus.UnitStatesReader (read-only)"
    if _fresh(section):
        units = section["snapshot"]["units"]
        if any(u["active_state"] == "failed" for u in units):
            section["status"], section["reason_code"] = "degraded", "unit_failed"
        elif any(u["status"] != "read" for u in units):
            section["status"], section["reason_code"] = "unknown", "unit_state_unread"
        else:
            section["status"], section["reason_code"] = "read", None
    return section


def _storage(now) -> dict:
    from . import operator_snapshots as snap

    kwargs = {} if _storage_probes is None else {"statvfs": _storage_probes[0], "stat": _storage_probes[1]}
    entries = [_pick(entry, STORAGE_FIELDS) for entry in snap.read_storage(**kwargs)]
    measured = any(entry["status"] == "measured" for entry in entries)
    return {"status": "measured" if measured else "unknown",
            "reason_code": None if measured else "no_location_measured",
            "locations": entries,
            "source": {"kind": "statvfs_at_read", "observed_at": now,
                       "withheld": ["path"]}}


#: The NOC snapshot's top-level fields (U3). Below them the snapshot is the
#: closed shape `noc_status.read_noc_status` checked, copied as checked.
NOC_FIELDS = ("collection", "reason_code", "observed_at", "active_checks", "interfaces",
              "interfaces_omitted", "uplink", "routes", "dns")


def _noc(now, reader: str = "operator") -> dict:
    from . import noc_status
    from .runtime_paths import noc_status_path

    section = _snapshot_section(noc_status_path(reader=reader), noc_status.read_noc_status,
                                noc_status.NOC_BYTES, now, noc_status.NOC_STALE_S, NOC_FIELDS,
                                schema=noc_status.NOC_SCHEMA, writer="az-noc-observe",
                                leaf=reader)
    snapshot = section["snapshot"]
    if _fresh(section):
        if snapshot["collection"] == "failed":
            section["status"], section["reason_code"] = "unknown", snapshot["reason_code"]
        else:
            # Observed, which is not "healthy": the fields say what was seen.
            section["status"], section["reason_code"] = "observed", None
    # Fixed statements, not observations: what this observer never does, so
    # a reader cannot take "not measured" for "down".
    section["observation"] = {"kind": "passive", "transmission": "none",
                              "active_checks": "none", "policy_rules_evaluated": False}
    section["not_measured"] = [{"field": name, "status": "not_measured",
                                "reason_code": "active_check_not_performed"}
                               for name in noc_status.ACTIVE_CHECK_FIELDS]
    section["role"] = {"status": "unknown", "reason_code": "role_evidence_not_provided"}
    section["identity"] = {"interfaces_by": "ifindex",
                           "withheld": ["interface_name", "mac", "address", "gateway",
                                        "nameserver", "search_domain"]}
    return section


def _operator_view(report, mio_status, storage) -> dict:
    """The catalog, import, admission and confirmations screen (S-04).

    Built by `operator_view_source` from what this account can read, as a
    versioned section of its own; never raises.
    """
    from .operator_view_source import read_section

    reading = report.profile.reading
    return read_section(usable_mib=None if reading is None else reading.usable_mib,
                        mio_status_section=mio_status, storage_section=storage)


def _guarded_section(build_section, now, reader: str = "operator") -> dict:
    try:
        return build_section(now) if reader == "operator" else build_section(now, reader)
    except Exception:  # noqa: BLE001 - presentation only; status continues
        return {"status": "unavailable", "reason_code": "internal_error"}


def _next_actions(report, lab_host, terminal) -> list:
    # Summaries that quote exception text or a path the view withholds.
    private = [text for text in (terminal.get("profile_reason"),
                                 *terminal.get("private_texts", ())) if text]
    actions = []
    for index, action in enumerate(report.next_actions):
        step = None
        if lab_host and action.command:
            step = next((name for command, name in LAB_HOST_STEPS
                         if command in action.command), None)
        summary = _free(terminal, f"next.{index}", action.summary)
        if summary is not None and any(text in action.summary for text in private):
            summary = None
        actions.append({"summary": summary,
                        # A step refused on a lab host carries no command to run.
                        "command": None if step else action.command,
                        "lab_host_unavailable_step": step,
                        "withheld": ["summary"] if summary is None else []})
        terminal.setdefault("next_commands", {})[index] = action.command
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
    reader: str = "operator",
) -> StatusView:
    """Project what `status` read into the read model and its terminal half.

    `as_of` is the instant the screen is evaluated at (`--as-of`, or the wall
    clock the command line read); `wall_now` is the wall clock, which the
    integration broker has always been asked at. `audit_seen` is the list
    `cli._health_reports` appended auditd's snapshot to, so the `audit` line
    and its source come from one read. `probe` and `boot_id` are fixed codes
    for what reading the probe result and this boot's id came to; `preamble`
    is the text the command printed about them, which only a terminal shows.
    `reader` picks which copy of the operator snapshots is read: the operator
    group's leaves, or the read-only UI's copies (ADR-0007).
    """

    from .lab_host import is_lab_host
    from .mio_status import status_summary as mio_summary

    terminal: dict = {"preamble": preamble, "text": {}}
    now = _epoch(as_of)
    lab_host = is_lab_host()
    broker = None
    if integration is not None:
        from .broker_cli import status_summary as broker_summary
        broker = broker_summary(now=wall_now)
        terminal["broker_level"] = broker["status_level"]
    # Read once: the M.I.O. section counts it as entryd's liveness evidence,
    # and the operator_view section reads the admission record from it.
    mio_status = _guarded_section(_mio_status, now, reader)
    # Measured once: the operator view shows the same free space.
    storage = _guarded_section(_storage, now)
    sections = {
        "profile": _profile(report, terminal),
        "mio": _mio(mio_summary(), now, terminal, mio_status),
        "capability": _capability(report),
        "enforcement": _enforcement(report, edge),
        "interfaces": _interfaces(report, terminal),
        "external_modules": _modules(report, terminal),
        "knowledge_lite": _knowledge(knowledge, terminal),
        "edge_core": _edge(edge, probe, boot_id, terminal),
        "integration": _integration(integration, broker, terminal),
        "fabric": _fabric(report),
        "edge_loop": _edge_loop(now, reader),
        "health": _health(report, audit_seen, now, terminal),
        "knowledge_status": _guarded_section(_knowledge_status, now, reader),
        "mio_status": mio_status,
        "services": _guarded_section(_services, now, reader),
        "storage": storage,
        "noc": _guarded_section(_noc, now, reader),
        "operator_view": _operator_view(report, mio_status, storage),
    }
    sections["next_actions"] = _next_actions(report, lab_host, terminal)
    view = {
        "schema": SCHEMA,
        "as_of": (datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z")
                  if now is not None else None),
        "clock": {"status": "known" if now is not None else "unknown",
                  "reason_code": None if now is not None else "clock_unknown"},
        "lab_host": bool(lab_host),
        # Which copy of the operator snapshots this view read (ADR-0007).
        "snapshot_reader": reader,
        "authority": dict(AUTHORITY),
        "sections": sections,
    }
    json.dumps(view, allow_nan=False)  # refuse a value JSON cannot carry, here
    return StatusView(view=view, terminal=terminal)


# -- the text an operator reads ----------------------------------------------
#
# Words, flags and counts come from the view; fixed and free sentences come
# from the terminal half, which holds them whole (the view may withhold one).


def render_text(status: StatusView, out: TextIO) -> None:
    """The `status` screen, from the read model and its terminal half."""

    terminal, s = status.terminal, status.view["sections"]
    out.write(terminal.get("preamble", ""))
    _text_profile(s["profile"], terminal, out)
    print(file=out)
    from .mio_status import describe
    print(describe(terminal["mio_reading"]), file=out)
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
    for index, module in enumerate(s["external_modules"]):
        print(f"    {module['name']}: {module['state']} -- {_text(terminal, f'module.{index}')}",
              file=out)
    print(file=out)
    if s["knowledge_lite"]["status"] != "not_collected":
        _text_knowledge(s["knowledge_lite"], terminal, out)
        print(file=out)
    if s["edge_core"]["status"] != "not_inspected":
        _text_edge(s["edge_core"], terminal, out)
        print(file=out)
    if s["integration"]["status"] != "not_collected":
        _text_integration(s["integration"], terminal, out)
        print(file=out)
    _text_fabric(s["fabric"], out)
    _text_edge_loop(s["edge_loop"], out)
    print(file=out)
    _text_health(s["health"], terminal, out)
    print(file=out)
    # L8: the operator snapshots (U2, U3) and the operator view (S-04) are
    # on the text screen as well as in `--json`: the same words and codes.
    _text_operator_snapshots(s, out)
    print(file=out)
    _text_operator_view(s.get("operator_view"), out)
    print(file=out)
    print("next:", file=out)
    if not s["next_actions"]:
        print("    nothing is outstanding.", file=out)
    for index, action in enumerate(s["next_actions"]):
        if action["lab_host_unavailable_step"]:
            print(f"    {action['lab_host_unavailable_step']} step unavailable on a lab host "
                  "(LAB_HOST_MARKER); requires a non-lab deployment", file=out)
            continue
        print(f"    {_text(terminal, f'next.{index}')}", file=out)
        command = terminal["next_commands"][index]
        if command:
            print(f"        {command}", file=out)


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


def _text_knowledge(section, terminal, out) -> None:
    readiness = section["readiness"]
    print("Knowledge Lite: " + readiness["word"], file=out)
    state, reason, freshness = terminal["knowledge_words"]
    print(f"    state: {state}", file=out)
    print(f"    reason: {reason}", file=out)
    print(f"    generation: {terminal['knowledge_generation']}", file=out)
    print(f"    freshness: {freshness}", file=out)
    if terminal.get("knowledge_bundle"):
        # Rendered from the view's checked copy; a fact it withheld says so.
        bundle = section["bundle"] or {}
        shown = lambda name: "withheld" if bundle.get(name) is None else bundle[name]  # noqa: E731
        # Key ids that only name a path are the operator's own and stay here;
        # ids outside their shape were never kept.
        signers = terminal.get("knowledge_signers")
        signers = "withheld" if signers is None else (", ".join(signers) or "none")
        expiry = bundle.get("next_expiry") or (
            "withheld" if "bundle.next_expiry" in section["withheld"] else "none")
        print(f"    bundle: {shown('digest_short')} (shortened); signing key ids: {signers}",
              file=out)
        print(f"    claims: static {shown('static_count')}; current {shown('current_count')}; "
              f"nearest expiry: {expiry}", file=out)
    print("    cryptographic implementation: not supported (Nexus#70 review pending)", file=out)
    print(f"    functional means: {_text(terminal, 'knowledge.means')}", file=out)
    for index in range(terminal["knowledge_limits"]):
        print(f"    it does not mean: {_text(terminal, f'knowledge.does_not_mean.{index}')}",
              file=out)


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
        print(f"        {_text(terminal, 'edge.issuer_reason')}", file=out)
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


def _text_integration(section, terminal, out) -> None:
    print("integration:", file=out)
    for index, row in enumerate(section["rows"]):
        subject = f" [{row['subject']}]" if row["subject"] else ""
        marker = "  DEFECT" if row["defect"] else ""
        print(f"    {row['axis']}{subject}: {row['value']}{marker}", file=out)
        print(f"        {_text(terminal, f'integration.{index}')}", file=out)
    print(file=out)
    print(f"enforcement capable: {'yes' if section['enforcement_capable'] else 'no'}", file=out)
    print(f"baseline ready: {'yes' if section['baseline_ready'] else 'no'}", file=out)
    print("continuing regardless: " + ", ".join(section["continues"]), file=out)
    print("Integration broker (informational): " + str(terminal["broker_level"])
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


#: The text screen's names for the operator snapshot sections.
_SNAPSHOT_LINES = (("knowledge_status", "Knowledge Lite (knowledge-lited)"),
                   ("mio_status", "M.I.O. (mio-entryd)"),
                   ("services", "unit states (units-observe)"),
                   ("noc", "passive NOC (noc-observe)"))


def _text_operator_snapshots(sections, out) -> None:
    print("operator snapshots (each written by its own daemon or observer):", file=out)
    for name, label in _SNAPSHOT_LINES:
        section = sections.get(name) or {}
        source = section.get("source") or {}
        reason = section.get("reason_code")
        written = source.get("written_at")
        age = source.get("age_s")
        when = ("never read" if written is None
                else f"written {age} s before as-of" if type(age) is int else "written at an unreadable time")
        print(f"    {label}: {section.get('status', 'unavailable')}"
              + (f" ({reason})" if reason else "") + f"; {when}", file=out)
    storage = sections.get("storage") or {}
    print(f"    storage: {storage.get('status', 'unavailable')}"
          + (f" ({storage['reason_code']})" if storage.get("reason_code") else ""), file=out)
    print("    an observer that is not enabled writes nothing: its line says never read "
          "(azazel-nexus setup, step operator-observers)", file=out)


def _text_operator_view(section, out) -> None:
    if not isinstance(section, dict) or section.get("status") == "unavailable":
        print("operator view: unavailable (internal)", file=out)
        return
    provider = section.get("provider") or {}
    codes = ", ".join(provider.get("reason_codes") or ()) or "none"
    print(f"operator view: {section['status']}"
          + (f" ({section['reason_code']})" if section.get("reason_code") else ""), file=out)
    print(f"    provider: {provider.get('state')}; refusing gates: {codes}", file=out)
    print(f"    admission build switch: {section.get('admission_build_switch')}", file=out)
    catalog = next((row for sec in section.get("sections") or () if sec.get("key") == "catalog"
                    for row in sec.get("rows") or () if row.get("axis") == "catalog_state"), {})
    print(f"    catalog: {catalog.get('value') or 'not read'}"
          + (f" ({catalog['reason_code']})" if catalog.get("reason_code") else ""), file=out)
    unread = section.get("unread_inputs") or ()
    if unread:
        print("    inputs not read or not usable here: " + ", ".join(unread), file=out)


def _text_health(entries, terminal, out) -> None:
    print("health:", file=out)
    for index, entry in enumerate(entries):
        mark = {"ok": "ok", "failed": "FAILED"}.get(entry["status"], "unknown")
        print(f"    {entry['subject']}: {mark} -- {_text(terminal, f'health.{index}.detail')}",
              file=out)
