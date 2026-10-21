"""Bounded observations of Edge decisions; this module grants no authority."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

MAX_LINE = 16 * 1024
INCIDENT_IDLE_S = 900
UPDATE_INTERVAL_S = 60
MAX_OPEN = 1024
MAX_OPENINGS_PER_MINUTE = 60
MAX_SEVERE_OPENINGS_PER_MINUTE = 30
MAX_SOURCE_OPENINGS_PER_MINUTE = 20
# One host showing more than five new severe (sid, port) pairs in a minute is
# itself scanning; five per source leaves 25 of the 30 severe openings to
# others, so one source cannot hold the severe allowance alone.
MAX_SOURCE_SEVERE_OPENINGS_PER_MINUTE = 5
# Edge's isolate/redirect range; intake openings and explanation queueing
# share it so a flood of ordinary events cannot crowd these out.
SEVERE_SEVERITY = 2
ACTIONS = frozenset({"observe", "notify", "throttle", "redirect", "isolate"})
STATUS_SCHEMA = "azazel-nexus/edge-intake-status/v1"
# Edge Core's own forwarding counts (#190, Edge#432). Counts are cumulative
# for one Edge process, which `since` (its start, epoch seconds) names.
FORWARD_STATS_SCHEMA = "azazel-edge/forward-stats/v1"
FORWARD_COUNT_MAX = 2**63 - 1
# Bounded so any reported start renders as a date (well before year 9999).
FORWARD_SINCE_MAX = 2**37
REFUSAL_CODES = frozenset(
    {
        "EDGE_TOO_LARGE",
        "EDGE_JSON",
        "EDGE_SHAPE",
        "EDGE_TYPE",
        "EDGE_RANGE",
        "EDGE_NOT_OBSERVE_ONLY",
        "peer_refused",
        "overloaded",
        "queue_full",
        "read_deadline",
        "read_error",
        "storage_failed",
        "status_write_failed",
        "evidence_segment_full",
        "incident_segment_full",
        "incident_ledger_torn",
        "incident_rate_limited",
        "segment_from_future",
        "EDGE_TYPE_attack_type",
        "EDGE_RANGE_attack_type",
        "EDGE_TYPE_category",
        "EDGE_RANGE_category",
        # The Deception Lite decoy socket (#196 P2): Nexus observations, not
        # Edge's, refused with their own codes.
        "DECOY_TOO_LARGE",
        "DECOY_JSON",
        "DECOY_SHAPE",
        "DECOY_TYPE",
        "DECOY_RANGE",
        "DECOY_ADDRESS",
        "DECOY_CLOCK",
        "decoy_peer_refused",
        "decoy_rate_limited",
        "decoy_overloaded",
        "decoy_read_deadline",
        "decoy_read_error",
        "decoy_accept_error",
        "decoy_evidence_segment_full",
        "decoy_storage_failed",
        "decoy_listener_unavailable",
    }
)


class EdgeEventRefused(ValueError):
    """Only a fixed code can escape an untrusted input boundary."""

    def __init__(self, code: str):
        self.code = code if code in REFUSAL_CODES else "EDGE_SHAPE"
        super().__init__(self.code)


def _require(ok, code="EDGE_SHAPE"):
    if not ok:
        raise EdgeEventRefused(code)


def _shape(value, keys, optional=()):
    _require(type(value) is dict)
    _require(set(keys) <= set(value) <= set(keys) | set(optional))


def _text(value, limit=256, *, field=None):
    suffix = "_" + field if field else ""
    _require(type(value) is str, "EDGE_TYPE" + suffix)
    printable = value.replace("\t", " ") if field else value
    _require(
        len(value) <= limit and (not printable or printable.isprintable()),
        "EDGE_RANGE" + suffix,
    )


def _int(value, maximum, minimum=0):
    _require(type(value) is int, "EDGE_TYPE")
    _require(minimum <= value <= maximum, "EDGE_RANGE")


def _number(value):
    _require(type(value) in (int, float), "EDGE_TYPE")
    try:
        _require(math.isfinite(value) and value >= 0, "EDGE_RANGE")
    except OverflowError:
        raise EdgeEventRefused("EDGE_RANGE") from None


def _strings(value, limit=32, width=2048):
    _require(type(value) is list, "EDGE_TYPE")
    _require(len(value) <= limit, "EDGE_RANGE")
    for item in value:
        _text(item, width)


def _timestamp(value):
    _text(value, 64)
    try:
        _require(
            bool(
                re.fullmatch(
                    r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)",
                    value,
                    re.ASCII,
                )
            ),
            "EDGE_RANGE",
        )
        _require(
            datetime.fromisoformat(value).tzinfo is not None,
            "EDGE_RANGE",
        )
    except ValueError:
        raise EdgeEventRefused("EDGE_RANGE") from None


def canonical(value) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class EdgeEvent:
    """Immutable canonical observation; callers receive detached mappings."""

    encoded: bytes

    def as_dict(self):
        return json.loads(self.encoded)


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _decode(raw):
    _require(type(raw) is bytes, "EDGE_TYPE")
    _require(len(raw) <= MAX_LINE, "EDGE_TOO_LARGE")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                EdgeEventRefused("EDGE_JSON")
            ),
        )
    except (UnicodeError, ValueError, RecursionError):
        raise EdgeEventRefused("EDGE_JSON") from None


@dataclass(frozen=True)
class ForwardStats:
    """Edge's own count of what its forwarder could not deliver.

    Reported by Edge over the intake socket, so it is a claim from the azedge
    peer, not an observation Nexus made: bounded, shown as reported, never
    stored as evidence and never counted as an accepted event.
    """

    dropped: int
    failed: int
    sent: int
    since: int

    def as_dict(self):
        return {"dropped": self.dropped, "failed": self.failed,
                "sent": self.sent, "since": self.since}


def _forward_stats(value) -> ForwardStats:
    _shape(value, ("schema", "dropped", "failed", "sent", "since"))
    _require(value["schema"] == FORWARD_STATS_SCHEMA)
    for key in ("dropped", "failed", "sent"):
        _int(value[key], FORWARD_COUNT_MAX)
    _int(value["since"], FORWARD_SINCE_MAX)
    return ForwardStats(value["dropped"], value["failed"], value["sent"], value["since"])


def parse_edge_line(raw: bytes) -> EdgeEvent | ForwardStats:
    """One intake line: an Edge event, or Edge's forward counts; nothing else.

    A line carrying ``schema`` is only ever the forward counts, in their own
    closed shape; every other line is held to the event shape as before.
    """
    value = _decode(raw)
    if type(value) is dict and "schema" in value:
        return _forward_stats(value)
    return _event(value)


def parse_edge_event(raw: bytes) -> EdgeEvent:
    """Refuse whole events so partial observations cannot imply a safe posture."""
    return _event(_decode(raw))


def _event(event) -> EdgeEvent:
    _shape(
        event,
        (
            "normalized",
            "defense",
            "enforcement",
            "enforcement_status",
            "source",
            "pipeline",
        ),
    )
    _require(
        event["source"] == "suricata_eve"
        and event["pipeline"] == "rust_event_engine_v1"
    )
    n, d, e, s = (
        event[k] for k in ("normalized", "defense", "enforcement", "enforcement_status")
    )
    _shape(
        n,
        (
            "ts",
            "src_ip",
            "dst_ip",
            "attack_type",
            "severity",
            "target_port",
            "protocol",
            "sid",
            "category",
            "event_type",
            "action",
            "confidence",
            "risk_score",
            "ingest_epoch",
        ),
        ("technique_ids",),
    )
    _timestamp(n["ts"])
    for key in ("src_ip", "dst_ip"):
        _text(n[key], 45)
        try:
            if n[key]:
                _require("%" not in n[key], "EDGE_RANGE")
                address = ipaddress.ip_address(n[key])
                if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                    address = address.ipv4_mapped
                n[key] = address.compressed
        except ValueError:
            raise EdgeEventRefused("EDGE_RANGE") from None
    for key in ("attack_type", "category"):
        _text(n[key], 1024, field=key)
    for key in ("protocol", "action", "event_type"):
        _text(n[key])
    for key, upper in (
        ("severity", 10),
        ("target_port", 65535),
        ("sid", 2**64 - 1),
        ("confidence", 100),
        ("risk_score", 100),
    ):
        _int(n[key], upper)
    _number(n["ingest_epoch"])
    if "technique_ids" in n:
        _strings(n["technique_ids"], 8, 9)
        _require(
            all(
                re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", t) for t in n["technique_ids"]
            ),
            "EDGE_RANGE",
        )
    _shape(d, ("action", "reason", "policy_reason", "delay_ms", "target"))
    for key in ("action", "reason", "policy_reason", "target"):
        _text(d[key])
    _require(d["action"] in ACTIONS, "EDGE_RANGE")
    _int(d["delay_ms"], 2**32 - 1)
    _shape(
        s,
        (
            "enforce_enabled",
            "enforce_level",
            "dry_run",
            "high_impact_auto",
            "allowed_actions",
        ),
    )
    for key in ("enforce_enabled", "dry_run", "high_impact_auto"):
        _require(type(s[key]) is bool, "EDGE_TYPE")
    _text(s["enforce_level"])
    _strings(s["allowed_actions"], 5, 16)
    _require(all(a in ACTIONS for a in s["allowed_actions"]), "EDGE_RANGE")
    _require(
        not s["enforce_enabled"]
        and s["dry_run"]
        and not s["high_impact_auto"]
        and s["enforce_level"] == "advisory",
        "EDGE_NOT_OBSERVE_ONLY",
    )
    _shape(
        e,
        (
            "mode",
            "trace_id",
            "selected_action",
            "target",
            "policy_reason",
            "command_plan",
            "rollback_plan",
            "executed_count",
            "failed_count",
            "errors",
            "rollback_hint",
            "result",
            "metadata",
        ),
    )
    for key in (
        "mode",
        "trace_id",
        "selected_action",
        "target",
        "policy_reason",
        "rollback_hint",
        "result",
    ):
        _text(e[key], 512)
    _require(e["selected_action"] in ACTIONS, "EDGE_RANGE")
    for key in ("command_plan", "rollback_plan", "errors"):
        _strings(e[key])
    for key in ("executed_count", "failed_count"):
        _int(e[key], 2**32 - 1)
    m = e["metadata"]
    _shape(
        m,
        (
            "original_dst_port",
            "selected_decoy_port",
            "redirect_policy_source",
            "redirect_mapping_matched",
            "unsupported_port_fallback",
            "fallback_reason",
            "release_task_id",
            "release_due_epoch",
            "release_resource_key",
            "release_owner_token",
            "release_tc_handle",
            "release_ledger_state",
        ),
    )
    _int(m["original_dst_port"], 65535)
    if m["selected_decoy_port"] is not None:
        _int(m["selected_decoy_port"], 65535)
    _require(type(m["redirect_mapping_matched"]) is bool, "EDGE_TYPE")
    for key in (
        "redirect_policy_source",
        "unsupported_port_fallback",
        "fallback_reason",
        "release_ledger_state",
    ):
        _text(m[key], 512)
    for key in (
        "release_task_id",
        "release_resource_key",
        "release_owner_token",
        "release_tc_handle",
    ):
        if m[key] is not None:
            _text(m[key], 512)
    if m["release_due_epoch"] is not None:
        _number(m["release_due_epoch"])
    _require(
        e["mode"] in {"disabled", "dry_run"}
        and e["executed_count"] == 0
        and e["failed_count"] == 0
        and e["result"] in {"no_disruptive_action", "planned_not_applied"}
        and m["release_ledger_state"] in {"not_applicable", "planned_only"},
        "EDGE_NOT_OBSERVE_ONLY",
    )
    # Command text is validated but has no place in a decision observation.
    event["enforcement"] = {
        k: e[k]
        for k in (
            "mode",
            "trace_id",
            "selected_action",
            "target",
            "policy_reason",
            "result",
        )
    }
    event["enforcement"]["release_ledger_state"] = m["release_ledger_state"]
    return EdgeEvent(canonical(event))


@dataclass(frozen=True)
class EvidenceRecord:
    """Bind receive time separately from the producer observation digest."""

    event: EdgeEvent
    digest: str
    received_at: float

    @classmethod
    def receive(cls, event: EdgeEvent, clock: Callable[[], float]):
        return cls(
            event, "sha256:" + hashlib.sha256(event.encoded).hexdigest(), clock()
        )

    def as_dict(self):
        return {
            "event": self.event.as_dict(),
            "digest": self.digest,
            "received_at": self.received_at,
        }


class IncidentTracker:
    """Bound incident cardinality and transition frequency independently of traffic.

    At most a quarter of `max_open` incidents are severe. When that many are
    open, a new severe incident closes held severe ones (reason `capacity`)
    until it fits, instead of being refused: the displaced incident was
    already opened, recorded and queued for explanation, and its close is
    recorded too, while a refused one would never be recorded at all. The
    least severe (2 before 1) go first, then the least recently seen, so a
    burst of new severity 2 incidents cannot push out a quiet severity 1 one.

    An ordinary incident becoming severe takes a severe opening (the global
    and per-source severe budgets) at that moment, and room among held severe
    incidents, exactly as a severe opening does; otherwise opening ordinary
    and escalating would bypass both. Without a severe opening the recorded
    severity stops at SEVERE_SEVERITY + 1 and the refusal is counted as rate
    limited. This falls closed: every severe privilege (the ledger's reserve,
    a held severe place, explanation priority) follows `most_severe`, so none
    is granted, and no marker beside the recorded severity is needed. It also
    loses no severe evidence: the evidence record keeps its own severity, the
    incident stays open, and its next severe event tries again.
    """

    def __init__(
        self, clock: Callable[[], float], max_open=MAX_OPEN, *, monotonic=time.monotonic
    ):
        self.clock, self.max_open = clock, max_open
        self.incidents = {}
        self.monotonic = monotonic
        self.openings = deque()
        self.severe_openings = deque()
        self.rate_limited = 0

    def tick(self, now=None):
        now = self.clock() if now is None else now
        transitions = []
        for key, item in list(self.incidents.items()):
            if now - item["last_seen"] > INCIDENT_IDLE_S:
                transitions.append(self._close(key, "idle", now))
        return transitions

    def _close(self, key, reason, now):
        # The close is recorded at intake time, like every other transition.
        return dict(self.incidents.pop(key), transition="closed", reason=reason,
                    last_update=now)

    def _opening(self, key, severe, now, transitions):
        """Take an opening from the matching budget; a severe one also gets room."""
        instant = self.monotonic()
        for budget in (self.openings, self.severe_openings):
            while budget and instant - budget[0][0] >= 60:
                budget.popleft()
        budget = self.severe_openings if severe else self.openings
        limit = MAX_SEVERE_OPENINGS_PER_MINUTE if severe else MAX_OPENINGS_PER_MINUTE
        source_limit = (MAX_SOURCE_SEVERE_OPENINGS_PER_MINUTE if severe
                        else MAX_SOURCE_OPENINGS_PER_MINUTE)
        source_count = sum(source == key[0] for _, source in budget)
        if len(budget) >= limit or source_count >= source_limit:
            return False
        budget.append((instant, key[0]))
        cap = self.max_open // 4
        if severe and cap:
            held = sorted(
                (k for k, v in self.incidents.items()
                 if k != key and v["most_severe"] <= SEVERE_SEVERITY),
                key=lambda k: (-self.incidents[k]["most_severe"],
                               self.incidents[k]["last_seen"]),
            )
            while len(held) >= cap:
                transitions.append(self._close(held.pop(0), "capacity", now))
        return True

    def add(self, record, *, evidence_stored=True):
        now = record.received_at
        transitions = self.tick(now)
        event = record.event.as_dict()
        n, d = event["normalized"], event["defense"]
        key = (n["src_ip"], n["sid"], n["target_port"])
        opened = key not in self.incidents
        severity = n["severity"]
        if opened:
            severe = severity <= SEVERE_SEVERITY
            if not self._opening(key, severe, now, transitions):
                self.rate_limited += 1
                return transitions
            if len(self.incidents) >= self.max_open:
                oldest = min(
                    self.incidents, key=lambda k: self.incidents[k]["last_seen"]
                )
                transitions.append(self._close(oldest, "capacity", now))
            identifier = hashlib.sha256(canonical([key, record.digest])).hexdigest()[
                :16
            ]
            self.incidents[key] = {
                "incident_id": "inc-" + identifier,
                "src_ip": key[0],
                "sid": key[1],
                "target_port": key[2],
                "count": 0,
                "first_seen": now,
                "last_seen": now,
                "most_severe": n["severity"],
                "technique_ids": [],
                "first_evidence": record.digest,
                "latest_evidence": record.digest,
                "last_update": now,
            }
        item = self.incidents[key]
        if not evidence_stored:
            # Sticky: the digests stay as correlation ids, but at least one of
            # this incident's evidence records is absent from the store.
            item["evidence_stored"] = False
        if (not opened and severity <= SEVERE_SEVERITY < item["most_severe"]
                and not self._opening(key, True, now, transitions)):
            self.rate_limited += 1
            severity = SEVERE_SEVERITY + 1
        escalated = not opened and severity < item["most_severe"]
        item.update(
            count=item["count"] + 1,
            last_seen=now,
            most_severe=min(item["most_severe"], severity),
            edge_would=d["action"],
            policy_reason=d["policy_reason"],
            attack_type=n["attack_type"],
            category=n["category"],
            protocol=n["protocol"],
            latest_evidence=record.digest,
            technique_ids=sorted(
                set(item["technique_ids"]) | set(n.get("technique_ids", []))
            )[:8],
        )
        # An escalation is recorded at once: the explainer acts on it, and a
        # throttle that delayed it would delay the explanation that matters.
        if opened or escalated or now - item["last_update"] >= UPDATE_INTERVAL_S:
            item["last_update"] = now
            transitions.append(dict(item, transition="opened" if opened else "updated"))
        return transitions


def read_intake_status(raw: bytes) -> dict | None:
    """Decode bounded liveness without turning an unavailable snapshot into health."""
    try:
        if len(raw) > 8192:
            return None
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
        _shape(
            value,
            (
                "schema",
                "written_at",
                "last_accepted_at",
                "accepted",
                "processed",
                "last_processed_at",
                "refused",
                "open_incidents",
                "queue_drops",
                "storage_failed",
            ),
            # Absent from a snapshot an older intake wrote, and edge_forward
            # also until Edge has reported its forward counts; decoy only
            # while the decoy socket is open (#196 P2).
            ("ledger_recovered", "edge_forward", "decoy"),
        )
        _require(value["schema"] == STATUS_SCHEMA)
        _require(type(value["storage_failed"]) is bool, "EDGE_TYPE")
        _number(value["written_at"])
        for key in ("last_accepted_at", "last_processed_at"):
            if value[key] is not None:
                _number(value[key])
        for key in ("accepted", "processed", "open_incidents", "queue_drops"):
            _int(value[key], 2**64 - 1)
        value.setdefault("ledger_recovered", 0)
        _int(value["ledger_recovered"], 2**64 - 1)
        # Processed counts every tracked event, accepted only stored ones.
        _require(value["processed"] >= value["accepted"])
        _require(
            type(value["refused"]) is dict and set(value["refused"]) <= REFUSAL_CODES
        )
        for count in value["refused"].values():
            _int(count, 2**64 - 1)
        if "edge_forward" in value:
            forward = value["edge_forward"]
            _shape(forward, ("dropped", "failed", "sent", "since", "reported_at", "restarts"))
            for key in ("dropped", "failed", "sent"):
                _int(forward[key], FORWARD_COUNT_MAX)
            _int(forward["since"], FORWARD_SINCE_MAX)
            _int(forward["restarts"], 2**64 - 1)
            _number(forward["reported_at"])
        if "decoy" in value:
            # Nexus's own decoy observations: never in accepted/processed,
            # which count Edge's events only.
            decoy = value["decoy"]
            _shape(decoy, ("accepted", "last_accepted_at"))
            _int(decoy["accepted"], 2**64 - 1)
            if decoy["last_accepted_at"] is not None:
                _number(decoy["last_accepted_at"])
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return None
