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
ACTIONS = frozenset({"observe", "notify", "throttle", "redirect", "isolate"})
STATUS_SCHEMA = "azazel-nexus/edge-intake-status/v1"
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
        "EDGE_TYPE_attack_type",
        "EDGE_RANGE_attack_type",
        "EDGE_TYPE_category",
        "EDGE_RANGE_category",
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


def parse_edge_event(raw: bytes) -> EdgeEvent:
    """Refuse whole events so partial observations cannot imply a safe posture."""
    _require(type(raw) is bytes, "EDGE_TYPE")
    _require(len(raw) <= MAX_LINE, "EDGE_TOO_LARGE")
    try:
        event = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object,
            parse_constant=lambda _: (_ for _ in ()).throw(
                EdgeEventRefused("EDGE_JSON")
            ),
        )
    except (UnicodeError, ValueError, RecursionError):
        raise EdgeEventRefused("EDGE_JSON") from None
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
    """Bound incident cardinality and transition frequency independently of traffic."""

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
                transitions.append(self._close(key, "idle"))
        return transitions

    def _close(self, key, reason):
        return dict(self.incidents.pop(key), transition="closed", reason=reason)

    def add(self, record):
        now = record.received_at
        transitions = self.tick(now)
        event = record.event.as_dict()
        n, d = event["normalized"], event["defense"]
        key = (n["src_ip"], n["sid"], n["target_port"])
        opened = key not in self.incidents
        if opened:
            instant = self.monotonic()
            for budget in (self.openings, self.severe_openings):
                while budget and instant - budget[0][0] >= 60:
                    budget.popleft()
            severe = n["severity"] <= 2
            budget = self.severe_openings if severe else self.openings
            limit = MAX_SEVERE_OPENINGS_PER_MINUTE if severe else MAX_OPENINGS_PER_MINUTE
            source_count = sum(source == key[0] for _, source in budget)
            if (len(budget) >= limit or
                    (not severe and source_count >= MAX_SOURCE_OPENINGS_PER_MINUTE)):
                self.rate_limited += 1
                return transitions
            budget.append((instant, key[0]))
            if len(self.incidents) >= self.max_open:
                oldest = min(
                    self.incidents, key=lambda k: self.incidents[k]["last_seen"]
                )
                transitions.append(self._close(oldest, "capacity"))
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
        escalated = not opened and n["severity"] < item["most_severe"]
        item.update(
            count=item["count"] + 1,
            last_seen=now,
            most_severe=min(item["most_severe"], n["severity"]),
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
                "refused",
                "open_incidents",
                "queue_drops",
                "storage_failed",
            ),
        )
        _require(value["schema"] == STATUS_SCHEMA)
        _require(type(value["storage_failed"]) is bool, "EDGE_TYPE")
        _number(value["written_at"])
        if value["last_accepted_at"] is not None:
            _number(value["last_accepted_at"])
        for key in ("accepted", "open_incidents", "queue_drops"):
            _int(value[key], 2**64 - 1)
        _require(
            type(value["refused"]) is dict and set(value["refused"]) <= REFUSAL_CODES
        )
        for count in value["refused"].values():
            _int(count, 2**64 - 1)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return None
