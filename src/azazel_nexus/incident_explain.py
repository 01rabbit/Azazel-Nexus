"""Pure, bounded observation-to-explanation logic. Never grants authority."""
from __future__ import annotations

import json
import re
import unicodedata
from collections import deque

from .edge_intake import ACTIONS, SEVERE_SEVERITY, _object, _shape, _text, _int, _number
from .lite_import import TECHNIQUE_ID, read_knowledge_refs
from .local_advisory import (
    HANDOFF_NOTICE,
    MACHINE_FIELDS,
    REFERENCE_BANNERS,
    read_delivered,
    read_frame,
    read_reference,
)
from .route_selection import RequestOutcome, TerminalEvent
from .sanitizer import PrivacyClass

MAX_PENDING = 64
MAX_PER_MINUTE = 6
MAX_LINE = 64 * 1024
CODES = frozenset({"transition_refused", "chain_broken", "queue_full", "mio_unavailable",
                   "mio_reply_refused", "knowledge_unavailable", "knowledge_reply_refused",
                   "storage_failed", "status_write_failed", "explanation_segment_full",
                   "cursor_refused", "read_failed", "cursor_overtaken", "stale_skipped",
                   "incident_segment_full", "ledger_tail_incomplete", "mio_gated",
                   "mio_handoff", "mio_local_non_advisory", "segment_from_future"})
QUESTION = ("Edge Core が次のセキュリティインシデントを検知しました。状況と、運用者が確認すべき点を説明してください。"
            "Edge の判断は観測のみで実行されていません。")
FIELDS = {"incident_id", "src_ip", "sid", "target_port", "count", "first_seen", "last_seen",
          "most_severe", "technique_ids", "first_evidence", "latest_evidence", "last_update",
          "edge_would", "policy_reason", "attack_type", "event_type"}


def closed_pairs(pairs):
    """Reject duplicate JSON keys at every boundary."""
    return _object(pairs)


def decode(raw):
    if type(raw) is not bytes or len(raw) > MAX_LINE:
        raise ValueError("bounded_json_refused")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def read_transition(value):
    """Validate the whole intake transition, including fields excluded from frames."""
    import ipaddress

    _shape(value, FIELDS, ("category", "protocol", "reason", "evidence_stored"))
    _text(value["event_type"], 32)
    # Present only as false: some of this incident's evidence hit a full day.
    if "evidence_stored" in value and value["evidence_stored"] is not False:
        raise ValueError("transition_refused")
    if value["event_type"] not in {"edge.incident." + t for t in ("opened", "updated", "closed")}:
        raise ValueError("transition_refused")
    if type(value["incident_id"]) is not str or not re.fullmatch(r"inc-[0-9a-f]{16}", value["incident_id"]):
        raise ValueError("transition_refused")
    _text(value["src_ip"], 45)
    if value["src_ip"]:
        ipaddress.ip_address(value["src_ip"])
    for key, cap in (("sid", 2**64-1), ("target_port", 65535), ("count", 2**64-1), ("most_severe", 10)):
        _int(value[key], cap)
    for key in ("first_seen", "last_seen", "last_update"):
        _number(value[key])
    for key in ("first_evidence", "latest_evidence"):
        if not isinstance(value[key], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value[key]):
            raise ValueError("transition_refused")
    for key, cap in (("attack_type", 1024), ("category", 1024), ("policy_reason", 256),
                     ("protocol", 256), ("edge_would", 16), ("reason", 32)):
        if key in value:
            _text(value[key], cap, field=key if key in {"attack_type", "category"} else None)
    if value["edge_would"] not in ACTIONS:
        raise ValueError("transition_refused")
    ids = value["technique_ids"]
    if type(ids) is not list or len(ids) > 8 or any(type(t) is not str or not TECHNIQUE_ID.fullmatch(t) for t in ids):
        raise ValueError("transition_refused")
    if (value["event_type"] == "edge.incident.closed") != ("reason" in value):
        raise ValueError("transition_refused")
    return json.loads(json.dumps(value, allow_nan=False))


def read_retention_boundary(value):
    """Validate the unsigned local prefix-retirement checkpoint."""
    _shape(value, ("oldest", "deleted", "sequence", "hash"))
    for key in ("oldest", "deleted"):
        if type(value[key]) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}\.jsonl", value[key], re.ASCII):
            raise ValueError("retention_refused")
    if value["deleted"] >= value["oldest"]:
        raise ValueError("retention_refused")
    _int(value["sequence"], 2**63-1)
    if type(value["hash"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", value["hash"]):
        raise ValueError("retention_refused")
    return value


def read_control(value):
    """Control records describe gaps/lifecycle, never advisory requests."""
    kind = value.get("event_type")
    if kind == "edge.incident.retention":
        read_retention_boundary({k: v for k, v in value.items() if k != "event_type"})
    elif kind in {"edge.incident.reset", "edge.incident.truncated"}:
        _shape(value, ("event_type", "at", "reason"))
        _number(value["at"])
        expected = "intake_started" if kind == "edge.incident.reset" else "incident_segment_full"
        if value["reason"] != expected:
            raise ValueError("control_refused")
    elif kind == "edge.incident.ledger_recovered":
        # A torn tail the intake cut off at start: where, how much, and the
        # digest of the bytes it kept privately. Never their content.
        _shape(value, ("event_type", "at", "segment", "offset", "torn_bytes", "sha256"))
        _number(value["at"])
        if type(value["segment"]) is not str or not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}\.jsonl", value["segment"], re.ASCII):
            raise ValueError("control_refused")
        _int(value["offset"], 2**63-1)
        _int(value["torn_bytes"], 64 * 1024, 1)
        if type(value["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"]):
            raise ValueError("control_refused")
    else:
        return False
    return True


# Edge Core main.rs decide_defense: producer values never extend this vocabulary.
POLICY_REASONS = frozenset({
    "severity_critical_contains_immediately", "severity_high_redirect_to_decoy",
    "severity_elevated_throttle_reversible", "severity_moderate_operator_notification",
    "baseline_observe_only",
})
CATEGORIES = frozenset({"Attempted Administrator Privilege Gain", "Attempted User Privilege Gain",
                        "Attempted Information Leak", "Potentially Bad Traffic",
                        "Misc Attack", "Misc activity", "Web Application Attack"})
PENDING_FIELDS = {"incident_id", "event_type", "first_seen", "target_port", "count",
                  "most_severe", "technique_ids", "edge_would", "policy_reason",
                  "attack_type", "category", "protocol"}


def private_text(text, limit=160):
    """NFKC then ASCII letters/spaces only; drop removed characters, bound words.

    This reduces syntax and identifier exposure, not prose injection in general.
    Plain alphabetic hostnames are indistinguishable from words: keep these local.
    """
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ")
    return " ".join(token[:32] for token in text.split())[:limit].strip() or "absent"


def explanation_input(t):
    """The only durable pending fields: no addresses, evidence or numeric rule ids."""
    t = read_transition(t)
    return {**{k: t[k] for k in PENDING_FIELDS - {"attack_type", "category", "protocol", "policy_reason"}},
            "attack_type": private_text(t["attack_type"]),
            "category": t.get("category") if t.get("category") in CATEGORIES else "other",
            "protocol": t.get("protocol") if t.get("protocol") in {"tcp", "udp", "icmp"} else "other",
            "policy_reason": t["policy_reason"] if t["policy_reason"] in POLICY_REASONS else "other"}


def read_pending(t):
    _shape(t, PENDING_FIELDS)
    if type(t["incident_id"]) is not str or not re.fullmatch(r"inc-[0-9a-f]{16}", t["incident_id"]):
        raise ValueError("pending_refused")
    if t["event_type"] not in {"edge.incident." + kind for kind in ("opened", "updated", "closed")}:
        raise ValueError("pending_refused")
    _number(t["first_seen"])
    for key, cap in (("target_port", 65535), ("count", 2**64-1), ("most_severe", 10)):
        _int(t[key], cap)
    ids = t["technique_ids"]
    if type(ids) is not list or len(ids) > 8 or any(type(i) is not str or not TECHNIQUE_ID.fullmatch(i) for i in ids):
        raise ValueError("pending_refused")
    _text(t["attack_type"], 160)
    if (private_text(t["attack_type"]) != t["attack_type"] or t["edge_would"] not in ACTIONS
            or t["policy_reason"] not in POLICY_REASONS | {"other"}
            or t["category"] not in CATEGORIES | {"other"}
            or t["protocol"] not in {"tcp", "udp", "icmp", "other"}):
        raise ValueError("pending_refused")
    return json.loads(json.dumps(t, allow_nan=False))


def build_frame(transition, sequence):
    t = explanation_input(transition) if "src_ip" in transition else read_pending(transition)
    _int(sequence, 2**63-1, 1)
    context = [
        {"kind": "edge_alert", "text": (
            f"incident={t['incident_id']}; signature={t['attack_type']}; "
            f"category={t['category']}; protocol={t['protocol']}; "
            f"destination_port={t['target_port']}; severity={t['most_severe']}; count={t['count']}")},
        {"kind": "edge_decision", "text": f"Edge would {t['edge_would']}; policy_reason={t['policy_reason']}"},
    ]
    context.extend({"kind": "technique", "text": t_id} for t_id in t["technique_ids"])
    return read_frame({"request_id": f"{t['incident_id']}:{sequence}",
                       "privacy_class": PrivacyClass.P3_RESTRICTED.value,
                       "question": QUESTION, "context": context})


class Selection:
    """Bounded pending work that serves the most severe incident first.

    Pending entries stay in arrival order (the checkpoint shape is unchanged);
    priority is computed when taking. An entry's priority is the most severe
    value queued for its incident, so an opened entry is explained before its
    queued escalation, which needs the opened baseline to stay eligible.
    """
    def __init__(self):
        self.explained = {}
        self.pending = deque()
        self.attempts = deque()
        self.displaced = None

    @staticmethod
    def _selected(t, baseline):
        """Openings, escalations past what was explained, and severe firsts.

        An incident whose opening was dropped (queue full, displaced, stale)
        has no baseline. An ordinary update of it stays unexplained, but one
        that reaches the severe range is explained as the incident's first:
        a severe escalation must not wait on an opening that will never come.
        """
        if t["event_type"] == "edge.incident.opened":
            return baseline is None
        if t["event_type"] != "edge.incident.updated":
            return False
        if baseline is None:
            return t["most_severe"] <= SEVERE_SEVERITY
        return t["most_severe"] < baseline

    def eligible(self, t):
        return self._selected(t, self.explained.get(t["incident_id"]))

    def _priorities(self):
        severity = {}
        for queued, _ in self.pending:
            ident = queued["incident_id"]
            severity[ident] = min(severity.get(ident, 10), queued["most_severe"])
        return [severity[queued["incident_id"]] for queued, _ in self.pending]

    def enqueue(self, t, sequence):
        self.displaced = None
        t = explanation_input(t) if "src_ip" in t else read_pending(t)
        baseline = self.explained.get(t["incident_id"])
        for queued, _ in self.pending:
            if queued["incident_id"] == t["incident_id"]:
                baseline = (queued["most_severe"] if baseline is None
                            else min(baseline, queued["most_severe"]))
        if not self._selected(t, baseline):
            return "skipped"
        if len(self.pending) >= MAX_PENDING:
            if t["most_severe"] > SEVERE_SEVERITY:
                return "queue_full"
            # Displace the newest ordinary entry of another incident: it is the
            # one drop-newest would have refused had this severe one come first,
            # and older ordinary work stays as accepted. Being newest, no later
            # entry of its incident depends on it. Severe-only queues still
            # drop the newest arrival.
            priorities = self._priorities()
            victims = [i for i, (queued, _) in enumerate(self.pending)
                       if priorities[i] > SEVERE_SEVERITY
                       and queued["incident_id"] != t["incident_id"]]
            if not victims:
                return "queue_full"
            self.displaced = self.pending[victims[-1]][0]["incident_id"]
            del self.pending[victims[-1]]
        self.pending.append((t, sequence))
        return "queued"

    def take(self, now):
        while self.attempts and now - self.attempts[0] >= 60:
            self.attempts.popleft()
        while self.pending and len(self.attempts) < MAX_PER_MINUTE:
            priorities = self._priorities()
            index = min(range(len(self.pending)), key=lambda i: (priorities[i], i))
            t, seq = self.pending[index]
            del self.pending[index]
            if self.eligible(t):
                self.attempts.append(now)
                return t, seq
        return None

    def mark(self, t):
        self.explained[t["incident_id"]] = t["most_severe"]
        if len(self.explained) > 1024:
            del self.explained[next(iter(self.explained))]


def read_mio_reply(reply):
    """Closed entryd reply, with separately validated advice/reference body."""
    base = {"route", "outcome", "reason", "ledger_seq"}
    if type(reply) is not dict or not base <= set(reply):
        raise ValueError("mio_reply_refused")
    if (reply["route"] == "deterministic handoff" and reply["outcome"] == "insufficient_information"
            and set(reply) == base | {"refusal", "advice", "fields"}
            and reply["reason"] == "insufficient_information" and reply["refusal"] is None
            and reply["fields"] == {}):
        _text(reply["advice"], 4096)
        _int(reply["ledger_seq"], 2**63-1)
        return {"route": reply["route"], "outcome": "refused", "reason": "mio_gated", "text": None,
                "content_kind": "none"}
    if reply["route"] not in {"local", "deterministic handoff"} or reply["outcome"] not in {o.value for o in RequestOutcome}:
        raise ValueError("mio_reply_refused")
    _text(reply["reason"], 2048)
    _int(reply["ledger_seq"], 2**63-1)
    advice = None
    if set(reply) == base and reply["route"] == "local" and reply["outcome"] != "answered":
        return {"route": "local", "outcome": reply["outcome"], "reason": "mio_local_non_advisory",
                "text": None, "content_kind": "none"}
    if reply["route"] == "local":
        body_keys = {"advice", "fields", "knowledge", *MACHINE_FIELDS}
        if not set(reply) <= base | body_keys:
            raise ValueError("mio_reply_refused")
        body = read_delivered({k: v for k, v in reply.items() if k in body_keys})
        advice = body["advice"]
    else:
        if "handoff" in reply:
            return _read_handoff(reply, base)
        # The pre-handoff shape carries no fixed notice, so a reference in it
        # could not be recorded with its label: it is refused, not guessed.
        # Only the bare "no reference" form of that shape is still read.
        if set(reply) != base | {"reference_status"} or reply["reference_status"] != "unavailable":
            raise ValueError("mio_reply_refused")
    reason = "mio_handoff" if reply["route"] == "deterministic handoff" else reply["reason"]
    kind = "ai_advice" if reply["route"] == "local" else "none"
    return {"route": reply["route"], "outcome": reply["outcome"], "reason": reason, "text": advice,
            "content_kind": kind}


_REASON_WORD = re.compile(r"[a-z][a-z0-9_]{0,63}")
_HANDOFF_FAILURE_ROUTES = {"local", "remote"}


def _read_handoff(reply, base):
    """The deterministic terminal step's reply: a reference or a fixed notice.

    Neither is an AI answer. A reference keeps its fixed banner as the text;
    a notice-only handoff carries no text, and the missing reason is kept in
    the record's reason so the operator sees why there was no reference.
    """
    if reply["route"] != "deterministic handoff":
        raise ValueError("mio_reply_refused")
    handoff = reply["handoff"]
    _shape(handoff, ("kind", "notice", "ai_attempts", "failures"))
    if handoff["notice"] not in HANDOFF_NOTICE.values():
        raise ValueError("mio_reply_refused")
    _int(handoff["ai_attempts"], 2)
    failures = handoff["failures"]
    if type(failures) is not list or len(failures) > handoff["ai_attempts"]:
        raise ValueError("mio_reply_refused")
    terminals = {event.value for event in TerminalEvent}
    for failure in failures:
        if (type(failure) is not dict or not {"route", "terminal_event"} <= set(failure)
                or not set(failure) <= {"route", "terminal_event", "refusal"}
                or failure["route"] not in _HANDOFF_FAILURE_ROUTES
                or failure["terminal_event"] not in terminals
                or ("refusal" in failure and (type(failure["refusal"]) is not str
                                              or not _REASON_WORD.fullmatch(failure["refusal"])))):
            raise ValueError("mio_reply_refused")
    if handoff["kind"] == "deterministic_reference":
        if (set(reply) != base | {"reference_status", "reference", "handoff"}
                or reply["reference_status"] != "attached"):
            raise ValueError("mio_reply_refused")
        text = read_reference(reply["reference"])["banner"]
        reason = "mio_handoff"
    elif handoff["kind"] == "deterministic_notice":
        if (set(reply) != base | {"reference_status", "reference_reason", "handoff"}
                or reply["reference_status"] != "unavailable"
                or type(reply["reference_reason"]) is not str
                or not _REASON_WORD.fullmatch(reply["reference_reason"])):
            raise ValueError("mio_reply_refused")
        text = None
        reason = "mio_handoff:" + reply["reference_reason"]
    else:
        raise ValueError("mio_reply_refused")
    # The fixed notice is kept with its language; `content_kind` labels what
    # `text` is, so a reader never shows a reference as if it were AI advice.
    return {"route": reply["route"], "outcome": reply["outcome"], "reason": reason, "text": text,
            "content_kind": handoff["kind"], "notice": handoff["notice"]}


#: What a record's `mio.text` is. Only `ai_advice` is an AI's output; both
#: deterministic kinds are fixed or verified material and say so.
CONTENT_KINDS = ("ai_advice", "deterministic_reference", "deterministic_notice", "none")
#: Derived on read, never written: a handoff record from before the label.
LEGACY_HANDOFF = "legacy_handoff"
CONTENT_LABELS = {
    "ai_advice": "AI advice (local model)",
    "deterministic_reference": "deterministic playbook reference (not AI)",
    "deterministic_notice": "deterministic handoff notice (not AI)",
    LEGACY_HANDOFF: "legacy unlabeled deterministic handoff (not AI)",
    "none": "no content",
}
#: The display state for each kind. Only an AI's advice is "explained".
CONTENT_STATES = {
    "ai_advice": "explained",
    "deterministic_reference": "reference_shown",
    "deterministic_notice": "notice_shown",
    "none": "unavailable",
}
#: States in which an explanation (of any kind) is on display.
SHOWN_STATES = frozenset({"explained", "reference_shown", "notice_shown"})
_HANDOFF_KINDS = frozenset({"deterministic_reference", "deterministic_notice", LEGACY_HANDOFF})


def content_kind(m):
    """The kind of a record's `mio`, derived from the route when unlabeled."""
    kind = m.get("content_kind")
    if kind is not None:
        return kind
    if m["route"] == "deterministic handoff":
        return LEGACY_HANDOFF
    return "ai_advice" if m["route"] == "local" and m["text"] else "none"


def content_state(kind, has_text):
    if kind == LEGACY_HANDOFF:
        return "reference_shown" if has_text else "unavailable"
    return CONTENT_STATES[kind]


def _check_content(kind, route, text, notice, *, banners=REFERENCE_BANNERS):
    """One consistency rule for records and snapshots; raises ValueError.

    `text` is the stored text (a record) or its summary (a snapshot), `""`
    or None meaning none. `banners` is the set a reference text must be in.
    """
    if kind not in CONTENT_STATES and kind != LEGACY_HANDOFF:
        raise ValueError("content_refused")
    if notice is not None and notice not in HANDOFF_NOTICE.values():
        raise ValueError("content_refused")
    if (notice is not None) != (kind in ("deterministic_reference", "deterministic_notice")):
        raise ValueError("content_refused")
    if kind in _HANDOFF_KINDS and route != "deterministic handoff":
        raise ValueError("content_refused")
    if kind == "ai_advice" and (route != "local" or not text):
        raise ValueError("content_refused")
    if kind in ("deterministic_notice", "none") and text:
        raise ValueError("content_refused")
    if kind == "deterministic_reference" and text not in banners:
        raise ValueError("content_refused")
    if kind == LEGACY_HANDOFF and text and text not in banners:
        raise ValueError("content_refused")


def _read_content(m):
    """Labelled records are checked as written; unlabeled ones as derived."""
    if m.get("content_kind") == LEGACY_HANDOFF or ("notice" in m and "content_kind" not in m):
        raise ValueError("record_refused")
    try:
        _check_content(content_kind(m), m["route"], m["text"], m.get("notice"))
    except ValueError:
        raise ValueError("record_refused") from None


RECORD_FIELDS = {"incident_id", "explained_at", "transition", "edge_would", "policy_reason",
                 "attack_type", "technique_ids", "mio", "knowledge_refs", "knowledge_state", "failure_codes"}


def read_record(value):
    _shape(value, RECORD_FIELDS)
    if type(value["incident_id"]) is not str or not re.fullmatch(r"inc-[0-9a-f]{16}", value["incident_id"]):
        raise ValueError("record_refused")
    _number(value["explained_at"])
    if value["transition"] not in {"opened", "updated"} or value["edge_would"] not in ACTIONS:
        raise ValueError("record_refused")
    _text(value["policy_reason"], 256)
    _text(value["attack_type"], 160, field="attack_type")
    if (private_text(value["attack_type"]) != value["attack_type"]
            or value["policy_reason"] not in POLICY_REASONS | {"other"}):
        raise ValueError("record_refused")
    ids = value["technique_ids"]
    if type(ids) is not list or len(ids) > 8 or any(type(t) is not str or not TECHNIQUE_ID.fullmatch(t) for t in ids):
        raise ValueError("record_refused")
    refs = read_knowledge_refs(value["knowledge_refs"])
    if any(r.technique_id not in ids for r in refs):
        raise ValueError("record_refused")
    if value["knowledge_state"] not in {"available", "no_context", "unavailable", "skipped"} or bool(refs) != (value["knowledge_state"] == "available"):
        raise ValueError("record_refused")
    codes = value["failure_codes"]
    if type(codes) is not list or len(codes) > len(CODES) or any(type(c) is not str or c not in CODES for c in codes):
        raise ValueError("record_refused")
    m = value["mio"]
    _shape(m, ("route", "outcome", "reason", "text"), ("content_kind", "notice"))
    if m["route"] not in {"local", "deterministic handoff", "unavailable"} or m["outcome"] not in {o.value for o in RequestOutcome} | {"unavailable"}:
        raise ValueError("record_refused")
    _text(m["reason"], 2048)
    if m["text"] is not None:
        _text(m["text"], 4096)
    _read_content(m)
    return json.loads(json.dumps(value, allow_nan=False))


RECENT_SCHEMA = "azazel-nexus/recent-incidents/v1"
RECENT_BYTES = 256 * 1024
RECOVERY_HINT = "inspect_incident_chain_then_remove_cursor_and_restart"
CLOSE_REASONS = ("idle", "capacity", "shutdown")


def build_recent_incident(transition, previous=None, record=None):
    """Project a validated transition and optional validated explanation, without identities."""
    t = read_transition(transition)
    clean = explanation_input(t)
    explanation = (previous["explanation"] if previous else
                   {"state": "pending", "route": "unavailable", "outcome": "unavailable",
                    "summary": "", "knowledge_refs": [], "failure_codes": []})
    if record is not None:
        r = read_record(record)
        if r["incident_id"] != t["incident_id"]:
            raise ValueError("recent_refused")
        explanation = explanation_summary(r)
    if (record is None and previous and t["event_type"] == "edge.incident.updated"
            and t["most_severe"] < previous["most_severe"]):
        explanation = {"state": "pending", "route": "unavailable", "outcome": "unavailable",
                       "summary": "", "knowledge_refs": [], "failure_codes": []}
    row = {**{k: t[k] for k in ("incident_id", "first_seen", "last_seen", "count",
                               "most_severe", "edge_would", "technique_ids")},
           "state": "closed" if t["event_type"] == "edge.incident.closed" else "open",
           "policy_reason": clean["policy_reason"], "explanation": explanation}
    # Audit records do not carry this; the ledger, recent rows and status do.
    if "evidence_stored" in t or previous and "evidence_stored" in previous:
        row["evidence_stored"] = False
    return row


def explanation_summary(record):
    r = read_record(record)
    refs = []
    for ref in r["knowledge_refs"][:8]:
        citation = {k: ref[k] for k in ("technique_id", "name", "claim_id")}
        try:
            _citation(citation, r["technique_ids"])
        except ValueError:
            continue
        refs.append(citation)
    m = r["mio"]
    kind = content_kind(m)
    summary = {"state": content_state(kind, bool(m["text"])),
               "route": m["route"], "outcome": m["outcome"],
               "summary": private_text(m["text"][:280], 280) if m["text"] else "",
               "knowledge_refs": refs, "failure_codes": r["failure_codes"],
               "content_kind": kind}
    if "notice" in m:
        summary["notice"] = m["notice"]
    return summary


def _summary_banners():
    return frozenset(private_text(b[:280], 280) for b in REFERENCE_BANNERS)


def build_recent_incidents(incidents, written_at):
    value = {"schema": RECENT_SCHEMA, "written_at": written_at,
             "incidents": sorted(incidents, key=lambda r: (r["last_seen"], r["first_seen"], r["incident_id"]),
                                 reverse=True)[:20]}
    checked = read_recent_incidents(json.dumps(value, allow_nan=False).encode())
    if checked is None:
        raise ValueError("recent_refused")
    return checked


def _citation(row, ids):
    _shape(row, ("technique_id", "name", "claim_id"))
    if (row["technique_id"] not in ids or row["claim_id"] != row["technique_id"]):
        raise ValueError("recent_refused")
    _text(row["name"], 120)
    # Citation names have already been validated by Knowledge. Reject address
    # syntax here as well: signed content is still untrusted display data.
    # A bare number token (a port, an integer address) is refused likewise.
    name = unicodedata.normalize("NFKC", row["name"])
    if not name or re.search(r"\d+(?:\.\d+){3}|(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*", name) or any(
            token.isdecimal() for token in re.split(r"[^\w]+|_", name)):
        raise ValueError("recent_refused")


def read_recent_incidents(raw):
    """Strict bounded operator boundary; never render partially valid content."""
    try:
        if type(raw) is not bytes or len(raw) > RECENT_BYTES:
            return None
        v = json.loads(raw.decode("utf-8"), object_pairs_hook=closed_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        _shape(v, ("schema", "written_at", "incidents"))
        if v["schema"] != RECENT_SCHEMA:
            return None
        _number(v["written_at"])
        if type(v["incidents"]) is not list or len(v["incidents"]) > 20:
            return None
        seen = set()
        for row in v["incidents"]:
            _shape(row, ("incident_id", "state", "first_seen", "last_seen", "count", "most_severe",
                         "edge_would", "policy_reason", "technique_ids", "explanation"),
                   ("evidence_stored",))
            if "evidence_stored" in row and row["evidence_stored"] is not False:
                return None
            ident = row["incident_id"]
            if type(ident) is not str or not re.fullmatch(r"inc-[0-9a-f]{16}", ident) or ident in seen:
                return None
            seen.add(ident)
            if (row["state"] not in {"open", "closed"} or row["edge_would"] not in ACTIONS
                    or row["policy_reason"] not in POLICY_REASONS | {"other"}):
                return None
            for key in ("first_seen", "last_seen"):
                _number(row[key])
            if row["last_seen"] < row["first_seen"]:
                return None
            _int(row["count"], 2**64-1)
            _int(row["most_severe"], 10)
            ids = row["technique_ids"]
            if type(ids) is not list or len(ids) > 8 or any(type(i) is not str or not TECHNIQUE_ID.fullmatch(i) for i in ids):
                return None
            e = row["explanation"]
            _shape(e, ("state", "route", "outcome", "summary", "knowledge_refs", "failure_codes"),
                   ("content_kind", "notice"))
            # The same consistency rule as a record, applied to the summary.
            if "content_kind" in e:
                try:
                    _check_content(e["content_kind"], e["route"], e["summary"], e.get("notice"),
                                   banners=_summary_banners())
                except ValueError:
                    return None
                if e["state"] != content_state(e["content_kind"], bool(e["summary"])):
                    return None
            elif "notice" in e or (e["state"] not in {"pending", "unavailable"}
                                   and not (e["state"] == "explained" and e["route"] == "local")):
                # Unlabeled rows (older snapshots, pending and unavailable
                # rows) may claim nothing but an AI explanation on the local
                # route; a handoff is never shown unlabeled.
                return None
            if (e["state"] not in {"pending", "unavailable"} | SHOWN_STATES
                    or e["route"] not in {"local", "deterministic handoff", "unavailable"}
                    or e["outcome"] not in {o.value for o in RequestOutcome} | {"unavailable"}):
                return None
            _text(e["summary"], 280)
            if e["summary"] and private_text(e["summary"], 280) != e["summary"]:
                return None
            codes = e["failure_codes"]
            if type(codes) is not list or len(codes) > len(CODES) or any(type(c) is not str or c not in CODES for c in codes):
                return None
            refs = e["knowledge_refs"]
            if type(refs) is not list or len(refs) > 8:
                return None
            for ref in refs:
                _citation(ref, ids)
        if v["incidents"] != sorted(v["incidents"], key=lambda r: (r["last_seen"], r["first_seen"], r["incident_id"]), reverse=True):
            return None
        return v
    except (ValueError, TypeError, UnicodeError, RecursionError, KeyError, OverflowError):
        return None


def read_explainer_status(raw):
    try:
        if type(raw) is not bytes or len(raw) > 8192:
            return None
        v = decode(raw)
        _shape(v, ("schema", "written_at", "last_explained_at", "explained", "refused", "pending",
                   "cursor_lag", "chain_broken", "recovery_hint", "storage_failed",
                   "mio_available", "knowledge_available", "audit_forward_dropped",
                   "audit_forward_refused"))
        if v["schema"] != "azazel-nexus/incident-explain-status/v1":
            return None
        _number(v["written_at"])
        if v["last_explained_at"] is not None:
            _number(v["last_explained_at"])
        for key in ("explained", "pending", "cursor_lag", "audit_forward_dropped", "audit_forward_refused"):
            _int(v[key], 2**64-1)
        for key in ("chain_broken", "storage_failed"):
            if type(v[key]) is not bool:
                return None
        for key in ("mio_available", "knowledge_available"):
            if v[key] is not None and type(v[key]) is not bool:
                return None
        if v["recovery_hint"] != (RECOVERY_HINT if v["chain_broken"] else None):
            return None
        if type(v["refused"]) is not dict or not set(v["refused"]) <= CODES:
            return None
        for n in v["refused"].values():
            _int(n, 2**64-1)
        return v
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        return None
