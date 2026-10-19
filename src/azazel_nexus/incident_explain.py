"""Pure, bounded observation-to-explanation logic. Never grants authority."""
from __future__ import annotations

import json
import re
from collections import deque

from .edge_intake import ACTIONS, _object, _shape, _text, _int, _number
from .lite_import import TECHNIQUE_ID, read_knowledge_refs
from .local_advisory import MACHINE_FIELDS, read_delivered, read_frame, read_reference
from .route_selection import RequestOutcome
from .sanitizer import PrivacyClass

MAX_PENDING = 64
MAX_PER_MINUTE = 6
MAX_LINE = 64 * 1024
CODES = frozenset({"transition_refused", "chain_broken", "queue_full", "mio_unavailable",
                   "mio_reply_refused", "knowledge_unavailable", "knowledge_reply_refused",
                   "storage_failed", "status_write_failed", "explanation_segment_full",
                   "cursor_refused", "read_failed"})
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

    _shape(value, FIELDS, ("category", "protocol", "reason"))
    _text(value["event_type"], 32)
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
    else:
        return False
    return True


def private_text(text, limit=256):
    """Free-form producer words may themselves contain network identifiers.

    Retain descriptive words; remove address literals, dotted names, URLs,
    email and mixed identifier tokens. Never insert a producer identifier as a kind.
    """
    text = text[:limit]
    return re.sub(r"\S+", lambda m: "[redacted]" if (
        any(c in m[0] for c in '.:@/\\-_') or any(c.isdigit() for c in m[0])
    ) else m[0], text) or "(absent)"


def build_frame(transition, sequence):
    t = read_transition(transition)
    _int(sequence, 2**63-1, 1)
    context = [
        {"kind": "edge_alert", "text": (
            f"incident={t['incident_id']}; signature={private_text(t['attack_type'])}; "
            f"category={private_text(t.get('category', 'unknown'))}; "
            f"protocol={private_text(t.get('protocol', 'unknown'))}; "
            f"destination_port={t['target_port']}; severity={t['most_severe']}; count={t['count']}")},
        {"kind": "edge_decision", "text": f"Edge would {t['edge_would']}; policy_reason={private_text(t['policy_reason'])}"},
    ]
    context.extend({"kind": "technique", "text": t_id} for t_id in t["technique_ids"])
    return read_frame({"request_id": f"{t['incident_id']}:{sequence}",
                       "privacy_class": PrivacyClass.P3_RESTRICTED.value,
                       "question": QUESTION, "context": context})


class Selection:
    """Drop newest at capacity. Remember a bounded set of explained ids."""
    def __init__(self):
        self.explained = {}
        self.pending = deque()
        self.attempts = deque()

    def eligible(self, t):
        old = self.explained.get(t["incident_id"])
        return (t["event_type"] == "edge.incident.opened" and old is None
                or t["event_type"] == "edge.incident.updated" and old is not None and t["most_severe"] < old)

    def enqueue(self, t, sequence):
        baseline = self.explained.get(t["incident_id"])
        for queued, _ in self.pending:
            if queued["incident_id"] == t["incident_id"]:
                baseline = (queued["most_severe"] if baseline is None
                            else min(baseline, queued["most_severe"]))
        selected = (t["event_type"] == "edge.incident.opened" and baseline is None
                    or t["event_type"] == "edge.incident.updated" and baseline is not None
                    and t["most_severe"] < baseline)
        if not selected:
            return "skipped"
        if len(self.pending) >= MAX_PENDING:
            return "queue_full"
        self.pending.append((t, sequence))
        return "queued"

    def take(self, now):
        while self.attempts and now - self.attempts[0] >= 60:
            self.attempts.popleft()
        while self.pending and len(self.attempts) < MAX_PER_MINUTE:
            t, seq = self.pending.popleft()
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
    if reply["route"] not in {"local", "deterministic handoff"} or reply["outcome"] not in {o.value for o in RequestOutcome}:
        raise ValueError("mio_reply_refused")
    _text(reply["reason"], 2048)
    _int(reply["ledger_seq"], 2**63-1)
    advice = None
    if reply["route"] == "local":
        body_keys = {"advice", "fields", "knowledge", *MACHINE_FIELDS}
        if not set(reply) <= base | body_keys:
            raise ValueError("mio_reply_refused")
        body = read_delivered({k: v for k, v in reply.items() if k in body_keys})
        advice = body["advice"]
    else:
        if set(reply) not in (base | {"reference_status"}, base | {"reference_status", "reference"}):
            raise ValueError("mio_reply_refused")
        if reply["reference_status"] == "attached" and "reference" in reply:
            advice = read_reference(reply["reference"])["banner"]
        elif reply["reference_status"] != "unavailable" or "reference" in reply:
            raise ValueError("mio_reply_refused")
    return {"route": reply["route"], "outcome": reply["outcome"], "reason": reply["reason"], "text": advice}


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
    _text(value["attack_type"], 1024, field="attack_type")
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
    _shape(m, ("route", "outcome", "reason", "text"))
    if m["route"] not in {"local", "deterministic handoff", "unavailable"} or m["outcome"] not in {o.value for o in RequestOutcome} | {"unavailable"}:
        raise ValueError("record_refused")
    _text(m["reason"], 2048)
    if m["text"] is not None:
        _text(m["text"], 4096)
    return json.loads(json.dumps(value, allow_nan=False))
