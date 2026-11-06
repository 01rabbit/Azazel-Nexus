"""Pure, bounded observation-to-explanation logic. Never grants authority."""
from __future__ import annotations

import json
import math
import re
import unicodedata
from collections import deque
from datetime import datetime

from .explanation_claims import (
    EDGE_CLAIM_LIMITATION,
    EVIDENCE_FIELD,
    EVIDENCE_NOT_CARRIED,
    EVIDENCE_SOURCE,
    EXPLANATION_KEYS,
    PROVENANCE_FIELD,
    edge_claim_limitations,
    evidence_observed_at,
    mio_claims,
)
from .edge_intake import ACTIONS, SEVERE_SEVERITY, _object, _shape, _text, _int, _number
from .lite_import import AS_OF, TECHNIQUE_ID, as_of_text, read_knowledge_refs, short_digest
from .local_advisory import (
    DELIVERY_TEXTS,
    HANDOFF_NOTICE,
    MACHINE_FIELDS,
    MIO_ASSISTANCE_STATES,
    REFERENCE_BANNERS,
    read_delivered,
    read_fast_assistance,
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
                   "mio_handoff", "mio_local_non_advisory", "mio_fast_unavailable",
                   "segment_from_future"})
QUESTION = ("Edge Core が次のセキュリティインシデントを検知しました。状況と、運用者が確認すべき点を説明してください。"
            "Edge の判断は観測のみで実行されていません。")
FIELDS = {"incident_id", "src_ip", "sid", "target_port", "count", "first_seen", "last_seen",
          "most_severe", "technique_ids", "first_evidence", "latest_evidence", "last_update",
          "edge_would", "policy_reason", "attack_type", "event_type"}
FAST_TRANSITION_KIND = "edge_transition"
MIO_TRACE_SEQUENCE_MAX = 999_999_999_999


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
    """The frame's input fields: no addresses, evidence or numeric rule ids.

    A pending entry is these plus the evidence pointers (`pending_entry`):
    digests and receive instants, which the frame never reads.
    """
    t = read_transition(t)
    return {**{k: t[k] for k in PENDING_FIELDS - {"attack_type", "category", "protocol", "policy_reason"}},
            "attack_type": private_text(t["attack_type"]),
            "category": t.get("category") if t.get("category") in CATEGORIES else "other",
            "protocol": t.get("protocol") if t.get("protocol") in {"tcp", "udp", "icmp"} else "other",
            "policy_reason": t["policy_reason"] if t["policy_reason"] in POLICY_REASONS else "other"}


#: The Edge evidence pointers a pending entry and an explanation record carry
#: (S-18, owner-decisions M17). Digests and receive instants only: the
#: content stays in intake's private evidence store, which the explainer
#: cannot read. Optional, so a checkpoint or a ledger written before them
#: still reads; a record without it projects as `evidence_refs_not_carried`.
#: The key is `EVIDENCE_FIELD` (`explanation_claims`).
#:
#: Which of the incident's evidence records a pointer names. When the
#: transition's first and latest pointers are the same record, one pointer
#: says so instead of naming it twice.
EVIDENCE_ROLES = ("first", "latest", "first_and_latest")
#: Why a pointer may not lead to a stored record. Never
#: `evidence_refs_not_carried`, which means no pointer was carried at all:
#: - `evidence_not_stored`: intake marked the incident (sticky `evidence_stored:
#:   false`): at least one of its evidence records hit a full day and was not
#:   stored. Which one is not known, so it is said of the record as a whole.
#: - `evidence_retention_elapsed`: a pointer's day was past intake's age
#:   retention when the explanation was written (its `retention` says which).
EVIDENCE_GAPS = ("evidence_not_stored", "evidence_retention_elapsed")
#: Intake's evidence age retention, in days (`edge_intaked.RETENTION_DAYS`;
#: `test_evidence_refs` keeps the two equal). Intake deletes a whole daily
#: segment once its day is this far behind its newest one, and sooner under
#: its byte bound. `window_elapsed` therefore means "intake may have retired
#: it", and `window_open` does not prove that the record is still stored:
#: the explainer never reads the private store, and says only what the two
#: instants decide.
EVIDENCE_RETENTION_DAYS = 14
EVIDENCE_RETENTION = ("window_open", "window_elapsed")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)


def evidence_pointer(t):
    """The pending evidence of a validated transition: digests and instants.

    Intake opens an incident at its first record's receive instant and
    updates `last_seen` with `latest_evidence` from the same record, so each
    pointer's `observed_at` is that record's `received_at`, as stored.
    """
    first = {"evidence_id": t["first_evidence"], "observed_at": t["first_seen"]}
    latest = {"evidence_id": t["latest_evidence"], "observed_at": t["last_seen"]}
    refs = ([{**first, "role": "first_and_latest"}] if first == latest else
            [{**first, "role": "first"}, {**latest, "role": "latest"}])
    return {"refs": refs, "gaps": ["evidence_not_stored"] if "evidence_stored" in t else []}


def pending_entry(t):
    """A transition as durable pending work: the frame's input plus evidence.

    The frame (`build_frame`) never reads the evidence: it goes to the
    explanation record, not to M.I.O.
    """
    t = read_transition(t)
    return {**explanation_input(t), EVIDENCE_FIELD: evidence_pointer(t)}


def evidence_retention(observed_at, explained_at):
    """`window_elapsed` when intake's age rule allowed the pointer's day to go."""
    def day(instant):
        return math.floor(instant / 86400) * 86400
    elapsed = day(observed_at) < day(explained_at) - EVIDENCE_RETENTION_DAYS * 86400
    return "window_elapsed" if elapsed else "window_open"


def record_evidence(pending, explained_at):
    """The record's evidence: each pointer with its retention as of writing."""
    refs = [{**ref, "retention": evidence_retention(ref["observed_at"], explained_at)}
            for ref in pending["refs"]]
    gaps = set(pending["gaps"])
    if any(ref["retention"] == "window_elapsed" for ref in refs):
        gaps.add("evidence_retention_elapsed")
    return {"refs": refs, "gaps": [g for g in EVIDENCE_GAPS if g in gaps]}


def _read_evidence(value, explained_at=None):
    """A pending entry's (no `explained_at`) or a record's evidence."""
    _shape(value, ("refs", "gaps"))
    refs, gaps = value["refs"], value["gaps"]
    keys = ("evidence_id", "role", "observed_at") + (() if explained_at is None else ("retention",))
    if type(refs) is not list or not 1 <= len(refs) <= 2:
        raise ValueError("evidence_refused")
    for ref in refs:
        _shape(ref, keys)
        if type(ref["evidence_id"]) is not str or not _DIGEST.fullmatch(ref["evidence_id"]):
            raise ValueError("evidence_refused")
        _number(ref["observed_at"])
        if (explained_at is not None
                and ref["retention"] != evidence_retention(ref["observed_at"], explained_at)):
            raise ValueError("evidence_refused")
    if [r["role"] for r in refs] not in (["first_and_latest"], ["first", "latest"]):
        raise ValueError("evidence_refused")
    allowed = EVIDENCE_GAPS if explained_at is not None else ("evidence_not_stored",)
    if type(gaps) is not list or gaps != [g for g in allowed if g in gaps]:
        raise ValueError("evidence_refused")
    if explained_at is not None and ("evidence_retention_elapsed" in gaps) != any(
            r["retention"] == "window_elapsed" for r in refs):
        raise ValueError("evidence_refused")


def read_pending(t):
    _shape(t, PENDING_FIELDS, (EVIDENCE_FIELD,))
    if EVIDENCE_FIELD in t:
        try:
            _read_evidence(t[EVIDENCE_FIELD])
        except ValueError:
            raise ValueError("pending_refused") from None
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
    pending = "src_ip" not in transition
    t = read_pending(transition) if pending else read_transition(transition)
    _int(sequence, 2**63-1, 1)
    edge = t if pending else explanation_input(t)
    context = [
        {"kind": "edge_alert", "text": (
            f"incident={edge['incident_id']}; signature={edge['attack_type']}; "
            f"category={edge['category']}; protocol={edge['protocol']}; "
            f"destination_port={edge['target_port']}; severity={edge['most_severe']}; count={edge['count']}")},
        {"kind": "edge_decision", "text": f"Edge would {edge['edge_would']}; policy_reason={edge['policy_reason']}"},
    ]
    context.extend({"kind": "technique", "text": t_id} for t_id in t["technique_ids"])
    # The explainer listener is the only ingress permitted to carry this
    # reserved machine projection. Prose stays in the ordinary report fields.
    evidence = (t.get(EVIDENCE_FIELD) if pending else evidence_pointer(t))
    evidence_refs = ([] if evidence is None else list(dict.fromkeys(
        ref["evidence_id"] for ref in evidence["refs"])))
    # The pinned trace grammar caps decimal sequence suffixes at twelve
    # digits. Preserve the general Edge sequence range; when it exceeds that
    # grammar, this optional M.I.O. projection is omitted.
    if sequence <= MIO_TRACE_SEQUENCE_MAX:
        structured = {
            "incident_id": t["incident_id"], "sequence": sequence,
            "event_type": edge["event_type"], "edge_would": edge["edge_would"],
            "attack_type": edge["attack_type"],
            "policy_reason": edge["policy_reason"], "category": edge["category"],
            "protocol": edge["protocol"], "target_port": edge["target_port"],
            "most_severe": edge["most_severe"], "count": edge["count"],
            "technique_ids": edge["technique_ids"], "evidence_refs": evidence_refs,
        }
        context.append({"kind": FAST_TRANSITION_KIND,
                        "text": json.dumps(structured, sort_keys=True, separators=(",", ":"))})
    return read_frame({"request_id": f"{t['incident_id']}:{sequence}",
                       "privacy_class": PrivacyClass.P3_RESTRICTED.value,
                       "question": QUESTION, "context": context})


def read_fast_transition(frame):
    """Validate the explainer-only structured projection inside a local frame."""
    entries = [item for item in frame["context"] if item["kind"] == FAST_TRANSITION_KIND]
    if not entries:
        return None
    if len(entries) != 1:
        raise ValueError("fast_transition_refused")
    try:
        value = json.loads(entries[0]["text"], object_pairs_hook=closed_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        required = {"incident_id", "sequence", "event_type", "edge_would", "attack_type", "policy_reason",
                    "category", "protocol", "target_port", "most_severe", "count",
                    "technique_ids", "evidence_refs"}
        _shape(value, required)
        if (type(value["incident_id"]) is not str
                or not re.fullmatch(r"inc-([0-9a-f]{16})", value["incident_id"])
                or type(value["sequence"]) is not int
                or not 1 <= value["sequence"] <= 999_999_999_999
                or frame["request_id"] != f"{value['incident_id']}:{value['sequence']}"
                or frame["privacy_class"] != PrivacyClass.P3_RESTRICTED.value
                or frame["question"] != QUESTION
                or value["event_type"] not in {"edge.incident." + kind
                                                for kind in ("opened", "updated", "closed")}
                or value["edge_would"] not in ACTIONS
                or value["policy_reason"] not in POLICY_REASONS | {"other"}
                or value["category"] not in CATEGORIES | {"other"}
                or value["protocol"] not in {"tcp", "udp", "icmp", "other"}):
            raise ValueError("fast_transition_refused")
        _text(value["attack_type"], 160, field="attack_type")
        if private_text(value["attack_type"]) != value["attack_type"]:
            raise ValueError("fast_transition_refused")
        _int(value["target_port"], 65535)
        _int(value["most_severe"], 10)
        _int(value["count"], 2**64-1)
        ids = value["technique_ids"]
        if type(ids) is not list or len(ids) > 8 or any(
                type(item) is not str or not TECHNIQUE_ID.fullmatch(item) for item in ids):
            raise ValueError("fast_transition_refused")
        refs = value["evidence_refs"]
        if (type(refs) is not list or len(refs) > 2 or
                any(type(ref) is not str or not _DIGEST.fullmatch(ref) for ref in refs)):
            raise ValueError("fast_transition_refused")
        edge_alert = (
            f"incident={value['incident_id']}; signature={value['attack_type']}; "
            f"category={value['category']}; protocol={value['protocol']}; "
            f"destination_port={value['target_port']}; severity={value['most_severe']}; "
            f"count={value['count']}"
        )
        expected_context = [
            {"kind": "edge_alert", "text": edge_alert},
            {"kind": "edge_decision", "text": (
                f"Edge would {value['edge_would']}; policy_reason={value['policy_reason']}"
            )},
            *({"kind": "technique", "text": technique_id}
              for technique_id in ids),
            {"kind": FAST_TRANSITION_KIND, "text": json.dumps(
                value, sort_keys=True, separators=(",", ":"))},
        ]
        machine_context = [item for item in frame["context"]
                           if item["kind"] in {
                               "edge_alert", "edge_decision", "technique", FAST_TRANSITION_KIND,
                           }]
        if machine_context != expected_context:
            raise ValueError("fast_transition_refused")
        return value
    except (TypeError, ValueError, KeyError):
        raise ValueError("fast_transition_refused") from None


def edge_fast_assistance_unavailable(frame):
    """Identify an Edge explainer frame whose cursor exceeds MIO's trace grammar."""
    if (frame.get("privacy_class") != PrivacyClass.P3_RESTRICTED.value
            or frame.get("question") != QUESTION
            or any(item["kind"] == FAST_TRANSITION_KIND for item in frame["context"])
            or not any(item["kind"] in {"edge_alert", "edge_decision", "technique"}
                       for item in frame["context"])):
        return False
    match = re.fullmatch(r"inc-[0-9a-f]{16}:([1-9][0-9]{12,18})", frame["request_id"])
    return match is not None and int(match.group(1)) > MIO_TRACE_SEQUENCE_MAX


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
        t = pending_entry(t) if "src_ip" in t else read_pending(t)
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


def validate_slow_analysis(value):
    """Validate bounded slow-analysis metadata without optional runtime imports.

    Public CORE contract: return None on success, raise ValueError on refusal.

    CORE cannot import the optional runtime. Unlike runtime normalization,
    malformed wire metadata refuses the reply instead of becoming closed.
    Valid slow output is not the incident fast conclusion and is not stored here.
    """
    try:
        if (type(value) is not dict or len(json.dumps(value, allow_nan=False).encode()) > 128 * 1024
                or set(value) - {'state', 'usage', 'generation_id', 'frame_id', 'trace_id',
                                 'assistance', 'calls', 'origin', 'result_handle', 'budget_version', 'generation_budget'}
                or value['state'] not in {'closed', 'degraded', 'queued', 'queue_full',
                                          'complete', 'timeout', 'cancelled', 'superseded', 'stale'}
                or value['usage'] not in {'known', 'unknown'}):
            raise ValueError("mio_reply_refused")
        if 'result_handle' in value and (type(value['result_handle']) is not str
                or re.fullmatch(r'[0-9a-f]{64}', value['result_handle']) is None):
            raise ValueError("mio_reply_refused")
        if 'assistance' in value:
            result = value['assistance']
            if (type(result) is not dict or result.get('schema_version') != 'mio.assistance.v1'
                    or result.get('frame_id') != value['frame_id']
                    or result.get('trace_id') != value['trace_id']
                    or value['frame_id'] != value['trace_id'] + ':frame'
                    or result.get('generation_method') not in {'model', 'static_reference'}):
                raise ValueError("mio_reply_refused")
        calls = value.get('calls', [])
        if type(calls) is not list or len(calls) > 16:
            raise ValueError("mio_reply_refused")
        for call in calls:
            if type(call) is not dict or set(call) != {'usage', 'timings'}:
                raise ValueError("mio_reply_refused")
            if call['usage'] is not None and (type(call['usage']) is not dict
                    or set(call['usage']) != {'tokens_in', 'tokens_out'}
                    or any(type(v) is not int or v < 0 for v in call['usage'].values())):
                raise ValueError("mio_reply_refused")
            if type(call['timings']) is not dict or any(type(v) not in (int, float)
                    or not math.isfinite(v) or v < 0 for v in call['timings'].values()):
                raise ValueError("mio_reply_refused")
        if value['usage'] == 'known' and (not calls or any(c['usage'] is None for c in calls)):
            raise ValueError("mio_reply_refused")
        if 'budget_version' in value or 'generation_budget' in value:
            from .generation_budget import read_budget
            if type(value.get('budget_version')) is not int or value['budget_version'] != 1:
                raise ValueError('mio_reply_refused')
            read_budget(value.get('generation_budget'), state=value['state'], usage=value['usage'])
            meta = value['generation_budget']
            sent = [task for task in meta['tasks'] if task['dispatched']]
            if len(calls) != len(sent) or any(call['usage'] != task['actual_usage'] for call,task in zip(calls,sent)):
                raise ValueError('mio_reply_refused')
            if value['state'] == 'complete':
                from .generation_budget import validate_model_assistance
                validate_model_assistance(value.get('assistance'),value['frame_id'],value['trace_id'])
        return
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ValueError("mio_reply_refused") from None


def read_mio_reply(reply):
    """Closed entryd reply, with separately validated advice/reference body."""
    if type(reply) is dict and "slow_analysis" in reply:
        validate_slow_analysis(reply["slow_analysis"])
        reply = {key: value for key, value in reply.items() if key != "slow_analysis"}
    fast = None
    if type(reply) is dict and "fast_assistance" in reply:
        fast = read_fast_assistance(reply["fast_assistance"])
        reply = {key: value for key, value in reply.items() if key != "fast_assistance"}
    def finish(value):
        # Preserve the request's ledger position with the validated reply.
        # The explanation record reader uses it to bind the optional fast
        # projection back to the Edge incident transition that produced it.
        value["ledger_seq"] = reply["ledger_seq"]
        if fast is not None:
            value["fast_assistance"] = fast
        return value
    base = {"route", "outcome", "reason", "ledger_seq"}
    if type(reply) is not dict or not base <= set(reply):
        raise ValueError("mio_reply_refused")
    if (reply["route"] == "deterministic handoff" and reply["outcome"] == "insufficient_information"
            and set(reply) == base | {"refusal", "advice", "fields"}
            and reply["reason"] == "insufficient_information" and reply["refusal"] is None
            and reply["fields"] == {}):
        _text(reply["advice"], 4096)
        _int(reply["ledger_seq"], 2**63-1)
        return finish({"route": reply["route"], "outcome": "refused", "reason": "mio_gated", "text": None,
                       "content_kind": "none"})
    if reply["route"] not in {"local", "deterministic handoff"} or reply["outcome"] not in {o.value for o in RequestOutcome}:
        raise ValueError("mio_reply_refused")
    _text(reply["reason"], 2048)
    _int(reply["ledger_seq"], 2**63-1)
    advice = None
    if set(reply) == base and reply["route"] == "local" and reply["outcome"] != "answered":
        return finish({"route": "local", "outcome": reply["outcome"], "reason": "mio_local_non_advisory",
                       "text": None, "content_kind": "none"})
    if reply["route"] == "local":
        body_keys = {"advice", "fields", "knowledge", *MACHINE_FIELDS}
        if not set(reply) <= base | body_keys:
            raise ValueError("mio_reply_refused")
        body = read_delivered({k: v for k, v in reply.items() if k in body_keys})
        advice = body["advice"]
        provenance = generation_provenance(body)
    else:
        if "handoff" in reply:
            return finish(_read_handoff(reply, base))
        # The pre-handoff shape carries no fixed notice, so a reference in it
        # could not be recorded with its label: it is refused, not guessed.
        # Only the bare "no reference" form of that shape is still read.
        if set(reply) != base | {"reference_status"} or reply["reference_status"] != "unavailable":
            raise ValueError("mio_reply_refused")
    reason = "mio_handoff" if reply["route"] == "deterministic handoff" else reply["reason"]
    kind = "ai_advice" if reply["route"] == "local" else "none"
    result = {"route": reply["route"], "outcome": reply["outcome"], "reason": reason, "text": advice,
              "content_kind": kind}
    if advice is not None:
        result[PROVENANCE_FIELD] = provenance
    return finish(result)


#: How a local-route answer was produced, recorded beside `content_kind`
#: (which stays `ai_advice` for every answered local reply, as existing
#: records and readers expect). Keyed by the delivery's `provenance.source`;
#: only the first is a model's own text, and the two matching methods carry a
#: fixed product banner (`local_advisory.DELIVERY_TEXTS`).
GENERATION_METHODS = {"model": "local_model_inference", "embedding": "embedding_matching",
                      "keyword": "deterministic_keyword_matching"}
#: The record's `mio` key for it is `PROVENANCE_FIELD`. Optional: records
#: written before it read, and a reader derives nothing from its absence.
_MODEL_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", re.ASCII)


def generation_provenance(body):
    """How a delivery `read_delivered` already checked was made, and what it said.

    Kept bounded, and only what the delivery's validated machine fields state:
    the method and retrieval, the admitted model's id when a model produced
    the text or ranked the candidates (None for keyword matching, which uses
    no model), the ranking's state, the candidate and the alternatives by id,
    and a model's own explanation fields when a model wrote them (each
    checked by `read_explanation` before delivery). No situation quotes, no
    playbook guidance, no frame. The delivery names no model generation (the
    admission ledger's generation and the model digest are not in it), so
    none is recorded, and a projection says so.
    """
    p = body["provenance"]
    source = p["source"]
    explanation = None
    if source == "model":
        explanation = {k: body["fields"]["model_" + k] for k in EXPLANATION_KEYS}
    return {"method": GENERATION_METHODS[source], "retrieval": p["retrieval"],
            "model_ref": None if source == "keyword" else p["model_id"],
            "state": p["state"],
            "candidate": {k: body["candidate"][k] for k in ("option_id", "kind")},
            "alternatives": [o["option_id"] for o in body["alternatives"]],
            "explanation": explanation}


_OPTION_ID = re.compile(r"[a-z0-9][a-z0-9_-]{2,63}", re.ASCII)
#: The longest explanation field a delivery carries: a label and a 160
#: character field (`local_advisory._FIELD_CAP`), with room for the label.
EXPLANATION_FIELD_CHARS = 256


def _read_provenance(m):
    p = m[PROVENANCE_FIELD]
    _shape(p, ("method", "retrieval", "model_ref", "state", "candidate", "alternatives",
               "explanation"))
    source = next((k for k, v in GENERATION_METHODS.items() if v == p["method"]), None)
    if (source is None or content_kind(m) != "ai_advice" or m["text"] not in DELIVERY_TEXTS[source]
            or p["retrieval"] not in ({"embedding", "keyword"} if source == "model" else {source})
            or (p["model_ref"] is None) != (source == "keyword")
            or p["model_ref"] is not None and (type(p["model_ref"]) is not str
                                               or not _MODEL_REF.fullmatch(p["model_ref"]))
            or p["state"] not in {"clear", "split", "none"}):
        raise ValueError("record_refused")
    candidate, alternatives = p["candidate"], p["alternatives"]
    _shape(candidate, ("option_id", "kind"))
    if (candidate["kind"] not in {"playbook", "other_suspicious"}
            or type(candidate["option_id"]) is not str or not _OPTION_ID.fullmatch(candidate["option_id"])
            or candidate["kind"] != "playbook" and candidate["option_id"] != candidate["kind"]
            or (candidate["kind"] == "other_suspicious") != (p["state"] == "none")
            or type(alternatives) is not list or not 1 <= len(alternatives) <= 5
            or any(type(a) is not str or not _OPTION_ID.fullmatch(a) for a in alternatives)
            or len(set(alternatives)) != len(alternatives) or candidate["option_id"] in alternatives):
        raise ValueError("record_refused")
    explanation = p["explanation"]
    if (explanation is None) != (source != "model"):
        raise ValueError("record_refused")
    if explanation is not None:
        _shape(explanation, EXPLANATION_KEYS)
        for value in explanation.values():
            if (type(value) is not str or not value or len(value) > EXPLANATION_FIELD_CHARS
                    or not all(c.isprintable() or c in "\n\t" for c in value)):
                raise ValueError("record_refused")


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


#: The optional, internal Fabric projection of a record
#: (`fabric_boundary.project_explanation`). Written only when the pinned Fabric
#: is present; never summarised, displayed or sent.
FABRIC_RECORD_FIELD = "fabric"
FABRIC_RECORD_BYTES = 32 * 1024
#: The claim id of the Edge decision, after the incident id, and the prefix of
#: each cited Knowledge reference's claim id.
EDGE_CLAIM_SUFFIX = ":edge"
KNOWLEDGE_CLAIM_PREFIX = "knowledge:"


def read_record(value):
    _shape(value, RECORD_FIELDS, (FABRIC_RECORD_FIELD, EVIDENCE_FIELD, "incident_sequence"))
    if type(value["incident_id"]) is not str or not re.fullmatch(r"inc-[0-9a-f]{16}", value["incident_id"]):
        raise ValueError("record_refused")
    if "incident_sequence" in value:
        _int(value["incident_sequence"], 2**63-1, 1)
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
    _shape(m, ("route", "outcome", "reason", "text"),
           ("content_kind", "notice", PROVENANCE_FIELD, "fast_assistance", "ledger_seq"))
    if m["route"] not in {"local", "deterministic handoff", "unavailable"} or m["outcome"] not in {o.value for o in RequestOutcome} | {"unavailable"}:
        raise ValueError("record_refused")
    _text(m["reason"], 2048)
    if m["text"] is not None:
        _text(m["text"], 4096)
    _read_content(m)
    if "ledger_seq" in m:
        _int(m["ledger_seq"], 2**63-1, 1)
    if PROVENANCE_FIELD in m:
        _read_provenance(m)
    if "fast_assistance" in m:
        fast = read_fast_assistance(m["fast_assistance"])
        # Older records predate incident_sequence and remain readable. New
        # records bind this projection to Edge's incident sequence. M.I.O.'s
        # ledger_seq is a separate counter and is validated independently.
        # Its fixed dependency_unavailable payload intentionally has a random
        # trace id because it can be produced without the Edge frame.
        if "incident_sequence" in value and fast["state"] != "dependency_unavailable":
            expected = f"mio-{value['incident_id'][4:]}-{value['incident_sequence']}"
            if fast["trace_id"] != expected or fast["frame_id"] != expected + ":frame":
                raise ValueError("record_refused")
    if EVIDENCE_FIELD in value:
        try:
            _read_evidence(value[EVIDENCE_FIELD], value["explained_at"])
        except ValueError:
            raise ValueError("record_refused") from None
    if FABRIC_RECORD_FIELD in value:
        _read_fabric_projection(value[FABRIC_RECORD_FIELD], value)
    return json.loads(json.dumps(value, allow_nan=False))


def _read_fabric_projection(f, record):
    """Check the stored projection against the record it was made from.

    Fabric's own models validated it when it was written; this reader runs
    without Fabric, so it checks what it can state from the record alone:

    - the keys `fabric_version` and `claim_set`, and `evidence_refs` exactly
      when the record carries evidence; a release-shaped version, and at most
      `FABRIC_RECORD_BYTES` of claim set;
    - `authority` is `descriptive_only` and `trace_id` is the incident id;
    - each `evidence_refs` item is the record's pointer as a Fabric
      `EvidenceRef`: its digest, `edge-core`, the incident id, its instant;
    - the first claim is the Edge decision: its id, `deterministic_core`, the
      statement made from the record's `edge_would` and `policy_reason`, the
      pointers' digests as its input references, and the limitations that say
      why a pointer may not lead to a stored record (or that none was carried);
    - when the record names a generation method, the M.I.O. answer's claims
      follow, exactly as `explanation_claims.mio_claims` makes them from the
      recorded provenance (candidate, then a model's explanation), with no
      model generation;
    - the rest are the record's cited references, each claim id once (first
      occurrence kept), in order: the id, `knowledge_advisory`, the statement
      from the reference's name and summary, the bundle digest as the only
      input reference, and the freshness.

    Other claim fields (schema version, confidence) are not checked here.
    A projection that drifted from its record is refused with the record.
    """
    evidence = record.get(EVIDENCE_FIELD)
    _shape(f, ("fabric_version", "claim_set") + (("evidence_refs",) if evidence else ()))
    if (type(f["fabric_version"]) is not str
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:rc[0-9]+)?", f["fabric_version"])):
        raise ValueError("record_refused")
    pointers = [ref["evidence_id"] for ref in evidence["refs"]] if evidence else []
    if evidence and f["evidence_refs"] != [
            {"evidence_id": ref["evidence_id"], "source": EVIDENCE_SOURCE,
             "trace_id": record["incident_id"], "observed_at": evidence_observed_at(ref["observed_at"])}
            for ref in evidence["refs"]]:
        raise ValueError("record_refused")
    cs = f["claim_set"]
    if (type(cs) is not dict or len(json.dumps(cs, allow_nan=False)) > FABRIC_RECORD_BYTES
            or cs.get("authority") != "descriptive_only" or cs.get("trace_id") != record["incident_id"]
            or type(cs.get("claims")) is not list or not cs["claims"]):
        raise ValueError("record_refused")
    claims = cs["claims"]
    if any(type(c) is not dict for c in claims):
        raise ValueError("record_refused")
    refs, seen = [], set()
    for r in record["knowledge_refs"]:  # each claim id once, first kept
        if r["claim_id"] not in seen:
            seen.add(r["claim_id"])
            refs.append(r)
    edge, cited = claims[0], claims[1:]
    if (edge.get("claim_id") != record["incident_id"] + EDGE_CLAIM_SUFFIX
            or edge.get("source") != "deterministic_core"
            or edge.get("statement") != (f"Edge would {record['edge_would']}; "
                                         f"policy_reason={record['policy_reason']}")
            or edge.get("input_refs") != pointers
            or edge.get("limitations") != edge_claim_limitations(
                record, len(refs) != len(record["knowledge_refs"]))):
        raise ValueError("record_refused")
    m = record["mio"]
    if PROVENANCE_FIELD in m:
        expected = mio_claims(record["incident_id"], m[PROVENANCE_FIELD], pointers)
        stated, cited = cited[:len(expected)], cited[len(expected):]
        if len(stated) != len(expected) or any(
                c.get("model_generation") is not None
                or any(c.get(k) != v for k, v in e.items())
                for c, e in zip(stated, expected)):
            raise ValueError("record_refused")
    if len(cited) != len(refs) or any(
            c.get("claim_id") != KNOWLEDGE_CLAIM_PREFIX + r["claim_id"] or c.get("source") != "knowledge_advisory"
            or c.get("statement") != r["name"] + (f": {r['summary']}" if r["summary"] else "")
            or c.get("input_refs") != [r["bundle_digest"]] or c.get("freshness") != r["freshness"]
            for c, r in zip(cited, refs)):
        raise ValueError("record_refused")


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
    elif previous and t["event_type"] in {"edge.incident.updated", "edge.incident.closed"}:
        # A newly observed transition cannot inherit a previous full-node receipt.
        fast = explanation.get("fast_assistance")
        if type(fast) is dict and "full_node_context" in fast:
            fast = dict(fast)
            fast["full_node_context"] = _full_node_projection(None, "not_queried", "not_queried")
            fast["unknowns"] = [x for x in fast["unknowns"] if not x.startswith("KNOWLEDGE_CONTEXT_")]
            fast["next_checks"] = [x for x in fast["next_checks"] if x != FULL_NODE_INCOMPLETE_CHECK]
            explanation = {**explanation, "fast_assistance": fast}
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


#: A displayed citation: what was cited, and from which verified bundle,
#: generation and freshness, as of which lookup instant, under which signed
#: dataset citation. The digest is shortened: a display aid, not a check.
CITATION_FIELDS = ("technique_id", "name", "claim_id")
CITATION_DISPLAY_FIELDS = ("bundle_digest_short", "generation", "freshness", "as_of", "citation",
                           "citation_state")
#: `shown`: the bundle's citation is displayed; `none`: the bundle declares
#: none; `withheld`: it declares one this display will not show (address syntax).
CITATION_STATES = ("shown", "none", "withheld")
#: The escaped JSON budget for one row's displayed citations.
CITATION_DISPLAY_BYTES = 6 * 1024

FULL_NODE_INCOMPLETE_CHECK = (
    "Request an authorized current full-node Knowledge snapshot; this partial or stale advisory "
    "is not a complete current snapshot."
)
FULL_NODE_LIMITATIONS = (
    "Source reports are unverified and advisory only.",
    "Producer limitations were reported; their text is withheld.",
    "Source-level freshness deadlines are not included in this projection.",
)
FULL_NODE_FRESHNESS_LIMITATION = "source-level freshness deadlines are not included in this projection"


def _full_node_projection(advisory, status, knowledge_outcome):
    """Project only closed metadata; never copy source prose or subjects."""
    result = {"full_node_context_status": status, "outcome": "not_queried",
              "source_kind": None, "claim_status": None, "trust": None,
              "snapshot_state": None, "generated_at": None, "expires_at": None,
              "limitations": []}
    if advisory is not None:
        result.update(outcome=advisory["snapshot_state"],
                      source_kind=advisory["source_kind"], claim_status=advisory["claim_status"],
                      trust=advisory["trust"], snapshot_state=advisory["snapshot_state"],
                      generated_at=advisory["generated_at"], expires_at=advisory["expires_at"],
                      limitations=[FULL_NODE_LIMITATIONS[0]])
        if FULL_NODE_FRESHNESS_LIMITATION in advisory["limitations"]:
            result["limitations"].append(FULL_NODE_LIMITATIONS[2])
        if any(item != FULL_NODE_FRESHNESS_LIMITATION for item in advisory["limitations"]):
            result["limitations"].append(FULL_NODE_LIMITATIONS[1])
    elif status == "unavailable":
        result["outcome"] = "unavailable"
    elif status == "received":
        result["outcome"] = knowledge_outcome if knowledge_outcome in {"expired", "rejected"} else "unavailable"
    elif status == "unknown":
        result["outcome"] = "unknown"
    return result


def _read_full_node_projection(value):
    _shape(value, ("full_node_context_status", "outcome", "source_kind", "claim_status", "trust",
                   "snapshot_state", "generated_at", "expires_at", "limitations"))
    status, outcome = value["full_node_context_status"], value["outcome"]
    if type(status) is not str or status not in {"unknown", "not_queried", "received", "unavailable"}:
        raise ValueError("recent_refused")
    if type(outcome) is not str or outcome not in {"unknown", "not_queried", "unavailable", "rejected", "expired", "complete", "partial", "stale"}:
        raise ValueError("recent_refused")
    fields = ("source_kind", "claim_status", "trust", "snapshot_state", "generated_at", "expires_at")
    if outcome in {"complete", "partial", "stale"}:
        if (status not in {"received", "unknown"} or value["source_kind"] != "fabric_knowledge_context_response_v1"
                or value["claim_status"] != "source_reported_unverified"
                or value["trust"] != "unverified_advisory_only" or value["snapshot_state"] != outcome):
            raise ValueError("recent_refused")
        for key in ("generated_at", "expires_at"):
            if type(value[key]) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value[key]):
                raise ValueError("recent_refused")
        if datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")) <= datetime.fromisoformat(value["generated_at"].replace("Z", "+00:00")):
            raise ValueError("recent_refused")
        if value["limitations"] not in ([FULL_NODE_LIMITATIONS[0]],
                                         [FULL_NODE_LIMITATIONS[0], FULL_NODE_LIMITATIONS[1]],
                                         [FULL_NODE_LIMITATIONS[0], FULL_NODE_LIMITATIONS[2]],
                                         [FULL_NODE_LIMITATIONS[0], FULL_NODE_LIMITATIONS[2], FULL_NODE_LIMITATIONS[1]]):
            raise ValueError("recent_refused")
    else:
        if any(value[k] is not None for k in fields) or value["limitations"] != []:
            raise ValueError("recent_refused")
        if (status, outcome) not in {("unknown", "unknown"), ("not_queried", "not_queried"),
                                     ("unavailable", "unavailable"), ("received", "unavailable"),
                                     ("received", "expired"), ("received", "rejected")}:
            raise ValueError("recent_refused")


def explanation_summary(record):
    r = read_record(record)
    refs = []
    for ref in r["knowledge_refs"][:8]:
        citation = {k: ref[k] for k in CITATION_FIELDS}
        citation.update(bundle_digest_short=short_digest(ref["bundle_digest"]),
                        generation=ref["generation"], freshness=ref["freshness"],
                        as_of=ref["as_of"], citation=ref["citation"],
                        citation_state="shown" if ref["citation"] else "none")
        try:
            _display_citation(citation["citation"])
            if citation_names_a_path(citation["citation"]):
                raise ValueError("citation_names_a_path")
        except ValueError:
            # Producer text with address syntax is not displayed; the rest of
            # the citation still is, and says that one was withheld.
            citation.update(citation="", citation_state="withheld")
        try:
            _citation(citation, r["technique_ids"])
        except ValueError:
            continue
        refs.append(citation)
    # Twenty rows share one bounded snapshot; drop citations from the end
    # rather than let escaped producer text push the snapshot over its bound.
    while refs and len(json.dumps(refs).encode()) > CITATION_DISPLAY_BYTES:
        refs.pop()
    # Nothing is dropped silently: the display bound, unsafe names and the
    # bytes bound are counted and shown as a number of omitted citations.
    omitted = len(r["knowledge_refs"]) - len(refs)
    m = r["mio"]
    kind = content_kind(m)
    summary = {"state": content_state(kind, bool(m["text"])),
               "route": m["route"], "outcome": m["outcome"],
               "summary": private_text(m["text"][:280], 280) if m["text"] else "",
               "knowledge_refs": refs, "failure_codes": r["failure_codes"],
               "content_kind": kind}
    if "notice" in m:
        summary["notice"] = m["notice"]
    if "fast_assistance" in m:
        fast = m["fast_assistance"]
        summary["fast_assistance"] = {
            "state": fast.get("state", "unknown"),
            "unknowns": [private_text(v[:240], 240) for v in fast.get("unknowns", [])[:8]],
            "next_checks": [private_text(v[:240], 240) for v in fast.get("next_checks", [])[:8]],
            "knowledge": [
                {"technique_id": item.get("technique_id"), "name": private_text(item.get("name", "")[:120], 120),
                 "summary": private_text(item.get("summary", "")[:240], 240),
                 "freshness": item.get("freshness"), "as_of": item.get("as_of"),
                 "citation": private_text(item.get("source_citation", "")[:160], 160),
                 "revocation_status": item.get("revocation_status"),
                 "claim_status": "reported_unverified"}
                for item in fast.get("knowledge", [])[:8]
            ],
            "dependency_outcome": fast.get("dependency_outcome", {}),
        }
        advisory = fast.get("fabric_knowledge_context_advisory")
        if "full_node_context_status" in fast or advisory is not None:
            summary["fast_assistance"]["full_node_context"] = _full_node_projection(
                advisory, fast.get("full_node_context_status", "unknown"),
                fast["dependency_outcome"]["knowledge"])
    if omitted:
        summary["knowledge_refs_omitted"] = omitted
    return summary


SLOW_RESULT_STATES = frozenset({"queued", "complete", "degraded", "timeout", "cancelled",
                                "superseded", "stale", "closed"})


def _public_model_text(value):
    """Bound optional model prose before the read-only operator projection."""
    if type(value) is not str or not value:
        raise ValueError("slow_result_refused")
    normalized = unicodedata.normalize("NFKC", value)
    # The MIO frame excludes network addresses, but a generated response is
    # still untrusted. Withhold any address/path-like string at this boundary.
    if (any(ch in normalized for ch in "/\\⁄∕∖⧸⧹﹨")
            or re.search(r"://|(?:^|\s)//|[\w.+-]+@[\w.-]+|\b\d+(?:\.\d+){3}\b", normalized)
            or re.search(r"(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*", normalized)):
        return "Details withheld verify through an authorized source"
    words = []
    current = []
    for char in normalized:
        if char.isalpha():
            current.append(char)
        else:
            if current:
                words.append("".join(current[:32]))
                current = []
            if char.isspace() and (not words or words[-1] != " "):
                words.append(" ")
    if current:
        words.append("".join(current[:32]))
    text = "".join(words).strip()
    return text[:240] or "Details withheld verify through an authorized source"


def slow_analysis_projection(value):
    """Project only a labelled, bounded advisory; never expose retrieval handles."""
    if type(value) is not dict or value.get("state") not in SLOW_RESULT_STATES:
        raise ValueError("slow_result_refused")
    state = value["state"]
    public_budget = None
    if 'generation_budget' in value or 'budget_version' in value:
        from .generation_budget import read_budget
        if value.get('budget_version') != 1:
            raise ValueError('slow_result_refused')
        meta = read_budget(value.get('generation_budget'), state=state, usage=value.get('usage'))
        if state=='complete':
            from .generation_budget import validate_model_assistance
            validate_model_assistance(value.get('assistance'),value.get('frame_id'),value.get('trace_id'))
        public_budget = {'version':1, 'outcome':meta['outcome'], 'coverage':meta['coverage'],
            'cleanup_state':meta['cleanup']['state'], 'superseded':meta['superseded'],
            'omitted_units':meta['upstream_selection']['omitted_units']+sum(t['selection']['omitted_units'] for t in meta['tasks']),
            'reasons':list(meta['reasons']), 'coordinator_disposition':meta.get('coordinator_disposition')}
    elif state == 'complete':
        return {'state':'degraded','usage':'unknown','budget':{
            'version':0,'outcome':'legacy_unverified','coverage':'unknown',
            'cleanup_state':'not_needed','superseded':False,'omitted_units':0}}
    if state != "complete":
        return {"state": state, "usage": "unknown", **({"budget":public_budget} if public_budget else {})}
    if value.get("usage") not in {"known", "unknown"}:
        raise ValueError("slow_result_refused")
    assistance = value.get("assistance")
    if (type(assistance) is not dict or assistance.get("schema_version") != "mio.assistance.v1"
            or assistance.get("generation_method") != "model"
            or type(assistance.get("hypotheses")) is not list
            or len(assistance["hypotheses"]) > 4):
        raise ValueError("slow_result_refused")
    hypotheses = []
    for item in assistance["hypotheses"]:
        if (type(item) is not dict or item.get("verification") != "model_proposed_unverified"
                or type(item.get("statement")) is not str or not 0 < len(item["statement"]) <= 480):
            raise ValueError("slow_result_refused")
        hypotheses.append(_public_model_text(item["statement"]))
    arrays = {}
    for key, maximum in (("unknowns", 24), ("next_checks", 8)):
        values = assistance.get(key)
        if (type(values) is not list or len(values) > maximum
                or any(type(item) is not str or not 0 < len(item) <= 480 for item in values)):
            raise ValueError("slow_result_refused")
        arrays[key] = [_public_model_text(item) for item in values[:8]]
    return {"state": "complete", "usage": value.get("usage", "unknown"),
            "verification": "model_proposed_unverified", "hypotheses": hypotheses,
            **arrays, **({"budget":public_budget} if public_budget else {})}


def _summary_banners():
    return frozenset(private_text(b[:280], 280) for b in REFERENCE_BANNERS)


#: Path separators, after NFKC (which folds the full-width `／` and `＼`),
#: and the look-alike slashes NFKC leaves alone.
_PATH_SEPARATORS = frozenset("/\\\u2044\u2215\u2216\u29f8\u29f9\ufe68")


def citation_names_a_path(text) -> bool:
    """Whether a citation might name a file or directory (R389-01, R389b-01).

    Deliberately narrow on the public side: a displayed citation is a short
    name ("MITRE ATT&CK v14.1"), and **any** path separator -- whatever comes
    before it (`source=/srv/...`, `source:./...`, a full-width colon) --
    withholds it. A citation that is withheld still says it was withheld.
    """
    value = unicodedata.normalize("NFKC", str(text))
    return any(ch in _PATH_SEPARATORS for ch in value)


def _public_refs(row):
    """`row` with every path-naming citation withheld; rows read earlier
    (a checkpoint from a previous release) are cleaned the same way."""
    explanation = row.get("explanation")
    if not isinstance(explanation, dict) or not isinstance(explanation.get("knowledge_refs"), list):
        return row
    refs = []
    for ref in explanation["knowledge_refs"]:
        if (isinstance(ref, dict) and isinstance(ref.get("citation"), str)
                and citation_names_a_path(ref["citation"])):
            ref = {**ref, "citation": "", "citation_state": "withheld"}
        refs.append(ref)
    return {**row, "explanation": {**explanation, "knowledge_refs": refs}}


def build_recent_incidents(incidents, written_at):
    value = {"schema": RECENT_SCHEMA, "written_at": written_at,
             "incidents": [_public_refs(r) for r in sorted(
                 incidents, key=lambda r: (r["last_seen"], r["first_seen"], r["incident_id"]),
                 reverse=True)[:20]]}
    checked = read_recent_incidents(json.dumps(value, allow_nan=False).encode())
    if checked is None:
        raise ValueError("recent_refused")
    return checked


def _display_name(text):
    # Citation names have already been validated by Knowledge. Reject address
    # syntax here as well: signed content is still untrusted display data.
    # A bare number token (a port, an integer address) is refused likewise.
    name = unicodedata.normalize("NFKC", text)
    if re.search(r"\d+(?:\.\d+){3}|(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*", name) or any(
            token.isdecimal() for token in re.split(r"[^\w]+|_", name)):
        raise ValueError("recent_refused")


_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
#: An IPv4 literal: four octets 0-255, not part of a longer alphanumeric token.
_CITATION_IPV4 = re.compile(rf"(?<![0-9A-Za-z]){_OCTET}(?:\.{_OCTET}){{3}}(?![0-9A-Za-z])")
#: A URL scheme separator, or a network path that starts with `//`.
_CITATION_URL = re.compile(r"://|(?:^|\s)//\S")
#: IPv6-like colon groups and host:port forms. These can also match harmless
#: text (`12:30:45`, `Revision:2024`); such a citation is withheld as a
#: *possible* address form, and the display says so.
_CITATION_POSSIBLE = re.compile(r"(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*|[\w.-]+:\d{1,5}(?!\d)")


def _display_citation(text):
    """A citation may name versions ("v14.1", "2024"); never an address or URL.

    Narrower than `_display_name`: numbers are allowed; IPv4 literals, URL
    forms (`scheme://`, `//host`), IPv6-like groups and host:port forms are not.
    """
    value = unicodedata.normalize("NFKC", text)
    if (_CITATION_IPV4.search(value) or _CITATION_URL.search(value)
            or _CITATION_POSSIBLE.search(value)):
        raise ValueError("recent_refused")


def _citation(row, ids):
    """Exactly the full display citation, or the legacy three-key one.

    Rows written before the display fields existed (a checkpoint or a
    `recent.json` from the previous release) still read; any other subset or
    superset is refused.
    """
    if type(row) is dict and set(row) == set(CITATION_FIELDS):
        legacy = True
    else:
        _shape(row, CITATION_FIELDS + CITATION_DISPLAY_FIELDS)
        legacy = False
    if (row["technique_id"] not in ids or row["claim_id"] != row["technique_id"]):
        raise ValueError("recent_refused")
    _text(row["name"], 120)
    if not row["name"]:
        raise ValueError("recent_refused")
    _display_name(row["name"])
    if legacy:
        return
    _text(row["citation"], 160)
    if row["citation_state"] not in CITATION_STATES or bool(row["citation"]) != (
            row["citation_state"] == "shown"):
        raise ValueError("recent_refused")
    if row["citation"]:
        _display_citation(row["citation"])
    _int(row["generation"], 2**63 - 1)
    if (type(row["bundle_digest_short"]) is not str
            or not re.fullmatch(r"sha256:[0-9a-f]{12}", row["bundle_digest_short"])
            or row["freshness"] not in {"static", "current"}
            or type(row["as_of"]) is not str or not AS_OF.fullmatch(row["as_of"])
            or as_of_text(row["as_of"]) != row["as_of"]):
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
                   ("content_kind", "notice", "knowledge_refs_omitted", "fast_assistance",
                    "slow_analysis"))
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
            if "knowledge_refs_omitted" in e:
                # At most sixteen references are recorded per explanation.
                _int(e["knowledge_refs_omitted"], 16 - len(refs), 1)
            if "fast_assistance" in e:
                f = e["fast_assistance"]
                _shape(f, ("state", "unknowns", "next_checks", "knowledge", "dependency_outcome"),
                       ("full_node_context",))
                if "full_node_context" in f:
                    _read_full_node_projection(f["full_node_context"])
                if type(f["state"]) is not str or f["state"] not in MIO_ASSISTANCE_STATES:
                    return None
                for key in ("unknowns", "next_checks"):
                    if type(f[key]) is not list or len(f[key]) > 8:
                        return None
                    for text in f[key]:
                        _text(text, 240)
                if type(f["knowledge"]) is not list or len(f["knowledge"]) > 8:
                    return None
                for item in f["knowledge"]:
                    _shape(item, ("technique_id", "name", "summary", "freshness", "as_of",
                                  "citation", "revocation_status", "claim_status"))
                    if (type(item["claim_status"]) is not str
                            or item["claim_status"] != "reported_unverified"
                            or type(item["freshness"]) is not str
                            or item["freshness"] not in {"current", "static"}
                            or type(item["revocation_status"]) is not str
                            or item["revocation_status"] not in {"clear", "unknown"}):
                        return None
                    if (type(item["technique_id"]) is not str
                            or not TECHNIQUE_ID.fullmatch(item["technique_id"])):
                        return None
                    _text(item["name"], 120)
                    _text(item["summary"], 240)
                    if (type(item["as_of"]) is not str or not AS_OF.fullmatch(item["as_of"])
                            or as_of_text(item["as_of"]) != item["as_of"]):
                        return None
                    _text(item["citation"], 160)
                _shape(f["dependency_outcome"], ("knowledge", "deception"))
                dependency = f["dependency_outcome"]
                if (type(dependency["knowledge"]) is not str
                        or dependency["knowledge"] not in {
                            "available", "partial", "absent", "not_queried", "timeout", "expired", "rejected", "unavailable"}
                        or type(dependency["deception"]) is not str
                        or dependency["deception"] not in {
                            "available", "absent", "timeout", "rejected", "unavailable"}):
                    return None
                if dependency["knowledge"] == "not_queried" and f["knowledge"]:
                    return None
            if "slow_analysis" in e:
                slow = e["slow_analysis"]
                if type(slow) is not dict or slow.get("state") not in SLOW_RESULT_STATES:
                    return None
                if slow.get("usage") not in {"known", "unknown"}:
                    return None
                if 'budget' in slow:
                    from .generation_budget import validate_public_budget
                    validate_public_budget(slow['budget'],state=slow['state'])
                    slow = {k:v for k,v in slow.items() if k != 'budget'}
                if slow["state"] == "complete":
                    if set(slow) != {"state", "usage", "verification", "hypotheses",
                                     "unknowns", "next_checks"}:
                        return None
                    if (slow["verification"] != "model_proposed_unverified"
                            or type(slow["hypotheses"]) is not list or len(slow["hypotheses"]) > 4):
                        return None
                    for text in slow["hypotheses"]:
                        _text(text, 240)
                        if _public_model_text(text) != text:
                            return None
                    for key, maximum in (("unknowns", 8), ("next_checks", 8)):
                        if type(slow[key]) is not list or len(slow[key]) > maximum:
                            return None
                        for text in slow[key]:
                            _text(text, 240)
                            if _public_model_text(text) != text:
                                return None
                elif set(slow) != {"state", "usage"} or slow["usage"] != "unknown":
                    return None
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
                   "audit_forward_refused"), ("slow_result_store",))
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
        if "slow_result_store" in v and v["slow_result_store"] not in {None, "available", "unavailable"}:
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
