"""Past reference of an ATT&CK technique answer (technique-knowledge/1), DESIGN-D53 v2.

A technique answer lives in the row's current Full-node projection only while
it answers the row's latest observation. When the projection is replaced (an
update, a close, an Edge reset, a late explanation of an earlier transition),
the answer is copied, once, into the row key `technique_past_reference`, then
shown only as a *past reference*: retained and viewable, never adoptable for a
current decision.

The binding holds four values that exist at capture time and nothing guessed:
`incident_id`, `observed_sequence`, `technique_ids`, `attempted_at`. The reader
requires an exact match (`capture_digest`, the incident id and the record's
technique ids); a mismatch refuses the whole snapshot. A stub (`binding_missing`,
`size_dropped`) carries no record and no binding. Nothing here performs I/O,
and nothing here reads the ledger: the record is the closed record that
already passed the signature, validator and projector as the current answer.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone

from .technique_knowledge import read_projection

__all__ = ["VERSION", "STUB_STATES", "capture_from_row", "capture_late", "merge", "read",
           "size_dropped_stub", "view", "is_retained"]

VERSION = "technique-past-reference/1"
STUB_STATES = ("binding_missing", "size_dropped")
KEY = "technique_past_reference"
_ID = re.compile(r"inc-[0-9a-f]{16}", re.ASCII)
_TID = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?", re.ASCII)
_SECONDS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_BINDING = ("incident_id", "observed_sequence", "technique_ids", "attempted_at")
_MAX_SEQUENCE = 2**63 - 1


def _refused():
    raise ValueError("recent_refused")


def digest(binding, record):
    raw = json.dumps({"binding": binding, "record": record}, sort_keys=True,
                     separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return "sha256:" + hashlib.sha256(raw.encode("ascii")).hexdigest()


def is_retained(value):
    return type(value) is dict and value.get("state") == "retained"


def _stub(state):
    return {"version": VERSION, "state": state}


def size_dropped_stub():
    return _stub("size_dropped")


def _verified(record):
    """The closed, verified record, or None. Anything else is never captured."""
    try:
        record = read_projection(record)
    except ValueError:
        return None
    if record["transport"] != "received" or record["verification"] != "ok":
        return None
    return record


def _candidate(record, incident_id, sequence, ids, attempted_at):
    """('retained', value) when the four binding values exist and match, else ('stub', ...)."""
    record_ids = [r["technique_id"] for r in record["techniques"]]
    if (type(incident_id) is not str or not _ID.fullmatch(incident_id)
            or type(sequence) is not int or isinstance(sequence, bool)
            or not 1 <= sequence <= _MAX_SEQUENCE
            or type(ids) is not list or ids != record_ids
            or type(attempted_at) is not str or not _SECONDS.fullmatch(attempted_at)):
        return ("stub", _stub("binding_missing"))
    binding = {"incident_id": incident_id, "observed_sequence": sequence,
               "technique_ids": list(ids), "attempted_at": attempted_at}
    record = json.loads(json.dumps(record))
    return ("retained", {"version": VERSION, "state": "retained", "binding": binding,
                         "record": record, "capture_digest": digest(binding, record)})


def capture_from_row(row):
    """The candidate for the answer in `row`'s current projection, or None.

    Only the row's own current projection and trace are read. A current answer
    exists only for the row's latest observation (`_is_latest`), so the trace's
    `observed_sequence` and `last_attempt` are the answer's.
    """
    fast = (row.get("explanation") or {}).get("fast_assistance")
    node = fast.get("full_node_context") if type(fast) is dict else None
    raw = node.get("technique_knowledge") if type(node) is dict else None
    if raw is None:
        return None
    record = _verified(raw)
    if record is None:
        return None
    trace = row.get("full_node_trace")
    attempt = trace.get("last_attempt") if type(trace) is dict else None
    if type(trace) is not dict or trace.get("transition_query") != "queried" or attempt is None:
        return ("stub", _stub("binding_missing"))
    return _candidate(record, row.get("incident_id"), trace.get("observed_sequence"),
                      attempt.get("technique_ids"), attempt.get("attempted_at"))


def capture_late(summary, t, sequence, attempt, attempted_at):
    """The candidate for a late explanation, from the unmodified call arguments only.

    `summary` is the explanation before `without_current_full_node`; the row's
    existing current, past and trace are not inputs.
    """
    if type(attempt) is not dict or not attempt.get("queried"):
        return None
    fast = summary.get("fast_assistance") if type(summary) is dict else None
    node = fast.get("full_node_context") if type(fast) is dict else None
    raw = node.get("technique_knowledge") if type(node) is dict else None
    if raw is None:
        return None
    record = _verified(raw)
    if record is None:
        return None
    return _candidate(record, t["incident_id"], sequence, sorted(set(t["technique_ids"])),
                      attempted_at)


def merge(existing, candidate):
    """The row's past reference after offering `candidate` (None, or a value).

    A newer observation replaces an older retained answer; the same or an older
    one never does. A candidate without a binding leaves a retained answer
    alone and otherwise says that one was lost.
    """
    if candidate is None:
        return existing
    kind, value = candidate
    if kind == "stub":
        return existing if existing is not None else value
    if not is_retained(existing):
        return value
    return value if value["binding"]["observed_sequence"] > existing["binding"]["observed_sequence"] else existing


def _instant(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def read(value, incident_id):
    """Strict reader of the row key; ValueError("recent_refused") on anything else."""
    if type(value) is not dict:
        _refused()
    if set(value) == {"version", "state"}:
        if value["version"] != VERSION or type(value["state"]) is not str or value["state"] not in STUB_STATES:
            _refused()
        return value
    if (set(value) != {"version", "state", "binding", "record", "capture_digest"}
            or value["version"] != VERSION or value["state"] != "retained"):
        _refused()
    binding = value["binding"]
    if type(binding) is not dict or set(binding) != set(_BINDING):
        _refused()
    seq = binding["observed_sequence"]
    ids = binding["technique_ids"]
    if (binding["incident_id"] != incident_id or type(binding["incident_id"]) is not str
            or not _ID.fullmatch(binding["incident_id"])
            or type(seq) is not int or isinstance(seq, bool) or not 1 <= seq <= _MAX_SEQUENCE
            or type(ids) is not list or not 1 <= len(ids) <= 8
            or any(type(i) is not str or not _TID.fullmatch(i) for i in ids) or ids != sorted(set(ids))
            or type(binding["attempted_at"]) is not str or not _SECONDS.fullmatch(binding["attempted_at"])):
        _refused()
    try:
        _instant(binding["attempted_at"])
        record = read_projection(value["record"])
    except ValueError:
        _refused()
    if (record["transport"] != "received" or record["verification"] != "ok"
            or [r["technique_id"] for r in record["techniques"]] != ids
            or type(value["capture_digest"]) is not str or not _DIGEST.fullmatch(value["capture_digest"])
            or value["capture_digest"] != digest(binding, value["record"])):
        _refused()
    return value


def view(value, row_state, now, *, whole_seconds=False):
    """The derived, closed view of a stored past reference (never stored).

    One function for the API, the UI and the handoff, so the words agree.
    A past reference is never adoptable; `freshness` is a separate axis.
    `now` is compared as it is (the status view); `whole_seconds=True` floors both
    instants, as the handoff does for its whole-second `judged_at`. The screen
    judges again on the device clock.
    """
    base = {"adoption": "not_adoptable", "revocation": "not_checked", "retained": False}
    if not is_retained(value):
        state = value["state"]
        return {**base, "kind": "past_unavailable", "state": state,
                "adoption_reason": state, "freshness": None}
    record = value["record"]
    freshness, judged_at = "unjudgeable", None
    if type(now) in (int, float) and math.isfinite(now) and now >= 0:
        judged_at = datetime.fromtimestamp(int(now), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            expires = _instant(record["expires_at"])
            lapsed = (math.floor(now) >= math.floor(expires)) if whole_seconds else now >= expires
            freshness = "expired" if lapsed else "fresh"
        except ValueError:
            freshness = "unjudgeable"
    closed = row_state == "closed"
    return {**base, "retained": True, "state": "retained",
            "kind": "past_closed" if closed else "past_before_update",
            "adoption_reason": "closed_incident" if closed else "past_observation",
            "freshness": freshness, "judged_at": judged_at,
            "binding": {"incident_id": value["binding"]["incident_id"],
                        "observed_sequence": value["binding"]["observed_sequence"],
                        "technique_ids": list(value["binding"]["technique_ids"]),
                        "attempted_at": value["binding"]["attempted_at"]},
            "technique_knowledge": json.loads(json.dumps(record))}
