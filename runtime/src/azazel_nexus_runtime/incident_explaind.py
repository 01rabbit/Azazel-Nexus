"""Read incident chains and append local explanations; no Edge connection exists."""
from __future__ import annotations

import json
import copy
import math
import os
import queue
import re
import signal
import stat
import sys
import tempfile
import threading
import time
from collections import Counter, deque
from dataclasses import asdict
from pathlib import Path

from azazel_nexus.audit import AuditEntry, GENESIS_HASH
from azazel_nexus.edge_intake import canonical
from azazel_nexus.fabric_boundary import project_explanation
from azazel_nexus.incident_explain import (
    EVIDENCE_FIELD, FABRIC_RECORD_FIELD, CODES, MAX_LINE, MAX_PENDING, MIO_TRACE_SEQUENCE_MAX,
    Selection, build_frame, decode,
    record_evidence,
    build_recent_incident, build_recent_incidents, read_recent_incidents, explanation_summary,
    SHOWN_STATES, closed_pairs, read_control, read_retention_boundary, read_mio_reply, read_record, read_transition, read_pending,
    slow_analysis_projection, guard_public_model_text,
)
from azazel_nexus.lite_import import read_knowledge_refs
from azazel_nexus.store_dirs import fsync_directory, store_directory

from .edge_intaked import DailySegments, EvidenceStore, SegmentFull
from .knowledge_client import lookup_context
from .mio_locald import KNOWLEDGE_MAX_S
from .mio_referenced import REFERENCE_DEADLINE_MS
from .mio_socket_client import ServiceRefused, _exchange
from .status_snapshot import UiCopy

POLL_SECONDS = 1
POLL_BYTES = 256 * 1024
POLL_LINES = 64
CHECKPOINT_BYTES = 2 * 1024 * 1024
#: Delivery failures retry after these waits, then the head is dropped: with
#: the exchange deadline, one record holds the queue head for about 12 s.
AUDIT_BACKOFF_S = (0.5, 1, 2)
AUDIT_DEADLINE_S = 2
DAY = re.compile(r"\d{4}-\d{2}-\d{2}\.jsonl", re.ASCII)


def atomic_json(path, value, mode):
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".snapshot-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(value) + b"\n")
            os.fchmod(stream.fileno(), mode)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        fsync_directory(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_file(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("file_refused")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("file_refused")
    return raw


def append_audit(event):
    from .bootstrap_audit_client import AuditAppendReceipt
    result = _exchange(
        "audit-submit", "azaudit", "audit.append", {"event_type": event["event_type"]},
        payload={k: v for k, v in event.items() if k != "event_type"}, deadline_s=AUDIT_DEADLINE_S)
    if set(result) != {"sequence", "event_hash"}:
        raise ValueError("audit_receipt_refused")
    return AuditAppendReceipt(**result)


def with_fabric_claims(value):
    """The record, with Fabric's `ClaimSet` view of it when the pin is present.

    Internal only: the view stays in this ledger. Summaries, recent rows,
    status and audit events are built from the record's own fields and never
    carry it. The record itself keeps the evidence pointers and the generation
    method the view is made from, so they survive when the view is dropped. Any failure leaves the record exactly as it was, because Fabric
    is optional (ADR-0001) and a projection must not cost an explanation --
    including a full day: `Explainer.explain` writes the plain record when the
    projected one no longer fits.
    """
    try:
        projection = project_explanation(value)
        if not projection.available:
            return value
        return read_record({**value, FABRIC_RECORD_FIELD: projection.view.as_ledger()})
    except Exception:  # noqa: BLE001 - the plain record is always written
        return value


class ExplanationStore(EvidenceStore):
    def __init__(self, root, **limits):
        DailySegments.__init__(self, root, "explanations", **limits)

    def append_record(self, value):
        checked = read_record(value)
        class Record:
            received_at = checked["explained_at"]
            def as_dict(self):
                return checked
        try:
            self.append(Record())
        except SegmentFull:
            raise SegmentFull("explanation_segment_full") from None


GENERATION_RESULT_STATES = frozenset({"complete", "degraded", "timeout", "cancelled",
                                      "superseded", "stale", "closed"})
GENERATION_RESULT_SEGMENT_BYTES = 2 * 1024 * 1024
GENERATION_RESULT_MAX_BYTES = 8 * 1024 * 1024


def read_generation_event(value, *, history=False):
    """A separate durable record; never an amendment to either incident chain."""
    if type(value) is not dict:
        raise ValueError("generation_event_refused")
    kind = value.get("event_type")
    binding = {"incident_id", "incident_sequence", "request_id", "frame_id", "trace_id",
               "generation_id", "result_handle", "recorded_at"}
    if kind == "mio.generation.receipt":
        if set(value) != binding | {"event_type"}:
            raise ValueError("generation_event_refused")
    elif kind == "mio.generation.result":
        extra = {'budget_version','generation_budget'} if ('budget_version' in value or 'generation_budget' in value) else set()
        if set(value) not in (binding | {"event_type", "state", "usage"} | extra,
                              binding | {"event_type", "state", "usage", "assistance"} | extra):
            raise ValueError("generation_event_refused")
        if value.get("state") not in GENERATION_RESULT_STATES:
            raise ValueError("generation_event_refused")
        if value.get("usage") not in {"known", "unknown"}:
            raise ValueError("generation_event_refused")
        if extra:
            from azazel_nexus.generation_budget import read_budget
            if type(value.get('budget_version')) is not int or type(value.get('generation_budget')) is not dict:
                raise ValueError('generation_event_refused')
            if value['budget_version'] != 1:
                if not history or value['generation_budget'].get('version') != value['budget_version']:
                    raise ValueError('generation_event_refused')
            else:
                read_budget(value['generation_budget'],state=value['state'],usage=value['usage'])
                if value['state']=='complete':
                    from azazel_nexus.generation_budget import validate_model_assistance
                    validate_model_assistance(value.get('assistance'),value['frame_id'],value['trace_id'])
        if value["state"] == "complete":
            assistance = value.get("assistance")
            if (type(assistance) is not dict or assistance.get("schema_version") != "mio.assistance.v1"
                    or assistance.get("generation_method") != "model"
                    or assistance.get("frame_id") != value["frame_id"]
                    or assistance.get("trace_id") != value["trace_id"]
                    or type(assistance.get("hypotheses")) is not list
                    or len(assistance["hypotheses"]) > 4):
                raise ValueError("generation_event_refused")
            for hypothesis in assistance["hypotheses"]:
                if (type(hypothesis) is not dict
                        or hypothesis.get("verification") != "model_proposed_unverified"
                        or type(hypothesis.get("statement")) is not str
                        or not 0 < len(hypothesis["statement"]) <= 480):
                    raise ValueError("generation_event_refused")
            for key, maximum in (("unknowns", 24), ("next_checks", 8)):
                values = assistance.get(key)
                if (type(values) is not list or len(values) > maximum
                        or any(type(item) is not str or not 0 < len(item) <= 480 for item in values)):
                    raise ValueError("generation_event_refused")
        elif "assistance" in value:
            raise ValueError("generation_event_refused")
    elif kind == 'mio.generation.cleanup':
        from azazel_nexus.generation_budget import CLEANUP_REASONS
        if (set(value) != binding | {'event_type','cleanup_version','cleanup_revision','cleanup_state','cleanup_reason'}
                or type(value['cleanup_version']) is not int or value['cleanup_version'] != 1
                or type(value['cleanup_revision']) is not int or value['cleanup_revision'] != 1
                or value['cleanup_state'] not in {'confirmed','unconfirmed'}
                or value['cleanup_reason'] not in CLEANUP_REASONS
                or (value['cleanup_state']=='confirmed') != (value['cleanup_reason']=='stop_confirmed')):
            raise ValueError('generation_cleanup_refused')
    elif kind == 'mio.generation.superseded':
        if set(value) != binding | {'event_type'}:
            raise ValueError('generation_superseded_refused')
    else:
        raise ValueError("generation_event_refused")
    ident, seq = value["incident_id"], value["incident_sequence"]
    if (type(ident) is not str or not re.fullmatch(r"inc-[0-9a-f]{16}", ident)
            or type(seq) is not int or not 1 <= seq <= MIO_TRACE_SEQUENCE_MAX
            or value["request_id"] != f"{ident}:{seq}"):
        raise ValueError("generation_event_refused")
    expected_trace = f"mio-{ident[4:]}-{seq}"
    if (value["trace_id"] != expected_trace or value["frame_id"] != expected_trace + ":frame"
            or type(value["generation_id"]) is not str
            or not re.fullmatch(r"[A-Za-z0-9._@:+-]{1,64}", value["generation_id"])
            or type(value["result_handle"]) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", value["result_handle"])):
        raise ValueError("generation_event_refused")
    stamp = value["recorded_at"]
    if type(stamp) not in (int, float) or not math.isfinite(stamp) or stamp < 0:
        raise ValueError("generation_event_refused")
    if len(canonical(value)) > 128 * 1024:
        raise ValueError("generation_event_refused")
    return json.loads(json.dumps(value, allow_nan=False))


def fold_generation_events(events, *, allow_legacy_superseded=True):
    """Validate full bindings and immutable, bounded per-job event transitions."""
    receipts,terminal,cleanup,superseded = {},{},{},{}
    binding = ('incident_id','incident_sequence','request_id','frame_id','trace_id','generation_id','result_handle')
    for event in events:
        handle,kind = event['result_handle'],event['event_type']
        if kind == 'mio.generation.receipt':
            old = receipts.get(handle)
            if old is not None and old != event:
                raise ValueError('generation_receipt_conflict')
            receipts[handle] = event
            continue
        receipt = receipts.get(handle)
        if receipt is None or any(receipt[k] != event[k] for k in binding):
            raise ValueError('generation_event_unbound')
        if kind == 'mio.generation.result':
            old = terminal.get(handle)
            if old is not None and old != event:
                if (allow_legacy_superseded and 'budget_version' not in old
                        and 'budget_version' not in event and event['state']=='superseded'
                        and old['state']!='superseded' and handle not in superseded):
                    superseded[handle] = event
                    continue
                raise ValueError('generation_result_duplicate')
            terminal[handle] = event
        elif kind == 'mio.generation.cleanup':
            result = terminal.get(handle)
            if (result is None or result.get('budget_version') != 1
                    or result['generation_budget']['cleanup']['state'] != 'pending'):
                raise ValueError('generation_cleanup_transition')
            old = cleanup.get(handle)
            if old is not None and old != event:
                raise ValueError('generation_cleanup_revision_conflict')
            cleanup[handle] = event
        elif kind == 'mio.generation.superseded':
            # Invalidation may precede result arrival; it binds to the receipt.
            old = superseded.get(handle)
            if old is not None and old != event:
                raise ValueError('generation_superseded_duplicate')
            superseded[handle] = event
        else:
            raise ValueError('generation_event_refused')
    return receipts,terminal,cleanup,superseded


class GenerationResultStore(DailySegments):
    """Private append-only event stream for slow M.I.O. receipts and results."""
    def __init__(self, root):
        super().__init__(root, "mio-generation-results", max_bytes=GENERATION_RESULT_MAX_BYTES,
                         days=14, segment_bytes=GENERATION_RESULT_SEGMENT_BYTES, mode=0o700)

    def prepare(self, now):
        path = self.path_at(self.bounded(now))
        self.current = path
        existed = path.exists()
        os.close(self.open_segment(path, 0o600))
        if not existed:
            path.unlink()
        self.retain()

    def append_event(self, value, *, segment_at=None):
        checked = read_generation_event(value)
        existing = self.events()
        if checked in existing:
            return
        if checked['event_type'] == 'mio.generation.result' and any(
                row['event_type']=='mio.generation.result' and row['result_handle']==checked['result_handle'] for row in existing):
            raise ValueError('generation_result_duplicate')
        if checked['event_type'] != 'mio.generation.receipt' and not any(
                row['event_type']=='mio.generation.receipt' and row['result_handle']==checked['result_handle'] for row in existing):
            raise ValueError('generation_result_receipt_segment_missing')
        fold_generation_events(existing + [checked])
        if checked['event_type'] != 'mio.generation.receipt':
            receipt = next(row for row in existing if row['event_type']=='mio.generation.receipt'
                           and row['result_handle']==checked['result_handle'])
            if segment_at is not None and self.path_at(self.bounded(segment_at)) != self.path_at(self.bounded(receipt['recorded_at'])):
                raise ValueError('generation_receipt_segment_mismatch')
            segment_at = receipt['recorded_at']
        path = self.path_at(self.bounded(
            checked["recorded_at"] if segment_at is None else segment_at))
        self.current = path
        self.retain()
        if checked["event_type"] != "mio.generation.receipt" and not path.exists():
            raise ValueError("generation_result_receipt_segment_missing")
        data = canonical(checked) + b"\n"
        if len(data) > 128 * 1024:
            raise SegmentFull("generation_result_segment_full")
        fd = self.open_segment(path, 0o600)
        try:
            if os.fstat(fd).st_size + len(data) > self.segment_bytes:
                raise SegmentFull("generation_result_segment_full")
            if os.write(fd, data) != len(data):
                raise OSError("generation result append incomplete")
            os.fsync(fd)
        finally:
            os.close(fd)
        self.retain()

    def events(self):
        rows = []
        for path in sorted(self.directory.glob("????-??-??.jsonl")):
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size > self.segment_bytes):
                raise ValueError("generation_result_segment_refused")
            raw = read_file(path, self.segment_bytes)
            if raw and not raw.endswith(b"\n"):
                raise ValueError("generation_result_tail_incomplete")
            for line in raw.splitlines():
                if not line or len(line) > 128 * 1024:
                    raise ValueError("generation_result_line_refused")
                value = json.loads(line.decode("utf-8"), object_pairs_hook=closed_pairs,
                                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                rows.append(read_generation_event(value, history=True))
        return rows


#: The deadline the explainer gives entry for one `mio.advise`.
ADVISE_DEADLINE_MS = REFERENCE_DEADLINE_MS
#: How much longer the explainer waits than that. Entry measures its deadline
#: after this client has connected and sent, and delivers the reply (with the
#: deterministic handoff and any reference) before that deadline; this margin
#: covers the connect, the framing and the delivery on either side of it, so
#: the explainer never gives up before entry has answered. Software budget.
ADVISE_CALLER_MARGIN_MS = 250


def advise(frame, *, caller_epoch=None, private_metadata=None):
    """One `mio.advise`; the caller waits strictly longer than entry's deadline."""
    if private_metadata is not None:
        private_metadata.clear()
    arguments = {"deadline_ms": ADVISE_DEADLINE_MS}
    if caller_epoch is not None:
        arguments['caller_epoch'] = caller_epoch
    reply = _exchange(
        "mio-advise", "azmioentry", "mio.advise", arguments,
        payload=frame, deadline_s=(ADVISE_DEADLINE_MS + ADVISE_CALLER_MARGIN_MS) / 1000)
    if caller_epoch is not None:
        metadata = reply.pop('generation_metadata', None)
        if private_metadata is not None:
            private_metadata.clear()
            if type(metadata) is dict:
                private_metadata.update(metadata)
    return reply


def poll_generation_result(receipt, *, deadline_s=0.05, caller_epoch=None, private_metadata=None):
    """Relay a bound result poll through entryd's explainer-only socket."""
    stale = {"state": "stale", "usage": "unknown"}
    if private_metadata is not None:
        private_metadata.clear()
    try:
        arguments = {key: receipt[key] for key in
                     ("result_handle", "generation_id", "frame_id", "trace_id")}
        arguments["deadline_ms"] = max(1, min(50, int(deadline_s * 1000)))
        if caller_epoch is not None:
            arguments['caller_epoch'] = caller_epoch
        response = _exchange(
            "mio-advise", "azmioentry", "mio.generation.result", arguments,
            deadline_s=deadline_s)
        if caller_epoch is not None:
            metadata = response.pop('generation_metadata', None)
            if private_metadata is not None:
                private_metadata.clear()
                if type(metadata) is dict:
                    private_metadata.update(metadata)
        if type(response) is not dict or set(response) != {"outcome", "slow_analysis"}:
            return None
        from .mio_generation import read_slow_analysis
        value = read_slow_analysis(response["slow_analysis"])
        if response["outcome"] != "generation_result":
            return None
        if value.get("state") == "stale":
            return stale
        if any(value.get(key) != receipt.get(key) for key in
               ("result_handle", "generation_id", "frame_id", "trace_id")):
            return stale
        return value
    except Exception:
        # Transport failure is retryable; do not confuse it with an expired
        # or revoked handle and append a false terminal record.
        return None


class Explainer:
    def __init__(self, *, incidents, state, status_path, clock=time.time,
                 monotonic=time.monotonic, mio=None, knowledge=None, store_limits=None, audit=None,
                 ui_status_path=None, ui_recent_path=None, mio_result=None):
        self.incidents, self.state, self.status_path = incidents, state, status_path
        # The read-only UI's byte-identical copies (ADR-0007); optional.
        self.ui_status = UiCopy(ui_status_path, name="az-incident-explaind")
        self.ui_recent = UiCopy(ui_recent_path, name="az-incident-explaind")
        self.clock, self.monotonic = clock, monotonic
        from .mio_generation_journal import new_epoch
        self.restart_epoch = new_epoch()
        self._generation_private = None
        self._generation_metadata = {}
        self._generation_bindings = {}
        self._generation_restart_unknown = set()
        self._generation_recovered = set()
        self.mio = mio or (lambda frame: advise(frame, caller_epoch=self.restart_epoch,
                                               private_metadata=self._generation_metadata))
        self.mio_result = mio_result or (lambda receipt, **kw: poll_generation_result(receipt,
            caller_epoch=self.restart_epoch, private_metadata=self._generation_metadata, **kw))
        self.knowledge = knowledge or (lambda ids: lookup_context(ids, deadline_s=KNOWLEDGE_MAX_S))
        self.store_limits = store_limits or {}
        self.generation_store = None
        self._generation_store_failed = False
        self._generation_replay_required = False
        self._generation_receipts = {}
        self._generation_terminal = {}
        self._generation_cleanup = {}
        self._generation_superseded = {}
        self._generation_cleanup_deadlines = {}
        self._generation_current = {}
        self.recent = []
        self.audit_severities = {}
        self.audit_forward_dropped = self.audit_forward_refused = 0
        self._audit_lock = threading.Lock()
        self.audit_pending = queue.Queue(maxsize=256)
        self.audit = audit or append_audit
        self._recent_value = None
        self._recent_at = float("-inf")
        self.selection = Selection()
        self.cursor = {"segment": None, "offset": 0, "sequence": 0, "last_hash": GENESIS_HASH, "broken": False}
        self.refused = Counter()
        self.explained = 0
        self.last_explained_at = None
        self.chain_broken = self.storage_failed = False
        self.cursor_lag = 0
        self.mio_available = self.knowledge_available = None
        self._checkpoint_value = self._status_value = None
        self._status_at = float("-inf")

    def refuse(self, code):
        assert code in CODES
        self.refused[code] += 1

    def snapshot(self):
        return {"schema": "azazel-nexus/incident-explain-status/v1", "written_at": self.clock(),
                "last_explained_at": self.last_explained_at, "explained": self.explained,
                "refused": dict(self.refused), "pending": len(self.selection.pending),
                "cursor_lag": self.cursor_lag, "chain_broken": self.chain_broken,
                "recovery_hint": "inspect_incident_chain_then_remove_cursor_and_restart" if self.chain_broken else None,
                "storage_failed": self.storage_failed, "mio_available": self.mio_available,
                "slow_result_store": ("unavailable" if self._generation_store_failed else
                                      "available" if self.generation_store is not None else None),
                "knowledge_available": self.knowledge_available,
                "audit_forward_dropped": self.audit_forward_dropped,
                "audit_forward_refused": self.audit_forward_refused}

    def count_audit(self, name, n=1):
        # The poller and the forwarding worker both count; += is not atomic.
        with self._audit_lock:
            setattr(self, name, getattr(self, name) + n)

    def recent_status(self):
        # Guard at the actual public file/UI write boundary as well as during
        # library projection. Never rely on partial binding to hide model text.
        rows = copy.deepcopy(self.recent)
        for row in rows:
            slow = row.get("explanation", {}).get("slow_analysis", {})
            if slow.get("state") == "complete":
                for field in ("hypotheses", "unknowns", "next_checks"):
                    if type(slow.get(field)) is list:
                        slow[field] = [guard_public_model_text(text) for text in slow[field]]
        value = build_recent_incidents(rows, self.clock())
        now = self.monotonic()
        # Rewrite unchanged rows every 20 s so a quiet node is not shown stale.
        if now - self._recent_at < 5 or (value["incidents"] == self._recent_value
                                         and now - self._recent_at < 20):
            return
        self._recent_at = now
        try:
            atomic_json(self.status_path.with_name("recent.json"), value, 0o644)
            # The same bytes for the read-only UI (ADR-0007); never raises.
            self.ui_recent.write(canonical(value) + b"\n")
            self._recent_value = value["incidents"]
        except Exception:  # noqa: BLE001 - fixed code, independent snapshot
            self.refuse("status_write_failed")

    def observe_transition(self, t, *, sequence=None):
        ident = t["incident_id"]
        try:
            if sequence is not None:
                self._supersede_generation_for_transition(ident, sequence)
            previous = next((r for r in self.recent if r["incident_id"] == ident), None)
            row = build_recent_incident(t, previous)
            if sequence is not None and isinstance(row.get("explanation"), dict):
                if row["explanation"].get("slow_analysis") is not None:
                    row["explanation"] = {**row["explanation"],
                                           "slow_analysis": {"state": "superseded",
                                                             "usage": "unknown"}}
            self.recent = build_recent_incidents(
                [r for r in self.recent if r["incident_id"] != ident] + [row], self.clock())["incidents"]
        except Exception:  # noqa: BLE001 - display projection must not cost the audit record
            self.refuse("transition_refused")
        old = self.audit_severities.get(ident)
        kind = t["event_type"].removeprefix("edge.incident.")
        selected = kind in {"opened", "closed"} or kind == "updated" and old is not None and t["most_severe"] < old
        if kind == "closed":
            self.audit_severities.pop(ident, None)
        else:
            self.audit_severities[ident] = t["most_severe"] if old is None else min(old, t["most_severe"])
            if len(self.audit_severities) > 1024:
                del self.audit_severities[next(iter(self.audit_severities))]
        if not selected:
            return
        from datetime import datetime, UTC
        from azazel_nexus.incident_explain import CLOSE_REASONS
        if kind == "closed" and t["reason"] not in CLOSE_REASONS:
            self.refuse("transition_refused")
            return
        event = {"event_type": "edge.incident." + ("escalated" if kind == "updated" else kind),
                 **{k: t[k] for k in ("incident_id", "most_severe", "edge_would", "count")},
                 "technique_count": len(t["technique_ids"]),
                 "occurred_at": datetime.fromtimestamp(t["last_update"], UTC).isoformat().replace("+00:00", "Z")}
        if kind == "closed":
            event["reason"] = t["reason"]
        try:
            self.audit_pending.put_nowait(event)
        except queue.Full:
            self.count_audit("audit_forward_dropped")

    def explanation_unavailable(self, ident, code, *, displaced=False):
        """Show why this incident's queued work produced no explanation.

        Displaced work is the newest ordinary entry of an incident that may
        already be explained (its opening taken, its escalation still queued).
        That earlier explanation remains true and is kept on display; the
        displacement is still counted as queue_full. Restricting victims to
        incidents with nothing else queued would not cover this case, since
        the opening is no longer queued once explained.
        """
        for row in self.recent:
            if row["incident_id"] == ident:
                if displaced and row["explanation"]["state"] in SHOWN_STATES:
                    continue
                row["explanation"] = {"state": "unavailable", "route": "unavailable",
                                      "outcome": "unavailable", "summary": "",
                                      "knowledge_refs": [], "failure_codes": [code]}

    @staticmethod
    def _generation_binding(event):
        return {key: event[key] for key in
                ("incident_id", "incident_sequence", "request_id", "frame_id",
                 "trace_id", "generation_id", "result_handle")}

    def _append_generation_event(self, event, *, segment_at=None):
        if self._generation_store_failed or self.generation_store is None:
            return False
        try:
            self.generation_store.append_event(event, segment_at=segment_at)
            return True
        except Exception:  # noqa: BLE001 - optional result store never blocks Edge intake
            self._generation_store_failed = True
            self.refuse("storage_failed")
            return False

    def _set_generation_projection(self, receipt, value):
        handle = receipt["result_handle"]
        if self._generation_current.get(receipt["incident_id"]) != handle:
            return
        try:
            projection = slow_analysis_projection(value)
        except ValueError:
            projection = {"state": "degraded", "usage": "unknown"}
            if value.get('budget_version') not in (None,1):
                projection['budget'] = dict(version=0,outcome='unsupported',coverage='unknown',
                    cleanup_state='unconfirmed',superseded=False,omitted_units=0)
        if handle in self._generation_restart_unknown and 'budget' not in projection:
            projection = dict(state='degraded', usage='unknown', budget=dict(
                version=1, outcome='stop_unconfirmed', coverage='unknown', cleanup_state='unconfirmed',
                superseded=handle in self._generation_superseded, omitted_units=0,
                reasons=['stop_unconfirmed']))
        binding = self._generation_bindings.get(handle)
        if projection.get('state') == 'complete' and binding is not None:
            if binding['created_at'] <= self.clock() < binding['expires_at']:
                from azazel_nexus import incident_explain as contract
                if hasattr(contract, 'valid_handoff_binding'):
                    projection['binding'] = copy.deepcopy(binding)
                else:
                    # Mixed A/base library cannot read B's new projection.
                    projection = {'state': 'degraded', 'usage': 'unknown'}
        if (projection.get('state') != 'complete' and (
                handle in self._generation_recovered or handle in self._generation_restart_unknown
                or value.get('generation_budget', {}).get('cleanup', {}).get('reason') == 'restart_unconfirmed')):
            from azazel_nexus.incident_explain import public_unknown_metadata
            unknowns = []
            try:
                observation = self._private_generation_journal().observation(receipt['request_id'])
                unknowns = public_unknown_metadata(observation['unknowns'])
            except (OSError, ValueError, KeyError, TypeError):
                pass  # Report unavailability even when the ID-only sidecar is unreadable.
            projection['recovery'] = dict(status='unavailable_after_restart', unknowns=unknowns)
        for row in self.recent:
            if row["incident_id"] == receipt["incident_id"]:
                explanation = dict(row["explanation"])
                explanation["slow_analysis"] = projection
                row["explanation"] = explanation

    def _generation_value(self, handle):
        if handle in self._generation_restart_unknown:
            return {'state': 'degraded', 'usage': 'unknown'}
        value = copy.deepcopy(self._generation_terminal.get(handle))
        if value is None:
            return {'state':'superseded' if handle in self._generation_superseded else 'queued','usage':'unknown'}
        if value.get('budget_version') == 1:
            from azazel_nexus.generation_budget import project_budget
            meta = value['generation_budget']
            cleanup = self._generation_cleanup.get(handle)
            if cleanup is not None:
                meta['cleanup'] = dict(state=cleanup['cleanup_state'],reason=cleanup['cleanup_reason'],remaining_ms=0)
            if handle in self._generation_superseded:
                meta['superseded'] = True
            value['state'],value['generation_budget'] = project_budget(meta)
            if value['state'] != 'complete':
                value.pop('assistance',None)
        elif handle in self._generation_superseded:
            value.update(state='superseded',usage='unknown')
            value.pop('assistance',None)
        return value

    def _private_generation_journal(self):
        if self._generation_private is None:
            from .mio_generation_journal import GenerationJournal
            self._generation_private = GenerationJournal(Path(self.state) / 'mio-generation-private')
        return self._generation_private

    def _capture_private_binding(self, receipt):
        """Copy the budget caller's body-free manifest after receipt identity checks."""
        raw = self._generation_metadata
        try:
            if (raw.get('epoch') != self.restart_epoch or raw.get('handle') != receipt['result_handle']
                    or any(raw.get(k) != receipt[k] for k in ('request_id', 'frame_id', 'generation_id'))
                    or raw.get('template_version') not in {'1.6.0', '1.7.0', '1.8.0', '1.9.0', '1.10.0'}):
                return
            created, expires = raw['created_at'], raw['expires_at']
            if (any(type(t) not in (int, float) or not math.isfinite(t) for t in (created, expires))
                    or not created <= self.clock() < expires or expires-created > 300):
                return
            from .mio_generation_journal import unknown_metadata
            unknowns = raw['unknowns']
            if (type(unknowns) is not list or len(unknowns) > 24
                    or unknown_metadata([u['id'] for u in unknowns]) != unknowns):
                return
            private = self._private_generation_journal()
            if private.seen(receipt['request_id']):
                private.remember_unknowns(receipt['request_id'], [u['id'] for u in unknowns])
            self._generation_bindings[receipt['result_handle']] = dict(
                provenance_version=1, incident_id=receipt['incident_id'], request_id=receipt['request_id'],
                frame_id=receipt['frame_id'], template_version=raw['template_version'],
                created_at=created, expires_at=expires, unknowns=copy.deepcopy(unknowns),
                evidence_refs=copy.deepcopy(raw.get('evidence_refs', [])),
                hypothesis_ids=copy.deepcopy(raw.get('hypothesis_ids', [])),
                advisory_refs=copy.deepcopy(raw.get('advisory_refs', [])),
                completeness=raw.get('completeness', 'partial'))
        except (OSError, KeyError, TypeError, ValueError):
            return

    def _cleanup_pending(self, handle):
        value = self._generation_value(handle)
        return value.get('budget_version') == 1 and value.get('generation_budget',{}).get('cleanup',{}).get('state') == 'pending'

    def _record_generation_cleanup(self, receipt, state, reason):
        handle = receipt['result_handle']
        if not self._cleanup_pending(handle) or handle in self._generation_cleanup:
            return
        event = dict(event_type='mio.generation.cleanup',**self._generation_binding(receipt),
            recorded_at=self.clock(),cleanup_version=1,cleanup_revision=1,
            cleanup_state=state,cleanup_reason=reason)
        if self._append_generation_event(event, segment_at=receipt['recorded_at']):
            self._generation_cleanup[handle] = read_generation_event(event)
            self._generation_cleanup_deadlines.pop(handle,None)
            self._set_generation_projection(receipt,self._generation_value(handle))
            return True
        self._set_generation_projection(receipt,{'state':'degraded','usage':'unknown'})
        return False

    def _record_generation_superseded(self, receipt):
        handle = receipt['result_handle']
        if handle in self._generation_superseded:
            return True
        event = dict(event_type='mio.generation.superseded',**self._generation_binding(receipt),recorded_at=self.clock())
        if self._append_generation_event(event,segment_at=receipt['recorded_at']):
            self._generation_superseded[handle] = event
            self._set_generation_projection(receipt,self._generation_value(handle))
            return True
        return False

    def _record_generation_terminal(self, receipt, value, *, sent_at=None):
        handle = receipt['result_handle']
        if handle in self._generation_restart_unknown:
            return False  # permanent, including direct late callbacks
        if handle in self._generation_terminal:
            if value.get('state') == 'superseded':
                return self._record_generation_superseded(receipt)
            if self._cleanup_pending(handle):
                raw = value.get('generation_budget',{}).get('cleanup',{})
                if raw.get('state') in ('confirmed','unconfirmed'):
                    deadline = self._generation_cleanup_deadlines.get(handle,self.monotonic())
                    if self.monotonic() >= deadline:
                        return self._record_generation_cleanup(receipt,'unconfirmed','confirmation_deadline')
                    return self._record_generation_cleanup(receipt,raw['state'],raw['reason'])
            return
        value = copy.deepcopy(value)
        if handle in self._generation_superseded:
            if value.get('budget_version') == 1:
                from azazel_nexus.generation_budget import project_budget
                meta = value['generation_budget']
                meta['result_state'] = 'superseded'
                meta['superseded'] = True
                value['state'],value['generation_budget'] = project_budget(meta)
            else:
                value['state'] = 'superseded'
            value.pop('assistance',None)
        state = value.get('state') if type(value) is dict else None
        if state not in GENERATION_RESULT_STATES:
            state = 'degraded'
        event = {'event_type':'mio.generation.result',**self._generation_binding(receipt),
            'state':state,'usage':value.get('usage','unknown'),'recorded_at':self.clock()}
        if 'generation_budget' in value or 'budget_version' in value:
            event.update(budget_version=value.get('budget_version'),generation_budget=value.get('generation_budget'))
        if state == 'complete':
            event['assistance'] = value.get('assistance')
        try:
            checked = read_generation_event(event)
        except ValueError:
            checked = read_generation_event({'event_type':'mio.generation.result',
                **self._generation_binding(receipt),'state':'degraded','usage':'unknown','recorded_at':self.clock()})
        durable = checked
        if checked.get('budget_version') == 1 and checked['state'] == 'complete':
            # Model bodies remain only in this process. Preserve accounting in
            # the durable receipt, with an explicitly unconfirmed restart view.
            from .mio_generation_journal import restored_status
            restored = restored_status(checked['generation_budget'], dict(
                generation_id=receipt['generation_id'], frame_id=receipt['frame_id'],
                trace_id=receipt['trace_id'], handle=handle))
            durable = {**checked, 'state': restored['state'], 'usage': restored['usage'],
                       'generation_budget': restored['generation_budget']}
            durable.pop('assistance', None)
        if not self._append_generation_event(durable,segment_at=receipt['recorded_at']):
            self._set_generation_projection(receipt,{'state':'degraded','usage':'unknown'})
            return False
        self._generation_terminal[handle] = checked
        if self._cleanup_pending(handle):
            remaining = checked['generation_budget']['cleanup']['remaining_ms']/1000
            start = self.monotonic() if sent_at is None else sent_at
            deadline = min(self._generation_cleanup_deadlines.get(handle,float('inf')),start+remaining)
            self._generation_cleanup_deadlines[handle] = deadline
        self._set_generation_projection(receipt,self._generation_value(handle))
        return True

    def _capture_generation_receipt(self, reply, transition, sequence, *, sent_at=None):
        if self._generation_store_failed or self.generation_store is None or type(reply) is not dict:
            return
        raw = reply.get("slow_analysis")
        if type(raw) is not dict:
            return
        from .mio_generation import read_slow_analysis
        value = read_slow_analysis(raw)
        if (value.get("state") not in {"queued", *GENERATION_RESULT_STATES}
                or "result_handle" not in value):
            return
        ident = transition["incident_id"]
        seq = int(sequence)
        expected_trace = f"mio-{ident[4:]}-{seq}"
        if (seq > MIO_TRACE_SEQUENCE_MAX or value.get("trace_id") != expected_trace
                or value.get("frame_id") != expected_trace + ":frame"
                or type(value.get("generation_id")) is not str):
            return
        receipt = {"event_type": "mio.generation.receipt", "incident_id": ident,
                   "incident_sequence": seq, "request_id": f"{ident}:{seq}",
                   "frame_id": value["frame_id"], "trace_id": value["trace_id"],
                   "generation_id": value["generation_id"],
                   "result_handle": value["result_handle"], "recorded_at": self.clock()}
        try:
            receipt = read_generation_event(receipt)
        except ValueError:
            return
        existing = self._generation_receipts.get(receipt["result_handle"])
        if existing is not None:
            if self._generation_binding(existing) != self._generation_binding(receipt):
                self._generation_store_failed = True
                self.refuse("storage_failed")
                return
            receipt = existing
        else:
            try:
                private = self._private_generation_journal()
                if private.seen(receipt['request_id']):
                    observation = private.observation(receipt['request_id'])
                    if observation.get('epoch') != self.restart_epoch or observation.get('handle') != receipt['result_handle']:
                        self._generation_restart_unknown.add(receipt['result_handle'])
                else:
                    from types import SimpleNamespace
                    private.reserve(receipt['request_id'], receipt['result_handle'], receipt['generation_id'],
                        SimpleNamespace(frame_id=receipt['frame_id'], trace_id=receipt['trace_id']), self.restart_epoch, 60)
            except (OSError, ValueError, KeyError):
                self._generation_restart_unknown.add(receipt['result_handle'])
            # Durable receipt first: polling never starts for an unrecorded job.
            if not self._append_generation_event(receipt):
                return
            self._generation_receipts[receipt["result_handle"]] = receipt
        current = self._generation_current.get(ident)
        if current is None or self._generation_receipts[current]["incident_sequence"] <= seq:
            self._generation_current[ident] = receipt["result_handle"]
        self._capture_private_binding(receipt)
        if receipt['result_handle'] in self._generation_restart_unknown:
            self._set_generation_projection(receipt, self._generation_value(receipt['result_handle']))
            return
        if value["state"] != "queued":
            self._record_generation_terminal(receipt, value, sent_at=sent_at)
        else:
            self._set_generation_projection(receipt, {"state": "queued", "usage": "unknown"})

    def _restore_generation_results(self):
        receipts,terminal,cleanup,superseded = fold_generation_events(self.generation_store.events())
        current = {}
        for handle,event in receipts.items():
            ident = event['incident_id']
            if ident not in current or receipts[current[ident]]['incident_sequence'] <= event['incident_sequence']:
                current[ident] = handle
        self._generation_receipts,self._generation_terminal = receipts,terminal
        self._generation_cleanup,self._generation_superseded = cleanup,superseded
        self._generation_cleanup_deadlines = {}
        self._generation_current = current
        self._generation_recovered.update(receipts)
        for handle,receipt in receipts.items():
            if handle not in terminal:
                # A receipt without a result is never re-adopted after restart,
                # including legacy receipts without an epoch sidecar.
                self._generation_restart_unknown.add(handle)
                try:
                    private = self._private_generation_journal()
                    if not private.seen(receipt['request_id']):
                        from types import SimpleNamespace
                        private.reserve(receipt['request_id'], handle, receipt['generation_id'],
                            SimpleNamespace(frame_id=receipt['frame_id'], trace_id=receipt['trace_id']),
                            'unavailable-before-restart', 60)
                    private.fence(receipt['request_id'], 'stale_epoch', restart_epoch=self.restart_epoch)
                except (OSError, ValueError, KeyError):
                    pass  # absence/corruption also leaves the receipt unknown
            if self._cleanup_pending(handle):
                self._record_generation_cleanup(receipt,'unconfirmed','restart_unconfirmed')
        for ident,handle in current.items():
            self._set_generation_projection(receipts[handle],self._generation_value(handle))

    def _supersede_generation_for_transition(self, ident, sequence):
        for handle,receipt in tuple(self._generation_receipts.items()):
            if receipt['incident_id'] == ident and receipt['incident_sequence'] < sequence:
                if not self._record_generation_superseded(receipt):
                    self._generation_replay_required = True

    def _poll_generation_results(self):
        if self._generation_store_failed:
            return
        for handle,receipt in tuple(self._generation_receipts.items()):
            if handle in self._generation_restart_unknown:
                continue
            pending = self._cleanup_pending(handle)
            if handle in self._generation_terminal and not pending:
                continue
            sent_at = self.monotonic()
            if pending and sent_at >= self._generation_cleanup_deadlines.get(handle,sent_at):
                self._record_generation_cleanup(receipt,'unconfirmed','confirmation_deadline')
                return
            try:
                value = self.mio_result(receipt,deadline_s=.05)
            except Exception:
                value = None
            if value is None:
                if pending:
                    self._record_generation_cleanup(receipt,'unconfirmed','observation_lost')
                return
            if type(value) is not dict or value.get('state') in (None,'queued'):
                if pending:
                    self._record_generation_cleanup(receipt,'unconfirmed','observation_lost')
                return
            if any(value.get(key) != receipt.get(key) for key in ('result_handle','generation_id','frame_id','trace_id')):
                if pending:
                    self._record_generation_cleanup(receipt,'unconfirmed','observation_lost')
                else:
                    self._record_generation_terminal(receipt,{'state':'stale','usage':'unknown'})
            elif pending:
                try:
                    from .mio_generation import read_slow_analysis
                    checked = read_slow_analysis(value)
                    if checked.get('budget_version') != 1:
                        raise ValueError
                    original = self._generation_terminal[handle]['generation_budget']
                    updated = checked['generation_budget']
                    immutable = set(original)-{'cleanup','outcome','reasons','superseded','result_state'}
                    if (original['result_state'] != updated['result_state'] and original['result_state'] != 'superseded') or any(original[k] != updated[k] for k in immutable) or not set(original['reasons']).issubset(updated['reasons']) or set(updated['reasons'])-set(original['reasons'])-{'stop_unconfirmed'}:
                        raise ValueError
                    raw = updated['cleanup']
                    if raw['state']=='pending':
                        deadline = min(self._generation_cleanup_deadlines[handle],sent_at+raw['remaining_ms']/1000)
                        self._generation_cleanup_deadlines[handle] = deadline
                        if self.monotonic() >= deadline:
                            self._record_generation_cleanup(receipt,'unconfirmed','confirmation_deadline')
                    elif raw['state'] in ('confirmed','unconfirmed'):
                        self._record_generation_terminal(receipt,checked,sent_at=sent_at)
                    else:
                        raise ValueError
                except (KeyError,TypeError,ValueError):
                    self._record_generation_cleanup(receipt,'unconfirmed','observation_lost')
            else:
                self._capture_private_binding(receipt)
                self._record_generation_terminal(receipt,value,sent_at=sent_at)
            return

    def forward_audit(self, stopped):
        # Keep the head inside the 256-entry queue during retries. This worker
        # alone removes heads; polling only appends and never waits for auditd.
        # A refusal is auditd's verdict on this record and retrying cannot
        # change it, so it is dropped at once; only failed delivery retries.
        attempts = 0
        while not stopped.is_set():
            with self.audit_pending.mutex:
                event = self.audit_pending.queue[0] if self.audit_pending.queue else None
            if event is None:
                stopped.wait(0.1)
                continue
            try:
                self.audit(event)
            except ServiceRefused as exc:
                if exc.refusal != "read_deadline":
                    self.count_audit("audit_forward_refused")
                elif self._audit_retry(stopped, attempts):
                    attempts += 1
                    continue
            except Exception:  # noqa: BLE001 - no peer text escapes
                if self._audit_retry(stopped, attempts):
                    attempts += 1
                    continue
            self.audit_pending.get_nowait()
            self.audit_pending.task_done()
            attempts = 0

    def _audit_retry(self, stopped, attempts):
        if attempts < len(AUDIT_BACKOFF_S):
            stopped.wait(AUDIT_BACKOFF_S[attempts])
            return True
        self.count_audit("audit_forward_dropped")
        return False

    def status(self):
        self.recent_status()
        value = self.snapshot()
        content = {k: v for k, v in value.items() if k != "written_at"}
        now = self.monotonic()
        # Like recent.json: rewrite unchanged content every 20 s, so an idle
        # explainer reads as alive rather than as an expired snapshot.
        if now - self._status_at < 5 or (content == self._status_value
                                         and now - self._status_at < 20):
            return
        self._status_at = now
        try:
            atomic_json(self.status_path, value, 0o644)
            self.ui_status.write(canonical(value) + b"\n")
            self._status_value = content
        except Exception:  # noqa: BLE001 - fixed code only
            self.refuse("status_write_failed")

    def checkpoint(self):
        if self._generation_replay_required:
            return
        value = {
            "cursor": self.cursor, "pending": list(self.selection.pending),
            "recent": build_recent_incidents(self.recent, 0),
            "audit_severities": self.audit_severities,
            "audit_forward_dropped": self.audit_forward_dropped,
            "audit_forward_refused": self.audit_forward_refused,
            "explained_ids": self.selection.explained, "explained": self.explained,
            "last_explained_at": self.last_explained_at, "refused": dict(self.refused),
            "chain_broken": self.chain_broken,
            "mio_available": self.mio_available, "knowledge_available": self.knowledge_available,
        }
        encoded = canonical(value)
        if encoded != self._checkpoint_value:
            atomic_json(self.state / "cursor.json", value, 0o600)
            self._checkpoint_value = encoded

    def restore(self):
        path = self.state / "cursor.json"
        if not path.exists():
            self.seed()
            return
        v = decode_checkpoint(read_file(path, CHECKPOINT_BYTES))
        self._checkpoint_value = canonical(v)
        self.cursor = v["cursor"]
        self.recent = v.get("recent", {"incidents": []})["incidents"]
        self.audit_severities = v.get("audit_severities", dict(v["explained_ids"]))
        self.audit_forward_dropped = v.get("audit_forward_dropped", 0)
        self.audit_forward_refused = v.get("audit_forward_refused", 0)
        self.selection.pending = deque((read_pending(t), s) for t, s in v["pending"])
        self.selection.explained = v["explained_ids"]
        self.explained, self.last_explained_at = v["explained"], v["last_explained_at"]
        self.refused, self.chain_broken = Counter(v["refused"]), v["chain_broken"]
        self.mio_available, self.knowledge_available = v["mio_available"], v["knowledge_available"]
        # A restart cannot reset the rolling rate budget. Conservatively wait 60s.
        self.selection.attempts = deque([self.monotonic()] * 6)

    def prepare(self):
        store_directory(self.state, 0o700)
        self.store = ExplanationStore(self.state, **self.store_limits)
        self.store.prepare(self.clock())
        try:
            self.generation_store = GenerationResultStore(self.state)
            self.generation_store.prepare(self.clock())
        except Exception:  # noqa: BLE001 - optional result storage cannot stop Edge intake
            self._generation_store_failed = True
            self.refuse("storage_failed")
        try:
            self.restore()
        except Exception:  # noqa: BLE001 - corrupt durable state must not replay history
            self.refuse("cursor_refused")
            raise ValueError("cursor_refused") from None
        if not self._generation_store_failed:
            try:
                self._restore_generation_results()
            except Exception:  # noqa: BLE001 - corrupt advisory data closes only this lane
                self._generation_store_failed = True
                self._generation_receipts.clear()
                self._generation_terminal.clear()
                self._generation_cleanup.clear()
                self._generation_superseded.clear()
                self._generation_cleanup_deadlines.clear()
                self._generation_current.clear()
                self.refuse("storage_failed")
        self._future()
        self.checkpoint()

    def _future(self):
        if self.store.future_segment:
            self.refused["segment_from_future"] = 1

    def seed(self):
        # Verify history without enqueueing it. Partial tails remain unconsumed.
        while True:
            before = dict(self.cursor)
            try:
                self.ingest(seeding=True)
            except FileNotFoundError:
                # Intake's retention can delete a segment while seeding walks
                # it. That is a read that failed, not a broken chain: the
                # next poll checks the gap against the retention boundary and
                # latches only if the chain itself is missing a link.
                self.refuse("read_failed")
                return
            if self.chain_broken or self.cursor == before:
                return

    def segments(self):
        result = []
        with os.scandir(self.incidents) as entries:
            for n, entry in enumerate(entries):
                if n >= 256:
                    raise ValueError("segment_list_refused")
                if DAY.fullmatch(entry.name):
                    if not entry.is_file(follow_symlinks=False):
                        raise ValueError("segment_refused")
                    result.append(Path(entry.path))
        return sorted(result)

    def ingest(self, *, seeding=False):
        c = self.cursor
        if c["broken"]:
            return
        paths = self.segments()
        try:
            boundary_path = self.incidents / "retained-boundary.json"
            try:
                boundary = read_retention_boundary(decode(read_file(boundary_path, MAX_LINE)))
            except FileNotFoundError:
                boundary = None
            if boundary is not None:
                # Ignore a retired prefix still present after a writer crash.
                paths = [p for p in paths if p.name > boundary["deleted"]]
                if not paths or paths[0].name != boundary["oldest"]:
                    raise ValueError("retention_refused")
                if c["segment"] is None or c["segment"] <= boundary["deleted"]:
                    if (boundary["sequence"] < c["sequence"] or
                            boundary["sequence"] == c["sequence"] and boundary["hash"] != c["last_hash"]):
                        raise ValueError("retention_refused")
                    if c["segment"] is not None:
                        self.refuse("cursor_overtaken")
                    c.update(segment=None, offset=0, sequence=boundary["sequence"], last_hash=boundary["hash"])
            if c["segment"] is not None and not any(p.name == c["segment"] for p in paths):
                raise ValueError("segment_missing")
        except (OSError, ValueError):
            self.break_chain()
            return
        self.cursor_lag = sum(p.stat().st_size if c["segment"] is None or p.name > c["segment"]
                              else max(0, p.stat().st_size-c["offset"]) if p.name == c["segment"] else 0
                              for p in paths)
        budget, lines = POLL_BYTES, 0
        for path in paths:
            if c["segment"] and path.name < c["segment"]:
                continue
            if path.name != c["segment"]:
                c.update(segment=path.name, offset=0)
            if c["broken"]:
                continue
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size < c["offset"]:
                    self.break_chain()
                    return
                stream.seek(c["offset"])
                while budget > MAX_LINE and lines < POLL_LINES:
                    raw = stream.readline(MAX_LINE + 1)
                    if not raw:
                        break
                    if not raw.endswith(b"\n") and len(raw) <= MAX_LINE:
                        # The writer may still be appending. Never advance a partial line.
                        if not self.refused["ledger_tail_incomplete"]:
                            self.refuse("ledger_tail_incomplete")
                        return
                    budget -= len(raw)
                    lines += 1
                    try:
                        v = decode(raw)
                        if type(v) is not dict or set(v) != {"sequence", "previous_hash", "event_hash", "event"}:
                            raise ValueError
                        if type(v["sequence"]) is not int or v["sequence"] != c["sequence"] + 1 or v["previous_hash"] != c["last_hash"]:
                            raise ValueError
                        if type(v["event"]) is not dict or not isinstance(v["event_hash"], str) or not re.fullmatch(r"[0-9a-f]{64}", v["event_hash"]):
                            raise ValueError
                        entry = AuditEntry(**v)
                        if entry.event_hash != entry.recomputed():
                            raise ValueError
                    except Exception:  # noqa: BLE001 - never expose hostile line or exception
                        self.break_chain()
                        return
                    c.update(offset=stream.tell(), sequence=entry.sequence, last_hash=entry.event_hash)
                    self.cursor_lag = max(0, self.cursor_lag - len(raw))
                    try:
                        event = entry.event
                        if read_control(event):
                            if event["event_type"] == "edge.incident.truncated":
                                self.refuse("incident_segment_full")
                            elif event["event_type"] == "edge.incident.reset":
                                for handle, receipt in tuple(self._generation_receipts.items()):
                                    if handle not in self._generation_terminal or self._generation_terminal[handle]["state"] != "superseded":
                                        if not self._record_generation_superseded(receipt):
                                            self._generation_replay_required = True
                                self.audit_severities.clear()
                                for row in self.recent:
                                    row["state"] = "closed"
                        else:
                            t = read_transition(event)
                            if seeding:
                                # Track comparison baselines without forwarding historical events.
                                if t["event_type"] != "edge.incident.closed":
                                    self.audit_severities[t["incident_id"]] = t["most_severe"]
                                    if len(self.audit_severities) > 1024:
                                        del self.audit_severities[next(iter(self.audit_severities))]
                                else:
                                    self.audit_severities.pop(t["incident_id"], None)
                                continue
                            self.observe_transition(t, sequence=entry.sequence)
                            if t["event_type"] == "edge.incident.opened" and self.clock() - t["first_seen"] > 3600:
                                self.refuse("stale_skipped")
                                self.explanation_unavailable(t["incident_id"], "stale_skipped")
                                continue
                            result = self.selection.enqueue(t, entry.sequence)
                            if (result == "skipped"
                                    and t["incident_id"] not in self.selection.explained):
                                # An ordinary update of an incident whose opening
                                # was never explained: nothing is coming, so the
                                # row must not keep promising an explanation.
                                self.explanation_unavailable(t["incident_id"], "queue_full",
                                                             displaced=True)
                            elif result == "queue_full":
                                self.refuse(result)
                                self.explanation_unavailable(t["incident_id"], result)
                            elif self.selection.displaced is not None:
                                # A severe arrival displaced ordinary work; count it the same way.
                                self.refuse("queue_full")
                                self.explanation_unavailable(self.selection.displaced, "queue_full",
                                                             displaced=True)
                    except Exception:  # noqa: BLE001 - authenticated chain still contains untrusted data
                        self.refuse("transition_refused")
                if budget <= MAX_LINE or lines >= POLL_LINES:
                    break

    def break_chain(self):
        self.cursor["broken"] = self.chain_broken = True
        self.refuse("chain_broken")

    def explain(self, t, sequence):
        codes = []
        t = read_pending(t)
        frame = build_frame(t, sequence)
        if sequence > MIO_TRACE_SEQUENCE_MAX:
            codes.append("mio_fast_unavailable")
        mio = {"route": "unavailable", "outcome": "unavailable", "reason": "mio_unavailable", "text": None}
        self.mio_available = False
        try:
            generation_sent_at = self.monotonic()
            reply = self.mio(frame)
        except Exception:  # noqa: BLE001 - transport failures have no public text
            codes.append("mio_unavailable")
        else:
            try:
                mio = read_mio_reply(reply)
                self.mio_available = True
                self._capture_generation_receipt(reply, t, sequence, sent_at=generation_sent_at)
                if mio["reason"] in {"mio_gated", "mio_handoff", "mio_local_non_advisory"}:
                    codes.append(mio["reason"])
                elif mio["reason"].startswith("mio_handoff:"):
                    # A handoff whose reference is missing keeps the reason
                    # in the record; the failure code stays the fixed word.
                    codes.append("mio_handoff")
            except Exception:  # noqa: BLE001 - refuse entire reply
                codes.append("mio_reply_refused")
                mio["reason"] = "mio_reply_refused"
        refs, state = [], "skipped"
        self.knowledge_available = None
        if t["technique_ids"]:
            self.knowledge_available = False
            try:
                response = self.knowledge(tuple(t["technique_ids"]))
            except Exception as exc:  # noqa: BLE001 - only the fixed public code escapes
                state = "unavailable"
                code = getattr(exc, "code", "knowledge_unavailable")
                codes.append(code if code in {"knowledge_unavailable", "knowledge_reply_refused"} else "knowledge_unavailable")
            else:
                try:
                    refs = [asdict(r) for r in read_knowledge_refs([asdict(r) for r in response])]
                    if any(r["technique_id"] not in t["technique_ids"] for r in refs):
                        raise ValueError
                    state = "available" if refs else "no_context"
                    self.knowledge_available = True
                except Exception:  # noqa: BLE001 - caller cannot inject partial refs
                    refs, state = [], "unavailable"
                    codes.append("knowledge_reply_refused")
        record = {"incident_id": t["incident_id"], "incident_sequence": sequence,
                  "explained_at": self.clock(),
                  "transition": t["event_type"].removeprefix("edge.incident."),
                  "edge_would": t["edge_would"], "policy_reason": t["policy_reason"],
                  "attack_type": t["attack_type"],
                  "technique_ids": t["technique_ids"], "mio": mio,
                  "knowledge_refs": refs, "knowledge_state": state, "failure_codes": codes}
        if EVIDENCE_FIELD in t:
            # The pointers carried since the transition, with their retention
            # as of this record. A pending entry from before them (a previous
            # release's checkpoint) has none, and its record says so.
            record[EVIDENCE_FIELD] = record_evidence(t[EVIDENCE_FIELD], record["explained_at"])
        try:
            value = read_record(record)
        except ValueError:
            # A reply that passed its own reader but does not make a valid
            # record is still refused as a reply: the incident is recorded
            # with no M.I.O. content rather than raising out of the loop.
            codes = [c for c in codes if not c.startswith("mio_")] + ["mio_reply_refused"]
            record.update(failure_codes=codes, mio={
                "route": "unavailable", "outcome": "unavailable",
                "reason": "mio_reply_refused", "text": None})
            self.mio_available = False
            value = read_record(record)
        stored = with_fabric_claims(value)
        try:
            self.store.append_record(stored)
        except SegmentFull:
            # The projection makes the record larger. A day that still has
            # room for the record itself must keep the explanation, so retry
            # once without it; a record that does not fit alone still raises.
            if stored is value:
                raise
            self.store.append_record(value)
        self._future()
        for row in self.recent:
            if row["incident_id"] == t["incident_id"]:
                row["explanation"] = explanation_summary(value)
        handle = self._generation_current.get(t["incident_id"])
        if handle is not None:
            self._set_generation_projection(
                self._generation_receipts[handle],
                self._generation_terminal.get(
                    handle, {"state": "queued", "usage": "unknown"}))
        for code in codes:
            self.refuse(code)
        self.selection.mark(t)
        self.explained += 1
        self.last_explained_at = value["explained_at"]

    def poll(self):
        if not self.storage_failed:
            try:
                try:
                    self.ingest()
                except (OSError, ValueError):
                    self.refuse("read_failed")
                self.checkpoint()
                while item := self.selection.take(self.monotonic()):
                    if item[0]["event_type"] == "edge.incident.opened" and self.clock() - item[0]["first_seen"] > 3600:
                        self.refuse("stale_skipped")
                        self.explanation_unavailable(item[0]["incident_id"], "stale_skipped")
                        self.checkpoint()
                        continue
                    try:
                        self.explain(*item)
                    except SegmentFull as exc:
                        self.refuse(exc.code)
                        self.explanation_unavailable(item[0]["incident_id"], exc.code)
                    except Exception:
                        self.explanation_unavailable(item[0]["incident_id"], "storage_failed")
                        raise
                    self.checkpoint()
                # One bounded slow-result IPC per poll tick. It never delays
                # the deterministic Edge process or waits for model work.
                self._poll_generation_results()
                self.checkpoint()
            except Exception:  # noqa: BLE001 - storage fails closed, Edge remains independent
                self.storage_failed = True
                self.refuse("storage_failed")
        self.status()

    def serve(self, *, stop=lambda: False, ready=None):
        try:
            self.prepare()
        except Exception:  # noqa: BLE001 - fail before READY, fixed status only
            self.storage_failed = True
            self.refuse("storage_failed")
            self.status()
            return 1
        audit_stop = threading.Event()
        audit_worker = threading.Thread(target=self.forward_audit, args=(audit_stop,), daemon=True)
        audit_worker.start()
        if ready:
            ready()
        while not stop():
            self.poll()
            # Interruptible polling shutdown; the audit worker has its own stop event.
            for _ in range(10):
                if stop():
                    break
                time.sleep(POLL_SECONDS / 10)
        audit_stop.set()
        audit_worker.join(AUDIT_DEADLINE_S + 1)
        self.count_audit("audit_forward_dropped", self.audit_pending.unfinished_tasks)
        try:
            self.checkpoint()
        except Exception:  # noqa: BLE001 - fixed storage diagnosis at shutdown
            self.storage_failed = True
            self.refuse("storage_failed")
        # The last status follows the last checkpoint, whatever the rewrite
        # throttle: a reader after shutdown sees the final pending count.
        self._status_at = float("-inf")
        self.status()
        return 1 if self.storage_failed else 0


def decode_checkpoint(raw):
    import json
    import math

    v = json.loads(raw.decode("utf-8"), object_pairs_hook=closed_pairs)
    if type(v) is not dict or not {"cursor", "pending", "explained_ids", "explained", "last_explained_at", "refused", "chain_broken", "mio_available", "knowledge_available"} <= set(v) <= {"cursor", "pending", "explained_ids", "explained", "last_explained_at", "refused", "chain_broken", "mio_available", "knowledge_available", "recent", "audit_severities", "audit_forward_dropped", "audit_forward_refused"}:
        raise ValueError
    if "recent" in v and read_recent_incidents(canonical(v["recent"])) is None:
        raise ValueError
    severities = v.get("audit_severities", {})
    if (type(severities) is not dict or len(severities) > 1024 or any(
            not re.fullmatch(r"inc-[0-9a-f]{16}", k) or type(n) is not int or not 0 <= n <= 10
            for k, n in severities.items())):
        raise ValueError
    for key in ("audit_forward_dropped", "audit_forward_refused"):
        n = v.get(key, 0)
        if type(n) is not int or not 0 <= n < 2**64:
            raise ValueError
    c = v["cursor"]
    if type(c) is not dict or set(c) != {"segment", "offset", "sequence", "last_hash", "broken"}:
        raise ValueError
    if c["segment"] is not None and (type(c["segment"]) is not str or not DAY.fullmatch(c["segment"])):
        raise ValueError
    if type(c["last_hash"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", c["last_hash"]):
        raise ValueError
    for count in (c["offset"], c["sequence"], v["explained"]):
        if type(count) is not int or not 0 <= count < 2**63:
            raise ValueError
    if type(c["broken"]) is not bool or type(v["chain_broken"]) is not bool:
        raise ValueError
    for key in ("mio_available", "knowledge_available"):
        if v[key] is not None and type(v[key]) is not bool:
            raise ValueError
    at = v["last_explained_at"]
    if at is not None and (type(at) not in {int, float} or not math.isfinite(at) or at < 0):
        raise ValueError
    if type(v["pending"]) is not list or len(v["pending"]) > MAX_PENDING:
        raise ValueError
    for row in v["pending"]:
        if type(row) is not list or len(row) != 2 or type(row[1]) is not int or not 1 <= row[1] < 2**63:
            raise ValueError
        read_pending(row[0])
    ids = v["explained_ids"]
    if type(ids) is not dict or len(ids) > 1024 or any(not re.fullmatch(r"inc-[0-9a-f]{16}", k) or type(n) is not int or not 0 <= n <= 10 for k, n in ids.items()):
        raise ValueError
    counts = v["refused"]
    if type(counts) is not dict or not set(counts) <= CODES or any(type(n) is not int or not 0 <= n < 2**63 for n in counts.values()):
        raise ValueError
    return v


def pending_pointers(path):
    """How many pending entries of a stopped explainer's checkpoint carry pointers.

    Read-only, and what decides a rollback past #392 (docs/operations.md):
    0 means the release before it reads this checkpoint unchanged. It reads
    the checkpoint itself, not status, which may lag the last checkpoint.
    """
    value = decode_checkpoint(read_file(Path(path), CHECKPOINT_BYTES))
    return sum(EVIDENCE_FIELD in row[0] for row in value["pending"])


def checkpoint_for_previous_release(path):
    """Rewrite a stopped explainer's checkpoint in the form before #392.

    The release before #392 refuses a pending entry with evidence pointers
    (`cursor_refused`). This keeps every pending entry and drops only its
    pointers, so a rolled-back explainer still explains the queued work; the
    records it writes then carry no pointers, as that release's always did.
    The checkpoint is validated first and nothing is written if it is
    refused. The original is kept beside it as `cursor.json.pre-rollback`,
    and both keep the checkpoint's owner and mode. An existing backup is
    never replaced: if it holds exactly this checkpoint (an interrupted run)
    the conversion goes on; any other backup refuses the run
    (`rollback_backup_exists`), so a second run cannot overwrite the first
    original with an already converted checkpoint. Run it as root with the
    explainer stopped (docs/operations.md). Returns how many entries lost
    their pointers.
    """
    path = Path(path)
    raw = read_file(path, CHECKPOINT_BYTES)
    value = decode_checkpoint(raw)
    stripped = 0
    for row in value["pending"]:
        if EVIDENCE_FIELD in row[0]:
            del row[0][EVIDENCE_FIELD]
            stripped += 1
    from azazel_nexus.incident_explain import PENDING_FIELDS
    if any(set(row[0]) != PENDING_FIELDS for row in value["pending"]):
        raise ValueError("cursor_refused")
    decode_checkpoint(canonical(value))
    backup = path.with_name(path.name + ".pre-rollback")
    try:
        kept = read_file(backup, CHECKPOINT_BYTES)
    except FileNotFoundError:
        kept = None
    except (OSError, ValueError):
        raise ValueError("rollback_backup_exists") from None
    if kept is not None and kept != raw:
        raise ValueError("rollback_backup_exists")
    info = os.stat(path, follow_symlinks=False)
    writes = [(backup, raw, os.link)] if kept is None else []
    writes.append((path, canonical(value) + b"\n", os.replace))
    for target, data, place in writes:
        fd, name = tempfile.mkstemp(dir=path.parent, prefix=".rollback-")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
                if os.geteuid() == 0:
                    os.fchown(stream.fileno(), info.st_uid, info.st_gid)
                stream.flush()
                os.fsync(stream.fileno())
            # The backup is linked, which fails if one appeared meanwhile;
            # only the checkpoint itself is replaced.
            try:
                place(name, target)
            except FileExistsError:
                raise ValueError("rollback_backup_exists") from None
        finally:
            if os.path.exists(name):
                os.unlink(name)
    fsync_directory(path.parent)
    return stripped


def main(argv=None):
    from .runtime_paths import (
        incident_explain_state_dir, incident_explain_status_path, incident_segments_dir,
        ui_copy_path,
    )
    from .systemd_notify import runtime_ready_callback

    if sys.argv[1:] if argv is None else argv:
        raise SystemExit("az-incident-explaind takes no arguments")
    stopped = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stopped.set())
    return Explainer(incidents=incident_segments_dir(), state=incident_explain_state_dir(),
                     status_path=incident_explain_status_path(),
                     ui_status_path=ui_copy_path("incident_explain_status"),
                     ui_recent_path=ui_copy_path("incident_recent")).serve(
                         stop=stopped.is_set, ready=runtime_ready_callback())


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
