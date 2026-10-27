"""Read incident chains and append local explanations; no Edge connection exists."""
from __future__ import annotations

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
from azazel_nexus.incident_explain import (
    CODES, MAX_LINE, MAX_PENDING, Selection, build_frame, decode,
    build_recent_incident, build_recent_incidents, read_recent_incidents, explanation_summary,
    closed_pairs, read_control, read_retention_boundary, read_mio_reply, read_record, read_transition, read_pending,
)
from azazel_nexus.lite_import import read_knowledge_refs
from azazel_nexus.store_dirs import fsync_directory, store_directory

from .edge_intaked import DailySegments, EvidenceStore, SegmentFull
from .knowledge_client import lookup_context
from .mio_locald import KNOWLEDGE_MAX_S
from .mio_referenced import REFERENCE_DEADLINE_MS
from .mio_socket_client import ServiceRefused, _exchange

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


class Explainer:
    def __init__(self, *, incidents, state, status_path, clock=time.time,
                 monotonic=time.monotonic, mio=None, knowledge=None, store_limits=None, audit=None):
        self.incidents, self.state, self.status_path = incidents, state, status_path
        self.clock, self.monotonic = clock, monotonic
        self.mio = mio or (lambda frame: _exchange(
            "mio-advise", "azmioentry", "mio.advise", {"deadline_ms": REFERENCE_DEADLINE_MS},
            payload=frame, deadline_s=REFERENCE_DEADLINE_MS / 1000))
        self.knowledge = knowledge or (lambda ids: lookup_context(ids, deadline_s=KNOWLEDGE_MAX_S))
        self.store_limits = store_limits or {}
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
                "knowledge_available": self.knowledge_available,
                "audit_forward_dropped": self.audit_forward_dropped,
                "audit_forward_refused": self.audit_forward_refused}

    def count_audit(self, name, n=1):
        # The poller and the forwarding worker both count; += is not atomic.
        with self._audit_lock:
            setattr(self, name, getattr(self, name) + n)

    def recent_status(self):
        value = build_recent_incidents(self.recent, self.clock())
        now = self.monotonic()
        # Rewrite unchanged rows every 20 s so a quiet node is not shown stale.
        if now - self._recent_at < 5 or (value["incidents"] == self._recent_value
                                         and now - self._recent_at < 20):
            return
        self._recent_at = now
        try:
            atomic_json(self.status_path.with_name("recent.json"), value, 0o644)
            self._recent_value = value["incidents"]
        except Exception:  # noqa: BLE001 - fixed code, independent snapshot
            self.refuse("status_write_failed")

    def observe_transition(self, t):
        ident = t["incident_id"]
        try:
            previous = next((r for r in self.recent if r["incident_id"] == ident), None)
            row = build_recent_incident(t, previous)
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
                if displaced and row["explanation"]["state"] == "explained":
                    continue
                row["explanation"] = {"state": "unavailable", "route": "unavailable",
                                      "outcome": "unavailable", "summary": "",
                                      "knowledge_refs": [], "failure_codes": [code]}

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
            self._status_value = content
        except Exception:  # noqa: BLE001 - fixed code only
            self.refuse("status_write_failed")

    def checkpoint(self):
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
            self.restore()
        except Exception:  # noqa: BLE001 - corrupt durable state must not replay history
            self.refuse("cursor_refused")
            raise ValueError("cursor_refused") from None
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
                            self.observe_transition(t)
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
        mio = {"route": "unavailable", "outcome": "unavailable", "reason": "mio_unavailable", "text": None}
        self.mio_available = False
        try:
            reply = self.mio(frame)
        except Exception:  # noqa: BLE001 - transport failures have no public text
            codes.append("mio_unavailable")
        else:
            try:
                mio = read_mio_reply(reply)
                self.mio_available = True
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
        value = read_record({"incident_id": t["incident_id"], "explained_at": self.clock(),
                             "transition": t["event_type"].removeprefix("edge.incident."),
                             "edge_would": t["edge_would"], "policy_reason": t["policy_reason"],
                             "attack_type": t["attack_type"],
                             "technique_ids": t["technique_ids"], "mio": mio,
                             "knowledge_refs": refs, "knowledge_state": state, "failure_codes": codes})
        self.store.append_record(value)
        self._future()
        for row in self.recent:
            if row["incident_id"] == t["incident_id"]:
                row["explanation"] = explanation_summary(value)
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


def main(argv=None):
    from .runtime_paths import incident_segments_dir, incident_explain_state_dir, incident_explain_status_path
    from .systemd_notify import runtime_ready_callback

    if sys.argv[1:] if argv is None else argv:
        raise SystemExit("az-incident-explaind takes no arguments")
    stopped = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stopped.set())
    return Explainer(incidents=incident_segments_dir(), state=incident_explain_state_dir(),
                     status_path=incident_explain_status_path()).serve(
                         stop=stopped.is_set, ready=runtime_ready_callback())


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
