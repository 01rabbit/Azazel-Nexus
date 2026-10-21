"""Receive Edge observations only; the explainer forwards selected audit transitions.

A second, separate socket receives the Deception Lite decoy's interactions
(#196 P2). They are Nexus's own observations: stored in their own evidence
leaf with their own ceilings, labelled as not Edge's, never counted as Edge
events, never fed to the incident tracker, and nothing is sent back on either
socket.
"""

from __future__ import annotations

import grp
import hashlib
import io
import json
import os
import pwd
import queue
import re
import selectors
import signal
import stat
import sys
import tempfile
import threading
import time
from collections import Counter, deque
from datetime import UTC, datetime
from pathlib import Path

from azazel_nexus.audit import GENESIS_HASH, AuditChainBroken, AuditLedger
from azazel_nexus.decoy_interaction import (
    MAX_INTERACTION_LINE,
    DecoyEventRefused,
    DecoyInteractionRecord,
    parse_interaction,
)
from azazel_nexus.edge_intake import (
    MAX_LINE,
    MAX_OPEN,
    SEVERE_SEVERITY,
    STATUS_SCHEMA,
    EdgeEventRefused,
    EvidenceRecord,
    ForwardStats,
    IncidentTracker,
    canonical,
    parse_edge_line,
)
from azazel_nexus.store_dirs import store_directory

from .principal import peer_credentials
from .refusal_log import REFUSAL_EVENT, BoundedRefusalLog
from .transport import bind_socket

MAX_CONNECTIONS = 64
# Connections finished at accept time per listener batch. Each costs at most
# RECV_ROUNDS reads of a 16 KiB line; the cap keeps one batch from starving
# registered readers and deadlines. The rest are registered as before.
MAX_INLINE = 64
RECV_ROUNDS = 8
# Records between acceptance and disk. Large enough to hold what an Edge
# forwarding thread (1024 lines) plus a full listen backlog (512) deliver at
# once after the intake resumes; a record is about 1-2 KiB, so a full queue
# stays a few MiB under MemoryMax. A load test lost 83% of that burst at 256.
QUEUE_SIZE = 2048
READ_DEADLINE_S = 2
LISTEN_BACKLOG = 512
STATUS_INTERVAL_S = 5
RETENTION_BYTES = 256 * 1024 * 1024
RETENTION_DAYS = 14
SEGMENT_BYTES = 64 * 1024 * 1024
INCIDENT_SEGMENT_BYTES = 16 * 1024 * 1024
TRUNCATION_RESERVE = 1024
# The tail of each incident segment is kept for severe incidents (severity <=
# SEVERE_SEVERITY) and control records, so ordinary churn while evidence is
# full cannot use up the day before a severity 1 incident arrives. Only a
# severe opening, a fall in recorded severity, a severe close and control
# records use it; a severe incident's routine refresh does not. A fall is
# measured against the severity this ledger recorded for the incident, so an
# incident it never recorded cannot claim the reserve with a severe update;
# the tracker lets an ordinary incident's severity fall into the severe range
# only after it took a severe opening.
SEVERE_RESERVE = 1024 * 1024
LEDGER_RECOVERED = "edge.incident.ledger_recovered"
RESERVED_CONTROL = frozenset({"edge.incident.reset", "edge.incident.truncated",
                              "edge.incident.retention", LEDGER_RECOVERED})
# A torn incident tail (bytes after the last newline of the last segment, left
# by a power cut during the shutdown batch) is recovered only up to this size:
# the explainer refuses any ledger line longer than this, so no record this
# ledger writes is longer. Anything larger is not one torn record.
TORN_TAIL_MAX = 64 * 1024
# Quarantined tails held before recovery refuses again and needs the
# operator: at most 64 x 64 KiB = 4 MiB in the private state area.
QUARANTINE_MAX = 64
SEGMENT_NAME = re.compile(r"\d{4}-\d{2}-\d{2}\.jsonl", re.ASCII)
# <segment>.<offset of the cut>.<sha256 of the bytes>.(pending|torn)
QUARANTINED = re.compile(r"\d{4}-\d{2}-\d{2}\.jsonl\.\d{1,12}\.[0-9a-f]{64}\.(pending|torn)", re.ASCII)
WORKER_JOIN_S = 20
# The decoy socket (#196 P2). One decoy daemon sends one short line per
# reach; these bounds keep a decoy, or whatever holds its account, from
# taking reader slots, queue places or evidence space from Edge.
DECOY_MAX_CONNECTIONS = 4
DECOY_ACCEPT_BATCH = 16
DECOY_BACKLOG = 16
# Interactions accepted per rolling minute; the rest are refused and counted.
# A reach is evidence that a decoy was touched, not a stream to keep: a
# scanner hitting a decoy a thousand times says no more than thirty records.
DECOY_PER_MINUTE = 30
# Its own leaf and ceilings, so a decoy flood cannot fill Edge's evidence day.
DECOY_SEGMENT_BYTES = 8 * 1024 * 1024
DECOY_RETENTION_BYTES = 64 * 1024 * 1024
# How far a segment's day may run ahead of the clock. During a run the clock
# is also held to monotonic elapsed time from the first write, so a forward
# jump cannot create a future segment; one found anyway (written while the
# clock was already wrong at start) is reported as segment_from_future.
FUTURE_SEGMENT_S = 86400
# A node without an RTC boots with its clock behind (the last shutdown time,
# or earlier) and steps it forward once time sync arrives, usually within
# minutes. While both the anchor and now are within this much elapsed time
# since boot, a step past the bound re-anchors instead of being held, so the
# whole run is not dated days behind. Later in uptime the bound holds; this
# is chosen over ordering the unit after time-sync.target, which waits only
# when a wait-sync service is enabled and then delays the intake that Edge
# writes to for as long as an offline node has no time source.
CLOCK_SETTLE_S = 900
# Elapsed time that also counts a suspend, which CLOCK_MONOTONIC does not, so
# a resumed node does not keep writing to a segment days behind.
ELAPSED = (
    (lambda: time.clock_gettime(time.CLOCK_BOOTTIME))
    if hasattr(time, "CLOCK_BOOTTIME") else time.monotonic
)


class SegmentFull(Exception):
    """A daily ceiling refuses this append, without poisoning tomorrow's writer."""

    def __init__(self, code):
        self.code = code


class DailySegments:
    """Delete oldest whole segments, always keeping newest and active paths."""

    def __init__(
        self, root, leaf, *, max_bytes=RETENTION_BYTES,
        days=RETENTION_DAYS, segment_bytes=SEGMENT_BYTES, mode=0o700,
        monotonic=ELAPSED,
    ):
        self.directory = root / leaf
        store_directory(self.directory, mode)
        self.max_bytes, self.days = max_bytes, days
        self.segment_bytes = segment_bytes
        self.monotonic = monotonic
        self.current = None
        self.age_anchor = None
        self.clock_anchor = None
        self.last_now = None
        self.future_segment = False

    def path_at(self, now):
        day = datetime.fromtimestamp(now, UTC).strftime("%Y-%m-%d")
        return self.directory / (day + ".jsonl")

    def bounded(self, now):
        """Hold a wall-clock time to monotonic elapsed time since the first one."""
        instant = self.monotonic()
        if self.clock_anchor is not None:
            wall, anchor = self.clock_anchor
            if (instant < CLOCK_SETTLE_S
                    and now > wall + instant - anchor + FUTURE_SEGMENT_S):
                self.clock_anchor = None
        if self.clock_anchor is None:
            self.clock_anchor = (now, instant)
        wall, anchor = self.clock_anchor
        self.last_now = min(now, wall + instant - anchor + FUTURE_SEGMENT_S)
        return self.last_now

    def retain(self):
        segments = []
        for path in self.directory.glob("????-??-??.jsonl"):
            try:
                day = (
                    datetime.strptime(path.stem, "%Y-%m-%d")
                    .replace(tzinfo=UTC)
                    .timestamp()
                )
            except ValueError:
                continue
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise OSError("intake segment refused")
            segments.append((day, path, info.st_size))
        segments.sort()
        if not segments:
            return
        # received_at/wall-clock jumps alone cannot age out stored observations.
        newest_day = segments[-1][0]
        # A segment dated beyond the clock was written while the clock ran
        # ahead; it must not become the age reference after a restart.
        self.future_segment = (self.last_now is not None
                               and newest_day > self.last_now + FUTURE_SEGMENT_S)
        if self.age_anchor is None:
            reference = newest_day
            if self.last_now is not None:
                reference = min(reference, self.last_now + FUTURE_SEGMENT_S)
            self.age_anchor = (reference, self.monotonic())
        anchor_day, anchor_time = self.age_anchor
        # Allow a normal midnight rollover, but not years of ageing from a
        # single forward wall-clock jump during this run.
        age_day = min(
            newest_day, anchor_day + self.monotonic() - anchor_time + 86400
        )
        if self.last_now is not None:
            age_day = min(age_day, self.last_now + FUTURE_SEGMENT_S)
        total = sum(size for _, _, size in segments)
        for day, path, size in segments[:-1]:
            if path == self.current:
                continue
            if day < age_day - self.days * 86400 or total > self.max_bytes:
                self.before_delete(path)
                path.unlink()
                total -= size

    def before_delete(self, path):
        pass

    def open_segment(self, path, mode):
        created = not path.exists()
        fd = os.open(
            path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            mode,
        )
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("intake segment refused")
            os.fchmod(fd, mode)
            if created:
                directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            return fd
        except BaseException:
            os.close(fd)
            raise


class EvidenceStore(DailySegments):
    """Rotate whole daily segments; never rewrite retained evidence."""

    full_code = "evidence_segment_full"

    def __init__(self, root, leaf="evidence", **limits):
        super().__init__(root, leaf, **limits)

    def prepare(self, now):
        # Probe actual append access before READY, including an existing segment.
        path = self.path_at(self.bounded(now))
        self.current = path
        existed = path.exists()
        os.close(self.open_segment(path, 0o640))
        if not existed:
            path.unlink()
        self.retain()

    def append(self, record):
        path = self.path_at(self.bounded(record.received_at))
        self.current = path
        self.retain()
        data = canonical(record.as_dict()) + b"\n"
        fd = self.open_segment(path, 0o640)
        try:
            if os.fstat(fd).st_size + len(data) > self.segment_bytes:
                raise SegmentFull(self.full_code)
            if os.write(fd, data) != len(data):
                raise OSError("evidence append incomplete")
            os.fsync(fd)
        finally:
            os.close(fd)
        self.retain()


class DecoyEvidenceStore(EvidenceStore):
    """Decoy interactions (#196 P2), beside Edge's evidence and never in it."""

    full_code = "decoy_evidence_segment_full"

    def __init__(self, root, **limits):
        limits.setdefault("segment_bytes", DECOY_SEGMENT_BYTES)
        limits.setdefault("max_bytes", DECOY_RETENTION_BYTES)
        super().__init__(root, "decoy-evidence", **limits)


class IncidentLedgerTorn(Exception):
    """An unterminated segment that automatic recovery may not repair."""


class IncidentLedger(DailySegments):
    """One chain through retained daily segments, with a durable left boundary."""

    def __init__(self, root, now, *, leaf="incidents", severe_reserve=SEVERE_RESERVE,
                 quarantine=None, **limits):
        limits.setdefault("segment_bytes", INCIDENT_SEGMENT_BYTES)
        super().__init__(root, leaf, mode=0o2750, **limits)
        self.severe_reserve = severe_reserve
        # Private directory for torn tails; None refuses a torn tail as before.
        self.quarantine = quarantine
        self.recovered = 0
        if quarantine is not None:
            self._open_quarantine()
        # Lowest severity recorded per open incident, so only a fall in
        # severity (not a routine refresh or an unknown incident) may use the
        # severe reserve. Closes remove entries even when they cannot be
        # recorded, so this follows the tracker's bounded open set.
        self.severities = {}
        self.ledger = None
        self.boundary = self.directory / "retained-boundary.json"
        self.head = (0, GENESIS_HASH)
        paths = sorted(self.directory.glob("????-??-??.jsonl"))
        if self.boundary.exists():
            boundary = json.loads(self.boundary.read_bytes())
            oldest = self.directory / boundary["oldest"]
            if (oldest not in paths or oldest.name != boundary["oldest"] or
                    boundary["deleted"] >= oldest.name or
                    type(boundary["sequence"]) is not int or boundary["sequence"] < 0 or
                    not isinstance(boundary["hash"], str) or len(boundary["hash"]) != 64):
                raise AuditChainBroken("retained incident boundary is missing")
            self.head = (boundary["sequence"], boundary["hash"])
            # A crash after the durable boundary but before unlink is safe:
            # only the prefix explicitly retired by that boundary is removed.
            for path in paths:
                if path.name <= boundary["deleted"]:
                    path.unlink()
            paths = sorted(self.directory.glob("????-??-??.jsonl"))
            if not paths or paths[0] != oldest:
                raise AuditChainBroken("retained incident boundary does not match")
        recorded = set()
        for path in paths:
            try:
                self.check_segment(path)
            except IncidentLedgerTorn:
                # Only the newest segment can be torn by an interrupted append;
                # a torn older one is damage, not a power cut.
                if path != paths[-1] or self.quarantine is None:
                    raise
                self._recover(path)
            for entry in AuditLedger(path, private=True, file_mode=0o640):
                if (entry.sequence != self.head[0] + 1 or
                        entry.previous_hash != self.head[1] or
                        entry.recomputed() != entry.event_hash):
                    raise AuditChainBroken("incident chain does not continue")
                self.head = (entry.sequence, entry.event_hash)
                if entry.event.get("event_type") == LEDGER_RECOVERED:
                    # Short torn tails share a record's opening bytes, so the
                    # digest alone does not name one recovery.
                    recorded.add((entry.event.get("segment"), entry.event.get("offset"),
                                  entry.event.get("sha256")))
        self.current = paths[-1] if paths else None
        self.select(now)
        if self.quarantine is not None:
            self._record_recoveries(recorded, now)
        self.retain()

    def _open_quarantine(self):
        store_directory(self.quarantine, 0o700)
        fd = os.open(self.quarantine, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            # It may hold addresses from a torn record: owner only.
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
        # A temporary file left by a power cut before its rename names nothing.
        for stale in self.quarantine.glob(".torn-*"):
            stale.unlink()

    def _held(self):
        return sorted(path for path in self.quarantine.iterdir()
                      if QUARANTINED.fullmatch(path.name))

    def _fsync_quarantine(self):
        fd = os.open(self.quarantine, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _recover(self, path):
        """Quarantine a torn tail after a verified prefix, then cut it off.

        Refuses (IncidentLedgerTorn, as without recovery) unless the bytes
        after the last newline are bounded and every complete line before
        them continues the chain from the previous segment. Each step is
        durable before the next, so a power cut here is redone on restart:
        quarantine first (idempotent for the same bytes), then truncate,
        then `_record_recoveries` writes the chain record and only then
        marks the quarantined file done.
        """
        # The name must be one the quarantine bound and the record can name.
        if not SEGMENT_NAME.fullmatch(path.name):
            raise IncidentLedgerTorn()
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > self.segment_bytes:
                raise IncidentLedgerTorn()
            chunks, remaining = [], info.st_size
            while remaining > 0:
                chunk = os.read(fd, min(remaining, 1 << 20))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            cut = data.rfind(b"\n") + 1
            tail = data[cut:]
            if not tail or len(tail) > TORN_TAIL_MAX:
                raise IncidentLedgerTorn()
            head, parser = self.head, AuditLedger(path)
            try:
                # The same line splitting AuditLedger.__iter__ applies to a file.
                lines = io.TextIOWrapper(io.BytesIO(data[:cut]), encoding="utf-8")
                for number, line in enumerate(lines, start=1):
                    if not line.strip():
                        continue
                    entry = parser._parse(line, f"line {number}")
                    if (entry.sequence != head[0] + 1 or entry.previous_hash != head[1] or
                            entry.recomputed() != entry.event_hash):
                        raise AuditChainBroken("incident chain does not continue")
                    head = (entry.sequence, entry.event_hash)
            except (AuditChainBroken, UnicodeDecodeError):
                raise IncidentLedgerTorn() from None
            def unchanged():
                after = os.fstat(fd)
                return (after.st_ino, after.st_dev, after.st_size) == (
                    info.st_ino, info.st_dev, len(data))

            if not unchanged():
                raise IncidentLedgerTorn()
            digest = hashlib.sha256(tail).hexdigest()
            name = f"{path.name}.{cut}.{digest}"
            created = False
            pending = self.quarantine / (name + ".pending")
            if os.path.lexists(self.quarantine / (name + ".torn")):
                # These bytes were already recovered here once; tearing again at
                # the same place is not an interrupted append.
                raise IncidentLedgerTorn()
            if os.path.lexists(pending):
                # Written before a power cut that came before the truncation.
                if (not stat.S_ISREG(pending.lstat().st_mode) or
                        hashlib.sha256(pending.read_bytes()).hexdigest() != digest):
                    raise IncidentLedgerTorn()
            else:
                if len(self._held()) >= QUARANTINE_MAX:
                    raise IncidentLedgerTorn()
                held, temporary = tempfile.mkstemp(dir=self.quarantine, prefix=".torn-")
                try:
                    with os.fdopen(held, "wb") as stream:
                        os.fchmod(stream.fileno(), 0o600)
                        stream.write(tail)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.rename(temporary, pending)
                    created = True
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
                self._fsync_quarantine()
            # Cut only the file that was verified, still exactly as it was
            # read; otherwise leave no quarantine that a later start would
            # record as a recovery that never happened.
            if not unchanged():
                if created:
                    pending.unlink()
                    self._fsync_quarantine()
                raise IncidentLedgerTorn()
            os.ftruncate(fd, cut)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _record_recoveries(self, recorded, now):
        """Put each quarantined tail on the chain once, then mark it done."""
        for pending in self._held():
            if pending.suffix != ".pending":
                continue
            segment, offset, digest = pending.stem.rsplit(".", 2)
            if (segment, int(offset), digest) not in recorded:
                try:
                    self.append({"event_type": LEDGER_RECOVERED, "at": now,
                                 "segment": segment, "offset": int(offset),
                                 "torn_bytes": pending.stat().st_size,
                                 "sha256": digest}, now)
                except SegmentFull:
                    # No room today: kept pending, recorded on a later start.
                    continue
            os.rename(pending, pending.with_suffix(".torn"))
            self._fsync_quarantine()
        self.recovered = len(self._held())

    def check_segment(self, path):
        if not stat.S_ISREG(path.lstat().st_mode):
            raise OSError("intake segment refused")
        with path.open("rb") as stream:
            size = stream.seek(0, os.SEEK_END)
            if size > self.segment_bytes:
                raise OSError("incident segment exceeds ceiling")
            if size:
                stream.seek(-1, os.SEEK_END)
                if stream.read(1) != b"\n":
                    raise IncidentLedgerTorn()

    def before_delete(self, path):
        paths = sorted(self.directory.glob("????-??-??.jsonl"))
        following = paths[paths.index(path) + 1]
        head = AuditLedger(path, private=True, file_mode=0o640).head()
        # An empty segment contributes no link; preserve the prior boundary.
        if head == (0, GENESIS_HASH) and self.boundary.exists():
            previous = json.loads(self.boundary.read_bytes())
            head = (previous["sequence"], previous["hash"])
        value = {"oldest": following.name, "sequence": head[0], "hash": head[1],
                 "deleted": path.name}
        fd, name = tempfile.mkstemp(dir=self.directory, prefix=".boundary-")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(canonical(value) + b"\n")
                os.fchmod(stream.fileno(), 0o640)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.boundary)
            directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def select(self, now):
        path = self.path_at(self.bounded(now))
        # A backwards clock must not insert entries before the chain head.
        # This also keeps appending to a segment from the future: the chain
        # continues only there, and status reports segment_from_future.
        if self.current is not None:
            path = max(path, self.current)
        if path == self.current and self.ledger is not None:
            return
        fd = self.open_segment(path, 0o640)
        os.close(fd)
        self.check_segment(path)
        self.current, self.ledger = path, AuditLedger(path, private=True, file_mode=0o640)
        self.truncated = any(
            entry.event.get("event_type") == "edge.incident.truncated"
            for entry in self.ledger
        )

    def _append(self, event, *, sync):
        entry = self.ledger.append(event, chain_from=self.head, sync=sync)
        self.head = (entry.sequence, entry.event_hash)

    def append(self, event, now, *, sync=True):
        self.select(now)
        # Keep room for one durable gap marker even when a transition is lost.
        required = len(canonical(event)) + 512
        kind, ident = event.get("event_type"), event.get("incident_id")
        severity = event.get("most_severe")
        severe = type(severity) is int and severity <= SEVERE_SEVERITY
        closed = kind == "edge.incident.closed"
        recorded = (self.severities.pop if closed else self.severities.get)(ident, None)
        reserved = kind in RESERVED_CONTROL or severe and (
            kind != "edge.incident.updated" or recorded is not None and severity < recorded)
        if not reserved:
            required += self.severe_reserve
        size = self.current.stat().st_size
        if size + required + TRUNCATION_RESERVE > self.segment_bytes:
            if not self.truncated:
                marker = {"event_type": "edge.incident.truncated", "at": now,
                          "reason": "incident_segment_full"}
                if size + len(canonical(marker)) + 512 <= self.segment_bytes:
                    self._append(marker, sync=sync)
                    self.truncated = True
            raise SegmentFull("incident_segment_full")
        self._append(event, sync=sync)
        if not closed and ident is not None and type(severity) is int:
            self.severities[ident] = severity if recorded is None else min(recorded, severity)
            if len(self.severities) > MAX_OPEN:
                del self.severities[next(iter(self.severities))]
        self.retain()

    def sync(self):
        fd = self.open_segment(self.current, 0o640)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class IntakeServer:
    """Accept independently of disk, bounded readers and a single ledger writer."""

    def __init__(
        self,
        *,
        path: Path,
        state: Path,
        status_path: Path,
        edge_uid: int,
        incident_root: Path | None = None,
        expected_gid=None,
        peer_uid=None,
        clock=time.time,
        max_connections=MAX_CONNECTIONS,
        queue_size=QUEUE_SIZE,
        read_deadline=READ_DEADLINE_S,
        decoy_path: Path | None = None,
        decoy_uid: int | None = None,
        decoy_gid=None,
        decoy_refusals=None,
        decoy_per_minute=DECOY_PER_MINUTE,
        monotonic=time.monotonic,
    ):
        self.path, self.state, self.status_path = path, state, status_path
        # The decoy socket is opened only with both its path and the decoy
        # account; a node without either runs the Edge intake as before.
        self.decoy_enabled = decoy_path is not None and decoy_uid is not None
        self.decoy_path, self.decoy_uid, self.decoy_gid = decoy_path, decoy_uid, decoy_gid
        self.decoy_refusals = (decoy_refusals if decoy_refusals is not None
                               else BoundedRefusalLog(state / "decoy-refusals.jsonl"))
        self.decoy_per_minute = decoy_per_minute
        self.decoy_window = deque()
        self.decoy_listening = False
        self.decoy_accepted = 0
        self.decoy_last_accepted_at = None
        self.monotonic = monotonic
        self.edge_uid, self.expected_gid = edge_uid, expected_gid
        self.incident_root = incident_root or state
        self.peer_uid = peer_uid or (lambda connection: peer_credentials(connection)[1])
        self.clock = clock
        self.max_connections, self.read_deadline = max_connections, read_deadline
        self.pending = queue.Queue(maxsize=queue_size)
        self.refused = Counter()
        self.accepted = 0
        self.last_accepted_at = None
        # Tracked with or without stored evidence, so a full evidence day does
        # not make a live Edge look stopped.
        self.processed = 0
        self.last_processed_at = None
        self.tracker = IncidentTracker(clock)
        self.lock = threading.Lock()
        self.finished = threading.Event()
        self.storage_failed = False
        self.open_incidents = 0
        self.ledger_recovered = 0
        # Edge's latest forward counts, as Edge reported them; None until the
        # first report this run.
        self.edge_forward = None

    def forward_stats(self, stats: ForwardStats):
        """Keep Edge's latest report; it is neither evidence nor an event."""
        with self.lock:
            previous = self.edge_forward
            restarts = 0 if previous is None else previous["restarts"]
            # A new process start, or counts that went back, is an Edge
            # restart: its counts began again at zero.
            if previous is not None and (
                    stats.since != previous["since"]
                    or any(getattr(stats, k) < previous[k] for k in ("dropped", "failed", "sent"))):
                restarts += 1
            self.edge_forward = dict(stats.as_dict(), reported_at=self.clock(),
                                     restarts=restarts)

    def refuse(self, code):
        with self.lock:
            self.refused[code] += 1

    def refuse_decoy(self, code, uid=None):
        """Count it in status and keep a bounded line (#211) of who and why."""
        self.refuse(code)
        self.decoy_refusals({"event_type": REFUSAL_EVENT,
                             "uid": uid if type(uid) is int else None,
                             "reason": code})

    def _decoy_admit(self):
        """A place in this minute's decoy allowance, or False."""
        instant = self.monotonic()
        while self.decoy_window and instant - self.decoy_window[0] >= 60:
            self.decoy_window.popleft()
        if len(self.decoy_window) >= self.decoy_per_minute:
            return False
        self.decoy_window.append(instant)
        return True

    def snapshot(self):
        with self.lock:
            return {
                "schema": STATUS_SCHEMA,
                "written_at": self.clock(),
                "last_accepted_at": self.last_accepted_at,
                "accepted": self.accepted,
                "processed": self.processed,
                "last_processed_at": self.last_processed_at,
                "refused": dict(self.refused),
                "open_incidents": self.open_incidents,
                "queue_drops": self.refused["queue_full"],
                "storage_failed": self.storage_failed,
                "ledger_recovered": self.ledger_recovered,
            } | ({} if self.edge_forward is None
                 else {"edge_forward": dict(self.edge_forward)}) | (
                {"decoy": {"accepted": self.decoy_accepted,
                           "last_accepted_at": self.decoy_last_accepted_at}}
                if self.decoy_listening else {})

    def _status(self):
        fd, name = tempfile.mkstemp(dir=self.status_path.parent, prefix=".status-")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(canonical(self.snapshot()) + b"\n")
                os.fchmod(stream.fileno(), 0o644)
            os.replace(name, self.status_path)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def _open_storage(self):
        store = EvidenceStore(self.state)
        store.prepare(self.clock())
        # Torn tails go to the intake's private state, never to the incident
        # leaf the explainer's group reads: they may hold addresses.
        quarantine = self.state / "incident-quarantine"
        ledger = (IncidentLedger(self.incident_root.parent, self.clock(),
                                 leaf=self.incident_root.name, quarantine=quarantine)
                  if self.incident_root != self.state
                  else IncidentLedger(self.state, self.clock(), quarantine=quarantine))
        with self.lock:
            self.ledger_recovered = ledger.recovered
        try:
            ledger.append(
                {"event_type": "edge.incident.reset", "at": self.clock(),
                 "reason": "intake_started"},
                self.clock(),
            )
        except SegmentFull as exc:
            self.refuse(exc.code)
        self.store, self.ledger = store, ledger
        if self.decoy_enabled:
            # Edge's intake never depends on the decoy's leaf: a failure here
            # leaves the decoy socket closed and is reported, nothing more.
            try:
                decoy_store = DecoyEvidenceStore(self.state)
                decoy_store.prepare(self.clock())
                self.decoy_store = decoy_store
            except Exception:  # noqa: BLE001 - expose only a fixed failure code
                self.refuse("decoy_listener_unavailable")
        self._future()

    def _store_decoy(self, record):
        """Store one interaction; a failure here is the decoy's alone."""
        try:
            self.decoy_store.append(record)
        except SegmentFull as exc:
            self.refuse(exc.code)
            return
        except Exception:  # noqa: BLE001 - must not stop Edge's evidence
            self.refuse("decoy_storage_failed")
            return
        with self.lock:
            self.decoy_accepted += 1
            self.decoy_last_accepted_at = record.received_at

    def _future(self):
        if self.store.future_segment or self.ledger.future_segment:
            with self.lock:
                self.refused["segment_from_future"] = 1

    def _transitions(self, transitions, *, batch=False):
        batch_time = self.clock() if batch else None
        for transition in transitions:
            event_type = "edge.incident." + transition.pop("transition")
            try:
                self.ledger.append(
                    dict(event_type=event_type, **transition),
                    batch_time if batch else self.clock(),
                    sync=not batch,
                )
            except SegmentFull as exc:
                self.refuse(exc.code)

    def _writer(self):
        next_status = 0
        if not hasattr(self, "store"):
            self._open_storage()
        while not self.finished.is_set() or not self.pending.empty():
            try:
                record = self.pending.get(timeout=0.1)
            except queue.Empty:
                record = None
            if isinstance(record, DecoyInteractionRecord):
                # Never an Edge event: not tracked, not counted as accepted
                # or processed, and no incident transition follows from it.
                if not self.storage_failed:
                    self._store_decoy(record)
                else:
                    self.refuse("decoy_storage_failed")
                self.pending.task_done()
                record = None
            if not self.storage_failed:
                try:
                    transitions = []
                    stored = True
                    if record is not None:
                        try:
                            self.store.append(record)
                        except SegmentFull as exc:
                            # A full evidence day must not hide new incidents
                            # (severity 1 included) for the rest of that day.
                            self.refuse(exc.code)
                            stored = False
                        transitions = self.tracker.add(record, evidence_stored=stored)
                        if not stored:
                            # While evidence is full the ledger alone takes the
                            # load: skip ordinary refreshes, keep openings,
                            # closings and severe updates.
                            transitions = [
                                t for t in transitions
                                if t["transition"] != "updated"
                                or t["most_severe"] <= SEVERE_SEVERITY
                            ]
                        with self.lock:
                            self.refused["incident_rate_limited"] = self.tracker.rate_limited
                    else:
                        transitions = self.tracker.tick()
                    self._transitions(transitions)
                    self._future()
                    with self.lock:
                        self.open_incidents = len(self.tracker.incidents)
                        if record is not None:
                            self.processed += 1
                            self.last_processed_at = record.received_at
                        if record is not None and stored:
                            self.accepted += 1
                            self.last_accepted_at = record.received_at
                except Exception:  # noqa: BLE001 - failures must not stop acceptance or expose input
                    # A broken writer stays closed for records until restart.
                    self.storage_failed = True
                    self.refuse("storage_failed")
            elif record is not None:
                self.refuse("storage_failed")
            if record is not None:
                self.pending.task_done()
            if time.monotonic() >= next_status:
                try:
                    self._status()
                except Exception:  # noqa: BLE001 - failures must not stop acceptance or expose input
                    self.refuse("status_write_failed")
                next_status = time.monotonic() + STATUS_INTERVAL_S
        if not self.storage_failed:
            try:
                try:
                    closed_at = self.clock()
                    self._transitions([
                        self.tracker._close(key, "shutdown", closed_at)
                        for key in list(self.tracker.incidents)
                    ], batch=True)
                finally:
                    self.ledger.sync()
                with self.lock:
                    self.open_incidents = 0
            except Exception:  # noqa: BLE001 - expose only a fixed failure code
                self.storage_failed = True
                self.refuse("storage_failed")
        try:
            self._status()
        except Exception:  # noqa: BLE001 - status failure is separate from record storage
            self.refuse("status_write_failed")

    def serve(self, *, stop=lambda: False, ready=None):
        try:
            self._open_storage()
        except Exception as exc:  # noqa: BLE001 - fail before binding or READY
            self.storage_failed = True
            self.refuse("incident_ledger_torn" if isinstance(exc, IncidentLedgerTorn)
                        else "storage_failed")
            try:
                self._status()
            except Exception:  # noqa: BLE001 - expose only a fixed failure code
                self.refuse("status_write_failed")
            return 1
        previous_umask = os.umask(0o117)
        try:
            listener = bind_socket(
                self.path,
                mode=0o660,
                backlog=LISTEN_BACKLOG,
                expected_gid=self.expected_gid,
            )
        finally:
            os.umask(previous_umask)
        listener.setblocking(False)
        decoy_listener = None
        if self.decoy_enabled and hasattr(self, "decoy_store"):
            # Its own leaf and group (azdecoy), so the decoy never reaches
            # Edge's socket and Edge never reaches this one.
            previous_umask = os.umask(0o117)
            try:
                decoy_listener = bind_socket(
                    self.decoy_path,
                    mode=0o660,
                    backlog=DECOY_BACKLOG,
                    expected_gid=self.decoy_gid,
                )
                decoy_listener.setblocking(False)
            except Exception:  # noqa: BLE001 - Edge's intake runs without it
                decoy_listener = None
                self.refuse("decoy_listener_unavailable")
            finally:
                os.umask(previous_umask)
        self.decoy_listening = decoy_listener is not None
        selector = selectors.DefaultSelector()
        clients = {}
        # Decoy readers, apart from Edge's: they never take an Edge slot.
        decoy_clients = {}
        worker = threading.Thread(target=self._writer, daemon=True)

        def close(connection, code=None):
            if connection in decoy_clients:
                _, _, uid = decoy_clients.pop(connection)
                if code:
                    self.refuse_decoy(code, uid)
                selector.unregister(connection)
                connection.close()
                return
            if code:
                self.refuse(code)
            selector.unregister(connection)
            clients.pop(connection)
            connection.close()

        def receive_decoy(connection, buffer):
            """One interaction line, as `receive` reads Edge's; never answered."""
            for _ in range(RECV_ROUNDS):
                try:
                    data = connection.recv(MAX_INTERACTION_LINE + 2 - len(buffer))
                except BlockingIOError:
                    return None
                except OSError:
                    return "decoy_read_error"
                buffer.extend(data)
                if len(buffer) > MAX_INTERACTION_LINE + 1:
                    return "DECOY_TOO_LARGE"
                if b"\n" in buffer:
                    if buffer.count(b"\n") != 1 or not buffer.endswith(b"\n"):
                        return "DECOY_SHAPE"
                    if not data:
                        try:
                            interaction = parse_interaction(bytes(buffer[:-1]))
                        except DecoyEventRefused as exc:
                            return exc.code
                        if not self._decoy_admit():
                            return "decoy_rate_limited"
                        try:
                            self.pending.put_nowait(
                                DecoyInteractionRecord.receive(interaction, self.clock))
                        except queue.Full:
                            return "decoy_overloaded"
                        return ""
                elif not data:
                    return "DECOY_SHAPE"
            return None

        def accept_decoy():
            """A finite batch from the decoy socket; the sender must be azdecoy."""
            for _ in range(DECOY_ACCEPT_BATCH):
                try:
                    incoming, _ = decoy_listener.accept()
                except BlockingIOError:
                    return
                try:
                    uid = self.peer_uid(incoming)
                except Exception:  # noqa: BLE001 - failures must not stop acceptance or expose input
                    uid = None
                if type(uid) is not int or uid != self.decoy_uid:
                    self.refuse_decoy("decoy_peer_refused", uid)
                    incoming.close()
                    continue
                incoming.setblocking(False)
                buffer = bytearray()
                code = receive_decoy(incoming, buffer)
                if code is not None:
                    if code:
                        self.refuse_decoy(code, uid)
                    incoming.close()
                    continue
                if len(decoy_clients) >= DECOY_MAX_CONNECTIONS:
                    self.refuse_decoy("decoy_overloaded", uid)
                    incoming.close()
                    continue
                decoy_clients[incoming] = (buffer, time.monotonic() + self.read_deadline, uid)
                selector.register(incoming, selectors.EVENT_READ)

        def receive(connection, buffer):
            """Read what is available; None while unfinished, else a code ("" = done)."""
            # Bounded rounds: an unfinished connection is read again on the
            # next select rather than holding the loop.
            for _ in range(RECV_ROUNDS):
                try:
                    data = connection.recv(MAX_LINE + 2 - len(buffer))
                except BlockingIOError:
                    return None
                except OSError:
                    return "read_error"
                buffer.extend(data)
                if len(buffer) > MAX_LINE + 1:
                    return "EDGE_TOO_LARGE"
                if b"\n" in buffer:
                    # Wait for EOF to refuse a second line as a whole.
                    if buffer.count(b"\n") != 1 or not buffer.endswith(b"\n"):
                        return "EDGE_SHAPE"
                    if not data:
                        try:
                            event = parse_edge_line(bytes(buffer[:-1]))
                            if type(event) is ForwardStats:
                                self.forward_stats(event)
                                return ""
                            record = EvidenceRecord.receive(event, self.clock)
                            self.pending.put_nowait(record)
                        except EdgeEventRefused as exc:
                            return exc.code
                        except queue.Full:
                            return "queue_full"
                        return ""
                elif not data:
                    return "EDGE_SHAPE"
            return None

        try:
            selector.register(listener, selectors.EVENT_READ)
            if decoy_listener is not None:
                selector.register(decoy_listener, selectors.EVENT_READ)
            worker.start()
            if ready:
                ready()
            while not stop():
                for key, _ in selector.select(0.05):
                    connection = key.fileobj
                    if connection is decoy_listener:
                        accept_decoy()
                        continue
                    if connection in decoy_clients:
                        code = receive_decoy(connection, decoy_clients[connection][0])
                        if code is not None:
                            close(connection, code)
                        continue
                    if connection is listener:
                        # A finite batch lets deadlines run even during a flood.
                        inline = 0
                        for _ in range(LISTEN_BACKLOG):
                            try:
                                incoming, _ = listener.accept()
                            except BlockingIOError:
                                break
                            try:
                                if self.peer_uid(incoming) != self.edge_uid:
                                    self.refuse("peer_refused")
                                    incoming.close()
                                    continue
                            except Exception:  # noqa: BLE001 - failures must not stop acceptance or expose input
                                self.refuse("peer_refused")
                                incoming.close()
                                continue
                            incoming.setblocking(False)
                            # Edge sends each line on its own connection and closes
                            # at once; finishing complete ones here keeps a burst
                            # from exhausting reader slots before the next select.
                            buffer = bytearray()
                            code = None
                            # Past the inline budget a connection is read only
                            # when no reader slot is left: dropping one whose
                            # line has already arrived would turn a burst from
                            # Edge's forwarding thread into lost events. A full
                            # backlog is never left for Edge to wait on.
                            if inline < MAX_INLINE or len(clients) >= self.max_connections:
                                inline += 1
                                code = receive(incoming, buffer)
                            if code is not None:
                                if code:
                                    self.refuse(code)
                                incoming.close()
                                continue
                            if len(clients) >= self.max_connections:
                                self.refuse("overloaded")
                                incoming.close()
                                continue
                            clients[incoming] = (
                                buffer,
                                time.monotonic() + self.read_deadline,
                            )
                            selector.register(incoming, selectors.EVENT_READ)
                        continue
                    code = receive(connection, clients[connection][0])
                    if code is not None:
                        close(connection, code)
                for connection, (_, deadline) in list(clients.items()):
                    if time.monotonic() >= deadline:
                        close(connection, "read_deadline")
                for connection, (_, deadline, _) in list(decoy_clients.items()):
                    if time.monotonic() >= deadline:
                        close(connection, "decoy_read_deadline")
                if decoy_listener is not None:
                    flush = getattr(self.decoy_refusals, "flush_due", None)
                    if flush is not None:
                        flush()
        finally:
            for connection in list(clients) + list(decoy_clients):
                close(connection)
            selector.close()
            listener.close()
            self.path.unlink(missing_ok=True)
            if decoy_listener is not None:
                decoy_listener.close()
                self.decoy_path.unlink(missing_ok=True)
                self.decoy_listening = False
            self.finished.set()
            if worker.ident is not None:
                worker.join(WORKER_JOIN_S)
                if worker.is_alive():
                    self.storage_failed = True
                    self.refuse("storage_failed")
                    try:
                        self._status()
                    except Exception:  # noqa: BLE001 - expose only a fixed failure code
                        self.refuse("status_write_failed")
                    return 1
        return 0


def main(argv=None):
    """Resolve installation-owned identity before opening the receive socket."""
    from .runtime_paths import (
        edge_intake_state_dir,
        incident_segments_dir,
        edge_intake_status_path,
        socket_path,
    )
    from .systemd_notify import runtime_ready_callback

    if sys.argv[1:] if argv is None else argv:
        raise SystemExit("az-edge-intaked takes no arguments")
    try:
        uid = pwd.getpwnam("azedge").pw_uid
        gid = grp.getgrnam("azedge").gr_gid
    except KeyError:
        raise SystemExit("edge intake account missing") from None
    # The decoy socket (#196 P2) is optional: without the azdecoy account
    # (installed since #196 P1) the intake serves Edge alone, as before.
    try:
        decoy_uid = pwd.getpwnam("azdecoy").pw_uid
        decoy_gid = grp.getgrnam("azdecoy").gr_gid
    except KeyError:
        decoy_uid = decoy_gid = None
    stopped = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stopped.set())
    server = IntakeServer(
        path=socket_path("edge-intake"),
        state=edge_intake_state_dir(),
        incident_root=incident_segments_dir(),
        status_path=edge_intake_status_path(),
        edge_uid=uid,
        expected_gid=gid,
        decoy_path=socket_path("decoy-intake") if decoy_uid is not None else None,
        decoy_uid=decoy_uid,
        decoy_gid=decoy_gid,
    )
    return server.serve(stop=stopped.is_set, ready=runtime_ready_callback())


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
