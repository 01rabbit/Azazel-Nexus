"""Receive Edge observations only; the explainer forwards selected audit transitions."""

from __future__ import annotations

import grp
import json
import os
import pwd
import queue
import selectors
import signal
import stat
import sys
import tempfile
import threading
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from azazel_nexus.audit import GENESIS_HASH, AuditChainBroken, AuditLedger
from azazel_nexus.edge_intake import (
    MAX_LINE,
    MAX_OPEN,
    SEVERE_SEVERITY,
    STATUS_SCHEMA,
    EdgeEventRefused,
    EvidenceRecord,
    IncidentTracker,
    canonical,
    parse_edge_event,
)
from azazel_nexus.store_dirs import store_directory

from .principal import peer_credentials
from .transport import bind_socket

MAX_CONNECTIONS = 64
# Connections finished at accept time per listener batch. Each costs at most
# RECV_ROUNDS reads of a 16 KiB line; the cap keeps one batch from starving
# registered readers and deadlines. The rest are registered as before.
MAX_INLINE = 64
RECV_ROUNDS = 8
QUEUE_SIZE = 256
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
RESERVED_CONTROL = frozenset({"edge.incident.reset", "edge.incident.truncated",
                              "edge.incident.retention"})
WORKER_JOIN_S = 20
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

    def __init__(self, root, **limits):
        super().__init__(root, "evidence", **limits)

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
                raise SegmentFull("evidence_segment_full")
            if os.write(fd, data) != len(data):
                raise OSError("evidence append incomplete")
            os.fsync(fd)
        finally:
            os.close(fd)
        self.retain()


class IncidentLedgerTorn(Exception):
    """An unterminated segment needs explicit operator recovery."""


class IncidentLedger(DailySegments):
    """One chain through retained daily segments, with a durable left boundary."""

    def __init__(self, root, now, *, leaf="incidents", severe_reserve=SEVERE_RESERVE, **limits):
        limits.setdefault("segment_bytes", INCIDENT_SEGMENT_BYTES)
        super().__init__(root, leaf, mode=0o2750, **limits)
        self.severe_reserve = severe_reserve
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
        for path in paths:
            self.check_segment(path)
            for entry in AuditLedger(path, private=True, file_mode=0o640):
                if (entry.sequence != self.head[0] + 1 or
                        entry.previous_hash != self.head[1] or
                        entry.recomputed() != entry.event_hash):
                    raise AuditChainBroken("incident chain does not continue")
                self.head = (entry.sequence, entry.event_hash)
        self.current = paths[-1] if paths else None
        self.select(now)
        self.retain()

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
    ):
        self.path, self.state, self.status_path = path, state, status_path
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

    def refuse(self, code):
        with self.lock:
            self.refused[code] += 1

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
            }

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
        ledger = (IncidentLedger(self.incident_root.parent, self.clock(), leaf=self.incident_root.name)
                  if self.incident_root != self.state else IncidentLedger(self.state, self.clock()))
        try:
            ledger.append(
                {"event_type": "edge.incident.reset", "at": self.clock(),
                 "reason": "intake_started"},
                self.clock(),
            )
        except SegmentFull as exc:
            self.refuse(exc.code)
        self.store, self.ledger = store, ledger
        self._future()

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
        selector = selectors.DefaultSelector()
        clients = {}
        worker = threading.Thread(target=self._writer, daemon=True)

        def close(connection, code=None):
            if code:
                self.refuse(code)
            selector.unregister(connection)
            clients.pop(connection)
            connection.close()

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
                            event = parse_edge_event(bytes(buffer[:-1]))
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
            worker.start()
            if ready:
                ready()
            while not stop():
                for key, _ in selector.select(0.05):
                    connection = key.fileobj
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
                            if inline < MAX_INLINE:
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
        finally:
            for connection in list(clients):
                close(connection)
            selector.close()
            listener.close()
            self.path.unlink(missing_ok=True)
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
    )
    return server.serve(stop=stopped.is_set, ready=runtime_ready_callback())


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
