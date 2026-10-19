"""Receive Edge observations only; auditd forwarding belongs to I3."""

from __future__ import annotations

import grp
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

from azazel_nexus.audit import AuditLedger
from azazel_nexus.edge_intake import (
    MAX_LINE,
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
QUEUE_SIZE = 256
READ_DEADLINE_S = 2
LISTEN_BACKLOG = 512
STATUS_INTERVAL_S = 5
RETENTION_BYTES = 256 * 1024 * 1024
RETENTION_DAYS = 14
SEGMENT_BYTES = 64 * 1024 * 1024


class SegmentFull(Exception):
    """A daily ceiling refuses this append, without poisoning tomorrow's writer."""

    def __init__(self, code):
        self.code = code


class DailySegments:
    """Delete oldest whole segments, always keeping newest and active paths."""

    def __init__(
        self, root, leaf, *, max_bytes=RETENTION_BYTES,
        days=RETENTION_DAYS, segment_bytes=SEGMENT_BYTES,
    ):
        self.directory = root / leaf
        store_directory(self.directory, 0o700)
        self.max_bytes, self.days = max_bytes, days
        self.segment_bytes = segment_bytes
        self.current = None
        self.age_anchor = None

    def path_at(self, now):
        day = datetime.fromtimestamp(now, UTC).strftime("%Y-%m-%d")
        return self.directory / (day + ".jsonl")

    def retain(self, now):
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
        if self.age_anchor is None:
            self.age_anchor = (newest_day, time.monotonic())
        anchor_day, anchor_time = self.age_anchor
        # Allow a normal midnight rollover, but not years of ageing from a
        # single forward wall-clock jump during this run.
        age_day = min(
            newest_day, anchor_day + time.monotonic() - anchor_time + 86400
        )
        total = sum(size for _, _, size in segments)
        for day, path, size in segments[:-1]:
            if path == self.current:
                continue
            if day < age_day - self.days * 86400 or total > self.max_bytes:
                path.unlink()
                total -= size

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
        path = self.path_at(now)
        self.current = path
        existed = path.exists()
        os.close(self.open_segment(path, 0o640))
        if not existed:
            path.unlink()
        self.retain(now)

    def append(self, record):
        path = self.path_at(record.received_at)
        self.current = path
        self.retain(record.received_at)
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
        self.retain(record.received_at)


class IncidentLedger(DailySegments):
    """Independent daily AuditLedger chains, with bounded startup verification."""

    def __init__(self, root, now, **limits):
        super().__init__(root, "incidents", **limits)
        self.ledger = None
        self.current = self.path_at(now)
        self.retain(now)
        self.select(now)
        self.retain(now)

    def select(self, now):
        path = self.path_at(now)
        if path == self.current and self.ledger is not None:
            return
        fd = self.open_segment(path, 0o600)
        try:
            if os.fstat(fd).st_size > self.segment_bytes:
                raise OSError("incident segment exceeds ceiling")
        finally:
            os.close(fd)
        ledger = AuditLedger(path, private=True)
        ledger.verify()
        self.current, self.ledger = path, ledger

    def append(self, event, now):
        self.select(now)
        # Reserve space for the chain envelope, hashes and sequence number.
        required = len(canonical(event)) + 512
        if self.current.stat().st_size + required > self.segment_bytes:
            raise SegmentFull("incident_segment_full")
        self.ledger.append(event)
        self.retain(now)


class IntakeServer:
    """Accept independently of disk, bounded readers and a single ledger writer."""

    def __init__(
        self,
        *,
        path: Path,
        state: Path,
        status_path: Path,
        edge_uid: int,
        expected_gid=None,
        peer_uid=None,
        clock=time.time,
        max_connections=MAX_CONNECTIONS,
        queue_size=QUEUE_SIZE,
        read_deadline=READ_DEADLINE_S,
    ):
        self.path, self.state, self.status_path = path, state, status_path
        self.edge_uid, self.expected_gid = edge_uid, expected_gid
        self.peer_uid = peer_uid or (lambda connection: peer_credentials(connection)[1])
        self.clock = clock
        self.max_connections, self.read_deadline = max_connections, read_deadline
        self.pending = queue.Queue(maxsize=queue_size)
        self.refused = Counter()
        self.accepted = 0
        self.last_accepted_at = None
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
        ledger = IncidentLedger(self.state, self.clock())
        try:
            ledger.append(
                {"event_type": "edge.incident.reset", "at": self.clock(),
                 "reason": "intake_started"},
                self.clock(),
            )
        except SegmentFull as exc:
            self.refuse(exc.code)
        self.store, self.ledger = store, ledger

    def _transitions(self, transitions):
        for transition in transitions:
            event_type = "edge.incident." + transition.pop("transition")
            try:
                self.ledger.append(
                    dict(event_type=event_type, **transition), self.clock()
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
                    if record is not None:
                        self.store.append(record)
                        transitions = self.tracker.add(record)
                        with self.lock:
                            self.refused["incident_rate_limited"] = self.tracker.rate_limited
                    else:
                        transitions = self.tracker.tick()
                    self._transitions(transitions)
                    with self.lock:
                        self.open_incidents = len(self.tracker.incidents)
                        if record is not None:
                            self.accepted += 1
                            self.last_accepted_at = record.received_at
                except SegmentFull as exc:
                    self.refuse(exc.code)
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
                self._transitions([
                    self.tracker._close(key, "shutdown")
                    for key in list(self.tracker.incidents)
                ])
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
        except Exception:  # noqa: BLE001 - fail startup before binding or signalling READY
            self.storage_failed = True
            self.refuse("storage_failed")
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
                            if len(clients) >= self.max_connections:
                                self.refuse("overloaded")
                                incoming.close()
                                continue
                            incoming.setblocking(False)
                            clients[incoming] = (
                                bytearray(),
                                time.monotonic() + self.read_deadline,
                            )
                            selector.register(incoming, selectors.EVENT_READ)
                        continue
                    buffer, deadline = clients[connection]
                    try:
                        data = connection.recv(MAX_LINE + 2 - len(buffer))
                    except OSError:
                        close(connection, "read_error")
                        continue
                    buffer.extend(data)
                    if len(buffer) > MAX_LINE + 1:
                        close(connection, "EDGE_TOO_LARGE")
                    elif b"\n" in buffer:
                        # Wait for EOF to refuse a second line as a whole.
                        if buffer.count(b"\n") != 1 or not buffer.endswith(b"\n"):
                            close(connection, "EDGE_SHAPE")
                        elif not data:
                            try:
                                event = parse_edge_event(bytes(buffer[:-1]))
                                record = EvidenceRecord.receive(event, self.clock)
                                self.pending.put_nowait(record)
                            except EdgeEventRefused as exc:
                                self.refuse(exc.code)
                            except queue.Full:
                                self.refuse("queue_full")
                            close(connection)
                    elif not data:
                        close(connection, "EDGE_SHAPE")
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
                worker.join()
        return 0


def main(argv=None):
    """Resolve installation-owned identity before opening the receive socket."""
    from .runtime_paths import (
        edge_intake_state_dir,
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
        status_path=edge_intake_status_path(),
        edge_uid=uid,
        expected_gid=gid,
    )
    return server.serve(stop=stopped.is_set, ready=runtime_ready_callback())


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
