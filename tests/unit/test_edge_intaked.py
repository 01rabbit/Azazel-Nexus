"""A stalled or hostile sender must not stall Edge's blocking connect."""

import ast
import json
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest
from azazel_nexus_runtime import edge_intaked as daemon
from test_edge_intake import edge_event, record

from azazel_nexus.audit import AuditLedger
from azazel_nexus.edge_intake import read_intake_status


def wait_for(predicate, timeout=3):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if predicate():
            return
        time.sleep(0.01)
    assert predicate()


@pytest.fixture
def running():
    servers = []
    with tempfile.TemporaryDirectory(prefix="i1-", dir="/tmp") as directory:
        root = Path(directory)

        def start(**kwargs):
            leaf = root / str(len(servers))
            leaf.mkdir()
            state = leaf / "state"
            state.mkdir()
            server = daemon.IntakeServer(
                path=leaf / "in.sock",
                state=state,
                status_path=leaf / "status.json",
                edge_uid=123,
                peer_uid=lambda _: 123,
                **kwargs,
            )
            stop, ready = threading.Event(), threading.Event()
            errors = []

            def run():
                try:
                    server.serve(stop=stop.is_set, ready=ready.set)
                except BaseException as exc:  # noqa: BLE001 - relay thread failures to pytest
                    errors.append(exc)
                    ready.set()

            thread = threading.Thread(target=run)
            servers.append((server, stop, thread, errors))
            thread.start()
            assert ready.wait(3)
            assert not errors
            return server

        yield start
        for server, stop, thread, errors in servers:
            stop.set()
            thread.join(4)
            assert not thread.is_alive()
            assert not errors
            assert not server.path.exists()


def send(server, data=None):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(1)
        client.connect(str(server.path))
        client.sendall(
            data if data is not None else json.dumps(edge_event()).encode() + b"\n"
        )


def test_event_stored_chain_verifies_and_status_is_readable(running):
    server = running()
    send(server)
    wait_for(lambda: server.accepted == 1)
    (path,) = (server.state / "evidence").glob("*.jsonl")
    stored = json.loads(path.read_text())
    assert stored["event"]["defense"] == edge_event()["defense"]
    assert path.stat().st_mode & 0o777 == 0o640
    ledger = AuditLedger(next((server.state / "incidents").glob("*.jsonl")))
    ledger.verify()
    assert [entry.event["event_type"] for entry in ledger] == [
        "edge.incident.reset", "edge.incident.opened"
    ]
    server._status()
    value = read_intake_status(server.status_path.read_bytes())
    assert value["accepted"] == 1
    assert value["open_incidents"] == 1
    assert value["last_accepted_at"] is not None
    assert value["queue_drops"] == 0
    assert server.status_path.stat().st_mode & 0o777 == 0o644
    assert server.path.stat().st_mode & 0o777 == 0o660


def test_peer_refused_without_record(running):
    server = running()
    server.peer_uid = lambda _: 999
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(server.path))
    wait_for(lambda: server.refused["peer_refused"] == 1)
    assert server.accepted == 0
    assert list((server.state / "evidence").glob("*.jsonl")) == []


def test_slow_client_deadline_does_not_block_another_event(running):
    server = running(read_deadline=0.2)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as slow:
        slow.connect(str(server.path))
        slow.sendall(b"{")
        send(server)
        wait_for(lambda: server.accepted == 1)
        wait_for(lambda: server.refused["read_deadline"] == 1)
        assert slow.recv(1) == b""


def test_capacity_keeps_accepting_while_all_readers_are_held(running):
    server = running()
    clients = []
    try:
        for _ in range(daemon.MAX_CONNECTIONS + 32):
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            clients.append(client)
            client.settimeout(1)
            started = time.monotonic()
            client.connect(str(server.path))
            assert time.monotonic() - started < 1
        wait_for(lambda: server.refused["overloaded"] >= 32)
    finally:
        for client in clients:
            client.close()


def test_bounded_queue_drops_without_waiting_for_writer(running, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = daemon.EvidenceStore.append

    def blocked(self, record):
        entered.set()
        assert release.wait(3)
        original(self, record)

    monkeypatch.setattr(daemon.EvidenceStore, "append", blocked)
    server = running(queue_size=1)
    try:
        send(server)
        assert entered.wait(2)
        send(server)
        wait_for(lambda: server.pending.qsize() == 1)
        send(server)
        wait_for(lambda: server.refused["queue_full"] == 1)
        assert server.snapshot()["queue_drops"] == 1
    finally:
        release.set()
    wait_for(lambda: server.accepted == 2)


@pytest.mark.parametrize(
    "data,code",
    [
        (b"{}\n", "EDGE_SHAPE"),
        (b"{}\n{}\n", "EDGE_SHAPE"),
        (b"x" * 16386, "EDGE_TOO_LARGE"),
        (b"{}", "EDGE_SHAPE"),
        (b"\xff\n", "EDGE_JSON"),
    ],
    ids=["shape", "two-lines", "oversize", "no-newline", "utf8"],
)
def test_bad_connection_is_counted_without_content(running, data, code):
    server = running()
    send(server, data)
    wait_for(lambda: server.refused[code] == 1)
    assert server.accepted == 0
    assert list((server.state / "evidence").glob("*.jsonl")) == []
    ledger = AuditLedger(next((server.state / "incidents").glob("*.jsonl")))
    assert [entry.event["event_type"] for entry in ledger] == ["edge.incident.reset"]


def test_storage_failure_stays_closed_but_listener_survives(running, monkeypatch):
    def failed(*_):
        raise OSError("SECRET")

    monkeypatch.setattr(daemon.EvidenceStore, "append", failed)
    server = running()
    send(server)
    wait_for(lambda: server.storage_failed)
    send(server)
    wait_for(lambda: server.refused["storage_failed"] >= 2)
    assert server.accepted == 0
    assert "SECRET" not in json.dumps(server.snapshot())


def test_retention_deletes_whole_oldest_segments_and_refuses_links(tmp_path):
    store = daemon.EvidenceStore(tmp_path, max_bytes=8, days=14)
    for day in ("2026-01-01", "2026-01-02", "2026-01-03"):
        (store.directory / (day + ".jsonl")).write_bytes(b"1234")
    now = daemon.datetime(2026, 1, 3, tzinfo=daemon.UTC).timestamp()
    store.retain(now)
    assert sorted(p.stem for p in store.directory.iterdir()) == [
        "2026-01-02",
        "2026-01-03",
    ]
    store.retain(now + 20 * 86400)
    assert sorted(p.stem for p in store.directory.iterdir()) == [
        "2026-01-02", "2026-01-03",
    ]
    victim = tmp_path / "victim"
    victim.write_text("SECRET")
    (store.directory / "1970-01-01.jsonl").symlink_to(victim)
    with pytest.raises(OSError):
        store.append(record(0))
    assert victim.read_text() == "SECRET"


def test_daemon_has_no_outbound_or_process_control_surface():
    tree = ast.parse(Path(daemon.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in {
                "connect",
                "connect_ex",
                "send",
                "sendall",
                "sendto",
            }
        if isinstance(node, ast.Import):
            assert not any(
                n.name.split(".")[0] in {"subprocess", "dbus"} for n in node.names
            )
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in {"subprocess", "dbus"}


def test_missing_edge_account_refuses_before_binding(monkeypatch):
    def missing(_):
        raise KeyError("SECRET")

    monkeypatch.setattr(daemon.pwd, "getpwnam", missing)
    with pytest.raises(SystemExit, match="^edge intake account missing$"):
        daemon.main([])


def test_socket_equals_fixed_i0_destination_and_registration():
    from azazel_nexus_runtime import runtime_paths
    from azazel_nexus_runtime.hardening import PROFILES

    from azazel_nexus.activation import CORE_UNITS, UnitTier

    core = next(p for p in PROFILES if p.unit == "azazel-edge-core.service")
    intake = next(p for p in PROFILES if p.unit == "azazel-edge-intaked.service")
    assert (
        "Environment",
        "AZAZEL_AI_SOCKET=" + str(runtime_paths.socket_path("edge-intake")),
    ) in core.extra
    assert intake.account == "azintake"
    assert intake.address_families == ("AF_UNIX",)
    assert not intake.capability_bounding_set
    assert ("PrivateNetwork", "yes") in intake.extra
    assert dict(intake.extra) == {
        "PrivateNetwork": "yes", "Restart": "no", "TimeoutStartSec": "30s",
        "MemoryMax": "256M", "TasksMax": "32", "LimitNOFILE": "256",
        "LimitFSIZE": "128M",
    }
    assert (
        next(u for u in CORE_UNITS if u.name == intake.unit).tier is UnitTier.SUPPORTING
    )


def test_writer_persists_transitions_without_transport(tmp_path):
    """Exercise real files even on hosts that prohibit Unix sockets."""
    server = daemon.IntakeServer(
        path=tmp_path / "unused.sock",
        state=tmp_path,
        status_path=tmp_path / "status.json",
        edge_uid=123,
        clock=lambda: 100,
    )
    for now in (0, 59, 60, 1000):
        server.pending.put(record(now))
    server.finished.set()
    server._writer()
    assert server.accepted == 4
    assert not server.storage_failed
    ledger = AuditLedger(next((tmp_path / "incidents").glob("*.jsonl")))
    ledger.verify()
    assert [entry.event["event_type"] for entry in ledger] == [
        "edge.incident.reset",
        "edge.incident.opened",
        "edge.incident.updated",
        "edge.incident.closed",
        "edge.incident.opened",
        "edge.incident.closed",
    ]
    server._status()
    assert read_intake_status(server.status_path.read_bytes())["accepted"] == 4


def test_broken_chain_refuses_new_records_without_content(tmp_path):
    (tmp_path / "incidents").mkdir()
    (tmp_path / "incidents/1970-01-01.jsonl").write_text("SECRET")
    server = daemon.IntakeServer(
        path=tmp_path / "unused.sock",
        state=tmp_path,
        status_path=tmp_path / "status.json",
        edge_uid=123,
        clock=lambda: 100,
    )
    ready = []
    assert server.serve(ready=lambda: ready.append(True)) == 1
    assert not ready
    assert not server.path.exists()
    assert server.accepted == 0
    assert server.storage_failed
    assert "SECRET" not in server.status_path.read_text()
    assert list((tmp_path / "evidence").glob("*.jsonl")) == []


@pytest.mark.parametrize("kind", [daemon.EvidenceStore, daemon.IncidentLedger])
def test_retention_keeps_newest_over_total_ceiling_and_ignores_wall_jump(tmp_path, kind):
    now = daemon.datetime(2026, 1, 20, tzinfo=daemon.UTC).timestamp()
    if kind is daemon.EvidenceStore:
        store = kind(tmp_path, max_bytes=1)
    else:
        store = kind(tmp_path, now, max_bytes=1)
    for day in ("2026-01-01", "2026-01-10", "2026-01-20"):
        (store.directory / (day + ".jsonl")).write_bytes(b"1234")
    store.retain(daemon.datetime(2099, 1, 1, tzinfo=daemon.UTC).timestamp())
    assert sorted(p.stem for p in store.directory.iterdir()) == ["2026-01-20"]
    store.max_bytes = 100
    for day in ("2026-01-01", "2026-01-10"):
        (store.directory / (day + ".jsonl")).write_bytes(b"1234")
    store.retain(daemon.datetime(2099, 1, 1, tzinfo=daemon.UTC).timestamp())
    assert sorted(p.stem for p in store.directory.iterdir()) == ["2026-01-10", "2026-01-20"]


def test_evidence_ceiling_refuses_append_and_resumes_next_day(tmp_path):
    item = record(0)
    size = max(len(daemon.canonical(record(now).as_dict())) + 1 for now in (0, 86400))
    store = daemon.EvidenceStore(tmp_path, max_bytes=1, segment_bytes=size)
    store.append(item)
    path = store.path_at(0)
    before = path.read_bytes()
    with pytest.raises(daemon.SegmentFull) as caught:
        store.append(item)
    assert caught.value.code == "evidence_segment_full"
    assert path.read_bytes() == before
    store.append(record(86400))
    assert store.path_at(86400).exists()


def test_segment_full_keeps_listener_and_next_day_writer(running, monkeypatch):
    original = daemon.EvidenceStore.append
    def full_once(self, item):
        monkeypatch.setattr(daemon.EvidenceStore, "append", original)
        raise daemon.SegmentFull("evidence_segment_full")
    monkeypatch.setattr(daemon.EvidenceStore, "append", full_once)
    server = running()
    send(server)
    wait_for(lambda: server.refused["evidence_segment_full"] == 1)
    assert not server.snapshot()["storage_failed"]
    send(server)
    wait_for(lambda: server.accepted == 1)


def test_startup_evidence_failure_is_before_ready_and_bind(tmp_path, monkeypatch):
    def failed(*_):
        raise OSError("SECRET")
    monkeypatch.setattr(daemon.EvidenceStore, "prepare", failed)
    server = daemon.IntakeServer(path=tmp_path / "in.sock", state=tmp_path,
                                 status_path=tmp_path / "status.json", edge_uid=123)
    ready = []
    assert server.serve(ready=lambda: ready.append(True)) == 1
    assert not ready and not server.path.exists()
    assert server.snapshot()["storage_failed"]
    assert "SECRET" not in json.dumps(server.snapshot())


def test_status_failure_does_not_poison_storage(tmp_path, monkeypatch):
    def failed(*_):
        raise OSError("SECRET")
    monkeypatch.setattr(daemon.IntakeServer, "_status", failed)
    server = daemon.IntakeServer(path=tmp_path / "unused.sock", state=tmp_path,
                                 status_path=tmp_path / "status.json", edge_uid=123)
    server.pending.put(record(0))
    server.finished.set()
    server._writer()
    assert server.accepted == 1
    assert server.refused["status_write_failed"] > 0
    assert not server.storage_failed
    assert server.refused["storage_failed"] == 0


def test_rate_limit_preserves_evidence_and_counts_status(tmp_path):
    server = daemon.IntakeServer(path=tmp_path / "unused.sock", state=tmp_path,
                                 status_path=tmp_path / "status.json", edge_uid=123,
                                 clock=lambda: 0)
    server.tracker.monotonic = lambda: 0
    for sid in range(65):
        server.pending.put(record(0, sid=sid))
    server.finished.set()
    server._writer()
    assert server.accepted == 65
    assert server.snapshot()["refused"]["incident_rate_limited"] == 5
    assert len(next((tmp_path / "evidence").glob("*.jsonl")).read_text().splitlines()) == 65
    ledger = AuditLedger(next((tmp_path / "incidents").glob("*.jsonl")))
    entries = [entry.event for entry in ledger]
    assert entries[0] == {"event_type": "edge.incident.reset", "at": 0,
                          "reason": "intake_started"}
    assert sum(e["event_type"] == "edge.incident.opened" for e in entries) == 60
    closed = [e for e in entries if e["event_type"] == "edge.incident.closed"]
    assert len(closed) == 60 and all(e["reason"] == "shutdown" for e in closed)
    assert read_intake_status(server.status_path.read_bytes())["storage_failed"] is False


def test_incident_segments_are_capped_and_only_current_verified(tmp_path):
    directory = tmp_path / "incidents"
    directory.mkdir()
    (directory / "1970-01-01.jsonl").write_text("old unverified data")
    ledger = daemon.IncidentLedger(tmp_path, 86400, segment_bytes=1024)
    event = {"event_type": "edge.incident.reset", "at": 86400, "reason": "intake_started"}
    ledger.append(event, 86400)
    before = ledger.current.read_bytes()
    ledger.segment_bytes = len(before)
    with pytest.raises(daemon.SegmentFull) as caught:
        ledger.append(event, 86400)
    assert caught.value.code == "incident_segment_full"
    assert ledger.current.read_bytes() == before
    ledger.segment_bytes = 1024
    ledger.append(event, 2 * 86400)
    ledger.ledger.verify()
    assert ledger.ledger.head()[0] == 1


@pytest.mark.parametrize("kind", [daemon.EvidenceStore, daemon.IncidentLedger])
def test_received_time_leap_does_not_age_existing_segments(tmp_path, kind):
    jan20 = daemon.datetime(2026, 1, 20, tzinfo=daemon.UTC).timestamp()
    future = daemon.datetime(2099, 1, 1, tzinfo=daemon.UTC).timestamp()
    if kind is daemon.EvidenceStore:
        store = kind(tmp_path)
    else:
        store = kind(tmp_path, jan20)
    old = store.directory / "2026-01-10.jsonl"
    if kind is daemon.EvidenceStore:
        old.write_text("retained evidence")
        store.append(record(jan20))
        store.append(record(future))
    else:
        AuditLedger(old, private=True).append({"at": jan20})
        store.append({"at": jan20}, jan20)
        store.append({"at": future}, future)
    assert old.exists()
    assert store.path_at(future).exists()


def test_writer_recovers_from_daily_ceiling_without_transport(tmp_path, monkeypatch):
    original = daemon.EvidenceStore.append
    def full_once(self, item):
        monkeypatch.setattr(daemon.EvidenceStore, "append", original)
        raise daemon.SegmentFull("evidence_segment_full")
    monkeypatch.setattr(daemon.EvidenceStore, "append", full_once)
    server = daemon.IntakeServer(path=tmp_path / "unused.sock", state=tmp_path,
                                 status_path=tmp_path / "status.json", edge_uid=123,
                                 clock=lambda: 86400)
    server.pending.put(record(0))
    server.pending.put(record(86400))
    server.finished.set()
    server._writer()
    assert server.accepted == 1
    assert server.refused["evidence_segment_full"] == 1
    assert not server.storage_failed


def test_status_reader_requires_boolean_storage_failure(tmp_path):
    server = daemon.IntakeServer(path=tmp_path / "unused.sock", state=tmp_path,
                                 status_path=tmp_path / "status.json", edge_uid=123)
    value = server.snapshot()
    assert read_intake_status(daemon.canonical(value))["storage_failed"] is False
    value["storage_failed"] = 1
    assert read_intake_status(daemon.canonical(value)) is None
    value.pop("storage_failed")
    assert read_intake_status(daemon.canonical(value)) is None


@pytest.mark.parametrize("kind", [daemon.EvidenceStore, daemon.IncidentLedger])
def test_retention_keeps_active_segment_when_clock_moves_back(tmp_path, kind):
    if kind is daemon.EvidenceStore:
        store = kind(tmp_path, max_bytes=1)
        store.append(record(20 * 86400))
        store.append(record(0))
    else:
        store = kind(tmp_path, 20 * 86400, max_bytes=1)
        store.append({"at": 0}, 0)
    assert store.path_at(0).exists()
    assert store.path_at(20 * 86400).exists()


def test_restart_marks_previous_open_incidents_reset(tmp_path):
    ledger = daemon.IncidentLedger(tmp_path, 0)
    ledger.append({"event_type": "edge.incident.opened", "incident_id": "inc-old"}, 0)
    server = daemon.IntakeServer(path=tmp_path / "unused.sock", state=tmp_path,
                                 status_path=tmp_path / "status.json", edge_uid=123,
                                 clock=lambda: 0)
    server._open_storage()
    events = [entry.event for entry in server.ledger.ledger]
    assert events[-1] == {"event_type": "edge.incident.reset", "at": 0,
                          "reason": "intake_started"}
    assert server.tracker.incidents == {}


@pytest.mark.parametrize("writer", ["store", "ledger"])
def test_runtime_writer_failure_stays_closed_without_transport(tmp_path, monkeypatch, writer):
    server = daemon.IntakeServer(path=tmp_path / "unused.sock", state=tmp_path,
                                 status_path=tmp_path / "status.json", edge_uid=123,
                                 clock=lambda: 0)
    server._open_storage()
    def failed(*_):
        raise OSError("SECRET")
    monkeypatch.setattr(getattr(server, writer), "append", failed)
    for _ in range(2):
        server.pending.put(record(0))
    server.finished.set()
    server._writer()
    assert server.accepted == 0
    assert server.snapshot()["storage_failed"] is True
    assert server.refused["storage_failed"] == 2
    assert "SECRET" not in server.status_path.read_text()
