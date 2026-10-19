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
from azazel_nexus.incident_explain import read_transition


def elapsed(step=86400):
    """A monotonic clock that keeps up with test clocks jumping whole days."""
    instant = iter(range(0, 2**40, step))
    return lambda: next(instant)


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
    store.retain()
    assert sorted(p.stem for p in store.directory.iterdir()) == [
        "2026-01-02",
        "2026-01-03",
    ]
    store.retain()
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
        "PrivateNetwork": "yes", "TimeoutStartSec": "30s",
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


@pytest.mark.parametrize("kind", [daemon.EvidenceStore])
def test_retention_keeps_newest_over_total_ceiling_and_ignores_wall_jump(tmp_path, kind):
    now = daemon.datetime(2026, 1, 20, tzinfo=daemon.UTC).timestamp()
    if kind is daemon.EvidenceStore:
        store = kind(tmp_path, max_bytes=1)
    else:
        store = kind(tmp_path, now, max_bytes=1)
    for day in ("2026-01-01", "2026-01-10", "2026-01-20"):
        (store.directory / (day + ".jsonl")).write_bytes(b"1234")
    store.retain()
    assert sorted(p.stem for p in store.directory.iterdir()) == ["2026-01-20"]
    store.max_bytes = 100
    for day in ("2026-01-01", "2026-01-10"):
        (store.directory / (day + ".jsonl")).write_bytes(b"1234")
    store.retain()
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
    # One source opens at most five severe incidents a minute.
    assert server.snapshot()["refused"]["incident_rate_limited"] == 60
    assert len(next((tmp_path / "evidence").glob("*.jsonl")).read_text().splitlines()) == 65
    ledger = AuditLedger(next((tmp_path / "incidents").glob("*.jsonl")))
    entries = [entry.event for entry in ledger]
    assert entries[0] == {"event_type": "edge.incident.reset", "at": 0,
                          "reason": "intake_started"}
    assert sum(e["event_type"] == "edge.incident.opened" for e in entries) == 5
    closed = [e for e in entries if e["event_type"] == "edge.incident.closed"]
    assert len(closed) == 5 and all(e["reason"] == "shutdown" for e in closed)
    assert read_intake_status(server.status_path.read_bytes())["storage_failed"] is False


def test_incident_segments_are_linked_capped_and_mark_truncation(tmp_path):
    ledger = daemon.IncidentLedger(tmp_path, 0, segment_bytes=4096, monotonic=elapsed())
    event = {"event_type": "edge.incident.reset", "at": 0, "reason": "intake_started"}
    ledger.append(event, 0)
    previous = ledger.head
    ledger.append(event, 86400)
    assert next(iter(ledger.ledger)).previous_hash == previous[1]
    while True:
        try:
            ledger.append(event, 86400)
        except daemon.SegmentFull as exc:
            assert exc.code == "incident_segment_full"
            break
    before = ledger.current.read_bytes()
    with pytest.raises(daemon.SegmentFull):
        ledger.append(event, 86400)
    assert ledger.current.read_bytes() == before
    assert ledger.current.stat().st_size <= 4096
    assert sum(e.event["event_type"] == "edge.incident.truncated" for e in ledger.ledger) == 1
    restarted = daemon.IncidentLedger(tmp_path, 86400, segment_bytes=4096)
    assert restarted.head == ledger.head
    with pytest.raises(daemon.SegmentFull):
        restarted.append(event, 86400)
    assert restarted.current.read_bytes() == before
    ledger.append(event, 2 * 86400)
    assert ledger.head[0] == restarted.head[0] + 1


@pytest.mark.parametrize("kind", [daemon.EvidenceStore, daemon.IncidentLedger])
def test_received_time_leap_does_not_age_existing_segments(tmp_path, kind):
    jan20 = daemon.datetime(2026, 1, 20, tzinfo=daemon.UTC).timestamp()
    future = daemon.datetime(2099, 1, 1, tzinfo=daemon.UTC).timestamp()
    if kind is daemon.EvidenceStore:
        store = kind(tmp_path)
    else:
        directory = tmp_path / "incidents"
        directory.mkdir()
        AuditLedger(directory / "2026-01-10.jsonl", private=True).append({"at": jan20})
        store = kind(tmp_path, jan20)
    old = store.directory / "2026-01-10.jsonl"
    if kind is daemon.EvidenceStore:
        old.write_text("retained evidence")
        store.append(record(jan20))
        store.append(record(future))
    else:
        store.append({"at": jan20}, jan20)
        store.append({"at": future}, future)
    assert old.exists()
    # The leap is held to monotonic time: no segment is dated in 2099.
    assert not store.path_at(future).exists()
    assert not store.future_segment


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
    if kind is daemon.EvidenceStore:
        assert store.path_at(0).exists()
    else:
        assert not store.path_at(0).exists()
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


def test_incident_retention_boundary_survives_restart_and_pending_unlink(tmp_path):
    ledger = daemon.IncidentLedger(tmp_path, 0, max_bytes=1)
    ledger.append({"at": 0}, 0)
    retired_path = ledger.current
    retired = retired_path.read_bytes()
    retired_head = ledger.head
    ledger.append({"at": 86400}, 86400)
    assert not retired_path.exists()
    boundary = json.loads(ledger.boundary.read_bytes())
    assert boundary == {"oldest": "1970-01-02.jsonl", "deleted": "1970-01-01.jsonl",
                        "sequence": retired_head[0], "hash": retired_head[1]}
    assert ledger.boundary.stat().st_mode & 0o777 == 0o640
    # Simulate power loss after boundary fsync and before the retired unlink.
    retired_path.write_bytes(retired)
    restarted = daemon.IncidentLedger(tmp_path, 86400, max_bytes=1)
    assert not retired_path.exists()
    assert restarted.head == ledger.head
    ledger.current.unlink()
    with pytest.raises(daemon.AuditChainBroken):
        daemon.IncidentLedger(tmp_path, 86400)


@pytest.mark.parametrize("change", ["delete_first", "delete_middle", "edit_link"])
def test_incident_missing_or_relinked_segment_refuses_startup(tmp_path, change):
    ledger = daemon.IncidentLedger(tmp_path, 0, monotonic=elapsed())
    for day in range(3):
        ledger.append({"at": day * 86400}, day * 86400)
    if change == "edit_link":
        path = ledger.path_at(2 * 86400)
        value = json.loads(path.read_bytes())
        value["previous_hash"] = "0" * 64
        path.write_text(json.dumps(value) + "\n")
    else:
        ledger.path_at(0 if change == "delete_first" else 86400).unlink()
    with pytest.raises(daemon.AuditChainBroken):
        daemon.IncidentLedger(tmp_path, 2 * 86400)


def test_torn_incident_final_line_refuses_with_fixed_status(tmp_path):
    ledger = daemon.IncidentLedger(tmp_path, 0)
    ledger.append({"at": 0}, 0)
    with ledger.current.open("ab") as stream:
        stream.write(b'{"SECRET":')
    before = ledger.current.read_bytes()
    server = daemon.IntakeServer(path=tmp_path / "in.sock", state=tmp_path,
                                 status_path=tmp_path / "status.json", edge_uid=123,
                                 clock=lambda: 0)
    ready = []
    assert server.serve(ready=lambda: ready.append(True)) == 1
    assert not ready and not server.path.exists()
    status = read_intake_status(server.status_path.read_bytes())
    assert status["refused"]["incident_ledger_torn"] == 1
    assert status["storage_failed"]
    assert "SECRET" not in server.status_path.read_text()
    assert ledger.current.read_bytes() == before


def test_shutdown_closes_1024_incidents_with_one_fsync(tmp_path, monkeypatch):
    server = daemon.IntakeServer(path=tmp_path / "unused.sock", state=tmp_path,
                                 status_path=tmp_path / "status.json", edge_uid=123,
                                 clock=lambda: 0)
    server._open_storage()
    transition = server.tracker.add(record(0))[0]
    for sid in range(1024):
        server.tracker.incidents[("10.0.0.8", sid, 443)] = dict(transition, sid=sid)
    calls = []
    original = daemon.os.fsync
    def fsync(fd):
        calls.append(fd)
        return original(fd)
    monkeypatch.setattr(daemon.os, "fsync", fsync)
    server.finished.set()
    server._writer()
    assert not server.storage_failed
    assert calls and len(calls) == 1
    assert sum(entry.event.get("reason") == "shutdown" for entry in server.ledger.ledger) == 1024
    server.ledger.ledger.verify()
    assert daemon.WORKER_JOIN_S == 20


def test_incident_and_evidence_have_separate_segment_ceilings(tmp_path):
    assert daemon.IncidentLedger(tmp_path, 0).segment_bytes == 16 * 1024 * 1024
    assert daemon.EvidenceStore(tmp_path).segment_bytes == 64 * 1024 * 1024


def gated(server):
    # Hold the accept loop so whole connections are complete in the backlog.
    gate = threading.Event()
    server.peer_uid = lambda _: (gate.wait(3), 123)[1]
    return gate


def test_burst_of_complete_connections_does_not_consume_reader_slots(running):
    server = running(max_connections=4)
    gate = gated(server)
    for _ in range(daemon.MAX_INLINE):
        send(server)
    gate.set()
    wait_for(lambda: server.accepted == daemon.MAX_INLINE)
    assert server.refused["overloaded"] == 0


def test_inline_finishing_is_capped_per_accept_batch(running):
    server = running(max_connections=0)
    gate = gated(server)
    for _ in range(100):
        send(server)
    gate.set()
    wait_for(lambda: server.accepted + server.refused["overloaded"] == 100)
    # Beyond the cap connections are registered as before; with no reader
    # slots that is overloaded, even though they were complete.
    assert (server.accepted, server.refused["overloaded"]) == (64, 36)
    assert daemon.MAX_INLINE == 64 and daemon.RECV_ROUNDS == 8


def send_large(server, data):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        # macOS buffers 8 KiB per unaccepted connection by default.
        client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * len(data))
        client.settimeout(1)
        client.connect(str(server.path))
        client.sendall(data)


@pytest.mark.parametrize(("data", "code"), [
    (b"{}\n{}\n", "EDGE_SHAPE"),
    (b"x" * (daemon.MAX_LINE + 2), "EDGE_TOO_LARGE"),
    (b"{" + b"x" * daemon.MAX_LINE + b"\n", "EDGE_TOO_LARGE"),
    (b"{\"a\": 1}\n", "EDGE_SHAPE"),
])
def test_complete_connection_refused_at_accept_without_a_slot(running, data, code):
    server = running(max_connections=0)
    gate = gated(server)
    send_large(server, data)
    gate.set()
    wait_for(lambda: server.refused[code] == 1)
    assert server.refused["overloaded"] == 0 and server.accepted == 0
    assert sum(server.refused.values()) == 1


@pytest.mark.parametrize("finish", [True, False])
def test_partial_line_at_accept_is_registered_then_finished_or_expires(running, finish):
    server = running(read_deadline=0.5)
    gate = gated(server)
    line = json.dumps(edge_event()).encode() + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(server.path))
        client.sendall(line[:10])
        gate.set()
        time.sleep(0.1)
        assert server.accepted == 0 and not any(server.refused.values())
        if finish:
            client.sendall(line[10:])
            client.shutdown(socket.SHUT_WR)
            wait_for(lambda: server.accepted == 1)
        else:
            wait_for(lambda: server.refused["read_deadline"] == 1)
    assert sum(server.refused.values()) == (0 if finish else 1)


def test_line_awaiting_eof_is_registered_then_finished(running):
    server = running(read_deadline=1)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(server.path))
        client.sendall(json.dumps(edge_event()).encode() + b"\n")
        time.sleep(0.2)
        assert server.accepted == 0
    wait_for(lambda: server.accepted == 1)
    assert not any(server.refused.values())


def test_full_evidence_day_still_opens_and_records_severe_incident(tmp_path, monkeypatch):
    def full(self, item):
        raise daemon.SegmentFull("evidence_segment_full")
    monkeypatch.setattr(daemon.EvidenceStore, "append", full)
    server = daemon.IntakeServer(path=tmp_path / "unused.sock", state=tmp_path,
                                 status_path=tmp_path / "status.json", edge_uid=123,
                                 clock=lambda: 100)
    server.pending.put(record(0, severity=1))
    server.finished.set()
    server._writer()
    assert server.refused["evidence_segment_full"] == 1
    assert server.accepted == 0 and not server.storage_failed
    ledger = AuditLedger(next((tmp_path / "incidents").glob("*.jsonl")))
    ledger.verify()
    events = [entry.event for entry in ledger]
    assert [e["event_type"] for e in events] == [
        "edge.incident.reset", "edge.incident.opened", "edge.incident.closed"]
    for event in events[1:]:
        assert event["evidence_stored"] is False
        assert event["latest_evidence"] == record(0).digest
        assert read_transition(event)["most_severe"] == 1


def test_incident_reserve_admits_severe_after_ordinary_fills_segment(tmp_path):
    assert daemon.IncidentLedger(tmp_path / "default", 0).severe_reserve == 1024 * 1024
    ledger = daemon.IncidentLedger(tmp_path, 0, segment_bytes=64 * 1024,
                                   severe_reserve=16 * 1024)
    def event(severity, n):
        return {"event_type": "edge.incident.opened", "incident_id": f"inc-{n:016x}",
                "most_severe": severity, "padding": "x" * 200}
    n = 0
    while True:
        n += 1
        try:
            ledger.append(event(3, n), 0)
        except daemon.SegmentFull as exc:
            assert exc.code == "incident_segment_full"
            break
    full = ledger.current.stat().st_size
    assert full <= 64 * 1024 - 16 * 1024 + 1024
    for severity in (2, 1):
        n += 1
        ledger.append(event(severity, n), 0)
    with pytest.raises(daemon.SegmentFull):
        ledger.append(event(3, n + 1), 0)
    events = [entry.event for entry in ledger.ledger]
    assert [e.get("most_severe") for e in events[-2:]] == [2, 1]
    assert sum(e["event_type"] == "edge.incident.truncated" for e in events) == 1
    ledger.ledger.verify()


def test_full_evidence_skips_ordinary_updates_and_flag_is_sticky(tmp_path, monkeypatch):
    original = daemon.EvidenceStore.append
    def full_at(self, item):
        if item.received_at in (60, 61, 62):
            raise daemon.SegmentFull("evidence_segment_full")
        return original(self, item)
    monkeypatch.setattr(daemon.EvidenceStore, "append", full_at)
    server = daemon.IntakeServer(path=tmp_path / "unused.sock", state=tmp_path,
                                 status_path=tmp_path / "status.json", edge_uid=123,
                                 clock=lambda: 100)
    # opened (stored), ordinary refresh, ordinary escalation, severe
    # escalation (all three unstored), then a stored escalation.
    for now, severity in ((0, 5), (60, 5), (61, 4), (62, 2), (63, 1)):
        server.pending.put(record(now, severity=severity))
    server.finished.set()
    server._writer()
    assert (server.processed, server.accepted) == (5, 2)
    assert server.last_processed_at == 63 and server.last_accepted_at == 63
    assert server.refused["evidence_segment_full"] == 3
    events = [entry.event for entry in AuditLedger(next((tmp_path / "incidents").glob("*.jsonl")))]
    kinds = [(e["event_type"].removeprefix("edge.incident."), e.get("most_severe"),
              e.get("evidence_stored")) for e in events[1:]]
    assert kinds == [("opened", 5, None), ("updated", 2, False), ("updated", 1, False),
                     ("closed", 1, False)]
    assert events[-1]["count"] == 5
    status = read_intake_status(server.status_path.read_bytes())
    assert (status["processed"], status["accepted"], status["last_processed_at"]) == (5, 2, 63)


def test_status_reader_checks_processed_fields(tmp_path):
    server = daemon.IntakeServer(path=tmp_path / "unused.sock", state=tmp_path,
                                 status_path=tmp_path / "status.json", edge_uid=123)
    value = server.snapshot()
    assert read_intake_status(daemon.canonical(value)) is not None
    for mutation in ({"processed": -1}, {"processed": True}, {"last_processed_at": "now"},
                     {"accepted": 1}):
        assert read_intake_status(daemon.canonical({**value, **mutation})) is None
    for key in ("processed", "last_processed_at"):
        assert read_intake_status(daemon.canonical(
            {k: v for k, v in value.items() if k != key})) is None


def test_incident_reserve_is_not_spent_on_severe_refreshes(tmp_path):
    ledger = daemon.IncidentLedger(tmp_path, 0, segment_bytes=64 * 1024,
                                   severe_reserve=16 * 1024)
    def event(kind, severity, n):
        return {"event_type": "edge.incident." + kind, "incident_id": f"inc-{n:016x}",
                "most_severe": severity, "padding": "x" * 200}
    ledger.append(event("opened", 2, 1), 0)
    n = 1
    while True:
        n += 1
        try:
            ledger.append(event("opened", 3, n), 0)
        except daemon.SegmentFull:
            break
    full = ledger.current.stat().st_size
    # Routine refreshes of an open severe incident use the ordinary space.
    for _ in range(200):
        with pytest.raises(daemon.SegmentFull):
            ledger.append(event("updated", 2, 1), 0)
    assert ledger.current.stat().st_size - full < 1024
    ledger.append(event("updated", 1, 1), 0)
    with pytest.raises(daemon.SegmentFull):
        ledger.append(event("updated", 1, 1), 0)
    ledger.append(event("opened", 1, 10**6), 0)
    # An ordinary incident becoming severe is a fall in recorded severity.
    ledger.append(event("updated", 2, 5), 0)
    ledger.append(event("closed", 1, 1), 0)
    events = [entry.event for entry in ledger.ledger]
    assert [(e["event_type"], e.get("most_severe")) for e in events[-4:]] == [
        ("edge.incident.updated", 1), ("edge.incident.opened", 1),
        ("edge.incident.updated", 2), ("edge.incident.closed", 1)]
    ledger.ledger.verify()


def test_severe_flood_from_one_source_does_not_hide_another_source(tmp_path):
    server = daemon.IntakeServer(path=tmp_path / "unused.sock", state=tmp_path,
                                 status_path=tmp_path / "status.json", edge_uid=123,
                                 clock=lambda: 0)
    server.tracker.monotonic = lambda: 0
    value = edge_event()
    # The writer runs after queueing, so stay within the 256-record queue.
    for port in range(250):
        value["normalized"].update(target_port=port, severity=1)
        server.pending.put(daemon.EvidenceRecord.receive(
            daemon.parse_edge_event(daemon.canonical(value)), lambda: 0))
    value["normalized"].update(src_ip="10.0.0.99")
    server.pending.put(daemon.EvidenceRecord.receive(
        daemon.parse_edge_event(daemon.canonical(value)), lambda: 0))
    server.finished.set()
    server._writer()
    entries = [e.event for e in AuditLedger(next((tmp_path / "incidents").glob("*.jsonl")))]
    opened = [e["src_ip"] for e in entries if e["event_type"] == "edge.incident.opened"]
    assert opened == ["10.0.0.8"] * 5 + ["10.0.0.99"]
    assert server.refused["incident_rate_limited"] == 245


def test_restart_after_future_segment_keeps_history_and_reports_it(tmp_path):
    jan10 = daemon.datetime(2026, 1, 10, tzinfo=daemon.UTC).timestamp()
    jan20 = daemon.datetime(2026, 1, 20, tzinfo=daemon.UTC).timestamp()
    future = daemon.datetime(2027, 6, 1, tzinfo=daemon.UTC).timestamp()
    # As an earlier version did: a forward jump wrote a future segment, and
    # that run's own retention left the history alone.
    ledger = daemon.IncidentLedger(tmp_path, jan10, monotonic=elapsed(10**8), days=10**6)
    for now in (jan10, jan20, future):
        ledger.append({"at": now}, now)
    evidence = daemon.EvidenceStore(tmp_path, monotonic=elapsed(10**8), days=10**6)
    for now in (jan10, jan20, future):
        evidence.append(record(now))
    for store in (ledger, evidence):
        assert store.path_at(future).exists()
    # The clock is corrected: nothing within 14 days of today is aged out.
    server = daemon.IntakeServer(path=tmp_path / "unused.sock", state=tmp_path,
                                 status_path=tmp_path / "status.json", edge_uid=123,
                                 clock=lambda: jan20)
    server.pending.put(record(jan20))
    server.finished.set()
    server._writer()
    for store in (server.ledger, server.store):
        assert store.future_segment
        assert store.path_at(jan10).exists() and store.path_at(jan20).exists()
    # Evidence returns to today; the incident chain can only continue in
    # the latest segment, so it stays there and the status says why.
    assert len(server.store.path_at(jan20).read_text().splitlines()) == 2
    assert server.ledger.current == server.ledger.path_at(future)
    status = read_intake_status(server.status_path.read_bytes())
    assert status["refused"]["segment_from_future"] == 1
