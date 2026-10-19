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
    ledger = AuditLedger(server.state / "incidents.jsonl")
    ledger.verify()
    assert [entry.event["event_type"] for entry in ledger] == ["edge.incident.opened"]
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
    assert not (server.state / "incidents.jsonl").exists()


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
    assert list(store.directory.iterdir()) == []
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
    ledger = AuditLedger(tmp_path / "incidents.jsonl")
    ledger.verify()
    assert [entry.event["event_type"] for entry in ledger] == [
        "edge.incident.opened",
        "edge.incident.updated",
        "edge.incident.closed",
        "edge.incident.opened",
    ]
    server._status()
    assert read_intake_status(server.status_path.read_bytes())["accepted"] == 4


def test_broken_chain_refuses_new_records_without_content(tmp_path):
    (tmp_path / "incidents.jsonl").write_text("SECRET")
    server = daemon.IntakeServer(
        path=tmp_path / "unused.sock",
        state=tmp_path,
        status_path=tmp_path / "status.json",
        edge_uid=123,
        clock=lambda: 100,
    )
    server.pending.put(record(100))
    server.finished.set()
    server._writer()
    assert server.accepted == 0
    assert server.storage_failed
    assert "SECRET" not in server.status_path.read_text()
    assert list((tmp_path / "evidence").glob("*.jsonl")) == []
