"""#196: the Deception Lite decoy's body (`az-decoyd`), §12.

`docs/deception-redirect-prerequisites.md` §5 D1, §8, §11 and §12. The decoy
refuses outside the decoy network namespace, listens on fixed ports, answers
with the loopback runtime's constant banners, counts (never keeps) at most
4096 bytes for at most a few seconds, and reports each served connection as
P2's closed event, one line to the intake's decoy socket. It holds bounds on
concurrency, rate and time, drops what the intake does not take, and never
writes, sends or logs a peer address.

These tests listen on loopback (`decoy_listener._BIND_ADDRESS` moved
in-process) and use a temporary Unix socket for the intake. The namespace
check is moved to temporary files. None of this is VM or hardware evidence.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest
from test_decoy_interaction_p2 import running, wait_for  # noqa: F401 - fixture

from azazel_nexus.decoy import MAX_DECOYS, DecoyRefused
from azazel_nexus.decoy_interaction import (
    DECOY_NAMES,
    MAX_BYTES_RECEIVED,
    RESPONDER_NAMES,
    build_interaction,
    parse_interaction,
)
from azazel_nexus_runtime import decoy_listener, decoy_netns, decoy_sender, decoyd
from azazel_nexus_runtime import edge_intaked
from azazel_nexus_runtime.decoy_loopback import MAX_READ_BYTES, RESPONDERS

LOOPBACK = "127.0.0.1"


# -- fixed values ------------------------------------------------------------


def test_the_served_decoys_are_fixed_closed_and_within_the_ceiling():
    names = [d.name for d in decoyd.SERVED]
    ports = [d.port for d in decoyd.SERVED]
    assert 0 < len(decoyd.SERVED) <= MAX_DECOYS
    assert set(names) <= DECOY_NAMES and len(set(names)) == len(names)
    assert {d.responder for d in decoyd.SERVED} <= set(RESPONDERS) == RESPONDER_NAMES
    assert all(1024 <= port <= 65535 for port in ports) and len(set(ports)) == len(ports)
    assert decoyd.ACCEPTS_PER_MINUTE == edge_intaked.DECOY_PER_MINUTE
    assert MAX_READ_BYTES == MAX_BYTES_RECEIVED == 4096
    assert 0 < decoyd.CONNECTION_SECONDS <= 5
    assert decoyd.MAX_CONCURRENT <= 8


def test_the_namespace_path_is_the_units():
    from azazel_nexus_runtime.hardening import DECOY_NAMESPACE_PATH

    assert decoy_netns.DECOY_NAMESPACE_PATH == DECOY_NAMESPACE_PATH
    assert decoy_netns._EXPECTED == DECOY_NAMESPACE_PATH
    assert decoy_netns._OWN == "/proc/self/ns/net"
    assert decoy_netns._INIT == "/proc/1/ns/net"
    assert decoy_listener._BIND_ADDRESS == decoy_listener.NAMESPACE_BIND_ADDRESS == "0.0.0.0"
    assert decoy_sender._PATH == decoy_sender.DECOY_INTAKE_SOCKET


# -- the namespace check -----------------------------------------------------


@pytest.fixture
def namespace_files(tmp_path, monkeypatch):
    """Two distinct inodes standing in for the decoy's and the host's namespace."""

    decoy, host = tmp_path / "decoy-ns", tmp_path / "host-ns"
    decoy.write_bytes(b"")
    host.write_bytes(b"")
    monkeypatch.setattr(decoy_netns, "_OWN", str(decoy))
    monkeypatch.setattr(decoy_netns, "_EXPECTED", str(decoy))
    monkeypatch.setattr(decoy_netns, "_INIT", str(host))
    return decoy, host


def test_inside_the_decoy_namespace_the_check_passes(namespace_files):
    decoy, _ = namespace_files
    found = decoy_netns.confirm_decoy_namespace()
    assert (found.device, found.inode) == (decoy.stat().st_dev, decoy.stat().st_ino)
    assert found.still_current()


def test_an_unreadable_host_namespace_leaves_the_positive_match_alone(
        namespace_files, monkeypatch, tmp_path):
    monkeypatch.setattr(decoy_netns, "_INIT", str(tmp_path / "unreadable"))
    assert decoy_netns.confirm_decoy_namespace().still_current()


@pytest.mark.parametrize("case,match", [
    ("own-elsewhere", "not in the decoy namespace"),
    ("no-decoy-namespace", "does not exist"),
    ("own-unreadable", "cannot be read"),
    ("host-namespace", "host's network namespace"),
])
def test_outside_the_decoy_namespace_the_check_refuses(
        namespace_files, monkeypatch, tmp_path, case, match):
    decoy, host = namespace_files
    if case == "own-elsewhere":
        monkeypatch.setattr(decoy_netns, "_OWN", str(host))
    elif case == "no-decoy-namespace":
        monkeypatch.setattr(decoy_netns, "_EXPECTED", str(tmp_path / "absent"))
    elif case == "own-unreadable":
        monkeypatch.setattr(decoy_netns, "_OWN", str(tmp_path / "absent"))
    else:
        monkeypatch.setattr(decoy_netns, "_INIT", str(decoy))
    with pytest.raises(decoy_netns.NotInDecoyNamespace, match=match):
        decoy_netns.confirm_decoy_namespace()


@pytest.mark.skipif(not Path("/proc/self/ns/net").exists(), reason="Linux /proc only")
def test_on_linux_the_hosts_own_namespace_is_refused(monkeypatch):
    """The real nsfs files: a namespace equal to PID 1's is the host's."""

    try:
        os.stat("/proc/1/ns/net")
    except OSError:
        pytest.skip("PID 1's namespace is not readable here")
    if os.stat("/proc/1/ns/net").st_ino != os.stat("/proc/self/ns/net").st_ino:
        pytest.skip("this test process is not in PID 1's namespace")
    monkeypatch.setattr(decoy_netns, "_EXPECTED", "/proc/self/ns/net")
    with pytest.raises(decoy_netns.NotInDecoyNamespace, match="host's"):
        decoy_netns.confirm_decoy_namespace()


def test_a_namespace_that_changed_since_the_check_is_no_longer_current(
        namespace_files, monkeypatch):
    _, host = namespace_files
    found = decoy_netns.confirm_decoy_namespace()
    monkeypatch.setattr(decoy_netns, "_OWN", str(host))
    assert not found.still_current()


# -- the listener in the namespace -------------------------------------------


@pytest.fixture
def no_socket(monkeypatch):
    made = []

    def refuse(*args):
        made.append(args)
        raise AssertionError("a socket was made")

    monkeypatch.setattr(decoy_listener, "_SOCKET", refuse)
    return made


@pytest.mark.parametrize("token", ["forged", "stale", "tuple"])
def test_the_namespace_listener_needs_a_current_namespace_before_a_socket(
        namespace_files, no_socket, token):
    found = decoy_netns.confirm_decoy_namespace()
    value = {"forged": decoy_netns.DecoyNamespace(found.device, found.inode + 1),
             "stale": decoy_netns.DecoyNamespace(0, 0),
             "tuple": (found.device, found.inode)}[token]
    with pytest.raises(DecoyRefused, match="only inside the decoy namespace"):
        decoy_listener.open_namespace_listener(value, 2222)
    assert no_socket == []


@pytest.mark.parametrize("port", [22, 1023, 65536, "2222", True, 2222.0])
def test_the_namespace_listener_refuses_a_port_outside_the_range(
        namespace_files, no_socket, port):
    with pytest.raises(DecoyRefused):
        decoy_listener.open_namespace_listener(decoy_netns.confirm_decoy_namespace(), port)
    assert no_socket == []


# -- serving -----------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((LOOPBACK, 0))
        return probe.getsockname()[1]


class FakeIntake:
    """A Unix socket that collects one line per connection, as the intake does."""

    def __init__(self, path: Path):
        self.path, self.lines = path, []
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(path))
        self.server.listen(16)
        self.server.settimeout(0.1)
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                connection, _ = self.server.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(2)
                data = b""
                while not data.endswith(b"\n"):
                    chunk = connection.recv(2048)
                    if not chunk:
                        break
                    data += chunk
                self.lines.append(data)

    def close(self):
        self._stop.set()
        self.thread.join(2)
        self.server.close()


@pytest.fixture
def short_dir():
    # A short path: AF_UNIX paths are limited to about 104 bytes on macOS.
    with tempfile.TemporaryDirectory(prefix="decoy-", dir="/tmp") as directory:
        yield Path(directory)


@pytest.fixture
def intake(short_dir, monkeypatch):
    fake = FakeIntake(short_dir / "decoy-intake.sock")
    monkeypatch.setattr(decoy_sender, "_PATH", str(fake.path))
    yield fake
    fake.close()


@pytest.fixture
def decoy(namespace_files, monkeypatch):
    """Start a DecoyServer on loopback; yields (server, {name: port})."""

    monkeypatch.setattr(decoy_listener, "_BIND_ADDRESS", LOOPBACK)
    started = []

    def start(**limits):
        namespace = decoy_netns.confirm_decoy_namespace()
        listeners, ports = [], {}
        for served in decoyd.SERVED:
            port = _free_port()
            entry = decoyd.ServedDecoy(served.name, served.responder, port)
            listeners.append((entry, decoy_listener.open_namespace_listener(namespace, port)))
            ports[served.name] = port
        server = decoyd.DecoyServer(listeners, **limits)
        stop, ready, errors = threading.Event(), threading.Event(), []

        def run():
            try:
                server.serve(stop.is_set, ready.set)
            except BaseException as exc:  # noqa: BLE001 - relay to pytest
                errors.append(exc)
                ready.set()

        thread = threading.Thread(target=run)
        thread.start()
        assert ready.wait(3)
        started.append((stop, thread, errors))
        return server, ports

    yield start
    for stop, thread, errors in started:
        stop.set()
        thread.join(4)
        assert not thread.is_alive() and not errors


def _visit(port, payload=b"", *, read_banner=True, close=True):
    client = socket.create_connection((LOOPBACK, port), timeout=3)
    banner = b""
    if read_banner:
        while True:
            chunk = client.recv(256)
            banner += chunk
            if not chunk or any(banner == value for value in RESPONDERS.values()):
                break
    if payload:
        client.sendall(payload)
    if close:
        client.shutdown(socket.SHUT_WR)
        client.settimeout(3)
        assert client.recv(16) == b""
        client.close()
    return banner, client


def _events(intake):
    return [parse_interaction(line.rstrip(b"\n"), now=time.time()).as_dict()
            for line in intake.lines]


@pytest.mark.parametrize("served", decoyd.SERVED, ids=lambda d: d.name)
def test_each_decoy_answers_with_its_banner_and_reports_one_closed_event(
        decoy, intake, served):
    server, ports = decoy()
    banner, _ = _visit(ports[served.name], b"probe\r\n")
    assert banner == RESPONDERS[served.responder]
    wait_for(lambda: len(intake.lines) == 1)
    (event,) = _events(intake)
    assert event["environment_id"] == served.name
    assert event["metadata"] == {"bytes_received": 7, "truncated": False,
                                 "responder": served.responder}
    assert server.counts["served"] == server.counts["sent"] == 1


def test_what_was_sent_is_counted_and_never_kept_or_forwarded(decoy, intake, capsys):
    server, ports = decoy()
    secret = b"user=root password=CorrectHorseBatteryStaple\r\n"
    _visit(ports["ssh-decoy"], secret)
    wait_for(lambda: len(intake.lines) == 1)
    (line,) = intake.lines
    assert b"CorrectHorse" not in line and b"password" not in line
    assert bytes(server._scratch) == bytes(len(server._scratch))
    assert "CorrectHorse" not in repr(vars(server))
    assert "CorrectHorse" not in capsys.readouterr().err


def test_no_peer_address_is_sent_or_kept(decoy, intake):
    server, ports = decoy()
    _, client = _visit(ports["http-decoy"], b"GET / HTTP/1.0\r\n\r\n", close=False)
    source_port = client.getsockname()[1]
    client.shutdown(socket.SHUT_WR)
    client.recv(16)
    client.close()
    wait_for(lambda: len(intake.lines) == 1)
    (line,) = intake.lines
    assert LOOPBACK.encode() not in line and b"127" not in line
    assert str(source_port).encode() not in line
    assert set(json.loads(line)) == {
        "schema_version", "event_id", "environment_id", "package_id", "node_id",
        "event_type", "observed_at", "evidence_refs", "metadata"}
    # The listeners' own (bound) address is in the server; the peer's is not.
    held = repr(vars(server))
    assert str(source_port) not in held and server._connections == {}


def test_reading_stops_at_the_ceiling_and_is_reported_truncated(decoy, intake):
    _, ports = decoy()
    _visit(ports["telnet-decoy"], b"x" * (MAX_READ_BYTES * 3), close=False)
    wait_for(lambda: len(intake.lines) == 1)
    (event,) = _events(intake)
    assert event["metadata"]["bytes_received"] == MAX_READ_BYTES
    assert event["metadata"]["truncated"] is True


def test_a_silent_peer_is_closed_at_the_deadline_and_still_reported(decoy, intake):
    server, ports = decoy(seconds=0.3)
    started = time.monotonic()
    banner, client = _visit(ports["ssh-decoy"], close=False)
    assert banner == RESPONDERS["ssh-banner"]
    client.settimeout(3)
    assert client.recv(16) == b""  # the decoy closed it
    assert time.monotonic() - started < 2.5
    client.close()
    wait_for(lambda: len(intake.lines) == 1)
    (event,) = _events(intake)
    assert event["metadata"]["bytes_received"] == 0


def test_concurrent_connections_over_the_bound_are_closed_unanswered(decoy, intake):
    server, ports = decoy(max_concurrent=2)
    held = [_visit(ports["ssh-decoy"], close=False)[1] for _ in range(2)]
    banner, extra = _visit(ports["http-decoy"], read_banner=True, close=False)
    assert banner == b""  # closed before any banner
    extra.close()
    wait_for(lambda: server.counts["dropped_busy"] == 1)
    for client in held:
        client.close()
    wait_for(lambda: len(intake.lines) == 2)
    assert server.counts["served"] == 2


def test_connections_over_the_rate_are_closed_unanswered(decoy, intake):
    server, ports = decoy(per_minute=2)
    assert _visit(ports["ssh-decoy"], b"a")[0] == RESPONDERS["ssh-banner"]
    assert _visit(ports["ssh-decoy"], b"b")[0] == RESPONDERS["ssh-banner"]
    assert _visit(ports["ssh-decoy"])[0] == b""
    wait_for(lambda: server.counts["dropped_rate"] == 1)
    wait_for(lambda: len(intake.lines) == 2)
    assert server.counts["served"] == 2


def test_without_an_intake_the_decoy_keeps_serving_and_only_counts(
        decoy, short_dir, monkeypatch):
    monkeypatch.setattr(decoy_sender, "_PATH", str(short_dir / "absent.sock"))
    server, ports = decoy()
    for _ in range(3):
        assert _visit(ports["ssh-decoy"], b"x")[0] == RESPONDERS["ssh-banner"]
    wait_for(lambda: server.counts["send_failed"] == 3)
    assert server.counts["sent"] == 0 and server.counts["served"] == 3


def test_an_intake_that_does_not_read_does_not_stop_the_decoy(decoy, short_dir, monkeypatch):
    """A full intake: connect blocks or fails within the send deadline."""

    path = short_dir / "stuck.sock"
    stuck = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stuck.bind(str(path))
    stuck.listen(0)  # never accepts
    monkeypatch.setattr(decoy_sender, "_PATH", str(path))
    try:
        server, ports = decoy()
        for _ in range(4):
            assert _visit(ports["http-decoy"], b"x")[0] == RESPONDERS["http-banner"]
        wait_for(lambda: server.counts["served"] == 4, timeout=6)
    finally:
        stuck.close()


def test_with_the_real_intake_the_interaction_is_stored_as_the_decoys(
        decoy, running, monkeypatch):  # noqa: F811 - fixture
    intake_server = running()
    monkeypatch.setattr(decoy_sender, "_PATH", str(intake_server.decoy_path))
    server, ports = decoy()
    _visit(ports["ssh-decoy"], b"SSH-2.0-probe\r\n")
    wait_for(lambda: intake_server.decoy_accepted == 1)
    (path,) = (intake_server.state / "decoy-evidence").glob("*.jsonl")
    record = json.loads(path.read_text())
    assert record["edge_observation"] is False
    assert record["environment_event"]["environment_id"] == "ssh-decoy"
    assert record["environment_event"]["metadata"]["bytes_received"] == 15
    assert not any(intake_server.refused.values())


# -- the sender --------------------------------------------------------------


def test_the_sender_sends_only_a_closed_interaction(intake):
    good = build_interaction(decoy_name="ssh-decoy", observed_at="2026-10-21T00:00:00Z",
                             bytes_received=1, truncated=False, responder="ssh-banner")
    assert decoy_sender.send_interaction(good) is True
    from azazel_nexus.decoy_interaction import DecoyInteraction

    assert decoy_sender.send_interaction(DecoyInteraction(b'{"peer":"192.0.2.1"}')) is False
    assert decoy_sender.send_interaction(good.line) is False
    wait_for(lambda: len(intake.lines) == 1)
    assert intake.lines == [good.line]


# -- the executable ----------------------------------------------------------


def test_the_executable_takes_no_argument(capsys):
    assert decoyd.main(["--namespace", "/run/netns/other"]) == 2
    assert "takes no argument" in capsys.readouterr().err


def test_on_this_host_the_executable_refuses_before_any_socket(no_socket, capsys):
    """No decoy namespace here (or not inside it): exit 1, nothing bound."""

    if Path(decoy_netns.DECOY_NAMESPACE_PATH).exists():
        pytest.skip("a decoy namespace exists on this host")
    assert decoyd.main([]) == 1
    assert "refusing to listen" in capsys.readouterr().err
    assert no_socket == []


def test_the_executable_serves_until_sigterm_and_logs_no_address(
        namespace_files, intake, monkeypatch, capsys):
    monkeypatch.setattr(decoy_listener, "_BIND_ADDRESS", LOOPBACK)
    served = tuple(decoyd.ServedDecoy(d.name, d.responder, _free_port())
                   for d in decoyd.SERVED)
    monkeypatch.setattr(decoyd, "SERVED", served)
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}

    def visit_then_stop():
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                _visit(served[0].port, b"hello")
                break
            except OSError:
                time.sleep(0.05)
        wait_for(lambda: len(intake.lines) == 1)
        os.kill(os.getpid(), signal.SIGTERM)

    visitor = threading.Thread(target=visit_then_stop)
    visitor.start()
    try:
        assert decoyd.main([]) == 0
    finally:
        visitor.join(5)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    err = capsys.readouterr().err
    assert f"{served[0].port} (ssh-decoy)" in err and "served 1" in err and "sent 1" in err
    assert LOOPBACK not in err and "0.0.0.0" not in err
