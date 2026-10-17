import json
import socket
import struct
import threading

import pytest

from azazel_nexus.audit import AuditUnavailable
from azazel_nexus_runtime import bootstrap_audit_client as audit_client_module
from azazel_nexus_runtime.bootstrap_audit_client import BootstrapAuditClient
from azazel_nexus_runtime.transport import send_frame

DIGEST = "sha256:" + "12" * 32
HASH = "ab" * 32
HEADER = struct.Struct("!I")


def _read_request(connection):
    header = connection.recv(HEADER.size)
    (size,) = HEADER.unpack(header)
    chunks = bytearray()
    while len(chunks) < size:
        chunks.extend(connection.recv(size - len(chunks)))
    return bytes(chunks)


def test_client_sends_fixed_audit_append_and_accepts_chain_receipt():
    received = []
    client_socket, server_socket = socket.socketpair()

    def serve():
        try:
            received.append(json.loads(_read_request(server_socket)))
            assert server_socket.recv(1) == b""
            send_frame(server_socket, {
                "ok": True,
                "result": {"sequence": 7, "event_hash": HASH},
            })
        finally:
            server_socket.close()

    thread = threading.Thread(target=serve)
    thread.start()
    BootstrapAuditClient(socket_factory=lambda: client_socket)(
        {
            "event_type": "bootstrap.start_intent",
            "approval_digest": DIGEST,
            "generation": 3,
            "occurred_at": "2026-10-14T01:02:03Z",
            "unit_key": "auditd",
        }
    )
    thread.join(timeout=1)
    assert not thread.is_alive()
    assert received == [{
        "verb": "audit.bootstrap.append",
        "arguments": {"event_type": "bootstrap.start_intent"},
        "event": {
            "approval_digest": DIGEST,
            "generation": 3,
            "occurred_at": "2026-10-14T01:02:03Z",
            "unit_key": "auditd",
        },
    }]


def test_client_observes_root_only_verified_writer_head():
    received = []
    client_socket, server_socket = socket.socketpair()

    def serve():
        try:
            received.append(json.loads(_read_request(server_socket)))
            assert server_socket.recv(1) == b""
            send_frame(server_socket, {
                "ok": True,
                "result": {
                    "verified": True,
                    "head_sequence": 7,
                    "head_hash": HASH,
                },
            })
        finally:
            server_socket.close()

    thread = threading.Thread(target=serve)
    thread.start()
    assert BootstrapAuditClient(socket_factory=lambda: client_socket).observe_head() == (
        7, HASH
    )
    thread.join(timeout=1)
    assert not thread.is_alive()
    assert received == [{"verb": "audit.bootstrap.observe", "arguments": {}}]


@pytest.mark.parametrize(
    "event",
    [
        None,
        {"event_type": "made.up", "unit_key": "auditd"},
        {"event_type": "bootstrap.start_intent", "approval_digest": DIGEST},
        {
            "event_type": "bootstrap.start_intent",
            "approval_digest": DIGEST,
            "generation": 1,
            "occurred_at": "2026-10-14T01:02:03Z",
            "unit_key": "auditd",
            "raw_path": "/tmp/x",
        },
        {
            "event_type": "bootstrap.start_intent",
            "approval_digest": DIGEST,
            "generation": 1,
            "occurred_at": "2026-10-14T01:02:03Z",
            "unit_key": "sshd",
        },
    ],
)
def test_invalid_or_undeclared_event_refuses_before_socket(event):
    calls = []
    client = BootstrapAuditClient(socket_factory=lambda: calls.append(True))
    with pytest.raises(AuditUnavailable):
        client(event)
    assert calls == []


@pytest.mark.parametrize(
    "response",
    [
        {"ok": False, "refusal": "principal_denied"},
        {"ok": True, "result": {"sequence": 0, "event_hash": HASH}},
        {"ok": True, "result": {"sequence": 1, "event_hash": "bad"}},
        {"ok": True, "result": {"sequence": 1, "event_hash": HASH, "extra": 1}},
    ],
)
def test_refusal_or_malformed_chain_receipt_fails_closed(response):
    client_socket, server_socket = socket.socketpair()

    def serve():
        try:
            _read_request(server_socket)
            assert server_socket.recv(1) == b""
            send_frame(server_socket, response)
        finally:
            server_socket.close()

    thread = threading.Thread(target=serve)
    thread.start()
    event = {
        "event_type": "bootstrap.grant_intent",
        "approval_digest": DIGEST,
        "generation": 1,
        "occurred_at": "2026-10-14T01:02:03Z",
    }
    with pytest.raises(AuditUnavailable):
        BootstrapAuditClient(socket_factory=lambda: client_socket)(event)
    thread.join(timeout=1)
    assert not thread.is_alive()


@pytest.mark.parametrize("result", [
    {"verified": False, "head_sequence": 7, "head_hash": HASH},
    {"verified": True, "head_sequence": 0, "head_hash": HASH},
    {"verified": True, "head_sequence": True, "head_hash": HASH},
    {"verified": True, "head_sequence": 7, "head_hash": "bad"},
    {"verified": True, "head_sequence": 7, "head_hash": HASH, "extra": 1},
])
def test_client_rejects_unverified_or_malformed_head(result):
    client_socket, server_socket = socket.socketpair()

    def serve():
        try:
            _read_request(server_socket)
            assert server_socket.recv(1) == b""
            send_frame(server_socket, {"ok": True, "result": result})
        finally:
            server_socket.close()

    thread = threading.Thread(target=serve)
    thread.start()
    client = BootstrapAuditClient(socket_factory=lambda: client_socket)
    with pytest.raises(AuditUnavailable):
        client.observe_head()
    thread.join(timeout=1)
    assert not thread.is_alive()


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), -float("inf")])
def test_client_rejects_nonfinite_deadline(timeout):
    with pytest.raises(ValueError, match="deadline"):
        BootstrapAuditClient(timeout_seconds=timeout)


class DeadlineSocket:
    def __init__(self, clock, response=b"", *, drip=0.0):
        self.clock = clock
        self.response = bytearray(response)
        self.drip = drip
        self.timeouts = []
        self.events = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def settimeout(self, value):
        self.timeouts.append(value)
        self.events.append(("timeout", value))

    def sendall(self, _data):
        self.events.append(("sendall", None))

    def shutdown(self, _how):
        self.events.append(("shutdown", None))

    def recv(self, size):
        self.clock.now += self.drip
        self.events.append(("recv", size))
        if not self.response:
            return b""
        result = bytes(self.response[:min(size, 1)])
        del self.response[:len(result)]
        return result

    def close(self):
        self.closed = True


class FakeClock:
    def __init__(self):
        self.now = 100.0

    def monotonic(self):
        return self.now


def _append_event():
    return {
        "event_type": "bootstrap.grant_intent",
        "approval_digest": DIGEST,
        "generation": 1,
        "occurred_at": "2026-10-14T01:02:03Z",
    }


@pytest.mark.parametrize("operation", ["observe", "append"])
def test_slow_drip_consumes_one_exchange_budget_across_recv_calls(
    monkeypatch, operation,
):
    clock = FakeClock()
    monkeypatch.setattr(audit_client_module.time, "monotonic", clock.monotonic)
    frame = HEADER.pack(100) + b"x" * 100
    connection = DeadlineSocket(clock, frame, drip=0.3)
    client = BootstrapAuditClient(
        socket_factory=lambda: connection, timeout_seconds=1.0
    )

    with pytest.raises(AuditUnavailable):
        client.observe_head() if operation == "observe" else client(_append_event())

    assert sum(event[0] == "recv" for event in connection.events) < 5
    assert connection.closed
    assert connection.timeouts
    assert all(0 < timeout <= 1.0 for timeout in connection.timeouts)


def test_fixed_socket_connector_is_timed_before_connect_and_closed_on_failure(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(audit_client_module.time, "monotonic", clock.monotonic)
    events = []

    class ConnectSocket:
        def settimeout(self, value):
            events.append(("timeout", value))

        def connect(self, path):
            events.append(("connect", path))
            raise OSError("connect refused")

        def close(self):
            events.append(("close", None))

    monkeypatch.setattr(audit_client_module.socket, "socket", lambda *_args: ConnectSocket())
    from azazel_nexus_runtime import runtime_paths

    monkeypatch.setattr(runtime_paths, "socket_path", lambda _name: "/run/audit.sock")
    with pytest.raises(OSError, match="connect refused"):
        BootstrapAuditClient._connect(clock.monotonic() + 2.0)

    assert [event[0] for event in events] == ["timeout", "connect", "close"]
    assert 0 < events[0][1] <= 2.0
    assert events[1] == ("connect", "/run/audit.sock")


@pytest.mark.parametrize("operation", ["observe", "append"])
def test_late_socket_factory_result_is_closed_without_io(monkeypatch, operation):
    clock = FakeClock()
    monkeypatch.setattr(audit_client_module.time, "monotonic", clock.monotonic)
    connection = DeadlineSocket(clock)

    def late_factory():
        clock.now += 1.1
        return connection

    client = BootstrapAuditClient(socket_factory=late_factory, timeout_seconds=1.0)
    with pytest.raises(AuditUnavailable):
        client.observe_head() if operation == "observe" else client(_append_event())

    assert connection.closed
    assert not any(event[0] in {"sendall", "shutdown", "recv"}
                   for event in connection.events)


@pytest.mark.parametrize("operation", ["observe", "append"])
@pytest.mark.parametrize("stage", ["send", "eof", "decode"])
def test_exchange_budget_covers_send_eof_and_decode(monkeypatch, operation, stage):
    clock = FakeClock()
    monkeypatch.setattr(audit_client_module.time, "monotonic", clock.monotonic)
    result = ({"verified": True, "head_sequence": 7, "head_hash": HASH}
              if operation == "observe" else {"sequence": 7, "event_hash": HASH})
    raw = json.dumps({"ok": True, "result": result}).encode()

    class SlowStageSocket(DeadlineSocket):
        def sendall(self, data):
            super().sendall(data)
            if stage == "send":
                clock.now += 1.1

        def recv(self, size):
            if not self.response:
                if stage == "eof":
                    clock.now += 1.1
                return b""
            value = bytes(self.response[:size])
            del self.response[:len(value)]
            return value

    connection = SlowStageSocket(clock, HEADER.pack(len(raw)) + raw)
    if stage == "decode":
        original_loads = json.loads

        def slow_decode(*args, **kwargs):
            decoded = original_loads(*args, **kwargs)
            clock.now += 1.1
            return decoded

        monkeypatch.setattr(audit_client_module.json, "loads", slow_decode)
    client = BootstrapAuditClient(socket_factory=lambda: connection, timeout_seconds=1.0)
    with pytest.raises(AuditUnavailable):
        client.observe_head() if operation == "observe" else client(_append_event())
    assert connection.closed
    if stage == "send":
        assert not any(event[0] == "shutdown" for event in connection.events)
