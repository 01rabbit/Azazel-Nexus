"""Authenticated read-only commission inventory client over fake sockets."""

from contextlib import contextmanager
import json
import socket
import struct
import threading
import time

import pytest

from azazel_nexus.inventory import InterfaceReadout
from azazel_nexus_runtime import bootstrap_commission_client as client_module
from azazel_nexus_runtime.bootstrap_commission_client import BootstrapCommissionClient
from azazel_nexus_runtime.bootstrap_commission_peer import CommissionPeerBinding
from azazel_nexus_runtime.commissiond import Snapshot
from azazel_nexus_runtime.transport import MAX_FRAME_BYTES
from azazel_nexus_runtime.units import UnitOperationFailed
from test_runtime_bootstrap_commission_peer import IDENTITY


_HEADER = struct.Struct("!I")
_DIGEST = "sha256:" + "42" * 32
_REQUEST = {"verb": "commission.inventory", "arguments": {}}
_SOCKET_PATH = "/var/lib/azazel/run/commission/commission.sock"


class _ConnectedSocket:
    def __init__(self, connection):
        self.connection = connection
        self.connected_path = None

    def connect(self, path):
        self.connected_path = path

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.connection.close()


class _Proof:
    path = _SOCKET_PATH

    def __init__(self, *, fail_at=None):
        self.fail_at = fail_at
        self.checks = 0

    def check(self, _connection):
        self.checks += 1
        if self.checks == self.fail_at:
            raise UnitOperationFailed("synthetic peer proof changed")


def _producer_response():
    snapshot = Snapshot(
        readouts=(InterfaceReadout(
            "private-kernel-name", {"physical_label": "Port A", "bus_path": "pci:0"},
        ),),
        permanent_macs=(None,),
        digest=_DIGEST,
    )
    return {"ok": True, "result": {
        "snapshot": snapshot.digest,
        "interfaces": snapshot.describe(),
    }}


def _client_socketpair(monkeypatch, *, binding=IDENTITY, response=None,
                       raw_response=None, timeout=0.5, proof=None, pause=False):
    client_end, server_end = socket.socketpair()
    wrapped = _ConnectedSocket(client_end)
    monkeypatch.setattr(
        client_module.socket, "socket",
        lambda family, kind: (family == socket.AF_UNIX and kind == socket.SOCK_STREAM)
        and wrapped,
    )
    observed = []
    if proof is None:
        proof = _Proof()

    @contextmanager
    def fake_proof(_binding, _deadline):
        yield proof

    monkeypatch.setattr(CommissionPeerBinding, "proof", fake_proof)
    retained = CommissionPeerBinding(IDENTITY, lambda: IDENTITY)
    client = BootstrapCommissionClient(
        binding_source=lambda: retained if binding is IDENTITY else binding,
        timeout_seconds=timeout,
    )

    def serve():
        try:
            header = server_end.recv(_HEADER.size)
            if not header:
                return
            (size,) = _HEADER.unpack(header)
            body = bytearray()
            while len(body) < size:
                part = server_end.recv(size - len(body))
                if not part:
                    break
                body.extend(part)
            observed.append(json.loads(bytes(body)))
            assert server_end.recv(1) == b""
            if pause:
                time.sleep(timeout * 2)
                return
            if raw_response is not None:
                server_end.sendall(raw_response)
            else:
                payload = json.dumps(response, separators=(",", ":")).encode()
                server_end.sendall(_HEADER.pack(len(payload)) + payload)
        finally:
            server_end.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return client, thread, wrapped, observed, proof


def test_fixed_read_only_inventory_request_and_actual_producer_response(monkeypatch):
    client, thread, connection, observed, proof = _client_socketpair(
        monkeypatch, response=_producer_response(),
    )

    assert client.observe_inventory() == _DIGEST
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert observed == [_REQUEST]
    assert connection.connected_path == _SOCKET_PATH
    assert proof.checks == 2  # before request and after response


def test_wrong_binding_refuses_before_opening_socket(monkeypatch):
    opens = []
    monkeypatch.setattr(
        client_module.socket, "socket", lambda *_args: opens.append(True),
    )
    client = BootstrapCommissionClient(binding_source=lambda: object())

    with pytest.raises(UnitOperationFailed, match="inventory unavailable"):
        client.observe_inventory()

    assert opens == []


def test_failed_pre_send_peer_proof_sends_no_request(monkeypatch):
    client, thread, _connection, observed, proof = _client_socketpair(
        monkeypatch, response=_producer_response(), proof=_Proof(fail_at=1),
    )

    with pytest.raises(UnitOperationFailed, match="inventory unavailable"):
        client.observe_inventory()
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert observed == []
    assert proof.checks == 1


def test_late_peer_failure_rejects_reply_after_request_was_sent(monkeypatch):
    client, thread, _connection, observed, proof = _client_socketpair(
        monkeypatch, response=_producer_response(), proof=_Proof(fail_at=2),
    )

    with pytest.raises(UnitOperationFailed, match="inventory unavailable"):
        client.observe_inventory()
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert observed == [_REQUEST]
    assert proof.checks == 2


@pytest.mark.parametrize("response", [
    {"ok": False, "refusal": "principal_denied"},
    {"ok": True, "result": {"snapshot": _DIGEST, "interfaces": [], "extra": 1}},
])
def test_refusal_or_invalid_inventory_response_is_rejected(monkeypatch, response):
    client, thread, _connection, _observed, _proof = _client_socketpair(
        monkeypatch, response=response,
    )

    with pytest.raises(UnitOperationFailed, match="inventory unavailable"):
        client.observe_inventory()
    thread.join(timeout=1)
    assert not thread.is_alive()


@pytest.mark.parametrize("payload", [
    b'{"ok":true,"ok":true,"result":{"snapshot":"' + _DIGEST.encode()
    + b'","interfaces":[]}}',
    b"{not-json}",
])
def test_duplicate_fields_and_malformed_json_are_rejected(monkeypatch, payload):
    client, thread, _connection, _observed, _proof = _client_socketpair(
        monkeypatch, raw_response=_HEADER.pack(len(payload)) + payload,
    )

    with pytest.raises(UnitOperationFailed, match="inventory unavailable"):
        client.observe_inventory()
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_trailing_bytes_are_rejected(monkeypatch):
    payload = json.dumps(_producer_response(), separators=(",", ":")).encode()
    client, thread, _connection, _observed, _proof = _client_socketpair(
        monkeypatch, raw_response=_HEADER.pack(len(payload)) + payload + b"x",
    )

    with pytest.raises(UnitOperationFailed, match="inventory unavailable"):
        client.observe_inventory()
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_oversized_frame_header_is_rejected_without_body(monkeypatch):
    client, thread, _connection, _observed, _proof = _client_socketpair(
        monkeypatch, raw_response=_HEADER.pack(MAX_FRAME_BYTES + 1),
    )

    with pytest.raises(UnitOperationFailed, match="inventory unavailable"):
        client.observe_inventory()
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_socket_deadline_bounds_response_wait(monkeypatch):
    client, thread, _connection, observed, _proof = _client_socketpair(
        monkeypatch, response=_producer_response(), timeout=0.05, pause=True,
    )

    with pytest.raises(UnitOperationFailed, match="inventory unavailable"):
        client.observe_inventory()
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert observed == [_REQUEST]
