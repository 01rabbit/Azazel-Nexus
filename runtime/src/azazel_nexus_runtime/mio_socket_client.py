"""Bounded, metadata-only AF_UNIX probes for the two M.I.O. services.

These probes confer no admission. Fixed uncommissioned identifiers cannot
activate a commissioned model or supply a remote envelope. Reply text is never
copied to the route ledger. Framing follows the existing bootstrap clients;
server ownership and kernel credentials follow repin_confirmation._exchange.
"""

from __future__ import annotations

import grp
import json
import pwd
import socket
import time

from azazel_nexus.audit import AuditUnavailable

from .bootstrap_audit_client import _pairs, _read_exact, _set_remaining_timeout
from .principal import SocketMisconfigured, peer_credentials, verify_socket
from .runtime_paths import socket_path
from .transport import _HEADER, MAX_FRAME_BYTES


def _exchange(leaf: str, account: str, verb: str, arguments: dict) -> dict:
    path = socket_path(leaf)
    uid = pwd.getpwnam(account).pw_uid
    gid = grp.getgrnam("azazel-operator").gr_gid
    verify_socket(path, expected_uid=uid, expected_gid=gid)
    deadline = time.monotonic() + 0.5
    raw = json.dumps({"verb": verb, "arguments": arguments}).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        _set_remaining_timeout(connection, deadline)
        connection.connect(str(path))
        pid, peer_uid, _ = peer_credentials(connection)
        if peer_uid != uid or pid <= 0:
            raise ValueError("M.I.O. peer refused")
        _set_remaining_timeout(connection, deadline)
        connection.sendall(_HEADER.pack(len(raw)) + raw)
        connection.shutdown(socket.SHUT_WR)
        (size,) = _HEADER.unpack(_read_exact(connection, _HEADER.size, deadline))
        if not 0 < size <= MAX_FRAME_BYTES:
            raise ValueError("M.I.O. response bound refused")
        response = json.loads(
            _read_exact(connection, size, deadline).decode(), object_pairs_hook=_pairs
        )
        _set_remaining_timeout(connection, deadline)
        if connection.recv(1):
            raise ValueError("M.I.O. trailing response refused")
    if (type(response) is not dict or set(response) != {"ok", "result"}
            or response["ok"] is not True or type(response["result"]) is not dict):
        raise ValueError("M.I.O. service refused")
    return response["result"]


def _probe(leaf: str) -> str:
    try:
        if leaf == "mio":
            reply = _exchange("mio", "azmio", "model.activate", {
                "model_id": "uncommissioned", "runtime_id": "uncommissioned",
            })
            if reply.get("readiness") == "refused":
                return "local_not_admitted"
            return "local_no_admission_evidence"
        reply = _exchange("remote", "azremote", "remote.infer", {
            "provider_id": "uncommissioned", "request_id": "route-probe",
        })
        if reply.get("outcome") == "not_sent":
            return "remote_not_admitted"
        return "remote_no_admission_evidence"
    except (OSError, KeyError, ValueError, AuditUnavailable, SocketMisconfigured):
        # Includes absent accounts/socket, refused connection, malformed frame,
        # deadline and explicit protocol refusal. Never report exception text.
        return "local_unavailable" if leaf == "mio" else "remote_unavailable"


class LocalSocketClient:
    def observe(self) -> str:
        return _probe("mio")

    def handle(self, request) -> dict:
        return {"readiness": "refused", "reason": self.observe()}


class RemoteSocketClient:
    def observe(self) -> str:
        return _probe("remote")

    def handle(self, request, *, audit=None) -> dict:
        return {"outcome": "unavailable", "refusal": self.observe()}
