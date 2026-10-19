"""Bounded AF_UNIX probes and local advisory payload exchange.

These probes confer no admission. Fixed uncommissioned identifiers cannot
activate a commissioned model or supply a remote envelope. Reply text is never
copied to the route ledger. Framing follows the existing bootstrap clients;
server ownership and kernel credentials follow repin_confirmation._exchange.
"""

from __future__ import annotations

import grp
import hashlib
import json
import pwd
import socket
import time

from azazel_nexus.advisory_response import AdvisoryRefused
from azazel_nexus.audit import AuditUnavailable
from azazel_nexus.local_advisory import read_delivered, read_reference

from .bootstrap_audit_client import _pairs, _read_exact, _set_remaining_timeout
from .principal import SocketMisconfigured, peer_credentials, verify_socket
from .runtime_paths import socket_path
from .transport import _HEADER, MAX_FRAME_BYTES


def _exchange(
    leaf: str, account: str, verb: str, arguments: dict, *,
    payload: dict | None = None, deadline_s: float = 0.5,
) -> dict:
    if type(deadline_s) not in {int, float} or not 0 < deadline_s <= 60:
        raise ValueError("M.I.O. deadline refused")
    deadline = time.monotonic() + deadline_s
    path = socket_path(leaf)
    uid = pwd.getpwnam(account).pw_uid
    gid = grp.getgrnam("azknowledge-read" if leaf == "knowledge-read" else "azazel-operator").gr_gid
    verify_socket(path, expected_uid=uid, expected_gid=gid)
    document = {"verb": verb, "arguments": arguments}
    if payload is not None:
        document["event"] = payload
    raw = json.dumps(document).encode()
    if len(raw) > MAX_FRAME_BYTES:
        raise ValueError("M.I.O. request bound refused")
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


def _reply_metadata(reply: dict) -> dict:
    validated = read_delivered(reply)
    return {k: v for k, v in validated.items() if k not in {"advice", "fields"}}


class LocalSocketClient:
    def observe(self) -> str:
        return _probe("mio")

    def reference(self, frame: dict, *, deadline_ms: int) -> dict | None:
        began = time.monotonic()
        try:
            reply = _exchange(
                "mio", "azmio", "mio.local.reference", {"deadline_ms": deadline_ms},
                payload=frame, deadline_s=deadline_ms / 1000,
            )
            if set(reply) != {"outcome", "reference"} or reply["outcome"] != "reference":
                return None
            document = read_reference(reply["reference"])
            if time.monotonic() - began >= deadline_ms / 1000:
                return None
            return document
        except Exception:  # noqa: BLE001 - optional reference; any reply defect means none
            return None

    def handle(self, request, *, audit=None) -> dict:
        if getattr(getattr(request, "verb", None), "name", None) != "mio.local.infer":
            return {"readiness": "refused", "reason": self.observe()}
        try:
            reply = _exchange(
                "mio", "azmio", "mio.local.infer", request.arguments,
                payload=request.payload, deadline_s=request.arguments["deadline_ms"] / 1000,
            )
            if reply.get("outcome") == "advisory":
                body = read_delivered(reply)
                if audit is not None:
                    audit({"event_type": "mio.local.advisory.read",
                           "digest": "sha256:" + hashlib.sha256(json.dumps(body).encode()).hexdigest(),
                           "text_characters": len(body["advice"]), "field_count": len(body["fields"])})
                return {**body, "outcome": "advisory", "refusal": None}
            if reply.get("outcome") == "not_advice":
                return {"outcome": "not_advice", "refusal": "not_advice"}
            if reply.get("outcome") == "timed_out":
                return {"outcome": "timed_out", "refusal": "deadline"}
            return {"outcome": "failed", "refusal": "local_refused"}
        except AdvisoryRefused:
            return {"outcome": "not_advice", "refusal": "not_advice"}
        except TimeoutError:
            return {"outcome": "timed_out", "refusal": "deadline"}
        except (OSError, KeyError, ValueError, SocketMisconfigured):
            return {"outcome": "failed", "refusal": "local_unavailable"}


class RemoteSocketClient:
    def observe(self) -> str:
        return _probe("remote")

    def handle(self, request, *, audit=None) -> dict:
        return {"outcome": "unavailable", "refusal": self.observe()}
