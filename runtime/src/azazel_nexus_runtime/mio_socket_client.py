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

from azazel_nexus import model_admission
from azazel_nexus.advisory_response import AdvisoryRefused
from azazel_nexus.audit import AuditUnavailable
from azazel_nexus.local_advisory import read_delivered, read_reference

from .bootstrap_audit_client import _pairs, _read_exact, _set_remaining_timeout
from .principal import SocketMisconfigured, peer_credentials, verify_socket
from .runtime_paths import socket_group, socket_path
from .protocol import Refusal
from .transport import _HEADER, MAX_FRAME_BYTES

_REFUSALS = frozenset(r.value for r in Refusal)


class ServiceRefused(ValueError):
    """The peer answered with a declared refusal reason; text stays fixed.

    A ValueError so existing callers keep treating it as any refusal; the
    reason lets a forwarder tell a verdict from a failed delivery.
    """

    def __init__(self, refusal: str) -> None:
        super().__init__("M.I.O. service refused")
        self.refusal = refusal


def _exchange(
    leaf: str, account: str, verb: str, arguments: dict, *,
    payload: dict | None = None, deadline_s: float = 0.5,
) -> dict:
    if type(deadline_s) not in {int, float} or not 0 < deadline_s <= 60:
        raise ValueError("M.I.O. deadline refused")
    deadline = time.monotonic() + deadline_s
    path = socket_path(leaf)
    uid = pwd.getpwnam(account).pw_uid
    gid = grp.getgrnam(socket_group(leaf)).gr_gid
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
    if (type(response) is dict and set(response) == {"ok", "refusal"}
            and response["ok"] is False and response["refusal"] in _REFUSALS):
        raise ServiceRefused(response["refusal"])
    if (type(response) is not dict or set(response) != {"ok", "result"}
            or response["ok"] is not True or type(response["result"]) is not dict):
        raise ValueError("M.I.O. service refused")
    return response["result"]


#: The longest a readiness probe may take. A request that probes passes a
#: smaller bound: probe time comes out of that request's one deadline.
PROBE_MAX_S = 0.5


def _probe(leaf: str, deadline_s: float = PROBE_MAX_S) -> str:
    try:
        if leaf == "mio":
            reply = _exchange("mio", "azmio", "model.activate", {
                "model_id": "uncommissioned", "runtime_id": "uncommissioned",
            }, deadline_s=deadline_s)
            if reply.get("readiness") == "refused":
                return "local_not_admitted"
            return "local_no_admission_evidence"
        reply = _exchange("remote", "azremote", "remote.infer", {
            "provider_id": "uncommissioned", "request_id": "route-probe",
        }, deadline_s=deadline_s)
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
    def observe(self, *, deadline_s: float = PROBE_MAX_S) -> str:
        return _probe("mio", min(PROBE_MAX_S, deadline_s))

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


#: Locald's read-only admission verb (`mio_locald.ADMISSION_VERB`).
ADMISSION_VERB_NAME = "mio.local.admission"


class LocalAdmissionReader:
    """Whether locald now holds an admitted local model; fail-closed.

    Read-only and bounded: one exchange with locald's own socket, at most
    `PROBE_MAX_S` and at most the share of the request's deadline it is
    given. Anything other than exactly `{"admitted": true}` from the
    authenticated `azmio` peer -- no socket, a refusal, a malformed or
    oversized reply, a timeout -- reads False, and so does every call while
    `LOCAL_MODEL_ADMISSION_ENABLED` is off, without touching the socket.
    True permits only *selecting* LOCAL; it is not an admission of its own.
    """

    @staticmethod
    def enabled() -> bool:
        return model_admission.LOCAL_MODEL_ADMISSION_ENABLED is True

    def __call__(self, *, deadline_s: float = PROBE_MAX_S) -> bool:
        if not self.enabled():
            return False
        if type(deadline_s) not in {int, float} or not deadline_s > 0:
            return False
        try:
            reply = _exchange("mio", "azmio", ADMISSION_VERB_NAME, {},
                              deadline_s=min(PROBE_MAX_S, deadline_s))
        except Exception:  # noqa: BLE001 - an unreadable admission is no admission
            return False
        return set(reply) == {"admitted"} and reply["admitted"] is True


class ReferenceSocketClient:
    """The model-free reference service (`mio_referenced`); never a model verb.

    Returns `(document, None)` or `(None, reason)`, where `reason` is a fixed
    word. The deadline is the caller's remaining share of the request's one
    deadline, measured on the same monotonic clock; a document that arrives
    at or after it is discarded, never attached late.
    """

    def __init__(self, *, clock=time.monotonic) -> None:
        self._clock = clock

    def reference(self, frame: dict, *, deadline_at: float) -> tuple[dict | None, str | None]:
        from .mio_referenced import ACCOUNT, REFERENCE_DEADLINE_MS, REFERENCE_REASONS

        remaining_ms = min(REFERENCE_DEADLINE_MS, int((deadline_at - self._clock()) * 1000))
        if remaining_ms <= 0:
            return None, "deadline"
        try:
            reply = _exchange(
                "mio-reference", ACCOUNT, "mio.reference", {"deadline_ms": remaining_ms},
                payload=frame, deadline_s=remaining_ms / 1000,
            )
        except ServiceRefused:
            return None, "reference_refused"
        except Exception:  # noqa: BLE001 - optional reference; never the request's failure
            return None, "reference_service_unavailable"
        if self._clock() >= deadline_at:
            return None, "deadline"
        if (set(reply) == {"outcome", "reason"} and reply["outcome"] == "unavailable"
                and reply["reason"] in REFERENCE_REASONS):
            return None, reply["reason"]
        if set(reply) != {"outcome", "reference"} or reply["outcome"] != "reference":
            return None, "reference_refused"
        try:
            return read_reference(reply["reference"]), None
        except Exception:  # noqa: BLE001 - a malformed reference is no reference
            return None, "reference_refused"


class RemoteSocketClient:
    def observe(self, *, deadline_s: float = PROBE_MAX_S) -> str:
        return _probe("remote", min(PROBE_MAX_S, deadline_s))

    def handle(self, request, *, audit=None, deadline_ms=None) -> dict:
        """No transport is reachable from here; the probe is still bounded.

        `deadline_ms` is the attempt's share of the request's one deadline and
        is the socket timeout of the exchange, so a remote daemon that accepts
        and never answers cannot hold the request past it.
        """
        bound = PROBE_MAX_S if deadline_ms is None else min(PROBE_MAX_S, deadline_ms / 1000)
        if bound <= 0:
            return {"outcome": "timed_out", "refusal": "deadline"}
        return {"outcome": "unavailable", "refusal": _probe("remote", bound)}
