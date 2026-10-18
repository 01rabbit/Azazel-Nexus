"""Bounded AF_UNIX probes and local advisory payload exchange.

These probes confer no admission. Fixed uncommissioned identifiers cannot
activate a commissioned model or supply a remote envelope. Reply text is never
copied to the route ledger. Framing follows the existing bootstrap clients;
server ownership and kernel credentials follow repin_confirmation._exchange.
"""

from __future__ import annotations

import grp
import json
import pwd
import re
import socket
import time

from azazel_nexus.advisory_response import AdvisoryRefused
from azazel_nexus.audit import AuditUnavailable
from azazel_nexus.lite_import import TECHNIQUE_ID
from azazel_nexus.local_advisory import read_local_advisory

from .bootstrap_audit_client import _pairs, _read_exact, _set_remaining_timeout
from .principal import SocketMisconfigured, peer_credentials, verify_socket
from .runtime_paths import socket_path
from .transport import _HEADER, MAX_FRAME_BYTES


def _exchange(
    leaf: str, account: str, verb: str, arguments: dict, *,
    payload: dict | None = None, deadline_s: float = 0.5,
) -> dict:
    path = socket_path(leaf)
    uid = pwd.getpwnam(account).pw_uid
    gid = grp.getgrnam("azazel-operator").gr_gid
    verify_socket(path, expected_uid=uid, expected_gid=gid)
    if not 0 < deadline_s <= 60:
        raise ValueError("M.I.O. deadline refused")
    deadline = time.monotonic() + deadline_s
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


# The local daemon is a separate process: authenticate transport, then validate
# metadata independently of the unchanged model advisory schema.
_REFERENCE_IDS = {
    "mitre-attack": r"(?:T[0-9]{4}(?:\.[0-9]{3})?|TA[0-9]{4})",
    "mitre-d3fend": r"D3-[A-Z0-9]{2,12}",
    "owasp-top10-2021": r"A(?:0[1-9]|10)",
    "owasp-asvs": r"V[0-9]{1,2}(?:\.[0-9]{1,2}){0,2}",
    "owasp-cheatsheet": r"[a-z0-9-]{3,64}",
    "nist-sp800-61r3": r"(?:govern|identify|protect|detect|respond|recover)",
    "cisa-kev": r"CVE-[0-9]{4}-[0-9]{4,7}",
}


def _reply_metadata(reply: dict) -> dict:
    """Refuse malformed metadata as a fixed local-unavailable response.

    Bounds mirror locald's two matches, eight references and five first-response
    items per match, and sixteen Knowledge refs. Missing fields support older
    locald replies; null playbook means no matches. Knowledge IDs are currently
    ATT&CK native primary keys, as in the authoritative Lite consumer contract.
    """
    def require(condition):
        if not condition:
            raise ValueError("M.I.O. metadata refused")

    def pattern(value, regex):
        return type(value) is str and re.fullmatch(regex, value, flags=re.ASCII) is not None

    def bounded_list(value, minimum, maximum):
        require(type(value) is list and minimum <= len(value) <= maximum)

    metadata = {"playbook": None}
    playbook = reply.get("playbook")
    if playbook is not None:
        require(type(playbook) is dict and set(playbook) == {
            "ids", "status", "references", "first_response",
        })
        ids = playbook["ids"]
        bounded_list(ids, 1, 2)
        require(all(pattern(ident, r"[a-z0-9][a-z0-9-]{2,63}") for ident in ids))
        require(len(set(ids)) == len(ids))
        statuses = playbook["status"]
        bounded_list(statuses, len(ids), len(ids))
        require(all(type(status) is str and status in {"template", "reviewed"}
                    for status in statuses))
        references = playbook["references"]
        bounded_list(references, len(ids), 8 * len(ids))
        for ref in references:
            require(type(ref) is dict and set(ref) == {"source", "id"})
            source = ref["source"]
            require(type(source) is str and source in _REFERENCE_IDS)
            require(pattern(ref["id"], _REFERENCE_IDS[source]))
        responses = playbook["first_response"]
        bounded_list(responses, len(ids), 5 * len(ids))
        require(all(type(text) is str and 0 < len(text.strip()) <= 160
                    and len(text) <= 160 and all(c.isprintable() or c in "\n\t" for c in text)
                    for text in responses))
        metadata["playbook"] = playbook
    if "knowledge" in reply:
        knowledge = reply["knowledge"]
        require(type(knowledge) is dict and set(knowledge) == {"claim_ids"})
        bounded_list(knowledge["claim_ids"], 1, 16)
        require(all(type(ident) is str and TECHNIQUE_ID.fullmatch(ident)
                    for ident in knowledge["claim_ids"]))
        metadata["knowledge"] = knowledge
    # Also rejects unpaired Unicode surrogates before forwarding JSON.
    require(len(json.dumps(metadata, ensure_ascii=False).encode("utf-8")) <= 16 * 1024)
    return metadata


class LocalSocketClient:
    def observe(self) -> str:
        return _probe("mio")

    def handle(self, request, *, audit=None) -> dict:
        if getattr(getattr(request, "verb", None), "name", None) != "mio.local.infer":
            return {"readiness": "refused", "reason": self.observe()}
        try:
            reply = _exchange(
                "mio", "azmio", "mio.local.infer", request.arguments,
                payload=request.payload, deadline_s=request.arguments["deadline_ms"] / 1000,
            )
            if reply.get("outcome") == "advisory":
                body = {}
                if reply.get("advice") is not None:
                    body["advice"] = reply["advice"]
                if "fields" in reply:
                    body["fields"] = reply["fields"]
                advisory = read_local_advisory(json.dumps(body))
                metadata = _reply_metadata(reply)
                if audit is not None:
                    audit(advisory.as_event(local=True))
                return {**body, **metadata, "outcome": "advisory", "refusal": None}
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
