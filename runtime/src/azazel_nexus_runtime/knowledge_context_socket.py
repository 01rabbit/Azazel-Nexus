"""Bounded local protocol for the optional Knowledge Context broker.

The M.I.O. local runtime talks to a dedicated broker over AF_UNIX. This
module has no peer address, credential, registry, or network transport; those
belong exclusively to ``knowledge_contextd``. Missing broker state degrades
to a fixed refusal.
"""

from __future__ import annotations

import json
import socket
import time
from enum import Enum
from typing import Any

from .bootstrap_audit_client import (
    AuditUnavailable, _pairs, _read_exact, _set_remaining_timeout,
)
from .principal import SocketMisconfigured, peer_credentials, verify_socket
from .runtime_paths import socket_path
from .transport import MAX_FRAME_BYTES, _HEADER

MAX_CONTEXT_FRAME_BYTES = 16 * 1024
MAX_CONTEXT_RESPONSE_BYTES = 48 * 1024


class KnowledgeContextUnavailable(ValueError):
    """The optional local broker did not provide verified context.

    `stage` is the broker's fixed word for how far a technique query got
    (one of `STAGES`), or None when the broker said nothing about it.
    """

    stage: str | None = None


#: How far a technique query got, as the broker reports it on a refusal.
STAGES = frozenset({"refused_before_send", "transport", "verification",
                    "technique_verification"})


class FullNodeContextStatus(str, Enum):
    """Local broker transport state, independent of Lite and claim validity."""

    NOT_QUERIED = "not_queried"
    RECEIVED = "received"
    UNAVAILABLE = "unavailable"


def read_context_frame(value: Any) -> dict:
    """Accept only a bounded JSON-compatible frame; never repair its shape."""
    if type(value) is not dict:
        raise KnowledgeContextUnavailable("frame shape")
    try:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False,
                         separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise KnowledgeContextUnavailable("frame encoding") from exc
    if not raw or len(raw) > MAX_CONTEXT_FRAME_BYTES:
        raise KnowledgeContextUnavailable("frame size")
    return value


def request_context(frame: dict, *, deadline_s: float) -> dict:
    """Request one validated context response from the local broker.

    Socket ownership is checked before connect and the peer uid is checked
    after connect. The caller deadline covers connect, write, and response.
    """
    if type(deadline_s) not in (int, float) or not 0 < deadline_s <= 10:
        raise KnowledgeContextUnavailable("deadline")
    frame = read_context_frame(frame)
    deadline = time.monotonic() + deadline_s
    document = {"verb": "knowledge.context",
                "arguments": {
                    "deadline_ms": min(10_000, int(deadline_s * 1000)),
                    "deadline_monotonic_ns": int(deadline * 1_000_000_000),
                },
                "event": {"frame": frame}}
    payload = json.dumps(document, ensure_ascii=False, allow_nan=False,
                         separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_FRAME_BYTES:
        raise KnowledgeContextUnavailable("request size")
    path = socket_path("knowledge-context")
    try:
        verify_socket(path, expected_uid=_service_uid(), expected_gid=_socket_gid())
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            _set_remaining_timeout(connection, deadline)
            connection.connect(str(path))
            pid, uid, _ = peer_credentials(connection)
            if pid <= 0 or uid != _service_uid():
                raise KnowledgeContextUnavailable("peer identity")
            _set_remaining_timeout(connection, deadline)
            connection.sendall(_HEADER.pack(len(payload)) + payload)
            connection.shutdown(socket.SHUT_WR)
            (size,) = _HEADER.unpack(_read_exact(connection, _HEADER.size, deadline))
            if not 0 < size <= MAX_CONTEXT_RESPONSE_BYTES:
                raise KnowledgeContextUnavailable("response size")
            reply = json.loads(_read_exact(connection, size, deadline).decode("utf-8"),
                               object_pairs_hook=_pairs)
            if connection.recv(1):
                raise KnowledgeContextUnavailable("trailing response")
    except KnowledgeContextUnavailable:
        raise
    except (AuditUnavailable, OSError, KeyError, ValueError, TimeoutError,
            RecursionError, SocketMisconfigured) as exc:
        raise KnowledgeContextUnavailable("broker unavailable") from exc
    if (type(reply) is not dict or set(reply) != {"ok", "result"}
            or reply["ok"] is not True or type(reply["result"]) is not dict):
        raise KnowledgeContextUnavailable("broker refused")
    result = reply["result"]
    if set(result) == {"refusal", "stage"} and result["stage"] in STAGES:
        refused = KnowledgeContextUnavailable("broker refused")
        refused.stage = result["stage"]
        raise refused
    if set(result) != {"response"} or type(result["response"]) is not dict:
        raise KnowledgeContextUnavailable("broker response shape")
    return result["response"]


def _socket_gid() -> int:
    import grp
    return grp.getgrnam("azknowledge-context-client").gr_gid


def _service_uid() -> int:
    import pwd
    return pwd.getpwnam("azknowledgeegress").pw_uid
