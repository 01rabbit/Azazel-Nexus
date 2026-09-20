"""The Unix domain socket every daemon speaks over (#37).

Nothing here listens on a network. `AF_UNIX` and `SOCK_STREAM`, a fixed frame,
and peer credentials the kernel attached. `tests/unit/test_runtime_boundary.py`
scans this package for `AF_INET` and refuses to find it.

**The frame.** Four bytes of big-endian length, then that many bytes of JSON.
A stream socket has no message boundaries, so a protocol over one has to say
where a message ends; leaving that implicit is how a request becomes whatever
arrived before the reader gave up.

The refusals are separate because their causes are:

| Refusal | Cause |
| --- | --- |
| `frame_too_large` | The declared length exceeds the ceiling |
| `truncated_frame` | The peer closed before the declared length arrived |
| `trailing_bytes` | Bytes followed the frame on a one-request connection |
| `malformed_frame` | A zero length, or a header that never arrived |
| `not_an_object` | Valid JSON that is not a request |
| `read_deadline` | The peer stopped sending and did not close |

`frame_too_large` is refused **without reading the body**. A ceiling enforced
after reading everything is a ceiling on nothing: the memory is already spent,
which is the whole thing the ceiling was for.

`read_deadline` is why nothing here can wait forever. A peer that connects,
sends three bytes and stops is the cheapest denial of service there is, and a
daemon with no deadline serves it indefinitely.
"""

from __future__ import annotations

import json
import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from .principal import (
    Principal,
    PrincipalPolicy,
    REQUIRED_SOCKET_MODE,
    peer_credentials,
    verify_socket,
)
from .protocol import Refusal, RequestRefused, Verb, VerbRegistry, fingerprint

__all__ = [
    "MAX_FRAME_BYTES",
    "READ_DEADLINE_SECONDS",
    "Request",
    "SocketServer",
    "bind_socket",
    "read_frame",
    "send_frame",
]

#: The ceiling on one request. Fixed, not configurable.
#:
#: A configurable ceiling is a ceiling whoever writes the configuration
#: chooses, and every request this protocol can express fits in a fraction of
#: this: ordinals, flags, enumerated values and digests.
MAX_FRAME_BYTES = 64 * 1024

#: How long a peer may hold a connection without completing a frame.
READ_DEADLINE_SECONDS = 5.0

_HEADER = struct.Struct("!I")


@dataclass(frozen=True)
class Request:
    """One validated request, and who the kernel said sent it."""

    verb: Verb
    arguments: dict
    principal: Principal


def bind_socket(path: Path, *, mode: int = REQUIRED_SOCKET_MODE, backlog: int = 16):
    """Bind, set the mode, then verify that what exists is what we made.

    `chmod` after `bind` is what makes the mode independent of the process
    umask; the verification that follows is not for that. It is for the case
    where the path is not the socket this call just created -- replaced
    between the two operations, or a leftover of the wrong type that `unlink`
    did not remove -- and for the owner. On failure the listener is closed
    rather than leaked, because a daemon that raises while holding a bound
    socket leaves the path occupied for the next start.
    """

    if path.exists():
        path.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(path))
        path.chmod(mode)
        verify_socket(path, expected_mode=mode)
        server.listen(backlog)
    except BaseException:
        server.close()
        raise
    return server


def read_frame(connection, *, limit: int = MAX_FRAME_BYTES) -> bytes:
    """One length-prefixed frame, or a refusal naming what went wrong."""

    header = _read_exactly(connection, _HEADER.size)
    if header is None:
        raise RequestRefused(Refusal.MALFORMED_FRAME, "no length header")
    (declared,) = _HEADER.unpack(header)
    if declared == 0:
        raise RequestRefused(Refusal.MALFORMED_FRAME, "zero length")
    if declared > limit:
        # Refused before the body is read. Reading it first to discover it is
        # too large spends exactly the resource the limit exists to protect.
        raise RequestRefused(Refusal.FRAME_TOO_LARGE, str(declared))
    body = _read_exactly(connection, declared)
    if body is None:
        raise RequestRefused(Refusal.TRUNCATED_FRAME, str(declared))
    if _read_exactly(connection, 1) is not None:
        raise RequestRefused(Refusal.TRAILING_BYTES, "")
    return body


def _read_exactly(connection, count: int) -> Optional[bytes]:
    """`count` bytes, or `None` if the peer closed first."""

    chunks: list[bytes] = []
    remaining = count
    while remaining:
        try:
            chunk = connection.recv(remaining)
        except socket.timeout as exc:
            raise RequestRefused(Refusal.READ_DEADLINE, "") from exc
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_frame(connection, payload: Any) -> None:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    connection.sendall(_HEADER.pack(len(body)) + body)


class SocketServer:
    """Accepts one connection at a time, refuses precisely, records bounded facts.

    The audit sink is injected and every refusal reaches it. A privilege
    boundary that does not record the calls it turned away is a privilege
    boundary nobody can tell has been probed.
    """

    def __init__(
        self,
        *,
        registry: VerbRegistry,
        policy: PrincipalPolicy,
        audit: Callable[[dict], Any],
        deadline: float = READ_DEADLINE_SECONDS,
    ) -> None:
        self.registry = registry
        self.policy = policy
        self.audit = audit
        self.deadline = deadline

    def serve_connection(
        self, connection, handler: Callable[[Request], Any]
    ) -> None:
        """Handle exactly one request on `connection`, then reply and return."""

        connection.settimeout(self.deadline)
        principal: Optional[Principal] = None
        raw = b""
        try:
            pid, uid, gid = peer_credentials(connection)
            principal = self.policy.classify(uid, gid, pid)
            raw = read_frame(connection)
            request = self._parse(raw, principal)
        except RequestRefused as refused:
            self._record_refusal(refused, principal, raw)
            self._reply_refusal(connection, refused)
            return

        try:
            result = handler(request)
        except RequestRefused as refused:
            self._record_refusal(refused, principal, raw, verb=request.verb.name)
            self._reply_refusal(connection, refused)
            return
        send_frame(connection, {"ok": True, "result": result})

    def _parse(self, raw: bytes, principal: Principal) -> Request:
        try:
            document = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RequestRefused(Refusal.MALFORMED_FRAME, "not json") from exc
        if not isinstance(document, dict):
            raise RequestRefused(Refusal.NOT_AN_OBJECT, "")
        arguments = document.get("arguments", {})
        if not isinstance(arguments, dict):
            raise RequestRefused(Refusal.NOT_AN_OBJECT, "arguments")
        verb = self.registry.resolve(document.get("verb"), principal)
        return Request(verb=verb, arguments=verb.bind(arguments), principal=principal)

    def _record_refusal(
        self,
        refused: RequestRefused,
        principal: Optional[Principal],
        raw: bytes,
        *,
        verb: Optional[str] = None,
    ) -> None:
        """Bounded facts only.

        A rejected frame is attacker-supplied, so nothing from it is written
        verbatim. What is recorded: the reason, the byte count, a fingerprint,
        and the caller's credentials -- which do not come from the caller. The
        verb name appears only when it is one this daemon declared.
        """

        event = {
            "event_type": "runtime.request_refused",
            "reason": refused.refusal.value,
            "request_bytes": len(raw),
            "request_fingerprint": fingerprint(raw),
        }
        known = verb or (
            refused.detail
            if refused.refusal is Refusal.PRINCIPAL_DENIED
            and refused.detail in self.registry
            else None
        )
        if known is not None:
            event["verb"] = known
        if refused.refusal in _BOUNDED_DETAILS and refused.detail:
            # Safe because these names are ours: a declared argument, or a key
            # from the fixed reserved set. `undeclared_argument` is
            # deliberately absent -- its detail is a key the *caller* chose,
            # and recording it would make the ledger a place anyone who can
            # reach the socket may write text into. The frame fingerprint
            # above is what correlates repeats.
            event["argument"] = refused.detail
        if principal is not None:
            event.update(principal.as_audit_fields())
        self.audit(event)

    @staticmethod
    def _reply_refusal(connection, refused: RequestRefused) -> None:
        try:
            send_frame(connection, {"ok": False, "refusal": refused.refusal.value})
        except OSError:
            # The peer that sent an unreadable frame may well be gone. Its
            # departure is not this daemon's failure, and the refusal is
            # already recorded.
            pass


#: Refusals whose detail is a name this daemon declared, not the caller's text.
#:
#: `UNDECLARED_ARGUMENT` is not here and must not be added: the key it names
#: was chosen by the caller. `tests/unit/test_runtime_transport.py` sends a
#: request with a long, distinctive undeclared key and asserts it appears
#: nowhere in the recorded event.
_BOUNDED_DETAILS = frozenset(
    {
        # Argument names this daemon declared.
        Refusal.MISSING_ARGUMENT,
        Refusal.ARGUMENT_TYPE,
        Refusal.ARGUMENT_RANGE,
        # A key from the fixed reserved set.
        Refusal.CLIENT_ASSERTED_PRINCIPAL,
        # Literals from this module: "zero length", "no length header",
        # "not json". Distinguishing them matters: a peer sending a zero
        # length, one sending no header at all, and one sending bytes that
        # are not JSON are three different things arriving at a socket.
        Refusal.MALFORMED_FRAME,
        # A uint32 rendered as decimal, so at most ten characters.
        Refusal.FRAME_TOO_LARGE,
        Refusal.TRUNCATED_FRAME,
    }
)
