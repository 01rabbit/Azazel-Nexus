"""Typed bootstrap event client for auditd's single-writer Unix socket."""

from __future__ import annotations

from contextlib import nullcontext
import json
import math
import re
import socket
import time
from dataclasses import dataclass

from azazel_nexus.audit import AuditUnavailable

from .auditd import EVENT_SCHEMAS
from .transport import MAX_FRAME_BYTES, _HEADER

_EVENTS = frozenset(name for name in EVENT_SCHEMAS if name.startswith("bootstrap."))
_HASH = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class AuditAppendReceipt:
    """Chain acknowledgement returned only after auditd accepted one append."""

    sequence: int
    event_hash: str

    def __post_init__(self):
        if (type(self.sequence) is not int or self.sequence <= 0
                or type(self.event_hash) is not str
                or not _HASH.fullmatch(self.event_hash)):
            raise ValueError("invalid audit append receipt")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response field")
        result[key] = value
    return result


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("bootstrap audit exchange expired")
    return remaining


def _set_remaining_timeout(connection, deadline):
    connection.settimeout(_remaining(deadline))


def _read_exact(connection, size, deadline):
    data = bytearray()
    while len(data) < size:
        _set_remaining_timeout(connection, deadline)
        part = connection.recv(size - len(data))
        _remaining(deadline)
        if not part:
            raise AuditUnavailable("bootstrap audit response truncated")
        data.extend(part)
    return bytes(data)


class BootstrapAuditClient:
    """Use only the fixed bootstrap observation and append operations.

    The private socket factory is a test seam. Production path and request
    vocabulary are fixed; neither an RPC caller nor event content selects a
    destination, operation or schema. Audit failure propagates to containment.
    The fixed production connector requires a retained server binding. Only
    explicitly injected transports may omit it as a trusted test seam.
    Synchronous identity revalidation is checked against the exchange deadline
    but cannot be preempted; its own connection/cleanup budgets remain separate.
    The observed head is auditd's in-memory last verified/appended head; it is
    not a fresh filesystem scan, external anchor, or proof against a privileged
    writer outside the auditd single-writer trust boundary.
    """

    def __init__(self, *, socket_factory=None, timeout_seconds=5.0, binding_source=None):
        if (type(timeout_seconds) not in (int, float)
                or timeout_seconds <= 0 or timeout_seconds > 30
                or not math.isfinite(timeout_seconds)):
            raise ValueError("bounded audit socket deadline required")
        self._timeout = timeout_seconds
        if socket_factory is not None and not callable(socket_factory):
            raise ValueError("audit socket factory must be callable")
        self._socket_factory = socket_factory
        if binding_source is not None and not callable(binding_source):
            raise ValueError("retained audit binding source must be callable")
        self._binding_source = binding_source

    @staticmethod
    def _connect(deadline, *, path=None):
        from .runtime_paths import socket_path

        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            _set_remaining_timeout(connection, deadline)
            connection.connect(str(socket_path("audit") if path is None else path))
            _remaining(deadline)
        except BaseException:
            connection.close()
            raise
        return connection

    def _exchange(self, request):
        """One monotonic I/O budget, including connect and trailing EOF.

        The injected factory is trusted test composition, not a bounded worker.
        Production uses only the fixed Unix socket connection above.
        """
        deadline = time.monotonic() + self._timeout
        if self._binding_source is None:
            if self._socket_factory is None:
                raise AuditUnavailable("retained audit server binding unavailable")
            # Explicit injected transport is a trusted test seam only.
            proof_context = nullcontext(None)
        else:
            from .bootstrap_audit_peer import AuditPeerBinding

            binding = self._binding_source()
            if type(binding) is not AuditPeerBinding:
                raise AuditUnavailable("verified audit server binding required")
            _remaining(deadline)
            proof_context = binding.proof(deadline)
        with proof_context as proof:
            connection = (self._connect(deadline, path=proof.path)
                          if self._socket_factory is None else self._socket_factory())
            with connection:
                if proof is not None:
                    proof.check(connection)
                _set_remaining_timeout(connection, deadline)
                connection.sendall(_HEADER.pack(len(request)) + request)
                _set_remaining_timeout(connection, deadline)
                # Server dispatch requires EOF after the single request.
                connection.shutdown(socket.SHUT_WR)
                (size,) = _HEADER.unpack(_read_exact(connection, _HEADER.size, deadline))
                if not 0 < size <= MAX_FRAME_BYTES:
                    raise ValueError("bootstrap audit response bound refused")
                raw = _read_exact(connection, size, deadline)
                _set_remaining_timeout(connection, deadline)
                if connection.recv(1):
                    raise ValueError("bootstrap audit response trailing bytes")
                _remaining(deadline)
                response = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
                if proof is not None:
                    proof.check(connection)
            _remaining(deadline)
        return response

    def observe_head(self) -> tuple[int, str]:
        """Return auditd's verified writer head through its root-only verb."""
        try:
            request = json.dumps(
                {"verb": "audit.bootstrap.observe", "arguments": {}},
                sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
            response = self._exchange(request)
            result = response.get("result") if type(response) is dict else None
            if (type(response) is not dict or set(response) != {"ok", "result"}
                    or response["ok"] is not True or type(result) is not dict
                    or set(result) != {"verified", "head_sequence", "head_hash"}
                    or result["verified"] is not True
                    or type(result["head_sequence"]) is not int
                    or result["head_sequence"] <= 0
                    or type(result["head_hash"]) is not str
                    or not _HASH.fullmatch(result["head_hash"])):
                raise ValueError("bootstrap audit observation refused")
            return result["head_sequence"], result["head_hash"]
        except Exception as error:
            raise AuditUnavailable("verified audit head unavailable") from error

    def __call__(self, event) -> AuditAppendReceipt:
        try:
            if type(event) is not dict:
                raise ValueError("event mapping required")
            event_type = event.get("event_type")
            if type(event_type) is not str or event_type not in _EVENTS:
                raise ValueError("bootstrap event type refused")
            schema = EVENT_SCHEMAS[event_type]
            fields = {item.name: item for item in schema}
            if not set(event).issubset({"event_type", *fields}):
                raise ValueError("bootstrap event has undeclared fields")
            payload = {key: value for key, value in event.items()
                       if key in fields and value is not None}
            if set(payload) != set(fields):
                raise ValueError("bootstrap event fields refused")
            for key, value in payload.items():
                fields[key].coerce(value)
            request = json.dumps(
                {"verb": "audit.bootstrap.append", "arguments": {"event_type": event_type},
                 "event": payload},
                sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
            if not request or len(request) > MAX_FRAME_BYTES:
                raise ValueError("bootstrap audit request exceeds bound")
            response = self._exchange(request)
            if (type(response) is not dict or set(response) != {"ok", "result"}
                    or response["ok"] is not True or type(response["result"]) is not dict
                    or set(response["result"]) != {"sequence", "event_hash"}
                    or type(response["result"]["sequence"]) is not int
                    or response["result"]["sequence"] <= 0
                    or type(response["result"]["event_hash"]) is not str
                    or not _HASH.fullmatch(response["result"]["event_hash"])):
                raise ValueError("bootstrap audit append response refused")
            return AuditAppendReceipt(
                response["result"]["sequence"], response["result"]["event_hash"]
            )
        except Exception as error:
            raise AuditUnavailable(
                "bootstrap event was not confirmed in the audit chain"
            ) from error
