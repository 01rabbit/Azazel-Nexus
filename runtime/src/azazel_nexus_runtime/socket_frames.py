"""Deadline-bound reads for the length-prefixed Unix socket exchanges.

Shared by the audit, Knowledge Context and M.I.O. socket clients. Its own
module so that a client which needs only these (`knowledge_context_socket`,
and so the model-free context observation service) does not import the audit
daemon's event schemas and everything they reach.
"""

from __future__ import annotations

import time

from azazel_nexus.audit import AuditUnavailable

__all__ = ["_pairs", "_read_exact", "_remaining", "_set_remaining_timeout"]


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
