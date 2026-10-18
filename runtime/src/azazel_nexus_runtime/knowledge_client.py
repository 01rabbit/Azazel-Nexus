"""Deadline-bounded Knowledge Lite client for local advisory context."""

from __future__ import annotations

import re

from azazel_nexus.lite_import import TECHNIQUE_ID, KnowledgeRef

from .mio_socket_client import _exchange


class KnowledgeUnavailable(Exception):
    """One fixed failure; callers must not expose transport or reply text."""

    def __init__(self) -> None:
        super().__init__("knowledge unavailable")


def lookup_context(technique_ids: tuple[str, ...], *,
                   deadline_s: float = 0.5) -> tuple[KnowledgeRef, ...]:
    """Query the existing local socket, authenticating azknowledge ownership.

    The shared AF_UNIX exchange verifies peer credentials and framing and uses
    one monotonic deadline across connect, send and receive. No retry or egress.
    """
    try:
        if (type(technique_ids) is not tuple or len(technique_ids) > 8
                or any(type(item) is not str or not TECHNIQUE_ID.fullmatch(item)
                       for item in technique_ids)):
            raise ValueError
        result = _exchange("knowledge-read", "azknowledge", "knowledge.lookup",
                           {"technique_ids": list(technique_ids)}, deadline_s=deadline_s)
        if (set(result) != {"refs", "reason_code"} or type(result["refs"]) is not list
                or len(result["refs"]) > 16
                or result["reason_code"] not in {
                    "available", "no_context", "no_bundle", "quarantined", "bundle_refused",
                    "revoked", "unverified", "trust_unreadable", "store_unreadable",
                }):
            raise ValueError
        # Missing/untrusted context must reach locald's unavailable audit path.
        if result["reason_code"] not in {"available", "no_context"}:
            raise ValueError
        refs = []
        fields = {"technique_id", "name", "summary", "claim_id", "bundle_digest", "freshness"}
        for row in result["refs"]:
            if type(row) is not dict or set(row) != fields:
                raise ValueError
            if any(type(value) is not str for value in row.values()):
                raise ValueError
            if (row["technique_id"] not in technique_ids
                    or not 0 < len(row["name"]) <= 120 or len(row["summary"]) > 240
                    or row["claim_id"] != row["technique_id"]
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", row["bundle_digest"])
                    or row["freshness"] not in {"current", "static"}
                    or any(not c.isprintable() for key in ("name", "summary") for c in row[key])):
                raise ValueError
            refs.append(KnowledgeRef(**row))
        if bool(refs) != (result["reason_code"] == "available"):
            raise ValueError
        return tuple(refs)
    except Exception:  # noqa: BLE001 - one public refusal for this transport boundary
        # Includes deadline, account/socket absence, malformed reply and refusal.
        raise KnowledgeUnavailable() from None
