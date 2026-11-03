"""Deadline-bounded Knowledge Lite client for local advisory context."""

from __future__ import annotations

from azazel_nexus.lite_import import TECHNIQUE_ID, KnowledgeRef, read_knowledge_refs

from .mio_socket_client import _exchange


class KnowledgeUnavailable(Exception):
    """One fixed failure; callers must not expose transport or reply text."""

    def __init__(self, code="knowledge_unavailable") -> None:
        self.code = code if code in {"knowledge_unavailable", "knowledge_reply_refused"} else "knowledge_unavailable"
        super().__init__("knowledge unavailable")


def lookup_context(technique_ids: tuple[str, ...], *,
                   deadline_s: float = 0.5) -> tuple[KnowledgeRef, ...]:
    """Query the existing local socket, authenticating azknowledge ownership.

    The shared AF_UNIX exchange verifies peer credentials and framing and uses
    one monotonic deadline across connect, send and receive. No retry or egress.
    """
    if (type(technique_ids) is not tuple or len(technique_ids) > 8
            or any(type(item) is not str or not TECHNIQUE_ID.fullmatch(item)
                   for item in technique_ids)):
        raise KnowledgeUnavailable()
    try:
        result = _exchange("knowledge-read", "azknowledge", "knowledge.lookup",
                           {"technique_ids": list(technique_ids)}, deadline_s=deadline_s)
    except Exception:  # noqa: BLE001 - transport ValueErrors are availability failures too
        raise KnowledgeUnavailable() from None
    try:
        if (type(result) is not dict or set(result) != {"refs", "reason_code"} or type(result["refs"]) is not list
                or len(result["refs"]) > 16
                or result["reason_code"] not in {
                    "available", "no_context", "no_bundle", "quarantined", "bundle_refused", "state_untrusted",
                    "revoked", "unverified", "trust_unreadable", "store_unreadable",
                }):
            raise ValueError
        refs = read_knowledge_refs(result["refs"])
        if any(ref.technique_id not in technique_ids for ref in refs):
            raise ValueError
        if result["reason_code"] not in {"available", "no_context"}:
            if refs:
                raise ValueError
            raise KnowledgeUnavailable()
        if bool(refs) != (result["reason_code"] == "available"):
            raise ValueError
        return tuple(refs)
    except KnowledgeUnavailable:
        raise
    except Exception:  # noqa: BLE001 - only reply validation happens in this block
        raise KnowledgeUnavailable("knowledge_reply_refused") from None
