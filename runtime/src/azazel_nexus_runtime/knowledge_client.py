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
                    "available", "no_context", "no_bundle", "quarantined", "bundle_refused", "state_untrusted",
                    "revoked", "unverified", "trust_unreadable", "store_unreadable",
                }):
            raise ValueError
        # Missing/untrusted context must reach locald's unavailable audit path.
        if result["reason_code"] not in {"available", "no_context"}:
            raise ValueError
        refs = read_knowledge_refs(result["refs"])
        if any(ref.technique_id not in technique_ids for ref in refs):
            raise ValueError
        if bool(refs) != (result["reason_code"] == "available"):
            raise ValueError
        return tuple(refs)
    except ValueError:
        raise KnowledgeUnavailable("knowledge_reply_refused") from None
    except Exception:  # noqa: BLE001 - one public refusal for this transport boundary
        # Includes deadline, account/socket absence, malformed reply and refusal.
        raise KnowledgeUnavailable() from None
