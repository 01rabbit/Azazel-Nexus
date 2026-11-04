"""Nexus adapter for Fabric's Knowledge Context v1 contract.

This module is optional and has no endpoint, credential, or commissioning
loader. Callers must supply a sanitized P0 frame, an already verified Knowledge
registry and an explicit maximum envelope lifetime. Fabric owns the semantic
payload; this module owns only the Nexus signed response envelope.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Mapping
from datetime import UTC, datetime

from .knowledge_peer import KnowledgeRegistry
from .sanitizer import PrivacyClass, SanitizerPolicy, sanitize
from .signature import SignatureRefused, verify_detached

ENVELOPE_SCHEMA = "azazel-nexus/knowledge-context-envelope/1"
ENVELOPE_DOMAIN = b"azazel-nexus/knowledge-context-envelope/v1\x00"
MAX_ENVELOPE_BYTES = 256 * 1024


class KnowledgeContextRefused(ValueError):
    """Malformed, stale, uncorrelated, or untrusted Knowledge Context."""


def _canonical(value: Mapping) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise KnowledgeContextRefused("invalid envelope document") from exc


def _instant(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return parsed.astimezone(UTC)
    except (ValueError, TypeError, AttributeError, OverflowError) as exc:
        raise KnowledgeContextRefused("invalid envelope timestamp") from exc


def make_request(
    frame: Mapping,
    *,
    privacy_class: PrivacyClass,
    policy: SanitizerPolicy,
    mission: str,
    alias_key: bytes,
    requested_at: str,
):
    """Create the versioned request from fields explicitly allowed by sanitizer.

    The P0 check is independent of policy. This initial full-node path does not
    transmit P1 aliases or any mission data even if a broader policy allows it.
    """
    if privacy_class is not PrivacyClass.P0_PUBLIC:
        raise KnowledgeContextRefused("only P0-public context queries are admitted")
    decision = sanitize(
        frame, privacy_class=privacy_class, policy=policy, mission=mission,
        alias_key=alias_key,
    )
    if not decision.allowed or decision.frame is None:
        raise KnowledgeContextRefused("sanitizer refused Knowledge Context query")
    from .fabric_boundary import (
        KnowledgeContextUnavailable,
        validate_knowledge_context_request,
    )

    try:
        sanitized = json.loads(decision.frame)
        if (not isinstance(sanitized, dict)
                or set(sanitized) != {
                    "body", "redaction_record_id", "remote_privacy_class",
                    "sanitizer_policy_version",
                }
                or sanitized["remote_privacy_class"] != PrivacyClass.P0_PUBLIC.value
                or sanitized["sanitizer_policy_version"] != policy.version):
            raise ValueError
        safe = sanitized["body"]
        if not isinstance(safe, dict) or not safe:
            raise ValueError
        # Fabric v1 models each query value as a bounded string entity. Refuse
        # nested or typed values; do not stringify or flatten them implicitly.
        if any(not isinstance(k, str) or not isinstance(v, str)
               for k, v in safe.items()):
            raise ValueError
        request = validate_knowledge_context_request({
            "schema_version": "knowledge-context-request/v1",
            # Never forward an incident ID or caller-supplied correlation.
            # These opaque request-local references are returned with the
            # response so the caller can correlate without exporting identity.
            "request_id": secrets.token_hex(16),
            "correlation_id": secrets.token_hex(16),
            "source_product": "azazel_nexus",
            "source_ref": "nexus:full-node-context-query",
            "requested_at": requested_at,
            "entities": [
                {"entity_type": name, "value": value}
                for name, value in sorted(safe.items())
            ],
        })
    except (ImportError, TypeError, ValueError, KeyError, RecursionError,
            KnowledgeContextUnavailable) as exc:
        raise KnowledgeContextRefused("sanitized query does not fit Fabric v1") from exc
    return request


def read_signed_response(
    raw: bytes,
    *,
    request,
    registry: KnowledgeRegistry,
    peer_id: str,
    now: str,
    max_ttl_seconds: int,
):
    """Verify key-id binding, signature, bounded transport TTL and Fabric binding.

    The key is resolved from Nexus's existing signed, commissioning-bound
    Knowledge registry. `key_id` is the SHA-256 fingerprint of that registry
    key, so an envelope cannot choose an unregistered verification key.
    `max_ttl_seconds` has no permissive default and must be supplied explicitly.
    """
    if (type(max_ttl_seconds) is not int or max_ttl_seconds < 1
            or type(registry) is not KnowledgeRegistry
            or not isinstance(peer_id, str) or not peer_id
            or not isinstance(raw, bytes) or not 64 < len(raw) <= MAX_ENVELOPE_BYTES):
        raise KnowledgeContextRefused("envelope configuration or size refused")
    from .fabric_boundary import (
        KnowledgeContextUnavailable,
        validate_knowledge_context_response,
    )

    signature, payload = raw[:64], raw[64:]
    try:
        peer = registry.resolve(peer_id, now=now)
        key = peer.public_key
        expected_key_id = "sha256:" + hashlib.sha256(key).hexdigest()
        doc = json.loads(payload)
        if (not isinstance(doc, dict) or _canonical(doc) != payload
                or set(doc) != {"schema", "key_id", "issued_at", "expires_at", "payload"}
                or doc["schema"] != ENVELOPE_SCHEMA
                or not isinstance(doc["key_id"], str) or not doc["key_id"]
                or doc["key_id"] != expected_key_id
                or not isinstance(doc["payload"], dict)):
            raise ValueError
        if not verify_detached(
            public_key=key, message=ENVELOPE_DOMAIN + payload, signature=signature
        ):
            raise ValueError
        issued = _instant(doc["issued_at"])
        expires = _instant(doc["expires_at"])
        current = _instant(now)
        if not issued <= current < expires or (expires - issued).total_seconds() > max_ttl_seconds:
            raise ValueError
        response = validate_knowledge_context_response(request, doc["payload"])
        semantic_generated = _instant(response.generated_at.isoformat())
        semantic_expires = _instant(response.expires_at.isoformat())
        if issued < semantic_generated or expires > semantic_expires:
            raise ValueError
        return response
    except (ImportError, TypeError, ValueError, KeyError, UnicodeError,
            RecursionError, OverflowError, SignatureRefused,
            KnowledgeContextUnavailable) as exc:
        raise KnowledgeContextRefused("signed Knowledge Context was refused") from exc


def canonical_signed_payload(document: Mapping) -> bytes:
    """Canonical envelope bytes for a signing service or an isolated fixture.

    Nexus deliberately has no signing key or signing implementation. Production
    callers must obtain signatures from the commissioned provider.
    """
    return _canonical(document)


__all__ = [
    "ENVELOPE_DOMAIN", "ENVELOPE_SCHEMA", "KnowledgeContextRefused",
    "MAX_ENVELOPE_BYTES", "canonical_signed_payload", "make_request",
    "read_signed_response",
]
