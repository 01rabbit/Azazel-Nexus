"""Pure Knowledge peer policy. Commissioned symbols, never caller URLs.

Uses the provider registry's endpoint grammar, sanitizer, signature verifier,
SPKI identity discipline and separate signing domains. No transport lives here.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType

from .provider_registry import ProviderRecord, ProviderRefused
from .sanitizer import NEVER_REMOTE, PrivacyClass, SanitizerPolicy, sanitize
from .signature import SignatureRefused, verify_detached

REGISTRY_DOMAIN = b"azazel-nexus/knowledge-registry/v1\x00"
CAPABILITY_DOMAIN = b"azazel-nexus/knowledge-capability/v1\x00"
RESPONSE_DOMAIN = b"azazel-nexus/knowledge-response/v1\x00"
SCHEMA = "azazel-nexus/knowledge-peer/1"
MAX_REGISTRY_BYTES = 65536


class KnowledgeRefused(ValueError):
    """Untrusted, incompatible, stale or inadmissible. No partial context."""


def canonical(document: Mapping) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def instant(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(UTC)
    except (ValueError, TypeError, AttributeError) as exc:
        raise KnowledgeRefused("invalid aware timestamp") from exc


def fresh(document: Mapping, now: str) -> None:
    if (
        not instant(document.get("issued_at"))
        <= instant(now)
        < instant(document.get("expires_at"))
    ):
        raise KnowledgeRefused("bundle is expired or not yet valid")


def signed_document(
    raw: bytes, *, domain: bytes, keys: Mapping[str, bytes], limit: int
) -> tuple[dict, str]:
    if not isinstance(raw, bytes) or not 64 < len(raw) <= limit:
        raise KnowledgeRefused("signed document size")
    signer = None
    for name, key in sorted(keys.items()):
        try:
            if verify_detached(
                public_key=key, message=domain + raw[64:], signature=raw[:64]
            ):
                signer = name
                break
        except SignatureRefused:
            continue
    if signer is None:
        raise KnowledgeRefused("bad signature")
    try:
        doc = json.loads(raw[64:])
        if (
            not isinstance(doc, dict)
            or canonical(doc) != raw[64:]
            or doc.get("schema") != SCHEMA
        ):
            raise ValueError
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise KnowledgeRefused("malformed or incompatible signed document") from exc
    return doc, signer


@dataclass(frozen=True)
class KnowledgePeer:
    endpoint: ProviderRecord
    addresses: tuple[str, ...]
    public_key: bytes
    max_inflight: int


@dataclass(frozen=True)
class KnowledgeRegistry:
    commissioning_digest: str
    peers: Mapping[str, KnowledgePeer]
    issued_at: str
    expires_at: str
    version: int

    def resolve(self, peer_id: str, *, now: str) -> KnowledgePeer:
        fresh({"issued_at": self.issued_at, "expires_at": self.expires_at}, now)
        try:
            return self.peers[peer_id]
        except KeyError as exc:
            raise KnowledgeRefused(
                "no module endpoint is configured for this symbol"
            ) from exc


def load_registry(
    raw: bytes, *, keys: Mapping[str, bytes], commissioning_digest: str, now: str
) -> KnowledgeRegistry:
    doc, _ = signed_document(
        raw, domain=REGISTRY_DOMAIN, keys=keys, limit=MAX_REGISTRY_BYTES
    )
    try:
        if set(doc) != {
            "schema",
            "commissioning_digest",
            "issued_at",
            "expires_at",
            "version",
            "peers",
        }:
            raise ValueError
        if (
            not commissioning_digest
            or doc["commissioning_digest"] != commissioning_digest
        ):
            raise ValueError
        fresh(doc, now)
        if (
            type(doc["version"]) is not int
            or doc["version"] < 1
            or not isinstance(doc["peers"], list)
        ):
            raise ValueError
        peers = {}
        for entry in doc["peers"]:
            if set(entry) != {"endpoint", "addresses", "public_key", "max_inflight"}:
                raise ValueError
            fields = dict(entry["endpoint"])
            fields["allowed_privacy_classes"] = tuple(
                PrivacyClass(c) for c in fields["allowed_privacy_classes"]
            )
            endpoint = ProviderRecord(**fields)
            # Fixed Knowledge protocol paths; no interpolation or HTTP injection.
            if (
                endpoint.path_template != "/knowledge/v1"
                or endpoint.model_id != "knowledge-v1"
            ):
                raise ValueError
            if (
                endpoint.max_request_bytes > 65536
                or endpoint.max_response_bytes > 262144
                or endpoint.deadline_seconds > 10
                or type(endpoint.port) is not int
            ):
                raise ValueError
            addresses = entry["addresses"]
            if (
                not isinstance(addresses, list)
                or not addresses
                or any(not isinstance(a, str) for a in addresses)
            ):
                raise ValueError
            addresses = tuple(str(ipaddress.ip_address(a)) for a in addresses)
            key = bytes.fromhex(entry["public_key"])
            if len(key) != 32 or key in keys.values():
                raise ValueError
            if (
                type(entry["max_inflight"]) is not int
                or not 1 <= entry["max_inflight"] <= 8
            ):
                raise ValueError
            if endpoint.provider_id in peers:
                raise ValueError
            peers[endpoint.provider_id] = KnowledgePeer(
                endpoint, addresses, key, entry["max_inflight"]
            )
        return KnowledgeRegistry(
            commissioning_digest,
            MappingProxyType(peers),
            doc["issued_at"],
            doc["expires_at"],
            doc["version"],
        )
    except (KeyError, TypeError, ValueError, AttributeError, ProviderRefused) as exc:
        raise KnowledgeRefused("invalid commissioned Knowledge registry") from exc


def prepare_query(
    peer: KnowledgePeer,
    *,
    frame: Mapping,
    privacy_class: PrivacyClass,
    policy: SanitizerPolicy,
    mission: str,
    alias_key: bytes,
    correlation: str,
) -> bytes:
    if (
        privacy_class in NEVER_REMOTE
        or privacy_class not in peer.endpoint.allowed_privacy_classes
    ):
        raise KnowledgeRefused("privacy class denied")
    if not isinstance(correlation, str) or not re.fullmatch(
        r"[a-f0-9]{32}", correlation
    ):
        raise KnowledgeRefused("correlation must be an opaque 128-bit token")
    decision = sanitize(
        frame,
        privacy_class=privacy_class,
        policy=policy,
        mission=mission,
        alias_key=alias_key,
    )
    if not decision.allowed:
        raise KnowledgeRefused("sanitizer denied query")
    body = canonical(
        {
            "schema": SCHEMA,
            "correlation": correlation,
            "query": json.loads(decision.frame),
        }
    )
    if len(body) > peer.endpoint.max_request_bytes:
        raise KnowledgeRefused("request size exceeded")
    return body


def negotiate(raw: bytes, *, peer: KnowledgePeer, correlation: str, now: str) -> None:
    doc, _ = signed_document(
        raw,
        domain=CAPABILITY_DOMAIN,
        keys={"peer": peer.public_key},
        limit=peer.endpoint.max_response_bytes,
    )
    fresh(doc, now)
    if (
        set(doc)
        != {
            "schema",
            "peer_id",
            "correlation",
            "issued_at",
            "expires_at",
            "versions",
            "capabilities",
        }
        or doc["peer_id"] != peer.endpoint.provider_id
        or doc["correlation"] != correlation
        or doc["versions"] != [1]
        or type(doc["versions"][0]) is not int
        or doc["capabilities"] != ["advisory-context"]
    ):
        raise KnowledgeRefused("capability/version mismatch")


@dataclass(frozen=True)
class PeerContext:
    peer_id: str
    bundle_version: str
    expires_at: str
    correlation: str
    facts: tuple[str, ...]
    inferences: tuple[str, ...]
    trust: str = "verified"


def read_context(
    raw: bytes, *, peer: KnowledgePeer, correlation: str, now: str
) -> PeerContext:
    doc, _ = signed_document(
        raw,
        domain=RESPONSE_DOMAIN,
        keys={"peer": peer.public_key},
        limit=peer.endpoint.max_response_bytes,
    )
    fresh(doc, now)
    if (
        set(doc)
        != {
            "schema",
            "peer_id",
            "correlation",
            "issued_at",
            "expires_at",
            "bundle_version",
            "facts",
            "inferences",
        }
        or doc["peer_id"] != peer.endpoint.provider_id
        or doc["correlation"] != correlation
    ):
        raise KnowledgeRefused("response identity/schema mismatch")
    if (
        not isinstance(doc["bundle_version"], str)
        or not 1 <= len(doc["bundle_version"]) <= 128
    ):
        raise KnowledgeRefused("invalid bundle version")
    for name in ("facts", "inferences"):
        if (
            not isinstance(doc[name], list)
            or len(doc[name]) > 64
            or any(not isinstance(s, str) or not 1 <= len(s) <= 2048 for s in doc[name])
        ):
            raise KnowledgeRefused("malformed advisory response")
    if not doc["facts"] and not doc["inferences"]:
        raise KnowledgeRefused("peer returned no context")
    return PeerContext(
        doc["peer_id"],
        doc["bundle_version"],
        doc["expires_at"],
        correlation,
        tuple(doc["facts"]),
        tuple(doc["inferences"]),
    )
