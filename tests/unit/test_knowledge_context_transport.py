"""Optional Fabric v1 Knowledge Context transport over commissioned Nexus mTLS."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from time import monotonic as REAL_MONOTONIC
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from azazel_nexus.knowledge_context_adapter import (
    ENVELOPE_DOMAIN,
    ENVELOPE_SCHEMA,
    KnowledgeContextRefused,
    canonical_signed_payload,
)
from azazel_nexus.knowledge_peer import KnowledgePeer, KnowledgeRegistry
from azazel_nexus.provider_registry import ProviderRecord
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy
from azazel_nexus_runtime.knowledge_egress import KnowledgeClient
from test_inference_egress import PINS, Server, material

NOW = "2026-11-04T12:00:00Z"
PEER_KEY = SigningKey(bytes(range(32, 64)))
PUBLIC_KEY = bytes(PEER_KEY.verify_key)
KEY_ID = "sha256:" + hashlib.sha256(PUBLIC_KEY).hexdigest()
POLICY = SanitizerPolicy.from_mapping(
    {
        "version": "knowledge-context-transport-test-1",
        "remote_default": "deny",
        "classes": {"P0-public": {"remote": "allow", "fields": ["indicator"]}},
        "aliases": [],
        "redactions": ["secret"],
        "limits": {"max_bytes": 2048},
    }
)
TLS = Path(__file__).resolve().parents[1] / "fixtures" / "tls"


def registry(port: int, *, deadline_seconds: int = 3) -> KnowledgeRegistry:
    endpoint = ProviderRecord(
        provider_id="knowledge-node-1",
        host="fetch.azazel.test",
        port=port,
        path_template="/knowledge/v1",
        certificate_pin=PINS["server-fetch"],
        client_identity="knowledge-test",
        model_id="knowledge-v1",
        max_request_bytes=4096,
        max_response_bytes=8192,
        deadline_seconds=deadline_seconds,
        allowed_privacy_classes=(PrivacyClass.P0_PUBLIC,),
    )
    peer = KnowledgePeer(
        endpoint=endpoint,
        addresses=("127.0.0.1",),
        public_key=PUBLIC_KEY,
        max_inflight=1,
    )
    return KnowledgeRegistry(
        commissioning_digest="sha256:" + "a" * 64,
        peers={endpoint.provider_id: peer},
        issued_at="2026-11-04T11:00:00Z",
        expires_at="2026-11-04T13:00:00Z",
        version=1,
    )


def client(
    peer_registry: KnowledgeRegistry,
    *,
    enabled: bool = False,
    max_ttl_seconds: int | None = None,
) -> KnowledgeClient:
    return KnowledgeClient(
        registry=peer_registry,
        peer_id="knowledge-node-1",
        ca_certificate=material("trusted-ca.crt"),
        identities={
            "knowledge-test": (material("client.crt"), material("client.key"))
        },
        knowledge_context_enabled=enabled,
        knowledge_context_max_ttl_seconds=max_ttl_seconds,
        utc_now=lambda: NOW,
    )


def query(peer: KnowledgeClient, *, privacy: PrivacyClass = PrivacyClass.P0_PUBLIC,
          deadline_s: float | None = None):
    return peer.request_context(
        frame={"indicator": "203.0.113.9", "secret": "private-value"},
        privacy_class=privacy,
        policy=POLICY,
        mission="synthetic-interop-test",
        alias_key=b"test-only",
        deadline_s=deadline_s,
    )


def _contract():
    return pytest.importorskip("azazel_fabric.knowledge_context")


def _signed_answer(body: bytes, *, mode: str = "valid") -> bytes:
    contract = _contract()
    request = contract.KnowledgeContextRequestV1.model_validate_json(body)
    subject = request.entities[0].model_dump(mode="json")
    response = {
        "schema_version": contract.RESPONSE_SCHEMA_VERSION,
        "request_id": request.request_id,
        "correlation_id": request.correlation_id,
        "source_product": request.source_product,
        "source_ref": request.source_ref,
        "provider_id": "knowledge-node-1",
        "snapshot": {
            "ref": "snapshot:synthetic-1",
            "state": "partial",
            "as_of": NOW,
        },
        "facts": [
            {
                "claim_class": "source_reported_fact",
                "fact_id": "fact-1",
                "subject": subject,
                "predicate": "listed_by",
                "value": "A synthetic source reports this indicator.",
                "provenance": ["feed:synthetic"],
            }
        ],
        "inferences": [],
        "unknowns": ["source-level freshness was not included"],
        "limitations": ["synthetic test data"],
        "generated_at": NOW,
        "expires_at": "2026-11-04T12:05:00Z",
        "authority": "advisory_only",
    }
    if mode == "wrong-request":
        response["request_id"] = "another-request"
    typed = contract.KnowledgeContextResponseV1.model_validate(response)
    semantic = json.loads(contract.canonical_knowledge_context_bytes(typed))
    envelope = {
        "schema": ENVELOPE_SCHEMA,
        "key_id": KEY_ID,
        "issued_at": NOW,
        "expires_at": "2026-11-04T12:05:00Z",
        "payload": semantic,
    }
    if mode == "expired":
        envelope["issued_at"] = "2026-11-04T11:59:00Z"
        envelope["expires_at"] = "2026-11-04T11:59:30Z"
    if mode == "wrong-key":
        envelope["key_id"] = "sha256:" + "0" * 64
    canonical = canonical_signed_payload(envelope)
    signature = PEER_KEY.sign(ENVELOPE_DOMAIN + canonical).signature
    if mode == "bad-signature":
        signature = b"x" * 64
    return signature + canonical


def test_full_node_context_is_disabled_without_explicit_configuration(monkeypatch):
    peer = client(registry(443))

    def forbidden(*args, **kwargs):
        raise AssertionError("disabled Knowledge Context attempted network I/O")

    monkeypatch.setattr("azazel_nexus_runtime.knowledge_egress.socket.socket", forbidden)
    with pytest.raises(KnowledgeContextRefused, match="disabled"):
        query(peer)


@pytest.mark.parametrize("enabled,ttl", [(True, None), (1, 30), (True, True), (True, 0)])
def test_full_node_context_requires_exact_enable_flag_and_explicit_positive_ttl(enabled, ttl):
    with pytest.raises(ValueError):
        client(registry(443), enabled=enabled, max_ttl_seconds=ttl)


@pytest.mark.parametrize("deadline", [0, -0.1, float("nan"), float("inf"), True, 10**1000])
def test_full_node_context_refuses_invalid_caller_deadline(deadline):
    peer = client(registry(443), enabled=True, max_ttl_seconds=30)
    with pytest.raises(KnowledgeContextRefused, match="deadline is invalid"):
        query(peer, deadline_s=deadline)


def test_full_node_context_caps_transport_to_caller_deadline(monkeypatch):
    _contract()
    from azazel_nexus_runtime import knowledge_egress

    peer = client(registry(443, deadline_seconds=60), enabled=True,
                  max_ttl_seconds=30)
    observed = []

    def refuse(_peer, _path, _body, deadline):
        observed.append(deadline)
        raise OSError("synthetic timeout")

    monkeypatch.setattr(
        knowledge_egress, "time", SimpleNamespace(monotonic=REAL_MONOTONIC)
    )
    monkeypatch.setattr(peer, "_post_path", refuse)
    started = REAL_MONOTONIC()
    with pytest.raises(KnowledgeContextRefused, match="refused or unavailable") as exc:
        query(peer, deadline_s=30)
    assert len(observed) == 1, f"pre-transport refusal cause: {exc.value.__cause__!r}"
    assert started + 30 <= observed[0] < started + 31


def test_loopback_mtls_sends_only_sanitized_p0_and_validates_signed_fabric_response():
    _contract()

    def respond(stream, body):
        answer = _signed_answer(body)
        stream.sendall(
            f"HTTP/1.1 200 OK\r\nContent-Length: {len(answer)}\r\n"
            "Connection: close\r\n\r\n".encode("ascii")
            + answer
        )

    server = Server(responder=respond, certificate="server-fetch")
    peer_registry = registry(server.port)
    # Keep both the signed envelope and semantic response at the commissioned
    # five-minute maximum; the semantic expiry may not outlive its envelope.
    peer = client(peer_registry, enabled=True, max_ttl_seconds=300)
    try:
        response = query(peer)
        assert response.authority == "advisory_only"
        assert response.snapshot.state == "partial"
        assert response.facts[0].claim_class == "source_reported_fact"
        assert server.peer_certificates and server.peer_certificates[0]
        assert len(server.requests) == 1
        headers, raw_body = server.requests[0]
        assert "POST /v1/knowledge-context HTTP/1.1" in headers
        sent = json.loads(raw_body)
        assert sent["entities"] == [
            {"entity_type": "indicator", "value": "203.0.113.9"}
        ]
        assert b"private-value" not in raw_body
        assert b"synthetic-interop-test" not in raw_body
    finally:
        server.close()


@pytest.mark.parametrize("mode", ["bad-signature", "expired", "wrong-key", "wrong-request"])
def test_loopback_refuses_bad_or_unbound_signed_response(mode):
    _contract()

    def respond(stream, body):
        answer = _signed_answer(body, mode=mode)
        stream.sendall(
            f"HTTP/1.1 200 OK\r\nContent-Length: {len(answer)}\r\n"
            "Connection: close\r\n\r\n".encode("ascii")
            + answer
        )

    server = Server(responder=respond, certificate="server-fetch")
    peer = client(registry(server.port), enabled=True, max_ttl_seconds=60)
    try:
        with pytest.raises(KnowledgeContextRefused, match="refused or unavailable"):
            query(peer)
        assert server.peer_certificates and server.peer_certificates[0]
        assert len(server.requests) == 1
    finally:
        server.close()
