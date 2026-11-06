"""Nexus transport envelope around the Fabric-owned semantic contract."""

from __future__ import annotations

import hashlib
import re

import pytest
from nacl.signing import SigningKey

from azazel_nexus.knowledge_peer import KnowledgePeer, KnowledgeRegistry
from azazel_nexus.knowledge_context_adapter import (
    ENVELOPE_DOMAIN,
    ENVELOPE_SCHEMA,
    KnowledgeContextRefused,
    canonical_signed_payload,
    make_request,
    read_signed_response,
)
from azazel_nexus.provider_registry import ProviderRecord
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy

fabric_contract = pytest.importorskip("azazel_fabric.knowledge_context")

NOW = "2026-11-04T12:00:00Z"
SIGNING_KEY = SigningKey(bytes(range(32)))
PUBLIC_KEY = bytes(SIGNING_KEY.verify_key)
KEY_ID = "sha256:" + hashlib.sha256(PUBLIC_KEY).hexdigest()
POLICY = SanitizerPolicy.from_mapping({
    "version": "context-test-1",
    "remote_default": "deny",
    "classes": {
        "P0-public": {"remote": "allow", "fields": ["indicator"]},
        "P1-sanitized": {"remote": "allow", "fields": ["indicator"]},
    },
    "aliases": [],
    "redactions": ["secret"],
    "limits": {"max_bytes": 2048},
})


def request(privacy=PrivacyClass.P0_PUBLIC, *, requested_at=NOW):
    return make_request(
        {"indicator": "203.0.113.9", "secret": "must-not-leave"},
        privacy_class=privacy,
        policy=POLICY,
        mission="unit-test",
        alias_key=b"test-only",
        requested_at=requested_at,
    )


def commissioned_registry():
    endpoint = ProviderRecord(
        provider_id="knowledge-node-1",
        host="knowledge.example.test",
        port=443,
        path_template="/knowledge/v1",
        certificate_pin="sha256:" + "a" * 64,
        client_identity="knowledge-client",
        model_id="knowledge-v1",
        max_request_bytes=4096,
        max_response_bytes=8192,
        deadline_seconds=5,
        allowed_privacy_classes=(PrivacyClass.P0_PUBLIC,),
    )
    peer = KnowledgePeer(
        endpoint=endpoint, addresses=("127.0.0.1",),
        public_key=PUBLIC_KEY, max_inflight=1,
    )
    return KnowledgeRegistry(
        commissioning_digest="sha256:" + "b" * 64,
        peers={endpoint.provider_id: peer},
        issued_at="2026-11-04T11:00:00Z",
        expires_at="2026-11-04T13:00:00Z",
        version=1,
    )


def response_payload(req):
    return {
        "schema_version": "knowledge-context-response/v1",
        "request_id": req.request_id,
        "correlation_id": req.correlation_id,
        "source_product": req.source_product,
        "source_ref": req.source_ref,
        "provider_id": "knowledge-node-1",
        "snapshot": {
            "ref": "snapshot:2026-11-04T11:59Z",
            "state": "complete",
            "as_of": "2026-11-04T11:59:00Z",
        },
        "facts": [{
            "claim_class": "source_reported_fact",
            "fact_id": "fact-1",
            "subject": {"entity_type": "indicator", "value": "203.0.113.9"},
            "predicate": "listed_by",
            "value": "Example feed reported this address",
            "provenance": ["feed:example"],
        }],
        "inferences": [],
        "unknowns": [],
        "limitations": ["fixture data"],
        "generated_at": NOW,
        "expires_at": "2026-11-04T12:05:00Z",
        "authority": "advisory_only",
    }


def signed(doc, *, key_id=KEY_ID, issued_at=NOW, expires_at="2026-11-04T12:05:00Z"):
    envelope = {
        "schema": ENVELOPE_SCHEMA,
        "key_id": key_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "payload": doc,
    }
    body = canonical_signed_payload(envelope)
    return SIGNING_KEY.sign(ENVELOPE_DOMAIN + body).signature + body


def verify(raw, req=None, **kwargs):
    req = req or request()
    return read_signed_response(
        raw,
        request=req,
        registry=commissioned_registry(),
        peer_id="knowledge-node-1",
        now=NOW,
        max_ttl_seconds=300,
        **kwargs,
    )


def test_request_is_p0_sanitized_and_uses_shared_fabric_type():
    req = request()
    assert type(req) is fabric_contract.KnowledgeContextRequestV1
    assert [(e.entity_type, e.value) for e in req.entities] == [
        ("indicator", "203.0.113.9")
    ]
    assert "must-not-leave" not in req.model_dump_json()
    assert re.fullmatch(r"[a-f0-9]{32}", req.request_id)
    assert re.fullmatch(r"[a-f0-9]{32}", req.correlation_id)
    assert req.source_ref == "nexus:full-node-context-query"
    assert "unit-test-0001" not in req.model_dump_json()


def test_p1_is_refused_even_when_local_policy_allows_it():
    with pytest.raises(KnowledgeContextRefused, match="only P0-public"):
        request(PrivacyClass.P1_SANITIZED)


def test_signed_response_is_fabric_valid_correlated_and_advisory():
    req = request()
    parsed = verify(signed(response_payload(req)), req)
    assert type(parsed) is fabric_contract.KnowledgeContextResponseV1
    assert parsed.authority == "advisory_only"
    assert parsed.facts[0].claim_class == "source_reported_fact"


def test_signed_response_provider_id_matches_commissioned_peer():
    req = request()
    doc = response_payload(req)
    doc["provider_id"] = "another-knowledge-peer"

    with pytest.raises(KnowledgeContextRefused):
        verify(signed(doc), req)


@pytest.mark.parametrize(
    "changes",
    [
        {"key_id": "uncommissioned-key"},
        {"issued_at": "2026-11-04T12:01:00Z"},
        {"expires_at": "2026-11-04T12:06:00Z"},
    ],
)
def test_unknown_key_future_issue_and_ttl_extension_are_refused(changes):
    req = request()
    envelope = {
        "schema": ENVELOPE_SCHEMA,
        "key_id": KEY_ID,
        "issued_at": NOW,
        "expires_at": "2026-11-04T12:05:00Z",
        "payload": response_payload(req),
    }
    envelope.update(changes)
    body = canonical_signed_payload(envelope)
    raw = SIGNING_KEY.sign(ENVELOPE_DOMAIN + body).signature + body
    with pytest.raises(KnowledgeContextRefused):
        verify(raw, req)


def test_bad_signature_expiry_and_wrong_request_binding_are_refused():
    req = request()
    raw = signed(response_payload(req))
    with pytest.raises(KnowledgeContextRefused):
        verify(b"x" * 64 + raw[64:], req)

    doc = response_payload(req)
    doc["request_id"] = "somebody-elses-request"
    with pytest.raises(KnowledgeContextRefused):
        verify(signed(doc), req)

    with pytest.raises(KnowledgeContextRefused):
        verify(signed(response_payload(req), expires_at="2026-11-04T11:59:59Z"), req)


def test_missing_commissioned_key_map_and_ttl_are_refused():
    req = request()
    raw = signed(response_payload(req))
    with pytest.raises(KnowledgeContextRefused):
        read_signed_response(raw, request=req, registry=None,
                             peer_id="knowledge-node-1", now=NOW,
                             max_ttl_seconds=300)
    with pytest.raises(KnowledgeContextRefused):
        read_signed_response(raw, request=req, registry=commissioned_registry(),
                             peer_id="knowledge-node-1", now=NOW,
                             max_ttl_seconds=0)


def test_semantic_expiry_cannot_outlive_signed_envelope():
    req = request()
    doc = response_payload(req)
    doc["expires_at"] = "2026-11-04T12:05:00Z"
    with pytest.raises(KnowledgeContextRefused):
        verify(signed(doc, expires_at="2026-11-04T12:04:00Z"), req)


def test_stale_semantic_response_refused_inside_fresh_signed_envelope():
    req = request(requested_at="2026-11-04T11:00:00Z")
    doc = response_payload(req)
    doc["snapshot"]["as_of"] = "2026-11-04T11:54:00Z"
    doc["generated_at"] = "2026-11-04T11:55:00Z"
    doc["expires_at"] = "2026-11-04T11:59:30Z"
    with pytest.raises(KnowledgeContextRefused):
        verify(signed(
            doc, issued_at="2026-11-04T11:59:00Z",
            expires_at="2026-11-04T12:04:00Z",
        ), req)
