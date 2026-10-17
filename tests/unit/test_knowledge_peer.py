"""Signed Knowledge decisions and loopback integration; test keys only."""

from __future__ import annotations

import copy
import json
import time
from dataclasses import replace

import pytest
from azazel_nexus_runtime.knowledge_egress import KnowledgeClient
from nacl.signing import SigningKey
from test_inference_egress import PINS, Server, answer, material

from azazel_nexus.knowledge_peer import (
    CAPABILITY_DOMAIN,
    REGISTRY_DOMAIN,
    RESPONSE_DOMAIN,
    SCHEMA,
    KnowledgeRefused,
    canonical,
    load_registry,
    prepare_query,
)
from azazel_nexus.lite_service import LiteReading, LiteState
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy

REGISTRY_KEY = SigningKey(bytes(range(32)))
PEER_KEY = SigningKey(bytes(range(32, 64)))
NOW = "2026-10-18T00:00:00Z"
ISSUED = "2026-10-17T00:00:00Z"
EXPIRES = "2026-10-19T00:00:00Z"
EMPTY = LiteReading(LiteState.UNAVAILABLE, "no cache")
CACHE = LiteReading(
    LiteState.AVAILABLE,
    "verified",
    artifact_digest="sha256:cache",
    served=({"id": "attack-T1059"},),
)
POLICY = SanitizerPolicy.from_mapping(
    {
        "version": "knowledge-test-1",
        "remote_default": "deny",
        "classes": {
            "P1-sanitized": {"remote": "allow", "fields": ["indicator", "subject"]}
        },
        "aliases": ["subject"],
        "redactions": ["secret"],
        "limits": {"max_bytes": 2048},
    }
)


def signed(doc, domain, key=PEER_KEY):
    return key.sign(domain + canonical(doc)).signature + canonical(doc)


def registry_doc(port=443):
    return {
        "schema": SCHEMA,
        "commissioning_digest": "test-commissioning",
        "issued_at": ISSUED,
        "expires_at": EXPIRES,
        "version": 1,
        "peers": [
            {
                "endpoint": {
                    "provider_id": "az04-test",
                    "host": "fetch.azazel.test",
                    "port": port,
                    "path_template": "/knowledge/v1",
                    "model_id": "knowledge-v1",
                    "certificate_pin": PINS["server-fetch"],
                    "client_identity": "knowledge-test",
                    "max_request_bytes": 4096,
                    "max_response_bytes": 8192,
                    "deadline_seconds": 1,
                    "allowed_privacy_classes": ["P1-sanitized"],
                },
                "addresses": ["127.0.0.1"],
                "public_key": bytes(PEER_KEY.verify_key).hex(),
                "max_inflight": 1,
            }
        ],
    }


def commissioned(doc=None, raw=None):
    return load_registry(
        raw
        if raw is not None
        else signed(doc or registry_doc(), REGISTRY_DOMAIN, REGISTRY_KEY),
        keys={"knowledge-registry": bytes(REGISTRY_KEY.verify_key)},
        commissioning_digest="test-commissioning",
        now=NOW,
    )


def client(registry, identity="client"):
    return KnowledgeClient(
        registry=registry,
        peer_id="az04-test",
        ca_certificate=material("trusted-ca.crt"),
        identities={
            "knowledge-test": (material(f"{identity}.crt"), material(f"{identity}.key"))
        },
        utc_now=lambda: NOW,
    )


def retrieve(transport, **overrides):
    args = {
        "local": EMPTY,
        "frame": {
            "indicator": "test-ioc",
            "subject": "sensitive-subject",
            "secret": "raw-secret",
        },
        "privacy_class": PrivacyClass.P1_SANITIZED,
        "policy": POLICY,
        "mission": "test-mission",
        "alias_key": b"test-only",
    }
    args.update(overrides)
    return transport.retrieve(**args)


class PeerServer(Server):
    def _serve(self):
        for _ in range(2):
            super()._serve()


def peer_server(mode="ok", **kwargs):
    def responder(stream, frame):
        request = json.loads(frame)
        common = {
            "schema": SCHEMA,
            "peer_id": "az04-test",
            "correlation": request["correlation"],
            "issued_at": ISSUED,
            "expires_at": EXPIRES,
        }
        capability = "query" not in request
        doc = dict(common)
        if capability:
            doc.update(versions=[1], capabilities=["advisory-context"])
        else:
            doc.update(
                bundle_version="fixture-1",
                facts=["observed IOC reference"],
                inferences=["Consider investigation; advisory only"],
            )
        if mode == "timeout":
            time.sleep(1.1)
            return
        if mode == "bad-version" and capability:
            doc["versions"] = [2]
        if mode == "expired" and not capability:
            doc["expires_at"] = ISSUED
        if mode == "schema" and not capability:
            doc["schema"] = "unknown/2"
        if mode == "malformed" and not capability:
            doc["facts"] = {"action": "execute"}
        if mode == "action" and not capability:
            doc["action"] = {"execute": "forbidden"}
        if mode == "correlation" and not capability:
            doc["correlation"] = "0" * 32
        body = signed(doc, CAPABILITY_DOMAIN if capability else RESPONSE_DOMAIN)
        if mode == "bad-signature" and not capability:
            body = b"x" * 64 + body[64:]
        if mode == "cap-signature" and capability:
            body = b"x" * 64 + body[64:]
        if mode == "oversize" and not capability:
            body = b"x" * 8193
        if mode == "truncated" and not capability:
            stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 8000\r\n\r\nshort")
            return
        if mode == "json" and not capability:
            body = PEER_KEY.sign(RESPONSE_DOMAIN + b"{" * 100).signature + b"{" * 100
        answer(body, status=302 if mode == "redirect" else 200)(stream, frame)

    return PeerServer(
        responder=responder,
        certificate=kwargs.pop("certificate", "server-fetch"),
        **kwargs,
    )


def test_empty_default_and_local_first_open_no_connection(monkeypatch):
    from azazel_nexus_runtime import knowledge_egress

    def forbidden(*args, **kwargs):
        pytest.fail("network used for local/default path")

    monkeypatch.setattr(knowledge_egress.socket, "socket", forbidden)
    absent = client(None)
    reading = retrieve(absent)
    assert reading.source_class == "no-context"
    assert reading.reason == "no module endpoint is configured on this node"
    assert retrieve(absent, local=CACHE).source_class == "embedded cache"
    assert (
        retrieve(client(commissioned()), local=CACHE).source_class == "embedded cache"
    )


@pytest.mark.parametrize(
    "privacy", [PrivacyClass.P2_MISSION, PrivacyClass.P3_RESTRICTED, None]
)
def test_privacy_denies_before_capability_traffic(privacy, monkeypatch):
    transport = client(commissioned())
    monkeypatch.setattr(
        transport, "_post", lambda *a: pytest.fail("denied data reached transport")
    )
    assert retrieve(transport, privacy_class=privacy).source_class == "no-context"


def test_sanitizer_and_request_budget_deny_before_connection(monkeypatch):
    transport = client(commissioned())
    monkeypatch.setattr(
        transport,
        "_post",
        lambda *a: pytest.fail("sanitizer denied frame reached transport"),
    )
    assert retrieve(transport, frame={"unlisted": "raw"}).source_class == "no-context"
    assert (
        retrieve(transport, frame={"indicator": "x" * 4000}).source_class
        == "no-context"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "expiry",
        "commissioning",
        "signature-role",
        "version",
        "address",
        "pin",
        "path",
        "class",
        "queue",
        "shared-key",
        "deadline",
        "duplicate",
    ],
)
def test_registry_failures(mutation):
    doc = registry_doc()
    entry = doc["peers"][0]
    endpoint = entry["endpoint"]
    if mutation == "expiry":
        doc["expires_at"] = NOW
    elif mutation == "commissioning":
        doc["commissioning_digest"] = "elsewhere"
    elif mutation == "version":
        doc["version"] = True
    elif mutation == "address":
        entry["addresses"] = ["arbitrary.example"]
    elif mutation == "pin":
        endpoint["certificate_pin"] = ""
    elif mutation == "path":
        endpoint["path_template"] = "/knowledge/v1\r\nInjected: true"
    elif mutation == "class":
        endpoint["allowed_privacy_classes"] = ["P2-mission"]
    elif mutation == "queue":
        entry["max_inflight"] = 100
    elif mutation == "shared-key":
        entry["public_key"] = bytes(REGISTRY_KEY.verify_key).hex()
    elif mutation == "deadline":
        endpoint["deadline_seconds"] = 999
    elif mutation == "duplicate":
        doc["peers"].append(copy.deepcopy(entry))
    raw = signed(
        doc,
        CAPABILITY_DOMAIN if mutation == "signature-role" else REGISTRY_DOMAIN,
        REGISTRY_KEY,
    )
    with pytest.raises(KnowledgeRefused):
        commissioned(raw=raw)


def test_unknown_symbol_and_expired_registry():
    registry = commissioned()
    with pytest.raises(KnowledgeRefused):
        registry.resolve("https://arbitrary.test", now=NOW)
    with pytest.raises(KnowledgeRefused):
        registry.resolve("az04-test", now=EXPIRES)


def test_queue_full_is_immediate_local_fallback(monkeypatch):
    transport = client(commissioned())
    assert transport.slots.acquire(False)
    monkeypatch.setattr(
        transport, "_post", lambda *a: pytest.fail("queue overflow reached transport")
    )
    try:
        result = retrieve(transport, local=CACHE, deeper=True)
        assert result.source_class == "embedded cache"
        assert result.reason == "knowledge queue full"
    finally:
        transport.slots.release()


def test_outer_request_budget_includes_envelope():
    registry = commissioned()
    peer = registry.resolve("az04-test", now=NOW)
    peer = replace(peer, endpoint=replace(peer.endpoint, max_request_bytes=100))
    with pytest.raises(KnowledgeRefused):
        prepare_query(
            peer,
            frame={"indicator": "test"},
            privacy_class=PrivacyClass.P1_SANITIZED,
            policy=POLICY,
            mission="m",
            alias_key=b"test",
            correlation="a" * 32,
        )


def test_loopback_all_three_states_and_sensitive_data_absence():
    server = peer_server()
    try:
        transport = client(commissioned(registry_doc(server.port)))
        full = retrieve(transport, local=CACHE, deeper=True)
        assert full.source_class == "full-node context"
        assert full.peer_context.facts == ("observed IOC reference",)
        assert full.peer_context.inferences == (
            "Consider investigation; advisory only",
        )
        assert full.asset_version == "fixture-1" and full.trust == "verified"
        assert len(server.requests) == 2 and all(server.peer_certificates)
        assert server.requests[0][0].startswith("POST /knowledge/v1/capabilities ")
        assert server.requests[1][0].startswith("POST /knowledge/v1/query ")
        transmitted = b"".join(body for _, body in server.requests)
        assert (
            b"raw-secret" not in transmitted and b"sensitive-subject" not in transmitted
        )
        assert b"test-mission" not in transmitted and b"alias:" in transmitted
        assert "query" not in json.loads(server.requests[0][1])
        event = full.as_event()
        assert event["correlation"] == full.peer_context.correlation
        assert "IOC" not in json.dumps(event)
        cached = retrieve(client(None), local=CACHE)
        unavailable = retrieve(client(None))
        assert [r.source_class for r in (full, cached, unavailable)] == [
            "full-node context",
            "embedded cache",
            "no-context",
        ]
        assert all(not r.blocks_core() for r in (full, cached, unavailable))
        # The three supplier words are not inputs to the Edge execution API.
        from test_core_lite_integration import cognition

        from azazel_nexus.capability import CapabilityState
        from azazel_nexus.integration import EdgePresence, build_view

        views = [
            build_view(
                capability=CapabilityState.CORE,
                knowledge=CACHE if r is not unavailable else EMPTY,
                cognition=cognition(),
                decoy=None,
                edge=EdgePresence.ABSENT,
                knowledge_peer=r is full,
            )
            for r in (full, cached, unavailable)
        ]
        assert (
            len({(v.enforcement_capable, v.baseline_ready, v.edge) for v in views}) == 1
        )
    finally:
        server.close()


@pytest.mark.parametrize(
    "mode",
    [
        "bad-signature",
        "cap-signature",
        "bad-version",
        "expired",
        "schema",
        "malformed",
        "action",
        "correlation",
        "oversize",
        "truncated",
        "json",
        "redirect",
        "timeout",
    ],
)
@pytest.mark.parametrize("local", [CACHE, EMPTY], ids=["cache", "no-context"])
def test_loopback_fail_closed(mode, local):
    server = peer_server(mode)
    try:
        transport = client(commissioned(registry_doc(server.port)))
        start = time.monotonic()
        reading = retrieve(transport, local=local, deeper=True)
        assert reading.source_class == (
            "embedded cache" if local is CACHE else "no-context"
        )
        assert not reading.blocks_core() and reading.peer_context is None
        assert time.monotonic() - start < 2
        if mode in {"cap-signature", "bad-version", "redirect", "timeout"}:
            assert len(server.requests) == 1  # No query and no retry.
    finally:
        server.close()


@pytest.mark.parametrize(
    "failure", ["client", "pin", "hostname", "issuer", "expired", "address"]
)
def test_loopback_tls_and_allowlist_fail_closed(failure):
    certificate = {
        "hostname": "server-wrong-name",
        "issuer": "server-untrusted-ca",
        "expired": "server-expired",
    }.get(failure, "server-fetch")
    server = peer_server(certificate=certificate)
    try:
        doc = registry_doc(server.port)
        if failure == "pin":
            doc["peers"][0]["endpoint"]["certificate_pin"] = PINS["server"]
        if failure == "address":
            doc["peers"][0]["addresses"] = ["127.0.0.2"]
        result = retrieve(
            client(
                commissioned(doc),
                "client-untrusted" if failure == "client" else "client",
            )
        )
        assert result.source_class == "no-context"
        assert server.requests == []
    finally:
        server.close()


@pytest.mark.parametrize("kind", ["capability", "response"])
@pytest.mark.parametrize(
    "mutation",
    [
        "ok",
        "signature",
        "expired",
        "future",
        "offset",
        "naive",
        "schema",
        "correlation",
        "unknown",
        "structure",
    ],
)
def test_signed_protocol_decisions_without_transport(kind, mutation):
    from azazel_nexus.knowledge_peer import negotiate, read_context

    peer = commissioned().resolve("az04-test", now=NOW)
    doc = {
        "schema": SCHEMA,
        "peer_id": "az04-test",
        "correlation": "c" * 32,
        "issued_at": ISSUED,
        "expires_at": EXPIRES,
    }
    if kind == "capability":
        doc.update(versions=[1], capabilities=["advisory-context"])
        domain, reader = CAPABILITY_DOMAIN, negotiate
    else:
        doc.update(bundle_version="test-1", facts=["reference"], inferences=["advice"])
        domain, reader = RESPONSE_DOMAIN, read_context
    if mutation == "expired":
        doc["expires_at"] = NOW
    elif mutation == "future":
        doc["issued_at"] = EXPIRES
    elif mutation == "offset":
        # Equivalent expiry instant, using an offset, must still be expired.
        doc["expires_at"] = "2026-10-18T09:00:00+09:00"
    elif mutation == "naive":
        doc["expires_at"] = "2026-10-19T00:00:00"
    elif mutation == "schema":
        doc["schema"] = "unknown"
    elif mutation == "correlation":
        doc["correlation"] = "d" * 32
    elif mutation == "unknown":
        doc["action"] = "execute"
    elif mutation == "structure":
        doc["versions" if kind == "capability" else "facts"] = {}
    raw = signed(doc, domain)
    if mutation == "signature":
        raw = b"x" * 64 + raw[64:]
    if mutation == "ok":
        context = reader(raw, peer=peer, correlation="c" * 32, now=NOW)
        if context:
            assert context.facts == ("reference",) and context.inferences == ("advice",)
    else:
        with pytest.raises(KnowledgeRefused):
            reader(raw, peer=peer, correlation="c" * 32, now=NOW)


def test_three_supply_states_never_move_edge_authority():
    from test_core_lite_integration import cognition

    from azazel_nexus.capability import CapabilityState
    from azazel_nexus.integration import EdgePresence, build_view
    from azazel_nexus.knowledge_peer import PeerContext
    from azazel_nexus.lite_service import knowledge_context

    context = PeerContext(
        "az04-test", "fixture-1", EXPIRES, "a" * 32, ("fact",), ("advice",)
    )
    readings = [
        knowledge_context(CACHE, correlation="a" * 32, peer=context),
        knowledge_context(CACHE, correlation="b" * 32),
        knowledge_context(EMPTY, correlation="c" * 32),
    ]
    assert [r.source_class for r in readings] == [
        "full-node context",
        "embedded cache",
        "no-context",
    ]
    views = [
        build_view(
            capability=CapabilityState.CORE,
            knowledge=CACHE if r.embedded_claims else EMPTY,
            cognition=cognition(),
            decoy=None,
            edge=EdgePresence.ABSENT,
            knowledge_peer=r.peer_context is not None,
        )
        for r in readings
    ]
    assert len({(v.enforcement_capable, v.baseline_ready, v.edge) for v in views}) == 1
    assert all(not r.blocks_core() for r in readings)
    assert all(
        set(r.as_event())
        == {
            "event_type",
            "source_class",
            "correlation",
            "reason",
            "asset_version",
            "freshness",
            "trust",
        }
        for r in readings
    )


def test_registry_expiry_rechecked_at_runtime(monkeypatch):
    transport = client(commissioned())
    transport.utc_now = lambda: EXPIRES
    monkeypatch.setattr(
        transport, "_post", lambda *a: pytest.fail("expired registry used")
    )
    assert retrieve(transport).source_class == "no-context"


@pytest.mark.parametrize("bad_capability", [False, True])
def test_runtime_signed_exchange_without_network(monkeypatch, bad_capability):
    """Exercise runtime orchestration; does not claim mTLS/loopback evidence."""
    transport = client(commissioned())
    calls = []

    def exchange(peer, suffix, body, deadline):
        request = json.loads(body)
        calls.append(suffix)
        doc = {
            "schema": SCHEMA,
            "peer_id": peer.endpoint.provider_id,
            "correlation": request["correlation"],
            "issued_at": ISSUED,
            "expires_at": EXPIRES,
        }
        if suffix == "/capabilities":
            doc.update(
                versions=[True] if bad_capability else [1],
                capabilities=["advisory-context"],
            )
            return signed(doc, CAPABILITY_DOMAIN)
        doc.update(
            bundle_version="test-1", facts=["fact"], inferences=["recommendation"]
        )
        return signed(doc, RESPONSE_DOMAIN)

    monkeypatch.setattr(transport, "_post", exchange)
    reading = retrieve(transport, local=CACHE, deeper=True)
    assert reading.source_class == (
        "embedded cache" if bad_capability else "full-node context"
    )
    assert calls == (
        ["/capabilities"] if bad_capability else ["/capabilities", "/query"]
    )
