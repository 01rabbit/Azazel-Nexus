"""Isolated acceptance matrix for the ordinary Knowledge Context path (#395).

One in-process chain per case, all synthetic and loopback only:

    synthetic Knowledge producer (loopback mTLS, test-only PKI and Ed25519 key)
      -> KnowledgeClient.request_context (commissioned registry, P0 sanitizer)
      -> KnowledgeContextBroker.handle (one in flight, fixed refusals, audit)
      -> mio_locald.LocalRuntimeService.handle(FAST_ASSESS)   (ordinary entry)
      -> fast_assistance result -> operator projection (stored/handoff shape)

The AF_UNIX hop between locald and the broker is replaced by a direct call
because it needs Linux peer credentials; that hop is covered by the isolated
real-process runner. Nothing here connects outside 127.0.0.1, loads a
production credential, or enables a service.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

pytest.importorskip("azazel_fabric.knowledge_context")
pytest.importorskip("azazel_mio", reason="M.I.O. is an optional runtime extra")

from azazel_nexus import incident_explain
from azazel_nexus.knowledge_context_adapter import ENVELOPE_DOMAIN, ENVELOPE_SCHEMA, canonical_signed_payload
from azazel_nexus.knowledge_peer import KnowledgePeer, KnowledgeRegistry
from azazel_nexus.provider_registry import ProviderRecord
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy
from azazel_nexus_runtime import mio_locald
from azazel_nexus_runtime.knowledge_context_socket import KnowledgeContextUnavailable
from azazel_nexus_runtime.knowledge_contextd import CONTEXT_VERB, KnowledgeContextBroker
from azazel_nexus_runtime.knowledge_egress import KnowledgeClient

import test_knowledge_context_transport as T
from test_inference_egress import Server

PRODUCER_PROSE = "PRODUCER-LIMITATION-PROSE-MUST-STAY-WITHHELD"
PRODUCER_VALUE = "PRODUCER-FACT-VALUE-MUST-STAY-WITHHELD"
QUESTION = "synthetic public observation context"

POLICY = SanitizerPolicy.from_mapping({
    "version": "knowledge-context-acceptance-1",
    "remote_default": "deny",
    "classes": {"P0-public": {"remote": "allow", "fields": ["question"]}},
    "aliases": [],
    "redactions": [],
    "limits": {"max_bytes": 4096},
})


def _ts(offset_s: float = 0.0) -> str:
    # MIO judges freshness against the real clock, so every time is relative.
    moment = datetime.now(UTC) + timedelta(seconds=offset_s)
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def _registry(port: int) -> KnowledgeRegistry:
    endpoint = ProviderRecord(
        provider_id="knowledge-node-1", host="fetch.azazel.test", port=port,
        path_template="/knowledge/v1", certificate_pin=T.PINS["server-fetch"],
        client_identity="knowledge-test", model_id="knowledge-v1",
        max_request_bytes=4096, max_response_bytes=8192, deadline_seconds=3,
        allowed_privacy_classes=(PrivacyClass.P0_PUBLIC,))
    peer = KnowledgePeer(endpoint=endpoint, addresses=("127.0.0.1",),
                         public_key=T.PUBLIC_KEY, max_inflight=1)
    return KnowledgeRegistry(
        commissioning_digest="sha256:" + "a" * 64, peers={endpoint.provider_id: peer},
        issued_at=_ts(-3600), expires_at=_ts(3600), version=1)


def _answer(body: bytes, mode: str) -> bytes:
    """Signed envelope for the exact request body, or a defect named by mode."""
    contract = T._contract()
    request = contract.KnowledgeContextRequestV1.model_validate_json(body)
    response = {
        "schema_version": contract.RESPONSE_SCHEMA_VERSION,
        "request_id": request.request_id,
        "correlation_id": request.correlation_id,
        "source_product": request.source_product,
        "source_ref": request.source_ref,
        "provider_id": "knowledge-node-1",
        "snapshot": {"ref": "snapshot:synthetic-1", "state": "partial", "as_of": _ts()},
        "facts": [],
        "inferences": [],
        "unknowns": [PRODUCER_VALUE],
        "limitations": [PRODUCER_PROSE],
        "generated_at": _ts(),
        "expires_at": _ts(60),
        "authority": "advisory_only",
    }
    if mode == "wrong-request":
        response["request_id"] = "another-request"
    if mode == "wrong-provider":
        response["provider_id"] = "some-other-node"
    typed = contract.KnowledgeContextResponseV1.model_validate(response)
    envelope = {
        "schema": ENVELOPE_SCHEMA, "key_id": T.KEY_ID,
        "issued_at": _ts(), "expires_at": _ts(120),
        "payload": json.loads(contract.canonical_knowledge_context_bytes(typed)),
    }
    if mode == "expired":
        envelope["issued_at"], envelope["expires_at"] = _ts(-120), _ts(-60)
    if mode == "wrong-key":
        envelope["key_id"] = "sha256:" + "0" * 64
    canonical = canonical_signed_payload(envelope)
    signature = T.PEER_KEY.sign(ENVELOPE_DOMAIN + canonical).signature
    if mode == "bad-signature":
        signature = b"x" * 64
    if mode == "tampered-payload":
        canonical = canonical.replace(b"snapshot:synthetic-1", b"snapshot:synthetic-2")
    return signature + canonical


def _http(status: str, body: bytes) -> bytes:
    return (f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n").encode("ascii") + body


class Chain:
    """One commissioned-in-test chain; counts producer calls and audit events."""

    def __init__(self, monkeypatch, mode: str, *, replay: bytes | None = None,
                 question: str = QUESTION, caller_deadline_ms: int = 4000):
        self.audit: list[dict] = []
        self.answers: list[bytes] = []
        self.reached = threading.Event()
        self.server = None
        port = 1  # nothing listens here: "producer-absent"

        def respond(stream, body):
            self.reached.set()
            if mode == "timeout":
                time.sleep(2.5)
                return
            if mode == "http-500":
                stream.sendall(_http("500 Internal Server Error", b"PRODUCER-ERROR-TEXT"))
                return
            if mode == "garbage":
                stream.sendall(_http("200 OK", b"not an envelope"))
                return
            if mode == "oversize":
                stream.sendall(_http("200 OK", b"x" * 9000))
                return
            answer = replay if mode == "replay" else _answer(body, mode)
            self.answers.append(answer)
            stream.sendall(_http("200 OK", answer))

        if mode != "producer-absent":
            self.server = Server(responder=respond, certificate="server-fetch")
            port = self.server.port
        client = KnowledgeClient(
            registry=_registry(port),
            peer_id="knowledge-node-1",
            ca_certificate=T.material("trusted-ca.crt"),
            identities={"knowledge-test": (T.material("client.crt"), T.material("client.key"))},
            knowledge_context_enabled=True,
            knowledge_context_max_ttl_seconds=300,
            utc_now=_ts,
        )
        self.broker = KnowledgeContextBroker(
            client=client, policy=POLICY, mission="acceptance", alias_key=b"k" * 32,
            enabled=True, audit=self.audit.append)

        def request_context(frame, *, deadline_s):
            """Same contract as the AF_UNIX client: response dict or Unavailable."""
            now = time.monotonic()
            reply = self.broker.handle(SimpleNamespace(
                verb=CONTEXT_VERB,
                arguments={"deadline_ms": int(deadline_s * 1000),
                           "deadline_monotonic_ns": int((now + deadline_s) * 1e9)},
                payload={"frame": frame}))
            if "response" not in reply:
                raise KnowledgeContextUnavailable("broker refused")
            return reply["response"]

        monkeypatch.setattr(mio_locald, "request_context", request_context)
        if mode != "timeout":
            # Headroom so a loaded CI host cannot turn a handshake into a timeout;
            # the timeout case keeps the shipped 0.25 s budget.
            monkeypatch.setattr(mio_locald, "KNOWLEDGE_MAX_S", 2.0)
        lane = SimpleNamespace(submit=lambda *a, **k: {"state": "closed", "usage": "unknown"})
        service = mio_locald.LocalRuntimeService(generation_lane=lane)
        frame = {"request_id": "acceptance", "privacy_class": "P0-public",
                 "question": question, "context": []}
        try:
            self.reply = service.handle(SimpleNamespace(
                verb=mio_locald.FAST_ASSESS_VERB, payload=frame,
                arguments={"deadline_ms": caller_deadline_ms}))
        finally:
            self.producer_requests = len(self.server.requests) if self.server else 0
            if self.server is not None:
                self.server.close()
        self.fast = self.reply["fast_assistance"]
        self.projection = incident_explain._full_node_projection(
            self.fast.get("fabric_knowledge_context_advisory"),
            self.fast.get("full_node_context_status", "unknown"),
            self.fast["dependency_outcome"]["knowledge"])
        incident_explain._read_full_node_projection(self.projection)  # stored shape is valid

    def everything(self) -> str:
        return json.dumps([self.reply, self.projection, self.audit], sort_keys=True, default=str)


def _comparable(fast: dict) -> dict:
    """Result fields Knowledge must not change. Excluded: the Knowledge-context
    fields and the unknowns/next_checks/handoff prose that legitimately mention
    the context state, plus per-run random ids."""
    skip = {"fabric_knowledge_context_advisory", "full_node_context_status",
            "unknowns", "next_checks", "handoff", "trace",
            "trace_id", "frame_id", "reasoning_trace"}
    return {k: v for k, v in fast.items() if k not in skip}


def test_valid_response_reaches_ordinary_fast_assess_as_unverified_advice(monkeypatch):
    chain = Chain(monkeypatch, "valid")
    fast = chain.fast
    assert fast["full_node_context_status"] == "received"
    advisory = fast["fabric_knowledge_context_advisory"]
    assert advisory["authority"] == "advisory_only"
    assert advisory["claim_status"] == "source_reported_unverified"
    assert advisory["trust"] == "unverified_advisory_only"
    assert advisory["snapshot_state"] == "partial"
    # Source, freshness and limits survive into the stored/handoff shape.
    p = chain.projection
    assert p["full_node_context_status"] == "received" and p["outcome"] == "partial"
    assert p["source_kind"] == "fabric_knowledge_context_response_v1"
    assert p["generated_at"] and p["expires_at"] and p["limitations"]
    assert "KNOWLEDGE_CONTEXT_PARTIAL" in fast["unknowns"]
    assert incident_explain.FULL_NODE_INCOMPLETE_CHECK in fast["next_checks"]
    # Producer prose and values are not exported anywhere downstream.
    text = json.dumps([chain.projection, chain.audit], sort_keys=True)
    assert PRODUCER_PROSE not in text and PRODUCER_VALUE not in text
    # Audit records the attempt and verified completion without content.
    assert [e["event_type"] for e in chain.audit] == [
        "knowledge.context.requested", "knowledge.context.completed"]
    assert QUESTION not in json.dumps(chain.audit)
    # Exactly one producer request, carrying only the sanitized question.
    assert len(chain.answers) == 1


def test_knowledge_advice_does_not_change_local_decision_or_authority(monkeypatch):
    received = Chain(monkeypatch, "valid").fast
    refused = Chain(monkeypatch, "bad-signature").fast
    assert refused["full_node_context_status"] == "unavailable"
    assert _comparable(received) == _comparable(refused)
    assert received.get("executable", False) is False
    assert "executable" not in json.dumps(received["fabric_knowledge_context_advisory"])


REFUSALS = ["bad-signature", "tampered-payload", "expired", "wrong-key", "wrong-request",
            "wrong-provider", "http-500", "garbage", "oversize", "producer-absent"]


CRAFTED = {"bad-signature", "tampered-payload", "expired", "wrong-key",
           "wrong-request", "wrong-provider"}


@pytest.mark.parametrize("mode", REFUSALS)
def test_invalid_or_missing_response_degrades_without_advisory(monkeypatch, mode):
    chain = Chain(monkeypatch, mode)
    # Control: the request really reached the producer (or none existed), so
    # the refusal is of this defect and not of a broken setup. The same
    # _answer() with mode "valid" is accepted in the first test above.
    assert chain.producer_requests == (0 if mode == "producer-absent" else 1)
    if mode in CRAFTED:
        assert len(chain.answers) == 1
    assert chain.fast["full_node_context_status"] == "unavailable"
    assert "fabric_knowledge_context_advisory" not in chain.fast
    assert chain.projection["outcome"] == "unavailable"
    assert chain.projection["source_kind"] is None and chain.projection["limitations"] == []
    # Local FAST_ASSESS still completed; no producer text leaks anywhere.
    assert chain.reply["outcome"] == "assessed"
    for leaked in (PRODUCER_PROSE, PRODUCER_VALUE, "PRODUCER-ERROR-TEXT", "snapshot:synthetic"):
        assert leaked not in chain.everything()
    assert chain.audit[-1]["outcome"] in {"unavailable", "timeout"}


def test_slow_producer_is_cut_off_at_the_knowledge_budget(monkeypatch):
    """The request reached the producer and was abandoned at the deadline.

    Locald caps the Knowledge wait at KNOWLEDGE_MAX_S (0.25 s) inside the
    caller deadline, so the lower bound below is that cap, not the producer's
    2.5 s sleep.
    """
    started = time.monotonic()
    chain = Chain(monkeypatch, "timeout", caller_deadline_ms=1500)
    elapsed = time.monotonic() - started
    assert chain.reached.is_set() and chain.producer_requests == 1
    assert mio_locald.KNOWLEDGE_MAX_S * 0.8 <= elapsed < 2.0
    assert chain.audit[-1]["elapsed_ms"] >= mio_locald.KNOWLEDGE_MAX_S * 1000 * 0.8
    assert chain.fast["full_node_context_status"] == "unavailable"
    assert "fabric_knowledge_context_advisory" not in chain.fast
    assert chain.reply["outcome"] == "assessed"


def test_replayed_earlier_answer_is_not_adopted_for_a_new_request(monkeypatch):
    first = Chain(monkeypatch, "valid", question="first public question")
    assert first.fast["full_node_context_status"] == "received"
    # A fresh client and broker stand for a restart of those objects (a process restart is not reproduced here); no state is carried over. The
    # producer now replays the earlier, still-fresh, correctly signed answer.
    second = Chain(monkeypatch, "replay", replay=first.answers[0],
                   question="second public question")
    assert second.producer_requests == 1 and second.answers == first.answers
    assert second.fast["full_node_context_status"] == "unavailable"
    assert "fabric_knowledge_context_advisory" not in second.fast
    # And an honest answer afterwards is accepted again (no poisoned state).
    third = Chain(monkeypatch, "valid", question="third public question")
    assert third.fast["full_node_context_status"] == "received"


def test_non_p0_and_disabled_paths_never_query_the_producer(monkeypatch):
    calls = []
    monkeypatch.setattr(mio_locald, "request_context",
                        lambda *a, **k: calls.append(1) or pytest.fail("queried"))
    lane = SimpleNamespace(submit=lambda *a, **k: {"state": "closed", "usage": "unknown"})
    service = mio_locald.LocalRuntimeService(generation_lane=lane)
    reply = service.handle(SimpleNamespace(
        verb=mio_locald.FAST_ASSESS_VERB, arguments={"deadline_ms": 1000},
        payload={"request_id": "m", "privacy_class": "P2-mission", "question": "q", "context": []}))
    fast = reply["fast_assistance"]
    assert not calls and fast["full_node_context_status"] == "not_queried"
    assert "fabric_knowledge_context_advisory" not in fast
    # The shipped broker factory is closed: no client, no egress.
    closed = KnowledgeContextBroker(audit=lambda e: None)
    out = closed.handle(SimpleNamespace(
        verb=CONTEXT_VERB, arguments={"deadline_ms": 500,
                                      "deadline_monotonic_ns": int((time.monotonic() + .5) * 1e9)},
        payload={"frame": {"privacy_class": "P0-public", "question": "q"}}))
    assert out == {"refusal": "unavailable"}
