"""Isolated acceptance matrix for the ordinary Knowledge Context path (#395, #439).

One in-process chain per case, all synthetic and loopback only:

    synthetic Knowledge producer (loopback mTLS, test-only PKI and Ed25519 key)
      <- KnowledgeClient.request_context (commissioned registry, P0 sanitizer)
      <- KnowledgeContextBroker.handle (one in flight, fixed refusals, audit)
      <- mio_locald.LocalRuntimeService.handle(FAST_ASSESS)   (ordinary entry)

Until #439 the ordinary entry forwarded a caller-classified free-form P0
`question` to the broker and adopted the answer as advice. Now the model host
is no broker client and the broker refuses every free-form question before
sending. This matrix keeps the commissioned producer of the old cases, so a
refusal is shown against a chain that would otherwise have answered: whatever
the producer would do, it receives nothing. The observation-origin technique
form is covered by `test_technique_knowledge_path.py` and the real-process
runner. Nothing here connects outside 127.0.0.1, loads a production
credential, or enables a service.
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

from azazel_nexus.knowledge_peer import KnowledgePeer, KnowledgeRegistry
from azazel_nexus.provider_registry import ProviderRecord
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy
from azazel_nexus_runtime import knowledge_context_socket, mio_locald
from azazel_nexus_runtime.knowledge_context_socket import KnowledgeContextUnavailable
from stop_helpers import granted_marker
from azazel_nexus_runtime.knowledge_contextd import CONTEXT_VERB, KnowledgeContextBroker
from azazel_nexus_runtime.knowledge_egress import KnowledgeClient

import test_knowledge_context_transport as T
from test_inference_egress import Server
from test_knowledge_contextd import OPEN_GATE

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


class Chain:
    """One commissioned-in-test chain; counts producer calls and audit events."""

    def __init__(self, monkeypatch, mode: str, *, question: str = QUESTION,
                 caller_deadline_ms: int = 4000):
        self.audit: list[dict] = []
        self.reached = threading.Event()
        self.server = None
        port = 1  # nothing listens here: "producer-absent"

        def respond(stream, body):
            self.reached.set()
            if mode == "timeout":
                time.sleep(2.5)
                return
            stream.sendall(_http("500 Internal Server Error", b"PRODUCER-ERROR-TEXT"))

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
        self.broker = KnowledgeContextBroker(**OPEN_GATE, grant_marker=granted_marker,
            client=client, policy=POLICY, mission="acceptance", alias_key=b"k" * 32,
            enabled=True, audit=self.audit.append)
        self.broker_calls = []

        def request_context(frame, *, deadline_s):
            """Same contract as the AF_UNIX client: response dict or Unavailable."""
            self.broker_calls.append(frame)
            raise KnowledgeContextUnavailable("not reached from the model host")

        # Wherever the model host might still reach for the socket client.
        monkeypatch.setattr(knowledge_context_socket, "request_context", request_context)
        lane = SimpleNamespace(submit=lambda *a, **k: {"state": "closed", "usage": "unknown"})
        service = mio_locald.LocalRuntimeService(generation_lane=lane)
        frame = {"request_id": "acceptance", "privacy_class": "P0-public",
                 "question": question, "context": []}
        try:
            self.reply = service.handle(SimpleNamespace(
                verb=mio_locald.FAST_ASSESS_VERB, payload=frame,
                arguments={"deadline_ms": caller_deadline_ms}))
            # The same question, sent to the commissioned broker directly.
            now = time.monotonic()
            self.direct = self.broker.handle(SimpleNamespace(
                verb=CONTEXT_VERB,
                arguments={"deadline_ms": 2000,
                           "deadline_monotonic_ns": int((now + 2.0) * 1e9)},
                payload={"frame": {"privacy_class": "P0-public", "question": question}}))
        finally:
            self.producer_requests = len(self.server.requests) if self.server else 0
            if self.server is not None:
                self.server.close()
        self.fast = self.reply["fast_assistance"]

    def everything(self) -> str:
        return json.dumps([self.reply, self.direct, self.audit], sort_keys=True, default=str)


MODES = ["valid", "timeout", "http-500", "producer-absent"]


@pytest.mark.parametrize("mode", MODES)
def test_a_free_form_question_never_reaches_the_producer(monkeypatch, mode):
    chain = Chain(monkeypatch, mode)
    # The ordinary entry does not ask: the model host is no broker client.
    assert chain.broker_calls == []
    assert chain.reply["outcome"] == "assessed"
    assert chain.fast["full_node_context_status"] == "not_queried"
    assert "fabric_knowledge_context_advisory" not in chain.fast
    # The commissioned broker refuses the question before sending.
    assert chain.direct == {"refusal": "unavailable"}
    assert chain.producer_requests == 0 and not chain.reached.is_set()
    assert [e["event_type"] for e in chain.audit] == ["knowledge.context.completed"]
    assert chain.audit[-1]["reason_code"] == "refused_before_send"
    assert QUESTION not in json.dumps(chain.audit)
    assert "PRODUCER-ERROR-TEXT" not in chain.everything()


def test_the_old_observation_sentence_is_refused_too(monkeypatch):
    chain = Chain(monkeypatch, "valid", question="ATT&CK technique context: T1059")
    assert chain.direct == {"refusal": "unavailable"}
    assert chain.producer_requests == 0 and chain.broker_calls == []
    assert chain.audit[-1]["reason_code"] == "refused_before_send"


def test_non_p0_and_disabled_paths_never_query_the_producer(monkeypatch):
    calls = []
    monkeypatch.setattr(knowledge_context_socket, "request_context",
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
    closed = KnowledgeContextBroker(**OPEN_GATE, grant_marker=granted_marker, audit=lambda e: None)
    for frame in ({"privacy_class": "P0-public", "question": "q"},
                  {"privacy_class": "P0-public", "techniques": ["T1059"]}):
        out = closed.handle(SimpleNamespace(
            verb=CONTEXT_VERB, arguments={"deadline_ms": 500,
                                          "deadline_monotonic_ns": int((time.monotonic() + .5) * 1e9)},
            payload={"frame": frame}))
        assert out["refusal"] == "unavailable" and "response" not in out
