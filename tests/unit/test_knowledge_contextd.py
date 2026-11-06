"""Dedicated Knowledge egress broker remains P0 and closed by default."""

from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "runtime" / "src"))

from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy
from azazel_nexus_runtime.knowledge_contextd import (
    CONTEXT_VERB, MAX_RESPONSE_BYTES, KnowledgeContextBroker,
)
from azazel_nexus_runtime.knowledge_context_socket import (
    KnowledgeContextUnavailable, read_context_frame,
)
from azazel_nexus_runtime.mio_locald import _read_assessment_payload
from azazel_nexus.local_advisory import FrameRefused


def _policy():
    return SanitizerPolicy(version="synthetic-v1", allowed={}, redactions=frozenset(),
                           aliases=frozenset(), time_buckets=frozenset(),
                           count_buckets=frozenset(), max_bytes=4096)


def _request(payload=None, deadline_ms=500, deadline_monotonic_ns=None):
    if deadline_monotonic_ns is None:
        import time
        deadline_monotonic_ns = int((time.monotonic() + deadline_ms / 1000)
                                    * 1_000_000_000)
    return SimpleNamespace(verb=CONTEXT_VERB, arguments={
                               "deadline_ms": deadline_ms,
                               "deadline_monotonic_ns": deadline_monotonic_ns},
                           payload=payload or {"frame": {
                               "privacy_class": "P0-public", "question": "public question"}})


def test_uncommissioned_broker_refuses_and_does_not_call_a_peer():
    class Forbidden:
        def request_context(self, **kwargs):
            pytest.fail("disabled broker attempted Knowledge egress")

    events = []
    broker = KnowledgeContextBroker(client=Forbidden(), policy=_policy(),
                                    mission="lab", alias_key=b"x" * 32,
                                    audit=events.append)
    assert broker.handle(_request()) == {"refusal": "unavailable"}
    assert events[-1]["outcome"] == "unavailable"


def test_expired_queued_request_does_not_reach_knowledge():
    class Forbidden:
        def request_context(self, **kwargs):
            pytest.fail("expired request reached Knowledge")

    broker = KnowledgeContextBroker(
        client=Forbidden(), policy=_policy(), mission="lab", alias_key=b"x" * 32,
        enabled=True, monotonic=lambda: 20.0,
    )
    request = _request(deadline_ms=500, deadline_monotonic_ns=19_000_000_000)
    assert broker.handle(request) == {"refusal": "timeout"}


def test_audit_failure_prevents_knowledge_egress():
    calls = []

    class Client:
        def request_context(self, **kwargs):
            calls.append(kwargs)
            return {"authority": "advisory_only"}

    def broken_audit(_event):
        raise OSError("synthetic audit failure")

    broker = KnowledgeContextBroker(
        client=Client(), policy=_policy(), mission="lab", alias_key=b"x" * 32,
        enabled=True, audit=broken_audit,
    )
    assert broker.handle(_request()) == {"refusal": "unavailable"}
    assert calls == []


def test_missing_egress_account_degrades_to_unavailable(monkeypatch):
    from azazel_nexus_runtime import knowledge_context_socket

    def missing_account():
        raise KeyError("synthetic absent account")

    monkeypatch.setattr(knowledge_context_socket, "_service_uid", missing_account)
    with pytest.raises(KnowledgeContextUnavailable):
        knowledge_context_socket.request_context(
            {"privacy_class": "P0-public", "question": "test"}, deadline_s=0.1,
        )


def test_commissioned_broker_hardcodes_p0_and_bounds_response():
    response = {"schema_version": "knowledge-context-response/v1", "authority": "advisory_only"}
    calls = []

    class Client:
        def request_context(self, **kwargs):
            calls.append(kwargs)
            return response

    broker = KnowledgeContextBroker(client=Client(), policy=_policy(), mission="lab",
                                    alias_key=b"x" * 32, enabled=True)
    assert broker.handle(_request()) == {"response": response}
    assert calls[0]["privacy_class"] is PrivacyClass.P0_PUBLIC
    assert calls[0]["frame"] == {"question": "public question"}
    assert calls[0]["deadline_s"] == pytest.approx(0.5, abs=0.001)

    class Oversized:
        def request_context(self, **kwargs):
            return {"oversize": "x" * MAX_RESPONSE_BYTES}

    oversized = KnowledgeContextBroker(client=Oversized(), policy=_policy(), mission="lab",
                                       alias_key=b"x" * 32, enabled=True)
    assert oversized.handle(_request()) == {"refusal": "unavailable"}


def test_broker_refuses_non_p0_without_calling_the_peer():
    class Forbidden:
        def request_context(self, **kwargs):
            pytest.fail("non-P0 request reached Knowledge egress")

    broker = KnowledgeContextBroker(client=Forbidden(), policy=_policy(),
                                    mission="lab", alias_key=b"x" * 32, enabled=True)
    request = _request({"frame": {"privacy_class": "P2-mission",
                                  "question": "synthetic mission question"}})
    assert broker.handle(request) == {"refusal": "unavailable"}


@pytest.mark.parametrize("frame", [None, [], {"text": "x" * 16_385}, {"nan": float("nan")}])
def test_local_frame_parser_rejects_unbounded_or_non_json_frames(frame):
    with pytest.raises(KnowledgeContextUnavailable):
        read_context_frame(frame)


def test_mio_assessment_caller_cannot_inject_verified_context():
    frame = {"request_id": "normal", "privacy_class": "P2-mission",
             "question": "public question", "context": []}
    assert _read_assessment_payload(frame) == frame
    with pytest.raises(FrameRefused, match="malformed_assessment_payload"):
        _read_assessment_payload({"frame": frame,
                                  "fabric_knowledge_context_response": {"authority": "advisory_only"}})


def test_ordinary_fast_assess_fetches_context_only_from_local_broker(monkeypatch):
    from azazel_nexus_runtime import mio_fast_assistance, mio_locald

    frame = {"request_id": "normal", "privacy_class": "P0-public",
             "question": "synthetic public question", "context": []}
    response = {"schema_version": "knowledge-context-response/v1",
                "authority": "advisory_only"}
    broker_calls = []
    monkeypatch.setattr(mio_locald, "request_context",
                        lambda received, *, deadline_s: (broker_calls.append((received, deadline_s)), response)[1])
    monkeypatch.setattr(mio_fast_assistance, "_frame", lambda raw: {"situation": "bounded"})
    projected = []

    def fast(_frame, **kwargs):
        projected.append(kwargs["fabric_knowledge_context_response"])
        return {"model_free": True}

    monkeypatch.setattr(mio_fast_assistance, "fast_assistance", fast)
    lane = SimpleNamespace(submit=lambda *args: {"state": "closed", "usage": "unknown"})
    service = mio_locald.LocalRuntimeService(generation_lane=lane)
    request = SimpleNamespace(verb=mio_locald.FAST_ASSESS_VERB, payload=frame,
                              arguments={"deadline_ms": 1000})
    result = service.handle(request)
    assert broker_calls and broker_calls[0][0] == {
        "privacy_class": "P0-public", "question": "synthetic public question"}
    assert 0 < broker_calls[0][1] <= mio_locald.KNOWLEDGE_MAX_S
    assert projected == [response]
    assert result["fast_assistance"] == {"model_free": True}


def test_ordinary_fast_assess_does_not_upgrade_mission_data_to_p0(monkeypatch):
    from azazel_nexus_runtime import mio_locald, mio_fast_assistance

    frame = {"request_id": "mission", "privacy_class": "P2-mission",
             "question": "synthetic mission question", "context": []}
    monkeypatch.setattr(mio_locald, "request_context",
                        lambda *args, **kwargs: pytest.fail("P2 frame reached full-node broker"))
    monkeypatch.setattr(mio_fast_assistance, "fast_assistance",
                        lambda frame, **kwargs: {"model_free": True})
    lane = SimpleNamespace(submit=lambda *args: {"state": "closed", "usage": "unknown"})
    reply = mio_locald.LocalRuntimeService(generation_lane=lane).handle(SimpleNamespace(
        verb=mio_locald.FAST_ASSESS_VERB, payload=frame,
        arguments={"deadline_ms": 1000}))
    assert reply["fast_assistance"] == {"model_free": True}
