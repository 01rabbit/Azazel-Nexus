"""Characterize the current Knowledge Context audit outcome vocabulary.

These tests record present behavior only; they are not a policy statement.
"""
import socket

from azazel_nexus.knowledge_context_adapter import KnowledgeContextRefused

from test_knowledge_contextd import _policy, _request
from azazel_nexus_runtime.knowledge_contextd import KnowledgeContextBroker


def _broker(client, events, **kwargs):
    return KnowledgeContextBroker(
        client=client, policy=_policy(), mission="lab", alias_key=b"x" * 32,
        enabled=True, audit=events.append, **kwargs)


def test_peer_socket_timeout_is_unavailable_not_timeout():
    # knowledge_egress.request_context wraps OSError (socket.timeout included)
    # in KnowledgeContextRefused, which is not a TimeoutError.
    class Client:
        def request_context(self, **_kwargs):
            try:
                raise socket.timeout("synthetic peer timeout")
            except OSError as exc:
                raise KnowledgeContextRefused("peer refused or unavailable") from exc

    events = []
    assert _broker(Client(), events).handle(_request()) == {"refusal": "unavailable"}
    assert [e["event_type"] for e in events] == [
        "knowledge.context.requested", "knowledge.context.completed"]
    assert events[-1]["outcome"] == "unavailable"


def test_busy_slot_is_timeout_and_writes_no_requested_event():
    class Forbidden:
        def request_context(self, **_kwargs):
            raise AssertionError("busy broker reached the peer")

    events = []
    broker = _broker(Forbidden(), events)
    assert broker._slot.acquire(blocking=False)
    assert broker.handle(_request()) == {"refusal": "timeout"}
    assert [e["event_type"] for e in events] == ["knowledge.context.completed"]
    assert events[0]["outcome"] == "timeout"


def test_already_expired_request_returns_timeout_without_any_audit():
    class Forbidden:
        def request_context(self, **_kwargs):
            raise AssertionError("expired request reached the peer")

    events = []
    broker = _broker(Forbidden(), events, monotonic=lambda: 20.0)
    request = _request(deadline_ms=500, deadline_monotonic_ns=19_000_000_000)
    assert broker.handle(request) == {"refusal": "timeout"}
    assert events == []


import pytest

from test_knowledge_context_transport import (
    POLICY as _TRANSPORT_POLICY, client as _egress_client, registry as _registry)


@pytest.mark.parametrize("raised", [socket.timeout("synthetic"),
                                    OSError("synthetic transport failure")])
def test_real_egress_wraps_transport_timeout_and_broker_reports_unavailable(
        monkeypatch, raised):
    # Real KnowledgeClient.request_context (registry, request building, slot);
    # only the send/receive section _post_path is replaced.
    peer = _egress_client(_registry(443, deadline_seconds=5), enabled=True,
                          max_ttl_seconds=30)

    def fail(_peer, _path, _body, _deadline):
        raise raised

    monkeypatch.setattr(peer, "_post_path", fail)
    events = []
    broker = KnowledgeContextBroker(
        client=peer, policy=_TRANSPORT_POLICY, mission="lab",
        alias_key=b"x" * 32, enabled=True, audit=events.append)
    request = _request(payload={"frame": {
        "privacy_class": "P0-public", "question": "public question"}})
    assert broker.handle(request) == {"refusal": "unavailable"}
    assert [e["event_type"] for e in events] == [
        "knowledge.context.requested", "knowledge.context.completed"]
    assert events[-1]["outcome"] == "unavailable"
    # the egress slot is released after the failure
    assert peer.slots.acquire(blocking=False)
