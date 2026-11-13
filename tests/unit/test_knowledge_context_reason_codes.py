"""reason_code on the completed audit event: one test per route of the table."""
import json
import os
import socket

import pytest

from azazel_nexus.knowledge_context_adapter import KnowledgeContextRefused
from azazel_nexus.knowledge_peer import KnowledgeRefused
from stop_helpers import granted_marker
from azazel_nexus_runtime.knowledge_contextd import KnowledgeContextBroker
from test_knowledge_contextd import _policy, _request
from test_knowledge_context_transport import (
    client as _egress_client, registry as _registry)


def real_client(monkeypatch, *, enabled=True, response=None):
    """The real KnowledgeClient.request_context with only the Fabric-dependent
    helpers replaced (azazel_fabric is not installed in every environment, and
    the broker's {"question": ...} frame is not a Fabric entity type)."""
    from azazel_nexus_runtime import knowledge_egress as eg
    monkeypatch.setattr(eg, "make_request", lambda *a, **k: object())
    monkeypatch.setattr(eg, "canonical_knowledge_context_request", lambda r: b"{}")
    monkeypatch.setattr(eg, "read_signed_response", response or (lambda *a, **k: {}))
    return _egress_client(_registry(443, deadline_seconds=5), enabled=enabled,
                          max_ttl_seconds=30)


SECRET = "SECRET-EXC-TEXT-9f3"
QUESTION = "QUESTION-TEXT-7c1 public question"


def _broker(client, events, **kw):
    return KnowledgeContextBroker(grant_marker=granted_marker, client=client, policy=_policy(), mission="lab",
                                  alias_key=b"x" * 32, enabled=True,
                                  audit=events.append, **kw)


def _completed(events):
    return [e for e in events if e["event_type"] == "knowledge.context.completed"]


def _real(monkeypatch, post, *, enabled=True, response=None):
    peer = real_client(monkeypatch, enabled=enabled, response=response)
    if post is not None:
        monkeypatch.setattr(peer, "_post_path", post)
    events = []
    broker = KnowledgeContextBroker(grant_marker=granted_marker, client=peer, policy=_policy(), mission="lab",
                                    alias_key=b"x" * 32, enabled=True,
                                    audit=events.append)
    req = _request(payload={"frame": {"privacy_class": "P0-public",
                                      "question": QUESTION}})
    return broker, req, events, peer


def _check(events, reason, outcome):
    done = _completed(events)
    assert len(done) == 1
    assert done[0]["outcome"] == outcome
    if reason is None:
        assert "reason_code" not in done[0]
    else:
        assert done[0]["reason_code"] == reason
    assert set(done[0]) <= {"event_type", "outcome", "elapsed_ms", "reason_code",
                            "response_bytes"}
    text = json.dumps(events)
    assert SECRET not in text and "QUESTION-TEXT" not in text


def test_frame_shape_refusal_is_refused_before_send():
    events = []
    broker = _broker(object(), events)
    req = _request(payload={"frame": {"privacy_class": "P1", "question": "q"}})
    assert broker.handle(req) == {"refusal": "unavailable"}
    _check(events, "refused_before_send", "unavailable")
    assert [e["event_type"] for e in events] == ["knowledge.context.completed"]


def test_uncommissioned_broker_is_refused_before_send():
    events = []
    broker = KnowledgeContextBroker(grant_marker=granted_marker, audit=events.append)
    assert broker.handle(_request()) == {"refusal": "unavailable"}
    _check(events, "refused_before_send", "unavailable")


def test_requested_audit_write_failure_is_refused_before_send():
    calls = []

    class Client:
        def request_context(self, **kw):
            calls.append(kw)

    events = []

    def audit(event):
        if event["event_type"] == "knowledge.context.requested":
            raise OSError(SECRET)
        events.append(event)

    broker = KnowledgeContextBroker(grant_marker=granted_marker, client=Client(), policy=_policy(), mission="lab",
                                    alias_key=b"x" * 32, enabled=True, audit=audit)
    assert broker.handle(_request()) == {"refusal": "unavailable"}
    assert not calls
    _check(events, "refused_before_send", "unavailable")


def test_busy_slot_is_timeout_with_busy():
    events = []
    broker = _broker(object(), events)
    assert broker._slot.acquire(blocking=False)
    assert broker.handle(_request()) == {"refusal": "timeout"}
    _check(events, "busy", "timeout")


def test_guarded_client_refusal_is_refused_before_send(tmp_path):
    from azazel_nexus_runtime import knowledge_context_config as cfg
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    info = os.lstat(manifest)
    guard = cfg._GuardedClient(object(), str(manifest),
                               (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns))
    manifest.unlink()
    events = []
    assert _broker(guard, events).handle(_request()) == {"refusal": "unavailable"}
    _check(events, "refused_before_send", "unavailable")


def test_real_egress_disabled_client_is_refused_before_send(monkeypatch):
    broker, req, events, _ = _real(monkeypatch, None, enabled=False)
    assert broker.handle(req) == {"refusal": "unavailable"}
    _check(events, "refused_before_send", "unavailable")


def test_real_egress_pre_send_section_failure_is_refused_before_send(monkeypatch):
    broker, req, events, peer = _real(monkeypatch, lambda *a: pytest.fail("sent"))
    peer.registry = None
    assert broker.handle(req) == {"refusal": "unavailable"}
    _check(events, "refused_before_send", "unavailable")


@pytest.mark.parametrize("raised", [socket.timeout(SECRET), OSError(SECRET),
                                    KnowledgeRefused(SECRET)])
def test_real_egress_post_path_failure_is_transport(monkeypatch, raised):
    def fail(*a):
        raise raised
    broker, req, events, _ = _real(monkeypatch, fail)
    assert broker.handle(req) == {"refusal": "unavailable"}
    _check(events, "transport", "unavailable")


def test_real_egress_verification_failure_is_verification(monkeypatch):
    def refuse(*a, **k):
        raise KnowledgeContextRefused(SECRET)
    broker, req, events, _ = _real(monkeypatch, lambda *a: b"raw", response=refuse)
    assert broker.handle(req) == {"refusal": "unavailable"}
    _check(events, "verification", "unavailable")


def test_broker_side_rejection_after_verification_is_verification():
    class NotADict:
        def model_dump(self, mode):
            return ["x"]

    class Big:
        def model_dump(self, mode):
            return {"x": "a" * 60000}

    for result in (NotADict(), Big()):
        class Client:
            def request_context(self, **kw):
                return result
        events = []
        assert _broker(Client(), events).handle(_request()) == {"refusal": "unavailable"}
        _check(events, "verification", "unavailable")


def test_late_response_is_timeout_with_late():
    clock = [10.0]

    class Client:
        def request_context(self, **kw):
            clock[0] = 11.0  # past the 500 ms deadline
            return {"authority": "advisory_only"}

    events = []
    broker = _broker(Client(), events, monotonic=lambda: clock[0])
    req = _request(deadline_ms=500, deadline_monotonic_ns=20_000_000_000)
    assert broker.handle(req) == {"refusal": "timeout"}
    _check(events, "late", "timeout")


def test_exception_without_fixed_attribute_gets_no_reason():
    class Client:
        def request_context(self, **kw):
            raise RuntimeError(SECRET)

    events = []
    assert _broker(Client(), events).handle(_request()) == {"refusal": "unavailable"}
    _check(events, None, "unavailable")


def test_unknown_stage_value_is_not_exported():
    class Boom(Exception):
        stage = SECRET

    class Client:
        def request_context(self, **kw):
            raise Boom(SECRET)

    events = []
    assert _broker(Client(), events).handle(_request()) == {"refusal": "unavailable"}
    _check(events, None, "unavailable")


def test_success_has_no_reason_code_and_fixed_keys():
    class Client:
        def request_context(self, **kw):
            return {"authority": "advisory_only"}

    events = []
    assert _broker(Client(), events).handle(_request()) == {"response": {"authority": "advisory_only"}}
    done = _completed(events)[0]
    assert set(done) == {"event_type", "outcome", "response_bytes", "elapsed_ms"}
    assert done["outcome"] == "verified_advisory"


def test_already_expired_and_completed_audit_failure_stay_unchanged():
    events = []
    broker = _broker(object(), events, monotonic=lambda: 20.0)
    req = _request(deadline_ms=500, deadline_monotonic_ns=19_000_000_000)
    assert broker.handle(req) == {"refusal": "timeout"}
    assert events == []

    class Client:
        def request_context(self, **kw):
            raise RuntimeError

    def audit(event):
        if event["event_type"].endswith("completed"):
            raise OSError
    broker = KnowledgeContextBroker(grant_marker=granted_marker, client=Client(), policy=_policy(), mission="lab",
                                    alias_key=b"x" * 32, enabled=True, audit=audit)
    assert broker.handle(_request()) == {"refusal": "unavailable"}
