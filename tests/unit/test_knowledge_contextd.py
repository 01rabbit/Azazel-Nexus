"""Dedicated Knowledge egress broker remains P0 and closed by default."""

from pathlib import Path
import struct
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "runtime" / "src"))

from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy
from stop_helpers import granted_marker
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


#: The one frame the broker accepts (#439): the observation-origin technique query.
TECHNIQUE_FRAME = {"privacy_class": "P0-public", "techniques": ["T1059"]}


def _request(payload=None, deadline_ms=500, deadline_monotonic_ns=None):
    if deadline_monotonic_ns is None:
        import time
        deadline_monotonic_ns = int((time.monotonic() + deadline_ms / 1000)
                                    * 1_000_000_000)
    return SimpleNamespace(verb=CONTEXT_VERB, arguments={
                               "deadline_ms": deadline_ms,
                               "deadline_monotonic_ns": deadline_monotonic_ns},
                           payload=payload or {"frame": dict(TECHNIQUE_FRAME)})


def _open_gate() -> dict:
    """Broker keywords for a usable observation rule (60 a minute).

    Every accepted frame is a technique query, and every technique query is
    judged by the observation gate; a test about anything after the gate opens
    it with these. The identity is a real file's, so the gate's re-check holds.
    """
    import os
    import tempfile

    from azazel_nexus_runtime.knowledge_context_config import ObservationRule

    fd, name = tempfile.mkstemp(prefix="azazel-observation-rule-")
    os.close(fd)
    info = os.lstat(name)
    return {"observation_rule": (ObservationRule("technique-set/1", 60),
                                 (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)),
            "observation_rule_path": name}


OPEN_GATE = _open_gate()


def test_uncommissioned_broker_refuses_and_does_not_call_a_peer():
    class Forbidden:
        def request_context(self, **kwargs):
            pytest.fail("disabled broker attempted Knowledge egress")

    events = []
    broker = KnowledgeContextBroker(**OPEN_GATE, grant_marker=granted_marker, client=Forbidden(), policy=_policy(),
                                    mission="lab", alias_key=b"x" * 32,
                                    audit=events.append)
    assert broker.handle(_request()) == {"refusal": "unavailable", "stage": "refused_before_send"}
    assert events[-1]["outcome"] == "unavailable"


def test_expired_queued_request_does_not_reach_knowledge():
    class Forbidden:
        def request_context(self, **kwargs):
            pytest.fail("expired request reached Knowledge")

    broker = KnowledgeContextBroker(**OPEN_GATE, grant_marker=granted_marker, 
        client=Forbidden(), policy=_policy(), mission="lab", alias_key=b"x" * 32,
        enabled=True, monotonic=lambda: 20.0,
    )
    request = _request(deadline_ms=500, deadline_monotonic_ns=19_000_000_000)
    assert broker.handle(request) == {"refusal": "timeout", "stage": "refused_before_send"}


def test_audit_failure_prevents_knowledge_egress():
    calls = []

    class Client:
        def request_context(self, **kwargs):
            calls.append(kwargs)
            return {"authority": "advisory_only"}

    def broken_audit(_event):
        raise OSError("synthetic audit failure")

    broker = KnowledgeContextBroker(**OPEN_GATE, grant_marker=granted_marker, 
        client=Client(), policy=_policy(), mission="lab", alias_key=b"x" * 32,
        enabled=True, audit=broken_audit,
    )
    assert broker.handle(_request()) == {"refusal": "unavailable", "stage": "refused_before_send"}
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


@pytest.mark.parametrize("peer", [(0, 20001, 20002), (123, 20002, 20003)])
def test_local_broker_client_refuses_invalid_pid_or_peer_uid(monkeypatch, peer):
    """Exercise the policy branch with synthetic kernel peer credentials."""
    from azazel_nexus_runtime import knowledge_context_socket

    calls = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _timeout):
            pass

        def connect(self, path):
            calls.append(("connect", path))

        def sendall(self, _payload):
            calls.append(("sendall",))

    def verify(path, *, expected_uid, expected_gid):
        calls.append(("verify_socket", expected_uid, expected_gid))

    monkeypatch.setattr(knowledge_context_socket, "_service_uid", lambda: 20001)
    monkeypatch.setattr(knowledge_context_socket, "_socket_gid", lambda: 20002)
    monkeypatch.setattr(knowledge_context_socket, "verify_socket", verify)
    monkeypatch.setattr(knowledge_context_socket, "peer_credentials", lambda _conn: peer)
    socket_module = knowledge_context_socket.socket
    monkeypatch.setattr(
        knowledge_context_socket,
        "socket",
        SimpleNamespace(
            socket=lambda *_a, **_k: Connection(),
            AF_UNIX=socket_module.AF_UNIX,
            SOCK_STREAM=socket_module.SOCK_STREAM,
            SHUT_WR=socket_module.SHUT_WR,
        ),
    )

    with pytest.raises(KnowledgeContextUnavailable, match="peer identity"):
        knowledge_context_socket.request_context(
            {"privacy_class": "P0-public", "question": "test"}, deadline_s=0.1,
        )
    assert calls[0] == ("verify_socket", 20001, 20002)
    assert calls[1][0] == "connect"
    assert all(call[0] != "sendall" for call in calls)


def test_truncated_broker_reply_becomes_optional_context_unavailable(monkeypatch):
    from azazel_nexus.audit import AuditUnavailable
    from azazel_nexus_runtime import knowledge_context_socket

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _timeout):
            pass

        def connect(self, _path):
            pass

        def getsockopt(self, _level, _option, _length):
            # Match the commissioned broker UID checked by request_context.
            return struct.pack("3i", 123, 20001, 20002)

        def sendall(self, _payload):
            pass

        def shutdown(self, _how):
            pass

    monkeypatch.setattr(knowledge_context_socket, "_service_uid", lambda: 20001)
    monkeypatch.setattr(knowledge_context_socket, "_socket_gid", lambda: 20002)
    monkeypatch.setattr(knowledge_context_socket, "verify_socket", lambda *_a, **_k: None)
    monkeypatch.setattr(knowledge_context_socket.socket, "socket",
                        lambda *_a, **_k: Connection())

    def truncated(*_args, **_kwargs):
        raise AuditUnavailable("synthetic truncated response")

    monkeypatch.setattr(knowledge_context_socket, "_read_exact", truncated)
    with pytest.raises(KnowledgeContextUnavailable):
        knowledge_context_socket.request_context(
            {"privacy_class": "P0-public", "question": "test"}, deadline_s=0.1,
        )


def test_deeply_nested_broker_reply_becomes_optional_context_unavailable(monkeypatch):
    from azazel_nexus_runtime import knowledge_context_socket
    from azazel_nexus_runtime.transport import _HEADER

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _timeout):
            pass

        def connect(self, _path):
            pass

        def sendall(self, _payload):
            pass

        def shutdown(self, _how):
            pass

        def recv(self, _size):
            return b""

    monkeypatch.setattr(knowledge_context_socket, "_service_uid", lambda: 20001)
    monkeypatch.setattr(knowledge_context_socket, "_socket_gid", lambda: 20002)
    monkeypatch.setattr(knowledge_context_socket, "verify_socket", lambda *_a, **_k: None)
    monkeypatch.setattr(knowledge_context_socket, "peer_credentials",
                        lambda _connection: (123, 20001, 20002))
    monkeypatch.setattr(knowledge_context_socket.socket, "socket",
                        lambda *_a, **_k: Connection())

    body = b"[" * 1200 + b"null" + b"]" * 1200
    reply_parts = iter((_HEADER.pack(len(body)), body))
    monkeypatch.setattr(knowledge_context_socket, "_read_exact",
                        lambda *_args, **_kwargs: next(reply_parts))
    with pytest.raises(KnowledgeContextUnavailable):
        knowledge_context_socket.request_context(
            {"privacy_class": "P0-public", "question": "test"}, deadline_s=0.1,
        )


def test_late_knowledge_response_is_not_delivered():
    clock = [10.0]

    class LateClient:
        def request_context(self, **_kwargs):
            clock[0] = 10.01
            return {"authority": "advisory_only"}

    broker = KnowledgeContextBroker(**OPEN_GATE, grant_marker=granted_marker, 
        client=LateClient(), policy=_policy(), mission="lab", alias_key=b"x" * 32,
        enabled=True, monotonic=lambda: clock[0],
    )
    request = _request(deadline_ms=500, deadline_monotonic_ns=10_005_000_000)
    assert broker.handle(request) == {"refusal": "timeout", "stage": "transport"}


def test_late_response_cannot_outlive_relative_deadline():
    clock = [10.0]

    class LateClient:
        def request_context(self, **_kwargs):
            clock[0] = 10.01
            return {"authority": "advisory_only"}

    broker = KnowledgeContextBroker(**OPEN_GATE, grant_marker=granted_marker, 
        client=LateClient(), policy=_policy(), mission="lab", alias_key=b"x" * 32,
        enabled=True, monotonic=lambda: clock[0],
    )
    request = _request(deadline_ms=5, deadline_monotonic_ns=10_500_000_000)
    assert broker.handle(request) == {"refusal": "timeout", "stage": "transport"}


def test_broker_size_limit_matches_escaped_wire_encoding():
    class UnicodeClient:
        def request_context(self, **_kwargs):
            return {"text": "秘密" * 5_000}

    broker = KnowledgeContextBroker(**OPEN_GATE, grant_marker=granted_marker, 
        client=UnicodeClient(), policy=_policy(), mission="lab", alias_key=b"x" * 32,
        enabled=True,
    )
    assert broker.handle(_request()) == {"refusal": "unavailable", "stage": "verification"}


def test_commissioned_broker_hardcodes_p0_and_bounds_response():
    response = {"schema_version": "knowledge-context-response/v1", "authority": "advisory_only"}
    calls = []

    class Client:
        def request_context(self, **kwargs):
            calls.append(kwargs)
            return response

    broker = KnowledgeContextBroker(**OPEN_GATE, grant_marker=granted_marker, client=Client(), policy=_policy(), mission="lab",
                                    alias_key=b"x" * 32, enabled=True)
    assert broker.handle(_request()) == {"response": response}
    assert calls[0]["privacy_class"] is PrivacyClass.P0_PUBLIC
    assert calls[0]["frame"] == {"techniques": ["T1059"]}
    assert calls[0]["deadline_s"] == pytest.approx(0.5, abs=0.001)

    class Oversized:
        def request_context(self, **kwargs):
            return {"oversize": "x" * MAX_RESPONSE_BYTES}

    oversized = KnowledgeContextBroker(**OPEN_GATE, grant_marker=granted_marker, client=Oversized(), policy=_policy(), mission="lab",
                                       alias_key=b"x" * 32, enabled=True)
    assert oversized.handle(_request()) == {"refusal": "unavailable", "stage": "verification"}


def test_broker_refuses_non_p0_without_calling_the_peer():
    class Forbidden:
        def request_context(self, **kwargs):
            pytest.fail("non-P0 request reached Knowledge egress")

    broker = KnowledgeContextBroker(**OPEN_GATE, grant_marker=granted_marker, client=Forbidden(), policy=_policy(),
                                    mission="lab", alias_key=b"x" * 32, enabled=True)
    for frame in ({"privacy_class": "P2-mission", "techniques": ["T1059"]},
                  {"privacy_class": "P2-mission", "question": "synthetic mission question"}):
        assert broker.handle(_request({"frame": frame}))["refusal"] == "unavailable"


@pytest.mark.parametrize("frame", [
    {"privacy_class": "P0-public", "question": "public question"},
    # The old observation sentence is a question too, whatever it says.
    {"privacy_class": "P0-public", "question": "ATT&CK technique context: T1059"},
    {"privacy_class": "P0-public", "question": "ATT&CK technique context: T1059 T1059.001"},
    {"privacy_class": "P0-public", "techniques": ["T1059"], "question": "x"},
])
def test_a_free_form_question_is_refused_before_sending(frame):
    """#439: the broker serves one account, which only asks for technique ids."""
    calls, events = [], []

    class Client:
        def request_context(self, **kwargs):
            calls.append(kwargs)
            return {"authority": "advisory_only"}

    broker = KnowledgeContextBroker(**OPEN_GATE, grant_marker=granted_marker, client=Client(),
                                    policy=_policy(), mission="lab", alias_key=b"x" * 32,
                                    enabled=True, audit=events.append)
    # The caller sees the same fixed word the ledger records, not a shape error.
    assert broker.handle(_request({"frame": frame})) == {"refusal": "unavailable",
                                                       "stage": "refused_before_send"}
    assert calls == []
    # Refused before the gate, the slot and the `requested` record.
    assert [e["event_type"] for e in events] == ["knowledge.context.completed"]
    assert events[-1]["reason_code"] == "refused_before_send"
    assert "question" not in str(events) and "public" not in str(events)
    # The same broker still serves the technique form.
    assert "response" in broker.handle(_request())
    assert calls[0]["frame"] == {"techniques": ["T1059"]}


def test_the_broker_admits_only_the_context_observation_account():
    import ast
    import inspect

    from azazel_nexus_runtime import knowledge_contextd

    calls = [node for node in ast.walk(ast.parse(inspect.getsource(knowledge_contextd.main)))
             if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "resolve"]
    (call,) = calls
    accounts = {k.arg: ast.literal_eval(k.value) for k in call.keywords}["service_accounts"]
    assert accounts == ("azmioctx",)


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


def test_ordinary_fast_assess_does_not_query_the_broker(monkeypatch):
    """#439: the model host is no broker client; its assessment is `not_queried`."""
    pytest.importorskip("azazel_mio", reason="M.I.O. is an optional runtime extra")
    from azazel_nexus_runtime import knowledge_context_socket, mio_fast_assistance, mio_locald

    frame = {"request_id": "normal", "privacy_class": "P0-public",
             "question": "synthetic public question", "context": []}
    monkeypatch.setattr(knowledge_context_socket, "request_context",
                        lambda *a, **k: pytest.fail("locald queried the broker"))
    assert not hasattr(mio_locald, "request_context")
    projected = []

    def fast(_frame, **kwargs):
        projected.append((kwargs["fabric_knowledge_context_response"],
                          kwargs["full_node_context_status"]))
        return {"model_free": True}

    monkeypatch.setattr(mio_fast_assistance, "fast_assistance", fast)
    submitted=[]
    def submit(source,situation,generation,*,upstream_coverage,upstream_selection):
        submitted.append((source,situation,upstream_coverage,upstream_selection))
        return {"state":"closed","usage":"unknown"}
    lane = SimpleNamespace(submit=submit)
    service = mio_locald.LocalRuntimeService(generation_lane=lane)
    request = SimpleNamespace(verb=mio_locald.FAST_ASSESS_VERB, payload=frame,
                              arguments={"deadline_ms": 1000})
    result = service.handle(request)
    assert projected == [(None, mio_locald.FullNodeContextStatus.NOT_QUERIED)]
    assert len(submitted)==1 and submitted[0][0]==frame
    from azazel_mio import MioSituationFrame
    assert isinstance(submitted[0][1],MioSituationFrame)
    assert submitted[0][1].to_dict()["noc_summary"]==frame["question"]
    assert submitted[0][2]=="intact"
    assert submitted[0][3]==dict(policy_version="nexus-frame-v2",coverage="intact",
        input_units=2,selected_units=2,omitted_units=0,omissions=[])
    assert result["fast_assistance"] == {"model_free": True}


def test_ordinary_fast_assess_does_not_upgrade_mission_data_to_p0(monkeypatch):
    pytest.importorskip("azazel_mio", reason="M.I.O. is an optional runtime extra")
    from azazel_nexus_runtime import knowledge_context_socket, mio_locald, mio_fast_assistance

    frame = {"request_id": "mission", "privacy_class": "P2-mission",
             "question": "synthetic mission question", "context": []}
    monkeypatch.setattr(knowledge_context_socket, "request_context",
                        lambda *args, **kwargs: pytest.fail("P2 frame reached full-node broker"))
    monkeypatch.setattr(mio_fast_assistance, "fast_assistance",
                        lambda frame, **kwargs: {"model_free": True})
    lane = SimpleNamespace(submit=lambda *args: {"state": "closed", "usage": "unknown"})
    reply = mio_locald.LocalRuntimeService(generation_lane=lane).handle(SimpleNamespace(
        verb=mio_locald.FAST_ASSESS_VERB, payload=frame,
        arguments={"deadline_ms": 1000}))
    assert reply["fast_assistance"] == {"model_free": True}


def test_a_refused_question_reaches_the_caller_as_refused_before_send(monkeypatch):
    """The product client reads the broker's refusal: stage refused_before_send, not 'broker response shape'."""
    from azazel_nexus_runtime import knowledge_context_socket as kcs
    broker = KnowledgeContextBroker(**OPEN_GATE, grant_marker=granted_marker,
                                    client=None, policy=_policy(), mission="lab",
                                    alias_key=b"x" * 32, enabled=True, audit=lambda e: None)
    reply = {"ok": True, "result": broker.handle(_request({"frame": {
        "privacy_class": "P0-public", "question": "public question"}}))}
    assert set(reply["result"]) == {"refusal", "stage"} and reply["result"]["stage"] in kcs.STAGES


def test_every_broker_stage_is_one_the_client_and_the_projection_know():
    """The broker's stage words are a subset of the client's STAGES, and each one has its own projection."""
    from azazel_nexus_runtime import knowledge_context_socket as kcs
    from azazel_nexus_runtime import knowledge_contextd as kd
    from azazel_nexus_runtime import mio_contextobsd as obs
    assert kd._STAGES <= kcs.STAGES
    projected = {s: (obs._refusal_projection(s)["transport"], obs._refusal_projection(s)["verification"])
                 for s in kcs.STAGES}
    assert projected["withdrawn"] == ("received", "withdrawn")
    assert projected["refused_before_send"] == ("refused", "not_run")
    assert projected["transport"] == ("unavailable", "not_run")


def test_early_returns_and_unnamed_client_failures_carry_a_stage():
    import types
    broker = KnowledgeContextBroker(**OPEN_GATE, grant_marker=granted_marker, client=None,
                                    policy=_policy(), mission="lab", alias_key=b"x" * 32,
                                    enabled=True, audit=lambda e: None)
    other = types.SimpleNamespace(verb=types.SimpleNamespace(name="other.verb"), arguments={}, payload={})
    assert broker.handle(other) == {"refusal": "unavailable", "stage": "refused_before_send"}
    expired = _request()
    expired.arguments["deadline_monotonic_ns"] = 1
    assert broker.handle(expired) == {"refusal": "timeout", "stage": "refused_before_send"}

    class Client:
        def request_context(self, **kwargs):
            raise RuntimeError("unnamed failure")  # no stage attribute
    broker = KnowledgeContextBroker(**OPEN_GATE, grant_marker=granted_marker, client=Client(),
                                    policy=_policy(), mission="lab", alias_key=b"x" * 32,
                                    enabled=True, audit=lambda e: None)
    assert broker.handle(_request()) == {"refusal": "unavailable", "stage": "transport"}
