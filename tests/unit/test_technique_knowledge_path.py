"""The technique path: broker stages, locald axes, and no hand-off to M.I.O."""

from __future__ import annotations

import inspect
import json
import os
import sys
from types import SimpleNamespace

import pytest

from _technique_fixture import make_response
from azazel_nexus import technique_knowledge as tk
from azazel_nexus_runtime import knowledge_context_config as cfg
from azazel_nexus_runtime import knowledge_contextd as kc
from azazel_nexus_runtime import mio_locald as locald
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.knowledge_context_socket import KnowledgeContextUnavailable
from stop_helpers import granted_marker
from test_knowledge_context_observation_gate import make, write_rule
from test_knowledge_contextd import _request
from test_mio_context_observe import core, locald_request, obs_frame, service_  # noqa: F401

IDS = ["T1059", "T1059.001"]


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(cfg, "_OWNER", os.getuid())
    return tmp_path


def technique_frame(ids=IDS, **kw):
    return _request(payload={"frame": {"privacy_class": "P0-public", "techniques": ids, **kw}})


# -- broker -------------------------------------------------------------------

def test_broker_judges_a_technique_query_by_the_observation_gate(env):
    broker, peer, events = make(None)
    assert broker.handle(technique_frame()) == {"refusal": "unavailable", "stage": "refused_before_send"}
    assert peer.calls == 0
    write_rule(env, 2)
    broker, peer, events = make(cfg.load_observation_rule())
    assert "response" in broker.handle(technique_frame()) and peer.calls == 1
    assert "response" in broker.handle(technique_frame())
    assert broker.handle(technique_frame()) == {"refusal": "unavailable", "stage": "refused_before_send"}
    assert peer.calls == 2
    assert events[-1]["reason_code"] == "rate_limited"


@pytest.mark.parametrize("frame", [
    {"privacy_class": "P0-public", "techniques": ["T1059", "T1059"]},
    {"privacy_class": "P0-public", "techniques": ["T1059.001", "T1059"]},
    {"privacy_class": "P0-public", "techniques": []},
    {"privacy_class": "P0-public", "techniques": "T1059"},
    {"privacy_class": "P0-public", "techniques": ["t1059"]},
    {"privacy_class": "P0-public", "techniques": [f"T{1000 + n}" for n in range(9)]},
    {"privacy_class": "P3-restricted", "techniques": ["T1059"]},
    {"privacy_class": "P0-public", "techniques": ["T1059"], "question": "x"},
    {"privacy_class": "P0-public", "techniques": ["T1059"], "extra": 1},
    {"techniques": ["T1059"]},
])
def test_broker_refuses_a_malformed_technique_frame_before_any_peer_call(env, frame):
    write_rule(env, 6)
    broker, peer, _ = make(cfg.load_observation_rule())
    reply = broker.handle(_request(payload={"frame": frame}))
    assert reply["refusal"] == "unavailable" and "response" not in reply
    assert peer.calls == 0


def test_broker_passes_the_typed_frame_to_the_client_and_other_frames_are_unchanged(env):
    write_rule(env, 6)
    seen = []

    class Peer:
        def request_context(self, **kw):
            seen.append(kw["frame"])
            return {"authority": "advisory_only"}

    broker, _, _ = make(cfg.load_observation_rule())
    broker._client = Peer()
    broker.handle(technique_frame(["T1059", "T1110"]))
    broker.handle(_request(payload={"frame": {"privacy_class": "P0-public", "question": "public question"}}))
    assert seen == [{"techniques": ["T1059", "T1110"]}, {"question": "public question"}]


@pytest.mark.parametrize("raised,stage", [
    ("refused_before_send", "refused_before_send"), ("transport", "transport"),
    ("verification", "verification"), ("technique_verification", "technique_verification"),
    (None, None)])
def test_broker_reports_how_far_a_technique_query_got(env, raised, stage):
    write_rule(env, 6)

    class Peer:
        def request_context(self, **kw):
            exc = ValueError("x")
            exc.stage = raised
            raise exc

    broker, _, _ = make(cfg.load_observation_rule())
    broker._client = Peer()
    reply = broker.handle(technique_frame())
    assert reply == ({"refusal": "unavailable", "stage": stage} if stage else {"refusal": "unavailable"})
    # a question query keeps the old one-word refusal
    assert broker.handle(_request(payload={"frame": {"privacy_class": "P0-public", "question": "q"}})) == {
        "refusal": "unavailable"}


# -- the local socket reader -----------------------------------------------------

def test_socket_client_raises_with_the_stage(monkeypatch):
    import socket, struct, tempfile, threading
    from pathlib import Path
    from azazel_nexus_runtime import knowledge_context_socket as sock
    path = Path(tempfile.mkdtemp(prefix="tk")) / "s"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)
    monkeypatch.setattr(sock, "socket_path", lambda name: path)
    monkeypatch.setattr(sock, "verify_socket", lambda *a, **k: None)
    monkeypatch.setattr(sock, "peer_credentials", lambda c: (1, 7, 1))
    monkeypatch.setattr(sock, "_service_uid", lambda: 7)
    monkeypatch.setattr(sock, "_socket_gid", lambda: 1)

    def serve(result):
        conn, _ = server.accept()
        with conn:
            size = struct.unpack(">I", conn.recv(4, socket.MSG_WAITALL))[0]
            conn.recv(size, socket.MSG_WAITALL)
            conn.recv(1)  # the client's shutdown: answer only after it, as the broker does
            body = json.dumps({"ok": True, "result": result}).encode()
            conn.sendall(struct.pack(">I", len(body)) + body)

    from azazel_nexus_runtime.transport import _HEADER
    assert _HEADER.pack(1) == struct.pack(">I", 1)
    for result, stage in (({"refusal": "unavailable", "stage": "verification"}, "verification"),
                          ({"refusal": "unavailable", "stage": "bogus"}, None),
                          ({"refusal": "unavailable"}, None)):
        t = threading.Thread(target=serve, args=(result,))
        t.start()
        with pytest.raises(KnowledgeContextUnavailable) as caught:
            sock.request_context({"privacy_class": "P0-public", "techniques": ["T1059"]}, deadline_s=2)
        t.join()
        assert caught.value.stage == stage
    server.close()


# -- locald: axes, and the technique answer never reaches M.I.O. -------------------

def observed(core, monkeypatch, request_context, ids=("T1059", "T1059.001")):
    monkeypatch.setattr(locald, "request_context", request_context)
    return service_().handle(locald_request(obs_frame(ids)))


@pytest.mark.parametrize("stage,pair", [
    ("refused_before_send", ("refused", "not_run")), ("transport", ("unavailable", "not_run")),
    ("verification", ("refused", "failed")), ("technique_verification", ("received", "failed")),
    (None, ("unavailable", "not_run"))])
def test_locald_maps_the_broker_stage_to_the_axes(core, monkeypatch, stage, pair):
    def refuse(frame, *, deadline_s):
        exc = KnowledgeContextUnavailable("broker refused")
        exc.stage = stage
        raise exc
    reply = observed(core, monkeypatch, refuse)
    record = reply["fast_assistance"]["technique_knowledge"]
    assert (record["transport"], record["verification"]) == pair
    assert record["techniques"] == [] and reply["timing"]["context"] == pair[0]


def test_locald_validator_refusal_is_received_but_failed(core, monkeypatch):
    bad = make_response(IDS)
    bad["limitations"] = ["Block it."]
    record = observed(core, monkeypatch, lambda f, *, deadline_s: bad)["fast_assistance"]["technique_knowledge"]
    assert (record["transport"], record["verification"]) == ("received", "failed")
    assert record["techniques"] == []


@pytest.mark.parametrize("payload", [{"response": "x"}, None, [], "text", {}])
def test_locald_non_response_values_are_a_failed_verification(core, monkeypatch, payload):
    record = observed(core, monkeypatch, lambda f, *, deadline_s: payload)["fast_assistance"]["technique_knowledge"]
    assert record["verification"] == "failed" and record["techniques"] == []


@pytest.mark.parametrize("name", ["Brute Force", "Block now", "This proves ransomware"])
def test_mio_never_receives_a_technique_answer(core, monkeypatch, name):
    answer = make_response(IDS, content={"T1059": (name, "execution", "15.1"), "T1059.001": ("PowerShell", "execution", "15.1")})
    reply = observed(core, monkeypatch, lambda f, *, deadline_s: answer)
    call, = core.calls
    # M.I.O. is run once, with no response and the unavailable word, as for no answer at all
    assert call["response"] is None
    assert call["status"] is locald.FullNodeContextStatus.UNAVAILABLE
    assert name not in json.dumps({k: v for k, v in call.items() if k != "source"}, default=str)
    fast = reply["fast_assistance"]
    assert "fabric_knowledge_context_advisory" not in fast and "full_node_context_received_at" not in fast
    for key in ("observations", "hypotheses", "unknowns", "next_checks", "reasoning_trace", "knowledge"):
        assert name.split()[0] not in json.dumps(fast.get(key, "")), key
    record = fast["technique_knowledge"]
    assert (record["transport"], record["verification"]) == ("received", "ok")


def test_the_existing_mio_hand_off_is_not_used_for_techniques():
    source = inspect.getsource(locald.LocalRuntimeService._observe_context)
    assert "fabric_knowledge_context_response=None" in source
    assert "FullNodeContextStatus.RECEIVED" not in source
    assert "fabric_knowledge_context_response=response" not in source
    # the other (question) path still uses it
    assert "fabric_knowledge_context_response=fabric_context_response" in inspect.getsource(locald)


def test_a_budget_too_small_for_a_query_is_recorded_as_unavailable(core, monkeypatch):
    calls = []
    monkeypatch.setattr(locald, "request_context", lambda *a, **k: calls.append(1))
    reply = service_().handle(locald_request(obs_frame(), deadline=40))
    assert calls == []
    record = reply["fast_assistance"]["technique_knowledge"]
    assert (record["transport"], record["verification"]) == ("unavailable", "not_run")
