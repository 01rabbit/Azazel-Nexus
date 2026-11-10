"""Observation-origin question gate in the broker (unit B2)."""
import json
import os

import pytest

from azazel_nexus_runtime import knowledge_context_config as cfg
from azazel_nexus_runtime import knowledge_contextd as kc
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.knowledge_contextd import KnowledgeContextBroker
from test_knowledge_contextd import _policy, _request

Q = "ATT&CK technique context: T1059 T1059.001"


class Peer:
    def __init__(self):
        self.calls = 0

    def request_context(self, **kw):
        self.calls += 1
        return {"authority": "advisory_only"}


def frame(question):
    return _request(payload={"frame": {"privacy_class": "P0-public",
                                       "question": question}})


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(cfg, "_OWNER", os.getuid())
    return tmp_path


def write_rule(root, limit=6):
    path = root / "etc/azazel/knowledge-context/observation-query.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    for part in (root / "etc", root / "etc/azazel", path.parent):
        os.chmod(part, 0o755)
    path.write_text(json.dumps({"schema": cfg.OBSERVATION_RULE_SCHEMA,
                                "rule": "technique-set/1",
                                "max_requests_per_minute": limit}))
    os.chmod(path, 0o644)
    return path


def make(rule=None, clock=None):
    events, peer = [], Peer()
    kw = {"monotonic": clock} if clock else {}
    broker = KnowledgeContextBroker(client=peer, policy=_policy(), mission="lab",
                                    alias_key=b"x" * 32, enabled=True,
                                    audit=events.append, observation_rule=rule, **kw)
    return broker, peer, events


def last(events):
    return events[-1]


def test_without_a_rule_an_observation_question_is_refused_and_no_peer_call(env):
    broker, peer, events = make(None)
    assert broker.handle(frame(Q)) == {"refusal": "unavailable"}
    assert peer.calls == 0
    assert [e["event_type"] for e in events] == ["knowledge.context.completed"]
    assert (last(events)["outcome"], last(events)["reason_code"]) == (
        "unavailable", "refused_before_send")


def test_existing_and_non_matching_questions_are_unchanged_without_a_rule(env):
    for q in ("public question", "synthetic public observation context"):
        broker, peer, events = make(None)
        assert broker.handle(frame(q)) == {"response": {"authority": "advisory_only"}}
        assert peer.calls == 1
        assert [e["event_type"] for e in events] == [
            "knowledge.context.requested", "knowledge.context.completed"]
        assert set(last(events)) == {"event_type", "outcome", "response_bytes", "elapsed_ms"}


def test_non_matching_question_is_not_limited_or_latched(env):
    path = write_rule(env, 1)
    broker, peer, events = make(cfg.load_observation_rule())
    for _ in range(5):
        assert "response" in broker.handle(frame("public question"))
    path.unlink()
    assert "response" in broker.handle(frame("public question"))
    assert peer.calls == 6


def test_rate_limit_counts_to_the_cap_and_recovers_after_60s(env):
    write_rule(env, 6)
    now = [100.0]
    broker, peer, events = make(cfg.load_observation_rule(), lambda: now[0])
    for i in range(6):
        now[0] = 100.0 + i
        assert "response" in broker.handle(frame(Q))
    now[0] = 106.0
    n = len(events)
    assert broker.handle(frame(Q)) == {"refusal": "unavailable"}
    assert peer.calls == 6
    assert [e["event_type"] for e in events[n:]] == ["knowledge.context.completed"]
    assert (last(events)["outcome"], last(events)["reason_code"]) == (
        "unavailable", "rate_limited")
    now[0] = 159.9   # first count (t=100) still inside the window
    assert broker.handle(frame(Q)) == {"refusal": "unavailable"}
    now[0] = 160.0   # t=100 has aged out
    assert "response" in broker.handle(frame(Q))
    assert peer.calls == 7


def test_busy_request_is_still_counted(env):
    write_rule(env, 2)
    now = [10.0]
    broker, peer, events = make(cfg.load_observation_rule(), lambda: now[0])
    assert broker._slot.acquire(blocking=False)
    assert broker.handle(frame(Q)) == {"refusal": "timeout"}
    assert last(events)["reason_code"] == "busy"
    assert broker.handle(frame(Q)) == {"refusal": "timeout"}
    assert broker.handle(frame(Q)) == {"refusal": "unavailable"}
    assert last(events)["reason_code"] == "rate_limited"


@pytest.mark.parametrize("mutate", ["remove", "replace", "rewrite"])
def test_rule_change_latches_closed_until_restart(env, mutate):
    path = write_rule(env, 6)
    broker, peer, events = make(cfg.load_observation_rule())
    assert "response" in broker.handle(frame(Q))
    if mutate == "remove":
        path.unlink()
    elif mutate == "replace":
        other = path.with_name("new.json")
        other.write_text(path.read_text())
        os.chmod(other, 0o644)
        os.replace(other, path)
    else:
        path.write_text(path.read_text() + " ")
    for _ in range(2):
        assert broker.handle(frame(Q)) == {"refusal": "unavailable"}
        assert last(events)["reason_code"] == "refused_before_send"
    # restoring the original content does not reopen it
    write_rule(env, 6)
    assert broker.handle(frame(Q)) == {"refusal": "unavailable"}
    assert peer.calls == 1
    # a restart (new broker, fresh read) reopens it
    fresh, peer2, _ = make(cfg.load_observation_rule())
    assert "response" in fresh.handle(frame(Q))


@pytest.mark.parametrize("question,observation", [
    ("ATT&CK technique context: T1059", True),
    ("ATT&CK technique context: T1059.001", True),
    (" ".join(["ATT&CK technique context:"] + ["T1059"] * 8), True),
    ("ATT&CK technique context: T1059 T1059", True),
    ("ATT&CK technique context:", False),
    ("ATT&CK technique context: ", False),
    (" ".join(["ATT&CK technique context:"] + ["T1059"] * 9), False),
    ("att&ck technique context: T1059", False),
    ("ATT&CK technique context: t1059", False),
    ("ATT&CK technique context: T1059 ", False),
    ("ATT&CK technique context: T1059\n", False),
    ("ATT&CK technique context: T105", False),
    ("ATT&CK technique context: T1059.01", False),
    ("ATT&CK technique context: T1059  T1060", False),
    (" ATT&CK technique context: T1059", False),
])
def test_sentence_pattern_boundaries(env, question, observation):
    broker, peer, events = make(None)   # no rule: observation => refused
    result = broker.handle(frame(question))
    if observation:
        assert result == {"refusal": "unavailable"} and peer.calls == 0
    else:
        assert "response" in result and peer.calls == 1


def test_gate_runs_before_the_requested_event(env):
    write_rule(env, 1)
    broker, peer, events = make(cfg.load_observation_rule())
    broker.handle(frame(Q))
    broker.handle(frame(Q))
    assert [e["event_type"] for e in events] == [
        "knowledge.context.requested", "knowledge.context.completed",
        "knowledge.context.completed"]


def test_audit_never_carries_question_text(env):
    broker, _, events = make(None)
    broker.handle(frame(Q))
    assert "T1059" not in json.dumps(events)


def test_main_reads_the_rule_once_and_records_loaded_only_when_present(env, monkeypatch):
    seen = []

    class Ledger:
        def __init__(self, path):
            self.path = path

        def verify(self): pass
        def append(self, event): seen.append(event)

    class Path:
        def open(self, *a, **k):
            import io
            return io.StringIO()
    monkeypatch.setattr(kc, "AuditLedger", lambda p: type("L", (Ledger,), {})(Path()))
    captured = {}
    monkeypatch.setattr(kc, "serve_forever", lambda **kw: captured.setdefault("h", kw) and 0)
    for rule_present in (False, True):
        seen.clear()
        if rule_present:
            write_rule(env, 3)
        assert kc.main([]) == 0
        commissioning = seen[0]
        if rule_present:
            assert commissioning["observation_rule"] == "loaded"
        else:
            assert commissioning == {"event_type": "knowledge.context.commissioning",
                                     "outcome": "absent"}
