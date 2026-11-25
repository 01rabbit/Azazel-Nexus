"""Observation-origin gate in the broker (unit B2).

Since #439 the broker accepts only the technique form (`{privacy_class,
techniques}`), and every one of those is judged by this gate. A free-form
`question` -- the old observation sentence included -- is refused before the
gate, so it is neither counted nor able to latch anything.
"""
import json
import os

import pytest

from azazel_nexus_runtime import knowledge_context_config as cfg
from azazel_nexus_runtime import knowledge_contextd as kc
from azazel_nexus_runtime import runtime_paths
from stop_helpers import granted_marker
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


def tech(ids=("T1059", "T1059.001"), at=None):
    """A technique request. ``at`` is the injected broker clock (seconds):
    the absolute deadline must come from that same clock, or the result
    depends on the host's real monotonic value (uptime) -- #448."""
    deadline = {} if at is None else {"deadline_monotonic_ns": int((at + 0.5) * 1_000_000_000)}
    return _request(payload={"frame": {"privacy_class": "P0-public",
                                       "techniques": list(ids)}}, **deadline)


GATED = {"refusal": "unavailable", "stage": "refused_before_send"}
BUSY = {"refusal": "timeout", "stage": "refused_before_send"}


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
    broker = KnowledgeContextBroker(grant_marker=granted_marker, client=peer, policy=_policy(), mission="lab",
                                    alias_key=b"x" * 32, enabled=True,
                                    audit=events.append, observation_rule=rule, **kw)
    return broker, peer, events


def last(events):
    return events[-1]


def test_without_a_rule_a_technique_query_is_refused_and_no_peer_call(env):
    broker, peer, events = make(None)
    assert broker.handle(tech()) == GATED
    assert peer.calls == 0
    assert [e["event_type"] for e in events] == ["knowledge.context.completed"]
    assert (last(events)["outcome"], last(events)["reason_code"]) == (
        "unavailable", "refused_before_send")


@pytest.mark.parametrize("rule", [False, True])
def test_a_question_is_refused_before_sending_with_or_without_a_rule(env, rule):
    if rule:
        write_rule(env, 6)
    for q in ("public question", "synthetic public observation context", Q):
        broker, peer, events = make(cfg.load_observation_rule() if rule else None)
        assert broker.handle(frame(q)) == {"refusal": "unavailable", "stage": "refused_before_send"}
        assert peer.calls == 0
        assert [e["event_type"] for e in events] == ["knowledge.context.completed"]
        assert last(events)["reason_code"] == "refused_before_send"


def test_a_question_is_not_counted_and_does_not_latch(env):
    path = write_rule(env, 1)
    broker, peer, events = make(cfg.load_observation_rule())
    for _ in range(5):
        assert broker.handle(frame("public question")) == {"refusal": "unavailable", "stage": "refused_before_send"}
    # the one-a-minute rule still has its one request
    assert "response" in broker.handle(tech())
    assert peer.calls == 1
    path.unlink()
    assert broker.handle(frame("public question")) == {"refusal": "unavailable", "stage": "refused_before_send"}
    assert broker.handle(tech()) == GATED
    assert peer.calls == 1


def test_rate_limit_counts_to_the_cap_and_recovers_after_60s(env):
    write_rule(env, 6)
    now = [100.0]
    broker, peer, events = make(cfg.load_observation_rule(), lambda: now[0])
    for i in range(6):
        now[0] = 100.0 + i
        assert "response" in broker.handle(tech(at=now[0]))
    now[0] = 106.0
    n = len(events)
    assert broker.handle(tech(at=now[0])) == GATED
    assert peer.calls == 6
    assert [e["event_type"] for e in events[n:]] == ["knowledge.context.completed"]
    assert (last(events)["outcome"], last(events)["reason_code"]) == (
        "unavailable", "rate_limited")
    now[0] = 159.9   # first count (t=100) still inside the window
    assert broker.handle(tech(at=now[0])) == GATED
    now[0] = 160.0   # t=100 has aged out
    assert "response" in broker.handle(tech(at=now[0]))
    assert peer.calls == 7


def test_busy_request_is_still_counted(env):
    write_rule(env, 2)
    now = [10.0]
    broker, peer, events = make(cfg.load_observation_rule(), lambda: now[0])
    assert broker._slot.acquire(blocking=False)
    assert broker.handle(tech(at=now[0])) == BUSY
    assert last(events)["reason_code"] == "busy"
    assert broker.handle(tech(at=now[0])) == BUSY
    assert broker.handle(tech(at=now[0])) == GATED
    assert last(events)["reason_code"] == "rate_limited"


@pytest.mark.parametrize("mutate", ["remove", "replace", "rewrite"])
def test_rule_change_latches_closed_until_restart(env, mutate):
    path = write_rule(env, 6)
    broker, peer, events = make(cfg.load_observation_rule())
    assert "response" in broker.handle(tech())
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
        assert broker.handle(tech()) == GATED
        assert last(events)["reason_code"] == "refused_before_send"
    # restoring the original content does not reopen it
    write_rule(env, 6)
    assert broker.handle(tech()) == GATED
    assert peer.calls == 1
    # a restart (new broker, fresh read) reopens it
    fresh, peer2, _ = make(cfg.load_observation_rule())
    assert "response" in fresh.handle(tech())


def test_unchanged_rule_stays_open(env):
    write_rule(env, 6)
    broker, peer, events = make(cfg.load_observation_rule())
    for _ in range(3):
        assert "response" in broker.handle(tech())
    assert peer.calls == 3


@pytest.mark.parametrize("same_size", [False, True])
def test_rewrite_with_unchanged_inode_mtime_and_size_still_latches(env, same_size):
    """Timestamps are coarse and can be restored; the content decides (#445)."""
    path = write_rule(env, 6)
    broker, peer, events = make(cfg.load_observation_rule())
    assert "response" in broker.handle(tech())
    before = os.lstat(path)
    text = path.read_text()
    path.write_text(text.replace('": 6', '": 9') if same_size else text + " ")
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = os.lstat(path)
    assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    if same_size:
        assert after.st_size == before.st_size
    # ctime cannot be set from user space; the content digest must carry the decision
    for _ in range(2):
        assert broker.handle(tech()) == GATED
        assert last(events)["reason_code"] == "refused_before_send"
    assert peer.calls == 1


def test_rule_identity_covers_content(env):
    path = write_rule(env, 6)
    first = cfg.observation_rule_identity(path)
    assert first == cfg.load_observation_rule()[1]
    path.write_text(path.read_text().replace('": 6', '": 9'))
    assert cfg.observation_rule_identity(path) != first
    path.unlink()
    assert cfg.observation_rule_identity(path) is None


def latch_events(events):
    return [e for e in events if e["event_type"] == "knowledge.context.observation_latched"]


@pytest.mark.parametrize("identity", [None, (), (1, 2, 3, 4), (1, 2, 3, 4, 5, 6), [1, 2, 3, 4, "x"], "abcde"])
def test_a_malformed_identity_closes_from_the_first_request(env, identity):
    write_rule(env, 6)
    broker, peer, events = make((cfg.ObservationRule("technique-set/1", 6), identity))
    for _ in range(3):
        assert broker.handle(tech()) == GATED
        assert last(events)["reason_code"] == "refused_before_send"
    assert peer.calls == 0
    assert [e["reason_code"] for e in latch_events(events)] == ["invalid_identity"]


@pytest.mark.parametrize("mutate,reason", [("remove", "missing"), ("replace", "changed"),
                                           ("rewrite", "changed"), ("unreadable", "unreadable")])
def test_latching_is_recorded_once_with_its_reason(env, mutate, reason):
    path = write_rule(env, 6)
    broker, peer, events = make(cfg.load_observation_rule())
    assert "response" in broker.handle(tech())
    assert latch_events(events) == []
    if mutate == "remove":
        path.unlink()
    elif mutate == "replace":
        other = path.with_name("new.json")
        other.write_text(path.read_text())
        os.chmod(other, 0o644)
        os.replace(other, path)
    elif mutate == "rewrite":
        path.write_text(path.read_text() + " ")
    else:
        path.unlink()
        path.mkdir()  # present but not a regular file
    for _ in range(3):
        assert broker.handle(tech()) == GATED
    assert latch_events(events) == [{"event_type": "knowledge.context.observation_latched",
                                     "outcome": "latched", "reason_code": reason}]


def test_a_failing_audit_sink_does_not_keep_the_gate_open(env):
    path = write_rule(env, 6)
    broker, peer, events = make(cfg.load_observation_rule())
    real = broker._audit

    def flaky(event):
        if event["event_type"] == "knowledge.context.observation_latched":
            raise OSError("sink down")
        real(event)
    broker._audit = flaky
    path.write_text(path.read_text() + " ")
    assert broker.handle(tech()) == GATED
    assert broker.handle(tech()) == GATED
    assert peer.calls == 0


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
def test_the_old_sentence_is_no_longer_a_way_in(env, question, observation):
    """Matching the old observation sentence or not, a question is refused (#439)."""
    write_rule(env, 60)
    broker, peer, events = make(cfg.load_observation_rule())
    assert broker.handle(frame(question)) == {"refusal": "unavailable", "stage": "refused_before_send"}
    assert peer.calls == 0
    assert last(events)["reason_code"] == "refused_before_send"


def test_gate_runs_before_the_requested_event(env):
    write_rule(env, 1)
    broker, peer, events = make(cfg.load_observation_rule())
    broker.handle(tech())
    broker.handle(tech())
    assert [e["event_type"] for e in events] == [
        "knowledge.context.requested", "knowledge.context.completed",
        "knowledge.context.completed"]


def test_audit_never_carries_question_text(env):
    broker, _, events = make(None)
    broker.handle(tech())
    assert "T1059" not in json.dumps(events)


def test_main_reads_the_rule_once_and_records_loaded_only_when_present(env, monkeypatch):
    seen = []

    class Ledger:
        def __init__(self, path):
            self.path = path

        def verify(self, **_kwargs): pass
        def __iter__(self): return iter(())
        def append(self, event): seen.append(event)

    class Path:
        def open(self, *a, **k):
            import io
            return io.StringIO()
    from azazel_nexus_runtime import runtime_paths
    runtime_paths.socket_path("knowledge-context").parent.mkdir(parents=True, exist_ok=True)
    runtime_paths.knowledge_context_state_dir().mkdir(parents=True, exist_ok=True)
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
