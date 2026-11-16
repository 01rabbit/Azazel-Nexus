"""`mio.context.observe` (T1): explainer-only, observation-origin Full lookup.

entry validates and relays; locald builds the fixed-sentence P0 question and
re-runs the core with `knowledge_lookup=None`. The shared core
(`azazel_mio`) is not required: it is replaced at the module boundary, so the
tests pin the contract of this repository's code only.
"""
import json
import os
import re
import sys
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import mio_entryd as entry
from azazel_nexus_runtime import mio_locald as locald
from azazel_nexus_runtime import mio_socket_client as client
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.knowledge_context_socket import KnowledgeContextUnavailable
from azazel_nexus_runtime.principal import Principal, PrincipalClass
from azazel_nexus_runtime.protocol import RequestRefused
from test_incident_explain import transition

from azazel_nexus.incident_explain import build_frame, pending_entry, read_fast_transition
from azazel_nexus.local_advisory import read_fast_assistance
from azazel_nexus.route_ledger import RouteChain
from azazel_nexus.sanitizer import PrivacyClass

QUESTION_FORM = re.compile(r"ATT&CK technique context: T[0-9]{4}(\.[0-9]{3})?"
                           r"( T[0-9]{4}(\.[0-9]{3})?){0,7}")
EXPLAINER = Principal(4242, 7, 1, frozenset({PrincipalClass.SERVICE}))


def obs_frame(ids=("T1059", "T1059.001"), **kw):
    t = transition(**kw)
    t["technique_ids"] = list(ids)
    return build_frame(pending_entry(t), 3)


def good_fast(status="not_queried", **extra):
    base = client.fast_assessment_degraded("unavailable")
    base["dependency_outcome"] = {"knowledge": "absent", "deception": "absent"}
    base["state"] = "evidence_gaps_identified"
    base["unknowns"] = ["Fast assessment unavailable"]
    base["full_node_context_status"] = status
    base.update(extra)
    return base


# ---- registry and entry ------------------------------------------------

def test_verb_is_in_the_explainer_registry_only_and_service_only():
    assert entry.CONTEXT_OBSERVE_VERB.name == "mio.context.observe"
    assert "mio.context.observe" in entry.ADVISE_REGISTRY.names()
    assert "mio.context.observe" not in entry.REGISTRY.names()
    assert entry.CONTEXT_OBSERVE_VERB.admits == frozenset({PrincipalClass.SERVICE})
    assert "mio.local.observe" in locald.REGISTRY.names()
    assert locald.CONTEXT_OBSERVE_VERB.admits == frozenset({PrincipalClass.SERVICE})


@pytest.mark.parametrize("verb", [entry.CONTEXT_OBSERVE_VERB, locald.CONTEXT_OBSERVE_VERB])
@pytest.mark.parametrize("value,ok", [(1, True), (350, True), (351, False), (-1, False),
                                      ("350", False), (True, False), (1.5, False)])
def test_deadline_argument_is_bounded_at_350(verb, value, ok):
    if ok:
        assert verb.bind({"deadline_ms": value}) == {"deadline_ms": value}
    else:
        with pytest.raises(RequestRefused):
            verb.bind({"deadline_ms": value})


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    runtime_paths.mio_state_dir().mkdir(parents=True)
    svc = entry.MioEntryService()
    svc._explainer_uid = 4242
    return svc


def req(frame, deadline=350, principal=EXPLAINER):
    return SimpleNamespace(verb=entry.CONTEXT_OBSERVE_VERB, arguments={"deadline_ms": deadline},
                           payload=frame, principal=principal)


def ledger_rows(service):
    chain = RouteChain(service.router.ledger.directory)
    chain.verify()
    return [item.event for item in chain]


def stub_relay(service, monkeypatch, result=None):
    calls = []

    def observe_context_timed(frame, *, deadline_s):
        calls.append((frame, deadline_s))
        return result or good_fast("received"), {"context": "received", "broker_ms": 12, "total_ms": 30}

    monkeypatch.setattr(service.local, "observe_context_timed", observe_context_timed, raising=False)
    return calls


def test_entry_relays_validated_projection_writes_no_ledger_and_reports_timing(service, monkeypatch):
    calls = stub_relay(service, monkeypatch)
    before = ledger_rows(service)
    frame = obs_frame()
    reply = service.handle(req(frame))
    assert reply["outcome"] == "context_observed"
    assert reply["fast_assistance"]["full_node_context_status"] == "received"
    assert set(reply["timing"]) == {"locald", "entry_ms"}
    assert reply["timing"]["locald"] == {"context": "received", "broker_ms": 12, "total_ms": 30}
    assert isinstance(reply["timing"]["entry_ms"], int)
    assert [c[0] for c in calls] == [frame]
    # deadline: 350 ms less entry's 30 ms delivery reserve, never more
    assert 0 < calls[0][1] <= 0.350 - entry.ENTRY_DELIVERY_RESERVE_MS / 1000 + 1e-6
    after = ledger_rows(service)
    assert [e for e in after if e not in before] == []
    assert not any(e["event_type"] in {"mio.request", "mio.route.selected"} for e in after[len(before):])


def test_entry_refuses_everything_but_the_explainer(service, monkeypatch):
    calls = stub_relay(service, monkeypatch)
    for principal in (None,
                      Principal(4243, 7, 1, frozenset({PrincipalClass.SERVICE})),
                      Principal(4242, 7, 1, frozenset({PrincipalClass.OPERATOR}))):
        with pytest.raises(RequestRefused, match="context_observe_explainer"):
            service.handle(req(obs_frame(), principal=principal))
    assert calls == []


def test_entry_refuses_p0_frame_missing_projection_and_zero_deadline(service, monkeypatch):
    calls = stub_relay(service, monkeypatch)
    frame = obs_frame()
    p0 = {"request_id": "x", "privacy_class": "P0-public",
          "question": "ATT&CK technique context: T1059", "context": [{"kind": "technique", "text": "T1059"}]}
    with pytest.raises(RequestRefused):
        service.handle(req(p0))
    for privacy in PrivacyClass:
        if privacy is not PrivacyClass.P3_RESTRICTED:
            with pytest.raises(RequestRefused):
                service.handle(req({**frame, "privacy_class": privacy.value}))
    no_projection = {**frame, "context": [c for c in frame["context"]
                                          if c["kind"] != "edge_fast_transition"
                                          and "transition" not in c["kind"]]}
    assert no_projection["context"] != frame["context"]
    with pytest.raises(RequestRefused):
        service.handle(req(no_projection))
    with pytest.raises(RequestRefused):
        service.handle(req(frame, deadline=0))
    # a tampered projection fails read_fast_transition
    tampered = json.loads(json.dumps(frame))
    for item in tampered["context"]:
        if "transition" in item["kind"]:
            item["text"] = item["text"].replace('"count":', '"count": ')
    with pytest.raises(RequestRefused):
        service.handle(req(tampered))
    assert calls == []


def test_branch_precedes_the_explainer_verb_refusal(service, monkeypatch):
    stub_relay(service, monkeypatch)
    # the same principal is refused for any other non-advice verb
    other = SimpleNamespace(verb=entry.ROUTE_VERB, arguments={"deadline_ms": 100,
                            "privacy_class": "P3-restricted"}, principal=EXPLAINER)
    with pytest.raises(RequestRefused, match="explainer_verb"):
        service.handle(other)
    assert service.handle(req(obs_frame()))["outcome"] == "context_observed"


def test_rate_slot_is_shared_with_the_explainer(service, monkeypatch):
    stub_relay(service, monkeypatch)
    ticks = [0.0]
    service.rate = entry.PrincipalRate(per_minute=0, burst=2, clock=lambda: ticks[0])
    service.handle(req(obs_frame()))
    # one slot left; an advice-verb call from the same uid consumes it
    advice = SimpleNamespace(verb=entry.ADVISE_VERB, arguments={"deadline_ms": 500},
                             payload=obs_frame(), principal=EXPLAINER)
    monkeypatch.setattr(service, "_handle", lambda *a, **k: {"outcome": "x"})
    service.handle(advice)
    with pytest.raises(RequestRefused) as refused:
        service.handle(req(obs_frame()))
    assert refused.value.refusal.value == "rate_limited"


# ---- relay client ------------------------------------------------------

def test_client_wires_the_local_verb_and_degrades_without_locald(monkeypatch):
    seen = {}

    def exchange(leaf, account, verb, arguments, *, payload=None, deadline_s):
        seen.update(leaf=leaf, account=account, verb=verb, arguments=arguments,
                    payload=payload, deadline_s=deadline_s)
        return {"outcome": "context_observed", "fast_assistance": good_fast("received"),
                "timing": {"context": "received", "broker_ms": 5, "total_ms": 9}}

    monkeypatch.setattr(client, "_exchange", exchange)
    local = client.LocalSocketClient()
    frame = obs_frame()
    value = local.observe_context(frame, deadline_s=0.32)
    assert value["full_node_context_status"] == "received"
    assert (seen["leaf"], seen["account"], seen["verb"]) == ("mio", "azmio", "mio.local.observe")
    assert seen["arguments"] == {"deadline_ms": 320} and seen["payload"] == frame
    assert local.last_observe_timing == {"context": "received", "broker_ms": 5, "total_ms": 9}

    def broken(*a, **k):
        raise OSError("no socket")

    monkeypatch.setattr(client, "_exchange", broken)
    degraded = local.observe_context(frame, deadline_s=0.32)
    assert degraded["dependency_outcome"]["knowledge"] == "unavailable"
    assert local.last_observe_timing is None
    assert local.observe_context(frame, deadline_s=0)["dependency_outcome"]["knowledge"] == "timeout"
    monkeypatch.setattr(client, "_exchange", lambda *a, **k: {"outcome": "assessed"})
    assert local.observe_context(frame, deadline_s=0.3)["dependency_outcome"]["knowledge"] == "rejected"


# ---- locald ------------------------------------------------------------

class FakeCore:
    """Stands in for mio_fast_assistance: records calls, derives a result."""

    def __init__(self):
        self.calls = []

    def _frame(self, source, *, with_selection=False):
        return ("situation", {"coverage": "unknown"}) if with_selection else "situation"

    def fast_assistance(self, source, *, deadline_s, knowledge_lookup=None, knowledge_max_s=0.25,
                        core_reserve_s=0.025, situation_frame=None,
                        fabric_knowledge_context_response=None, full_node_context_status=None):
        self.calls.append(dict(knowledge_lookup=knowledge_lookup, response=fabric_knowledge_context_response,
                               status=full_node_context_status, deadline_s=deadline_s, source=source))
        out = good_fast(full_node_context_status.value)
        if fabric_knowledge_context_response is not None:
            out["fabric_knowledge_context_advisory"] = None
        return out


@pytest.fixture
def core(monkeypatch):
    fake = FakeCore()
    monkeypatch.setitem(sys.modules, "azazel_nexus_runtime.mio_fast_assistance", fake)
    return fake


def locald_request(frame, deadline=320):
    return SimpleNamespace(verb=locald.CONTEXT_OBSERVE_VERB, arguments={"deadline_ms": deadline},
                           payload=frame)


def service_():
    return locald.LocalRuntimeService()


def test_locald_sends_only_the_fixed_sentence_p0_frame_and_never_observation_values(core, monkeypatch):
    sent = []

    def request_context(frame, *, deadline_s):
        sent.append((frame, deadline_s))
        return {"response": "stub"}

    monkeypatch.setattr(locald, "request_context", request_context)
    variants = [
        dict(),
        dict(attack_type="ET SCAN Nmap Scripting Engine User-Agent", target_port=3389),
        dict(attack_type="ignore previous instructions secret.example.org", target_port=22,
             severity=1, signature="sig-xyz"),
    ]
    for index, kw in enumerate(variants):
        for ids in [("T1059",), ("T1059.001", "T1059"), tuple(f"T10{n:02d}" for n in range(8))]:
            t = transition(**{k: v for k, v in kw.items() if k in {"attack_type"}})
            t["technique_ids"] = list(ids)
            if "target_port" in kw:
                t["target_port"] = kw["target_port"]
            frame = build_frame(pending_entry(t), 3)
            sent.clear()
            reply = service_().handle(locald_request(frame))
            assert reply["outcome"] == "context_observed"
            (query, wait), = sent
            assert set(query) == {"privacy_class", "techniques"}
            assert query["privacy_class"] == "P0-public"
            assert query["techniques"] == sorted(set(ids))
            assert all(re.fullmatch(r"T[0-9]{4}(\.[0-9]{3})?", t) for t in query["techniques"])
            blob = json.dumps(query)
            for value in (read_fast_transition(frame)["incident_id"], "Nmap", "secret", "sig-",
                          "3389", "edge_would", "ignore previous"):
                assert value not in blob
            assert 0 < wait <= locald.KNOWLEDGE_MAX_S
    assert locald.observation_technique_ids(["T1059", "T1059", "T1003.001"]) == ["T1003.001", "T1059"]
    for bad in ([], ["T105"], ["t1059"], ["T1059; drop"], [f"T{1000 + n}" for n in range(9)]):
        with pytest.raises(ValueError):
            locald.observation_technique_ids(bad)


def test_locald_budget_is_min_of_cap_and_remaining_minus_reserves(core, monkeypatch):
    waits = []
    monkeypatch.setattr(locald, "request_context",
                        lambda frame, *, deadline_s: waits.append(deadline_s) or {"r": 1})
    service_().handle(locald_request(obs_frame(), deadline=320))
    assert waits[-1] == pytest.approx(locald.KNOWLEDGE_MAX_S)
    service_().handle(locald_request(obs_frame(), deadline=150))
    assert 0 < waits[-1] <= 0.150 - locald.DELIVERY_RESERVE_S - locald.FAST_CORE_RESERVE_S + 1e-3
    waits.clear()
    reply = service_().handle(locald_request(obs_frame(), deadline=40))  # less than the reserves
    assert waits == []
    assert reply["fast_assistance"]["full_node_context_status"] == "unavailable"


def test_locald_technique_answer_is_projected_and_never_given_to_the_core(core, monkeypatch):
    from _technique_fixture import make_response
    monkeypatch.setattr(locald, "request_context", lambda frame, *, deadline_s: make_response(
        ["T1059", "T1059.001"], {"T1059": "found", "T1059.001": "no_match"},
        content={"T1059.001": ("PowerShell", "execution", "15.1")}))
    reply = service_().handle(locald_request(obs_frame()))
    call, = core.calls
    assert call["knowledge_lookup"] is None
    # the core is run as for an unavailable Full lookup: no response reaches it
    assert call["status"] is locald.FullNodeContextStatus.UNAVAILABLE and call["response"] is None
    fast = reply["fast_assistance"]
    assert fast["full_node_context_status"] == "unavailable"
    assert "full_node_context_received_at" not in fast
    record = fast["technique_knowledge"]
    assert (record["transport"], record["verification"]) == ("received", "ok")
    assert [(r["technique_id"], r["coverage"], r["useful_content"]) for r in record["techniques"]] == [
        ("T1059", "found", True), ("T1059.001", "no_match", False)]
    # the value passes the delivery reader
    assert read_fast_assistance(fast) == fast
    assert set(reply["timing"]) == {"context", "broker_ms", "total_ms"}
    assert reply["timing"]["context"] == "received"
    assert all(type(reply["timing"][k]) is int for k in ("broker_ms", "total_ms"))
    assert reply["timing"]["total_ms"] <= 350


@pytest.mark.parametrize("failure", [KnowledgeContextUnavailable("deadline"),
                                     KnowledgeContextUnavailable("peer identity"),
                                     TimeoutError(), OSError("refused")])
def test_locald_unavailable_has_the_same_shape_and_no_received_at(core, monkeypatch, failure):
    def refuse(frame, *, deadline_s):
        raise failure
    monkeypatch.setattr(locald, "request_context", refuse)
    reply = service_().handle(locald_request(obs_frame()))
    fast = reply["fast_assistance"]
    assert reply["outcome"] == "context_observed"
    assert fast["full_node_context_status"] == "unavailable"
    assert "full_node_context_received_at" not in fast
    assert core.calls[-1]["knowledge_lookup"] is None and core.calls[-1]["response"] is None
    assert reply["timing"]["context"] == "unavailable"
    assert fast["technique_knowledge"]["transport"] == "unavailable"
    assert fast["technique_knowledge"]["verification"] == "not_run"
    read_fast_assistance(fast)


def test_locald_refuses_bad_frames_and_deadlines_without_querying(core, monkeypatch):
    monkeypatch.setattr(locald, "request_context",
                        lambda *a, **k: pytest.fail("queried the broker"))
    p0 = {"request_id": "x", "privacy_class": "P0-public",
          "question": "ATT&CK technique context: T1059", "context": [{"kind": "technique", "text": "T1059"}]}
    assert service_().handle(locald_request(p0))["refusal"] == "malformed_frame"
    assert service_().handle(locald_request(obs_frame(), deadline=0))["refusal"] == "deadline"
    assert core.calls == []


def test_received_at_requires_received_status_in_the_delivery_reader():
    ok = good_fast("received", full_node_context_received_at="2026-11-11T01:02:03.123456Z")
    assert read_fast_assistance(ok) == ok
    ok2 = good_fast("received", full_node_context_received_at="2026-11-11T01:02:03Z")
    assert read_fast_assistance(ok2) == ok2
    for status in ("unavailable", "not_queried"):
        with pytest.raises(ValueError):
            read_fast_assistance(good_fast(status, full_node_context_received_at="2026-11-11T01:02:03Z"))
    for bad in ("2026-11-11 01:02:03Z", "2026-11-11T01:02:03+00:00", "2026-13-11T01:02:03Z", 5, None):
        with pytest.raises(ValueError):
            read_fast_assistance(good_fast("received", full_node_context_received_at=bad))
    # rows without the key still read
    read_fast_assistance(good_fast("received"))
    read_fast_assistance(good_fast("not_queried"))


# ---- advise equivalence (R1 section 5), needs the pinned shared core --------

#: Fields R1 section 5 lets the Full response change; everything else must be
#: identical to the advise result. `unknowns`/`next_checks` differ only by the
#: Full-derived items.
FULL_FIELDS = {"fabric_knowledge_context_advisory", "full_node_context_status",
               "full_node_context_received_at", "handoff", "reasoning_trace",
               "trace", "trace_id", "frame_id"}


def comparable(fast):
    from azazel_nexus.incident_explain import FULL_NODE_INCOMPLETE_CHECK
    out = {k: v for k, v in fast.items() if k not in FULL_FIELDS}
    out["dependency_outcome"] = {k: v for k, v in fast["dependency_outcome"].items() if k != "knowledge"}
    out["unknowns"] = [u for u in fast["unknowns"] if not u.startswith("KNOWLEDGE_CONTEXT_")]
    out["next_checks"] = [c for c in fast["next_checks"] if c != FULL_NODE_INCOMPLETE_CHECK]
    return out


def test_comparator_ignores_only_the_listed_fields():
    from azazel_nexus.incident_explain import FULL_NODE_INCOMPLETE_CHECK
    base = good_fast("not_queried")
    full = good_fast("received", full_node_context_received_at="2026-11-11T00:00:00Z",
                     fabric_knowledge_context_advisory=None)
    full["unknowns"] = base["unknowns"] + ["KNOWLEDGE_CONTEXT_PARTIAL"]
    full["next_checks"] = base["next_checks"] + [FULL_NODE_INCOMPLETE_CHECK]
    full["trace_id"] = "mio-0123456789abcdef-9"
    full["dependency_outcome"] = {"knowledge": "available", "deception": "absent"}
    assert comparable(full) == comparable(base)
    for key, value in (("state", "complete"), ("hypotheses", [{"x": 1}]), ("knowledge", [{"x": 1}])):
        assert comparable({**full, key: value}) != comparable(base)
    assert comparable({**full, "unknowns": full["unknowns"] + ["other"]}) != comparable(base)


def test_real_core_unavailable_rerun_matches_advise_outside_full_fields(monkeypatch):
    pytest.importorskip("azazel_mio")
    from azazel_nexus_runtime import mio_fast_assistance as adapter
    from azazel_nexus_runtime.knowledge_context_socket import FullNodeContextStatus

    frame = obs_frame()
    situation, _ = adapter._frame(frame, with_selection=True)
    advise = adapter.fast_assistance(frame, deadline_s=1.0, knowledge_lookup=None,
                                     situation_frame=situation,
                                     full_node_context_status=FullNodeContextStatus.NOT_QUERIED)

    def refuse(query, *, deadline_s):
        raise KnowledgeContextUnavailable("refused")

    monkeypatch.setattr(locald, "request_context", refuse)
    reply = service_().handle(locald_request(frame))
    observed = reply["fast_assistance"]
    assert observed["full_node_context_status"] == "unavailable"
    assert comparable(observed) == comparable(advise)


def test_timing_is_local_to_each_request(monkeypatch):
    """Review O1: two interleaved requests keep their own timing (no shared attribute)."""
    import threading
    gate = threading.Barrier(2)

    def exchange(leaf, account, verb, arguments, *, payload=None, deadline_s):
        gate.wait(timeout=5)                                   # both are inside before either returns
        return {"outcome": "context_observed", "fast_assistance": good_fast("received"),
                "timing": {"context": "received", "broker_ms": arguments["deadline_ms"],
                           "total_ms": arguments["deadline_ms"]}}

    monkeypatch.setattr(client, "_exchange", exchange)
    local = client.LocalSocketClient()
    frame, out = obs_frame(), {}

    def run(ms):
        out[ms] = local.observe_context_timed(frame, deadline_s=ms / 1000)[1]

    threads = [threading.Thread(target=run, args=(ms,)) for ms in (100, 200)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert out[100]["broker_ms"] == 100 and out[200]["broker_ms"] == 200
