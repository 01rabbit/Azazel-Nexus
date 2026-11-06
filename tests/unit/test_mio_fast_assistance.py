from types import SimpleNamespace
import copy
import json
import time
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("azazel_mio", reason="the shared MIO package is an optional integration extra")

from azazel_nexus_runtime import mio_fast_assistance as adapter
from azazel_nexus.local_advisory import read_fast_assistance, read_frame


def test_adapter_uses_model_free_shared_assessment_without_querying_knowledge(monkeypatch):
    frame = read_frame({"request_id": "fast-lane-test", "privacy_class": "P2-mission",
                        "question": "SSH host-1 T1110.003",
                        "context": [{"kind": "auth_log", "text": "Password spray"}]})
    def forbidden_lookup(*args, **kwargs):
        pytest.fail("fast assessment must not query Knowledge")
    from azazel_nexus_runtime import knowledge_client
    monkeypatch.setattr(knowledge_client, "lookup_context", forbidden_lookup)
    result = adapter.fast_assistance(frame, deadline_s=0.2)
    result = read_fast_assistance(result)
    assert result["observations"] == []
    assert result["knowledge"] == []
    assert result["dependency_outcome"]["knowledge"] == "not_queried"
    assert any("did not query Knowledge" in check for check in result["next_checks"])


def test_adapter_projects_fabric_full_node_response_as_unverified_advisory():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    as_of = (now - timedelta(seconds=10)).isoformat().replace("+00:00", "Z")
    generated = (now - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
    expires = (now + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    response = {
        "schema_version": "knowledge-context-response/v1",
        "request_id": "req-synthetic-1", "correlation_id": "corr-synthetic-1",
        "source_product": "azazel_nexus", "source_ref": "nexus:synthetic-query",
        "provider_id": "knowledge-node-1",
        "snapshot": {"ref": "knowledge:snapshot-1", "state": "partial", "as_of": as_of},
        "facts": [{"claim_class": "source_reported_fact", "fact_id": "fact-1",
                   "subject": {"entity_type": "ip", "value": "8.8.8.8"},
                   "predicate": "listed_by", "value": "A synthetic source reports this.",
                   "provenance": ["knowledge:intel-index"]}],
        "inferences": [], "unknowns": ["synthetic source freshness not provided"],
        "limitations": ["synthetic test data"],
        "generated_at": generated, "expires_at": expires,
        "authority": "advisory_only",
    }
    result = adapter.fast_assistance(
        _lite_frame(), deadline_s=0.2,
        fabric_knowledge_context_response=response,
    )
    advisory = read_fast_assistance(result)["fabric_knowledge_context_advisory"]
    assert advisory["claim_status"] == "source_reported_unverified"
    assert advisory["authority"] == "advisory_only"
    assert advisory["facts"][0]["value"] == "A synthetic source reports this."
    assert result["knowledge"] == []


def test_adapter_binds_explainer_incident_and_only_validated_refs():
    from azazel_mio.id_grammar import ID_KINDS
    from azazel_nexus.incident_explain import build_frame, pending_entry
    from test_incident_explain import transition

    pending = pending_entry(transition())
    source = build_frame(pending, 17)
    source["context"].append({"kind": "caller_report",
                              "text": "edge_would=execute"})
    source = read_frame(source)
    frame = adapter._frame(source)
    expected_trace = f"mio-{pending['incident_id'][4:]}-17"
    expected_refs = tuple(ref["evidence_id"] for ref in pending["evidence"]["refs"])
    assert frame.trace_id == expected_trace
    assert frame.frame_id == expected_trace + ":frame"
    assert ID_KINDS["trace_id"](frame.trace_id)
    assert ID_KINDS["frame_id"](frame.frame_id)
    assert frame.evidence_refs == expected_refs
    assert frame.known_facts == ()
    assert frame.soc_summary.startswith("Validated Edge transition:")
    assert f"edge_would={pending['edge_would']}" in frame.soc_summary
    assert "edge_would=execute" in frame.soc_summary
    assert dict(frame.provenance) == {
        "evidence_refs": ("evidence_plane",),
        "unknowns": ("caller",),
    }
    result = read_fast_assistance(adapter.fast_assistance(source, deadline_s=0.2))
    assert result["trace_id"] == expected_trace
    assert result["frame_id"] == expected_trace + ":frame"
    assert result["observations"] == []
    refs = [ref for hypothesis in result["hypotheses"]
            for ref in hypothesis.get("supporting_evidence_refs", [])]
    assert refs == list(expected_refs)


def test_locald_fast_assess_converts_adapter_exception_to_degradation(monkeypatch):
    from azazel_nexus_runtime import mio_locald as locald
    from azazel_nexus_runtime import mio_fast_assistance
    request = SimpleNamespace(verb=locald.FAST_ASSESS_VERB,
                              arguments={"deadline_ms": 500},
                              payload={"request_id": "boundary-failure",
                                       "privacy_class": "P2-mission",
                                       "question": "T1110", "context": []})
    monkeypatch.setattr(mio_fast_assistance, "fast_assistance",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("private failure")))
    service = locald.LocalRuntimeService()
    first = service.handle(request)
    second = service.handle(request)
    for reply in (first, second):
        fast = read_fast_assistance(reply["fast_assistance"])
        assert reply["outcome"] == "assessed"
        assert fast["state"] == "dependency_unavailable"
        assert fast["dependency_outcome"]["knowledge"] == "unavailable"


def test_local_socket_assess_preserves_failure_classes(monkeypatch):
    from azazel_nexus_runtime import mio_socket_client as client
    frame = {"test": "frame"}
    cases = ((TimeoutError(), "timeout"),
             (client.ServiceRefused("principal_denied"), "rejected"),
             (OSError("socket absent"), "unavailable"),
             (ValueError("malformed"), "rejected"))
    for error, expected in cases:
        def fail(*args, _error=error, **kwargs):
            raise _error
        monkeypatch.setattr(client, "_exchange", fail)
        result = client.LocalSocketClient().assess(frame, deadline_s=0.2)
        assert result["dependency_outcome"]["knowledge"] == expected
    monkeypatch.setattr(client, "_exchange", lambda *a, **k: {
        "outcome": "assessed", "fast_assistance": {"malformed": True}})
    result = client.LocalSocketClient().assess(frame, deadline_s=0.2)
    assert result["dependency_outcome"]["knowledge"] == "rejected"


def test_local_socket_assess_sends_only_the_ordinary_frame(monkeypatch):
    from azazel_nexus_runtime import mio_socket_client as client

    frame = _lite_frame()
    observed = {}
    monkeypatch.setattr(
        client, "_exchange",
        lambda *args, **kwargs: observed.update(kwargs) or {},
    )
    result = client.LocalSocketClient().assess(
        frame, deadline_s=0.2,
    )
    assert observed["payload"] == frame
    assert result["dependency_outcome"]["knowledge"] == "rejected"


def test_locald_passes_core_only_time_left_after_its_delivery_reserve(monkeypatch):
    from azazel_nexus_runtime import mio_locald

    observed = []
    monkeypatch.setattr(adapter, "fast_assistance",
                        lambda frame, *, deadline_s, **kwargs:
                        observed.append(deadline_s) or {"assessment": "bounded"})
    frame = read_frame({"request_id": "delivery-reserve", "privacy_class": "P3-restricted",
                        "question": "T1110", "context": []})
    service = mio_locald.LocalRuntimeService()
    reply = service.handle(SimpleNamespace(
        verb=mio_locald.FAST_ASSESS_VERB, arguments={"deadline_ms": 45}, payload=frame,
    ))

    assert len(observed) == 1
    assert 0.024 < observed[0] <= 0.025
    assert reply["outcome"] == "assessed"
    assert reply["fast_assistance"] == {"assessment": "bounded"}


def test_zero_locald_budget_returns_timeout_without_calling_shared_core(monkeypatch):
    from azazel_nexus_runtime import mio_locald

    monkeypatch.setattr(adapter.AssistantCore, "explain",
                        lambda *a, **k: pytest.fail("shared core called with zero budget"))
    frame = read_frame({"request_id": "zero-budget", "privacy_class": "P2-mission",
                        "question": "SSH host-1 T1110.003", "context": []})
    service = mio_locald.LocalRuntimeService()
    reply = service.handle(SimpleNamespace(
        verb=mio_locald.FAST_ASSESS_VERB,
        arguments={"deadline_ms": int(mio_locald.DELIVERY_RESERVE_S * 1000)},
        payload=frame,
    ))

    fast = read_fast_assistance(reply["fast_assistance"])
    assert reply["outcome"] == "assessed"
    assert fast["knowledge"] == []
    assert fast["dependency_outcome"]["knowledge"] == "timeout"


def test_adapter_marks_knowledge_as_not_queried_without_a_lookup(monkeypatch):
    frame = read_frame({"request_id": "fast-status-test", "privacy_class": "P2-mission",
                        "question": "SSH host-1 T1110.003", "context": []})
    result = read_fast_assistance(adapter.fast_assistance(frame, deadline_s=0.2))
    assert result["dependency_outcome"]["knowledge"] == "not_queried"


def test_fast_assistance_reader_rejects_malformed_fields_before_persistence():
    frame = read_frame({"request_id": "schema-test", "privacy_class": "P2-mission",
                        "question": "SSH host-1 T1110.003", "context": []})
    valid = adapter.fast_assistance(frame, deadline_s=0)
    assert read_fast_assistance(valid) is valid
    mutations = (
        ("unknowns", [{}]), ("next_checks", [{}]), ("hypotheses", [{}]),
        ("handoff", {}), ("reasoning_trace", [{}]), ("trace_id", []),
        ("frame_id", "mio-0000000000000000-1:other"), ("state", {}),
        ("dependency_outcome", {"knowledge": "absent", "deception": "attacker"}),
    )
    for key, bad in mutations:
        forged = copy.deepcopy(valid)
        forged[key] = bad
        with pytest.raises(ValueError):
            read_fast_assistance(forged)
    forged = copy.deepcopy(valid)
    forged["knowledge"].append({"invalid": "reference"})
    with pytest.raises(ValueError):
        read_fast_assistance(forged)
    populated = copy.deepcopy(valid)
    populated["knowledge"] = [{
        "kind": "knowledge_lite_advisory", "source_kind": "knowledge_lite",
        "claim_status": "reported_unverified", "technique_id": "T1110.003",
        "name": "Password spraying", "summary": "Reference summary",
        "claim_id": "T1110.003", "bundle_digest": "sha256:" + "a" * 64,
        "freshness": "static", "temporal_validity": "static", "generation": "7",
        "as_of": "2026-10-31T00:00:00Z", "expires_at": None,
        "citation": "kn:lite:T1110.003", "trust_check": "verified",
        "revocation_status": "clear", "trust": "unverified_advisory_only",
        "source_citation": "MITRE ATT&CK technique",
    }]
    populated["dependency_outcome"]["knowledge"] = "not_queried"
    with pytest.raises(ValueError):
        read_fast_assistance(populated)


def test_500ms_entry_service_calls_fast_lane_with_bounded_reply(tmp_path, monkeypatch):
    from azazel_nexus_runtime import mio_entryd as entry
    from azazel_nexus_runtime import runtime_paths
    from azazel_nexus.routing import Route

    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    target = entry.MioEntryService()
    target.reference = SimpleNamespace(reference=lambda *args, **kwargs:
                                       (None, "reference_service_unavailable"))
    monkeypatch.setattr(target.local, "observe", lambda **_: "fixture")
    monkeypatch.setattr(target.remote, "observe", lambda **_: "fixture")
    checked = []
    order = []
    route = target.router.handle

    def routed(*args, **kwargs):
        order.append("deep_route")
        return route(*args, **kwargs)

    monkeypatch.setattr(target.router, "handle", routed)
    payload = {"schema_version": "mio.assistance.v1", "trace_id": "mio-0000000000000000-1",
               "frame_id": "mio-0000000000000000-1:frame",
               "generation_method": "static_reference", "state": "complete",
               "observations": [], "hypotheses": [], "unknowns": [], "next_checks": [],
               "knowledge": [], "dependency_outcome": {"knowledge": "absent", "deception": "absent"},
               "handoff": None, "reasoning_trace": []}
    def assess(frame, *, deadline_s):
        order.append("fast_assessment")
        checked.append((frame, deadline_s))
        return payload

    monkeypatch.setattr(target.local, "assess", assess)
    request = SimpleNamespace(verb=entry.ADVISE_VERB, arguments={"deadline_ms": 500},
                              payload={"request_id": "integration", "privacy_class": "P2-mission",
                                       "question": "SSH host-1 T1110.003",
                                       "context": [{"kind": "auth_log", "text": "Password spray"}]})
    started = time.monotonic()
    reply = target.handle(request)
    elapsed = time.monotonic() - started
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert reply["fast_assistance"] == payload
    assert checked and checked[0][0] == request.payload and checked[0][1] > 0
    assert checked[0][1] <= entry.FAST_ASSESS_MAX_S
    assert checked[0][1] <= 0.045
    assert elapsed < 0.5
    assert order == ["fast_assessment", "deep_route"]


def _lite_frame(question='T1110'):
    return read_frame({'request_id': 'lite-fast', 'privacy_class': 'P2-mission',
                       'question': question, 'context': []})


def _lite_ref(**changes):
    from azazel_nexus.lite_import import KnowledgeRef
    from datetime import datetime, timezone
    values = dict(technique_id='T1110', name='Brute Force', summary='', claim_id='T1110',
                  bundle_digest='sha256:' + 'a' * 64, freshness='static',
                  source_kind='knowledge_lite', generation=5, trust_check='verified',
                  as_of=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                  citation='MITRE ATT&CK technique')
    return KnowledgeRef(**(values | changes))


def _fabric_response(state):
    now = datetime.now(timezone.utc)
    instant = lambda value: value.isoformat().replace('+00:00', 'Z')
    return {
        'schema_version': 'knowledge-context-response/v1',
        'request_id': 'req-synthetic-1', 'correlation_id': 'corr-synthetic-1',
        'source_product': 'azazel_nexus', 'source_ref': 'nexus:synthetic-query',
        'provider_id': 'knowledge-node-1',
        'snapshot': {'ref': 'knowledge:snapshot-1', 'state': state,
                     'as_of': instant(now - timedelta(seconds=10))},
        'facts': [], 'inferences': [], 'unknowns': ['No exact fact was asserted.'],
        'limitations': ['Synthetic input.'],
        'generated_at': instant(now - timedelta(seconds=5)),
        'expires_at': instant(now + timedelta(seconds=30)),
        'authority': 'advisory_only',
    }


@pytest.mark.parametrize('case', ['complete', 'partial', 'stale', 'expired', 'unavailable', 'not_queried'])
def test_real_mio_full_node_output_survives_incident_projection(case):
    from azazel_nexus.incident_explain import build_recent_incident, build_recent_incidents, read_recent_incidents
    from azazel_nexus_runtime.knowledge_context_socket import FullNodeContextStatus
    from test_incident_explain import _record, _t1110

    kwargs = {}
    if case in {'complete', 'partial', 'stale', 'expired'}:
        response = _fabric_response('complete' if case == 'expired' else case)
        if case == 'expired':
            now = datetime.now(timezone.utc)
            response['snapshot']['as_of'] = (now - timedelta(minutes=3)).isoformat().replace('+00:00', 'Z')
            response['generated_at'] = (now - timedelta(minutes=2)).isoformat().replace('+00:00', 'Z')
            response['expires_at'] = (now - timedelta(minutes=1)).isoformat().replace('+00:00', 'Z')
        kwargs['fabric_knowledge_context_response'] = response
    elif case == 'unavailable':
        kwargs['full_node_context_status'] = FullNodeContextStatus.UNAVAILABLE
    fast = read_fast_assistance(adapter.fast_assistance(_lite_frame(), deadline_s=.5, **kwargs))
    record = _record({'route': 'unavailable', 'outcome': 'unavailable',
                      'reason': 'mio_unavailable', 'text': None, 'fast_assistance': fast})
    record['incident_id'] = _t1110()['incident_id']
    row = build_recent_incident(_t1110(), record=record)
    snapshot = build_recent_incidents([row], 1)
    assert read_recent_incidents(json.dumps(snapshot).encode()) == snapshot
    projected = snapshot['incidents'][0]['explanation']['fast_assistance']['full_node_context']
    assert projected['outcome'] == case
    assert projected['full_node_context_status'] == (
        'received' if case in {'complete', 'partial', 'stale', 'expired'} else case)
    if case in {'complete', 'partial', 'stale'}:
        assert projected['snapshot_state'] == case
        assert projected['source_kind'] == 'fabric_knowledge_context_response_v1'
        assert projected['claim_status'] == 'source_reported_unverified'
        assert projected['trust'] == 'unverified_advisory_only'


@pytest.mark.parametrize(('snapshot_state', 'expected'), [
    ('partial', 'unavailable'), ('stale', 'unavailable'), ('complete', 'available'),
])
def test_full_node_snapshot_status_is_not_a_verified_or_complete_claim(snapshot_state, expected):
    result = read_fast_assistance(adapter.fast_assistance(
        _lite_frame(), deadline_s=.5,
        fabric_knowledge_context_response=_fabric_response(snapshot_state)))
    receipt = result['fabric_knowledge_context_advisory']
    assert result['full_node_context_status'] == 'received'
    assert result['dependency_outcome']['knowledge'] == expected
    assert receipt['snapshot_state'] == snapshot_state
    assert receipt['claim_status'] == 'source_reported_unverified'
    assert receipt['trust'] == 'unverified_advisory_only'
    assert receipt['authority'] == 'advisory_only'
    assert result['knowledge'] == [] and result['observations'] == []
    assert result['handoff']['current_action'] is None
    if snapshot_state != 'complete':
        assert f'KNOWLEDGE_CONTEXT_{snapshot_state.upper()}' in result['unknowns']
        assert result['next_checks'][0] == (
            'Request an authorized current full-node Knowledge snapshot; '
            'this partial or stale advisory is not a complete current snapshot.')
    else:
        assert 'KNOWLEDGE_CONTEXT_PARTIAL' not in result['unknowns']
        assert 'KNOWLEDGE_CONTEXT_STALE' not in result['unknowns']


@pytest.mark.parametrize('snapshot_state', ['partial', 'stale'])
def test_lite_success_does_not_hide_incomplete_full_node_snapshot(snapshot_state):
    result = read_fast_assistance(adapter.fast_assistance(
        _lite_frame(), deadline_s=.5, knowledge_lookup=lambda *a, **k: (_lite_ref(),),
        fabric_knowledge_context_response=_fabric_response(snapshot_state)))
    assert result['dependency_outcome']['knowledge'] == 'available'
    assert result['full_node_context_status'] == 'received'
    assert result['knowledge'][0]['source_kind'] == 'knowledge_lite'
    assert result['fabric_knowledge_context_advisory']['snapshot_state'] == snapshot_state
    assert f'KNOWLEDGE_CONTEXT_{snapshot_state.upper()}' in result['unknowns']


@pytest.mark.parametrize(('lite', 'expected'), [
    ('none', 'unavailable'), ('empty', 'unavailable'), ('available', 'available'),
])
def test_locald_broker_failure_is_separate_from_lite(monkeypatch, lite, expected):
    from azazel_nexus_runtime import mio_locald
    calls = []
    def unavailable(frame, *, deadline_s):
        calls.append((frame, deadline_s))
        raise mio_locald.KnowledgeContextUnavailable('private peer text')
    monkeypatch.setattr(mio_locald, 'request_context', unavailable)
    lookup = {'none': None, 'empty': lambda *a, **k: (),
              'available': lambda *a, **k: (_lite_ref(),)}[lite]
    source = {**_lite_frame(), 'privacy_class': 'P0-public'}
    reply = mio_locald.LocalRuntimeService(knowledge_lookup=lookup).handle(SimpleNamespace(
        verb=mio_locald.FAST_ASSESS_VERB, arguments={'deadline_ms': 1000}, payload=source))
    result = read_fast_assistance(reply['fast_assistance'])
    assert len(calls) == 1 and calls[0][0]['privacy_class'] == 'P0-public'
    assert 0 < calls[0][1] <= mio_locald.KNOWLEDGE_MAX_S
    assert result['full_node_context_status'] == 'unavailable'
    assert result['dependency_outcome']['knowledge'] == expected
    assert len(result['knowledge']) == (1 if lite == 'available' else 0)
    assert 'private peer text' not in str(reply)
    assert 'fabric_knowledge_context_advisory' not in result


def test_broker_failure_survives_socket_reader(monkeypatch):
    from azazel_nexus_runtime import mio_locald, mio_socket_client
    monkeypatch.setattr(mio_locald, 'request_context', lambda *a, **k: (
        _ for _ in ()).throw(mio_locald.KnowledgeContextUnavailable('private')))
    source = {**_lite_frame(), 'privacy_class': 'P0-public'}
    reply = mio_locald.LocalRuntimeService().handle(SimpleNamespace(
        verb=mio_locald.FAST_ASSESS_VERB, arguments={'deadline_ms': 1000}, payload=source))
    monkeypatch.setattr(mio_socket_client, '_exchange', lambda *a, **k: reply)
    result = mio_socket_client.LocalSocketClient().assess(source, deadline_s=.5)
    assert result['full_node_context_status'] == 'unavailable'
    assert result['dependency_outcome']['knowledge'] == 'unavailable'


@pytest.mark.parametrize(('privacy', 'deadline_ms'), [
    ('P3-restricted', 1000), ('P0-public', 44),
])
def test_full_node_not_queried_only_when_no_request_is_made(monkeypatch, privacy, deadline_ms):
    from azazel_nexus_runtime import mio_locald
    def forbidden(*args, **kwargs):
        pytest.fail('broker must not be called')
    monkeypatch.setattr(mio_locald, 'request_context', forbidden)
    source = {**_lite_frame(), 'privacy_class': privacy}
    reply = mio_locald.LocalRuntimeService().handle(SimpleNamespace(
        verb=mio_locald.FAST_ASSESS_VERB, arguments={'deadline_ms': deadline_ms}, payload=source))
    result = read_fast_assistance(reply['fast_assistance'])
    assert result['full_node_context_status'] == 'not_queried'
    assert result['dependency_outcome']['knowledge'] == 'not_queried'


def test_full_node_status_reader_rejects_untrusted_or_contradictory_values():
    result = adapter.fast_assistance(_lite_frame(), deadline_s=.5,
        fabric_knowledge_context_response=_fabric_response('partial'))
    assert read_fast_assistance(result) is result
    for bad in ('timeout', 'private peer text', None, {}, True):
        forged = copy.deepcopy(result)
        forged['full_node_context_status'] = bad
        with pytest.raises(ValueError):
            read_fast_assistance(forged)
    for bad in ('unavailable', 'not_queried'):
        forged = copy.deepcopy(result)
        forged['full_node_context_status'] = bad
        with pytest.raises(ValueError):
            read_fast_assistance(forged)
    legacy = copy.deepcopy(result)
    del legacy['full_node_context_status']
    assert read_fast_assistance(legacy) is legacy


def test_live_lite_claim_preserves_exact_metadata_and_same_frame(monkeypatch):
    source = _lite_frame('SSH T1110 and invalid T1110.003x')
    ref = _lite_ref()
    calls, frames = [], []
    real = adapter.AssistantCore.explain
    def explain(self, frame, **kwargs):
        frames.append(frame.to_dict())
        assert kwargs['knowledge_attempted'] is True
        assert kwargs['knowledge_lite_advisories'][0].citation == ref.claim_id
        return real(self, frame, **kwargs)
    monkeypatch.setattr(adapter.AssistantCore, 'explain', explain)
    def lookup(ids, *, deadline_s):
        calls.append((ids, deadline_s))
        return (ref,)
    result = read_fast_assistance(adapter.fast_assistance(source, deadline_s=.2,
                                                         knowledge_lookup=lookup))
    assert calls[0][0] == ('T1110',)
    assert 0 < calls[0][1] <= .175
    claim, = result['knowledge']
    for field in ('name', 'summary', 'claim_id', 'bundle_digest', 'freshness', 'as_of'):
        assert claim[field] == getattr(ref, field)
    assert claim['generation'] == '5'
    assert claim['source_kind'] == 'knowledge_lite'
    assert claim['source_citation'] == ref.citation
    assert claim['citation'] == ref.claim_id
    assert claim['trust_check'] == 'verified' and claim['revocation_status'] == 'clear'
    assert claim['claim_status'] == 'reported_unverified'
    assert frames[0]['known_facts'] == [] and frames[0]['noc_summary'] == source['question']
    assert result['handoff']['frame_id'] == frames[0]['frame_id']
    assert result['dependency_outcome']['knowledge'] == 'available'


def test_lite_empty_result_is_absent_and_no_ids_never_queries():
    result = read_fast_assistance(adapter.fast_assistance(_lite_frame(), deadline_s=.2,
                                                         knowledge_lookup=lambda *a, **k: ()))
    assert result['knowledge'] == []
    assert result['dependency_outcome']['knowledge'] == 'absent'
    def forbidden(*a, **k):
        pytest.fail('no exact technique IDs')
    result = adapter.fast_assistance(_lite_frame('T1110x XT1110 T1110.003x'),
                                    deadline_s=.2, knowledge_lookup=forbidden)
    assert result['dependency_outcome']['knowledge'] == 'not_queried'


@pytest.mark.parametrize('refs', [(_lite_ref(trust_check='unknown'),),
                                  (_lite_ref(freshness='expired'),),
                                  (_lite_ref(claim_id='T1059'),),
                                  ({'technique_id': 'T1110'},),
                                  (_lite_ref(technique_id='T1059', claim_id='T1059'),),
                                  (_lite_ref(as_of='2099-01-01T00:00:00Z'),),
                                  (_lite_ref(freshness='current', as_of='2020-01-01T00:00:00Z'),)])
def test_lite_malformed_stale_or_untrusted_refs_degrade_without_refs(refs):
    result = read_fast_assistance(adapter.fast_assistance(_lite_frame(), deadline_s=.2,
                                                         knowledge_lookup=lambda *a, **k: refs))
    assert result['knowledge'] == []
    assert result['dependency_outcome']['knowledge'] == 'unavailable'


@pytest.mark.parametrize('error, outcome', [(TimeoutError(), 'timeout'),
                                           (OSError('private service detail'), 'unavailable')])
def test_lite_lookup_failures_are_bounded_public_outcomes(error, outcome):
    def lookup(*a, **k):
        raise error
    result = read_fast_assistance(adapter.fast_assistance(_lite_frame(), deadline_s=.2,
                                                         knowledge_lookup=lookup))
    assert result['knowledge'] == []
    assert result['dependency_outcome']['knowledge'] == outcome
    assert 'private service detail' not in repr(result)


def test_core_reserve_skips_lookup_and_discards_late_result(monkeypatch):
    def forbidden(*a, **k):
        pytest.fail('core reserve cannot fund lookup')
    monkeypatch.setattr(adapter.time, 'monotonic', lambda: 10.0)
    result = adapter.fast_assistance(_lite_frame(), deadline_s=.024, knowledge_lookup=forbidden)
    assert result['knowledge'] == []
    assert result['dependency_outcome']['knowledge'] == 'not_queried'
    clock = [10.0]
    monkeypatch.setattr(adapter.time, 'monotonic', lambda: clock[0])
    def late(*a, **k):
        clock[0] += .198
        return (_lite_ref(),)
    result = adapter.fast_assistance(_lite_frame(), deadline_s=.2, knowledge_lookup=late)
    assert result['knowledge'] == []
    assert result['dependency_outcome']['knowledge'] == 'timeout'


def test_all_local_refs_are_validated_before_bounded_prefix():
    refs = tuple(_lite_ref() for _ in range(16))
    result = read_fast_assistance(adapter.fast_assistance(_lite_frame(), deadline_s=.2,
                                                         knowledge_lookup=lambda *a, **k: refs))
    assert len(result['knowledge']) == 8
    result = adapter.fast_assistance(_lite_frame(), deadline_s=.2,
                                    knowledge_lookup=lambda *a, **k: refs[:15] + (_lite_ref(trust_check='unknown'),))
    assert result['knowledge'] == []
    assert result['dependency_outcome']['knowledge'] == 'unavailable'


def test_normal_locald_fast_assess_injects_authenticated_lookup():
    from azazel_nexus_runtime import mio_locald
    source = _lite_frame()
    calls = []
    def lookup(ids, *, deadline_s):
        calls.append((ids, deadline_s))
        return (_lite_ref(),)
    service = mio_locald.LocalRuntimeService(knowledge_lookup=lookup)
    reply = service.handle(SimpleNamespace(verb=mio_locald.FAST_ASSESS_VERB,
                           arguments={'deadline_ms': 500}, payload=source))
    fast = read_fast_assistance(reply['fast_assistance'])
    assert calls[0][0] == ('T1110',)
    assert calls[0][1] <= mio_locald.KNOWLEDGE_MAX_S
    assert fast['knowledge'][0]['citation'] == 'T1110'
    forged = copy.deepcopy(fast)
    forged['knowledge'][0]['citation'] = 'unrelated'
    with pytest.raises(ValueError):
        read_fast_assistance(forged)


def test_normal_locald_assessment_requests_context_from_local_broker(monkeypatch):
    from azazel_nexus_runtime import mio_locald

    source = {"request_id": "p0-normal", "privacy_class": "P0-public",
              "question": "synthetic public question", "context": []}
    response = {
        "schema_version": "knowledge-context-response/v1",
        "request_id": "req-synthetic-1",
        "correlation_id": "corr-synthetic-1",
        "source_product": "azazel_nexus",
        "source_ref": "nexus:synthetic-query",
        "provider_id": "knowledge-node-1",
        "snapshot": {"ref": "knowledge:snapshot-1", "state": "partial",
                      "as_of": "2026-07-06T11:59:00Z"},
        "facts": [{"claim_class": "source_reported_fact", "fact_id": "fact-1",
                   "subject": {"entity_type": "host", "value": "host-1.example.com"},
                   "predicate": "listed_by", "value": "A synthetic source reports this.",
                   "provenance": ["knowledge:intel-index"]}],
        "inferences": [], "unknowns": ["synthetic source freshness not provided"],
        "limitations": ["synthetic test data"],
        "generated_at": "2026-07-06T12:00:00Z",
        "expires_at": "2026-07-06T12:00:30Z",
        "authority": "advisory_only",
    }
    observed = {}
    from azazel_nexus_runtime import mio_fast_assistance
    fast_calls = []
    clock = [20.0]
    monkeypatch.setattr(mio_locald.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        mio_fast_assistance,
        "fast_assistance",
        lambda frame, **kwargs: (
            observed.update(kwargs), fast_calls.append(kwargs),
            {"outcome": "synthetic"},
        )[-1],
    )
    broker_calls = []
    monkeypatch.setattr(
        mio_locald, "request_context",
        lambda frame, *, deadline_s: (
            broker_calls.append((frame, deadline_s)),
            clock.__setitem__(0, clock[0] + 0.2),
            response,
        )[-1],
    )
    service = mio_locald.LocalRuntimeService()
    reply = service.handle(SimpleNamespace(
        verb=mio_locald.FAST_ASSESS_VERB,
        arguments={"deadline_ms": 500},
        payload={"frame": source},
    ))
    assert observed["fabric_knowledge_context_response"] == response
    assert broker_calls and broker_calls[0][0] == {
        "privacy_class": "P0-public", "question": "synthetic public question"}
    assert 0 < broker_calls[0][1] <= mio_locald.KNOWLEDGE_MAX_S
    assert fast_calls[0]["deadline_s"] == pytest.approx(0.28)
    assert reply["fast_assistance"] == {"outcome": "synthetic"}


def test_normal_locald_rejects_caller_supplied_fabric_response(monkeypatch):
    from azazel_nexus_runtime import mio_locald, mio_fast_assistance

    monkeypatch.setattr(
        mio_fast_assistance, "fast_assistance",
        lambda *a, **k: pytest.fail("unverified caller response reached MIO"),
    )
    reply = mio_locald.LocalRuntimeService().handle(SimpleNamespace(
        verb=mio_locald.FAST_ASSESS_VERB,
        arguments={"deadline_ms": 500},
        payload={"frame": _lite_frame(),
                 "fabric_knowledge_context_response": {"authority": "advisory_only"}},
    ))
    assert reply == {"outcome": "failed", "refusal": "malformed_frame"}


def test_locald_rejects_unknown_keys_in_wrapped_assessment_payload(monkeypatch):
    from azazel_nexus_runtime import mio_locald, mio_fast_assistance

    monkeypatch.setattr(
        mio_fast_assistance, "fast_assistance",
        lambda *a, **k: pytest.fail("malformed assessment payload reached MIO"),
    )
    reply = mio_locald.LocalRuntimeService().handle(SimpleNamespace(
        verb=mio_locald.FAST_ASSESS_VERB,
        arguments={"deadline_ms": 500},
        payload={"frame": _lite_frame(),
                 "fabric_knowledge_context_response": {}, "extra": "refuse"},
    ))
    assert reply == {"outcome": "failed", "refusal": "malformed_frame"}


def test_normal_locald_fast_assess_skips_lookup_without_a_budget(monkeypatch):
    from azazel_nexus_runtime import mio_locald
    monkeypatch.setattr(adapter.time, 'monotonic', lambda: 10.0)
    calls = []
    service = mio_locald.LocalRuntimeService(
        knowledge_lookup=lambda *args, **kwargs: calls.append((args, kwargs)))
    reply = service.handle(SimpleNamespace(
        verb=mio_locald.FAST_ASSESS_VERB,
        arguments={'deadline_ms': 47}, payload=_lite_frame()))
    fast = read_fast_assistance(reply['fast_assistance'])
    assert calls == []
    assert fast['dependency_outcome']['knowledge'] == 'not_queried'
    assert fast['knowledge'] == []


def test_current_at_lookup_survives_second_boundary(monkeypatch):
    from datetime import datetime, timezone
    monotonic = [10.0]
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            if monotonic[0] == 10.0:
                return cls(2026, 11, 2, 0, 0, 0, 900000, tzinfo=timezone.utc)
            return cls(2026, 11, 2, 0, 0, 1, 100000, tzinfo=timezone.utc)
    monkeypatch.setattr(adapter, 'datetime', Clock)
    monkeypatch.setattr(adapter.time, 'monotonic', lambda: monotonic[0])
    def lookup(*args, deadline_s):
        assert deadline_s == pytest.approx(.225)
        monotonic[0] += .2
        return (_lite_ref(freshness='current', as_of='2026-11-02T00:00:00Z'),)
    result = read_fast_assistance(adapter.fast_assistance(
        _lite_frame(), deadline_s=.25, knowledge_lookup=lookup))
    assert result['dependency_outcome']['knowledge'] == 'available'
    assert result['knowledge'][0]['as_of'] == '2026-11-02T00:00:00Z'
    assert result['knowledge'][0]['temporal_validity'] == 'current_at_lookup'


@pytest.mark.parametrize('as_of', ['2020-01-01T00:00:00Z', '2099-01-01T00:00:00Z'])
def test_discarded_temporal_tail_invalidates_whole_reply(as_of):
    prefix = tuple(_lite_ref() for _ in range(15))
    tail = (_lite_ref(freshness='current', as_of=as_of),)
    result = read_fast_assistance(adapter.fast_assistance(
        _lite_frame(), deadline_s=.2, knowledge_lookup=lambda *a, **k: prefix + tail))
    assert result['knowledge'] == []
    assert result['dependency_outcome']['knowledge'] == 'unavailable'


def test_slow_selection_records_loss_before_projection_without_changing_fast_frame():
    source = _lite_frame('x' * 600)
    frame, selection = adapter._frame(source, with_selection=True)
    assert selection['coverage'] == 'unknown'
    assert selection['omitted_units'] >= 1
    assert selection['omissions'][0]['reason'] == 'upstream_projection'
    assert len(frame.to_dict()['noc_summary']) == 480
    ordinary = adapter._frame(source)
    assert ordinary.to_dict()['noc_summary'] == frame.to_dict()['noc_summary']
    assert 'x' * 20 not in str(selection)
