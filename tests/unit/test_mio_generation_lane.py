"""Explicit inert fixture capability/provider; production readers cannot mint it."""
from dataclasses import replace
import json
import threading
import time
from types import SimpleNamespace

import pytest

pytest.importorskip('azazel_mio')
from azazel_mio import MioSituationFrame
from azazel_nexus_runtime import mio_generation as generation
from azazel_nexus_runtime.mio_fast_assistance import _frame
from azazel_nexus_runtime.mio_serve import LocalInferenceResult


class FixtureLane(generation.GenerationLane):
    """Test-only authorization override; deliberately absent from product code."""
    def _authorized(self, generation_id):
        return generation_id == 'fixture-generation' and self.capability.role == 'generation'

    def _status(self, *args, **kwargs):
        return super()._status(*args, **kwargs) | {'origin': 'fixture'}


class FixtureServer:
    def __init__(self, known=True, block=False):
        self.known, self.block = known, block
        self.entered, self.stopped = threading.Event(), threading.Event()
        self.requests = []

    def infer(self, request, deadline_s, **kwargs):
        self.requests.append(request)
        self.entered.set()
        if self.block:
            self.stopped.wait(deadline_s + .2)
            raise TimeoutError
        task = request.response_format['json_schema']['name']
        if task == 'generate_hypotheses':
            value = {'hypotheses': [dict(hypothesis_id=f'h{i}',
                hypothesis_alternative_id=alt, statement='More evidence is required.',
                status='proposed', supporting_evidence_refs=['ev:ssh:1'],
                contradicting_evidence_refs=[], assumptions=[],
                falsification_conditions=['Check evidence.'], expected_observations=[],
                missing_evidence=[]) for i, alt in enumerate(
                    ('hostile_activity', 'benign_activity'), 1)]}
        elif task == 'identify_evidence_gaps':
            value = {'evidence_gaps': []}
        else:
            value = dict(summary='Observe', recommended_action='OBSERVE',
                rationale='Evidence is limited', evidence_refs=['ev:ssh:1'], limitations=[])
        return LocalInferenceResult(json.dumps(value), 12 if self.known else None,
                                    7 if self.known else None, {'total_ms': .1})

    def stop(self):
        self.stopped.set()


def setup(known=True, block=False, deadline_s=.5):
    source = dict(request_id='fixture-event', question='Investigate anomaly',
                  privacy_class='P2-mission', context=[])
    frame = _frame(source)
    payload = frame.to_dict()
    payload['evidence_refs'] = ['ev:ssh:1']
    frame = MioSituationFrame.from_dict(payload)
    capability = generation.GenerationCapability('fixture-generation', 'fixture-model',
        '2099-01-01T00:00:00Z', 1, lambda: True)
    server = FixtureServer(known, block)
    return FixtureLane(capability=capability, server=server, deadline_s=deadline_s), source, frame


def result(lane, source, frame):
    until = time.monotonic() + 2
    while time.monotonic() < until:
        value = lane.submit(source, frame, 'fixture-generation')
        if value['state'] != 'queued':
            return value
        time.sleep(.005)
    pytest.fail('fixture worker did not finish')


@pytest.mark.parametrize('known', [True, False])
def test_real_core_receives_fixture_structured_transport_and_actual_usage(known):
    lane, source, frame = setup(known)
    value = result(lane, source, frame)
    assert lane.server.requests
    assert value['origin'] == 'fixture'
    assert value['usage'] == ('known' if known else 'unknown')
    assert value['frame_id'] == frame.frame_id and value['trace_id'] == frame.trace_id
    assert value['assistance']['frame_id'] == frame.frame_id
    assert generation.read_slow_analysis(value) == value
    assert all(r.max_tokens == 768 for r in lane.server.requests)


def test_default_wrong_role_expired_and_unsealed_evidence_are_closed(monkeypatch):
    lane, source, frame = setup()
    for capability in (None, object(), lane.capability,
                       replace(lane.capability, role='embedding'),
                       replace(lane.capability, expires_at='2020-01-01T00:00:00Z')):
        assert not generation.authorized(capability, 'fixture-generation')
    # Even both software switches alone cannot turn unsealed fixture evidence into a grant.
    monkeypatch.setattr(generation.model_admission, 'LOCAL_MODEL_ADMISSION_ENABLED', True)
    monkeypatch.setattr(generation, 'GENERATION_ADMISSION_ENABLED', True)
    for role, expiry, gen in [('embedding', '2099-01-01T00:00:00Z', 'fixture-generation'),
                              ('generation', '2020-01-01T00:00:00Z', 'fixture-generation'),
                              ('generation', '2099-01-01T00:00:00Z', 'other-generation')]:
        cap = replace(lane.capability, role=role, expires_at=expiry, _seal=generation._SEAL)
        assert not generation.authorized(cap, gen)
    closed = generation.GenerationLane(capability=lane.capability, server=lane.server)
    assert closed.submit(source, frame, 'fixture-generation')['state'] == 'closed'
    assert not lane.server.requests


def test_one_pending_slot_and_timeout_stops_provider():
    lane, source, frame = setup(block=True, deadline_s=.08)
    assert lane.submit(source, frame, 'fixture-generation')['state'] == 'queued'
    assert lane.server.entered.wait(.5)
    assert lane.submit(source | {'request_id': 'second'}, frame, 'fixture-generation')['state'] == 'queued'
    assert lane.submit(source | {'request_id': 'third'}, frame, 'fixture-generation')['state'] == 'queue_full'
    assert result(lane, source, frame)['state'] == 'timeout'
    assert lane.server.stopped.is_set()
    lane.cancel()


def test_supersession_stops_work_and_rejects_old_publication():
    lane, source, frame = setup(block=True)
    lane.submit(source, frame, 'fixture-generation')
    assert lane.server.entered.wait(.5)
    assert lane.submit(source | {'question': 'Changed report'}, frame, 'fixture-generation')['state'] == 'queued'
    assert result(lane, source, frame)['state'] == 'superseded'
    assert lane.server.stopped.is_set()
    lane.cancel()


def test_generation_and_frame_mismatch_do_not_publish(monkeypatch):
    lane, source, frame = setup()
    assert lane.submit(source, frame, 'wrong-generation')['state'] == 'closed'
    from azazel_mio import AssistantCore
    monkeypatch.setattr(AssistantCore, 'explain', lambda *a, **k: SimpleNamespace(
        to_dict=lambda: {'frame_id': 'wrong', 'trace_id': frame.trace_id}))
    value = result(lane, source, frame)
    assert value['state'] == 'degraded' and 'assistance' not in value


def test_normal_locald_preserves_fast_knowledge_and_closed_slow():
    from azazel_nexus_runtime.mio_locald import LocalRuntimeService, FAST_ASSESS_VERB
    from azazel_nexus.lite_import import KnowledgeRef
    from datetime import datetime, UTC
    ref = KnowledgeRef(technique_id='T1110', name='Brute force', summary='', claim_id='T1110',
        bundle_digest='sha256:' + 'a' * 64, freshness='static', source_kind='knowledge_lite',
        generation=5, trust_check='verified', as_of=datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),
        citation='MITRE ATT&CK technique')
    service = LocalRuntimeService(knowledge_lookup=lambda *a, **k: (ref,))
    reply = service.handle(SimpleNamespace(verb=FAST_ASSESS_VERB,
        arguments={'deadline_ms': 500}, payload=dict(request_id='normal-fixture',
        privacy_class='P2-mission', question='T1110', context=[])))
    assert reply['fast_assistance']['knowledge'][0]['claim_id'] == 'T1110'
    assert reply['slow_analysis']['state'] == 'closed'
    assert reply['fast_assistance']['frame_id'] == reply['slow_analysis']['frame_id']
