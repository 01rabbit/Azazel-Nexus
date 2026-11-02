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
        self.reply = None  # raw model text override for malformed-content tests

    def infer(self, request, deadline_s, **kwargs):
        self.requests.append(request)
        self.entered.set()
        if self.block:
            self.stopped.wait(deadline_s + .2)
            raise TimeoutError
        if self.reply is not None:
            return LocalInferenceResult(self.reply, 12, 7, {'total_ms': .1})
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


DEEP_NESTING = '[' * 100000 + ']' * 100000


@pytest.mark.parametrize('reply', ['{not json', '[]', '"text"', 'null', DEEP_NESTING,
                                   '{"summary": NaN}', '{"summary": Infinity}',
                                   '{"summary": -Infinity}', '{"summary": 1e999}'],
                         ids=['not-json', 'list', 'string', 'null', 'deep-nesting',
                              'nan', 'infinity', 'negative-infinity', 'overflow-float'])
def test_malformed_model_content_degrades_job_but_keeps_provider(reply):
    lane, source, frame = setup()
    lane.server.reply = reply
    value = result(lane, source, frame)
    assert lane.server.requests
    assert value['state'] == 'degraded'
    assert not lane.server.stopped.is_set()
    # Same provider serves a later job after the content failure.
    lane.server.reply = None
    calls = len(lane.server.requests)
    later = result(lane, source | {'request_id': 'after-malformed'}, frame)
    assert len(lane.server.requests) > calls
    assert later['state'] in {'complete', 'degraded'}
    assert not lane.server.stopped.is_set()


class GatedServer(FixtureServer):
    """First request waits for stop(); stop() releases it, then sleeps before finishing."""
    def __init__(self):
        super().__init__()
        self.release, self.stop_done = threading.Event(), threading.Event()
        self.second_started_after_stop = None

    def infer(self, request, deadline_s, **kwargs):
        if not self.requests:
            self.entered.set()
            self.release.wait(2)
        else:
            self.second_started_after_stop = self.stop_done.is_set()
        return super().infer(request, deadline_s, **kwargs)

    def stop(self):
        self.release.set()
        time.sleep(.3)  # slower than the lane's former join timeout
        self.stop_done.set()
        super().stop()


def test_queued_job_waits_for_prior_watcher_stop():
    lane, source, frame = setup(deadline_s=.5)
    lane.server = GatedServer()
    assert lane.submit(source, frame, 'fixture-generation')['state'] == 'queued'
    assert lane.server.entered.wait(.5)
    # Same request ID with changed content supersedes the active in-flight job.
    # The provider stop then succeeds, so the lane is stopped for good: the
    # pending replacement is dropped and degraded, and never reaches infer().
    second = source | {'question': 'Changed report'}
    assert lane.submit(second, frame, 'fixture-generation')['state'] == 'queued'
    value = result(lane, second, frame)
    assert value['state'] == 'degraded'
    assert lane.server.stop_done.is_set()
    assert lane._pending is None
    assert lane.server.second_started_after_stop is None
    assert len(lane.server.requests) == 1
    # New work on the stopped lane gets no handle and no inference.
    third = source | {'question': 'Third report'}
    refused = lane.submit(third, frame, 'fixture-generation')
    assert refused['state'] == 'degraded' and 'result_handle' not in refused
    assert len(lane.server.requests) == 1


class NoTextServer(FixtureServer):
    def infer(self, request, deadline_s, **kwargs):
        super().infer(request, deadline_s, **kwargs)
        return SimpleNamespace(tokens_in=12, tokens_out=7, timings={'total_ms': .1})


def test_infer_result_without_text_is_provider_failure():
    lane, source, frame = setup()
    lane.server = NoTextServer()
    value = result(lane, source, frame)
    assert lane.server.requests
    assert value['state'] == 'degraded'
    assert lane.server.stopped.is_set()


class StopFailsServer(FixtureServer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stop_calls = 0

    def stop(self):
        self.stop_calls += 1
        self.stopped.set()  # releases a blocked infer; termination is still unconfirmed
        raise OSError('stop failed')


def assert_fenced_after_stop_failure(lane, source, frame, value):
    assert value['state'] == 'degraded'
    until = time.monotonic() + 2
    while lane._active is not None and time.monotonic() < until:
        time.sleep(.005)
    assert lane._active is None
    assert lane._receipts[value['result_handle']]['status']['state'] == 'degraded'
    calls = len(lane.server.requests)
    later = lane.submit(source | {'request_id': 'after-stop-failure'}, frame, 'fixture-generation')
    assert later['state'] == 'degraded'
    assert len(lane.server.requests) == calls


def test_stop_failure_after_transport_failure_fences_provider():
    lane, source, frame = setup()
    lane.server = StopFailsServer()
    lane.server.infer = lambda *a, **k: SimpleNamespace(tokens_in=1, tokens_out=1, timings={})
    value = result(lane, source, frame)
    assert lane.server.stop_calls >= 1
    assert_fenced_after_stop_failure(lane, source, frame, value)


def test_stop_failure_in_deadline_watcher_fences_provider():
    lane, source, frame = setup(deadline_s=.08)
    lane.server = StopFailsServer(block=True)
    value = result(lane, source, frame)
    assert lane.server.requests and lane.server.stop_calls >= 1
    assert_fenced_after_stop_failure(lane, source, frame, value)


class HungStopFailsServer(StopFailsServer):
    """infer() never returns until the test releases it; stop() raises."""
    def __init__(self):
        super().__init__()
        self.release = threading.Event()

    def infer(self, request, deadline_s, **kwargs):
        self.requests.append(request)
        self.entered.set()
        self.release.wait(10)
        raise TimeoutError


def _wait(predicate):
    until = time.monotonic() + 2
    while not predicate() and time.monotonic() < until:
        time.sleep(.005)
    return predicate()


def _workers():
    return [t for t in threading.enumerate() if t.name == 'mio-generation']


def test_stop_failure_publishes_degraded_while_infer_is_still_blocked():
    lane, source, frame = setup(deadline_s=.08)
    server = lane.server = HungStopFailsServer()
    try:
        receipt = lane.submit(source, frame, 'fixture-generation')
        handle = receipt['result_handle']
        assert server.entered.wait(2)
        # A second job queues behind the blocked worker before the deadline fires.
        queued = lane.submit(source | {'request_id': 'second'}, frame, 'fixture-generation')
        polled = lambda: lane.poll(handle, 'fixture-generation', frame.trace_id)
        assert _wait(lambda: polled()['state'] == 'degraded')  # infer has NOT returned
        assert not server.release.is_set() and lane._active is not None
        assert lane._pending is None
        assert lane.poll(queued['result_handle'], 'fixture-generation',
                         frame.trace_id)['state'] == 'degraded'
        assert len(_workers()) == 1
        calls = len(server.requests)
        later = lane.submit(source | {'request_id': 'third'}, frame, 'fixture-generation')
        assert later['state'] == 'degraded' and 'result_handle' not in later
        assert lane._pending is None and len(_workers()) == 1
        assert len(server.requests) == calls
        # Late worker completion and an explicit cancel cannot rewrite the receipt.
        lane.cancel()
        assert polled()['state'] == 'degraded'
        server.release.set()
        assert _wait(lambda: lane._active is None)
        assert polled()['state'] == 'degraded'
        assert server.stop_calls == 1  # stop() attempted once, never retried
        assert len(server.requests) == calls
    finally:
        server.release.set()


class StopOnceServer(FixtureServer):
    """stop() succeeds the first time; a second call would raise."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stop_calls = 0

    def stop(self):
        self.stop_calls += 1
        if self.stop_calls > 1:
            raise OSError('second stop must never happen')
        super().stop()


def test_successful_watcher_stop_is_not_repeated_by_worker():
    lane, source, frame = setup(deadline_s=.08)
    lane.server = StopOnceServer(block=True)  # infer raises after stop => transport failure
    value = result(lane, source, frame)
    assert _wait(lambda: lane._active is None)
    assert lane.server.requests
    assert lane.server.stop_calls == 1
    assert not lane._fenced
    assert lane._stopped
    assert value['state'] == 'timeout'
    assert lane._receipts[value['result_handle']]['status']['state'] == 'timeout'
    before = len(lane.server.requests)
    later = lane.submit(source | {'request_id': 'after-stop'}, frame, 'fixture-generation')
    assert later['state'] == 'degraded' and 'result_handle' not in later
    assert len(lane.server.requests) == before and lane.server.stop_calls == 1


def test_successful_stop_degrades_pending_job_without_inference():
    lane, source, frame = setup(block=True, deadline_s=.08)
    assert lane.submit(source, frame, 'fixture-generation')['state'] == 'queued'
    assert lane.server.entered.wait(.5)
    pending = lane.submit(source | {'request_id': 'pending'}, frame, 'fixture-generation')
    assert pending['state'] == 'queued'
    assert _wait(lambda: lane._stopped and lane._active is None)
    assert lane._pending is None
    assert lane._receipts[pending['result_handle']]['status']['state'] == 'degraded'
    assert len(lane.server.requests) == 1  # the pending job never reached the stopped server


class FenceVisibleOnlyUnderLockLane(FixtureLane):
    """The fence reads True only while _lock is held, so admission must inspect it under the lock."""

    @property
    def _fenced(self):
        owned = self._lock._is_owned()  # RLock: True only for the thread holding _lock
        self.__dict__.setdefault('_fence_inspections', []).append(owned)
        return owned or self.__dict__.get('_fence_flag', False)

    @_fenced.setter
    def _fenced(self, value):
        self.__dict__['_fence_flag'] = value


def test_submit_rechecks_fence_inside_lock_before_admitting_work():
    lane, source, frame = setup()
    racing = FenceVisibleOnlyUnderLockLane(capability=lane.capability, server=lane.server,
                                           deadline_s=.5)
    value = racing.submit(source, frame, 'fixture-generation')
    inspections = racing.__dict__.get('_fence_inspections', [])
    assert value['state'] == 'degraded' and 'result_handle' not in value
    # The admission decision read the fence while _lock was held, and it refused the work.
    assert inspections and inspections[-1] is True
    assert racing._receipts == {} and racing._pending is None and racing._worker is None
    assert not lane.server.requests


def test_cancel_before_any_provider_request_does_not_stop_provider():
    lane, source, frame = setup(block=True)
    # Hold the lane lock so the worker sees the job only after it is cancelled.
    with lane._lock:
        assert lane.submit(source, frame, 'fixture-generation')['state'] == 'queued'
        lane.cancel()
    assert result(lane, source, frame)['state'] == 'cancelled'
    assert not lane.server.requests
    assert not lane.server.stopped.is_set()


def test_expiry_before_any_provider_request_does_not_stop_provider():
    lane, source, frame = setup(block=True, deadline_s=.05)
    with lane._lock:
        assert lane.submit(source, frame, 'fixture-generation')['state'] == 'queued'
        time.sleep(.15)  # deadline passes while still pending
    assert result(lane, source, frame)['state'] == 'timeout'
    assert not lane.server.requests
    assert not lane.server.stopped.is_set()


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


@pytest.mark.parametrize('next_request', ['fixture-event', 'new-event'])
def test_explicit_result_poll_survives_changed_current_assessment(monkeypatch, next_request):
    from azazel_nexus_runtime.mio_locald import LocalRuntimeService, FAST_ASSESS_VERB, GENERATION_RESULT_VERB
    from azazel_nexus_runtime import mio_socket_client as client
    lane, source, frame = setup()
    service = LocalRuntimeService(generation_lane=lane, generation_id='fixture-generation')
    def exchange(socket, account, verb, arguments, **kwargs):
        return service.handle(SimpleNamespace(verb=SimpleNamespace(name=verb),
            arguments=arguments, payload=kwargs.get('payload')))
    monkeypatch.setattr(client, '_exchange', exchange)
    socket = client.LocalSocketClient()
    fast = socket.assess(source, deadline_s=.5)
    receipt = socket.last_slow_analysis
    until = time.monotonic() + 2
    while time.monotonic() < until:
        original = socket.generation_result(receipt)
        if original['state'] != 'queued':
            break
        time.sleep(.005)
    assert original['state'] in {'complete', 'degraded'}
    assert original['frame_id'] == fast['frame_id']
    changed = socket.assess(source | {'request_id': next_request, 'question': 'Changed'}, deadline_s=.5)
    assert changed['frame_id'] != original['frame_id']
    assert socket.generation_result(receipt) == original
    assert socket.last_slow_analysis['frame_id'] == changed['frame_id']
    for key in ('generation_id', 'trace_id', 'result_handle', 'frame_id'):
        assert socket.generation_result(receipt | {key: 'wrong'})['state'] == 'stale'
    # Polling does not invoke inference, even after a new current event exists.
    lane.cancel()


def test_result_expiry_and_retention_cap(monkeypatch):
    lane, source, frame = setup()
    value = result(lane, source, frame)
    assert lane.poll(value['result_handle'], 'fixture-generation', frame.trace_id) == value
    assert lane.poll('f' * 64, 'fixture-generation', frame.trace_id)['state'] == 'stale'
    record = lane._receipts[value['result_handle']]
    record['expires'] = time.monotonic() - 1
    assert lane.poll(value['result_handle'], 'fixture-generation', frame.trace_id)['state'] == 'stale'
    assert not lane._results
    for n in range(20):
        result(lane, source | {'request_id': str(n)}, frame)
    assert len(lane._receipts) <= 16
    assert len(lane._results) <= 16
    lane.capability = replace(lane.capability, role='embedding')
    latest = next(reversed(lane._receipts))
    assert lane.poll(latest, 'fixture-generation', frame.trace_id)['state'] == 'stale'


def test_result_poll_without_capability_never_dispatches():
    lane, source, frame = setup()
    value = result(lane, source, frame)
    calls = len(lane.server.requests)
    assert lane.poll(value['result_handle'], 'fixture-generation', frame.trace_id) == value
    assert len(lane.server.requests) == calls
    lane.capability = replace(lane.capability, role='embedding')
    assert lane.poll(value['result_handle'], 'fixture-generation', frame.trace_id)['state'] == 'stale'


@pytest.mark.parametrize('ttl', [0, -1, float('inf'), 301, True])
def test_invalid_result_ttl_rejected(ttl):
    with pytest.raises(ValueError):
        generation.GenerationLane(result_ttl_s=ttl)


def test_pending_same_source_retry_after_stop_returns_original_handle():
    lane, source, frame = setup(block=True, deadline_s=.08)
    lane.submit(source, frame, 'fixture-generation')
    assert lane.server.entered.wait(.5)
    other = source | {'request_id': 'pending'}
    pending = lane.submit(other, frame, 'fixture-generation')
    assert _wait(lambda: lane._stopped and lane._active is None)
    calls = len(lane.server.requests)
    retry = lane.submit(other, frame, 'fixture-generation')
    assert retry['state'] == 'degraded' and retry['result_handle'] == pending['result_handle']
    assert lane.poll(pending['result_handle'], 'fixture-generation', frame.trace_id)['state'] == 'degraded'
    fresh = lane.submit(source | {'request_id': 'new'}, frame, 'fixture-generation')
    assert fresh['state'] == 'degraded' and 'result_handle' not in fresh
    assert len(lane.server.requests) == calls and len(lane._results) <= 16


def test_pending_same_source_retry_after_fence_returns_original_handle():
    lane, source, frame = setup(deadline_s=.08)
    server = lane.server = HungStopFailsServer()
    try:
        lane.submit(source, frame, 'fixture-generation')
        assert server.entered.wait(2)
        other = source | {'request_id': 'second'}
        queued = lane.submit(other, frame, 'fixture-generation')
        assert _wait(lambda: lane._fenced and lane._pending is None)
        calls = len(server.requests)
        retry = lane.submit(other, frame, 'fixture-generation')
        assert retry['state'] == 'degraded' and retry['result_handle'] == queued['result_handle']
        fresh = lane.submit(source | {'request_id': 'new'}, frame, 'fixture-generation')
        assert fresh['state'] == 'degraded' and 'result_handle' not in fresh
        assert len(server.requests) == calls
    finally:
        server.release.set()


def test_completed_cached_output_survives_lane_stop():
    lane, source, frame = setup()
    done = result(lane, source, frame)
    assert done['state'] == 'complete'
    lane.server.stop()
    lane._mark_stopped()
    calls = len(lane.server.requests)
    again = lane.submit(source, frame, 'fixture-generation')
    assert again == done and len(lane.server.requests) == calls


def test_active_same_source_retry_after_stop_or_fence_is_terminal():
    lane, source, frame = setup(deadline_s=.08)
    server = lane.server = HungStopFailsServer()
    try:
        first = lane.submit(source, frame, 'fixture-generation')
        assert server.entered.wait(2)
        assert _wait(lambda: lane._fenced)
        retry = lane.submit(source, frame, 'fixture-generation')
        assert retry['state'] == 'degraded' and retry['result_handle'] == first['result_handle']
        # F2: receipt pruned while the active key still matches -> no unpollable handle.
        lane._receipts.clear()
        pruned = lane.submit(source, frame, 'fixture-generation')
        assert pruned['state'] == 'degraded' and 'result_handle' not in pruned
    finally:
        server.release.set()
