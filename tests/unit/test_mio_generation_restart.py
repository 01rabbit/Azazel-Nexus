"""Restart safety: durable intent, no body persistence, and epoch fencing."""
import copy
import json
import os
import threading
from types import SimpleNamespace as NS

import pytest

from azazel_nexus_runtime import incident_explaind as daemon
from azazel_nexus_runtime.mio_generation_journal import GenerationJournal, request_key
from azazel_nexus_runtime.mio_budget_session import BudgetSession
from azazel_nexus_runtime.mio_generation import read_slow_analysis
from test_mio_budget_lane import make, Lane, Server, terminal
from test_generation_budget_receipts import metadata, live
from test_mio_entryd import service


def durable(make, tmp_path, deadline=5):
    lane, server, source, frame = make(deadline)
    lane._journal = GenerationJournal(tmp_path / 'journal')
    return lane, server, source, frame


def restart(lane, tmp_path):
    return Lane(capability=lane.capability, server=Server(), budget_enabled=True,
                journal_dir=tmp_path / 'journal')


def join(lane):
    worker = lane._worker
    if worker is not None:
        worker.join(2)
        assert not worker.is_alive()


def test_complete_body_is_not_persisted_or_readopted(make, tmp_path, monkeypatch):
    lane, server, source, frame = durable(make, tmp_path)
    original = BudgetSession.finish
    def finish(session, result):
        original(session, result)
        session.frame_unknowns = {'um:1': 'SECRET-MODEL-BODY', 'u1': 'SECRET-FRAME',
                                  'ux:impact': 'SECRET-FIXED-BODY'}
    monkeypatch.setattr(BudgetSession, 'finish', finish)
    value = terminal(lane, source, frame)
    join(lane)
    assert value['state'] == 'complete'
    payload = next((tmp_path/'journal').glob('*.json')).read_text()
    assert 'SECRET' not in payload and 'Benign report' not in payload and 'assistance' not in payload
    assert os.stat(next((tmp_path/'journal').glob('*.json'))).st_mode & 0o777 == 0o600
    resumed = restart(lane, tmp_path)
    result = resumed.poll(value['result_handle'], 'fixture', frame.trace_id)
    assert read_slow_analysis(result) == result
    assert result['state'] == 'degraded' and 'assistance' not in result
    assert result['generation_budget']['outcome'] == 'stop_unconfirmed'
    observation = resumed.private_observation(source['request_id'])
    assert observation['fenced'] and observation['sent_count'] == 3
    assert {u['origin'] for u in observation['unknowns']} == {'frame', 'model_asserted', 'fixed_projection'}
    assert all(u['status'] == 'unavailable_after_restart' for u in observation['unknowns'])
    assert resumed.submit(source, frame, 'fixture')['state'] == 'degraded'
    assert not resumed.server.requests


def test_timeout_primary_result_and_sent_count_survive(make, tmp_path):
    lane, server, source, frame = durable(make, tmp_path, deadline=.8)
    server.block = server.stop_fail = True
    result = terminal(lane, source, frame)
    join(lane)
    before = result['generation_budget']
    assert before['primary_outcome'] == 'deadline_exceeded'
    resumed = restart(lane, tmp_path)
    after = resumed.poll(result['result_handle'], 'fixture', frame.trace_id)['generation_budget']
    assert after['primary_outcome'] == before['primary_outcome']
    assert after['result_state'] == before['result_state'] == 'timeout'
    assert after['job_calls'] == before['job_calls'] == 1
    assert after['cleanup']['state'] == 'unconfirmed'
    assert after['outcome'] == 'stop_unconfirmed'
    # Outcome-less send stays unknown even when a terminal timeout was durable.
    assert resumed.private_observation(source['request_id'])['sent_count'] is None


def test_degraded_primary_reason_is_preserved_without_false_stop_confirmation(make, tmp_path):
    lane, server, source, frame = durable(make, tmp_path)
    server.finish = 'length'
    before = terminal(lane, source, frame)
    join(lane)
    resumed = restart(lane, tmp_path)
    after = resumed.poll(before['result_handle'], 'fixture', frame.trace_id)
    assert after['generation_budget']['primary_outcome'] == before['generation_budget']['primary_outcome'] == 'output_incomplete'
    assert after['generation_budget']['cleanup']['state'] == before['generation_budget']['cleanup']['state'] == 'not_needed'
    assert after['state'] == 'degraded'


def reserve(journal, source, frame):
    journal.reserve(source['request_id'], 'a'*64, 'fixture', frame, 'old-epoch', 60)
    journal.intent(source['request_id'], 'generate_hypotheses')


def test_unacknowledged_intent_permanently_refuses_same_request(make, tmp_path):
    lane, server, source, frame = durable(make, tmp_path)
    reserve(lane._journal, source, frame)
    resumed = restart(lane, tmp_path)
    value = resumed.submit(source, frame, 'fixture', caller_epoch='new-epoch')
    assert value['state'] == 'degraded' and 'generation_budget' not in value
    assert resumed.private_observation(source['request_id'])['sent_count'] is None
    assert resumed._journal.records[request_key(source['request_id'])]['fenced']
    with pytest.raises(ValueError, match='closed'):
        resumed._journal.received(source['request_id'])
    assert not resumed.server.requests
    # A separate request may run; the existing physical stop fence remains separate.
    fresh = terminal(resumed, {'request_id': 'fresh'}, frame)
    join(resumed)
    assert fresh['state'] == 'complete' and len(resumed.server.requests) == 3


@pytest.mark.parametrize('damage', ['json', 'version', 'missing', 'request', 'handle', 'outcome', 'partial'])
def test_damaged_request_is_unknown_but_other_requests_are_allowed(make, tmp_path, damage):
    lane, _, source, frame = durable(make, tmp_path)
    reserve(lane._journal, source, frame)
    key = request_key(source['request_id'])
    path = tmp_path/'journal'/f'{key}.json'
    value = json.loads(path.read_text())
    if damage == 'json':
        path.write_text('{')
    elif damage == 'partial':
        (tmp_path/'journal'/f'{key}.crash.pending').write_text('{')
    else:
        if damage == 'version': value['journal_version'] = 2
        if damage == 'missing': del value['epoch']
        if damage == 'request': value['request_id'] = 'another-request'
        if damage == 'handle': value['intents'][0]['handle'] = 'b'*64
        if damage == 'outcome': value['outcomes'] = [dict(seq=1,request_id='other',handle='a'*64,received=True,sent_count=1)]
        path.write_text(json.dumps(value))
    resumed = restart(lane, tmp_path)
    assert resumed.submit(source, frame, 'fixture')['state'] == 'degraded'
    observation = resumed.private_observation(source['request_id'])
    assert observation['state'] == 'unknown' and observation['fenced'] and observation['sent_count'] is None
    assert resumed.poll('a'*64, 'fixture', frame.trace_id)['state'] != 'complete'
    assert not resumed.server.requests
    assert terminal(resumed, {'request_id': 'fresh'}, frame)['state'] == 'complete'
    join(resumed)


def test_missing_record_with_remaining_temp_is_not_initial_state(make, tmp_path):
    lane, _, source, frame = durable(make, tmp_path)
    reserve(lane._journal, source, frame)
    path = tmp_path/'journal'/f'{request_key(source["request_id"])}.json'
    path.rename(path.with_suffix('.pending'))
    resumed = restart(lane, tmp_path)
    assert resumed.submit(source, frame, 'fixture')['state'] == 'degraded'
    assert not resumed.server.requests


def test_existing_physical_fence_still_blocks_fresh_request(make, tmp_path):
    lane, server, source, frame = durable(make, tmp_path)
    server._nexus_stop_unconfirmed = True
    assert lane.submit(source, frame, 'fixture')['state'] == 'degraded'
    assert not server.requests


def test_owner_fence_directory_is_default_journal_location(make, tmp_path):
    original, server, source, frame = make()
    server._fence_path = tmp_path/'stop-fence.json'
    lane = Lane(capability=original.capability,server=server,budget_enabled=True)
    assert lane._journal.directory == tmp_path/'generation-journal'
    assert terminal(lane, source, frame)['state'] == 'complete'
    join(lane)
    assert (tmp_path/'generation-journal'/f'{request_key(source["request_id"])}.json').exists()


def test_write_ahead_is_durable_at_send_and_outcome_follows(make, tmp_path):
    lane, server, source, frame = durable(make, tmp_path)
    original = server.infer
    def infer(*args, **kwargs):
        guard = kwargs['dispatch_guard']
        from contextlib import contextmanager
        @contextmanager
        def checked_guard():
            with guard() as sent:
                on_disk = GenerationJournal(tmp_path/'journal').records[request_key(source['request_id'])]
                assert len(on_disk['intents']) == len(server.requests)+1
                assert len(on_disk['outcomes']) == len(server.requests)
                yield sent
        kwargs['dispatch_guard'] = checked_guard
        return original(*args, **kwargs)
    server.infer = infer
    assert terminal(lane, source, frame)['state'] == 'complete'
    join(lane)
    record = lane._journal.records[request_key(source['request_id'])]
    assert len(record['intents']) == len(record['outcomes']) == 3


def test_fsync_failure_never_dispatches(make, tmp_path, monkeypatch):
    lane, server, source, frame = durable(make, tmp_path)
    original = lane._journal._write
    def fail_intent(key, value):
        if value['intents']:
            raise OSError('synthetic fsync failure')
        return original(key, value)
    monkeypatch.setattr(lane._journal, '_write', fail_intent)
    result = terminal(lane, source, frame)
    join(lane)
    assert result['state'] != 'complete' and not server.requests


def test_slow_intent_write_does_not_hold_terminal_publication_or_send_after_freeze(make, tmp_path, monkeypatch):
    lane, server, source, frame = durable(make, tmp_path, deadline=.8)
    writing, release = threading.Event(), threading.Event()
    original = lane._journal._write
    def slow_write(key, value):
        if value['intents'] and not writing.is_set():
            writing.set()
            assert release.wait(2)
        return original(key, value)
    monkeypatch.setattr(lane._journal, '_write', slow_write)
    receipt = lane.submit(source, frame, 'fixture', upstream_coverage='intact')
    assert writing.wait(1)
    import time
    end = time.monotonic() + 1
    try:
        while time.monotonic() < end:
            value = lane.poll(receipt['result_handle'], 'fixture', frame.trace_id)
            if value['state'] != 'queued':
                break
            time.sleep(.002)
        assert value['state'] != 'queued'
        assert value['generation_budget']['primary_outcome'] == 'deadline_exceeded'
        assert not server.requests
    finally:
        release.set()
    join(lane)
    assert not server.requests


def test_epoch_mismatch_latches_unknown_even_after_late_result(make, tmp_path):
    lane, server, source, frame = durable(make, tmp_path)
    server.block = True
    receipt = lane.submit(source, frame, 'fixture', caller_epoch='before', upstream_coverage='intact')
    assert server.entered.wait(1)
    value = lane.poll(receipt['result_handle'], 'fixture', frame.trace_id, caller_epoch='after')
    assert value['state'] == 'degraded' and 'assistance' not in value
    assert lane.private_observation(source['request_id'])['reason'] == 'stale_epoch'
    assert lane.private_observation(source['request_id'])['restart_epoch'] == 'after'
    server.release.set()
    join(lane)
    for epoch in ('before', 'after', None):
        value = lane.poll(receipt['result_handle'], 'fixture', frame.trace_id, caller_epoch=epoch)
        assert value['state'] != 'complete' and 'assistance' not in value
    assert len(server.requests) == 1


def test_completed_epoch_mismatch_cannot_reexpose_text(make, tmp_path):
    lane, _, source, frame = durable(make, tmp_path)
    result = terminal(lane, source, frame)
    join(lane)
    assert result['state'] == 'complete'
    assert lane.poll(result['result_handle'], 'fixture', frame.trace_id, caller_epoch='another')['state'] == 'degraded'
    assert lane.submit(source, frame, 'fixture')['state'] == 'degraded'
    assert 'assistance' not in lane.poll(result['result_handle'], 'fixture', frame.trace_id)


def test_explainer_only_restart_never_polls_or_adopts_pending_result(tmp_path):
    from test_incident_explaind import make as explain, append, transition, handoff
    t = transition()
    trace = f'mio-{t["incident_id"][4:]}-1'
    queued = dict(state='queued',usage='unknown',generation_id='fixture',
                  frame_id=trace+':frame',trace_id=trace,result_handle='a'*64)
    original = explain(tmp_path, mio=lambda _: {**handoff(),'slow_analysis':queued}, mio_result=lambda *a,**k:None)
    append(original, t)
    original.poll()
    restarted = explain(tmp_path, mio_result=lambda *a,**k:pytest.fail('old result polled'))
    assert restarted.restart_epoch != original.restart_epoch
    restarted.poll()
    receipt = restarted._generation_receipts['a'*64]
    assert not restarted._record_generation_terminal(receipt, live())
    value = restarted.recent[0]['explanation']['slow_analysis']
    assert value['state'] == 'degraded' and value['budget']['outcome'] == 'stop_unconfirmed'
    assert value['budget']['cleanup_state'] == 'unconfirmed'
    assert restarted._private_generation_journal().observation(receipt['request_id'])['reason'] == 'stale_epoch'
    assert restarted._private_generation_journal().observation(receipt['request_id'])['restart_epoch'] == restarted.restart_epoch


def test_budgeted_explainer_result_store_contains_no_model_body(tmp_path):
    from test_generation_budget_receipts import explainer
    e, _, receipt, _ = explainer(tmp_path)
    # New handle/request, independent of the fixture's existing timeout.
    receipt = {**receipt, 'result_handle':'b'*64, 'incident_sequence':2,
               'request_id':receipt['incident_id']+':2',
               'trace_id':'mio-0123456789abcdef-2', 'frame_id':'mio-0123456789abcdef-2:frame'}
    assert e._append_generation_event(receipt)
    e._generation_receipts[receipt['result_handle']] = receipt
    value = live()
    value.update({k:receipt[k] for k in ('result_handle','trace_id','frame_id')})
    value['assistance'].update(frame_id=receipt['frame_id'],trace_id=receipt['trace_id'])
    value['assistance']['hypotheses'][0]['statement'] = 'SECRET-MODEL-BODY'
    assert e._record_generation_terminal(receipt,value)
    assert e._generation_value(receipt['result_handle'])['state'] == 'complete'
    rows = e.generation_store.events()
    assert 'SECRET-MODEL-BODY' not in json.dumps(rows)
    e._restore_generation_results()
    assert e._generation_value(receipt['result_handle'])['state'] == 'degraded'


def test_private_binding_uses_original_lifetime_and_withholds_without_verified_sources(tmp_path):
    from test_generation_budget_receipts import explainer
    e, _, receipt, _ = explainer(tmp_path)
    e._generation_metadata = dict(epoch=e.restart_epoch,handle=receipt['result_handle'],
        **{k:receipt[k] for k in ('request_id','frame_id','generation_id')},
        template_version='1.8.0',created_at=0.,expires_at=10.,unknowns=[])
    e._capture_private_binding(receipt)
    binding = e._generation_bindings[receipt['result_handle']]
    assert binding['expires_at'] == 10.
    assert binding['evidence_refs'] == binding['hypothesis_ids'] == binding['advisory_refs'] == []
    assert receipt['result_handle'] not in json.dumps(binding) and e.restart_epoch not in json.dumps(binding)


def test_explainer_sidecar_preserves_unknown_ids_and_origin_without_body(tmp_path):
    from test_generation_budget_receipts import explainer
    from azazel_nexus_runtime.mio_generation_journal import unknown_metadata
    e, _, receipt, _ = explainer(tmp_path)
    private = e._private_generation_journal()
    private.reserve(receipt['request_id'],receipt['result_handle'],receipt['generation_id'],
        NS(frame_id=receipt['frame_id'],trace_id=receipt['trace_id']),e.restart_epoch,60)
    e._generation_metadata = dict(epoch=e.restart_epoch,handle=receipt['result_handle'],
        **{k:receipt[k] for k in ('request_id','frame_id','generation_id')},
        template_version='1.8.0',created_at=0.,expires_at=10.,unknowns=unknown_metadata(['u1','um:1','ux:impact']))
    e._capture_private_binding(receipt)
    observation = GenerationJournal(private.directory).observation(receipt['request_id'])
    assert {u['id'] for u in observation['unknowns']} == {'u1','um:1','ux:impact'}
    assert all(u['status'] == 'unavailable_after_restart' for u in observation['unknowns'])


@pytest.mark.parametrize('name', ['advise','entry_poll','assess','local_poll'])
def test_optional_epoch_is_bounded_and_legacy_arguments_remain_identical(name):
    from azazel_nexus_runtime import mio_entryd, mio_locald
    from azazel_nexus_runtime.protocol import RequestRefused
    verbs = dict(advise=mio_entryd.ADVISE_VERB, entry_poll=mio_entryd.POLL_GENERATION_RESULT_VERB,
                 assess=mio_locald.FAST_ASSESS_VERB,local_poll=mio_locald.GENERATION_RESULT_VERB)
    verb = verbs[name]
    args = {arg.name: (10 if arg.name == 'deadline_ms' else 'fixture') for arg in verb.arguments}
    assert verb.bind(args) == args
    assert verb.bind({**args,'caller_epoch':'epoch-1'}) == {**args,'caller_epoch':'epoch-1'}
    for extra in ({'caller_epoch':'x'*65}, {'caller_epoch':'with space'}, {'arbitrary':'value'}):
        with pytest.raises(RequestRefused):
            verb.bind({**args,**extra})


def test_epoch_travels_explainer_entry_client_local_lane_and_stale_poll_is_withheld(make, service, tmp_path, monkeypatch):
    """Exercise all runtime adapters/argument binders without privileged sockets."""
    import sys
    from types import ModuleType
    from azazel_nexus.incident_explain import build_frame
    from azazel_nexus.generation_budget import selection_unknown
    from azazel_nexus_runtime import mio_locald, mio_entryd, mio_socket_client as client
    from azazel_nexus_runtime.principal import Principal, PrincipalClass
    from test_incident_explain import transition
    lane, server, _, frame = durable(make, tmp_path)
    source = build_frame(transition(), 1)
    ident = source['request_id'].split(':')[0]
    frame.trace_id = f'mio-{ident[4:]}-1'
    frame.frame_id = frame.trace_id + ':frame'
    selection = selection_unknown()
    selection['coverage'] = 'intact'
    adapter = ModuleType('azazel_nexus_runtime.mio_fast_assistance')
    adapter._frame = lambda *a,**k: (frame,selection)
    adapter.fast_assistance = lambda *a,**k: client.fast_assessment_degraded('unavailable')
    monkeypatch.setitem(sys.modules,adapter.__name__,adapter)
    local = mio_locald.LocalRuntimeService(generation_lane=lane,generation_id='fixture')
    principal = Principal(os.getuid(),os.getgid(),1,frozenset({PrincipalClass.SERVICE}))
    service._explainer_uid = principal.uid
    calls = []
    def local_exchange(leaf, account, verb, arguments, **kw):
        if verb not in ('mio.local.assess','mio.local.generation.result'):
            raise OSError('synthetic unavailable optional service')
        bound = mio_locald.REGISTRY.resolve(verb,principal).bind(arguments)
        calls.append((verb,bound.copy()))
        return local.handle(NS(verb=NS(name=verb),arguments=bound,payload=kw.get('payload')))
    def entry_exchange(leaf, account, verb, arguments, **kw):
        bound = mio_entryd.ADVISE_REGISTRY.resolve(verb,principal).bind(arguments)
        calls.append((verb,bound.copy()))
        return service.handle(NS(verb=NS(name=verb),arguments=bound,payload=kw.get('payload'),principal=principal))
    monkeypatch.setattr(client,'_exchange',local_exchange)
    monkeypatch.setattr(daemon,'_exchange',entry_exchange)
    details = {}
    reply = daemon.advise(source,caller_epoch='caller-before',private_metadata=details)
    receipt = reply['slow_analysis']
    assert 'result_handle' in receipt, reply
    join(lane)
    assert lane._journal.records[request_key(source['request_id'])]['epoch'] == 'caller-before'
    result = daemon.poll_generation_result(receipt,caller_epoch='caller-before',private_metadata=details)
    assert result['state'] == 'complete'
    assert details['handle'] == receipt['result_handle'] and details['epoch'] == 'caller-before'
    assert 'generation_metadata' not in reply and 'generation_metadata' not in result
    expired = daemon.poll_generation_result(receipt,caller_epoch='caller-after',private_metadata=details)
    assert expired['state'] == 'degraded' and 'assistance' not in expired
    assert expired['generation_budget']['outcome'] == 'stop_unconfirmed'
    assert details == {}
    assert [call[0] for call in calls] == ['mio.advise','mio.local.assess',
        'mio.generation.result','mio.local.generation.result','mio.generation.result','mio.local.generation.result']
    assert all('caller_epoch' in call[1] for call in calls)
