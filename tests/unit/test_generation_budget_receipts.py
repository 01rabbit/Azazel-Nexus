"""CORE-only receipt validation plus bounded durable cleanup/supersession replay."""
import copy
import json
from types import SimpleNamespace
import pytest
from azazel_nexus.generation_budget import TASKS, CAPS, task_placeholder, read_budget, project_budget, selection_unknown
from azazel_nexus.incident_explain import _validate_slow_analysis, slow_analysis_projection, build_recent_incident, build_recent_incidents
from azazel_nexus_runtime import incident_explaind as daemon


def metadata(*, complete=True, pending=False):
    tasks=[task_placeholder(task) for task in TASKS]
    for i,task in enumerate(tasks):
        if not complete and i>0: break
        task.update(dispatched=True,count_kind='exact',input_tokens_bound=12,input_limit=3000,
            output_tokens_cap=CAPS[i],output_min=CAPS[i],context_limit=4096,context_slack=32,
            allocated_ms=100,elapsed_ms=10,actual_usage={'tokens_in':12,'tokens_out':7},
            finish_reason='stop',context_integrity='preserved',validated=complete,
            selection=dict(policy_version='fixture-v1',coverage='intact',input_units=1,
                selected_units=1,omitted_units=0,omissions=[]))
    return dict(version=1,profile_id='fixture-v1',outcome='within_budget' if complete else 'deadline_exceeded',
        reasons=[] if complete else ['timeout'],coverage='intact' if complete else 'unknown',upstream_coverage='intact',
        upstream_selection=dict(policy_version='nexus-frame-v1',coverage='intact',input_units=2,
            selected_units=2,omitted_units=0,omissions=[]),
        elapsed_ms=50,deadline_ms=5000,result_state='complete' if complete else 'timeout',
        primary_outcome='within_budget' if complete else 'deadline_exceeded',superseded=False,
        cleanup=dict(state='pending' if pending else 'not_needed',reason=None,remaining_ms=1000 if pending else 0),
        job_calls=3 if complete else 1,tasks=tasks,core_complete=complete)


def live(meta=None):
    meta=meta or metadata()
    trace='mio-0123456789abcdef-1'
    state=project_budget(meta)[0]
    value=dict(state=state,usage='known',budget_version=1,generation_budget=meta,
        generation_id='fixture',trace_id=trace,frame_id=trace+':frame',result_handle='a'*64,
        calls=[dict(usage=t['actual_usage'],timings={}) for t in meta['tasks'] if t['dispatched']])
    if state=='complete':
        value['assistance']=dict(schema_version='mio.assistance.v1',generation_method='model',state='complete',
            trace_id=trace,frame_id=trace+':frame',hypotheses=[dict(verification='model_proposed_unverified',statement='Benign report'),
            dict(verification='model_proposed_unverified',statement='Unresolved report')],
            unknowns=['https://example.invalid/private'],next_checks=['Check approved records'])
    return value


def test_core_reader_and_public_projection_without_runtime_dependency():
    value=live();_validate_slow_analysis(value)
    shown=slow_analysis_projection(value)
    assert shown['state']=='complete' and shown['budget']['coverage']=='intact'
    assert shown['unknowns']==['Details withheld verify through an authorized source']
    assert value['result_handle'] not in json.dumps(shown) and value['trace_id'] not in json.dumps(shown)
    legacy={k:v for k,v in value.items() if k not in ('generation_budget','budget_version')}
    assert slow_analysis_projection(legacy)['budget']['outcome']=='legacy_unverified'


@pytest.mark.parametrize('change',[
    lambda m:m.update(version=2), lambda m:m.update(coverage='selected'),
    lambda m:m['tasks'].reverse(), lambda m:m['tasks'].__setitem__(1,copy.deepcopy(m['tasks'][0])),
    lambda m:m['tasks'][0].update(input_tokens_bound=13),
    lambda m:m['tasks'][0]['actual_usage'].update(tokens_out=10000),
    lambda m:m['tasks'][1].update(dispatched=False),
    lambda m:m.update(reasons=['timeout']), lambda m:m['cleanup'].update(state='pending',remaining_ms=10),
    lambda m:m['tasks'][2].update(finish_reason=None),
    lambda m:m['tasks'][1].update(context_integrity='unknown'),
    lambda m:m.update(upstream_coverage='unknown'),
    lambda m:m['tasks'][0].update(input_tokens_bound=True),
    lambda m:m['tasks'][0].update(allocated_ms=float('nan')),
])
def test_forged_success_rejected(change):
    meta=metadata();change(meta)
    with pytest.raises(ValueError): read_budget(meta,state='complete',usage='known')


def test_missing_metadata_cannot_downgrade_new_result_to_legacy():
    value=live();del value['generation_budget']
    with pytest.raises(ValueError): _validate_slow_analysis(value)
    value=live();value['generation_budget']['version']=2
    with pytest.raises(ValueError): _validate_slow_analysis(value)


def test_selected_survives_later_intact_and_upstream_unknown_prevents_complete():
    meta=metadata()
    meta['tasks'][0]['selection'].update(coverage='selected',input_units=2,omitted_units=1,
        omissions=[dict(kind='semantic_unit',ordinal=1,reason='optional_detail')])
    meta['coverage']='selected'
    assert read_budget(meta,state='complete',usage='known')['coverage']=='selected'
    assert slow_analysis_projection(live(meta))['budget']['omitted_units']==1
    meta['upstream_coverage']='unknown';meta['upstream_selection']['coverage']='unknown';meta['coverage']='unknown'
    with pytest.raises(ValueError): read_budget(meta,state='complete',usage='known')


def explainer(tmp_path):
    clock=SimpleNamespace(now=0.)
    e=daemon.Explainer(incidents=tmp_path/'incidents',state=tmp_path/'state',status_path=tmp_path/'status',
        clock=lambda:0.,monotonic=lambda:clock.now)
    e.generation_store=daemon.GenerationResultStore(tmp_path)
    e.generation_store.prepare(0)
    value=live(metadata(complete=False,pending=True))
    receipt=dict(event_type='mio.generation.receipt',incident_id='inc-0123456789abcdef',incident_sequence=1,
        request_id='inc-0123456789abcdef:1',frame_id=value['frame_id'],trace_id=value['trace_id'],
        generation_id='fixture',result_handle=value['result_handle'],recorded_at=0)
    assert e._append_generation_event(receipt)
    e._generation_receipts[receipt['result_handle']]=receipt
    e._generation_current[receipt['incident_id']]=receipt['result_handle']
    assert e._record_generation_terminal(receipt,value,sent_at=0.)
    return e,clock,receipt,value


def test_cleanup_and_supersession_are_independent_bounded_events(tmp_path):
    e,clock,receipt,value=explainer(tmp_path);handle=receipt['result_handle']
    original=copy.deepcopy(e._generation_terminal[handle])
    assert e._record_generation_superseded(receipt)
    assert e._record_generation_cleanup(receipt,'unconfirmed','stop_failed')
    assert e._record_generation_superseded(receipt)
    e._record_generation_cleanup(receipt,'confirmed','stop_confirmed')
    folded=e._generation_value(handle)
    assert folded['state']=='degraded' and folded['generation_budget']['superseded']
    assert folded['generation_budget']['primary_outcome']=='deadline_exceeded'
    assert e._generation_terminal[handle]==original
    rows=e.generation_store.events()
    assert [r['event_type'] for r in rows]==['mio.generation.receipt','mio.generation.result',
        'mio.generation.superseded','mio.generation.cleanup']
    e._restore_generation_results()
    assert e._generation_value(handle)==folded
    assert e.generation_store.events()==rows
    duplicate=rows[-1]
    e.generation_store.append_event(duplicate,segment_at=0)
    assert e.generation_store.events()==rows
    conflict={**duplicate,'cleanup_state':'confirmed','cleanup_reason':'stop_confirmed'}
    with pytest.raises(ValueError): e.generation_store.append_event(conflict,segment_at=0)


def test_restart_pending_immediately_records_unconfirmed_and_never_polls(tmp_path):
    e,clock,receipt,value=explainer(tmp_path)
    e._restore_generation_results()
    assert e._generation_value(receipt['result_handle'])['generation_budget']['cleanup']['reason']=='restart_unconfirmed'
    e.mio_result=lambda *_a,**_k:pytest.fail('restart pending must not poll')
    e._poll_generation_results()
    assert len(e.generation_store.events())==3


@pytest.mark.parametrize('failure',['ttl','network','deadline'])
def test_pending_observation_loss_or_expiry_is_final(tmp_path,failure):
    e,clock,receipt,value=explainer(tmp_path)
    if failure=='deadline': clock.now=1.1
    e.mio_result=(lambda *_a,**_k:None) if failure=='network' else (lambda *_a,**_k:{'state':'stale','usage':'unknown'})
    e._poll_generation_results()
    handle=receipt['result_handle']
    folded=e._generation_value(handle)
    assert folded['generation_budget']['cleanup']['state']=='unconfirmed'
    assert folded['generation_budget']['cleanup']['reason']==('confirmation_deadline' if failure=='deadline' else 'observation_lost')
    e.mio_result=lambda *_a,**_k:pytest.fail('terminal cleanup must not poll')
    e._poll_generation_results()


def test_pending_deadline_never_extends_and_confirm_after_deadline_is_refused(tmp_path):
    e,clock,receipt,value=explainer(tmp_path)
    handle=receipt['result_handle'];clock.now=.8
    e.mio_result=lambda *_a,**_k:copy.deepcopy(value)
    e._poll_generation_results()
    assert e._generation_cleanup_deadlines[handle]==1.
    clock.now=1.1
    result=copy.deepcopy(value)
    result['generation_budget']['cleanup']=dict(state='confirmed',reason='stop_confirmed',remaining_ms=0)
    e.mio_result=lambda *_a,**_k:result
    e._poll_generation_results()
    assert e._generation_value(handle)['generation_budget']['cleanup']['state']=='unconfirmed'


def test_cleanup_requires_pending_result_full_binding_and_correct_segment(tmp_path):
    e,clock,receipt,value=explainer(tmp_path)
    event=dict(event_type='mio.generation.cleanup',**e._generation_binding(receipt),recorded_at=0,
        cleanup_version=1,cleanup_revision=1,cleanup_state='unconfirmed',cleanup_reason='stop_failed')
    with pytest.raises(ValueError): e.generation_store.append_event({**event,'generation_id':'wrong'},segment_at=0)
    with pytest.raises(ValueError): e.generation_store.append_event(event,segment_at=86400)
    assert len(e.generation_store.events())==2


def test_core_only_process_can_read_budget_without_runtime_installed(tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path
    core=Path(__file__).resolve().parents[2]/'src'
    paths=[str(core)]+[p for p in os.environ.get('PYTHONPATH','').split(os.pathsep) if p.endswith('/deps')]
    code='''import importlib.util,json
assert importlib.util.find_spec("azazel_nexus_runtime") is None
from azazel_nexus.incident_explain import slow_analysis_projection
from azazel_nexus.generation_budget import read_budget
value=json.loads(__import__("sys").stdin.read())
assert slow_analysis_projection(value)["budget"]["outcome"] == "within_budget"
'''
    proc=subprocess.run([sys.executable,'-c',code],input=json.dumps(live()),text=True,
        cwd=tmp_path,env={**os.environ,'PYTHONPATH':os.pathsep.join(paths)},capture_output=True)
    assert proc.returncode==0,proc.stderr


def test_unknown_version_history_is_preserved_and_projects_unsupported(tmp_path):
    e,clock,receipt,_=explainer(tmp_path)
    # Use a separate future-version fixture stream, retaining its bytes exactly.
    other=daemon.GenerationResultStore(tmp_path/'future')
    other.prepare(0);other.append_event(receipt)
    value=live();value['budget_version']=2;value['generation_budget']['version']=2
    future=dict(event_type='mio.generation.result',**e._generation_binding(receipt),recorded_at=0,
        state='complete',usage='known',budget_version=2,generation_budget=value['generation_budget'],assistance=value['assistance'])
    with pytest.raises(ValueError):other.append_event(future,segment_at=0)
    path=other.path_at(0)
    with path.open('ab') as stream:stream.write(json.dumps(future).encode()+b'\n')
    original=path.read_bytes()
    assert other.events()[-1]==future
    e.generation_store=other
    e.recent=[dict(incident_id=receipt['incident_id'],explanation={})]
    e._restore_generation_results()
    assert e.recent[0]['explanation']['slow_analysis']['budget']['outcome']=='unsupported'
    assert e._generation_terminal[receipt['result_handle']]==future
    assert path.read_bytes()==original
    from azazel_nexus.generation_budget import validate_public_budget
    validate_public_budget(dict(version=0,outcome='unsupported',coverage='unknown',cleanup_state='unconfirmed',superseded=False,omitted_units=0))


def test_cleanup_confirmation_before_deadline_is_recorded_once(tmp_path):
    e,clock,receipt,value=explainer(tmp_path)
    clock.now=.5
    value=copy.deepcopy(value)
    value['generation_budget']['cleanup']=dict(state='confirmed',reason='stop_confirmed',remaining_ms=0)
    e.mio_result=lambda *_a,**_k:value
    e._poll_generation_results()
    assert e._generation_value(receipt['result_handle'])['generation_budget']['cleanup']['state']=='confirmed'
    e.mio_result=lambda *_a,**_k:pytest.fail('confirmed must not poll')
    e._poll_generation_results()
    assert len(e.generation_store.events())==3


def test_cleanup_storage_failure_does_not_publish_false_confirmation(tmp_path,monkeypatch):
    e,clock,receipt,value=explainer(tmp_path)
    monkeypatch.setattr(e.generation_store,'append_event',lambda *a,**kw:(_ for _ in ()).throw(OSError('fixture')))
    assert e._record_generation_cleanup(receipt,'confirmed','stop_confirmed') is False
    assert e._generation_store_failed
    assert not e._generation_cleanup
    assert e._generation_value(receipt['result_handle'])['generation_budget']['cleanup']['state']=='pending'


def test_planned_context_fit_is_checked_even_when_actual_short_output_fits():
    meta=metadata()
    meta['tasks'][0].update(input_tokens_bound=3500,input_limit=4000)
    meta['tasks'][0]['actual_usage']['tokens_in']=3500
    # Actual 3500+7+32 fits C; the reserved 3500+768+32 does not.
    with pytest.raises(ValueError): read_budget(meta,state='complete',usage='known')


def test_confirmation_that_arrives_after_local_deadline_cannot_confirm(tmp_path):
    e,clock,receipt,value=explainer(tmp_path)
    clock.now=.8
    confirmed=copy.deepcopy(value)
    confirmed['generation_budget']['cleanup']=dict(state='confirmed',reason='stop_confirmed',remaining_ms=0)
    def reply(*args,**kw):
        clock.now=1.1
        return confirmed
    e.mio_result=reply
    e._poll_generation_results()
    assert e._generation_value(receipt['result_handle'])['generation_budget']['cleanup']['state']=='unconfirmed'


def test_superseded_projection_cannot_hide_invalid_original_complete():
    meta=metadata();meta['superseded']=True;meta['outcome']='superseded';meta['reasons']=['timeout']
    with pytest.raises(ValueError):read_budget(meta,state='superseded',usage='known')
    meta=metadata();meta['superseded']=True;meta['outcome']='superseded'
    assert read_budget(meta,state='superseded',usage='known')['primary_outcome']=='within_budget'


def test_submillisecond_remaining_is_not_expiry_and_exposed_unconfirmed_never_reverts(monkeypatch):
    from azazel_nexus_runtime import mio_generation as generation
    lane=generation.GenerationLane()
    record=dict(status=live(metadata(complete=False,pending=True)),end=1000.)
    clock=SimpleNamespace(now=999.9995)
    monkeypatch.setattr(generation,'time',SimpleNamespace(monotonic=lambda:clock.now))
    before=lane._public_record(record)
    assert before['generation_budget']['cleanup']['remaining_ms']==0
    assert before['generation_budget']['cleanup']['state']=='pending'
    assert not lane._fenced
    clock.now=1000.
    final=lane._public_record(record)
    assert final['generation_budget']['cleanup']['state']=='unconfirmed' and lane._fenced
    # A delayed publication from the stop observer cannot undo what was exposed.
    record['status']['generation_budget']['cleanup']=dict(state='confirmed',reason='stop_confirmed',remaining_ms=0)
    after=lane._public_record(record)
    assert after==final


def test_early_supersession_keeps_polling_until_real_result_and_cleanup(tmp_path):
    e,clock,receipt,value=explainer(tmp_path)
    # New isolated receipt, invalidated while still queued.
    receipt={**receipt,'result_handle':'b'*64}
    value={**value,'result_handle':'b'*64}
    assert e._append_generation_event(receipt)
    e._generation_receipts[receipt['result_handle']]=receipt
    assert e._record_generation_superseded(receipt)
    handle=receipt['result_handle']
    assert handle not in e._generation_terminal
    assert e._generation_value(handle)['state']=='superseded'
    e.mio_result=lambda r,**kw:value if r['result_handle']==handle else None
    # Finish the older pending cleanup so this poll reaches the new receipt.
    older=next(r for r in e._generation_receipts.values() if r['result_handle']!=handle)
    e._record_generation_cleanup(older,'unconfirmed','observation_lost')
    e._poll_generation_results()
    original=e._generation_terminal[handle]
    assert original['generation_budget']['result_state']=='superseded'
    assert original['generation_budget']['tasks'][0]['actual_usage']=={'tokens_in':12,'tokens_out':7}
    assert e._cleanup_pending(handle)
    stopped=copy.deepcopy(value)
    stopped['generation_budget']['cleanup']=dict(state='unconfirmed',reason='stop_failed',remaining_ms=0)
    stopped['state'],stopped['generation_budget']=project_budget(stopped['generation_budget'])
    e.mio_result=lambda *_a,**_k:stopped
    e._poll_generation_results()
    assert e._generation_value(handle)['state']=='degraded'
    assert e._generation_value(handle)['generation_budget']['outcome']=='stop_unconfirmed'
    assert e._generation_value(handle)['generation_budget']['superseded']
    e._restore_generation_results()
    assert e._generation_value(handle)['generation_budget']['outcome']=='stop_unconfirmed'
