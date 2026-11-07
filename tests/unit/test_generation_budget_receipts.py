"""CORE-only receipt validation plus bounded durable cleanup/supersession replay."""
import copy
import json
from types import SimpleNamespace
import pytest
from azazel_nexus.generation_budget import TASKS, CAPS, task_placeholder, read_budget, project_budget, selection_unknown
from azazel_nexus.incident_explain import validate_slow_analysis, slow_analysis_projection, build_recent_incident, build_recent_incidents
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
    value = dict(version=1,profile_id='fixture-v1',outcome='within_budget' if complete else 'deadline_exceeded',
        reasons=[] if complete else ['timeout'],coverage='intact' if complete else 'unknown',upstream_coverage='intact',
        upstream_selection=dict(policy_version='nexus-frame-v1',coverage='intact',input_units=2,
            selected_units=2,omitted_units=0,omissions=[]),
        elapsed_ms=50,deadline_ms=5000,result_state='complete' if complete else 'timeout',
        primary_outcome='within_budget' if complete else 'deadline_exceeded',superseded=False,
        cleanup=dict(state='pending' if pending else 'not_needed',reason=None,remaining_ms=1000 if pending else 0),
        job_calls=3 if complete else 1,tasks=tasks,core_complete=complete)
    from azazel_nexus.generation_budget import verified_tuple_from_props
    value['verified_tuple']=verified_tuple_from_props(dict(model_alias='fixture',model_path='/fixture/model.gguf',
        model_ftype='fixture',chat_template='fixture',bos_token='BOS',eos_token='EOS',build_info='fixture',
        default_generation_settings={'n_ctx':4096}))
    value['profile']=dict(version=1,origin='fixture',reserve_fraction=.1,minimum_reserve_ms=500.,weights=[45,20,35],
        slack=32,output_caps=list(CAPS),output_mins=list(CAPS),minimum_provider_ms=[50.,50.,50.],template_version='fixture-v1',configured_context_limit=4096)
    return value



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
    value=live();validate_slow_analysis(value)
    shown=slow_analysis_projection(value)
    assert shown['state']=='complete' and shown['budget']['coverage']=='intact'
    assert shown['unknowns']==['Details withheld verify through an authorized source']
    assert value['result_handle'] not in json.dumps(shown) and value['trace_id'] not in json.dumps(shown)
    legacy={k:v for k,v in value.items() if k not in ('generation_budget','budget_version')}
    assert slow_analysis_projection(legacy)['budget']['outcome']=='legacy_unverified'


@pytest.mark.parametrize(('version', 'accepted'), [
    ('1.6.0', True), ('1.7.0', True), ('1.8.0', True), ('1.9.0', False),
    ('1.7', False), ('1.7.0-extra', False),
])
def test_template_version_allowlist_keeps_old_receipts_and_rejects_unknown(version, accepted):
    meta = metadata()
    meta['profile']['template_version'] = version
    for task in meta['tasks']:
        task['selection']['policy_version'] = version
    if accepted:
        assert read_budget(meta, state='complete', usage='known')['profile']['template_version'] == version
    else:
        with pytest.raises(ValueError):
            read_budget(meta, state='complete', usage='known')


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
    with pytest.raises(ValueError): validate_slow_analysis(value)
    value=live();value['generation_budget']['version']=2
    with pytest.raises(ValueError): validate_slow_analysis(value)


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


@pytest.mark.parametrize('isolated_core',[True,False],ids=['core-without-site-packages','current-installation'])
def test_core_reader_in_isolated_and_current_installation(tmp_path,isolated_core):
    import importlib.util
    import os
    import subprocess
    import sys
    from pathlib import Path
    core=Path(__file__).resolve().parents[2]/'src'
    code='''import importlib.util,json,sys
payload=json.loads(sys.stdin.read())
if payload["isolated_core"]:
    assert importlib.util.find_spec("azazel_nexus_runtime") is None
    assert importlib.util.find_spec("azazel_mio") is None
    assert importlib.util.find_spec("azazel_fabric") is None
else:
    assert (importlib.util.find_spec("azazel_fabric") is not None)==payload["fabric_available"]
    if payload["fabric_available"]:
        import azazel_fabric
from azazel_nexus.incident_explain import validate_slow_analysis,slow_analysis_projection
from azazel_nexus.generation_budget import read_budget
value=payload["value"]
validate_slow_analysis(value)
read_budget(value["generation_budget"],state=value["state"],usage=value["usage"])
assert slow_analysis_projection(value)["budget"]["outcome"]=="within_budget"
assert not any(name==root or name.startswith(root+".") for name in sys.modules
               for root in ("azazel_nexus_runtime","azazel_mio"))
'''
    payload=dict(value=live(),isolated_core=isolated_core,
        fabric_available=importlib.util.find_spec('azazel_fabric') is not None)
    # -S removes installed/editable finders, not just PYTHONPATH entries.
    flags=['-S'] if isolated_core else []
    env={**os.environ,'PYTHONPATH':str(core)} if isolated_core else dict(os.environ)
    proc=subprocess.run([sys.executable,*flags,'-c',code],input=json.dumps(payload),text=True,
        cwd=tmp_path,env=env,capture_output=True)
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


@pytest.mark.parametrize('change',[
    lambda m:m['tasks'][0].update(allocated_ms=1,elapsed_ms=1000),
    lambda m:m['tasks'][0].update(allocated_ms=None),
    lambda m:m['tasks'][0].update(output_tokens_cap=7,output_min=1),
    lambda m:m.update(elapsed_ms=4999),
    lambda m:m['tasks'][1].update(context_limit=8192),
    lambda m:m['tasks'][1]['selection'].update(policy_version='unknown-template'),
    lambda m:m.pop('verified_tuple'),
    lambda m:m['tasks'][0].update(input_limit=4000),
    lambda m:[t.update(allocated_ms=2000) for t in m['tasks']],
])
def test_r4_reader_rejects_time_profile_and_tuple_counterexamples(change):
    value=metadata();change(value)
    with pytest.raises(ValueError):read_budget(value,state='complete',usage='known')


@pytest.mark.parametrize('change',[
    lambda m:[t.update(allocated_ms=1,elapsed_ms=.5) for t in m['tasks']],
    lambda m:m['profile'].update(reserve_fraction=.00001,minimum_reserve_ms=.001),
    lambda m:m['profile'].update(weights=[1,1,1]),
    lambda m:m['profile'].update(slack=0),
    lambda m:m['profile'].update(minimum_provider_ms=[1,1,1]),
    lambda m:m['profile'].update(configured_context_limit=None),
    lambda m:m['profile'].update(configured_context_limit=2048),
])
def test_stage7_reader_refuses_minimum_policy_and_context_contradictions(change):
    value=live();change(value['generation_budget'])
    value['generation_budget']['elapsed_ms']=2 if value['generation_budget']['tasks'][0]['allocated_ms']==1 else 50
    with pytest.raises(ValueError):validate_slow_analysis(value)
    with pytest.raises(ValueError):slow_analysis_projection(value)


@pytest.mark.parametrize(('verified','configured'),[(8192,2048),(2048,8192)])
def test_reader_accepts_context_minimum_from_two_known_limits(verified,configured):
    from azazel_nexus.generation_budget import canonical_digest
    value=metadata();v=value['verified_tuple'];v['context_limit']=verified
    v['tuple_id']=canonical_digest({k:x for k,x in v.items() if k!='tuple_id'})
    value['profile']['configured_context_limit']=configured
    for task in value['tasks']:
        task['context_limit']=2048
        task['input_limit']=2048-task['output_tokens_cap']-task['context_slack']
    assert read_budget(value,state='complete',usage='known')['tasks'][0]['context_limit']==2048


@pytest.mark.parametrize('allocation',[1,5000])
def test_failed_receipt_cannot_claim_impossible_allocations(allocation):
    value=metadata(complete=False);value['tasks'][0]['allocated_ms']=allocation
    with pytest.raises(ValueError):read_budget(value,state='timeout',usage='known')


def test_public_dispatch_is_bounded_and_does_not_claim_fence_observation():
    from azazel_nexus.generation_budget import validate_public_budget
    meta = metadata(complete=False, pending=True)
    meta['cleanup'] = dict(state='unconfirmed', reason='observation_lost', remaining_ms=0)
    _, meta = project_budget(meta)
    shown = slow_analysis_projection(live(meta))
    budget = shown['budget']
    assert budget['fence_state'] == 'unknown'
    assert [t['dispatched'] for t in budget['dispatch']] == [True, False, False]
    validate_public_budget(budget, state='degraded')
    for key, value in [('fence_state', True), ('dispatch', [{'task':'secret', 'dispatched':False}])]:
        bad = copy.deepcopy(budget)
        bad[key] = value
        with pytest.raises(ValueError):
            validate_public_budget(bad, state='degraded')


@pytest.mark.parametrize('sent', [0, 1, 2, 3])
def test_degraded_public_dispatch_allows_each_sent_prefix(sent):
    from azazel_nexus.generation_budget import TASKS, validate_public_budget
    budget = dict(version=1, outcome='deadline_exceeded', coverage='unknown',
                  cleanup_state='not_needed', superseded=False, omitted_units=0,
                  fence_state='unknown', dispatch=[
                      dict(task=task, dispatched=i < sent) for i, task in enumerate(TASKS)])
    validate_public_budget(budget, state='degraded')


def test_legacy_complete_projection_without_dispatch_remains_valid():
    from azazel_nexus.generation_budget import validate_public_budget
    budget = slow_analysis_projection(live())['budget']
    budget.pop('dispatch')
    budget.pop('fence_state')
    validate_public_budget(budget, state='complete')
