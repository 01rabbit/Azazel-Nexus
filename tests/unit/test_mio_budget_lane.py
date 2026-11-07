"""Budget path with a mocked agreed MIO API and controlled local transport."""
import copy
from contextlib import nullcontext
import json
import sys
import threading
import time
from types import ModuleType, SimpleNamespace as NS
import pytest
from azazel_nexus.generation_budget import TASKS, CAPS, read_budget
from azazel_nexus_runtime.mio_generation import GenerationLane, GenerationCapability, read_slow_analysis
from azazel_nexus_runtime.mio_serve import LocalInferenceResult


class Lane(GenerationLane):
    def _authorized(self, generation):
        return generation == 'fixture'


class Server:
    def __init__(self):
        self.requests=[]
        self.counts=[]
        self.stopped=threading.Event()
        self.entered=threading.Event()
        self.release=threading.Event()
        self.fail_task=None
        self.integrity='preserved'
        self.finish='stop'
        self.known=True
        self.block=False
        self.stop_hang=False
        self.stop_fail=False
        self.context=4096
    def context_limit(self, deadline_s):
        return self.context
    def count_chat_tokens(self, request, deadline_s):
        self.counts.append(request)
        task=request.response_format['json_schema']['name']
        return None if task==self.fail_task else 12
    def verified_tuple(self,deadline_s):
        from azazel_nexus.generation_budget import verified_tuple_from_props
        return verified_tuple_from_props(dict(model_alias='fixture',model_path='/fixture/model.gguf',
            model_ftype='fixture',chat_template='fixture',bos_token='BOS',eos_token='EOS',build_info='fixture',
            default_generation_settings={'n_ctx':self.context}))
    def prepare_native(self,request,deadline_s,*,expected_tuple):
        from azazel_nexus_runtime.mio_serve import NativePrompt,TokenCountUnknown,request_digest
        if self.verified_tuple(deadline_s)!=expected_tuple:raise TokenCountUnknown('changed')
        count=self.count_chat_tokens(request,deadline_s)
        if type(count) is not int or count<1:raise TokenCountUnknown('unknown')
        return NativePrompt(tuple(range(count)),request_digest(request),expected_tuple['tuple_id'])
    def infer_native(self,request,deadline_s,*,prepared,expected_tuple,**kwargs):
        from azazel_nexus_runtime.mio_serve import TokenCountUnknown
        if self.verified_tuple(deadline_s)!=expected_tuple:raise TokenCountUnknown('changed')
        return self.infer(request,deadline_s,**kwargs)
    def infer(self, request, deadline_s, **kw):
        if kw.get('before_dispatch') is not None:kw['before_dispatch']()
        with kw['dispatch_guard']() if kw.get('dispatch_guard') else nullcontext() as record_sent:
            self.requests.append((request, deadline_s))
            if record_sent:record_sent()
        if kw.get('on_dispatch') is not None:kw['on_dispatch']()
        self.entered.set()
        if self.block:
            self.release.wait(5)
        return LocalInferenceResult('{}',12 if self.known else None,7 if self.known else None,{},self.finish,self.integrity)
    def stop(self):
        self.stopped.set()
        if self.stop_hang:
            self.release.wait(5)
        if self.stop_fail:
            raise OSError('fixture')
        self.release.set()
        from azazel_nexus_runtime.mio_supervisor import StopResult, StopState
        return StopResult(StopState.CONFIRMED, 'fixture_stop_confirmed')


@pytest.fixture
def make(monkeypatch):
    mio=ModuleType('azazel_mio')
    api=ModuleType('azazel_mio.budget')
    api.GenerationBudget=lambda **kw:NS(**kw)
    api.GenerationOutcome=NS
    api.PromptSelection=NS
    class BudgetError(ValueError):
        def __init__(self,reason,detail):self.reason=reason;self.detail=detail
    api.BudgetError=BudgetError
    model=ModuleType('azazel_mio.model_adapter')
    model.MioModelUnavailable=type('MioModelUnavailable',(ValueError,),{})
    schema=ModuleType('azazel_mio.model_schema')
    schema.model_response_schema=lambda task:{}
    playbook=ModuleType('azazel_mio.playbook')
    playbook.compiled_model_response_schema=lambda task,prompt:{'type':'object','title':'effective-'+task}
    class Core:
        def __init__(self,model): self.model=model
        def explain(self,frame,*,generation_budget,**kw):
            selections={}; calls=dict.fromkeys(TASKS,0); results=dict.fromkeys(TASKS,'not_started')
            reason=None
            plan = TASKS + (('update_hypotheses',) if self.model.job['source'].get('fourth_task') else ())
            for task in plan:
                try:
                    budget=generation_budget(task)
                    count=budget.count_tokens('fixture')
                    if count is None:
                        reason='count_unknown'; break
                    selected=self.model.job['source'].get('selected_first') and task==TASKS[0]
                    selections[task]=NS(coverage='selected' if selected else 'full',kept=('core',),
                        dropped=(('optional','optional_detail'),) if selected else (),token_count=count,template_version='fixture-v1')
                    def on_dispatch():
                        if calls[task]:raise RuntimeError('duplicate notification')
                        calls[task]=1
                    self.model.invoke_budgeted(task,'fixture',on_dispatch)
                    results[task]='validated'
                except Exception:
                    if self.model.job['source'].get('supersede_after_failure'):
                        self.model.job['reason']='superseded';self.model.job['cancelled'].set()
                    break
            receipt=NS(state='complete' if all(v=='validated' for v in results.values()) else 'failed',
                task_results=results,calls_sent=calls,selections=selections,reason=reason,
                usage={t:self.model.usage_for_task(t) for t in TASKS},coordinator_disposition=None)
            data=dict(schema_version='mio.assistance.v1',state='complete',generation_method='model',
                frame_id=frame.frame_id,trace_id=frame.trace_id,hypotheses=[dict(verification='model_proposed_unverified',statement='Benign report'),
                dict(verification='model_proposed_unverified',statement='Unresolved report')],unknowns=[],next_checks=[])
            return NS(generation_receipt=receipt,to_dict=lambda:data)
    mio.AssistantCore=Core; mio.budget=api
    for name,module in [('azazel_mio',mio),('azazel_mio.budget',api),('azazel_mio.model_adapter',model),('azazel_mio.model_schema',schema),('azazel_mio.playbook',playbook)]:
        monkeypatch.setitem(sys.modules,name,module)
    lanes=[]
    def create(deadline=5):
        server=Server()
        lane=Lane(capability=GenerationCapability('fixture','fixture','2099-01-01T00:00:00Z',1,lambda:True,model_context_limit=4096),
            server=server,deadline_s=deadline,budget_enabled=True)
        frame=NS(frame_id='trace:frame',trace_id='trace')
        source={'request_id':'fixture'}
        lanes.append((lane,server))
        return lane,server,source,frame
    yield create
    for lane,server in lanes:
        server.release.set()


def terminal(lane,source,frame):
    first=lane.submit(source,frame,'fixture',upstream_coverage='intact')
    until=time.monotonic()+2
    while time.monotonic()<until:
        status=lane.poll(first['result_handle'],'fixture',frame.trace_id)
        if status['state']!='queued': return status
        time.sleep(.002)
    pytest.fail('budget result did not terminate')


def test_three_tasks_use_counts_caps_and_shared_deadline(make):
    lane,server,source,frame=make()
    value=terminal(lane,source,frame)
    assert value['state']=='complete',value
    assert [r.max_tokens for r,_ in server.requests]==list(CAPS)
    assert [r.response_format['json_schema']['schema']['title'] for r,_ in server.requests]==['effective-'+task for task in TASKS]
    assert len(server.counts)==6
    assert len(server.requests)==3
    meta=read_budget(value['generation_budget'],state='complete',usage='known')
    assert meta['job_calls']==3 and meta['core_complete'] and meta['coverage']=='intact'
    assert read_slow_analysis(value)==value
    assert all(t['actual_usage']=={'tokens_in':12,'tokens_out':7} for t in meta['tasks'])
    assert sum(t['elapsed_ms'] for t in meta['tasks'])<meta['deadline_ms']


def test_truncated_upstream_frame_is_budget_exhausted_before_dispatch(make):
    lane, server, source, frame = make()
    frame.truncated = True
    result = lane.submit(source, frame, 'fixture', upstream_coverage='unknown')
    assert result['state'] == 'degraded'
    assert result['generation_budget']['primary_outcome'] == 'budget_exhausted'
    assert result['generation_budget']['job_calls'] == 0
    assert not server.requests and not server.counts


def test_rejected_revision_supersedes_pending_request(make):
    lane, server, source, frame = make()
    server.block = True
    active = lane.submit({'request_id': 'other'}, frame, 'fixture', upstream_coverage='intact')
    assert server.entered.wait(2)
    pending = lane.submit({**source, 'revision': 1}, frame, 'fixture', upstream_coverage='intact')
    bad = NS(frame_id=frame.frame_id, trace_id=frame.trace_id, truncated=True)
    rejected = lane.submit({**source, 'revision': 2}, bad, 'fixture', upstream_coverage='unknown')
    assert rejected['generation_budget']['job_calls'] == 0
    assert not lane._active['cancelled'].is_set()
    assert lane._active['handle'] == active['result_handle']
    assert lane._pending is None
    old = lane.poll(pending['result_handle'], 'fixture', frame.trace_id)
    assert old['state'] == 'superseded'
    meta = read_budget(old['generation_budget'], state=old['state'], usage=old['usage'])
    assert meta['primary_outcome'] == 'cancelled' and 'superseded' in meta['reasons']
    assert meta['job_calls'] == 0


def test_rejected_revision_does_not_replace_prior_failure(make):
    lane, server, source, frame = make()
    server.block = True
    first = lane.submit({**source, 'revision': 1}, frame, 'fixture', upstream_coverage='intact')
    assert server.entered.wait(2)
    lane._active['budget_session'].note_failure('truncated', 'runtime_truncated')
    bad = NS(frame_id=frame.frame_id, trace_id=frame.trace_id, truncated=True)
    lane.submit({**source, 'revision': 2}, bad, 'fixture', upstream_coverage='unknown')
    server.release.set()
    until = time.monotonic() + 2
    while time.monotonic() < until:
        old = lane.poll(first['result_handle'], 'fixture', frame.trace_id)
        if old['state'] != 'queued':
            break
        time.sleep(.002)
    assert old['state'] == 'superseded'
    meta = old['generation_budget']
    assert meta['primary_outcome'] == 'runtime_truncated'
    assert meta['reasons'][0] == 'truncated' and 'superseded' in meta['reasons']
    assert meta['job_calls'] == 1


def test_second_count_unknown_preserves_first_usage_and_unsent_tasks(make):
    lane,server,source,frame=make();server.fail_task=TASKS[1]
    value=terminal(lane,source,frame)
    assert value['state']=='degraded' and len(server.requests)==1
    meta=value['generation_budget']
    assert meta['outcome']=='token_count_unknown'
    assert meta['job_calls']==1
    assert meta['tasks'][0]['actual_usage']=={'tokens_in':12,'tokens_out':7}
    assert [t['dispatched'] for t in meta['tasks']]==[True,False,False]


@pytest.mark.parametrize(('attribute','bad','outcome'),[
    ('integrity','truncated','runtime_truncated'),('integrity','unknown','truncation_unknown'),
    ('finish','length','output_incomplete'),('known',False,'token_usage_unknown')])
def test_invalid_provider_completion_never_advances(make,attribute,bad,outcome):
    lane,server,source,frame=make();setattr(server,attribute,bad)
    value=terminal(lane,source,frame)
    assert value['state']=='degraded' and len(server.requests)==1
    assert value['generation_budget']['outcome']==outcome
    assert value['generation_budget']['job_calls']==1


def test_unknown_context_does_not_send(make):
    lane,server,source,frame=make();server.context=None
    value=terminal(lane,source,frame)
    assert not server.requests
    assert value['generation_budget']['outcome']=='token_count_unknown'


def test_stop_hang_terminates_independently_and_late_return_cannot_complete(make):
    lane,server,source,frame=make(deadline=1)
    server.block=True;server.stop_hang=True
    value=terminal(lane,source,frame)
    assert value['state']=='timeout',value
    assert server.stopped.is_set()
    meta=value['generation_budget']
    assert meta['cleanup']['state']=='pending'
    until=time.monotonic()+2
    while time.monotonic()<until:
        value=lane.poll(value['result_handle'],'fixture',frame.trace_id)
        if value['generation_budget']['cleanup']['state']=='unconfirmed': break
        time.sleep(.005)
    assert value['state']=='degraded' and lane._fenced
    assert value['generation_budget']['primary_outcome']=='deadline_exceeded'
    assert value['generation_budget']['outcome']=='stop_unconfirmed'
    server.release.set();time.sleep(.02)
    assert lane.poll(value['result_handle'],'fixture',frame.trace_id)==value
    assert lane.submit({'request_id':'new'},frame,'fixture')['state']=='degraded'


def test_context_fit_refuses_before_any_call(make):
    lane,server,source,frame=make();server.context=700
    value=terminal(lane,source,frame)
    assert not server.requests
    assert value['generation_budget']['outcome']=='budget_exhausted'
    assert value['generation_budget']['job_calls']==0


def test_stop_confirmed_before_global_deadline_preserves_timeout_and_prior_usage(make):
    lane,server,source,frame=make(deadline=1)
    original=server.infer
    def block_second(request,deadline_s,**kw):
        if server.requests: server.block=True
        return original(request,deadline_s,**kw)
    server.infer=block_second
    value=terminal(lane,source,frame)
    until=time.monotonic()+1
    while value['generation_budget']['cleanup']['state']=='pending' and time.monotonic()<until:
        value=lane.poll(value['result_handle'],'fixture',frame.trace_id)
        time.sleep(.002)
    assert value['state']=='timeout'
    assert value['generation_budget']['cleanup']['state']=='confirmed'
    assert value['generation_budget']['primary_outcome']=='deadline_exceeded'
    assert value['generation_budget']['job_calls']==2
    assert value['generation_budget']['tasks'][0]['actual_usage']=={'tokens_in':12,'tokens_out':7}
    assert not value['generation_budget']['tasks'][2]['dispatched']
    assert lane._stopped and not lane._fenced


def test_provider_failure_records_dispatched_call_even_without_usage(make):
    lane,server,source,frame=make()
    def unavailable(request,deadline_s,**kw):
        with kw['dispatch_guard']() as record_sent:
            server.requests.append((request,deadline_s));record_sent()
        kw['on_dispatch']()
        raise OSError('private fixture message')
    server.infer=unavailable
    value=terminal(lane,source,frame)
    assert value['generation_budget']['job_calls']==1
    assert value['generation_budget']['tasks'][0]['actual_usage'] is None
    assert value['generation_budget']['primary_outcome']=='provider_unavailable'
    assert 'private fixture message' not in json.dumps(value)


@pytest.mark.parametrize('raw',['{"a":1,"a":2}','{"a":NaN}','[]'])
def test_budget_malformed_json_stops_later_tasks_without_stopping_idle_provider(make,raw):
    lane,server,source,frame=make()
    original=server.infer
    def malformed(request,deadline_s,**kw):
        reply=original(request,deadline_s,**kw)
        return LocalInferenceResult(raw,reply.tokens_in,reply.tokens_out,{},'stop','preserved')
    server.infer=malformed
    value=terminal(lane,source,frame)
    assert len(server.requests)==1
    assert value['generation_budget']['outcome']=='output_invalid'
    assert not server.stopped.is_set()


def test_auth_revocation_preserves_first_sent_usage_and_blocks_followups(make):
    lane,server,source,frame=make()
    allowed=[True];lane._authorized=lambda generation:allowed[0]
    original=server.infer
    def revoke(*args,**kw):
        result=original(*args,**kw);allowed[0]=False;return result
    server.infer=revoke
    first=lane.submit(source,frame,'fixture',upstream_coverage='intact')
    until=time.monotonic()+1
    while lane._receipts[first['result_handle']]['status']['state']=='queued' and time.monotonic()<until: time.sleep(.002)
    value=lane._receipts[first['result_handle']]['status']
    assert value['state']=='closed'
    assert len(server.requests)==1
    assert value['generation_budget']['job_calls']==1
    assert value['generation_budget']['tasks'][0]['actual_usage']=={'tokens_in':12,'tokens_out':7}


def test_unknown_upstream_cannot_complete(make):
    lane,server,source,frame=make()
    # A pre-existing upstream loss can never become within_budget.
    first=lane.submit(source,frame,'fixture',upstream_coverage='unknown')
    until=time.monotonic()+1
    while time.monotonic()<until:
        value=lane.poll(first['result_handle'],'fixture',frame.trace_id)
        if value['state']!='queued':break
        time.sleep(.002)
    assert value['state']=='degraded' and value['generation_budget']['coverage']=='unknown'
    assert 'assistance' not in value


def test_expired_queue_does_not_reset_deadline_or_read_provider(make):
    lane,server,source,frame=make()
    lane._worker=NS(is_alive=lambda:True)
    first=lane.submit(source,frame,'fixture',upstream_coverage='intact')
    lane._pending['end']=time.monotonic()-1
    lane._pending['submitted']=lane._pending['end']-lane.deadline_s
    lane._run()
    value=lane.poll(first['result_handle'],'fixture',frame.trace_id)
    assert value['state']=='timeout'
    assert value['generation_budget']['job_calls']==0
    assert not server.requests and not server.counts


def test_stop_failure_fences_without_losing_primary_reason(make):
    lane,server,source,frame=make(deadline=1)
    server.block=True;server.stop_fail=True
    value=terminal(lane,source,frame)
    until=time.monotonic()+1
    while value['generation_budget']['cleanup']['state']=='pending' and time.monotonic()<until:
        value=lane.poll(value['result_handle'],'fixture',frame.trace_id)
        time.sleep(.002)
    assert value['state']=='degraded' and lane._fenced
    assert value['generation_budget']['cleanup']['reason']=='stop_failed'
    assert value['generation_budget']['primary_outcome']=='deadline_exceeded'


def test_selected_first_task_cannot_be_erased_by_later_full_selection(make):
    from azazel_nexus.incident_explain import slow_analysis_projection
    lane,server,source,frame=make()
    value=terminal(lane,{**source,'selected_first':True},frame)
    assert value['state']=='complete'
    assert value['generation_budget']['coverage']=='selected'
    assert all(t['selection']['coverage']=='selected' for t in value['generation_budget']['tasks'])
    shown=slow_analysis_projection(value)
    assert shown['budget']['coverage']=='selected' and shown['budget']['omitted_units']==1
    assert 'optional_detail' not in json.dumps(shown)


def test_fourth_task_request_is_not_three_task_success(make):
    lane,server,source,frame=make()
    value=terminal(lane,{**source,'fourth_task':True},frame)
    assert len(server.requests)==3
    assert value['state']=='degraded' and 'assistance' not in value
    assert value['generation_budget']['outcome']=='budget_exhausted'


def test_hung_token_counter_terminates_without_dispatch_and_stops_lane(make):
    lane,server,source,frame=make(deadline=1)
    def blocked_count(*a,**kw):
        server.entered.set();server.release.wait(5);return 12
    server.count_chat_tokens=blocked_count
    value=terminal(lane,source,frame)
    assert not server.requests
    assert value['generation_budget']['job_calls']==0
    assert value['generation_budget']['primary_outcome']=='deadline_exceeded'
    assert lane._stopped
    assert value['generation_budget']['cleanup']['state'] in ('pending','confirmed')


def test_actual_input_must_equal_exact_precount_and_cannot_be_hidden(make):
    lane,server,source,frame=make()
    original=server.infer
    def mismatched(*args,**kw):
        reply=original(*args,**kw)
        return LocalInferenceResult(reply.text,13,7,{},'stop','preserved')
    server.infer=mismatched
    value=terminal(lane,source,frame)
    assert value['generation_budget']['outcome']=='output_invalid'
    assert value['generation_budget']['tasks'][0]['actual_usage']['tokens_in']==13
    assert len(server.requests)==1


def test_budget_admission_refusal_records_three_unsent_tasks_without_handle(make):
    lane,server,source,frame=make();lane._authorized=lambda generation:False
    value=lane.submit(source,frame,'fixture',upstream_coverage='intact')
    assert value['state']=='closed' and 'result_handle' not in value
    assert value['generation_budget']['outcome']=='admission_closed'
    assert value['generation_budget']['job_calls']==0
    assert len(value['generation_budget']['tasks'])==3
    assert not server.requests
    assert read_slow_analysis(value)==value


def test_missing_effective_schema_is_count_unknown_without_unbudgeted_retry(make,monkeypatch):
    lane,server,source,frame=make()
    monkeypatch.delattr(sys.modules['azazel_mio.playbook'],'compiled_model_response_schema')
    value=terminal(lane,source,frame)
    assert not server.requests
    assert value['generation_budget']['job_calls']==0
    assert value['generation_budget']['outcome']=='token_count_unknown'


def test_tokenizer_timeout_keeps_count_unknown_but_stops_owned_provider(make):
    lane,server,source,frame=make()
    def timed_out(*a,**kw):raise TimeoutError('fixture tokenization timeout')
    server.count_chat_tokens=timed_out
    value=terminal(lane,source,frame)
    assert value['generation_budget']['primary_outcome']=='token_count_unknown'
    assert not server.requests and value['generation_budget']['job_calls']==0
    assert server.stopped.is_set() and lane._stopped
    assert value['generation_budget']['cleanup']['state'] in ('pending','confirmed')


def test_later_supersession_does_not_erase_primary_truncation(make):
    lane,server,source,frame=make();server.integrity='truncated'
    value=terminal(lane,{**source,'supersede_after_failure':True},frame)
    assert value['state']=='superseded'
    assert value['generation_budget']['primary_outcome']=='runtime_truncated'
    assert value['generation_budget']['outcome']=='superseded'
    assert value['generation_budget']['reasons'][:2]==['truncated','superseded']
    assert value['generation_budget']['tasks'][0]['actual_usage']=={'tokens_in':12,'tokens_out':7}


@pytest.mark.parametrize('moment',['initial','after_first'])
def test_missing_or_changed_tuple_refuses_new_dispatch_and_retains_sent_usage(make,moment):
    lane,server,source,frame=make()
    if moment=='initial':
        server.verified_tuple=lambda *_:None
    else:
        original=server.infer
        def change(*a,**kw):
            result=original(*a,**kw);server.context=8192;return result
        server.infer=change
    value=terminal(lane,source,frame);meta=value['generation_budget']
    assert value['state']=='degraded' and meta['primary_outcome']=='token_count_unknown'
    assert meta['job_calls']==(0 if moment=='initial' else 1)
    assert len(server.requests)==meta['job_calls']
    if moment=='after_first':assert meta['tasks'][0]['actual_usage']==dict(tokens_in=12,tokens_out=7)


def test_primary_reason_and_bounded_followup_sequence_are_independent():
    from azazel_nexus_runtime.mio_budget_session import BudgetSession
    session=object.__new__(BudgetSession)
    session.lock=threading.RLock();session.reason=None;session.outcome=None;session.failures=[]
    session.note_failure('truncated','runtime_truncated')
    for reason in ['cancelled','admission_closed','timeout']*20:session.note_failure(reason,reason)
    assert session.reason=='truncated' and session.outcome=='runtime_truncated'
    assert session.failures==['truncated','cancelled','admission_closed','timeout']


@pytest.mark.parametrize(('verified','configured'),[(8192,2048),(2048,8192)])
def test_lane_plans_with_minimum_context_and_preserves_three_task_results(make,verified,configured):
    from dataclasses import replace
    lane,server,source,frame=make();server.context=verified
    lane.capability=replace(lane.capability,model_context_limit=configured)
    value=terminal(lane,source,frame);meta=value['generation_budget']
    assert value['state']=='complete' and meta['job_calls']==3
    assert meta['verified_tuple']['context_limit']==verified
    assert meta['profile']['configured_context_limit']==configured
    assert all(t['context_limit']==2048 and t['actual_usage']==dict(tokens_in=12,tokens_out=7)
        and t['finish_reason']=='stop' and t['context_integrity']=='preserved' for t in meta['tasks'])


@pytest.mark.parametrize('limit',[None,True,0,-1,2048.0,2**32])
def test_unknown_capability_context_is_unsent_count_unknown(make,limit):
    from dataclasses import replace
    lane,server,source,frame=make();lane.capability=replace(lane.capability,model_context_limit=limit)
    value=terminal(lane,source,frame)
    assert value['generation_budget']['primary_outcome']=='token_count_unknown'
    assert value['generation_budget']['job_calls']==0 and not server.requests and not server.counts


def test_model_bound_prevents_dispatch_even_when_server_context_is_larger(make):
    from dataclasses import replace
    lane,server,source,frame=make();server.context=8192
    lane.capability=replace(lane.capability,model_context_limit=2048)
    server.count_chat_tokens=lambda *_:1522
    value=terminal(lane,source,frame);meta=value['generation_budget']
    assert meta['primary_outcome']=='budget_exhausted' and meta['job_calls']==0 and not server.requests
    assert meta['tasks'][0]['context_limit']==2048 and meta['tasks'][0]['input_limit']==1248


def test_cancel_after_positive_send_preserves_sent_count_and_usage(make):
    lane,server,source,frame=make()
    def infer(request,deadline_s,**kw):
        kw['before_dispatch']()
        with kw['dispatch_guard']() as record_sent:
            server.requests.append((request,deadline_s));record_sent()  # controlled positive transport send
        lane._active['reason']='cancelled';lane._active['cancelled'].set()
        kw['on_dispatch']()  # cancellation cannot erase a positive send
        return LocalInferenceResult('{}',12,7,{},'stop','preserved')
    server.infer=infer
    value=terminal(lane,source,frame);meta=value['generation_budget']
    assert value['state']=='cancelled' and meta['job_calls']==1
    assert meta['tasks'][0]['actual_usage']==dict(tokens_in=12,tokens_out=7)


def test_second_call_postsend_failure_retains_first_call_usage(make):
    lane,server,source,frame=make();original=server.infer
    def infer(request,deadline_s,**kw):
        if server.requests:
            with kw['dispatch_guard']() as record_sent:
                server.requests.append((request,deadline_s));record_sent()
            kw['on_dispatch']()
            raise TimeoutError('fixture after positive send')
        return original(request,deadline_s,**kw)
    server.infer=infer
    value=terminal(lane,source,frame);meta=value['generation_budget']
    assert meta['job_calls']==2 and len(server.requests)==2
    assert meta['tasks'][0]['actual_usage']==dict(tokens_in=12,tokens_out=7)
    assert meta['tasks'][1]['dispatched'] and meta['tasks'][1]['actual_usage'] is None
    assert meta['primary_outcome']=='deadline_exceeded'


@pytest.mark.parametrize(('order','target'),[('sent_first',1),('sent_first',2),('freeze_first',1),('fence_first',1)])
def test_nonblocking_send_accounting_is_ordered_with_real_controller_freeze(make,monkeypatch,order,target):
    """No network: actual native HTTP method + nonblocking Peer and controller."""
    from pathlib import Path
    from types import MethodType
    from azazel_nexus_runtime import mio_serve, mio_budget_session
    entered=threading.Event();release=threading.Event();notified=[];peers=[]
    base=mio_budget_session.BudgetSession
    class Session(base):
        def invoke_budgeted(self,task,prompt,on_dispatch):
            ordinal=TASKS.index(task)+1
            def notify():
                if order=='sent_first' and ordinal==target:
                    entered.set();assert release.wait(2)
                on_dispatch();notified.append(ordinal)
            return super().invoke_budgeted(task,prompt,notify)
    monkeypatch.setattr(mio_budget_session,'BudgetSession',Session)
    lane,server,source,frame=make(deadline=1.5)
    server.socket_path=Path('/fixture/native.sock');server._check_admission=lambda:None
    server._verified_tuple=lambda end:server.verified_tuple(1)
    server._http=MethodType(mio_serve.LocalServer._http,server)
    server.infer_native=MethodType(mio_serve.LocalServer.infer_native,server)
    raw=json.dumps(dict(content='{}',truncated=False,stop=True,stop_type='eos',tokens_evaluated=12,tokens_predicted=7)).encode()
    response=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(raw)).encode()+b'\r\n\r\n'+raw
    class Peer:
        def __init__(self):self.index=len(peers)+1;peers.append(self);self.sent=0;self.read=0;self.attempts=0
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def connect(self,path):assert path=='/fixture/native.sock'
        def settimeout(self,value):self.timeout=value
        def send(self,data):
            assert self.timeout==0  # never block the freeze/accounting gate
            self.attempts+=1
            if order in ('freeze_first','fence_first') and self.index==target and self.attempts==1:raise BlockingIOError()
            count=min(7,len(data)) if self.index==target else len(data)
            self.sent+=count;return count
        def recv(self,size):data=response[self.read:self.read+size];self.read+=len(data);return data
    def writable(_r,w,_x,timeout):
        entered.set()
        if order=='fence_first':
            with lane._lock:lane._fenced=True
        else:assert release.wait(2)
        return [],w,[]
    monkeypatch.setattr(mio_serve.socket,'socket',lambda *a:Peer())
    monkeypatch.setattr(mio_serve.select,'select',writable)
    try:
        value=terminal(lane,source,frame)
        assert entered.is_set() and not release.is_set()  # control did not wait for notify/write readiness
        meta=value['generation_budget'];expected=target if order=='sent_first' else 0
        assert value['state'] in (('cancelled',) if order=='fence_first' else ('timeout','degraded'))
        assert meta['job_calls']==expected
        assert sum(p.sent for p in peers)>0 if expected else sum(p.sent for p in peers)==0
        if target==2:assert meta['tasks'][0]['actual_usage']==dict(tokens_in=12,tokens_out=7)
        assert not meta['core_complete']
        release.set()
        until=time.monotonic()+1
        while order=='sent_first' and target not in notified and time.monotonic()<until:time.sleep(.002)
        assert notified==list(range(1,expected+1))
        saved=lane.poll(value['result_handle'],'fixture',frame.trace_id)
        assert saved['generation_budget']['job_calls']==expected and saved['state']!='complete'
        if target==2:assert saved['generation_budget']['tasks'][0]['actual_usage']==dict(tokens_in=12,tokens_out=7)
    finally:release.set()


@pytest.mark.parametrize(('fault','cleanup'),[('version','not_needed'),('profile','pending'),('oversized','unconfirmed'),('version_complete','not_needed'),('version_closed','not_needed')])
def test_malformed_metadata_repair_round_trips_known_usage_through_client_and_store(make,monkeypatch,tmp_path,fault,cleanup):
    from azazel_nexus_runtime import mio_generation, mio_socket_client, incident_explaind
    lane,server,source,_=make();server.integrity='preserved' if fault=='version_complete' else 'truncated'
    count=3 if fault=='version_complete' else 1
    trace='mio-0123456789abcdef-1';frame=NS(frame_id=trace+':frame',trace_id=trace)
    original=lane._execute
    def corrupted(job):
        value=original(job);session=job['budget_session']
        if fault=='version_closed':
            session.note_failure('admission_closed','admission_closed')
            value=session.snapshot('closed','admission_closed')
        assert mio_generation.read_slow_analysis(value)['usage']=='known'
        if cleanup=='pending':session.cleanup=dict(state='pending',reason=None,remaining_ms=100)
        elif cleanup=='unconfirmed':session.cleanup=dict(state='unconfirmed',reason='observation_lost',remaining_ms=0)
        if fault.startswith('version'):value['generation_budget']['version']=99
        elif fault=='profile':
            value['generation_budget']['profile']['configured_context_limit']=None
            session.verified_tuple=None  # immutable accounting basis still holds the verified source
        else:value['generation_budget']['reasons']=['x'*150000]
        assert mio_generation.read_slow_analysis(value)==dict(state='closed',usage='unknown')
        session.frozen=copy.deepcopy(value)
        return value
    lane._execute=corrupted
    value=terminal(lane,source,frame)
    checked=mio_generation.read_slow_analysis(value)
    assert checked['state']=='degraded' and checked['usage']=='known'
    meta=checked['generation_budget']
    assert meta['version']==1 and meta['job_calls']==count and meta['verified_tuple'] is not None
    assert meta['primary_outcome']==('output_invalid' if count==3 else 'runtime_truncated') and 'malformed' in meta['reasons']
    assert meta['tasks'][0]['actual_usage']==dict(tokens_in=12,tokens_out=7)
    assert meta['cleanup']['state']==cleanup and not meta['core_complete'] and 'assistance' not in checked
    monkeypatch.setattr(mio_socket_client,'_exchange',lambda *_a,**_k:json.loads(json.dumps(dict(outcome='generation_result',slow_analysis=checked))))
    delivered=mio_socket_client.LocalSocketClient().generation_result(checked)
    assert delivered==checked and delivered['calls'][0]['usage']==dict(tokens_in=12,tokens_out=7)
    e=incident_explaind.Explainer(incidents=tmp_path/'incidents',state=tmp_path/'state',status_path=tmp_path/'status',clock=lambda:0.,monotonic=lambda:0.)
    e.generation_store=incident_explaind.GenerationResultStore(tmp_path);e.generation_store.prepare(0)
    receipt=dict(event_type='mio.generation.receipt',incident_id='inc-0123456789abcdef',incident_sequence=1,
        request_id='inc-0123456789abcdef:1',frame_id=frame.frame_id,trace_id=trace,generation_id='fixture',result_handle=value['result_handle'],recorded_at=0)
    assert e._append_generation_event(receipt)
    e._generation_receipts[receipt['result_handle']]=receipt;e._generation_current[receipt['incident_id']]=receipt['result_handle']
    assert e._record_generation_terminal(receipt,delivered,sent_at=0.)
    e._restore_generation_results()
    restored=e._generation_value(receipt['result_handle'])
    assert restored['usage']=='known' and restored['generation_budget']['job_calls']==count
    read_budget(restored['generation_budget'],state=restored['state'],usage=restored['usage'])
    stored=next(row for row in e.generation_store.events() if row['event_type']=='mio.generation.result')
    assert stored['generation_budget']['tasks'][0]['actual_usage']==dict(tokens_in=12,tokens_out=7)
    assert restored['generation_budget']['tasks'][0]['actual_usage']==dict(tokens_in=12,tokens_out=7)
    assert restored['generation_budget']['primary_outcome']==meta['primary_outcome']
    assert all(t['actual_usage']==dict(tokens_in=12,tokens_out=7) for t in restored['generation_budget']['tasks'][:count])
    if cleanup=='pending':assert restored['generation_budget']['cleanup']['reason']=='restart_unconfirmed'
    else:assert restored['generation_budget']['cleanup']['state']==cleanup
    assert restored['state']=='degraded' and 'assistance' not in restored


@pytest.mark.parametrize('unknown',['model_bound','server_tuple'])
def test_zero_send_metadata_repair_keeps_unknowns_closed_without_inventing_context(make,unknown):
    from dataclasses import replace
    from azazel_nexus_runtime.mio_generation import read_slow_analysis
    lane,server,source,frame=make()
    if unknown=='model_bound':lane.capability=replace(lane.capability,model_context_limit=None)
    else:server.verified_tuple=lambda *_:None
    original=lane._execute
    def corrupt(job):
        value=original(job);assert read_slow_analysis(value)['state']=='degraded'
        value['generation_budget']['version']=99;job['budget_session'].frozen=copy.deepcopy(value)
        return value
    lane._execute=corrupt
    value=read_slow_analysis(terminal(lane,source,frame))
    assert value['state']=='degraded' and value['usage']=='unknown'
    assert value['generation_budget']['job_calls']==0 and not server.requests
    assert value['generation_budget']['primary_outcome']=='token_count_unknown'
    assert all(t['context_limit'] is None for t in value['generation_budget']['tasks'])
