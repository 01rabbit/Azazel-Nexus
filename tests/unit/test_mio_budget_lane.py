"""Budget path with a mocked agreed MIO API and controlled local transport."""
import copy
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
        if kw.get('on_dispatch') is not None:kw['on_dispatch']()
        self.requests.append((request, deadline_s))
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
        lane=Lane(capability=GenerationCapability('fixture','fixture','2099-01-01T00:00:00Z',1,lambda:True),
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
        kw['on_dispatch']()
        server.requests.append((request,deadline_s))
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
