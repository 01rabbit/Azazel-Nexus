"""Run explicitly with the pinned #48 wheel; provider is controlled, not a model."""
import copy
from contextlib import nullcontext
from dataclasses import asdict
from datetime import UTC, datetime
import json
import threading
import time
from types import SimpleNamespace as NS

import pytest
from azazel_mio import MioSituationFrame
from azazel_mio import budget as api
from azazel_nexus.generation_budget import TASKS, MIO_REASON_OUTCOMES
from azazel_nexus.incident_explain import slow_analysis_projection
from azazel_nexus_runtime import mio_budget_session as session_module
from azazel_nexus_runtime.mio_budget_session import BudgetSession
from azazel_nexus_runtime.mio_generation import GenerationCapability, GenerationLane
from azazel_nexus_runtime.mio_serve import LocalInferenceResult


class FixtureLane(GenerationLane):
    def _authorized(self,generation):return generation=='api-fixture'


class ControlledServer:
    def __init__(self):self.requests=[];self.stopped=False;self.dispatch_callbacks=[]
    def context_limit(self,deadline_s):return 4096
    def count_chat_tokens(self,request,deadline_s):return 12
    def verified_tuple(self,deadline_s):
        from azazel_nexus.generation_budget import verified_tuple_from_props
        return verified_tuple_from_props(dict(model_alias='fixture',model_path='/fixture/model.gguf',
            model_ftype='fixture',chat_template='fixture',bos_token='BOS',eos_token='EOS',build_info='fixture',
            default_generation_settings={'n_ctx':self.context_limit(deadline_s)}))
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
    def infer(self,request,deadline_s,**kw):
        if kw.get('before_dispatch') is not None:kw['before_dispatch']()
        task=request.response_format['json_schema']['name']
        with kw['dispatch_guard']() if kw.get('dispatch_guard') else nullcontext() as record_sent:
            self.requests.append(task)
            if record_sent:record_sent()
        if kw.get('on_dispatch') is not None:
            self.dispatch_callbacks.append(kw['on_dispatch']);kw['on_dispatch']()
        if task==TASKS[0]:
            def h(i,slot):
                return dict(hypothesis_id='h'+str(i),hypothesis_alternative_id=slot,
                    statement='possible',status='proposed',supporting_evidence_refs=['ev:ssh:1'],
                    contradicting_evidence_refs=[],assumptions=[],falsification_conditions=['different observation'],
                    expected_observations=[],missing_evidence=[])
            value={'hypotheses':[h(1,'hostile_activity'),h(2,'benign_activity')]}
        elif task==TASKS[1]:value={'evidence_gaps':[]}
        else:value=dict(summary='uncertain',recommended_action='OBSERVE',rationale='review',
            evidence_refs=['ev:ssh:1'],limitations=['unverified'])
        return LocalInferenceResult(json.dumps(value),12,7,{},'stop','preserved')
    def stop(self):self.stopped=True


def inputs():
    trace='mio-0123456789abcdef-1'
    frame=MioSituationFrame.build(frame_id=trace+':frame',trace_id=trace,
        created_at=datetime.now(UTC).isoformat().replace('+00:00','Z'),mission='Review activity',
        current_defensive_state='OBSERVE',threat_level='UNKNOWN',known_facts=('event',),
        unknowns=('unknown',),contradictions=('counterexample',),evidence_refs=('ev:ssh:1',))
    cap=GenerationCapability('api-fixture','fixture-model','2099-01-01T00:00:00Z',1,lambda:True,model_context_limit=4096)
    return frame,cap


def run(server=None):
    frame,cap=inputs();server=server or ControlledServer()
    lane=FixtureLane(capability=cap,server=server,deadline_s=5,budget_enabled=True)
    first=lane.submit({'request_id':'api-fixture'},frame,'api-fixture',upstream_coverage='intact')
    until=time.monotonic()+2
    while time.monotonic()<until:
        value=lane.poll(first['result_handle'],'api-fixture',frame.trace_id)
        if value['state']!='queued':return lane,server,value
        time.sleep(.002)
    pytest.fail('real MIO fixture did not terminate')


def test_real_assistant_core_receipt_and_actual_dispatch_are_aligned():
    lane,server,value=run()
    assert value['state']=='complete',value
    assert server.requests==list(TASKS)
    assert value['generation_budget']['job_calls']==3
    assert value['generation_budget']['core_complete']
    assert value['generation_budget']['coordinator_disposition'] is None
    assert all(t['validated'] for t in value['generation_budget']['tasks'])


def test_later_task_selection_is_accounted_in_product_receipt():
    _, _, value = run()
    tasks = value['generation_budget']['tasks']
    assert tasks[0]['selection']['coverage'] == 'intact'
    for task in tasks[1:]:
        selection = task['selection']
        assert selection['coverage'] == 'selected'
        assert selection['omitted_units'] > 0
        assert selection['selected_units'] + selection['omitted_units'] == selection['input_units']
        assert len(selection['omissions']) == selection['omitted_units']


def test_rejected_revision_supersedes_active_with_real_core():
    from dataclasses import replace
    class BlockingServer(ControlledServer):
        def __init__(self):
            super().__init__()
            self.entered = threading.Event()
            self.release = threading.Event()
        def infer(self, request, deadline_s, **kw):
            result = super().infer(request, deadline_s, **kw)
            self.entered.set()
            assert self.release.wait(2)
            return result
        def stop(self):
            from azazel_nexus_runtime.mio_supervisor import StopResult, StopState
            self.release.set()
            return StopResult(StopState.CONFIRMED, 'fixture_stop_confirmed')
    frame, cap = inputs()
    server = BlockingServer()
    lane = FixtureLane(capability=cap, server=server, deadline_s=5, budget_enabled=True)
    first = lane.submit({'request_id': 'same', 'revision': 1}, frame, cap.generation_id, upstream_coverage='intact')
    try:
        assert server.entered.wait(2)
        other = lane.submit({'request_id': 'other'}, frame, cap.generation_id, upstream_coverage='intact')
        bad = replace(frame, truncated=True)
        new = lane.submit({'request_id': 'same', 'revision': 2}, bad, cap.generation_id, upstream_coverage='unknown')
        assert new['generation_budget']['primary_outcome'] == 'budget_exhausted'
        assert new['generation_budget']['job_calls'] == 0
        assert lane._active['cancelled'].is_set()
        assert lane._pending['handle'] == other['result_handle'] and not lane._pending['cancelled'].is_set()
    finally:
        server.release.set()
    until = time.monotonic() + 2
    while time.monotonic() < until:
        old = lane.poll(first['result_handle'], cap.generation_id, frame.trace_id)
        if old['state'] != 'queued':
            break
        time.sleep(.002)
    assert old['state'] == 'superseded'
    meta = old['generation_budget']
    assert meta['primary_outcome'] == 'cancelled' and 'superseded' in meta['reasons']
    assert meta['job_calls'] == 1
    assert meta['tasks'][0]['actual_usage'] == {'tokens_in': 12, 'tokens_out': 7}


@pytest.mark.parametrize('address', ['１０.０.０.１', '２００１：ｄｂ８：：１', '::ffff:192.0.2.1'])
def test_normalized_address_report_has_zero_dispatches(address):
    from azazel_nexus.local_advisory import read_frame
    from azazel_nexus_runtime.mio_fast_assistance import _frame
    source = read_frame({'request_id': 'privacy-fixture', 'privacy_class': 'P3-restricted',
                         'question': 'Review synthetic report', 'context': [
                             {'kind': 'operator_report', 'text': 'unverified ' + address}]})
    frame, selection = _frame(source, with_selection=True)
    _, cap = inputs()
    server = ControlledServer()
    lane = FixtureLane(capability=cap, server=server, deadline_s=5, budget_enabled=True)
    result = lane.submit(source, frame, cap.generation_id, upstream_coverage=selection['coverage'],
                         upstream_selection=selection)
    assert frame.truncated and result['generation_budget']['primary_outcome'] == 'budget_exhausted'
    assert result['generation_budget']['job_calls'] == 0 and server.requests == []


@pytest.mark.parametrize(('fault','reason'),[('missing','dispatch_tracking_unavailable'),('duplicate','send_notification_conflict')])
def test_notification_contract_violations_fail_closed_preserving_actual_usage(monkeypatch,fault,reason):
    captured=[]
    class FaultSession(BudgetSession):
        def invoke_budgeted(self,task,prompt,on_dispatch):
            def notify():
                if fault=='missing':return
                on_dispatch()
                try:on_dispatch()
                except RuntimeError:pass
            return super().invoke_budgeted(task,prompt,notify)
        def finish(self,assistance):
            captured.append(assistance.generation_receipt)
            return super().finish(assistance)
    monkeypatch.setattr(session_module,'BudgetSession',FaultSession)
    lane,server,value=run()
    assert value['state']=='degraded',value
    assert server.requests==[TASKS[0]]
    assert value['generation_budget']['job_calls']==1
    assert value['generation_budget']['tasks'][0]['actual_usage']=={'tokens_in':12,'tokens_out':7}
    assert reason in value['generation_budget']['reasons']
    assert reason in slow_analysis_projection(value)['budget']['reasons']
    assert captured[0].reason==reason
    assert captured[0].calls_sent[TASKS[0]]==(0 if fault=='missing' else 1)


def test_late_notification_is_rejected_without_mutating_finished_receipts(monkeypatch):
    callbacks=[];receipts=[]
    class CaptureSession(BudgetSession):
        def invoke_budgeted(self,task,prompt,on_dispatch):
            callbacks.append(on_dispatch)
            return super().invoke_budgeted(task,prompt,on_dispatch)
        def finish(self,assistance):
            receipts.append(assistance.generation_receipt)
            return super().finish(assistance)
    monkeypatch.setattr(session_module,'BudgetSession',CaptureSession)
    lane,server,value=run()
    assert value['state']=='complete',value
    before=asdict(receipts[0]);saved=copy.deepcopy(value)
    for callback in callbacks+server.dispatch_callbacks:
        with pytest.raises(RuntimeError):callback()
    assert server.requests==list(TASKS)
    assert asdict(receipts[0])==before
    assert lane.poll(value['result_handle'],'api-fixture',value['trace_id'])==saved


def test_predispatch_gate_refusal_does_not_notify_or_send(monkeypatch):
    notified=[];receipts=[]
    class CancelSession(BudgetSession):
        def invoke_budgeted(self,task,prompt,on_dispatch):
            self.job['cancelled'].set()
            def notify():notified.append(task);on_dispatch()
            return super().invoke_budgeted(task,prompt,notify)
        def finish(self,assistance):receipts.append(assistance.generation_receipt);return super().finish(assistance)
    monkeypatch.setattr(session_module,'BudgetSession',CancelSession)
    lane,server,value=run()
    assert value['state']=='cancelled',value
    assert not notified and not server.requests
    assert value['generation_budget']['job_calls']==0
    if receipts:assert sum(receipts[0].calls_sent.values())==0


@pytest.mark.parametrize('reason',sorted(MIO_REASON_OUTCOMES))
def test_closed_mio_reason_is_retained_in_private_and_public_receipt(reason):
    frame,cap=inputs();lane=FixtureLane(capability=cap,server=ControlledServer(),budget_enabled=True)
    start=time.monotonic()
    job=dict(submitted=start,end=start+5,frame=frame,generation='api-fixture',handle='a'*64,
        upstream_coverage='unknown',source={'request_id':'fixture'},cancelled=threading.Event())
    session=BudgetSession(lane,job,api)
    receipt=api.GenerationOutcome('failed',dict.fromkeys(TASKS,'not_started'),dict.fromkeys(TASKS,0),
        dict.fromkeys(TASKS,None),reason,{},coordinator_disposition='cancelled')
    session.finish(NS(generation_receipt=receipt,to_dict=lambda:dict(state='error_fallback',generation_method='static_reference')))
    state={'cancelled':'cancelled','superseded':'superseded','stale':'stale'}.get(session.outcome,'degraded')
    value=session.snapshot(state,session.outcome)
    assert value['generation_budget']['primary_outcome']==MIO_REASON_OUTCOMES[reason]
    assert value['generation_budget']['reasons']==[reason]
    shown=slow_analysis_projection(value)
    assert shown['budget']['reasons']==[reason]
    assert shown['budget']['coordinator_disposition']=='cancelled'


def test_provider_presend_refusal_is_zero_in_both_adapter_and_mio(monkeypatch):
    receipts=[]
    class CaptureSession(BudgetSession):
        def finish(self,assistance):receipts.append(assistance.generation_receipt);return super().finish(assistance)
    monkeypatch.setattr(session_module,'BudgetSession',CaptureSession)
    server=ControlledServer()
    def refuse(*args,**kwargs):raise OSError('fixture pre-send refusal')
    server.infer=refuse
    lane,server,value=run(server)
    assert value['generation_budget']['job_calls']==0
    assert not server.requests
    assert receipts and sum(receipts[0].calls_sent.values())==0
    assert value['generation_budget']['primary_outcome']=='provider_unavailable'


def test_compile_budget_rejection_keeps_observed_exact_count_in_unsent_receipt():
    server=ControlledServer()
    server.context_limit=lambda deadline_s:2048
    server.count_chat_tokens=lambda request,deadline_s:1522
    lane,server,value=run(server)
    assert not server.requests and value['generation_budget']['job_calls']==0
    task=value['generation_budget']['tasks'][0]
    assert task['count_kind']=='exact' and task['input_tokens_bound']==1522
    assert task['context_limit']==2048 and task['output_tokens_cap']==768 and task['context_slack']==32
    assert value['generation_budget']['primary_outcome']=='budget_exhausted'


@pytest.mark.parametrize('chunk',[7,1000000])
def test_real_api_http_positive_send_boundary_preserves_normal_results(monkeypatch,chunk):
    """Actual product HTTP/native methods, in-memory socket, no model/process/network."""
    from pathlib import Path
    from azazel_nexus_runtime import mio_serve
    class WireServer(ControlledServer):
        _http=mio_serve.LocalServer._http
        def __init__(self):
            super().__init__();self.socket_path=Path('/fixture/native.sock');self.payloads=[];self.positive_sends=0
        def _check_admission(self):pass  # explicit controlled fixture, not production authorization
        def _verified_tuple(self,end):return self.verified_tuple(end)
        def infer_native(self,request,deadline_s,**kw):
            self.current_request=request
            return mio_serve.LocalServer.infer_native(self,request,deadline_s,**kw)
    server=WireServer()
    class Peer:
        def __init__(self):self.sent=b'';self.response=b'';self.read=0
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def settimeout(self,value):assert value>=0
        def connect(self,path):assert path=='/fixture/native.sock'
        def send(self,data):
            part=bytes(data[:chunk]);self.sent+=part;server.positive_sends+=1
            if b'\r\n\r\n' in self.sent:
                head,body=self.sent.split(b'\r\n\r\n',1)
                size=int(next(line.split(b':')[1] for line in head.split(b'\r\n') if line.startswith(b'Content-Length:')))
                if len(body)==size:
                    server.payloads.append(json.loads(body))
                    result=ControlledServer.infer(server,server.current_request,1)
                    raw=json.dumps(dict(content=result.text,stop=True,stop_type='eos',truncated=False,
                        tokens_evaluated=12,tokens_predicted=7,timings={'prompt_n':12,'predicted_n':7})).encode()
                    self.response=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(raw)).encode()+b'\r\n\r\n'+raw
            return len(part)
        def recv(self,size):
            data=self.response[self.read:self.read+size];self.read+=len(data);return data
    monkeypatch.setattr(mio_serve.socket,'socket',lambda *a:Peer())
    lane,server,value=run(server);meta=value['generation_budget']
    assert value['state']=='complete' and meta['job_calls']==3 and meta['coverage']=='selected'
    assert sum(t['selection']['omitted_units'] for t in meta['tasks']) > 0
    assert len(server.payloads)==3 and server.requests==list(TASKS)
    assert all(p['prompt']==list(range(12)) for p in server.payloads)
    assert [p['n_predict'] for p in server.payloads]==[768,384,512]
    assert all(t['actual_usage']==dict(tokens_in=12,tokens_out=7) and t['context_integrity']=='preserved'
        and t['finish_reason']=='stop' and t['validated'] for t in meta['tasks'])
    assert server.positive_sends>=3


def test_current_harness_declares_explicit_fixture_context_without_production_admission():
    import importlib.util
    from pathlib import Path
    from azazel_nexus_runtime.mio_generation import authorized
    spec=importlib.util.spec_from_file_location('budget_fixture_harness',Path(__file__).parents[1]/'e2e_local_inference/harness.py')
    harness=importlib.util.module_from_spec(spec);spec.loader.exec_module(harness)
    lane,cap=harness.fixture_generation_lane(None)
    assert cap.model_context_limit==2048 and not lane.budget_enabled
    assert authorized(cap,harness.GENERATION_ID) is False
