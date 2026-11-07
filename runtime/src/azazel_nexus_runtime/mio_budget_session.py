"""Product-owned budget execution; MIO owns semantic compilation and grounding."""
from __future__ import annotations
import copy
from contextlib import contextmanager
import json
import math
import threading
import time
from azazel_nexus.generation_budget import (TASKS, CAPS, coverage, task_placeholder,
    selection_unknown, project_budget, integer, validate_selection, validate_model_assistance,
    MIO_REASON_OUTCOMES, COORDINATOR_DISPOSITIONS, validate_verified_tuple, effective_context_limit, context_integer, validate_profile, read_budget, REASONS, OUTCOMES)
from .mio_generation_budget import (BudgetPlanner, BudgetProfile, TaskBudget,
    BudgetRefused, BudgetReason, mio_budget_for_task)
from .mio_serve import LocalInferenceRequest, NativePrompt, TokenCountUnknown


class BudgetSession:
    def __init__(self, lane, job, api):
        self.lane, self.job, self.api = lane, job, api
        self.last_model = getattr(lane.capability,'model_id','unavailable')
        self.lock = threading.RLock()
        self.tasks = [task_placeholder(task) for task in TASKS]
        self.planner = None
        self.reason = None
        self.failures = []
        self.verified_tuple = None
        self._accounting_basis = None
        self.prepared = {}
        settings = lane.budget_settings
        configured=getattr(lane.capability,'model_context_limit',None)
        configured=configured if context_integer(configured) else None
        self.profile_metadata = dict(version=1,origin='fixture',reserve_fraction=settings.reserve_fraction,
            minimum_reserve_ms=settings.minimum_reserve_ms,weights=list(settings.weights),slack=settings.slack,
            output_caps=list(lane.output_caps),output_mins=list(lane.output_caps),
            minimum_provider_ms=list(settings.minimum_provider_ms),template_version=None,
            configured_context_limit=configured)
        self.mio_reason = None
        self.coordinator_disposition = None
        self.outcome = None
        self.core_complete = False
        self.started = job['submitted']
        self.in_flight = False
        self.needs_stop = False
        self.call_end = job['end']
        self.current_started = None
        self.cleanup = dict(state='not_needed', reason=None, remaining_ms=0)
        self.frozen = None
        self.done = threading.Event()
        self.assistance = None
        self.calls = []
        # Private material follows the lifetime of the local receipt, not the
        # wire-visible budget schema.
        self.frame_unknowns = {}

    def note_failure(self, reason, outcome):
        with self.lock:
            if reason not in self.failures and len(self.failures)<14:self.failures.append(reason)
            if self.reason is None:self.reason,self.outcome=reason,outcome

    def reject(self, reason, outcome):
        from azazel_mio.model_adapter import MioModelUnavailable
        self.note_failure(reason,outcome)
        raise MioModelUnavailable(reason)

    def remaining(self):
        return self.job['end'] - time.monotonic()

    def read_remaining(self):
        return self.remaining()-self.lane.budget_settings.reserve(self.lane.deadline_s)/2

    def _provider_read(self, operation):
        with self.lock:
            if self.frozen is not None or self.lane._stopped or self.lane._fenced or self.read_remaining()<=0:
                raise ValueError('generation_closed')
            self.in_flight = True
            self.call_end = self.job['end']-self.lane.budget_settings.reserve(self.lane.deadline_s)/2
        try:
            return operation()
        except TimeoutError:
            self.needs_stop = True
            raise
        finally:
            with self.lock:
                self.in_flight = False

    def initialize(self):
        try:
            verified=self._provider_read(lambda:self.lane.server.verified_tuple(self.read_remaining()))
            validate_verified_tuple(verified)
            self.verified_tuple=copy.deepcopy(verified)
            context=effective_context_limit(verified['context_limit'],self.profile_metadata['configured_context_limit'])
            settings=self.lane.budget_settings
            specs=tuple(TaskBudget(t,max(1,context-cap-settings.slack),cap,cap,minimum/1000)
                for t,cap,minimum in zip(TASKS,self.lane.output_caps,settings.minimum_provider_ms))
            profile=BudgetProfile('fixture-v1',context,specs,slack=settings.slack)
            for record,spec in zip(self.tasks,specs):
                record.update(input_limit=spec.input_limit if spec.input_limit+spec.output_cap+profile.slack<=context else None,
                    output_tokens_cap=spec.output_cap,output_min=spec.output_min,context_limit=context,context_slack=profile.slack)
            def counter(task, prompt):
                if not self.lane._authorized(self.job['generation']) or self.job['cancelled'].is_set():
                    return None
                request = self.request(task, prompt)
                prepared=self._provider_read(lambda:self.lane.server.prepare_native(request,self.read_remaining(),expected_tuple=self.verified_tuple))
                if type(prepared) is not NativePrompt or prepared.tuple_id!=self.verified_tuple['tuple_id']:
                    raise TokenCountUnknown('native_tuple_unknown')
                count=len(prepared.tokens)
                self.prepared[task]=(prompt,prepared)
                if integer(count):
                    with self.lock:
                        if self.frozen is None:
                            self.tasks[TASKS.index(task)].update(count_kind='exact',input_tokens_bound=count)
                return count
            self.planner = BudgetPlanner(profile, submitted=self.started,
                deadline_s=self.lane.deadline_s, counter=counter, clock=time.monotonic,settings=settings,verified_context_limit=verified['context_limit'],
                configured_context_limit=self.profile_metadata['configured_context_limit'])
            self._accounting_basis=(copy.deepcopy(self.verified_tuple),copy.deepcopy(self.profile_metadata))
        except Exception:
            self.reject('count_unknown', 'token_count_unknown')

    def request(self, task, prompt):
        from azazel_mio.playbook import compiled_model_response_schema
        schema = compiled_model_response_schema(task,prompt)
        if type(schema) is not dict:
            raise ValueError('effective_schema_unavailable')
        return LocalInferenceRequest((('user', prompt),),
            max_tokens=self.lane.output_caps[TASKS.index(task)],
            response_format={'type':'json_schema','json_schema':{
                'name':task,'strict':True,'schema':schema}})

    def budget_for_task(self, task):
        try:
            return mio_budget_for_task(self.planner, task, budget_type=self.api.GenerationBudget)
        except BudgetRefused as exc:
            reason = 'count_unknown' if exc.reason is BudgetReason.COUNT_UNKNOWN else 'budget_exhausted'
            self.note_failure(reason,MIO_REASON_OUTCOMES[reason])
            raise self.api.BudgetError(reason,'adapter_budget_gate') from None

    def usage_for_task(self, task):
        with self.lock:
            usage = self.tasks[TASKS.index(task)]['actual_usage']
            return None if usage is None else dict(input_tokens=usage['tokens_in'], output_tokens=usage['tokens_out'])

    def __call__(self, task, prompt):
        self.reject('dispatch_tracking_unavailable','output_invalid')

    def invoke_budgeted(self, task, prompt, on_dispatch):
        from .mio_generation import _reject_json_constant, _finite_json_float, _unique_json_object
        if self.reason is not None:
            self.reject(self.reason, self.outcome)
        try:
            allocation = self.planner.plan(task, prompt)
        except BudgetRefused as exc:
            self.reject(exc.reason.value, {'count_unknown':'token_count_unknown','timeout':'deadline_exceeded'}.get(exc.reason.value,'budget_exhausted'))
        idx = TASKS.index(task)
        request = self.request(task, prompt)
        with self.lock:
            record = self.tasks[idx]
            record.update(count_kind='exact', input_tokens_bound=allocation.input_tokens,
                input_limit=allocation.input_limit, output_tokens_cap=allocation.output_cap,
                output_min=self.planner.profile.tasks[idx].output_min,
                context_limit=allocation.context_limit, context_slack=allocation.context_slack,
                allocated_ms=allocation.provider_seconds*1000)
            # Same gate covers revocation/cancel, deadline and dispatch bookkeeping.
            if (self.job['cancelled'].is_set() or self.lane._stopped or self.lane._fenced
                    or not self.lane._authorized(self.job['generation']) or self.remaining() <= 0):
                self.reject('cancelled', 'cancelled')
            self.in_flight = True
            began = time.monotonic()
            self.current_started = began
            self.call_end = min(began + allocation.provider_seconds, self.job['end'])
            call = {'usage':None,'timings':{}}
        def before_dispatch():
            with self.lock:
                if (self.frozen is not None or self.job['cancelled'].is_set() or self.lane._stopped or self.lane._fenced
                        or not self.lane._authorized(self.job['generation']) or time.monotonic()>=self.call_end):
                    self.reject('cancelled','cancelled')
                if not callable(on_dispatch):
                    self.reject('dispatch_tracking_unavailable','output_invalid')
        def record_sent():
            # Called inside the nonblocking send gate, before freeze can snapshot.
            if record['dispatched'] or self.frozen is not None:
                self.reject('send_notification_conflict','output_invalid')
            record['dispatched'] = True
            self.calls.append(call)
        @contextmanager
        def dispatch_guard():
            # Same lock order as terminal publication; serialize lane fence too.
            with self.lock,self.lane._lock:
                before_dispatch()
                yield record_sent
        def dispatch():
            # MIO notification is outside the gate: a slow callback cannot hold
            # terminalization, and freeze cannot erase the already recorded send.
            try:
                on_dispatch()
            except Exception:
                self.reject('send_notification_conflict','output_invalid')
        try:
            cached=self.prepared.get(task)
            if cached is None or cached[0]!=prompt:raise TokenCountUnknown('native_count_unknown')
            result = self.lane.server.infer_native(request,
                deadline_s=max(.000001,self.call_end-time.monotonic()),allow_unknown_usage=True,on_dispatch=dispatch,before_dispatch=before_dispatch,dispatch_guard=dispatch_guard,
                prepared=cached[1],expected_tuple=self.verified_tuple)
            with self.lock:
                if self.frozen is not None:
                    return self.reject('timeout','deadline_exceeded')
                if not record['dispatched']:
                    self.reject('dispatch_tracking_unavailable','output_invalid')
                usage = (dict(tokens_in=result.tokens_in,tokens_out=result.tokens_out)
                         if integer(result.tokens_in) and integer(result.tokens_out) else None)
                record['actual_usage'] = usage
                call['usage'] = usage
                if type(result.timings) is not dict:
                    raise ValueError('invalid_timings')
                call['timings'] = {key:value for key,value in result.timings.items()
                    if key in ('total_ms','prompt_n','prompt_ms','predicted_n','predicted_ms','predicted_per_second')
                    and type(value) in (int,float) and math.isfinite(value) and value>=0}
                record['finish_reason'] = result.finish_reason if result.finish_reason in ('stop','length','content_filter','tool_calls') else None
                record['context_integrity'] = result.context_integrity if result.context_integrity in ('preserved','truncated') else 'unknown'
            if time.monotonic() >= self.call_end:
                self.reject('timeout','deadline_exceeded')
            if result.context_integrity == 'truncated':
                self.reject('truncated','runtime_truncated')
            if result.context_integrity != 'preserved':
                self.reject('truncation_unknown','truncation_unknown')
            if result.finish_reason != 'stop':
                self.reject('output_incomplete','output_incomplete')
            if usage is None:
                self.reject('token_usage_unknown','token_usage_unknown')
            if (usage['tokens_in'] != allocation.input_tokens or usage['tokens_out'] > allocation.output_cap
                    or usage['tokens_in']+usage['tokens_out']+allocation.context_slack > allocation.context_limit):
                self.reject('malformed','output_invalid')
            try:
                if type(result.text) is not str or len(result.text.encode('utf-8')) > 128*1024:
                    raise ValueError
                value = json.loads(result.text, parse_constant=_reject_json_constant,
                    parse_float=_finite_json_float, object_pairs_hook=_unique_json_object)
                if type(value) is not dict:
                    raise ValueError
            except Exception:
                self.reject('malformed','output_invalid')
            self.planner.completed(task)
            return value
        except TokenCountUnknown:
            self.reject('count_unknown','token_count_unknown')
        except TimeoutError:
            if not record['dispatched']:
                self.needs_stop=True
                self.reject('count_unknown','token_count_unknown')
            self.reject('timeout','deadline_exceeded')
        except Exception:
            if self.reason is None:
                self.note_failure('provider_unavailable','provider_unavailable')
            raise
        finally:
            with self.lock:
                if self.frozen is None:
                    record['elapsed_ms'] = max(0,(time.monotonic()-began)*1000)
                self.in_flight = False

    def finish(self, assistance):
        """Validate MIO's separate receipt before promoting any generated text."""
        receipt = getattr(assistance, 'generation_receipt', None)
        try:
            if not isinstance(receipt,self.api.GenerationOutcome):
                raise ValueError
            self.frame_unknowns = copy.deepcopy(getattr(receipt, 'frame_unknowns', {}))
            raw_reason = receipt.reason
            self.mio_reason = raw_reason if raw_reason in MIO_REASON_OUTCOMES else ('malformed' if raw_reason is not None else None)
            disposition = receipt.coordinator_disposition
            if disposition is not None and disposition not in COORDINATOR_DISPOSITIONS:
                raise ValueError
            self.coordinator_disposition = disposition
            if self.mio_reason is not None and self.reason is None:
                self.note_failure(self.mio_reason,MIO_REASON_OUTCOMES[self.mio_reason])
            if (receipt is None or set(receipt.calls_sent) != set(TASKS) or set(receipt.task_results) != set(TASKS)
                    or set(receipt.usage) != set(TASKS) or set(receipt.selections) - set(TASKS)):
                raise ValueError
            inherited = self.job.get('upstream_coverage','unknown')
            for idx, task in enumerate(TASKS):
                record = self.tasks[idx]
                if type(receipt.calls_sent[task]) is not int or receipt.calls_sent[task] != int(record['dispatched']):
                    raise ValueError
                actual = record['actual_usage']
                expected = None if actual is None else dict(input_tokens=actual['tokens_in'],output_tokens=actual['tokens_out'])
                if receipt.usage[task] != expected:
                    raise ValueError
                raw = receipt.selections.get(task)
                if raw is None:
                    continue
                if (not isinstance(raw,self.api.PromptSelection) or raw.coverage not in ('full','selected') or type(raw.kept) is not tuple
                        or type(raw.dropped) is not tuple or len(raw.kept)+len(raw.dropped)>4096
                        or any(type(unit) is not str for unit in raw.kept)
                        or len(set(raw.kept))!=len(raw.kept) or type(raw.template_version) is not str
                        or not 0<len(raw.template_version)<=64 or raw.token_count != record['input_tokens_bound']):
                    raise ValueError
                omitted = []
                for ordinal, item in enumerate(raw.dropped):
                    if (type(item) is not tuple or len(item)!=2 or type(item[0]) is not str
                            or item[1] not in ('duplicate','optional_detail','lower_priority')):
                        raise ValueError
                    omitted.append(dict(kind='semantic_unit', ordinal=len(raw.kept)+ordinal, reason=item[1]))
                dropped_ids = [item[0] for item in raw.dropped]
                if len(set(dropped_ids)) != len(dropped_ids) or set(dropped_ids)&set(raw.kept) or (raw.coverage=='full' and omitted):
                    raise ValueError
                selected = raw.coverage == 'selected' or bool(omitted) or inherited == 'selected'
                sel = dict(policy_version=raw.template_version,
                    coverage='unknown' if inherited=='unknown' else 'selected' if selected else 'intact',
                    input_units=len(raw.kept)+len(omitted), selected_units=len(raw.kept),
                    omitted_units=len(omitted), omissions=omitted)
                validate_selection(sel)
                if self.profile_metadata['template_version'] is None:self.profile_metadata['template_version']=raw.template_version
                record['selection'] = sel
                inherited = sel['coverage']
                record['validated'] = receipt.task_results.get(task) == 'validated'
            public = assistance.to_dict()
            self.core_complete = (receipt.state == 'complete' and receipt.reason is None and self.reason is None
                and public.get('state') == 'complete' and public.get('generation_method') == 'model'
                and all(t['dispatched'] and t['validated'] for t in self.tasks))
            if self.core_complete:
                validate_model_assistance(public,self.job['frame'].frame_id,self.job['frame'].trace_id)
                self.assistance = public
            elif self.reason is None:
                self.note_failure('malformed','output_invalid')
        except Exception:
            self.core_complete = False
            if self.reason is None:
                self.note_failure('malformed','output_invalid')

    def snapshot(self, state, outcome):
        with self.lock:
            elapsed = max(0,(time.monotonic()-self.started)*1000)
            reasons = list(self.failures)
            if self.reason is not None and self.reason not in reasons:reasons.insert(0,self.reason)
            if self.mio_reason is not None and self.mio_reason not in reasons:
                reasons.append(self.mio_reason)
            tasks = copy.deepcopy(self.tasks)
            if self.in_flight and self.current_started is not None:
                sent = [t for t in tasks if t['dispatched']]
                if sent and sent[-1]['elapsed_ms'] == 0:
                    sent[-1]['elapsed_ms'] = max(0,(time.monotonic()-self.current_started)*1000)
            meta = dict(version=1,profile_id='fixture-v1',outcome=outcome,reasons=reasons,
                coverage=coverage(self.job.get('upstream_coverage','unknown'),tasks),
                upstream_coverage=self.job.get('upstream_coverage','unknown'),
                upstream_selection=copy.deepcopy(self.job.get('upstream_selection',selection_unknown())), elapsed_ms=elapsed,
                deadline_ms=self.lane.deadline_s*1000,result_state=state,primary_outcome=self.outcome or outcome,terminal_outcome=outcome,
                verified_tuple=copy.deepcopy(self.verified_tuple),profile=copy.deepcopy(self.profile_metadata),
                superseded=False,cleanup=copy.deepcopy(self.cleanup),job_calls=sum(t['dispatched'] for t in tasks),
                tasks=tasks,core_complete=self.core_complete,coordinator_disposition=self.coordinator_disposition)
            projected, meta = project_budget(meta)
            status = self.lane._status(projected,self.job['frame'],self.job['generation'],
                result_handle=self.job['handle'],budget_version=1,generation_budget=meta,calls=copy.deepcopy(self.calls))
            if self.calls and all(c['usage'] is not None for c in self.calls):
                status['usage']='known'
            if projected=='complete':
                status['assistance']=self.assistance
            return status


    def failure_snapshot(self):
        """Rebuild failed v1 metadata from accounting, never from the faulty wire value."""
        with self.lock:
            safe=BudgetSession(self.lane,self.job,None)
            basis=self._accounting_basis
            if basis is None and self.verified_tuple is not None:
                basis=(self.verified_tuple,self.profile_metadata)
            if basis is not None:
                verified,profile=copy.deepcopy(basis)
                validate_verified_tuple(verified)
                validate_profile(profile)
                context=(None if profile['configured_context_limit'] is None else
                    effective_context_limit(verified['context_limit'],profile['configured_context_limit']))
                safe.verified_tuple=verified
                safe.profile_metadata=profile
                for i,(task,cap) in enumerate(zip(safe.tasks if context is not None else (),profile['output_caps'])):
                    task.update(context_limit=context,context_slack=profile['slack'],output_tokens_cap=cap,
                        output_min=profile['output_mins'][i],input_limit=max(1,context-cap-profile['slack']) if context>cap+profile['slack'] else None)
            if self.reason in REASONS and self.outcome in OUTCOMES:
                safe.note_failure(self.reason,self.outcome)
            safe.note_failure('malformed','output_invalid')
            for i,call in enumerate(self.calls[:3]):
                task=safe.tasks[i];task['dispatched']=True
                actual=call.get('usage')
                if (type(actual) is dict and set(actual)=={'tokens_in','tokens_out'}
                        and all(integer(v) for v in actual.values())):
                    task['actual_usage']=copy.deepcopy(actual)
                safe.calls.append(dict(usage=task['actual_usage'],timings={}))
            safe.cleanup=copy.deepcopy(self.cleanup)
            status=safe.snapshot('degraded','output_invalid')
            read_budget(status['generation_budget'],state=status['state'],usage=status['usage'])
            return status
