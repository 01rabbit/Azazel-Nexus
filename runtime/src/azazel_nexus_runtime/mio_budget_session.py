"""Product-owned budget execution; MIO owns semantic compilation and grounding."""
from __future__ import annotations
import copy
import json
import math
import threading
import time
from azazel_nexus.generation_budget import (TASKS, CAPS, coverage, task_placeholder,
    selection_unknown, project_budget, integer, validate_selection, validate_model_assistance)
from .mio_generation_budget import (BudgetPlanner, BudgetProfile, TaskBudget,
    BudgetRefused, BudgetReason, mio_budget_for_task)
from .mio_serve import LocalInferenceRequest


class BudgetSession:
    def __init__(self, lane, job, api):
        self.lane, self.job, self.api = lane, job, api
        self.last_model = getattr(lane.capability,'model_id','unavailable')
        self.lock = threading.RLock()
        self.tasks = [task_placeholder(task) for task in TASKS]
        self.planner = None
        self.reason = None
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

    def reject(self, reason, outcome):
        from azazel_mio.model_adapter import MioModelUnavailable
        with self.lock:
            if self.reason is None:
                self.reason, self.outcome = reason, outcome
        raise MioModelUnavailable(reason)

    def remaining(self):
        return self.job['end'] - time.monotonic()

    def read_remaining(self):
        return self.remaining()-max(.5,self.lane.deadline_s*.1)/2

    def _provider_read(self, operation):
        with self.lock:
            if self.frozen is not None or self.lane._stopped or self.lane._fenced or self.read_remaining()<=0:
                raise ValueError('generation_closed')
            self.in_flight = True
            self.call_end = self.job['end']-max(.5,self.lane.deadline_s*.1)/2
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
            context = self._provider_read(lambda:self.lane.server.context_limit(self.read_remaining()))
            if type(context) is not int or context <= 0:
                raise ValueError
            specs = tuple(TaskBudget(t, max(1, context - cap - 32), cap, cap, .05)
                          for t, cap in zip(TASKS, self.lane.output_caps))
            profile = BudgetProfile('fixture-v1', context, specs)
            def counter(task, prompt):
                if not self.lane._authorized(self.job['generation']) or self.job['cancelled'].is_set():
                    return None
                request = self.request(task, prompt)
                return self._provider_read(lambda:self.lane.server.count_chat_tokens(request,self.read_remaining()))
            self.planner = BudgetPlanner(profile, submitted=self.started,
                deadline_s=self.lane.deadline_s, counter=counter, clock=time.monotonic)
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
            self.reject(exc.reason.value, 'token_count_unknown' if exc.reason is BudgetReason.COUNT_UNKNOWN else 'budget_exhausted')

    def usage_for_task(self, task):
        with self.lock:
            usage = self.tasks[TASKS.index(task)]['actual_usage']
            return None if usage is None else dict(input_tokens=usage['tokens_in'], output_tokens=usage['tokens_out'])

    def __call__(self, task, prompt):
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
            record['dispatched'] = True
            call = {'usage':None,'timings':{}}
            self.calls.append(call)
        try:
            result = self.lane.server.infer(request,
                deadline_s=max(.000001,self.call_end-time.monotonic()), allow_unknown_usage=True)
            with self.lock:
                if self.frozen is not None:
                    return self.reject('timeout','deadline_exceeded')
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
        except TimeoutError:
            self.reject('timeout','deadline_exceeded')
        except Exception:
            if self.reason is None:
                self.reason, self.outcome = 'provider_unavailable','provider_unavailable'
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
                if (raw.coverage not in ('full','selected') or type(raw.kept) is not tuple
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
                record['selection'] = sel
                inherited = sel['coverage']
                record['validated'] = receipt.task_results.get(task) == 'validated'
            public = assistance.to_dict()
            if receipt.reason is not None and self.reason is None:
                self.reason = receipt.reason if receipt.reason in ('budget_exhausted','count_unknown','malformed','task_plan_unsupported') else 'malformed'
                self.outcome = {'count_unknown':'token_count_unknown','malformed':'output_invalid'}.get(self.reason,'budget_exhausted')
            self.core_complete = (receipt.state == 'complete' and receipt.reason is None
                and public.get('state') == 'complete' and public.get('generation_method') == 'model'
                and all(t['dispatched'] and t['validated'] for t in self.tasks))
            if self.core_complete:
                validate_model_assistance(public,self.job['frame'].frame_id,self.job['frame'].trace_id)
                self.assistance = public
            elif self.reason is None:
                self.reason,self.outcome = 'malformed','output_invalid'
        except Exception:
            self.core_complete = False
            if self.reason is None:
                self.reason,self.outcome = 'malformed','output_invalid'

    def snapshot(self, state, outcome):
        with self.lock:
            elapsed = max(0,(time.monotonic()-self.started)*1000)
            reasons = [] if self.reason is None else [self.reason]
            tasks = copy.deepcopy(self.tasks)
            if self.in_flight and self.current_started is not None:
                sent = [t for t in tasks if t['dispatched']]
                if sent and sent[-1]['elapsed_ms'] == 0:
                    sent[-1]['elapsed_ms'] = max(0,(time.monotonic()-self.current_started)*1000)
            meta = dict(version=1,profile_id='fixture-v1',outcome=outcome,reasons=reasons,
                coverage=coverage(self.job.get('upstream_coverage','unknown'),tasks),
                upstream_coverage=self.job.get('upstream_coverage','unknown'),
                upstream_selection=copy.deepcopy(self.job.get('upstream_selection',selection_unknown())), elapsed_ms=elapsed,
                deadline_ms=self.lane.deadline_s*1000,result_state=state,primary_outcome=outcome,
                superseded=False,cleanup=copy.deepcopy(self.cleanup),job_calls=sum(t['dispatched'] for t in tasks),
                tasks=tasks,core_complete=self.core_complete)
            projected, meta = project_budget(meta)
            status = self.lane._status(projected,self.job['frame'],self.job['generation'],
                result_handle=self.job['handle'],budget_version=1,generation_budget=meta,calls=copy.deepcopy(self.calls))
            if self.calls and all(c['usage'] is not None for c in self.calls):
                status['usage']='known'
            if projected=='complete':
                status['assistance']=self.assistance
            return status
