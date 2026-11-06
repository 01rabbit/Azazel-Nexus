"""Closed generation seam. Production has no generation admission loader yet.

Only a future independently authenticated generation loader may mint the sealed
capability. Embedding evidence is never a substitute. No process is started here.
"""
from __future__ import annotations

import copy
from contextlib import nullcontext
import hashlib
import json
import math
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from azazel_nexus import model_admission
from azazel_nexus.generation_budget import CAPS, read_budget, project_budget
from .mio_generation_budget import BudgetSettings

GENERATION_ADMISSION_ENABLED = False
_SEAL = object()


@dataclass(frozen=True)
class GenerationCapability:
    generation_id: str
    model_id: str
    expires_at: str
    reserve_mib: int
    recheck: object = field(repr=False)
    role: str = 'generation'
    _seal: object = field(default=None, repr=False)
    model_context_limit: int | None = None  # loader supplies the verified model record's bound


def authorized(value, generation_id):
    """No production reader mints this type in this release."""
    try:
        return (model_admission.LOCAL_MODEL_ADMISSION_ENABLED is True
                and GENERATION_ADMISSION_ENABLED is True
                and type(value) is GenerationCapability and value._seal is _SEAL
                and value.role == 'generation' and value.generation_id == generation_id
                and type(value.reserve_mib) is int and value.reserve_mib > 0
                and datetime.now(UTC) < datetime.fromisoformat(value.expires_at.replace('Z', '+00:00'))
                and value.recheck() is True)
    except Exception:
        return False


def _reject_json_constant(name):
    """Non-standard JSON NaN/Infinity/-Infinity is invalid model content."""
    raise ValueError('non_standard_json_constant')


def _finite_json_float(value):
    """Reject exponent overflow, which Python's JSON decoder otherwise maps to inf."""
    result = float(value)
    if not math.isfinite(result):
        raise ValueError('non_finite_json_number')
    return result


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_json_key')
        result[key] = value
    return result


class StructuredGenerationTransport:
    """Product-owned bounded AF_UNIX server -> MIO StructuredTransport."""
    def __init__(self, server, capability, *, deadline, cancelled, check, state=None):
        self.server, self.capability = server, capability
        self.deadline, self.cancelled, self.check = deadline, cancelled, check
        # state: job-owned {'gate': Lock, 'in_flight': bool}. The gate
        # makes "may start a provider request" and "a request is in flight" atomic
        # with respect to the cancel/deadline watcher.
        self.state = state if state is not None else {
            'gate': threading.Lock(), 'in_flight': False}
        self.last_model = capability.model_id
        self.calls = []
        self.failed = False

    def __call__(self, task, prompt):
        from azazel_mio.model_adapter import MioModelBlocked, MioModelUnavailable
        from azazel_mio.model_schema import model_response_schema
        from .mio_serve import LocalInferenceRequest
        state = self.state
        with state['gate']:
            remaining = self.deadline - time.monotonic()
            if self.cancelled.is_set() or remaining <= 0 or not self.check():
                raise MioModelBlocked('generation_closed')
            state['in_flight'] = True
        try:
            result = self.server.infer(LocalInferenceRequest(
                (('user', prompt),), max_tokens=CAPS[('generate_hypotheses', 'identify_evidence_gaps', 'recommend').index(task)],
                response_format={'type': 'json_schema', 'json_schema': {
                    'name': task, 'strict': True, 'schema': model_response_schema(task)}}),
                deadline_s=remaining, allow_unknown_usage=True)
            if self.cancelled.is_set() or time.monotonic() >= self.deadline or not self.check():
                raise MioModelBlocked('generation_stale')
            # A malformed infer result is a transport failure, so access it inside this try.
            text = result.text
            if type(text) is not str:
                raise TypeError('malformed_infer_result')
            usage = None
            if (type(result.tokens_in) is int and result.tokens_in >= 0
                    and type(result.tokens_out) is int and result.tokens_out >= 0):
                usage = {'tokens_in': result.tokens_in, 'tokens_out': result.tokens_out}
            timings = {k: v for k, v in result.timings.items()
                       if type(v) in (int, float) and math.isfinite(v) and v >= 0}
            self.calls.append({'usage': usage, 'timings': timings})
        except MioModelBlocked:
            raise
        except Exception:
            # Transport/provider failure only: the server is no longer trusted.
            self.failed = True
            raise MioModelUnavailable('generation_unavailable') from None
        finally:
            with state['gate']:
                state['in_flight'] = False
        # Content failure is per job: the provider stays usable and is not stopped.
        try:
            value = json.loads(text, parse_constant=_reject_json_constant,
                               parse_float=_finite_json_float,
                               object_pairs_hook=_unique_json_object)
        except (TypeError, ValueError, RecursionError):
            raise MioModelUnavailable('generation_content_invalid') from None
        if type(value) is not dict:
            raise MioModelUnavailable('generation_content_invalid')
        return value


class GenerationLane:
    """One worker, one pending request, sixteen retained bounded results.

    The provider is stopped only when a request is in flight, bounding work as
    well as publication. Timeout, cancel, or supersession while a provider
    request is in flight stops the provider from a watcher while infer() is
    still blocked. A transport failure stops it only after the failed call has
    returned. An idle provider is kept on supersession. The loader must
    replace a stopped server explicitly: after a successful stop() the lane is
    stopped for good (_stopped), drops/degrades its pending job and rejects later
    submits without a handle or inference. If stop() raises, termination is
    unconfirmed: once that failure is known, the lane fences the server
    permanently and changes active/pending receipts to degraded. A
    timeout/cancelled receipt may remain visible while stop() is still pending.
    Later submits degrade without inference.
    No restart/spawn occurs here. Exact-source repeats and explicit handles poll
    results. Handles retain original bindings for at most sixty seconds (maximum
    configurable TTL: three hundred seconds), with sixteen retained records.
    """
    def __init__(self, *, capability=None, server=None, deadline_s=5.0, result_ttl_s=60.0,
                 budget_enabled=False, output_caps=CAPS, budget_settings=None):
        if type(deadline_s) not in (int, float) or not math.isfinite(deadline_s) or not 0 < deadline_s <= 30:
            raise ValueError('invalid_generation_deadline')
        if type(result_ttl_s) not in (int, float) or not math.isfinite(result_ttl_s) or not 0 < result_ttl_s <= 300:
            raise ValueError('invalid_result_ttl')
        if (type(budget_enabled) is not bool or type(output_caps) is not tuple or len(output_caps) != 3
                or any(type(cap) is not int or not 1 <= cap <= 768 for cap in output_caps)):
            raise ValueError('invalid_generation_profile')
        self.budget_settings = budget_settings if budget_settings is not None else BudgetSettings()
        if type(self.budget_settings) is not BudgetSettings:raise ValueError('invalid_budget_settings')
        self.budget_enabled, self.output_caps = budget_enabled, output_caps
        self.result_ttl_s = result_ttl_s
        self._receipts = {}
        self.capability, self.server, self.deadline_s = capability, server, deadline_s
        self._lock = threading.RLock()
        self._stop_lock = threading.Lock()
        self._fenced = False  # set permanently when provider stop() raises
        self._stopped = False  # set permanently when provider stop() succeeded
        self._pending = None
        self._active = None
        self._worker = None
        self._results = {}

    def _authorized(self, generation_id):
        return authorized(self.capability, generation_id)

    def _status(self, state, frame, generation_id, **extra):
        return {'state': state, 'generation_id': generation_id,
                'frame_id': frame.frame_id, 'trace_id': frame.trace_id,
                'usage': 'unknown', **extra}

    def _decline(self, state, frame, generation_id, outcome, upstream_coverage, upstream_selection):
        if not self.budget_enabled:
            return self._status(state,frame,generation_id)
        from .mio_budget_session import BudgetSession
        submitted = time.monotonic()
        job = dict(submitted=submitted,end=submitted+self.deadline_s,frame=frame,
            generation=generation_id,handle=None,upstream_coverage=upstream_coverage,
            upstream_selection=upstream_selection)
        session = BudgetSession(self,job,None)
        session.note_failure(outcome,outcome)
        value = session.snapshot(state,outcome)
        value.pop('result_handle',None)
        return value

    def _cancel(self, job, reason):
        job['cancelled'].set()
        job['reason'] = reason
        if job.get('budget_session') is not None:
            return  # control worker observes cancellation; terminal supersession is consumer-owned
        with self._lock:
            record = self._receipts.get(job['handle'])
            # A fenced lane's degraded receipts are final; never rewrite them.
            if record and not self._fenced:
                record['status'] = self._status(reason, job['frame'], job['generation'],
                                                 result_handle=job['handle'])
        # stop() is the existing bounded supervisor process-group termination.
        # Do not call it in the fast caller: the worker/timer owns cancellation.

    def _retain(self, key, status):
        """Cache one terminal status under the existing sixteen-entry bound (caller holds lock)."""
        self._results[key] = status
        while len(self._results) > 16:
            del self._results[next(iter(self._results))]

    def _prune(self):
        now = time.monotonic()
        for handle, record in list(self._receipts.items()):
            if now >= record['expires']:
                self._receipts.pop(handle)
        while len(self._receipts) > 16:
            self._receipts.pop(next(iter(self._receipts)))
        live = set(self._receipts)
        self._results = {key: value for key, value in self._results.items()
                         if value.get('result_handle') in live}

    def _public_record(self, record):
        value = copy.deepcopy(record['status'])
        meta = value.get('generation_budget')
        if meta is not None:
            final = record.get('cleanup_final')
            if final is None and meta['cleanup']['state'] == 'pending':
                now = time.monotonic()
                meta['cleanup']['remaining_ms'] = max(0,int((record['end']-now)*1000))
                # A zero millisecond display before E is not an elapsed deadline.
                if now >= record['end']:
                    final = dict(state='unconfirmed',reason='confirmation_deadline',remaining_ms=0)
                    record['cleanup_final'] = final
                    self._fenced = True
            if final is not None:
                meta['cleanup'] = copy.deepcopy(final)
                value['state'],value['generation_budget'] = project_budget(meta)
                value.pop('assistance',None)
        return value

    def poll(self, result_handle, generation_id, trace_id):
        """Read one original job, never dispatch or consult embedding admission."""
        stale = {'state': 'stale', 'usage': 'unknown'}
        if not self._authorized(generation_id):
            return stale
        with self._lock:
            self._prune()
            record = self._receipts.get(result_handle) if type(result_handle) is str else None
            if (not record or record['generation'] != generation_id
                    or record['trace'] != trace_id):
                return stale
            return self._public_record(record)

    def submit(self, source, frame, generation_id, *, upstream_coverage='unknown', upstream_selection=None):
        from azazel_nexus.generation_budget import validate_selection, selection_unknown
        if upstream_selection is None:
            upstream_selection = selection_unknown()
            upstream_selection['coverage'] = upstream_coverage
        validate_selection(upstream_selection)
        if upstream_selection['coverage'] != upstream_coverage:
            raise ValueError('invalid_upstream_coverage')
        if upstream_coverage not in ('intact', 'selected', 'unknown'):
            raise ValueError('invalid_upstream_coverage')
        if not self._authorized(generation_id):
            return self._decline('closed',frame,generation_id,'admission_closed',upstream_coverage,upstream_selection)
        if self.server is None:
            return self._decline('degraded',frame,generation_id,'model_unavailable',upstream_coverage,upstream_selection)
        fingerprint = hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()
        key = (generation_id, fingerprint)
        with self._lock:
            self._prune()
            if key in self._results:
                cached = self._results[key]
                record = self._receipts.get(cached.get('result_handle'))
                return self._public_record(record) if record is not None else copy.deepcopy(cached)
            for job in (self._active, self._pending):
                if job and job['key'] == key:
                    # Exact retry of existing work stays pollable even after a stop/fence;
                    # then the receipt (timeout/cancelled/degraded) is the truth, not 'queued'.
                    record = self._receipts.get(job['handle'])
                    if not record:
                        # Receipt TTL/eviction applies even while the lane is still
                        # running. Never return a queued handle that poll() cannot read.
                        return self._status('degraded', frame, generation_id)
                    if self._fenced or self._stopped:
                        return self._public_record(record)
                    return self._status('queued', job['frame'], generation_id, result_handle=job['handle'])
            # _fence()/_mark_stopped() set their flags under this lock: new work is
            # refused here, so a stop that lands mid-call admits no receipt or pending job.
            if self._fenced or self._stopped:
                return self._status('degraded', frame, generation_id)
            # A new revision of the same caller request supersedes its old work.
            for job in (self._active, self._pending):
                if job and job['source']['request_id'] == source['request_id']:
                    self._cancel(job, 'superseded')
            if self._pending and self._pending['cancelled'].is_set():
                self._pending = None
            if self._pending is not None:
                return self._status('queue_full', frame, generation_id)
            handle = secrets.token_hex(32)
            queued = self._status('queued', frame, generation_id, result_handle=handle)
            submitted = time.monotonic()
            self._receipts[handle] = dict(generation=generation_id, trace=frame.trace_id,
                expires=submitted + self.result_ttl_s, end=submitted+self.deadline_s, status=queued)
            self._prune()
            self._pending = dict(handle=handle, key=key, source=copy.deepcopy(source), frame=frame,
                                 generation=generation_id, cancelled=threading.Event(),
                                 submitted=submitted,
                                 end=submitted + self.deadline_s, reason='cancelled',
                                 upstream_coverage=upstream_coverage, upstream_selection=copy.deepcopy(upstream_selection))
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(target=self._run, daemon=True,
                                                name='mio-generation')
                self._worker.start()
            return copy.deepcopy(queued)

    def cancel(self):
        with self._lock:
            for job in (self._active, self._pending):
                if job:
                    self._cancel(job, 'cancelled')

    def _stop_provider(self, job):
        """Stop the provider; never raises. A stop failure fences the server for this lane.

        The fence is permanent: no further request may reach a provider whose
        termination is unconfirmed. The loader must supply a new lane/server.
        """
        with self._stop_lock:
            if self._fenced:
                return False  # already fenced: stop() was attempted once, never again
            if job.get('stopped'):
                return True  # stop() already succeeded for this job: never call it twice
            try:
                self.server.stop()
            except Exception:
                self._fence(job)
                return False
            job['stopped'] = True
            self._mark_stopped()
        return True

    def _mark_stopped(self, *, budget=False):
        """Fence the lane against the stopped provider; degrade and drop the pending job."""
        with self._lock:
            self._stopped = True
            pending, self._pending = self._pending, None
            record = self._receipts.get(pending['handle']) if pending else None
            if record:
                if budget:
                    from .mio_budget_session import BudgetSession
                    session = BudgetSession(self,pending,None)
                    session.note_failure('model_unavailable','model_unavailable')
                    record['status'] = session.snapshot('degraded','model_unavailable')
                else:
                    record['status'] = self._status('degraded', pending['frame'], pending['generation'],
                                                     result_handle=pending['handle'])
                # Dropped pending work: an exact retry gets this terminal receipt, not a bare degraded.
                self._retain(pending['key'], copy.deepcopy(record['status']))

    def _fence(self, job):
        """Fence permanently and publish degraded receipts now, without waiting for infer().

        The only worker the lane may retain is the one blocked in infer(); the
        pending job is dropped and its receipt degraded, so nothing else is
        queued or run. A late return of the blocked worker cannot overwrite these.
        """
        with self._lock:
            self._fenced = True
            job['stop_failed'] = True
            pending, self._pending = self._pending, None
            for item in (job, pending):
                record = self._receipts.get(item['handle']) if item else None
                if record:
                    record['status'] = self._status('degraded', item['frame'], item['generation'],
                                                     result_handle=item['handle'])
                    if item is pending:
                        self._retain(item['key'], copy.deepcopy(record['status']))

    def _execute(self, job):
        """Run one job. The provider is stopped only while one of its requests is in flight."""
        if self.budget_enabled:
            try:
                from azazel_mio import AssistantCore
                from azazel_mio import budget as api
                import inspect
                if ('generation_budget' not in inspect.signature(AssistantCore.explain).parameters
                        or any(not hasattr(api,name) for name in ('GenerationBudget','GenerationOutcome','PromptSelection','BudgetError'))):
                    raise ImportError('budget_api_unavailable')
            except (ImportError,AttributeError,ValueError):
                session=self._make_budget_session(job,None)
                job['budget_session']=session
                session.note_failure('count_unknown','token_count_unknown')
                session.frozen=session.snapshot('degraded','token_count_unknown')
                return copy.deepcopy(session.frozen)
            return self._execute_budget(job,AssistantCore,api)
        from azazel_mio import AssistantCore
        if self._fenced or self._stopped:
            return self._status('degraded', job['frame'], job['generation'])
        if job['cancelled'].is_set() or time.monotonic() >= job['end']:
            # Cancelled or expired before any provider request: no watcher, no stop.
            return self._status(job['reason'] if job['cancelled'].is_set() else 'timeout',
                                job['frame'], job['generation'])
        state = {'gate': threading.Lock(), 'in_flight': False}
        timer_stop = threading.Event()
        def watch():
            while not timer_stop.wait(.01):
                if job['cancelled'].is_set() or time.monotonic() >= job['end']:
                    if not job['cancelled'].is_set():
                        self._cancel(job, 'timeout')
                    # The transport checks cancel/deadline under this gate before it
                    # marks a request in flight, so no request can begin after this read.
                    with state['gate']:
                        in_flight = state['in_flight']
                    if in_flight:
                        self._stop_provider(job)
                    return
        watcher = threading.Thread(target=watch, daemon=True, name='mio-generation-deadline')
        watcher.start()
        transport = StructuredGenerationTransport(self.server, self.capability,
            deadline=job['end'], cancelled=job['cancelled'],
            check=lambda: self._authorized(job['generation'])
                           and not (self._fenced or self._stopped),
            state=state)
        status = self._status('degraded', job['frame'], job['generation'])
        try:
            result = AssistantCore(model=transport).explain(job['frame'],
                now=datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),
                knowledge_attempted=False, cancel_check=job['cancelled'].is_set,
                stale_check=lambda: not self._authorized(job['generation'])).to_dict()
            if (result['frame_id'] != job['frame'].frame_id
                    or result['trace_id'] != job['frame'].trace_id):
                raise ValueError('binding_mismatch')
            if not self._authorized(job['generation']):
                status['state'] = 'closed'
            elif not job['cancelled'].is_set() and time.monotonic() < job['end']:
                status.update(state='complete' if result['generation_method'] == 'model' else 'degraded',
                              assistance=result, calls=transport.calls)
                if transport.calls and all(call['usage'] is not None for call in transport.calls):
                    status['usage'] = 'known'
        except Exception:
            pass
        finally:
            timer_stop.set()
            # Unbounded join: a watcher already inside _stop_provider must finish before
            # this job ends, so a queued next job never races a stale provider stop.
            watcher.join()
        # Only a transport/provider failure stops the provider here; content failures do not.
        if transport.failed:
            self._stop_provider(job)
        if job.get('stop_failed'):
            # Stop raised: termination is unconfirmed, so report degraded, not timeout/cancelled.
            return self._status('degraded', job['frame'], job['generation'])
        if job['cancelled'].is_set() or time.monotonic() >= job['end']:
            status = self._status(job['reason'] if job['cancelled'].is_set() else 'timeout',
                                  job['frame'], job['generation'])
        return status

    def _update_budget_cleanup(self, job, state, reason):
        session = job['budget_session']
        with session.lock:
            if session.cleanup['state'] != 'pending':
                return
            session.cleanup = dict(state=state, reason=reason, remaining_ms=0)
            if session.frozen is not None:
                status = copy.deepcopy(session.frozen)
                status['generation_budget']['cleanup'] = copy.deepcopy(session.cleanup)
                projected, meta = project_budget(status['generation_budget'])
                status.update(state=projected, generation_budget=meta)
                if projected != 'complete':
                    status.pop('assistance', None)
                session.frozen = status
            else:
                status = None
        with self._lock:
            if state == 'unconfirmed':
                self._fenced = True
            if status is not None:
                record = self._receipts.get(job['handle'])
                if record is not None:
                    record['status'] = copy.deepcopy(status)
                    status = self._public_record(record)
                    record['status'] = copy.deepcopy(status)
                self._retain(job['key'], copy.deepcopy(status))

    def _start_budget_stop(self, job):
        session = job['budget_session']
        with session.lock:
            if session.cleanup['state'] != 'not_needed':
                return
            session.cleanup = dict(state='pending', reason=None,
                remaining_ms=max(0,int((job['end']-time.monotonic())*1000)))
        # Closing the dispatch gate is synchronous. stop() never runs on the
        # deadline/control worker, so a hung provider cannot hold result termination.
        self._mark_stopped(budget=True)
        def stop():
            try:
                self.server.stop()
            except Exception:
                self._update_budget_cleanup(job, 'unconfirmed', 'stop_failed')
            else:
                if time.monotonic() < job['end']:
                    self._update_budget_cleanup(job, 'confirmed', 'stop_confirmed')
                else:
                    self._update_budget_cleanup(job, 'unconfirmed', 'confirmation_deadline')
        threading.Thread(target=stop, daemon=True, name='mio-budget-stop').start()
        def expire():
            while time.monotonic() < job['end']:
                with session.lock:
                    if session.cleanup['state'] != 'pending':
                        return
                session.done.wait(min(.01,max(0,job['end']-time.monotonic())))
                # done is not a stop confirmation; never wait on inference.
                if session.done.is_set():
                    time.sleep(min(.01,max(0,job['end']-time.monotonic())))
            self._update_budget_cleanup(job, 'unconfirmed', 'confirmation_deadline')
        threading.Thread(target=expire, daemon=True, name='mio-budget-cleanup').start()

    def _make_budget_session(self, job, api):
        """Product default; isolated transport fixtures may override this constructor seam."""
        from .mio_budget_session import BudgetSession
        return BudgetSession(self,job,api)

    def _execute_budget(self, job, core_type, api):
        session = self._make_budget_session(job,api)
        job['budget_session'] = session
        def work():
            try:
                session.initialize()
                result = core_type(model=session).explain(job['frame'],
                    now=datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    knowledge_attempted=False, cancel_check=job['cancelled'].is_set,
                    stale_check=lambda: not self._authorized(job['generation']),
                    generation_budget=session.budget_for_task)
                with session.lock:
                    if session.frozen is None:
                        session.finish(result)
            except Exception:
                with session.lock:
                    if session.reason is None:
                        session.note_failure('malformed','output_invalid')
            finally:
                session.done.set()
        if job['cancelled'].is_set():
            session.note_failure(job['reason'],job['reason'])
            session.done.set()
        elif time.monotonic() >= job['end']:
            session.note_failure('timeout','deadline_exceeded')
            session.done.set()
        elif self._stopped or self._fenced:
            session.note_failure('model_unavailable','model_unavailable')
            session.done.set()
        else:
            threading.Thread(target=work, daemon=True,name='mio-budget-infer').start()
        while True:
            now = time.monotonic()
            with session.lock:
                expired = now >= job['end'] or (session.in_flight and now >= session.call_end)
                revoked = not self._authorized(job['generation'])
                cancelled = job['cancelled'].is_set()
                done = session.done.is_set()
                reserve_exhausted = not done and now >= job['end']-self.budget_settings.reserve(self.deadline_s)/2
                in_flight = session.in_flight
                failure = session.reason
                needs_stop = session.needs_stop
            if expired or revoked or cancelled or done or reserve_exhausted or needs_stop:
                if revoked:
                    session.note_failure('admission_closed','admission_closed')
                    state,outcome='closed','admission_closed'
                elif cancelled:
                    session.note_failure(job['reason'],job['reason'])
                    state,outcome=job['reason'],job['reason']
                elif expired:
                    session.note_failure('timeout','deadline_exceeded')
                    state,outcome='timeout','deadline_exceeded'
                elif reserve_exhausted:
                    session.note_failure('budget_exhausted','budget_exhausted')
                    state,outcome='degraded','budget_exhausted'
                elif needs_stop and failure is None:
                    session.note_failure('count_unknown','token_count_unknown')
                    state,outcome='degraded','token_count_unknown'
                elif failure:
                    state = {'deadline_exceeded':'timeout','cancelled':'cancelled','superseded':'superseded','stale':'stale','admission_closed':'closed'}.get(session.outcome,'degraded')
                    outcome=session.outcome
                elif session.core_complete and session.remaining() > self.budget_settings.reserve(self.deadline_s)/2:
                    state,outcome='complete','within_budget'
                else:
                    session.note_failure('budget_exhausted','budget_exhausted')
                    state,outcome='degraded','budget_exhausted'
                if in_flight or needs_stop or (failure in ('provider_unavailable','timeout') and any(t['dispatched'] for t in session.tasks)):
                    self._start_budget_stop(job)
                elif not done:
                    # A CPU-bound compiler may return late; it cannot admit new work.
                    self._mark_stopped(budget=True)
                with session.lock:
                    if state=='complete' and (session.assistance.get('frame_id') != job['frame'].frame_id
                            or session.assistance.get('trace_id') != job['frame'].trace_id):
                        session.note_failure('malformed','output_invalid')
                        state,outcome='degraded','output_invalid'
                    status = session.snapshot(state,outcome)
                    if state=='complete' and status['generation_budget']['coverage']=='unknown':
                        session.note_failure('truncation_unknown','truncation_unknown')
                        status=session.snapshot('degraded','truncation_unknown')
                    session.frozen = copy.deepcopy(status)
                return status
            session.done.wait(.002)

    def _run(self):
        while True:
            with self._lock:
                job, self._pending = self._pending, None
                self._active = job
                if job is None:
                    self._worker = None
                    return
            try:
                status = self._execute(job)
            except Exception:
                status = self._status('degraded', job['frame'], job['generation'])
            session = job.get('budget_session')
            with (session.lock if session is not None else nullcontext()):
                with self._lock:
                    if session is not None:
                        status = copy.deepcopy(session.frozen or status)
                    status['result_handle'] = job['handle']
                    # Retained output has the same hard byte/schema bound as the wire reader.
                    if read_slow_analysis(status) == {'state':'closed','usage':'unknown'}:
                        if session is not None:
                            # Malformed new metadata cannot downgrade to an old-format result.
                            status = session.failure_snapshot()
                            session.frozen = copy.deepcopy(status)
                        else:
                            status = self._status('degraded', job['frame'], job['generation'],
                                                  result_handle=job['handle'])
                    self._prune()
                    if job['handle'] in self._receipts:
                        record = self._receipts[job['handle']]
                        record['status'] = copy.deepcopy(status)
                        status = self._public_record(record)
                        record['status'] = copy.deepcopy(status)
                    self._retain(job['key'], status)
                    self._active = None

def read_slow_analysis(value):
    """Use the same dependency-free reader as CORE; malformed slow data is closed."""
    from azazel_nexus.incident_explain import _validate_slow_analysis
    try:
        _validate_slow_analysis(value)
        return copy.deepcopy(value)
    except Exception:
        return {'state':'closed','usage':'unknown'}
