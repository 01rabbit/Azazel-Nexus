"""Closed generation seam. Production has no generation admission loader yet.

Only a future independently authenticated generation loader may mint the sealed
capability. Embedding evidence is never a substitute. No process is started here.
"""
from __future__ import annotations

import copy
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
                (('user', prompt),), max_tokens=768,
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
                               parse_float=_finite_json_float)
        except (TypeError, ValueError, RecursionError):
            raise MioModelUnavailable('generation_content_invalid') from None
        if type(value) is not dict:
            raise MioModelUnavailable('generation_content_invalid')
        return value


class GenerationLane:
    """One worker, one pending request, sixteen retained bounded results.

    The provider is stopped only when a request is in flight (supersession,
    cancel, deadline, or transport failure), bounding work as well as
    publication; an idle provider is kept on supersession. The loader must
    replace a stopped server explicitly. If stop() raises, termination is
    unconfirmed: the lane fences the server permanently, reports degraded
    (never timeout/cancelled), and later submits degrade without inference.
    No restart/spawn occurs here. Exact-source repeats and explicit handles poll
    results. Handles retain original bindings for at most sixty seconds (maximum
    configurable TTL: three hundred seconds), with sixteen retained records.
    """
    def __init__(self, *, capability=None, server=None, deadline_s=5.0, result_ttl_s=60.0):
        if type(deadline_s) not in (int, float) or not math.isfinite(deadline_s) or not 0 < deadline_s <= 30:
            raise ValueError('invalid_generation_deadline')
        if type(result_ttl_s) not in (int, float) or not math.isfinite(result_ttl_s) or not 0 < result_ttl_s <= 300:
            raise ValueError('invalid_result_ttl')
        self.result_ttl_s = result_ttl_s
        self._receipts = {}
        self.capability, self.server, self.deadline_s = capability, server, deadline_s
        self._lock = threading.RLock()
        self._stop_lock = threading.Lock()
        self._fenced = False  # set permanently when provider stop() raises
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

    def _cancel(self, job, reason):
        job['cancelled'].set()
        job['reason'] = reason
        with self._lock:
            record = self._receipts.get(job['handle'])
            # A fenced lane's degraded receipts are final; never rewrite them.
            if record and not self._fenced:
                record['status'] = self._status(reason, job['frame'], job['generation'],
                                                 result_handle=job['handle'])
        # stop() is the existing bounded supervisor process-group termination.
        # Do not call it in the fast caller: the worker/timer owns cancellation.

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
            return copy.deepcopy(record['status'])

    def submit(self, source, frame, generation_id):
        if not self._authorized(generation_id):
            return self._status('closed', frame, generation_id)
        if self.server is None or self._fenced:
            return self._status('degraded', frame, generation_id)
        fingerprint = hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()
        key = (generation_id, fingerprint)
        with self._lock:
            # _fence() sets the flag under this lock: recheck so a fence that landed
            # after the unlocked fast path above can never admit a new receipt/pending.
            if self._fenced:
                return self._status('degraded', frame, generation_id)
            self._prune()
            if key in self._results:
                return copy.deepcopy(self._results[key])
            for job in (self._active, self._pending):
                if job and job['key'] == key:
                    return self._status('queued', job['frame'], generation_id, result_handle=job['handle'])
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
            self._receipts[handle] = dict(generation=generation_id, trace=frame.trace_id,
                expires=time.monotonic() + self.result_ttl_s, status=queued)
            self._prune()
            self._pending = dict(handle=handle, key=key, source=copy.deepcopy(source), frame=frame,
                                 generation=generation_id, cancelled=threading.Event(),
                                 end=time.monotonic() + self.deadline_s, reason='cancelled')
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
        return True

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

    def _execute(self, job):
        """Run one job. The provider is stopped only while one of its requests is in flight."""
        from azazel_mio import AssistantCore
        if self._fenced:
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
            check=lambda: self._authorized(job['generation']) and not self._fenced,
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
            with self._lock:
                status['result_handle'] = job['handle']
                # Retained output has the same hard byte/schema bound as the wire reader.
                if read_slow_analysis(status).get('state') == 'closed' and status['state'] != 'closed':
                    status = self._status('degraded', job['frame'], job['generation'],
                                          result_handle=job['handle'])
                self._prune()
                if job['handle'] in self._receipts:
                    self._receipts[job['handle']]['status'] = copy.deepcopy(status)
                self._results[job['key']] = status
                while len(self._results) > 16:
                    del self._results[next(iter(self._results))]
                self._active = None


def read_slow_analysis(value):
    """Fail closed on malformed advisory metadata without losing the fast result."""
    closed = {'state': 'closed', 'usage': 'unknown'}
    try:
        if (type(value) is not dict or len(json.dumps(value, allow_nan=False).encode()) > 128 * 1024
                or set(value) - {'state', 'usage', 'generation_id', 'frame_id', 'trace_id',
                                 'assistance', 'calls', 'origin', 'result_handle'}
                or value['state'] not in {'closed', 'degraded', 'queued', 'queue_full',
                                          'complete', 'timeout', 'cancelled', 'superseded', 'stale'}
                or value['usage'] not in {'known', 'unknown'}):
            return closed
        if 'result_handle' in value and (type(value['result_handle']) is not str
                or re.fullmatch(r'[0-9a-f]{64}', value['result_handle']) is None):
            return closed
        if 'assistance' in value:
            result = value['assistance']
            if (type(result) is not dict or result.get('schema_version') != 'mio.assistance.v1'
                    or result.get('frame_id') != value['frame_id']
                    or result.get('trace_id') != value['trace_id']
                    or value['frame_id'] != value['trace_id'] + ':frame'
                    or result.get('generation_method') not in {'model', 'static_reference'}):
                return closed
        calls = value.get('calls', [])
        if type(calls) is not list or len(calls) > 16:
            return closed
        for call in calls:
            if type(call) is not dict or set(call) != {'usage', 'timings'}:
                return closed
            if call['usage'] is not None and (type(call['usage']) is not dict
                    or set(call['usage']) != {'tokens_in', 'tokens_out'}
                    or any(type(v) is not int or v < 0 for v in call['usage'].values())):
                return closed
            if type(call['timings']) is not dict or any(type(v) not in (int, float)
                    or not math.isfinite(v) or v < 0 for v in call['timings'].values()):
                return closed
        if value['usage'] == 'known' and (not calls or any(c['usage'] is None for c in calls)):
            return closed
        return copy.deepcopy(value)
    except Exception:
        return closed
