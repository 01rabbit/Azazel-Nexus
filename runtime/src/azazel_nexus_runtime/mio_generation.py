"""Closed generation seam. Production has no generation admission loader yet.

Only a future independently authenticated generation loader may mint the sealed
capability. Embedding evidence is never a substitute. No process is started here.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
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


class StructuredGenerationTransport:
    """Product-owned bounded AF_UNIX server -> MIO StructuredTransport."""
    def __init__(self, server, capability, *, deadline, cancelled, check):
        self.server, self.capability = server, capability
        self.deadline, self.cancelled, self.check = deadline, cancelled, check
        self.last_model = capability.model_id
        self.calls = []
        self.failed = False

    def __call__(self, task, prompt):
        from azazel_mio.model_adapter import MioModelBlocked, MioModelUnavailable
        from azazel_mio.model_schema import model_response_schema
        from .mio_serve import LocalInferenceRequest
        remaining = self.deadline - time.monotonic()
        if self.cancelled.is_set() or remaining <= 0 or not self.check():
            raise MioModelBlocked('generation_closed')
        try:
            result = self.server.infer(LocalInferenceRequest(
                (('user', prompt),), max_tokens=768,
                response_format={'type': 'json_schema', 'json_schema': {
                    'name': task, 'strict': True, 'schema': model_response_schema(task)}}),
                deadline_s=remaining, allow_unknown_usage=True)
            if self.cancelled.is_set() or time.monotonic() >= self.deadline or not self.check():
                raise MioModelBlocked('generation_stale')
            usage = None
            if (type(result.tokens_in) is int and result.tokens_in >= 0
                    and type(result.tokens_out) is int and result.tokens_out >= 0):
                usage = {'tokens_in': result.tokens_in, 'tokens_out': result.tokens_out}
            timings = {k: v for k, v in result.timings.items()
                       if type(v) in (int, float) and math.isfinite(v) and v >= 0}
            self.calls.append({'usage': usage, 'timings': timings})
            value = json.loads(result.text)
            if type(value) is not dict:
                raise ValueError
            return value
        except MioModelBlocked:
            raise
        except Exception:
            self.failed = True
            raise MioModelUnavailable('generation_unavailable') from None


class GenerationLane:
    """One worker, one pending request, sixteen retained bounded results.

    Superseding an active request stops its owned provider, bounding work as
    well as publication. The loader must replace a stopped server explicitly.
    No restart/spawn occurs here. A repeat of the exact source polls its result.
    """
    def __init__(self, *, capability=None, server=None, deadline_s=5.0):
        if type(deadline_s) not in (int, float) or not math.isfinite(deadline_s) or not 0 < deadline_s <= 30:
            raise ValueError('invalid_generation_deadline')
        self.capability, self.server, self.deadline_s = capability, server, deadline_s
        self._lock = threading.RLock()
        self._stop_lock = threading.Lock()
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
        # stop() is the existing bounded supervisor process-group termination.
        # Do not call it in the fast caller: the worker/timer owns cancellation.

    def submit(self, source, frame, generation_id):
        if not self._authorized(generation_id):
            return self._status('closed', frame, generation_id)
        if self.server is None:
            return self._status('degraded', frame, generation_id)
        fingerprint = hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()
        key = (generation_id, fingerprint)
        with self._lock:
            if key in self._results:
                return copy.deepcopy(self._results[key])
            for job in (self._active, self._pending):
                if job and job['key'] == key:
                    return self._status('queued', job['frame'], generation_id)
            # A new revision of the same caller request supersedes its old work.
            for job in (self._active, self._pending):
                if job and job['source']['request_id'] == source['request_id']:
                    self._cancel(job, 'superseded')
            if self._pending and self._pending['cancelled'].is_set():
                self._pending = None
            if self._pending is not None:
                return self._status('queue_full', frame, generation_id)
            self._pending = dict(key=key, source=copy.deepcopy(source), frame=frame,
                                 generation=generation_id, cancelled=threading.Event(),
                                 end=time.monotonic() + self.deadline_s, reason='cancelled')
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(target=self._run, daemon=True,
                                                name='mio-generation')
                self._worker.start()
            return self._status('queued', frame, generation_id)

    def cancel(self):
        with self._lock:
            for job in (self._active, self._pending):
                if job:
                    self._cancel(job, 'cancelled')

    def _stop_provider(self):
        with self._stop_lock:
            self.server.stop()

    def _run(self):
        from azazel_mio import AssistantCore
        while True:
            with self._lock:
                job, self._pending = self._pending, None
                self._active = job
                if job is None:
                    self._worker = None
                    return
            timer_stop = threading.Event()
            def watch(job=job, timer_stop=timer_stop):
                while not timer_stop.wait(.01):
                    if job['cancelled'].is_set() or time.monotonic() >= job['end']:
                        if not job['cancelled'].is_set():
                            self._cancel(job, 'timeout')
                        self._stop_provider()
                        return
            watcher = threading.Thread(target=watch, daemon=True, name='mio-generation-deadline')
            watcher.start()
            transport = StructuredGenerationTransport(self.server, self.capability,
                deadline=job['end'], cancelled=job['cancelled'],
                check=lambda: self._authorized(job['generation']))
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
                watcher.join(timeout=.1)
            if (transport.failed or job['cancelled'].is_set()
                    or time.monotonic() >= job['end']):
                self._stop_provider()
            if job['cancelled'].is_set() or time.monotonic() >= job['end']:
                status = self._status(job['reason'] if job['cancelled'].is_set() else 'timeout',
                                      job['frame'], job['generation'])
            with self._lock:
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
                                 'assistance', 'calls', 'origin'}
                or value['state'] not in {'closed', 'degraded', 'queued', 'queue_full',
                                          'complete', 'timeout', 'cancelled', 'superseded'}
                or value['usage'] not in {'known', 'unknown'}):
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
