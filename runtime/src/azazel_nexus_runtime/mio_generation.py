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
from .mio_supervisor import StopResult, StopState

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
    permanently. The active job keeps its terminal result independently of
    cleanup; pending work that cannot be sent degrades. Stop confirmation must
    be observed before the original job end, including for legacy jobs.
    Later submits degrade without inference.
    No restart/spawn occurs here. Exact-source repeats and explicit handles poll
    results. Handles retain original bindings for at most sixty seconds (maximum
    configurable TTL: three hundred seconds), with sixteen retained records.
    """
    def __init__(self, *, capability=None, server=None, deadline_s=5.0, result_ttl_s=60.0,
                 budget_enabled=False, output_caps=CAPS, budget_settings=None, journal_dir=None):
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
        self._submission_lock = threading.Lock()
        self._stop_lock = threading.Lock()
        self._fenced = bool(getattr(server, "_nexus_stop_unconfirmed", False) or getattr(server, "_nexus_stop_pending", False))
        self._stopped = bool(getattr(server, "_nexus_stopped", False))
        self._stop_threads = []
        self._infer_threads = []
        self._watcher_threads = []
        self._legacy_cleanup = {'state': 'not_needed', 'reason': None, 'remaining_ms': 0}
        self._pending = None
        self._active = None
        self._worker = None
        self._results = {}
        from .mio_generation_journal import GenerationJournal, new_epoch
        self._epoch = new_epoch()
        self._journal = None
        self._journal_failed = False
        self._restart_records = {}
        if budget_enabled:
            fence_path = getattr(server, '_fence_path', None)
            if journal_dir is None and fence_path is not None:
                journal_dir = fence_path.parent / 'generation-journal'
            if journal_dir is not None:
                try:
                    self._journal = GenerationJournal(journal_dir)
                    for record in self._journal.records.values():
                        self._restart_records[record['handle']] = record['request_id']
                        if not record['fenced']:
                            self._journal.fence(record['request_id'], 'restart_unconfirmed', restart_epoch=self._epoch)
                except (OSError, ValueError, TypeError):
                    self._journal_failed = True

    def _restarted(self, request_id, frame, generation_id):
        from .mio_generation_journal import restored_status
        observation = self._journal.observation(request_id)
        if ('handle' not in observation or observation.get('generation_id') != generation_id
                or observation.get('frame_id') != frame.frame_id):
            return self._status('degraded', frame, generation_id)
        return restored_status(observation.get('terminal'), observation,
                               uncertain=observation['sent_count'] is None)

    def private_observation(self, request_id):
        """Local diagnostics only; never attached to the public receipt."""
        if self._journal is None:
            return {'state': 'unknown', 'reason': 'journal_unavailable'}
        return self._journal.observation(request_id)

    def private_metadata(self, handle, caller_epoch):
        """Non-secret binding on the epoch-only internal transport."""
        from .mio_advisory_manifest import project_sources
        from .mio_generation_journal import unknown_metadata
        with self._lock:
            record = self._receipts.get(handle)
            if (not self.budget_enabled or not record or record.get('epoch') != caller_epoch
                    or record.get('restart_reason') or time.monotonic() >= record['expires']):
                return None
            meta = record['status'].get('generation_budget', {})
            return dict(request_id=record['request_id'], handle=handle, epoch=record['epoch'],
                        frame_id=record['status']['frame_id'], generation_id=record['generation'],
                        created_at=record['created_at'], expires_at=record['expires_at'],
                        template_version=(meta.get('profile') or {}).get('template_version'),
                        unknowns=unknown_metadata(record.get('frame_unknowns', {})),
                        evidence_refs=project_sources(record.get('source_manifest', []), time.time(),
                            record['expires_at'] - record['created_at']),
                        **copy.deepcopy(record.get('manifest', dict(hypothesis_ids=[], advisory_refs=[],
                            completeness='partial', unlisted_prose_ids=False))))

    def _journal_finish(self, job, status, unknowns):
        if self._journal is None:
            return
        try:
            self._journal.finish(job['source']['request_id'], status, unknowns)
        except (OSError, ValueError, KeyError):
            self._journal_failed = True
            self._persist_stop_fence()

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

    def _cancel(self, job, reason, *, defer_legacy_result=False):
        with self._lock:
            if job.get('budget_session') is not None:
                job['reason'] = reason
                job['cancelled'].set()
                return  # budget control worker owns its terminal result
            if 'terminal_status' in job:
                return
            job['reason'] = reason
            job['cancelled'].set()
            if not defer_legacy_result:
                self._finish_legacy(job, reason)
        # stop() is the existing bounded supervisor process-group termination.
        # Do not call it in the fast caller: the worker/timer owns cancellation.

    def _finish_legacy(self, job, state):
        """Latch the result independently of asynchronous stop/fence observations."""
        with self._lock:
            if 'terminal_status' not in job:
                job['terminal_status'] = self._status(state, job['frame'], job['generation'],
                                                       result_handle=job['handle'])
            record = self._receipts.get(job['handle'])
            if record is not None:
                record['status'] = copy.deepcopy(job['terminal_status'])
            return copy.deepcopy(job['terminal_status'])

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
                    self._persist_stop_fence()
            if final is not None:
                meta['cleanup'] = copy.deepcopy(final)
                value['state'],value['generation_budget'] = project_budget(meta)
                value.pop('assistance',None)
        return value

    def poll(self, result_handle, generation_id, trace_id, *, caller_epoch=None):
        """Read one original job, never dispatch or consult embedding admission."""
        stale = {'state': 'stale', 'usage': 'unknown'}
        if not self._authorized(generation_id):
            return stale
        fence_request = None
        with self._lock:
            if self.budget_enabled and type(result_handle) is str and result_handle in self._restart_records:
                from .mio_generation_journal import restored_status
                observation = self._journal.observation(self._restart_records[result_handle])
                if observation.get('generation_id') != generation_id or observation.get('trace_id') != trace_id:
                    return stale
                return restored_status(observation.get('terminal'), observation,
                                       uncertain=observation.get('sent_count') is None)
            self._prune()
            record = self._receipts.get(result_handle) if type(result_handle) is str else None
            if (not record or record['generation'] != generation_id
                    or record['trace'] != trace_id):
                return stale
            if self.budget_enabled and caller_epoch is not None and caller_epoch != record.get('epoch'):
                record['restart_reason'] = 'stale_epoch'
                fence_request = record['request_id']
                for job in (self._active, self._pending):
                    if job and job['handle'] == result_handle:
                        self._cancel(job, 'stale')
            if record.get('restart_reason'):
                from .mio_generation_journal import restored_status
                result = restored_status(record['status'].get('generation_budget'), dict(
                    generation_id=record['generation'], frame_id=record['status']['frame_id'],
                    trace_id=record['trace'], handle=result_handle), uncertain=True)
            else:
                result = self._public_record(record)
        if fence_request is not None and self._journal is not None:
            try:
                self._journal.fence(fence_request, 'stale_epoch', restart_epoch=caller_epoch)
            except (OSError, ValueError):
                self._journal_failed = True
        return result

    def submit(self, source, frame, generation_id, *, upstream_coverage='unknown', upstream_selection=None,
               caller_epoch=None):
        # Serial admission permits durable reservation without holding the
        # control/dispatch lock during disk I/O.
        with self._submission_lock:
            return self._submit(source, frame, generation_id, upstream_coverage=upstream_coverage,
                                upstream_selection=upstream_selection, caller_epoch=caller_epoch)

    def _submit(self, source, frame, generation_id, *, upstream_coverage, upstream_selection, caller_epoch):
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
        if self.budget_enabled and self._journal_failed:
            return self._status('degraded', frame, generation_id)
        if self.budget_enabled and caller_epoch is not None:
            with self._lock:
                other_epoch = next((r for r in self._receipts.values()
                    if r.get('request_id') == source['request_id'] and r.get('epoch') != caller_epoch), None)
            if other_epoch is not None:
                return self.poll(other_epoch['status']['result_handle'], generation_id, frame.trace_id,
                                 caller_epoch=caller_epoch)
        if self.budget_enabled and getattr(frame, 'truncated', False):
            # A rejected revision still invalidates older work for this request.
            # Mark and cancel under the lane lock, but never acquire a session
            # lock here: dispatch and terminal publication take session first.
            pending_receipts = []
            with self._lock:
                for job in (self._active, self._pending):
                    if job and job['source']['request_id'] == source['request_id']:
                        job['rejected_revision_supersession'] = True
                        self._cancel(job, 'superseded')
                        if job is self._pending and job.get('budget_session') is None:
                            pending_receipts.append(job)
                if self._pending and self._pending['cancelled'].is_set():
                    self._pending = None
            for job in pending_receipts:
                # Detached pending work cannot acquire a worker or dispatch.
                from .mio_budget_session import BudgetSession
                from azazel_nexus.generation_budget import project_budget
                session = BudgetSession(self, job, None)
                session.note_failure('cancelled', 'cancelled')
                session.note_failure('superseded', 'cancelled')
                status = session.snapshot('cancelled', 'cancelled')
                meta = status['generation_budget']
                meta['superseded'] = True
                status['state'], status['generation_budget'] = project_budget(meta)
                with self._lock:
                    job['terminal_status'] = status
                    record = self._receipts.get(job['handle'])
                    if record is not None:
                        record['status'] = copy.deepcopy(status)
            return self._decline('degraded',frame,generation_id,'budget_exhausted',upstream_coverage,upstream_selection)
        fingerprint = hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()
        key = (generation_id, fingerprint)
        with self._lock:
            self._prune()
            if self._journal is not None and self._journal.seen(source['request_id']):
                live = next((r for r in self._receipts.values() if r.get('request_id') == source['request_id']), None)
                if live is None or live.get('restart_reason'):
                    return self._restarted(source['request_id'], frame, generation_id)
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
            if self._fenced or self._stopped or self._server_closed():
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
            epoch = caller_epoch if caller_epoch is not None else self._epoch
            submitted = time.monotonic()
            created_at = time.time()
            if self._journal is not None:
                # Exact request IDs are permanent tombstones, even with a changed source.
                if self._journal.seen(source['request_id']):
                    return self._restarted(source['request_id'], frame, generation_id)
                # Other submits are serialized, but timeout/stop/publication
                # can proceed while reservation is fsynced.
                self._lock.release()
                try:
                    self._journal.reserve(source['request_id'], handle, generation_id, frame, epoch, self.result_ttl_s)
                except (OSError, ValueError):
                    return self._status('degraded', frame, generation_id)
                finally:
                    self._lock.acquire()
                if self._fenced or self._stopped or self._server_closed():
                    return self._restarted(source['request_id'], frame, generation_id)
            queued = self._status('queued', frame, generation_id, result_handle=handle)
            self._receipts[handle] = dict(generation=generation_id, trace=frame.trace_id,
                expires=submitted + self.result_ttl_s, end=submitted+self.deadline_s, status=queued,
                request_id=source['request_id'], epoch=epoch,
                created_at=created_at, expires_at=created_at+self.result_ttl_s)
            self._prune()
            self._pending = dict(handle=handle, key=key, source=copy.deepcopy(source), frame=frame,
                                 generation=generation_id, cancelled=threading.Event(), epoch=epoch,
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

    def _server_closed(self):
        return any(getattr(self.server, name, False) for name in
                   ('_nexus_stop_unconfirmed', '_nexus_stop_pending', '_nexus_stopped'))

    def _persist_stop_fence(self):
        self._fenced = True
        if self.server is not None:
            setattr(self.server, '_nexus_stop_unconfirmed', True)
            persist = getattr(self.server, 'fence_stop', None)
            if persist is not None:
                try:
                    persist()
                except OSError:
                    self._fence_write_failed = True

    def stop_observation(self):
        """Local diagnostics, separate from the fixed generation receipt schema."""
        return dict(scope='owned_runtime_group_no_new_session_or_cgroup',
                    fenced=self._fenced,
                    stop_threads_alive=sum(t.is_alive() for t in self._stop_threads),
                    infer_threads_alive=sum(t.is_alive() for t in self._infer_threads),
                    watcher_threads_alive=sum(t.is_alive() for t in self._watcher_threads),
                    worker_alive=self._worker is not None and self._worker.is_alive(),
                    cleanup=copy.deepcopy(self._legacy_cleanup),
                    fence_write_failed=getattr(self, '_fence_write_failed', False))

    def _stop_provider(self, job):
        """Bound the caller's wait; a hung stop retains its thread and fences."""
        with self._stop_lock:
            if self._fenced:
                return False
            if job.get('stopped'):
                return True
            setattr(self.server, '_nexus_stop_pending', True)
            self._legacy_cleanup = dict(state='pending', reason=None,
                remaining_ms=max(0, int((job['end'] - time.monotonic()) * 1000)))
            result = []
            def stop():
                try:
                    stopped = self.server.stop()
                except Exception:
                    stopped = None
                result.append((stopped, time.monotonic()))
            worker = threading.Thread(target=stop, daemon=True, name='mio-provider-stop')
            self._stop_threads.append(worker)
            worker.start()
            worker.join(timeout=max(0, job.get('end', time.monotonic()) - time.monotonic()))
            with self._lock:
                # Even a completed zero-time join cannot confirm after E. Both
                # completion and its publication must be strictly before E.
                late = time.monotonic() >= job['end'] or (result and result[0][1] >= job['end'])
                if (self._fenced or late or worker.is_alive() or not result
                        or not isinstance(result[0][0], StopResult)
                        or result[0][0].state is not StopState.CONFIRMED):
                    job['stop_thread_alive'] = worker.is_alive()
                    self._fence(job, reason='confirmation_deadline' if late else 'stop_failed')
                    return False
                job['stopped'] = True
                self._legacy_cleanup = dict(state='confirmed', reason='stop_confirmed', remaining_ms=0)
                setattr(self.server, '_nexus_stopped', True)
                setattr(self.server, '_nexus_stop_pending', False)
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

    def _fence(self, job, *, reason='stop_failed'):
        """Record unconfirmed cleanup without changing the active terminal result."""
        with self._lock:
            self._persist_stop_fence()
            job['stop_failed'] = True
            if self._legacy_cleanup['state'] != 'unconfirmed':
                self._legacy_cleanup = dict(state='unconfirmed', reason=reason, remaining_ms=0)
            state = (job['reason'] if job['cancelled'].is_set() else
                     'timeout' if time.monotonic() >= job['end'] else 'degraded')
            self._finish_legacy(job, state)
            pending, self._pending = self._pending, None
            if pending is not None:
                self._retain(pending['key'], self._finish_legacy(pending, 'degraded'))

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
        if self._fenced or self._stopped or self._server_closed():
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
                    deadline_cancel = not job['cancelled'].is_set()
                    if deadline_cancel:
                        # Do not expose timeout before the in-flight stop has
                        # been classified at its confirmation deadline.
                        self._cancel(job, 'timeout', defer_legacy_result=True)
                    # The transport checks cancel/deadline under this gate before it
                    # marks a request in flight, so no request can begin after this read.
                    with state['gate']:
                        in_flight = state['in_flight']
                    if in_flight:
                        self._stop_provider(job)
                    if deadline_cancel:
                        self._finish_legacy(job, 'timeout')
                    return
        watcher = threading.Thread(target=watch, daemon=True, name='mio-generation-deadline')
        self._watcher_threads = [t for t in self._watcher_threads if t.is_alive()] + [watcher]
        watcher.start()
        transport = StructuredGenerationTransport(self.server, self.capability,
            deadline=job['end'], cancelled=job['cancelled'],
            check=lambda: self._authorized(job['generation'])
                           and not (self._fenced or self._stopped or self._server_closed()),
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
            watcher.join(timeout=max(0, job['end'] - time.monotonic()))
            if watcher.is_alive():
                job['watcher_alive'] = True
                self._fence(job, reason='confirmation_deadline')
        if job['cancelled'].is_set() or time.monotonic() >= job['end']:
            self._finish_legacy(job, job['reason'] if job['cancelled'].is_set() else 'timeout')
        # Only a transport/provider failure stops the provider here; content failures do not.
        if transport.failed and not self._fenced:
            self._stop_provider(job)
            self._finish_legacy(job, 'degraded')
        return copy.deepcopy(job.get('terminal_status', status))

    def _update_budget_cleanup(self, job, state, reason):
        session = job['budget_session']
        with session.lock:
            if session.cleanup['state'] != 'pending':
                return
            # The stop worker can be delayed acquiring this lock after its
            # initial deadline check. Confirmation is decided at publication,
            # still against the original job end.
            if state == 'confirmed' and time.monotonic() >= job['end']:
                state, reason = 'unconfirmed', 'confirmation_deadline'
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
                self._persist_stop_fence()
            if status is not None:
                record = self._receipts.get(job['handle'])
                if record is not None:
                    record['status'] = copy.deepcopy(status)
                    status = self._public_record(record)
                    record['status'] = copy.deepcopy(status)
                self._retain(job['key'], copy.deepcopy(status))
        if status is not None:
            self._journal_finish(job, status, session.frame_unknowns)

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
        try:
            setattr(self.server, '_nexus_stop_pending', True)
        except Exception:
            self._update_budget_cleanup(job, 'unconfirmed', 'stop_failed')
            return
        def stop():
            try:
                result = self.server.stop()
            except Exception:
                self._update_budget_cleanup(job, 'unconfirmed', 'stop_failed')
            else:
                if not isinstance(result, StopResult) or result.state is not StopState.CONFIRMED:
                    self._update_budget_cleanup(job, 'unconfirmed', 'stop_failed')
                    return
                # Socket teardown wakes infer asynchronously. Wait only to the
                # original E; a lingering infer thread never confirms cleanup.
                session.done.wait(max(0, job['end'] - time.monotonic()))
                infer = job.get('infer_thread')
                if infer is not None:
                    infer.join(timeout=max(0, job['end'] - time.monotonic()))
                if (session.done.is_set() and (infer is None or not infer.is_alive())
                        and time.monotonic() < job['end']):
                    setattr(self.server, '_nexus_stopped', True)
                    setattr(self.server, '_nexus_stop_pending', False)
                    self._update_budget_cleanup(job, 'confirmed', 'stop_confirmed')
                else:
                    self._update_budget_cleanup(job, 'unconfirmed', 'confirmation_deadline')
        worker = threading.Thread(target=stop, daemon=True, name='mio-budget-stop')
        self._stop_threads.append(worker)
        worker.start()
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
            if job.get('rejected_revision_supersession'):
                session.note_failure('cancelled', 'cancelled')
            session.note_failure(job['reason'],job['reason'])
            session.done.set()
        elif time.monotonic() >= job['end']:
            session.note_failure('timeout','deadline_exceeded')
            session.done.set()
        elif self._stopped or self._fenced or self._server_closed():
            session.note_failure('model_unavailable','model_unavailable')
            session.done.set()
        else:
            infer = threading.Thread(target=work, daemon=True, name='mio-budget-infer')
            job['infer_thread'] = infer
            self._infer_threads = [t for t in self._infer_threads if t.is_alive()] + [infer]
            infer.start()
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
                    if job.get('rejected_revision_supersession'):
                        session.note_failure('cancelled', 'cancelled')
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
                    elif 'terminal_status' in job:
                        status = copy.deepcopy(job['terminal_status'])
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
                        if session is not None:
                            record['frame_unknowns'] = copy.deepcopy(session.frame_unknowns)
                            record['unknown_origins'] = copy.deepcopy(session.unknown_origins)
                            record['manifest'] = copy.deepcopy(session.manifest)
                            record['source_manifest'] = copy.deepcopy(session.source_manifest)
                        record['status'] = copy.deepcopy(status)
                        status = self._public_record(record)
                        record['status'] = copy.deepcopy(status)
                    self._retain(job['key'], status)
                    self._active = None
            if session is not None:
                self._journal_finish(job, status, session.frame_unknowns)

def read_slow_analysis(value):
    """Use the same dependency-free reader as CORE; malformed slow data is closed."""
    from azazel_nexus.incident_explain import validate_slow_analysis
    try:
        validate_slow_analysis(value)
        return copy.deepcopy(value)
    except Exception:
        return {'state':'closed','usage':'unknown'}
