"""Private, body-free write-ahead receipts for a single runtime owner.

Files are permanent request tombstones, independent of the result cache TTL.
Atomic replacement appends observations to a request's logical journal. A torn
temporary file is itself a reference: it must never turn into a fresh request.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import threading
import time

from azazel_nexus.generation_budget import TASKS, read_budget, project_budget

VERSION = 1
MAX_BYTES = 256 * 1024
IDENTIFIER = re.compile(r'[A-Za-z0-9._:@+-]{1,128}')
HEX = re.compile(r'[0-9a-f]{64}')
POLICIES = {'unknown', 'nexus-frame-v1', 'nexus-frame-v2', 'fixture-v1',
            'transport-fixture-v1', '1.6.0', '1.7.0', '1.8.0', '1.9.0'}


def new_epoch():
    return f'{time.time_ns():x}-{secrets.token_hex(16)}'


def request_key(request_id):
    if type(request_id) is not str or not IDENTIFIER.fullmatch(request_id):
        raise ValueError('journal_request_refused')
    return hashlib.sha256(request_id.encode()).hexdigest()


def unknown_metadata(mapping):
    """Inspect IDs only. Never inspect, redact, hash or serialize their bodies."""
    result = []
    for ident in mapping:
        if type(ident) is not str:
            continue
        if re.fullmatch(r'u[1-9][0-9]{0,2}', ident):
            origin, category = 'frame', 'frame_unknown'
        elif re.fullmatch(r'um:[1-9][0-9]{0,2}', ident):
            origin, category = 'model_asserted', 'model_unknown'
        elif ident in {'ux:identity', 'ux:success', 'ux:baseline', 'ux:impact'}:
            origin, category = 'fixed_projection', ident[3:]
        else:
            continue
        result.append(dict(id=ident, origin=origin, category=category, status='unresolved'))
    return result


def private_status(status):
    """Closed accounting metadata only; no assistance, calls/timing keys or prose."""
    meta = read_budget(status['generation_budget'], state=status['state'], usage=status['usage'])
    for selection in [meta['upstream_selection'], *(t['selection'] for t in meta['tasks'])]:
        if selection['policy_version'] not in POLICIES:
            raise ValueError('journal_policy_refused')
    return meta


def restored_status(meta, binding, *, uncertain=False):
    """Keep primary/terminal failures, never restore model content as complete."""
    value = dict(state='degraded', usage='unknown', generation_id=binding['generation_id'],
                 frame_id=binding['frame_id'], trace_id=binding['trace_id'],
                 result_handle=binding['handle'])
    if meta is None:
        # There is no truthful sent/unsent boolean for an unacknowledged intent.
        # Do not fabricate a public dispatch count; private state says unknown.
        return value
    meta = copy.deepcopy(meta)
    if meta['result_state'] == 'complete':
        meta.update(result_state='degraded', core_complete=False, terminal_outcome='stop_unconfirmed')
        uncertain = True
    if uncertain or meta['cleanup']['state'] == 'pending':
        meta['cleanup'] = dict(state='unconfirmed', reason='restart_unconfirmed', remaining_ms=0)
    value['state'], meta = project_budget(meta)
    value.update(budget_version=1, generation_budget=meta,
                 calls=[dict(usage=t['actual_usage'], timings={}) for t in meta['tasks'] if t['dispatched']])
    if value['calls'] and all(c['usage'] is not None for c in value['calls']):
        value['usage'] = 'known'
    read_budget(meta, state=value['state'], usage=value['usage'])
    return value


class GenerationJournal:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.lock = threading.RLock()
        self.records = {}
        self.invalid = set()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._sync(self.directory.parent)
        self._load()

    @staticmethod
    def _sync(path):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _validate(self, value, key):
        required = {'journal_version', 'request_id', 'handle', 'generation_id', 'frame_id',
                    'trace_id', 'epoch', 'template_version', 'created_at', 'expires_at',
                    'intents', 'outcomes', 'terminal', 'unknowns', 'fenced', 'restart_reason', 'restart_epoch'}
        if type(value) is not dict or set(value) != required:
            raise ValueError('journal_fields')
        if type(value['journal_version']) is not int or value['journal_version'] != VERSION:
            raise ValueError('journal_version')
        if request_key(value['request_id']) != key or not HEX.fullmatch(value['handle']):
            raise ValueError('journal_binding')
        for field in ('generation_id', 'frame_id', 'trace_id', 'epoch'):
            if type(value[field]) is not str or not IDENTIFIER.fullmatch(value[field]):
                raise ValueError('journal_identifier')
        if value['frame_id'] != value['trace_id'] + ':frame' or value['template_version'] not in POLICIES:
            raise ValueError('journal_binding')
        incident = re.fullmatch(r'inc-([0-9a-f]{16}):([1-9][0-9]{0,11})', value['request_id'])
        if incident and value['trace_id'] != f'mio-{incident[1]}-{incident[2]}':
            raise ValueError('journal_request_frame')
        if any(type(value[k]) not in (float, int) or not math.isfinite(value[k]) or value[k] < 0
               for k in ('created_at', 'expires_at')) or value['expires_at'] <= value['created_at']:
            raise ValueError('journal_time')
        if type(value['fenced']) is not bool or value['restart_reason'] not in (None, 'restart_unconfirmed', 'stale_epoch', 'journal_failed'):
            raise ValueError('journal_fence')
        if value['fenced'] != (value['restart_reason'] is not None):
            raise ValueError('journal_fence_binding')
        if value['restart_epoch'] is not None and (type(value['restart_epoch']) is not str
                or not IDENTIFIER.fullmatch(value['restart_epoch'])):
            raise ValueError('journal_restart_epoch')
        if type(value['unknowns']) is not list or len(value['unknowns']) > 2048:
            raise ValueError('journal_unknowns')
        expected = unknown_metadata([u['id'] for u in value['unknowns']])
        if expected != value['unknowns'] or len({u['id'] for u in expected}) != len(expected):
            raise ValueError('journal_unknowns')
        if type(value['intents']) is not list or len(value['intents']) > 3 or type(value['outcomes']) is not list:
            raise ValueError('journal_intents')
        for seq, intent in enumerate(value['intents'], 1):
            if set(intent) != {'journal_version', 'request_id', 'handle', 'task', 'seq', 'epoch', 'template_version', 'created_at'}:
                raise ValueError('journal_intent_fields')
            if any(intent[k] != value[k] for k in ('journal_version', 'request_id', 'handle', 'epoch', 'template_version')):
                raise ValueError('journal_intent_binding')
            if type(intent['seq']) is not int or intent['seq'] != seq or intent['task'] != TASKS[seq-1]:
                raise ValueError('journal_sequence')
            if type(intent['created_at']) not in (int, float) or not math.isfinite(intent['created_at']) or intent['created_at'] < value['created_at']:
                raise ValueError('journal_time')
        if len(value['outcomes']) > len(value['intents']):
            raise ValueError('journal_outcome_count')
        for seq, outcome in enumerate(value['outcomes'], 1):
            if (set(outcome) != {'seq', 'request_id', 'handle', 'received', 'sent_count'}
                    or type(outcome['seq']) is not int or type(outcome['sent_count']) is not int
                    or outcome['received'] is not True or outcome != dict(
                    seq=seq, request_id=value['request_id'], handle=value['handle'], received=True, sent_count=seq)):
                raise ValueError('journal_outcome_binding')
        if value['terminal'] is not None:
            # The public reader accepts this accounting without model text.
            meta = value['terminal']
            state = project_budget(meta)[0]
            private_status(dict(generation_budget=meta, state=state,
                                usage='known' if state == 'complete' else 'unknown'))
            if not len(value['outcomes']) <= meta['job_calls'] <= len(value['intents']):
                raise ValueError('journal_dispatch_binding')
        return value

    def _load(self):
        for path in self.directory.iterdir():
            key = path.name.split('.')[0]
            if not HEX.fullmatch(key):
                continue
            if path.name != key + '.json':
                self.invalid.add(key)  # partial write is a durable reference
                continue
            try:
                if path.stat().st_size > MAX_BYTES:
                    raise ValueError('journal_size')
                from .mio_generation import _unique_json_object, _reject_json_constant
                raw = json.loads(path.read_text(), object_pairs_hook=_unique_json_object,
                                 parse_constant=_reject_json_constant)
                self.records[key] = self._validate(raw, key)
            except (OSError, ValueError, TypeError, KeyError, RecursionError):
                self.invalid.add(key)

    def _write(self, key, value):
        self._validate(value, key)
        data = json.dumps(value, allow_nan=False, sort_keys=True).encode()
        if len(data) > MAX_BYTES:
            raise ValueError('journal_size')
        path = self.directory / (key + '.json')
        tmp = self.directory / (key + '.' + secrets.token_hex(8) + '.pending')
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
            self._sync(self.directory)
        except (OSError, ValueError):
            self.invalid.add(key)
            raise
        self.records[key] = copy.deepcopy(value)

    def seen(self, request_id):
        key = request_key(request_id)
        return key in self.records or key in self.invalid

    def reserve(self, request_id, handle, generation_id, frame, epoch, ttl):
        key = request_key(request_id)
        with self.lock:
            if self.seen(request_id):
                raise ValueError('journal_request_exists')
            now = time.time()
            value = dict(journal_version=VERSION, request_id=request_id, handle=handle,
                         generation_id=generation_id, frame_id=frame.frame_id, trace_id=frame.trace_id,
                         epoch=epoch, template_version='unknown', created_at=now, expires_at=now+ttl,
                         intents=[], outcomes=[], terminal=None, unknowns=unknown_metadata(
                             {f'u{i}' for i, _ in enumerate(getattr(frame, 'unknowns', ()), 1)}),
                         fenced=False, restart_reason=None, restart_epoch=None)
            self._write(key, value)

    def intent(self, request_id, task, template_version='unknown'):
        key = request_key(request_id)
        with self.lock:
            if key in self.invalid:
                raise ValueError('journal_invalid')
            value = copy.deepcopy(self.records[key])
            if value['terminal'] is not None or value['fenced']:
                raise ValueError('journal_closed')
            seq = len(value['intents']) + 1
            if len(value['outcomes']) != seq-1:
                raise ValueError('journal_unconfirmed')
            if seq == 1:
                value['template_version'] = template_version
            elif template_version != value['template_version']:
                raise ValueError('journal_template_changed')
            value['intents'].append(dict(journal_version=VERSION, request_id=request_id,
                handle=value['handle'], task=task, seq=seq, epoch=value['epoch'],
                template_version=value['template_version'], created_at=time.time()))
            self._write(key, value)

    def received(self, request_id):
        key = request_key(request_id)
        with self.lock:
            value = copy.deepcopy(self.records[key])
            if key in self.invalid or value['fenced']:
                raise ValueError('journal_closed')
            seq = len(value['intents'])
            if seq != len(value['outcomes']) + 1:
                raise ValueError('journal_sequence')
            value['outcomes'].append(dict(seq=seq, request_id=request_id, handle=value['handle'], received=True, sent_count=seq))
            self._write(key, value)

    def finish(self, request_id, status, unknowns):
        key = request_key(request_id)
        with self.lock:
            if key in self.invalid:
                raise ValueError('journal_invalid')
            value = copy.deepcopy(self.records[key])
            if value['fenced']:
                return  # stale epoch or recovery is permanent, even after late infer
            meta = private_status(status)
            if value['terminal'] is not None:
                # Only a pending cleanup observation may evolve; result is latched.
                previous = value['terminal']
                if previous['cleanup']['state'] != 'pending':
                    return
                meta = copy.deepcopy(previous)
                meta['cleanup'] = copy.deepcopy(status['generation_budget']['cleanup'])
                _, meta = project_budget(meta)
            value['terminal'] = meta
            value['unknowns'] = unknown_metadata(unknowns) or value['unknowns']
            self._write(key, value)

    def remember_unknowns(self, request_id, identifiers):
        """Explainer's epoch sidecar mirrors identifiers, never result bodies."""
        key = request_key(request_id)
        with self.lock:
            if key in self.invalid:
                raise ValueError('journal_invalid')
            value = copy.deepcopy(self.records[key])
            if value['fenced']:
                return
            value['unknowns'] = unknown_metadata(identifiers)
            self._write(key, value)

    def fence(self, request_id, reason, *, restart_epoch=None):
        key = request_key(request_id)
        with self.lock:
            value = copy.deepcopy(self.records[key])
            if value['fenced']:
                return
            value.update(fenced=True, restart_reason=reason, restart_epoch=restart_epoch)
            self._write(key, value)

    def observation(self, request_id):
        key = request_key(request_id)
        # Writers replace whole immutable snapshots only after fsync. Reading
        # one published snapshot must not block timeout/poll on a disk write.
        value = copy.deepcopy(self.records.get(key))
        if key in self.invalid or value is None:
            return dict(state='unknown', reason='journal_invalid', fenced=True,
                        sent_count=None, unknowns=[])
        value.update(state='unknown', reason=value['restart_reason'] or 'restart_unconfirmed',
                     fenced=True, sent_count=(len(value['outcomes']) if len(value['outcomes']) == len(value['intents']) else None))
        for item in value['unknowns']:
            item['status'] = 'unavailable_after_restart'
        return value
