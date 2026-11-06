"""Dependency-free generation receipt rules, shared by runtime and CORE readers."""
from __future__ import annotations
import copy
import json
import math

TASKS = ('generate_hypotheses', 'identify_evidence_gaps', 'recommend')
# Fixture limits reserve the full schema output allowance; they are not HG evidence.
CAPS = (768, 384, 512)
COVERAGES = ('intact', 'selected', 'unknown')
OUTCOMES = frozenset({'within_budget', 'budget_exhausted', 'token_count_unknown',
    'runtime_truncated', 'truncation_unknown', 'output_incomplete', 'token_usage_unknown',
    'output_invalid', 'deadline_exceeded', 'stop_unconfirmed', 'admission_closed',
    'provider_unavailable', 'model_unavailable', 'cancelled', 'superseded', 'stale'})
REASONS = OUTCOMES | {'count_unknown', 'truncated', 'timeout', 'malformed', 'task_plan_unsupported'}
CLEANUP_REASONS = {'stop_confirmed', 'stop_failed', 'confirmation_deadline',
                   'observation_lost', 'restart_unconfirmed'}


def integer(v):
    return type(v) is int and v >= 0


def number(v):
    return type(v) in (int, float) and math.isfinite(v) and v >= 0


def coverage(upstream, tasks):
    values = [upstream] + [task['selection']['coverage'] for task in tasks]
    if len(tasks) != 3 or any(v not in COVERAGES for v in values):
        return 'unknown'
    return max(values, key=COVERAGES.index)


def selection_unknown():
    return {'policy_version': 'unknown', 'coverage': 'unknown', 'input_units': 0,
            'selected_units': 0, 'omitted_units': 0, 'omissions': []}


def task_placeholder(task):
    return dict(task=task, dispatched=False, count_kind='unknown', input_tokens_bound=None,
        input_limit=None, output_tokens_cap=None, output_min=None, context_limit=None,
        context_slack=None, allocated_ms=None, elapsed_ms=0, actual_usage=None,
        finish_reason=None, context_integrity='unknown', validated=False,
        selection=selection_unknown())


def validate_selection(s):
    if (type(s) is not dict or set(s) != {'policy_version', 'coverage', 'input_units',
            'selected_units', 'omitted_units', 'omissions'}
            or type(s['policy_version']) is not str or not 0 < len(s['policy_version']) <= 64
            or s['coverage'] not in COVERAGES
            or any(not integer(s[k]) or s[k] > 4096 for k in ('input_units', 'selected_units', 'omitted_units'))
            or s['selected_units'] + s['omitted_units'] != s['input_units']
            or type(s['omissions']) is not list or len(s['omissions']) != s['omitted_units']):
        raise ValueError('generation_selection_refused')
    seen = set()
    for item in s['omissions']:
        if (type(item) is not dict or set(item) != {'kind', 'ordinal', 'reason'}
                or item['kind'] not in {'semantic_unit', 'projection'}
                or not integer(item['ordinal']) or item['ordinal'] >= s['input_units']
                or item['ordinal'] in seen
                or item['reason'] not in {'duplicate', 'optional_detail', 'lower_priority', 'upstream_projection'}):
            raise ValueError('generation_selection_refused')
        seen.add(item['ordinal'])
    if s['coverage'] == 'intact' and s['omitted_units']:
        raise ValueError('generation_selection_refused')
    return s


def read_budget(value, *, state=None, usage=None):
    try:
        keys = {'version','profile_id','outcome','reasons','coverage','upstream_coverage',
                'elapsed_ms','deadline_ms','result_state','primary_outcome','superseded',
                'cleanup','job_calls','tasks','core_complete','upstream_selection'}
        if (type(value) is not dict or set(value) != keys or type(value['version']) is not int
                or value['version'] != 1 or value['profile_id'] != 'fixture-v1'
                or value['outcome'] not in OUTCOMES or value['primary_outcome'] not in OUTCOMES
                or value['result_state'] not in {'complete','degraded','timeout','cancelled','superseded','closed','stale'}
                or type(value['superseded']) is not bool or type(value['core_complete']) is not bool
                or type(value['reasons']) is not list or len(value['reasons']) > 16
                or len(set(value['reasons'])) != len(value['reasons'])
                or any(r not in REASONS for r in value['reasons'])
                or value['coverage'] not in COVERAGES or value['upstream_coverage'] not in COVERAGES
                or not number(value['elapsed_ms']) or not number(value['deadline_ms'])
                or not 0 < value['deadline_ms'] <= 30000 or not integer(value['job_calls'])
                or type(value['tasks']) is not list or len(value['tasks']) != 3):
            raise ValueError
        validate_selection(value['upstream_selection'])
        if value['upstream_selection']['coverage'] != value['upstream_coverage']:
            raise ValueError
        cleanup = value['cleanup']
        if (type(cleanup) is not dict or set(cleanup) != {'state','reason','remaining_ms'}
                or cleanup['state'] not in {'not_needed','pending','confirmed','unconfirmed'}
                or not integer(cleanup['remaining_ms']) or cleanup['remaining_ms'] > value['deadline_ms']):
            raise ValueError
        if cleanup['state'] in {'not_needed','pending'}:
            if cleanup['reason'] is not None or (cleanup['state'] == 'not_needed' and cleanup['remaining_ms']):
                raise ValueError
        elif (cleanup['reason'] not in CLEANUP_REASONS or cleanup['remaining_ms'] != 0
                or (cleanup['state'] == 'confirmed') != (cleanup['reason'] == 'stop_confirmed')):
            raise ValueError
        unsent = False
        for i, task in enumerate(value['tasks']):
            if type(task) is not dict or set(task) != set(task_placeholder(TASKS[i])) or task['task'] != TASKS[i]:
                raise ValueError
            if type(task['dispatched']) is not bool or type(task['validated']) is not bool:
                raise ValueError
            if task['count_kind'] not in {'exact','upper_bound','unknown'} or task['context_integrity'] not in {'preserved','truncated','unknown'}:
                raise ValueError
            for key in ('input_tokens_bound','input_limit','output_tokens_cap','output_min','context_limit','context_slack'):
                if task[key] is not None and not integer(task[key]):
                    raise ValueError
            if not number(task['elapsed_ms']) or (task['allocated_ms'] is not None and not number(task['allocated_ms'])):
                raise ValueError
            if task['finish_reason'] is not None and task['finish_reason'] not in {'stop','length','content_filter','tool_calls'}:
                raise ValueError
            validate_selection(task['selection'])
            actual = task['actual_usage']
            if actual is not None and (type(actual) is not dict or set(actual) != {'tokens_in','tokens_out'} or any(not integer(v) for v in actual.values())):
                raise ValueError
            if not task['dispatched']:
                unsent = True
                if actual is not None or task['finish_reason'] is not None or task['validated']:
                    raise ValueError
            elif unsent:
                raise ValueError
        if value['job_calls'] != sum(t['dispatched'] for t in value['tasks']) or value['coverage'] != coverage(value['upstream_coverage'], value['tasks']):
            raise ValueError
        projected = ('degraded' if cleanup['state'] == 'unconfirmed' else
                     'superseded' if value['superseded'] else value['result_state'])
        if state is not None and state != projected:
            raise ValueError
        expected_outcome = ('stop_unconfirmed' if cleanup['state'] == 'unconfirmed' else
                            'superseded' if value['superseded'] else value['primary_outcome'])
        if value['outcome'] != expected_outcome or (projected == 'complete') != (value['outcome'] == 'within_budget'):
            raise ValueError
        if value['result_state'] == 'complete':
            if (value['primary_outcome'] != 'within_budget' or not value['core_complete'] or value['coverage'] == 'unknown' or value['reasons']
                    or cleanup['state'] != 'not_needed' or value['elapsed_ms'] >= value['deadline_ms']
                    or usage not in (None, 'known')):
                raise ValueError
            for task in value['tasks']:
                p,o,c,s = (task[k] for k in ('input_tokens_bound','output_tokens_cap','context_limit','context_slack'))
                actual = task['actual_usage']
                if (not task['dispatched'] or not task['validated'] or task['count_kind'] != 'exact'
                        or any(v is None for v in (p,o,c,s,task['input_limit'],task['output_min']))
                        or not 0 < task['output_min'] <= o <= 768 or p > task['input_limit']
                        or p + o + s > c or actual is None or actual['tokens_in'] != p
                        or actual['tokens_out'] > o or actual['tokens_in'] + actual['tokens_out'] + s > c
                        or task['finish_reason'] != 'stop' or task['context_integrity'] != 'preserved'):
                    raise ValueError
        if len(json.dumps(value, allow_nan=False).encode()) > 128*1024:
            raise ValueError
        return copy.deepcopy(value)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError('generation_budget_refused') from None


def project_budget(value):
    """Project result/cleanup/supersession axes without changing the original result."""
    value = copy.deepcopy(value)
    if value['cleanup']['state'] == 'unconfirmed':
        value['outcome'] = 'stop_unconfirmed'
        if 'stop_unconfirmed' not in value['reasons']:
            value['reasons'].append('stop_unconfirmed')
        state = 'degraded'
    elif value['superseded']:
        value['outcome'] = 'superseded'
        state = 'superseded'
    else:
        value['outcome'] = value['primary_outcome']
        state = value['result_state']
    return state, value


def validate_public_budget(value, *, state=None):
    if (type(value) is not dict or set(value) != {'version','outcome','coverage','cleanup_state','superseded','omitted_units'}
            or type(value['version']) is not int or value['version'] not in (0,1)
            or value['coverage'] not in COVERAGES or type(value['superseded']) is not bool
            or value['cleanup_state'] not in {'not_needed','pending','confirmed','unconfirmed'}
            or not integer(value['omitted_units']) or value['omitted_units'] > 16384
            or (value['version']==0 and value['outcome'] not in {'legacy_unverified','unsupported'})
            or (value['version']==1 and value['outcome'] not in OUTCOMES)):
        raise ValueError('generation_public_budget_refused')
    if value['coverage']=='intact' and value['omitted_units']:
        raise ValueError('generation_public_budget_refused')
    if state is not None:
        if (state=='complete') != (value['version']==1 and value['outcome']=='within_budget'):
            raise ValueError('generation_public_budget_refused')
        if state=='complete' and (value['coverage']=='unknown' or value['cleanup_state']!='not_needed' or value['superseded']):
            raise ValueError('generation_public_budget_refused')
        if value['cleanup_state']=='unconfirmed' and value['version']==1 and (state!='degraded' or value['outcome']!='stop_unconfirmed'):
            raise ValueError('generation_public_budget_refused')
        if value['superseded'] and value['cleanup_state']!='unconfirmed' and state!='superseded':
            raise ValueError('generation_public_budget_refused')



def validate_model_assistance(value, frame_id, trace_id):
    if (type(value) is not dict or value.get('schema_version')!='mio.assistance.v1'
            or value.get('state')!='complete' or value.get('generation_method')!='model'
            or value.get('frame_id')!=frame_id or value.get('trace_id')!=trace_id
            or type(value.get('hypotheses')) is not list or not 2<=len(value['hypotheses'])<=4):
        raise ValueError('generation_assistance_refused')
    for item in value['hypotheses']:
        if (type(item) is not dict or item.get('verification')!='model_proposed_unverified'
                or type(item.get('statement')) is not str or not 0<len(item['statement'])<=480):
            raise ValueError('generation_assistance_refused')
    for key,limit in (('unknowns',24),('next_checks',8)):
        if (type(value.get(key)) is not list or len(value[key])>limit
                or any(type(v) is not str or not 0<len(v)<=480 for v in value[key])):
            raise ValueError('generation_assistance_refused')
