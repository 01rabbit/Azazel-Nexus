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
MIO_REASON_OUTCOMES = {
    'budget_exhausted':'budget_exhausted', 'count_unknown':'token_count_unknown',
    'malformed':'output_invalid', 'task_plan_unsupported':'budget_exhausted',
    'dispatch_tracking_unavailable':'output_invalid', 'send_notification_conflict':'output_invalid',
    'insufficient_evidence':'output_invalid', 'validation_rejected':'output_invalid',
    'dependency_unavailable':'provider_unavailable', 'error_fallback':'output_invalid',
    'operator_cancelled':'cancelled', 'stale_superseded':'superseded',
    'cancelled':'cancelled', 'superseded':'superseded', 'backpressure':'model_unavailable',
    'in_flight_duplicate':'model_unavailable', 'pre_restart':'stale',
    'unknown_or_evicted':'stale', 'ticket_mismatch':'stale', 'already_completed':'stale',
    'unknown':'output_invalid',
}
COORDINATOR_DISPOSITIONS = frozenset({'current','cancelled','superseded','backpressure',
    'in_flight_duplicate','pre_restart','unknown_or_evicted','ticket_mismatch','already_completed','unknown'})
REASONS = OUTCOMES | set(MIO_REASON_OUTCOMES) | {'truncated','timeout'}
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
        if (type(value) is not dict or not keys<=set(value) or set(value)-keys-{'coordinator_disposition','verified_tuple','profile','terminal_outcome'} or type(value['version']) is not int
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
        if value.get('coordinator_disposition') is not None and value['coordinator_disposition'] not in COORDINATOR_DISPOSITIONS:
            raise ValueError
        profile=value.get('profile')
        verified=value.get('verified_tuple')
        if profile is not None:validate_profile(profile)
        if verified is not None:validate_verified_tuple(verified)
        configured=None if profile is None else profile['configured_context_limit']
        context=None if verified is None or configured is None else effective_context_limit(verified['context_limit'],configured)
        terminal=value.get('terminal_outcome',value['primary_outcome'])
        if terminal not in OUTCOMES:raise ValueError
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
            if profile is not None:
                if task['allocated_ms'] is not None and task['allocated_ms']<profile['minimum_provider_ms'][i]:raise ValueError
                for field,expected in (('output_tokens_cap',profile['output_caps'][i]),('output_min',profile['output_mins'][i]),('context_slack',profile['slack'])):
                    if task[field] is not None and task[field]!=expected:raise ValueError
            if task['context_limit'] is not None and task['context_limit']!=context:
                raise ValueError
            if all(task[k] is not None for k in ('input_limit','output_tokens_cap','context_slack','context_limit')) and task['input_limit']+task['output_tokens_cap']+task['context_slack']>task['context_limit']:
                raise ValueError
            validate_selection(task['selection'])
            actual = task['actual_usage']
            if actual is not None and (type(actual) is not dict or set(actual) != {'tokens_in','tokens_out'} or any(not integer(v) for v in actual.values())):
                raise ValueError
            if not task['dispatched']:
                unsent = True
                if actual is not None or task['finish_reason'] is not None or task['validated']:
                    raise ValueError
            elif unsent or context is None:
                raise ValueError
        if profile is not None:
            reserve=max(profile['minimum_reserve_ms'],value['deadline_ms']*profile['reserve_fraction'])
            if sum(t['allocated_ms'] or 0 for t in value['tasks'])>max(0,value['deadline_ms']-reserve)+1e-6:raise ValueError
        if value['job_calls'] != sum(t['dispatched'] for t in value['tasks']) or value['coverage'] != coverage(value['upstream_coverage'], value['tasks']):
            raise ValueError
        projected = ('degraded' if cleanup['state'] == 'unconfirmed' else
                     'superseded' if value['superseded'] else value['result_state'])
        if state is not None and state != projected:
            raise ValueError
        expected_outcome = ('stop_unconfirmed' if cleanup['state'] == 'unconfirmed' else
                            'superseded' if value['superseded'] else terminal)
        if value['outcome'] != expected_outcome or (projected == 'complete') != (value['outcome'] == 'within_budget'):
            raise ValueError
        if value['result_state'] == 'complete':
            if profile is None or verified is None or context is None or profile['template_version'] is None:raise ValueError
            reserve=max(profile['minimum_reserve_ms'],value['deadline_ms']*profile['reserve_fraction'])
            if (value['elapsed_ms']>=value['deadline_ms']-reserve/2
                    or any(t['allocated_ms'] is None or t['allocated_ms']<minimum or t['elapsed_ms']>t['allocated_ms'] for t,minimum in zip(value['tasks'],profile['minimum_provider_ms']))
                    or sum(t['allocated_ms'] for t in value['tasks'])>value['deadline_ms']-reserve+1e-6
                    or sum(t['elapsed_ms'] for t in value['tasks'])>value['elapsed_ms']+1e-6
                    or any(t['selection']['policy_version']!=profile['template_version'] for t in value['tasks'])):
                raise ValueError
            if (value['primary_outcome'] != 'within_budget' or not value['core_complete'] or value['coverage'] == 'unknown' or value['reasons']
                    or cleanup['state'] != 'not_needed' or value['elapsed_ms'] >= value['deadline_ms']
                    or value.get('coordinator_disposition') not in (None,'current')
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
        value['outcome'] = value.get('terminal_outcome',value['primary_outcome'])
        state = value['result_state']
    return state, value


def validate_public_budget(value, *, state=None):
    if (type(value) is not dict or not {'version','outcome','coverage','cleanup_state','superseded','omitted_units'} <= set(value)
            or set(value)-{'version','outcome','coverage','cleanup_state','superseded','omitted_units','reasons','coordinator_disposition','dispatch','fence_state'}
            or type(value['version']) is not int or value['version'] not in (0,1)
            or value['coverage'] not in COVERAGES or type(value['superseded']) is not bool
            or value['cleanup_state'] not in {'not_needed','pending','confirmed','unconfirmed'}
            or not integer(value['omitted_units']) or value['omitted_units'] > 16384
            or (value['version']==0 and value['outcome'] not in {'legacy_unverified','unsupported'})
            or (value['version']==1 and value['outcome'] not in OUTCOMES)):
        raise ValueError('generation_public_budget_refused')
    if (type(value.get('reasons',[])) is not list or len(value.get('reasons',[]))>16
            or any(type(r) is not str or r not in REASONS for r in value.get('reasons',[]))
            or (value.get('coordinator_disposition') is not None and value['coordinator_disposition'] not in COORDINATOR_DISPOSITIONS)):
        raise ValueError('generation_public_budget_refused')
    # Optional fields are a closed projection of the validated receipt. Fence
    # is unknown: cleanup observation alone does not prove current lane state.
    if ('dispatch' in value) != ('fence_state' in value):
        raise ValueError('generation_public_budget_refused')
    if 'dispatch' in value:
        dispatch = value['dispatch']
        if (value['version'] != 1 or value['fence_state'] != 'unknown'
                or type(dispatch) is not list or len(dispatch) != len(TASKS)
                or any(type(item) is not dict or set(item) != {'task', 'dispatched'}
                       or item['task'] != task or type(item['dispatched']) is not bool
                       for item, task in zip(dispatch, TASKS))
                or any(not dispatch[i]['dispatched'] and dispatch[i+1]['dispatched']
                       for i in range(len(dispatch)-1))
                or (value['outcome'] == 'within_budget'
                    and not all(item['dispatched'] for item in dispatch))):
            raise ValueError('generation_public_budget_refused')
    if value['coverage']=='intact' and value['omitted_units']:
        raise ValueError('generation_public_budget_refused')
    if state is not None:
        if (state=='complete') != (value['version']==1 and value['outcome']=='within_budget'):
            raise ValueError('generation_public_budget_refused')
        if state=='complete' and (value['coverage']=='unknown' or value['cleanup_state']!='not_needed' or value['superseded'] or value.get('reasons',[]) or value.get('coordinator_disposition') not in (None,'current')):
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


def canonical_digest(value):
    import hashlib
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def verified_tuple_from_props(props):
    """Identifiers declared by the authenticated serving instance, never public text."""
    try:
        fields=('model_alias','model_path','model_ftype','chat_template','bos_token','eos_token','build_info')
        if type(props) is not dict or any(type(props.get(k)) is not str or not 0<len(props[k])<=65536 for k in fields):
            raise ValueError
        context=props['default_generation_settings']['n_ctx']
        if not integer(context) or not 0<context<=2**31-1:raise ValueError
        file_id=canonical_digest([props['model_path'],props['model_ftype']])
        result=dict(version=1,model_id=canonical_digest(props['model_alias']),model_file_id=file_id,
            tokenizer_id=canonical_digest([file_id,props['bos_token'],props['eos_token']]),
            template_id=canonical_digest(props['chat_template']),runtime_id=canonical_digest(props['build_info']),
            context_limit=context)
        result['tuple_id']=canonical_digest(result)
        return result
    except (KeyError,TypeError,ValueError,OverflowError):
        raise ValueError('verified_tuple_unknown') from None


def validate_verified_tuple(value):
    import re
    keys={'version','model_id','model_file_id','tokenizer_id','template_id','runtime_id','context_limit','tuple_id'}
    if (type(value) is not dict or set(value)!=keys or type(value['version']) is not int or value['version']!=1
            or not integer(value['context_limit']) or not 0<value['context_limit']<=2**31-1
            or any(type(value[k]) is not str or re.fullmatch('[0-9a-f]{64}',value[k]) is None
                   for k in keys-{'version','context_limit'})
            or value['tuple_id']!=canonical_digest({k:v for k,v in value.items() if k!='tuple_id'})):
        raise ValueError('verified_tuple_refused')
    return value


SELECTION_VERSIONS=frozenset({'1.6.0','1.7.0','1.8.0','1.9.0','fixture-v1','transport-fixture-v1'})

def validate_profile(value):
    keys={'version','origin','reserve_fraction','minimum_reserve_ms','weights','slack','output_caps','output_mins','minimum_provider_ms','template_version','configured_context_limit'}
    if (type(value) is not dict or set(value)!=keys or type(value['version']) is not int or value['version']!=1
            or value['origin']!='fixture' or not number(value['reserve_fraction']) or not 0<value['reserve_fraction']<1
            or not number(value['minimum_reserve_ms']) or value['minimum_reserve_ms']<=0 or not integer(value['slack'])
            or any(type(value[k]) is not list or len(value[k])!=3 for k in ('weights','output_caps','output_mins','minimum_provider_ms'))
            or any(not integer(v) or v<=0 for v in value['weights'])
            or any(not integer(o) or not integer(m) or not 0<m<=o<=768 for o,m in zip(value['output_caps'],value['output_mins']))
            or any(not number(v) or v<=0 for v in value['minimum_provider_ms'])
            or value['template_version'] not in (None,*SELECTION_VERSIONS)
            or (value['configured_context_limit'] is not None and not context_integer(value['configured_context_limit']))):
        raise ValueError('generation_profile_refused')
    validate_fixture_policy(value['reserve_fraction'],value['minimum_reserve_ms'],value['weights'],value['slack'],value['minimum_provider_ms'])
    return value


# fixture-v1 is an adopted policy, not a self-described way to weaken a receipt.
FIXTURE_RESERVE_FRACTION=.1
FIXTURE_MINIMUM_RESERVE_MS=500.
FIXTURE_WEIGHTS=(45,20,35)
FIXTURE_SLACK=32
FIXTURE_MINIMUM_PROVIDER_MS=(50.,50.,50.)


def validate_fixture_policy(fraction,reserve,weights,slack,minimums):
    if (not number(fraction) or fraction!=FIXTURE_RESERVE_FRACTION
            or not number(reserve) or reserve!=FIXTURE_MINIMUM_RESERVE_MS
            or type(weights) not in (tuple,list) or len(weights)!=3
            or any(type(v) is not int for v in weights) or tuple(weights)!=FIXTURE_WEIGHTS
            or type(slack) is not int or slack!=FIXTURE_SLACK
            or type(minimums) not in (tuple,list) or len(minimums)!=3
            or any(not number(v) for v in minimums) or tuple(minimums)!=FIXTURE_MINIMUM_PROVIDER_MS):
        raise ValueError('generation_fixture_policy_refused')


def context_integer(value):
    return type(value) is int and 0<value<=2**31-1


def effective_context_limit(verified_context_limit,configured_context_limit):
    if not context_integer(verified_context_limit) or not context_integer(configured_context_limit):
        raise ValueError('generation_context_unknown')
    return min(verified_context_limit,configured_context_limit)
