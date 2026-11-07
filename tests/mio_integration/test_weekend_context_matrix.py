"""Twelve model-free consumer combinations, not process or commissioning evidence."""
from datetime import UTC, datetime, timedelta

import pytest

from azazel_nexus.lite_import import KnowledgeRef
from azazel_nexus.local_advisory import read_fast_assistance, read_frame
from azazel_nexus_runtime.knowledge_context_socket import FullNodeContextStatus
from azazel_nexus_runtime.mio_fast_assistance import fast_assistance


def response(state):
    now = datetime.now(UTC)
    instant = lambda value: value.isoformat().replace('+00:00', 'Z')
    # Withheld is a valid partial response with no disclosed subjects, never
    # an invented fourth Fabric snapshot enum.
    return dict(
        schema_version='knowledge-context-response/v1',
        request_id='weekend-request', correlation_id='weekend-correlation',
        source_product='azazel_nexus', source_ref='nexus:synthetic-query',
        provider_id='knowledge-lab',
        snapshot=dict(ref='knowledge:lab-snapshot',
                      state='partial' if state == 'withheld' else state,
                      as_of=instant(now - timedelta(seconds=10))),
        facts=[], inferences=[],
        unknowns=['Subject withheld by producer privacy policy.' if state == 'withheld'
                  else 'No exact fact was asserted.'],
        limitations=['Synthetic input; no operational authority.'],
        generated_at=instant(now - timedelta(seconds=5)),
        expires_at=instant(now + timedelta(seconds=30)), authority='advisory_only')


@pytest.mark.parametrize('lite', [False, True], ids=['noLite', 'Lite'])
@pytest.mark.parametrize('state', ['complete', 'partial', 'stale', 'withheld', 'invalid', 'timeout'])
def test_full_node_state_and_lite_remain_independent(state, lite):
    source = read_frame(dict(request_id='weekend-context', privacy_class='P0-public',
                             question='Synthetic SSH T1110 observation', context=[]))
    ref = KnowledgeRef(
        technique_id='T1110', name='Brute Force', summary='', claim_id='T1110',
        bundle_digest='sha256:' + 'a' * 64, freshness='static',
        source_kind='knowledge_lite', generation=5, trust_check='verified',
        as_of=datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),
        citation='Synthetic MITRE ATT&CK reference')
    kwargs = dict(knowledge_lookup=lambda *a, **k: (ref,) if lite else ())
    if state == 'timeout':
        # A timeout has no wire response. This is the consumer's existing
        # bounded unavailable state; actual timeout timing is a transport test.
        kwargs['full_node_context_status'] = FullNodeContextStatus.UNAVAILABLE
    else:
        value = response('complete' if state == 'invalid' else state)
        if state == 'invalid':
            value['authority'] = 'execute'
        kwargs['fabric_knowledge_context_response'] = value
    result = read_fast_assistance(fast_assistance(source, deadline_s=.5, **kwargs))
    assert result['generation_method'] == 'static_reference'
    assert result['full_node_context_status'] == ('unavailable' if state == 'timeout' else 'received')
    assert len(result['knowledge']) == int(lite)
    assert result['observations'] == []
    assert result['trace_id'] and result['frame_id'] == result['trace_id'] + ':frame'
    assert result['unknowns'] and result['next_checks']
    assert result['handoff']['current_action'] is None
    assert result['handoff']['frame_id'] == result['frame_id']
    advisory = result.get('fabric_knowledge_context_advisory')
    if state in {'invalid', 'timeout'}:
        assert advisory is None
        if state == 'invalid':
            assert 'KNOWLEDGE_CONTEXT_REJECTED' in result['unknowns']
    else:
        expected = 'partial' if state == 'withheld' else state
        assert advisory['snapshot_state'] == expected
        assert advisory['authority'] == 'advisory_only'
        assert advisory['trust'] == 'unverified_advisory_only'
        assert advisory['claim_status'] == 'source_reported_unverified'
        if expected != 'complete':
            assert 'KNOWLEDGE_CONTEXT_' + expected.upper() in result['unknowns']
    expected_outcome = ('available' if lite or state == 'complete' else
                        'rejected' if state == 'invalid' else 'unavailable')
    assert result['dependency_outcome']['knowledge'] == expected_outcome
