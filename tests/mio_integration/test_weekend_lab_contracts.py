"""Host-safe assertions: no Docker, model, UI server or network is started."""
import copy
import json
from pathlib import Path

import pytest

from azazel_nexus_lab.weekend_fixture import fixture_lane, poll, production_control
from azazel_nexus_lab.weekend_ui import noc_frame, panels, supplement
from test_budget_api import ControlledServer, inputs

REPO = Path(__file__).resolve().parents[2]


def test_three_task_short_fixture_tracks_budget_and_same_cap_production_refusal():
    from azazel_nexus.generation_budget import TASKS
    from azazel_nexus_runtime.mio_serve import LocalInferenceResult
    class ShortServer(ControlledServer):
        def infer(self, request, deadline_s, **kwargs):
            # Exercise real notification/receipt accounting with a fixed short
            # schema. Native real-model transport is a separate selector.
            value = super().infer(request, deadline_s, **kwargs)
            return LocalInferenceResult('{"ok":true}', value.tokens_in, value.tokens_out,
                                        {}, 'stop', 'preserved')
    frame, _ = inputs()
    server = ShortServer()
    lane, cap = fixture_lane(REPO, server, short=True)
    assert lane._authorized(cap.generation_id)
    assert production_control(cap, server, frame)['state'] == 'closed'
    assert not server.requests
    first = lane.submit({'request_id': 'short-fixture'}, frame, cap.generation_id, upstream_coverage='intact')
    value = poll(lane, first, cap.generation_id, frame.trace_id)
    meta = value['generation_budget']
    assert server.requests == list(TASKS)
    assert meta['job_calls'] == 3
    assert all(t['validated'] and t['context_integrity'] == 'preserved' and
               t['actual_usage'] == {'tokens_in': 12, 'tokens_out': 7} for t in meta['tasks'])
    assert value['state'] != 'complete'  # transport fixture cannot establish meaning


def paired_fixture():
    from test_incident_explain import transition, _record
    from azazel_nexus.incident_explain import build_frame, read_mio_reply
    from azazel_nexus_runtime.mio_fast_assistance import fast_assistance
    edge = transition()
    fast = fast_assistance(build_frame(edge, 17), deadline_s=.5)
    record = _record(read_mio_reply(dict(route='local', outcome='abandoned', reason='no advice',
        ledger_seq=41, fast_assistance=fast)))
    record.update(incident_id=edge['incident_id'], incident_sequence=17)
    return dict(cases={'P01': {'fast_assistance': fast_assistance(noc_frame(), deadline_s=.5)},
                       'P04': {'record': record}})


def test_ui_trace_noc_soc_projection_preserves_identity_and_marks_guidance():
    value = panels(paired_fixture())
    assert [r['case'] for r in value['rows']] == ['NOC1', 'SOC1']
    assert value['rows'][1]['association'] == 'incident_bound'
    assert value['rows'][0]['association'] == 'lab_case_association_not_event_evidence'
    for row in value['rows']:
        assert row['incident_id'] and row['trace_id'] and row['frame_id']
        assert row['evidence'] and row['unknowns'] and row['next_checks'] and row['lab_guidance']
        assert row['handoff']['current_action'] is None
    assert 'human_review_required' in value['semantic_acceptance']
    assert 'not_accepted' in value['deception']


def test_ui_rejects_cross_incident_trace_and_does_not_modify_production_assets():
    from types import SimpleNamespace
    receipt = paired_fixture()
    forged = copy.deepcopy(receipt)
    forged['cases']['P04']['record']['incident_id'] = 'inc-' + 'f' * 16
    with pytest.raises(ValueError):
        panels(forged)
    original = b'<html><body></body></html>'
    instance = SimpleNamespace(static={'/': (original, 'text/html'), '/index.html': (original, 'text/html')})
    supplement(instance, receipt)
    assert b'/static/weekend.js' in instance.static['/'][0]
    assert b'textContent' in instance.static['/static/weekend.js'][0]
    assert b'innerHTML' not in instance.static['/static/weekend.js'][0]
    assert original == b'<html><body></body></html>'


def test_complete_seam_is_signed_before_transport_and_production_stays_partial(tmp_path):
    # Actual Knowledge app/query/adapter, in-process ASGI only. No listener/UI.
    from _api_support import make_client
    from test_knowledge_context_route import _configure, _request, _DOMAIN
    from azazel_nexus_lab.weekend_knowledge import configure_complete
    from nacl.signing import VerifyKey
    client, settings, _, _ = make_client(tmp_path)
    signer = _configure(settings)
    original = client.post('/v1/knowledge-context', json=_request())
    assert original.status_code == 200
    assert json.loads(original.content[64:])['payload']['snapshot']['state'] == 'partial'
    configure_complete(client.app)
    complete = client.post('/v1/knowledge-context', json=_request())
    assert complete.status_code == 200
    VerifyKey(signer.public_key).verify(_DOMAIN + complete.content[64:], complete.content[:64])
    value = json.loads(complete.content[64:])
    assert value['payload']['snapshot']['state'] == 'complete'
    assert value['payload']['authority'] == 'advisory_only'
    assert any('LAB ONLY' in item for item in value['payload']['limitations'])
    wrong_profile = {**_request(), 'source_product': 'azazel_edge'}
    assert client.post('/v1/knowledge-context', json=wrong_profile).status_code == 403
    signer_config = settings.knowledge_context_transport
    settings.knowledge_context_transport = None
    assert client.post('/v1/knowledge-context', json=_request()).status_code == 404
    from dataclasses import replace
    from test_knowledge_context_route import _TestPeer
    settings.knowledge_context_transport = replace(signer_config, peer_authenticator=_TestPeer(None))
    assert client.post('/v1/knowledge-context', json=_request()).status_code == 401
    fresh, fresh_settings, _, _ = make_client(tmp_path / 'production-control')
    _configure(fresh_settings)
    control = fresh.post('/v1/knowledge-context', json=_request())
    assert control.status_code == 200
    assert json.loads(control.content[64:])['payload']['snapshot']['state'] == 'partial'
