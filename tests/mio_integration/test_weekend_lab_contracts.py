"""Host-safe assertions: no Docker, model, UI server or network is started."""
import copy
import json
from pathlib import Path

import pytest

from azazel_nexus_lab.weekend_fixture import fixture_lane, poll, production_control
from azazel_nexus_lab.weekend_ui import noc_frame, panels, supplement
from test_budget_api import ControlledServer, inputs

REPO = Path(__file__).resolve().parents[2]


def test_ledger_records_are_not_publication_ready_before_real_daemon_throttle(tmp_path):
    from test_incident_explaind import make, append, records
    from test_incident_explain import transition
    from azazel_nexus_lab.weekend_process import published_incidents
    ui = tmp_path / 'ui-recent.json'
    daemon = make(tmp_path, ui_recent_path=ui)
    daemon.poll()  # Startup publishes an empty read model at monotonic 0.
    paths = {'operator': tmp_path / 'recent.json', 'ui': ui}
    daemon.monotonic = lambda: 1
    append(daemon)
    append(daemon, transition(incident_id='inc-' + 'f' * 16))
    daemon.poll()
    durable = records(daemon)
    assert len(durable) == 2
    assert published_incidents(paths, durable) is None
    daemon.monotonic = lambda: 4.999
    daemon.poll()
    assert published_incidents(paths, durable) is None
    daemon.monotonic = lambda: 5
    daemon.poll()
    value = published_incidents(paths, durable)
    assert set(value) == {'operator', 'ui'}
    assert paths['operator'].read_bytes() == ui.read_bytes()
    assert {r['incident_id'] for r in value['ui']['incidents']} == {r['incident_id'] for r in durable}


@pytest.mark.parametrize('damage', ['absent', 'invalid', 'missing_incident', 'pending'])
def test_publication_requires_both_strict_snapshots_with_explanations(tmp_path, damage):
    from test_incident_explaind import make, append, records
    from azazel_nexus_lab.weekend_process import published_incidents
    ui = tmp_path / 'ui-recent.json'
    daemon = make(tmp_path, ui_recent_path=ui)
    append(daemon)
    daemon.poll()
    paths = {'operator': tmp_path / 'recent.json', 'ui': ui}
    durable = records(daemon)
    assert published_incidents(paths, durable) is not None
    value = json.loads(ui.read_text())
    if damage == 'absent':
        # A different, absent UI leaf must not accept the operator's good copy.
        paths['ui'] = tmp_path / 'not-published.json'
    elif damage == 'invalid':
        ui.write_text('{}')
    else:
        if damage == 'missing_incident':
            value['incidents'] = []
        else:
            from azazel_nexus.incident_explain import build_recent_incident
            from test_incident_explain import transition
            value['incidents'] = [build_recent_incident(transition())]
        ui.write_text(json.dumps(value))
    assert published_incidents(paths, durable) is None


def handoff_fixture(tmp_path):
    import io
    from datetime import datetime, timezone
    from types import SimpleNamespace
    from azazel_nexus.handoff_cli import run
    from test_handoff import example, INCIDENT, NOW
    root, parent = tmp_path / 'root', tmp_path / 'export'
    root.mkdir()
    parent.mkdir(mode=0o700)
    example.build_fixture(root)
    stream = io.StringIO()
    now = datetime.fromtimestamp(NOW, timezone.utc).isoformat().replace('+00:00', 'Z')
    assert run(SimpleNamespace(incident=INCIDENT, output_dir=parent), now=now,
               out=stream, principal='root', root=root) == 0
    return parent, INCIDENT, stream.getvalue()


def test_handoff_verifies_real_cli_child_package_and_all_three_files(tmp_path):
    from azazel_nexus_lab.weekend_process import verify_handoff
    parent, incident, stdout = handoff_fixture(tmp_path)
    value = verify_handoff(parent, incident)
    assert str(tmp_path / value['directory']) in stdout
    assert set(value['files']) == {'manifest.json', 'handoff.json', 'handoff.ja.md'}
    assert value['files']['manifest.json'] in stdout


@pytest.mark.parametrize('damage', ['bytes', 'size', 'incident', 'path', 'symlink', 'extra_package'])
def test_handoff_rejects_corrupt_or_ambiguous_exports(tmp_path, damage):
    from azazel_nexus_lab.weekend_process import verify_handoff
    parent, incident, _ = handoff_fixture(tmp_path)
    package = next(parent.iterdir())
    path = package / 'handoff.json'
    manifest_path = package / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    if damage == 'bytes':
        data = path.read_bytes()
        path.write_bytes(b'X' + data[1:])  # same size; digest must catch it
    elif damage == 'size':
        manifest['files'][0]['bytes'] += 1
    elif damage == 'incident':
        manifest['incident_id'] = 'inc-' + 'f' * 16
    elif damage == 'path':
        manifest['files'][0]['name'] = '../handoff.json'
    elif damage == 'symlink':
        saved = package / 'saved.json'
        path.rename(saved)
        path.symlink_to(saved.name)
    else:
        (parent / 'extra-package').mkdir()
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(AssertionError):
        verify_handoff(parent, incident)


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
    def explained(edge, sequence):
        fast = fast_assistance(build_frame(edge, sequence), deadline_s=.5)
        record = _record(read_mio_reply(dict(route='local', outcome='abandoned', reason='no advice',
            ledger_seq=41, fast_assistance=fast)))
        record.update(incident_id=edge['incident_id'], incident_sequence=sequence)
        return record
    record = explained(transition(), 17)
    from azazel_nexus_lab.weekend_process import noc_event
    from azazel_nexus.edge_intake import EvidenceRecord, IncidentTracker, parse_edge_event
    event = parse_edge_event(json.dumps(noc_event()).encode())
    noc_transition = IncidentTracker(lambda: 0).add(EvidenceRecord.receive(event, lambda: 0))[0]
    noc_transition['event_type'] = 'edge.incident.' + noc_transition.pop('transition')
    return dict(cases={'P01': {'fast_assistance': fast_assistance(noc_frame(), deadline_s=.5)},
                       'P04': {'record': record}},
                noc_incident={'record': explained(noc_transition, 18)})


def test_ui_trace_noc_soc_projection_preserves_identity_and_marks_guidance():
    value = panels(paired_fixture())
    assert [r['case'] for r in value['rows']] == ['NOC1', 'SOC1']
    assert value['rows'][1]['association'] == 'incident_bound'
    assert value['rows'][0]['association'] == 'incident_bound'
    assert value['rows'][0]['incident_id'] != value['rows'][1]['incident_id']
    for row in value['rows']:
        assert row['incident_id'] and row['trace_id'] and row['frame_id']
        assert row['evidence'] and row['unknowns'] and row['next_checks'] and row['lab_guidance']
        assert row['handoff']['current_action'] is None
    assert 'human_review_required' in value['semantic_acceptance']
    assert 'not_accepted' in value['deception']


def test_ui_rejects_cross_incident_trace_and_does_not_modify_production_assets():
    from azazel_nexus_runtime.ui_serve import UiApp, LoginCodes, FixtureSource
    receipt = paired_fixture()
    forged = copy.deepcopy(receipt)
    forged['cases']['P04']['record']['incident_id'] = 'inc-' + 'f' * 16
    with pytest.raises(ValueError):
        panels(forged)
    forged = copy.deepcopy(receipt)
    forged['noc_incident']['record']['incident_id'] = 'inc-' + 'e' * 16
    with pytest.raises(ValueError):
        panels(forged)
    def app():
        return UiApp(source=FixtureSource(REPO / 'tests/fixtures/ui/demo-status-view.json'),
                     codes=LoginCodes(lambda _: None, 'http://127.0.0.1:8443/'), port=8443)
    production = app()
    original = dict(production.static)
    original_document = production.view_document()
    instance = app()
    supplement(instance, receipt)
    assert b'/static/weekend.js' in instance.static['/'][0]
    assert b'textContent' in instance.static['/static/weekend.js'][0]
    assert b'innerHTML' not in instance.static['/static/weekend.js'][0]
    assert production.static == original == app().static
    assert production.view_document() == original_document
    assert b'weekend_lab' not in original_document


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


@pytest.mark.parametrize('args', [[], ['--lite']])
def test_locald_exec_preserves_interpreter_and_guarded_process_entry(monkeypatch, args):
    import sys
    from azazel_nexus_lab import weekend_locald
    launcher = REPO / 'tests/real_process/_weekend_locald_process.py'
    assert launcher.is_file()
    class ExecCalled(Exception):
        pass
    def execute(executable, argv):
        assert executable == sys.executable
        assert argv == [sys.executable, '-B', str(launcher), *args]
        raise ExecCalled
    monkeypatch.setattr(weekend_locald.os, 'execv', execute)
    with pytest.raises(ExecCalled):
        weekend_locald.main(args)
