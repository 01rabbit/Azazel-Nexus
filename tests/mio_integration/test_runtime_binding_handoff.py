"""Real MIO receipt -> runtime recent.json -> library; controlled provider only."""
import json
import time
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from azazel_nexus import handoff, incident_explain
from azazel_nexus.status_view import _recent_extra
from azazel_nexus_runtime import incident_explaind
from azazel_nexus_runtime.mio_budget_session import BudgetSession
from test_budget_api import ControlledServer, FixtureLane, inputs
from test_handoff import INCIDENT, package, root, write_slow_recent  # noqa: F401


def execute(tmp_path, *, server=None, frame_age=0, broker=(), receipt_transform=None, expected="complete"):
    frame, cap = inputs()
    trace = f'mio-{INCIDENT[4:]}-1'
    frame = replace(frame, trace_id=trace, frame_id=trace + ':frame',
        created_at=datetime.fromtimestamp(time.time()-frame_age, UTC).isoformat())
    class CallerLane(FixtureLane):
        def _make_budget_session(self, job, api):
            class CallerSession(BudgetSession):
                def finish(self, assistance):
                    if receipt_transform is not None:
                        assistance = replace(assistance, generation_receipt=receipt_transform(assistance.generation_receipt))
                    return super().finish(assistance)
            session = CallerSession(self, job, api)
            session.broker_results = broker  # caller metadata seam, never model text
            return session
    lane = CallerLane(capability=cap, server=server or ControlledServer(), deadline_s=5,
                      budget_enabled=True, journal_dir=tmp_path / 'journal')
    receipt = lane.submit({'request_id': INCIDENT + ':1'}, frame, 'api-fixture',
                          upstream_coverage='intact', caller_epoch='epoch')
    end = time.monotonic() + 2
    while time.monotonic() < end:
        value = lane.poll(receipt['result_handle'], 'api-fixture', trace, caller_epoch='epoch')
        if value['state'] != 'queued':
            break
        time.sleep(.002)
    worker = lane._worker
    if worker:
        worker.join(2)
        assert not worker.is_alive()
    assert value['state'] == expected, value
    metadata = lane.private_metadata(receipt['result_handle'], 'epoch')
    return lane, frame, cap, value, metadata


def project(root, tmp_path, frame, value, metadata):
    write_slow_recent(root)
    path = root / 'var/lib/azazel/run/incident-explain-status/recent.json'
    recent = json.loads(path.read_text())
    explainer = incident_explaind.Explainer(incidents=tmp_path/'incidents', state=tmp_path/'state',
        status_path=path.with_name('status.json'), clock=time.time)
    explainer.prepare()
    explainer.restart_epoch = 'epoch'
    explainer.recent = recent['incidents']
    explainer._generation_metadata = metadata or {}
    explainer._capture_generation_receipt({'slow_analysis': value}, {'incident_id': INCIDENT}, 1)
    explainer.recent_status()
    explainer.checkpoint()
    recent = json.loads(path.read_text())
    assert incident_explain.read_recent_incidents(path.read_bytes()) == recent
    return recent, path


def check_export(root, recent, *, available):
    now = time.time()
    result = package(root, now=now)
    advisory = result['ai_assessment']['slow_advisory']
    assert advisory['status'] == ('available' if available else 'unavailable')
    files = handoff.encode_files(result)
    exported = json.loads(files['handoff.json'])['ai_assessment']['slow_advisory']
    assert exported == advisory
    markdown = files['handoff.ja.md'].decode()
    snapshot = {}
    _recent_extra(recent, snapshot, now)
    shown = snapshot['incidents'][0]['explanation']['slow_analysis']
    assert (shown['state'] == 'complete') is available
    if available:
        assert '事実・判断・実行指示として扱わない' in markdown
        assert advisory['authority'] == 'advisory_only_not_fact'
        assert advisory['verification'] == 'model_proposed_unverified'
        assert advisory['hypotheses'] and advisory['next_checks']
        assert shown['provenance_summary']['verified_current_sources'] >= 1
    else:
        assert not advisory['hypotheses'] and not advisory['next_checks']
    return advisory


def test_runtime_complete_manifest_displays_and_exports(root, tmp_path):
    lane, frame, _, value, metadata = execute(tmp_path)
    assert lane._receipts[value['result_handle']]['source_manifest'][0]['authority'] == 'runtime_caller_asserted'
    assert metadata['hypothesis_ids'] == ['h1', 'h2']
    assert set(metadata['advisory_refs']) == {'h1', 'h2', 'ev:ssh:1'}
    assert metadata['completeness'] == 'complete' and not metadata['unlisted_prose_ids']
    assert metadata['evidence_refs'] == [
        dict(id='ev:ssh:1', source='frame', trust='verified', freshness='current'),
        dict(id='u1', source='frame', trust='verified', freshness='current')]
    recent, _ = project(root, tmp_path, frame, value, metadata)
    binding = recent['incidents'][0]['explanation']['slow_analysis']['binding']
    assert incident_explain.valid_handoff_binding(binding, INCIDENT, time.time())
    assert 'epoch' not in binding and 'unlisted_prose_ids' not in binding
    assert 'possible' not in json.dumps(metadata)
    check_export(root, recent, available=True)
    # Projection never refreshes receipt lifetime.
    assert lane.private_metadata(value['result_handle'], 'epoch')['expires_at'] == metadata['expires_at']


@pytest.mark.parametrize('mutation', ['partial', 'missing', 'incident', 'expired', 'unlisted',
                                     'unverified', 'version', 'template', 'um_body_unavailable'])
def test_real_projection_negative_binding(root, tmp_path, mutation):
    _, frame, _, value, metadata = execute(tmp_path)
    recent, path = project(root, tmp_path, frame, value, metadata)
    binding = recent['incidents'][0]['explanation']['slow_analysis']['binding']
    if mutation == 'partial': binding['completeness'] = 'partial'
    elif mutation == 'missing': del binding['advisory_refs']
    elif mutation == 'incident': binding['incident_id'] = 'inc-0000000000000000'
    elif mutation == 'expired': binding['expires_at'] = time.time()-1
    elif mutation == 'unlisted': binding['advisory_refs'].append('u999')
    elif mutation == 'unverified': binding['evidence_refs'][0]['trust'] = 'unverified'
    elif mutation == 'version': binding['provenance_version'] = 99
    elif mutation == 'template': binding['template_version'] = '9.9.9'
    else:
        binding['advisory_refs'].append('um:1')
        binding['unknowns'].append(dict(id='um:1', origin='model_asserted', category='model_unknown',
                                       status='unavailable_after_restart'))
    assert not incident_explain.valid_handoff_binding(binding, INCIDENT, time.time())
    path.write_text(json.dumps(recent))
    check_export(root, recent, available=False)


@pytest.mark.parametrize('text', ['possible u999', 'possible (h999).', 'possible kn:attack:T1059.001',
                                  'possible ev:ssh:999', 'possible um:999', 'possible ux:impact'])
def test_unlisted_raw_prose_is_private_partial_and_withheld(root, tmp_path, text):
    class ProseServer(ControlledServer):
        def infer(self, *args, **kwargs):
            result = super().infer(*args, **kwargs)
            value = json.loads(result.text)
            if 'hypotheses' in value:
                value['hypotheses'][0]['statement'] = text
            return replace(result, text=json.dumps(value))
    _, frame, _, value, metadata = execute(tmp_path, server=ProseServer())
    assert metadata['unlisted_prose_ids'] and metadata['completeness'] == 'partial'
    assert metadata['advisory_refs'] == ['ev:ssh:1', 'h1', 'h2']
    recent, _ = project(root, tmp_path, frame, value, metadata)
    check_export(root, recent, available=False)


@pytest.mark.parametrize('broker', [
    {'trust': 'unverified', 'observed_at': 'NOW'},
    {'trust': 'verified'},
    {'trust': 'verified', 'observed_at': '2000-01-01T00:00:00Z'},
    {'trust': 'verified', 'observed_at': 'NOW', 'revoked': True},
])
def test_broker_metadata_does_not_inherit_frame_authority(root, tmp_path, broker):
    broker = dict(broker, evidence_refs=['ev:ssh:1'])
    if broker.get('observed_at') == 'NOW': broker['observed_at'] = time.time()
    _, frame, _, value, metadata = execute(tmp_path, broker=(broker,))
    ref = metadata['evidence_refs'][0]
    assert ref['source'] == 'knowledge-broker'
    assert ref['trust'] != 'verified' or ref['freshness'] != 'current'
    recent, _ = project(root, tmp_path, frame, value, metadata)
    check_export(root, recent, available=False)


def test_expired_frame_observation_is_not_refreshed(root, tmp_path, monkeypatch):
    lane, frame, _, value, metadata = execute(tmp_path, frame_age=59)
    assert all(ref['freshness'] == 'current' for ref in metadata['evidence_refs'])
    # Expire the source observation while the original receipt remains live.
    later = time.time()+2
    with monkeypatch.context() as patch:
        patch.setattr(time, 'time', lambda: later)
        metadata = lane.private_metadata(value['result_handle'], 'epoch')
    assert all(ref['freshness'] == 'expired' for ref in metadata['evidence_refs'])
    recent, _ = project(root, tmp_path, frame, value, metadata)
    check_export(root, recent, available=False)


@pytest.mark.parametrize('restart', ['runtime', 'epoch'])
def test_restart_cannot_promote_complete_or_reexport_advice(root, tmp_path, restart):
    lane, frame, cap, value, _ = execute(tmp_path)
    if restart == 'runtime':
        lane = FixtureLane(capability=cap, server=ControlledServer(), budget_enabled=True,
                           journal_dir=tmp_path/'journal')
    result = lane.poll(value['result_handle'], 'api-fixture', frame.trace_id, caller_epoch='after')
    assert result['state'] == 'degraded' and 'assistance' not in result
    assert result['generation_budget']['primary_outcome'] == 'within_budget'
    assert result['generation_budget']['outcome'] == 'stop_unconfirmed'
    observation = lane.private_observation(INCIDENT+':1')
    assert observation['unknowns'][0]['id'] == 'u1'
    assert observation['unknowns'][0]['status'] == 'unavailable_after_restart'
    metadata = lane.private_metadata(value['result_handle'], 'after')
    assert metadata is None
    recent, _ = project(root, tmp_path, frame, result, metadata)
    check_export(root, recent, available=False)


def test_explainer_only_restart_keeps_unknown_and_terminal_accounting(root, tmp_path):
    lane, frame, _, value, _ = execute(tmp_path)
    # Supply the live metadata in this Explainer's epoch, as its caller would.
    metadata = lane.private_metadata(value['result_handle'], 'epoch')
    recent, path = project(root, tmp_path, frame, value, metadata)
    check_export(root, recent, available=True)
    restarted = incident_explaind.Explainer(incidents=tmp_path/'incidents', state=tmp_path/'state',
        status_path=path.with_name('status.json'), clock=time.time,
        mio_result=lambda *a, **k: pytest.fail('restored result must not be polled'))
    restarted.prepare()
    restarted._poll_generation_results()
    restarted.recent_status()
    recent = json.loads(path.read_text())
    shown = recent['incidents'][0]['explanation']['slow_analysis']
    assert shown['state'] == 'degraded'
    receipt = restarted._generation_receipts[value['result_handle']]
    restored = restarted._generation_value(value['result_handle'])
    assert restored['generation_budget']['primary_outcome'] == 'within_budget'
    assert restored['generation_budget']['outcome'] == 'stop_unconfirmed'
    unknowns = restarted._private_generation_journal().observation(receipt['request_id'])['unknowns']
    assert unknowns[0]['id'] == 'u1' and unknowns[0]['status'] == 'unavailable_after_restart'
    assert lane.poll(value['result_handle'], 'api-fixture', frame.trace_id, caller_epoch='epoch')['state'] == 'complete'
    check_export(root, recent, available=False)


def test_raw_prose_member_and_structured_unknown_are_manifested(root, tmp_path):
    class ReferencingServer(ControlledServer):
        def infer(self, *args, **kwargs):
            result = super().infer(*args, **kwargs)
            value = json.loads(result.text)
            if 'hypotheses' in value:
                value['hypotheses'][0]['statement'] = 'possible ev:ssh:1'
                value['hypotheses'][0]['missing_evidence'] = ['unknown']
            return replace(result, text=json.dumps(value))
    _, frame, _, value, metadata = execute(tmp_path, server=ReferencingServer())
    assert 'u1' in metadata['advisory_refs']
    assert metadata['completeness'] == 'complete' and not metadata['unlisted_prose_ids']
    recent, _ = project(root, tmp_path, frame, value, metadata)
    check_export(root, recent, available=True)


@pytest.mark.parametrize('body_present', [True, False])
def test_model_unknown_requires_live_body_before_id_only_projection(root, tmp_path, body_present):
    class UnknownServer(ControlledServer):
        def infer(self, *args, **kwargs):
            result = super().infer(*args, **kwargs)
            value = json.loads(result.text)
            if 'hypotheses' in value:
                value['hypotheses'][0]['missing_evidence'] = ['PRIVATE-MODEL-UNKNOWN-BODY']
            return replace(result, text=json.dumps(value))
    def transform(receipt):
        if body_present:
            return receipt
        return replace(receipt, frame_unknowns={k: v if not k.startswith('um:') else ''
                                                for k, v in receipt.frame_unknowns.items()})
    _, frame, _, value, metadata = execute(tmp_path, server=UnknownServer(), receipt_transform=transform)
    assert 'um:1' in metadata['advisory_refs']
    assert metadata['completeness'] == ('complete' if body_present else 'partial')
    assert 'PRIVATE-MODEL-UNKNOWN-BODY' not in json.dumps(metadata)
    recent, _ = project(root, tmp_path, frame, value, metadata)
    check_export(root, recent, available=body_present)
    for directory in (tmp_path/'journal', tmp_path/'state/mio-generation-private'):
        for path in directory.glob('*.json'):
            assert 'PRIVATE-MODEL-UNKNOWN-BODY' not in path.read_text()


def test_degraded_result_preserves_primary_reason_through_restart_and_export(root, tmp_path):
    class IncompleteServer(ControlledServer):
        def infer(self, *args, **kwargs):
            return replace(super().infer(*args, **kwargs), finish_reason='length')
    _, frame, cap, value, metadata = execute(tmp_path, server=IncompleteServer(), expected='degraded')
    assert value['generation_budget']['primary_outcome'] == 'output_incomplete'
    recent, _ = project(root, tmp_path, frame, value, metadata)
    before = check_export(root, recent, available=False)
    resumed = FixtureLane(capability=cap, server=ControlledServer(), budget_enabled=True,
                          journal_dir=tmp_path/'journal')
    after = resumed.poll(value['result_handle'], 'api-fixture', frame.trace_id, caller_epoch='after')
    assert after['state'] == 'degraded'
    assert after['generation_budget']['primary_outcome'] == 'output_incomplete'
    assert after['generation_budget']['reasons'] == value['generation_budget']['reasons']
    # A separate Explainer projects the restored runtime value to a fresh recent file.
    second = tmp_path/'second'
    second.mkdir()
    recent, _ = project(root, second, frame, after, None)
    assert check_export(root, recent, available=False)['budget']['reasons'] == before['budget']['reasons']
