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
        binding = recent['incidents'][0]['explanation']['slow_analysis']['binding']
        assert shown['binding'] == advisory['binding'] == binding
        for key in ('incident_id', 'request_id', 'frame_id', 'template_version',
                    'created_at', 'expires_at', 'completeness'):
            assert str(binding[key]) in markdown
        for item in binding['unknowns'] + binding['evidence_refs']:
            assert all(str(value) in markdown for value in item.values())
    else:
        assert not advisory['hypotheses'] and not advisory['next_checks']
        assert advisory['reason_code'] == shown['reason_code']
        assert advisory['reason_ja'] == shown['reason_ja']
        assert advisory['reason_code'] in markdown and advisory['reason_ja'] in markdown
        if 'recovery' in shown:
            assert advisory['recovery'] == shown['recovery']
            assert 'unavailable_after_restart' in markdown
    return advisory


def test_runtime_complete_manifest_displays_and_exports(root, tmp_path):
    lane, frame, _, value, metadata = execute(tmp_path)
    assert lane._receipts[value['result_handle']]['source_manifest'][0]['authority'] == 'runtime_caller_asserted'
    assert metadata['hypothesis_ids'] == ['h1', 'h2']
    assert set(metadata['advisory_refs']) == {'h1', 'h2', 'ev:ssh:1'}
    assert metadata['completeness'] == 'complete' and not metadata['unlisted_prose_ids']
    observed = datetime.fromisoformat(frame.created_at).timestamp()
    assert metadata['evidence_refs'] == [
        dict(id='ev:ssh:1', source='frame', trust='verified', freshness='current',
             observed_at=observed, valid_until=observed + 60),
        dict(id='u1', source='frame', trust='verified', freshness='current',
             observed_at=observed, valid_until=observed + 60)]
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
    advisory = check_export(root, recent, available=False)
    expected_reason = {'incident': 'incident_mismatch', 'expired': 'binding_expired',
                       'unverified': 'source_unverified', 'template': 'template_unknown'}
    assert advisory['reason_code'] == expected_reason.get(mutation, 'binding_unverified')


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
    advisory = check_export(root, recent, available=False)
    assert advisory['reason_code'] == 'unavailable_after_restart'
    assert advisory['recovery']['status'] == 'unavailable_after_restart'


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
    assert shown['recovery']['status'] == 'unavailable_after_restart'
    assert shown['recovery']['unknowns'][0] == dict(
        id='u1', origin='frame', category='frame_unknown', status='unavailable_after_restart')
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


class ProseProvider(ControlledServer):
    def __init__(self, text):
        super().__init__()
        self.prose = text

    def infer(self, *args, **kwargs):
        result = super().infer(*args, **kwargs)
        value = json.loads(result.text)
        if 'hypotheses' in value:
            value['hypotheses'][0]['statement'] = self.prose
        return replace(result, text=json.dumps(value))


@pytest.mark.parametrize('text', [
    'possible ｕ９９９', 'possible h999:unverified', 'possible u999-h999',
    'possible ｈ９９９：unverified', 'possible h1-u1', 'possible h1:unverified',
    'possible u999_suffix', 'possible prefixu999', 'possible h9999',
    'possible U999', 'possible um:999-unverified', 'possible ev:ssh:1-h999',
    'possible 日本u999', 'possible ' + 'x' * 129 + '-u999', 'possible h1:',
])
def test_normalized_or_ambiguous_raw_refs_withhold_real_receipt(root, tmp_path, text):
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    # The real schema/receipt remains complete; only advice authorization closes.
    assert metadata['completeness'] == 'partial'
    assert metadata['advisory_refs'] == ['ev:ssh:1', 'h1', 'h2']
    recent, _ = project(root, tmp_path, frame, value, metadata)
    check_export(root, recent, available=False)


@pytest.mark.parametrize('text', ['possible (h1).', 'possible ｈ１', 'possible ev:ssh:1'])
def test_normalized_unambiguous_member_still_exports(root, tmp_path, text):
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    assert metadata['completeness'] == 'complete'
    recent, _ = project(root, tmp_path, frame, value, metadata)
    check_export(root, recent, available=True)


@pytest.mark.parametrize('text', [
    'possible u\u200b999', 'possible h\u200d999', 'possible ev\u200b:ssh:999',
    'possible u\u0301999', 'possible h1\u0301',
    'possible h\u200c1', 'possible \ufeffh1', 'possible h1\u202e',
    'possible h\u20661', 'possible h\u093e1', 'possible ｈ\u0301１',
    'possible h1\u200b\u0301', 'possible a\u0301 h1', 'possible a\u200b\u0301 h1',
    'possible u\u3164999', 'possible u\u115f999', 'possible u\u1160999',
    'possible ev\u3164:ssh:999', 'possible u\u20dd999', 'possible h1\u20dd',
    'possible h1\ue000', 'possible h1\u0378', 'possible h1\ufe0f',
    'possible h1\U000e0100', 'possible h1\x00', 'possible h1\U000e0061',
])
def test_format_and_combining_id_marks_withhold_real_receipt(root, tmp_path, text):
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    assert metadata['completeness'] == 'partial'
    assert metadata['advisory_refs'] == ['ev:ssh:1', 'h1', 'h2']
    recent, _ = project(root, tmp_path, frame, value, metadata)
    assert check_export(root, recent, available=False)['reason_code'] == 'binding_unverified'


@pytest.mark.parametrize('text', ['possible \u200b h1', 'possible \u0301 h1'])
def test_unsupported_marks_anywhere_withhold_complete_receipt(root, tmp_path, text):
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    assert metadata['completeness'] == 'partial'
    recent, _ = project(root, tmp_path, frame, value, metadata)
    check_export(root, recent, available=False)


def test_auth_evidence_id_still_displays_and_exports(root, tmp_path, monkeypatch):
    original_frame, cap = inputs()
    monkeypatch.setitem(execute.__globals__, 'inputs', lambda: (
        replace(original_frame, evidence_refs=('ev:auth:1',)), cap))

    class AuthProvider(ControlledServer):
        def infer(self, *args, **kwargs):
            result = super().infer(*args, **kwargs)
            return replace(result, text=result.text.replace('ev:ssh:1', 'ev:auth:1'))

    _, frame, _, value, metadata = execute(tmp_path, server=AuthProvider())
    assert metadata['completeness'] == 'complete'
    assert 'ev:auth:1' in metadata['advisory_refs']
    recent, _ = project(root, tmp_path, frame, value, metadata)
    check_export(root, recent, available=True)


@pytest.mark.parametrize('source', ['frame', 'broker'])
def test_saved_recent_expires_at_source_deadline_without_metadata_refresh(root, tmp_path, monkeypatch, source):
    broker = ({'evidence_refs': ['ev:ssh:1'], 'trust': 'verified',
               'observed_at': time.time() - 59},) if source == 'broker' else ()
    lane, frame, _, value, metadata = execute(tmp_path, frame_age=59 if source == 'frame' else 0,
                                             broker=broker)
    record = lane._receipts[value['result_handle']]
    receipt_expiry = record['expires_at']
    refs = metadata['evidence_refs']
    assert metadata['expires_at'] == min(receipt_expiry, *(ref['valid_until'] for ref in refs))
    assert metadata['expires_at'] < receipt_expiry
    assert all(ref['valid_until'] - ref['observed_at'] == 60 for ref in refs)
    recent, path = project(root, tmp_path, frame, value, metadata)
    saved = path.read_bytes()
    check_export(root, recent, available=True)
    later = time.time() + 2
    assert metadata['expires_at'] < later < receipt_expiry
    # Re-read exactly the saved bytes. No runtime lookup or reprojection occurs.
    with monkeypatch.context() as patch:
        patch.setattr(time, 'time', lambda: later)
        reread = incident_explain.read_recent_incidents(path.read_bytes())
        binding = reread['incidents'][0]['explanation']['slow_analysis']['binding']
        assert all(ref['freshness'] == 'current' for ref in binding['evidence_refs'])
        assert 'expired' in {incident_explain.handoff_ref_freshness(ref, later)
                             for ref in binding['evidence_refs']}
        check_export(root, reread, available=False)
    assert path.read_bytes() == saved
    assert record['expires_at'] == receipt_expiry


@pytest.mark.parametrize('mutation', ['missing_observed', 'missing_until', 'null', 'future',
                                     'expired', 'at_deadline', 'inverted', 'too_short'])
def test_saved_ref_deadlines_are_independently_checked(root, tmp_path, mutation):
    _, frame, _, value, metadata = execute(tmp_path)
    recent, path = project(root, tmp_path, frame, value, metadata)
    binding = recent['incidents'][0]['explanation']['slow_analysis']['binding']
    ref = binding['evidence_refs'][0]
    now = time.time()
    if mutation == 'missing_observed': del ref['observed_at']
    elif mutation == 'missing_until': del ref['valid_until']
    elif mutation == 'null': ref['valid_until'] = None
    elif mutation == 'future': ref['observed_at'] = now + 1
    elif mutation in {'expired', 'at_deadline'}:
        ref['observed_at'] = now - 60
        ref['valid_until'] = now - 1 if mutation == 'expired' else now
        assert incident_explain.handoff_ref_freshness(ref, now) == 'expired'
    elif mutation == 'inverted': ref['valid_until'] = ref['observed_at']
    else: ref['valid_until'] = binding['expires_at'] - 1
    assert binding['expires_at'] > now  # binding lifetime alone cannot authorize
    assert not incident_explain.valid_handoff_binding(binding, INCIDENT, now)
    path.write_text(json.dumps(recent))
    check_export(root, recent, available=False)


@pytest.mark.parametrize('text', [
    'my_password=syntheticvalue', 'pwd=syntheticvalue', 'PASSWD: syntheticvalue',
    'my_password：syntheticvalue', 'service_token: syntheticvalue',
    'prefixAPI-keySuffix=syntheticvalue', 'prefixprivate_keySuffix: syntheticvalue',
    'my_pass=syntheticvalue', 'my_passphrase=syntheticvalue',
    'prefixcredentialSuffix: syntheticvalue', 'prefixbearerSuffix=syntheticvalue',
    'prefixcookieSuffix=syntheticvalue', 'prefixsecretSuffix: syntheticvalue',
    '"my_password": "syntheticvalue"', "'pwd': 'syntheticvalue'",
    'my_access_key=syntheticvalue', 'clientSecret: syntheticvalue',
    'my_secret_key=syntheticvalue', 'my_session_id=syntheticvalue',
    'my_session-key=syntheticvalue', 'my_sessionToken=syntheticvalue',
    'my_auth=syntheticvalue', 'my_refresh_token=syntheticvalue',
    'my_otp=syntheticvalue', 'my_pin=syntheticvalue',
    'user_pass=syntheticvalue', 'PASS: syntheticvalue', 'passcode: syntheticvalue',
    'pin: syntheticvalue', 'auth: syntheticvalue', 'otp: syntheticvalue', 'key: syntheticvalue',
    'p!wd: syntheticvalue', 'p,w;d: syntheticvalue',
    'p\"wd: syntheticvalue', 'p a s s w o r d: syntheticvalue',
])
def test_secret_key_value_prose_is_wholly_withheld(root, tmp_path, text):
    fixed = 'Details withheld verify through an authorized source'
    assert incident_explain._public_model_text(text) == fixed
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    recent, _ = project(root, tmp_path, frame, value, metadata)
    shown = recent['incidents'][0]['explanation']['slow_analysis']
    assert shown['hypotheses'][0] == fixed
    # Both '=' and ':' are in the requested repertoire. A complete manifest
    # must still export only the fixed replacement, never the secret value.
    assert metadata['completeness'] == 'complete'
    advisory = check_export(root, recent, available=True)
    assert advisory['hypotheses'][0] == fixed
    assert 'syntheticvalue' not in json.dumps(recent)
    assert all(b'syntheticvalue' not in data for data in handoff.encode_files(package(root, now=time.time())).values())


@pytest.mark.parametrize('text', ['p\u200bwd=syntheticvalue', 'my_ac\u200ccess_key=syntheticvalue',
                                  'client\ufeffSecret: syntheticvalue', 'PA\u202eSS: syntheticvalue',
                                  'p\u3164wd=syntheticvalue', 'p\u115fwd=syntheticvalue',
                                  'p\u1160wd=syntheticvalue', 'p\u20ddwd=syntheticvalue',
                                  'p\ufe0fwd=syntheticvalue', 'p\u0301wd=syntheticvalue'])
def test_format_obscured_secret_is_removed_before_public_projection(root, tmp_path, text):
    fixed = 'Details withheld verify through an authorized source'
    assert incident_explain._public_model_text(text) == fixed
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    # Both boundaries close: raw reference ambiguity and public prose privacy.
    assert metadata['completeness'] == 'partial'
    recent, _ = project(root, tmp_path, frame, value, metadata)
    assert recent['incidents'][0]['explanation']['slow_analysis']['hypotheses'][0] == fixed
    check_export(root, recent, available=False)
    assert 'syntheticvalue' not in json.dumps(recent)
    assert all(b'syntheticvalue' not in data for data in handoff.encode_files(package(root, now=time.time())).values())


@pytest.mark.parametrize('text,expected', [('compass: north', 'compass north'),
    ('bypass: allowed', 'bypass allowed'), ('passive: yes', 'passive yes'),
    ('passing: normal', 'passing normal'), ('spinning: normal', 'spinning normal'),
    ('author: Alice', 'author Alice'), ('author_name: Alice', 'authorname Alice'),
    ('keynote: normal', 'keynote normal'), ('adoption: normal', 'adoption normal')])
def test_ordinary_words_containing_pass_remain_visible(root, tmp_path, text, expected):
    assert incident_explain._public_model_text(text) == expected
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    assert metadata['completeness'] == 'complete'
    recent, _ = project(root, tmp_path, frame, value, metadata)
    assert recent['incidents'][0]['explanation']['slow_analysis']['hypotheses'][0] == expected
    assert check_export(root, recent, available=True)['hypotheses'][0] == expected
    files = handoff.encode_files(package(root, now=time.time()))
    assert expected.encode() in files['handoff.json']
    assert expected.encode() in files['handoff.ja.md']


@pytest.mark.parametrize('text', [
    '仮説を確認してください。 (h1)', 'ネットワークの遅延を確認。 ev:ssh:1',
    'ひらがな・カタカナ・漢字「観測」', '可能性： ｈ１。',
    'か\u3099くせつを確認。 h1',
])
def test_allowlisted_japanese_and_normalized_members_export(root, tmp_path, text):
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    assert metadata['completeness'] == 'complete'
    recent, _ = project(root, tmp_path, frame, value, metadata)
    shown = recent['incidents'][0]['explanation']['slow_analysis']['hypotheses'][0]
    assert shown != 'Details withheld verify through an authorized source'
    check_export(root, recent, available=True)


@pytest.mark.parametrize('mark', ['\u3164', '\u20dd', '\ufe0f', '\u0301'])
@pytest.mark.parametrize('field', ['hypotheses', 'unknowns', 'next_checks'])
def test_recent_writer_guards_each_field_independently_of_binding(root, tmp_path, mark, field):
    # Start with a real complete receipt and valid binding. Inject only at the
    # in-memory public write seam to prove the writer itself guards all fields.
    _, frame, _, value, metadata = execute(tmp_path)
    recent, path = project(root, tmp_path, frame, value, metadata)
    recent['incidents'][0]['explanation']['slow_analysis'][field] = [f'p{mark}wd=syntheticvalue']
    explainer = incident_explaind.Explainer(incidents=tmp_path/'writer-incidents',
        state=tmp_path/'writer-state', status_path=path.with_name('status.json'), clock=time.time)
    explainer.prepare()
    explainer.recent = recent['incidents']
    explainer.recent_status()
    saved = path.read_bytes()
    assert b'syntheticvalue' not in saved
    reread = incident_explain.read_recent_incidents(saved)
    assert reread is not None
    slow = reread['incidents'][0]['explanation']['slow_analysis']
    assert slow[field] == ['Details withheld verify through an authorized source']
    assert slow['binding']['completeness'] == 'complete'
    check_export(root, reread, available=True)
    assert all(b'syntheticvalue' not in data for data in handoff.encode_files(package(root, now=time.time())).values())


@pytest.mark.parametrize('mark', ['\u3164', '\u20dd', '\ufe0f', '!', ',', ' ', '\ue000'])
def test_secret_skeleton_is_independent_of_character_allowlist(mark):
    import unicodedata
    text = unicodedata.normalize('NFKC', f'p{mark}wd=syntheticvalue')
    assert incident_explain._public_secret_text(text)


@pytest.mark.parametrize('text', ['h1\ud800', 'h1\udfff', 'h1\u0378', 'h1\ue000',
                                  'h1\n', 'h1\t', 'h1\u3099', 'h1\u309a'])
def test_unsupported_codepoints_never_claim_exhaustive_references(text):
    from azazel_nexus_runtime.mio_advisory_manifest import references
    assert references({'statement': text}) == (set(), set(), True)
    assert incident_explain._public_model_text(text) == 'Details withheld verify through an authorized source'


def test_nfkc_composed_secret_letter_is_withheld_by_repertoire():
    import unicodedata
    text = 'p\u0301wd=syntheticvalue'
    # NFKC composes p + acute; the ASCII skeleton keeps its boundary, not p.
    # The independent allowlist must therefore reject this whole model text.
    assert incident_explain._secret_skeleton(unicodedata.normalize('NFKC', text)) == '|wd|syntheticvalue'
    assert incident_explain.guard_public_model_text(text) == 'Details withheld verify through an authorized source'


@pytest.mark.parametrize('text', [
    'hint,pwd: syntheticvalue', 'hint;pwd: syntheticvalue',
    'hint(pwd): syntheticvalue', 'hint:pwd: syntheticvalue',
    'foo,pin: syntheticvalue', 'foo,auth: syntheticvalue',
    'status: good pwd: syntheticvalue', 'status:good:pwd:syntheticvalue',
    'status=good=pwd=syntheticvalue', 'hint: p,w;d: syntheticvalue',
    'hint: user_pass: syntheticvalue', 'hint: clientSecret: syntheticvalue',
    'hint(PwD): syntheticvalue',
    'ｈｉｎｔ（ｐｗｄ）： syntheticvalue',
])
def test_punctuated_secret_keys_withheld_through_real_receipt(root, tmp_path, text):
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    recent, path = project(root, tmp_path, frame, value, metadata)
    # A complete manifest must not mask a privacy failure.
    assert metadata['completeness'] == 'complete'
    fixed = 'Details withheld verify through an authorized source'
    assert recent['incidents'][0]['explanation']['slow_analysis']['hypotheses'][0] == fixed
    assert check_export(root, recent, available=True)['hypotheses'][0] == fixed
    assert b'syntheticvalue' not in path.read_bytes()
    assert all(b'syntheticvalue' not in data for data in
               handoff.encode_files(package(root, now=time.time())).values())


@pytest.mark.parametrize('separator', [chr(i) for i in range(128)
    if not chr(i).isalnum()])
def test_short_secret_key_elements_use_all_ascii_non_alphanumerics(separator):
    # Test the secret check independently: unsupported control characters
    # also close the separate repertoire guard, but cannot hide a key here.
    assert incident_explain._public_secret_text(f'hint{separator}pwd: syntheticvalue')


@pytest.mark.parametrize('text', [
    'hint,p\u200bwd: syntheticvalue', 'hint;pw\u2060d: syntheticvalue',
    'hint: pw\ufeffd: syntheticvalue',
])
def test_original_key_elements_remove_format_controls_before_secret_check(text):
    assert incident_explain._public_secret_text(text)


@pytest.mark.parametrize('text', [
    'packet loss 5% h1', 'A & B h1', 'retry + backoff h1',
    *[f'observation {symbol} h1' for symbol in '/*#@~^|<>=$'],
])
def test_requested_ascii_symbols_keep_manifest_complete(root, tmp_path, text):
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    assert metadata['completeness'] == 'complete'
    recent, _ = project(root, tmp_path, frame, value, metadata)
    advisory = check_export(root, recent, available=True)
    # Slash still triggers the independent path privacy guard.
    if '/' not in text:
        assert advisory['hypotheses'][0] != 'Details withheld verify through an authorized source'
    expected = {'packet loss 5% h1': 'packet loss h', 'A & B h1': 'A B h',
                'retry + backoff h1': 'retry backoff h'}.get(text)
    if expected is not None:
        assert recent['incidents'][0]['explanation']['slow_analysis']['hypotheses'][0] == expected
        assert advisory['hypotheses'][0] == expected
        files = handoff.encode_files(package(root, now=time.time()))
        assert json.loads(files['handoff.json'])['ai_assessment']['slow_advisory']['hypotheses'][0] == expected
        assert expected.encode() in files['handoff.ja.md']


@pytest.mark.parametrize('text,expected,complete', [
    ('status: good', 'status good', True),
    ('hint: see u1', 'hint see u', True),
    ('仮説h1を確認', None, False),
    ('参照ev:ssh:1を確認。', None, False),
    ('不明点u1を確認。', None, False),
    ('仮説 h1、ev:ssh:1。', '仮説 hevssh', True),
    ('不明点（u1）。', '不明点u', True),
])
def test_delimited_ids_and_ordinary_key_prose_contract(root, tmp_path, text, expected, complete):
    class UnknownReferenceProvider(ProseProvider):
        def infer(self, *args, **kwargs):
            result = super().infer(*args, **kwargs)
            payload = json.loads(result.text)
            if 'hypotheses' in payload:
                # Bind u1 via the actual frame unknown body, not a synthetic manifest.
                payload['hypotheses'][0]['missing_evidence'] = ['unknown']
            return replace(result, text=json.dumps(payload))
    _, frame, _, value, metadata = execute(tmp_path, server=UnknownReferenceProvider(text))
    assert 'u1' in metadata['advisory_refs']
    assert metadata['completeness'] == ('complete' if complete else 'partial')
    recent, _ = project(root, tmp_path, frame, value, metadata)
    advisory = check_export(root, recent, available=complete)
    if complete:
        assert advisory['hypotheses'][0] == expected
        files = handoff.encode_files(package(root, now=time.time()))
        assert expected in json.loads(files['handoff.json'])['ai_assessment']['slow_advisory']['hypotheses']
        assert expected in files['handoff.ja.md'].decode()


@pytest.mark.parametrize('identifier,complete', [
    ('h¹', True), ('𝐡1', True), ('ｈ１', True),
    ('h⁹⁹⁹', False), ('𝐡999', False), ('ｈ９９９', False),
])
def test_compatibility_ids_follow_normalized_membership(root, tmp_path, identifier, complete):
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider('possible ' + identifier))
    assert metadata['completeness'] == ('complete' if complete else 'partial')
    assert metadata['unlisted_prose_ids'] is (not complete)
    assert metadata['advisory_refs'] == ['ev:ssh:1', 'h1', 'h2']
    recent, _ = project(root, tmp_path, frame, value, metadata)
    check_export(root, recent, available=complete)


_R12_SECRET_PROSE = [
    'hint、pwd: syntheticvalue', 'hint。pwd: syntheticvalue',
    'hint「pwd」: syntheticvalue', 'hint【pwd】: syntheticvalue',
    'foo、pin: syntheticvalue', 'foo「auth」: syntheticvalue',
    'a=1、pwd=syntheticvalue', 'hint,p,w;d: syntheticvalue',
    'hint、ＰＷＤ： syntheticvalue', 'hint「p」【w】、d: syntheticvalue',
    'hint、pa、ss、wd: syntheticvalue', 'hint、to、ke、n=syntheticvalue',
    'a=1。p\u200bwd=syntheticvalue',
]


@pytest.mark.parametrize('text', _R12_SECRET_PROSE)
def test_r12_unicode_key_boundaries_through_real_receipt(root, tmp_path, text):
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    complete = '\u200b' not in text
    assert metadata['completeness'] == ('complete' if complete else 'partial')
    recent, path = project(root, tmp_path, frame, value, metadata)
    fixed = 'Details withheld verify through an authorized source'
    assert recent['incidents'][0]['explanation']['slow_analysis']['hypotheses'] == [fixed, 'possible']
    advisory = check_export(root, recent, available=complete)
    if complete:
        assert advisory['hypotheses'][0] == fixed
    assert b'syntheticvalue' not in path.read_bytes()
    assert all(b'syntheticvalue' not in data for data in
               handoff.encode_files(package(root, now=time.time())).values())


@pytest.mark.parametrize('text', _R12_SECRET_PROSE[:8])
@pytest.mark.parametrize('field', ['hypotheses', 'unknowns', 'next_checks'])
def test_r12_recent_writer_unicode_key_boundaries(root, tmp_path, text, field):
    _, frame, _, value, metadata = execute(tmp_path)
    recent, path = project(root, tmp_path, frame, value, metadata)
    recent['incidents'][0]['explanation']['slow_analysis'][field] = [text]
    explainer = incident_explaind.Explainer(incidents=tmp_path/'writer-incidents',
        state=tmp_path/'writer-state', status_path=path.with_name('status.json'), clock=time.time)
    explainer.prepare()
    explainer.recent = recent['incidents']
    explainer.recent_status()
    saved = path.read_bytes()
    assert b'syntheticvalue' not in saved
    reread = incident_explain.read_recent_incidents(saved)
    assert reread is not None
    slow = reread['incidents'][0]['explanation']['slow_analysis']
    assert slow[field] == ['Details withheld verify through an authorized source']
    assert slow['binding']['completeness'] == 'complete'
    check_export(root, reread, available=True)
    assert all(b'syntheticvalue' not in data for data in
               handoff.encode_files(package(root, now=time.time())).values())


@pytest.mark.parametrize('separator', ['、', '。', '「', '」', '【', '】', '：', '仮', 'é', '😀'])
@pytest.mark.parametrize('key', ['pass', 'pwd', 'passwd', 'passphrase', 'passcode',
                               'pin', 'auth', 'otp', 'key', 'token'])
def test_r12_unicode_separators_and_aliases_independent_of_repertoire(separator, key):
    import unicodedata
    text = unicodedata.normalize('NFKC', f'hint{separator}{key}: syntheticvalue')
    assert incident_explain._public_secret_text(text)


@pytest.mark.parametrize('text', ['hint,p,w;d: syntheticvalue',
    'hint、pa、ss、ph、ra、se: syntheticvalue', 'hint【pa】【ss】【co】【de】: syntheticvalue',
    'hint,to,ke,n: syntheticvalue', 'hint,a,u,t,h: syntheticvalue'])
def test_r12_short_fragment_sequences_detect_aliases(text):
    assert incident_explain._public_secret_text(text)


@pytest.mark.parametrize('text', ['hint,passi,ve: normal', 'hint,passw,ord: normal',
                                  'hint,to,ken: normal', 'hint,p,word,d: normal'])
def test_r12_fragment_joining_never_crosses_long_elements(text):
    assert not incident_explain._public_secret_text(text)


@pytest.mark.parametrize('text,expected', [
    ('hint、pwd: v', 'hint|pwd|v'), ('hint。pwd=v', 'hint|pwd|v'),
    ('hint「pwd」： v', 'hint|pwd|v'), ('hint【pwd】: v', 'hint|pwd|v'),
    ('hint,p,w;d: v', 'hint|p|w|d|v'),
    ('a=1、p\u200bwd=v', 'a|1|pwd|v'),
    ('ｈｉｎｔ、ｐｗｄ： v', 'hint|pwd|v'),
])
def test_r12_skeleton_preserves_boundaries_after_nfkc_and_cf_removal(text, expected):
    assert incident_explain._secret_skeleton(text) == expected


@pytest.mark.parametrize('text,expected', [
    ('hint、passi、ve: normal', 'hintpassive normal'),
    # Projection joins to+ken; the writer must recheck the resulting long label.
    ('hint、to、ken: normal', 'Details withheld verify through an authorized source'),
    ('hint、p、word、d: normal', 'hintpwordd normal'),
])
def test_r12_long_elements_stop_fragment_joining_through_real_receipt(root, tmp_path, text, expected):
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    assert metadata['completeness'] == 'complete'
    recent, path = project(root, tmp_path, frame, value, metadata)
    assert recent['incidents'][0]['explanation']['slow_analysis']['hypotheses'][0] == expected
    assert expected.encode() in path.read_bytes()
    assert check_export(root, recent, available=True)['hypotheses'][0] == expected
    files = handoff.encode_files(package(root, now=time.time()))
    assert expected in json.loads(files['handoff.json'])['ai_assessment']['slow_advisory']['hypotheses']
    assert expected.encode() in files['handoff.ja.md']


@pytest.mark.parametrize('key', ['hint、pwd', 'hint,p,w;d', 'foo「auth」'])
@pytest.mark.parametrize('secret_value', ['合成秘匿値', '１２３４', '。。。'])
def test_r12_key_is_guarded_when_value_has_no_skeleton_letters(root, tmp_path, key, secret_value):
    text = f'{key}: {secret_value}'
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    assert metadata['completeness'] == 'complete'
    recent, path = project(root, tmp_path, frame, value, metadata)
    fixed = 'Details withheld verify through an authorized source'
    assert recent['incidents'][0]['explanation']['slow_analysis']['hypotheses'][0] == fixed
    assert check_export(root, recent, available=True)['hypotheses'][0] == fixed
    files = handoff.encode_files(package(root, now=time.time()))
    assert fixed in json.loads(files['handoff.json'])['ai_assessment']['slow_advisory']['hypotheses']
    assert fixed.encode() in files['handoff.ja.md']
    assert secret_value not in json.dumps(recent, ensure_ascii=False)
    assert all(secret_value not in data.decode() for data in [path.read_bytes(), *files.values()])


@pytest.mark.parametrize('text', [
    'prefixTokenSuffix=v', 'prefixTokenSuffix=syntheticvalue',
    'myAccessKey: syntheticvalue', 'x_password_y=syntheticvalue',
    *[f'prefix{label}Suffix=syntheticvalue' for label in (
        'password', 'passwd', 'passphrase', 'passcode', 'secret', 'credential',
        'token', 'bearer', 'cookie', 'api_key', 'api-key', 'apiKey',
        'access_key', 'access-key', 'secret_key', 'secret-key',
        'private_key', 'private-key', 'client_secret', 'client-secret',
        'refresh_token', 'refresh-token', 'session_id', 'session-id',
        'session_key', 'session-key', 'session_token', 'session-token')],
])
def test_r13_long_label_substrings_through_real_receipt(root, tmp_path, text):
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    assert metadata['completeness'] == 'complete'
    recent, path = project(root, tmp_path, frame, value, metadata)
    fixed = 'Details withheld verify through an authorized source'
    assert recent['incidents'][0]['explanation']['slow_analysis']['hypotheses'] == [fixed, 'possible']
    assert check_export(root, recent, available=True)['hypotheses'][0] == fixed
    files = handoff.encode_files(package(root, now=time.time()))
    assert json.loads(files['handoff.json'])['ai_assessment']['slow_advisory']['hypotheses'][0] == fixed
    assert fixed.encode() in files['handoff.ja.md']
    assert all(b'syntheticvalue' not in data for data in [path.read_bytes(), *files.values()])
    assert b'prefixTokenSuffix' not in path.read_bytes()


@pytest.mark.parametrize('text,expected', [
    ('check auth status h1', 'check auth status h'),
    ('pin the route h1', 'pin the route h'),
    ('pass the check h1', 'pass the check h'),
    ('key observation h1', 'key observation h'),
])
def test_r13_natural_short_alias_prose_through_real_receipt(root, tmp_path, text, expected):
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    assert metadata['completeness'] == 'complete'
    recent, path = project(root, tmp_path, frame, value, metadata)
    assert recent['incidents'][0]['explanation']['slow_analysis']['hypotheses'][0] == expected
    assert expected.encode() in path.read_bytes()
    assert check_export(root, recent, available=True)['hypotheses'][0] == expected
    files = handoff.encode_files(package(root, now=time.time()))
    assert json.loads(files['handoff.json'])['ai_assessment']['slow_advisory']['hypotheses'][0] == expected
    assert expected.encode() in files['handoff.ja.md']


@pytest.mark.parametrize('text,expected', [
    ('pin_status: syntheticvalue', 'pinstatus syntheticvalue'),
    ('user.auth.name: syntheticvalue', 'userauthname syntheticvalue'),
    ('pass-mode: syntheticvalue', 'passmode syntheticvalue'),
    ('my otp value: syntheticvalue', 'my otp value syntheticvalue'),
    ('my_key_name: syntheticvalue', 'mykeyname syntheticvalue'),
    ('hint,pwd,status: syntheticvalue', 'hintpwdstatus syntheticvalue'),
])
def test_r13_short_alias_requires_its_own_immediate_value(root, tmp_path, text, expected):
    # R13-L1 explicitly narrows the old W8 rule: another key element between
    # the short alias and operator does not make that alias a secret key.
    assert not incident_explain._public_secret_text(text)
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    assert metadata['completeness'] == 'complete'
    recent, path = project(root, tmp_path, frame, value, metadata)
    assert recent['incidents'][0]['explanation']['slow_analysis']['hypotheses'][0] == expected
    assert check_export(root, recent, available=True)['hypotheses'][0] == expected
    files = handoff.encode_files(package(root, now=time.time()))
    assert expected.encode() in path.read_bytes()
    assert json.loads(files['handoff.json'])['ai_assessment']['slow_advisory']['hypotheses'][0] == expected
    assert expected.encode() in files['handoff.ja.md']


@pytest.mark.parametrize('alias', ['pass', 'pwd', 'pin', 'auth', 'otp', 'key'])
@pytest.mark.parametrize('suffix', ['=syntheticvalue', ' : syntheticvalue',
    '   ：syntheticvalue', ' abcdefgh', ' Ab12Cd34', ' abcdefghijklmnop  '])
def test_r13_short_alias_value_forms_through_real_receipt(root, tmp_path, alias, suffix):
    text = alias + suffix
    assert incident_explain._public_secret_text(text)
    _, frame, _, value, metadata = execute(tmp_path, server=ProseProvider(text))
    assert metadata['completeness'] == 'complete'
    recent, path = project(root, tmp_path, frame, value, metadata)
    fixed = 'Details withheld verify through an authorized source'
    assert recent['incidents'][0]['explanation']['slow_analysis']['hypotheses'] == [fixed, 'possible']
    assert check_export(root, recent, available=True)['hypotheses'][0] == fixed
    files = handoff.encode_files(package(root, now=time.time()))
    assert json.loads(files['handoff.json'])['ai_assessment']['slow_advisory']['hypotheses'][0] == fixed
    assert fixed.encode() in files['handoff.ja.md']
    secret_value = suffix.replace('=', '').replace(':', '').replace('：', '').strip()
    assert all(secret_value.encode() not in data for data in [path.read_bytes(), *files.values()])


@pytest.mark.parametrize('alias', ['pass', 'pwd', 'pin', 'auth', 'otp', 'key'])
@pytest.mark.parametrize('suffix', [' abcdefg', ' status h1', ' observation h1',
                                   '_status: normal', '-mode=normal', ''])
def test_r13_short_alias_context_boundary(alias, suffix):
    assert not incident_explain._public_secret_text(alias + suffix)


@pytest.mark.parametrize('text', ['prefixTokenSuffix', 'prefixPasswdSuffix',
    'prefixPassphraseSuffix', 'prefixPasscodeSuffix', 'myAccessKey',
    'x_password_y', 'hint、to、ke、n'])
def test_r13_long_labels_need_no_value_context(text):
    assert incident_explain._public_secret_text(text)
