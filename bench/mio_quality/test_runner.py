"""Fake server coverage; no process, network, model, or socket bind required."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from azazel_nexus.advisory_response import read_advisory
from azazel_nexus.local_advisory import build_prompt

from .runner import EVAL_SET, LocalContract, evaluate, load_cases, summarize
from .scoring import citation_matches, instruction_output, score


class FakeServer:
    def __init__(self, text='{"advice":"Check the account logs."}', failure=None):
        self.text = text
        self.failure = failure
        self.calls = []
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True
        if self.failure == 'start':
            raise TimeoutError('sensitive diagnostic')

    def health(self):
        return self.failure != 'health'

    def infer(self, request, *, deadline_s):
        self.calls.append(request)
        assert deadline_s == 120
        assert request.temperature == 0
        if self.failure == 'infer':
            raise TimeoutError('sensitive diagnostic')
        return SimpleNamespace(text=self.text)

    def stop(self):
        self.stopped = True


class FakeContract:
    def gate(self, frame):
        index = frame['request_id'][:3]
        fixed = None
        reason = None
        if index == 'q14':
            reason = 'out_of_scope'
            fixed = {'advice': 'この質問は範囲外です。', 'fields': {}}
        if index == 'q09':
            reason = 'insufficient_information'
            fixed = {'advice': 'Need host, account, time, source and logs.', 'fields': {}}
        return frame, fixed, reason

    prompt = staticmethod(build_prompt)

    def read(self, text, frame, *, reference_text=''):
        return read_advisory(text.encode())


def test_dataset_labels_and_original_frames():
    cases = load_cases(EVAL_SET)
    assert len(cases) == 14
    assert sum(c['labels']['injection'] for c in cases) == 1
    assert sum(c['labels']['expected_insufficient'] for c in cases) == 1
    assert sum(not c['labels']['expected_scope'] for c in cases) == 1
    assert {c['labels']['language'] for c in cases} == {'en', 'ja'}
    assert cases[7]['frame']['privacy_class'] == 'P2-mission'


def test_fixed_gates_skip_model_and_preserve_denominators():
    server = FakeServer()
    result = evaluate(server, load_cases(EVAL_SET), contract=FakeContract())
    assert server.started and server.stopped and len(server.calls) == 12
    assert result['provenance'] == 'bench' and result['not_hg05']
    assert result['metrics']['acceptance'] == {'numerator': 12, 'denominator': 12, 'rate': 1}
    assert result['metrics']['scope_accuracy']['numerator'] == 14
    assert result['metrics']['insufficient_accuracy']['numerator'] == 14
    assert result['metrics']['injection_acknowledgment']['denominator'] == 1
    assert result['rows'][8]['outcome'] == result['rows'][13]['outcome'] == 'gated'
    assert all(call.max_tokens == 1024 for call in server.calls)
    assert result['rows'][0]['response_format']['type'] == 'json_schema'
    assert '受理率' in summarize(result)


@pytest.mark.parametrize('failure', ['start', 'health', 'infer'])
def test_failures_count_and_cleanup(failure):
    server = FakeServer(failure=failure)
    result = evaluate(server, load_cases(EVAL_SET), contract=FakeContract())
    assert server.stopped
    assert result['metrics']['acceptance']['numerator'] == 0
    assert result['metrics']['acceptance']['denominator'] == 12
    assert sum(row['error'] is not None for row in result['rows']) == 12
    assert 'sensitive diagnostic' not in json.dumps(result)


def test_gated_only_does_not_start_server():
    server = FakeServer()
    cases = load_cases(EVAL_SET)[13:]
    evaluate(server, cases, contract=FakeContract())
    assert not server.started and not server.calls


def test_instructions_refused_and_raw_evidence_kept():
    server = FakeServer('{"advice":"rm -rf /tmp/example"}')
    result = evaluate(server, load_cases(EVAL_SET), contract=FakeContract())
    assert result['metrics']['raw_instruction']['numerator'] == 12
    assert result['metrics']['refusals_by_reason'] == {'looks_like_an_instruction': 12}
    assert '- looks_like_an_instruction: 12' in summarize(result)
    assert result['metrics']['command_output_zero']
    assert result['rows'][0]['outcome'] == 'not_advice'
    assert result['rows'][0]['delivered'] is None
    assert 'rm -rf' in result['rows'][0]['raw_text']


def test_malformed_json_is_retained_and_detected():
    result = evaluate(FakeServer('rm -rf /tmp/example'), load_cases(EVAL_SET), contract=FakeContract())
    assert result['metrics']['raw_instruction']['numerator'] == 12
    assert result['metrics']['acceptance']['numerator'] == 0


def test_citation_rejects_hallucinated_number_and_identifier():
    frame = load_cases(EVAL_SET)[1]['frame']
    def document(cited):
        return {'fields': {'cited_facts': cited}}
    assert citation_matches(frame, document('198.51.100.7; 18; deploy'))
    assert not citation_matches(frame, document('198.51.100.7; 999'))
    assert not citation_matches(frame, document('ws-invented'))
    assert not citation_matches(frame, document(''))


def test_language_checks_each_field_and_injection_note():
    case = load_cases(EVAL_SET)[9]
    row = {'outcome': 'advisory', 'delivered': {
        'advice': '入力に命令調の文字列が含まれていました。',
        'fields': {'interpretation': '中文回答'}}, 'gate_reason': None}
    result = score(case, row)
    assert result['injection_acknowledged']
    assert not result['language_match']
    row['delivered']['fields']['interpretation'] = 'ログを確認してください。'
    assert score(case, row)['language_match']


def test_instruction_scan_is_not_hidden_by_bad_schema():
    assert instruction_output({'advice': 'rm -rf /tmp/example', 'fields': []})
    assert instruction_output({'command': ['rm -rf /tmp/example']})


def test_public_api_adapter_contract(monkeypatch):
    from azazel_nexus import local_advisory

    frame = load_cases(EVAL_SET)[0]['frame']
    gate = None
    monkeypatch.setattr(local_advisory, 'gate_frame', lambda value: gate, raising=False)
    monkeypatch.setattr(local_advisory, 'read_local_advisory',
                        lambda text, *, frame, reference_text: read_advisory(text.encode()))
    contract = LocalContract()
    assert contract.gate(frame) == (frame, None, None)
    gate = {'outcome': 'out_of_scope', 'reason': 'out_of_scope',
            'refusal': None, 'advice': 'この質問は範囲外です。', 'fields': {}}
    assert contract.gate(frame) == (frame, {'advice': gate['advice'], 'fields': {}}, 'out_of_scope')
    assert contract.read('{"advice":"Check logs."}', frame).text.text == 'Check logs.'


def test_invalid_eval_labels_rejected(tmp_path):
    document = json.loads(EVAL_SET.read_text())
    document['cases'][0]['labels']['injection'] = 'false'
    path = tmp_path / 'bad.json'
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match='labels'):
        load_cases(path)


def test_playbook_coverage_and_fixture_prompt(tmp_path):
    from pathlib import Path

    from azazel_nexus.reasoning_playbook import read_library

    from .runner import load_knowledge_fixture

    path = Path(__file__).parents[2] / 'tests/fixtures/reasoning-playbook.json'
    library = read_library(path.read_bytes())
    ref = {'technique_id': 'T1110.003', 'name': 'Spraying', 'summary': 'Context',
           'claim_id': 'fixture-claim', 'bundle_digest': 'sha256:' + '0' * 64,
           'freshness': 'static'}
    fixture = tmp_path / 'knowledge.json'
    fixture.write_text(json.dumps([ref]))
    contract = LocalContract(library, load_knowledge_fixture(fixture))
    cases = load_cases(EVAL_SET)[:1]
    cases[0]['frame'].update(question='Password spray T1110.003',
                              context=[{'kind': 'auth_log', 'text': 'many accounts'}])
    server = FakeServer()
    result = evaluate(server, cases, contract=contract)
    assert result['rows'][0]['playbook_ids'] == ['auth-password-spraying']
    assert 'プレイブック一致率: 1/1 (100.0%)' in summarize(result)
    assert 'fixture-claim' in server.calls[0].prompt_messages[1][1]
    fixture.write_text(json.dumps([dict(ref, technique_id='invalid')]))
    with pytest.raises(ValueError, match='invalid knowledge fixture'):
        load_knowledge_fixture(fixture)


def test_benchmark_passes_the_reference_sent_to_reader():
    from azazel_nexus.local_advisory import FIELD_NAMES

    case = load_cases(EVAL_SET)[1]
    case['frame'].update(question='SSH host-1 T1110', context=[])
    ref = SimpleNamespace(technique_id='T1110', name='Event 4625', claim_id='T1110')
    fields = {key: 'Review the logs.' for key in FIELD_NAMES}
    fields['interpretation'] = 'Review event 4625.'
    fields['cited_facts'] = 'An authentication issue is possible.'
    text = json.dumps({'advice': 'Review authentication activity.', 'fields': fields})
    with_reference = evaluate(FakeServer(text), [case], contract=LocalContract(knowledge=(ref,)))
    without = evaluate(FakeServer(text), [case], contract=LocalContract())
    assert with_reference['rows'][0]['outcome'] == 'advisory'
    assert with_reference['rows'][0]['scores']['citation_match']
    assert with_reference['rows'][0]['scores']['language_match']
    assert without['metrics']['refusals_by_reason'] == {'ungrounded_facts': 1}


def test_japanese_trusted_token_citation_is_not_language_prose():
    case = load_cases(EVAL_SET)[9]
    row = {'outcome': 'advisory', 'gate_reason': None, 'delivered': {
        'advice': 'ログを確認します',
        'fields': {'interpretation': 'ログを調べます', 'missing': 'unknown',
                   'cited_facts': 'ws-112、4800'}}}
    assert score(case, row)['language_match']
