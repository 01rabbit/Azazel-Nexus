"""Evaluate fixed local-advice frames without changing production admission."""
from __future__ import annotations

import argparse
import json
import math
import re
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

from azazel_nexus.advisory_response import AdvisoryRefused
from azazel_nexus.reasoning_playbook import compose, load_library, match, technique_ids
from bench.mio_local.runner import digest, runtime_server

from .scoring import aggregate, score

EVAL_SET = Path(__file__).with_name('eval_set.json')
SCHEMA = 'azazel-nexus/mio-quality/1'


def advisory_document(advisory):
    return {'advice': advisory.text.text if advisory.text else None,
            'fields': dict(advisory.data.fields) if advisory.data else {}}


class LocalContract:
    """Bench adapter for deterministic retrieval and optional explanation."""

    def __init__(self, playbooks=None, knowledge=(), retriever=None):
        from azazel_nexus import local_advisory

        self.retriever = retriever
        self.retrievals = {}
        self.api = local_advisory
        self.playbooks = playbooks
        self.knowledge = knowledge
        if not hasattr(self.api, 'gate_frame'):
            raise RuntimeError('Lane A gate_frame API is required')

    def gate(self, frame, deadline_s=120):
        from azazel_nexus_runtime.mio_embedding import retrieve

        values = retrieve(frame, self.playbooks, self.retriever, end=time.monotonic() + deadline_s)
        self.retrievals[frame['request_id']] = values
        result = self.api.gate_frame(frame, max(values[1], default=-1.0))
        if result is None:
            return frame, None, None
        return frame, {'advice': result['advice'], 'fields': result['fields']}, result['reason']

    def matches(self, frame):
        return self.retrievals[frame['request_id']][0]

    def prompt(self, frame):
        ids = technique_ids(frame)
        knowledge = tuple(ref for ref in self.knowledge if ref.technique_id in ids)[:16]
        return self.api.build_prompt(frame, playbooks=self.matches(frame), knowledge=knowledge)

    def pipeline(self, server, frame, deadline_s):
        from azazel_nexus_runtime.mio_locald import retrieval_pipeline

        end = time.monotonic() + deadline_s - self.retrievals[frame['request_id']][3] / 1000
        ids = technique_ids(frame)
        knowledge = tuple(ref for ref in self.knowledge if ref.technique_id in ids)[:16]
        books, similarities, method, embed_ms = self.retrievals[frame['request_id']]
        return retrieval_pipeline(server, frame, books, knowledge, end=end,
                                  similarities=similarities, retrieval=method, embed_ms=embed_ms)

    def read(self, text, frame, *, reference_text=''):
        return self.api.read_local_advisory(text, frame=frame, reference_text=reference_text)


def evaluate(server, cases, *, contract, max_tokens=1024, deadline_s=120):
    """Fake-injectable server with start/health/infer/stop, like LocalServer.

    Preflight every gate before starting a server. Gated frames never invoke
    inference. Failures remain in every applicable denominator.
    """
    from azazel_nexus_runtime.mio_serve import LocalInferenceRequest, inference_document

    prepared = [(case, contract.gate(case['frame'], deadline_s=deadline_s)
                 if isinstance(contract, LocalContract) else contract.gate(case['frame'])) for case in cases]
    rows = []
    startup_error = None
    needs_server = server is not None and any(advice is None for _, (_, advice, _) in prepared)
    try:
        if needs_server:
            try:
                server.start()
                if not server.health():
                    raise RuntimeError('unhealthy')
            except Exception as exc:  # noqa: BLE001 - record type, never exception contents
                startup_error = type(exc).__name__
        for case, (frame, fixed_advisory, reason) in prepared:
            row = {'frame_id': case['frame']['request_id'], 'gate_reason': reason,
                   'outcome': 'error', 'error': None, 'refusal': None,
                   'raw_text': None, 'raw_document': None, 'delivered': None, 'playbook_ids': []}
            began = time.monotonic()
            if hasattr(contract, 'matches'):
                row['playbook_ids'] = [entry.id for entry in contract.matches(frame)]
            if fixed_advisory is not None:
                row.update(outcome='gated', delivered=fixed_advisory)
            elif startup_error:
                row['error'] = startup_error
            else:
                try:
                    if hasattr(contract, 'pipeline'):
                        generations = []
                        row['generations'] = generations

                        def infer(request, *, deadline_s, generations=generations, row=row):
                            result = server.infer(request, deadline_s=deadline_s)
                            try:
                                raw_document = json.loads(result.text)
                            except (ValueError, TypeError):
                                raw_document = {'advice': result.text}
                            generations.append({'request': inference_document(request),
                                                'raw_text': result.text,
                                                'raw_document': raw_document,
                                                'phase': 'explanation'})
                            row['raw_text'] = '\n'.join(g['raw_text'] for g in generations)
                            row['raw_document'] = {'generations': [g['raw_document'] for g in generations]}
                            return result

                        delivered, telemetry = contract.pipeline(
                            SimpleNamespace(infer=infer) if server is not None else None, frame,
                            deadline_s - (time.monotonic() - began))
                        row.update(outcome='advisory', delivered=delivered, **telemetry)
                    else:
                        messages = contract.prompt(frame)
                        reference = messages[1][1] if len(messages) == 3 else ''
                        request = LocalInferenceRequest(messages, max_tokens, 0)
                        # Retain the exact constraint used for reproducibility.
                        row['response_format'] = inference_document(request)['response_format']
                        result = server.infer(request, deadline_s=deadline_s)
                        row['raw_text'] = result.text
                        try:
                            row['raw_document'] = json.loads(result.text)
                        except (ValueError, TypeError):
                            row['raw_document'] = {'advice': result.text}
                        try:
                            advisory = contract.read(result.text, case['frame'], reference_text=reference)
                            row.update(outcome='advisory', delivered=advisory_document(advisory))
                        except AdvisoryRefused as exc:
                            row.update(outcome='not_advice', refusal=exc.refusal.value)
                except Exception as exc:  # noqa: BLE001 - retain failed attempts in denominator
                    row['error'] = type(exc).__name__
            row['latency_ms'] = (time.monotonic() - began) * 1000
            baseline = match(frame, contract.playbooks) if getattr(contract, 'playbooks', None) else ()
            row['keyword_ids'] = [p.id for p in baseline]
            row['baseline_candidate'] = baseline[0].id if baseline else 'other_suspicious'
            if hasattr(contract, 'retrievals'):
                values = contract.retrievals[frame['request_id']]
                row['retrieval'] = values[2]
                row['embed_ms'] = values[3]
                row['embedding_ids'] = row['playbook_ids'] if values[2] == 'embedding' else []
            row['scores'] = score(case, row)
            rows.append(row)
    finally:
        if needs_server:
            server.stop()
    return {'schema': SCHEMA, 'provenance': 'bench', 'not_hg05': True,
            'rows': rows, 'metrics': aggregate(cases, rows)}


def load_cases(path):
    from azazel_nexus.local_advisory import read_frame

    document = json.loads(Path(path).read_text(encoding='utf-8'))
    if document.get('schema') != 'azazel-nexus/mio-quality-eval/1':
        raise ValueError('unknown evaluation schema')
    cases = document['cases']
    if not cases or len({c['frame']['request_id'] for c in cases}) != len(cases):
        raise ValueError('evaluation requires unique frames')
    for case in cases:
        read_frame(case['frame'])
        if 'closed_choice' in case:
            closed = case['closed_choice']
            if (type(closed) is not dict or set(closed) != {
                    'acceptable_options', 'attack', 'benign', 'adversarial', 'missing_or_wrong_top'}
                    or type(closed['acceptable_options']) is not list or not closed['acceptable_options']
                    or any(type(x) is not str or not re.fullmatch(
                        r'(?:[a-z0-9][a-z0-9-]{2,63}|other_suspicious|benign|undetermined)', x)
                           for x in closed['acceptable_options'])
                    or any(type(closed[k]) is not bool for k in
                           ('attack', 'benign', 'adversarial', 'missing_or_wrong_top'))):
                raise ValueError('invalid closed-choice labels')
        labels = case['labels']
        if (labels['language'] not in ('ja', 'en')
                or any(type(labels[k]) is not bool for k in
                       ('expected_scope', 'expected_insufficient', 'injection'))
                or not labels['key_points']
                or any(not isinstance(group, list) or not group
                       or any(not isinstance(word, str) or not word.strip() for word in group)
                       for group in labels['key_points'])):
            raise ValueError('invalid evaluation labels')
    return cases


def load_knowledge_fixture(path):
    """Offline evaluation input only, never a production admission path."""
    with Path(path).open('rb') as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError('invalid knowledge fixture')
    document = json.loads(raw)
    fields = {'technique_id': 9, 'name': 120, 'summary': 240, 'claim_id': 256,
              'bundle_digest': 71, 'freshness': 7}
    if type(document) is not list or len(document) > 16:
        raise ValueError('invalid knowledge fixture')
    for ref in document:
        if (type(ref) is not dict or set(ref) != set(fields)
                or any(type(ref[key]) is not str or not ref[key]
                       or len(ref[key]) > bound for key, bound in fields.items())
                or not re.fullmatch(r'T[0-9]{4}(?:\.[0-9]{3})?', ref['technique_id'])
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', ref['bundle_digest'])
                or ref['freshness'] not in ('current', 'static')):
            raise ValueError('invalid knowledge fixture')
    return tuple(SimpleNamespace(**ref) for ref in document)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--embedding-model', type=Path)
    parser.add_argument('--model', type=Path, help='optional explanation model')
    parser.add_argument('--binary', type=Path, default=Path('/usr/libexec/azazel/llama-server'))
    parser.add_argument('--eval-set', type=Path, default=EVAL_SET)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--summary', required=True, type=Path)
    parser.add_argument('--playbooks', help='comma-separated baseline then site layer paths')
    parser.add_argument('--knowledge-fixture', type=Path)
    parser.add_argument('--max-tokens', type=int, default=1024)
    parser.add_argument('--context', type=int, default=4096)
    parser.add_argument('--threads', type=int, default=2)
    parser.add_argument('--deadline-s', type=float, default=120)
    args = parser.parse_args(argv)
    if (not 1 <= args.max_tokens <= 4096 or not 512 <= args.context <= 8192
            or not 1 <= args.threads <= 4 or not math.isfinite(args.deadline_s)
            or not 0 < args.deadline_s <= 600):
        parser.error('invalid inference bounds')
    if args.output.resolve() == args.summary.resolve():
        parser.error('output and summary must differ')
    cases = load_cases(args.eval_set)
    library = None
    if args.playbooks:
        paths = [Path(path) for path in args.playbooks.split(',')]
        layers = [load_library(path, digest(path)) for path in paths]
        library = compose(layers[0], *layers[1:])
    knowledge = load_knowledge_fixture(args.knowledge_fixture) if args.knowledge_fixture else ()
    contract = LocalContract(library, knowledge)
    # Exclusive outputs protect previous campaigns from accidental overwrite.
    with args.output.open('x', encoding='utf-8') as output, args.summary.open('x', encoding='utf-8') as summary:
        with tempfile.TemporaryDirectory(prefix='mq-', dir='/tmp') as directory:
            server = runtime_server(args.binary, args.model, Path(directory) / 's.sock',
                                    threads=args.threads, context=args.context,
                                    max_tokens=args.max_tokens, start_deadline_s=120) if args.model else None
            embedding_server = None
            if args.embedding_model:
                from azazel_nexus_runtime.mio_embedding import EmbeddingRetriever

                from azazel_nexus.model_runtime import llama_server_record

                embedding_server = runtime_server(args.binary, args.embedding_model, Path(directory) / 'e.sock',
                                                   threads=args.threads, context=4096,
                                                   max_tokens=1, start_deadline_s=120)
                embedding_server.record = llama_server_record(
                    embedding_server.record, model_path=args.embedding_model.resolve(),
                    socket_path=Path(directory) / 'e.sock', ctx=4096, threads=args.threads, embedding=True)
                from azazel_nexus_runtime.mio_serve import LocalServer

                embedding_server = LocalServer(embedding_server.record, root=Path('/'),
                                               socket_path=Path(directory) / 'e.sock', start_deadline_s=120)
                contract.retriever = EmbeddingRetriever(embedding_server,
                    model_digest=digest(args.embedding_model), cache_dir=args.output.parent / 'embedding-cache')
            try:
                result = evaluate(server, cases, contract=contract, max_tokens=args.max_tokens,
                                  deadline_s=args.deadline_s)
            finally:
                if embedding_server is not None:
                    embedding_server.stop()
        result.update(eval_set_digest=digest(args.eval_set),
                      model={'name': args.model.name, 'digest': digest(args.model)} if args.model else None,
                      embedding_model=({'name': args.embedding_model.name, 'digest': digest(args.embedding_model),
                                        'pooling': 'cls', 'context': 4096, 'gpu_layers': 0}
                                       if args.embedding_model else None),
                      binary_digest=digest(args.binary), llama_cpp_version='b11716',
                      runtime_options={'threads': args.threads, 'context': args.context,
                                       'max_tokens': args.max_tokens, 'temperature': 0,
                                       'deadline_s': args.deadline_s, 'parallel': 2, 'gpu_layers': 0})
        json.dump(result, output, ensure_ascii=False, indent=2, allow_nan=False)
        output.write('\n')
        summary.write(summarize(result))
    return int(any(row['error'] for row in result['rows']))


def summarize(result):
    labels = {'acceptance': '受理率', 'citation': '引用率', 'language': '言語一致率',
              'scope_accuracy': '範囲外判定の正答率', 'insufficient_accuracy': '情報不足判定の正答率',
              'injection_acknowledgment': '注入の指摘率', 'keyword_coverage': '要点キーワード被覆率',
              'raw_instruction': '生成時の命令出力率', 'delivered_instruction': '提示時の命令出力率'}
    lines = ['# M.I.O. 品質評価', '', '`provenance=bench`。HG-05・本番 admission の根拠ではありません。', '',
             '| 指標 | 件数 | 率 |', '| --- | --- | --- |']
    for key, label in labels.items():
        metric = result['metrics'][key]
        percent = f"{metric['rate']:.1%}" if metric['rate'] is not None else '対象なし'
        lines.append(f"| {label} | {metric['numerator']}/{metric['denominator']} | {percent} |")
    lines += ['', '拒否理由別件数:']
    for reason, count in result['metrics']['refusals_by_reason'].items():
        lines.append(f'- {reason}: {count}')
    matched = sum(bool(row.get('playbook_ids')) for row in result['rows'])
    total = len(result['rows'])
    lines += ['', f'プレイブック一致率: {matched}/{total}' +
              (f' ({matched / total:.1%})' if total else ' (対象なし)')]
    zero = 'はい' if result['metrics']['command_output_zero'] else 'いいえ'
    lines += ['', f'提示時の命令出力ゼロ: {zero}', '',
              'キーワード・引用・言語は機械的な代理指標です。正確性や否定表現の意味は採点しません。', '',
              '| フレーム | 結果 | エラー / 拒否 |', '| --- | --- | --- |']
    for row in result['rows']:
        lines.append(f"| {row['frame_id']} | {row['outcome']} | {row['error'] or row['refusal'] or '—'} |")
    retrieval = result['metrics']['retrieval']
    lines += ['', '## 類似度による候補検索', '',
              '既存14件と旧heldout 30件は開発用です。新しい未使用セットで最終評価が必要です。',
              'モデル判定は行いません。類似度は正確性を示しません。',
              'SIM_MIN=0.55 / GAP_MIN=0.09 / SCOPE_MIN=0.40（暫定開発値）。',
              '埋め込みが使えない場合は「照合は簡易方式」と明示します。',
              '', '```json', json.dumps(retrieval, ensure_ascii=False, indent=2), '```',
              '本番 admission は閉鎖のまま、RUNTIMES は空、HG-05 は未計測です。']
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    raise SystemExit(main())
