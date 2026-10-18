"""Evaluate fixed local-advice frames without changing production admission."""
from __future__ import annotations

import argparse
import json
import math
import tempfile
from pathlib import Path

from azazel_nexus.advisory_response import AdvisoryRefused
from bench.mio_local.runner import digest, runtime_server

from .scoring import aggregate, score

EVAL_SET = Path(__file__).with_name('eval_set.json')
SCHEMA = 'azazel-nexus/mio-quality/1'


def advisory_document(advisory):
    return {'advice': advisory.text.text if advisory.text else None,
            'fields': dict(advisory.data.fields) if advisory.data else {}}


class LocalContract:
    """Lane A public API adapter. No fallback to the unguarded old reader."""

    def __init__(self):
        from azazel_nexus import local_advisory

        self.api = local_advisory
        if not hasattr(self.api, 'gate_frame'):
            raise RuntimeError('Lane A gate_frame API is required')

    def gate(self, frame):
        result = self.api.gate_frame(frame)
        if result is None:
            return frame, None, None
        return frame, {'advice': result['advice'], 'fields': result['fields']}, result['reason']

    def prompt(self, frame):
        return self.api.build_prompt(frame)

    def read(self, text, frame):
        return self.api.read_local_advisory(text, frame=frame)


def evaluate(server, cases, *, contract, max_tokens=512, deadline_s=120):
    """Fake-injectable server with start/health/infer/stop, like LocalServer.

    Preflight every gate before starting a server. Gated frames never invoke
    inference. Failures remain in every applicable denominator.
    """
    from azazel_nexus_runtime.mio_serve import LocalInferenceRequest, inference_document

    prepared = [(case, contract.gate(case['frame'])) for case in cases]
    rows = []
    startup_error = None
    needs_server = any(advice is None for _, (_, advice, _) in prepared)
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
                   'raw_text': None, 'raw_document': None, 'delivered': None}
            if fixed_advisory is not None:
                row.update(outcome='gated', delivered=fixed_advisory)
            elif startup_error:
                row['error'] = startup_error
            else:
                try:
                    request = LocalInferenceRequest(contract.prompt(frame), max_tokens, 0)
                    # Retain the exact constraint used for reproducibility.
                    row['response_format'] = inference_document(request)['response_format']
                    result = server.infer(request, deadline_s=deadline_s)
                    row['raw_text'] = result.text
                    try:
                        row['raw_document'] = json.loads(result.text)
                    except (ValueError, TypeError):
                        row['raw_document'] = {'advice': result.text}
                    try:
                        advisory = contract.read(result.text, case['frame'])
                        row.update(outcome='advisory', delivered=advisory_document(advisory))
                    except AdvisoryRefused as exc:
                        row.update(outcome='not_advice', refusal=exc.refusal.value)
                except Exception as exc:  # noqa: BLE001 - retain failed attempts in denominator
                    row['error'] = type(exc).__name__
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
    if len(cases) != 14 or len({c['frame']['request_id'] for c in cases}) != 14:
        raise ValueError('evaluation must contain fourteen unique frames')
    for case in cases:
        read_frame(case['frame'])
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', required=True, type=Path)
    parser.add_argument('--binary', type=Path, default=Path('/usr/libexec/azazel/llama-server'))
    parser.add_argument('--eval-set', type=Path, default=EVAL_SET)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--summary', required=True, type=Path)
    parser.add_argument('--max-tokens', type=int, default=512)
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
    contract = LocalContract()
    # Exclusive outputs protect previous campaigns from accidental overwrite.
    with args.output.open('x', encoding='utf-8') as output, args.summary.open('x', encoding='utf-8') as summary:
        with tempfile.TemporaryDirectory(prefix='mq-', dir='/tmp') as directory:
            server = runtime_server(args.binary, args.model, Path(directory) / 's.sock',
                                    threads=args.threads, context=args.context,
                                    max_tokens=args.max_tokens, start_deadline_s=120)
            result = evaluate(server, cases, contract=contract, max_tokens=args.max_tokens,
                              deadline_s=args.deadline_s)
        result.update(eval_set_digest=digest(args.eval_set),
                      model={'name': args.model.name, 'digest': digest(args.model)},
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
    zero = 'はい' if result['metrics']['command_output_zero'] else 'いいえ'
    lines += ['', f'提示時の命令出力ゼロ: {zero}', '',
              'キーワード・引用・言語は機械的な代理指標です。正確性や否定表現の意味は採点しません。', '',
              '| フレーム | 結果 | エラー / 拒否 |', '| --- | --- | --- |']
    for row in result['rows']:
        lines.append(f"| {row['frame_id']} | {row['outcome']} | {row['error'] or row['refusal'] or '—'} |")
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    raise SystemExit(main())
