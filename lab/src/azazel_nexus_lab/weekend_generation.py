"""G01: fixed short fixture, cold job once and two warm jobs on one owned model."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import time


def run(binary, model, root, output):
    from azazel_nexus_lab.weekend_process import require_container
    # This model-only fixture never switches service UIDs or owns root paths.
    # Keep the disposable-container and loopback-only checks for uid 1001.
    require_container(root=False)
    from azazel_nexus_lab.weekend_fixture import harness, fixture_lane, native_fixture_wire, poll, production_control
    from azazel_nexus_lab.weekend_ui import noc_frame
    from azazel_nexus_runtime.mio_fast_assistance import _frame
    from azazel_nexus.generation_budget import TASKS
    repo = Path(__file__).resolve().parents[3]
    assert binary.is_file() and os.access(binary, os.X_OK) and model.is_file()
    root.mkdir(parents=True, exist_ok=False)
    output.mkdir(parents=True, exist_ok=False)
    assert os.environ.get('AZAZEL_ROOT') == str(root), 'set synthetic AZAZEL_ROOT before process imports'
    existing = harness(repo)
    record = existing.record_for(root, binary, model, root / 'serve.sock')
    direct = existing.DirectLlamaFixture(record, root=root, socket_path=root / 'serve.sock')
    wire = native_fixture_wire(repo, direct)
    def digest(path):
        with path.open('rb') as stream:
            return hashlib.file_digest(stream, 'sha256').hexdigest()
    receipt = dict(schema='weekend-g01/v1', synthetic=True, tasks=list(TASKS), runs=[],
        model_sha256=digest(model), binary_sha256=digest(binary),
        meaning_validation=False, D3b='NOT_ACCEPTED', retries=0)
    try:
        start = time.monotonic()
        direct.start()
        receipt['startup_s'] = time.monotonic() - start
        pid = direct.process.pid
        for index in range(3):
            lane, cap = fixture_lane(repo, wire, short=True)
            frame = _frame(noc_frame(f'weekend-g01-{index}'))
            control = production_control(cap, wire, frame)
            before = len(wire.requests)
            begin = time.monotonic()
            first = lane.submit(noc_frame(f'weekend-g01-{index}'), frame, cap.generation_id,
                                upstream_coverage='intact')
            value = poll(lane, first, cap.generation_id, frame.trace_id)
            elapsed = time.monotonic() - begin
            meta = value['generation_budget']
            requests = wire.requests[before:]
            receipt['runs'].append(dict(index=index, temperature='cold' if index == 0 else 'warm',
                pid=pid, elapsed_s=elapsed, terminal=value, requests=requests, production_control=control,
                frame_binding=dict(trace_id=frame.trace_id, frame_id=frame.frame_id,
                                   evidence_refs=list(frame.evidence_refs))))
            assert elapsed <= 30 and direct.process.pid == pid
            assert len(requests) == 3 and all(r['positive_send'] for r in requests)
            assert meta['job_calls'] == 3
            assert all(t['validated'] and t['count_kind'] == 'exact' and
                t['context_integrity'] == 'preserved' and t['finish_reason'] == 'stop' and
                t['actual_usage']['tokens_in'] is not None and t['actual_usage']['tokens_out'] is not None
                for t in meta['tasks'])
            assert all(t['input_tokens_bound'] + t['output_tokens_cap'] + t['context_slack'] <=
                       t['context_limit'] for t in meta['tasks'])
            assert value['state'] != 'complete'  # schema transport success only
        receipt['mechanical_acceptance'] = True
    finally:
        wire.stop()
        receipt['owned_model_stopped'] = direct.process is None
        (output / 'g01.json').write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + '\n')
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    run(args.binary, args.model, args.root, args.output)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
