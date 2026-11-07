"""F01: isolated early cancel, using the existing real-model fixture harness.

This tests the product stop implementation on a fixture-owned process. It
neither admits production inference nor claims ordinary-entry composition.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace


def test_f01_owned_model_early_cancel(real_assets, tmp_path):
    binary, model = real_assets
    # The executor runs this test only inside its disposable Linux container.
    # An explicit evidence directory is required; no repeat may overwrite F01.
    evidence = Path(os.environ['W3_F01_EVIDENCE'])
    env = dict(os.environ, AZAZEL_ROOT=str(tmp_path),
               AZ_E2E_TELEMETRY_DIR=str(evidence))
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), str(binary), str(model)],
        env=env, capture_output=True, text=True, timeout=300,
    )
    (evidence / 'child.log').write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-4000:]
    receipt = json.loads((evidence / 'F01-receipt.json').read_text())
    physical = json.loads((evidence / 'F01-watchdog.json').read_text())
    assert receipt['cleanup']['state'] == 'confirmed'
    assert receipt['T_result'] < receipt['T_job_end']
    assert physical['parent_reaped'] and physical['group_members'] == []
    assert physical['owned_socket_absent'] and not physical['infer_alive']


def run(binary, model):
    from harness import DirectLlamaFixture, fixture_generation_lane, record_for
    from azazel_nexus import model_admission
    from azazel_nexus.runtime_lifecycle import LifecycleState
    from azazel_nexus_runtime import mio_generation
    from azazel_nexus_runtime.mio_serve import LocalServer, LocalInferenceRequest
    from azazel_nexus_runtime.mio_supervisor import ServingProcess, _process_identity, _group_members

    evidence = Path(os.environ['W3_F01_EVIDENCE'])
    root = Path(os.environ['AZAZEL_ROOT'])
    sock = root / 'llama.sock'
    record = record_for(root, binary, model, sock)  # existing ctx/threads/tokens unchanged
    fixture = DirectLlamaFixture(record, root=root, socket_path=sock)
    fixture.start()
    process = fixture.process
    # Test-only attachment, never a new production constructor or admission.
    # The process was spawned by the existing harness with start_new_session.
    owner = object.__new__(LocalServer)
    owner.socket_path = sock
    owner._socket_identity = None
    owner._fence_path = root / 'stop-fence.json'
    owner._nexus_stop_unconfirmed = False
    owner._last_stop = None
    owner._stop_lock = threading.RLock()
    owner._fence_lock = threading.Lock()
    owner.state = LifecycleState.SERVING
    owner._child = ServingProcess(record, root=root)
    owner._child.process = process
    owner._child.start_identity = _process_identity(process.pid)
    owner._capture_socket()
    lane, _ = fixture_generation_lane(owner)  # existing original E=30s
    session = SimpleNamespace(lock=threading.RLock(), done=threading.Event(),
                              cleanup={'state': 'not_needed'}, frozen=None)
    began = time.monotonic()
    job = {'end': began + lane.deadline_s, 'budget_session': session}
    def infer():
        try:
            fixture.infer(LocalInferenceRequest((('user', 'Explain a network delay.'),), 512, 0),
                          deadline_s=lane.deadline_s)
        except Exception:
            pass  # Cancellation tears down the real socket; cleanup is verified below.
        finally:
            session.done.set()
    worker = threading.Thread(target=infer, name='f01-owned-infer', daemon=True)
    job['infer_thread'] = worker
    lane._infer_threads.append(worker)
    worker.start()
    try:
        # Observe actual positive wire send, never substitute an inference result.
        while not any(r.get('method') == 'POST' and (r.get('sent_bytes') or 0) > 0
                      for r in fixture.telemetry.data['requests']):
            if time.monotonic() >= job['end'] or session.done.is_set():
                raise AssertionError('real inference did not remain in flight for early cancel')
            time.sleep(.001)
        assert not session.done.is_set(), 'model finished before early cancel'
        cancelled = time.monotonic()
        lane._start_budget_stop(job)
        while session.cleanup['state'] == 'pending' and time.monotonic() < job['end']:
            time.sleep(.001)
        result_at = time.monotonic()
        receipt = dict(scope='owned_runtime_group_no_new_session_or_cgroup',
                       evidence_kind='fixture_owned_real_model_stop',
                       T_cancel=cancelled, T_result=result_at, T_job_end=job['end'],
                       cleanup=dict(session.cleanup), fenced=lane._fenced)
        with (evidence / 'F01-receipt.json').open('x') as stream:
            json.dump(receipt, stream, indent=2)
        # Independent lab observation. It cannot rewrite the receipt above.
        observe_end = time.monotonic() + 5
        while True:
            members = _group_members(process.pid)
            physical = dict(T_observed=time.monotonic(), T_stop_observe=5,
                            parent_reaped=process.poll() is not None,
                            group_members=None if members is None else list(members),
                            owned_socket_absent=not sock.exists(), infer_alive=worker.is_alive())
            if (physical['parent_reaped'] and members == () and physical['owned_socket_absent']
                    and not physical['infer_alive']) or time.monotonic() >= observe_end:
                break
            time.sleep(.01)
        with (evidence / 'F01-watchdog.json').open('x') as stream:
            json.dump(physical, stream, indent=2)
        assert receipt['cleanup']['state'] == 'confirmed', receipt
        assert not lane._fenced
        assert model_admission.LOCAL_MODEL_ADMISSION_ENABLED is False
        assert mio_generation.GENERATION_ADMISSION_ENABLED is False
        print('F01 early_cancel confirmed; production admission remains closed')
    finally:
        # Only the fixture owner cleans its own group; outer container is final owner.
        owner.stop()
        worker.join(timeout=max(0, job['end'] - time.monotonic()))
        fixture.telemetry.finish(process)


if __name__ == '__main__':
    run(Path(sys.argv[1]), Path(sys.argv[2]))
