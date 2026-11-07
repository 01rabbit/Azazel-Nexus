"""G4 controlled faults; scope and watchdog observations are separate evidence."""
import json
import errno
import os
import socket
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime import mio_generation
from azazel_nexus_runtime import mio_supervisor as supervisor
from azazel_nexus_runtime.mio_serve import LocalServer, LocalServerRefused
from azazel_nexus.runtime_lifecycle import LifecycleState


class ProcessStub:
    pid = 12345
    returncode = None

    def __init__(self, *, exited=False, timeout=False):
        self.exited, self.timeout = exited, timeout
        self.waits = 0

    def poll(self):
        return 0 if self.exited else None

    def wait(self, timeout):
        self.waits += 1
        if self.timeout:
            raise subprocess.TimeoutExpired('owned-stub', timeout)
        self.exited = True
        self.returncode = 0
        return 0


def owned(monkeypatch, process, members=None):
    monkeypatch.setattr(supervisor, '_process_identity', lambda pid: 'start-1')
    monkeypatch.setattr(supervisor, '_group_members', members or (lambda group: () if process.exited else (process.pid,)))


def test_f02_term_ignored_then_kill_confirms(monkeypatch):
    process = ProcessStub(timeout=True)
    owned(monkeypatch, process)
    signals = []
    def kill(group, sig):
        signals.append(sig)
        if sig == supervisor.signal.SIGKILL:
            process.timeout = False
    monkeypatch.setattr(supervisor.os, 'killpg', kill)
    result = supervisor._terminate_group(process, group=process.pid, identity='start-1')
    assert signals == [supervisor.signal.SIGTERM, supervisor.signal.SIGKILL]
    assert result.state is supervisor.StopState.CONFIRMED and process.waits == 2


def test_f03_exited_parent_child_remaining_is_not_confirmed(monkeypatch):
    process = ProcessStub(exited=True)
    owned(monkeypatch, process, lambda group: (12346,))
    clock = iter(range(100))
    monkeypatch.setattr(supervisor.time, 'monotonic', lambda: next(clock))
    monkeypatch.setattr(supervisor.time, 'sleep', lambda delay: None)
    signals = []
    monkeypatch.setattr(supervisor.os, 'killpg', lambda group, sig: signals.append(sig))
    result = supervisor._terminate_group(process, group=process.pid, identity='start-1')
    assert signals == [supervisor.signal.SIGTERM, supervisor.signal.SIGKILL]
    assert result.state is supervisor.StopState.UNCONFIRMED
    assert result.reason == 'group_remaining'


def test_f03_exited_parent_child_terminated_and_reaped(monkeypatch):
    process = ProcessStub(exited=True)
    members = [12346]
    owned(monkeypatch, process, lambda group: tuple(members))
    monkeypatch.setattr(supervisor, '_process_identity', lambda pid: None)
    monkeypatch.setattr(supervisor.os, 'killpg', lambda group, sig: members.clear())
    result = supervisor._terminate_group(process, group=process.pid, identity='start-1')
    assert result.state is supervisor.StopState.CONFIRMED and process.waits == 1


def test_f04_signal_refusal_retains_process(monkeypatch):
    process = ProcessStub()
    owned(monkeypatch, process)
    handle = supervisor.ServingProcess(object(), root=object())
    handle.process, handle.start_identity = process, 'start-1'
    monkeypatch.setattr(supervisor.os, 'killpg', lambda *args: (_ for _ in ()).throw(PermissionError()))
    result = handle.stop()
    assert result.state is supervisor.StopState.REFUSED
    assert handle.process is process


@pytest.mark.parametrize('identity', [None, 'reused-pid'])
def test_unknown_or_reused_identity_never_signals(monkeypatch, identity):
    process = ProcessStub()
    owned(monkeypatch, process)
    monkeypatch.setattr(supervisor.os, 'killpg', lambda *args: pytest.fail('unowned signal'))
    result = supervisor._terminate_group(process, group=process.pid, identity=identity)
    assert result.state is supervisor.StopState.UNKNOWN


def test_f05_wait_timeout_is_unconfirmed(monkeypatch):
    process = ProcessStub(timeout=True)
    owned(monkeypatch, process)
    monkeypatch.setattr(supervisor.os, 'killpg', lambda *args: None)
    result = supervisor._terminate_group(process, group=process.pid, identity='start-1')
    assert result.state is supervisor.StopState.UNCONFIRMED
    assert result.reason == 'wait_timeout'


def session_job(seconds=.05):
    session = SimpleNamespace(lock=threading.RLock(), cleanup={'state': 'not_needed'},
                              frozen=None, done=threading.Event())
    return session, {'budget_session': session, 'end': time.monotonic() + seconds}


def await_cleanup(session):
    until = time.monotonic() + 2
    while time.monotonic() < until:
        with session.lock:
            if session.cleanup['state'] not in ('pending', 'not_needed'):
                return session.cleanup
        time.sleep(.001)
    pytest.fail('cleanup did not terminate')


def test_f05_stop_hang_is_bounded_and_visible():
    release = threading.Event()
    def stop():
        release.wait(2)
        return supervisor.StopResult(supervisor.StopState.CONFIRMED, 'stub')
    server = SimpleNamespace(stop=stop)
    lane = mio_generation.GenerationLane(server=server)
    session, job = session_job()
    session.done.set()
    try:
        lane._start_budget_stop(job)
        assert await_cleanup(session)['state'] == 'unconfirmed'
        assert lane.stop_observation()['stop_threads_alive'] == 1
        assert lane._fenced and mio_generation.GenerationLane(server=server)._fenced
    finally:
        release.set()
        for worker in lane._stop_threads:
            worker.join(1)
    assert session.cleanup['state'] == 'unconfirmed'


def test_f06_infer_thread_alive_prevents_budget_confirmation():
    server = SimpleNamespace(stop=lambda: supervisor.StopResult(supervisor.StopState.CONFIRMED, 'stub'))
    lane = mio_generation.GenerationLane(server=server)
    session, job = session_job()
    lane._start_budget_stop(job)
    assert await_cleanup(session)['state'] == 'unconfirmed'
    assert lane._fenced
    session.done.set()  # A late infer return cannot promote a terminal receipt.
    for worker in lane._stop_threads:
        worker.join(1)
    assert session.cleanup['state'] == 'unconfirmed'


def test_normal_stop_waits_for_infer_completion_before_original_end():
    server = SimpleNamespace(stop=lambda: supervisor.StopResult(supervisor.StopState.CONFIRMED, 'stub'))
    lane = mio_generation.GenerationLane(server=server)
    session, job = session_job(1)
    lane._start_budget_stop(job)
    assert session.cleanup['state'] == 'pending'
    session.done.set()
    assert await_cleanup(session)['state'] == 'confirmed'
    assert not lane._fenced and lane._stopped


def test_f07_confirmation_at_original_job_end_is_unconfirmed(monkeypatch):
    lane = mio_generation.GenerationLane()
    session = SimpleNamespace(lock=threading.RLock(), cleanup={'state': 'pending'}, frozen=None)
    job = {'budget_session': session, 'end': 10.0}
    monkeypatch.setattr(mio_generation.time, 'monotonic', lambda: 10.0)
    lane._update_budget_cleanup(job, 'confirmed', 'stop_confirmed')
    assert session.cleanup == {'state': 'unconfirmed', 'reason': 'confirmation_deadline', 'remaining_ms': 0}
    assert lane._fenced is True
    lane._update_budget_cleanup(job, 'confirmed', 'stop_confirmed')
    assert session.cleanup['state'] == 'unconfirmed'


def local_handle(tmp_path):
    # Admission is not bypassed: the fixture constructs only the stop side of
    # an inert server, and never calls a production spawn or inference path.
    handle = object.__new__(LocalServer)
    handle.socket_path = tmp_path / 'owned.sock'
    handle._socket_identity = None
    handle._fence_path = tmp_path / 'stop-fence.json'
    handle._nexus_stop_unconfirmed = False
    handle._last_stop = None
    handle._stop_lock = threading.RLock()
    handle._fence_lock = threading.Lock()
    handle.state = LifecycleState.SERVING
    handle._child = supervisor.ServingProcess(object(), root=tmp_path)
    handle._child.process = ProcessStub()
    handle._child.start_identity = 'start-1'
    return handle


@pytest.mark.parametrize('completed_at', [10.0, 10.001])
def test_f07_legacy_timeout_and_unconfirmed_fence_coexist(tmp_path, monkeypatch, completed_at):
    handle = local_handle(tmp_path)
    monkeypatch.setattr(handle, 'stop', lambda: supervisor.StopResult(supervisor.StopState.CONFIRMED, 'stub'))
    lane = mio_generation.GenerationLane(server=handle)
    frame = SimpleNamespace(frame_id='frame', trace_id='trace')
    job = dict(handle='handle', key=('generation', 'source'), frame=frame,
               generation='generation', end=10.0, reason='cancelled', cancelled=threading.Event())
    lane._receipts['handle'] = dict(status=lane._status('queued', frame, 'generation'))
    clock = [10.0]
    monkeypatch.setattr(mio_generation.time, 'monotonic', lambda: clock[0])

    class CompletedStopWorker:
        def __init__(self, *, target, **kwargs):
            self.target = target
        def start(self):
            clock[0] = completed_at
            self.target()
        def join(self, *, timeout):
            assert timeout == 0  # worker completed even though no time remains
        def is_alive(self):
            return False

    monkeypatch.setattr(mio_generation, 'threading', SimpleNamespace(Thread=CompletedStopWorker))
    lane._cancel(job, 'timeout')  # actual boundary, never an early timeout injection
    assert not lane._stop_provider(job)
    assert lane._receipts['handle']['status']['state'] == 'timeout'
    assert lane.stop_observation()['cleanup'] == dict(
        state='unconfirmed', reason='confirmation_deadline', remaining_ms=0)
    assert lane._fenced and not lane._stopped
    assert json.loads(handle._fence_path.read_text())['state'] == 'unconfirmed'
    lane._cancel(job, 'cancelled')
    lane._fence(job)
    assert job['reason'] == 'timeout'
    assert lane._receipts['handle']['status']['state'] == 'timeout'
    # Restart restoration and dispatch rejection use the real durable fence.
    restored = local_handle(tmp_path)
    restored._restore_stop_fence()
    assert restored.state is LifecycleState.FENCED
    with pytest.raises(LocalServerRefused, match='fenced'):
        restored.start()


def test_f07_legacy_stop_completion_before_end_observed_at_end_fences(tmp_path, monkeypatch):
    handle = local_handle(tmp_path)
    monkeypatch.setattr(handle, 'stop', lambda: supervisor.StopResult(supervisor.StopState.CONFIRMED, 'stub'))
    lane = mio_generation.GenerationLane(server=handle)
    frame = SimpleNamespace(frame_id='frame', trace_id='trace')
    job = dict(handle='handle', key=('generation', 'source'), frame=frame,
               generation='generation', end=10.0, reason='cancelled', cancelled=threading.Event())
    lane._receipts['handle'] = dict(status=lane._status('queued', frame, 'generation'))
    clock = [9.0]
    monkeypatch.setattr(mio_generation.time, 'monotonic', lambda: clock[0])

    class LateObservationWorker:
        def __init__(self, *, target, **kwargs):
            self.target = target
        def start(self):
            self.target()  # stop itself completes before E
        def join(self, *, timeout):
            assert timeout == 1.0
            clock[0] = 10.0  # publication observes it only at E
        def is_alive(self):
            return False

    monkeypatch.setattr(mio_generation, 'threading', SimpleNamespace(Thread=LateObservationWorker))
    lane._cancel(job, 'cancelled')
    assert not lane._stop_provider(job)
    assert lane._receipts['handle']['status']['state'] == 'cancelled'
    assert lane.stop_observation()['cleanup']['state'] == 'unconfirmed'
    assert lane._fenced and json.loads(handle._fence_path.read_text())['state'] == 'unconfirmed'


def test_f08_unconfirmed_stop_is_durable_and_restart_refuses(tmp_path, monkeypatch):
    handle = local_handle(tmp_path)
    monkeypatch.setattr(handle._child, 'stop', lambda **kw: supervisor.StopResult(supervisor.StopState.REFUSED, 'signal_refused'))
    assert handle.stop().state is supervisor.StopState.REFUSED
    value = json.loads(handle._fence_path.read_text())
    assert value['state'] == 'unconfirmed' and value['start_identity'] == 'start-1'
    assert value['socket_path'] == str(handle.socket_path)
    # Restore using the same method called by the real constructor, without
    # changing admission constants to construct a live provider in the test.
    restored = local_handle(tmp_path)
    restored._restore_stop_fence()
    lane = mio_generation.GenerationLane(server=restored)
    assert lane._fenced and restored.state is LifecycleState.FENCED
    with pytest.raises(LocalServerRefused, match='fenced'):
        restored.start()
    monkeypatch.setattr(restored._child, 'stop', lambda **kw: supervisor.StopResult(supervisor.StopState.CONFIRMED, 'late'))
    restored.stop()
    assert json.loads(restored._fence_path.read_text())['state'] == 'unconfirmed'
    assert restored.state is LifecycleState.FENCED


from test_mio_budget_lane import make  # existing controlled MIO/compiler fixture


@pytest.mark.parametrize('control', ['cancel', 'supersede', 'revoke'])
def test_f08_control_stop_retains_fence(make, control):
    lane, server, source, frame = make(deadline=1)
    server.block = server.stop_fail = True
    lane.submit(source, frame, 'fixture')
    assert server.entered.wait(.5)
    job = lane._active
    if control == 'cancel':
        lane.cancel()
    elif control == 'supersede':
        lane.submit({**source, 'question': 'replacement'}, frame, 'fixture')
    else:
        lane._authorized = lambda generation: False
    session = job['budget_session']
    assert await_cleanup(session)['reason'] == 'stop_failed'
    assert lane._fenced and mio_generation.GenerationLane(server=server)._fenced
    assert len(server.requests) == 1
    refused = lane.submit({**source, 'question': 'new send'}, frame, 'fixture')
    assert 'result_handle' not in refused


def test_owned_socket_removed_only_after_group_confirmation(tmp_path, monkeypatch):
    handle = local_handle(tmp_path)
    handle.socket_path.write_bytes(b'stub inode')
    st = handle.socket_path.lstat()
    handle._socket_identity = (st.st_dev, st.st_ino)
    monkeypatch.setattr(handle, '_socket_stop_state', lambda: supervisor.StopResult(supervisor.StopState.CONFIRMED, 'inactive-stub'))
    monkeypatch.setattr(handle._child, 'stop', lambda **kw: supervisor.StopResult(supervisor.StopState.CONFIRMED, 'stub'))
    assert handle.stop().state is supervisor.StopState.CONFIRMED
    assert not handle.socket_path.exists() and handle.state is LifecycleState.STOPPED
    assert handle._child.process is None


def test_unknown_socket_inode_retains_process_and_fences(tmp_path, monkeypatch):
    handle = local_handle(tmp_path)
    handle.socket_path.write_bytes(b'unowned inode')
    monkeypatch.setattr(handle._child, 'stop', lambda **kw: supervisor.StopResult(supervisor.StopState.CONFIRMED, 'stub'))
    assert handle.stop().state is supervisor.StopState.UNKNOWN
    assert handle.socket_path.exists() and handle._child.process is not None
    assert handle.state is LifecycleState.FENCED


def test_replaced_socket_is_never_unlinked(tmp_path, monkeypatch):
    handle = local_handle(tmp_path)
    handle.socket_path.write_bytes(b'replacement')
    st = handle.socket_path.lstat()
    handle._socket_identity = (st.st_dev, st.st_ino + 1)
    monkeypatch.setattr(handle._child, 'stop', lambda **kw: supervisor.StopResult(supervisor.StopState.CONFIRMED, 'stub'))
    assert handle.stop().state is supervisor.StopState.CONFIRMED
    assert handle.socket_path.read_bytes() == b'replacement'


@pytest.mark.parametrize('code,expected', [
    (0, supervisor.StopState.UNCONFIRMED),
    (errno.EAGAIN, supervisor.StopState.UNCONFIRMED),
    (errno.ECONNREFUSED, supervisor.StopState.CONFIRMED),
    (errno.EPERM, supervisor.StopState.UNKNOWN),
])
def test_owned_listener_probe_controls_unlink_and_fence(tmp_path, monkeypatch, code, expected):
    handle = local_handle(tmp_path)
    handle.socket_path.write_bytes(b'controlled socket inode')
    st = handle.socket_path.stat()
    handle._socket_identity = (st.st_dev, st.st_ino)
    class Probe:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def setblocking(self, value): assert value is False
        def connect_ex(self, path):
            assert path == str(handle.socket_path)
            return code
    monkeypatch.setattr(socket, 'socket', lambda *a: Probe())
    monkeypatch.setattr(handle._child, 'stop', lambda **kw: supervisor.StopResult(supervisor.StopState.CONFIRMED, 'stub'))
    assert handle.stop().state is expected
    if expected is supervisor.StopState.CONFIRMED:
        assert not handle.socket_path.exists() and handle._child.process is None
    else:
        assert handle.socket_path.exists() and handle._child.process is not None
        assert handle.state is LifecycleState.FENCED
        assert json.loads(handle._fence_path.read_text())['state'] == 'unconfirmed'


def test_f09_setsid_escape_retaining_owned_pipe_fences(tmp_path, monkeypatch):
    import select
    # A real fixture parent owns a new session. Its child escapes with setsid,
    # inherits the owned stdout pipe and remains after the direct parent is reaped.
    # Identity/group reads are controlled here so this fault also runs in a
    # host sandbox that denies ps. The child answers the external watchdog.
    marker = tmp_path / 'escape.json'
    handle = local_handle(tmp_path)
    child_code = """import os,sys,json
os.setsid()
with open(sys.argv[1],'w') as f: json.dump({'pid':os.getpid(),'group':os.getpgrp()}, f)
print('READY', flush=True)
for line in sys.stdin:
    if line.strip() != 'PING': break
    print('PONG', flush=True)
"""
    parent_code = "import subprocess,sys; subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]], stdin=sys.stdin, stdout=sys.stdout)"
    parent = subprocess.Popen([sys.executable, '-c', parent_code, child_code, str(marker)],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              start_new_session=True)
    try:
        assert select.select([parent.stdout], [], [], 2)[0]
        assert parent.stdout.readline() == b'READY\n'
        parent.wait(timeout=2)
        handle._child.process = parent
        handle._child.start_identity = 'controlled-spawn-identity'
        monkeypatch.setattr(supervisor, '_process_identity', lambda pid: None)
        monkeypatch.setattr(supervisor, '_group_members', lambda group: ())
        result = handle.stop()
        observation = json.loads(marker.read_text())
        assert observation['pid'] == observation['group'] != parent.pid
        parent.stdin.write(b'PING\n')
        parent.stdin.flush()
        assert select.select([parent.stdout], [], [], 2)[0]
        assert parent.stdout.readline() == b'PONG\n'  # physical survivor after receipt
        assert result.state is supervisor.StopState.UNCONFIRMED
        assert result.reason == 'owned_pipe_writer_remaining'
        assert handle._child.process is parent
        fence = json.loads(handle._fence_path.read_text())
        assert fence['state'] == 'unconfirmed' and fence['pid'] == parent.pid
        from azazel_nexus_runtime.mio_serve import LocalInferenceRequest
        with pytest.raises(LocalServerRefused, match='not serving'):
            handle.infer(LocalInferenceRequest((('user', 'must not send'),)), deadline_s=1)
        with pytest.raises(LocalServerRefused, match='fenced'):
            handle.start()
        assert result.scope == 'owned_runtime_group_no_new_session_or_cgroup'
        audit = dict(scope=result.scope, receipt=result.state.value,
                     group_members=[], parent_reaped=True, physical_survivor=True,
                     fence=fence['state'], additional_send_refused=True,
                     premise_violated=True, cleanup_owner='test_pipe_eof_then_disposable_container')
        destination = os.environ.get('W3_PHYSICAL_AUDIT_DIR')
        if destination:
            from pathlib import Path
            with (Path(destination) / 'F09-watchdog.json').open('x') as stream:
                json.dump(audit, stream, indent=2)
    finally:
        parent.stdin.close()  # EOF terminates the escaped test child, no PID kill.
        assert select.select([parent.stdout], [], [], 2)[0]
        assert parent.stdout.read() == b''
        parent.stdout.close()
        parent.wait(timeout=2)


@pytest.mark.parametrize('entry', ['supervise', 'run_once'])
def test_one_shot_unconfirmed_retains_identity_and_refuses_repeat(tmp_path, monkeypatch, entry):
    from azazel_nexus.model_runtime import RuntimeBinary
    from azazel_nexus.runtime_lifecycle import BudgetLedger, RestartBudget
    starts = []
    process = ProcessStub()
    process.stdout = process.stderr = None
    def spawn(*args, **kwargs):
        starts.append(process)
        return process
    monkeypatch.setattr(supervisor.subprocess, 'Popen', spawn)
    monkeypatch.setattr(supervisor, '_process_identity', lambda pid: 'owned-start')
    monkeypatch.setattr(supervisor, '_drain_bounded', lambda *a, **kw: (b'READY', b'', False, False, True))
    monkeypatch.setattr(supervisor, '_terminate_group', lambda *a, **kw: supervisor.StopResult(supervisor.StopState.REFUSED, 'signal_refused'))
    record = RuntimeBinary('stub', '/usr/libexec/azazel/owned-stub', 'fixture', 'sha256:' + '0' * 64, ('/usr/libexec/azazel/owned-stub',))
    ledger = BudgetLedger(tmp_path / 'state' / 'budget.json')
    state = supervisor.Supervision(record, tmp_path, RestartBudget(generation=1), ledger=ledger)
    if entry == 'supervise':
        supervisor.supervise(state)
        report = state.reports[-1]
        supervisor.supervise(state)
        assert len(state.reports) == 1 and state.budget.fenced
        assert state.budget.remaining > 0  # cleanup fence is independent of spent restarts
        assert ledger.load(generation=1, runtime_id='stub').fenced
    else:
        report = supervisor.run_once(record, root=tmp_path, ledger=ledger)
    assert supervisor.run_once(record, root=tmp_path, ledger=ledger).state is LifecycleState.FENCED
    assert supervisor.run_once(record, root=tmp_path).state is LifecycleState.FENCED
    assert report.state is LifecycleState.FENCED and report.process is process
    assert (report.group, report.start_identity) == (process.pid, 'owned-start')
    fence = json.loads((ledger.path.parent / 'stop-fence.json').read_text())
    assert (fence['pid'], fence['group'], fence['start_identity']) == (process.pid, process.pid, 'owned-start')
    assert fence['state'] == 'unconfirmed'
    # A fresh interpreter's in-memory state is empty; the durable fence still refuses.
    monkeypatch.setattr(supervisor, '_unconfirmed_runs', {})
    assert supervisor.run_once(record, root=tmp_path, ledger=ledger).state is LifecycleState.FENCED
    assert len(starts) == 1


def test_one_shot_fence_write_failure_still_refuses_repeat(tmp_path, monkeypatch):
    from azazel_nexus.model_runtime import RuntimeBinary
    starts = []
    process = ProcessStub()
    process.stdout = process.stderr = None
    def spawn(*args, **kwargs):
        starts.append(process)
        return process
    monkeypatch.setattr(supervisor.subprocess, 'Popen', spawn)
    monkeypatch.setattr(supervisor, '_process_identity', lambda pid: 'owned-start')
    monkeypatch.setattr(supervisor, '_drain_bounded', lambda *a, **kw: (b'', b'', False, False, True))
    monkeypatch.setattr(supervisor, '_terminate_group', lambda *a, **kw: supervisor.StopResult(supervisor.StopState.UNKNOWN, 'unknown'))
    monkeypatch.setattr(supervisor, '_write_stop_fence', lambda *a: (_ for _ in ()).throw(PermissionError()))
    record = RuntimeBinary('stub', '/usr/libexec/azazel/owned-stub', 'fixture', 'sha256:' + '0' * 64, ('/usr/libexec/azazel/owned-stub',))
    report = supervisor.run_once(record, root=tmp_path)
    assert report.state is LifecycleState.FENCED and report.process is process
    assert 'fence_write_failed' in report.reason
    assert supervisor.run_once(record, root=tmp_path) is report
    assert len(starts) == 1


@pytest.mark.parametrize('failure', ['selector', 'wait', 'cleanup'])
@pytest.mark.parametrize('entry', ['supervise', 'run_once'])
def test_one_shot_observation_exception_fences_before_retry(tmp_path, monkeypatch, failure, entry):
    from azazel_nexus.model_runtime import RuntimeBinary
    from azazel_nexus.runtime_lifecycle import BudgetLedger, RestartBudget
    starts = []
    process = ProcessStub()
    process.stdout = process.stderr = None
    def spawn(*args, **kwargs):
        starts.append(process)
        return process
    def fail(*args, **kwargs):
        raise OSError(errno.EMFILE, 'injected observation failure')
    monkeypatch.setattr(supervisor.subprocess, 'Popen', spawn)
    monkeypatch.setattr(supervisor, '_process_identity', lambda pid: 'owned-start')
    if failure == 'selector':
        monkeypatch.setattr(supervisor.selectors, 'DefaultSelector', fail)
    else:
        monkeypatch.setattr(supervisor, '_drain_bounded', lambda *a, **kw: (b'', b'', False, False, False))
    if failure == 'wait':
        monkeypatch.setattr(process, 'wait', fail)
    monkeypatch.setattr(supervisor, '_terminate_group', fail if failure == 'cleanup' else
                        lambda *a, **kw: supervisor.StopResult(supervisor.StopState.REFUSED, 'signal_refused'))
    record = RuntimeBinary('exception-stub', '/usr/libexec/azazel/owned-stub', 'fixture', 'sha256:' + '0' * 64, ('/usr/libexec/azazel/owned-stub',))
    ledger = BudgetLedger(tmp_path / 'state' / 'budget.json')
    state = supervisor.Supervision(record, tmp_path, RestartBudget(generation=1), ledger=ledger)
    if entry == 'supervise':
        supervisor.supervise(state)
        report = state.reports[-1]
        supervisor.supervise(state)
        assert state.budget.fenced and ledger.load(generation=1, runtime_id=record.runtime_id).fenced
        assert len(state.reports) == 1
    else:
        report = supervisor.run_once(record, root=tmp_path, ledger=ledger)
    assert report.state is LifecycleState.FENCED and report.process is process
    assert 'OSError' in report.reason and 'injected observation failure' in report.reason
    fence = json.loads((ledger.path.parent / 'stop-fence.json').read_text())
    assert (fence['state'], fence['pid'], fence['group'], fence['start_identity']) == ('unconfirmed', process.pid, process.pid, 'owned-start')
    assert supervisor.run_once(record, root=tmp_path, ledger=ledger).state is LifecycleState.FENCED
    monkeypatch.setattr(supervisor, '_unconfirmed_runs', {})
    assert supervisor.run_once(record, root=tmp_path, ledger=ledger).state is LifecycleState.FENCED
    assert len(starts) == 1


def test_one_shot_observation_exception_propagates_after_confirmed_cleanup(tmp_path, monkeypatch):
    from azazel_nexus.model_runtime import RuntimeBinary
    process = ProcessStub()
    process.stdout = process.stderr = None
    monkeypatch.setattr(supervisor.subprocess, 'Popen', lambda *a, **kw: process)
    monkeypatch.setattr(supervisor, '_process_identity', lambda pid: 'owned-start')
    monkeypatch.setattr(supervisor.selectors, 'DefaultSelector', lambda: (_ for _ in ()).throw(OSError(errno.EMFILE, 'selector failure')))
    monkeypatch.setattr(supervisor, '_terminate_group', lambda *a, **kw: supervisor.StopResult(supervisor.StopState.CONFIRMED, 'stopped'))
    record = RuntimeBinary('confirmed-stub', '/usr/libexec/azazel/owned-stub', 'fixture', 'sha256:' + '0' * 64, ('/usr/libexec/azazel/owned-stub',))
    with pytest.raises(OSError, match='selector failure'):
        supervisor.run_once(record, root=tmp_path)
    assert not (tmp_path / 'stop-fence.json').exists()


def test_run_once_normal_cleanup_is_not_fenced(monkeypatch, tmp_path):
    from azazel_nexus.model_runtime import RuntimeBinary
    process = ProcessStub()
    process.stdout = process.stderr = None
    owned(monkeypatch, process)
    monkeypatch.setattr(supervisor.subprocess, 'Popen', lambda *args, **kwargs: process)
    monkeypatch.setattr(supervisor, '_drain_bounded', lambda *args, **kwargs: (b'READY', b'', False, False, False))
    record = RuntimeBinary('stub', '/usr/libexec/azazel/owned-stub', 'fixture', 'sha256:' + '0' * 64, ('/usr/libexec/azazel/owned-stub',))
    report = supervisor.run_once(record, root=tmp_path)
    assert report.state is LifecycleState.SERVING
    assert report.exit_code == 0 and process.waits == 2


def test_linux_stat_parsing_handles_spaces_and_parentheses(monkeypatch):
    from pathlib import Path
    # Fields 3..22: pgrp is field 5; starttime is field 22.
    raw = '123 (owned (runtime) name) S 1 123 ' + ' '.join(['0'] * 16) + ' 98765'
    monkeypatch.setattr(Path, 'read_text', lambda path: raw)
    assert supervisor._proc_stat(123) == (123, '98765')


def test_fake_serving_adapter_records_spawn_identity(monkeypatch, tmp_path):
    from admission_helpers import install_fake_serving
    from azazel_nexus_runtime import mio_serve

    install_fake_serving(monkeypatch)
    process = ProcessStub()
    observed = []
    monkeypatch.setattr(supervisor.subprocess, 'Popen', lambda *args, **kwargs: process)
    def identity(pid):
        observed.append(pid)
        return 'fixture-start'
    monkeypatch.setattr(supervisor, '_process_identity', identity)
    handle = mio_serve.ServingProcess(
        SimpleNamespace(executable='/usr/libexec/azazel/fake', argv=('fake',)), root=tmp_path)
    handle.start()
    assert observed == [process.pid]
    assert handle.start_identity == 'fixture-start'


@pytest.mark.parametrize('flag', ['_nexus_stop_pending', '_nexus_stopped', '_nexus_stop_unconfirmed'])
def test_existing_lane_cannot_reuse_same_server_after_other_lane_stop(make, flag):
    lane, server, source, frame = make()
    other = type(lane)(capability=lane.capability, server=server)
    setattr(server, flag, True)
    for candidate in (lane, other):
        refused = candidate.submit(source, frame, 'fixture')
        assert refused['state'] == 'degraded' and 'result_handle' not in refused
    assert server.requests == []
