"""Long-lived serving against a fake AF_UNIX HTTP process, never llama.cpp."""
from __future__ import annotations

import json
import signal
import socket
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime.mio_serve import (
    MAX_REQUEST_BYTES,
    LocalInferenceRequest,
    LocalServer,
    LocalServerRefused,
)

from azazel_nexus.model_runtime import (
    RUNTIMES,
    RuntimeBinary,
    RuntimeRefused,
    llama_server_record,
)
from azazel_nexus.runtime_lifecycle import BudgetLedger, LifecycleState, RestartBudget

FAKE = r'''
import json, os, signal, socket, sys, time
path, mode = sys.argv[1:]
if mode == 'crash':
    sys.exit(9)
if 'AZ_PARENT_MARKER' in os.environ:
    sys.exit(8)
# More than pipe capacity: serving must not stall behind child output.
os.write(1, b'x' * 200000)
os.write(2, b'y' * 200000)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(4)
while True:
    c, _ = s.accept()
    with c:
        raw = b''
        while b'\r\n\r\n' not in raw:
            raw += c.recv(4096)
        head, body = raw.split(b'\r\n\r\n', 1)
        length = int(next(x.split(b':')[1] for x in head.split(b'\r\n')
                          if x.lower().startswith(b'content-length:')))
        while len(body) < length:
            body += c.recv(4096)
        health = head.startswith(b'GET /health ')
        if not health and mode == 'hang':
            time.sleep(30)
        if not health and mode == 'exit':
            os._exit(7)
        if not health and mode == 'oversize':
            c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n')
            continue
        if not health and mode == 'headers':
            c.sendall(b'HTTP/1.1 200 OK\r\nX: ' + b'x' * 20000)
            continue
        if not health and mode == 'slow':
            try:
                for byte in b'HTTP/1.1 200 OK\r\n':
                    c.sendall(bytes([byte]))
                    time.sleep(.03)
            except BrokenPipeError:
                pass
            continue
        value = {'status': 'ok'} if health else {
            'choices': [{'message': {'content': '{"advice":"fixture", "fields":{}}'}}],
            'usage': {'prompt_tokens': 12, 'completion_tokens': 7},
            'timings': {'prompt_ms': 1.5, 'predicted_ms': 2.5}}
        data = json.dumps(value).encode() if mode != 'invalid' or health else b'{broken'
        c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(data)).encode()
                  + b'\r\n\r\n' + data)
'''


@pytest.fixture
def server(tmp_path):
    binary = tmp_path / 'usr/libexec/azazel/fake'
    binary.parent.mkdir(parents=True)
    binary.write_text(f'#!{sys.executable}\n' + FAKE)
    binary.chmod(0o700)
    # Short paths also work under macOS's 104-byte sockaddr_un ceiling.
    with tempfile.TemporaryDirectory(prefix='azb-', dir='/tmp') as directory:
        sock = Path(directory) / 's.sock'
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.bind(str(sock))
            sock.unlink()
        except PermissionError:
            pytest.skip('environment denies AF_UNIX bind (PermissionError)')
        handles = []

        def make(mode='ok', **kwargs):
            record = RuntimeBinary('fake', '/usr/libexec/azazel/fake', 'test',
                                   'sha256:' + '0' * 64,
                                   ('/usr/libexec/azazel/fake', str(sock), mode))
            handle = LocalServer(record, root=tmp_path, socket_path=sock,
                                 start_deadline_s=2, **kwargs)
            handles.append(handle)
            return handle

        yield make
        for handle in handles:
            handle.stop()


def request():
    return LocalInferenceRequest((('user', 'private fixture question'),), 32, 0)


@pytest.mark.parametrize(('metadata', 'integrity'), [
    ({}, 'unknown'),
    ({'truncated': False}, 'preserved'),
    ({'truncated': True}, 'truncated'),
    ({'timings': {'truncated': True}}, 'truncated'),
    ({'truncated': False, 'timings': {'truncated': True}}, 'truncated'),
])
def test_infer_extracts_request_integrity_without_inferring_it_from_stop(metadata, integrity):
    handle = object.__new__(LocalServer)
    handle._child = SimpleNamespace(alive=True)
    handle.state = LifecycleState.SERVING
    response = {'choices': [{'message': {'content': '{}'}, 'finish_reason': 'stop'}],
                'usage': {'prompt_tokens': 12, 'completion_tokens': 7}, **metadata}
    handle._http = lambda *args: json.dumps(response).encode()
    result = handle.infer(request(), 1)
    assert result.finish_reason == 'stop'
    assert result.context_integrity == integrity
    assert (result.tokens_in, result.tokens_out) == (12, 7)


@pytest.mark.parametrize('bad', [0, 1, 'false', None])
def test_infer_treats_non_boolean_truncation_metadata_as_unknown(bad):
    handle = object.__new__(LocalServer)
    handle._child = SimpleNamespace(alive=True)
    handle.state = LifecycleState.SERVING
    response = {'choices': [{'message': {'content': '{}'}}],
                'usage': {'prompt_tokens': 12, 'completion_tokens': 7},
                'truncated': bad}
    handle._http = lambda *args: json.dumps(response).encode()
    assert handle.infer(request(), 1).context_integrity == 'unknown'


@pytest.mark.parametrize('finish', [None, 'length', 'stop'])
def test_infer_preserves_finish_reason_without_claiming_context_integrity(finish):
    handle = object.__new__(LocalServer)
    handle._child = SimpleNamespace(alive=True)
    handle.state = LifecycleState.SERVING
    response = {'choices': [{'message': {'content': '{}'}, 'finish_reason': finish}],
                'usage': {'prompt_tokens': 12, 'completion_tokens': 7}}
    handle._http = lambda *args: json.dumps(response).encode()
    result = handle.infer(request(), 1)
    assert result.finish_reason == finish
    assert result.context_integrity == 'unknown'


@pytest.mark.real_process
def test_serves_repeatedly_discards_output_replaces_environment(server, monkeypatch):
    monkeypatch.setenv('AZ_PARENT_MARKER', 'must not inherit')
    handle = server()
    handle.start()
    pid = handle._child.process.pid
    handle.start()
    assert handle._child.process.pid == pid
    assert handle.health()
    for _ in range(2):
        result = handle.infer(request(), deadline_s=2)
        assert json.loads(result.text)['advice'] == 'fixture'
        assert (result.tokens_in, result.tokens_out) == (12, 7)
        assert result.timings['prompt_ms'] == 1.5
        assert 'fixture' not in repr(result)
    handle.stop()
    handle.stop()
    assert not handle.health()
    assert not handle.socket_path.exists()
    assert handle.budget.spent == 0


@pytest.mark.real_process
@pytest.mark.parametrize('mode', ['oversize', 'invalid', 'headers'])
def test_response_refusals(server, mode):
    handle = server(mode)
    handle.start()
    with pytest.raises(LocalServerRefused):
        handle.infer(request(), deadline_s=2)


@pytest.mark.real_process
@pytest.mark.parametrize('mode', ['hang', 'slow'])
def test_deadline_is_total_including_dripping_headers(server, mode):
    handle = server(mode)
    handle.start()
    began = time.monotonic()
    with pytest.raises(TimeoutError):
        handle.infer(request(), deadline_s=.15)
    assert time.monotonic() - began < 1


@pytest.mark.real_process
def test_crash_restart_budget_persists_and_fences(server, tmp_path):
    ledger = BudgetLedger(tmp_path / 'budget.json')
    fenced = []
    handle = server('crash', budget=RestartBudget(generation=1, limit=1),
                    ledger=ledger, on_budget_spent=fenced.append)
    for _ in range(2):
        with pytest.raises(LocalServerRefused):
            handle.start()
    with pytest.raises(LocalServerRefused, match='fenced'):
        handle.start()
    assert handle.state is LifecycleState.FENCED
    assert ledger.load(generation=1, runtime_id='fake').fenced
    assert fenced == ['mio-local']
    with pytest.raises(LocalServerRefused, match='fenced'):
        handle.start()
    assert fenced == ['mio-local']


@pytest.mark.real_process
def test_restart_after_kill_cleans_socket_and_spends_budget(server):
    handle = server()
    handle.start()
    handle._child.process.send_signal(signal.SIGKILL)
    handle._child.process.wait(timeout=2)
    assert not handle.health()
    handle.start()
    assert handle.health()
    assert handle.budget.spent == 1


@pytest.mark.real_process
def test_inference_after_process_exit_is_not_replayed(server):
    handle = server('exit')
    handle.start()
    with pytest.raises(LocalServerRefused):
        handle.infer(request(), deadline_s=1)
    assert handle.budget.spent == 0


def test_request_limits_and_private_repr():
    assert 'private fixture question' not in repr(request())
    with pytest.raises(LocalServerRefused):
        LocalInferenceRequest((('user', 'x' * (MAX_REQUEST_BYTES + 1)),))
    for tokens in (0, True, -1, 32769):
        with pytest.raises(LocalServerRefused):
            LocalInferenceRequest((('user', 'x'),), max_tokens=tokens)
    for temperature in (float('nan'), float('inf'), -1, True):
        with pytest.raises(LocalServerRefused):
            LocalInferenceRequest((('user', 'x'),), temperature=temperature)


def test_llama_record_has_fixed_literal_argv_and_no_admission():
    binary = RuntimeBinary('llama', '/usr/libexec/azazel/llama-server', 'b11716',
                           'sha256:' + '0' * 64, ('/usr/libexec/azazel/llama-server',))
    record = llama_server_record(binary, model_path=Path('/models/a b.gguf'),
                                 socket_path=Path('/run/mio.sock'), ctx=1024, threads=4)
    assert record.argv == (binary.executable, '-m', '/models/a b.gguf', '--host',
                           '/run/mio.sock', '-c', '1024', '-t', '4', '--no-webui', '-n', '256')
    assert set(RUNTIMES) == {"llama-cpp-b11716"}
    for overrides in ({'model_path': Path('relative')}, {'ctx': 0}, {'threads': True},
                      {'socket_path': Path('/tmp/not-unix')},
                      {'model_path': Path('/models/{template}')},
                      {'model_path': Path('/models/../escape')}):
        args = {'model_path': Path('/models/test.gguf'), 'socket_path': Path('/run/mio.sock')}
        args.update(overrides)
        with pytest.raises(RuntimeRefused):
            llama_server_record(binary, **args)


@pytest.mark.parametrize('response', [
    b'HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nx',
    b'HTTP/1.1 200 OK\r\nX: ' + b'x' * 17000,
    b'HTTP/1.1 200 OK\r\n',
])
def test_http_parser_refuses_unbounded_or_incomplete_responses(monkeypatch, response):
    handle, peer = _wire_handle(monkeypatch, response)
    with pytest.raises(LocalServerRefused):
        handle._http('GET', '/health', b'', time.monotonic() + 1)
    assert peer.read <= 16384


def _wire_handle(monkeypatch, response):
    import azazel_nexus_runtime.mio_serve as module

    class Peer:
        read = 0
        sent = b''

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, value):
            assert 0 < value <= 1

        def connect(self, path):
            assert path == '/tmp/test.sock'

        def sendall(self, data):
            self.sent += data

        def recv(self, size):
            data = response[self.read:self.read + size]
            self.read += len(data)
            return data

    peer = Peer()
    monkeypatch.setattr(module.socket, 'socket', lambda *args: peer)
    binary = RuntimeBinary('test', '/usr/libexec/azazel/test', 'test', '',
                           ('/usr/libexec/azazel/test',))
    return LocalServer(binary, root=Path('/'), socket_path=Path('/tmp/test.sock')), peer


def test_http_parser_accepts_bounded_body_and_sends_no_tcp_target(monkeypatch):
    handle, peer = _wire_handle(
        monkeypatch, b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}')
    assert handle._http('POST', '/v1/chat/completions', b'{}', time.monotonic() + 1) == b'{}'
    assert peer.sent.startswith(b'POST /v1/chat/completions HTTP/1.1\r\n')
    assert peer.sent.endswith(b'\r\n\r\n{}')


def test_encoded_request_size_is_checked_before_transport(monkeypatch):
    handle, _ = _wire_handle(monkeypatch, b'')
    monkeypatch.setattr(type(handle._child), 'alive', property(lambda self: True))
    handle.state = LifecycleState.SERVING
    with pytest.raises(LocalServerRefused, match='byte ceiling'):
        handle.infer(LocalInferenceRequest((('user', '\u0000' * 60000),)), 1)


@pytest.fixture(autouse=True)
def explicit_fake_serving(monkeypatch):
    from admission_helpers import install_fake_serving

    install_fake_serving(monkeypatch)
