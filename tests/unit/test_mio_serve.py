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


def test_budget_server_reads_context_and_tokenizes_rendered_prompt():
    handle = object.__new__(LocalServer)
    handle._child = SimpleNamespace(alive=True)
    handle.state = LifecycleState.SERVING
    seen = []
    def http(method, path, body, end):
        seen.append((method, path, body))
        if path == '/props':
            return b'{"default_generation_settings":{"n_ctx":2048}}'
        return b'{"tokens":[1,2,3]}'
    handle._http = http
    assert handle.context_limit(1) == 2048
    assert handle.tokenize_rendered('rendered fixture', 1) == 3
    assert json.loads(seen[1][2]) == {'content': 'rendered fixture', 'add_special': True}


def test_count_chat_applies_template_and_shares_deadline(monkeypatch):
    monkeypatch.setattr(time, 'monotonic', lambda: 5.)
    handle = object.__new__(LocalServer)
    handle._child = SimpleNamespace(alive=True)
    handle.state = LifecycleState.SERVING
    seen = []
    def http(method, path, body, end):
        seen.append((path, json.loads(body), end))
        return (b'{"prompt":"rendered fixture"}' if path == '/apply-template'
                else b'{"tokens":[1,2,3]}')
    handle._http = http
    assert handle.count_chat_tokens(request(), 1) == 3
    assert [item[0] for item in seen] == ['/apply-template', '/tokenize']
    assert seen[0][1]['messages'] == [{'role': 'user', 'content': 'private fixture question'}]
    assert seen[1][1]['content'] == 'rendered fixture'
    assert seen[0][2] == seen[1][2] == 6.


@pytest.mark.parametrize('value', [None, True, 0, -1, '2048'])
def test_budget_server_refuses_invalid_context_limit(value):
    handle = object.__new__(LocalServer)
    handle._child = SimpleNamespace(alive=True)
    handle.state = LifecycleState.SERVING
    handle._http = lambda *args: json.dumps({'default_generation_settings': {'n_ctx': value}}).encode()
    with pytest.raises(LocalServerRefused):
        handle.context_limit(1)


@pytest.mark.parametrize('tokens', [None, [True], [-1], ['1'], {}])
def test_budget_server_refuses_invalid_tokens(tokens):
    handle = object.__new__(LocalServer)
    handle._child = SimpleNamespace(alive=True)
    handle.state = LifecycleState.SERVING
    handle._http = lambda *args: json.dumps({'tokens': tokens}).encode()
    with pytest.raises(LocalServerRefused):
        handle.tokenize_rendered('fixture', 1)


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


@pytest.mark.parametrize('finish',['future_reason',True,7])
def test_unknown_finish_reason_remains_unconfirmed_completion(finish):
    handle=object.__new__(LocalServer)
    handle._child=SimpleNamespace(alive=True)
    handle.state=LifecycleState.SERVING
    response={'choices':[{'message':{'content':'{}'},'finish_reason':finish}],
        'usage':{'prompt_tokens':12,'completion_tokens':7},'truncated':False}
    handle._http=lambda *args:json.dumps(response).encode()
    result=handle.infer(request(),1)
    assert result.finish_reason is None and result.context_integrity=='preserved'


@pytest.mark.real_process
def test_dispatch_notification_is_once_after_request_gates(server):
    handle=server();handle.start();notified=[]
    handle.infer(request(),1,on_dispatch=lambda:notified.append('sent'))
    assert notified==['sent']
    with pytest.raises(LocalServerRefused):
        handle.infer(LocalInferenceRequest((('user','\u0000'*60000),)),1,on_dispatch=lambda:notified.append('oversized'))
    assert notified==['sent']
    handle.stop()
    with pytest.raises(LocalServerRefused):handle.infer(request(),1,on_dispatch=lambda:notified.append('stopped'))
    assert notified==['sent']


def native_handle():
    handle=object.__new__(LocalServer)
    handle._child=SimpleNamespace(alive=True);handle.state=LifecycleState.SERVING
    props=dict(model_alias='fixture',model_path='/fixture/model.gguf',model_ftype='Q4',
        chat_template='fixture-template',bos_token='BOS',eos_token='EOS',build_info='fixture-build',
        default_generation_settings={'n_ctx':2048})
    return handle,props


def test_native_count_and_completion_use_identical_tokens_and_primary_integrity_fields():
    handle,props=native_handle();seen=[];notified=[]
    def http(method,path,body,end,**kw):
        seen.append((path,body))
        if kw.get('on_dispatch'):kw['on_dispatch']()
        if path=='/props':return json.dumps(props).encode()
        if path=='/apply-template':return b'{"prompt":"rendered"}'
        if path=='/tokenize':return b'{"tokens":[1,2,3]}'
        return b'{"content":"{}","stop":true,"stop_type":"eos","truncated":false,"tokens_evaluated":3,"tokens_predicted":2,"timings":{"prompt_n":3,"predicted_n":2}}'
    handle._http=http
    req=LocalInferenceRequest((('user','fixture'),),32,response_format={'type':'json_schema','json_schema':{'schema':{'type':'object'}}})
    verified=handle.verified_tuple(1)
    prepared=handle.prepare_native(req,1,expected_tuple=verified)
    result=handle.infer_native(req,1,prepared=prepared,expected_tuple=verified,on_dispatch=lambda:notified.append(1))
    body=json.loads(next(body for path,body in seen if path=='/completion'))
    assert body['prompt']==[1,2,3] and body['n_predict']==32
    assert '/v1/chat/completions' not in [path for path,_ in seen]
    assert (result.tokens_in,result.tokens_out,result.finish_reason,result.context_integrity)==(3,2,'stop','preserved')
    assert notified==[1]


@pytest.mark.parametrize('flag',[None,0,1,'false'])
def test_native_invalid_or_missing_truncated_remains_unknown(flag):
    from azazel_nexus_runtime.mio_serve import native_result
    value=dict(content='{}',stop=True,stop_type='eos',tokens_evaluated=3,tokens_predicted=2)
    if flag is not None:value['truncated']=flag
    assert native_result(value,1).context_integrity=='unknown'


def test_tuple_change_during_count_rejects_before_dispatch():
    from azazel_nexus_runtime.mio_serve import TokenCountUnknown
    handle,props=native_handle();seen=[]
    def http(method,path,body,end,**kw):
        seen.append(path)
        if path=='/props':return json.dumps(props).encode()
        if path=='/apply-template':return b'{"prompt":"rendered"}'
        props['model_path']='/fixture/changed.gguf'
        return b'{"tokens":[1,2,3]}'
    handle._http=http;verified=handle.verified_tuple(1)
    with pytest.raises(TokenCountUnknown):handle.prepare_native(request(),1,expected_tuple=verified)
    assert '/completion' not in seen


def test_verified_tuple_requires_model_tokenizer_template_and_context():
    from azazel_nexus_runtime.mio_serve import TokenCountUnknown
    handle,props=native_handle();props.pop('bos_token')
    handle._http=lambda *args:json.dumps(props).encode()
    with pytest.raises(TokenCountUnknown):handle.verified_tuple(1)


@pytest.mark.parametrize('bad',[None,True,-1,3.0,'3'])
def test_native_usage_requires_strict_counts_without_timings_inference(bad):
    from azazel_nexus_runtime.mio_serve import native_result
    value=dict(content='{}',truncated=False,stop=True,stop_type='eos',tokens_evaluated=bad,
        tokens_predicted=2,timings={'prompt_n':3,'predicted_n':2})
    result=native_result(value,1)
    assert (result.tokens_in,result.tokens_out)==(None,None)
    assert result.context_integrity=='preserved'


def test_native_top_level_truncated_is_primary_and_stop_does_not_infer_it():
    from azazel_nexus_runtime.mio_serve import native_result
    value=dict(content='{}',truncated=True,stop=True,stop_type='eos',tokens_evaluated=3,
        tokens_predicted=2,timings={'truncated':False})
    assert native_result(value,1).context_integrity=='truncated'
    value.pop('truncated')
    assert native_result(value,1).context_integrity=='unknown'


def test_tuple_change_after_count_refuses_before_completion_notification():
    from azazel_nexus_runtime.mio_serve import TokenCountUnknown,NativePrompt,request_digest
    handle,props=native_handle();seen=[]
    def http(method,path,body,end,**kw):
        seen.append(path)
        if kw.get('on_dispatch'):kw['on_dispatch']()
        if path=='/props':return json.dumps(props).encode()
        return b'{"content":"{}","truncated":false,"stop":true,"stop_type":"eos","tokens_evaluated":3,"tokens_predicted":2}'
    handle._http=http
    req=LocalInferenceRequest((('user','fixture'),),32,response_format={'type':'json_schema','json_schema':{'schema':{'type':'object'}}})
    verified=handle.verified_tuple(1)
    prepared=NativePrompt((1,2,3),request_digest(req),verified['tuple_id'])
    props['build_info']='changed-build'
    with pytest.raises(TokenCountUnknown):handle.infer_native(req,1,prepared=prepared,expected_tuple=verified,on_dispatch=lambda:seen.append('sent'))
    assert seen==['/props','/props']
