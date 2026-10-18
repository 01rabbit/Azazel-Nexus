"""Embedding HTTP, cache lifecycle and runtime fallback, without socket binds."""
import hashlib
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime.mio_embedding import (
    EmbeddingRetriever,
    document_text,
    retrieve,
)
from azazel_nexus_runtime.mio_serve import LocalServer, LocalServerRefused

from azazel_nexus.model_runtime import RUNTIMES, RuntimeBinary, llama_server_record
from azazel_nexus.reasoning_playbook import read_library
from azazel_nexus.runtime_lifecycle import LifecycleState


@pytest.fixture
def library():
    return read_library((Path(__file__).parents[1] / 'fixtures/reasoning-playbook.json').read_bytes())


@pytest.fixture
def frame():
    return {'request_id': 'embed', 'privacy_class': 'P2-mission',
            'question': 'Explain host-1 unusual behavior',
            'context': [{'kind': 'log', 'text': 'observation without keywords'}]}


class FakeEmbedding:
    def __init__(self):
        self.calls = []

    def start(self, deadline_s=None):
        pass

    def embed(self, texts, deadline_s):
        self.calls.append(texts)
        return [[1., 0.] for _ in texts]


def test_probe_text_and_keyword_miss_still_retrieves(library, frame, tmp_path):
    entry = library.entries[0]
    assert document_text(entry) == (f"{entry.title['ja']} / {entry.title['en']}. "
        f"{entry.guidance['interpretation']['ja'][0]} {entry.guidance['interpretation']['en'][0]} "
        + ' '.join((*entry.match['keywords']['ja'], *entry.match['keywords']['en'])))
    server = FakeEmbedding()
    retriever = EmbeddingRetriever(server, model_digest='sha256:' + '1' * 64, cache_dir=tmp_path)
    books, scores, method, _ = retrieve(frame, library, retriever, end=time.monotonic() + 5)
    assert method == 'embedding' and scores == (1.,)
    assert books[0].evidence['keywords'] == ()
    assert server.calls[-1] == [frame['question'] + '\n' + frame['context'][0]['text']]
    assert frame['question'] not in next(tmp_path.glob('*.json')).read_text()


def test_cache_reload_corruption_and_model_key(library, frame, tmp_path):
    server = FakeEmbedding()
    def new(model='1'):
        return EmbeddingRetriever(server, model_digest='sha256:' + model * 64, cache_dir=tmp_path)
    end = time.monotonic() + 10
    new().retrieve(frame, library, end=end)
    assert len(server.calls) == 2
    new().retrieve(frame, library, end=end)
    assert len(server.calls) == 3  # cached docs, query only
    path = next(tmp_path.glob('*.json'))
    envelope = json.loads(path.read_text())
    envelope['payload']['vectors'][0][0] = .25
    path.write_text(json.dumps(envelope))
    new().retrieve(frame, library, end=end)
    assert len(server.calls) == 5
    new('2').retrieve(frame, library, end=end)
    assert len(server.calls) == 7 and len(list(tmp_path.glob('*.json'))) == 2
    # A correctly hashed malformed vector is still rejected and recomputed.
    envelope['payload']['vectors'] = [[0., 0.]]
    payload = json.dumps(envelope['payload'], sort_keys=True, ensure_ascii=False).encode()
    envelope['sha256'] = hashlib.sha256(payload).hexdigest()
    path.write_text(json.dumps(envelope))
    new().retrieve(frame, library, end=end)
    assert len(server.calls) == 9


def test_unavailable_embeddings_fall_back(library, frame):
    class Unavailable:
        def retrieve(self, *args, **kwargs):
            raise LocalServerRefused('secret')
    books, scores, method, _ = retrieve(frame, library, Unavailable(), end=time.monotonic() + 5)
    assert books == () and scores == () and method == 'keyword'


@pytest.mark.parametrize('bad', [[], [0., 0.], [float('nan')], [True], [[1.]], [10 ** 400]])
def test_fake_endpoint_rejects_malformed_vectors(monkeypatch, bad):
    server = object.__new__(LocalServer)
    server._child = SimpleNamespace(alive=True)
    server.state = LifecycleState.SERVING
    monkeypatch.setattr(server, '_http', lambda *args: json.dumps({
        'data': [{'index': 0, 'embedding': bad}]}).encode())
    with pytest.raises(LocalServerRefused):
        server.embed(['query'], 1)


def test_fake_endpoint_order_and_pinned_embedding_record(monkeypatch, tmp_path):
    server = object.__new__(LocalServer)
    server._child = SimpleNamespace(alive=True)
    server.state = LifecycleState.SERVING
    def http(method, path, body, end):
        assert path == '/v1/embeddings' and json.loads(body) == {'input': ['a', 'b']}
        return json.dumps({'data': [{'index': 1, 'embedding': [0., 2.]},
                                    {'index': 0, 'embedding': [2., 0.]}]}).encode()
    monkeypatch.setattr(server, '_http', http)
    assert server.embed(['a', 'b'], 1) == [[1., 0.], [0., 1.]]
    binary = RuntimeBinary('test', '/usr/libexec/azazel/llama-server', 'b11716',
                           'sha256:' + '0' * 64, ('/usr/libexec/azazel/llama-server',))
    record = llama_server_record(binary, model_path=tmp_path / 'model', socket_path=tmp_path / 'e.sock',
                                 embedding=True)
    assert record.digest == binary.digest and record.executable == binary.executable
    assert '--embedding' in record.argv and record.argv[record.argv.index('--pooling') + 1] == 'cls'
    assert set(RUNTIMES) == {"llama-cpp-b11716"}


def test_changed_library_reloads_documents(library, frame, tmp_path):
    from dataclasses import replace

    server = FakeEmbedding()
    retriever = EmbeddingRetriever(server, model_digest='sha256:' + '1' * 64, cache_dir=tmp_path)
    end = time.monotonic() + 5
    retriever.retrieve(frame, library, end=end)
    changed = replace(library, entries=(replace(library.entries[0], title={'ja': '変更', 'en': 'Changed'}),))
    retriever.retrieve(frame, changed, end=end)
    assert len(server.calls) == 4
    assert 'Changed' in server.calls[2][0]


def test_service_admission_precedes_embedding(library, frame, tmp_path):
    from azazel_nexus_runtime.mio_locald import INFER_VERB, LocalRuntimeService

    class Forbidden:
        def retrieve(self, *args, **kwargs):
            pytest.fail('embedding before admission')
    service = LocalRuntimeService(playbooks=library, retriever=Forbidden())
    reply = service.handle(SimpleNamespace(verb=INFER_VERB, payload=frame,
                                           arguments={'deadline_ms': 1000}))
    assert reply['outcome'] == 'advisory'
    assert reply['provenance']['retrieval'] == 'keyword'


def test_service_embedding_scope_and_fallback_audit(library, frame, tmp_path):
    from azazel_nexus_runtime.mio_locald import INFER_VERB, LocalRuntimeService

    (tmp_path / 'fixture.model').write_bytes(b'GGUF' + b'\0' * 4096)
    server = FakeEmbedding()
    retriever = EmbeddingRetriever(server, model_digest='sha256:' + '1' * 64, cache_dir=tmp_path)
    service = LocalRuntimeService(staging=tmp_path, reserve=object(), admitted=lambda _: True,
        model_id='fixture', runtime_id='fixture', runtime=lambda _: object(),
        server=None,  # embedding-only service: explanation is optional
        playbooks=library, retriever=retriever)
    request = SimpleNamespace(verb=INFER_VERB, payload=frame, arguments={'deadline_ms': 1000})
    events = []
    reply = service.handle(request, audit=events.append)
    assert reply['outcome'] == 'advisory' and reply['provenance']['retrieval'] == 'embedding'
    def unavailable(*args, **kwargs):
        raise LocalServerRefused('sensitive')
    retriever.retrieve = unavailable
    frame['question'] = 'SSH host-1'
    frame['context'] = []
    reply = service.handle(request, audit=events.append)
    assert reply['outcome'] == 'advisory'
    assert reply['provenance']['retrieval'] == 'keyword'
    assert any(e.get('method') == 'keyword' for e in events)
    assert 'sensitive' not in str(events)


def test_embedding_startup_uses_remaining_deadline(monkeypatch, tmp_path):
    binary = RuntimeBinary('test', '/usr/libexec/azazel/llama-server', 'b11716',
                           'sha256:' + '0' * 64, ('/usr/libexec/azazel/llama-server',))
    server = LocalServer(binary, root=tmp_path, socket_path=tmp_path / 'e.sock', start_deadline_s=10)
    child = SimpleNamespace(alive=False, process=None)
    child.start = lambda: setattr(child, 'alive', True)
    child.stop = lambda: setattr(child, 'alive', False)
    server._child = child
    deadlines = []
    monkeypatch.setattr(server, 'health', lambda deadline_s: deadlines.append(deadline_s) or True)
    server.start(deadline_s=.01)
    assert deadlines and 0 < deadlines[0] <= .01
    with pytest.raises(LocalServerRefused):
        server.start(deadline_s=0)


@pytest.fixture(autouse=True)
def explicit_fake_serving(monkeypatch):
    from admission_helpers import install_fake_serving

    install_fake_serving(monkeypatch)
