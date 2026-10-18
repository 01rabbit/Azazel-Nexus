"""Local embedding retrieval and checked, atomically promoted document cache.

No production admission: callers supply a separately managed LocalServer.
Cache contains trusted playbook vectors only, never situation queries.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
import time
from pathlib import Path

from azazel_nexus.reasoning_playbook import match

MAX_CACHE_BYTES = 32 * 1024 * 1024


def normalized(vector):
    try:
        if (type(vector) is not list or not 1 <= len(vector) <= 8192
                or any(type(v) not in (int, float) or not math.isfinite(v) for v in vector)):
            raise ValueError('invalid_embedding')
        length = math.hypot(*vector)
    except OverflowError:
        raise ValueError('invalid_embedding') from None
    if not math.isfinite(length) or length == 0:
        raise ValueError('invalid_embedding')
    return [v / length for v in vector]


def document_text(entry):
    # Exact probe representation, including first interpretation in each language.
    return (f"{entry.title['ja']} / {entry.title['en']}. "
            f"{entry.guidance['interpretation']['ja'][0]} "
            f"{entry.guidance['interpretation']['en'][0]} "
            + ' '.join((*entry.match['keywords']['ja'], *entry.match['keywords']['en'])))


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False).encode('utf-8')


class EmbeddingRetriever:
    def __init__(self, server, *, model_digest, cache_dir: Path):
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', model_digest):
            raise ValueError('invalid_model_digest')
        self.server = server
        self.model_digest = model_digest
        self.cache_dir = Path(cache_dir)
        self._key = None
        self._vectors = None

    def prepare(self, library, *, end):
        docs = [document_text(e) for e in library.entries]
        library_digest = hashlib.sha256(encoded({
            'layers': [layer.digest for layer in library.layers],
            'ids': [e.id for e in library.entries], 'docs': docs})).hexdigest()
        key = hashlib.sha256(encoded([library_digest, self.model_digest])).hexdigest()
        if key == self._key:
            return
        path = self.cache_dir / (key + '.json')
        vectors = None
        try:
            if path.is_symlink():
                raise ValueError('invalid_cache')
            with path.open('rb') as stream:
                raw = stream.read(MAX_CACHE_BYTES + 1)
            if len(raw) > MAX_CACHE_BYTES:
                raise ValueError('invalid_cache')
            envelope = json.loads(raw)
            payload = envelope['payload']
            if (set(envelope) != {'payload', 'sha256'} or set(payload) != {'key', 'vectors'}
                    or payload['key'] != key
                    or hashlib.sha256(encoded(payload)).hexdigest() != envelope['sha256']):
                raise ValueError('invalid_cache')
            vectors = self._validate(payload['vectors'], len(docs))
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            vectors = None
        if vectors is None:
            self.server.start(deadline_s=self._remaining(end))
            vectors = []
            # Bounded batches fit LocalServer's request and response ceilings.
            for offset in range(0, len(docs), 8):
                vectors.extend(self.server.embed(docs[offset:offset + 8], deadline_s=self._remaining(end)))
            vectors = self._validate(vectors, len(docs))
            payload = {'key': key, 'vectors': vectors}
            raw = encoded({'payload': payload, 'sha256': hashlib.sha256(encoded(payload)).hexdigest()})
            if len(raw) > MAX_CACHE_BYTES:
                raise ValueError('cache_too_large')
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            descriptor, temporary = tempfile.mkstemp(prefix='.embedding-', dir=self.cache_dir)
            try:
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
            finally:
                Path(temporary).unlink(missing_ok=True)
        self._key, self._vectors = key, vectors

    @staticmethod
    def _remaining(end):
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('embedding_deadline')
        return remaining

    @staticmethod
    def _validate(vectors, count):
        if type(vectors) is not list or len(vectors) != count:
            raise ValueError('invalid_embedding_count')
        result = [normalized(v) for v in vectors]
        if len({len(v) for v in result}) > 1:
            raise ValueError('invalid_embedding_dimension')
        return result

    def retrieve(self, frame, library, *, end):
        self.prepare(library, end=end)
        self.server.start(deadline_s=self._remaining(end))
        query = frame['question'] + '\n' + '\n'.join(i['text'] for i in frame['context'])
        vectors = self.server.embed([query], deadline_s=self._remaining(end))
        query_vector = self._validate(vectors, 1)[0]
        if self._vectors and len(query_vector) != len(self._vectors[0]):
            raise ValueError('invalid_embedding_dimension')
        evidence = {p.id: p for p in match(frame, library, limit=512, include_unmatched=True)}
        ranked = sorted(((max(-1., min(1., sum(a * b for a, b in zip(query_vector, v, strict=True)))), e.id)
                         for e, v in zip(library.entries, self._vectors, strict=True)),
                        key=lambda item: (-item[0], item[1]))[:3]
        return tuple(evidence[identity] for _, identity in ranked), tuple(score for score, _ in ranked)


def retrieve(frame, library, retriever, *, end):
    from .mio_supervisor import SupervisorRefused

    began = time.monotonic()
    if retriever is not None and library is not None:
        try:
            books, similarities = retriever.retrieve(frame, library, end=end)
            return books, similarities, 'embedding', (time.monotonic() - began) * 1000
        except (OSError, ValueError, TimeoutError, RuntimeError, SupervisorRefused):
            pass
    books = match(frame, library) if library is not None else ()
    return books, (), 'keyword', (time.monotonic() - began) * 1000
