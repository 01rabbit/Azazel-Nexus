"""Bounded, deterministic reference data. Advice confers no operational authority."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from .local_advisory import read_frame

SCHEMA = 'azazel-nexus/reasoning-playbook/1'
MAX_BYTES = 2 * 1024 * 1024
_ID = r'[a-z0-9][a-z0-9-]{2,63}'
_ATTACK = r'T\d{4}(?:\.\d{3})?'
_CATEGORIES = frozenset(('authentication', 'network', 'endpoint', 'web_application',
                         'email', 'cloud', 'vulnerability', 'data_exfiltration', 'insider',
                         'availability', 'deception', 'supply_chain', 'edge_network'))
_REFERENCES = {
    'mitre-attack': r'(?:T\d{4}(?:\.\d{3})?|TA\d{4})',
    'mitre-d3fend': r'D3-[A-Z0-9]{2,12}',
    'owasp-top10-2021': r'A(?:0[1-9]|10)',
    'owasp-asvs': r'V\d{1,2}(?:\.\d{1,2}){0,2}',
    'owasp-cheatsheet': r'[a-z0-9-]{3,64}',
    'nist-sp800-61r3': r'(?:govern|identify|protect|detect|respond|recover)',
    'cisa-kev': r'CVE-\d{4}-\d{4,7}',
}
_UNSAFE = re.compile(
    r'://|www\.|`|\$\(|&&|\||;\s*[A-Za-z_]|rm\s+-|sudo\s|chmod\s|curl\s|wget\s|'
    r'powershell\s+-|iptables\s|nft\s|enforcement|block_all', re.IGNORECASE,
)
_JAPANESE = re.compile(r'[ぁ-ゖァ-ヺ一-鿿]')


class PlaybookRefused(ValueError):
    """Fixed reasons only; never include document text or paths."""


def _require(ok, reason='malformed_library'):
    if not ok:
        raise PlaybookRefused(reason)


def _fields(value, names):
    _require(type(value) is dict and set(value) == set(names))


def _pattern(value, pattern):
    _require(type(value) is str and re.fullmatch(pattern, value, flags=re.ASCII) is not None)


def _text(value, maximum):
    _require(type(value) is str and 0 < len(value.strip()) and len(value) <= maximum)
    value.encode('utf-8')
    _require(not _UNSAFE.search(value), 'unsafe_text')
    _require(not any(ord(c) < 32 and c not in '\n\t' for c in value), 'unsafe_text')


def _list(value, maximum, minimum=0):
    _require(type(value) is list and minimum <= len(value) <= maximum)


def _bilingual(value, maximum, *, lists=False):
    _fields(value, ('ja', 'en'))
    for items in value.values():
        if lists:
            _list(items, 5, 1)
            for item in items:
                _text(item, maximum)
        else:
            _text(items, maximum)


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class Entry:
    id: str
    status: str
    category: str
    title: Mapping
    references: tuple[Mapping, ...]
    match: Mapping
    guidance: Mapping


@dataclass(frozen=True)
class Layer:
    library_id: str
    version: str
    digest: str


@dataclass(frozen=True)
class Library:
    library_id: str
    layer: str
    version: str
    disable: tuple[str, ...]
    entries: tuple[Entry, ...]
    layers: tuple[Layer, ...]


@dataclass(frozen=True)
class Match:
    id: str
    score: int
    status: str
    title: str
    references: tuple[Mapping, ...]
    guidance: Mapping


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, 'duplicate_key')
        result[key] = value
    return result


def read_library(raw: bytes) -> Library:
    """Read one strict UTF-8 layer, rejecting unknown and duplicate fields."""
    _require(type(raw) is bytes, 'malformed_library')
    _require(len(raw) <= MAX_BYTES, 'library_too_large')
    try:
        doc = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                         parse_constant=lambda _: _require(False))
        return _read(doc, raw)
    except PlaybookRefused:
        raise
    except (UnicodeError, ValueError, RecursionError, TypeError, KeyError):
        raise PlaybookRefused('malformed_library') from None


def _read(doc, raw):
    _fields(doc, ('schema', 'library_id', 'layer', 'version', 'disable', 'entries'))
    _require(doc['schema'] == SCHEMA)
    _pattern(doc['library_id'], r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}')
    _require(doc['layer'] in ('baseline', 'site'))
    _pattern(doc['version'], r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)')
    _list(doc['disable'], 512)
    for identity in doc['disable']:
        _pattern(identity, _ID)
    _require(len(set(doc['disable'])) == len(doc['disable']))
    _require(doc['layer'] != 'baseline' or not doc['disable'])
    _list(doc['entries'], 512)
    entries = []
    for entry in doc['entries']:
        _fields(entry, ('id', 'status', 'category', 'title', 'references', 'match', 'guidance'))
        _pattern(entry['id'], _ID)
        _require(entry['status'] in ('template', 'reviewed'))
        _require(doc['layer'] != 'baseline' or entry['status'] == 'template')
        _require(type(entry['category']) is str and entry['category'] in _CATEGORIES)
        _bilingual(entry['title'], 160)
        _list(entry['references'], 8, 1)
        for ref in entry['references']:
            _fields(ref, ('source', 'id'))
            _require(type(ref['source']) is str and ref['source'] in _REFERENCES)
            _pattern(ref['id'], _REFERENCES[ref['source']])
        rules = entry['match']
        _fields(rules, ('keywords', 'attack_techniques', 'context_kinds', 'min_score'))
        _fields(rules['keywords'], ('ja', 'en'))
        for words in rules['keywords'].values():
            _list(words, 24, 1)
            for word in words:
                _text(word, 48)
            _require(len({word.casefold() for word in words}) == len(words))
        for field, pattern in (('attack_techniques', _ATTACK),
                               ('context_kinds', r'[a-z0-9_]{1,64}')):
            _list(rules[field], 512)
            for item in rules[field]:
                _pattern(item, pattern)
            _require(len(set(rules[field])) == len(rules[field]))
        _require(type(rules['min_score']) is int and rules['min_score'] >= 1)
        _fields(entry['guidance'], ('interpretation', 'checks', 'first_response', 'benign', 'missing'))
        for guidance in entry['guidance'].values():
            _bilingual(guidance, 160, lists=True)
        entries.append(Entry(**_freeze(entry)))
    _require(len({e.id for e in entries}) == len(entries))
    layer = Layer(doc['library_id'], doc['version'], 'sha256:' + hashlib.sha256(raw).hexdigest())
    return Library(doc['library_id'], doc['layer'], doc['version'], tuple(doc['disable']),
                   tuple(entries), (layer,))


def load_library(path: Path, expected_digest: str) -> Library:
    """Verify bounded regular data against the supplied Mission Pack component pin."""
    _pattern(expected_digest, r'sha256:[0-9a-f]{64}')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            _require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_BYTES, 'invalid_file')
            raw = stream.read(MAX_BYTES + 1)
        _require(len(raw) <= MAX_BYTES, 'library_too_large')
    except (OSError, ValueError, TypeError) as exc:
        if isinstance(exc, PlaybookRefused):
            raise
        raise PlaybookRefused('invalid_file') from None
    _require('sha256:' + hashlib.sha256(raw).hexdigest() == expected_digest, 'digest_mismatch')
    return read_library(raw)


def compose(baseline: Library, *site_layers: Library) -> Library:
    """Apply each site's removals, then replacements/additions, in supplied order."""
    _require(baseline.layer == 'baseline', 'invalid_layer_order')
    entries = {entry.id: entry for entry in baseline.entries}
    layers = list(baseline.layers)
    for site in site_layers:
        _require(site.layer == 'site', 'invalid_layer_order')
        for identity in site.disable:
            entries.pop(identity, None)
        entries.update((entry.id, entry) for entry in site.entries)
        layers.extend(site.layers)
    _require(len(entries) <= 512, 'too_many_entries')
    return Library(baseline.library_id, 'composed', baseline.version, (),
                   tuple(entries[key] for key in sorted(entries)), tuple(layers))


def technique_ids(frame) -> tuple[str, ...]:
    """Bounded exact technique tokens from validated frame text, in stable order."""
    checked = read_frame(frame)
    text = ' '.join([checked['question'], *(item['text'] for item in checked['context'])])
    return tuple(sorted(set(re.findall(r'(?<![A-Za-z0-9_.])T\d{4}(?:\.\d{3})?(?![A-Za-z0-9_.])',
                                      text, flags=re.ASCII))))[:8]


def match(frame, library: Library, *, limit=2) -> tuple[Match, ...]:
    _require(type(limit) is int and 0 <= limit <= 512, 'invalid_limit')
    checked = read_frame(frame)
    language = 'ja' if _JAPANESE.search(checked['question']) else 'en'
    text = ' '.join([checked['question'], *(item['text'] for item in checked['context'])]).casefold()
    # Matching is not limited to the eight ids sent to Knowledge lookup.
    ids = set(re.findall(r'(?<![a-z0-9_.])t\d{4}(?:\.\d{3})?(?![a-z0-9_.])', text, re.ASCII))
    kinds = {item['kind'] for item in checked['context']}
    matches = []
    for entry in library.entries:
        rules = entry.match
        score = (3 * sum(identity.casefold() in ids for identity in rules['attack_techniques'])
                 + sum(word.casefold() in text for word in rules['keywords'][language])
                 + int(bool(kinds.intersection(rules['context_kinds']))))
        if score >= rules['min_score']:
            matches.append(Match(entry.id, score, entry.status, entry.title[language],
                                 entry.references, MappingProxyType({
                                     key: value[language] for key, value in entry.guidance.items()})))
    return tuple(sorted(matches, key=lambda item: (-item.score, item.id))[:limit])
