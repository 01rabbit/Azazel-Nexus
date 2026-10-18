"""Strict data, pinned reads and explainable matching without operational imports."""
import copy
import hashlib
import json
from pathlib import Path

import pytest

from azazel_nexus.reasoning_playbook import (
    MAX_BYTES,
    PlaybookRefused,
    compose,
    load_library,
    match,
    read_library,
    technique_ids,
)

FIXTURE = Path(__file__).parents[1] / 'fixtures' / 'reasoning-playbook.json'


def document():
    return json.loads(FIXTURE.read_bytes())


def library(doc=None):
    return read_library(json.dumps(doc or document(), ensure_ascii=False).encode())


def frame(question='Password spray T1110.003', kind='auth_log'):
    return {'request_id': 'fixture', 'privacy_class': 'P2-mission', 'question': question,
            'context': [{'kind': kind, 'text': 'many accounts'}]}


@pytest.mark.parametrize('change', [
    lambda d: d.update(unknown=True),
    lambda d: d.update(disable=['auth-password-spraying']),
    lambda d: d.update(schema='unknown'),
    lambda d: d.update(version='1.0'),
    lambda d: d['entries'][0].update(id='../bad'),
    lambda d: d['entries'][0].update(status='reviewed'),
    lambda d: d['entries'][0].update(category=[]),
    lambda d: d['entries'][0]['references'][0].update(id='T1110.003junk'),
    lambda d: d['entries'][0]['references'][0].update(source='unknown'),
    lambda d: d['entries'][0]['match'].update(min_score=True),
    lambda d: d['entries'][0]['match'].update(unknown=True),
    lambda d: d['entries'][0]['match']['keywords'].update(en=[]),
    lambda d: d['entries'][0]['guidance']['checks'].update(en=['x' * 161]),
    lambda d: d['entries'][0]['guidance']['checks'].update(fr=['text']),
    lambda d: d['entries'].append(copy.deepcopy(d['entries'][0])),
])
def test_validator_refuses(change):
    doc = document()
    change(doc)
    with pytest.raises(PlaybookRefused) as caught:
        library(doc)
    assert str(caught.value) in ('malformed_library', 'unsafe_text')


@pytest.mark.parametrize('text', ['https://example.invalid', 'www.example.invalid', '`example`',
                                  '$(id)', 'one && two', 'one | two', 'one; id', 'rm -rf',
                                  'sudo x', 'chmod x', 'curl x', 'wget x', 'powershell -x',
                                  'iptables x', 'nft x', 'enforcement', 'block_all'])
def test_unsafe_text_refused(text):
    doc = document()
    doc['entries'][0]['guidance']['checks']['en'] = [text]
    with pytest.raises(PlaybookRefused, match='unsafe_text'):
        library(doc)


def test_oversize_duplicates_and_invalid_utf8():
    for raw in (b' ' * (MAX_BYTES + 1), b'{"schema":1,"schema":2}', b'\xff', b'NaN',
                b'[' * 2000, b'"\\ud800"', b'9' * 5000):
        with pytest.raises(PlaybookRefused):
            read_library(raw)


def test_pinned_regular_read(tmp_path):
    raw = FIXTURE.read_bytes()
    path = tmp_path / 'library.json'
    path.write_bytes(raw)
    digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
    assert load_library(path, digest).entries[0].id == 'auth-password-spraying'
    with pytest.raises(PlaybookRefused, match='digest_mismatch'):
        load_library(path, 'sha256:' + '0' * 64)
    link = tmp_path / 'link'
    link.symlink_to(path)
    for invalid in (link, tmp_path, tmp_path / 'absent'):
        with pytest.raises(PlaybookRefused, match='invalid_file'):
            load_library(invalid, digest)


def test_compose_override_disable_add_and_provenance():
    base = library()
    doc = document()
    doc.update(layer='site', library_id='fixture-site', version='2.0.0')
    doc['entries'][0].update(status='reviewed', title={'ja': 'サイト用', 'en': 'Site reviewed'})
    override = library(doc)
    assert compose(base, override).entries[0].title['en'] == 'Site reviewed'
    doc.update(disable=['auth-password-spraying'])
    doc['entries'][0]['id'] = 'site-new-entry'
    combined = compose(base, override, library(doc))
    assert [e.id for e in combined.entries] == ['site-new-entry']
    assert [(layer.library_id, layer.version) for layer in combined.layers] == [
        ('fixture-baseline', '1.0.0'), ('fixture-site', '2.0.0'), ('fixture-site', '2.0.0')]
    assert all(layer.digest.startswith('sha256:') for layer in combined.layers)
    with pytest.raises(TypeError):
        combined.entries[0].title['en'] = 'mutated'
    with pytest.raises(PlaybookRefused, match='invalid_layer_order'):
        compose(override)


def test_match_score_language_order_and_exact_tokens():
    doc = document()
    other = copy.deepcopy(doc['entries'][0])
    other['id'] = 'aaa-other-entry'
    doc['entries'].append(other)
    lib = library(doc)
    matches = match(frame(), lib)
    assert [m.id for m in matches] == ['aaa-other-entry', 'auth-password-spraying']
    assert [m.score for m in matches] == [6, 6]
    assert matches[0].title == 'Password spraying'
    assert match(frame('スプレー T1110.003'), lib, limit=1)[0].score == 5
    assert match(frame('スプレー T1110.003'), lib)[0].title == 'パスワードスプレー'
    assert not match(frame('XT1110.0039', kind='observation'), library())
    assert technique_ids(frame('T1110.003 T1110.003 T1059')) == ('T1059', 'T1110.003')
    assert match(frame(), lib) == matches
    assert match(frame(), lib, limit=0) == ()


def test_escaped_surrogate_is_refused_with_fixed_reason():
    doc = document()
    doc['entries'][0]['title']['en'] = '\ud800'
    with pytest.raises(PlaybookRefused, match='^malformed_library$'):
        read_library(json.dumps(doc).encode())


@pytest.mark.parametrize(('source', 'identity'), [
    ('mitre-attack', 'TA0001'), ('mitre-d3fend', 'D3-ANET'),
    ('owasp-top10-2021', 'A10'), ('owasp-asvs', 'V4.1.2'),
    ('owasp-cheatsheet', 'session-management'), ('nist-sp800-61r3', 'respond'),
    ('cisa-kev', 'CVE-2026-12345'),
])
def test_reference_source_formats(source, identity):
    doc = document()
    doc['entries'][0]['references'] = [{'source': source, 'id': identity}]
    assert library(doc).entries[0].references[0]['id'] == identity
    doc['entries'][0]['references'][0]['id'] = identity + '/invalid'
    with pytest.raises(PlaybookRefused):
        library(doc)
