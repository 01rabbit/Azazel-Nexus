"""D-PUBLIC controlled receipt -> recent -> status -> JSON/Markdown regressions."""
from dataclasses import replace

import pytest

from azazel_nexus.model_text import is_typed_content_digest
from azazel_nexus_runtime.mio_advisory_manifest import references

import test_runtime_binding_handoff as flow
from test_handoff import root  # noqa: F401
from test_model_text import DIGEST, INVALID_DIGESTS


@pytest.fixture
def digest_provider(monkeypatch):
    frame, cap = flow.inputs()
    monkeypatch.setattr(flow, 'inputs', lambda: (replace(frame, evidence_refs=(DIGEST,)), cap))

    class Provider(flow.ProseProvider):
        def infer(self, *args, **kwargs):
            result = super().infer(*args, **kwargs)
            return replace(result, text=result.text.replace('ev:ssh:1', DIGEST))
    return Provider


@pytest.mark.parametrize('text', ['possible h1', 'possible ' + DIGEST, '参照 ' + DIGEST + '。'])
def test_digest_receipt_binding_displays_and_exports(root, tmp_path, digest_provider, text):
    _, frame, _, value, metadata = flow.execute(tmp_path, server=digest_provider(text))
    assert metadata['completeness'] == 'complete'
    assert not metadata['unlisted_prose_ids']
    assert DIGEST in metadata['advisory_refs']
    recent, path = flow.project(root, tmp_path, frame, value, metadata)
    advisory = flow.check_export(root, recent, available=True)
    assert advisory['binding']['evidence_refs'][0]['id'] == DIGEST
    assert DIGEST.encode() in path.read_bytes()
    files = flow.handoff.encode_files(flow.package(root, now=flow.time.time()))
    assert all(DIGEST.encode() in files[name] for name in ('handoff.json', 'handoff.ja.md'))


@pytest.mark.parametrize('reference', ['sha256:' + 'f' * 64,
    *[value for value in INVALID_DIGESTS if type(value) is str and not value.endswith('\n')],
    DIGEST + ' ｓｈａ２５６：' + DIGEST[7:]])
def test_unlisted_or_malformed_digest_prose_is_partial(root, tmp_path, digest_provider, reference):
    _, frame, _, value, metadata = flow.execute(tmp_path, server=digest_provider('possible ' + reference))
    assert metadata['completeness'] == 'partial'
    if reference == 'sha256:' + 'f' * 64:
        assert metadata['unlisted_prose_ids']
        assert reference not in metadata['advisory_refs']
    recent, _ = flow.project(root, tmp_path, frame, value, metadata)
    flow.check_export(root, recent, available=False)


@pytest.mark.parametrize('text', [DIGEST + '+Abc', DIGEST + '/Abc', 'token=' + DIGEST])
def test_r1_punctuation_and_secret_label_keep_manifest_but_withhold_body(
        root, tmp_path, digest_provider, text):
    assert references({'statement': text}) == (set(), {DIGEST}, False)
    _, frame, _, value, metadata = flow.execute(tmp_path, server=digest_provider(text))
    assert metadata['completeness'] == 'complete'
    assert not metadata['unlisted_prose_ids']
    assert DIGEST in metadata['advisory_refs']
    recent, path = flow.project(root, tmp_path, frame, value, metadata)
    fixed = flow.incident_explain._MODEL_TEXT_WITHHELD
    slow = recent['incidents'][0]['explanation']['slow_analysis']
    assert slow['hypotheses'][0] == fixed
    advisory = flow.check_export(root, recent, available=True)
    assert advisory['hypotheses'][0] == fixed
    assert advisory['binding']['evidence_refs'][0]['id'] == DIGEST
    files = flow.handoff.encode_files(flow.package(root, now=flow.time.time()))
    bodies = [path.read_bytes(), files['handoff.json'], files['handoff.ja.md']]
    # The digest remains legitimate binding metadata, never raw model prose.
    assert all(text.encode() not in body and b'Abc' not in body for body in bodies)
    assert all(DIGEST.encode() in body for body in bodies)
    assert fixed in files['handoff.ja.md'].decode()


@pytest.mark.parametrize('suffix', ['Abc', '_x', '-1', '.x', ':1'])
def test_r1_id_character_suffix_is_ambiguous_and_partial(
        root, tmp_path, digest_provider, suffix):
    text = DIGEST + suffix
    assert not is_typed_content_digest(text)
    assert references({'statement': text}) == (set(), set(), True)
    _, frame, _, value, metadata = flow.execute(tmp_path, server=digest_provider(text))
    assert metadata['completeness'] == 'partial'
    assert not metadata['unlisted_prose_ids']
    assert text not in metadata['advisory_refs']
    recent, path = flow.project(root, tmp_path, frame, value, metadata)
    flow.check_export(root, recent, available=False)
    bodies = [path.read_bytes(), *flow.handoff.encode_files(
        flow.package(root, now=flow.time.time())).values()]
    assert all(text.encode() not in body for body in bodies)


# Original R14 three counterexamples + old six, R12 eight, R13 substring.
_SECRET_PROSE = [
    'pwd syntheticvalue h1', 'pwd syntheticvalue; status: good',
    'auth syntheticvalue confirmed', 'pin_status: syntheticvalue',
    'user.auth.name: syntheticvalue', 'pass-mode: syntheticvalue',
    'my otp value: syntheticvalue', 'my_key_name: syntheticvalue',
    'hint,pwd,status: syntheticvalue', *flow._R12_SECRET_PROSE[:8],
    'prefixTokenSuffix=v',
]


@pytest.mark.parametrize('text', _SECRET_PROSE)
def test_digest_binding_preserves_r12_r13_r14_secret_withholding(root, tmp_path, digest_provider, text):
    _, frame, _, value, metadata = flow.execute(tmp_path, server=digest_provider(text))
    assert metadata['completeness'] == 'complete'
    recent, path = flow.project(root, tmp_path, frame, value, metadata)
    fixed = flow.incident_explain._MODEL_TEXT_WITHHELD
    assert recent['incidents'][0]['explanation']['slow_analysis']['hypotheses'][0] == fixed
    assert flow.check_export(root, recent, available=True)['hypotheses'][0] == fixed
    bodies = [path.read_bytes(), *flow.handoff.encode_files(flow.package(root, now=flow.time.time())).values()]
    assert all(b'syntheticvalue' not in body and b'prefixTokenSuffix' not in body for body in bodies)


@pytest.mark.parametrize('mark', ['\u3164', '\u20dd', '\ufe0f', '\u0301'])
@pytest.mark.parametrize('field', ['hypotheses', 'unknowns', 'next_checks'])
def test_digest_binding_preserves_r10_m1_writer_guard(root, tmp_path, digest_provider, mark, field):
    _, frame, _, value, metadata = flow.execute(tmp_path, server=digest_provider('possible h1'))
    recent, path = flow.project(root, tmp_path, frame, value, metadata)
    recent['incidents'][0]['explanation']['slow_analysis'][field] = [f'p{mark}wd=syntheticvalue']
    explainer = flow.incident_explaind.Explainer(incidents=tmp_path/'writer-incidents',
        state=tmp_path/'writer-state', status_path=path.with_name('status.json'), clock=flow.time.time)
    explainer.prepare()
    explainer.recent = recent['incidents']
    explainer.recent_status()
    reread = flow.incident_explain.read_recent_incidents(path.read_bytes())
    slow = reread['incidents'][0]['explanation']['slow_analysis']
    assert slow['binding']['completeness'] == 'complete'
    assert slow[field] == [flow.incident_explain._MODEL_TEXT_WITHHELD]
    flow.check_export(root, reread, available=True)
    assert all(b'syntheticvalue' not in body for body in [path.read_bytes(),
        *flow.handoff.encode_files(flow.package(root, now=flow.time.time())).values()])
