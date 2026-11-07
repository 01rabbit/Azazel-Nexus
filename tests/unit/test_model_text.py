"""D-PUBLIC: a content digest is an exact ID type, never a general token pass."""
import copy

import pytest

from azazel_nexus import handoff, incident_explain
from azazel_nexus.model_text import is_typed_content_digest
from test_handoff import INCIDENT, NOW, binding

DIGEST = 'sha256:' + '0123456789abcdef' * 4
INVALID_DIGESTS = [
    DIGEST[:-1], DIGEST + '0', DIGEST.upper(), 'SHA256:' + DIGEST[7:],
    'sha256:' + 'ABCDEF0123456789' * 4,
    'sha512:' + DIGEST[7:], 'digest:' + DIGEST[7:], DIGEST[7:],
    'sha256:' + 'AbCdEfGh0123_-' * 5,
    'sha256:' + 'AbCdEfGh0123+/' * 5 + '=',
    'sha256:' + 'ａ' * 64, 'ｓｈａ２５６：' + DIGEST[7:],
    'sha256:' + 'a' * 31 + '\u200b' + 'a' * 33,
    'sha\u2060256:' + DIGEST[7:], DIGEST + '\n',
    'x' + DIGEST, DIGEST + ':1', None, 256,
]


def digest_binding():
    value = copy.deepcopy(binding())
    old = value['evidence_refs'][0]['id']
    value['evidence_refs'][0]['id'] = DIGEST
    value['advisory_refs'] = [DIGEST if ref == old else ref for ref in value['advisory_refs']]
    return value


@pytest.mark.parametrize('value', [DIGEST, 'sha256:' + '0' * 64, 'sha256:' + 'f' * 64])
def test_exact_typed_content_digest(value):
    assert is_typed_content_digest(value)


@pytest.mark.parametrize('value', INVALID_DIGESTS)
def test_malformed_digest_is_not_a_binding_id(value):
    assert not is_typed_content_digest(value)
    candidate = digest_binding()
    candidate['evidence_refs'][0]['id'] = value
    candidate['advisory_refs'] = [value]
    assert not incident_explain.valid_handoff_binding(candidate, INCIDENT, NOW)
    assert incident_explain.public_slow_analysis(
        {'state': 'complete', 'binding': candidate}, INCIDENT, NOW)['state'] != 'complete'


def test_typed_digest_binding_still_requires_membership_and_source_policy():
    candidate = digest_binding()
    assert incident_explain.valid_handoff_binding(candidate, INCIDENT, NOW)
    assert incident_explain.public_slow_analysis(
        {'state': 'complete', 'binding': candidate}, INCIDENT, NOW)['binding'] == candidate
    candidate['advisory_refs'].append('sha256:' + 'f' * 64)
    assert not incident_explain.valid_handoff_binding(candidate, INCIDENT, NOW)
    candidate = digest_binding()
    candidate['evidence_refs'][0]['source'] = DIGEST
    assert not incident_explain.valid_handoff_binding(candidate, INCIDENT, NOW)


def test_export_digest_allowance_is_scoped_to_binding_reference_fields():
    assert not handoff.scan_package({'binding': digest_binding()})
    for key in ('id', 'advisory_refs', 'source', 'note', 'request_id', 'frame_id'):
        assert handoff.scan_package({key: DIGEST})
    for key in ('source', 'category'):
        assert handoff.scan_package({'binding': {'evidence_refs': [{key: DIGEST}]}})
    for value in INVALID_DIGESTS:
        if type(value) is str:
            assert handoff.scan_package({'binding': {'evidence_refs': [{'id': value}]}})
    # Free prose/identifier guards still reject long tokens, including bare digests.
    assert incident_explain.guard_public_model_text(DIGEST) == incident_explain._MODEL_TEXT_WITHHELD
    assert incident_explain.guard_public_model_text('A' * 32) == incident_explain._MODEL_TEXT_WITHHELD
