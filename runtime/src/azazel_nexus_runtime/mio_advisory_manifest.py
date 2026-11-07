"""Body-free caller manifest. Membership is not authority for model prose."""
from datetime import datetime
import math
import re
import unicodedata

_REFERENCE_FIELDS = frozenset({
    'hypothesis_id', 'gap_id', 'supporting_evidence_refs', 'contradicting_evidence_refs',
    'discriminates_hypothesis_ids', 'evidence_refs', 'knowledge_refs', 'unknown_ids',
    'support_refs', 'refute_refs', 'purpose_hypothesis_ids',
})
_KINDS = ('event_id', 'structured_ref', 'suricata_ref', 'knowledge_ref', 'fixture_ref',
          'hypothesis_id', 'gap_id', 'unknown_id')
_TOKENS = re.compile(r'[\w.:-]+')
_REFERENCE_LIKE = re.compile(r'(?i)(?:[ugh][0-9]|(?:um|ux|ev|kn|suricata_sid|sha256):)')


def references(value):
    """Extract IDs before display sanitization, using MIO's shared grammar."""
    from azazel_mio.id_grammar import id_ok
    structured, prose = set(), set()
    ambiguous = False

    def walk(item, reference=False):
        nonlocal ambiguous
        if type(item) is dict:
            for key, child in item.items():
                walk(child, key in _REFERENCE_FIELDS)
        elif type(item) in (list, tuple):
            for child in item:
                walk(child, reference)
        elif type(item) is str:
            if reference:
                # Preserve invalid references as incompleteness, never publish them.
                structured.add(item)
            else:
                # Match the public text normalization, but never salvage a
                # valid substring from a joined or malformed reference.
                for match in _TOKENS.finditer(unicodedata.normalize('NFKC', item)):
                    token = match[0].rstrip('.')
                    if id_ok(token, _KINDS):
                        prose.add(token)
                    elif _REFERENCE_LIKE.search(token):
                        ambiguous = True
    walk(value)
    valid = {ref for ref in structured if id_ok(ref, _KINDS)}
    return valid, prose, ambiguous or valid != structured


def timestamp(value):
    try:
        if type(value) is str:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if parsed.tzinfo is None:
                return None
            value = parsed.timestamp()
        return value if type(value) in (int, float) and math.isfinite(value) else None
    except (ValueError, OverflowError):
        return None


def freshness(observed, now, lifetime):
    observed = timestamp(observed)
    if observed is None or observed > now:
        return 'unknown'
    return 'current' if now - observed < lifetime else 'expired'


def source_manifest(frame, unknowns, broker_results=()):
    """Caller inputs only. A broker claim must come from its verified adapter.

    The current budget caller configures no broker. The optional seam accepts
    adapter-checked metadata, never model output or raw request trust claims.
    """
    from azazel_mio.id_grammar import id_ok
    result = {}
    for ident in (*frame.evidence_refs, *frame.knowledge_refs, *unknowns):
        if id_ok(ident, _KINDS) and (ident not in unknowns or re.fullmatch(r'u[1-9][0-9]{0,2}', ident)):
            result[ident] = dict(id=ident, source='frame', trust='verified', authority='runtime_caller_asserted',
                                 observed_at=timestamp(frame.created_at), revoked=False)
    for item in broker_results:
        for ident in item.get('evidence_refs', ()):
            if id_ok(ident, _KINDS):
                # Broker metadata takes precedence on collision; it cannot be
                # laundered into a verified frame ref by sharing an identifier.
                result[ident] = dict(id=ident, source='knowledge-broker', authority='runtime_caller_asserted',
                    trust='verified' if item.get('trust') == 'verified' else 'unverified',
                    observed_at=timestamp(item.get('observed_at')), revoked=item.get('revoked') is True)
    return list(result.values())


def project_sources(sources, now, lifetime):
    return [dict(id=item['id'], source=item['source'], trust=item['trust'],
                 observed_at=item['observed_at'],
                 valid_until=(item['observed_at'] + lifetime if item['observed_at'] is not None else None),
                 freshness='revoked' if item['revoked'] else freshness(item['observed_at'], now, lifetime))
            for item in sources]


def finish_manifest(public, unknowns, raw_structured, raw_prose, invalid=False):
    """Only called after receipt and assistance validation have succeeded."""
    from azazel_mio.id_grammar import id_ok
    structured, prose, bad = references(public)
    structured |= raw_structured
    prose |= raw_prose
    hypotheses = [h['hypothesis_id'] for h in public.get('advice_provenance', {}).get('hypotheses', ())]
    # The validated provenance is the receipt's structured hypothesis identity.
    # Older assistance without it cannot establish a complete manifest.
    unlisted = bool(prose - structured)
    missing_body = any(ref.startswith('um:') and not unknowns.get(ref) for ref in structured)
    complete = (not (invalid or bad or unlisted or missing_body) and bool(hypotheses)
                and len(structured) <= 128 and len(hypotheses) <= 4
                and all(id_ok(ref, ('hypothesis_id',)) for ref in hypotheses))
    return dict(hypothesis_ids=hypotheses, advisory_refs=sorted(structured)[:128],
                completeness='complete' if complete else 'partial', unlisted_prose_ids=unlisted)
