"""Adapter from Nexus's validated local advice frame to shared MIO core."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import re
import secrets
import time

from azazel_mio import AssistantCore, KnowledgeLiteAdvisory, MioSituationFrame

from azazel_nexus.reasoning_playbook import technique_ids

from .knowledge_client import KnowledgeUnavailable, lookup_context


def _frame(source: dict) -> MioSituationFrame:
    """Project request prose only into explicitly untrusted summary fields."""
    token = secrets.token_hex(8)
    context = tuple(item['text'] for item in source['context'])
    return MioSituationFrame.build(
        frame_id=f"mio-{token}-1:frame", trace_id=f"mio-{token}-1",
        created_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
        mission="Assess the supplied security situation; no operational authority",
        current_defensive_state='OBSERVE', threat_level='UNKNOWN',
        # These are bounded reports, never promoted into known_facts.
        known_facts=(), unknowns=("Situation question and context are untrusted reports",),
        provenance={"unknowns": ("caller",)},
        noc_summary=source['question'][:480], soc_summary=' | '.join(context)[:480],
    )


def fast_assistance(source: dict, *, deadline_s: float) -> dict:
    """Run the static shared assessment and optional authorized Knowledge read."""
    end = time.monotonic() + max(0.0, deadline_s)
    status = 'absent'
    advisories = ()
    source_citations = {}
    ids = technique_ids(source)
    if ids:
        budget = min(0.25, end - time.monotonic())
        if budget <= 0:
            status = 'timeout'
        else:
            try:
                refs = lookup_context(ids, deadline_s=budget)
                # Nexus accepts an empty source summary, while MIO's public
                # advisory type requires useful bounded content. Never invent
                # a summary: omit malformed rows and report the projection as
                # rejected (retaining any valid rows in the same reply).
                valid_refs = tuple(ref for ref in refs
                                   if isinstance(ref.summary, str)
                                   and 0 < len(ref.summary) <= 1200)
                status = ('partial' if valid_refs and len(valid_refs) != len(refs) else
                          'rejected' if not valid_refs and refs else
                          'available' if valid_refs else 'absent')
                source_citations = {ref.technique_id: ref.citation for ref in valid_refs}
                # lookup_context returns only read_knowledge_refs-validated rows
                # from the authorized azknowledge peer. A successful lookup
                # establishes clear revocation at lookup time, not future trust.
                advisories = tuple(KnowledgeLiteAdvisory(
                    technique_id=ref.technique_id, name=ref.name, summary=ref.summary,
                    claim_id=ref.claim_id, bundle_digest=ref.bundle_digest,
                    freshness=ref.freshness, generation=str(ref.generation),
                    as_of=ref.as_of,
                    citation=(ref.citation if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}", ref.citation)
                              else "kn:lite:" + ref.technique_id),
                    revocation_status='clear',
                    trust_check=ref.trust_check, expires_at=None,
                ) for ref in valid_refs)
            except KnowledgeUnavailable as error:
                status = ('timeout' if error.code == 'knowledge_timeout' else
                          'rejected' if error.code in {'knowledge_reply_refused', 'knowledge_peer_refused'}
                          else 'unavailable')
            except TimeoutError:
                status = 'timeout'
            except Exception:
                status = 'unavailable'
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    result = AssistantCore(model=None).explain(
        _frame(source), now=now, knowledge_lite_advisories=advisories).to_dict()
    # The shared core's citation token is intentionally identifier-shaped;
    # retain Nexus's validated source citation verbatim beside that token.
    for item in result.get('knowledge', ()):
        if item.get('kind') == 'knowledge_lite_advisory':
            item['source_citation'] = source_citations.get(item.get('technique_id'), '')
    # The core reports absence when no refs were supplied. Preserve typed local
    # lookup degradation even when the deterministic reasoning itself succeeds.
    outcome = result.get('dependency_outcome')
    if isinstance(outcome, dict):
        outcome['knowledge'] = status
    return result
