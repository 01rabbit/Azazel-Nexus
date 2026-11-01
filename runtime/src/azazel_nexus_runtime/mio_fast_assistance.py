"""Adapter from Nexus's validated local advice frame to shared MIO core."""
from __future__ import annotations

from datetime import datetime, timezone
import secrets

from azazel_mio import AssistantCore, MioSituationFrame


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
    """Run the deterministic shared assessment without querying Knowledge."""
    if deadline_s <= 0:
        from .mio_socket_client import fast_assessment_degraded
        return fast_assessment_degraded("timeout")
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    result = AssistantCore(model=None).explain(
        _frame(source), now=now, knowledge_attempted=False).to_dict()
    return result
