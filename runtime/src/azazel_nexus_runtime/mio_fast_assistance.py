"""Adapter from Nexus's validated local advice frame to shared MIO core."""
from __future__ import annotations

from datetime import datetime, timezone
import secrets

from azazel_mio import AssistantCore, MioSituationFrame
from azazel_mio.id_grammar import ID_KINDS
from azazel_nexus.incident_explain import FAST_TRANSITION_KIND, read_fast_transition


def _frame(source: dict) -> MioSituationFrame:
    """Project untrusted request prose and explainer-validated Edge data."""
    transition = read_fast_transition(source)
    token = secrets.token_hex(8)
    trace_id = (f"mio-{transition['incident_id'][4:]}-{transition['sequence']}"
                if transition is not None else f"mio-{token}-1")
    frame_id = f"{trace_id}:frame"
    if not ID_KINDS["trace_id"](trace_id) or not ID_KINDS["frame_id"](frame_id):
        raise ValueError("invalid_frame_correlation")
    context = tuple(item['text'] for item in source['context']
                    if item['kind'] != FAST_TRANSITION_KIND)
    evidence_refs = ()
    provenance = {"unknowns": ("caller",)}
    edge_summary = ""
    if transition is not None:
        edge_summary = "Validated Edge transition: " + "; ".join((
            f"event_type={transition['event_type']}",
            f"edge_would={transition['edge_would']}",
            f"policy_reason={transition['policy_reason']}",
            f"category={transition['category']}",
            f"protocol={transition['protocol']}",
            f"target_port={transition['target_port']}",
            f"severity={transition['most_severe']}",
            f"count={transition['count']}",
            "technique_ids=" + ",".join(transition['technique_ids']),
        ))
        evidence_refs = tuple(transition["evidence_refs"])
        provenance = {
            "evidence_refs": ("evidence_plane",),
            "unknowns": ("caller",),
        }
    return MioSituationFrame.build(
        frame_id=frame_id, trace_id=trace_id,
        created_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
        mission="Assess the supplied security situation; no operational authority",
        current_defensive_state='OBSERVE', threat_level='UNKNOWN',
        # Caller question/context remain reports, never known facts.
        known_facts=(),
        unknowns=("Situation question and context are untrusted reports",),
        evidence_refs=evidence_refs, provenance=provenance,
        noc_summary=source['question'][:480],
        soc_summary=' | '.join(([edge_summary] if edge_summary else []) + list(context))[:480],
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
