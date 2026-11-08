"""Model-free deterministic guidance for the incident explainer (no model, no socket).

Builds the MIO situation frame from the explainer's validated frame, hands the supplied report
text to `azazel_mio.guidance` and returns the guidance dict that the record stores. The module
returns None when MIO's guidance module is not installed; the explanation record is then written
without it and everything else is unchanged.
"""
from __future__ import annotations

from azazel_nexus.guidance_record import read_guidance
from azazel_nexus.handoff import contains_network_address

REPORT_KIND = "operator_report"


def _withheld_values(source: dict) -> list[str]:
    values = []
    for item in source.get("context", ()):
        if item.get("kind") in {"event", "raw_event", "edge_event"} or str(item.get("kind", "")).startswith("raw_"):
            values.append(item.get("text", ""))
    return [v for v in values if v]


def guidance_for_frame(source: dict, *, withheld_values=(), knowledge_facts=(), knowledge_unknowns=(),
                       effective_read_capabilities=()):
    try:
        from azazel_mio.guidance import build_guidance
    except ImportError:
        return None
    from .mio_fast_assistance import _frame
    frame = _frame(source)
    reports = [item["text"] for item in source["context"] if item["kind"] == REPORT_KIND]
    # Network addresses never enter guidance text; the report fragment carrying one is withheld whole.
    reports = ["[withheld]" if contains_network_address(t) else t for t in reports]
    decision = next((item["text"] for item in source["context"] if item["kind"] == "edge_decision"), None)
    edge = {"selected_action": "observe" if decision and "observe" in decision else None, "result": "not_executed",
            "executed_count": 0} if decision else None
    incident_id = source["request_id"].split(":")[0]
    guidance = build_guidance(
        frame, report_texts=reports, edge_decision=edge, knowledge_facts=knowledge_facts,
        knowledge_unknowns=knowledge_unknowns, withheld_values=list(withheld_values) or _withheld_values(source),
        effective_read_capabilities=effective_read_capabilities, request_id=source["request_id"],
        incident_id=incident_id, privacy_class=source.get("privacy_class")).to_dict()
    return read_guidance(guidance)
