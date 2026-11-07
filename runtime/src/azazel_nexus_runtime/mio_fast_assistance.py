"""Adapter from Nexus's validated local advice frame to shared MIO core."""
from __future__ import annotations

from datetime import datetime, timezone
import secrets
import time
from dataclasses import asdict

from azazel_nexus.lite_import import KnowledgeRef, read_knowledge_refs
from azazel_nexus.reasoning_playbook import technique_ids
from azazel_nexus.incident_explain import FAST_TRANSITION_KIND, read_fast_transition
from azazel_nexus.handoff import contains_network_address

from azazel_mio import (
    AssistantCore,
    FabricKnowledgeContextResponseAdvisory,
    KnowledgeLiteAdvisory,
    MioSituationFrame,
)
from azazel_mio.id_grammar import ID_KINDS
from .knowledge_context_socket import FullNodeContextStatus


def _frame(source: dict, *, with_selection=False):
    """Project untrusted request prose and explainer-validated Edge data."""
    transition = read_fast_transition(source)
    token = secrets.token_hex(8)
    trace_id = (f"mio-{transition['incident_id'][4:]}-{transition['sequence']}"
                if transition is not None else f"mio-{token}-1")
    frame_id = f"{trace_id}:frame"
    if not ID_KINDS["trace_id"](trace_id) or not ID_KINDS["frame_id"](frame_id):
        raise ValueError("invalid_frame_correlation")
    context = tuple(item for item in source['context'] if item['kind'] != FAST_TRANSITION_KIND)
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
    # Only omit the exact display projections generated from this transition;
    # other prose, including contradictory reports, remains mandatory.
    duplicates = set()
    if transition is not None:
        duplicates = {
            ('edge_alert', f"incident={transition['incident_id']}; signature={transition['attack_type']}; "
             f"category={transition['category']}; protocol={transition['protocol']}; "
             f"destination_port={transition['target_port']}; severity={transition['most_severe']}; count={transition['count']}"),
            ('edge_decision', f"Edge would {transition['edge_would']}; policy_reason={transition['policy_reason']}"),
        }
    duplicate_count = sum((item['kind'], item['text']) in duplicates for item in context)
    selected_context = [item['text'] for item in context if (item['kind'], item['text']) not in duplicates]
    noc = source['question']
    if transition is not None:
        noc += ' | Edge signature (unverified report): ' + transition['attack_type']
    soc = ' | '.join(([edge_summary] if edge_summary else []) + selected_context)
    # Refuse address-bearing prose as a whole for the model lane; the Edge
    # source is not an authorization to expose addresses in a prompt.
    raw_context = any(item['kind'] in {'event', 'raw_event', 'edge_event'}
                      or item['kind'].startswith('raw_') for item in context)
    excluded = [len(noc) > 480 or contains_network_address(noc),
                len(soc) > 480 or raw_context or contains_network_address(soc)]
    projected = sum(excluded)
    selection = {'policy_version':'nexus-frame-v2',
        'coverage':'unknown' if projected else 'selected' if duplicate_count else 'intact',
        'input_units':2+duplicate_count,'selected_units':2-projected,'omitted_units':projected+duplicate_count,
        'omissions':[{'kind':'projection','ordinal':i,'reason':'upstream_projection'}
                     for i,omit in enumerate(excluded) if omit]
                    + [{'kind':'projection','ordinal':2+i,'reason':'duplicate'}
                       for i in range(duplicate_count)]}
    frame = MioSituationFrame.build(
        frame_id=frame_id, trace_id=trace_id,
        created_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
        mission="Assess the supplied security situation; no operational authority",
        current_defensive_state='OBSERVE', threat_level='UNKNOWN',
        # Caller question/context remain reports, never known facts.
        known_facts=(),
        unknowns=("Situation question and context are untrusted reports",),
        evidence_refs=evidence_refs, provenance=provenance,
        # Preserve the fast model-free projection. The budgeted lane refuses
        # input_truncated frames before any provider dispatch.
        noc_summary=noc[:480],
        soc_summary=soc[:480],
        input_truncated=bool(projected),
    )
    if frame.to_dict().get('truncated') is True:
        selection['coverage'] = 'unknown'
    return (frame,selection) if with_selection else frame


def fast_assistance(source: dict, *, deadline_s: float, knowledge_lookup=None,
                    knowledge_max_s: float = 0.25, core_reserve_s: float = 0.025,
                    situation_frame=None,
                    fabric_knowledge_context_response: dict | None = None,
                    full_node_context_status: FullNodeContextStatus | None = None) -> dict:
    """Read optional authenticated local context, then run the model-free core.

    The caller already reserves socket delivery time. Keep the existing 25ms fast-core budget
    for core composition; a 500ms entry request cannot fund a lookup.
    This is a software budget, not a hardware latency guarantee.
    """
    from .mio_socket_client import fast_assessment_degraded
    if full_node_context_status is None:
        full_node_context_status = (FullNodeContextStatus.RECEIVED
                                    if fabric_knowledge_context_response is not None
                                    else FullNodeContextStatus.NOT_QUERIED)
    if not isinstance(full_node_context_status, FullNodeContextStatus):
        raise ValueError("invalid_full_node_context_status")
    if (full_node_context_status is FullNodeContextStatus.RECEIVED) != (
            fabric_knowledge_context_response is not None):
        raise ValueError("inconsistent_full_node_context_status")
    if deadline_s <= 0:
        return fast_assessment_degraded("timeout")
    end = time.monotonic() + deadline_s
    frame = situation_frame if situation_frame is not None else _frame(source)
    ids = technique_ids(source)
    attempted = False
    advisories = ()
    failure = None
    budget = min(knowledge_max_s, end - time.monotonic() - core_reserve_s)
    if knowledge_lookup is not None and ids:
        if budget < core_reserve_s:
            # Leave the remaining slack to the model-free core. No query was
            # attempted, so reserve `timeout` for an actual bounded read.
            pass
        else:
            attempted = True
            try:
                lookup_started = datetime.now(timezone.utc).replace(microsecond=0)
                raw = tuple(knowledge_lookup(ids, deadline_s=budget))
                # Revalidate injected/local replies before trust is projected.
                if any(type(ref) is not KnowledgeRef for ref in raw):
                    raise ValueError("invalid_knowledge_refs")
                refs = read_knowledge_refs([asdict(ref) for ref in raw])
                if any(ref.technique_id not in ids for ref in refs):
                    raise ValueError("invalid_knowledge_refs")
                now = datetime.now(timezone.utc)
                for ref in refs:
                    as_of = datetime.fromisoformat(ref.as_of.replace('Z', '+00:00'))
                    # The trusted service evaluated freshness at its live
                    # lookup instant, truncated to UTC seconds. Crossing a
                    # second boundary during bounded I/O does not expire it.
                    if as_of > now or (ref.freshness == 'current' and as_of < lookup_started):
                        raise ValueError("stale_knowledge_refs")
                if time.monotonic() > end - core_reserve_s:
                    raise TimeoutError
                # The authenticated reader verifies the commissioned signature,
                # revocations, anti-rollback watermark and unchanged trust on
                # every read; only those admitted rows can be 'verified'.
                advisories = tuple(KnowledgeLiteAdvisory(
                    technique_id=ref.technique_id, name=ref.name, summary=ref.summary,
                    claim_id=ref.claim_id, bundle_digest=ref.bundle_digest,
                    freshness=ref.freshness, generation=str(ref.generation),
                    as_of=ref.as_of, citation=ref.claim_id,
                    source_citation=ref.citation, trust_check=ref.trust_check,
                    revocation_status='clear',
                ) for ref in refs[:8])
            except TimeoutError:
                failure = "timeout"
            except ValueError:
                failure = "unavailable"
            except Exception:
                failure = "unavailable"
    if (full_node_context_status is FullNodeContextStatus.UNAVAILABLE
            and not advisories and not frame.knowledge_refs and failure is None):
        failure = "unavailable"
    if failure:
        payload = frame.to_dict()
        payload['knowledge_status'] = failure
        frame = MioSituationFrame.from_dict(payload)
    if time.monotonic() >= end:
        return fast_assessment_degraded("timeout")
    # Preserve the consumer clock's sub-second precision. Knowledge Context
    # producers may legitimately sign a response generated later in this same
    # second; truncating `now` would falsely classify it as future-dated.
    now = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    fabric_response = None
    if fabric_knowledge_context_response is not None:
        if type(fabric_knowledge_context_response) is not dict:
            return fast_assessment_degraded("rejected")
        fabric_response = FabricKnowledgeContextResponseAdvisory(
            response=fabric_knowledge_context_response
        )
    result = AssistantCore(model=None).explain(
        frame, now=now, knowledge_attempted=attempted,
        knowledge_lite_advisories=advisories,
        fabric_knowledge_context_response=fabric_response).to_dict()
    # Nexus transport metadata is separate from the shared MIO output contract.
    result["full_node_context_status"] = full_node_context_status.value
    return result
