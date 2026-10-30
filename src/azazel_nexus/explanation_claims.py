"""The explanation ledger's claim words, shared by its reader and Fabric's writer.

`incident_explain` reads the explanation ledger; `fabric_boundary` projects it
onto Fabric. Both state these words. The Fabric boundary is reachable from the
content plane, which must not reach the explanation plane
(`test_broker_privilege_boundary`), so it cannot import `incident_explain`;
both import this module instead. Standard library only.
"""
from __future__ import annotations

#: The record key of the Edge evidence pointers (`incident_explain`).
EVIDENCE_FIELD = "evidence"
#: The record's `mio` key of a local answer's generation method and model.
PROVENANCE_FIELD = "provenance"
#: The claim ids of the M.I.O. answer, after the incident id (records with a
#: recorded generation method only): the candidate it ranked, and a model's
#: own explanation of it when a model wrote one.
MIO_CLAIM_SUFFIX = ":mio"
MIO_EXPLANATION_SUFFIX = ":mio:explanation"
#: A model's explanation fields, in the order the delivery states them.
EXPLANATION_KEYS = ("reason", "check_1", "check_2", "check_3", "missing")
#: The Edge claim's fixed first limitation, and the one said when no
#: evidence pointer was carried (a record from before them).
EDGE_CLAIM_LIMITATION = "reported_by_edge_core_not_executed_by_nexus"
EVIDENCE_NOT_CARRIED = "evidence_refs_not_carried"
#: Every Edge evidence pointer is projected as this Fabric `EvidenceRef.source`
#: (as `fabric_boundary.project_edge_evidence` does for a stored record).
EVIDENCE_SOURCE = "edge-core"


def evidence_observed_at(instant):
    """A pointer's receive instant as Fabric `EvidenceRef.observed_at` text."""
    from datetime import UTC, datetime

    try:
        return datetime.fromtimestamp(instant, UTC).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        raise ValueError("record_refused") from None


def edge_claim_limitations(record, merged):
    """The Edge claim's limitations, from the record alone (writer and reader)."""
    evidence = record.get(EVIDENCE_FIELD)
    return ([EDGE_CLAIM_LIMITATION]
            + (list(evidence["gaps"]) if evidence is not None else [EVIDENCE_NOT_CARRIED])
            + (["duplicate_knowledge_refs_merged"] if merged else []))


def mio_claims(incident_id, provenance, pointers):
    """The M.I.O. answer's claims, as `Claim` keyword arguments.

    Built from the recorded provenance alone, so the writer constructs Fabric
    `Claim`s from them and the reader compares a stored projection with them.
    The fixed delivery banner is not a claim: it is product text, not what
    the answer said.

    - The candidate: which class was ranked first, how clear the ranking was,
      and the alternatives in order. Embedding matching ranked it with the
      admitted model (`local_model`, `model_ref`); keyword matching is
      deterministic (`deterministic_core`, no model) -- also when a model
      then explained the keyword candidate.
    - A model's explanation, when one was delivered: its own validated text
      (`local_model`, `model_ref`), citing the candidate claim.

    The delivery names no model generation, so a claim with a model says
    `model_generation_not_delivered`.
    """
    p = provenance
    method, retrieval = p["method"], p["retrieval"]
    ranked_by_model = retrieval == "embedding"
    candidate = p["candidate"]
    alternatives = ", ".join(p["alternatives"]) or "none"
    claims = [{
        "claim_id": incident_id + MIO_CLAIM_SUFFIX,
        "statement": (f"candidate {candidate['kind']} {candidate['option_id']} "
                      f"(state={p['state']}); alternatives: {alternatives}"),
        "source": "local_model" if ranked_by_model else "deterministic_core",
        "model_ref": p["model_ref"] if ranked_by_model else None,
        "input_refs": list(pointers),
        "limitations": [f"generation_method={method}", f"retrieval={retrieval}"]
                       + (["model_generation_not_delivered"] if ranked_by_model else [])
                       + ["advisory_only_not_a_decision"],
    }]
    if p["explanation"] is not None:
        claims.append({
            "claim_id": incident_id + MIO_EXPLANATION_SUFFIX,
            "statement": "\n".join(p["explanation"][k] for k in EXPLANATION_KEYS),
            "source": "local_model",
            "model_ref": p["model_ref"],
            "input_refs": list(pointers) + [incident_id + MIO_CLAIM_SUFFIX],
            "limitations": [f"generation_method={method}", "model_generation_not_delivered",
                            "advisory_only_not_a_decision"],
        })
    return claims
