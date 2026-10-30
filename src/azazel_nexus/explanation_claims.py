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
#: The claim id of the M.I.O. answer, after the incident id (records with a
#: recorded generation method only), and the Fabric `ClaimSource` of each
#: method: a model's text and a model's ranking are `local_model`; keyword
#: matching is deterministic and names no model.
MIO_CLAIM_SUFFIX = ":mio"
METHOD_CLAIM_SOURCES = {"local_model_inference": "local_model", "embedding_matching": "local_model",
                        "deterministic_keyword_matching": "deterministic_core"}
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


def mio_claim_limitations(provenance):
    """The M.I.O. claim's limitations, from its recorded provenance."""
    return ([f"generation_method={provenance['method']}"]
            + (["model_generation_not_delivered"] if provenance["model_ref"] else [])
            + ["advisory_only_not_a_decision"])
