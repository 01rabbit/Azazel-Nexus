"""Builders for technique-answer responses (the Fabric response in its JSON form)."""

from __future__ import annotations

import copy

from azazel_nexus import technique_knowledge as tk

GENERATED = "2026-11-13T00:00:10Z"
EXPIRES = "2026-11-13T00:01:10Z"
AS_OF = "2026-11-12T00:00:00Z"
CONTENT = {
    "T1110": ("Brute Force", "credential-access", "15.1"),
    "T1595.002": ("Active Scanning: Vulnerability Scanning", "reconnaissance", "15.1"),
    "T1059": ("Command and Scripting Interpreter", "execution", "15.1"),
    "T1059.001": ("PowerShell", "execution", "15.1"),
    "T1566": ("Phishing", "initial-access", "15.1"),
}


def fact(tid, i, n, value, *, predicate=None, provenance=None):
    return {"claim_class": "source_reported_fact", "fact_id": f"tq-{i}-{n}",
            "subject": {"entity_type": tk.ENTITY_TYPE, "value": tid},
            "predicate": predicate or tk._PREDICATES[n], "value": value,
            "provenance": list(provenance or (tk.COVERAGE_PROVENANCE if n == 0 else tk.CONTENT_PROVENANCE))}


def make_response(ids, coverage=None, *, content=None, version="15.1"):
    """A valid response; `coverage` maps id -> word (default found for known ids)."""
    content = {**CONTENT, **(content or {})}
    coverage = coverage or {t: "found" for t in ids}
    facts = []
    for i, tid in enumerate(ids):
        word = coverage[tid]
        facts.append(fact(tid, i, 0, word))
        if word == "found":
            name, tactics, _ = content[tid]
            facts += [fact(tid, i, 1, name), fact(tid, i, 2, tactics), fact(tid, i, 3, version)]
    words = set(coverage.values())
    if words == {"found"}:
        state = "complete"
    elif words & {"stale", "unavailable"}:
        state = "stale"
    else:
        state = "partial"
    as_of = GENERATED if "unavailable" in words else AS_OF
    ref = tk.SNAPSHOT_REF_PREFIX + (version if "found" in words else "none")
    return {
        "schema_version": "knowledge-context-response/v1", "request_id": "r" * 8,
        "correlation_id": "c" * 8, "source_product": "azazel_nexus",
        "source_ref": "nexus:full-node-context-query", "provider_id": "az04-test",
        "snapshot": {"ref": ref, "state": state, "as_of": as_of},
        "facts": facts, "inferences": [],
        "unknowns": [tk.NO_MATCH_UNKNOWN] if "no_match" in words else [],
        "limitations": list(tk.LIMITATIONS), "generated_at": GENERATED, "expires_at": EXPIRES,
        "authority": "advisory_only"}


def mutated(response, fn):
    value = copy.deepcopy(response)
    fn(value)
    return value
