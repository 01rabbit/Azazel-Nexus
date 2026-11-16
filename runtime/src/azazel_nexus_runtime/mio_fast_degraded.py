"""The fixed, model-free degraded fast-assistance payload.

Its own module so that a model-free process (`mio_contextobsd`) and the fast
core (`mio_fast_assistance`) can build it without importing the socket
client, which reads the model admission constant.
"""

from __future__ import annotations

import secrets

__all__ = ["fast_assessment_degraded"]


def fast_assessment_degraded(status: str) -> dict:
    """Fixed model-free degradation payload for an absent/late reply."""
    if status not in {"timeout", "unavailable", "rejected"}:
        status = "unavailable"
    trace_id = f"mio-{secrets.token_hex(8)}-1"
    return {"schema_version": "mio.assistance.v1", "trace_id": trace_id,
            "frame_id": trace_id + ":frame", "generation_method": "static_reference",
            "state": "dependency_unavailable",
            "observations": [], "hypotheses": [], "unknowns": ["Fast assessment unavailable"],
            "next_checks": [], "knowledge": [], "handoff": None, "reasoning_trace": [],
            "dependency_outcome": {"knowledge": status, "deception": "absent"},
            }
