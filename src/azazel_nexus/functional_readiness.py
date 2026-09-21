"""Which embedded features have a functional layer, and which do not (#53).

The control plane of Knowledge Lite, M.I.O. and Deception Lite is implemented:
trust, cache, generations, rollback, admission gates, the sanitizer, the decoy
lifecycle, and the degradation each of them produces. **None of the three can
currently provide the capability it exists for.**

That is a different fact from any the status vocabulary already had, and it
needs its own word. `unavailable` means "supply content and it works", and
saying that of a feature whose functional layer does not exist tells an
operator to go looking for content that nothing could accept.

| word | means |
| --- | --- |
| `available` / `stale` / `unavailable` / `quarantined` | the feature works; this is what it currently holds |
| `missing` | the feature's code is not on this node -- a defect |
| **`control-plane-only`** | the code is here, the control plane works, **and the functional layer does not exist yet** |

**An absent external peer is none of these.** A node with no AZ-04 or AZ-06
peer is the designed node. A node whose embedded feature cannot supply
anything is not, and the two must not share a word.

## The declarations below are tied to the code that makes them true

A hand-maintained "not done yet" list goes stale the day someone finishes the
work and forgets the list. Each entry here is paired with a test in
`tests/unit/test_functional_readiness.py` that asserts the *mechanical reason*
the feature is not functional -- the default claim reader that refuses, the
resource gate that always rejects, the decoy module that defines no verb able
to start anything. When one of those stops being true, its test fails, and
whoever made it stop being true has to come here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

__all__ = [
    "CONTROL_PLANE_ONLY",
    "READINESS",
    "Readiness",
    "readiness_for",
]

#: The value a not-yet-functional embedded feature reports.
CONTROL_PLANE_ONLY = "control-plane-only"


@dataclass(frozen=True)
class Readiness:
    """Whether one embedded feature can currently supply its capability."""

    feature: str
    functional: bool
    #: What the functional layer still needs. Required when not functional:
    #: "not done" without "what is missing" is a state nobody can act on.
    missing: str
    #: The issue that closes it.
    issue: str

    def __post_init__(self) -> None:
        if not self.functional:
            if not self.missing.strip():
                raise ValueError(
                    f"{self.feature} is declared not functional and does not say "
                    "what is missing; an operator cannot act on that"
                )
            if not self.issue.strip():
                raise ValueError(
                    f"{self.feature} is declared not functional and names no "
                    "issue; an untracked gap is a gap nobody closes"
                )

    def reason(self) -> str:
        return (
            f"the control plane is implemented and the functional layer is not: "
            f"{self.missing} ({self.issue}). This is an embedded feature that "
            "cannot supply its capability, which is not the same fact as an "
            "external peer being absent"
        )


READINESS: Mapping[str, Readiness] = {
    "knowledge_lite": Readiness(
        feature="knowledge_lite",
        functional=False,
        missing=(
            "no signed Knowledge bundle format is accepted and no supply route is "
            "connected, so nothing can be admitted"
        ),
        issue="Nexus#67",
    ),
    "mio": Readiness(
        feature="mio",
        functional=False,
        missing=(
            "the Core reserve is unmeasured (HG-05), so the resource gate refuses "
            "every local model provider and none is ever admitted"
        ),
        issue="Nexus#68",
    ),
    "deception_lite": Readiness(
        feature="deception_lite",
        functional=False,
        missing=(
            "no decoy process or container is started by anything; the runtime "
            "binds nothing, so no decoy can be reached even on loopback"
        ),
        issue="Nexus#69",
    ),
}


def readiness_for(feature: str) -> Readiness:
    try:
        return READINESS[feature]
    except KeyError:  # pragma: no cover - a typo in a caller, not a node state
        raise KeyError(f"{feature!r} is not an embedded feature this module tracks")
