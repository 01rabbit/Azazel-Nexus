"""Which embedded features have a functional layer, and which do not (#53).

The control plane of Knowledge Lite, M.I.O. and Deception Lite is implemented:
trust, cache, generations, rollback, admission gates, the sanitizer, the decoy
lifecycle, and the degradation each of them produces.

**Knowledge Lite is functional** (Nexus#67): a correct bundle can be imported
offline and its real claims served read-only. Deception Lite has a functional
layer that reaches only this host. M.I.O. has none.

A feature declared `functional` must say what that means **and what it does
not**, because a capability word grows claims it was never given. Knowledge
Lite being functional says nothing about the cryptographic implementation
being supported, about a peer being connected, or about Edge authority.

That is a different fact from any the status vocabulary already had, and it
needs its own word. `unavailable` means "supply content and it works", and
saying that of a feature whose functional layer does not exist tells an
operator to go looking for content that nothing could accept.

| word | means |
| --- | --- |
| `available` / `stale` / `unavailable` / `quarantined` | the feature works; this is what it currently holds |
| `missing` | the feature's code is not on this node -- a defect |
| **`control-plane-only`** | the code is here, the control plane works, **and the functional layer does not exist yet** |
| **`loopback-only`** | the functional layer exists and reaches **only this host**; nothing outside can be affected by it |

`loopback-only` was added for Deception Lite
([#69](https://github.com/01rabbit/Azazel-Nexus/issues/69)). Decoys now
really start and really listen, so `control-plane-only` became false -- and
`available` would be worse than either, because a decoy nobody outside this
host can reach deceives nobody. A word that said the capability was being
supplied would be describing a deception with no one on the other end of it.

**An absent external peer is none of these.** A node with no AZ-04 or AZ-06
peer is the designed node. A node whose embedded feature cannot supply
anything is not, and the two must not share a word.

## The declarations below are tied to the code that makes them true

A hand-maintained "not done yet" list goes stale the day someone finishes the
work and forgets the list. Each entry here is paired with a test in
`tests/unit/test_functional_readiness.py` that asserts the *mechanical reason*
the feature is not functional -- the default claim reader that refuses, the
resource gate that always rejects, and, for the loopback decoy runtime, the
absence of any internet address family in the distribution that binds. When
one of those stops being true, its test fails, and whoever made it stop being
true has to come here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

__all__ = [
    "CONTROL_PLANE_ONLY",
    "LOOPBACK_ONLY",
    "READINESS",
    "Readiness",
    "readiness_for",
]

#: The value a not-yet-functional embedded feature reports.
CONTROL_PLANE_ONLY = "control-plane-only"

#: The value a feature reports when its functional layer exists and reaches
#: only this host. Distinct from both neighbours on purpose: it is not
#: `control-plane-only`, because something really runs; and it is not
#: `available`, because nothing outside this host can be affected by it.
LOOPBACK_ONLY = "loopback-only"


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
    #: What `functional` means for this feature, in one sentence. Required
    #: when functional: a bare "functional" is a word an operator fills in
    #: from hope.
    means: str = ""
    #: What it explicitly does **not** mean. Required when functional, and
    #: the more important half: a capability word tends to grow claims it was
    #: never given.
    does_not_mean: tuple[str, ...] = ()
    #: True when the functional layer exists and reaches only this host.
    #: Still not functional -- a capability nothing outside can be affected by
    #: is not a capability being supplied -- but it is a different fact from
    #: having no functional layer at all, and the operator's next action
    #: differs.
    loopback_only: bool = False

    def __post_init__(self) -> None:
        if self.functional and self.loopback_only:
            raise ValueError(
                f"{self.feature} is declared functional and loopback-only; if "
                "nothing outside this host can be affected by it, it is not "
                "supplying its capability"
            )
        if self.functional:
            if not self.means.strip():
                raise ValueError(
                    f"{self.feature} is declared functional and does not say "
                    "what that means; a bare capability word is one an "
                    "operator fills in from hope"
                )
            if not self.does_not_mean:
                raise ValueError(
                    f"{self.feature} is declared functional and says nothing "
                    "it does not mean; a capability word grows claims it was "
                    "never given unless the limits travel with it"
                )
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

    @property
    def value(self) -> str:
        """The word a display leads with for this feature."""

        return LOOPBACK_ONLY if self.loopback_only else CONTROL_PLANE_ONLY

    def reason(self) -> str:
        if self.functional:
            limits = "; ".join(self.does_not_mean)
            return f"{self.means}. It does not mean: {limits}"
        if self.loopback_only:
            return (
                "the functional layer exists and reaches only this host: "
                f"{self.missing} ({self.issue}). This is an embedded feature "
                "that really runs and that nothing outside this host can be "
                "affected by, which is not the capability being supplied, and "
                "is not the same fact as an external peer being absent"
            )
        return (
            f"the control plane is implemented and the functional layer is not: "
            f"{self.missing} ({self.issue}). This is an embedded feature that "
            "cannot supply its capability, which is not the same fact as an "
            "external peer being absent"
        )


READINESS: Mapping[str, Readiness] = {
    "knowledge_lite": Readiness(
        feature="knowledge_lite",
        functional=True,
        missing="",
        issue="Nexus#67",
        means=(
            "a correct Knowledge Lite bundle can be imported offline by an "
            "operator and its real claims served read-only"
        ),
        does_not_mean=(
            "that this node's cryptographic implementation is supported -- the "
            "hand-written Ed25519 verifier is under review (Nexus#70)",
            # Worded without the reassurance vocabulary on purpose. Saying
            # "no AZ-04 peer is connected" puts `connected` on a line naming
            # AZ-04, and the screen-wide guard in `test_wizard_and_cli.py`
            # cannot tell a denial from a claim -- nor should it have to. The
            # same precedent already keeps those words out of the Edge row's
            # name.
            "that this node has an AZ-04 Knowledge peer at all; there is no "
            "peer route and no download",
            "any share of Edge authority; Knowledge is advice, and the "
            "deterministic arbiter in Azazel-Edge decides",
        ),
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
        loopback_only=True,
        missing=(
            "decoys start and listen, and only on private Unix sockets in the "
            "runtime's own directory. Nothing outside this host can reach one, "
            "and no path here can bind an address or a port at all, so no "
            "hostile party can be observed by it yet"
        ),
        issue="Nexus#69",
    ),
}


def readiness_for(feature: str) -> Readiness:
    try:
        return READINESS[feature]
    except KeyError:  # pragma: no cover - a typo in a caller, not a node state
        raise KeyError(f"{feature!r} is not an embedded feature this module tracks")
