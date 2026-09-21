"""The six axes an operator reads, and the words that must stay apart (#55, E4).

`docs/capability-model.md` §7 and issue #55. This module renders nothing --
it produces the rows a renderer prints -- because the rule worth enforcing is
about *which distinctions survive*, and a distinction is lost in the data long
before it is lost on a screen.

## Six axes, reported independently

| axis | values |
| --- | --- |
| `capability` | `CORE` / `LITE` / `FULL` |
| `freshness` | `available` / `stale` / `unavailable` / `quarantined` / `missing` / `control-plane-only` |
| `cognition_route` | `CORE ONLY` / `LOCAL` / `HYBRID`, and remote `disabled` / `unavailable` |
| `knowledge_supplier` | `Knowledge Lite` / `AZ-04 peer` / `none` |
| `deception_supplier` | `Deception Lite` / `AZ-06 peer` / `none` |
| `edge` | `absent` / `corrupt` / `version-mismatch` / `digest-mismatch` / `unhealthy` / `not-running` / `unknown` / `verified-ready` |

Independent means an input that moves one axis moves **only** that one, and
`tests/unit/test_integration.py` varies each input and asserts the others do
not follow. A summary that collapses two axes hides which one failed, which is
the whole reason §8 of `docs/mio-runtime.md` demands per-dimension reasons.

## Six words that are not five

`disabled` is a decision -- somebody chose not to connect. `unavailable` is an
attempt that did not arrive. `stale` is having something too old to serve.
`quarantined` is having something that cannot be trusted. `missing` is an
**embedded** feature that is not there at all. **`control-plane-only`** is an
embedded feature whose code is here, whose control plane works, and whose
functional layer does not exist yet.

The last one exists because `unavailable` means *supply content and it works*,
and saying that of a feature nothing could accept content for sends an
operator looking for something no path can deliver. `functional_readiness.py`
holds which features are in that state and why.

The operator's next action differs for every one of them, so a renderer that
prints any two of them as one word has told its operator to do the wrong
thing. They are kept apart here, and a test asserts no two share a value.

## An absent peer and an absent embedded feature are not the same fact

An external AZ-04 or AZ-06 peer that is not connected is `unavailable`: a node
with no peers is the designed node, not a degraded one.

An embedded feature that is not there is `missing`, and the row is marked a
**defect**. Describing both with one word makes a required feature read like
an optional one -- and it is the required one whose absence somebody has to
act on.

## What continues is not optional

Every row carries what keeps working under that value, and no row may carry
an empty list. A node that lost its remote cognition path and renders a
screen of red is telling its operator it is broken while it is doing its job
(`operator.CapabilityReport.retained`, issue #29, restated per axis).

## Two things this view never claims

`enforcement_capable` and `baseline_ready` are derived, and both are `False`
unless Edge is `verified-ready`. `edge_package.py` is the **only** producer of
that state, it reaches it only when all five of its checks passed on a package
that is actually on disk, and a test asserts both claims stay `False` over
every combination of the other five axes -- because "we are ready" asserted
from a capability the node happens to have is exactly the claim that must be
impossible.

The seven words that are not `verified-ready` are not interchangeable. `#44`
requires the five checks to fail separately on the display, and the edge row
carries one word per distinct next action rather than one word for "not
ready".
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Sequence

from .capability import CapabilityState
from .cognition import CognitionReading, CognitionState, RemoteState
from .decoy import DecoyState, DecoyStatus
from .functional_readiness import CONTROL_PLANE_ONLY, readiness_for
from .lite_service import LiteReading, LiteState

__all__ = [
    "AXES",
    "Axis",
    "NEXUS_ALWAYS",
    "EdgePresence",
    "IntegrationRefused",
    "IntegrationView",
    "MISSING",
    "Supplier",
    "build_view",
]

#: The six axes, in the order an operator reads them.
AXES = (
    "capability",
    "freshness",
    "cognition_route",
    "knowledge_supplier",
    "deception_supplier",
    "edge",
)

#: An embedded feature that is not there. Distinct from `unavailable`, which
#: is a peer that did not answer, and from `stale`, which is having something.
MISSING = "missing"


class IntegrationRefused(Exception):
    """A view that would mislead is not built."""


class EdgePresence(str, Enum):
    """What is known about the local Edge Core. Only `verified-ready` grants.

    Eight words rather than three, because [#44](https://github.com/01rabbit/Azazel-Nexus/issues/44)
    requires the five checks to fail **separately** on the display as well as
    in the decision. "Edge is not installed" is a deployment step;
    "Edge is installed and its digest does not match what we pinned" is a
    security finding; "Edge is installed and nothing has run its health
    contract" is nobody having looked. An operator's next action differs for
    each, and a screen that printed one word for all of them would send
    somebody to do the wrong thing.

    `unknown` is what an unconfigured node and an unrun probe both produce:
    not configured and not checked are absences of evidence, and neither
    grants.
    """

    ABSENT = "absent"
    CORRUPT = "corrupt"
    VERSION_MISMATCH = "version-mismatch"
    DIGEST_MISMATCH = "digest-mismatch"
    UNHEALTHY = "unhealthy"
    NOT_RUNNING = "not-running"
    UNKNOWN = "unknown"
    VERIFIED_READY = "verified-ready"


class Supplier(str, Enum):
    """Where a capability's content comes from, when it comes from anywhere."""

    KNOWLEDGE_LITE = "Knowledge Lite"
    KNOWLEDGE_PEER = "AZ-04 peer"
    DECEPTION_LITE = "Deception Lite"
    DECEPTION_PEER = "AZ-06 peer"
    NONE = "none"


@dataclass(frozen=True)
class Axis:
    """One reading on one axis, with what continues under it."""

    axis: str
    subject: str
    value: str
    reason: str
    continues: tuple[str, ...]
    #: True only for an embedded feature that is absent. A peer's absence is
    #: never a defect, and the flag is what keeps the two from being read as
    #: one.
    defect: bool = False

    def __post_init__(self) -> None:
        if self.axis not in AXES:
            raise IntegrationRefused(f"{self.axis!r} is not one of the six axes")
        if not self.value.strip():
            raise IntegrationRefused(f"the {self.axis} row has no value")
        if not self.reason.strip():
            raise IntegrationRefused(
                f"the {self.axis} row has no reason; an unexplained state reads "
                "as agreement"
            )
        if not self.continues:
            raise IntegrationRefused(
                f"the {self.axis} row lists nothing that continues. A node that "
                "prints only what it lost tells its operator it is broken while "
                "it is doing its job"
            )

    def as_event(self) -> dict:
        return {
            "axis": self.axis,
            "subject": self.subject,
            "value": self.value,
            "reason": self.reason,
            "continues": list(self.continues),
            "defect": self.defect,
        }


#: What this node keeps whatever any axis says. Stated once so that every
#: row's `continues` starts from something true.
#:
#: **"Edge deterministic decisions" is deliberately absent.** It is the thing
#: an operator most wants to read, and on a node whose Edge is `absent` or
#: `unknown` it would be a claim about a component that is not there -- the
#: same false reassurance `edge-baseline-ready` exists to prevent. The edge
#: row adds it, and only when Edge is `verified-ready`.
NEXUS_ALWAYS = (
    "audit",
    "operator plane",
    "deterministic explanations",
    "inventory and commissioning",
)


@dataclass(frozen=True)
class IntegrationView:
    """The six axes together, and the two things they never claim."""

    rows: tuple[Axis, ...]
    edge: EdgePresence

    def __post_init__(self) -> None:
        seen = {row.axis for row in self.rows}
        missing = [axis for axis in AXES if axis not in seen]
        if missing:
            raise IntegrationRefused(
                f"the view is missing {missing}; an axis nobody reports is a "
                "dimension nobody can act on"
            )

    @property
    def enforcement_capable(self) -> bool:
        """Derived. `False` unless Edge is verified-ready, which it never is."""

        return self.edge is EdgePresence.VERIFIED_READY

    @property
    def baseline_ready(self) -> bool:
        """Derived, on the same evidence and for the same reason."""

        return self.edge is EdgePresence.VERIFIED_READY

    def row(self, axis: str, subject: str = "") -> Axis:
        for candidate in self.rows:
            if candidate.axis == axis and (not subject or candidate.subject == subject):
                return candidate
        raise IntegrationRefused(f"no {axis} row for {subject!r}")

    @property
    def defects(self) -> tuple[Axis, ...]:
        return tuple(row for row in self.rows if row.defect)

    @property
    def continues(self) -> tuple[str, ...]:
        kept: set[str] = set()
        for row in self.rows:
            kept.update(row.continues)
        return tuple(sorted(kept))

    def as_event(self) -> dict:
        return {
            "event_type": "nexus.integration.view",
            "edge": self.edge.value,
            "enforcement_capable": self.enforcement_capable,
            "baseline_ready": self.baseline_ready,
            "continues": list(self.continues),
            "rows": [row.as_event() for row in self.rows],
        }


def build_view(
    *,
    capability: CapabilityState,
    knowledge: Optional[LiteReading],
    cognition: CognitionReading,
    decoy: Optional[DecoyStatus],
    edge: EdgePresence,
    knowledge_peer: bool = False,
    deception_peer: bool = False,
) -> IntegrationView:
    """Assemble the six axes. `None` means the embedded feature is not there.

    `knowledge=None` and `decoy=None` are the **defect** case, not the
    routine one: a Knowledge Lite holding no artifact reports `unavailable`
    through its own reading, and only a feature that is absent altogether has
    no reading to report.
    """

    rows = (
        _capability_row(capability),
        _knowledge_freshness_row(knowledge),
        _deception_freshness_row(decoy),
        _cognition_row(cognition),
        _knowledge_supplier_row(knowledge, knowledge_peer),
        _deception_supplier_row(decoy, deception_peer),
        _edge_row(edge),
    )
    return IntegrationView(rows=rows, edge=edge)


def _capability_row(capability: CapabilityState) -> Axis:
    return Axis(
        axis="capability",
        subject="",
        value=capability.value,
        reason=(
            f"the node is {capability.value}; a capability state is what the node "
            "can do and never what it is permitted to decide"
        ),
        continues=NEXUS_ALWAYS,
    )


def _knowledge_freshness_row(knowledge: Optional[LiteReading]) -> Axis:
    if knowledge is None:
        return Axis(
            axis="freshness",
            subject="knowledge_lite",
            value=MISSING,
            reason=(
                "the embedded Knowledge Lite cache is not present on this node. "
                "This is a required internal feature, so its absence is a defect "
                "and not the routine state a disconnected peer produces"
            ),
            continues=NEXUS_ALWAYS,
            defect=True,
        )
    readiness = readiness_for("knowledge_lite")
    if not readiness.functional:
        # Reported over whatever the cache currently holds. A cache that
        # correctly reports `unavailable` while nothing could ever fill it is
        # telling an operator to go and find content, and there is no content
        # to find until Nexus#67 lands.
        return Axis(
            axis="freshness",
            subject="knowledge_lite",
            value=CONTROL_PLANE_ONLY,
            reason=f"{readiness.reason()}. The cache itself reports: {knowledge.reason}",
            continues=NEXUS_ALWAYS,
        )
    return Axis(
        axis="freshness",
        subject="knowledge_lite",
        value=knowledge.state.value,
        reason=knowledge.reason,
        continues=NEXUS_ALWAYS
        + (("Knowledge Lite advice",) if knowledge.state is LiteState.AVAILABLE else ()),
    )


def _deception_freshness_row(decoy: Optional[DecoyStatus]) -> Axis:
    if decoy is None:
        return Axis(
            axis="freshness",
            subject="deception_lite",
            value=MISSING,
            reason=(
                "the embedded Deception Lite runtime is not present on this node. "
                "This is a required internal feature, so its absence is a defect "
                "and not the routine state a disconnected peer produces"
            ),
            continues=NEXUS_ALWAYS,
            defect=True,
        )
    readiness = readiness_for("deception_lite")
    if not readiness.functional:
        return Axis(
            axis="freshness",
            subject="deception_lite",
            value=CONTROL_PLANE_ONLY,
            reason=f"{readiness.reason()}. The runtime itself reports: {decoy.reason}",
            continues=NEXUS_ALWAYS,
        )
    return Axis(
        axis="freshness",
        subject="deception_lite",
        value=_decoy_freshness(decoy.state),
        reason=decoy.reason,
        continues=NEXUS_ALWAYS
        + (("decoy observation",) if decoy.state is DecoyState.EXPOSED else ()),
    )


def _decoy_freshness(state: DecoyState) -> str:
    """Map a decoy's lifecycle onto the freshness vocabulary, keeping the words apart.

    `DISABLED` and `ELIGIBLE` both mean nothing is listening, and both report
    `unavailable` -- the decoy's own reason says which. `QUARANTINED` keeps
    its own word, because "we had it and it is not trustworthy" is the
    distinction the whole vocabulary exists for.
    """

    if state is DecoyState.QUARANTINED:
        return LiteState.QUARANTINED.value
    if state is DecoyState.EXPOSED:
        return LiteState.AVAILABLE.value
    return LiteState.UNAVAILABLE.value


def _cognition_row(cognition: CognitionReading) -> Axis:
    local = cognition.state is not CognitionState.CORE_ONLY
    readiness = readiness_for("mio")
    suffix = "" if readiness.functional else f"; local M.I.O. {CONTROL_PLANE_ONLY}"
    return Axis(
        axis="cognition_route",
        subject="mio",
        value=(
            f"{cognition.state.value}; remote M.I.O. {cognition.remote.value}{suffix}"
        ),
        reason=(
            ("" if readiness.functional else f"{readiness.reason()} | ")
            + f"{cognition.asset_reason} | resource: {cognition.resource_reason} | "
            f"topology: {cognition.topology_reason} | trust: "
            f"{cognition.trust_health_reason}"
        ),
        continues=NEXUS_ALWAYS + (("local M.I.O. explanations",) if local else ()),
    )


def _knowledge_supplier_row(knowledge: Optional[LiteReading], peer: bool) -> Axis:
    suppliers = _suppliers(
        embedded=(
            knowledge is not None
            and knowledge.sources_capability
            and readiness_for("knowledge_lite").functional
        ),
        embedded_name=Supplier.KNOWLEDGE_LITE,
        peer=peer,
        peer_name=Supplier.KNOWLEDGE_PEER,
    )
    return Axis(
        axis="knowledge_supplier",
        subject="knowledge",
        value=", ".join(supplier.value for supplier in suppliers),
        reason=_supplier_reason(suppliers, Supplier.KNOWLEDGE_PEER),
        continues=NEXUS_ALWAYS,
    )


def _deception_supplier_row(decoy: Optional[DecoyStatus], peer: bool) -> Axis:
    suppliers = _suppliers(
        embedded=(
            decoy is not None and decoy.exposed and readiness_for("deception_lite").functional
        ),
        embedded_name=Supplier.DECEPTION_LITE,
        peer=peer,
        peer_name=Supplier.DECEPTION_PEER,
    )
    return Axis(
        axis="deception_supplier",
        subject="deception",
        value=", ".join(supplier.value for supplier in suppliers),
        reason=_supplier_reason(suppliers, Supplier.DECEPTION_PEER),
        continues=NEXUS_ALWAYS,
    )


def _suppliers(
    *, embedded: bool, embedded_name: Supplier, peer: bool, peer_name: Supplier
) -> tuple[Supplier, ...]:
    supplying = tuple(
        name
        for name, present in ((embedded_name, embedded), (peer_name, peer))
        if present
    )
    return supplying or (Supplier.NONE,)


def _supplier_reason(suppliers: Sequence[Supplier], peer_name: Supplier) -> str:
    if suppliers == (Supplier.NONE,):
        return (
            f"nothing is supplying this capability; {peer_name.value} is a "
            "capability extension and its absence is unavailable, not a defect"
        )
    if peer_name not in suppliers:
        return (
            f"supplied by the embedded runtime alone; {peer_name.value} is "
            "unavailable, which is the designed state for a node with no peers"
        )
    return f"supplied by {', '.join(supplier.value for supplier in suppliers)}"


def _edge_row(edge: EdgePresence) -> Axis:
    reasons = {
        EdgePresence.ABSENT: (
            "no Edge package is installed on this node. This is a deployment "
            "step, not a security finding; enforcement-capable and "
            "baseline-ready are not claimed"
        ),
        EdgePresence.CORRUPT: (
            "an Edge package is on this node and cannot be read as the pinned "
            "one -- a missing or unreadable manifest, a contract this node "
            "does not verify, or a declared posture that is not observe-only. "
            "Nothing about it was verified, so nothing is claimed"
        ),
        EdgePresence.VERSION_MISMATCH: (
            "the installed Edge package is not the pinned version. It has not "
            "been evaluated by anything this node was commissioned against, "
            "so enforcement-capable and baseline-ready are not claimed"
        ),
        EdgePresence.DIGEST_MISMATCH: (
            "the installed Edge artifact does not match the digest its own "
            "manifest declares. **This is a security finding**: the artifact "
            "on disk is not the one described. It is reported and not repaired"
        ),
        EdgePresence.UNHEALTHY: (
            "the Edge health contract was run and did not answer healthy. The "
            "package is present and matches; the component says it is not in "
            "the posture it should be"
        ),
        EdgePresence.NOT_RUNNING: (
            "the Edge package is present, matched and healthy, and the payload "
            "is not running. A one-shot health answer says nothing about a "
            "daemon, so this is its own finding"
        ),
        EdgePresence.UNKNOWN: (
            "nothing has established what the local Edge Core is -- no package "
            "root is configured, or a check was not run. Unknown never grants, "
            "so enforcement-capable and baseline-ready are not claimed"
        ),
        EdgePresence.VERIFIED_READY: (
            "the Edge package is present, version- and digest-matched, healthy "
            "and running"
        ),
    }
    return Axis(
        axis="edge",
        subject="edge_core",
        value=edge.value,
        reason=reasons[edge],
        continues=NEXUS_ALWAYS
        + (
            ("Edge deterministic decisions",)
            if edge is EdgePresence.VERIFIED_READY
            else ()
        ),
    )
