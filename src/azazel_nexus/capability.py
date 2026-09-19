"""Capability state, and the one thing it is not (Nexus#15).

    `CORE`, `LITE`, and `FULL` are **capability states, not authority levels**.
    -- docs/capability-model.md §1

This module exists to make that sentence mechanical. Every function here can
remove a capability; none of them can return an authority, because there is no
authority in this module to return. Azazel-Edge's deterministic arbiter holds
it in every state.

Degradation is driven by the loss of an optional component, never by a change
in authority (`docs/capability-model.md` §7). So the only thing a lost
component does here is subtract.
"""

from __future__ import annotations

from enum import Enum

__all__ = [
    "CORE_CAPABILITIES",
    "CapabilityState",
    "OptionalComponent",
    "degrade",
    "state_for",
]


class CapabilityState(str, Enum):
    """What the node can currently do. Never what it is permitted to decide."""

    CORE = "CORE"
    LITE = "LITE"
    FULL = "FULL"


class OptionalComponent(str, Enum):
    """Components whose loss subtracts a capability and nothing else."""

    EXTERNAL_KNOWLEDGE_NODE = "external_knowledge_node"
    EXTERNAL_DECEPTION_NODE = "external_deception_node"
    KNOWLEDGE_LITE = "knowledge_lite"
    DECEPTION_LITE = "deception_lite"
    LOCAL_MODEL = "local_model"
    REMOTE_COGNITION = "remote_cognition"


#: What survives with every optional component gone.
#:
#: This is the list the doctrine is about: "Nexus and Boot must be useful as
#: CORE with no external Knowledge, no Deception, no remote cognition, and no
#: cloud connectivity." Nothing in this set depends on an optional component,
#: so nothing in it can be removed by losing one.
CORE_CAPABILITIES = frozenset(
    {
        "evidence",
        "evaluators",
        "arbiter_interface",
        "audit",
        "operator_plane",
        "deterministic_explanations",
    }
)

#: Which component each non-core capability depends on. A capability absent
#: from this map is a core capability and cannot be subtracted here.
_CAPABILITY_SOURCE = {
    "extended_knowledge": OptionalComponent.EXTERNAL_KNOWLEDGE_NODE,
    "knowledge_lite": OptionalComponent.KNOWLEDGE_LITE,
    "full_host_redirect": OptionalComponent.EXTERNAL_DECEPTION_NODE,
    "deception_lite": OptionalComponent.DECEPTION_LITE,
    "local_cognition": OptionalComponent.LOCAL_MODEL,
    "remote_cognition": OptionalComponent.REMOTE_COGNITION,
}


def degrade(
    available: frozenset[str], lost: OptionalComponent | frozenset[OptionalComponent]
) -> frozenset[str]:
    """Remove exactly the capabilities the lost component sourced.

    A core capability is never removed, whatever is lost. If this ever stops
    holding, an optional component has become load-bearing for the
    deterministic control path -- which is the failure this module exists to
    make impossible to ship quietly.
    """

    if isinstance(lost, OptionalComponent):
        lost = frozenset({lost})
    removed = {
        capability
        for capability, source in _CAPABILITY_SOURCE.items()
        if source in lost
    }
    return frozenset(available - removed) | (available & CORE_CAPABILITIES)


def state_for(available: frozenset[str]) -> CapabilityState:
    """Report the capability state the available set amounts to.

    `FULL` requires every sourced capability; `LITE` requires at least one Lite
    service; anything else is `CORE`. A node with no optional component at all
    is `CORE` and fully functional -- that is the expected state, not a fault.
    """

    if not CORE_CAPABILITIES <= available:
        missing = sorted(CORE_CAPABILITIES - available)
        raise ValueError(
            f"core capabilities are missing: {missing}. A core capability is "
            "never sourced from an optional component, so this is not a "
            "degradation -- it is a broken node."
        )
    if set(_CAPABILITY_SOURCE) <= available:
        return CapabilityState.FULL
    if available & {"knowledge_lite", "deception_lite"}:
        return CapabilityState.LITE
    return CapabilityState.CORE
