"""The only place Azazel-Nexus imports `azazel_fabric` (ADR-0001).

Fabric is pinned to exactly one verified tag and consumed through this module
alone. Containing the import in one file is what makes its absence a bounded,
testable condition instead of an import error somewhere unpredictable;
`tests/unit/test_boundary_static.py` scans the package and fails if a second
import site appears.

Fabric is an **optional extra**, never a dependency. Nexus must be useful as
`CORE` with no external Knowledge, no Deception, no remote cognition and no
cloud connectivity, and a `CORE` path that fails when a contract library is
missing is not a `CORE` path. So every failure mode here returns a `Projection`
marked unavailable with a reason, and nothing propagates an exception to a
caller that only wanted to know what this node can currently do.

Three things this module structurally cannot do
-----------------------------------------------
*It cannot raise a capability.* A projection renders
`capability.CapabilityState` and the capability set it was handed. It adds no
capability, and it never writes back into what it was given. Whether Fabric is
present changes how the state can be *shown*, and nothing about what is true.

*It cannot issue an enforcement intent.* `StatusView.current_action` carries
`ActionIntent` — an enforcement intent issued by an arbiter. Nexus integrates
released components without creating another decision authority, so this module
leaves that field `None` in every case and a test pins that it does.

*It cannot report a capability state as an operating mode.* `ModeState.name`
is the series' operating-mode vocabulary (`portal`, `shield`, `scapegoat`,
`observe`, `lockdown`) and those are Azazel-Edge's modes. `CORE` / `LITE` /
`FULL` are capability states, which is a different question with a different
owner — publishing one as the other is the confusion Nexus#OF-04 already had to
correct once. The capability state travels in `product_view`, Nexus's own
namespace, and a test refuses it anywhere in `mode`.

What a present Fabric does and does not prove
---------------------------------------------
A successful projection attests **one** mapping in
`docs/contract-ownership.md` §3.1 — capability/mode publication through
`ModeState` / `StatusView`. It attests nothing about the other rows, and a
module existing in the pinned tag is not evidence that any mapping onto it
holds. `PLANNED_FABRIC_MODULES` below is a presence probe for the families §3
maps, reported and never assumed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from azazel_nexus.capability import CapabilityState

__all__ = [
    "FABRIC_PIN",
    "PLANNED_FABRIC_MODULES",
    "REQUIRED_FABRIC_MODULES",
    "Projection",
    "project_capability",
]

#: The exact tag this module is written against (ADR-0001). No branch pin, no
#: submodule, no copied source. `v0.9.0rc2` is the newest published candidate
#: and it is signed; Azazel-Edge, Azazel-Deception and Azazel-Knowledge are all
#: on it. A release candidate is still an exact tag — it promises no
#: stability, so this moves to `v0.9.0` when Fabric cuts it.
FABRIC_PIN = "v0.9.0rc2"

#: What this module needs to produce a projection at all.
REQUIRED_FABRIC_MODULES = ("azazel_fabric.view", "azazel_fabric.schema.mode")

#: Fabric families that `docs/contract-ownership.md` §3 maps Nexus records onto
#: and that no Nexus code consumes yet. Listed because an unmet requirement is
#: only trackable while something names it: §2 asserted for months that two of
#: these did not exist in Fabric, after they did.
PLANNED_FABRIC_MODULES = (
    "azazel_fabric.cti_contracts",
    "azazel_fabric.deception_contracts",
    "azazel_fabric.mio_contracts",
    "azazel_fabric.provisioning_contracts",
)

#: A constant, not a clock read. This module produces the same bytes for the
#: same input, so its output can be compared across runs and machines; a
#: timestamp would make every projection differ from every other for a reason
#: that has nothing to do with the node.
_FIXED_INSTANT = "1970-01-01T00:00:00Z"

#: Nexus holds no operating mode. `ModeState.name` is required, so the
#: projection names the absence rather than picking one of Edge's modes.
_MODE_NAME = "not_operational"
_MODE_REASON = (
    "Azazel-Nexus holds no operating mode; Azazel-Edge's deterministic arbiter "
    "does. This field names that absence rather than claiming one of Edge's modes."
)

#: Likewise for defensive posture, which is Edge's to report.
_POSTURE = "unknown"


@dataclass(frozen=True)
class Projection:
    """The outcome of rendering Nexus's capability state through Fabric."""

    available: bool
    #: Why a projection could not be produced. Empty exactly when available.
    reason: str
    #: Fabric's own version string when it could be read, else None.
    fabric_version: str | None = None
    #: The projected view, when one was produced. Deliberately typed `Any`:
    #: this module must import cleanly with Fabric absent, so it cannot name a
    #: Fabric type in an annotation evaluated at import time.
    view: Any = None
    #: Mapped-but-unconsumed families the pinned tag does not provide.
    #: Reported, never treated as an error: `CORE` does not need them.
    missing_planned: tuple[str, ...] = ()


def _import_fabric() -> tuple[Any | None, str]:
    try:
        import azazel_fabric  # noqa: PLC0415 -- deliberately deferred
    except ImportError as exc:
        return None, f"azazel_fabric is not installed ({exc})"
    return azazel_fabric, ""


def _missing_planned() -> tuple[str, ...]:
    import importlib.util  # noqa: PLC0415

    missing = []
    for name in PLANNED_FABRIC_MODULES:
        try:
            if importlib.util.find_spec(name) is None:
                missing.append(name)
        except (ImportError, ValueError):
            missing.append(name)
    return tuple(missing)


def project_capability(
    state: CapabilityState, available: frozenset[str] | set[str] | None = None
) -> Projection:
    """Render a capability state through Fabric's shared view model, if present.

    Returns a `Projection` in every case. A caller that needs the truth about
    this node reads `capability`; this is only how that truth can be shown
    alongside the other Azazel products.
    """

    capabilities = tuple(sorted(available or ()))

    fabric, failure = _import_fabric()
    if fabric is None:
        return Projection(available=False, reason=failure)

    version = getattr(fabric, "__version__", None)

    try:
        from azazel_fabric.schema.mode import ModeState  # noqa: PLC0415
        from azazel_fabric.view import StatusView  # noqa: PLC0415
    except ImportError as exc:
        return Projection(
            available=False,
            reason=f"a required Fabric module is unavailable at the pinned tag ({exc})",
            fabric_version=version,
            missing_planned=_missing_planned(),
        )

    try:
        view = StatusView(
            schema_version="1.0",
            product="Azazel-Nexus",
            generated_at=_FIXED_INSTANT,
            mode=ModeState(
                name=_MODE_NAME, since=_FIXED_INSTANT, reason=_MODE_REASON
            ),
            posture=_POSTURE,
            headline=f"Azazel-Nexus capability state: {state.value}",
            reasons=[f"capability: {name}" for name in capabilities],
            # Left empty on purpose. Nexus issues no enforcement intent.
            next_actions=[],
            health=[],
            evidence_ids=[],
            product_view={
                # Nexus's own namespace. The capability state lives here and
                # not in `mode`, because a capability state is not an
                # operating mode and must not be readable as one.
                "capability_state": state.value,
                "capabilities": list(capabilities),
                "authority": [],
                "authority_note": (
                    "Azazel-Nexus holds no decision or enforcement authority in "
                    "any capability state."
                ),
            },
        )
    except Exception as exc:  # noqa: BLE001 -- a projection must not crash a caller
        # Fabric's models may tighten between tags. A view Nexus cannot build
        # is a presentation problem, never a correctness one: the node's own
        # capability state is unchanged and is what a caller should read.
        return Projection(
            available=False,
            reason=f"projection failed against the pinned tag ({type(exc).__name__}: {exc})",
            fabric_version=version,
            missing_planned=_missing_planned(),
        )

    return Projection(
        available=True,
        reason="",
        fabric_version=version,
        view=view,
        missing_planned=_missing_planned(),
    )
