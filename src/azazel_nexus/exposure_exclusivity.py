"""The exposure tier and an enforcing Edge, not in one governed set (#196 G6 prep).

`docs/deception-exposure-grant.md` §6.2: until Edge declares that its
enforcement touches only its own table (Azazel-Edge#412), the Deception Lite
exposure tier and an enforce-posture Edge unit are mutually exclusive in one
generation, and the controller refuses a governed set holding both. An
enforcing Edge could flush or replace the ruleset that holds the decoy's
table, as `nftables.service` can (§6.2, "Not enabled together").

`exposure_enforcement_conflict` is that judgement over a governed set (the
`definitions` an `ActivationController` is built with), pure.

**What counts as enforcing.** A `UnitDefinition` carries no Edge posture;
the tier is what it says. Every `UnitTier.ENFORCEMENT` unit is counted, not
only Edge's: an enforcement unit is one that acts on the network, which is
what may flush the table, and narrowing the rule to Edge would rest on a
name. `azazel-edge-core.service` as this build declares it is
`EDGE_BASELINE` with a fixed observe-only posture (`edge_package` refuses a
manifest that declares enforcement) and does not conflict. No governed set
in this build holds an enforcement unit (`CORE_UNITS`).

**Implemented, not wired.** `ActivationController.__init__` does not call
it, the activation pass does not import this module, and
`_withholding_reason` still withholds the tier as `isolation_evidence_absent`
unconditionally (`tests/unit/test_exposure_g6_parts.py`). G6 makes the
controller refuse such a set. Nothing here grants, starts or changes a unit.
"""

from __future__ import annotations

from typing import Iterable

from .activation import DECEPTION_EXPOSURE_UNITS, UnitDefinition, UnitTier

__all__ = [
    "EXPOSURE_ENFORCEMENT_EXCLUSIVE",
    "exposure_enforcement_conflict",
]

EXPOSURE_ENFORCEMENT_EXCLUSIVE = "exposure_enforcement_exclusive"


def exposure_enforcement_conflict(definitions: Iterable[UnitDefinition]) -> str | None:
    """Why `definitions` may not hold the exposure tier, or None.

    A set holding any exposure unit (by tier or by name, as the controller's
    together-or-none rule counts them) together with any `ENFORCEMENT` unit
    is refused; so is anything that is not a sequence of `UnitDefinition`.
    """

    try:
        governed = tuple(definitions)
    except TypeError:
        governed = None
    if governed is None or any(type(d) is not UnitDefinition for d in governed):
        return (f"{EXPOSURE_ENFORCEMENT_EXCLUSIVE}: the governed set is not a "
                "sequence of unit definitions")
    exposure = any(d.tier is UnitTier.DECEPTION_EXPOSURE
                   or d.name in DECEPTION_EXPOSURE_UNITS for d in governed)
    enforcing = sorted(d.name for d in governed if d.tier is UnitTier.ENFORCEMENT)
    if exposure and enforcing:
        return (f"{EXPOSURE_ENFORCEMENT_EXCLUSIVE}: the governed set holds the "
                f"Deception Lite exposure tier and {len(enforcing)} enforcement "
                "unit(s); until Edge's enforcement is confined to its own table "
                "(Azazel-Edge#412) the two are not governed together")
    return None
