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

**Wired by G6** as a withhold (`docs/deception-exposure-wiring.md` §4.2,
L2; owner decision Q-E): `ActivationController._withholding_reason` asks it
first among the exposure tier's own checks, so a governed set holding both
withholds the tier and the enforcement unit keeps its own verdict; the
controller's construction does not refuse. Nothing here grants, starts or
changes a unit.
"""

from __future__ import annotations

from typing import Iterable

from .activation import DECEPTION_EXPOSURE_UNITS, UnitDefinition, UnitTier

__all__ = [
    "EXPOSURE_ENFORCEMENT_CODES",
    "EXPOSURE_ENFORCEMENT_EXCLUSIVE",
    "EXPOSURE_ENFORCEMENT_PHRASES",
    "EXPOSURE_ENFORCEMENT_UNREADABLE",
    "exposure_enforcement_conflict",
]

EXPOSURE_ENFORCEMENT_UNREADABLE = "exposure_enforcement_unreadable"
EXPOSURE_ENFORCEMENT_EXCLUSIVE = "exposure_enforcement_exclusive"
#: In the order they are judged.
EXPOSURE_ENFORCEMENT_CODES: tuple[str, ...] = (
    EXPOSURE_ENFORCEMENT_UNREADABLE, EXPOSURE_ENFORCEMENT_EXCLUSIVE)

#: Each code's fixed phrase: no unit name and no count. The issue that lifts
#: the exclusion is Azazel-Edge#412.
EXPOSURE_ENFORCEMENT_PHRASES: dict[str, str] = {
    EXPOSURE_ENFORCEMENT_UNREADABLE: ("the governed set is not a sequence of unit "
                                      "definitions"),
    EXPOSURE_ENFORCEMENT_EXCLUSIVE: ("the governed set holds the Deception Lite "
                                     "exposure tier and an enforcement unit; until "
                                     "Edge's enforcement is confined to its own "
                                     "table the two are not governed together"),
}


def exposure_enforcement_conflict(definitions: Iterable[UnitDefinition]) -> str | None:
    """Why `definitions` may not hold the exposure tier, or None.

    `"<code>: <phrase>"` (`EXPOSURE_ENFORCEMENT_PHRASES`). Anything that is
    not a sequence of `UnitDefinition` is `exposure_enforcement_unreadable`;
    a set holding any exposure unit (by tier or by name, as the controller's
    together-or-none rule counts them) together with any `ENFORCEMENT` unit
    is `exposure_enforcement_exclusive`.
    """

    try:
        governed = tuple(definitions)
    except TypeError:
        governed = None
    if governed is None or any(type(d) is not UnitDefinition for d in governed):
        code = EXPOSURE_ENFORCEMENT_UNREADABLE
        return f"{code}: {EXPOSURE_ENFORCEMENT_PHRASES[code]}"
    exposure = any(d.tier is UnitTier.DECEPTION_EXPOSURE
                   or d.name in DECEPTION_EXPOSURE_UNITS for d in governed)
    enforcing = any(d.tier is UnitTier.ENFORCEMENT for d in governed)
    if exposure and enforcing:
        code = EXPOSURE_ENFORCEMENT_EXCLUSIVE
        return f"{code}: {EXPOSURE_ENFORCEMENT_PHRASES[code]}"
    return None
