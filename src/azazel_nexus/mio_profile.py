"""Which cognition routes an operator has allowed this node to consider (#82).

A **profile** is the ceiling on the candidate set that route selection may
later choose from. It is not a grant: selecting the widest profile admits no
provider, because every admission gate still runs afterwards
(`cognition.admit_local_model`, and the Core reserve that `HG-05` has not
measured).

`docs/mio-route-policy.md` §2 is the specification. This module is its
foundation: the profile, what the operator explicitly set, how a profile is
recommended at commissioning, and what withdrawing consent does.

## The path an operator actually takes

1. **Immediately after install, uncommissioned: `CORE`.** Remote is disabled
   and no provider is admitted. `profile_in_force` returns `CORE` for an
   uncommissioned node whatever is written in a file -- "it is in the config"
   is not a grant, the same rule the decoy runtime already holds to.
2. **At commissioning, with all four prerequisites explicitly set, the
   recommendation is `FASTEST_PERMITTED`.** That is the standard path for a
   normal deployment, not an advanced option behind a flag.
3. **Anything missing, or the Core reserve unmeasured, and remote leaves the
   candidate set** -- `LOCAL_ONLY`, or `CORE` when no provider could be
   admitted at all.

## `FASTEST_PERMITTED` does not mean "prefer remote"

It means: of the candidates that are *permitted*, take the one predicted to
answer soonest **within the deadline**. When local is sooner, local is chosen.
A profile that preferred remote would be a permanent setting, and a permanent
setting is exactly what a measured prediction exists to replace.

What it does deliver is the thing an operator reasonably expects: when a
permitted online provider really is faster, it is used, and the record says
why.

## Absence is never consent

`RemoteOptIn` records the prerequisites the operator **explicitly set**. A
prerequisite that was never answered is missing, not permissive. The four are
listed rather than counted, so a missing one can be named to the operator
instead of reported as "incomplete".

## Withdrawal is a permit change, not a failure

An operator may withdraw remote consent at any time. Withdrawal **removes**
the remote candidate rather than failing it -- immediately, not at the next
restart and not at the next commissioning. An in-flight request on that route
either falls back to local once or is refused. It is never completed by the
route the operator has just withdrawn; that is the one outcome withdrawal
exists to prevent.

## Nothing here grants authority

No profile, no opt-in and no withdrawal changes Edge readiness, action
authority, an activation lease, or enforcement. M.I.O. is an advisory plane
and the Azazel-Edge arbiter is the sole decider.
`tests/unit/test_mio_profile.py` drives every profile and both consent states
and asserts the Edge answer is identical throughout.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional

__all__ = [
    "InFlightDisposition",
    "NO_OPT_IN",
    "MioProfile",
    "PREREQUISITES",
    "profile_rows",
    "ProfileRefused",
    "Recommendation",
    "RemoteOptIn",
    "RemotePrerequisite",
    "Withdrawal",
    "admits_any_provider",
    "disposition_on_withdrawal",
    "profile_in_force",
    "recommend_profile",
    "remote_reachable",
]


class ProfileRefused(Exception):
    """A profile statement that cannot be believed. Refused, never repaired."""


class MioProfile(str, Enum):
    """The ceiling on what route selection may consider."""

    #: No M.I.O. provider is admitted. Explanation and status only.
    CORE = "core"
    #: Approved on-premises models only.
    LOCAL_ONLY = "local-only"
    #: The earliest-answering of the permitted candidates, local or remote.
    FASTEST_PERMITTED = "fastest-permitted"
    #: The remote route is disabled in configuration **and** at runtime.
    REMOTE_DISABLED = "remote-disabled"


class RemotePrerequisite(str, Enum):
    """What an operator must explicitly set before remote may be considered.

    Four separate facts, not one switch. An operator who set three of them has
    not "partially enabled remote" -- they have a node where remote is not
    permitted and one named thing left to do.
    """

    REMOTE_USE = "remote use"
    PRIVACY_POLICY = "privacy policy"
    PROVIDER = "provider"
    COMMS_PERMISSION = "comms permission"


#: All four, in the order an operator is asked. Listed rather than derived
#: from the enum so that adding a fifth is a deliberate edit here.
PREREQUISITES = (
    RemotePrerequisite.REMOTE_USE,
    RemotePrerequisite.PRIVACY_POLICY,
    RemotePrerequisite.PROVIDER,
    RemotePrerequisite.COMMS_PERMISSION,
)


@dataclass(frozen=True)
class Withdrawal:
    """An operator taking remote consent back. Who, when, and why."""

    operator: str
    at: str
    reason: str

    def __post_init__(self) -> None:
        for field in ("operator", "at", "reason"):
            if not str(getattr(self, field)).strip():
                raise ProfileRefused(
                    f"a withdrawal records {field}; an unexplained withdrawal is "
                    "indistinguishable from a fault, and the operator who has to "
                    "undo it cannot tell which it was"
                )

    def as_event(self) -> dict:
        return {
            "event_type": "mio.remote.opt_in.withdrawn",
            "operator": self.operator,
            "at": self.at,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class RemoteOptIn:
    """What the operator explicitly set, and whether it still stands."""

    #: Only the prerequisites explicitly set. Never inferred from a default.
    granted: frozenset[RemotePrerequisite]
    operator: str
    at: str
    withdrawn: Optional[Withdrawal] = None

    def __post_init__(self) -> None:
        for field in ("operator", "at"):
            if not str(getattr(self, field)).strip():
                raise ProfileRefused(f"a remote opt-in records {field}")
        unknown = set(self.granted) - set(PREREQUISITES)
        if unknown:
            raise ProfileRefused(f"unknown prerequisite(s): {sorted(unknown)}")

    @property
    def missing(self) -> tuple[RemotePrerequisite, ...]:
        """Which prerequisites were never set, in the order they are asked."""

        return tuple(p for p in PREREQUISITES if p not in self.granted)

    @property
    def complete(self) -> bool:
        return not self.missing

    def active(self) -> bool:
        """Whether remote may be considered at all.

        Complete **and** not withdrawn. A withdrawn opt-in keeps its record --
        the prerequisites were genuinely set once, and erasing that would lose
        the fact an audit reader needs -- but it stops permitting.
        """

        return self.complete and self.withdrawn is None

    def reason(self) -> str:
        if self.withdrawn is not None:
            return (
                f"remote consent was withdrawn by {self.withdrawn.operator} at "
                f"{self.withdrawn.at}: {self.withdrawn.reason}"
            )
        if self.complete:
            return f"all four remote prerequisites were set by {self.operator} at {self.at}"
        return (
            "remote is not permitted; "
            f"{[p.value for p in self.missing]} were never set. Absence of a "
            "setting is not consent to it"
        )

    def as_event(self) -> dict:
        return {
            "event_type": "mio.remote.opt_in",
            "operator": self.operator,
            "at": self.at,
            "granted": sorted(p.value for p in self.granted),
            "missing": [p.value for p in self.missing],
            "withdrawn": self.withdrawn.as_event() if self.withdrawn else None,
        }


#: An opt-in nobody has made. Distinct from a withdrawn one on purpose: the
#: operator's next action differs, and so does what the audit should say.
NO_OPT_IN = RemoteOptIn(granted=frozenset(), operator="(none)", at="(none)")


@dataclass(frozen=True)
class Recommendation:
    """The profile commissioning proposes, and why that one."""

    profile: MioProfile
    reason: str
    #: What would have to change for the recommendation to widen. Empty when
    #: it is already the widest. A recommendation with no path to a wider one
    #: is a dead end an operator cannot act on.
    blocked_by: tuple[str, ...] = ()

    def as_event(self) -> dict:
        return {
            "event_type": "mio.profile.recommended",
            "profile": self.profile.value,
            "reason": self.reason,
            "blocked_by": list(self.blocked_by),
        }


def recommend_profile(
    *, opt_in: RemoteOptIn, reserve_measured: bool
) -> Recommendation:
    """What commissioning should propose for this node.

    `reserve_measured` is the `HG-05` fact and is supplied, never read here:
    this module owns no measurement and must not appear to.

    The order matters. An unmeasured reserve means no provider of any kind can
    be admitted, so the honest proposal is `CORE` -- proposing `LOCAL_ONLY` to
    a node that can admit no local model sends an operator to configure a
    model nothing would accept.
    """

    if not reserve_measured:
        return Recommendation(
            profile=MioProfile.CORE,
            reason=(
                "the Core reserve is unmeasured (docs/hardware-gates.md HG-05), "
                "so no provider -- local or remote -- can be admitted. "
                "Deterministic explanations continue unchanged"
            ),
            blocked_by=("the Core reserve is unmeasured (HG-05)",),
        )
    if opt_in.active():
        return Recommendation(
            profile=MioProfile.FASTEST_PERMITTED,
            reason=(
                f"{opt_in.reason()}. Permitted local and remote candidates are "
                "compared on observed evidence and the one predicted to answer "
                "soonest within the deadline is chosen -- which is local "
                "whenever local is sooner"
            ),
        )
    return Recommendation(
        profile=MioProfile.LOCAL_ONLY,
        reason=f"{opt_in.reason()}; local providers may still be admitted",
        blocked_by=tuple(p.value for p in opt_in.missing)
        or ("remote consent was withdrawn",),
    )


def profile_in_force(
    *, commissioned: bool, selected: Optional[MioProfile]
) -> MioProfile:
    """The profile this node actually operates under.

    An uncommissioned node is `CORE` whatever is written down. A selection
    made in a file that no commissioning confirmed is a selection nobody
    approved, and the same rule already governs the decoy runtime: being
    written in the configuration is not a reason to start.
    """

    if not commissioned:
        return MioProfile.CORE
    if selected is None:
        return MioProfile.CORE
    if not isinstance(selected, MioProfile):  # pragma: no cover - caller error
        raise ProfileRefused(f"{selected!r} is not a profile this node knows")
    return selected


#: The profiles under which a remote candidate may be considered **at all**.
#: `REMOTE_DISABLED` is absent by not being in the table, which is the only
#: way in -- the same containment the decoy allowlist uses.
_REMOTE_REACHABLE = frozenset({MioProfile.FASTEST_PERMITTED})


def remote_reachable(profile: MioProfile) -> bool:
    """Whether this profile lets route selection even look at a remote route.

    `LOCAL_ONLY` and `REMOTE_DISABLED` both answer `False` and are still
    **different words**: the first prefers local and the second is the absence
    of a remote route. An operator's next action differs, so the status
    vocabulary keeps them apart even where this predicate does not.
    """

    return profile in _REMOTE_REACHABLE


def admits_any_provider(profile: MioProfile) -> bool:
    """Whether any provider may be admitted under this profile.

    False only for `CORE`. **This is a ceiling, not a grant**: `True` here
    means route selection may consider a candidate, never that one exists.
    Every admission gate still runs, and on every node in this build the
    resource gate refuses for want of a measured Core reserve.
    """

    return profile is not MioProfile.CORE


class InFlightDisposition(str, Enum):
    """What happens to a request already on the remote route when consent goes.

    There is deliberately no `COMPLETED` member. Completing a request by the
    route an operator has just withdrawn is the single outcome withdrawal
    exists to prevent, so it is absent from the vocabulary rather than
    forbidden by a check somewhere.
    """

    LOCAL_FALLBACK = "local fallback"
    REFUSED = "refused"


def disposition_on_withdrawal(*, local_available: bool) -> InFlightDisposition:
    """Fall back to local once if there is a local answer; otherwise refuse."""

    return (
        InFlightDisposition.LOCAL_FALLBACK
        if local_available
        else InFlightDisposition.REFUSED
    )


def profile_rows(
    *, profile: MioProfile, opt_in: RemoteOptIn, reserve_measured: bool
) -> tuple[Mapping[str, object], ...]:
    """What status shows about the cognition ceiling.

    Three separate facts. One word cannot carry them: a node may be on
    `FASTEST_PERMITTED`, have remote permitted, and still admit nothing
    because the reserve is unmeasured -- and an operator reading a single
    summary word would go looking for the wrong thing.
    """

    return (
        {
            "axis": "mio_profile",
            "value": profile.value,
            "reason": (
                "the ceiling on what route selection may consider; it admits "
                "nothing by itself"
            ),
        },
        {
            "axis": "mio_remote_consent",
            "value": (
                "permitted"
                if opt_in.active()
                else ("withdrawn" if opt_in.withdrawn else "not-given")
            ),
            "reason": opt_in.reason(),
        },
        {
            "axis": "mio_provider_admission",
            "value": "possible" if reserve_measured else "refused",
            "reason": (
                "providers may be admitted"
                if reserve_measured
                else "the Core reserve is unmeasured (HG-05), so every provider "
                "is refused at the resource gate whatever the profile permits"
            ),
        },
    )
