"""What must be established before a remote cognition route is even a candidate (#84).

`docs/mio-route-policy.md` §3. This module answers one question — **may a
remote route carry this request at all?** — and it answers it on a node that
has no remote route, no client, and no way to reach one.

## It establishes nothing by talking to anything

There is **no client here**. No socket, no `ssl`, no handshake, no request.
`tests/unit/test_cognition.py::test_the_module_contains_no_egress_path` scans
the cognition plane for exactly those imports and stays green;
`tests/unit/test_remote_trust.py` scans this module the same way.

Separating the judgement from the communication is not tidiness. The judgement
has to run on a node that cannot communicate, and answer *"no, and here is
which condition is missing"*. A judgement that needed a handshake to reach
that answer would be unable to give it on the node that most needs it.

Evidence is therefore **supplied by the caller**, never gathered here. What
gathers it — if anything ever does — is outside the library, the way
`az-edge-probed` is.

## Three values, and `not-checked` is neither of the others

`edge_package.Evidence` already carries this vocabulary and is reused rather
than re-declared. Two copies of a three-valued word drift into two meanings.

- `PASSED` — checked, and it held
- `FAILED` — checked, and it did not
- `NOT_CHECKED` — **nobody looked**

Reporting an unchecked mTLS as `FAILED` sends an operator to fix a provider
that is fine. Reporting it as `PASSED` says a thing nobody established. On
every node in this build all four signals are `NOT_CHECKED`, so remote is not
permitted — **and that is the correct state, not a defect.**

## The privacy class is a separate refusal, and stays separate

`P2-mission` and `P3-restricted` are never remote. That is refused in
`routing` (route eligibility) and again in `sanitizer` (the egress boundary).
This module is a **third independent refusal**, not a replacement for either.
Three exist so that editing one does not silently open the others, and
`test_remote_trust.py` checks that a class refusal survives every trust signal
passing.

## Speed cannot reach this module

Nothing here takes a latency, a prediction or a deadline. A remote route that
is reachable, healthy and fastest is still excluded when a condition is
missing, because the condition is all this module looks at. That is the whole
content of "policy-first": the permit stage cannot be argued with by the
predict stage.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional

from .edge_package import Evidence
from .mio_profile import MioProfile, RemoteOptIn, remote_reachable
from .sanitizer import NEVER_REMOTE, PrivacyClass

__all__ = [
    "ENDPOINT_ALLOWLIST",
    "Exclusion",
    "RemoteAdmission",
    "RemoteTrustReading",
    "TrustSignal",
    "remote_admission",
    "unchecked_reading",
]


class TrustSignal(str, Enum):
    """What must hold before a remote provider may be considered.

    Four, evaluated independently. A single `trusted` flag would let one
    established condition stand in for three that were not.
    """

    MUTUAL_TLS = "mutual TLS"
    PROVIDER_IDENTITY = "provider identity"
    ENDPOINT_ALLOWLIST = "endpoint allowlist"
    PROVIDER_HEALTH = "provider health"


#: The endpoints a remote route could ever name. Fixed in code, and empty in
#: this build because no provider has been admitted to name one.
#:
#: It is a **constant, not a parameter**. An allowlist taken from runtime
#: input is an allowlist the input can widen, which is the same discipline
#: the decoy runtime holds to for its bind addresses.
ENDPOINT_ALLOWLIST: tuple[str, ...] = ()


class Exclusion(str, Enum):
    """Why a remote route is not a candidate. One named cause, never a flag."""

    PROFILE = "the profile does not permit a remote route"
    CONSENT = "the operator has not opted in, or has withdrawn"
    TRUST = "a trust signal is not established"
    PRIVACY_CLASS = "this privacy class is never remote"
    UNSANITISED = "the frame has not been sanitised"
    NO_ENDPOINT = "no endpoint is on the allowlist"


@dataclass(frozen=True)
class RemoteTrustReading:
    """What was established about a remote provider, and what was not."""

    signals: Mapping[TrustSignal, Evidence]
    reasons: Mapping[TrustSignal, str]

    def __post_init__(self) -> None:
        missing = [s for s in TrustSignal if s not in self.signals]
        if missing:
            raise ValueError(
                f"a trust reading reports every signal; {[s.value for s in missing]} "
                "are absent, and an absent signal would read as neither passed "
                "nor failed nor unchecked"
            )
        for signal, evidence in self.signals.items():
            if not isinstance(evidence, Evidence):
                raise ValueError(f"{signal.value} carries {evidence!r}, not an Evidence")
            if not str(self.reasons.get(signal, "")).strip():
                raise ValueError(
                    f"{signal.value} is {evidence.value} with no reason; a signal "
                    "an operator cannot act on is one they will work around"
                )

    @property
    def established(self) -> bool:
        """Every signal `PASSED`. `NOT_CHECKED` is not established."""

        return all(e is Evidence.PASSED for e in self.signals.values())

    def withheld(self) -> tuple[tuple[TrustSignal, Evidence, str], ...]:
        """Every signal that is not `PASSED`, with its evidence and reason."""

        return tuple(
            (signal, self.signals[signal], self.reasons[signal])
            for signal in TrustSignal
            if self.signals[signal] is not Evidence.PASSED
        )


def unchecked_reading(reason: Optional[str] = None) -> RemoteTrustReading:
    """The reading every node in this build produces: nobody has looked.

    Not a placeholder. It is the honest answer on a node with no remote route
    and no way to reach one, and it is what keeps remote out of the candidate
    set without anything having to fail.
    """

    because = reason or (
        "no remote provider has been admitted on this node, so nothing has "
        "been checked about one. Nobody looked is not a failure"
    )
    return RemoteTrustReading(
        signals={signal: Evidence.NOT_CHECKED for signal in TrustSignal},
        reasons={signal: because for signal in TrustSignal},
    )


@dataclass(frozen=True)
class RemoteAdmission:
    """Whether a remote route is a candidate, and the one reason it is not."""

    permitted: bool
    #: The first condition that excluded it. One cause, so an operator has one
    #: thing to do rather than a list to work through in an unknown order.
    excluded_by: Optional[Exclusion]
    reason: str

    def __post_init__(self) -> None:
        if self.permitted and self.excluded_by is not None:
            raise ValueError("a permitted route names an exclusion")
        if not self.permitted and self.excluded_by is None:
            raise ValueError(
                "a route was excluded with no named cause; an exclusion an "
                "operator cannot act on is an exclusion they will route around"
            )

    def as_event(self) -> dict:
        return {
            "event_type": "mio.remote.admission",
            "permitted": self.permitted,
            "excluded_by": self.excluded_by.name.lower() if self.excluded_by else None,
            "reason": self.reason,
        }


def remote_admission(
    *,
    profile: MioProfile,
    opt_in: RemoteOptIn,
    trust: RemoteTrustReading,
    privacy_class: PrivacyClass,
    sanitised: bool,
) -> RemoteAdmission:
    """May a remote route carry this request?

    **The absolute refusal is reported first.** `P2` and `P3` can never go
    remote, so an exclusion that instead said "opt in" or "widen the profile"
    would invite an operator to grant a permission that would not help this
    request -- and a permission granted for no benefit is still granted.
    Everything after the class check is genuinely changeable, and those are
    reported in the order an operator can act in.

    An earlier draft ordered profile and consent first, on the reasoning that
    they are the operator's to change. A test showed what that costs: a
    restricted request on an uncommissioned node was told to finish
    commissioning, which would not have let it travel.
    """

    def refuse(cause: Exclusion, reason: str) -> RemoteAdmission:
        return RemoteAdmission(permitted=False, excluded_by=cause, reason=reason)

    # Never remote, whatever else holds, and reported before anything an
    # operator could be tempted to change on its account.
    if privacy_class in NEVER_REMOTE:
        return refuse(
            Exclusion.PRIVACY_CLASS,
            f"{privacy_class.value} is never remote in this build. No trust "
            "signal, profile or consent changes that, so there is nothing to "
            "grant here",
        )

    if not remote_reachable(profile):
        return refuse(
            Exclusion.PROFILE,
            f"the profile is {profile.value!r}; route selection may not consider "
            "a remote route under it",
        )
    if not opt_in.active():
        return refuse(Exclusion.CONSENT, opt_in.reason())

    if privacy_class is PrivacyClass.P1_SANITIZED and not sanitised:
        return refuse(
            Exclusion.UNSANITISED,
            f"{privacy_class.value} may travel only once the sanitizer has "
            "produced a frame; an unsanitised frame is not an eligible one",
        )

    if not trust.established:
        withheld = ", ".join(
            f"{signal.value} is {evidence.value}" for signal, evidence, _ in trust.withheld()
        )
        return refuse(
            Exclusion.TRUST,
            f"a remote route needs every trust signal established; {withheld}",
        )
    if not ENDPOINT_ALLOWLIST:
        return refuse(
            Exclusion.NO_ENDPOINT,
            "no endpoint is on the allowlist, so there is nowhere a remote "
            "route could go. The allowlist is fixed in code and is empty in "
            "this build",
        )
    return RemoteAdmission(
        permitted=True,
        excluded_by=None,
        reason=(
            f"the profile permits it, the operator opted in, {privacy_class.value} "
            "is eligible, and every trust signal is established"
        ),
    )
