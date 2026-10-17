"""Which permitted candidate answers, and what happens when it does not (#81).

`docs/mio-route-policy.md` §3–§8. A **pure decision layer**: it takes readings
and returns a decision. There is no client here, no socket, no HTTP, no TLS
and no provider execution — `tests/unit/test_route_selection.py` scans for
them. Like `remote_trust`, it must be able to say *"here is why this candidate
cannot be chosen"* on a node that cannot talk to anything.

## The order is fixed

1. **Permit.** Privacy class, profile, opt-in, trust signals, allowlist,
   health, and provider admission (`HG-05`). A candidate that fails any of
   these is excluded **before speed is looked at**.
2. **Predict.** Only permitted candidates, and only from fresh observations
   meeting the sample floor, the success floor and the deadline.
3. **Degrade honestly.** With nothing predictable, no candidate is called
   fastest. The decision names what it fell back to and why.
4. **Choose.** Among permitted and predictable candidates, the one predicted
   to finish inside the deadline, with a stated tie-break.
5. **Fall back once.** At most one fallback per request, from the *original*
   permitted set, and never to the provider that just failed.
6. **Never say a withdrawn route completed.** Cancellation, failure, timeout,
   a withdrawn opt-in and a policy change each have their own terminal word.

## The tie-break is stated, not discovered

Equal predictions resolve to the **narrower** route, by
`routing.ROUTE_ORDER`. Local before remote, and the deterministic handoff
before either. Two candidates predicted to answer equally soon are not equal
in what they disclose, so the tie is broken by disclosure rather than by
whichever the iteration happened to reach first.

That also makes the choice replay: the same readings give the same route,
which §8 needs for a decision to be auditable at all.

## What the record carries, and what it must never

Every candidate appears in the decision with its disposition and reason —
excluded, unpredictable, missing its deadline, not soonest, or selected. An
operator who cannot see why a candidate was *not* used cannot act on it.

It carries **no request**: no prompt, no body, no evidence, no identifier and
no endpoint. Reasons are built from module constants and integers, and the
record is bounded by there being at most one entry per route.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional, Sequence

from .mio_profile import MioProfile
from .remote_trust import RemoteAdmission
from .route_evidence import Prediction
from .routing import ROUTE_ORDER, Route
from .sanitizer import PrivacyClass

__all__ = [
    "CandidateReading",
    "Disposition",
    "FallbackDecision",
    "MAX_FALLBACKS",
    "NEVER_ANSWERED",
    "RequestOutcome",
    "Selection",
    "SelectionRefused",
    "TerminalEvent",
    "fallback_once",
    "outcome_for",
    "select",
]

#: One. A second failure is not a third chance; it is evidence.
MAX_FALLBACKS = 1


class SelectionRefused(Exception):
    """A decision that cannot be made from what was supplied."""


class Disposition(str, Enum):
    """What became of one candidate. Five outcomes, none of them a flag.

    `EXCLUDED` and `UNPREDICTABLE` are **different words**: the first is a
    permission an operator can grant, the second is evidence nobody has
    gathered. Telling an operator to change a policy when what is missing is
    a measurement sends them to the wrong place.
    """

    SELECTED = "selected"
    #: Not permitted. Speed was never consulted.
    EXCLUDED = "excluded"
    #: Permitted, but there is not enough fresh evidence to predict it.
    UNPREDICTABLE = "unpredictable"
    #: Permitted and predictable, and predicted to miss the deadline.
    MISSES_DEADLINE = "misses deadline"
    #: Permitted, predictable, inside the deadline, and not the soonest.
    NOT_SOONEST = "not soonest"


@dataclass(frozen=True)
class CandidateReading:
    """One candidate's fate in one decision, with the reason for it."""

    candidate: Route
    disposition: Disposition
    reason: str
    predicted_ms: Optional[int] = None
    sample_count: int = 0

    def __post_init__(self) -> None:
        if not str(self.reason).strip():
            raise SelectionRefused(
                f"{self.candidate.value} has no reason; a candidate an operator "
                "cannot account for is one they will route around"
            )

    def as_event(self) -> dict:
        return {
            "candidate": self.candidate.value,
            "disposition": self.disposition.value,
            "reason": self.reason,
            "predicted_ms": self.predicted_ms,
            "sample_count": self.sample_count,
        }


@dataclass(frozen=True)
class Selection:
    """The route, every candidate's fate, and the basis for the comparison."""

    route: Route
    reason: str
    candidates: tuple[CandidateReading, ...]
    profile: MioProfile
    privacy_class: PrivacyClass
    #: The permitted set at the moment of the decision. A fallback may not
    #: leave it, so it is recorded rather than recomputed later.
    permitted: tuple[Route, ...]

    def __post_init__(self) -> None:
        seen = [reading.candidate for reading in self.candidates]
        if len(seen) != len(set(seen)):
            raise SelectionRefused("a candidate appears twice in one decision")
        if self.route not in seen:
            raise SelectionRefused(
                f"the chosen route {self.route.value!r} is not among the "
                "candidates considered"
            )

    def reading_for(self, candidate: Route) -> Optional[CandidateReading]:
        for reading in self.candidates:
            if reading.candidate is candidate:
                return reading
        return None

    def as_event(self) -> dict:
        """Bounded by construction: at most one entry per route, and no request."""

        return {
            "event_type": "mio.route.selected",
            "route": self.route.value,
            "reason": self.reason,
            "profile": self.profile.value,
            "privacy_class": self.privacy_class.value,
            "permitted": [route.value for route in self.permitted],
            "candidates": [reading.as_event() for reading in self.candidates],
        }


def select(
    *,
    profile: MioProfile,
    privacy_class: PrivacyClass,
    remote: RemoteAdmission,
    local_admitted: bool,
    local_refusal: str,
    predictions: Mapping[Route, Prediction],
    deadline_ms: int,
) -> Selection:
    """Pick a route, and account for every candidate that was not picked.

    `remote` is the whole of the remote permit decision (`remote_trust`), and
    `local_admitted` is whether the resource gate admitted a local provider —
    which is `False` on every node in this build, because the Core reserve is
    unmeasured. Both are **supplied**: this layer decides nothing about
    permission, it only orders what permission has already allowed.
    """

    if deadline_ms < 1:
        raise SelectionRefused("a deadline is a positive number of milliseconds")

    readings: list[CandidateReading] = []
    permitted: list[Route] = []

    # 1. Permit. The deterministic handoff is always permitted and is never
    #    removed; it is the floor the other two stand on.
    permitted.append(Route.DETERMINISTIC_HANDOFF)

    if not local_admitted:
        readings.append(
            CandidateReading(
                candidate=Route.LOCAL,
                disposition=Disposition.EXCLUDED,
                reason=local_refusal,
            )
        )
    else:
        permitted.append(Route.LOCAL)

    if not remote.permitted:
        readings.append(
            CandidateReading(
                candidate=Route.REMOTE,
                disposition=Disposition.EXCLUDED,
                reason=remote.reason,
            )
        )
    else:
        permitted.append(Route.REMOTE)

    # 2. Predict, over the permitted candidates only. Speed is never asked
    #    about a candidate that could not be used anyway.
    eligible: list[tuple[Route, int]] = []
    for candidate in (Route.LOCAL, Route.REMOTE):
        if candidate not in permitted:
            continue
        prediction = predictions.get(candidate)
        if prediction is None or not prediction.predictable:
            readings.append(
                CandidateReading(
                    candidate=candidate,
                    disposition=Disposition.UNPREDICTABLE,
                    reason=(
                        prediction.reason
                        if prediction is not None
                        else "no observations have been recorded for this candidate, "
                        "so it cannot be predicted. An unmeasured route is not a "
                        "slow one, and it is not offered as a fast one"
                    ),
                    sample_count=prediction.sample_count if prediction else 0,
                )
            )
            continue
        if not prediction.meets(deadline_ms=deadline_ms):
            readings.append(
                CandidateReading(
                    candidate=candidate,
                    disposition=Disposition.MISSES_DEADLINE,
                    reason=(
                        f"predicted {prediction.p95_ms} ms against a deadline of "
                        f"{deadline_ms} ms, at a success rate of "
                        f"{prediction.success_percent}%"
                    ),
                    predicted_ms=prediction.p95_ms,
                    sample_count=prediction.sample_count,
                )
            )
            continue
        eligible.append((candidate, prediction.p95_ms or 0))

    # 3. Nothing predictable: degrade, and say so rather than guess.
    if not eligible:
        readings.append(
            CandidateReading(
                candidate=Route.DETERMINISTIC_HANDOFF,
                disposition=Disposition.SELECTED,
                reason=(
                    "no permitted candidate could be predicted to answer inside "
                    "the deadline, so the deterministic handoff answers. Nothing "
                    "is claimed to be fastest on evidence that was not gathered"
                ),
            )
        )
        return Selection(
            route=Route.DETERMINISTIC_HANDOFF,
            reason=(
                "degraded to the deterministic handoff: "
                + (
                    "no candidate is permitted besides it"
                    if len(permitted) == 1
                    else "no permitted candidate is predictable inside the deadline"
                )
            ),
            candidates=tuple(readings),
            profile=profile,
            privacy_class=privacy_class,
            permitted=tuple(permitted),
        )

    # 4. Choose: soonest inside the deadline, ties to the narrower route.
    chosen, chosen_ms = min(eligible, key=lambda pair: (pair[1], ROUTE_ORDER.index(pair[0])))
    tied = [route for route, ms in eligible if ms == chosen_ms and route is not chosen]
    for candidate, predicted in eligible:
        if candidate is chosen:
            continue
        readings.append(
            CandidateReading(
                candidate=candidate,
                disposition=Disposition.NOT_SOONEST,
                reason=(
                    f"predicted {predicted} ms against {chosen_ms} ms for "
                    f"{chosen.value}"
                    + (
                        "; equal, and resolved to the narrower route because two "
                        "candidates that answer equally soon are not equal in "
                        "what they disclose"
                        if predicted == chosen_ms
                        else ""
                    )
                ),
                predicted_ms=predicted,
                sample_count=predictions[candidate].sample_count,
            )
        )
    readings.append(
        CandidateReading(
            candidate=chosen,
            disposition=Disposition.SELECTED,
            reason=(
                f"predicted {chosen_ms} ms, inside the {deadline_ms} ms deadline"
                + (
                    f"; tied with {[r.value for r in tied]} and chosen as the "
                    "narrower route"
                    if tied
                    else ""
                )
            ),
            predicted_ms=chosen_ms,
            sample_count=predictions[chosen].sample_count,
        )
    )
    return Selection(
        route=chosen,
        reason=(
            f"{chosen.value} is predicted to answer soonest inside the deadline, "
            f"at {chosen_ms} ms, from "
            f"{predictions[chosen].sample_count} fresh observation(s)"
        ),
        candidates=tuple(readings),
        profile=profile,
        privacy_class=privacy_class,
        permitted=tuple(permitted),
    )


@dataclass(frozen=True)
class FallbackDecision:
    """Where one request goes after its route failed, and whether that was the one."""

    failed: Route
    route: Route
    reason: str
    #: True once the single permitted fallback has been used.
    spent: bool

    def as_event(self) -> dict:
        return {
            "event_type": "mio.route.fallback",
            "failed_route": self.failed.value,
            "route": self.route.value,
            "reason": self.reason,
            "spent": self.spent,
        }


def fallback_once(
    *,
    selection: Selection,
    failed: Route,
    already_spent: bool,
    still_permitted: Sequence[Route] = (),
) -> FallbackDecision:
    """Fall back at most once, inside the original permitted set.

    Three rules, each of which is a refusal:

    **The target comes from the permitted set recorded in the decision.**
    Re-running the permit stage on a failure is how a failure becomes a reason
    to widen, and widening on failure is the direction that must be impossible.

    **Never the provider that just failed.** A retry to the same route is not
    a fallback; it is the same attempt again, and it is what a timeout is
    evidence against.

    **Once.** A second failure lands on the deterministic handoff, which is
    always available and is never removed.

    `still_permitted` narrows the set further — a remote opt-in withdrawn
    between the decision and the failure removes that route here, so a
    withdrawn route is never the thing a fallback lands on.
    """

    if already_spent:
        return FallbackDecision(
            failed=failed,
            route=Route.DETERMINISTIC_HANDOFF,
            reason=(
                f"the one permitted fallback was already spent; {failed.value} "
                "failing again is evidence rather than a third chance, so the "
                "deterministic handoff answers"
            ),
            spent=True,
        )

    narrowed = set(still_permitted) if still_permitted else set(selection.permitted)
    targets = [
        route
        for route in ROUTE_ORDER
        if route in selection.permitted
        and route in narrowed
        and route is not failed
        and route is not Route.DETERMINISTIC_HANDOFF
    ]
    if not targets:
        return FallbackDecision(
            failed=failed,
            route=Route.DETERMINISTIC_HANDOFF,
            reason=(
                f"{failed.value} failed and no other route was permitted for this "
                "request, so the deterministic handoff answers. The permitted set "
                "is the one recorded when the route was chosen; a failure does not "
                "widen it"
            ),
            spent=True,
        )
    target = targets[0]
    return FallbackDecision(
        failed=failed,
        route=target,
        reason=(
            f"{failed.value} failed; falling back once to {target.value}, which "
            "was permitted when the route was chosen. This is the only fallback "
            "this request gets"
        ),
        spent=True,
    )


class TerminalEvent(str, Enum):
    """What ended a request's use of a route."""

    ANSWERED = "answered"
    #: No advisory was produced, without a route failure or a fallback.
    NO_ANSWER = "no answer"
    FAILED = "failed"
    TIMED_OUT = "timed out"
    CANCELLED = "cancelled"
    OPT_IN_WITHDRAWN = "remote opt-in withdrawn"
    POLICY_CHANGED = "policy changed"
    #: The handshake, the chain, the name or the pin did not hold (#98).
    #:
    #: Not folded into `FAILED`. A provider that is up and answering with the
    #: wrong key is a different fact from one that is down, and an operator
    #: who sees "failed" for both will go and check whether the service is
    #: running -- which it is.
    TLS_FAILED = "mutual TLS did not hold"
    #: The sanitizer boundary produced nothing to send, or what it produced
    #: was not believed at the transport (#98).
    #:
    #: Also not `FAILED`. Nothing went wrong with the provider or the link;
    #: this node declined to send, and reporting that as a failure of the
    #: route is how a refusal comes to look like an outage somebody should
    #: fix by loosening something.
    SANITIZER_FAILED = "sanitisation did not hold"
    #: The response came back and was not advice (#98).
    #:
    #: A provider that answers with a command has answered. It has not
    #: advised, and `ANSWERED` is the word for having advised.
    NOT_ADVICE = "the response was not advice"


class RequestOutcome(str, Enum):
    """How a request ended on a route.

    There is deliberately **no `COMPLETED`**. "Completed" is the word that
    would let a cancelled, failed, timed-out, withdrawn or re-policied request
    be reported as though the route had done its job. Success has its own
    word, `ANSWERED`, and the five others have theirs — so the ambiguous one
    is absent from the vocabulary rather than forbidden by a check that could
    be edited.
    """

    ANSWERED = "answered"
    FELL_BACK = "fell back"
    REFUSED = "refused"
    ABANDONED = "abandoned"


#: Which terminal events may never be reported as the route having answered.
NEVER_ANSWERED = (
    TerminalEvent.NO_ANSWER,
    TerminalEvent.FAILED,
    TerminalEvent.TIMED_OUT,
    TerminalEvent.CANCELLED,
    TerminalEvent.OPT_IN_WITHDRAWN,
    TerminalEvent.POLICY_CHANGED,
    TerminalEvent.TLS_FAILED,
    TerminalEvent.SANITIZER_FAILED,
    TerminalEvent.NOT_ADVICE,
)


def outcome_for(
    event: TerminalEvent, *, fallback_available: bool
) -> RequestOutcome:
    """Map what happened to how the request ended. Never to `ANSWERED` but for one.

    Only `TerminalEvent.ANSWERED` produces `RequestOutcome.ANSWERED`.
    No advisory without a failure ends the attempt as `REFUSED`, even when
    a fallback is available. Other endings follow their refusal, cancellation
    or fallback rules — they never report the route as having delivered.
    """

    if event is TerminalEvent.ANSWERED:
        return RequestOutcome.ANSWERED
    if event is TerminalEvent.NO_ANSWER:
        return RequestOutcome.REFUSED
    if event is TerminalEvent.SANITIZER_FAILED:
        # This node declined to send. Falling back to a *different remote*
        # would be this node trying again elsewhere with something it just
        # decided must not leave -- so a sanitisation that did not hold ends
        # the remote attempt outright, whatever else is available.
        return RequestOutcome.REFUSED
    if event in (TerminalEvent.OPT_IN_WITHDRAWN, TerminalEvent.POLICY_CHANGED):
        # A permit change, not a failure. The route is removed rather than
        # retried, and the request is answered elsewhere or not at all.
        return RequestOutcome.FELL_BACK if fallback_available else RequestOutcome.REFUSED
    if event is TerminalEvent.CANCELLED:
        return RequestOutcome.ABANDONED
    return RequestOutcome.FELL_BACK if fallback_available else RequestOutcome.REFUSED
