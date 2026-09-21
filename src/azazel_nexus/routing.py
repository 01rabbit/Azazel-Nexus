"""Route selection and the fallback table (#5, E2).

`docs/mio-runtime.md` §5 and §7. Two rules hold over everything here, and both
are checked over *every* case rather than a representative one.

**A fallback never escalates.** `DETERMINISTIC_HANDOFF -> LOCAL -> REMOTE` is
ordered, and every fallback lands at or below the route it fell back from.
A fallback that widened the route would turn a failure into a reason to
disclose more, which is the direction that must be impossible.

**Nothing here blocks the deterministic path.** The no-model handoff is always
available and is never removed, in any trigger, under any pressure. It is the
floor of the ladder, so there is nowhere below it to fall.

## Declared, not discovered

    Budgets are declared, not discovered.

`Budgets` holds numbers a policy states. `Budgets.exceeded` takes the current
counters as an **argument**: this module keeps no counters, because a budget
check that read a counter it also owned could be satisfied by forgetting to
increment it. Whoever holds the request state passes it in.

## The clock is an argument

An expiry is compared against an instant the caller supplies. Nothing here
reads a clock, so a decision replays: `docs/mio-runtime.md` §9 requires the
route decision **and the inputs that produced it** to be audit-visible, and an
input that was the wall clock is not an input anyone can check later.

## What is not here

No provider is ever selected, because no provider can be admitted while the
Core reserve is unmeasured (`docs/hardware-gates.md` HG-05). `select_route`
therefore answers `DETERMINISTIC_HANDOFF` on the product path today, with a
reason naming why — and the `LOCAL` and `REMOTE` branches exist, are reached
by the tests, and are what HG-05 closing turns on. No egress function exists
in this module or anywhere else in the package.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional, Sequence

from .cognition import ProviderAdmission
from .lite_cache import classify_freshness
from .sanitizer import PrivacyClass

__all__ = [
    "Budgets",
    "FallbackTrigger",
    "PROTECTED_FROM_SHEDDING",
    "RequestEnvelope",
    "Route",
    "RouteDecision",
    "SHEDDING_ORDER",
    "fallback_for",
    "select_route",
]


class Route(str, Enum):
    """Local-first, in order. The first is never removed."""

    DETERMINISTIC_HANDOFF = "deterministic handoff"
    LOCAL = "local"
    REMOTE = "remote"


#: Narrowest to widest. `ROUTE_ORDER.index` is how "never escalates" is
#: expressed as a comparison rather than as a set of special cases.
ROUTE_ORDER = (Route.DETERMINISTIC_HANDOFF, Route.LOCAL, Route.REMOTE)


def _narrower_or_equal(result: Route, origin: Route) -> bool:
    return ROUTE_ORDER.index(result) <= ROUTE_ORDER.index(origin)


@dataclass(frozen=True)
class RequestEnvelope:
    """`docs/mio-runtime.md` §5: a correlation ID, class, deadline and expiry.

    The correlation ID is supplied, never generated. A generated one would
    make two runs of the same request differ, and §9 requires the decision and
    its inputs to be replayable.
    """

    correlation_id: str
    privacy_class: PrivacyClass
    deadline: str
    expiry: str

    def __post_init__(self) -> None:
        for name in ("correlation_id", "deadline", "expiry"):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"a request envelope carries a {name}")

    def expired_at(self, now: str) -> bool:
        """Whether this request's expiry has passed at `now`.

        An expiry that cannot be read counts as passed. A response arriving
        against an envelope nobody can date is one nobody can date, and §7
        discards rather than merges in that case.
        """

        return classify_freshness(self.expiry, as_of=now).value != "current"


@dataclass(frozen=True)
class Budgets:
    """What a policy declares. This module counts nothing."""

    max_request_bytes: int
    max_response_bytes: int
    requests_per_hour: int
    deadline_seconds: int
    max_concurrency: int

    def __post_init__(self) -> None:
        for name in (
            "max_request_bytes",
            "max_response_bytes",
            "requests_per_hour",
            "deadline_seconds",
            "max_concurrency",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} is declared as a positive whole number")

    def exceeded(self, counters: Mapping[str, int]) -> Optional[str]:
        """Which budget the supplied counters exceed, or `None`.

        Counters are an argument. A check that read a counter it also owned
        could be satisfied by forgetting to increment it, and nobody would
        find out from this side.
        """

        for name, limit in (
            ("request_bytes", self.max_request_bytes),
            ("response_bytes", self.max_response_bytes),
            ("requests_this_hour", self.requests_per_hour),
            ("in_flight", self.max_concurrency),
        ):
            current = counters.get(name, 0)
            if not isinstance(current, int) or isinstance(current, bool) or current < 0:
                return f"{name} is not a count: {current!r}"
            if current > limit:
                return f"{name} is {current} against a declared limit of {limit}"
        return None


def select_route(
    *,
    envelope: RequestEnvelope,
    admissions: Sequence[ProviderAdmission],
    remote_enabled: bool,
    now: str,
    budgets: Budgets,
    counters: Mapping[str, int] = {},
) -> "RouteDecision":
    """Pick a route for one request, and record what picked it.

    The ladder is descended from the top only as far as the evidence allows,
    and the first thing checked is the one that can remove every rung: an
    expired request is not routed anywhere.
    """

    inputs = {
        "correlation_id": envelope.correlation_id,
        "privacy_class": envelope.privacy_class.value,
        "expiry": envelope.expiry,
        "now": now,
        "admitted_providers": sorted(
            outcome.provider for outcome in admissions if outcome.admitted
        ),
        "remote_enabled": remote_enabled,
    }

    if envelope.expired_at(now):
        return RouteDecision(
            route=Route.DETERMINISTIC_HANDOFF,
            reason=(
                f"request {envelope.correlation_id} expired at {envelope.expiry} and "
                f"it is {now}; an expired request is answered deterministically "
                "rather than sent anywhere"
            ),
            inputs=inputs,
        )

    over = budgets.exceeded(counters)
    if over is not None:
        return RouteDecision(
            route=Route.DETERMINISTIC_HANDOFF,
            reason=f"a declared budget is exhausted: {over}; the request is not widened",
            inputs=inputs,
        )

    admitted = [outcome.provider for outcome in admissions if outcome.admitted]
    if not admitted:
        return RouteDecision(
            route=Route.DETERMINISTIC_HANDOFF,
            reason=(
                "no cognition provider is admitted, so the deterministic no-model "
                "handoff answers; it is always available and is never removed"
            ),
            inputs=inputs,
        )

    if not remote_enabled or envelope.privacy_class not in _REMOTE_ELIGIBLE:
        return RouteDecision(
            route=Route.LOCAL,
            reason=(
                f"{len(admitted)} provider(s) admitted and remote is "
                + (
                    "not enabled"
                    if not remote_enabled
                    else f"not eligible for {envelope.privacy_class.value}"
                )
                + "; local answers and nothing leaves"
            ),
            inputs=inputs,
        )

    return RouteDecision(
        route=Route.REMOTE,
        reason=(
            f"remote is enabled and {envelope.privacy_class.value} is remote-eligible; "
            "the local answer is produced regardless and remote is additive"
        ),
        inputs=inputs,
    )


#: The classes a remote route may ever carry. `P2-mission` and `P3-restricted`
#: are absent, and `sanitizer.NEVER_REMOTE` says the same thing at the egress
#: boundary -- two independent refusals, because one of them being edited
#: should not silently open the other.
_REMOTE_ELIGIBLE = frozenset({PrivacyClass.P0_PUBLIC, PrivacyClass.P1_SANITIZED})


@dataclass(frozen=True)
class RouteDecision:
    """The route, and the inputs that produced it (§9)."""

    route: Route
    reason: str
    inputs: Mapping[str, object]

    def blocks_deterministic_path(self) -> bool:
        return False

    def as_event(self) -> dict:
        return {
            "event_type": "mio.route.selected",
            "route": self.route.value,
            "reason": self.reason,
            "inputs": dict(self.inputs),
        }


class FallbackTrigger(str, Enum):
    """`docs/mio-runtime.md` §7. Each converges to a safe local state."""

    PROVIDER_TIMEOUT = "provider timeout or deadline expiry"
    AUTHENTICATION_FAILURE = "authentication or mTLS failure"
    STALE_OR_REPLAYED = "stale or replayed response"
    UNPARSEABLE_OR_OVERSIZE = "response fails parsing, or exceeds its size budget"
    PRIVACY_DENIAL = "privacy-policy denial"
    ASSET_VERIFICATION_FAILURE = "asset verification failure"
    RESOURCE_PRESSURE = "resource pressure"
    COGNITION_RESTART = "restart of any cognition service"


@dataclass(frozen=True)
class Fallback:
    """What one trigger does, and what it is forbidden from doing."""

    trigger: FallbackTrigger
    #: The widest route still available afterwards.
    ceiling: Route
    result: str
    #: Stated rather than implied: what this fallback must never do.
    never: str

    def as_event(self) -> dict:
        return {
            "event_type": "mio.route.fallback",
            "trigger": self.trigger.value,
            "ceiling": self.ceiling.value,
            "result": self.result,
            "never": self.never,
        }


_FALLBACKS = (
    Fallback(
        FallbackTrigger.PROVIDER_TIMEOUT,
        Route.LOCAL,
        "the local result is returned unchanged and only the sanitized request "
        "fingerprint is recorded",
        "a deadline expiry never queues data for later submission",
    ),
    Fallback(
        FallbackTrigger.AUTHENTICATION_FAILURE,
        Route.LOCAL,
        "the provider is unavailable",
        "no retry with relaxed trust",
    ),
    Fallback(
        FallbackTrigger.STALE_OR_REPLAYED,
        Route.LOCAL,
        "the response is discarded",
        "it is not merged, not even partially",
    ),
    Fallback(
        FallbackTrigger.UNPARSEABLE_OR_OVERSIZE,
        Route.LOCAL,
        "the response is discarded and nothing is rendered from it",
        "a response over budget is never truncated and shown as an answer",
    ),
    Fallback(
        FallbackTrigger.PRIVACY_DENIAL,
        Route.LOCAL,
        "no egress occurs at all",
        "zero bytes leave; a denial is not a smaller disclosure",
    ),
    Fallback(
        FallbackTrigger.ASSET_VERIFICATION_FAILURE,
        Route.DETERMINISTIC_HANDOFF,
        "the provider is not admitted; the local or Core path answers",
        "an unverified asset is never run to see whether it works",
    ),
    Fallback(
        FallbackTrigger.RESOURCE_PRESSURE,
        Route.DETERMINISTIC_HANDOFF,
        "remote work is shed, then optional model work, then the local model",
        "capture, evidence, audit and lease expiry are never shed",
    ),
    Fallback(
        FallbackTrigger.COGNITION_RESTART,
        Route.DETERMINISTIC_HANDOFF,
        "the node resumes at CORE ONLY and re-admits before rising",
        "a restart alone never restores a provider",
    ),
)

FALLBACKS: Mapping[FallbackTrigger, Fallback] = {
    fallback.trigger: fallback for fallback in _FALLBACKS
}

#: What resource pressure sheds, in order. `docs/mio-runtime.md` §7.
SHEDDING_ORDER = ("remote work", "optional model work", "the local model")

#: What it never sheds, at any pressure. These are not last in the order --
#: they are absent from it, which is a stronger statement than being last.
#:
#: `docs/mio-runtime.md` §7 writes these as "capture, evidence, audit, lease
#: expiry". The names here are this package's own for the same four things
#: (`degradation.RETENTION_ORDER` and `degradation.UNDROPPABLE`), and the
#: alignment is deliberate rather than incidental: the bare word `capture` is
#: a **retired role word** in this repository -- it was an interface role in
#: Azazel-Boot's old commissioning list -- and
#: `tests/unit/test_commissioning.py` refuses it as a string value anywhere in
#: the package. Writing the contract's prose word verbatim would have
#: reintroduced a vocabulary this product retired on purpose.
PROTECTED_FROM_SHEDDING = frozenset(
    {"capture_spool", "evidence_objects", "audit_chain", "lease_expiry"}
)


def fallback_for(trigger: FallbackTrigger, *, from_route: Route) -> Fallback:
    """The fallback, narrowed to no wider than the route it fell back from.

    A trigger's ceiling is the widest route it leaves available; if the
    request was already narrower, it stays narrower. Widening on a failure is
    the one direction this function cannot produce.
    """

    declared = FALLBACKS[trigger]
    if _narrower_or_equal(declared.ceiling, from_route):
        return declared
    return Fallback(
        trigger=declared.trigger,
        ceiling=from_route,
        result=f"{declared.result} (already at {from_route.value}; not widened)",
        never=declared.never,
    )
