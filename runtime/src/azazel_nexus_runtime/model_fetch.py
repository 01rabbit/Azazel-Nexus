"""Resolving a source symbol, and driving a bounded fetch (#96).

`azazel_nexus.model_acquisition` decides **whether** a model may be fetched
and produces a plan. This module is where the symbol in that plan becomes an
address, and where a transfer would be driven. It lives in the runtime
distribution because that is where privileged, outward-facing work belongs --
`az-edge-probed` and `az-core-reserve-probe` sit in the same place for the
same reason.

## There is no fetcher here

The acceptance this module was written against says a node that has not
opted in must have **no acquisition path** -- absent, not configured off. It
is stronger than that: there is no acquisition path in this distribution at
all, for any node, opted in or not.

`drive_fetch` takes a `fetcher` and has no default. Nothing in this package
constructs one, and nothing here imports `socket`, `ssl`, `http` or
`urllib`. `tests/unit/test_runtime_boundary.py` already refuses to find
`AF_INET`, `AF_INET6`, `AF_PACKET` or `create_connection` anywhere in this
package, and that scan passes with this module in it. **A build that shipped
today could not fetch anything even if somebody confirmed it**, because the
code that would open the connection does not exist.

What is here is the shape such code would have to fit: a plan it did not
choose, an address it did not spell, a deadline it cannot extend, a byte
ceiling it cannot exceed, and an attempt budget it cannot refill.

## The endpoints cannot resolve either

`ENDPOINT_FOR` maps every known symbol to a host under `.invalid`, which RFC
2606 reserves and guarantees will never resolve in the DNS. That is not a
placeholder to be tidied up later; it is the second lock. Filling in a real
host is a deliberate, reviewable change to this table, and until somebody
makes it, a fetcher wired in by mistake would resolve nothing.

The table is checked against `KNOWN_SOURCES` at **import time**. A symbol in
the library and not here -- or here and not in the library -- stops this
module from loading, rather than failing at the moment an operator finally
confirms a fetch. The two tables are one fact recorded twice, and the check
is what keeps them one fact.

## The library holds the symbols, this holds the addresses

Deliberately not together. A library that knew the address would be a
library one import away from using it, and `route_selection` and
`remote_trust` -- pure judgement layers with no client -- are reachable from
the library.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterable, Mapping, Optional

from azazel_nexus.model_acquisition import (
    KNOWN_SOURCES,
    MIN_FREE_HEADROOM_BYTES,
    AcquisitionPlan,
)

__all__ = [
    "ENDPOINT_FOR",
    "Endpoint",
    "FetchOutcome",
    "FetchRefused",
    "FetchResult",
    "drive_fetch",
    "endpoint_for",
]


@dataclass(frozen=True)
class Endpoint:
    """Where a symbol resolves. Fixed in the build, never supplied."""

    host: str
    port: int
    #: The path component, with `{digest}` the only substitution. A template
    #: with any other hole would be a template something could steer.
    path_template: str

    def __post_init__(self) -> None:
        if not self.host.endswith(".invalid"):
            raise ValueError(
                f"{self.host!r} is not under .invalid. Every endpoint in this "
                "build is a host RFC 2606 guarantees cannot resolve; naming a "
                "real one is a deliberate change to this table, not a typo"
            )
        holes = self.path_template.count("{")
        if holes != 1 or "{digest}" not in self.path_template:
            raise ValueError(
                f"{self.path_template!r} has holes other than {{digest}}. A "
                "template with another hole is a template something can steer"
            )


#: Every symbol `KNOWN_SOURCES` names, and nothing else. Checked below.
ENDPOINT_FOR: Mapping[str, Endpoint] = {
    "vendor-primary": Endpoint(
        host="models-primary.azazel.invalid",
        port=443,
        path_template="/artifacts/{digest}",
    ),
    "vendor-mirror": Endpoint(
        host="models-mirror.azazel.invalid",
        port=443,
        path_template="/artifacts/{digest}",
    ),
}

# One fact recorded twice; this is what keeps it one fact. A mismatch stops
# the import rather than waiting for somebody to confirm a fetch.
if set(ENDPOINT_FOR) != set(KNOWN_SOURCES):
    raise ImportError(
        "the endpoint table and KNOWN_SOURCES disagree: "
        f"{sorted(set(ENDPOINT_FOR) ^ set(KNOWN_SOURCES))}. A symbol that "
        "resolves to nothing, or an address nothing can name, is a fetch that "
        "fails at the worst possible moment"
    )


class FetchOutcome(str, Enum):
    """How a drive ended. `COMPLETE` is not `VERIFIED` and not `PROMOTED`."""

    #: Every declared byte arrived. Whether they are the right bytes is
    #: decided by `model_catalog.verify_artifact`, not here.
    COMPLETE = "complete"
    #: The deadline passed. Whatever arrived is discarded by the caller.
    TIMED_OUT = "timed_out"
    #: The transfer stopped early. Resumable from `received`.
    INTERRUPTED = "interrupted"
    #: More bytes arrived than were declared.
    OVERRAN = "overran"
    #: No fetcher exists, which is the state of this distribution.
    NO_FETCHER = "no_fetcher"


class FetchRefused(Exception):
    """The drive did not start. Nothing was written."""


@dataclass(frozen=True)
class FetchResult:
    """What a drive did. Never a verdict about the bytes."""

    outcome: FetchOutcome
    received: int
    reason: str

    @property
    def complete(self) -> bool:
        return self.outcome is FetchOutcome.COMPLETE

    def as_event(self) -> dict:
        """The symbol's outcome and a count. No host, no path, no bytes."""

        return {
            "event_type": "mio.model.acquisition.fetched",
            "outcome": self.outcome.value,
            "received": self.received,
            "reason": self.reason,
        }


def endpoint_for(plan: AcquisitionPlan) -> Endpoint:
    """Resolve the plan's symbol. Refuses rather than constructing one."""

    try:
        return ENDPOINT_FOR[plan.source_id]
    except KeyError:
        raise FetchRefused(
            f"{plan.source_id!r} resolves to no endpoint in this build"
        ) from None


def drive_fetch(
    plan: AcquisitionPlan,
    *,
    fetcher: Optional[Callable[..., Iterable[bytes]]] = None,
    sink: Optional[Callable[[bytes], None]] = None,
    elapsed: Optional[Callable[[], int]] = None,
) -> FetchResult:
    """Drive one attempt at `plan`, bounded by everything the plan carries.

    There is no default `fetcher`, and nothing in this distribution provides
    one, so the ordinary result of calling this is `NO_FETCHER`. That is the
    acceptance condition, not a gap: a node with no acquisition path is a
    node where this returns nothing having happened.

    The bounds are the plan's and cannot be widened from here: the deadline,
    the declared size, and the chunk the resume offset is counted in. A
    fetcher that yields more than was declared is stopped at the byte that
    exceeds it -- a file that grew is not the file that was planned for.
    """

    endpoint = endpoint_for(plan)
    if fetcher is None:
        return FetchResult(
            outcome=FetchOutcome.NO_FETCHER,
            received=plan.resume_from,
            reason=(
                "this distribution contains no fetcher. The path is absent "
                "rather than disabled, so there is no setting that turns it on "
                f"and {endpoint.host} could not be reached in any case"
            ),
        )
    if sink is None:
        raise FetchRefused("a drive writes somewhere or it does not run")

    clock = elapsed or (lambda: 0)
    received = plan.resume_from
    for chunk in fetcher(
        host=endpoint.host,
        port=endpoint.port,
        path=endpoint.path_template.format(digest=plan.expected_digest),
        offset=plan.resume_from,
        chunk_bytes=plan.chunk_bytes,
    ):
        if clock() > plan.timeout_seconds:
            return FetchResult(
                outcome=FetchOutcome.TIMED_OUT,
                received=received,
                reason=(
                    f"the deadline of {plan.timeout_seconds}s passed. A fetch "
                    "with no deadline is one nobody learns has stopped"
                ),
            )
        if received + len(chunk) > plan.expected_size_bytes:
            return FetchResult(
                outcome=FetchOutcome.OVERRAN,
                received=received,
                reason=(
                    f"more than the declared {plan.expected_size_bytes} bytes "
                    "arrived. A file that grew is not the file that was "
                    "planned for"
                ),
            )
        sink(chunk)
        received += len(chunk)

    if received != plan.expected_size_bytes:
        return FetchResult(
            outcome=FetchOutcome.INTERRUPTED,
            received=received,
            reason=(
                f"{received} of {plan.expected_size_bytes} bytes arrived. "
                "Resumable from here; the digest is still checked afterwards, "
                "so resuming cannot skip verification"
            ),
        )
    return FetchResult(
        outcome=FetchOutcome.COMPLETE,
        received=received,
        reason=(
            "every declared byte arrived. Whether they are the right bytes is "
            "decided by the same verification an offline import goes through, "
            "and nothing here has decided it"
        ),
    )
