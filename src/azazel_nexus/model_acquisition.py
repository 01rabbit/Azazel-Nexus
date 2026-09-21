"""Whether a model may be fetched, and from which named source (#96).

The installer may do the fetching. It does not do it by default, and it never
does it because something asked nicely.

```
catalog names a SYMBOL --> this build resolves the symbol, or refuses
                       --> operator confirms, explicitly, in setup
                       --> capacity checked BEFORE a byte moves
                       --> fetch (runtime service) --> the #95 path verifies
                                                   \\--> offline import, always
```

## A symbol, never a location

`ModelEntry.source_id` names a source. It cannot spell one: no dot, no
slash, no colon, nothing a URL or a path could be built from. **If a catalog
could carry an endpoint, a catalog signature would become a way to point a
node at any host on the internet**, and whoever signs catalogs would hold
that power over every node their catalog reaches.

So the catalog chooses *among sources this build already knows*, and knows
none it was not built with. That is the discipline `remote_trust` holds for
endpoints, applied one layer up.

This module holds the symbols. It does **not** hold the endpoints: the
resolution from symbol to host lives in the runtime distribution, with the
code that is allowed to open a socket. A library that knew the address would
be a library one import away from using it.

## Not configured off. Absent.

"Default off" is a setting, and a setting is a thing that can be set. There
is no fetch in this distribution: no `socket`, no `ssl`, no `http`, no
`urllib`, in this module or anywhere `route_selection` or `remote_trust` can
reach. `tests/unit/test_model_acquisition.py` scans for their absence rather
than for a flag's value, the same way `test_cognition.py` scans for the
absence of a remote client.

What this module produces is a **plan**: a decided, bounded description of a
fetch that some other component, running with different privileges and
started by an explicit operator action, may carry out. Producing a plan
fetches nothing. A plan is not a permission slip either -- every refusal
below happens before one exists.

## The operator confirms here, and separately

Acquisition is its own confirmation (`operator_view.Confirmation`). An
operator who chose `fastest-permitted`, consented to remote advisory
routing, and acknowledged a licence has consented to **none** of this:
routing a sanitised question to a remote advisor and downloading several
gibibytes onto this disk are different acts with different consequences.

## Fetching is not admitting, and failing is not fatal

A fetched artifact lands where an imported one lands and goes through the
**same** verification -- `model_catalog.verify_artifact`, via `model_import`.
There is no second verifier and no shortcut for bytes that arrived over a
socket; if anything, those deserve the stricter path, and they get the same
one.

And when acquisition cannot happen -- no source, no consent, no network, a
timeout, a digest that did not match -- the offline import route is
untouched. **A node that cannot download is a node that installs from a USB
stick**, not a node that cannot install.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional

from .model_catalog import ModelEntry

__all__ = [
    "AcquisitionPlan",
    "AcquisitionRefused",
    "KNOWN_SOURCES",
    "MAX_ATTEMPTS",
    "MIN_FREE_HEADROOM_BYTES",
    "Refusal",
    "RESUME_CHUNK_BYTES",
    "SourceConsent",
    "TIMEOUT_SECONDS",
    "plan_acquisition",
]

#: Every source symbol this build knows. A catalog may choose among these and
#: cannot add to them: an unknown symbol is a refusal, not a lookup.
#:
#: The endpoints these resolve to are **not here**. They live in
#: `azazel_nexus_runtime.model_fetch`, which checks at import that its table
#: covers exactly this set -- a symbol in one and not the other stops the
#: runtime from loading rather than failing at the moment somebody fetches.
KNOWN_SOURCES = ("vendor-primary", "vendor-mirror")

#: A fetch that has not finished in this long has not failed loudly, which is
#: worse. A fetch with no deadline is one nobody learns has stopped.
TIMEOUT_SECONDS = 3600

#: Attempts, total, including the first. Resume makes a retry cheap; it does
#: not make an unbounded number of them acceptable.
MAX_ATTEMPTS = 3

#: A resumed fetch continues from a byte offset, so the unit of progress has
#: to be bounded and the same on both sides of an interruption.
RESUME_CHUNK_BYTES = 8 * 1024 * 1024

#: Free space kept for the node itself, matching the offline import's rule.
#: A node that fetches a model and can no longer write its audit chain has
#: not gained anything.
MIN_FREE_HEADROOM_BYTES = 2 * 1024 * 1024 * 1024


class Refusal(str, Enum):
    """Why no plan was produced. Each reached on its own."""

    NOT_CONFIRMED = "not_confirmed"
    NO_SOURCE_DECLARED = "no_source_declared"
    UNKNOWN_SOURCE = "unknown_source"
    INSUFFICIENT_DISK = "insufficient_disk"
    ALREADY_INSTALLED = "already_installed"
    ATTEMPTS_EXHAUSTED = "attempts_exhausted"


class AcquisitionRefused(Exception):
    """No plan exists, and nothing was fetched, staged or changed."""

    def __init__(self, cause: Refusal, detail: str = "") -> None:
        super().__init__(f"{cause.value}: {detail}" if detail else cause.value)
        self.cause = cause


@dataclass(frozen=True)
class SourceConsent:
    """The operator's explicit, separate confirmation that a fetch may happen.

    Not a profile, not a remote-routing opt-in, not a licence. Someone who
    granted all three has granted none of this: sending a sanitised question
    to a remote advisor and pulling gibibytes onto this disk are different
    acts with different consequences, and one "yes" that covered both would
    be a "yes" nobody knowingly gave.
    """

    #: The symbols the operator confirmed, one at a time. Never "all".
    sources: frozenset
    operator: str
    at: str

    def __post_init__(self) -> None:
        for field in ("operator", "at"):
            if not str(getattr(self, field)).strip():
                raise AcquisitionRefused(
                    Refusal.NOT_CONFIRMED, f"a confirmation records {field}"
                )
        unknown = sorted(set(self.sources) - set(KNOWN_SOURCES))
        if unknown:
            raise AcquisitionRefused(
                Refusal.UNKNOWN_SOURCE,
                f"{unknown} name no source this build knows. A confirmation "
                "for a symbol that resolves to nothing would be a confirmation "
                "an operator could not have understood",
            )

    def covers(self, source_id: str) -> bool:
        return source_id in self.sources


#: An operator who has confirmed nothing. The state of every node until one
#: does, and a value rather than a `None` so that "nobody asked" has a shape.
NO_CONSENT = SourceConsent(sources=frozenset(), operator="(none)", at="(none)")


@dataclass(frozen=True)
class AcquisitionPlan:
    """A decided, bounded fetch. Holding one has fetched nothing.

    It names a **symbol**, a size, a digest and a deadline. It does not name
    a host, a URL, a port or a path: resolving the symbol is the runtime
    service's job, and a plan that carried an address would be an address
    this layer had handled.
    """

    model_id: str
    source_id: str
    expected_digest: str
    expected_size_bytes: int
    resume_from: int
    timeout_seconds: int = TIMEOUT_SECONDS
    chunk_bytes: int = RESUME_CHUNK_BYTES
    attempts_remaining: int = MAX_ATTEMPTS

    def __post_init__(self) -> None:
        if self.source_id not in KNOWN_SOURCES:
            raise AcquisitionRefused(
                Refusal.UNKNOWN_SOURCE,
                f"{self.source_id!r} is not one of {list(KNOWN_SOURCES)}",
            )
        if not 0 <= self.resume_from <= self.expected_size_bytes:
            raise AcquisitionRefused(
                Refusal.INSUFFICIENT_DISK,
                f"a resume offset of {self.resume_from} is not inside an "
                f"artifact of {self.expected_size_bytes} bytes",
            )
        if self.attempts_remaining < 1:
            raise AcquisitionRefused(
                Refusal.ATTEMPTS_EXHAUSTED, "a plan with no attempt left is not a plan"
            )

    @property
    def remaining_bytes(self) -> int:
        return self.expected_size_bytes - self.resume_from

    def as_event(self) -> dict:
        """The symbol, the sizes and the deadline. No address, because
        there is none here to leak."""

        return {
            "event_type": "mio.model.acquisition.planned",
            "model_id": self.model_id,
            "source_id": self.source_id,
            "expected_digest": self.expected_digest,
            "expected_size_bytes": self.expected_size_bytes,
            "resume_from": self.resume_from,
            "timeout_seconds": self.timeout_seconds,
            "attempts_remaining": self.attempts_remaining,
        }


def plan_acquisition(
    entry: ModelEntry,
    *,
    consent: SourceConsent = NO_CONSENT,
    free_bytes: int,
    resume_from: int = 0,
    attempts_used: int = 0,
    installed: Mapping[str, str] = {},
) -> AcquisitionPlan:
    """Decide whether this model may be fetched, and bound the fetch.

    Refuses in a fixed order, cheapest and most absolute first, so that a
    node never checks the disk for something it was never permitted to fetch.
    Producing a plan fetches nothing; every refusal here happens before one
    exists.
    """

    if entry.source_id is None:
        raise AcquisitionRefused(
            Refusal.NO_SOURCE_DECLARED,
            f"{entry.model_id} declares no source. The catalog permits no "
            "online route for it, so the only way in is an operator's import",
        )
    if entry.source_id not in KNOWN_SOURCES:
        raise AcquisitionRefused(
            Refusal.UNKNOWN_SOURCE,
            f"{entry.source_id!r} is not a source this build knows. A symbol "
            "resolves against a fixed table or it resolves to nothing",
        )
    if not consent.covers(entry.source_id):
        raise AcquisitionRefused(
            Refusal.NOT_CONFIRMED,
            f"no operator has confirmed a fetch from {entry.source_id!r}. "
            "A profile, a remote-routing opt-in and a licence are three other "
            "confirmations and none of them is this one",
        )
    if installed.get(entry.model_id) == entry.digest:
        raise AcquisitionRefused(
            Refusal.ALREADY_INSTALLED,
            f"{entry.model_id} at this digest is already installed. Fetching "
            "it again would spend the disk and the time for nothing",
        )
    attempts_remaining = MAX_ATTEMPTS - attempts_used
    # `AcquisitionPlan` refuses an exhausted budget too. Both are wanted: this
    # one refuses before the disk is consulted and can say how many attempts
    # were made, and the dataclass invariant holds for a plan built directly.
    if attempts_remaining < 1:
        raise AcquisitionRefused(
            Refusal.ATTEMPTS_EXHAUSTED,
            f"{attempts_used} attempts have been made. Resume makes a retry "
            "cheap; it does not make an unbounded number of them acceptable",
        )
    needed = (entry.size_bytes - resume_from) + MIN_FREE_HEADROOM_BYTES
    if free_bytes < needed:
        raise AcquisitionRefused(
            Refusal.INSUFFICIENT_DISK,
            f"{free_bytes} bytes free against {needed} needed. Checked before "
            "a byte moves: a node must not discover the disk is full with "
            "half an artifact on it",
        )
    return AcquisitionPlan(
        model_id=entry.model_id,
        source_id=entry.source_id,
        expected_digest=entry.digest,
        expected_size_bytes=entry.size_bytes,
        resume_from=resume_from,
        attempts_remaining=attempts_remaining,
    )
