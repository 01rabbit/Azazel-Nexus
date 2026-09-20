"""What stops and what continues, for every condition and every failure mode.

Issue #30, the consumer side of SO-06. The acceptance condition it inherits is
severe and worth restating before anything else:

    "100% continuation" means zero divergence on the deterministic path. Not
    "nearly the same".

So this module's only real assertion is a negative one: **no optional
component, failing in any way, subtracts a core capability.** Everything else
here exists to make that assertion checkable rather than stated.

Three design choices carry the issue's requirements:

*Absent is not corrupt.* Each failure mode maps to its own disposition, and
the mapping is injective -- a test asserts it. "We have no Knowledge node" and
"the Knowledge node returned something we could not parse" call for different
operator actions, and a system that renders both as "unavailable" has thrown
away the difference before anyone could act on it.

*Reasons are independent.* Two components failing produce two reasons. A
single "degraded" line is a node that knows more than it is saying, and the
second failure is the one nobody investigates.

*A hanging component is modelled by a deadline, never by waiting.* The clock
is injected. A test for `HANGING` advances a counter past a budget and
returns; no test in this repository sleeps, and none may. A suite that proves
timeout handling by actually hanging is a suite that stops being run.

Capability states are `FULL -> LITE -> CORE`. None of them is an authority
level: the deterministic arbiter holds the same authority in all three
(`docs/capability-model.md` §1), and nothing here returns one.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterable, Mapping, Optional, Sequence, TypeVar

from .capability import (
    CORE_CAPABILITIES,
    CapabilityState,
    OptionalComponent,
    degrade,
    state_for,
)

__all__ = [
    "CONDITIONS",
    "Condition",
    "DeadlineExceeded",
    "DegradationReason",
    "Disposition",
    "FailureMode",
    "MATRIX",
    "Outcome",
    "assess",
    "call_with_deadline",
    "matrix",
    "retain_under_pressure",
]

T = TypeVar("T")


class FailureMode(str, Enum):
    """The five ways an optional component fails. Never four.

    Collapsing any pair of these is the failure this enum exists to prevent:
    an operator answering "it is not installed" does something different from
    one answering "it answered and the answer was garbage".
    """

    #: Not configured on this node at all.
    ABSENT = "absent"
    #: Configured and reachable, and it declined.
    REFUSING = "refusing"
    #: Configured and reachable, and it did not answer inside the budget.
    HANGING = "hanging"
    #: Answered, and the answer could not be used.
    CORRUPT = "corrupt"
    #: Answered with something whose validity has lapsed.
    EXPIRED = "expired"


class Disposition(str, Enum):
    """What the node did about it, in the words an operator needs."""

    NOT_CONFIGURED = "not_configured"
    REFUSED = "refused"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    QUARANTINED = "quarantined"
    STALE = "stale"


#: One disposition per mode, and no two modes share one.
#:
#: The injectivity is the point and it is asserted in the tests. A mapping in
#: which `ABSENT` and `CORRUPT` landed on the same disposition would satisfy
#: every other check here while destroying the distinction the issue names.
DISPOSITIONS: Mapping[FailureMode, Disposition] = {
    FailureMode.ABSENT: Disposition.NOT_CONFIGURED,
    FailureMode.REFUSING: Disposition.REFUSED,
    FailureMode.HANGING: Disposition.DEADLINE_EXCEEDED,
    FailureMode.CORRUPT: Disposition.QUARANTINED,
    FailureMode.EXPIRED: Disposition.STALE,
}


@dataclass(frozen=True)
class Condition:
    """One row of the degradation table."""

    key: str
    #: What is lost. `None` for a condition that is not a component at all.
    component: Optional[OptionalComponent]
    #: What an operator is told narrows.
    degrades: str
    #: Beyond the core capabilities, which are implied for every row.
    also_continues: tuple[str, ...] = ()

    @property
    def must_continue(self) -> frozenset[str]:
        return frozenset(CORE_CAPABILITIES) | frozenset(self.also_continues)


#: The conditions, in issue #30's order, plus one it did not list.
#:
#: Knowledge Lite appears twice on purpose. The two rows lose the same
#: capability and owe the operator different things: one says there is no
#: tactical cache, the other says there is one and it is stale. A table that
#: merged them would be a table in which a node serving lapsed intelligence
#: looked like a node serving none.
#:
#: **`deception_lite_absent` is an eighth row that issue #30 does not list,
#: and it is added rather than left out.** The issue's fourth row covers the
#: *external* AZ-06 node; the embedded Deception Lite runtime is a separate
#: component that `capability.py` already sources a capability from, and a
#: matrix that omitted it would leave one optional component whose failure
#: nothing here tests -- while reading as though that component were out of
#: scope. `test_the_matrix_covers_every_optional_component` is what found the
#: gap and what keeps it closed.
CONDITIONS = (
    Condition(
        "local_model_absent",
        OptionalComponent.LOCAL_MODEL,
        "the depth of explanation and advice",
    ),
    Condition(
        "remote_path_unreachable",
        OptionalComponent.REMOTE_COGNITION,
        "remote advice",
        also_continues=("local_cognition",),
    ),
    Condition(
        "knowledge_node_absent",
        OptionalComponent.EXTERNAL_KNOWLEDGE_NODE,
        "extended threat context",
    ),
    Condition(
        "deception_node_absent",
        OptionalComponent.EXTERNAL_DECEPTION_NODE,
        "materialisation of a bounded environment",
    ),
    Condition(
        "knowledge_lite_absent",
        OptionalComponent.KNOWLEDGE_LITE,
        "the tactical cache",
    ),
    Condition(
        "knowledge_lite_expired",
        OptionalComponent.KNOWLEDGE_LITE,
        "the tactical cache, which is present and must be shown as stale",
    ),
    Condition(
        "deception_lite_absent",
        OptionalComponent.DECEPTION_LITE,
        "the embedded bounded-environment runtime",
    ),
    Condition(
        "audit_pressure",
        None,
        "records with the longest retention. The chain itself does not stop",
    ),
)

_BY_KEY = {condition.key: condition for condition in CONDITIONS}


class DeadlineExceeded(Exception):
    """A component did not answer inside its budget. Nothing waited for it."""


@dataclass(frozen=True)
class DegradationReason:
    """One failure, named on its own. Never merged with another."""

    condition: str
    mode: FailureMode
    disposition: Disposition
    detail: str

    def __post_init__(self) -> None:
        if self.condition not in _BY_KEY:
            raise ValueError(
                f"{self.condition!r} is not a declared condition; a reason for "
                "something the matrix does not cover is a reason nothing checks"
            )
        if self.disposition is not DISPOSITIONS[self.mode]:
            raise ValueError(
                f"{self.mode.value!r} is reported as {self.disposition.value!r}; "
                "each mode has exactly one disposition, and blurring two of "
                "them is how 'missing' and 'broken' become the same screen"
            )

    @property
    def stale(self) -> bool:
        return self.disposition is Disposition.STALE


@dataclass(frozen=True)
class Outcome:
    """What the node is, after everything that failed has failed."""

    state: CapabilityState
    retained: tuple[str, ...]
    lost: tuple[str, ...]
    reasons: tuple[DegradationReason, ...]

    def __post_init__(self) -> None:
        missing = sorted(CORE_CAPABILITIES - set(self.retained))
        if missing:
            raise AssertionError(
                f"an optional component's failure subtracted {missing}. "
                "SO-06: zero divergence on the deterministic path, not nearly "
                "none. This is not a degradation to report -- it is the "
                "failure the whole capability model exists to make impossible"
            )

    @property
    def stale_sources(self) -> tuple[str, ...]:
        """Conditions whose data is present and lapsed, named individually."""

        return tuple(reason.condition for reason in self.reasons if reason.stale)

    @property
    def deterministic_path_intact(self) -> bool:
        return CORE_CAPABILITIES <= set(self.retained)


def assess(
    available: Iterable[str],
    failures: Mapping[str, FailureMode],
    *,
    details: Optional[Mapping[str, str]] = None,
) -> Outcome:
    """Apply every failure, independently, and report what is left.

    `failures` is keyed by condition, so two conditions that lose the same
    component still produce two reasons. That is deliberate: `knowledge_lite`
    absent and `knowledge_lite` expired subtract the same capability and owe
    the operator different sentences.
    """

    starting = frozenset(available)
    details = details or {}
    reasons: list[DegradationReason] = []
    lost_components: set[OptionalComponent] = set()

    for key, mode in failures.items():
        condition = _BY_KEY.get(key)
        if condition is None:
            raise ValueError(
                f"{key!r} is not a declared condition. The matrix is the list "
                "of what this node knows how to degrade under; an undeclared "
                "failure would degrade it in a way nothing tested"
            )
        reasons.append(
            DegradationReason(
                condition=key,
                mode=mode,
                disposition=DISPOSITIONS[mode],
                detail=details.get(key) or _default_detail(condition, mode),
            )
        )
        if condition.component is not None:
            lost_components.add(condition.component)

    remaining = degrade(starting, frozenset(lost_components))
    return Outcome(
        state=state_for(remaining),
        retained=tuple(sorted(remaining)),
        lost=tuple(sorted(starting - remaining)),
        # Sorted by condition so two runs over the same failures report in the
        # same order. A reason list whose order depended on dict insertion
        # would make two identical nodes render differently.
        reasons=tuple(sorted(reasons, key=lambda r: r.condition)),
    )


def _default_detail(condition: Condition, mode: FailureMode) -> str:
    return (
        f"{DISPOSITIONS[mode].value}: {condition.degrades} is unavailable. "
        "The deterministic control path is unaffected."
    )


def matrix() -> tuple[tuple[str, FailureMode, Disposition, bool], ...]:
    """Every condition against every mode. The table issue #30 asks for.

    Returned as data rather than printed, so the tests check the table and the
    documentation is checked against the same table.
    """

    rows = []
    for condition in CONDITIONS:
        for mode in FailureMode:
            outcome = assess(
                frozenset(CORE_CAPABILITIES) | {"knowledge_lite", "local_cognition"},
                {condition.key: mode},
            )
            rows.append(
                (
                    condition.key,
                    mode,
                    DISPOSITIONS[mode],
                    outcome.deterministic_path_intact,
                )
            )
    return tuple(rows)


#: The table, evaluated once. 7 conditions x 5 modes.
MATRIX = matrix()


def call_with_deadline(
    call: Callable[[], T],
    *,
    budget_ms: int,
    clock: Callable[[], int],
) -> T:
    """Run `call` against an injected clock and refuse what overran.

    The clock is injected and the budget is checked **after** the call
    returns, which is the honest shape for a synchronous port: this module
    cannot interrupt a callee, and pretending otherwise with a thread would
    leave the callee running while reporting it stopped.

    What it gives is a model of `HANGING` that finishes: a test advances the
    counter past the budget and returns, and the outcome is
    `DeadlineExceeded` with no wall-clock time spent. A real caller enforces
    the budget where it can be enforced -- at a socket, at a subprocess, in
    the daemon that owns the call -- and reports it through this same verdict.
    """

    if budget_ms <= 0:
        raise ValueError("a deadline of zero or less admits nothing at all")
    started = clock()
    result = call()
    elapsed = clock() - started
    if elapsed > budget_ms:
        raise DeadlineExceeded(
            f"the component took {elapsed}ms against a {budget_ms}ms budget. "
            "Its answer is not used: a late answer accepted is a budget that "
            "does not exist"
        )
    return result


#: Audit records in the order retention releases them under pressure.
#:
#: The chain is not in this list and cannot be: `retain_under_pressure`
#: refuses to drop it. A node that freed space by dropping links would be a
#: node whose ledger reports itself intact while missing entries.
RETENTION_ORDER = ("capture_spool", "explanatory_advice", "evidence_objects")

#: What retention pressure may never release.
UNDROPPABLE = ("audit_chain",)


def retain_under_pressure(
    holdings: Sequence[str], *, release: int
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Release the longest-retention records first. Never the chain.

    Returns `(kept, released)`. Raises if the pressure could only be relieved
    by dropping something undroppable: the audit chain does not stop, and a
    write it cannot complete is reported as a failure rather than dropped
    (`IMPLEMENTATION_SPEC.md` §6.4, and the fail-closed rule in `audit.py`).
    """

    if release < 0:
        raise ValueError("a negative release frees nothing")
    kept = list(holdings)
    released: list[str] = []
    for candidate in RETENTION_ORDER:
        if len(released) >= release:
            break
        if candidate in kept:
            kept.remove(candidate)
            released.append(candidate)
    if len(released) < release:
        raise AssertionError(
            f"{release} records had to be released and only {len(released)} "
            f"were droppable. What remains is {UNDROPPABLE}, and retention "
            "pressure never releases it: a ledger that freed space by dropping "
            "links would report itself intact while missing entries"
        )
    return tuple(kept), tuple(released)
