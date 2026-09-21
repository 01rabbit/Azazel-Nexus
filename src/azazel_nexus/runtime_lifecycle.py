"""The lifecycle a model process has, and the budget it runs out of (#114).

#112 fixed the service **boundary** on a build that starts nothing. This is
the **lifecycle**: what states a real process moves through, what evidence
each one needs, and what happens when it keeps failing.

Nothing here starts a process. `azazel_nexus` refuses `subprocess` across the
package and that is not relaxed; the supervisor that spawns one is
`azazel_nexus_runtime.mio_supervisor`, and it asks this module what it is
allowed to do.

## Readiness is three-valued, and starting is not being ready

A process that started is a process that started. Whether it can answer is a
separate observation, and if nobody made it the answer is `NOT_CHECKED` --
not `FAILED`, which is a decision, and certainly not `PASSED`.

Collapsing them is how a node that never probed comes to look like a node
that probed and was satisfied.

## The restart budget is finite, and running out is a decision

A supervisor that restarts forever turns a broken provider into a permanent
load on the node, and turns a crash loop into something that looks like a
service that is merely slow. The budget is spent per generation; **exhausting
it fences** rather than continuing, and a fence is not cleared by restarting
the supervisor.

Restarting **never widens**. A process that comes back comes back under the
same containment it had, and a supervisor that could raise a limit on restart
would be a supervisor that grants privilege by failing.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional

__all__ = [
    "BinaryVerdict",
    "BudgetLedger",
    "LifecycleRefused",
    "LifecycleState",
    "MAX_RESTARTS",
    "Provenance",
    "RollbackOutcome",
    "RollbackRefusal",
    "Readiness",
    "RestartBudget",
    "RestartVerdict",
    "STDIO_BYTE_CEILING",
    "plan_rollback",
    "verify_runtime_binary",
]

#: How many times one provider may be restarted within a generation before
#: the supervisor stops trying and fences it.
#:
#: Small on purpose. A provider that has died three times is a provider whose
#: next start is not evidence of anything, and the operator needs to see a
#: fence rather than a graph of restarts.
MAX_RESTARTS = 3

#: The most stdout **and** stderr bytes kept from one process run.
#:
#: Kept, not read: the supervisor stops reading past this. A ceiling enforced
#: after reading everything is a ceiling on nothing, and a provider that can
#: write without bound into a pipe the node is draining is a provider that
#: decides how much memory the node spends on it.
STDIO_BYTE_CEILING = 64 * 1024


class LifecycleRefused(Exception):
    """A lifecycle transition that may not happen. Refused, never repaired."""


class LifecycleState(str, Enum):
    """Where a supervised process is. One value per condition, never merged.

    There is deliberately **no `RUNNING`**. "Running" would let a process that
    started and cannot answer be reported the same as one that is serving,
    and the difference between those two is the whole reason readiness is
    observed separately.
    """

    #: Nothing has been started.
    ABSENT = "absent"
    #: A process exists and no readiness observation has been made.
    STARTED = "started"
    #: A process exists and answered a readiness probe.
    SERVING = "serving"
    #: A process existed and exited without being asked to.
    CRASHED = "crashed"
    #: A process existed and was stopped by the supervisor.
    STOPPED = "stopped"
    #: The restart budget is spent. Nothing starts again without an operator.
    FENCED = "fenced"


class Readiness(str, Enum):
    """Whether a process answered. Three answers, never two."""

    PASSED = "passed"
    FAILED = "failed"
    #: Nobody observed. Not a pass, and not a failure either.
    NOT_CHECKED = "not-checked"


class Provenance(str, Enum):
    """Where a runtime binary came from. Two are never interchangeable."""

    #: Shipped by the package and verified against its own declaration.
    PACKAGED = "packaged"
    #: Hand-built to exercise the supervisor. Refused for admission, by name.
    FIXTURE = "fixture"


@dataclass(frozen=True)
class BinaryVerdict:
    """Whether a runtime binary may be started, and every reason it may not.

    Every reason, not the first: an operator who fixes one and is then told
    about the next has been sent round twice.
    """

    admissible: bool
    refusals: tuple

    def __post_init__(self) -> None:
        if self.admissible and self.refusals:
            raise LifecycleRefused(
                "a binary cannot be admissible and refused; one of the two is "
                "describing a different binary"
            )
        if not self.admissible and not self.refusals:
            raise LifecycleRefused(
                "a binary was refused with no reason; a refusal an operator "
                "cannot act on is one that will be worked around"
            )


def verify_runtime_binary(
    path: Path,
    *,
    expected_digest: str,
    expected_provenance: Provenance = Provenance.PACKAGED,
    declared_provenance: Optional[Provenance] = None,
    signature_verified: Optional[bool] = None,
) -> BinaryVerdict:
    """Digest, signature and provenance. All three, or it does not start.

    `RuntimeBinary` declared a digest and nothing checked it (#97). Declaring
    a digest that nothing compares against is a field that reads like a
    guarantee and is one.

    `signature_verified` is supplied because this module does not own asset
    verification, and `None` -- nobody checked -- refuses exactly as `False`
    does, with a different reason. `declared_provenance` is likewise supplied:
    a binary cannot be asked where it came from, only told.
    """

    refusals: list = []

    if declared_provenance is None:
        refusals.append(
            "no provenance was declared; a binary whose origin nobody stated "
            "is not one this node was commissioned to run"
        )
    elif declared_provenance is not expected_provenance:
        refusals.append(
            f"the binary declares itself {declared_provenance.value!r} and "
            f"this path admits only {expected_provenance.value!r}; a fixture "
            "is how the supervisor is tested, never how a provider is admitted"
        )

    if signature_verified is None:
        refusals.append(
            "no signature verification result was supplied; an unchecked "
            "binary is not a verified one, and absence of a check is not a pass"
        )
    elif not signature_verified:
        refusals.append("the binary's signature did not verify")

    try:
        actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        refusals.append(f"{path.name} is not present")
        actual = None
    except OSError as exc:
        refusals.append(f"{path.name} could not be read: {exc}")
        actual = None

    if actual is not None and actual != expected_digest:
        # The message names neither digest in full. A refusal that printed the
        # expected value would hand an attacker the target.
        refusals.append(
            f"{path.name} does not hash to the digest its runtime record "
            "declares"
        )

    if refusals:
        return BinaryVerdict(admissible=False, refusals=tuple(refusals))
    return BinaryVerdict(admissible=True, refusals=())


class BudgetLedger:
    """Restart budgets on disk, so a restart does not refill one.

    A budget held only in memory is a budget the failure being budgeted
    clears, by taking the supervisor down with it -- and the failure most
    likely to take a supervisor down is the one it is restarting. Without
    this, a provider that crashes hard enough to kill its supervisor gets a
    fresh three restarts every time, for ever, and the node calls that
    "occasionally slow".

    Keyed by generation **and** runtime id. Two providers fail independently;
    one exhausting its budget says nothing about the other.

    An unreadable ledger is **not** "no budgets spent". Everything it governs
    is treated as fenced until somebody looks, because the alternative is a
    corrupt file silently returning a provider to service -- the same rule
    `watchdog.FenceStore` holds to, and for the same reason.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def _read(self) -> tuple:
        """`(entries, readable)`. Unreadable is a fact the caller must see."""

        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}, True
        except (OSError, json.JSONDecodeError):
            return {}, False
        if not isinstance(raw, dict):
            return {}, False
        return raw, True

    def load(
        self, *, generation: int, runtime_id: str, limit: int = MAX_RESTARTS
    ) -> "RestartBudget":
        entries, readable = self._read()
        if not readable:
            spent = RestartBudget(generation=generation, limit=limit, spent=limit)
            spent.fenced = True
            return spent
        record = entries.get(f"{generation}:{runtime_id}")
        if not isinstance(record, dict):
            return RestartBudget(generation=generation, limit=limit)
        try:
            return RestartBudget(
                generation=generation,
                limit=int(record.get("limit", limit)),
                spent=int(record.get("spent", 0)),
                fenced=bool(record.get("fenced", False)),
            )
        except (TypeError, ValueError, LifecycleRefused):
            # A malformed entry is not a fresh budget. Same rule as above.
            broken = RestartBudget(generation=generation, limit=limit, spent=limit)
            broken.fenced = True
            return broken

    def save(self, budget: "RestartBudget", *, runtime_id: str) -> None:
        entries, readable = self._read()
        if not readable:
            # **Write nothing.** An earlier version set `entries = {}` here
            # and carried on, which is not "do not overwrite" -- it is
            # overwriting, with the damaged file replaced by a clean one that
            # says one provider is fenced and nothing else ever was.
            #
            # Found by mutation: removing the branch changed no behaviour,
            # because the branch did not have any. Leaving the file alone
            # keeps the evidence an operator needs and costs nothing: an
            # unreadable ledger already loads as fenced for every provider,
            # so there is no state worth recording into it.
            return
        entries[f"{budget.generation}:{runtime_id}"] = {
            "limit": budget.limit,
            "spent": budget.spent,
            "fenced": budget.fenced,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(entries, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )


@dataclass(frozen=True)
class RestartVerdict:
    """Whether a restart may happen, and what the node does instead."""

    may_restart: bool
    remaining: int
    state: LifecycleState
    reason: str


@dataclass
class RestartBudget:
    """How many restarts are left, per generation.

    Per **generation**, not per boot: a budget that a reboot refilled would be
    a budget a crash loop refills by taking the node down with it.
    """

    generation: int
    limit: int = MAX_RESTARTS
    spent: int = 0
    #: Set once the budget is exhausted. Held by the caller on disk, so that
    #: restarting the supervisor does not clear it.
    fenced: bool = False

    def __post_init__(self) -> None:
        if self.limit < 1:
            raise LifecycleRefused(
                "a budget of zero restarts is not a budget; nothing would ever "
                "come back and nothing would say why"
            )
        if self.spent < 0:
            raise LifecycleRefused("a spent count below zero is not a count")

    @property
    def remaining(self) -> int:
        return max(self.limit - self.spent, 0)

    def spend(self) -> RestartVerdict:
        """Take one restart, or refuse and fence.

        Refusing is the last act: once fenced, this returns the same refusal
        for ever. Returning a process to service is an operator's decision
        against a revalidated generation, exactly as it is for a fenced unit
        -- and a supervisor that could un-fence itself would be a supervisor
        that grants itself a fresh budget by asking twice.
        """

        if self.fenced:
            return RestartVerdict(
                may_restart=False,
                remaining=0,
                state=LifecycleState.FENCED,
                reason=(
                    f"the restart budget for generation {self.generation} is "
                    "spent and the provider is fenced; returning it to service "
                    "is an operator's decision, not this supervisor's"
                ),
            )
        if self.remaining < 1:
            self.fenced = True
            return RestartVerdict(
                may_restart=False,
                remaining=0,
                state=LifecycleState.FENCED,
                reason=(
                    f"{self.spent} restarts in generation {self.generation} "
                    f"reached the limit of {self.limit}; a provider that has "
                    "died this often is one whose next start is not evidence "
                    "of anything"
                ),
            )
        self.spent += 1
        if self.remaining < 1:
            # Granted, and **not** fenced yet. The fence belongs to the next
            # request, not to this grant: fencing here would spend a budget
            # of N on N-1 restarts, and a limit that means one fewer than it
            # says is a limit nobody can reason about.
            return RestartVerdict(
                may_restart=True,
                remaining=0,
                state=LifecycleState.STARTED,
                reason=(
                    f"restart {self.spent} of {self.limit} for generation "
                    f"{self.generation}; this was the last one"
                ),
            )
        return RestartVerdict(
            may_restart=True,
            remaining=self.remaining,
            state=LifecycleState.STARTED,
            reason=(
                f"restart {self.spent} of {self.limit} for generation "
                f"{self.generation}"
            ),
        )

    def as_event(self) -> dict:
        return {
            "event_type": "mio.runtime.restart_budget",
            "generation": self.generation,
            "limit": self.limit,
            "spent": self.spent,
            "remaining": self.remaining,
            "fenced": self.fenced,
        }


class RollbackRefusal(str, Enum):
    """Why a provider was not rolled back. One value per condition."""

    NO_REASON = "no_reason"
    NO_ACTOR = "no_actor"
    SAME_GENERATION = "same_generation"
    NO_PREDECESSOR = "no_predecessor"
    TARGET_UNVERIFIABLE = "target_unverifiable"


@dataclass(frozen=True)
class RollbackOutcome:
    """Whether the provider moved, and what the node is running either way.

    `running_generation` is the answer to the only question that matters
    after a failed rollback: **what is this node on now.** A rollback that
    failed and left the field ambiguous would be a rollback an operator has
    to go and find out about.
    """

    rolled_back: bool
    running_generation: int
    from_generation: Optional[int]
    to_generation: Optional[int]
    reason: str
    refusal: Optional[RollbackRefusal]
    state: LifecycleState

    def __post_init__(self) -> None:
        if self.rolled_back and self.refusal is not None:
            raise LifecycleRefused(
                "a rollback cannot have happened and been refused; one of the "
                "two is describing a different rollback"
            )
        if not self.rolled_back and self.refusal is None:
            raise LifecycleRefused(
                "a rollback that did not happen names why, or nobody can act "
                "on it"
            )
        if not self.reason.strip():
            raise LifecycleRefused(
                "a rollback records why -- an unexplained reversal is one "
                "nobody can audit afterwards"
            )

    def as_event(self) -> dict:
        return {
            "event_type": "mio.runtime.rollback",
            "rolled_back": self.rolled_back,
            "running_generation": self.running_generation,
            "from_generation": self.from_generation,
            "to_generation": self.to_generation,
            "refusal": self.refusal.value if self.refusal else None,
            "reason": self.reason,
            "state": self.state.value,
        }


def plan_rollback(
    *,
    current_generation: int,
    target_generation: Optional[int],
    reason: str,
    actor: str,
    target_verdict: Optional[BinaryVerdict],
) -> RollbackOutcome:
    """Decide whether a provider may return to an earlier generation.

    **The target is verified before anything moves.** A rollback to something
    that does not verify is not a return to a safe world; it is a second
    failure entered deliberately, and the node would have given up a working
    generation to reach it. So the order is: check the destination, then
    move -- never move and then discover.

    On every refusal the node stays on `current_generation`. That is the
    atomicity: there is no state in which this has half-happened, because the
    only mutation is the caller's, and it is told not to make it.

    Nothing here unmasks, grants, extends a lease or enforces. A provider
    that came back came back under the containment it had; a rollback that
    could widen would be a way to gain privilege by failing twice.
    """

    def refuse(refusal: RollbackRefusal, why: str) -> RollbackOutcome:
        return RollbackOutcome(
            rolled_back=False,
            running_generation=current_generation,
            from_generation=current_generation,
            to_generation=target_generation,
            reason=why,
            refusal=refusal,
            state=LifecycleState.ABSENT,
        )

    if not reason.strip():
        return refuse(
            RollbackRefusal.NO_REASON,
            "a rollback records why; an unexplained reversal is one nobody "
            "can audit afterwards",
        )
    if not actor.strip():
        return refuse(
            RollbackRefusal.NO_ACTOR,
            "a rollback records who performed it",
        )
    if target_generation is None:
        return refuse(
            RollbackRefusal.NO_PREDECESSOR,
            "there is no earlier generation to return to, so this node stays "
            "where it is rather than having nowhere to be",
        )
    if target_generation == current_generation:
        return refuse(
            RollbackRefusal.SAME_GENERATION,
            f"generation {target_generation} is already current; a rollback to "
            "it would record a reversal that did not happen",
        )
    if target_verdict is None or not target_verdict.admissible:
        refusals = target_verdict.refusals if target_verdict else (
            "the target was not verified at all",
        )
        return refuse(
            RollbackRefusal.TARGET_UNVERIFIABLE,
            "the generation this would return to does not verify "
            f"({'; '.join(refusals)}), so the node keeps the one it has. "
            "Rolling back into a second failure is not a recovery",
        )

    return RollbackOutcome(
        rolled_back=True,
        running_generation=target_generation,
        from_generation=current_generation,
        to_generation=target_generation,
        reason=reason,
        refusal=None,
        state=LifecycleState.STARTED,
    )
