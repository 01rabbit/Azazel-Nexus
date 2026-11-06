"""Pure budget planning seam; it does not grant model admission or perform I/O.

The profile and exact counter must be tied by the caller to the admitted runtime,
model, tokenizer and chat template. This seam is not yet connected to MIO.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Callable

TASKS = ('generate_hypotheses', 'identify_evidence_gaps', 'recommend')
WEIGHTS = (45, 20, 35)


class BudgetReason(str, Enum):
    BUDGET_EXHAUSTED = 'budget_exhausted'
    COUNT_UNKNOWN = 'count_unknown'
    TRUNCATED = 'truncated'
    STOP_UNCONFIRMED = 'stop_unconfirmed'
    TIMEOUT = 'timeout'
    MALFORMED = 'malformed'


class BudgetRefused(ValueError):
    def __init__(self, reason: BudgetReason):
        self.reason = reason
        super().__init__(reason.value)


class CleanupState(str, Enum):
    NOT_NEEDED = 'not_needed'
    PENDING = 'pending'
    CONFIRMED = 'confirmed'
    UNCONFIRMED = 'unconfirmed'


def settle_cleanup(state: CleanupState, reason: str, *, now: float, end: float) -> CleanupState:
    """Pure monotonic decision; the caller must persist it and fence dispatch."""
    if state is not CleanupState.PENDING or not _number(now) or not _number(end):
        raise ValueError('invalid_cleanup_transition')
    if reason == 'stop_confirmed' and now < end:
        return CleanupState.CONFIRMED
    if reason in ('stop_confirmed', 'stop_failed', 'confirmation_deadline',
                  'observation_lost', 'restart_unconfirmed'):
        return CleanupState.UNCONFIRMED
    raise ValueError('invalid_cleanup_reason')


def _integer(value, *, minimum=0):
    return type(value) is int and value >= minimum


def _number(value, *, minimum=0):
    return type(value) in (int, float) and math.isfinite(value) and value >= minimum


@dataclass(frozen=True)
class TaskBudget:
    """Tuple offered to a future MIO compiler; no profile values are invented here."""
    task: str
    input_limit: int
    output_cap: int
    output_min: int
    minimum_provider_s: float

    def __post_init__(self):
        if (self.task not in TASKS or not _integer(self.input_limit, minimum=1)
                or not _integer(self.output_min, minimum=1)
                or not _integer(self.output_cap, minimum=self.output_min)
                or self.output_cap > 768 or not _number(self.minimum_provider_s)
                or self.minimum_provider_s == 0):
            raise ValueError('invalid_task_budget')


@dataclass(frozen=True)
class BudgetProfile:
    """Caller-supplied, verified tuple and three task reservations."""
    profile_id: str
    context_limit: int
    tasks: tuple[TaskBudget, TaskBudget, TaskBudget]
    slack: int = 32
    origin: str = 'fixture'

    def __post_init__(self):
        if (type(self.profile_id) is not str or not self.profile_id
                or len(self.profile_id) > 64 or not _integer(self.context_limit, minimum=1)
                or not _integer(self.slack) or self.origin not in ('fixture', 'verified')
                or type(self.tasks) is not tuple or len(self.tasks) != 3
                or any(type(task) is not TaskBudget for task in self.tasks)
                or tuple(task.task for task in self.tasks) != TASKS):
            raise ValueError('invalid_budget_profile')


@dataclass(frozen=True)
class Allocation:
    task: str
    input_tokens: int
    input_limit: int
    output_cap: int
    context_limit: int
    context_slack: int
    provider_seconds: float
    count_kind: str = 'exact'


@dataclass(frozen=True)
class SelectionReceipt:
    """MIO hook return boundary; validation and connection remain future work."""
    coverage: str
    input_units: int
    selected_units: int
    omitted_units: int


class BudgetPlanner:
    """One absolute deadline; count each final prompt before dispatch.

    Caller supplies a counter for the exact request including chat template and
    schema injection. Counter absence/failure is refusal, never a character guess.
    """
    def __init__(self, profile: BudgetProfile, *, submitted: float, deadline_s: float,
                 counter: Callable[[str, str], int] | None, clock: Callable[[], float]):
        if (type(profile) is not BudgetProfile or not _number(submitted)
                or not _number(deadline_s) or not 0 < deadline_s <= 30):
            raise ValueError('invalid_budget_deadline')
        self.profile = profile
        self.end = submitted + deadline_s
        self.reserve = max(.5, deadline_s * .1)
        self.counter = counter
        self.clock = clock
        self.next_task = 0
        self._planned = False

    def plan(self, task: str, prompt: str) -> Allocation:
        now = self.clock()
        if not _number(now):
            raise ValueError('invalid_clock')
        if self.next_task >= 3 or self._planned or task != TASKS[self.next_task]:
            raise BudgetRefused(BudgetReason.BUDGET_EXHAUSTED)
        if now >= self.end:
            raise BudgetRefused(BudgetReason.TIMEOUT)
        if type(prompt) is not str or self.counter is None:
            raise BudgetRefused(BudgetReason.COUNT_UNKNOWN)
        try:
            count = self.counter(task, prompt)
        except Exception:
            raise BudgetRefused(BudgetReason.COUNT_UNKNOWN) from None
        if not _integer(count):
            raise BudgetRefused(BudgetReason.COUNT_UNKNOWN)
        now = self.clock()
        if not _number(now):
            raise ValueError('invalid_clock')
        idx = self.next_task
        spec = self.profile.tasks[idx]
        # R/2 is held for final processing; R/6 for each remaining task.
        remaining_reserve = self.reserve / 2 + self.reserve * (3 - idx) / 6
        available = self.end - now - remaining_reserve
        weighted = available * WEIGHTS[idx] / sum(WEIGHTS[idx:])
        future_minimum = sum(item.minimum_provider_s for item in self.profile.tasks[idx + 1:])
        allocation = min(weighted, available - future_minimum)
        if (count > spec.input_limit
                or count + spec.output_cap + self.profile.slack > self.profile.context_limit
                or allocation < spec.minimum_provider_s):
            raise BudgetRefused(BudgetReason.BUDGET_EXHAUSTED)
        self._planned = True
        return Allocation(task, count, spec.input_limit, spec.output_cap,
                          self.profile.context_limit, self.profile.slack, allocation)

    def completed(self, task: str) -> None:
        if self.next_task >= 3 or not self._planned or task != TASKS[self.next_task]:
            raise BudgetRefused(BudgetReason.BUDGET_EXHAUSTED)
        self.next_task += 1
        self._planned = False


def mio_budget_for_task(planner: BudgetPlanner, task: str, *, budget_type=None):
    """Create the agreed MIO tuple without importing MIO in CORE-only environments.

    The caller must keep the resulting callback inside the authorized provider
    boundary. Planning, dispatch and result validation remain separate steps.
    """
    if (type(planner) is not BudgetPlanner or planner.next_task >= 3
            or planner._planned or task != TASKS[planner.next_task]):
        raise BudgetRefused(BudgetReason.BUDGET_EXHAUSTED)
    if budget_type is None:
        from azazel_mio.budget import GenerationBudget
        budget_type = GenerationBudget
    spec = planner.profile.tasks[planner.next_task]
    input_limit = min(spec.input_limit,
                      planner.profile.context_limit - spec.output_cap - planner.profile.slack)
    if input_limit <= 0:
        raise BudgetRefused(BudgetReason.BUDGET_EXHAUSTED)

    def count_tokens(prompt):
        try:
            if type(prompt) is not str or planner.counter is None or planner.clock() >= planner.end:
                return None
            count = planner.counter(task, prompt)
            if planner.clock() >= planner.end or not _integer(count):
                return None
            return count
        except Exception:
            return None

    return budget_type(input_tokens=input_limit, output_tokens=spec.output_cap,
                       context_limit=planner.profile.context_limit,
                       safety_margin=planner.profile.slack, count_tokens=count_tokens)
