"""Pure budget planning seam; it does not grant model admission or perform I/O.

The profile and exact counter must be tied by the caller to the admitted runtime,
model, tokenizer and chat template. The product session connects this seam to the opt-in MIO budget API.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Callable
from azazel_nexus.generation_budget import (effective_context_limit,validate_fixture_policy,
    FIXTURE_RESERVE_FRACTION,FIXTURE_MINIMUM_RESERVE_MS,FIXTURE_WEIGHTS,
    FIXTURE_SLACK,FIXTURE_MINIMUM_PROVIDER_MS)

TASKS = ('generate_hypotheses', 'identify_evidence_gaps', 'recommend')
WEIGHTS = FIXTURE_WEIGHTS


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
class BudgetSettings:
    reserve_fraction: float = FIXTURE_RESERVE_FRACTION
    minimum_reserve_ms: float = FIXTURE_MINIMUM_RESERVE_MS
    weights: tuple[int,int,int] = WEIGHTS
    slack: int = FIXTURE_SLACK
    minimum_provider_ms: tuple[float,float,float] = FIXTURE_MINIMUM_PROVIDER_MS

    def __post_init__(self):
        if (not _number(self.reserve_fraction) or not 0<self.reserve_fraction<1
                or not _number(self.minimum_reserve_ms) or self.minimum_reserve_ms<=0
                or type(self.weights) is not tuple or len(self.weights)!=3
                or any(not _integer(v,minimum=1) for v in self.weights)
                or not _integer(self.slack)
                or type(self.minimum_provider_ms) is not tuple or len(self.minimum_provider_ms)!=3
                or any(not _number(v) or v<=0 for v in self.minimum_provider_ms)):
            raise ValueError('invalid_budget_settings')
        validate_fixture_policy(self.reserve_fraction,self.minimum_reserve_ms,self.weights,self.slack,self.minimum_provider_ms)

    def reserve(self, seconds):
        return max(self.minimum_reserve_ms/1000,seconds*self.reserve_fraction)


@dataclass(frozen=True)
class TaskBudget:
    """Tuple offered to the MIO compiler; profile values are explicit."""
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
    slack: int = FIXTURE_SLACK
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
    """MIO hook selection shape; runtime validates the concrete receipt."""
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
                 counter: Callable[[str, str], int] | None, clock: Callable[[], float],
                 verified_context_limit, configured_context_limit, settings=None):
        if (type(profile) is not BudgetProfile or not _number(submitted)
                or not _number(deadline_s) or not 0 < deadline_s <= 30):
            raise ValueError('invalid_budget_deadline')
        self.profile = profile
        self.end = submitted + deadline_s
        self.settings = settings if settings is not None else BudgetSettings()
        if (type(self.settings) is not BudgetSettings
                or profile.context_limit!=effective_context_limit(verified_context_limit,configured_context_limit)
                or profile.slack!=self.settings.slack
                or any(task.minimum_provider_s!=minimum/1000 for task,minimum in zip(profile.tasks,self.settings.minimum_provider_ms))):
            raise ValueError('invalid_budget_profile_context_or_policy')
        self.reserve = self.settings.reserve(deadline_s)
        self.allocated_total = 0.
        self.provider_cap = max(0.,deadline_s-self.reserve)
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
        available = min(self.end-now-remaining_reserve,self.provider_cap-self.allocated_total)
        weighted = available * self.settings.weights[idx] / sum(self.settings.weights[idx:])
        future_minimum = sum(item.minimum_provider_s for item in self.profile.tasks[idx + 1:])
        allocation = min(weighted, available - future_minimum)
        if (count > spec.input_limit
                or count + spec.output_cap + self.profile.slack > self.profile.context_limit
                or allocation < spec.minimum_provider_s):
            raise BudgetRefused(BudgetReason.BUDGET_EXHAUSTED)
        self._planned = True
        self.allocated_total += allocation
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
