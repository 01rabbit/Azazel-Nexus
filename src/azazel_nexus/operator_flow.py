"""Pure setup step evaluation. Observations are scoped facts, never grants."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum


class State(str, Enum):
    COMPLETE = "complete"
    MISSING = "missing"
    REFUSED = "refused"
    UNKNOWN = "unknown"
    OPTIONAL = "optional"


@dataclass(frozen=True)
class Observation:
    state: State
    reason: str
    command: str


@dataclass(frozen=True)
class Step:
    name: str
    status: str
    reason: str
    next_command: str


ORDER = (
    "installed-files", "host-preflight", "commissioning", "commission-review",
    "bootstrap-deployment", "bootstrap-selection", "knowledge-store", "knowledge-trust",
    "mission-pack", "fetch-commissioning", "model-import-fetched", "provider-admission",
    "activation-units",
)

NOTICE = (
    "Read-only guidance; no actions performed. Provider admission is blocked. "
    "Enforcement readiness is not established; Edge retains decision and enforcement authority."
)


def evaluate(observations: Mapping[str, Observation]) -> tuple[Step, ...]:
    """Evaluate all steps in order, retaining explicit uncertainty and scope.

    COMPLETE means only the named read succeeded. Missing evidence cannot be
    upgraded by a later step. No caller-supplied HG-05 value can admit a provider.
    """
    statuses = {
        State.COMPLETE: "done", State.MISSING: "needed", State.REFUSED: "blocked",
        State.UNKNOWN: "needed", State.OPTIONAL: "not-applicable",
    }
    steps = []
    for name in ORDER:
        if name == "provider-admission":
            steps.append(Step(name, "blocked", "HG-05: unmeasured; provider admission blocked",
                              "azazel-nexus hil-preflight"))
            continue
        observation = observations.get(name, Observation(
            State.UNKNOWN, "observation unavailable; inspect local state", "azazel-nexus setup"))
        steps.append(Step(name, statuses[observation.state], observation.reason, observation.command))
    return tuple(steps)


def next_step(steps: tuple[Step, ...]) -> Step:
    """The first unresolved step; provider-admission always prevents exhaustion."""
    return next(step for step in steps if step.status in {"needed", "blocked"})
