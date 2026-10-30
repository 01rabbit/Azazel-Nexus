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
    details: Mapping | None = None


@dataclass(frozen=True)
class Step:
    name: str
    status: str
    reason: str
    next_command: str


ORDER = (
    "installed-files", "host-preflight", "commissioning", "commission-review",
    "bootstrap-deployment", "bootstrap-selection", "knowledge-store", "knowledge-trust",
    "mission-pack", "fetch-commissioning", "model-import-fetched",
    # M24: the NOC and unit-state observers. Not enabled by the installer
    # (SPEC 2.3); this step is where an operator enables them.
    "operator-observers", "provider-admission",
    "activation-units", "integration-broker", "mio-configuration",
)

NOTICE = (
    "Read-only guidance; no actions performed. Provider admission is blocked. "
    "Enforcement readiness is not established; Edge retains decision and enforcement authority."
)


def evaluate(observations: Mapping[str, Observation], *, lab_host: bool = False) -> tuple[Step, ...]:
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
            steps.append(Step(name, "blocked", "HG-05: unmeasured; provider admission blocked"
                              + ("; unavailable on a lab host (LAB_HOST_MARKER)" if lab_host else ""),
                              "none available; unavailable on a lab host (LAB_HOST_MARKER)" if lab_host
                              else "azazel-nexus hil-preflight"))
            continue
        observation = observations.get(name, Observation(
            State.UNKNOWN, "observation unavailable; inspect local state", "none available; requires readable local evidence"))
        if (lab_host and observation.state is not State.COMPLETE
                and name in {"host-preflight", "commissioning", "commission-review", "model-import-fetched"}):
            observation = Observation(
                observation.state, observation.reason + "; unavailable on a lab host (LAB_HOST_MARKER); "
                + ("ordered flow stops here until this evidence is complete; later steps remain visible in setup"
                   if observation.state is not State.OPTIONAL else "optional step; ordered flow continues"),
                "none available; unavailable on a lab host (LAB_HOST_MARKER)")
        steps.append(Step(name, statuses[observation.state], observation.reason, observation.command))
    return tuple(steps)


def next_step(steps: tuple[Step, ...]) -> Step:
    """The first unresolved step; provider-admission always prevents exhaustion."""
    return next(step for step in steps if step.status in {"needed", "blocked"})
