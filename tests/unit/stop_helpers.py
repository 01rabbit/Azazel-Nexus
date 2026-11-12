"""Fakes for the Knowledge Context broker's stop contract (docs: stop contract).

``ContextdModel`` is the broker's runtime state as the manager reports it:
running or not, a pending job, and what a ``StopUnit`` does to both. It is
driven by a fake clock so that "within 20 s" is exact and nothing sleeps.
``ModelManager`` is a ``RecordingUnitManager`` whose answer for the broker's
inactivity comes from that model; ``authority`` is the real
``ContextdStopAuthority`` over the model's two verbs.
"""

from __future__ import annotations

from azazel_nexus.activation import CORE_UNITS
from azazel_nexus_runtime.units import (
    CONTEXTD_UNIT,
    ContextdStopAuthority,
    RecordingUnitManager,
    UnitOperationFailed,
)

CTX = CONTEXTD_UNIT
JOB = (5, "/org/freedesktop/systemd1/job/5")
NO_JOB = (0, "/")


class FakeClock:
    """Monotonic time that only advances when something sleeps."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class ContextdModel:
    """The broker as the manager sees it.

    ``stop_takes``: seconds from StopUnit until the broker is inactive with no
    job. ``stop_works=False``: StopUnit is accepted and nothing changes.
    """

    def __init__(self, clock: FakeClock, *, running: bool = False, job=NO_JOB,
                 stop_takes: float = 1.0, stop_works: bool = True,
                 timeline: list | None = None) -> None:
        self.clock = clock
        self.running = running
        self.job = job
        self.stop_takes = stop_takes
        self.stop_works = stop_works
        self.stopped_at: float | None = None
        self.stops = 0
        self.timeline = timeline if timeline is not None else []

    def _settle(self) -> None:
        if (self.stopped_at is not None and self.stop_works
                and self.clock() >= self.stopped_at + self.stop_takes):
            self.running = False
            self.job = NO_JOB

    def inactive(self) -> bool:
        self._settle()
        return not self.running

    def current_job(self, unit: str):
        self._settle()
        return self.job

    def stop(self) -> str:
        self.stops += 1
        self.timeline.append(("stop", CTX))
        self.stopped_at = self.clock()
        return "/org/freedesktop/systemd1/job/9"


class ModelManager(RecordingUnitManager):
    """A recording manager whose broker inactivity comes from the model."""

    def __init__(self, model: ContextdModel, *, enabled=(), **kwargs) -> None:
        super().__init__((d.name for d in CORE_UNITS), **kwargs)
        for unit in enabled:
            self.unmask_and_enable(unit)
        self.calls.clear()
        self.model = model
        self.timeline = model.timeline
        self.on_mask = None

    def mask(self, unit: str) -> None:
        if self.on_mask is not None:
            self.on_mask(unit)
        super().mask(unit)

    def is_inactive(self, unit: str) -> bool:
        if unit == CTX:
            return self.model.inactive()
        return super().is_inactive(unit)

    def is_active(self, unit: str) -> bool:
        if unit == CTX:
            return not self.model.inactive()
        return super().is_active(unit)


def authority(model: ContextdModel) -> ContextdStopAuthority:
    return ContextdStopAuthority(stop=model.stop, job=model.current_job)


def failing_authority() -> ContextdStopAuthority:
    def fail(*_args):
        raise UnitOperationFailed("systemd D-Bus call did not complete")

    return ContextdStopAuthority(stop=fail, job=fail)


def granted_marker():
    """A broker's grant marker that exists and never changes (for tests that
    are about something else than the grant)."""
    from azazel_nexus_runtime.activation_markers import MarkerIdentity
    return MarkerIdentity(1, 2, 3)
