"""`az-activated`: the only component that may widen what this node runs (#39).

The decision is the library's. `azazel_nexus.activation.ActivationController`
checks the verified generation, the lease, health and the commissioning
record, and decides per tier. This daemon carries that out against a service
manager, and adds the one thing a decision cannot have: **a rollback**.

## Activation is a transaction

A pass that enables three units and fails on the fourth has left the node in a
state nobody chose. Either the whole set is granted or none of it is, so a
failure re-masks everything this pass widened -- including the units that
succeeded.

Rolling *forward* is not available. The failure means the service manager did
not do what it was asked, and a component that responds to that by asking for
more is a component that has stopped believing its own error handling.

## If the rollback itself fails

It narrows further: mask everything governed, not just what this pass
touched. The direction is the invariant. There is no failure of a rollback
that is answered by widening.

## What it does not have

No shell. No command line. No unit name, path, argument or environment from a
caller. Units are addressed by a key from `units.UNIT_NAMES`, which is a
lookup and not an interpolation.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from azazel_nexus.activation import (
    ARTIFACT_TRANSPORT,
    LOCAL_MODEL_PROVIDER,
    REMOTE_INFERENCE_TRANSPORT,
    ActivationController,
    ActivationLease,
    ActivationOutcome,
    CORE_UNITS,
    EdgeBaselineState,
    UnitController,
    UnitDefinition,
    UnitState,
)
from azazel_nexus.audit import AuditLedger, AuditUnavailable
from azazel_nexus.commissioning import CommissioningRecord
from azazel_nexus.generation import GenerationStore

from azazel_nexus.model_runtime import RUNTIMES

from .mio_remoted import TRANSPORT
from .model_fetch import ENDPOINT_FOR
from .units import DbusUnitManager, UnitManager

__all__ = [
    "ActivationDaemon",
    "ManagedUnitController",
    "RollbackFailed",
    "wired_capabilities",
]


def wired_capabilities() -> frozenset:
    """What this **installed distribution** can actually serve.

    The library decides whether a unit may be granted and cannot answer this:
    what is wired is a fact about the runtime distribution, which the library
    is forbidden to import. So it is read here, from the thing itself, and
    passed in as evidence.

    Read from `ENDPOINT_FOR`, `RUNTIMES` and `TRANSPORT` rather than from a
    flag, a setting or a version string. A flag is a second place the truth is written down, and the one
    that is wrong is always the one nobody looked at. An empty table is not a
    disabled feature: it is a build in which no source symbol resolves to an
    endpoint, so `az-model-fetchd` would start and exit.

    A commissioned Source Registry fills the table. That is signed deployment
    data, and this function then reports the transport as wired without a line
    of code changing -- which is the point of deriving it.
    """

    wired = set()
    if ENDPOINT_FOR:
        wired.add(ARTIFACT_TRANSPORT)
    if RUNTIMES:
        wired.add(LOCAL_MODEL_PROVIDER)
    if TRANSPORT is not None:
        wired.add(REMOTE_INFERENCE_TRANSPORT)
    return frozenset(wired)


class RollbackFailed(Exception):
    """The node could not be returned to the state it started the pass in."""


class ManagedUnitController(UnitController):
    """Bridges the library's controller to a `UnitManager`.

    The library defines `unmask_and_enable` as the guarded entry point and
    forbids a subclass from overriding it; this implements the two unguarded
    verbs beneath it and records what it widened, so a failed pass knows what
    to take back.
    """

    def __init__(self, manager: UnitManager) -> None:
        self.manager = manager
        self.widened: list[str] = []

    def state(self, unit: str) -> UnitState:
        return self.manager.state(unit)

    def _mask(self, unit: str) -> None:
        self.manager.mask(unit)

    def _unmask_and_enable(self, unit: str) -> None:
        # Recorded before the call, not after. A call that fails part way
        # through has still changed something, and a rollback that only knows
        # about calls that returned cleanly would leave exactly that behind.
        self.widened.append(unit)
        self.manager.unmask_and_enable(unit)


@dataclass
class ActivationDaemon:
    """One activation pass per boot, with the rollback the decision cannot have."""

    generations: GenerationStore
    ledger: AuditLedger
    manager: UnitManager
    definitions: Sequence[UnitDefinition] = CORE_UNITS

    def activate(
        self,
        *,
        now: str,
        actor: str,
        lease: Optional[ActivationLease] = None,
        record: Optional[CommissioningRecord] = None,
        edge: Optional[EdgeBaselineState] = None,
        healthy: bool = True,
        wired: Optional[Sequence[str]] = None,
    ) -> ActivationOutcome:
        units = ManagedUnitController(self.manager)
        controller = ActivationController(
            units=units,
            generations=self.generations,
            ledger=self.ledger,
            definitions=self.definitions,
        )
        try:
            outcome = controller.activate(
                now=now,
                actor=actor,
                lease=lease,
                record=record,
                edge=edge,
                healthy=healthy,
                # `None` means "ask the distribution", which is what a node
                # does. A caller may pass a set to exercise a build other than
                # this one; it may not pass one to widen this one, because the
                # unit still starts nothing.
                wired=wired_capabilities() if wired is None else wired,
            )
        except AuditUnavailable:
            # The library attempts to narrow before it raises, but a failed
            # mask plus an unavailable ledger must not skip this layer's
            # broader fail-closed escalation.
            if controller.unmaskable:
                failures = self._remask_all(
                    now=now,
                    actor=actor,
                    event_type="activation.audit_failure_remasked",
                    error_type="AuditUnavailable",
                )
                if failures:
                    raise RollbackFailed(
                        "audit became unavailable while narrowing failed; these "
                        f"governed units remain unmasked: {sorted(failures)}"
                    )
            raise
        except Exception as exc:  # noqa: BLE001 - unexpected policy failure narrows
            failures = self._remask_all(
                now=now,
                actor=actor,
                event_type="activation.composition_failed",
                error_type=type(exc).__name__,
            )
            if failures:
                raise RollbackFailed(
                    "an unexpected activation error occurred and these governed "
                    f"units could not be remasked: {sorted(failures)}"
                ) from exc
            raise
        if controller.unmaskable:
            # The library could not narrow something. It recorded that and
            # kept withholding rather than letting the exception leave the
            # pass -- which is what would have stranded the units already
            # widened. Escalating is this layer's half.
            self._narrow_everything(
                now=now, actor=actor, after=sorted(controller.unmaskable)
            )
        if any(
            not verdict.granted and _is_failure(verdict) for verdict in outcome.verdicts
        ):
            self._roll_back(units, now=now, actor=actor, outcome=outcome)
        return outcome

    def _remask_all(
        self, *, now: str, actor: str, event_type: str, error_type: str
    ) -> list[str]:
        """Retry narrowing of every governed unit and record the attempt."""

        failures: list[str] = []
        for definition in self.definitions:
            try:
                self.manager.mask(definition.name)
            except Exception as exc:  # noqa: BLE001 - collect all failures
                failures.append(f"{definition.name}: {type(exc).__name__}")
        self._record(
            {
                "event_type": event_type,
                "error_type": error_type,
                "remask_failures": sorted(failures),
                "occurred_at": now,
                "actor": actor,
            }
        )
        return failures

    def _roll_back(
        self,
        units: ManagedUnitController,
        *,
        now: str,
        actor: str,
        outcome: ActivationOutcome,
    ) -> None:
        """Re-mask everything this pass widened. All of it, including successes."""

        taken_back: list[str] = []
        failures: list[str] = []
        for unit in units.widened:
            try:
                self.manager.mask(unit)
                taken_back.append(unit)
            except Exception as exc:  # noqa: BLE001 - recorded below, then escalated
                failures.append(f"{unit}: {exc}")

        self._record(
            {
                "event_type": "activation.rolled_back",
                "widened": sorted(units.widened),
                "masked_again": sorted(taken_back),
                "could_not_mask": sorted(failures),
                "occurred_at": now,
                "actor": actor,
            }
        )
        if failures:
            self._narrow_everything(now=now, actor=actor, after=failures)

    def _narrow_everything(self, *, now: str, actor: str, after: Sequence[str]) -> None:
        """A rollback that failed is answered by narrowing further, never less.

        Every governed unit, not only the ones this pass touched. The
        direction is the invariant: there is no failure here whose answer is
        to widen.
        """

        unreachable: list[str] = []
        for definition in self.definitions:
            try:
                self.manager.mask(definition.name)
            except Exception as exc:  # noqa: BLE001
                unreachable.append(f"{definition.name}: {exc}")
        self._record(
            {
                "event_type": "activation.rollback_failed",
                "after": sorted(after),
                "still_unreachable": sorted(unreachable),
                "occurred_at": now,
                "actor": actor,
            }
        )
        raise RollbackFailed(
            "the node could not be returned to the state it started this pass "
            f"in; {sorted(after)} would not mask, and {sorted(unreachable)} "
            "did not respond to the wider narrowing either"
        )

    def _record(self, event: dict) -> None:
        try:
            self.ledger.append(event)
        except AuditUnavailable:
            # The narrowing has already happened. Refusing to narrow because
            # the ledger is unavailable would mean the node stays wide while
            # nobody can write down that it should not be.
            pass


def _is_failure(verdict) -> bool:
    """A unit that was tried and failed, as opposed to one withheld by policy.

    A withheld unit is the decision working. A failed one is the service
    manager not doing what it was asked, and only the second calls for a
    rollback.
    """

    return verdict.reason.startswith("activation_failed")


def _run_once(
    *, manager: UnitManager, root: Path, now: str, actor: str
) -> ActivationOutcome:
    """Compose the existing decision engine with fixed persistent paths.

    Production evidence readers for the lease, commissioning signature,
    measured health and Edge baseline do not exist yet. They are therefore
    explicit absences, not guessed values or data loaded from unauthenticated
    files. ``healthy=False`` is important: the library API's test-friendly
    default is not evidence a production daemon may inherit.
    """

    state = root / "var/lib/azazel/state"
    daemon = ActivationDaemon(
        generations=GenerationStore(root / "var/lib/azazel/generations"),
        ledger=AuditLedger(state / "activation.jsonl"),
        manager=manager,
        definitions=CORE_UNITS,
    )
    outcome = daemon.activate(
        now=now,
        actor=actor,
        lease=None,
        record=None,
        edge=None,
        healthy=False,
        wired=wired_capabilities(),
    )
    if outcome.granted:
        # This composition has no producer for any admission evidence. A
        # grant here would mean a future change silently supplied authority.
        failures: list[str] = []
        for definition in CORE_UNITS:
            try:
                manager.mask(definition.name)
            except Exception as exc:  # noqa: BLE001 - fail closed on invariant break
                failures.append(f"{definition.name}: {type(exc).__name__}")
        raise RuntimeError(
            "production activation composed without authenticated evidence "
            "but the decision engine granted a unit; emergency remask failures: "
            f"{sorted(failures)}"
        )
    return outcome


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run one fail-closed activation pass against systemd's system bus.

    A zero exit status means the pass completed and its decision was recorded;
    it does **not** mean any unit was granted. Authenticated admission-input
    producers are not implemented, so this composition always supplies their
    explicit absence and cannot widen a unit.
    """

    if argv is None:
        argv = sys.argv[1:]
    if argv:
        print("az-activated accepts no command-line arguments", file=sys.stderr)
        return 2
    from .runtime_paths import ROOT

    invocation_id = os.environ.get("INVOCATION_ID", "")
    if (
        os.geteuid() != 0
        or not Path("/run/systemd/system").is_dir()
        or not re.fullmatch(r"[0-9a-fA-F]{32}", invocation_id)
        or ROOT != Path("/")
    ):
        print(
            "az-activated requires its root systemd service context and fixed "
            "host paths",
            file=sys.stderr,
        )
        return 1

    from .systemd_bus import SystemdBusSession

    now = (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )
    try:
        with SystemdBusSession.connect() as session:
            manager = DbusUnitManager(call=session)
            outcome = _run_once(
                manager=manager,
                root=Path("/"),
                now=now,
                actor="azazel-activated",
            )
    except Exception as exc:  # noqa: BLE001 - the service boundary fails closed
        print(
            f"az-activated failed before completing a safe pass: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 1

    reasons = sorted({verdict.reason.split(":", 1)[0] for verdict in outcome.verdicts})
    print(
        f"az-activated completed safely: granted=0, "
        f"withheld={len(outcome.withheld)}, reasons={','.join(reasons)}"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
