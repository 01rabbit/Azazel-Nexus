"""`az-watchdog`: it can narrow, and it has no way to widen (#41).

Three conditions, three different records, three different operator actions:

| Condition | Detected by | Answer |
| --- | --- | --- |
| deadline exceeded | `degradation.call_with_deadline`, with an injected clock | fence the unit |
| daemon unhealthy | a structured probe that answers or does not | fence the unit |
| generation mismatch | re-deriving the digest from the tree | fence **everything** |

The third is different in kind. A deadline or an unhealthy daemon is one
capability failing; a generation whose tree no longer hashes to what was
promoted means the configuration every unit is running under is not the one
that was validated, and narrowing one unit would leave the rest running under
it.

## It cannot widen. Structurally, not by convention.

There is no import of `ActivationAuthorization` here, no mint, and no call to
`unmask_and_enable` -- `azazel_nexus`'s own static scan keeps the widening
path inside `activation.py`, and `tests/unit/test_runtime_watchdog.py` checks
this module against the same rule.

So a watchdog that concludes a masked unit ought to be running cannot act on
that. Returning a unit to service is `az-activated`'s decision, against a
revalidated generation and a valid lease, on the next boot.

## A fence survives the watchdog

Held on disk and reloaded at startup. A fence that a process restart cleared
would be a fence that the failure it is fencing could clear, by taking the
watchdog down with it.

## Narrowing needs no permission, including from the ledger

If the audit ledger cannot be written, the fence still happens. Refusing to
narrow because nobody can write down that the node narrowed would leave the
node wide *and* unrecorded, which is worse on both counts.

## Nothing here waits

`hanging` is modelled with a deadline and an injected clock (Nexus#30). No
test sleeps, and the static scan in the degradation tests already refuses
`sleep` in that module; this one is held to the same rule.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Optional, Sequence

from azazel_nexus.audit import AuditChainBroken, AuditLedger, AuditUnavailable
from azazel_nexus.degradation import DeadlineExceeded, call_with_deadline
from azazel_nexus.generation import GenerationRefused, GenerationStore

from .principal import PrincipalClass
from .protocol import Argument, ArgumentKind, Verb, VerbRegistry
from .units import UNIT_NAMES, UnitKey, UnitManager, resolve

__all__ = [
    "FenceReason",
    "FenceStore",
    "REGISTRY",
    "VERBS",
    "WatchdogService",
]


DETAIL_MAX_LENGTH = 256


class FenceReason(str, Enum):
    """Why a unit was fenced. One value per condition, never merged."""

    DEADLINE_EXCEEDED = "deadline_exceeded"
    UNHEALTHY = "unhealthy"
    #: Fail-closed because stored fences could not be read; not a unit observation.
    FENCE_STORE_UNREADABLE = "fence_store_unreadable"
    GENERATION_MISMATCH = "generation_mismatch"
    RESTART_INTERRUPTED = "restart_interrupted"
    #: A supervised provider used every restart its generation allowed (#114).
    #:
    #: Not `RESTART_INTERRUPTED`. That one means a restart was cut short and
    #: nobody knows what state it left; this means the restarts completed,
    #: each one failed, and the count ran out. An operator sent to look for an
    #: interrupted restart when the fact is "it died three times" has been
    #: sent to the wrong place.
    RESTART_BUDGET_SPENT = "restart_budget_spent"


VERBS = (
    Verb(
        "watchdog.status",
        admits=frozenset({PrincipalClass.ROOT, PrincipalClass.OPERATOR}),
    ),
    Verb(
        "watchdog.probe",
        arguments=(
            Argument("unit", ArgumentKind.ENUM, choices=tuple(k.value for k in UnitKey)),
            Argument("budget_ms", ArgumentKind.ORDINAL, maximum=60_000),
        ),
        admits=frozenset({PrincipalClass.ROOT}),
    ),
)

REGISTRY = VerbRegistry(VERBS)


class FenceStore:
    """Fences on disk, so a restart does not clear them.

    A fence held only in memory is one the failure being fenced can clear, by
    taking the watchdog down with it -- which is the failure most likely to
    take a watchdog down.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> dict[str, str]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError):
            # An unreadable fence file is not "no fences". Everything this
            # daemon governs stays fenced until somebody looks, because the
            # alternative is a corrupt file silently returning a node to
            # service.
            return {unit: FenceReason.FENCE_STORE_UNREADABLE.value for unit in UNIT_NAMES.values()}
        if not isinstance(raw, dict):
            return {unit: FenceReason.FENCE_STORE_UNREADABLE.value for unit in UNIT_NAMES.values()}
        return {
            str(unit): str(reason)
            for unit, reason in raw.items()
            if unit in set(UNIT_NAMES.values())
        }

    def save(self, fences: dict[str, str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(fences, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )


@dataclass
class WatchdogService:
    """Detects, narrows, records. Never the other direction.

    Startup re-masks stored fences without recording a transition. An
    unreadable fence file likewise fails closed without creating a record.
    """

    manager: UnitManager
    ledger: AuditLedger
    fences: FenceStore
    generations: Optional[GenerationStore] = None
    #: Monotonic milliseconds, injected. Nothing here reads a clock.
    clock: Callable[[], int] = lambda: 0

    def __post_init__(self) -> None:
        self._fenced = self.fences.load()
        self._pending: dict[str, list[dict]] = {}
        self._reapply()

    def _reapply(self) -> None:
        """Mask everything the stored fences name, at startup.

        Persisting a fence is bookkeeping; this is what makes it a fence. A
        watchdog that loaded its fences and left the units running would have
        survived the restart with a list of things it believes are stopped.

        It also settles what a crash between masking and persisting leaves
        behind: whichever of the two happened, the next start reconciles.
        """

        for unit in sorted(self._fenced):
            try:
                self.manager.mask(unit)
            except Exception:  # noqa: BLE001 - it stays fenced regardless
                pass

    @property
    def fenced(self) -> dict[str, str]:
        return dict(self._fenced)

    # -- detection --------------------------------------------------------

    def probe(self, key: str, *, budget_ms: int, now: str, call: Callable[[], bool]) -> bool:
        """Ask a daemon whether it is well, inside a budget.

        A daemon that does not answer is not healthy: an unanswered probe and
        a negative answer are both "not established", and neither is "fine".
        They are recorded as different reasons because the operator's next
        step differs.
        """

        unit = resolve(key)
        try:
            healthy = call_with_deadline(call, budget_ms=budget_ms, clock=self.clock)
        except DeadlineExceeded:
            self._fence(unit, FenceReason.DEADLINE_EXCEEDED, now=now, detail="probe_deadline_exceeded")
            return False
        if not healthy:
            self._fence(unit, FenceReason.UNHEALTHY, now=now, detail="the daemon reported itself unwell")
            return False
        return True

    def check_generation(self, *, now: str) -> bool:
        """Re-derive the current generation's digest from its tree.

        A mismatch fences **everything**, not one unit. The configuration
        every unit is running under is not the one that was validated, and
        narrowing a single unit would leave the rest running under it.
        """

        if self.generations is None:
            return True
        current = self.generations.current()
        if current is None:
            return True
        try:
            self.generations.verify(current.number)
        except GenerationRefused:
            for unit in sorted(UNIT_NAMES.values()):
                self._fence(
                    unit, FenceReason.GENERATION_MISMATCH, now=now, detail="generation_verification_refused"
                )
            return False
        return True

    def note_interrupted_restart(self, key: str, *, now: str, detail: str) -> None:
        unit = resolve(key)
        self._fence(unit, FenceReason.RESTART_INTERRUPTED, now=now, detail=detail)

    def note_restart_budget_spent(self, key: str, *, now: str, detail: str) -> None:
        """A supervised provider ran out of restarts. Fence its unit (#114).

        The supervisor holds the count and this holds the consequence. Keeping
        them apart is the same separation the rest of this daemon has: the
        component that **observes** a failure is not the component that
        **narrows** on it, and neither of them can widen.

        `key` is a `UnitKey` value, resolved through the fixed table. There is
        no path by which a caller names an arbitrary unit -- a supervisor that
        could would be a supervisor that fences anything it liked by failing.
        """

        unit = resolve(key)
        self._fence(unit, FenceReason.RESTART_BUDGET_SPENT, now=now, detail=detail)

    # -- narrowing --------------------------------------------------------

    def _fence(self, unit: str, reason: FenceReason, *, now: str, detail: str) -> None:
        """Mask, persist, then record -- and each step survives the others failing.

        The order between masking and persisting is not load-bearing, and an
        earlier version of this docstring claimed it was. A crash between them
        is reconciled by `_reapply` at the next start, whichever happened
        first. What *is* load-bearing is that none of the three can stop the
        other two: a unit that will not mask is still fenced, a fence that
        cannot be written to disk is still in force for this process, and a
        record that cannot be appended does not undo any of it.

        The record is last because it is the step whose failure matters least
        at the moment it fails -- and refusing to narrow because nobody can
        write down that the node narrowed would leave it wide *and*
        unrecorded.

        Identical observations still mask and persist, but create no event.
        Failed appends remain queued in memory, including their original
        prior state, reason, timestamp and detail. A later observation of the
        same unit retries them in order, even if the reason has since changed.
        Each per-unit list can grow while the ledger stays down and the reason
        keeps changing: each entry is a real observed transition, bounded by
        observations. Successful appends remove them; these pending lists are
        lost on restart.
        Startup reapplication (including unreadable-file fail-closed fences)
        creates no transition and therefore no record.
        """

        previous_reason = self._fenced.get(unit)
        try:
            self.manager.mask(unit)
        except Exception:  # noqa: BLE001 - the fence is recorded regardless
            # A unit that will not mask is still fenced as far as this daemon
            # is concerned: it will not be returned to service, and the
            # failure is in the record below.
            pass
        self._fenced[unit] = reason.value
        try:
            self.fences.save(self._fenced)
        except OSError:
            pass
        if previous_reason != reason.value:
            self._pending.setdefault(unit, []).append(
                {
                    "event_type": "watchdog.fenced",
                    "unit": unit,
                    "reason": reason.value,
                    "detail": "".join(
                        char if 32 <= ord(char) <= 126 else " "
                        for char in detail[:DETAIL_MAX_LENGTH]
                    ),
                    "occurred_at": now,
                    "previous_state": "in_service" if previous_reason is None else "fenced",
                    "previous_reason": previous_reason,
                    "state": "fenced",
                }
            )
        pending = self._pending.get(unit, [])
        while pending:
            try:
                self.ledger.append(pending[0])
            except (AuditUnavailable, AuditChainBroken):
                # Narrowing stands; retain the actual transition for retry.
                return
            pending.pop(0)
        self._pending.pop(unit, None)

    # -- the socket -------------------------------------------------------

    def handle(self, request) -> dict:
        if request.verb.name == "watchdog.status":
            return {"fenced": self.fenced}
        raise NotImplementedError(
            "watchdog.probe is driven by the service loop in #42, which is "
            "what supplies the call it times"
        )


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stop: Callable[[], bool] = lambda: False,
    ready: Optional[Callable[[], None]] = None,
) -> int:
    from .principal import PrincipalPolicy
    from .runtime_paths import audit_sink, socket_path, watchdog_state_dir
    from .serve import serve_forever
    from .units import DbusUnitManager

    def refuse(method: str, unit: str) -> object:
        raise NotImplementedError(
            "a D-Bus connection is supplied by the service manager; running "
            "this daemon outside one is what the E2E harness does, and it "
            "injects its own"
        )

    service = WatchdogService(
        manager=DbusUnitManager(call=refuse),
        ledger=AuditLedger(watchdog_state_dir() / "watchdog.jsonl"),
        fences=FenceStore(watchdog_state_dir() / "fences.json"),
    )
    return serve_forever(
        path=socket_path("watchdog"),
        registry=REGISTRY,
        policy=PrincipalPolicy.resolve(),
        audit=audit_sink("watchdog"),
        handler=service.handle,
        stop=stop,
        ready=ready,
    )


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
