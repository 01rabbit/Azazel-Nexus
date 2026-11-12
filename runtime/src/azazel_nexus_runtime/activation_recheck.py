"""`az-activation-recheck`: the periodic check of the Knowledge Context broker's grant.

`docs/activation-observe-baseline.md` ("Stopping a granted broker"). The main
pass (`az-activated`) runs once per boot, so nothing in it notices an approval
expiring, an operator being revoked or health being lost while the broker is
running. This runs every `RECHECK_PERIOD` (a timer, `hardening.RECHECK_UNIT`)
and does one thing: when the pass would no longer grant the broker, it
withdraws the broker (`activation_withdraw.withdraw_contextd`).

It never widens and never decides for any other unit:

* it takes the pass lock without waiting; if the main pass (or another
  recheck) holds it, it changes nothing, writes nothing to the ledger, prints
  one line and exits 0;
* it acts only if the broker has a marker, is not masked, or is not inactive
  or has a job; with none of those there is nothing to withdraw and it ends
  without collecting anything;
* the verdict (`contextd_verdict`) is a pure function of inputs collected by
  `collect_pass_inputs`, which only reads. Collection failing is a withhold;
* it does not call `activate`, write markers for other units, mask another
  unit, or raise a floor (approval retirement, below, is the one separate
  write, and only on an explicit operator revocation).
"""

from __future__ import annotations

import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from azazel_nexus.activation import (
    CORE_UNITS,
    UnitTier,
    common_withholding_reason,
)
from azazel_nexus.audit import AuditLedger
from azazel_nexus.generation import GenerationStore

from .activation_budget import PassBudgetExpired, bind_remaining, check_budget
from .activation_lock import (
    PassLockBusy, PassLockDirectoryMissing, PassLockRefused, acquire_pass_lock,
)
from .activation_markers import contextd_marker_present
from .activation_pass import PassInputs, collect_pass_inputs
from .activation_retire import (
    RetireRefused, resume_pending_retirement, retire_if_revoked, retirement_pending,
)
from .activation_withdraw import NO_JOB, WithdrawalUnconfirmed, withdraw_contextd
from .units import (
    CONTEXTD_UNIT,
    ContextdStopAuthority,
    DbusUnitManager,
    UnitManager,
)

__all__ = ["ContextdVerdict", "contextd_triggers", "contextd_verdict", "main", "run_recheck"]

ACTOR = "azazel-activation-recheck"
#: One monotonic budget for the recheck's bus work, from before the bus
#: connects. Bus work and the finalizer end by `budget - RECHECK_RECORD_SECONDS`
#: (16 s), which keeps the hold at 20 s or less before the records, strictly
#: less than `activated.PASS_LOCK_WAIT_SECONDS` (25 s). The records are
#: appended inside the lock (the ledger's append has no lock of its own); the
#: append is local file I/O and is not time-bounded. The last
#: `RECHECK_RECORD_SECONDS` of the budget are left for it.
#: `azazel-activation-recheck.service` has `TimeoutStartSec=40s`.
RECHECK_BUDGET_SECONDS = 18.0
RECHECK_RECORD_SECONDS = 2.0
RECHECK_FINALIZER_SECONDS = 5.0
#: Retirement and input collection end this long after the start; collection
#: that has not finished is a withhold.
RECHECK_COLLECT_SECONDS = 6.0
#: The wiring set is read only to answer "is this capability built in".
_CONTEXTD_DEFINITION = next(d for d in CORE_UNITS if d.name == CONTEXTD_UNIT)

@dataclass(frozen=True)
class ContextdVerdict:
    """Whether the pass would grant the broker now, and why not."""

    granted: bool
    reason: str

    @property
    def label(self) -> str:
        """The fixed part of the reason (no digest, no free text)."""
        return self.reason.split(":", 1)[0]


def contextd_verdict(inputs: Optional[PassInputs], now: str, *,
                     wired=None, retirement_blocked: bool = False) -> ContextdVerdict:
    """Would the main pass grant the Knowledge Context broker, given `inputs`?

    Pure: it reads `inputs` and the wiring set and nothing else, and it calls
    none of `activate`, the marker writers, the floor raise or the ledger.
    The conditions are the library's own (`common_withholding_reason`, the
    ones a SUPPORTING unit meets in `ActivationController`), applied to the
    verified lease, health and generation digest the collection produced.
    Missing or incomplete inputs withhold, and so does an approval
    retirement that is pending or failed (`retirement_blocked`): the main
    pass grants nothing in that state either.

    Differences from the main pass that are not modelled here: Edge evidence
    and the floors are inputs to `complete` (collection), not re-derived; a
    pass that would withhold for a reason `collect_pass_inputs` accepts is
    not matched, which can only leave the broker running, never grant it.
    """
    if retirement_blocked:
        return ContextdVerdict(False, "retirement_pending")
    if type(inputs) is not PassInputs:
        return ContextdVerdict(False, "inputs_unavailable")
    if (not inputs.complete or inputs.lease is None or inputs.healthy is not True
            or type(inputs.generation_digest) is not str):
        return ContextdVerdict(False, "inputs_incomplete")
    if _CONTEXTD_DEFINITION.tier is not UnitTier.SUPPORTING:
        return ContextdVerdict(False, "tier_not_supporting")
    if wired is None:
        from .activated import wired_capabilities
        wired = wired_capabilities()
    reason = common_withholding_reason(
        _CONTEXTD_DEFINITION, wired=wired, healthy=True, lease=inputs.lease,
        now=now, generation_digest=inputs.generation_digest)
    if reason is not None:
        return ContextdVerdict(False, reason)
    return ContextdVerdict(True, "granted")


def contextd_triggers(manager: UnitManager, authority: ContextdStopAuthority,
                      root: Path) -> tuple[str, ...]:
    """What, if anything, makes the broker worth evaluating.

    A marker, a unit-file state other than exactly `masked` (`masked-runtime`
    is not it), or an ActiveState other than `inactive`/`failed`, or a job. A
    read that fails counts: an unreadable broker is evaluated, not assumed
    quiet.
    """
    found: list[str] = []
    try:
        if contextd_marker_present(root):
            found.append("marker")
    except Exception:  # noqa: BLE001 - unreadable is evaluated
        found.append("marker_unreadable")
    try:
        if authority.file_state(CONTEXTD_UNIT) != "masked":
            found.append("not_masked")
    except Exception:  # noqa: BLE001
        found.append("state_unreadable")
    try:
        # Exactly `inactive`: a unit left `failed` is a trigger too (it is
        # withdrawn, and a withdrawal accepts `failed` as quiet).
        if authority.active_state(CONTEXTD_UNIT) != "inactive":
            found.append("not_inactive")
        elif authority.job(CONTEXTD_UNIT) != NO_JOB:
            found.append("job")
    except Exception:  # noqa: BLE001
        found.append("activity_unreadable")
    return tuple(found)


def run_recheck(
    *, manager: UnitManager, authority: ContextdStopAuthority, root: Path, now: str,
    producers, invocation_id: str, retirement=None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    started: Optional[float] = None,
    budget_seconds: float = RECHECK_BUDGET_SECONDS,
    record_seconds: float = RECHECK_RECORD_SECONDS,
    finalizer_seconds: float = RECHECK_FINALIZER_SECONDS,
    collect_seconds: float = RECHECK_COLLECT_SECONDS,
) -> int:
    """One recheck under the pass lock; the process exit status.

    One budget (`RECHECK_BUDGET_SECONDS`, counted from `started`, which the
    entry point takes before it connects to the bus) bounds the lock hold, so
    the main pass's lock wait is longer than any recheck. It is kept
    cooperatively: checked between phases, and every bus call is refused or
    shortened to the time that is left (`bind_remaining`), the finalizer's
    included. Retirement and collection end by `collect_seconds`; collection
    that did not finish is a withhold. The withdrawal's steps end
    `finalizer_seconds` before the finalizer's end, which is
    `record_seconds` before the budget; the last seconds are for the record,
    so an unconfirmed withdrawal is recorded before the exit.
    """
    start = clock() if started is None else started
    final = start + budget_seconds - record_seconds  # the finalizer ends here
    work = final - finalizer_seconds  # the withdrawal's own steps end here
    collect = min(work, start + collect_seconds)
    try:
        lock = acquire_pass_lock(root, wait_seconds=0.0, clock=clock, sleep=sleep)
    except PassLockBusy:
        print("az-activation-recheck: the activation pass lock is held; nothing changed")
        return 0
    except PassLockDirectoryMissing:
        # No directory, so no marker and no lock to take. Only a broker that
        # is nevertheless there is worth a failure.
        if contextd_triggers(manager, authority, root) == ():
            return 0
        print("az-activation-recheck: the activation directory is missing",
              file=sys.stderr)
        return 1
    except PassLockRefused:
        print("az-activation-recheck: the activation pass lock is unusable",
              file=sys.stderr)
        return 1
    with lock:
        status = 0
        retirement_blocked = False
        inputs = None
        ledger = AuditLedger(root / "var/lib/azazel/state/activation.jsonl")
        unrecorded: list[str] = []

        def record(event: dict) -> None:
            # Appended here, with the lock held, in the order the transitions
            # happen: the ledger's append reads the head and then writes, with
            # no lock of its own, so only this lock keeps two writers from
            # extending the same head. A record that cannot be written is
            # reported, never swallowed: the exit status becomes non-zero.
            try:
                ledger.append(event)
            except Exception:  # noqa: BLE001 - reported through the exit status
                unrecorded.append(event.get("event_type", "?"))
                print("az-activation-recheck could not append a record "
                      f"({event.get('event_type', '?')})", file=sys.stderr)

        def finish(code: int) -> int:
            return 1 if unrecorded else code

        try:
            bind_remaining(manager, collect, clock)
            if retirement is not None:
                # Independent of whether the broker needs withdrawing: an
                # approval whose operator was explicitly revoked is retired
                # either way.
                try:
                    outcome = retirement(root=root, now=now)
                except RetireRefused:
                    print("az-activation-recheck: approval retirement did not "
                          "complete", file=sys.stderr)
                    status, retirement_blocked = 1, True
                else:
                    if outcome != "none":
                        record(_retired_event(outcome, now, invocation_id))
            check_budget(collect, clock)
            triggers = contextd_triggers(manager, authority, root)
            if not triggers:
                return finish(status)
            check_budget(collect, clock)
            try:
                inputs = collect_pass_inputs(
                    producers=producers,
                    generations=GenerationStore(root / "var/lib/azazel/generations"),
                    ledger=ledger, now=now)
            except Exception:  # noqa: BLE001 - a collection that failed is a withhold
                inputs = None
            check_budget(collect, clock)
        except PassBudgetExpired:
            # Retirement or collection did not finish in time: withhold and
            # withdraw (and never call a retirement that failed "done").
            print("az-activation-recheck: collection did not finish in time",
                  file=sys.stderr)
            status, retirement_blocked = 1, retirement_blocked or retirement is not None
            inputs = None
        if not retirement_blocked:
            try:
                retirement_blocked = retirement_pending(root)
            except Exception:  # noqa: BLE001 - unreadable counts as pending
                retirement_blocked = True
        verdict = contextd_verdict(inputs, now, retirement_blocked=retirement_blocked)
        if verdict.granted:
            return finish(status)
        try:
            withdraw_contextd(
                reason=f"recheck:{verdict.label}", manager=manager, authority=authority,
                root=root, ledger=ledger, now=now, actor=ACTOR,
                invocation_id=invocation_id, deadline=work, final_deadline=final,
                bind_deadline=lambda d: bind_remaining(manager, d, clock),
                sink=record, clock=clock, sleep=sleep)
        except WithdrawalUnconfirmed:
            # Already recorded and left masked as far as it could be. Other
            # units are not narrowed from here: this process decides for the
            # broker alone.
            print("az-activation-recheck: withdrawal of the Knowledge Context broker "
                  "is unconfirmed", file=sys.stderr)
            return 1
        return finish(status)


def _retired_event(outcome: str, now: str, invocation_id: str) -> dict:
    return {
        "event_type": "activation.approval_retired", "outcome": outcome,
        "invocation_id": invocation_id, "occurred_at": now, "actor": ACTOR}


def production_retirement(root: Path = Path("/")):
    """`retire_if_revoked` over the host's trust store, floor and policy."""
    from azazel_nexus.activation_policy import load_activation_policy
    from azazel_nexus.operator_store import load_operator_trust

    from .activation_high_water import raise_high_water, read_high_water

    def retire(*, root: Path, now: str) -> str:
        # A retirement that was already classified is finished first, with no
        # trust and no policy: the clock skew it needs is in the record.
        resumed = resume_pending_retirement(
            root=root, read_floor=read_high_water, raise_floor=raise_high_water, now=now)
        if resumed != "none":
            return resumed
        try:
            trust = load_operator_trust()
            skew = load_activation_policy().max_clock_skew_seconds
        except Exception:  # noqa: BLE001 - nothing proves a revocation
            return "none"
        return retire_if_revoked(root=root, trust=trust, read_floor=read_high_water,
                                 raise_floor=raise_high_water, now=now, skew_seconds=skew)

    return retire


def main(argv=None) -> int:
    """Entry point of `az-activation-recheck`; accepts no arguments."""
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        print("az-activation-recheck accepts no command-line arguments", file=sys.stderr)
        return 2
    from .runtime_paths import ROOT

    invocation_id = os.environ.get("INVOCATION_ID", "")
    if (os.geteuid() != 0 or not Path("/run/systemd/system").is_dir()
            or not re.fullmatch(r"[0-9a-fA-F]{32}", invocation_id) or ROOT != Path("/")):
        print("az-activation-recheck requires its root systemd service context and "
              "fixed host paths", file=sys.stderr)
        return 1
    from .activation_pass import production_producers
    from .commissioning_input import load_commissioning_evidence
    from .systemd_bus import SystemdBusSession

    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    started = time.monotonic()  # before the connect: connecting counts
    try:
        with SystemdBusSession.connect(
                lambda: started + RECHECK_BUDGET_SECONDS - RECHECK_RECORD_SECONDS
                - RECHECK_FINALIZER_SECONDS - time.monotonic()) as session:
            return run_recheck(
                manager=DbusUnitManager(call=session),
                authority=ContextdStopAuthority.from_session(session),
                root=Path("/"), now=now, invocation_id=invocation_id, started=started,
                retirement=production_retirement(),
                producers=production_producers(
                    commissioning_evidence=load_commissioning_evidence, systemd=session))
    except Exception as exc:  # noqa: BLE001 - the service boundary reports a class only
        print(f"az-activation-recheck failed: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
