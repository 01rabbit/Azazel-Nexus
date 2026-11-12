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

from .activation_budget import PassBudgetExpired, alarm_budget
from .activation_lock import (
    PassLockBusy, PassLockDirectoryMissing, PassLockRefused, acquire_pass_lock,
)
from .activation_markers import contextd_marker_present
from .activation_pass import PassInputs, collect_pass_inputs
from .activation_retire import (
    RetireRefused, resume_pending_retirement, retire_if_revoked, retirement_pending,
)
from .activation_withdraw import NO_JOB, QUIET_STATES, WithdrawalUnconfirmed, withdraw_contextd
from .units import (
    CONTEXTD_UNIT,
    ContextdStopAuthority,
    DbusUnitManager,
    UnitManager,
)

__all__ = ["ContextdVerdict", "contextd_triggers", "contextd_verdict", "main", "run_recheck"]

ACTOR = "azazel-activation-recheck"
#: One monotonic budget for a recheck. `azazel-activation-recheck.service` has
#: `TimeoutStartSec=40s`; 35 s leaves 5 s for the record and the exit. It also
#: bounds how long the pass lock is held (the main pass waits
#: `activated.PASS_LOCK_WAIT_SECONDS` for it).
RECHECK_BUDGET_SECONDS = 35.0
#: Of which at most this long for retirement and collecting the inputs.
RECHECK_COLLECT_SECONDS = 15.0
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
        if authority.active_state(CONTEXTD_UNIT) not in QUIET_STATES:
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
    budget_seconds: float = RECHECK_BUDGET_SECONDS,
    collect_seconds: float = RECHECK_COLLECT_SECONDS,
) -> int:
    """One recheck under the pass lock; the process exit status.

    The whole recheck has one monotonic budget (`RECHECK_BUDGET_SECONDS`,
    inside the unit's `TimeoutStartSec=40s`), so the withdrawal's record is
    written before systemd would kill the process. Collecting inputs is
    limited by an alarm (`RECHECK_COLLECT_SECONDS`); collection that does not
    finish is a withhold, and the withdrawal gets what is left.
    """
    deadline = clock() + budget_seconds
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
        try:
            with alarm_budget(collect_seconds):
                if retirement is not None:
                    # Independent of whether the broker needs withdrawing: an
                    # approval whose operator was explicitly revoked is
                    # retired either way.
                    try:
                        outcome = retirement(root=root, now=now)
                    except RetireRefused:
                        print("az-activation-recheck: approval retirement did not "
                              "complete", file=sys.stderr)
                        status, retirement_blocked = 1, True
                    else:
                        if outcome != "none":
                            _retired_record(root, outcome, now, invocation_id)
                triggers = contextd_triggers(manager, authority, root)
                if not triggers:
                    return status
                ledger = AuditLedger(root / "var/lib/azazel/state/activation.jsonl")
                try:
                    inputs = collect_pass_inputs(
                        producers=producers,
                        generations=GenerationStore(root / "var/lib/azazel/generations"),
                        ledger=ledger, now=now)
                except Exception:  # noqa: BLE001 - a collection that failed is a withhold
                    inputs = None
        except PassBudgetExpired:
            # Retirement or collection did not finish: withhold and withdraw.
            print("az-activation-recheck: collection did not finish in time",
                  file=sys.stderr)
            status, retirement_blocked = 1, retirement_blocked or retirement is not None
            inputs = None
            ledger = AuditLedger(root / "var/lib/azazel/state/activation.jsonl")
        if not retirement_blocked:
            try:
                retirement_blocked = retirement_pending(root)
            except Exception:  # noqa: BLE001 - unreadable counts as pending
                retirement_blocked = True
        verdict = contextd_verdict(inputs, now, retirement_blocked=retirement_blocked)
        if verdict.granted:
            return status
        try:
            withdraw_contextd(
                reason=f"recheck:{verdict.label}", manager=manager, authority=authority,
                root=root, ledger=ledger, now=now, actor=ACTOR,
                invocation_id=invocation_id, deadline=deadline, clock=clock, sleep=sleep)
        except WithdrawalUnconfirmed:
            # Already recorded and left masked as far as it could be. Other
            # units are not narrowed from here: this process decides for the
            # broker alone.
            print("az-activation-recheck: withdrawal of the Knowledge Context broker "
                  "is unconfirmed", file=sys.stderr)
            return 1
    return status


def _retired_record(root: Path, outcome: str, now: str, invocation_id: str) -> None:
    try:
        AuditLedger(root / "var/lib/azazel/state/activation.jsonl").append({
            "event_type": "activation.approval_retired", "outcome": outcome,
            "invocation_id": invocation_id, "occurred_at": now, "actor": ACTOR})
    except Exception:  # noqa: BLE001 - the retirement does not depend on its record
        print("az-activation-recheck could not append a retirement record",
              file=sys.stderr)


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
    try:
        with SystemdBusSession.connect() as session:
            return run_recheck(
                manager=DbusUnitManager(call=session),
                authority=ContextdStopAuthority.from_session(session),
                root=Path("/"), now=now, invocation_id=invocation_id,
                retirement=production_retirement(),
                producers=production_producers(
                    commissioning_evidence=load_commissioning_evidence, systemd=session))
    except Exception as exc:  # noqa: BLE001 - the service boundary reports a class only
        print(f"az-activation-recheck failed: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
