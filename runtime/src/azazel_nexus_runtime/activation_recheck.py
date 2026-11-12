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
    UnitState,
    UnitTier,
    common_withholding_reason,
)
from azazel_nexus.audit import AuditLedger
from azazel_nexus.generation import GenerationStore

from .activation_lock import PassLockBusy, PassLockRefused, acquire_pass_lock
from .activation_markers import contextd_marker_present
from .activation_pass import PassInputs, collect_pass_inputs
from .activation_withdraw import NO_JOB, WithdrawalUnconfirmed, withdraw_contextd
from .units import (
    CONTEXTD_UNIT,
    ContextdStopAuthority,
    DbusUnitManager,
    UnitManager,
)

__all__ = ["ContextdVerdict", "contextd_triggers", "contextd_verdict", "main", "run_recheck"]

ACTOR = "azazel-activation-recheck"
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
                     wired=None) -> ContextdVerdict:
    """Would the main pass grant the Knowledge Context broker, given `inputs`?

    Pure: it reads `inputs` and the wiring set and nothing else, and it calls
    none of `activate`, the marker writers, the floor raise or the ledger.
    The conditions are the library's own (`common_withholding_reason`, the
    ones a SUPPORTING unit meets in `ActivationController`), applied to the
    verified lease, health and generation digest the collection produced.
    Missing or incomplete inputs withhold.
    """
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

    A marker, a file state other than masked, or a state other than inactive
    or a job. A read that fails counts: an unreadable broker is evaluated, not
    assumed quiet.
    """
    found: list[str] = []
    try:
        if contextd_marker_present(root):
            found.append("marker")
    except Exception:  # noqa: BLE001 - unreadable is evaluated
        found.append("marker_unreadable")
    try:
        if manager.state(CONTEXTD_UNIT) is not UnitState.MASKED:
            found.append("not_masked")
    except Exception:  # noqa: BLE001
        found.append("state_unreadable")
    try:
        if manager.is_inactive(CONTEXTD_UNIT) is not True:
            found.append("not_inactive")
        elif authority.job(CONTEXTD_UNIT) != NO_JOB:
            found.append("job")
    except Exception:  # noqa: BLE001
        found.append("activity_unreadable")
    return tuple(found)


def run_recheck(
    *, manager: UnitManager, authority: ContextdStopAuthority, root: Path, now: str,
    producers, invocation_id: str, clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """One recheck under the pass lock; the process exit status."""
    try:
        lock = acquire_pass_lock(root, wait_seconds=0.0, clock=clock, sleep=sleep)
    except PassLockBusy:
        print("az-activation-recheck: the activation pass lock is held; nothing changed")
        return 0
    except PassLockRefused:
        print("az-activation-recheck: the activation pass lock is unusable",
              file=sys.stderr)
        return 1
    with lock:
        triggers = contextd_triggers(manager, authority, root)
        if not triggers:
            return 0
        ledger = AuditLedger(root / "var/lib/azazel/state/activation.jsonl")
        try:
            inputs = collect_pass_inputs(
                producers=producers,
                generations=GenerationStore(root / "var/lib/azazel/generations"),
                ledger=ledger, now=now)
        except Exception:  # noqa: BLE001 - a collection that failed is a withhold
            inputs = None
        verdict = contextd_verdict(inputs, now)
        if verdict.granted:
            return 0
        try:
            withdraw_contextd(
                reason=f"recheck:{verdict.label}", manager=manager, authority=authority,
                root=root, ledger=ledger, now=now, actor=ACTOR,
                invocation_id=invocation_id, clock=clock, sleep=sleep)
        except WithdrawalUnconfirmed:
            # Already recorded and left masked. Other units are not narrowed
            # from here: this process decides for the broker alone.
            print("az-activation-recheck: withdrawal of the Knowledge Context broker "
                  "is unconfirmed", file=sys.stderr)
            return 1
    return 0


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
                producers=production_producers(
                    commissioning_evidence=load_commissioning_evidence, systemd=session))
    except Exception as exc:  # noqa: BLE001 - the service boundary reports a class only
        print(f"az-activation-recheck failed: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
