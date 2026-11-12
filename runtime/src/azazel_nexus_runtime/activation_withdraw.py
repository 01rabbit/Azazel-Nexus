"""Withdrawing the Knowledge Context broker's grant (design: stop contract).

`docs/activation-observe-baseline.md` ("Stopping a granted broker"). The
broker is the one granted unit the controller can stop, because it is the one
whose output reaches a model prompt. `withdraw_contextd(reason)` is the one
sequence, called with the pass lock held by the main pass (preflight) and by
the periodic recheck:

1. unlink the broker's grant marker (no-follow) and confirm it is gone
   (`t_marker`); no other marker is touched;
2. mask the broker and reload the manager (`t_reload`);
3. if the broker is not inactive, or has a job, send StopUnit in mode
   `replace` (`t_stop`);
4. wait, within the remaining budget (at most 20 s), until its ActiveState is
   `inactive` and its job is `(0, "/")` (`t_inactive`);
5. record `activation.grant_withdrawn` with the reason and the timings in
   milliseconds since detection.

Any step that cannot be confirmed leaves the broker masked and records
`activation.withdrawal_unconfirmed` (the record failing changes nothing),
then raises `WithdrawalUnconfirmed`. The caller exits non-zero.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Callable, Optional

from azazel_nexus.audit import AuditLedger

from .activation_markers import remove_contextd_marker
from .units import CONTEXTD_UNIT, ContextdStopAuthority, UnitManager

__all__ = [
    "NO_JOB",
    "STOP_WAIT_SECONDS",
    "WithdrawalUnconfirmed",
    "clear_contextd_job",
    "contextd_is_quiet",
    "withdraw_contextd",
]

#: The upper bound on waiting for the stop to take effect.
STOP_WAIT_SECONDS = 20.0
_POLL_SECONDS = 0.1
#: systemd's `Job` property when the unit has no job.
NO_JOB = (0, "/")


class WithdrawalUnconfirmed(Exception):
    """The broker's withdrawal could not be confirmed; it is left masked."""


def _ms(since: float, clock: Callable[[], float]) -> int:
    return max(0, int((clock() - since) * 1000))


def contextd_is_quiet(manager: UnitManager, authority: ContextdStopAuthority) -> bool:
    """Inactive and without a job. Anything unreadable is not quiet."""
    try:
        return (manager.is_inactive(CONTEXTD_UNIT) is True
                and authority.job(CONTEXTD_UNIT) == NO_JOB)
    except Exception:  # noqa: BLE001 - unreadable is not confirmed quiet
        return False


def _wait_until(done: Callable[[], bool], *, give_up: float,
                clock: Callable[[], float], sleep: Callable[[float], None]) -> bool:
    while True:
        if done():
            return True
        if clock() >= give_up:
            return False
        sleep(_POLL_SECONDS)


def _record(ledger: AuditLedger, event: dict) -> None:
    try:
        ledger.append(event)
    except Exception:  # noqa: BLE001 - the withdrawal does not depend on its record
        print("az-activation could not append a withdrawal record", file=sys.stderr)


def withdraw_contextd(
    *, reason: str, manager: UnitManager, authority: ContextdStopAuthority,
    root: Path, ledger: AuditLedger, now: str, actor: str, invocation_id: str,
    deadline: Optional[float] = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Withdraw the broker; returns the recorded timings, or raises.

    `deadline` is a monotonic instant the whole withdrawal must end by (the
    main pass's overall budget); the stop wait is also capped at 20 s.
    """
    started = clock()
    timings: dict = {"t_marker_ms": None, "t_reload_ms": None,
                     "t_stop_ms": None, "t_inactive_ms": None}
    stage = "marker"

    def unconfirmed(why: str) -> WithdrawalUnconfirmed:
        _record(ledger, {
            "event_type": "activation.withdrawal_unconfirmed",
            "unit": CONTEXTD_UNIT, "reason": reason, "stage": stage, "why": why,
            "invocation_id": invocation_id, **timings,
            "occurred_at": now, "actor": actor,
        })
        return WithdrawalUnconfirmed(
            f"withdrawal of the Knowledge Context broker unconfirmed at {stage}")

    needs_stop = False
    try:
        remove_contextd_marker(root)
        timings["t_marker_ms"] = _ms(started, clock)
        stage = "mask"
        manager.mask(CONTEXTD_UNIT)
        stage = "reload"
        manager.reload()
        timings["t_reload_ms"] = _ms(started, clock)
        stage = "read"
        needs_stop = (manager.is_inactive(CONTEXTD_UNIT) is not True
                      or authority.job(CONTEXTD_UNIT) != NO_JOB)
        if needs_stop:
            stage = "stop"
            authority.stop(CONTEXTD_UNIT)
            timings["t_stop_ms"] = _ms(started, clock)
            stage = "inactive"
            give_up = clock() + STOP_WAIT_SECONDS
            if deadline is not None:
                give_up = min(give_up, deadline)
            if not _wait_until(lambda: contextd_is_quiet(manager, authority),
                               give_up=give_up, clock=clock, sleep=sleep):
                raise TimeoutError("the broker did not become inactive in time")
        timings["t_inactive_ms"] = _ms(started, clock)
    except Exception as exc:  # noqa: BLE001 - recorded as a class name, then raised
        raise unconfirmed(type(exc).__name__) from None
    _record(ledger, {
        "event_type": "activation.grant_withdrawn",
        "unit": CONTEXTD_UNIT, "reason": reason, "stopped": needs_stop,
        "invocation_id": invocation_id, **timings,
        "occurred_at": now, "actor": actor,
    })
    return timings


def clear_contextd_job(
    *, authority: ContextdStopAuthority, ledger: AuditLedger, now: str, actor: str,
    reason: str, invocation_id: str, deadline: Optional[float] = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Replace a start job the manager has queued for a broker that is not granted.

    Returns True when a job was found and replaced. A job that cannot be
    read or replaced within the budget raises `WithdrawalUnconfirmed`.
    """
    started = clock()
    try:
        if authority.job(CONTEXTD_UNIT) == NO_JOB:
            return False
        authority.stop(CONTEXTD_UNIT)
        give_up = clock() + STOP_WAIT_SECONDS
        if deadline is not None:
            give_up = min(give_up, deadline)
        if not _wait_until(lambda: authority.job(CONTEXTD_UNIT) == NO_JOB,
                           give_up=give_up, clock=clock, sleep=sleep):
            raise TimeoutError("the queued job did not clear in time")
    except Exception as exc:  # noqa: BLE001 - recorded as a class name, then raised
        _record(ledger, {
            "event_type": "activation.withdrawal_unconfirmed",
            "unit": CONTEXTD_UNIT, "reason": reason, "stage": "job",
            "why": type(exc).__name__, "invocation_id": invocation_id,
            "occurred_at": now, "actor": actor,
        })
        raise WithdrawalUnconfirmed(
            "queued job of the Knowledge Context broker unconfirmed") from None
    _record(ledger, {
        "event_type": "activation.queued_job_replaced",
        "unit": CONTEXTD_UNIT, "reason": reason, "t_ms": _ms(started, clock),
        "invocation_id": invocation_id, "occurred_at": now, "actor": actor,
    })
    return True
