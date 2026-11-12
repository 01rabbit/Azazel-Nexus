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
4. wait, within the remaining budget (at most 20 s), until it is quiet: its
   ActiveState is `inactive` (or `failed`, see below) and its job is
   `(0, "/")` (`t_inactive`);
5. record `activation.grant_withdrawn` with the reason and the timings in
   milliseconds since detection.

`failed` counts as quiet for this confirmation only. After a SIGKILL final
kill systemd keeps the unit loaded as `failed` (result `timeout`) and
`StopUnit` does not return it to `inactive`; the process is gone, and waiting
for `inactive` would make the withdrawal permanently unconfirmed. The record
says so (`quiet_state`). Nothing else treats `failed` as inactive.

Any step that cannot be confirmed first runs a containment finalizer for this
one unit (remove the marker, mask, reload, one stop if it is not quiet), then
records `activation.withdrawal_unconfirmed` with what the finalizer reached
(`final_masked`, `final_quiet`; the record failing changes nothing), then
raises `WithdrawalUnconfirmed`. The caller exits non-zero.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Callable, Optional

from azazel_nexus.audit import AuditLedger

from .activation_markers import remove_contextd_marker
from .units import CONTEXTD_UNIT, ContextdStopAuthority, UnitManager, UnitOperationFailed

__all__ = [
    "NO_JOB",
    "STOP_WAIT_SECONDS",
    "WithdrawalUnconfirmed",
    "clear_contextd_job",
    "QUIET_STATES",
    "contextd_is_quiet",
    "contextd_is_running",
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


#: ActiveStates in which no process of the broker remains.
QUIET_STATES = ("inactive", "failed")


def contextd_is_quiet(authority: ContextdStopAuthority) -> bool:
    """No process (`inactive`, or `failed` after a kill) and no job. Unreadable is not quiet."""
    try:
        return (authority.active_state(CONTEXTD_UNIT) in QUIET_STATES
                and authority.job(CONTEXTD_UNIT) == NO_JOB)
    except Exception:  # noqa: BLE001 - unreadable is not confirmed quiet
        return False


def contextd_is_running(authority: ContextdStopAuthority) -> bool:
    """Anything but exactly `inactive`: a process may exist, or the unit is `failed`.

    `failed` is deliberately not quiet here. It counts as quiet only in
    `contextd_is_quiet`, to confirm a withdrawal that was already done (a unit
    left `failed` by a kill has no process, but nothing else may treat it as
    inactive: a preflight or a recheck still withdraws it). Unreadable counts
    as not running (the caller's own mask makes the unit readable and its
    checks refuse otherwise).
    """
    try:
        return authority.active_state(CONTEXTD_UNIT) != "inactive"
    except Exception:  # noqa: BLE001
        return False


def _job_twice(authority: ContextdStopAuthority) -> tuple:
    """The job, read again once: the unit can be dropped between GetUnit and Get."""
    try:
        return authority.job(CONTEXTD_UNIT)
    except Exception:  # noqa: BLE001
        return authority.job(CONTEXTD_UNIT)


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


def _contain(*, manager: UnitManager, authority: ContextdStopAuthority, root: Path,
             stop_sent: bool, give_up: Optional[float] = None,
             clock: Callable[[], float] = time.monotonic) -> dict:
    """Contextd-only finalizer: reach the masked, quiet state as far as possible.

    Marker removed (local, not a bus call), masked, reloaded, and one stop if
    the broker is not quiet and none was sent. Every step is tried whatever
    the others did, but none is started after `give_up` (the bus calls are
    also refused by their session then); the result states what was reached,
    read back from the manager.
    """
    def late() -> bool:
        return give_up is not None and clock() >= give_up

    try:
        remove_contextd_marker(root)
    except Exception:  # noqa: BLE001
        pass
    for step in (lambda: manager.mask(CONTEXTD_UNIT), manager.reload):
        if late():
            break
        try:
            step()
        except Exception:  # noqa: BLE001 - every step is tried
            pass
    try:
        if not late() and not stop_sent and not contextd_is_quiet(authority):
            authority.stop(CONTEXTD_UNIT)
    except Exception:  # noqa: BLE001
        pass
    masked = quiet = False
    if not late():
        try:
            masked = authority.file_state(CONTEXTD_UNIT) == "masked"
        except Exception:  # noqa: BLE001
            masked = False
        quiet = contextd_is_quiet(authority)
    return {"final_masked": masked, "final_quiet": quiet}


def withdraw_contextd(
    *, reason: str, manager: UnitManager, authority: ContextdStopAuthority,
    root: Path, ledger: AuditLedger, now: str, actor: str, invocation_id: str,
    deadline: Optional[float] = None,
    final_deadline: Optional[float] = None,
    bind_deadline: Optional[Callable[[float], None]] = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Withdraw the broker; returns the recorded timings, or raises.

    `deadline` is the monotonic instant the withdrawal's steps must end by
    (the caller's budget less its reserve); the stop wait is also capped at
    20 s. A step started after it is not started: the finalizer runs instead,
    inside the reserve, up to `final_deadline`. `bind_deadline(d)` is called
    with the deadline that bounds the bus calls from then on (first
    `deadline`, then `final_deadline` for the finalizer), so no call outlasts
    the time that is left.
    """
    started = clock()
    timings: dict = {"t_marker_ms": None, "t_reload_ms": None,
                     "t_stop_ms": None, "t_inactive_ms": None}
    stage = "marker"
    stop_sent = False

    def over() -> None:
        if deadline is not None and clock() >= deadline:
            raise TimeoutError("the budget for the withdrawal is used")

    def unconfirmed(why: str) -> WithdrawalUnconfirmed:
        if bind_deadline is not None and final_deadline is not None:
            bind_deadline(final_deadline)
        reached = _contain(manager=manager, authority=authority, root=root,
                           stop_sent=stop_sent, give_up=final_deadline, clock=clock)
        _record(ledger, {
            "event_type": "activation.withdrawal_unconfirmed",
            "unit": CONTEXTD_UNIT, "reason": reason, "stage": stage, "why": why,
            "invocation_id": invocation_id, **timings, **reached,
            "occurred_at": now, "actor": actor,
        })
        return WithdrawalUnconfirmed(
            f"withdrawal of the Knowledge Context broker unconfirmed at {stage}")

    needs_stop = False
    quiet_state = "inactive"
    if bind_deadline is not None and deadline is not None:
        bind_deadline(deadline)
    try:
        remove_contextd_marker(root)
        timings["t_marker_ms"] = _ms(started, clock)
        stage = "mask"
        over()
        manager.mask(CONTEXTD_UNIT)
        stage = "reload"
        over()
        manager.reload()
        timings["t_reload_ms"] = _ms(started, clock)
        stage = "verify_mask"
        # Persistent `masked` exactly: `masked-runtime` goes at the next boot.
        if authority.file_state(CONTEXTD_UNIT) != "masked":
            raise UnitOperationFailed("the broker is not persistently masked")
        stage = "read"
        over()
        needs_stop = (authority.active_state(CONTEXTD_UNIT) not in QUIET_STATES
                      or _job_twice(authority) != NO_JOB)
        if needs_stop:
            stage = "stop"
            over()
            authority.stop(CONTEXTD_UNIT)
            stop_sent = True
            timings["t_stop_ms"] = _ms(started, clock)
            stage = "inactive"
            give_up = clock() + STOP_WAIT_SECONDS
            if deadline is not None:
                give_up = min(give_up, deadline)
            if not _wait_until(lambda: contextd_is_quiet(authority),
                               give_up=give_up, clock=clock, sleep=sleep):
                raise TimeoutError("the broker did not become quiet in time")
        quiet_state = authority.active_state(CONTEXTD_UNIT)
        timings["t_inactive_ms"] = _ms(started, clock)
    except Exception as exc:  # noqa: BLE001 - recorded as a class name, then raised
        raise unconfirmed(type(exc).__name__) from None
    _record(ledger, {
        "event_type": "activation.grant_withdrawn",
        "unit": CONTEXTD_UNIT, "reason": reason, "stopped": needs_stop,
        "quiet_state": quiet_state,
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
