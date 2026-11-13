"""Withdrawing the Knowledge Context broker's grant (design: stop contract).

`docs/activation-observe-baseline.md` ("Stopping a granted broker"). The
broker is the one granted unit the controller can stop, because it is the one
whose output reaches a model prompt. `withdraw_contextd(reason)` is the one
sequence, called with the pass lock held by the main pass (preflight) and by
the periodic recheck:

1. unlink the broker's grant marker (no-follow) and confirm it is gone
   (`t_marker`); no other marker is touched;
2. mask the broker and reload the manager (`t_reload`); job reads, StopUnit
   and polling have their own transport limit that ends before the time kept
   for this step, and a finished session is replaced by a fresh one;
3. if the broker is not inactive, or has a job, send StopUnit in mode
   `replace` (`t_stop`);
4. wait, within the remaining budget (at most 20 s), until it is quiet: its
   ActiveState is `inactive` (or `failed`, see below), its job is
   `(0, "/")` and its cgroup is confirmed empty (`contextd_cgroup`:
   `empty`, `populated` or `unknown`; only `empty` counts) (`t_inactive`);
5. record `activation.grant_withdrawn` with the reason, the cgroup state and
   the timings in milliseconds since detection.

`failed` counts as quiet for this confirmation only, and only with an empty
cgroup. After a SIGKILL final kill systemd keeps the unit loaded as `failed`
(result `timeout`) and `StopUnit` does not return it to `inactive`; waiting
for `inactive` would make the withdrawal permanently unconfirmed. But systemd
can also leave a unit `failed` while a process is still in its cgroup, so
`failed` alone says nothing about processes: a cgroup that is `populated` or
`unknown` leaves the withdrawal unconfirmed. The record says which state it
found (`quiet_state`, `cgroup`). Nothing else treats `failed` as inactive.

Any step that cannot be confirmed first runs a containment finalizer for this
one unit (remove the marker, mask, reload, one stop if it is not quiet), then
records `activation.withdrawal_unconfirmed` with what the finalizer reached
(`final_masked`, `final_quiet`; the record failing changes nothing), then
raises `WithdrawalUnconfirmed`. The caller exits non-zero.
"""

from __future__ import annotations

import contextlib
import sys
import time
from pathlib import Path
from typing import Callable, Optional

from azazel_nexus.audit import AuditLedger

from .activation_budget import bind_remaining
from .activation_markers import contextd_marker_present, remove_contextd_marker
from .units import CONTEXTD_UNIT, ContextdStopAuthority, UnitManager, UnitOperationFailed

__all__ = [
    "JOB_WAIT_SECONDS",
    "MASK_RESERVE_SECONDS",
    "NO_JOB",
    "job_wait_limit",
    "STOP_WAIT_SECONDS",
    "WithdrawalUnconfirmed",
    "clear_contextd_job",
    "QUIET_STATES",
    "QueuedJobState",
    "release_queued_job",
    "contextd_already_withdrawn",
    "contextd_is_quiet",
    "contextd_is_running",
    "contextd_start_is_queued",
    "withdraw_contextd",
]

#: The upper bound on waiting for the stop to take effect.
STOP_WAIT_SECONDS = 20.0
_POLL_SECONDS = 0.1
#: systemd's `Job` property when the unit has no job.
NO_JOB = (0, "/")
#: How long to wait for a replaced start job to disappear. A job normally goes
#: in milliseconds; this is a ceiling, not an expectation.
JOB_WAIT_SECONDS = 5.0
#: Time that always remains for the mask, the reload and the exact-masked
#: confirmation after the job wait: the wait ends this long before the deadline
#: the bus session is bound to, so a slow job can never use the time the mask needs.
MASK_RESERVE_SECONDS = 3.0


def job_wait_limit(deadline: Optional[float], clock: Callable[[], float]) -> float:
    """The monotonic instant a wait for a replaced job must end by."""
    limit = clock() + JOB_WAIT_SECONDS
    if deadline is not None:
        limit = min(limit, deadline - MASK_RESERVE_SECONDS)
    return limit


class WithdrawalUnconfirmed(Exception):
    """The broker's withdrawal could not be confirmed; it is left masked."""


def _ms(since: float, clock: Callable[[], float]) -> int:
    return max(0, int((clock() - since) * 1000))


#: ActiveStates in which no process of the broker remains.
QUIET_STATES = ("inactive", "failed")


def contextd_cgroup(authority: ContextdStopAuthority) -> str:
    """`empty`, `populated` or `unknown`: the broker's cgroup. Unreadable is `unknown`."""
    try:
        state = authority.cgroup_state(CONTEXTD_UNIT)
    except Exception:  # noqa: BLE001 - unreadable is unknown
        return "unknown"
    return state if state in ("empty", "populated") else "unknown"


def contextd_is_quiet(authority: ContextdStopAuthority) -> bool:
    """`inactive` or `failed`, no job, and the cgroup confirmed empty.

    `ActiveState` is what systemd believes; a `failed` unit can still have
    processes. Only an empty cgroup completes the confirmation. Unreadable, and
    `unknown`, are not quiet.
    """
    try:
        return (authority.active_state(CONTEXTD_UNIT) in QUIET_STATES
                and authority.job(CONTEXTD_UNIT) == NO_JOB
                and contextd_cgroup(authority) == "empty")
    except Exception:  # noqa: BLE001 - unreadable is not confirmed quiet
        return False


def contextd_already_withdrawn(authority: ContextdStopAuthority, root: Path) -> bool:
    """`failed`, no job, unit-file state exactly `masked`, no marker and an empty cgroup.

    A broker a kill left `failed` after its withdrawal. Nothing runs, nothing
    is queued and nothing can start it, so there is nothing to withdraw again:
    the recheck does not trigger on it and the main pass's preflight accepts it.
    Every other `failed` (unmasked, a marker, a job) is still a trigger.
    A `failed` unit whose cgroup is `populated` or `unknown` is not withdrawn:
    a process may remain, and the recheck keeps reporting it.
    Unreadable is not "already withdrawn".
    """
    try:
        return (authority.active_state(CONTEXTD_UNIT) == "failed"
                and authority.job(CONTEXTD_UNIT) == NO_JOB
                and authority.file_state(CONTEXTD_UNIT) == "masked"
                and not contextd_marker_present(root)
                and contextd_cgroup(authority) == "empty")
    except Exception:  # noqa: BLE001
        return False


def contextd_is_running(authority: ContextdStopAuthority,
                        root: Optional[Path] = None) -> bool:
    """Anything but `inactive` with an empty cgroup: a process may exist, or the unit is `failed`.

    `failed` is not quiet here, except the one already-withdrawn shape
    (`contextd_already_withdrawn`, which needs `root` for the marker). It counts
    as quiet in `contextd_is_quiet`, to confirm a withdrawal that was just done.
    `inactive` is not running only when the cgroup is confirmed `empty`; a
    `populated` or `unknown` cgroup counts as running (the safe side: the caller
    then withdraws, and a withdrawal that cannot confirm an empty cgroup fails
    closed).
    An ActiveState that cannot be read counts as running too: nothing says
    that no process exists, so the withdrawal (which fails closed) is needed.
    """
    try:
        state = authority.active_state(CONTEXTD_UNIT)
    except Exception:  # noqa: BLE001 - unreadable: a withdrawal is needed
        return True
    if state == "inactive":
        return contextd_cgroup(authority) != "empty"
    if state == "failed" and root is not None and contextd_already_withdrawn(authority, root):
        return False
    return True


def contextd_start_is_queued(authority: ContextdStopAuthority) -> bool:
    """Exactly `inactive`, not masked, with a start job waiting.

    Such a start job cannot run before READY (the broker is `After=` and
    `Requires=` the controller); masking the unit and reloading would make
    systemd fail it, so the main pass's preflight leaves the unit alone and
    decides at the verdict. Unreadable is not queued.
    """
    try:
        return (authority.active_state(CONTEXTD_UNIT) == "inactive"
                and authority.job(CONTEXTD_UNIT) != NO_JOB
                and authority.file_state(CONTEXTD_UNIT) != "masked")
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
        left = give_up - clock()
        if left <= 0:
            return False  # no call is started once the allowance is gone
        if done():
            return True
        sleep(min(_POLL_SECONDS, left))  # never oversleeps the deadline


def _record(ledger: AuditLedger, event: dict) -> None:
    try:
        ledger.append(event)
    except Exception:  # noqa: BLE001 - the withdrawal does not depend on its record
        print("az-activation could not append a withdrawal record", file=sys.stderr)


def _contain(*, manager: UnitManager, authority: ContextdStopAuthority, root: Path,
             stop_sent: bool, give_up: Optional[float] = None,
             clock: Callable[[], float] = time.monotonic, settle=None,
             fresh) -> dict:
    """Contextd-only finalizer: reach the masked, quiet state as far as possible.

    Marker removed (local, not a bus call), masked, reloaded, and one stop if
    the broker is not quiet and none was sent. Every step is tried whatever
    the others did, but none is started after `give_up` (the bus calls are
    also refused by their session then); the result states what was reached,
    read back from the manager.
    """
    def late() -> bool:
        return give_up is not None and clock() >= give_up

    stack = contextlib.ExitStack()
    cur = {"manager": manager, "authority": authority}
    swaps = [0]

    def usable() -> None:
        """Before every step: a session that finished (a job operation ran out of its
        transport allowance, in the finalizer's own settlement too) is replaced by a
        new one, so the reserved mask, reload and exact-masked confirmation run on a
        session that can still send them."""
        if fresh is None or swaps[0] >= 4 or late():
            return  # bounded: at most one new session per step, and never past give_up
        if not getattr(getattr(cur["manager"], "call", None), "broken", False):
            return
        swaps[0] += 1
        try:
            m, a = stack.enter_context(fresh())
        except Exception:  # noqa: BLE001 - go on with the old session
            return
        if give_up is not None:
            bind_remaining(m, give_up, clock)
        cur["manager"], cur["authority"] = m, a

    try:
        try:
            remove_contextd_marker(root)
        except Exception:  # noqa: BLE001
            pass
        usable()
        if settle is not None and not late():
            # A job still pending (or never looked at, when the withdrawal failed
            # before its job stage) is replaced and recorded BEFORE the mask and the
            # reload, which would make systemd fail it. Once: `settle` knows.
            try:
                settle(True)
            except Exception:  # noqa: BLE001 - the mask goes on
                pass
        for step in (lambda m: m.mask(CONTEXTD_UNIT), lambda m: m.reload()):
            usable()
            if late():
                break
            try:
                step(cur["manager"])
            except Exception:  # noqa: BLE001 - every step is tried
                # The call itself finished the session: the same step, once more,
                # on a new one.
                before = cur["manager"]
                usable()
                if cur["manager"] is not before and not late():
                    try:
                        step(cur["manager"])
                    except Exception:  # noqa: BLE001
                        pass
        usable()
        try:
            if not late() and not stop_sent and not contextd_is_quiet(cur["authority"]):
                cur["authority"].stop(CONTEXTD_UNIT)
        except Exception:  # noqa: BLE001
            pass
        usable()
        masked = quiet = False
        if not late():
            try:
                masked = cur["authority"].file_state(CONTEXTD_UNIT) == "masked"
            except Exception:  # noqa: BLE001
                masked = False
            quiet = contextd_is_quiet(cur["authority"])
        cgroup = contextd_cgroup(cur["authority"]) if not late() else "unknown"
        return {"final_masked": masked, "final_quiet": quiet, "cgroup": cgroup}
    finally:
        stack.close()


class QueuedJobState:
    """Whether the pass left the broker's start job queued, and whether it was dealt with.

    `held` is set by the preflight when it finds the broker inactive, unmasked
    and with a start job queued; `done` once the job has been replaced (or its
    fate recorded). Shared by everything that can mask the broker afterwards.
    """

    def __init__(self) -> None:
        self.held = False
        self.done = False


def release_queued_job(*, state: QueuedJobState, authority: ContextdStopAuthority,
                       ledger: AuditLedger, now: str, actor: str, invocation_id: str,
                       deadline: Optional[float], reason: str,
                       clock: Callable[[], float] = time.monotonic,
                       sleep: Callable[[float], None] = time.sleep,
                       sink: Optional[Callable[[dict], None]] = None,
                       transport: Optional[Callable[[float], None]] = None) -> None:
    """Replace the held start job BEFORE the broker is masked, once.

    Masking and reloading make systemd fail a pending start job ("Failed to
    start"), which is neither a replacement nor a record. So whatever is about
    to mask the broker (the verdict's mask, a rollback, an emergency narrowing)
    calls this first: `StopUnit(replace)`, wait until no job is left, record
    `activation.queued_job_replaced`. If the job is already gone, its fate is
    recorded as `activation.queued_job_ended` with what can still be read.
    A replacement that fails is recorded by `clear_contextd_job` and does not
    stop the mask that follows (the reload then fails the job: fail-closed).
    """
    if not state.held or state.done:
        return
    state.done = True
    emit = sink if sink is not None else (lambda event: _record(ledger, event))
    try:
        replaced = clear_contextd_job(
            authority=authority, ledger=ledger, now=now, actor=actor, reason=reason,
            invocation_id=invocation_id, deadline=job_wait_limit(deadline, clock),
            sink=sink, clock=clock, sleep=sleep, transport=transport, outer=deadline)
    except Exception:  # noqa: BLE001 - recorded by clear_contextd_job; the mask goes on
        return
    if replaced:
        return
    observed: dict = {}
    for key, read in (("active_state", authority.active_state),
                      ("unit_file_state", authority.file_state)):
        try:
            observed[key] = read(CONTEXTD_UNIT)
        except Exception:  # noqa: BLE001 - what cannot be read is not recorded
            observed[key] = None
    emit({
        "event_type": "activation.queued_job_ended", "unit": CONTEXTD_UNIT,
        "reason": reason, "observed_active_state": observed["active_state"],
        "observed_unit_file_state": observed["unit_file_state"],
        "invocation_id": invocation_id, "occurred_at": now, "actor": actor,
    })


def withdraw_contextd(
    *, reason: str, manager: UnitManager, authority: ContextdStopAuthority,
    root: Path, ledger: AuditLedger, now: str, actor: str, invocation_id: str,
    deadline: Optional[float] = None,
    final_deadline: Optional[float] = None,
    bind_deadline: Optional[Callable[[float], None]] = None,
    sink: Optional[Callable[[dict], None]] = None,
    fresh,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Withdraw the broker; returns the recorded timings, or raises.

    The record is handed to `sink` when one is given, and appended to
    `ledger` (failures swallowed) otherwise. The recheck passes a sink that
    appends under the pass lock and remembers a failure, so that an unwritten
    record makes its exit status non-zero.

    `deadline` is the monotonic instant the withdrawal's steps must end by
    (the caller's budget less its reserve); the stop wait is also capped at
    20 s. A step started after it is not started: the finalizer runs instead,
    inside the reserve, up to `final_deadline`. `bind_deadline(d)` is called
    with the deadline that bounds the bus calls from then on (first
    `deadline`, then `final_deadline` for the finalizer), so no call outlasts
    the time that is left.
    """
    started = clock()
    emit = sink if sink is not None else (lambda event: _record(ledger, event))
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
                           stop_sent=stop_sent, give_up=final_deadline, clock=clock,
                           settle=settle_job, fresh=fresh)
        emit({
            "event_type": "activation.withdrawal_unconfirmed",
            "unit": CONTEXTD_UNIT, "reason": reason, "stage": stage, "why": why,
            "invocation_id": invocation_id, **timings, **reached,
            "occurred_at": now, "actor": actor,
        })
        return WithdrawalUnconfirmed(
            f"withdrawal of the Knowledge Context broker unconfirmed at {stage}")

    needs_stop = False
    quiet_state = "inactive"
    cgroup = "unknown"
    job_attempted = False

    def settle_job(in_finalizer: bool = False) -> bool:
        """Replace a pending start job, once, with the queued-job record.

        The one place that does it, for the job stage and for the finalizer: a
        job found is replaced (`StopUnit replace`, wait bounded so that the mask
        keeps its reserve) and recorded as `activation.queued_job_replaced`
        exactly once; a wait that times out is recorded and the mask goes on.
        """
        nonlocal job_attempted, stop_sent
        if job_attempted:
            return False
        job_attempted = True
        # The finalizer works against the final deadline (the steps' own deadline
        # has passed by then); the job stage against the steps' deadline.
        base = (final_deadline if (in_finalizer and final_deadline is not None)
                else (deadline if deadline is not None else final_deadline))
        try:
            replaced = clear_contextd_job(
                authority=authority, ledger=ledger, now=now, actor=actor,
                reason=reason, invocation_id=invocation_id,
                deadline=job_wait_limit(base, clock),
                sink=emit, clock=clock, sleep=sleep,
                transport=bind_deadline, outer=base)
        except WithdrawalUnconfirmed:
            return False  # recorded by clear_contextd_job; masking follows
        if replaced:
            stop_sent = True
            timings["t_stop_ms"] = _ms(started, clock)
        return replaced

    if bind_deadline is not None and deadline is not None:
        bind_deadline(deadline)
    try:
        remove_contextd_marker(root)
        timings["t_marker_ms"] = _ms(started, clock)
        stage = "job"
        over()
        settle_job()
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
                      or _job_twice(authority) != NO_JOB
                      or contextd_cgroup(authority) != "empty")
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
        stage = "cgroup"
        cgroup = contextd_cgroup(authority)
        if quiet_state not in QUIET_STATES or cgroup != "empty":
            raise UnitOperationFailed("the broker's cgroup is not confirmed empty")
        timings["t_inactive_ms"] = _ms(started, clock)
    except Exception as exc:  # noqa: BLE001 - recorded as a class name, then raised
        raise unconfirmed(type(exc).__name__) from None
    emit({
        "event_type": "activation.grant_withdrawn",
        "unit": CONTEXTD_UNIT, "reason": reason, "stopped": needs_stop,
        "quiet_state": quiet_state, "cgroup": cgroup,
        "invocation_id": invocation_id, **timings,
        "occurred_at": now, "actor": actor,
    })
    return timings


def clear_contextd_job(
    *, authority: ContextdStopAuthority, ledger: AuditLedger, now: str, actor: str,
    reason: str, invocation_id: str, deadline: Optional[float] = None,
    sink: Optional[Callable[[dict], None]] = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    transport: Optional[Callable[[float], None]] = None,
    outer: Optional[float] = None,
) -> bool:
    """Replace a start job the manager has queued for a broker that is not granted.

    Returns True when a job was found and replaced. A job that cannot be
    read or replaced within the budget raises `WithdrawalUnconfirmed`.

    `deadline` bounds the job operations themselves, not only the sleeps between
    polls: when `transport` is given it is called with `deadline` before the first
    Job read and with `outer` afterwards, so that the session's own per-call limit
    (the Job reads, StopUnit and the polling) ends before the time reserved for
    the mask that follows.
    """
    if transport is not None and deadline is not None:
        transport(deadline)
    try:
        return _clear_job(authority, ledger, now, actor, reason, invocation_id,
                          deadline, sink, clock, sleep)
    finally:
        if transport is not None and outer is not None:
            transport(outer)


def _clear_job(authority, ledger, now, actor, reason, invocation_id, deadline, sink,
               clock, sleep) -> bool:
    started = clock()
    emit = sink if sink is not None else (lambda event: _record(ledger, event))
    try:
        if _job_twice(authority) == NO_JOB:
            return False
        authority.stop(CONTEXTD_UNIT)
        give_up = clock() + STOP_WAIT_SECONDS
        if deadline is not None:
            give_up = min(give_up, deadline)
        if not _wait_until(lambda: authority.job(CONTEXTD_UNIT) == NO_JOB,
                           give_up=give_up, clock=clock, sleep=sleep):
            raise TimeoutError("the queued job did not clear in time")
    except Exception as exc:  # noqa: BLE001 - recorded as a class name, then raised
        emit({
            "event_type": "activation.withdrawal_unconfirmed",
            "unit": CONTEXTD_UNIT, "reason": reason, "stage": "job",
            "why": type(exc).__name__, "invocation_id": invocation_id,
            "occurred_at": now, "actor": actor,
        })
        raise WithdrawalUnconfirmed(
            "queued job of the Knowledge Context broker unconfirmed") from None
    emit({
        "event_type": "activation.queued_job_replaced",
        "unit": CONTEXTD_UNIT, "reason": reason, "t_ms": _ms(started, clock),
        "invocation_id": invocation_id, "occurred_at": now, "actor": actor,
    })
    return True
