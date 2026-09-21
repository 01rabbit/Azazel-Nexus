"""The second module that may start a process, and the only one that
supervises one (#114).

`edge_probed.py` runs a fixed health contract once and exits. This starts a
**long-lived** process and watches it: readiness, a bounded request, a crash,
a restart against a finite budget, a rollback, and bounded output.

Both exemptions are named in `tests/unit/test_runtime_activated.py`. Naming
them is the point: you can say where this product executes, and a third
module cannot acquire the ability by accident.

## What a caller may influence

A **runtime ID**, and nothing else. It is looked up in
`model_runtime.RUNTIMES` -- code in the package, empty in this build -- and
the resulting record carries the whole argv, already fixed, with no hole
anything can fill.

There is no parameter here for a command, a path, an environment variable, an
option or a working directory. The environment is **replaced, not
inherited**: a provider that inherited this daemon's environment would
inherit whatever the service manager happened to set, which is not something
this node decided.

## Bounded on every axis that a process can be unbounded on

| axis | bound |
| --- | --- |
| time to start and answer | a deadline, with an injected clock |
| stdout and stderr | `STDIO_BYTE_CEILING`, and reading **stops** there |
| restarts | `RestartBudget`, per generation, fencing when spent |
| children | its own process group, killed as a group |

## Nothing here widens

No lease, no activation, no unmask, no enforcement. A process that comes back
comes back under the same containment it had. `run_once` returns what
happened; deciding what a node may do about it belongs to the components that
own that decision.
"""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

from azazel_nexus.model_runtime import RuntimeBinary, RuntimeRefused, resolve_runtime
from azazel_nexus.runtime_lifecycle import (
    BudgetLedger,
    LifecycleState,
    Readiness,
    RestartBudget,
    STDIO_BYTE_CEILING,
)

__all__ = [
    "ProcessReport",
    "SupervisorRefused",
    "Supervision",
    "run_once",
    "supervise",
]

#: How long a process gets to start, answer and be reaped. A supervisor with
#: no deadline is a supervisor that can wait for ever on a process that will
#: never answer -- which is the failure it exists to notice.
DEFAULT_DEADLINE_SECONDS = 10

#: How long a terminated process gets to exit before it is killed.
GRACE_SECONDS = 2


class SupervisorRefused(Exception):
    """A process that will not be started. Refused, never repaired."""


@dataclass(frozen=True)
class ProcessReport:
    """One run of one process. Counts, a state, a reason -- never output.

    `stdout_bytes` and `stderr_bytes` are **counts**. The output itself is
    not carried: a report that held it would be a report that carried
    whatever a provider chose to write into the journal.
    """

    state: LifecycleState
    readiness: Readiness
    exit_code: Optional[int]
    signalled: Optional[int]
    stdout_bytes: int
    stderr_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool
    reason: str

    def as_event(self) -> dict:
        return {
            "event_type": "mio.runtime.process",
            "state": self.state.value,
            "readiness": self.readiness.value,
            "exit_code": self.exit_code,
            "signalled": self.signalled,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "truncated": self.stdout_truncated or self.stderr_truncated,
            "reason": self.reason,
        }


def _drain_bounded(
    process: subprocess.Popen,
    *,
    ceiling: int,
    remaining: Callable[[], float],
) -> tuple:
    """Read at most `ceiling` bytes from each pipe, then **stop reading**.

    Stopping is the point. `Popen.communicate` reads until EOF, so a ceiling
    applied to its result is a ceiling on what is kept, not on what the node
    spent getting there -- and a provider that can make this daemon drain two
    megabytes has decided how much memory this daemon uses, whatever the
    report says afterwards.

    Returns `(stdout, stderr, stdout_truncated, stderr_truncated, timed_out)`.
    """

    selector = selectors.DefaultSelector()
    buffers = {}
    truncated = {}
    for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
        buffers[name] = bytearray()
        truncated[name] = False
        if stream is not None:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)

    timed_out = False
    try:
        while selector.get_map():
            budget = remaining()
            if budget <= 0:
                timed_out = True
                break
            for key, _events in selector.select(timeout=min(budget, 0.25)):
                name = key.data
                try:
                    chunk = key.fileobj.read(4096)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    selector.unregister(key.fileobj)
                    continue
                if chunk is None:
                    continue
                if chunk == b"":
                    selector.unregister(key.fileobj)
                    continue
                room = ceiling - len(buffers[name])
                if len(chunk) >= room:
                    buffers[name].extend(chunk[:room])
                    truncated[name] = True
                    # Stop reading this pipe entirely. The writer will block
                    # or fail, and either is a bounded outcome.
                    selector.unregister(key.fileobj)
                else:
                    buffers[name].extend(chunk)
            if not selector.get_map():
                break
            if process.poll() is not None and not selector.get_map():
                break
    finally:
        selector.close()

    return (
        bytes(buffers["stdout"]),
        bytes(buffers["stderr"]),
        truncated["stdout"],
        truncated["stderr"],
        timed_out,
    )


def run_once(
    record: RuntimeBinary,
    *,
    root: Path,
    deadline_seconds: int = DEFAULT_DEADLINE_SECONDS,
    ready_token: bytes = b"READY",
    clock: Optional[Callable[[], float]] = None,
) -> ProcessReport:
    """Start one process, observe it, and make sure nothing is left behind.

    `root` is where `record.executable` is resolved **relative to**, so a test
    can supply its own tree without this module gaining a path parameter a
    caller could point anywhere. The argv is still the record's.

    Returns rather than raises for every way a process can misbehave: a
    supervisor whose ordinary outcomes were exceptions would be a supervisor
    whose caller writes `except Exception` and continues.
    """

    now = clock or time.monotonic
    started = now()

    def remaining() -> float:
        return deadline_seconds - (now() - started)

    # **Absolute**, and resolved before the child chdirs. On POSIX the child
    # changes directory and *then* execs, so a relative program path is
    # resolved against `cwd` rather than against the directory this daemon
    # was started in -- which silently becomes "no such file" for a binary
    # that is plainly there.
    binary = (root / record.executable.lstrip("/")).resolve()
    argv = [str(binary), *record.argv[1:]]

    try:
        process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            # Replaced, never inherited. A provider that inherited this
            # daemon's environment would inherit whatever the service manager
            # happened to set.
            env={"PATH": "/nonexistent", "LC_ALL": "C"},
            cwd=str(root),
            # Its own process group, so that a child this process spawns is
            # killed with it rather than left orphaned on the node.
            start_new_session=True,
            close_fds=True,
        )
    except (OSError, ValueError) as exc:
        return ProcessReport(
            state=LifecycleState.ABSENT,
            readiness=Readiness.NOT_CHECKED,
            exit_code=None,
            signalled=None,
            stdout_bytes=0,
            stderr_bytes=0,
            stdout_truncated=False,
            stderr_truncated=False,
            reason=f"the process did not start: {exc}",
        )

    # Captured now, while the child is certainly alive. `start_new_session`
    # makes it a session leader, so its group id is its pid -- and once it is
    # reaped, `os.getpgid(pid)` raises and the group becomes unfindable. A
    # cleanup that can only run while the thing it cleans up is alive is a
    # cleanup that misses exactly the orphans it exists for.
    group = process.pid

    readiness = Readiness.NOT_CHECKED
    try:
        out, err, stdout_truncated, stderr_truncated, timed_out = _drain_bounded(
            process, ceiling=STDIO_BYTE_CEILING, remaining=remaining
        )
        stdout_bytes = len(out)
        stderr_bytes = len(err)
        if not timed_out:
            try:
                process.wait(timeout=max(remaining(), 0.05))
            except subprocess.TimeoutExpired:
                timed_out = True
        if ready_token in out:
            readiness = Readiness.PASSED
        elif out or err:
            readiness = Readiness.FAILED
    finally:
        _terminate_group(process, group=group)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    code = process.returncode
    signalled = -code if code is not None and code < 0 else None

    if timed_out:
        return ProcessReport(
            state=LifecycleState.STOPPED,
            # Whatever was observed before the deadline, carried through
            # rather than reset. A provider that answered and *then* flooded
            # did both, and a report that said `not-checked` would erase the
            # first -- while one that said `failed` would invent a failure
            # nobody observed. A process that simply hung said nothing, so it
            # still reports `not-checked`, from the same field.
            readiness=readiness,
            exit_code=None,
            signalled=signalled,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            reason=(
                f"the process did not finish inside {deadline_seconds}s and "
                "was stopped; a process with no deadline is one nobody learns "
                "has stopped answering"
            ),
        )

    if signalled is not None:
        state = LifecycleState.CRASHED
        reason = f"the process was terminated by signal {signalled}"
    elif code:
        state = LifecycleState.CRASHED
        reason = f"the process exited {code} without being asked to"
    else:
        state = (
            LifecycleState.SERVING
            if readiness is Readiness.PASSED
            else LifecycleState.STOPPED
        )
        reason = (
            "the process answered and exited cleanly"
            if readiness is Readiness.PASSED
            else "the process exited cleanly without answering a readiness probe"
        )

    return ProcessReport(
        state=state,
        readiness=readiness,
        exit_code=code,
        signalled=signalled,
        stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        reason=reason,
    )


def _terminate_group(process: subprocess.Popen, *, group: int) -> None:
    """Stop the process **and anything it started**.

    By process group, because a provider that forks leaves the node with a
    child nothing is watching -- and an orphan that keeps a port or a file
    open is a failure that outlives the thing that caused it.

    `group` is passed in rather than derived from the process, because a
    parent that has already exited cannot be asked for its group: the
    children are still there, and the one way to find them has gone with it.
    """

    if process.poll() is None:
        _signal_group(group, signal.SIGTERM)
        try:
            process.wait(timeout=GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
    # Unconditionally, and after reaping. A parent that exited cleanly may
    # still have left the group populated, which is the orphan case.
    _signal_group(group, signal.SIGKILL)
    try:
        process.wait(timeout=GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass


def _signal_group(group: int, sig: int) -> None:
    try:
        os.killpg(group, sig)
    except (ProcessLookupError, PermissionError, OSError):
        pass


@dataclass
class Supervision:
    """One provider, supervised across restarts within one generation."""

    record: RuntimeBinary
    root: Path
    budget: RestartBudget
    deadline_seconds: int = DEFAULT_DEADLINE_SECONDS
    reports: list = field(default_factory=list)
    #: Where the budget is written after every change. Without it the budget
    #: lives only in this process, and the failure most likely to end this
    #: process is the one it is restarting -- so a provider that crashes hard
    #: enough would get a fresh budget every time, for ever.
    ledger: Optional[BudgetLedger] = None
    #: Called once, when the budget runs out, with the unit key to fence.
    #: Supplied rather than imported: the component that observes a failure is
    #: not the component that narrows on it, and this one cannot widen.
    on_budget_spent: Optional[Callable[[str], None]] = None
    #: The unit key handed to `on_budget_spent`. A value from
    #: `units.UnitKey`, never an arbitrary unit name.
    unit_key: str = "mio-local"

    @property
    def state(self) -> LifecycleState:
        if self.budget.fenced and not self.budget.remaining:
            return LifecycleState.FENCED
        if not self.reports:
            return LifecycleState.ABSENT
        return self.reports[-1].state


def supervise(supervision: Supervision, *, attempts: int = 8) -> Supervision:
    """Run, and restart on a crash until the budget is spent.

    `attempts` is a hard stop on the loop itself, above the budget. A loop
    bounded only by the thing it is testing is a loop that runs for ever when
    that thing is wrong, and a test that hangs is a test nobody keeps.
    """

    if attempts < 1:
        raise SupervisorRefused("a supervision that runs nothing supervises nothing")

    for _ in range(attempts):
        if supervision.budget.fenced and not supervision.budget.remaining:
            # Includes a budget **loaded from disk** as already spent, which
            # is what stops a reboot from handing back three more restarts.
            break
        report = run_once(
            supervision.record,
            root=supervision.root,
            deadline_seconds=supervision.deadline_seconds,
        )
        supervision.reports.append(report)
        if report.state is not LifecycleState.CRASHED:
            break
        verdict = supervision.budget.spend()
        if supervision.ledger is not None:
            # Persisted on **every** spend, not only on the last. A crash
            # between the spend and the write would otherwise hand back the
            # restart that was just used.
            supervision.ledger.save(
                supervision.budget, runtime_id=supervision.record.runtime_id
            )
        if not verdict.may_restart:
            supervision.reports.append(
                ProcessReport(
                    state=LifecycleState.FENCED,
                    readiness=Readiness.NOT_CHECKED,
                    exit_code=None,
                    signalled=None,
                    stdout_bytes=0,
                    stderr_bytes=0,
                    stdout_truncated=False,
                    stderr_truncated=False,
                    reason=verdict.reason,
                )
            )
            if supervision.on_budget_spent is not None:
                # The consequence, handed to whoever owns narrowing. It runs
                # after the budget is persisted, so a failure here leaves a
                # node that is fenced in the ledger rather than one that
                # believes it has restarts left.
                supervision.on_budget_spent(supervision.unit_key)
            break
    return supervision


def start_for(
    runtime_id: str, *, root: Path, deadline_seconds: int = DEFAULT_DEADLINE_SECONDS
) -> ProcessReport:
    """Resolve a **symbol** and run what it names. The only entry a caller has.

    `runtime_id` is looked up, never joined to a path and never formatted
    into a command. `RUNTIMES` is empty in this build, so the ordinary result
    is a refusal.
    """

    try:
        record = resolve_runtime(runtime_id)
    except RuntimeRefused as exc:
        raise SupervisorRefused(str(exc)) from exc
    return run_once(record, root=root, deadline_seconds=deadline_seconds)
