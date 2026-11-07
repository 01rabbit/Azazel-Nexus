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
`model_runtime.RUNTIMES` -- code in the package, pinned in this build -- and
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
import json
import selectors
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional, Sequence

from azazel_nexus.model_runtime import (
    RuntimeBinary,
    RuntimeRefused,
    resolve_runtime,
)
from azazel_nexus.runtime_lifecycle import (
    STDIO_BYTE_CEILING,
    BudgetLedger,
    LifecycleState,
    Readiness,
    RestartBudget,
)

__all__ = [
    "ProcessReport",
    "ServingProcess",
    "SupervisorRefused",
    "StopResult",
    "StopState",
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


class StopState(str, Enum):
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"
    REFUSED = "refused"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class StopResult:
    state: StopState
    reason: str

    scope: str = "owned_runtime_group_no_new_session_or_cgroup"


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

    # Retain ownership on uncertain cleanup; never publish it through as_event().
    process: subprocess.Popen | None = field(default=None, repr=False, compare=False)
    start_identity: str | None = field(default=None, repr=False)
    group: int | None = field(default=None, repr=False)

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


def _write_stop_fence(path: Path, value: dict) -> None:
    """Shared durable uncertainty record; callers close their gate before writing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.pending")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _stop_fence_present(path: Path) -> bool:
    # Each state directory has one owner. Unknown/corrupt records fail closed.
    try:
        path.read_text()
        return True
    except FileNotFoundError:
        return path.with_suffix(".json.pending").exists()
    except (OSError, ValueError):
        return True


_unconfirmed_runs: dict[tuple[Path, str], ProcessReport] = {}


def run_once(
    record: RuntimeBinary,
    *,
    root: Path,
    deadline_seconds: int = DEFAULT_DEADLINE_SECONDS,
    ready_token: bytes = b"READY",
    clock: Optional[Callable[[], float]] = None,
    ledger: Optional[BudgetLedger] = None,
) -> ProcessReport:
    """Start one process, observe it, and make sure nothing is left behind.

    `root` is where `record.executable` is resolved **relative to**, so a test
    can supply its own tree without this module gaining a path parameter a
    caller could point anywhere. The argv is still the record's.

    Returns rather than raises for every way a process can misbehave: a
    supervisor whose ordinary outcomes were exceptions would be a supervisor
    whose caller writes `except Exception` and continues.
    """

    owner = (root.resolve(), record.runtime_id)
    fence_path = (ledger.path.parent if ledger is not None else root) / "stop-fence.json"
    if owner in _unconfirmed_runs:
        return _unconfirmed_runs[owner]
    if _stop_fence_present(fence_path):
        return ProcessReport(
            state=LifecycleState.FENCED, readiness=Readiness.NOT_CHECKED,
            exit_code=None, signalled=None, stdout_bytes=0, stderr_bytes=0,
            stdout_truncated=False, stderr_truncated=False,
            reason="prior process cleanup unconfirmed; provider fenced",
        )
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
    identity = _process_identity(process.pid)

    readiness = Readiness.NOT_CHECKED
    stdout_bytes = stderr_bytes = 0
    stdout_truncated = stderr_truncated = False
    observation_error = None
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
    except Exception as exc:
        observation_error = exc
    finally:
        try:
            cleanup = _terminate_group(process, group=group, identity=identity)
        except Exception as exc:
            cleanup = StopResult(StopState.UNKNOWN, f"cleanup observation exception: {type(exc).__name__}: {exc}")
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    if cleanup.state is not StopState.CONFIRMED:
        report = ProcessReport(
            state=LifecycleState.FENCED, readiness=readiness, exit_code=process.returncode,
            signalled=None, stdout_bytes=stdout_bytes, stderr_bytes=stderr_bytes,
            stdout_truncated=stdout_truncated, stderr_truncated=stderr_truncated,
            reason="process cleanup unconfirmed: " + cleanup.reason + (
                f"; observation exception: {type(observation_error).__name__}: {observation_error}"
                if observation_error is not None else ""
            ),
            process=process, start_identity=identity, group=group,
        )
        _unconfirmed_runs[owner] = report
        try:
            _write_stop_fence(fence_path, dict(
                runtime_id=record.runtime_id, pid=process.pid,
                start_identity=identity, group=group, state="unconfirmed", time=time.time(),
            ))
        except OSError:
            # Keep ownership and refusal even when durable storage is unavailable.
            report = ProcessReport(**{**report.__dict__, "reason": report.reason + "; fence_write_failed"})
            _unconfirmed_runs[owner] = report
        return report

    if observation_error is not None:
        raise observation_error

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


def _proc_stat(pid: int) -> tuple[int, str]:
    # comm can contain spaces and parentheses; fields after its final ')' start at 3.
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return int(fields[2]), fields[19]


def _process_identity(pid: int) -> str | None:
    try:
        if sys.platform.startswith("linux"):
            return _proc_stat(pid)[1]
        result = subprocess.run(
            ["/bin/ps", "-o", "lstart=", "-p", str(pid)],
            capture_output=True, text=True, timeout=GRACE_SECONDS, check=False,
        )
        return result.stdout.strip() or None
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        return None


def _group_members(group: int) -> tuple[int, ...] | None:
    """Observe only membership of our recorded group. None means unknown."""
    try:
        if sys.platform.startswith("linux"):
            members = []
            for path in Path("/proc").iterdir():
                if path.name.isdecimal():
                    try:
                        pgid, _ = _proc_stat(int(path.name))
                    except (FileNotFoundError, ProcessLookupError):
                        continue
                    if pgid == group:
                        members.append(int(path.name))
            return tuple(members)
        result = subprocess.run(
            ["/bin/ps", "-o", "pid=", "-g", str(group)],
            capture_output=True, text=True, timeout=GRACE_SECONDS, check=False,
        )
        if result.returncode not in (0, 1) or result.stderr.strip():
            return None
        return tuple(int(pid) for pid in result.stdout.split())
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        return None


def _terminate_group(process: subprocess.Popen, *, group: int,
                     identity: str | None = None) -> StopResult:
    """Bounded stop of a spawn-owned session; never infer identity from a PID alone.

    A reaped leader may leave the original group populated. Its pgid remains
    reserved while those members exist. A different leader identity refuses
    signalling; escaped descendants are outside the stated scope.
    """
    if identity is None or group != process.pid:
        return StopResult(StopState.UNKNOWN, "start_identity_unknown")
    try:
        current = _process_identity(process.pid)
        # poll reaps only our direct child. An absent /proc entry is acceptable
        # only after that child has been reaped, with its spawn identity retained.
        reaped = process.poll() is not None
        if current != identity and (current is not None or not reaped):
            return StopResult(StopState.UNKNOWN, "start_identity_mismatch")
        for sig in (signal.SIGTERM, signal.SIGKILL):
            members = _group_members(group)
            if members is None:
                return StopResult(StopState.UNKNOWN, "group_observation_failed")
            if members:
                current = _process_identity(process.pid)
                if current is not None and current != identity:
                    return StopResult(StopState.UNKNOWN, "start_identity_mismatch")
                try:
                    os.killpg(group, sig)
                except ProcessLookupError:
                    pass  # Verify absence below; ESRCH alone is not confirmation.
            try:
                process.wait(timeout=GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                if sig == signal.SIGKILL:
                    return StopResult(StopState.UNCONFIRMED, "wait_timeout")
                continue
            until = time.monotonic() + GRACE_SECONDS
            while True:
                members = _group_members(group)
                if members is None:
                    return StopResult(StopState.UNKNOWN, "group_observation_failed")
                if not members:
                    # EOF proves no inherited writer remains on owned output
                    # pipes. Never close them first and mistake that for EOF.
                    for name in ("stdout", "stderr"):
                        stream = getattr(process, name, None)
                        if stream is None:
                            continue
                        os.set_blocking(stream.fileno(), False)
                        drained = 0
                        while drained <= STDIO_BYTE_CEILING:
                            try:
                                chunk = os.read(stream.fileno(), 4096)
                            except BlockingIOError:
                                return StopResult(StopState.UNCONFIRMED, "owned_pipe_writer_remaining")
                            if not chunk:
                                break
                            drained += len(chunk)
                        else:
                            return StopResult(StopState.UNCONFIRMED, "owned_pipe_eof_unconfirmed")
                    return StopResult(StopState.CONFIRMED, "parent_reaped_group_absent")
                if time.monotonic() >= until:
                    break
                time.sleep(0.01)
        return StopResult(StopState.UNCONFIRMED, "group_remaining")
    except PermissionError:
        return StopResult(StopState.REFUSED, "signal_refused")
    except (OSError, ValueError):
        return StopResult(StopState.UNKNOWN, "process_observation_failed")


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
        if self.budget.fenced:
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
        if supervision.budget.fenced:
            # Includes a budget **loaded from disk** as already spent, which
            # is what stops a reboot from handing back three more restarts.
            break
        report = run_once(
            supervision.record,
            root=supervision.root,
            deadline_seconds=supervision.deadline_seconds,
            ledger=supervision.ledger,
        )
        supervision.reports.append(report)
        if report.state is LifecycleState.FENCED:
            supervision.budget.fenced = True
            if supervision.ledger is not None:
                supervision.ledger.save(supervision.budget, runtime_id=supervision.record.runtime_id)
            break
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
    into a command. `RUNTIMES` is pinned in this build, so the ordinary result
    is a refusal.
    """

    try:
        record = resolve_runtime(runtime_id)
    except RuntimeRefused as exc:
        raise SupervisorRefused(str(exc)) from exc
    return run_once(record, root=root, deadline_seconds=deadline_seconds)


class ServingProcess:
    """Long-lived process handle. Output is discarded, never piped or logged."""

    def __init__(self, record: RuntimeBinary, *, root: Path, descriptors=None) -> None:
        self.record = record
        self.descriptors = descriptors
        self.root = root
        self.process: subprocess.Popen | None = None
        self.start_identity: str | None = None

    def start(self) -> None:
        from azazel_nexus import model_admission

        if model_admission.LOCAL_MODEL_ADMISSION_ENABLED is not True:
            raise SupervisorRefused("ADMISSION_DISABLED")
        if self.descriptors is None:
            raise SupervisorRefused("held verified descriptors required")
        if self.process is not None:
            raise SupervisorRefused("stop the previous process group before starting")
        self.descriptors.recheck(full=True)
        executable = f"/proc/self/fd/{self.descriptors.binary_fd}"
        argv = [executable, *self.record.argv[1:]]
        index = argv.index("-m") + 1
        argv[index] = f"/proc/self/fd/{self.descriptors.model_fd}"
        try:
            self.process = subprocess.Popen(
                argv, executable=executable,
                pass_fds=(self.descriptors.binary_fd, self.descriptors.model_fd),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env={"PATH": "/nonexistent", "LC_ALL": "C"}, cwd=str(self.root),
                start_new_session=True, close_fds=True,
            )
        except (OSError, ValueError):
            raise SupervisorRefused("the serving process did not start") from None
        self.start_identity = _process_identity(self.process.pid)

    @property
    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def stop(self, *, retain: bool = False) -> StopResult:
        if self.process is None:
            return StopResult(StopState.UNKNOWN, "no_owned_process_identity")
        result = _terminate_group(self.process, group=self.process.pid, identity=self.start_identity)
        if result.state is StopState.CONFIRMED and not retain:
            self.process = None
        return result
