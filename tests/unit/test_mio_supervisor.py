"""Process lifecycle, driven against a **real process** (#114).

#112 fixed the service boundary on a build that starts nothing, and its
`crashed` state was an injected one. That is not a crash. This file starts
`tests/fixtures/runtime_stub/...`, an actual process, and watches it start,
answer, stay silent, hang, crash, die by signal, flood its output and leave a
child behind.

## Two kinds of evidence, kept apart

Every test here is marked `real_process` or `injected`, and
`test_the_two_kinds_of_evidence_are_distinguishable` asserts that both sets
are non-empty and disjoint. Mixing them into one list would let a suite of
injected states read as a suite of process evidence -- which is precisely the
confusion #112 left behind and #114 exists to remove.

## Nothing here is a provider

The stub is under `tests/`. It is not in `model_runtime.RUNTIMES`, not in the
catalog, not in the installer, not in the preset;
`test_runtime_stub_containment.py` scans for that in both directions. No real
model, no real inference, no provider admission is claimed.

## Everything finishes

Deadlines are seconds, the supervision loop has a hard attempt bound above
the restart budget, and no test sleeps waiting for something to happen.
"""

from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "runtime" / "src"))

from azazel_nexus.model_runtime import RuntimeBinary  # noqa: E402
from azazel_nexus.runtime_lifecycle import (  # noqa: E402
    LifecycleState,
    MAX_RESTARTS,
    Readiness,
    RestartBudget,
    STDIO_BYTE_CEILING,
)
from azazel_nexus_runtime.mio_supervisor import (  # noqa: E402
    ProcessReport,
    Supervision,
    SupervisorRefused,
    run_once,
    start_for,
    supervise,
)

STUB_ROOT = REPO_ROOT / "tests" / "fixtures" / "runtime_stub"
STUB = "/usr/libexec/azazel/az-runtime-stub"

real_process = pytest.mark.real_process
injected = pytest.mark.injected


def stub(behaviour: str = "ready") -> RuntimeBinary:
    """A record naming the stub, with the behaviour **in the fixed argv**.

    Not in an environment variable: the supervisor replaces the environment,
    and a stub steered by one would be a stub steered by something the
    supervisor does not control -- which is the opposite of what is being
    tested.
    """

    return RuntimeBinary(
        runtime_id="stub",
        executable=STUB,
        version="1",
        digest="sha256:" + "0" * 64,
        argv=(STUB, behaviour),
    )


def run(behaviour: str = "ready", **kwargs) -> ProcessReport:
    kwargs.setdefault("deadline_seconds", 10)
    return run_once(stub(behaviour), root=STUB_ROOT, **kwargs)


# == real process: start and readiness ====================================


@real_process
def test_a_real_process_starts_and_answers():
    report = run("ready")
    assert report.state is LifecycleState.SERVING
    assert report.readiness is Readiness.PASSED
    assert report.exit_code == 0


@real_process
def test_starting_is_not_being_ready():
    """A process that started is a process that started.

    The stub exits cleanly having said nothing. Reporting that as ready would
    be reporting a start as an answer.
    """

    report = run("silent")
    assert report.state is LifecycleState.STOPPED
    assert report.readiness is Readiness.NOT_CHECKED
    assert report.readiness is not Readiness.PASSED
    assert report.readiness is not Readiness.FAILED


@real_process
def test_a_process_that_never_answers_is_stopped_at_its_deadline():
    """Bounded in wall-clock, so this test cannot hang either."""

    began = time.monotonic()
    report = run("hang", deadline_seconds=1)
    elapsed = time.monotonic() - began

    assert report.state is LifecycleState.STOPPED
    assert report.readiness is Readiness.NOT_CHECKED
    assert elapsed < 10, f"the supervisor waited {elapsed:.1f}s on a 1s deadline"


# == real process: crash ==================================================


@real_process
def test_a_real_process_crash_is_observed_as_a_crash():
    """**Actually crashed**, not a state somebody set."""

    report = run("crash")
    assert report.state is LifecycleState.CRASHED
    assert report.exit_code == 9


@real_process
def test_a_process_killed_by_a_signal_is_a_crash_and_names_the_signal():
    report = run("signal")
    assert report.state is LifecycleState.CRASHED
    assert report.signalled == signal.SIGKILL


@real_process
def test_a_crash_does_not_stop_the_deterministic_path():
    """The whole doctrine, against a process that really died."""

    from azazel_nexus.cognition import CognitionReading, CognitionState, RemoteState

    report = run("crash")
    assert report.state is LifecycleState.CRASHED

    reading = CognitionReading(
        state=CognitionState.CORE_ONLY,
        remote=RemoteState.DISABLED,
        resource_reason="unmeasured",
        topology_reason="unmeasured",
        asset_reason="the provider crashed",
        trust_health_reason="none",
    )
    assert reading.blocks_deterministic_path() is False
    assert reading.state is CognitionState.CORE_ONLY


# == real process: output is bounded, and the bound is on the reading =====


@real_process
def test_output_beyond_the_ceiling_stops_the_read_rather_than_being_trimmed():
    """The stub writes two megabytes. The node must not spend two megabytes.

    Found while building this: `Popen.communicate` reads to EOF, so the first
    implementation read all of it and trimmed afterwards -- a ceiling on what
    is kept, not on what the node spent. A provider that can make the daemon
    drain that much has decided how much memory the daemon uses.
    """

    report = run("flood", deadline_seconds=5)
    assert report.stdout_truncated is True
    assert report.stdout_bytes <= STDIO_BYTE_CEILING, (
        f"the supervisor kept {report.stdout_bytes} bytes against a ceiling "
        f"of {STDIO_BYTE_CEILING}"
    )


@real_process
def test_a_flood_after_a_ready_reports_both_facts():
    """It answered, and then it flooded. A report that said `not-checked`
    would erase the first; one that said `failed` would invent a failure."""

    report = run("flood", deadline_seconds=5)
    assert report.readiness is Readiness.PASSED
    assert report.stdout_truncated is True
    assert report.state is not LifecycleState.SERVING


@real_process
def test_no_report_carries_the_output_itself():
    report = run("flood", deadline_seconds=5)
    rendered = repr(report.as_event())
    assert "xxxx" not in rendered
    assert "stdout_bytes" in rendered


# == real process: nothing is left behind =================================


@real_process
def test_a_forked_child_does_not_outlive_the_run():
    """An orphan that keeps a port or a file open is a failure that outlives
    the thing that caused it."""

    report = run("orphan", deadline_seconds=5)
    assert report.readiness is Readiness.PASSED

    # The report deliberately carries no output, so the child is looked for
    # in the process tree rather than read out of it.
    deadline = time.monotonic() + 5
    survivors = []
    while time.monotonic() < deadline:
        survivors = _stub_processes()
        if not survivors:
            break
        time.sleep(0.1)
    assert survivors == [], f"{survivors} survived the run"


def _stub_processes() -> list:
    """Every live process whose command line names the stub."""

    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes()
            status = (entry / "status").read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            continue
        if b"az-runtime-stub" not in cmdline:
            continue
        # A zombie is not a survivor: it holds nothing and is reaped.
        if "State:\tZ" in status:
            continue
        found.append(int(entry.name))
    return found


@real_process
def test_the_process_tree_is_clean_after_every_behaviour():
    """Swept once at the end rather than trusted per case."""

    for behaviour in ("ready", "silent", "crash", "signal", "hang", "flood"):
        run(behaviour, deadline_seconds=2)
    deadline = time.monotonic() + 5
    survivors = _stub_processes()
    while survivors and time.monotonic() < deadline:
        time.sleep(0.1)
        survivors = _stub_processes()
    assert survivors == [], f"{survivors} survived"


# == real process: restart budget and fencing =============================


@real_process
def test_a_crashing_process_is_restarted_until_the_budget_is_spent():
    """Then it stops, and it says so. A supervisor that restarts for ever
    turns a crash loop into something that looks merely slow."""

    supervision = Supervision(
        record=stub("crash"),
        root=STUB_ROOT,
        budget=RestartBudget(generation=1),
        deadline_seconds=5,
    )
    supervise(supervision)

    starts = [r for r in supervision.reports if r.state is LifecycleState.CRASHED]
    assert len(starts) == MAX_RESTARTS + 1, (
        f"{len(starts)} starts for a budget of {MAX_RESTARTS} restarts"
    )
    assert supervision.state is LifecycleState.FENCED
    assert supervision.budget.remaining == 0
    assert supervision.reports[-1].state is LifecycleState.FENCED
    assert "fenced" in supervision.reports[-1].reason or "limit" in supervision.reports[-1].reason


@real_process
def test_a_healthy_process_spends_no_budget():
    supervision = Supervision(
        record=stub("ready"),
        root=STUB_ROOT,
        budget=RestartBudget(generation=1),
        deadline_seconds=5,
    )
    supervise(supervision)
    assert supervision.budget.spent == 0
    assert supervision.state is LifecycleState.SERVING


@real_process
def test_a_fence_is_not_cleared_by_supervising_again():
    """Returning a provider to service is an operator's decision against a
    revalidated generation -- not something a supervisor grants itself by
    being asked twice."""

    budget = RestartBudget(generation=1)
    first = Supervision(
        record=stub("crash"), root=STUB_ROOT, budget=budget, deadline_seconds=5
    )
    supervise(first)
    assert first.state is LifecycleState.FENCED

    second = Supervision(
        record=stub("ready"), root=STUB_ROOT, budget=budget, deadline_seconds=5
    )
    supervise(second)
    assert second.reports == [], "a fenced provider was started again"
    assert second.state is LifecycleState.FENCED


# == the caller supplies a symbol, and nothing else =======================


@injected
def test_a_symbol_that_resolves_to_nothing_starts_nothing():
    """`RUNTIMES` is empty in this build, so this is the shipped answer."""

    with pytest.raises(SupervisorRefused) as caught:
        start_for("stub", root=STUB_ROOT)
    assert "not a runtime this build contains" in str(caught.value)


@injected
@pytest.mark.parametrize(
    "hostile",
    ["../../../bin/sh", "/bin/sh", "", "stub; sh", None, 7],
    ids=["traversal", "absolute", "empty", "injection", "none", "number"],
)
def test_nothing_a_caller_can_spell_starts_a_process(hostile):
    with pytest.raises(SupervisorRefused):
        start_for(hostile, root=STUB_ROOT)


@injected
def test_the_supervisor_takes_no_command_path_or_environment():
    """Checked on the signature, so a parameter appearing is a failure here
    rather than a capability nobody noticed."""

    import inspect

    for function in (run_once, start_for):
        parameters = set(inspect.signature(function).parameters)
        for forbidden in ("command", "argv", "env", "environment", "shell", "cwd"):
            assert forbidden not in parameters, (
                f"{function.__name__} takes {forbidden!r} from its caller"
            )


@injected
def test_the_environment_is_replaced_and_never_inherited():
    """A provider that inherited this daemon's environment would inherit
    whatever the service manager happened to set."""

    import ast

    source = (
        REPO_ROOT / "runtime" / "src" / "azazel_nexus_runtime" / "mio_supervisor.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    popen_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "attr", "") == "Popen"
    ]
    assert popen_calls, "the supervisor no longer starts anything"
    for call in popen_calls:
        keywords = {kw.arg for kw in call.keywords}
        assert "env" in keywords, "the environment is inherited"
        assert "shell" not in keywords, "a shell was introduced"
        assert "start_new_session" in keywords, "children would be orphaned"


# == the two kinds of evidence are not the same thing =====================


def test_the_two_kinds_of_evidence_are_distinguishable():
    """Injected states and real processes are separate claims.

    #112 reported an injected `crashed` state, and calling that process
    evidence was the confusion this issue exists to remove. Both sets are
    non-empty and disjoint, so a suite of injected states can never read as
    process evidence.
    """

    import inspect

    module = sys.modules[__name__]
    real, fake = set(), set()
    for name, function in vars(module).items():
        if not name.startswith("test_") or not inspect.isfunction(function):
            continue
        marks = {mark.name for mark in getattr(function, "pytestmark", ())}
        if "real_process" in marks:
            real.add(name)
        if "injected" in marks:
            fake.add(name)

    assert real, "no test claims to drive a real process"
    assert fake, "no test is marked as injected"
    assert real & fake == set(), f"{sorted(real & fake)} claim to be both"
    assert len(real) >= 10, f"only {len(real)} real-process tests"
