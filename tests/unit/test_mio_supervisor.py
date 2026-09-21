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

#: A fixed instant. Nothing here reads a clock.
NOW = "2026-09-21T00:00:00Z"
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

    before = _stub_processes()
    report = run("orphan", deadline_seconds=5)
    assert report.readiness is Readiness.PASSED

    assert _no_new_survivors(before), "a forked child survived the run"


def _no_new_survivors(before: list, *, seconds: float = 5.0) -> bool:
    """No stub process this run started is still alive.

    Compared against a snapshot rather than against zero. A run that demanded
    an empty machine would fail whenever anything else left a stub behind --
    another suite, an interrupted session, a mutation run that deliberately
    leaked -- and a test that fails for somebody else's mess is a test that
    gets deleted.

    What it still catches is the only thing it is about: a process **this**
    call started and did not clean up.
    """

    known = set(before)
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        new = [pid for pid in _stub_processes() if pid not in known]
        if not new:
            return True
        time.sleep(0.1)
    return [pid for pid in _stub_processes() if pid not in known] == []


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

    before = _stub_processes()
    for behaviour in ("ready", "silent", "crash", "signal", "hang", "flood", "env"):
        run(behaviour, deadline_seconds=2)
    assert _no_new_survivors(before), "a behaviour left a process behind"


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


@real_process
def test_the_environment_is_replaced_and_never_inherited(monkeypatch):
    """Found by mutation: the old test checked that `env=` was **present**,
    which `env=dict(os.environ)` satisfies.

    The property is not the keyword, it is what the child actually receives.
    The parent sets a marker and the stub exits 3 if it sees it -- through
    the exit code, because the report deliberately carries no output.

    What inheritance would hand a provider is not abstract: this process
    holds `GH_TOKEN`, `AWS_SECRET_ACCESS_KEY` and a messaging token, and a
    model runtime is the last thing that should be able to read them.
    """

    monkeypatch.setenv("AZ_PARENT_MARKER", "inherited")
    report = run("env", deadline_seconds=5)

    assert report.exit_code == 0, (
        "the provider inherited this daemon's environment"
    )
    assert report.readiness is Readiness.PASSED


@real_process
def test_the_marker_would_be_seen_if_it_were_inherited(monkeypatch):
    """The control. Run the same stub **without** the supervisor's
    replacement and it exits 3, so the test above is not passing because the
    stub never looks."""

    import subprocess

    monkeypatch.setenv("AZ_PARENT_MARKER", "inherited")
    binary = STUB_ROOT / STUB.lstrip("/")
    completed = subprocess.run(  # noqa: S603 - fixed argv, test-only
        [str(binary), "env"], capture_output=True, env=dict(os.environ)
    )
    assert completed.returncode == 3, (
        "the stub does not notice the marker, so the test above proves nothing"
    )


@injected
def test_the_supervisor_passes_an_explicit_environment():
    """And the shape, still: a `Popen` without `env=` inherits by default, so
    the keyword's absence is its own failure."""

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
        assert "env" in keywords, "the environment is inherited by default"
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


# == the budget survives the supervisor, and the fence survives the daemon ==
#
# The failure most likely to end a supervisor is the one it is restarting. A
# budget held only in memory is therefore a budget that a hard-enough crash
# refills -- three restarts, every time, for ever, and the node calls that
# "occasionally slow".
#
# Every test here starts real processes and then destroys the objects holding
# the state, which is what a daemon restart and a reboot look like from the
# ledger's point of view.


def _ledger(tmp_path):
    from azazel_nexus.runtime_lifecycle import BudgetLedger

    return BudgetLedger(tmp_path / "budgets.json")


def _supervision(tmp_path, behaviour="crash", *, ledger=None, on_spent=None):
    from azazel_nexus.runtime_lifecycle import BudgetLedger

    ledger = ledger if ledger is not None else _ledger(tmp_path)
    return Supervision(
        record=stub(behaviour),
        root=STUB_ROOT,
        budget=ledger.load(generation=1, runtime_id="stub"),
        deadline_seconds=5,
        ledger=ledger,
        on_budget_spent=on_spent,
    )


@real_process
def test_a_spent_budget_is_not_refilled_by_restarting_the_supervisor(tmp_path):
    """**The requirement.** The supervisor object is thrown away and rebuilt
    from the ledger -- which is what a daemon restart leaves behind."""

    ledger = _ledger(tmp_path)
    first = _supervision(tmp_path, ledger=ledger)
    supervise(first)
    assert first.state is LifecycleState.FENCED
    started = len([r for r in first.reports if r.state is LifecycleState.CRASHED])
    assert started == MAX_RESTARTS + 1

    # The daemon restarts: nothing of the old object survives but the file.
    second = _supervision(tmp_path, ledger=ledger)
    assert second.budget.fenced is True
    assert second.budget.remaining == 0
    supervise(second)
    assert second.reports == [], "a fenced provider was started again"
    assert second.state is LifecycleState.FENCED


@real_process
def test_a_reboot_does_not_hand_back_the_budget(tmp_path):
    """A fresh `BudgetLedger` over the same path is what a reboot looks
    like: new process, new objects, same disk."""

    from azazel_nexus.runtime_lifecycle import BudgetLedger

    supervise(_supervision(tmp_path))

    rebooted = BudgetLedger(tmp_path / "budgets.json")
    budget = rebooted.load(generation=1, runtime_id="stub")
    assert budget.fenced is True
    assert budget.spend().may_restart is False


@real_process
def test_the_budget_is_persisted_on_every_spend_not_only_the_last(tmp_path):
    """A crash between the spend and the write would otherwise hand back the
    restart that was just used."""

    import json

    ledger = _ledger(tmp_path)
    supervision = _supervision(tmp_path, ledger=ledger)
    supervision.budget.limit = 2
    supervise(supervision, attempts=3)

    entries = json.loads((tmp_path / "budgets.json").read_text(encoding="utf-8"))
    assert "1:stub" in entries
    assert entries["1:stub"]["spent"] >= 1


@real_process
def test_another_provider_in_the_same_generation_keeps_its_own_budget(tmp_path):
    """One provider exhausting its budget says nothing about another."""

    from azazel_nexus.runtime_lifecycle import BudgetLedger

    ledger = _ledger(tmp_path)
    supervise(_supervision(tmp_path, ledger=ledger))

    other = ledger.load(generation=1, runtime_id="other-stub")
    assert other.fenced is False
    assert other.spend().may_restart is True


@real_process
def test_a_later_generation_starts_with_its_own_budget(tmp_path):
    """Per generation, so a promotion is a fresh start -- and a reboot is
    not."""

    ledger = _ledger(tmp_path)
    supervise(_supervision(tmp_path, ledger=ledger))
    assert ledger.load(generation=1, runtime_id="stub").fenced is True
    assert ledger.load(generation=2, runtime_id="stub").fenced is False


@injected
def test_an_unreadable_ledger_fences_rather_than_forgetting(tmp_path):
    """A corrupt file is not "no budgets spent". The alternative is a
    damaged file silently returning a provider to service."""

    ledger = _ledger(tmp_path)
    (tmp_path / "budgets.json").write_text("{not json", encoding="utf-8")
    budget = ledger.load(generation=1, runtime_id="stub")
    assert budget.fenced is True
    assert budget.spend().may_restart is False


@injected
def test_an_unreadable_ledger_is_not_overwritten(tmp_path):
    """Replacing it would destroy the record that made everything fenced."""

    ledger = _ledger(tmp_path)
    path = tmp_path / "budgets.json"
    path.write_text("{not json", encoding="utf-8")
    budget = ledger.load(generation=1, runtime_id="stub")
    ledger.save(budget, runtime_id="stub")
    assert "1:stub" in path.read_text(encoding="utf-8"), (
        "the save wrote something"
    )


# -- the watchdog holds the consequence -----------------------------------


def _watchdog(tmp_path, manager):
    from azazel_nexus.audit import AuditLedger
    from azazel_nexus_runtime.watchdog import FenceStore, WatchdogService

    return WatchdogService(
        manager=manager,
        ledger=AuditLedger(tmp_path / "audit.jsonl"),
        fences=FenceStore(tmp_path / "fences.json"),
    )


@real_process
def test_a_spent_budget_fences_the_unit_through_the_watchdog(tmp_path):
    """The supervisor holds the count; the watchdog holds the consequence.

    Keeping them apart is the separation the rest of the daemon has: the
    component that **observes** a failure is not the one that **narrows** on
    it, and neither can widen.
    """

    from azazel_nexus_runtime.units import UNIT_NAMES, RecordingUnitManager
    from azazel_nexus_runtime.watchdog import FenceReason

    manager = RecordingUnitManager(UNIT_NAMES.values())
    watchdog = _watchdog(tmp_path, manager)

    def fence(key: str) -> None:
        watchdog.note_restart_budget_spent(
            key, now=NOW, detail="the restart budget for this generation is spent"
        )

    supervise(_supervision(tmp_path, on_spent=fence))

    unit = "azazel-mio-locald.service"
    assert watchdog.fenced.get(unit) == FenceReason.RESTART_BUDGET_SPENT.value
    assert ("mask", unit) in [(c[0], c[1]) for c in manager.calls]


@real_process
def test_the_fence_survives_a_watchdog_restart(tmp_path):
    """A fence a process restart cleared would be a fence the failure can
    clear, by taking the watchdog down with it."""

    from azazel_nexus_runtime.units import UNIT_NAMES, RecordingUnitManager
    from azazel_nexus_runtime.watchdog import FenceReason

    manager = RecordingUnitManager(UNIT_NAMES.values())
    watchdog = _watchdog(tmp_path, manager)
    supervise(
        _supervision(
            tmp_path,
            on_spent=lambda key: watchdog.note_restart_budget_spent(
                key, now=NOW, detail="spent"
            ),
        )
    )

    # The daemon restarts: a new service over the same fence file.
    restarted = _watchdog(tmp_path, RecordingUnitManager(UNIT_NAMES.values()))
    unit = "azazel-mio-locald.service"
    assert restarted.fenced.get(unit) == FenceReason.RESTART_BUDGET_SPENT.value


@real_process
def test_the_budget_fence_is_its_own_reason(tmp_path):
    """Not `RESTART_INTERRUPTED`. That means a restart was cut short and
    nobody knows what it left; this means the restarts completed, each one
    failed, and the count ran out."""

    from azazel_nexus_runtime.watchdog import FenceReason

    assert FenceReason.RESTART_BUDGET_SPENT is not FenceReason.RESTART_INTERRUPTED
    values = [reason.value for reason in FenceReason]
    assert len(values) == len(set(values))


@real_process
def test_the_fence_is_recorded_in_the_audit_chain(tmp_path):
    """A node that narrowed and did not write it down is one nobody can
    account for afterwards."""

    from azazel_nexus.audit import AuditLedger
    from azazel_nexus_runtime.units import UNIT_NAMES, RecordingUnitManager

    manager = RecordingUnitManager(UNIT_NAMES.values())
    watchdog = _watchdog(tmp_path, manager)
    supervise(
        _supervision(
            tmp_path,
            on_spent=lambda key: watchdog.note_restart_budget_spent(
                key, now=NOW, detail="the restart budget for this generation is spent"
            ),
        )
    )

    events = [e.event for e in AuditLedger(tmp_path / "audit.jsonl")]
    assert events, "the fence was not recorded"
    assert any("restart_budget_spent" in repr(event) for event in events)


@real_process
def test_a_budget_fence_widens_nothing(tmp_path):
    """The whole point of handing the consequence to the watchdog."""

    import ast

    from azazel_nexus_runtime.units import UNIT_NAMES, RecordingUnitManager

    manager = RecordingUnitManager(UNIT_NAMES.values())
    watchdog = _watchdog(tmp_path, manager)
    supervise(
        _supervision(
            tmp_path,
            on_spent=lambda key: watchdog.note_restart_budget_spent(
                key, now=NOW, detail="spent"
            ),
        )
    )

    widening = [c for c in manager.calls if c[0] != "mask"]
    assert widening == [], f"the fence widened something: {widening}"

    module = (
        REPO_ROOT / "runtime" / "src" / "azazel_nexus_runtime" / "mio_supervisor.py"
    )
    tree = ast.parse(module.read_text(encoding="utf-8"))
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
    }
    assert used & {"unmask_and_enable", "ActivationAuthorization", "grant"} == set()


@real_process
def test_edge_authority_is_unchanged_by_a_budget_fence(tmp_path):
    from azazel_nexus.cognition import CognitionReading, CognitionState, RemoteState

    supervise(_supervision(tmp_path))
    reading = CognitionReading(
        state=CognitionState.CORE_ONLY,
        remote=RemoteState.DISABLED,
        resource_reason="the provider is fenced",
        topology_reason="unmeasured",
        asset_reason="none",
        trust_health_reason="none",
    )
    assert reading.blocks_deterministic_path() is False
    assert reading.state is CognitionState.CORE_ONLY


# == rollback, with a real process on both sides ==========================
#
# A rollback whose destination was never checked is not a return to a safe
# world; it is a second failure entered deliberately, having given up a
# working generation to reach it. So the destination is verified first and
# every refusal leaves the node where it was.


def _verdict(admissible: bool, *refusals):
    from azazel_nexus.runtime_lifecycle import BinaryVerdict

    return BinaryVerdict(admissible=admissible, refusals=tuple(refusals))


def _roll(**overrides):
    from azazel_nexus.runtime_lifecycle import plan_rollback

    fields = dict(
        current_generation=2,
        target_generation=1,
        reason="the provider crashed through its budget",
        actor="operator@console",
        target_verdict=_verdict(True),
    )
    fields.update(overrides)
    return plan_rollback(**fields)


@real_process
def test_a_rollback_runs_the_generation_it_returned_to(tmp_path):
    """**Real process on both sides.** Generation 2's provider crashes;
    generation 1's answers. The rollback is only meaningful if what it
    returned to actually runs."""

    crashing = run("crash")
    assert crashing.state is LifecycleState.CRASHED

    outcome = _roll()
    assert outcome.rolled_back is True
    assert outcome.running_generation == 1

    restored = run("ready")
    assert restored.state is LifecycleState.SERVING
    assert restored.readiness is Readiness.PASSED


@real_process
def test_a_rollback_to_a_generation_that_does_not_verify_keeps_the_old_one(
    tmp_path,
):
    """**The safety property.** The node keeps the generation it has rather
    than entering a second failure."""

    from azazel_nexus.runtime_lifecycle import RollbackRefusal

    outcome = _roll(target_verdict=_verdict(False, "the digest does not match"))
    assert outcome.rolled_back is False
    assert outcome.running_generation == 2, "the node moved anyway"
    assert outcome.refusal is RollbackRefusal.TARGET_UNVERIFIABLE

    # And the generation it kept still runs.
    assert run("ready").state is LifecycleState.SERVING


@injected
def test_the_destination_is_verified_before_anything_moves():
    """Order, not intention: an unverified destination never reaches the
    branch that moves."""

    import ast
    from pathlib import Path

    import azazel_nexus.runtime_lifecycle as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "plan_rollback"
    )
    returns = [n for n in ast.walk(function) if isinstance(n, ast.Return)]
    # The last return is the only one that reports a rollback; everything
    # before it refuses.
    assert len(returns) >= 5, "the refusal branches were removed"


@injected
@pytest.mark.parametrize(
    "overrides,expected",
    [
        ({"reason": "   "}, "NO_REASON"),
        ({"actor": ""}, "NO_ACTOR"),
        ({"target_generation": 2}, "SAME_GENERATION"),
        ({"target_generation": None}, "NO_PREDECESSOR"),
        ({"target_verdict": None}, "TARGET_UNVERIFIABLE"),
    ],
    ids=["no-reason", "no-actor", "same", "no-predecessor", "unverified"],
)
def test_every_refusal_leaves_the_node_where_it_was(overrides, expected):
    """The atomicity. There is no state in which this half-happened."""

    from azazel_nexus.runtime_lifecycle import RollbackRefusal

    outcome = _roll(**overrides)
    assert outcome.rolled_back is False
    assert outcome.refusal is getattr(RollbackRefusal, expected)
    assert outcome.running_generation == 2


@injected
def test_a_rollback_that_happened_and_was_refused_cannot_be_built():
    from azazel_nexus.runtime_lifecycle import (
        LifecycleRefused,
        RollbackOutcome,
        RollbackRefusal,
    )

    with pytest.raises(LifecycleRefused):
        RollbackOutcome(
            rolled_back=True,
            running_generation=1,
            from_generation=2,
            to_generation=1,
            reason="x",
            refusal=RollbackRefusal.NO_REASON,
            state=LifecycleState.STARTED,
        )
    with pytest.raises(LifecycleRefused):
        RollbackOutcome(
            rolled_back=False,
            running_generation=2,
            from_generation=2,
            to_generation=1,
            reason="x",
            refusal=None,
            state=LifecycleState.ABSENT,
        )


@injected
def test_a_rollback_always_records_a_reason():
    """Including the refusals: an operator told only that it did not happen
    has been told nothing they can act on."""

    for overrides in ({}, {"reason": "  "}, {"target_generation": None}):
        assert _roll(**overrides).reason.strip()


@real_process
def test_a_rollback_widens_nothing(tmp_path):
    """A rollback that could widen would be a way to gain privilege by
    failing twice."""

    import ast
    from pathlib import Path

    import azazel_nexus.runtime_lifecycle as module

    outcome = _roll()
    assert outcome.rolled_back is True
    assert run("ready").state is LifecycleState.SERVING

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
    }
    offenders = sorted(
        name
        for name in used
        if any(t in name.lower() for t in ("unmask", "lease", "enforce", "grant"))
    )
    assert offenders == [], f"the rollback path names {offenders}"


@real_process
def test_the_rolled_back_generation_gets_its_own_budget(tmp_path):
    """Per generation, so returning to an older one does not inherit the
    fence that made the newer one unusable -- nor hand back the newer one's
    restarts."""

    ledger = _ledger(tmp_path)
    spent = Supervision(
        record=stub("crash"),
        root=STUB_ROOT,
        budget=ledger.load(generation=2, runtime_id="stub"),
        deadline_seconds=5,
        ledger=ledger,
    )
    supervise(spent)
    assert spent.state is LifecycleState.FENCED

    outcome = _roll()
    assert outcome.running_generation == 1
    restored = Supervision(
        record=stub("ready"),
        root=STUB_ROOT,
        budget=ledger.load(generation=1, runtime_id="stub"),
        deadline_seconds=5,
        ledger=ledger,
    )
    supervise(restored)
    assert restored.state is LifecycleState.SERVING
    assert ledger.load(generation=2, runtime_id="stub").fenced is True, (
        "the rollback cleared the fence on the generation that failed"
    )


@real_process
def test_edge_authority_is_unchanged_across_a_rollback(tmp_path):
    from azazel_nexus.cognition import CognitionReading, CognitionState, RemoteState

    for outcome in (_roll(), _roll(target_verdict=_verdict(False, "bad"))):
        reading = CognitionReading(
            state=CognitionState.CORE_ONLY,
            remote=RemoteState.DISABLED,
            resource_reason=str(outcome.running_generation),
            topology_reason="unmeasured",
            asset_reason="none",
            trust_health_reason="none",
        )
        assert reading.blocks_deterministic_path() is False
        assert reading.state is CognitionState.CORE_ONLY
