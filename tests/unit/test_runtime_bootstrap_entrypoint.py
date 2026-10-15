"""Selected bootstrap entrypoint composition with synthetic resources only."""

from contextlib import contextmanager
from hashlib import sha256
from types import SimpleNamespace

import pytest

from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_entrypoint as entrypoint
from azazel_nexus_runtime.bootstrap import BootstrapResult
from azazel_nexus_runtime.bootstrap_audit_client import AuditAppendReceipt
from azazel_nexus_runtime.bootstrap_audit import AuditObservation
from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.units import UnitKey, UnitOperationFailed
from test_runtime_bootstrap import (
    Harness, RecordingManager, _owned_grant_transaction,
    evidence as harness_evidence,
)


def _evidence():
    return harness_evidence.__wrapped__(None)


class FakeClient:
    def __init__(self):
        self.sequence = 1
        self.digest = "a" * 64

    def __call__(self, event):
        self.sequence += 1
        self.digest = sha256(repr(event).encode()).hexdigest()
        return AuditAppendReceipt(self.sequence, self.digest)

    def observe_head(self):
        return self.sequence, self.digest


class FakeDeadlineGuard:
    def __init__(self, events):
        self.events = events
        self.deadlines = []
        self.releases = 0

    def __call__(self, deadline):
        self.deadlines.append(deadline)
        self.events.append(("deadline-guard", deadline))

    def release_after_stop(self):
        self.releases += 1
        self.events.append(("deadline-release", None))


class FakeLifetime:
    def __init__(self, events):
        self.events = events
        self._stopped = False
        self.deadline_guard = FakeDeadlineGuard(events)
        events.append(("lifetime-deadline-guard", self.deadline_guard))

    def __enter__(self):
        self.events.append("lifetime-enter")
        return self

    def __exit__(self, *_exc):
        self.events.append("lifetime-exit")

    def stopped(self):
        return self._stopped

    def wait(self, _seconds):
        self.events.append("wait")
        self._stopped = True


def _install_composition(monkeypatch, *, events, selection="retained", guard=None,
                         manager=None, fail_manager=False, fail_lifetime=False,
                         fail_manager_exit=False, fail_lifetime_exit=False):
    guard = guard or (lambda: events.append("guard"))

    @contextmanager
    def lock():
        events.append("lock-enter")
        try:
            yield guard
        finally:
            events.append("lock-exit")

    monkeypatch.setattr(entrypoint, "bootstrap_transaction", lock)
    @contextmanager
    def once(received_guard):
        assert received_guard is guard
        events.append("controller-claimed")
        yield received_guard
        events.append("controller-retained")

    monkeypatch.setattr(entrypoint, "bootstrap_controller_once", once)
    monkeypatch.setattr(entrypoint, "load_bootstrap_selection",
                        lambda: events.append("selection-read") or selection)

    @contextmanager
    def manager_context(received_guard, *, job_timeout_seconds):
        events.append(("manager-enter", received_guard, job_timeout_seconds))
        if fail_manager:
            raise RuntimeError("manager construction")
        try:
            yield manager
        finally:
            events.append("manager-exit")
            if fail_manager_exit:
                raise RuntimeError("manager teardown")

    monkeypatch.setattr(entrypoint, "bootstrap_narrowing_manager_in_transaction",
                        manager_context)

    class Lifetime(FakeLifetime):
        def __enter__(self):
            if fail_lifetime:
                events.append("lifetime-fail")
                raise RuntimeError("lifetime construction")
            return super().__enter__()

        def __exit__(self, *exc):
            super().__exit__(*exc)
            if fail_lifetime_exit:
                raise RuntimeError("lifetime teardown")

    monkeypatch.setattr(entrypoint, "BootstrapProcessLifetime",
                        lambda: Lifetime(events))
    client = FakeClient()
    if manager is not None:
        manager._bootstrap_audit_client = lambda: client
    monkeypatch.setattr(entrypoint, "protected_bootstrap_inputs",
                        lambda: (events.append("refresh-factory") or "refresh"))
    monkeypatch.setattr(entrypoint, "protected_bootstrap_generation_admission",
                        lambda: (events.append("admit-factory") or "admit"))
    monkeypatch.setattr(entrypoint, "protected_bootstrap_initial_admission",
                        lambda: events.append("initial-factory"))  # None: legacy path
    monkeypatch.setattr(entrypoint, "notify_ready", lambda: None)
    monkeypatch.setattr(entrypoint, "notify_watchdog", lambda: None)
    return guard, client


def test_composition_holds_one_lock_and_wires_fixed_callbacks_and_shared_client(monkeypatch):
    events = []
    manager = SimpleNamespace()
    guard, client = _install_composition(
        monkeypatch, events=events, manager=manager,
    )

    class Supervisor:
        def __init__(self, **options):
            events.append("supervisor-construct")
            assert options["manager"] is manager
            assert options["record"] is options["audit_head_reader"] is client
            assert options["refresh"] == "refresh"
            assert options["admit_generation"] == "admit"
            assert options["controller_ready"] is entrypoint.notify_ready
            assert options["controller_watchdog"] is entrypoint.notify_watchdog
            lifetime_guard = next(
                event[1] for event in events
                if isinstance(event, tuple) and event[0] == "lifetime-deadline-guard"
            )
            assert options["deadline_guard"] is lifetime_guard
            assert options["emergency_narrow"] is narrow_ref[0]
            assert options["poll_seconds"] == entrypoint._POLL_SECONDS
            assert options["stopped"].__self__ is options["wait"].__self__
            self.options = options

        def run(self):
            events.append("supervisor-run")
            with self.options["transaction"]() as borrowed:
                assert borrowed is guard
                borrowed()
            return BootstrapResult()

    monkeypatch.setattr(entrypoint, "BootstrapSupervisor", Supervisor)
    narrow_calls = []
    narrow_ref = []

    def narrow():
        assert "lock-exit" not in events
        narrow_calls.append(True)
        events.append("narrow")

    narrow_ref.append(narrow)

    result = entrypoint.run_selected_bootstrap("retained", narrow=narrow)

    assert type(result) is BootstrapResult and result.state == "stopped"
    assert narrow_calls == [True]
    assert events.index("lock-enter") < events.index("narrow")
    assert events.index("controller-claimed") < events.index("narrow")
    manager_enter = next(i for i, event in enumerate(events)
                         if isinstance(event, tuple) and event[0] == "manager-enter")
    assert manager_enter < events.index("lifetime-enter")
    manager_event = events[manager_enter]
    assert manager_event[1] is guard
    assert manager_event[2] == entrypoint._JOB_TIMEOUT_SECONDS
    assert events.index("lifetime-exit") < events.index("manager-exit")
    manager_exit = events.index("manager-exit")
    assert manager_exit < events.index("lock-exit")
    assert events.count("lock-enter") == 1


def test_supervisor_receives_exactly_the_fixed_composition_callbacks(monkeypatch):
    events = []
    manager = SimpleNamespace()
    guard, client = _install_composition(monkeypatch, events=events, manager=manager)
    captured = {}
    monkeypatch.setattr(entrypoint, "protected_bootstrap_initial_admission",
                        lambda: "initial")

    class Supervisor:
        def __init__(self, **options):
            captured.update(options)

        def run(self):
            with captured["transaction"]() as borrowed:
                assert borrowed is guard
            return BootstrapResult()

    monkeypatch.setattr(entrypoint, "BootstrapSupervisor", Supervisor)
    entrypoint.run_selected_bootstrap("retained", narrow=lambda: None)

    assert captured["manager"] is manager
    assert captured["record"] is captured["audit_head_reader"] is client
    assert captured["refresh"] == "refresh"
    assert captured["admit_generation"] == "admit"
    assert captured["initial_admission"] == "initial"
    assert set(captured) == {
        "manager", "refresh", "initial_admission", "admit_generation",
        "deadline_guard", "record", "audit_head_reader", "controller_ready",
        "controller_watchdog", "transaction", "emergency_narrow", "stopped",
        "wait", "poll_seconds",
    }
    assert captured["controller_ready"] is entrypoint.notify_ready
    assert captured["controller_watchdog"] is entrypoint.notify_watchdog
    assert captured["poll_seconds"] == entrypoint._POLL_SECONDS
    assert captured["stopped"].__self__ is captured["wait"].__self__


def test_initial_admission_factory_is_fixed_and_takes_no_selection(monkeypatch):
    import inspect
    from azazel_nexus_runtime import bootstrap_inputs

    assert not inspect.signature(
        bootstrap_inputs.protected_bootstrap_initial_admission).parameters
    events = []
    _install_composition(monkeypatch, events=events, manager=SimpleNamespace())
    seen = []
    monkeypatch.setattr(entrypoint, "protected_bootstrap_initial_admission",
                        lambda *a, **k: seen.append((a, k)) or "initial")

    class Supervisor:
        def __init__(self, **_options):
            pass

        def run(self):
            return BootstrapResult()

    monkeypatch.setattr(entrypoint, "BootstrapSupervisor", Supervisor)
    entrypoint.run_selected_bootstrap("retained", narrow=lambda: None)
    assert seen == [((), {})]


def test_lock_acquisition_failure_does_not_narrow(monkeypatch):
    events = []

    @contextmanager
    def unavailable_lock():
        events.append("lock-attempt")
        raise ApprovalRefused("not acquired")
        yield None

    monkeypatch.setattr(entrypoint, "bootstrap_transaction", unavailable_lock)
    with pytest.raises(ApprovalRefused, match="not acquired"):
        entrypoint.run_selected_bootstrap("retained", narrow=lambda: events.append("narrow"))
    assert events == ["lock-attempt"]


def test_selection_mismatch_refuses_inside_lock_and_attempts_narrow(monkeypatch):
    events = []
    _install_composition(monkeypatch, events=events, selection="changed")
    narrow_calls = []

    with pytest.raises(ApprovalRefused, match="selection changed"):
        entrypoint.run_selected_bootstrap(
            "retained", narrow=lambda: (events.append("narrow"), narrow_calls.append(True)),
        )

    assert narrow_calls == [True]
    assert events.index("lock-enter") < events.index("narrow") < events.index("lock-exit")
    assert not any(isinstance(event, tuple) and event[0] == "manager-enter"
                   for event in events)


def test_selection_is_re_read_after_initial_narrow_before_manager_creation(monkeypatch):
    events = []
    _install_composition(monkeypatch, events=events)
    retained_reads = iter(("retained", "changed"))
    monkeypatch.setattr(
        entrypoint, "load_bootstrap_selection",
        lambda: (events.append("selection-read") or next(retained_reads)),
    )
    narrow_calls = []

    with pytest.raises(ApprovalRefused, match="during initial narrowing"):
        entrypoint.run_selected_bootstrap(
            "retained", narrow=lambda: (events.append("narrow"), narrow_calls.append(True)),
        )

    assert events.count("selection-read") == 2
    assert narrow_calls == [True, True]  # initial narrowing and failure-path retry
    assert not any(isinstance(event, tuple) and event[0] == "manager-enter"
                   for event in events)
    read_positions = [i for i, event in enumerate(events) if event == "selection-read"]
    narrow_positions = [i for i, event in enumerate(events) if event == "narrow"]
    assert read_positions[0] < narrow_positions[0] < read_positions[1]


@pytest.mark.parametrize("failure", ["manager", "lifetime", "supervisor"])
def test_construction_failure_attempts_narrow_while_lock_is_held(
    monkeypatch, failure,
):
    events = []
    manager = SimpleNamespace()
    _install_composition(
        monkeypatch, events=events, manager=manager,
        fail_manager=failure == "manager", fail_lifetime=failure == "lifetime",
    )
    if failure == "supervisor":
        class BrokenSupervisor:
            def __init__(self, **_options):
                events.append("supervisor-fail")
                raise RuntimeError("supervisor construction")

        monkeypatch.setattr(entrypoint, "BootstrapSupervisor", BrokenSupervisor)

    def narrow():
        assert "lock-exit" not in events
        events.append("narrow")

    with pytest.raises(RuntimeError):
        entrypoint.run_selected_bootstrap("retained", narrow=narrow)
    assert events.count("narrow") == 2
    assert events.index("lock-enter") < events.index("narrow") < events.index("lock-exit")


@pytest.mark.parametrize("failure", ["construction", "run", "teardown"])
def test_emergency_narrow_failure_is_attached_to_primary_error(monkeypatch, failure):
    events = []
    manager = SimpleNamespace()
    _install_composition(
        monkeypatch,
        events=events,
        manager=manager,
        fail_manager=failure == "construction",
        fail_lifetime_exit=failure == "teardown",
    )
    if failure in {"run", "teardown"}:
        class Supervisor:
            def __init__(self, **_options):
                pass

            def run(self):
                if failure == "run":
                    raise RuntimeError("primary run failure")
                return BootstrapResult()

        monkeypatch.setattr(entrypoint, "BootstrapSupervisor", Supervisor)

    primary_text = {
        "construction": "manager construction",
        "run": "primary run failure",
        "teardown": "lifetime teardown",
    }[failure]
    narrow_calls = []

    def narrow():
        assert "lock-exit" not in events
        narrow_calls.append(True)
        if len(narrow_calls) == 2:
            raise OSError("emergency narrowing detail")

    with pytest.raises(RuntimeError, match=primary_text) as caught:
        entrypoint.run_selected_bootstrap("retained", narrow=narrow)

    assert narrow_calls == [True, True]
    assert caught.value.__notes__ == [entrypoint.EMERGENCY_UNCONFIRMED]
    assert "emergency narrowing detail" not in str(caught.value)
    assert events.index("lock-enter") < events.index("lock-exit")


def test_borrowed_transaction_does_not_reacquire_and_preserves_primary_error(monkeypatch):
    events = []
    guard_calls = []
    primary = RuntimeError("supervisor primary failure")

    def guard():
        guard_calls.append(True)
        if len(guard_calls) == 4:
            raise ApprovalRefused("secondary guard failure")

    manager = SimpleNamespace()
    _install_composition(monkeypatch, events=events, guard=guard, manager=manager)

    class FailedSupervisor:
        def __init__(self, **options):
            self.options = options

        def run(self):
            with self.options["transaction"]() as borrowed:
                assert borrowed is guard
                raise primary

    monkeypatch.setattr(entrypoint, "BootstrapSupervisor", FailedSupervisor)
    narrowed = []
    with pytest.raises(RuntimeError) as caught:
        entrypoint.run_selected_bootstrap(
            "retained", narrow=lambda: narrowed.append(True),
        )

    assert caught.value is primary
    assert events.count("lock-enter") == 1
    assert len(guard_calls) >= 5
    assert narrowed == [True, True]


def test_invalid_selection_narrowing_uses_one_separate_held_lock(monkeypatch):
    events = []

    def guard():
        events.append("guard")

    @contextmanager
    def lock():
        events.append("lock-enter")
        try:
            yield guard
        finally:
            events.append("lock-exit")

    monkeypatch.setattr(entrypoint, "bootstrap_transaction", lock)
    primary = ApprovalRefused("selection invalid")
    narrow_calls = []

    entrypoint.narrow_invalid_selection(
        primary, narrow=lambda: (events.append("narrow"), narrow_calls.append(True)),
    )

    assert narrow_calls == [True]
    assert events.index("lock-enter") < events.index("guard")
    assert events.index("guard") < events.index("narrow") < events.index("lock-exit")
    assert getattr(primary, "__notes__", []) == []


def test_invalid_selection_lock_contention_does_not_narrow(monkeypatch):
    events = []

    @contextmanager
    def contended_lock():
        events.append("lock-attempt")
        raise ApprovalRefused("lock busy")
        yield None

    monkeypatch.setattr(entrypoint, "bootstrap_transaction", contended_lock)
    with pytest.raises(ApprovalRefused, match="lock busy"):
        entrypoint.narrow_invalid_selection(
            ApprovalRefused("selection invalid"),
            narrow=lambda: events.append("narrow"),
        )
    assert events == ["lock-attempt"]


def test_invalid_selection_guard_failure_is_noted_and_skips_narrow(monkeypatch):
    events = []

    def guard():
        raise ApprovalRefused("guard detail")

    @contextmanager
    def lock():
        events.append("lock-enter")
        yield guard
        events.append("lock-exit")

    monkeypatch.setattr(entrypoint, "bootstrap_transaction", lock)
    primary = RuntimeError("selection handling failed")
    narrow_calls = []
    entrypoint.narrow_invalid_selection(
        primary, narrow=lambda: narrow_calls.append(True),
    )

    assert narrow_calls == []
    assert events == ["lock-enter", "lock-exit"]
    assert primary.__notes__ == [entrypoint.EMERGENCY_UNCONFIRMED]


def test_actual_supervisor_runs_with_harness_dependencies(monkeypatch):
    from azazel_nexus_runtime import bootstrap as bootstrap_module

    evidence = _evidence()
    harness = Harness(evidence, manager=RecordingManager())
    manager = harness.manager
    client = FakeClient()
    manager._bootstrap_audit_client = lambda: client
    events = []

    def guard():
        events.append("guard")

    _install_composition(monkeypatch, events=events, manager=manager, guard=guard)
    monkeypatch.setattr(entrypoint, "protected_bootstrap_inputs",
                        lambda: harness.refresh)
    monkeypatch.setattr(entrypoint, "protected_bootstrap_generation_admission",
                        lambda: harness.admit)
    monkeypatch.setattr(entrypoint, "protected_bootstrap_initial_admission",
                        lambda: None)  # legacy path under the actual supervisor

    @contextmanager
    def store_factory(_guard):
        yield harness.grant_store

    original_supervisor = bootstrap_module.BootstrapSupervisor

    def actual_supervisor(**options):
        options.update(
            grant_store_factory=store_factory,
            boot_id_reader=lambda: evidence[0].approval.context.boot_id,
            prestart=lambda _context: AuditObservation(1, "a" * 64, 1, 100),
            audit_continuation=lambda _context, previous: previous,
            boottime_ns=harness.clock,
        )
        return original_supervisor(**options)

    monkeypatch.setattr(entrypoint, "BootstrapSupervisor", actual_supervisor)
    result = entrypoint.run_selected_bootstrap(
        "retained", narrow=lambda: events.append("narrow"),
    )

    assert type(result) is BootstrapResult and result.state == "stopped"
    assert [unit for op, unit in manager.calls if op == "start_and_wait"] == [
        UnitKey.AUDITD, UnitKey.COMMISSIOND,
    ]
    assert "wait" in events


def test_real_once_barrier_precedes_supervisor_and_refuses_second_attempt(tmp_path, monkeypatch):
    import os
    from azazel_nexus.bootstrap_controller_once import _controller_once_at
    from azazel_nexus.bootstrap_lock import BootstrapTransactionGuard

    events = []
    original_guard = BootstrapTransactionGuard(lambda: None)
    _install_composition(monkeypatch, events=events, manager=SimpleNamespace(),
                         guard=original_guard)
    directory = tmp_path / "controller-barrier"
    directory.mkdir(mode=0o700)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    constructions = []

    @contextmanager
    def once(guard):
        fd = os.open(directory, flags)
        try:
            with _controller_once_at(
                fd, owner=os.getuid(), reopen=lambda: os.open(directory, flags), guard=guard,
            ) as retained:
                yield retained
        finally:
            os.close(fd)

    # Manager and Supervisor receive the retained composite guard, not a
    # replacement lock. This test uses only an ordinary temporary directory.
    @contextmanager
    def manager_context(guard, **_kwargs):
        guard()
        yield SimpleNamespace(_bootstrap_audit_client=lambda: FakeClient())

    class Supervisor:
        def __init__(self, **_kwargs):
            assert (directory / "controller-used").is_file()
            constructions.append(True)

        def run(self):
            return BootstrapResult()

    monkeypatch.setattr(entrypoint, "bootstrap_controller_once", once)
    monkeypatch.setattr(entrypoint, "bootstrap_narrowing_manager_in_transaction", manager_context)
    monkeypatch.setattr(entrypoint, "BootstrapSupervisor", Supervisor)
    assert entrypoint.run_selected_bootstrap("retained", narrow=lambda: None).state == "stopped"
    with pytest.raises(ApprovalRefused):
        entrypoint.run_selected_bootstrap("retained", narrow=lambda: None)
    assert constructions == [True]
    assert (directory / "controller-used").is_file()


def test_public_manager_widening_methods_still_refuse_without_bus_access():
    opened = []
    manager = BootstrapNarrowingManager(
        job_timeout_seconds=0.1,
        session_factory=lambda: opened.append(True),
    )
    with pytest.raises(UnitOperationFailed, match="widening refused"):
        manager.open_pair(_owned_grant_transaction(), approval=None,
                          check_publish=lambda: None)
    with pytest.raises(UnitOperationFailed, match="widening refused"):
        manager.start_and_wait(UnitKey.AUDITD, transaction=None,
                              check_start=lambda: None)
    assert opened == []
