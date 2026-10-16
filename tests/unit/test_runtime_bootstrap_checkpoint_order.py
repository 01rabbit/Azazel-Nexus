"""Full-check ordering after READY-budget Option C redundant-checkpoint removal.

Every irreversible step must still be immediately preceded by a fresh full
check, and a failing check at each remaining position must stop the next
irreversible step. Synthetic fakes only; this is not live systemd.
"""

import pytest

from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_overlay_files
from azazel_nexus_runtime.bootstrap import BootstrapSupervisor
from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.units import UnitKey, UnitOperationFailed
import test_runtime_bootstrap as supervisor_tests
from test_runtime_bootstrap import Harness
from test_runtime_bootstrap_controller import IDENTITY, OWNER, PROFILE_DIGEST
from test_runtime_bootstrap_controller_ready import (
    DelayedReadyBus, ReadyThenStartBus, _manager, _transaction as _ready_transaction,
)
from test_runtime_bootstrap_manager_publication import (
    _environment, _manager_fixture, _transaction,
)

evidence = supervisor_tests.evidence

# Full checks that remain inside one open_pair (_publish_and_inspect_pair):
# 1 before journal retire, 2 before journal create, 3/4 and 5/6 around each
# O_EXCL create and journal replace, 7 before D-Bus Reload.
MANAGER_OPEN_PAIR_CHECKS = 7
IRREVERSIBLE_PUBLICATION = {
    "journal_create", "create_file", "journal_replace", "reload",
}


class _StoreProxy:
    def __init__(self, store, events):
        self._store, self._events = store, events

    def create(self, journal):
        self._events.append("journal_create")
        return self._store.create(journal)

    def replace(self, current, updated):
        self._events.append("journal_replace")
        return self._store.replace(current, updated)

    def __getattr__(self, name):
        return getattr(self._store, name)


def _run_publication(tmp_path, monkeypatch, fail_at=None):
    events, state = [], {"checks": 0}
    with _environment(tmp_path) as env:
        manager, _sessions, bus, approval, *_ = _manager_fixture(env, monkeypatch)
        directories, store, guard = manager._publication_inputs
        manager._publication_inputs = (directories, _StoreProxy(store, events), guard)
        real_create = bootstrap_overlay_files._create_candidate

        def create_candidate(*args, **kwargs):
            events.append("create_file")
            return real_create(*args, **kwargs)

        monkeypatch.setattr(bootstrap_overlay_files, "_create_candidate", create_candidate)
        real_call = bus.call

        async def call(message):
            if message.member == "Reload":
                events.append("reload")
            return await real_call(message)

        bus.call = call

        def check_publish():
            state["checks"] += 1
            events.append("check")
            if state["checks"] == fail_at:
                raise ApprovalRefused("synthetic admission loss")

        error = None
        try:
            manager._publish_and_inspect_pair(
                _transaction(approval), approval=approval, check_publish=check_publish,
            )
        except (ApprovalRefused, UnitOperationFailed,
                bootstrap_overlay_files.OverlayPublicationUncertain) as exc:
            error = exc
    return events, state["checks"], error


def test_publication_each_irreversible_step_follows_a_full_check(tmp_path, monkeypatch):
    events, checks, error = _run_publication(tmp_path, monkeypatch)
    assert error is None
    assert checks == MANAGER_OPEN_PAIR_CHECKS
    assert [e for e in events if e != "check"] == [
        "journal_create", "create_file", "journal_replace",
        "create_file", "journal_replace", "reload",
    ]
    for index, event in enumerate(events):
        if event in IRREVERSIBLE_PUBLICATION:
            assert index and events[index - 1] == "check", (index, events)
    # Nothing but the Reload-gating check remains between last replace and Reload.
    last_replace = len(events) - 1 - events[::-1].index("journal_replace")
    assert events[last_replace + 1:] == ["check", "reload"]
    # No full check after Reload inside open_pair (bootstrap runs check_publish next).
    assert events[-1] == "reload"


@pytest.mark.parametrize("position", range(1, MANAGER_OPEN_PAIR_CHECKS + 1))
def test_publication_failed_check_stops_next_irreversible_step(
    tmp_path, monkeypatch, position,
):
    events, checks, error = _run_publication(tmp_path, monkeypatch, fail_at=position)
    assert error is not None
    assert checks == position
    assert events[-1] == "check"  # nothing irreversible ran after the failed check


class _EventedHarness:
    """Supervisor with real READY observer; events record every full check."""

    def __init__(self, evidence, monkeypatch, fail_at=None):
        self.events, self.checks, self.fail_at = [], 0, fail_at
        bus = ReadyThenStartBus()
        self.real, _sessions = _manager(bus, monkeypatch, timeout=0.1)
        h = self.h = Harness(evidence)
        s = h.supervisor
        events = self.events

        original_check = s._check

        def check():
            self.checks += 1
            events.append("check")
            if self.checks == self.fail_at:
                raise ApprovalRefused("synthetic admission loss")
            return original_check()

        monkeypatch.setattr(s, "_check", check)
        advance = s._advance_grant

        def record_advance(phase, **kwargs):
            events.append(f"advance:{phase}")
            return advance(phase, **kwargs)

        monkeypatch.setattr(s, "_advance_grant", record_advance)
        create = h.grant_store.create

        def store_create(journal):
            events.append("grant_create")
            return create(journal)

        monkeypatch.setattr(h.grant_store, "create", store_create)
        monkeypatch.setattr(s, "controller_ready", lambda: events.append("notify"))

        def record_flag(owner_name):
            def setter(obj, name, value):
                if name == "_controller_ready_confirmed" and value is True:
                    events.append(owner_name)
                object.__setattr__(obj, name, value)
            return setter

        monkeypatch.setattr(BootstrapSupervisor, "__setattr__", record_flag("flag:supervisor"))
        monkeypatch.setattr(BootstrapNarrowingManager, "__setattr__", record_flag("flag:manager"))

        def bind_publication(transaction, approval):
            self.real._controller_binding = (IDENTITY, OWNER, PROFILE_DIGEST)
            self.real._controller_grant = transaction

        h.manager.open_pair_after_publish = bind_publication
        h.manager.confirm_controller_ready = self.real.confirm_controller_ready
        start = h.manager.start_and_wait

        def start_and_wait(unit, *, transaction, check_start):
            if unit is UnitKey.AUDITD:
                events.append("start_submit")
            return start(unit, transaction=transaction, check_start=check_start)

        h.manager.start_and_wait = start_and_wait

    def run(self):
        try:
            self.h.supervisor.run()
        except Exception:
            pass
        return self.events


# Event -> must be immediately preceded by a full check.
CHECK_GATED = (
    "grant_create", "advance:pair_grant_opened", "notify", "flag:manager",
    "flag:supervisor", "advance:auditd_start_intent", "start_submit",
)


def test_supervisor_each_irreversible_step_follows_a_full_check(evidence, monkeypatch):
    events = _EventedHarness(evidence, monkeypatch).run()
    for name in CHECK_GATED:
        assert name in events, (name, events)
        index = events.index(name)
        assert events[index - 1] == "check", (name, events)
    # pair_grant_intent is advanced atomically with the create (no widening).
    assert events[events.index("advance:pair_grant_intent") - 1] == "grant_create"
    # Exactly one full check between the pair_grant_opened advance and READY=1.
    opened = events.index("advance:pair_grant_opened")
    assert events[opened:events.index("notify")] == [
        "advance:pair_grant_opened", "check",
    ]
    # Flag order: manager flag is set before the supervisor's final check.
    assert events.index("flag:manager") < events.index("flag:supervisor")


@pytest.mark.parametrize("target", CHECK_GATED)
def test_supervisor_failed_check_stops_next_irreversible_step(
    evidence, monkeypatch, target,
):
    clean = _EventedHarness(evidence, monkeypatch).run()
    position = clean[:clean.index(target)].count("check")
    assert position >= 1
    with monkeypatch.context() as m:
        failing = _EventedHarness(evidence, m, fail_at=position)
        events = failing.run()
    assert events.count("check") >= position
    assert target not in events


def test_full_check_budget_before_ready_is_reduced(evidence, monkeypatch):
    events = _EventedHarness(evidence, monkeypatch).run()
    before_notify = events[:events.index("notify")]
    # Supervisor-side full checks before READY=1 with a one-check fake open_pair:
    # 2 prestart + 1 publication + 1 in open_pair + 1 post-open_pair + 1 READY
    # (confirm_controller_ready's first checkpoint) = 6. Before the removal it
    # was 8 (extra self._check() after pair_grant_opened and check_ready()).
    assert before_notify.count("check") == 6
    # Production total before READY is 12 (was 20); see the report.


def _ready_run(monkeypatch, fail_at=None):
    bus = DelayedReadyBus(ready_after=1)
    manager, _sessions = _manager(bus, monkeypatch)
    events = []
    state = {"n": 0}

    def setter(obj, name, value):
        if name == "_controller_ready_confirmed" and value is True:
            events.append("flag")
        object.__setattr__(obj, name, value)

    monkeypatch.setattr(BootstrapNarrowingManager, "__setattr__", setter)

    def check_ready():
        state["n"] += 1
        events.append("check")
        if state["n"] == fail_at:
            raise ApprovalRefused("synthetic admission loss")

    error = None
    try:
        manager.confirm_controller_ready(
            _ready_transaction(), check_ready=check_ready,
            notify=lambda: events.append("notify"),
        )
    except (ApprovalRefused, UnitOperationFailed) as exc:
        error = exc
    return events, state["n"], error, manager


def test_controller_ready_notify_and_flag_follow_full_checks(monkeypatch):
    events, checks, error, manager = _ready_run(monkeypatch)
    assert error is None and manager._controller_ready_confirmed is True
    assert events[0] == "check" and events[1] == "notify"
    assert events[-1] == "flag" and events[-2] == "check"
    assert events.count("notify") == 1
    # pre-notify, post-notify, then loop-top/not-ready/post-inspect checks for
    # this fake (ready_after=1): 6. The duplicate trailing checkpoint after the
    # loop was removed (was 7); the last check is immediately followed by the flag.
    assert checks == 6


@pytest.mark.parametrize("position", range(1, 7))
def test_controller_ready_failed_check_stops_next_step(monkeypatch, position):
    events, checks, error, manager = _ready_run(monkeypatch, fail_at=position)
    assert error is not None and checks == position
    assert events[-1] == "check"
    assert "flag" not in events and manager._controller_ready_confirmed is False
    assert events.count("notify") == (0 if position == 1 else 1)


def _stop_after_opened(evidence, monkeypatch, *, fail_next_check):
    ev = _EventedHarness(evidence, monkeypatch)
    h, s = ev.h, ev.h.supervisor
    original = s._advance_grant
    state = {}

    def advance(phase, **kwargs):
        result = original(phase, **kwargs)
        if phase == "pair_grant_opened":
            h.stop = True
            state["armed"] = ev.checks
            if fail_next_check:
                ev.fail_at = ev.checks + 1
        return result

    s._advance_grant = advance
    return ev, state


def test_stop_with_admission_loss_after_pair_opened_still_raises(evidence, monkeypatch):
    ev, _ = _stop_after_opened(evidence, monkeypatch, fail_next_check=True)
    with pytest.raises(ApprovalRefused, match="synthetic admission loss"):
        ev.h.supervisor.run()
    assert "notify" not in ev.events


def test_stop_with_passing_check_after_pair_opened_returns(evidence, monkeypatch):
    ev, _ = _stop_after_opened(evidence, monkeypatch, fail_next_check=False)
    ev.h.supervisor.run()
    assert "notify" not in ev.events
    assert "advance:auditd_start_intent" not in ev.events
