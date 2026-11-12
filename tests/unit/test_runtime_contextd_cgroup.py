"""S-A, S-B and R of the stop contract (work unit 46).

S-A: the broker's withdrawal is confirmed only when its cgroup is empty.
S-B: an unexpected error in the main pass narrows, and the original error is raised.
R:   an unexpected error in the recheck withholds and still withdraws.
Faults are injected with monkeypatch; the acceptance is what the node ends in.
"""

from __future__ import annotations

import os

import pytest

from azazel_nexus.audit import AuditChainBroken, AuditLedger
from azazel_nexus.activation import UnitState
from azazel_nexus_runtime import activated, activation_recheck
from azazel_nexus_runtime.activation_retire import RetireRefused
from azazel_nexus_runtime.activation_withdraw import (
    WithdrawalUnconfirmed, contextd_already_withdrawn, contextd_is_quiet, contextd_is_running,
)
from azazel_nexus_runtime.activation_recheck import ContextdVerdict
from azazel_nexus_runtime.contextd_cgroup import read_contextd_cgroup
from azazel_nexus_runtime.units import ContextdStopAuthority
from stop_helpers import CTX, JOB, NO_JOB, ContextdModel, FakeClock, authority
from test_runtime_activation_recheck import (  # noqa: F401 - fixtures
    events_after, granted, markers, recheck, withdrawn,
)
from test_runtime_activation_contextd import ctx_world  # noqa: F401
from test_runtime_activation_review_fixes import (  # noqa: F401 - fixtures
    NOW, _pass, queued, ready_ok,
)

UNIT = "azazel-knowledge-contextd.service"
SELF_OK = "0::/system.slice/run-abc.service\n"
DEFAULT = object()


def mount_id_of(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for line in open(f"/proc/self/fdinfo/{fd}"):
            if line.startswith("mnt_id:"):
                return int(line.split(":")[1])
    finally:
        os.close(fd)


def mountinfo_for(base, *, fstype="cgroup2", mount_root="/", point="/sys/fs/cgroup",
                  device=None, mount_id=None):
    dev = os.stat(base).st_dev if device is None else device
    mid = mount_id_of(base) if mount_id is None else mount_id
    return (f"{mid} 25 {os.major(dev)}:{os.minor(dev)} {mount_root} {point} rw,nosuid - {fstype} cgroup2 rw\n"
            "31 25 0:5 / /proc rw - proc proc rw\n")


def make_root(tmp_path, *, self_cgroup=SELF_OK, mountinfo=DEFAULT, slice_dir=True,
              unit_dir=True, events="populated 1\nfrozen 0\n"):
    root = tmp_path / "r"
    (root / "proc/self").mkdir(parents=True)
    if self_cgroup is not None:
        (root / "proc/self/cgroup").write_text(self_cgroup)
    base = root / "sys/fs/cgroup"
    base.mkdir(parents=True)
    if mountinfo is DEFAULT:
        mountinfo = mountinfo_for(base)
    if mountinfo is not None:
        (root / "proc/self/mountinfo").write_text(mountinfo)
    if slice_dir:
        (base / "system.slice").mkdir()
        if unit_dir:
            (base / "system.slice" / UNIT).mkdir()
            if events is not None:
                (base / "system.slice" / UNIT / "cgroup.events").write_text(events)
    return root


# -- the reader ---------------------------------------------------------------------------


@pytest.mark.parametrize("events,expected", [
    ("populated 1\nfrozen 0\n", "populated"), ("populated 0\nfrozen 0\n", "empty"),
    ("frozen 0\n", "unknown"), ("populated 2\n", "unknown"),
    ("populated 0\npopulated 1\n", "unknown"), ("populated\n", "unknown"), ("", "unknown")])
def test_the_reader_parses_cgroup_events_exactly(tmp_path, events, expected):
    assert read_contextd_cgroup("active", root=make_root(tmp_path, events=events)) == expected


def test_a_missing_events_file_is_unknown(tmp_path):
    assert read_contextd_cgroup("inactive", root=make_root(tmp_path, events=None)) == "unknown"


@pytest.mark.parametrize("state,expected", [
    ("inactive", "empty"), ("failed", "empty"), ("active", "unknown"),
    ("deactivating", "unknown"), ("activating", "unknown")])
def test_an_absent_broker_cgroup_is_empty_only_for_a_stopped_unit(tmp_path, state, expected):
    root = make_root(tmp_path, unit_dir=False)
    assert read_contextd_cgroup(state, root=root) == expected


@pytest.mark.parametrize("state", ["inactive", "failed"])
def test_an_absent_system_slice_is_unknown(tmp_path, state):
    assert read_contextd_cgroup(state, root=make_root(tmp_path, slice_dir=False)) == "unknown"


@pytest.mark.parametrize("kwargs", [
    dict(self_cgroup="0::/docker/abc/system.slice/x.service\n"),   # host cgroup namespace
    dict(self_cgroup="0::/system.slice/a.service\n0::/other\n"),
    dict(self_cgroup="1:cpu:/system.slice/a.service\n"),
    dict(self_cgroup="0::/user.slice/a.service\n"),
    dict(self_cgroup="0::/system.slice/a b.service\n"),
    dict(self_cgroup="0::/system.slice/a.service"),                  # no newline
    dict(self_cgroup=None),
    dict(mountinfo=None),
    dict(mountinfo="30 25 0:27 / /sys/fs/cgroup rw - cgroup cgroup rw\n"),   # v1
    dict(mountinfo="30 25 0:27 / /sys/fs/cgroup/unified rw - cgroup2 cgroup2 rw\n"),
    dict(mountinfo="31 25 0:5 / /proc rw - proc proc rw\n"),
    dict(mountinfo="30 25 0:99999 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n"),  # other device
])
@pytest.mark.parametrize("state", ["inactive", "failed", "active"])
def test_a_cgroup_root_that_is_not_ours_is_unknown(tmp_path, kwargs, state):
    # even where the file says `populated 0` and the directory is absent
    assert read_contextd_cgroup(state, root=make_root(tmp_path, events="populated 0\n", **kwargs)) == "unknown"
    assert read_contextd_cgroup(state, root=make_root(tmp_path / "b", unit_dir=False, **kwargs)) == "unknown"


@pytest.mark.parametrize("variant", ["mount_root", "fstype", "point", "device", "id_absent"])
def test_the_mount_of_the_opened_directory_must_be_our_cgroup2(tmp_path, variant):
    root = make_root(tmp_path, events="populated 0\n")
    base = root / "sys/fs/cgroup"
    good = mountinfo_for(base)
    text = {
        "mount_root": mountinfo_for(base, mount_root="/docker/x"),
        "fstype": mountinfo_for(base, fstype="tmpfs"),
        "point": mountinfo_for(base, point="/sys/fs/cgroup/unified"),
        "device": mountinfo_for(base, device=os.makedev(0, 4242)),
        "id_absent": mountinfo_for(base, mount_id=mount_id_of(base) + 100000),
    }[variant]
    (root / "proc/self/mountinfo").write_text(text)
    assert read_contextd_cgroup("inactive", root=root) == "unknown"
    (root / "proc/self/mountinfo").write_text(good)
    assert read_contextd_cgroup("inactive", root=root) == "empty"


def test_stacked_mounts_are_told_apart_by_mount_id_not_by_position(tmp_path):
    root = make_root(tmp_path, events="populated 0\n")
    base = root / "sys/fs/cgroup"
    mine = mountinfo_for(base).split("\n")[0] + "\n"
    other = mountinfo_for(base, mount_id=mount_id_of(base) + 7).split("\n")[0] + "\n"
    # a decoy cgroup2 line with another ID, later in the file, does not matter ...
    (root / "proc/self/mountinfo").write_text(mine + other)
    assert read_contextd_cgroup("active", root=root) == "empty"
    # ... and a cgroup2 line that is not the opened directory's mount does not rescue a
    # tmpfs mounted over it (the opened directory belongs to the tmpfs line)
    tmpfs = mountinfo_for(base, fstype="tmpfs").split("\n")[0] + "\n"
    decoy = mountinfo_for(base, mount_id=mount_id_of(base) + 7).split("\n")[0] + "\n"
    (root / "proc/self/mountinfo").write_text(decoy + tmpfs)
    assert read_contextd_cgroup("active", root=root) == "unknown"


def test_an_unreadable_mount_id_is_unknown(tmp_path, monkeypatch):
    from azazel_nexus_runtime import contextd_cgroup
    root = make_root(tmp_path, events="populated 0\n")
    monkeypatch.setattr(contextd_cgroup, "_mount_id", lambda fd: None)
    assert read_contextd_cgroup("active", root=root) == "unknown"


def test_a_populated_zero_is_empty_only_if_the_mount_is_unchanged_afterwards(tmp_path, monkeypatch):
    from azazel_nexus_runtime import contextd_cgroup
    root = make_root(tmp_path, events="populated 0\n")
    assert read_contextd_cgroup("active", root=root) == "empty"
    real = contextd_cgroup._trust
    seen = []

    def changing(r, fd):
        seen.append(1)
        return real(r, fd) if len(seen) == 1 else None

    monkeypatch.setattr(contextd_cgroup, "_trust", changing)
    assert read_contextd_cgroup("active", root=root) == "unknown"
    assert len(seen) == 2
    # a populated 1 is reported as it is
    seen.clear()
    root = make_root(tmp_path / "p", events="populated 1\n")
    assert read_contextd_cgroup("active", root=root) == "populated"


@pytest.mark.parametrize("case", ["populated", "empty_file", "absent", "unknown_root",
                                  "no_events"])
def test_no_descriptor_is_left_open(tmp_path, case):
    kwargs = {"populated": {}, "empty_file": dict(events="populated 0\n"),
              "absent": dict(unit_dir=False), "unknown_root": dict(self_cgroup="x\n"),
              "no_events": dict(events=None)}[case]
    root = make_root(tmp_path, **kwargs)
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(5):
        read_contextd_cgroup("inactive", root=root)
    assert len(os.listdir("/proc/self/fd")) == before


def test_an_absent_leaf_is_empty_only_if_the_mount_is_unchanged_afterwards(tmp_path, monkeypatch):
    from azazel_nexus_runtime import contextd_cgroup
    root = make_root(tmp_path, unit_dir=False)
    assert read_contextd_cgroup("inactive", root=root) == "empty"
    real = contextd_cgroup._trust
    seen = []

    def changing(r, fd):
        seen.append(1)
        answer = real(r, fd)
        return answer if len(seen) == 1 else None  # the second read finds another state

    monkeypatch.setattr(contextd_cgroup, "_trust", changing)
    assert read_contextd_cgroup("inactive", root=root) == "unknown"
    assert len(seen) == 2


def test_a_symlinked_component_is_unknown(tmp_path):
    root = make_root(tmp_path, events="populated 0\n")
    unit = root / "sys/fs/cgroup/system.slice" / UNIT
    other = tmp_path / "elsewhere"
    unit.rename(other)
    unit.symlink_to(other)
    assert read_contextd_cgroup("inactive", root=root) == "unknown"
    slice_dir = root / "sys/fs/cgroup/system.slice"
    slice_dir.unlink() if slice_dir.is_symlink() else None
    root2 = make_root(tmp_path / "c", events="populated 0\n")
    s = root2 / "sys/fs/cgroup/system.slice"
    moved = tmp_path / "moved"
    s.rename(moved)
    s.symlink_to(moved)
    assert read_contextd_cgroup("inactive", root=root2) == "unknown"


def test_a_symlinked_events_file_is_unknown(tmp_path):
    root = make_root(tmp_path)
    events = root / "sys/fs/cgroup/system.slice" / UNIT / "cgroup.events"
    target = tmp_path / "t"
    target.write_text("populated 0\n")
    events.unlink()
    events.symlink_to(target)
    assert read_contextd_cgroup("inactive", root=root) == "unknown"


def test_the_production_authority_reads_files_under_its_cgroup_root(tmp_path):
    class Session:
        stop_contextd = unit_job = contextd_active_state = contextd_file_state = staticmethod(lambda *a: None)
    root = make_root(tmp_path, events="populated 1\n")
    guard = ContextdStopAuthority.from_session(Session, cgroup_root=root)
    guard._state = lambda unit: "failed"
    assert guard.cgroup_state(CTX) == "populated"
    # the default root is "/": a test host is not a cgroup-v2 systemd node, never `empty`
    bare = ContextdStopAuthority(stop=lambda: "/x", job=lambda u: NO_JOB,
                                 state=lambda u: "inactive", file_state=lambda u: "masked")
    assert bare.cgroup_state(CTX) == "unknown"


# -- the judgments ------------------------------------------------------------------------


def _model(cgroup, *, failed=True):
    model = ContextdModel(FakeClock())
    model.failed = failed
    model.cgroup_override = cgroup
    return model


@pytest.mark.parametrize("cgroup,quiet", [("empty", True), ("populated", False), ("unknown", False)])
def test_quiet_and_already_withdrawn_need_an_empty_cgroup(tmp_path, cgroup, quiet):
    guard = authority(_model(cgroup))
    assert contextd_is_quiet(guard) is quiet
    assert contextd_already_withdrawn(guard, tmp_path) is quiet
    assert contextd_is_running(guard, tmp_path) is (not quiet)


@pytest.mark.parametrize("cgroup,running", [("empty", False), ("populated", True), ("unknown", True)])
def test_an_inactive_unit_is_running_unless_its_cgroup_is_empty(cgroup, running):
    assert contextd_is_running(authority(_model(cgroup, failed=False))) is running


def test_an_unreadable_active_state_counts_as_running():
    def fail(*_a):
        raise RuntimeError("x")
    guard = ContextdStopAuthority(stop=fail, job=fail, state=fail, file_state=fail,
                                  cgroup=lambda a: "empty")
    assert contextd_is_running(guard) is True and contextd_is_quiet(guard) is False


@pytest.mark.parametrize("cgroup", ["populated", "unknown"])
def test_a_failed_broker_that_is_not_empty_is_unconfirmed_every_period(granted, cgroup):
    stage = granted
    stage.model.ends_failed = True
    stage.model.cgroup_override = None
    stage.model.leftover = cgroup == "populated"
    if cgroup == "unknown":
        stage.model.cgroup_override = "unknown"
        # the override is global; keep it unknown only after the stop took effect
    stage.world.healthy = False
    assert recheck(stage) == 1
    ev = events_after(stage)
    [unconfirmed] = [e for e in ev if e["event_type"] == "activation.withdrawal_unconfirmed"]
    assert unconfirmed["cgroup"] == cgroup
    assert not [e for e in ev if e["event_type"] == "activation.grant_withdrawn"]
    # still masked and without a marker, but it is reported again and again
    assert CTX not in markers(stage) and stage.manager.state(CTX) is UnitState.MASKED
    assert activation_recheck.contextd_triggers(
        stage.manager, authority(stage.model), stage.world.root) != ()
    stops = stage.model.stops
    assert recheck(stage) == 1
    assert stage.model.stops > stops
    assert len([e for e in events_after(stage)
                if e["event_type"] == "activation.withdrawal_unconfirmed"]) == 2


def test_a_withdrawal_with_an_empty_cgroup_records_it(granted):
    stage = granted
    stage.model.ends_failed = True
    stage.world.healthy = False
    assert recheck(stage) == 0
    [done] = [e for e in events_after(stage) if e["event_type"] == "activation.grant_withdrawn"]
    assert done["cgroup"] == "empty" and done["quiet_state"] == "failed"


@pytest.mark.parametrize("cgroup", ["populated", "unknown"])
def test_an_inactive_broker_with_a_cgroup_not_empty_is_a_trigger(granted, cgroup):
    stage = granted
    stage.model.running = False
    stage.model.cgroup_override = cgroup
    assert "cgroup_not_empty" in activation_recheck.contextd_triggers(
        stage.manager, authority(stage.model), stage.world.root)
    stage.model.cgroup_override = "empty"
    assert "cgroup_not_empty" not in activation_recheck.contextd_triggers(
        stage.manager, authority(stage.model), stage.world.root)


# -- S-B ----------------------------------------------------------------------------------


def _boom(exc):
    def f(*a, **k):
        raise exc
    return f


def _contained(queued):
    return (queued.manager.state(CTX) is UnitState.MASKED and queued.model.job == NO_JOB
            and queued.model.start_job_failed is False and not queued.model.running
            and CTX not in (queued.world.markers() or []))


@pytest.mark.parametrize("target,exc", [
    ("retirement_pending", ValueError("x")), ("retirement_pending", OSError("x")),
    ("write_accepted_grant", OSError("x"))])
def test_an_unexpected_error_while_the_job_is_held_narrows_and_is_raised_again(
        queued, monkeypatch, target, exc):
    monkeypatch.setattr(activated, target, _boom(exc))
    with pytest.raises(type(exc)) as seen:
        _pass(queued)
    assert seen.value is exc
    assert exc.narrowed is True  # marked, so no outer layer contains it again
    assert isinstance(exc.__cause__, RuntimeError)  # the narrowing's own error is chained
    assert _contained(queued)
    assert queued.model.stops == 1  # the held job was replaced first
    assert queued.manager.timeline.index(("stop", CTX)) < queued.manager.timeline.index(("mask", CTX))


@pytest.mark.parametrize("withheld", [False, True])
def test_a_broken_ledger_does_not_stop_the_containment(queued, monkeypatch, withheld):
    if withheld:
        from test_runtime_activation_pass import SCOPE
        queued.world.sign(units=SCOPE)
    error = AuditChainBroken("broken")
    monkeypatch.setattr(AuditLedger, "append", _boom(error))
    with pytest.raises(AuditChainBroken) as seen:
        _pass(queued)
    assert seen.value is error
    assert _contained(queued)


def test_an_error_that_is_already_narrowed_is_not_narrowed_again(queued, monkeypatch):
    error = RuntimeError("already narrowed")
    error.narrowed = True
    monkeypatch.setattr(activated, "retirement_pending", _boom(error))
    calls = []
    real = activated._narrow_final
    monkeypatch.setattr(activated, "_narrow_final",
                        lambda *a, **k: (calls.append(1), real(*a, **k))[1])
    with pytest.raises(RuntimeError) as seen:
        _pass(queued)
    assert seen.value is error and calls == []


def test_a_failing_containment_does_not_hide_the_original_error(queued, monkeypatch):
    error = ValueError("original")
    monkeypatch.setattr(activated, "retirement_pending", _boom(error))
    monkeypatch.setattr(activated, "_narrow_final", _boom(RuntimeError("narrowing failed")))
    with pytest.raises(ValueError) as seen:
        _pass(queued)
    assert seen.value is error
    assert isinstance(seen.value.__cause__, RuntimeError)  # the narrowing is chained
    assert seen.value.narrowed is True  # no outer layer contains it again


# -- R ------------------------------------------------------------------------------------


def _rc(stage, retirement):
    from azazel_nexus_runtime.activation_recheck import run_recheck
    stage.world.healthy = False
    return run_recheck(manager=stage.manager, authority=authority(stage.model),
                       root=stage.world.root, now=NOW, producers=stage.world.producers(),
                       invocation_id="c" * 32, clock=stage.clock, sleep=stage.clock.sleep,
                       retirement=retirement)


@pytest.mark.parametrize("exc", [OSError("state"), ValueError("v"), RuntimeError("r"),
                                 RetireRefused("refused")])
def test_a_retirement_error_withholds_and_still_withdraws(granted, exc):
    assert _rc(granted, _boom(exc)) == 1
    assert withdrawn(granted)
    labels = [e for e in events_after(granted) if e["event_type"] == "activation.grant_withdrawn"]
    assert labels and labels[0]["reason"] == "recheck:retirement_pending"


@pytest.mark.parametrize("outcome", [None, "bogus", 3, ("retired",)])
def test_a_retirement_result_that_is_not_an_outcome_is_not_recorded(granted, outcome):
    assert _rc(granted, lambda **k: outcome) == 1
    assert withdrawn(granted)
    assert not [e for e in events_after(granted) if e["event_type"] == "activation.approval_retired"]


@pytest.mark.parametrize("bad", ["raises", "no_label", "granted_wrong"])
def test_a_verdict_error_is_not_granted_and_still_withdraws(granted, monkeypatch, bad):
    class Odd:
        granted = True
        @property
        def label(self):
            raise RuntimeError("label")
    if bad == "raises":
        monkeypatch.setattr(activation_recheck, "contextd_verdict", _boom(RuntimeError("v")))
    elif bad == "no_label":
        monkeypatch.setattr(activation_recheck, "contextd_verdict", lambda *a, **k: Odd())
    else:
        monkeypatch.setattr(activation_recheck, "contextd_verdict",
                            lambda *a, **k: type("V", (), {"granted": 1, "label": 5})())
    assert _rc(granted, None) == 1
    assert withdrawn(granted)
    [event] = [e for e in events_after(granted) if e["event_type"] == "activation.grant_withdrawn"]
    assert event["reason"] == "recheck:verdict_error"


# -- more S-B (deadline, broken session), R look-alikes, the default is fail-closed ----------------------


def _fresh_for(queued):
    import contextlib

    @contextlib.contextmanager
    def fresh():
        yield queued.manager, authority(queued.model)
    return fresh


@pytest.mark.parametrize("cause", ["deadline", "broken_session"])
def test_a_spent_deadline_or_a_broken_session_still_raises_the_original_error(
        queued, monkeypatch, cause):
    from types import SimpleNamespace
    original = ValueError("original")
    kwargs = {}

    def fail(*a, **k):
        if cause == "deadline":
            queued.clock.sleep(activated.MAIN_PASS_BUDGET_SECONDS
                               - activated.MAIN_PASS_RESERVE_SECONDS
                               - activated.MAIN_PASS_READY_SECONDS + 0.5)
        else:
            queued.manager.call = SimpleNamespace(broken=True)
        raise original

    if cause == "broken_session":
        kwargs["fresh_manager"] = _fresh_for(queued)
    monkeypatch.setattr(activated, "retirement_pending", fail)
    with pytest.raises(ValueError) as seen:
        _pass(queued, **kwargs)
    assert seen.value is original
    assert original.narrowed is True
    assert isinstance(original.__cause__, RuntimeError)
    assert "finished or the time ended" in str(original.__cause__)
    assert queued.manager.state(CTX) is UnitState.MASKED


def test_the_default_authority_without_a_readable_cgroup_fails_closed(granted, tmp_path):
    """No fake of the cgroup reader: a node whose cgroup root is not ours (here a
    stand-in tree) reads `unknown`, so a failed broker is never called withdrawn."""
    from azazel_nexus_runtime.activation_recheck import run_recheck

    class Session:
        stop_contextd = staticmethod(granted.model.stop)
        unit_job = staticmethod(granted.model.current_job)
        contextd_active_state = staticmethod(granted.model.active_state)
        contextd_file_state = staticmethod(granted.model.file_state_of)

    root = make_root(tmp_path, self_cgroup="0::/docker/x/system.slice/a.service\n",
                     events="populated 0\n")
    guard = ContextdStopAuthority.from_session(Session, cgroup_root=root)
    granted.model.ends_failed = True
    granted.world.healthy = False
    rc = run_recheck(manager=granted.manager, authority=guard, root=granted.world.root,
                     now=NOW, producers=granted.world.producers(), invocation_id="c" * 32,
                     clock=granted.clock, sleep=granted.clock.sleep)
    assert rc == 1
    [event] = [e for e in events_after(granted)
               if e["event_type"] == "activation.withdrawal_unconfirmed"]
    assert event["cgroup"] == "unknown"


class _EqualsEverything:
    def __eq__(self, other):
        return True

    def __hash__(self):
        return 1


class _Retired(str):
    def __eq__(self, other):
        return True

    __hash__ = str.__hash__


@pytest.mark.parametrize("outcome", [_EqualsEverything(), _Retired("retired"), b"retired"])
def test_a_look_alike_retirement_result_is_a_withhold(granted, outcome):
    assert _rc(granted, lambda **k: outcome) == 1
    assert withdrawn(granted)
    assert not [e for e in events_after(granted) if e["event_type"] == "activation.approval_retired"]


@pytest.mark.parametrize("verdict", [
    ContextdVerdict(True, "bogus"), ContextdVerdict(True, "granted:extra"),
    ContextdVerdict(True, 5), ContextdVerdict(False, 5), ContextdVerdict(False, "granted"),
    ContextdVerdict(False, "made_up: x")])
def test_a_verdict_that_does_not_match_what_a_grant_looks_like_is_a_withhold(
        granted, monkeypatch, verdict):
    monkeypatch.setattr(activation_recheck, "contextd_verdict", lambda *a, **k: verdict)
    assert _rc(granted, None) == 1
    assert withdrawn(granted)
    [event] = [e for e in events_after(granted) if e["event_type"] == "activation.grant_withdrawn"]
    assert event["reason"] == "recheck:verdict_error"


def test_a_duck_typed_granted_verdict_is_not_trusted(granted, monkeypatch):
    class Duck:
        granted = True
        label = "granted"
    monkeypatch.setattr(activation_recheck, "contextd_verdict", lambda *a, **k: Duck())
    assert _rc(granted, None) == 1
    assert withdrawn(granted)
    [event] = [e for e in events_after(granted) if e["event_type"] == "activation.grant_withdrawn"]
    assert event["reason"] == "recheck:verdict_error"


@pytest.mark.parametrize("reason,label", [
    ("retirement_pending", "retirement_pending"),
    ("lease_expired: the lease ran from a to b", "lease_expired"),
    ("health_not_established: x", "health_not_established")])
def test_a_real_withhold_keeps_its_label_in_the_record(granted, monkeypatch, reason, label):
    monkeypatch.setattr(activation_recheck, "contextd_verdict",
                        lambda *a, **k: ContextdVerdict(False, reason))
    assert _rc(granted, None) == 0
    assert withdrawn(granted)
    [event] = [e for e in events_after(granted) if e["event_type"] == "activation.grant_withdrawn"]
    assert event["reason"] == f"recheck:{label}"


def test_a_failed_narrowing_is_named_on_stderr_and_the_original_is_raised(
        queued, monkeypatch, capsys):
    error = ValueError("original")
    monkeypatch.setattr(activated, "retirement_pending", _boom(error))
    monkeypatch.setattr(activated, "_narrow_final", _boom(OSError("secret detail")))
    with pytest.raises(ValueError) as seen:
        _pass(queued)
    assert seen.value is error and isinstance(error.__cause__, OSError)
    err = capsys.readouterr().err
    assert ("az-activated the narrowing after an unexpected error failed (OSError)\n" in err)
    assert "secret detail" not in err
