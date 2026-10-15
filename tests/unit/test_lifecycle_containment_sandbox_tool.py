"""Contract tests for the operator-only lifecycle containment fixture tool.

Everything external (systemd, subprocess, kill, staging, uuid) is monkeypatched;
no real unit is started and no sudo is attempted.
"""

import json
import signal
from hashlib import sha256
from types import SimpleNamespace

import pytest

from tools import qualify_lifecycle_containment_sandbox as containment

TOKEN = "0123456789abcdef0123456789abcdef"
CONTROLLER_PID = 4321
AUDIT_PID = 5555


def test_plan_only_main_does_no_external_work(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("plan-only mode performed external work")

    monkeypatch.setattr(containment.subprocess, "run", forbidden)
    monkeypatch.setattr(containment.os, "kill", forbidden)
    monkeypatch.setattr("sys.argv", ["qualify"])

    assert containment.main() == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["execute"] is False
    assert plan["probe_sha256"] == sha256(containment.PROBE.encode()).hexdigest()
    assert plan["cases"] == [
        "queued_start_containment",
        "audit_death_follow_stop",
        "run_marker_mount_view",
    ]


def test_run_all_refuses_non_root_before_any_case(monkeypatch):
    calls = []
    monkeypatch.setattr(containment.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(containment, "CASES", (lambda: calls.append("case"),))

    with pytest.raises(PermissionError, match="operator root"):
        containment.run_all()
    assert calls == []


def _lstat(mode, uid=0):
    return lambda path: SimpleNamespace(st_mode=mode, st_uid=uid)


def test_run_stage_accepts_root_owned_protected_tmpfs(monkeypatch):
    monkeypatch.setattr(containment.os, "lstat", _lstat(0o40755))
    monkeypatch.setattr(containment, "_mount_fstype", lambda mountpoint: "tmpfs")
    assert containment._run_stage() == "/run"


def test_run_stage_refuses_a_run_that_is_not_tmpfs(monkeypatch):
    monkeypatch.setattr(containment.os, "lstat", _lstat(0o40755))
    monkeypatch.setattr(containment, "_mount_fstype", lambda mountpoint: "ext4")
    with pytest.raises(ValueError, match="per-boot tmpfs"):
        containment._run_stage()


def test_mount_fstype_reads_the_last_entry_at_the_exact_mountpoint(tmp_path):
    mounts = tmp_path / "mounts"
    mounts.write_text(
        "sysfs /sys sysfs rw 0 0\n"
        "tmpfs /run/user/1000 tmpfs rw 0 0\n"
        "overlay /run overlay rw 0 0\n"
        "tmpfs /run tmpfs rw,nosuid,nodev,noexec 0 0\n"
    )
    assert containment._mount_fstype("/run", mounts=str(mounts)) == "tmpfs"
    assert containment._mount_fstype("/var", mounts=str(mounts)) is None


@pytest.mark.parametrize(
    ("mode", "uid"),
    [
        (0o40775, 0),  # group-writable
        (0o40757, 0),  # world-writable
        (0o100644, 0),  # not a directory
        (0o40755, 1000),  # not root-owned
    ],
)
def test_run_stage_refuses_unprotected_parent(monkeypatch, mode, uid):
    monkeypatch.setattr(containment.os, "lstat", _lstat(mode, uid))
    with pytest.raises(ValueError, match="protected /run"):
        containment._run_stage()


def test_cleanup_confirms_all_units(monkeypatch):
    seen = []
    monkeypatch.setattr(containment, "_confirm_or_stop", seen.append)
    stopped, error = containment._cleanup(["a.service", "b.service"])
    assert stopped == ["a.service", "b.service"]
    assert error is None
    assert seen == stopped


def test_cleanup_reports_error_when_a_confirm_raises(monkeypatch):
    def confirm(unit):
        if unit == "b.service":
            raise RuntimeError("stuck " + unit)

    monkeypatch.setattr(containment, "_confirm_or_stop", confirm)
    stopped, error = containment._cleanup(["a.service", "b.service", "c.service"])
    assert stopped == ["a.service", "c.service"]
    assert error == "RuntimeError: stuck b.service"


def test_finish_passes_only_when_contained_clean_and_removed(monkeypatch, tmp_path):
    monkeypatch.setattr(containment, "_confirm_or_stop", lambda unit: None)
    directory = tmp_path / "stage"
    directory.mkdir()
    report = containment._finish({"contained": True}, ["u.service"], directory, error=None)
    assert report["error"] is None
    assert report["cleanup_confirmed"] is True
    assert report["retained_directory"] is None
    assert report["passed"] is True
    assert not directory.exists()


@pytest.mark.parametrize(
    ("contained", "error"), [(False, None), (True, "boom"), (None, None)])
def test_finish_does_not_pass_when_uncontained_or_errored(
        monkeypatch, tmp_path, contained, error):
    monkeypatch.setattr(containment, "_confirm_or_stop", lambda unit: None)
    directory = tmp_path / "stage"
    directory.mkdir()
    report = {} if contained is None else {"contained": contained}
    report = containment._finish(report, ["u.service"], directory, error=error)
    assert report["cleanup_confirmed"] is True
    assert report["passed"] is False


def test_finish_retains_directory_when_stop_or_rmtree_fails(monkeypatch, tmp_path):
    def confirm(unit):
        raise RuntimeError("unconfirmed")

    monkeypatch.setattr(containment, "_confirm_or_stop", confirm)
    monkeypatch.setattr(containment, "_rmtree", lambda directory: False)
    directory = tmp_path / "stage"
    directory.mkdir()
    report = containment._finish({"contained": True}, ["u.service"], directory, error=None)
    assert report["cleanup_confirmed"] is False
    assert report["retained_directory"] == str(directory)
    assert "unconfirmed" in report["error"]
    assert report["passed"] is False
    assert directory.exists()


class _Harness:
    """Common monkeypatching for the run_* cases; records cleanup and kills."""

    def __init__(self, tmp_path, monkeypatch):
        self.directory = tmp_path / "stage"
        self.directory.mkdir()
        self.units = containment.fixture_units(TOKEN)
        self.confirmed = []
        self.kills = []
        self.launched = []
        self.argvs = []
        monkeypatch.setattr(containment, "_stage_parent", lambda: str(tmp_path))
        monkeypatch.setattr(containment, "_run_stage", lambda: str(tmp_path))
        monkeypatch.setattr(containment.tempfile, "mkdtemp",
                            lambda *, prefix, dir: str(self.directory))
        monkeypatch.setattr(containment.uuid, "uuid4",
                            lambda: SimpleNamespace(hex=TOKEN))
        monkeypatch.setattr(containment.time, "sleep", lambda seconds: None)
        monkeypatch.setattr(containment.os, "kill",
                            lambda pid, sig: self.kills.append((pid, sig)))
        monkeypatch.setattr(containment, "_confirm_or_stop", self.confirmed.append)
        monkeypatch.setattr(containment, "cgroup_drained", lambda unit: True)
        monkeypatch.setattr(containment, "cgroup_populated", lambda unit: True)

        def run(argv, **kwargs):
            self.launched.append(argv[-1])
            self.argvs.append(list(argv))
            return SimpleNamespace(stdout="", returncode=0)

        monkeypatch.setattr(containment.subprocess, "run", run)

    def assert_cleaned(self, report, expected_units):
        assert sorted(self.confirmed) == sorted(expected_units)
        assert report["cleanup_confirmed"] is True
        assert report["retained_directory"] is None
        assert not self.directory.exists()


def _settled(units, state="inactive"):
    return {unit: {"ActiveState": state, "MainPID": "0"} for unit in units}


def _queued_setup(harness, monkeypatch, *, helper_events,
                  controller_events=(("controller", "preready", 1),),
                  controller_state="activating", job_state="waiting"):
    helpers = [harness.units["audit"], harness.units["commission"]]
    jobs = {"count": 0}

    def list_jobs(units):
        jobs["count"] += 1
        if jobs["count"] == 1:
            return [(unit, "start", job_state) for unit in helpers]
        return []

    events = {"count": 0}

    def read_events(directory):
        events["count"] += 1
        # 1st: pre-kill snapshot (controller only); later: post-drain re-read.
        if events["count"] == 1:
            return [("controller", "preready", 1)]
        return list(controller_events) + helper_events

    def show(unit, props):
        if props == ["ActiveState"]:
            return {"ActiveState": controller_state}
        return {"MainPID": str(CONTROLLER_PID)}

    monkeypatch.setattr(containment, "_list_jobs", list_jobs)
    monkeypatch.setattr(containment, "_read_events", read_events)
    monkeypatch.setattr(containment, "_show", show)
    monkeypatch.setattr(containment, "_await",
                        lambda units, predicate, timeout, **kw: (
                            _settled(units), True))
    return jobs


def test_queued_start_containment_happy_path(tmp_path, monkeypatch):
    harness = _Harness(tmp_path, monkeypatch)
    jobs = _queued_setup(harness, monkeypatch, helper_events=[])

    report = containment.run_queued_start_containment()

    assert report["error"] is None
    assert report["contained"] is True
    assert report["passed"] is True
    assert report["helpers_queued_during_gate"] is True
    assert report["no_helper_events_before_kill"] is True
    assert report["helper_started_after_kill"] is False
    assert report["jobs_drained"] is True
    assert jobs["count"] == 2
    assert harness.kills == [(CONTROLLER_PID, signal.SIGKILL)]
    assert harness.launched == ["controller", "audit", "commission"]
    harness.assert_cleaned(report, harness.units.values())


def test_queued_start_containment_fails_when_helper_started(tmp_path, monkeypatch):
    harness = _Harness(tmp_path, monkeypatch)
    _queued_setup(harness, monkeypatch, helper_events=[("audit", "start", 7)])

    report = containment.run_queued_start_containment()

    assert report["helper_started_after_kill"] is True
    assert report["contained"] is False
    assert report["passed"] is False
    harness.assert_cleaned(report, harness.units.values())


def test_queued_start_containment_fails_when_kill_landed_after_ready(
        tmp_path, monkeypatch):
    harness = _Harness(tmp_path, monkeypatch)
    _queued_setup(harness, monkeypatch, helper_events=[],
                  controller_events=(("controller", "preready", 1),
                                     ("controller", "ready", 2)))

    report = containment.run_queued_start_containment()

    assert report["killed_before_ready"] is False
    assert report["contained"] is False


def test_queued_start_containment_fails_when_marker_was_written(tmp_path, monkeypatch):
    harness = _Harness(tmp_path, monkeypatch)
    _queued_setup(harness, monkeypatch, helper_events=[])
    (harness.directory / "controller-used").write_text("")

    report = containment.run_queued_start_containment()

    assert report["killed_before_ready"] is False
    assert report["contained"] is False


@pytest.mark.parametrize(
    ("controller_state", "job_state"), [("active", "waiting"), ("activating", "running")])
def test_queued_start_containment_requires_activating_controller_and_waiting_helpers(
        tmp_path, monkeypatch, controller_state, job_state):
    harness = _Harness(tmp_path, monkeypatch)
    _queued_setup(harness, monkeypatch, helper_events=[],
                  controller_state=controller_state, job_state=job_state)

    report = containment.run_queued_start_containment()

    assert report["contained"] is False


def _audit_setup(harness, monkeypatch, *, controller_state="active", audit_result="signal"):
    units = harness.units
    awaits = {"count": 0}

    def fake_await(names, predicate, timeout, **kwargs):
        awaits["count"] += 1
        if awaits["count"] == 1:
            return _settled(names, "active"), True
        return _settled(names, "inactive"), True

    def show(unit, props):
        if unit == units["audit"]:
            if props == ["Result"]:
                return {"Result": audit_result}
            return {"MainPID": str(AUDIT_PID)}
        assert unit == units["controller"]
        return {"ActiveState": controller_state, "SubState": "running",
                "MainPID": str(CONTROLLER_PID)}

    monkeypatch.setattr(containment, "_await", fake_await)
    monkeypatch.setattr(containment, "_show", show)
    return awaits


def test_audit_death_follow_stop_happy_path(tmp_path, monkeypatch):
    harness = _Harness(tmp_path, monkeypatch)
    awaits = _audit_setup(harness, monkeypatch)

    report = containment.run_audit_death_follow_stop()

    assert report["error"] is None
    assert report["contained"] is True
    assert report["passed"] is True
    assert report["controller_survived"] is True
    assert report["helpers_stopped"] is True
    assert awaits["count"] == 2
    assert harness.kills == [(AUDIT_PID, signal.SIGKILL)]
    assert all(pid != CONTROLLER_PID for pid, _ in harness.kills)
    harness.assert_cleaned(report, harness.units.values())


def test_audit_death_follow_stop_fails_when_controller_failed(tmp_path, monkeypatch):
    harness = _Harness(tmp_path, monkeypatch)
    _audit_setup(harness, monkeypatch, controller_state="failed")

    report = containment.run_audit_death_follow_stop()

    assert report["controller_survived"] is False
    assert report["contained"] is False
    assert report["passed"] is False
    harness.assert_cleaned(report, harness.units.values())


def test_audit_death_follow_stop_requires_a_signal_exit_for_audit(tmp_path, monkeypatch):
    harness = _Harness(tmp_path, monkeypatch)
    _audit_setup(harness, monkeypatch, audit_result="success")

    report = containment.run_audit_death_follow_stop()

    assert report["audit_result"] == "success"
    assert report["contained"] is False


_REFUSED = {"LoadState": "loaded", "ConditionResult": "no", "ActiveState": "inactive",
            "SubState": "dead", "ExecMainPID": "0", "Result": "success"}


def _marker_setup(harness, monkeypatch, *, write_marker, recheck=_REFUSED,
                  recheck_ran=False):
    units = harness.units
    recheck_events = {"count": 0}

    def fake_await(names, predicate, timeout, **kwargs):
        if names == [units["controller"]]:
            if write_marker:
                (harness.directory / "controller-used").write_text("")
            return _settled(names, "active"), True
        return _settled(names), True

    def show(unit, props):
        assert "recheck" in unit
        return dict(recheck)

    def read_events(directory):
        recheck_events["count"] += 1
        events = [("controller", "preready", 1)]
        if recheck_ran and recheck_events["count"] > 1:
            events.append(("recheck", "recheck", 9))
        return events

    monkeypatch.setattr(containment, "_await", fake_await)
    monkeypatch.setattr(containment, "_show", show)
    monkeypatch.setattr(containment, "_read_events", read_events)


def test_run_marker_mount_view_happy_path(tmp_path, monkeypatch):
    harness = _Harness(tmp_path, monkeypatch)
    _marker_setup(harness, monkeypatch, write_marker=True)

    report = containment.run_run_marker_mount_view()

    assert report["error"] is None
    assert report["marker_visible_on_host"] is True
    assert report["rerun_refused"] is True
    assert report["contained"] is True
    assert report["passed"] is True
    assert harness.launched == ["controller", "recheck"]
    # The controller is enqueued without blocking; the recheck blocks so its
    # condition is evaluated before the refusal is judged.
    assert "--no-block" in harness.argvs[0]
    assert "--no-block" not in harness.argvs[1]
    recheck_unit = next(unit for unit in harness.confirmed if "recheck" in unit)
    assert recheck_unit.startswith(containment.PREFIX)
    harness.assert_cleaned(report, [harness.units["controller"], recheck_unit])


def test_run_marker_mount_view_accepts_a_garbage_collected_refused_recheck(
        tmp_path, monkeypatch):
    harness = _Harness(tmp_path, monkeypatch)
    _marker_setup(harness, monkeypatch, write_marker=True,
                  recheck={"LoadState": "not-found", "ActiveState": "inactive",
                           "ExecMainPID": "0"})

    report = containment.run_run_marker_mount_view()

    assert report["rerun_refused"] is True
    assert report["contained"] is True


def test_run_marker_mount_view_fails_when_the_recheck_ran(tmp_path, monkeypatch):
    harness = _Harness(tmp_path, monkeypatch)
    _marker_setup(harness, monkeypatch, write_marker=True, recheck_ran=True)

    report = containment.run_run_marker_mount_view()

    assert report["new_recheck_events"] == [("recheck", "recheck", 9)]
    assert report["rerun_refused"] is False
    assert report["contained"] is False


def test_run_marker_mount_view_fails_without_marker(tmp_path, monkeypatch):
    harness = _Harness(tmp_path, monkeypatch)
    _marker_setup(harness, monkeypatch, write_marker=False)

    report = containment.run_run_marker_mount_view()

    assert report["marker_visible_on_host"] is False
    assert report["contained"] is False
    assert report["passed"] is False
    assert len(harness.confirmed) == 2
    assert not harness.directory.exists()


def test_run_all_aggregates_cases(monkeypatch):
    monkeypatch.setattr(containment.os, "geteuid", lambda: 0)

    def run_ok():
        return {"passed": True}

    def run_bad():
        return {"passed": False}

    monkeypatch.setattr(containment, "CASES", (run_ok, run_bad))
    report = containment.run_all()
    assert set(report["cases"]) == {"ok", "bad"}
    assert report["passed"] is False
