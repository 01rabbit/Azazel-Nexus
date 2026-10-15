"""Operator-only systemd containment fixtures; not a runtime gate.

This extends the READY-order fixture to the lifecycle containment cases the
native timer sandbox left not-qualified, using the same uniquely named transient
fixture units and trivial probes -- never the product units:

  1. queued_start_containment  -- the controller dies while the helpers' start
     jobs are still queued behind its pre-READY gate; the delayed helper starts
     must be contained (never run), with empty cgroups and drained jobs.
  2. audit_death_follow_stop   -- with all three active, audit is killed; the
     commissioner (BindsTo audit) must follow-stop while the controller survives.
  3. run_marker_mount_view     -- the controller writes its once-marker under a
     per-boot /run tmpfs path while sandboxed (PrivateTmp), and the manager's
     ConditionPathExists (host view) must see it and refuse a re-run: the
     marker/mount-view agreement the product unit relies on.

It reuses the READY-order fixture's unit/command/probe, cgroup and job readers,
and its stop/cleanup, and the native timer tool's staging. Default is plan-only;
``--execute`` needs an interactive operator's root session and never attempts
sudo. It fabricates no enrollment/pins/approval/time/epoch/generation input and
asserts nothing about product admission or deployment.
"""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

# Allow `python /abs/path/tools/qualify_lifecycle_containment_sandbox.py` from any
# cwd, not only `-m tools...` from the repo root.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.qualify_bootstrap_deadline_sandbox import _stage_parent  # noqa: E402
from tools.qualify_ready_order_sandbox import (  # noqa: E402
    PREFIX,
    PROBE,
    _GATE_SECONDS,
    _await,
    _confirm_or_stop,
    _list_jobs,
    _read_events,
    _show,
    cgroup_drained,
    cgroup_populated,
    command,
    fixture_units,
)

_STAGE_PREFIX = "azazel-nexus-containment-"
_DRAIN_DEADLINE_SECONDS = 15


def _mount_fstype(mountpoint, mounts="/proc/self/mounts"):
    """The filesystem type mounted exactly at `mountpoint`, or None."""
    fstype = None
    with open(mounts) as stream:
        for line in stream:
            fields = line.split()
            if len(fields) >= 3 and fields[1] == mountpoint:
                fstype = fields[2]  # the last matching entry is the visible one
    return fstype


def _run_stage():
    """Per-boot tmpfs parent, mirroring the product once-marker dir under /run.

    /run is the shared host view (PrivateTmp isolates only /tmp and /var/tmp), so
    a marker a sandboxed service writes here is what the manager's condition sees.
    """
    info = os.lstat("/run")
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("protected /run staging parent required")
    if _mount_fstype("/run") != "tmpfs":
        raise ValueError("/run must be the per-boot tmpfs")
    return "/run"


def _rmtree(directory):
    try:
        shutil.rmtree(directory)
        return True
    except Exception:
        return False


def _cleanup(attempted):
    """Confirm every attempted fixture unit stopped; report, do not swallow."""
    stopped, error = [], None
    for unit in attempted:
        try:
            _confirm_or_stop(unit)
            stopped.append(unit)
        except Exception as failure:
            stop_error = type(failure).__name__ + ": " + str(failure)
            error = stop_error if error is None else error + "; " + stop_error
    return stopped, error


def _drain_cgroups(units):
    deadline = time.monotonic() + _DRAIN_DEADLINE_SECONDS
    while True:
        cgroups = {unit: cgroup_drained(unit) for unit in units}
        if all(cgroups.values()) or time.monotonic() >= deadline:
            return cgroups
        time.sleep(0.2)


def _finish(report, attempted, directory, *, error):
    """Containment is already observed; now confirm stop, then remove staging."""
    stopped, cleanup_error = _cleanup(attempted)
    if cleanup_error:
        error = cleanup_error if error is None else error + "; " + cleanup_error
    removed = _rmtree(directory)
    report["error"] = error
    report["cleanup_confirmed"] = set(attempted) == set(stopped) and removed
    report["retained_directory"] = None if removed else str(directory)
    report["passed"] = bool(error is None and report.get("contained")
                            and report["cleanup_confirmed"])
    return report


def run_queued_start_containment():
    """Kill the controller mid-gate; the queued helper starts must be contained."""
    token = uuid.uuid4().hex
    units = fixture_units(token)
    directory = Path(tempfile.mkdtemp(prefix=_STAGE_PREFIX, dir=_stage_parent()))
    marker = directory / "controller-used"
    attempted = []
    error = None
    report = {"case": "queued_start_containment", "token": token, "units": units}
    try:
        (directory / "probe.py").write_text(PROBE)
        for role in ("controller", "audit", "commission"):
            attempted.append(units[role])
            subprocess.run(command(role, units[role], directory, units=units, marker=marker),
                           check=True, timeout=10)
        # Still inside the controller's pre-READY gate: helpers must be queued
        # as waiting start jobs behind an activating controller.
        time.sleep(min(1.5, _GATE_SECONDS / 2))
        queued = _list_jobs(set(units.values()))
        waiting = {row[0] for row in queued if row[1] == "start" and row[2] == "waiting"}
        helpers_queued = {units["audit"], units["commission"]} <= waiting
        report["queued_jobs"] = queued
        report["helpers_queued_during_gate"] = helpers_queued
        controller_activating = _show(
            units["controller"], ["ActiveState"]).get("ActiveState") == "activating"
        # Live baseline: the controller really runs in its own cgroup, so its later
        # drain is observed rather than credited to a wrong cgroup path.
        controller_populated = cgroup_populated(units["controller"])
        pre_helper_events = [event for event in _read_events(directory)
                             if event[0] in ("audit", "commission")]
        # Kill the controller before it signals READY.
        main_pid = int(_show(units["controller"], ["MainPID"]).get("MainPID", "0"))
        if main_pid <= 1:
            raise RuntimeError("controller fixture main PID unavailable mid-gate")
        report["controller_main_pid"] = main_pid
        os.kill(main_pid, signal.SIGKILL)
        states, settled = _await(
            list(units.values()),
            lambda state: state.get("ActiveState") in ("inactive", "failed"), 30,
        )
        cgroups = _drain_cgroups(set(units.values()))
        pending = _list_jobs(set(units.values()))
        # Re-read after the drain so a late helper stamp cannot be missed.
        events = _read_events(directory)
        helper_started = any(event[0] in ("audit", "commission") for event in events)
        controller_phases = [event[1] for event in events if event[0] == "controller"]
        # Positive proof the kill landed before READY: the probe creates the marker
        # and stamps "ready" only once its gate ends.
        killed_before_ready = controller_phases == ["preready"] and not marker.exists()
        report.update({
            "controller_activating_at_snapshot": controller_activating,
            "controller_populated_before_kill": controller_populated,
            "no_helper_events_before_kill": not pre_helper_events,
            "controller_phases": controller_phases,
            "killed_before_ready": killed_before_ready,
            "all_settled": settled,
            "helper_started_after_kill": helper_started,
            "final_states": {unit: states[unit].get("ActiveState")
                             for unit in units.values()},
            "cgroups_drained": cgroups,
            "all_cgroups_drained": all(cgroups.values()),
            "jobs_drained": not pending,
        })
        report["contained"] = bool(
            helpers_queued and controller_activating and controller_populated
            and not pre_helper_events and killed_before_ready and settled
            and not helper_started and all(cgroups.values()) and not pending)
    except Exception as failure:
        error = type(failure).__name__ + ": " + str(failure)
    except BaseException:
        _finish(report, attempted, directory, error="interrupted")
        raise
    return _finish(report, attempted, directory, error=error)


def run_audit_death_follow_stop():
    """Kill audit with all three active; commission follows, controller survives."""
    token = uuid.uuid4().hex
    units = fixture_units(token)
    directory = Path(tempfile.mkdtemp(prefix=_STAGE_PREFIX, dir=_stage_parent()))
    marker = directory / "controller-used"
    attempted = []
    error = None
    report = {"case": "audit_death_follow_stop", "token": token, "units": units}
    try:
        (directory / "probe.py").write_text(PROBE)
        for role in ("controller", "audit", "commission"):
            attempted.append(units[role])
            subprocess.run(command(role, units[role], directory, units=units, marker=marker),
                           check=True, timeout=10)
        active, all_active = _await(
            list(units.values()),
            lambda state: state.get("ActiveState") == "active", 40,
        )
        populated_before = {unit: cgroup_populated(unit) for unit in units.values()}
        # Kill audit (not the controller); commission BindsTo audit must follow.
        audit_pid = int(_show(units["audit"], ["MainPID"]).get("MainPID", "0"))
        if audit_pid <= 1:
            raise RuntimeError("audit fixture main PID unavailable")
        os.kill(audit_pid, signal.SIGKILL)
        helpers = [units["audit"], units["commission"]]
        helper_states, helpers_down = _await(
            helpers, lambda state: state.get("ActiveState") in ("inactive", "failed"), 30,
        )
        helpers_stopped = helpers_down and all(
            helper_states[unit].get("MainPID", "0") == "0" for unit in helpers)
        # A failed unit stays loaded until reset-failed, so audit's result is readable.
        audit_result = _show(units["audit"], ["Result"]).get("Result")
        helper_cgroups = _drain_cgroups(set(helpers))
        # Read the controller only after the helpers have fully drained.
        controller_state = _show(units["controller"], ["ActiveState", "SubState", "MainPID"])
        controller_survived = controller_state.get("ActiveState") == "active"
        controller_cgroup_populated = cgroup_populated(units["controller"])
        report.update({
            "all_active": all_active,
            "audit_pid": audit_pid,
            "audit_result": audit_result,
            "populated_before": populated_before,
            "all_populated_before": all(populated_before.values()),
            "helper_states": {unit: helper_states[unit].get("ActiveState") for unit in helpers},
            "helpers_stopped": helpers_stopped,
            "controller_state": controller_state.get("ActiveState"),
            "controller_survived": controller_survived,
            "helper_cgroups_drained": helper_cgroups,
            "all_helper_cgroups_drained": all(helper_cgroups.values()),
            "controller_cgroup_populated_after": controller_cgroup_populated,
        })
        report["contained"] = bool(
            all_active and all(populated_before.values()) and audit_result == "signal"
            and helpers_stopped and controller_survived
            and all(helper_cgroups.values()) and controller_cgroup_populated)
    except Exception as failure:
        error = type(failure).__name__ + ": " + str(failure)
    except BaseException:
        _finish(report, attempted, directory, error="interrupted")
        raise
    return _finish(report, attempted, directory, error=error)


def run_run_marker_mount_view():
    """Controller writes its /run once-marker under PrivateTmp; manager sees it."""
    token = uuid.uuid4().hex
    units = fixture_units(token)
    directory = Path(tempfile.mkdtemp(prefix=_STAGE_PREFIX, dir=_run_stage()))
    marker = directory / "controller-used"
    attempted = []
    error = None
    report = {"case": "run_marker_mount_view", "token": token,
              "staging_parent": str(directory.parent)}
    try:
        (directory / "probe.py").write_text(PROBE)
        attempted.append(units["controller"])
        subprocess.run(command("controller", units["controller"], directory,
                               units=units, marker=marker), check=True, timeout=10)
        active, controller_up = _await(
            [units["controller"]], lambda state: state.get("ActiveState") == "active", 40,
        )
        # Supporting evidence only: root's lookup of the shared /run view. The proof
        # that the manager saw the service-written marker is the refusal below.
        marker_on_host = marker.is_file()
        recheck_unit = PREFIX + uuid.uuid4().hex + "-recheck.service"
        attempted.append(recheck_unit)
        before = _read_events(directory)
        # Blocking (no --no-block): systemd-run returns only once the start job has
        # run, so the condition has been *evaluated*, not merely not-yet-dispatched.
        recheck_argv = [part for part in command("recheck", recheck_unit, directory,
                                                 units=units, marker=marker)
                        if part != "--no-block"]
        completed = subprocess.run(recheck_argv, capture_output=True, text=True, timeout=40)
        properties = _show(recheck_unit, ["LoadState", "ConditionResult", "ActiveState",
                                          "SubState", "ExecMainPID", "Result"])
        new_recheck = [event for event in _read_events(directory)
                       if event not in before and event[0] == "recheck"]
        # A condition-skipped transient unit may already be garbage-collected.
        condition_refused = (properties.get("ConditionResult") == "no"
                             or properties.get("LoadState") == "not-found")
        refused = bool(condition_refused and not new_recheck
                       and properties.get("ExecMainPID", "0") == "0"
                       and properties.get("ActiveState") in ("inactive", None))
        # The parent was validated as root-owned tmpfs /run by _run_stage (which
        # raises otherwise), so staging here is the per-boot mount-view guarantee.
        report.update({
            "controller_active": controller_up
            and active[units["controller"]].get("ActiveState") == "active",
            "marker_visible_on_host": marker_on_host,
            "recheck_returncode": completed.returncode,
            "rerun_properties": properties,
            "new_recheck_events": new_recheck,
            "rerun_refused": refused,
        })
        report["contained"] = bool(
            report["controller_active"] and marker_on_host and refused)
    except Exception as failure:
        error = type(failure).__name__ + ": " + str(failure)
    except BaseException:
        _finish(report, attempted, directory, error="interrupted")
        raise
    return _finish(report, attempted, directory, error=error)


CASES = (run_queued_start_containment, run_audit_death_follow_stop, run_run_marker_mount_view)


def run_all():
    if os.geteuid() != 0:
        raise PermissionError("operator root authentication required; no sudo attempted")
    cases = {}
    for case in CASES:
        name = case.__name__.removeprefix("run_")
        try:
            cases[name] = case()
        except Exception as failure:
            # A failure before a case's own try (e.g. staging) must not abort the rest.
            cases[name] = {"case": name, "passed": False,
                           "error": type(failure).__name__ + ": " + str(failure)}
    return {"scope": "systemd lifecycle containment fixtures only; "
                     "not product admission/deployment",
            "probe_sha256": sha256(PROBE.encode()).hexdigest(),
            "cases": cases,
            "passed": all(case["passed"] for case in cases.values())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({
            "execute": False,
            "probe_sha256": sha256(PROBE.encode()).hexdigest(),
            "cases": [case.__name__.removeprefix("run_") for case in CASES],
            "scope": "systemd lifecycle containment fixtures only; "
                     "not product admission/deployment"}))
        return 0
    report = run_all()
    print(json.dumps(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
