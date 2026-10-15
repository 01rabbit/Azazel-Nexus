"""Operator-only systemd READY-order and bind-stop fixture; not a runtime gate.

This exercises the *mechanics* the product units declare -- Type=notify READY
sequencing (controller -> audit -> commission), After/Requires/BindsTo follow-stop
when the controller dies, empty helper cgroups, drained jobs, and the
``ConditionPathExists=!.../controller-used`` once-marker refusing a re-run -- using
uniquely named transient fixture units that run trivial probes. It fabricates no
enrollment, pins, approval, time, epoch or generation input and asserts nothing
about product admission or deployment.

Default is plan-only. ``--execute`` needs an interactive operator's root session.
No product unit, provider, network, persistence, media or firmware is operated.
The staging and fixture stop/cleanup are reused from the native timer tool.
"""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

# Allow `python /abs/path/tools/qualify_ready_order_sandbox.py` from any cwd, not
# only `-m tools...` from the repo root: put the repo root on the path first.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.qualify_bootstrap_deadline_sandbox import (  # noqa: E402
    _stage_parent,
    _stop_fixture,
)


PREFIX = "azazel-nexus-readyorder-"
ROLES = ("controller", "audit", "commission", "recheck")
UNIT_PATTERN = re.compile(
    r"azazel-nexus-readyorder-[0-9a-f]{32}-"
    r"(?:controller|audit|commission|recheck)\.service"
)
EVENT_PATTERN = re.compile(
    r"(controller|audit|commission|recheck) (preready|ready|start|recheck) ([0-9]+)"
)
# Transient fixtures live beneath system.slice like any systemd-run unit.
_CGROUP_BASE = "/sys/fs/cgroup/system.slice"
_GATE_SECONDS = 4.0
_WAIT_SECONDS = 120.0

# Security subset copied from the controller declaration, kept deliberately
# distinct from it: Type=notify fixtures with their own lifecycle/journal
# settings. These are not the product controller and never claim to be.
PROPERTIES = (
    "Type=notify", "NotifyAccess=main", "User=root", "Restart=no",
    "RuntimeMaxSec=180s", "TimeoutStartSec=30s", "TimeoutStopSec=5s",
    "KillMode=control-group", "SendSIGKILL=yes", "NoNewPrivileges=yes",
    "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
    "PrivateDevices=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
    "ProtectControlGroups=yes", "RestrictNamespaces=yes", "RestrictSUIDSGID=yes",
    "LockPersonality=yes", "MemoryDenyWriteExecute=yes",
    "SystemCallArchitectures=native", "SystemCallFilter=@system-service",
    "CapabilityBoundingSet=", "AmbientCapabilities=", "IPAddressDeny=any",
    "RestrictAddressFamilies=AF_UNIX AF_NETLINK", "UMask=0027",
    "SetLoginEnvironment=no", "StandardOutput=journal", "StandardError=journal",
    "SyslogIdentifier=azazel-nexus-readyorder-probe",
    "UnsetEnvironment=GCONV_PATH GLIBC_TUNABLES LD_ASSUME_KERNEL LD_AUDIT "
    "LD_BIND_NOT LD_BIND_NOW LD_DEBUG LD_DEBUG_OUTPUT LD_DYNAMIC_WEAK LD_HWCAP_MASK "
    "LD_LIBRARY_PATH LD_ORIGIN_PATH LD_POINTER_GUARD LD_PREFER_MAP_32BIT_EXEC "
    "LD_PRELOAD LD_PROFILE LD_PROFILE_OUTPUT LD_SHOW_AUXV LD_TRACE_LOADED_OBJECTS "
    "LD_TRACE_PRELINKING LD_USE_LOAD_BIAS LD_VERBOSE LD_WARN LOCPATH MALLOC_TRACE "
    "NLSPATH PYTHONEXECUTABLE PYTHONHOME PYTHONPATH TZDIR __PYVENV_LAUNCHER__",
)

PROBE = f'''import os, socket, sys, time
from pathlib import Path

role = sys.argv[1]
directory = Path(__file__).resolve().parent
events = directory / "events"
marker = directory / "controller-used"


def stamp(phase):
    line = ("%s %s %d\\n" % (role, phase, time.clock_gettime_ns(time.CLOCK_MONOTONIC)))
    fd = os.open(events, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, line.encode("ascii"))
    finally:
        os.close(fd)


def notify_ready():
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        raise SystemExit("fixture requires a systemd NOTIFY_SOCKET")
    target = "\\0" + address[1:] if address.startswith("@") else address
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        if sock.sendto(b"READY=1", target) != len(b"READY=1"):
            raise SystemExit("fixture notification incomplete")


if role == "controller":
    stamp("preready")
    time.sleep({_GATE_SECONDS})
    os.close(os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600))
    stamp("ready")
    notify_ready()
    time.sleep({_WAIT_SECONDS})
elif role in ("audit", "commission"):
    stamp("start")
    notify_ready()
    time.sleep({_WAIT_SECONDS})
elif role == "recheck":
    stamp("recheck")
    notify_ready()
    time.sleep({_WAIT_SECONDS})
else:
    raise SystemExit("unknown fixture role")
'''


def fixture_units(token):
    """Three sibling unit names sharing one 32-hex token for dependency wiring."""
    if re.fullmatch(r"[0-9a-f]{32}", token) is None:
        raise ValueError("fixture token must be 32 lowercase hex characters")
    return {role: PREFIX + token + "-" + role + ".service"
            for role in ("controller", "audit", "commission")}


def _dependencies(role, units):
    """audit follows the controller; commission follows both, in that order."""
    if role == "audit":
        order = (units["controller"],)
    elif role == "commission":
        order = (units["controller"], units["audit"])
    else:
        return []
    properties = []
    for dependency in order:
        properties += ["--property=After=" + dependency,
                       "--property=Requires=" + dependency,
                       "--property=BindsTo=" + dependency]
    return properties


def command(role, unit, directory, *, units, marker):
    """Build the systemd-run argv for one fixture role; never a product unit."""
    if role not in ROLES:
        raise ValueError("fixed fixture role required")
    if type(unit) is not str or UNIT_PATTERN.fullmatch(unit) is None:
        raise ValueError("unique readyorder fixture unit required")
    if not unit.endswith("-" + role + ".service"):
        raise ValueError("fixture unit name must match its role")
    condition = []
    if role in ("controller", "recheck"):
        # The product once-guard: refuse to start when the marker already exists.
        condition = ["--property=ConditionPathExists=!" + str(marker)]
    return ["/usr/bin/systemd-run", "--quiet", "--no-block",
            "--unit=" + unit,
            *["--property=" + value for value in PROPERTIES],
            "--property=ReadWritePaths=" + str(directory),
            *condition,
            *_dependencies(role, units),
            "/usr/bin/python3.13", "-IS", str(directory / "probe.py"), role]


def parse_events(text):
    """Parse the shared append-only timeline; reject any malformed line."""
    events = []
    for line in text.splitlines():
        if not line:
            continue
        match = EVENT_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError("malformed fixture event line: " + repr(line))
        events.append((match.group(1), match.group(2), int(match.group(3))))
    return events


def ready_order_satisfied(events):
    """controller preready < ready, then audit start, then commission start."""
    phase = {}
    for role, name, moment in events:
        if (role, name) in phase:
            return False
        phase[(role, name)] = moment
    required = (("controller", "preready"), ("controller", "ready"),
                ("audit", "start"), ("commission", "start"))
    if any(key not in phase for key in required):
        return False
    preready = phase[("controller", "preready")]
    ready = phase[("controller", "ready")]
    audit = phase[("audit", "start")]
    commission = phase[("commission", "start")]
    return preready < ready < audit < commission


def pending_jobs(text, units):
    """Rows of `systemctl list-jobs --no-legend` naming one of our fixture units."""
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[1] in units:
            rows.append((fields[1], fields[2], fields[3]))
    return rows


def _populated_value(unit, base):
    """None when the cgroup is absent, else the cgroup.events `populated` field."""
    path = os.path.join(base, unit)
    try:
        directory_fd = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except FileNotFoundError:
        return None
    try:
        fd = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=directory_fd)
        try:
            raw = os.read(fd, 4096)
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)
    values = {}
    for line in raw.decode("ascii").splitlines():
        key, separator, value = line.partition(" ")
        if separator:
            values[key] = value
    return values.get("populated")


def cgroup_populated(unit, base=_CGROUP_BASE):
    """A present cgroup reporting populated 1: a live baseline before the kill.

    Absence is not credited here: emptiness only counts as *drain* once the unit
    has first been observed populated, so a wrong slice/name cannot pass silently.
    """
    return _populated_value(unit, base) == "1"


def cgroup_drained(unit, base=_CGROUP_BASE):
    """A removed cgroup, or one whose cgroup.events reports populated 0."""
    return _populated_value(unit, base) in (None, "0")


def rerun_refused(properties, new_recheck_events):
    """Condition evaluated false, nothing ran, and no recheck marker appeared."""
    return (properties.get("ConditionResult") == "no"
            and properties.get("ActiveState") == "inactive"
            and properties.get("ExecMainPID", "0") == "0"
            and not new_recheck_events)


def _show(unit, properties):
    output = subprocess.run(
        ["/usr/bin/systemctl", "show", unit, "--property=" + ",".join(properties)],
        check=True, capture_output=True, text=True, timeout=5,
    ).stdout
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def _list_jobs(units):
    output = subprocess.run(
        ["/usr/bin/systemctl", "list-jobs", "--no-pager", "--no-legend"],
        check=True, capture_output=True, text=True, timeout=5,
    ).stdout
    return pending_jobs(output, units)


def _read_events(directory):
    path = directory / "events"
    try:
        return parse_events(path.read_text())
    except FileNotFoundError:
        return []


def _confirm_or_stop(unit):
    """Confirm a fixture unit is stopped, stopping it only if still loaded.

    A transient unit that followed-stopped (BindsTo) or was Condition-skipped is
    garbage-collected by systemd once inactive, so by cleanup time it is usually
    already gone -- the terminal stopped state, not a leak. _stop_fixture's first
    `systemctl stop` errors on such a unit, so skip it when the unit is already
    not-found, and tolerate a race into garbage collection after the check.
    """
    if _show(unit, ["LoadState"]).get("LoadState") == "not-found":
        return
    try:
        _stop_fixture(unit)
    except subprocess.CalledProcessError:
        if _show(unit, ["LoadState"]).get("LoadState") != "not-found":
            raise


def _await(units, accept, deadline_seconds,
           properties=("ActiveState", "SubState", "MainPID")):
    deadline = time.monotonic() + deadline_seconds
    states = {}
    while True:
        states = {unit: _show(unit, list(properties)) for unit in units}
        if all(accept(state) for state in states.values()):
            return states, True
        if time.monotonic() >= deadline:
            return states, False
        time.sleep(0.1)


def run():
    if os.geteuid() != 0:
        raise PermissionError("operator root authentication required; no sudo attempted")
    token = uuid.uuid4().hex
    units = fixture_units(token)
    directory = Path(tempfile.mkdtemp(
        prefix="azazel-nexus-readyorder-", dir=_stage_parent(),
    ))
    marker = directory / "controller-used"
    attempted, stopped = [], []
    error = None
    removed = False
    ready_order = controller_death = rerun = None
    try:
        (directory / "probe.py").write_text(PROBE)
        # Enqueue all three before the controller reaches READY, so systemd must
        # hold the helpers behind the ordering/requirement edges, not us.
        for role in ("controller", "audit", "commission"):
            unit = units[role]
            attempted.append(unit)
            subprocess.run(command(role, unit, directory, units=units, marker=marker),
                           check=True, timeout=10)
        # Snapshot while the controller is still in its pre-READY gate: systemd
        # must be holding the helpers behind the ordering/requirement edges.
        held_jobs = _list_jobs(set(units.values()))
        held_events = _read_events(directory)
        held_helper_events = [event for event in held_events
                              if event[0] in ("audit", "commission")]
        active, all_active = _await(
            list(units.values()),
            lambda state: state.get("ActiveState") == "active", 40,
        )
        ordered_events = _read_events(directory)
        # Baseline: every unit is actually running inside its own cgroup now, so a
        # later absence/emptiness is credited as drain, not an unobserved path.
        populated_before = {unit: cgroup_populated(unit) for unit in units.values()}
        ready_order = {
            "held_jobs": held_jobs,
            "held_helper_events": held_helper_events,
            "helpers_held_before_ready": not held_helper_events,
            "events": ordered_events,
            "all_active": all_active,
            "ordered": ready_order_satisfied(ordered_events),
            "active_states": {unit: active[unit].get("ActiveState")
                              for unit in units.values()},
            "cgroups_populated_before": populated_before,
            "all_populated_before": all(populated_before.values()),
        }

        # Controller death: kill only its main process and let BindsTo cascade.
        main_pid = int(_show(units["controller"], ["MainPID"]).get("MainPID", "0"))
        if main_pid <= 1:
            raise RuntimeError("controller fixture main PID unavailable")
        os.kill(main_pid, signal.SIGKILL)
        helper_units = [units["audit"], units["commission"]]
        helper_states, helpers_inactive = _await(
            helper_units,
            lambda state: state.get("ActiveState") in ("inactive", "failed"), 30,
        )
        # Confirm stop/containment BEFORE any runner cleanup touches the units.
        helpers_stopped = helpers_inactive and all(
            helper_states[unit].get("MainPID", "0") == "0" for unit in helper_units)
        # cgroup teardown can lag the ActiveState transition; retry bounded.
        drain_deadline = time.monotonic() + 15
        while True:
            cgroups = {unit: cgroup_drained(unit) for unit in units.values()}
            if all(cgroups.values()) or time.monotonic() >= drain_deadline:
                break
            time.sleep(0.2)
        drained_jobs = _list_jobs(set(units.values()))
        controller_death = {
            "controller_main_pid": main_pid,
            "helper_states": {unit: helper_states[unit].get("ActiveState")
                              for unit in helper_units},
            "helpers_stopped": helpers_stopped,
            "cgroups_drained": cgroups,
            "all_cgroups_drained": all(cgroups.values()),
            "pending_jobs": drained_jobs,
            "jobs_drained": not drained_jobs,
        }

        # Re-run refusal: a fresh controller against the consumed once-marker.
        recheck_unit = PREFIX + uuid.uuid4().hex + "-recheck.service"
        attempted.append(recheck_unit)
        before_recheck = _read_events(directory)
        subprocess.run(command("recheck", recheck_unit, directory,
                               units=units, marker=marker), check=True, timeout=10)
        # Wait for the condition to be *evaluated* false, not merely for inactivity:
        # a freshly enqueued unit reports inactive before systemd resolves it.
        _await([recheck_unit],
               lambda state: state.get("ConditionResult") == "no", 10,
               properties=("ConditionResult", "ActiveState", "SubState", "ExecMainPID"))
        properties = _show(recheck_unit,
                           ["ConditionResult", "ActiveState", "SubState",
                            "ExecMainPID", "Result"])
        after_recheck = _read_events(directory)
        new_recheck = [event for event in after_recheck
                       if event not in before_recheck and event[0] == "recheck"]
        rerun = {
            "properties": properties,
            "new_recheck_events": new_recheck,
            "refused": rerun_refused(properties, new_recheck),
        }
    except Exception as failure:
        error = type(failure).__name__ + ": " + str(failure)
    finally:
        for unit in attempted:
            try:
                _confirm_or_stop(unit)
                stopped.append(unit)
            except Exception as failure:
                stop_error = type(failure).__name__ + ": " + str(failure)
                error = stop_error if error is None else error + "; " + stop_error
        if attempted == stopped:
            try:
                shutil.rmtree(directory)
                removed = True
            except Exception as failure:
                cleanup_error = type(failure).__name__ + ": " + str(failure)
                error = cleanup_error if error is None else error + "; " + cleanup_error

    passed = bool(
        error is None
        and ready_order and ready_order["ordered"] and ready_order["all_active"]
        and ready_order["helpers_held_before_ready"]
        and ready_order["all_populated_before"]
        and controller_death and controller_death["helpers_stopped"]
        and controller_death["all_cgroups_drained"]
        and controller_death["jobs_drained"]
        and rerun and rerun["refused"]
    )
    return {"scope": "systemd ready-order & bind-stop fixture only; "
                     "not product READY/admission/deployment",
            "token": token, "units": units,
            "ready_order": ready_order, "controller_death": controller_death,
            "rerun_refusal": rerun, "staging_parent": str(directory.parent),
            "probe_sha256": sha256(PROBE.encode()).hexdigest(),
            "properties": list(PROPERTIES), "error": error,
            "cleanup_confirmed": attempted == stopped and removed,
            "unconfirmed_units": [unit for unit in attempted if unit not in stopped],
            "retained_directory": None if removed else str(directory),
            "passed": passed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({
            "execute": False,
            "probe_sha256": sha256(PROBE.encode()).hexdigest(),
            "staging_parent": "/var/lib", "properties": list(PROPERTIES),
            "scope": "systemd ready-order & bind-stop fixture only; "
                     "not product READY/admission/deployment"}))
        return 0
    report = run()
    print(json.dumps(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
