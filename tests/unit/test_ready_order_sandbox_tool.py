"""Contract tests for the operator-only READY-order / bind-stop fixture tool.

These exercise planning, argv construction and the pure verification logic, plus
a fully monkeypatched run() control-flow walk. They never invoke systemd and
start no real process.
"""

import json
import os
import socket
import subprocess
import sys
from hashlib import sha256
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime.hardening import PROFILES, render_unit
from azazel_nexus_runtime.launch_environment import BOOTSTRAP_UNSET_ENVIRONMENT

from tools import qualify_ready_order_sandbox as sandbox

TOKEN = "0123456789abcdef0123456789abcdef"


def test_default_plan_never_runs_subprocess_or_touches_systemd(monkeypatch, capsys, private_os):
    private_os(sandbox)
    def forbidden(*args, **kwargs):
        pytest.fail("plan-only mode performed external work")

    monkeypatch.setattr(sandbox.subprocess, "run", forbidden)
    monkeypatch.setattr(sandbox.os, "kill", forbidden)
    monkeypatch.setattr("sys.argv", ["qualify"])

    assert sandbox.main() == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["execute"] is False
    assert plan["probe_sha256"] == sha256(sandbox.PROBE.encode()).hexdigest()
    assert plan["properties"] == list(sandbox.PROPERTIES)
    assert "not product READY" in plan["scope"]


def test_nonroot_run_refuses_before_staging(monkeypatch, private_os):
    private_os(sandbox)
    calls = []
    monkeypatch.setattr(sandbox.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(sandbox, "_stage_parent", lambda: calls.append("stage"))
    monkeypatch.setattr(sandbox.tempfile, "mkdtemp", lambda **kwargs: calls.append("mkdtemp"))

    with pytest.raises(PermissionError, match="operator root"):
        sandbox.run()
    assert calls == []


def test_fixture_units_require_hex_token():
    units = sandbox.fixture_units(TOKEN)
    assert units == {
        "controller": f"azazel-nexus-readyorder-{TOKEN}-controller.service",
        "audit": f"azazel-nexus-readyorder-{TOKEN}-audit.service",
        "commission": f"azazel-nexus-readyorder-{TOKEN}-commission.service",
    }
    with pytest.raises(ValueError, match="32 lowercase hex"):
        sandbox.fixture_units("not-hex")


def test_command_refuses_product_unit_and_bad_role(tmp_path):
    units = sandbox.fixture_units(TOKEN)
    marker = tmp_path / "controller-used"
    with pytest.raises(ValueError, match="fixed fixture role"):
        sandbox.command("activate", units["controller"], tmp_path, units=units, marker=marker)
    with pytest.raises(ValueError, match="unique readyorder fixture unit"):
        sandbox.command("controller", "azazel-activated.service", tmp_path,
                        units=units, marker=marker)
    with pytest.raises(ValueError, match="match its role"):
        sandbox.command("audit", units["controller"], tmp_path, units=units, marker=marker)


def test_command_wires_notify_ordering_and_once_condition(tmp_path):
    units = sandbox.fixture_units(TOKEN)
    marker = tmp_path / "controller-used"

    controller = sandbox.command("controller", units["controller"], tmp_path,
                                 units=units, marker=marker)
    assert controller[0] == "/usr/bin/systemd-run"
    assert "--no-block" in controller
    assert "--property=Type=notify" in controller
    assert "--property=ConditionPathExists=!" + str(marker) in controller
    assert controller[-4:] == ["/usr/bin/python3.13", "-IS",
                               str(tmp_path / "probe.py"), "controller"]
    # The controller/recheck guard declares no sibling ordering edges.
    assert not any(part.startswith("--property=After=") for part in controller)

    audit = sandbox.command("audit", units["audit"], tmp_path, units=units, marker=marker)
    assert "--property=After=" + units["controller"] in audit
    assert "--property=Requires=" + units["controller"] in audit
    assert "--property=BindsTo=" + units["controller"] in audit
    assert audit[-1] == "audit"
    assert not any(units["audit"] in part for part in audit
                   if part.startswith("--property=After="))

    commission = sandbox.command("commission", units["commission"], tmp_path,
                                 units=units, marker=marker)
    for dependency in (units["controller"], units["audit"]):
        assert "--property=After=" + dependency in commission
        assert "--property=BindsTo=" + dependency in commission
    # controller is ordered before audit in the commission edge list.
    after = [part.removeprefix("--property=After=") for part in commission
             if part.startswith("--property=After=")]
    assert after == [units["controller"], units["audit"]]


def test_properties_are_notify_fixtures_sharing_controller_security_subset():
    controller_profile = next(profile for profile in PROFILES
                              if profile.unit == "azazel-activated.service")
    section = render_unit(controller_profile).split("[Service]\n", 1)[1].split("\n[", 1)[0]
    declared = {}
    for line in section.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            declared[key] = value
    values = dict(item.split("=", 1) for item in sandbox.PROPERTIES)

    fixture_only = {
        "Type", "RuntimeMaxSec", "TimeoutStartSec", "TimeoutStopSec",
        "StandardOutput", "StandardError", "SyslogIdentifier", "UnsetEnvironment",
        "NotifyAccess",
    }
    shared = values.keys() - fixture_only
    assert shared
    assert all(declared[key] == values[key] for key in shared)
    assert values["Type"] == "notify"
    unset = values["UnsetEnvironment"].split()
    assert set(unset) == set(BOOTSTRAP_UNSET_ENVIRONMENT)
    assert len(unset) == len(set(unset))


@pytest.mark.real_process
def test_probe_resolves_its_directory_and_stamps_the_argv_role(tmp_path):
    # Runs the real PROBE text: it must take the role from argv, resolve its own
    # directory from __file__ (NOT a directory argv the tool never passes), stamp
    # the event, and send READY=1. This is the command()<->PROBE arg contract the
    # monkeypatched run() tests cannot exercise.
    probe = tmp_path / "probe.py"
    probe.write_text(sandbox.PROBE)
    # A short socket path: AF_UNIX paths are capped (~104 bytes) and the pytest
    # tmp_path is often too long to bind under.
    socket_path = f"/tmp/azn-notify-{os.getpid()}.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(socket_path)
    server.settimeout(10)
    environment = {"NOTIFY_SOCKET": socket_path, "PATH": os.environ.get("PATH", "")}
    process = subprocess.Popen([sys.executable, "-IS", str(probe), "audit"],
                               env=environment)
    try:
        payload, _ = server.recvfrom(64)
        assert payload == b"READY=1"
        # The stamp precedes the notification, so the event is already written.
        parsed = sandbox.parse_events((tmp_path / "events").read_text())
        assert parsed == [("audit", "start", parsed[0][2])]
    finally:
        process.terminate()
        process.wait(timeout=5)
        server.close()
        if os.path.exists(socket_path):
            os.unlink(socket_path)


def test_parse_events_rejects_malformed_lines():
    text = "controller preready 10\ncontroller ready 20\naudit start 30\n"
    assert sandbox.parse_events(text) == [
        ("controller", "preready", 10), ("controller", "ready", 20),
        ("audit", "start", 30),
    ]
    with pytest.raises(ValueError, match="malformed"):
        sandbox.parse_events("controller exploded 5\n")


@pytest.mark.parametrize(
    ("events", "expected"),
    [
        ([("controller", "preready", 1), ("controller", "ready", 2),
          ("audit", "start", 3), ("commission", "start", 4)], True),
        # audit before controller ready: a helper ran too early.
        ([("controller", "preready", 1), ("audit", "start", 2),
          ("controller", "ready", 3), ("commission", "start", 4)], False),
        # commission before audit: wrong helper order.
        ([("controller", "preready", 1), ("controller", "ready", 2),
          ("commission", "start", 3), ("audit", "start", 4)], False),
        # missing commission entirely.
        ([("controller", "preready", 1), ("controller", "ready", 2),
          ("audit", "start", 3)], False),
        # duplicate phase.
        ([("controller", "preready", 1), ("controller", "ready", 2),
          ("controller", "ready", 3), ("audit", "start", 4),
          ("commission", "start", 5)], False),
    ],
)
def test_ready_order_requires_controller_ready_then_helpers(events, expected):
    assert sandbox.ready_order_satisfied(events) is expected


def test_pending_jobs_selects_only_our_units():
    units = set(sandbox.fixture_units(TOKEN).values())
    text = (
        f"1 azazel-nexus-readyorder-{TOKEN}-audit.service start waiting\n"
        f"2 azazel-nexus-readyorder-{TOKEN}-commission.service start waiting\n"
        "3 unrelated.service start running\n"
    )
    rows = sandbox.pending_jobs(text, units)
    assert rows == [
        (f"azazel-nexus-readyorder-{TOKEN}-audit.service", "start", "waiting"),
        (f"azazel-nexus-readyorder-{TOKEN}-commission.service", "start", "waiting"),
    ]


def test_cgroup_drained_accepts_absent_or_unpopulated(tmp_path):
    assert sandbox.cgroup_drained("missing.service", base=str(tmp_path)) is True

    empty = tmp_path / "empty.service"
    empty.mkdir()
    (empty / "cgroup.events").write_text("populated 0\nfrozen 0\n")
    assert sandbox.cgroup_drained("empty.service", base=str(tmp_path)) is True

    busy = tmp_path / "busy.service"
    busy.mkdir()
    (busy / "cgroup.events").write_text("populated 1\nfrozen 0\n")
    assert sandbox.cgroup_drained("busy.service", base=str(tmp_path)) is False


def test_cgroup_populated_requires_present_and_populated_one(tmp_path):
    # Absence is NOT a live baseline: a wrong slice/name must not pass as "ran".
    assert sandbox.cgroup_populated("missing.service", base=str(tmp_path)) is False

    empty = tmp_path / "empty.service"
    empty.mkdir()
    (empty / "cgroup.events").write_text("populated 0\nfrozen 0\n")
    assert sandbox.cgroup_populated("empty.service", base=str(tmp_path)) is False

    busy = tmp_path / "busy.service"
    busy.mkdir()
    (busy / "cgroup.events").write_text("populated 1\nfrozen 0\n")
    assert sandbox.cgroup_populated("busy.service", base=str(tmp_path)) is True


def test_rerun_refused_requires_condition_no_and_no_new_run():
    refused = {"ConditionResult": "no", "ActiveState": "inactive", "ExecMainPID": "0"}
    assert sandbox.rerun_refused(refused, []) is True
    # The guard did not fire.
    assert sandbox.rerun_refused({"ConditionResult": "yes", "ActiveState": "inactive",
                                  "ExecMainPID": "0"}, []) is False
    # It refused, but a recheck event somehow appeared.
    assert sandbox.rerun_refused(refused, [("recheck", "recheck", 9)]) is False


def test_confirm_or_stop_treats_already_gone_unit_as_stopped(monkeypatch):
    stopped = []
    monkeypatch.setattr(sandbox, "_stop_fixture", lambda unit: stopped.append(unit))
    monkeypatch.setattr(sandbox, "_show", lambda unit, properties: {"LoadState": "not-found"})
    # A follow-stopped or condition-skipped transient unit is garbage-collected:
    # that is the terminal stopped state, so no stop is attempted.
    sandbox._confirm_or_stop("azazel-nexus-readyorder-" + TOKEN + "-audit.service")
    assert stopped == []


def test_confirm_or_stop_stops_a_still_loaded_unit(monkeypatch):
    stopped = []
    monkeypatch.setattr(sandbox, "_stop_fixture", lambda unit: stopped.append(unit))
    monkeypatch.setattr(sandbox, "_show", lambda unit, properties: {"LoadState": "loaded"})
    unit = "azazel-nexus-readyorder-" + TOKEN + "-controller.service"
    sandbox._confirm_or_stop(unit)
    assert stopped == [unit]


def test_confirm_or_stop_tolerates_race_into_garbage_collection(monkeypatch):
    seen = {"count": 0}

    def show(unit, properties):
        seen["count"] += 1
        return {"LoadState": "loaded"} if seen["count"] == 1 else {"LoadState": "not-found"}

    def raced(unit):
        raise sandbox.subprocess.CalledProcessError(5, ["systemctl", "stop", unit])

    monkeypatch.setattr(sandbox, "_show", show)
    monkeypatch.setattr(sandbox, "_stop_fixture", raced)
    # Loaded at the check, gone by the stop: re-confirmed not-found, so no raise.
    sandbox._confirm_or_stop("azazel-nexus-readyorder-" + TOKEN + "-commission.service")


def test_confirm_or_stop_reraises_a_genuine_stop_failure(monkeypatch):
    def raced(unit):
        raise sandbox.subprocess.CalledProcessError(5, ["systemctl", "stop", unit])

    monkeypatch.setattr(sandbox, "_show", lambda unit, properties: {"LoadState": "loaded"})
    monkeypatch.setattr(sandbox, "_stop_fixture", raced)
    # Still loaded after the failed stop: a real failure, surfaced.
    with pytest.raises(sandbox.subprocess.CalledProcessError):
        sandbox._confirm_or_stop("azazel-nexus-readyorder-" + TOKEN + "-controller.service")


class _FakeSystemd:
    """A minimal synchronous stand-in for the relevant systemctl/systemd-run.

    It models the real hold: the controller stamps preready at enqueue but the
    helpers stamp nothing until the first active poll (``_ready_once``), so the
    pre-READY snapshot sees no helper events and list-jobs shows them waiting.
    """

    def __init__(self, directory, units):
        self.directory = directory
        self.units = units
        self.events = directory / "events"
        self.counter = 0
        self.killed = False
        self.readied = False
        self.launched = []

    def _append(self, line):
        self.counter += 1
        with open(self.events, "a") as stream:
            stream.write(f"{line} {self.counter}\n")

    def _ready_once(self):
        if not self.readied:
            self.readied = True
            self._append("controller ready")
            self._append("audit start")
            self._append("commission start")

    def run(self, argv, **kwargs):
        if argv[0] == "/usr/bin/systemd-run":
            role = argv[-1]
            self.launched.append(role)
            if role == "controller":
                self._append("controller preready")
            # audit/commission are held behind the controller; recheck is refused.
            return SimpleNamespace(stdout="", returncode=0)
        if argv[0] == "/usr/bin/systemctl" and argv[1] == "show":
            unit = argv[2]
            properties = next(part.removeprefix("--property=") for part in argv
                              if part.startswith("--property="))
            return SimpleNamespace(stdout=self._show(unit, properties))
        if argv[0] == "/usr/bin/systemctl" and argv[1] == "list-jobs":
            if self.readied:
                return SimpleNamespace(stdout="")
            waiting = "".join(
                f"{index} {self.units[role]} start waiting\n"
                for index, role in enumerate(("audit", "commission"), start=1))
            return SimpleNamespace(stdout=waiting)
        pytest.fail(f"unexpected subprocess command: {argv!r}")

    def _show(self, unit, properties):
        if properties == "MainPID":
            return "MainPID=4321\n"
        if "recheck" in unit:
            return ("ConditionResult=no\nActiveState=inactive\nSubState=dead\n"
                    "ExecMainPID=0\nResult=success\n")
        helpers = (self.units["audit"], self.units["commission"])
        if self.killed and unit in helpers:
            return "ActiveState=inactive\nSubState=dead\nMainPID=0\n"
        self._ready_once()
        return "ActiveState=active\nSubState=running\nMainPID=4321\n"


def _happy_run(tmp_path, monkeypatch):
    directory = tmp_path / "readyorder-fixture"
    directory.mkdir()
    monkeypatch.setattr(sandbox.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sandbox, "_stage_parent", lambda: str(tmp_path))
    monkeypatch.setattr(sandbox.tempfile, "mkdtemp",
                        lambda *, prefix, dir: str(directory))
    monkeypatch.setattr(sandbox.uuid, "uuid4",
                        lambda: SimpleNamespace(hex=TOKEN))
    monkeypatch.setattr(sandbox, "cgroup_populated", lambda unit: True)
    monkeypatch.setattr(sandbox, "cgroup_drained", lambda unit: True)

    order = []
    monkeypatch.setattr(sandbox, "_stop_fixture",
                        lambda unit: order.append(("stop", unit)))

    real_rmtree = sandbox.shutil.rmtree

    def tracked_rmtree(path):
        order.append(("rmtree", str(path)))
        real_rmtree(path)

    monkeypatch.setattr(sandbox.shutil, "rmtree", tracked_rmtree)

    fake = _FakeSystemd(directory, sandbox.fixture_units(TOKEN))

    def kill(pid, signal_number):
        assert pid == 4321
        fake.killed = True

    monkeypatch.setattr(sandbox.os, "kill", kill)
    monkeypatch.setattr(sandbox.subprocess, "run", fake.run)
    return directory, order, fake


def test_run_walks_order_death_and_rerun_then_cleans_up(tmp_path, monkeypatch, private_os):
    private_os(sandbox)
    directory, order, fake = _happy_run(tmp_path, monkeypatch)
    report = sandbox.run()

    assert report["error"] is None
    assert report["passed"] is True
    assert report["cleanup_confirmed"] is True
    assert report["retained_directory"] is None
    assert report["ready_order"]["ordered"] is True
    assert report["ready_order"]["all_active"] is True
    # Helpers were genuinely held behind the controller before it readied.
    assert report["ready_order"]["helpers_held_before_ready"] is True
    assert report["ready_order"]["held_helper_events"] == []
    assert len(report["ready_order"]["held_jobs"]) == 2
    assert all(row[2] == "waiting" for row in report["ready_order"]["held_jobs"])
    assert report["ready_order"]["all_populated_before"] is True
    assert report["controller_death"]["helpers_stopped"] is True
    assert report["controller_death"]["all_cgroups_drained"] is True
    assert report["controller_death"]["jobs_drained"] is True
    assert report["rerun_refusal"]["refused"] is True
    assert fake.launched == ["controller", "audit", "commission", "recheck"]

    # Every unit is stopped/confirmed BEFORE the staging directory is removed.
    stops = [index for index, item in enumerate(order) if item[0] == "stop"]
    rmtrees = [index for index, item in enumerate(order) if item[0] == "rmtree"]
    assert len(stops) == 4 and len(rmtrees) == 1
    assert max(stops) < rmtrees[0]
    assert not directory.exists()


def test_run_fails_when_a_helper_runs_before_controller_ready(tmp_path, monkeypatch, private_os):
    private_os(sandbox)
    directory, order, _ = _happy_run(tmp_path, monkeypatch)

    class EarlyHelper(_FakeSystemd):
        # A dropped ordering edge: audit starts during the controller's gate.
        def run(self, argv, **kwargs):
            if argv[0] == "/usr/bin/systemd-run" and argv[-1] == "audit":
                self.launched.append("audit")
                self._append("audit start")
                return SimpleNamespace(stdout="", returncode=0)
            return super().run(argv, **kwargs)

    broken = EarlyHelper(directory, sandbox.fixture_units(TOKEN))
    monkeypatch.setattr(sandbox.subprocess, "run", broken.run)
    monkeypatch.setattr(sandbox.os, "kill",
                        lambda pid, sig: setattr(broken, "killed", True))
    report = sandbox.run()

    assert report["passed"] is False
    assert report["ready_order"]["helpers_held_before_ready"] is False
    assert report["ready_order"]["held_helper_events"]
    assert report["ready_order"]["ordered"] is False


def test_run_retains_directory_when_a_stop_is_unconfirmed(tmp_path, monkeypatch, private_os):
    private_os(sandbox)
    directory, order, fake = _happy_run(tmp_path, monkeypatch)

    def flaky_stop(unit):
        order.append(("stop", unit))
        if unit.endswith("-commission.service"):
            raise RuntimeError("fixture stop unconfirmed: " + unit)

    monkeypatch.setattr(sandbox, "_stop_fixture", flaky_stop)
    report = sandbox.run()

    assert report["cleanup_confirmed"] is False
    assert report["retained_directory"] == str(directory)
    assert any(unit.endswith("-commission.service")
               for unit in report["unconfirmed_units"])
    assert "fixture stop unconfirmed" in report["error"]
    assert directory.exists()
    assert not any(item[0] == "rmtree" for item in order)
