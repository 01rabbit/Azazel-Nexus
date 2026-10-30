"""The real-systemd integration runner's own honesty (A7).

`tools/vm_integration.py` runs only against a disposable node with systemd as
PID 1 (a privileged container or a VM); nothing here starts it. What can be
checked without a node is the part that could make its record lie or make it
widen anything: the confidentiality filter, the accounting of pass/fail/skip,
the transports' quoting, the fixture stimulus, and that the runner never
touches activation inputs, approvals or the admission switch.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from tools import vm_integration as vmit  # noqa: E402

SOURCE = (REPO / "tools" / "vm_integration.py").read_text(encoding="utf-8")


def test_the_record_filter_removes_inventory_facts():
    raw = {
        "detail": "edge decided for 10.0.3.8 inc-0123456789abcdef boot 730a31eb-d5de-45f5-b76a-88a9e1454463",
        "nested": [{"digest": "sha256:" + "a" * 64, "id": "b" * 32, "mac": "02:42:AC:11:00:02"}],
        "count": 3,
    }
    clean = json.dumps(vmit.redact(raw))
    for leaked in ("10.0.3.8", "0123456789abcdef", "730a31eb", "a" * 64, "b" * 32, "02:42:AC"):
        assert leaked not in clean
    assert vmit.redact(raw)["count"] == 3
    assert "inc-<redacted>" in clean and "<addr>" in clean and "<uuid>" in clean


def test_the_commit_stays_readable_while_details_are_filtered():
    # run() puts the source block back after filtering; a commit id is not an
    # inventory fact and the record must name what was installed.
    assert "record = dict(redact(record, words=target.host_words()), source=source)" in SOURCE


def _record(tmp_path, checks):
    record = {"schema": vmit.SCHEMA, "scope": "test", "source": {"commit": "c" * 40, "worktree": "clean"},
              "phases": [{"phase": "prepare", "facts": {"machine": "aarch64", "os": "Debian 13",
                                                         "kernel": "k", "systemd": "257", "virtualization": "none"},
                          "checks": checks}]}
    path = tmp_path / "run.json"
    path.write_text(json.dumps(record))
    return path


def test_summary_and_render_count_every_status_and_keep_rows_intact(tmp_path):
    checks = [{"id": "a.one", "status": "pass", "title": "t1", "detail": "x | y"},
              {"id": "a.two", "status": "fail", "title": "t2", "detail": "line\nbreak"},
              {"id": "a.three", "status": "skip", "title": "t3", "detail": ""}]
    path = _record(tmp_path, checks)
    assert vmit.summary(json.loads(path.read_text())) == {"pass": 1, "fail": 1, "skip": 1}
    text = vmit.render([str(path)])
    assert "pass 1 / fail 1 / skip 1" in text
    rows = [line for line in text.splitlines() if line.startswith("| `")]
    assert len(rows) == 3
    assert all(re.sub(r"\\\|", "", row).count("|") == 4 for row in rows)


def test_a_scenario_that_raises_is_a_recorded_failure_not_a_crash():
    checks = vmit.Checks("scenarios")

    def boom():
        raise RuntimeError("no socket")

    assert checks.guard("x", "a scenario", boom) is None
    item, = checks.result()["checks"]
    assert item["status"] == "fail" and item["id"] == "scenarios.x" and "no socket" in item["detail"]
    with pytest.raises(AssertionError):
        checks.add("y", "passed-ish", "not a status")


@pytest.mark.parametrize("spec", ["docker:", "docker:bad name", "docker:-x", "ssh:", "ssh:host;rm",
                                  "ssh:-oProxyCommand=x", "ssh:-x", "ftp:host", "plain"])
def test_targets_refuse_malformed_specs(spec):
    with pytest.raises(SystemExit):
        vmit.make_target(spec)


def test_docker_and_ssh_targets_build_the_documented_commands(monkeypatch):
    calls = []
    monkeypatch.setattr(vmit.subprocess, "run",
                        lambda argv, **kw: calls.append(argv) or subprocess.CompletedProcess(argv, 0, b"", b""))
    docker = vmit.make_target("docker:azn-vmit@colima")
    docker.run(["systemctl", "is-active", "x.service"])
    assert calls[-1] == ["docker", "--context", "colima", "exec", "-i", "azn-vmit",
                         "systemctl", "is-active", "x.service"]
    ssh = vmit.make_target("ssh:rabbit@vm.example")
    ssh.run(["python3", "-c", "print('a b')"])
    argv = calls[-1]
    # "--" ends ssh's options before the destination.
    assert argv[:5] == ["ssh", "-o", "BatchMode=yes", "--", "rabbit@vm.example"]
    # One remote shell word list, quoted, always through sudo -n (no password prompt).
    assert argv[5] == "cd / && sudo -n python3 -c 'print('\"'\"'a b'\"'\"')'"
    assert docker.kind() == "container" and ssh.kind() == "vm"


def test_the_stimulus_changes_only_the_source_address(monkeypatch):
    monkeypatch.setattr(vmit, "SRC", REPO)
    fixture = (REPO / "tests/fixtures/edge/rust_event_engine_v1.jsonl").read_bytes().splitlines()
    for k in (1, 7):
        lines = vmit.golden_lines(k)
        assert [line.replace(f"10.0.{k}.8".encode(), b"10.0.0.8") for line in lines] == [fixture[3], fixture[5]]
        events = vmit.eve_events(k)
        alerts = [e for e in events if e["event_type"] == "alert"]
        assert [e["src_ip"] for e in alerts] == [f"10.0.{k}.8"] * 2
        assert any(e["event_type"] == "flow" for e in events)
        assert alerts[0]["alert"]["metadata"]["mitre_technique_id"]


def test_the_runner_never_touches_activation_inputs_or_admission():
    # Hand-made markers are the rehearsal-only start (they vanish at reboot).
    # Nothing may write an approval, policy, lease, generation, enrollment or
    # bootstrap selection, flip the admission switch, or drive a real unit
    # start through the controller.
    for forbidden in ("/etc/azazel/activation", "activation_cli", "operator_enrollment",
                      "/etc/azazel/bootstrap", "bootstrap_cli", "LOCAL_MODEL_ADMISSION_ENABLED =",
                      "model_admission_cli", "mission-pack.json", "commission_cli"):
        assert forbidden not in SOURCE, forbidden
    starts = re.findall(r'systemctl\("start",[^)]*\)', SOURCE)
    controller = [call for call in starts if "azazel-activated" in call]
    assert starts and all("--job-mode=ignore-requirements" in call or "unit, timeout" in call
                          for call in starts if call not in controller)
    # The controller is started by hand only after a restart under Rosetta, where
    # the boot's own pass died before deciding; it then runs one ordinary pass.
    assert len(controller) == 1
    after = SOURCE[SOURCE.index("def node_after_restart"):]
    assert after.index('if options.get("rosetta")') < after.index(controller[0]) < after.index("journal = out(")
    assert re.findall(r'"/run/azazel-activation/granted"', SOURCE)


def test_lab_keys_live_on_tmpfs_and_are_labelled():
    assert vmit.NODE_LAB.startswith("/run/")
    assert vmit.LAB_LABEL.startswith("azn-vmit-lab")
    assert 'f"{name}.pem"' in SOURCE and "umask 077" in SOURCE
    # The cleanup overwrites before unlinking.
    cleanup = SOURCE[SOURCE.index("def node_cleanup"):]
    assert cleanup.index('b"\\0" * size') < cleanup.index("path.unlink()")


def test_every_node_phase_is_reachable_from_the_controller():
    assert set(vmit.NODE_PHASES) == {"prepare", "start", "scenarios", "after-restart", "cleanup"}
    for phase in ("prepare", "start", "scenarios", "after-restart", "cleanup"):
        assert f'"{phase}"' in SOURCE[SOURCE.index("def run(args"):SOURCE.index("def summary(")]


def test_a_vm_restart_waits_for_a_new_boot_id_and_survives_the_hang_up(monkeypatch):
    target = vmit.make_target("ssh:rabbit@vm.example")
    boots = iter([b"old\n", b"old\n", b"new\n"])
    states = iter([b"starting\n", b"running\n", b"running\n"])
    calls = []

    def run(argv, *, input=None, timeout=600):
        calls.append(argv)
        if argv == ["cat", "/proc/sys/kernel/random/boot_id"]:
            return subprocess.CompletedProcess(argv, 0, next(boots), b"")
        if argv == ["systemctl", "reboot"]:
            raise subprocess.TimeoutExpired(argv, timeout)
        return subprocess.CompletedProcess(argv, 0, next(states), b"")

    monkeypatch.setattr(target, "run", run)
    monkeypatch.setattr(vmit.time, "sleep", lambda seconds: None)
    assert target.restart() == "systemctl reboot (a new kernel boot)"
    # The same boot id after "running" is not a reboot: it waited for the new one.
    assert calls.count(["cat", "/proc/sys/kernel/random/boot_id"]) == 3


@pytest.mark.parametrize("leak", [
    "fe80::1ff:fe23:4567:890a", "2001:db8::8a2e:370:7334", "::ffff:10.0.0.1",
    "2001:0db8:0000:0000:0000:ff00:0042:8329", "02-42-AC-11-00-02", "02:42:ac:11:00:02", "0xDEADBEEF",
    "ABCDEF0123456789ABCDEF0123456789", "aa8f381b99a4", "10.0.3.8", "192.168.40.100",
])
def test_the_filter_covers_addresses_in_every_spelling(leak):
    assert leak.lower() not in vmit.redact(f"seen {leak} here").lower()


@pytest.mark.parametrize("kept", ["13:46:28", "2026-10-28T13:23:11Z", "version 1.2.3.4", "v6.0.3.1",
                                  "std::map", "granted=0, withheld=16", "T1110", "257.13-1"])
def test_the_filter_keeps_times_versions_and_words(kept):
    assert vmit.redact(f"x {kept} y") == f"x {kept} y"


def test_the_node_host_name_is_removed_by_name():
    assert vmit.redact({"d": "on azn-vm1 and AZN-VM1.lab"}, words=["azn-vm1"]) == {"d": "on <host> and <host>.lab"}


class _Node(vmit.Target):
    description = "fake"

    def __init__(self, failure):
        self.failure = failure

    def run(self, argv, *, input=None, timeout=600):
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    def put(self, local, remote):
        pass

    def restart(self):
        raise self.failure

    def kind(self):
        return "container"


@pytest.mark.parametrize("failure", [SystemExit("node did not come back"), subprocess.TimeoutExpired("x", 1),
                                     KeyboardInterrupt()])
def test_cleanup_runs_even_when_the_restart_fails(tmp_path, monkeypatch, failure):
    node = _Node(failure)
    phases = []
    monkeypatch.setattr(vmit, "make_target", lambda spec: node)
    monkeypatch.setattr(vmit, "source_archive",
                        lambda repo, scratch: (scratch / "a.tar", {"commit": "c" * 40, "worktree": "clean"}))
    monkeypatch.setattr(vmit, "node_phase", lambda target, phase, options, **kw: phases.append(phase) or {
        "phase": phase, "checks": [{"id": f"{phase}.ok", "status": "pass", "title": "", "detail": ""}]})
    out = tmp_path / "run.json"
    args = vmit.argparse.Namespace(target="docker:x", edge_package=None, rosetta=False, wheelhouse=None,
                                   out=str(out), scratch=str(tmp_path), disposable_node=True)
    if isinstance(failure, KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            vmit.run(args)
    else:
        assert vmit.run(args) == 1
    assert phases == ["prepare", "start", "scenarios", "cleanup"]
    record = json.loads(out.read_text())
    ids = [c["id"] for p in record["phases"] for c in p["checks"]]
    assert ids[-2:] == ["controller.interrupted", "cleanup.ok"]


def test_run_needs_the_operators_disposable_node_statement():
    with pytest.raises(SystemExit):
        vmit.main(["run", "--target", "docker:x"])
    assert 'options.get("disposable_node")' in SOURCE


def test_rosetta_is_checked_on_the_node_and_its_drop_in_is_runtime_only():
    assert str(vmit.ROSETTA_DROPIN).startswith("/run/systemd/system/service.d/")
    prepare = SOURCE[SOURCE.index("def node_prepare"):SOURCE.index("def knowledge_reason")]
    assert prepare.index("rosetta_detected()") < prepare.index("rosetta_adapt(checks)")
    assert prepare.index("Path(VENV)") < prepare.index("rosetta_adapt(checks)")


def test_capacity_copies_survive_the_next_runs_work_directory_reset():
    assert not str(vmit.CAPACITY_KEEP).startswith(vmit.NODE_WORK)
    prepare = SOURCE[SOURCE.index("def node_prepare"):SOURCE.index("def knowledge_reason")]
    assert "CAPACITY_KEEP" in prepare  # an interrupted run's copies make the next run refuse


# -- the Edge package of the node's CPU (S-11) -------------------------------


def test_the_edge_package_names_are_the_pinned_ones_per_cpu():
    from azazel_nexus.edge_package import PINS

    assert set(vmit.EDGE_PACKAGES) == set(PINS)
    for machine, (manifest, archive) in vmit.EDGE_PACKAGES.items():
        assert (manifest, archive) == (PINS[machine].manifest_name, PINS[machine].artifact_name)


def test_a_packager_directory_must_hold_exactly_one_cpus_package(tmp_path):
    for name in vmit.EDGE_PACKAGES["aarch64"]:
        (tmp_path / name).write_text("x")
    assert vmit.edge_package_names(tmp_path) == vmit.EDGE_PACKAGES["aarch64"]
    for name in vmit.EDGE_PACKAGES["x86_64"]:
        (tmp_path / name).write_text("x")
    with pytest.raises(SystemExit):
        vmit.edge_package_names(tmp_path)
    with pytest.raises(SystemExit):
        vmit.edge_package_names(tmp_path / "empty")


def test_the_node_refuses_a_binary_that_is_not_for_its_cpu():
    install = SOURCE[SOURCE.index("def edge_install"):SOURCE.index("# --- The rehearsal-only start")]
    assert "if arch != machine:" in install and "raise RuntimeError" in install
    assert "fixed x86_64 name" not in SOURCE
