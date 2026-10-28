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
    assert "record = dict(redact(record), source=source)" in SOURCE


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
                                  "ftp:host", "plain"])
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
    assert argv[:3] == ["ssh", "-o", "BatchMode=yes"] and argv[3] == "rabbit@vm.example"
    # One remote shell word list, quoted, always through sudo -n (no password prompt).
    assert argv[4] == "cd / && sudo -n python3 -c 'print('\"'\"'a b'\"'\"')'"
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
    assert starts and all("--job-mode=ignore-requirements" in call or "unit, timeout" in call for call in starts)
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
