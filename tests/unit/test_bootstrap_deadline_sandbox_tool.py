"""Contract tests for the operator-only native timer qualification tool.

These tests exercise planning and validation only; they never invoke systemd.
"""

import json
import stat
from hashlib import sha256
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import hardening
from azazel_nexus_runtime.launch_environment import BOOTSTRAP_UNSET_ENVIRONMENT

from tools import qualify_bootstrap_deadline_sandbox as sandbox


def _properties(**overrides):
    result = {
        "Result": "signal",
        "ExecMainCode": "2",
        "ExecMainStatus": "9",
    }
    result.update(overrides)
    return result


def test_default_plan_never_reads_native_or_runs_subprocess(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("plan-only mode performed external work")

    monkeypatch.setattr(sandbox, "checked_native", forbidden)
    monkeypatch.setattr(sandbox.subprocess, "run", forbidden)
    monkeypatch.setattr("sys.argv", ["qualify", "--native", "/not/read"])

    assert sandbox.main() == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["execute"] is False
    assert plan["native_sha256"] == sandbox.NATIVE_SHA256
    assert plan["properties"] == list(sandbox.PROPERTIES)
    assert "not READY" in plan["scope"]


def test_nonroot_run_refuses_before_read_or_create(monkeypatch):
    calls = []
    monkeypatch.setattr(sandbox.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(sandbox, "checked_native", lambda path: calls.append("read"))
    monkeypatch.setattr(sandbox.tempfile, "mkdtemp", lambda **kwargs: calls.append("create"))

    with pytest.raises(PermissionError, match="operator root"):
        sandbox.run("/not/read")
    assert calls == []


def test_command_uses_only_fixed_mode_and_fixture_unit(tmp_path):
    with pytest.raises(ValueError, match="fixed fixture mode"):
        sandbox.command("azazel-activated.service", tmp_path, "arbitrary")
    with pytest.raises(ValueError, match="unique qualification fixture"):
        sandbox.command("azazel-activated.service", tmp_path, "release")

    unit = "azazel-nexus-qualification-0123456789abcdef0123456789abcdef.service"
    argv = sandbox.command(unit, tmp_path, "release")
    assert argv[0] == "/usr/bin/systemd-run"
    assert "--unit=" + unit in argv
    assert "/usr/bin/python3.13" in argv
    assert argv[-2:] == [str(tmp_path / "probe.py"), "release"]
    assert not any("azazel-activated.service" in part for part in argv)


@pytest.mark.parametrize(
    ("mode", "properties", "output", "expected"),
    [
        ("expiry", _properties(), "ARMED\n", True),
        ("expiry", _properties(Result="timeout"), "ARMED\n", False),
        ("expiry", _properties(ExecMainStatus="15"), "ARMED\n", False),
        ("expiry", _properties(), "ARMED\nTraceback (most recent call last):\n", False),
        (
            "release",
            _properties(Result="success", ExecMainCode="1", ExecMainStatus="0"),
            "ARMED\nRELEASE_SURVIVED\n",
            True,
        ),
        (
            "release",
            _properties(Result="success", ExecMainCode="1", ExecMainStatus="0"),
            "ARMED\nRELEASE_SURVIVED\nTraceback (most recent call last):\n",
            False,
        ),
    ],
)
def test_passed_requires_exact_result_and_markers(mode, properties, output, expected):
    assert sandbox.passed(mode, properties, output) is expected


def test_checked_native_reads_only_unchanged_ordinary_file(tmp_path, monkeypatch):
    data = b"n" * 71048
    path = tmp_path / "native.so"
    path.write_bytes(data)
    monkeypatch.setattr(sandbox, "NATIVE_SHA256", sha256(data).hexdigest())

    assert sandbox.checked_native(path) == data


def test_checked_native_rejects_symlink_digest_and_size(tmp_path, monkeypatch):
    data = b"n" * 71048
    ordinary = tmp_path / "ordinary.so"
    ordinary.write_bytes(data)
    link = tmp_path / "linked.so"
    link.symlink_to(ordinary)
    with pytest.raises(OSError):
        sandbox.checked_native(link)

    monkeypatch.setattr(sandbox, "NATIVE_SHA256", "0" * 64)
    with pytest.raises(ValueError, match="digest"):
        sandbox.checked_native(ordinary)

    short = tmp_path / "short.so"
    short.write_bytes(b"short")
    with pytest.raises(ValueError, match="ordinary file"):
        sandbox.checked_native(short)


def _service_properties(rendered):
    section = rendered.split("[Service]\n", 1)[1].split("\n[", 1)[0]
    values = {}
    for line in section.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    return values


def test_sandbox_fixed_hardening_subset_matches_controller_declaration():
    controller = next(profile for profile in hardening.PROFILES
                      if profile.unit == "azazel-activated.service")
    declared = _service_properties(hardening.render_unit(controller))
    sandbox_values = dict(item.split("=", 1) for item in sandbox.PROPERTIES)

    # These are deliberately fixture-specific lifecycle and journal settings,
    # not claims that the qualification unit is the product controller.
    fixture_only = {
        "Type", "RemainAfterExit", "RuntimeMaxSec", "TimeoutStartSec",
        "TimeoutStopSec", "StandardOutput", "StandardError", "SyslogIdentifier",
        "UnsetEnvironment",
    }
    shared = sandbox_values.keys() - fixture_only
    assert shared
    assert all(declared[key] == sandbox_values[key] for key in shared)
    assert sandbox_values["Type"] == "exec"
    assert sandbox_values["TimeoutStartSec"] == "5s"
    assert sandbox_values["TimeoutStopSec"] == "5s"
    unset_names = sandbox_values["UnsetEnvironment"].split()
    assert len(unset_names) == len(set(unset_names))
    assert set(unset_names) == set(BOOTSTRAP_UNSET_ENVIRONMENT)


def test_run_retains_fixture_and_results_when_stop_is_unconfirmed(tmp_path, monkeypatch):
    directory = tmp_path / "qualification-fixture"
    directory.mkdir()
    monkeypatch.setattr(sandbox.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sandbox, "checked_native", lambda path: b"synthetic native")
    monkeypatch.setattr(sandbox, "_stage_parent", lambda: "/synthetic/root-exec-parent")

    def make_tempdir(*, prefix, dir):
        assert dir == "/synthetic/root-exec-parent"
        return str(directory)

    monkeypatch.setattr(sandbox.tempfile, "mkdtemp", make_tempdir)
    removals = []
    monkeypatch.setattr(sandbox.shutil, "rmtree", lambda path: removals.append(path))

    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/bin/systemd-run":
            return SimpleNamespace(stdout="")
        if argv[0] == "/usr/bin/systemctl" and argv[1] == "show":
            properties = next(part.removeprefix("--property=") for part in argv
                              if part.startswith("--property="))
            if properties == "LoadState,ActiveState,SubState,MainPID,ControlPID":
                return SimpleNamespace(stdout=(
                    "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                    "MainPID=0\nControlPID=0\n"
                ))
            return SimpleNamespace(stdout="ActiveState=failed\nSubState=failed\nResult=signal\n"
                                    "ExecMainCode=2\nExecMainStatus=9\n")
        if argv[0] == "/usr/bin/journalctl":
            return SimpleNamespace(stdout="ARMED\n")
        if argv[0] == "/usr/bin/systemctl" and argv[1] == "stop":
            return SimpleNamespace(stdout="")
        if argv[0] == "/usr/bin/systemctl" and argv[1] == "reset-failed":
            return SimpleNamespace(returncode=1)
        pytest.fail(f"unexpected subprocess command: {argv!r}")

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)
    report = sandbox.run("/synthetic/native.so")

    assert report["error"].startswith("RuntimeError: fixture stop unconfirmed:")
    assert report["cleanup_confirmed"] is False
    assert len(report["results"]) == 1
    assert report["results"][0]["passed"] is True
    assert len(report["unconfirmed_units"]) == 1
    assert report["retained_directory"] == str(directory)
    assert (directory / sandbox.NATIVE_NAME).read_bytes() == b"synthetic native"
    assert (directory / "probe.py").is_file()
    assert removals == []


def test_run_reports_removal_failure_after_both_trials_pass(tmp_path, monkeypatch):
    directory = tmp_path / "qualification-fixture"
    directory.mkdir()
    monkeypatch.setattr(sandbox.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sandbox, "checked_native", lambda path: b"synthetic native")
    monkeypatch.setattr(sandbox, "_stage_parent", lambda: "/synthetic/root-exec-parent")

    def make_tempdir(*, prefix, dir):
        assert dir == "/synthetic/root-exec-parent"
        return str(directory)

    monkeypatch.setattr(sandbox.tempfile, "mkdtemp", make_tempdir)

    def fail_remove(path):
        raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(sandbox.shutil, "rmtree", fail_remove)

    unit_modes = {}
    cleanup_order = {}

    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/bin/systemd-run":
            unit = next(part.removeprefix("--unit=") for part in argv
                        if part.startswith("--unit="))
            unit_modes[unit] = argv[-1]
            cleanup_order[unit] = []
            return SimpleNamespace(stdout="")
        if argv[0] == "/usr/bin/systemctl" and argv[1] == "show":
            properties = next(part.removeprefix("--property=") for part in argv
                              if part.startswith("--property="))
            if properties == "LoadState,ActiveState,SubState,MainPID,ControlPID":
                cleanup_order[argv[2]].append("verify")
                return SimpleNamespace(stdout=(
                    "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                    "MainPID=0\nControlPID=0\n"
                ))
            mode = unit_modes[argv[2]]
            status = "0" if mode == "release" else "9"
            code = "1" if mode == "release" else "2"
            result = "success" if mode == "release" else "signal"
            active = "inactive" if mode == "release" else "failed"
            substate = "exited" if mode == "release" else "failed"
            return SimpleNamespace(stdout=(
                f"ActiveState={active}\nSubState={substate}\nResult={result}\n"
                f"ExecMainCode={code}\nExecMainStatus={status}\n"
            ))
        if argv[0] == "/usr/bin/journalctl":
            unit = next(part.removeprefix("--unit=") for part in argv
                        if part.startswith("--unit="))
            mode = unit_modes[unit]
            markers = "ARMED\nRELEASE_SURVIVED\n" if mode == "release" else "ARMED\n"
            return SimpleNamespace(stdout=markers)
        if argv[0] == "/usr/bin/systemctl" and argv[1] in ("stop", "reset-failed"):
            cleanup_order[argv[2]].append(argv[1])
            return SimpleNamespace(stdout="", returncode=0)
        pytest.fail(f"unexpected subprocess command: {argv!r}")

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)
    report = sandbox.run("/synthetic/native.so")

    assert report["error"] == "OSError: synthetic cleanup failure"
    assert report["cleanup_confirmed"] is False
    assert report["unconfirmed_units"] == []
    assert len(report["results"]) == 2
    assert all(item["passed"] for item in report["results"])
    assert report["retained_directory"] == str(directory)
    assert (directory / "probe.py").is_file()
    assert len(cleanup_order) == 2
    assert all(order == ["stop", "reset-failed", "verify"]
               for order in cleanup_order.values())


def test_stage_parent_accepts_only_mocked_root_owned_exec_parent(monkeypatch):
    seen = []

    def fake_lstat(path):
        seen.append(path)
        return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)

    monkeypatch.setattr(sandbox.os, "lstat", fake_lstat)
    monkeypatch.setattr(sandbox.os, "statvfs",
                        lambda path: SimpleNamespace(f_flag=0))
    monkeypatch.setattr(sandbox.os, "ST_NOEXEC", 8, raising=False)

    assert sandbox._stage_parent() == "/var/lib"
    assert seen == ["/var", "/var/lib"]


@pytest.mark.parametrize("unsafe", ["symlink", "writable", "noexec"])
def test_stage_parent_refuses_unsafe_parent_or_noexec_filesystem(monkeypatch, unsafe):
    def fake_lstat(path):
        mode = stat.S_IFDIR | 0o755
        if path == "/var/lib" and unsafe == "symlink":
            mode = stat.S_IFLNK | 0o777
        elif path == "/var/lib" and unsafe == "writable":
            mode = stat.S_IFDIR | 0o777
        return SimpleNamespace(st_mode=mode, st_uid=0)

    monkeypatch.setattr(sandbox.os, "lstat", fake_lstat)
    monkeypatch.setattr(sandbox.os, "statvfs", lambda path: SimpleNamespace(
        f_flag=8 if unsafe == "noexec" else 0,
    ))
    monkeypatch.setattr(sandbox.os, "ST_NOEXEC", 8, raising=False)

    with pytest.raises(ValueError, match="protected qualification staging parent"
                       if unsafe != "noexec" else "filesystem is noexec"):
        sandbox._stage_parent()


def test_stop_fixture_accepts_gc_after_reset_only_with_zero_pids(monkeypatch):
    commands = []

    def fake_run(argv, **kwargs):
        commands.append(argv[1])
        if argv[1] == "show":
            return SimpleNamespace(stdout=(
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                "MainPID=0\nControlPID=0\n"
            ))
        return SimpleNamespace(returncode=1 if argv[1] == "reset-failed" else 0)

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)
    sandbox._stop_fixture("azazel-nexus-qualification-0123456789abcdef0123456789abcdef.service")

    assert commands == ["stop", "reset-failed", "show"]


def test_stop_fixture_refuses_unknown_or_nonzero_process_state(monkeypatch):
    def fake_run(argv, **kwargs):
        if argv[1] == "show":
            return SimpleNamespace(stdout=(
                "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                "MainPID=23\nControlPID=0\n"
            ))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="fixture stop unconfirmed"):
        sandbox._stop_fixture("azazel-nexus-qualification-0123456789abcdef0123456789abcdef.service")
