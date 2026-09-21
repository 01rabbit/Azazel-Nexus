"""The harness's accounting, which is the part that can lie (#43).

A stage that could not run must never be counted as one that passed. That is
the whole reason this file exists: the rest of the harness is checked by
running it, and the one thing running it cannot check is whether its own
report is honest about what it did not do.

Nothing here starts a daemon or touches a host. The harness's actual run is
`tools/e2e.py`, and it is not part of the unit suite -- a suite that spawned
subprocesses and bound sockets on every contributor's machine is a suite
people stop running.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.e2e_harness import (  # noqa: E402
    EXECUTED,
    FAILED,
    MAX_ROOT_BYTES,
    NOT_EXECUTED,
    Harness,
    NotExecuted,
    Report,
    StageResult,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
STAGES = (REPO_ROOT / "tools" / "e2e_stages.py").read_text(encoding="utf-8")
INSTALLER = (REPO_ROOT / "packaging" / "install.sh").read_text(encoding="utf-8")


# -- a skip is not a pass -------------------------------------------------


def test_a_stage_that_was_not_executed_is_not_counted_as_passed():
    report = Report(
        stages=[
            StageResult("one", EXECUTED),
            StageResult("two", NOT_EXECUTED, "systemd is not running"),
        ]
    )
    assert report.summary() == {
        "passed": 1,
        "not_executed": 1,
        "failed": 0,
        "total": 2,
    }


def test_a_run_with_a_skipped_stage_is_not_a_complete_run():
    """`--require-all` is what a host with systemd would use.

    Without it the run is useful and incomplete, and the report says which.
    """

    report = Report(
        stages=[StageResult("two", NOT_EXECUTED, "systemd is not running")]
    )
    assert report.ok() is True
    assert report.ok(require_all=True) is False


def test_a_failed_stage_fails_the_run_either_way():
    report = Report(stages=[StageResult("one", FAILED, "it did not work")])
    assert report.ok() is False
    assert report.ok(require_all=True) is False


def test_a_skip_must_say_why():
    """An unexplained skip reads as a pass to anyone scanning the report."""

    with pytest.raises(ValueError):
        StageResult("two", NOT_EXECUTED)
    with pytest.raises(ValueError):
        StageResult("two", NOT_EXECUTED, "   ")


def test_a_failure_must_say_why():
    with pytest.raises(ValueError):
        StageResult("two", FAILED, "")


def test_an_unknown_status_cannot_be_recorded():
    """With a detail supplied, so the *status* check is what refuses it.

    Without one the "a skip must say why" branch fires first and the test
    passes whether or not the status is validated at all.
    """

    with pytest.raises(ValueError) as refused:
        StageResult("two", "probably fine", "it seemed to work")
    assert "not a stage status" in str(refused.value)


def test_the_report_says_plainly_what_it_does_not_establish():
    report = Report(stages=[StageResult("one", EXECUTED)])
    text = report.render()
    assert "not a stage that passed" in text
    assert "nothing about real hardware" in text
    assert "nothing about what systemd enforces" in text


def test_a_skipped_stage_is_rendered_as_not_run_rather_than_as_a_tick():
    report = Report(
        stages=[StageResult("two", NOT_EXECUTED, "systemd is not running")]
    )
    rendered = report.render()
    assert "NOT RUN" in rendered
    assert not re.search(r"^ok\s+two", rendered, re.M)


# -- the harness itself ---------------------------------------------------


def test_a_stage_that_raises_not_executed_is_skipped_not_failed(tmp_path):
    """The bug the harness found on its first run, pinned.

    `NotExecuted` lived in the runner, which the stages imported again under
    a second module name -- so `except NotExecuted` in one did not catch the
    other's, and every skip was reported as a failure. A duplicated module is
    two modules.
    """

    harness = Harness(tmp_path)

    def skip():
        raise NotExecuted("there is no service manager here")

    harness.stage("systemd", skip)
    assert harness.report.stages[0].status == NOT_EXECUTED
    assert "service manager" in harness.report.stages[0].detail


def test_a_stage_that_raises_anything_else_is_a_failure(tmp_path):
    harness = Harness(tmp_path)

    def broken():
        raise RuntimeError("the digest did not match")

    harness.stage("generation", broken)
    assert harness.report.stages[0].status == FAILED
    assert "digest did not match" in harness.report.stages[0].detail


def test_a_stage_that_overruns_its_deadline_is_a_failure_not_a_slow_pass(tmp_path):
    import tools.e2e_harness as harness_module

    harness = Harness(tmp_path)
    original = harness_module.STAGE_DEADLINE_SECONDS
    harness_module.STAGE_DEADLINE_SECONDS = 0.0
    try:
        harness.stage("slow", lambda: "done")
    finally:
        harness_module.STAGE_DEADLINE_SECONDS = original
    assert harness.report.stages[0].status == FAILED
    assert "deadline" in harness.report.stages[0].detail


def test_a_root_too_long_for_a_unix_socket_is_refused_with_the_arithmetic():
    """`AF_UNIX path too long` from inside a subprocess is a puzzle.

    The harness hit it on its first run, from a scratch directory whose name
    was long. Refused up front now, with the numbers in the message.
    """

    with pytest.raises(ValueError) as refused:
        Harness(Path("/" + "x" * (MAX_ROOT_BYTES + 1)))
    assert "107" in str(refused.value)


# -- the stages cover what the issue lists --------------------------------

#: The sequence issue #43 gives, in its order, plus what later issues added.
#:
#: Pinned as a tuple rather than as a set: a stage disappearing and a stage
#: moving are both failures, and a set would notice neither. A new stage is
#: added here deliberately, with the issue that asked for it.
REQUIRED_STAGES = (
    # Installation is three halves needing three privileges: write access to
    # the prefix, root, and a running systemd. One stage would have to claim
    # all three or none.
    "install files",
    "install accounts",
    "units masked and disabled",
    "inventory",
    "operator-confirmed commissioning",
    "verified generation",
    "activation",
    "health and status",
    "daemon failure",
    "remask and rollback",
    "audit chain",
    # Nexus#56 (E5): the nine CORE + Lite configurations, composed. Last
    # because it depends on nothing the earlier stages set up -- it drives
    # the library, not the installed tree -- and a stage with no prerequisite
    # placed early would hide that it has none.
    "CORE + Lite configurations",
    # Nexus#44: the five Edge checks, each broken on its own against a
    # package written into the harness root. Also has no prerequisite.
    "Edge package verification",
    # Nexus#69: decoys bound on real Unix sockets, reached, and crashed.
    # Also has no prerequisite.
    "loopback decoy runtime",
)


def test_every_stage_the_issue_lists_is_run_in_order():
    found = re.findall(r'harness\.stage\(\s*"([^"]+)"', STAGES)
    assert tuple(found) == REQUIRED_STAGES


def test_a_stage_blocked_by_a_skipped_prerequisite_is_skipped_not_failed(tmp_path):
    """Nothing about the product went wrong, so nothing may read as broken.

    Found on CI: the runner is not root, `useradd` failed, and five later
    stages then failed with `AttributeError` because the first had not set
    anything up. Five failures for one missing privilege buries the skip that
    explains them.
    """

    harness = Harness(tmp_path)

    def skip():
        raise NotExecuted("not root here")

    harness.stage("install accounts", skip)
    harness.stage("inventory", lambda: "unreached", requires=("install accounts",))

    blocked = harness.report.stages[1]
    assert blocked.status == NOT_EXECUTED
    assert "install accounts" in blocked.detail
    assert harness.report.ok() is True


def test_a_stage_whose_prerequisite_ran_is_not_skipped(tmp_path):
    harness = Harness(tmp_path)
    harness.stage("install accounts", lambda: "created")
    harness.stage("inventory", lambda: "listed", requires=("install accounts",))
    assert harness.report.stages[1].status == EXECUTED


def test_no_stage_claims_the_run_was_on_real_hardware():
    """Words that would turn a container run into a hardware claim."""

    for phrase in (
        "hardware verified",
        "verified on hardware",
        "production",
        "rugged",
        "real hardware succeeded",
    ):
        assert phrase not in STAGES.lower(), f"a stage says {phrase!r}"


# -- the installer's own half --------------------------------------------


def test_the_installer_refuses_rather_than_pretending_without_systemd(tmp_path):
    """Run, not grepped.

    The first version searched the script for the refusal message, which
    survives a mutation that only changes the condition guarding it. A
    message that is never printed is not a refusal.
    """

    if Path("/run/systemd/system").is_dir():
        pytest.skip("systemd is running here, so the refusal is not reachable")

    # `--without-accounts` so that the account refusal, which fires first for
    # a non-root caller, does not stand in for the one under test. The two
    # refusals have different exit codes precisely so they can be told apart.
    result = subprocess.run(
        ["sh", str(REPO_ROOT / "packaging" / "install.sh"), "--without-accounts"],
        env={"DESTDIR": str(tmp_path), "PATH": "/usr/sbin:/usr/bin:/bin:/sbin"},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 3, result.stdout + result.stderr
    assert "refusing to install: systemd is not running" in result.stderr
    assert not (tmp_path / "etc").exists(), (
        "the installer created files before refusing; a refusal that has "
        "already changed the host is a partial install"
    )


def test_the_without_service_manager_mode_says_loudly_what_it_did_not_do():
    assert "SERVICE-MANAGER STAGE NOT EXECUTED" in INSTALLER
    assert "nothing here established that it would not" in INSTALLER


def test_the_two_refusals_have_different_exit_codes():
    """So a caller can tell "no systemd" from "not root" without parsing text."""

    assert "exit 3" in INSTALLER and "exit 4" in INSTALLER


def test_the_installer_refuses_to_create_accounts_without_root(tmp_path):
    """The other half that needs a privilege, refused rather than attempted.

    This is what CI hit: `useradd: Permission denied` from a script that had
    already started installing. A refusal that has changed the host is a
    partial install.
    """

    import os

    if os.geteuid() == 0:
        pytest.skip("this process is root, so the refusal is not reachable")

    result = subprocess.run(
        ["sh", str(REPO_ROOT / "packaging" / "install.sh"), "--without-service-manager"],
        env={"DESTDIR": str(tmp_path), "PATH": "/usr/sbin:/usr/bin:/bin:/sbin"},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 4, result.stdout + result.stderr
    assert "accounts and directory ownership need root" in result.stderr
    assert not (tmp_path / "etc").exists()


def test_the_without_accounts_mode_says_that_ownership_was_not_applied():
    assert "ACCOUNT STAGE NOT EXECUTED" in INSTALLER
    # Matched within one `echo`: the sentence is split across two, and a
    # search for the joined phrase finds nothing however correct the message.
    assert "ownership the layout declares is not" in INSTALLER


def test_the_installer_runs_and_creates_the_declared_layout(tmp_path):
    """The real script, against a prefix. Not a reimplementation of it.

    Accounts are the one thing it does to the host either way; the harness
    runs on a throwaway container, and an installer that pretended to create
    them would be testing a different script.
    """

    from azazel_nexus.layout import LAYOUT

    libexec = tmp_path / "usr/libexec/azazel"
    libexec.mkdir(parents=True)
    for name in ("az-activated", "az-commissiond", "az-auditd", "az-watchdog"):
        shim = libexec / name
        shim.write_text("#!/bin/sh\nexit 0\n")
        shim.chmod(0o755)

    result = subprocess.run(
        [
            "sh",
            str(REPO_ROOT / "packaging" / "install.sh"),
            "--without-service-manager",
            "--without-accounts",
        ],
        env={"DESTDIR": str(tmp_path), "PATH": "/usr/sbin:/usr/bin:/bin:/sbin"},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "SERVICE-MANAGER STAGE NOT EXECUTED" in result.stdout
    assert "ACCOUNT STAGE NOT EXECUTED" in result.stdout

    for spec in LAYOUT:
        created = tmp_path / spec.path.lstrip("/")
        assert created.is_dir(), f"{spec.path} was not created"
        assert created.stat().st_mode & 0o777 == spec.mode


def test_an_unknown_installer_option_is_refused():
    result = subprocess.run(
        ["sh", str(REPO_ROOT / "packaging" / "install.sh"), "--make-it-work"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 2
    assert "unknown option" in result.stderr


def test_the_lite_matrix_stage_actually_composes_nine_configurations(tmp_path):
    """The stage body, executed rather than read.

    `test_every_stage_the_issue_lists_is_run_in_order` checks the stage
    *list*; nothing else in the unit suite runs a stage's body. A stage that
    had quietly stopped composing anything would still be listed, still
    report `ok`, and still say something plausible.

    The readiness assertions inside the stage are deliberately a second check
    of what `test_core_lite_integration.py` already holds. Two checks of one
    property at two layers is not the same mistake as two implementations of
    one rule: this one fires if the other is deleted.
    """

    from tools.e2e_harness import Harness
    from tools.e2e_stages import _lite_matrix

    detail = _lite_matrix(Harness(tmp_path))
    assert detail.startswith("9 CORE + Lite configurations")
    assert "enforcement or baseline readiness" in detail
    assert "what continues" in detail
