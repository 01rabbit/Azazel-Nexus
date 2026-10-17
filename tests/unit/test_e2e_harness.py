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

import inspect
import re
import shutil
import stat
import subprocess
import sys
import tempfile
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
from tools.stage_runtime_entrypoints import declared_daemons


@pytest.fixture
def short_root():
    """A harness root short enough for the daemons' unix socket addresses.

    pytest's tmp_path can exceed MAX_ROOT_BYTES on CI runners, and the
    harness rightly refuses such a root.
    """
    root = Path(tempfile.mkdtemp(prefix="az-e2e-", dir="/tmp"))
    yield root
    shutil.rmtree(root, ignore_errors=True)


REPO_ROOT = Path(__file__).resolve().parents[2]
STAGES = (REPO_ROOT / "tools" / "e2e_stages.py").read_text(encoding="utf-8")
INSTALLER = (REPO_ROOT / "packaging" / "install.sh").read_text(encoding="utf-8")


def _copy_installer_tree_for_layout_test(tmp_path: Path) -> Path:
    """Copy actual installer inputs and substitute harmless wrapper files."""
    root = tmp_path / "installer-tree"
    shutil.copytree(REPO_ROOT / "packaging", root / "packaging")
    (root / "tools").mkdir()
    for name in ("install_profile_fields.py", "stage_runtime_entrypoints.py"):
        shutil.copy2(REPO_ROOT / "tools" / name, root / "tools" / name)
    shutil.copytree(REPO_ROOT / "src", root / "src")
    shutil.copytree(REPO_ROOT / "runtime" / "src", root / "runtime" / "src")
    fake_stager = root / "tools" / "stage_runtime_entrypoints.py"
    fake_stager.write_text(
        "import os\n"
        "from pathlib import Path\n"
        "dest = Path(os.environ['DESTDIR']) / 'usr/libexec/azazel'\n"
        "dest.mkdir(parents=True, exist_ok=True)\n"
        f"for name in {tuple(declared_daemons())!r}:\n"
        "    target = dest / name\n"
        "    target.write_text('#!/bin/sh\\nexit 0\\n', encoding='ascii')\n"
        "    target.chmod(0o755)\n",
        encoding="utf-8",
    )
    return root


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


def test_a_stage_that_raises_not_executed_is_skipped_not_failed(short_root):
    """The bug the harness found on its first run, pinned.

    `NotExecuted` lived in the runner, which the stages imported again under
    a second module name -- so `except NotExecuted` in one did not catch the
    other's, and every skip was reported as a failure. A duplicated module is
    two modules.
    """

    harness = Harness(short_root)

    def skip():
        raise NotExecuted("there is no service manager here")

    harness.stage("systemd", skip)
    assert harness.report.stages[0].status == NOT_EXECUTED
    assert "service manager" in harness.report.stages[0].detail


def test_a_stage_that_raises_anything_else_is_a_failure(short_root):
    harness = Harness(short_root)

    def broken():
        raise RuntimeError("the digest did not match")

    harness.stage("generation", broken)
    assert harness.report.stages[0].status == FAILED
    assert "digest did not match" in harness.report.stages[0].detail


def test_a_stage_that_overruns_its_deadline_is_a_failure_not_a_slow_pass(short_root):
    import tools.e2e_harness as harness_module

    harness = Harness(short_root)
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
    # Nexus#72: the probe writes a result and the library reads it, with
    # the stale, mismatched and tampered cases all withholding.
    "Edge probe to status",
    # Nexus#67: the producer's six fixtures through the inbox, with the
    # Edge answer read before and after each one.
    "Knowledge Lite offline import",
    # Nexus#68: the Core reserve input path -- record, validation, reserve,
    # admission gate -- in the three states that matter. It takes no
    # measurement and needs no hardware, which is why it can be here at all:
    # what it drives is the machinery around a number that does not exist.
    "M.I.O. entry handoff",
    "Knowledge Lite status",
    "Operator setup flow",
    "Core reserve input path",
)


def test_every_stage_the_issue_lists_is_run_in_order():
    found = re.findall(r'harness\.stage\(\s*"([^"]+)"', STAGES)
    assert tuple(found) == REQUIRED_STAGES


def test_a_stage_blocked_by_a_skipped_prerequisite_is_skipped_not_failed(short_root):
    """Nothing about the product went wrong, so nothing may read as broken.

    Found on CI: the runner is not root, `useradd` failed, and five later
    stages then failed with `AttributeError` because the first had not set
    anything up. Five failures for one missing privilege buries the skip that
    explains them.
    """

    harness = Harness(short_root)

    def skip():
        raise NotExecuted("not root here")

    harness.stage("install accounts", skip)
    harness.stage("inventory", lambda: "unreached", requires=("install accounts",))

    blocked = harness.report.stages[1]
    assert blocked.status == NOT_EXECUTED
    assert "install accounts" in blocked.detail
    assert harness.report.ok() is True


def test_a_stage_whose_prerequisite_ran_is_not_skipped(short_root):
    harness = Harness(short_root)
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


def test_the_installer_refuses_rather_than_pretending_without_systemd():
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
        env={"PATH": "/usr/sbin:/usr/bin:/bin:/sbin"},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 3, result.stdout + result.stderr
    assert "refusing to install: systemd is not running" in result.stderr


def test_destdir_refuses_host_systemd_changes_before_staging_files(tmp_path):
    result = subprocess.run(
        ["sh", str(REPO_ROOT / "packaging" / "install.sh"), "--without-accounts"],
        env={
            "DESTDIR": str(tmp_path),
            "PATH": "/usr/sbin:/usr/bin:/bin:/sbin",
        },
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert "DESTDIR stages files but cannot stage systemd state" in result.stderr
    assert list(tmp_path.iterdir()) == []


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
    """The real installer creates its declared layout against a prefix.

    The copied installer/profile/package inputs remain real; only wrapper
    staging is replaced with harmless executable placeholders. This covers
    the layout path, not runtime-import qualification, native deadline
    support, or installed-runtime readiness.
    """

    from azazel_nexus.layout import LAYOUT

    if not Path("/etc/os-release").is_file():
        pytest.skip("installer requires the host's os-release install profile")

    installer_root = _copy_installer_tree_for_layout_test(tmp_path)
    result = subprocess.run(
        [
            "sh",
            str(installer_root / "packaging" / "install.sh"),
            "--without-service-manager",
            "--without-accounts",
        ],
        env={
            "DESTDIR": str(tmp_path),
            "PATH": "/usr/sbin:/usr/bin:/bin:/sbin",
            "PYTHON": sys.executable,
        },
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
        assert stat.S_IMODE(created.stat().st_mode) == spec.mode


def test_an_unknown_installer_option_is_refused():
    result = subprocess.run(
        ["sh", str(REPO_ROOT / "packaging" / "install.sh"), "--make-it-work"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 2
    assert "unknown option" in result.stderr


def test_the_lite_matrix_stage_actually_composes_nine_configurations(short_root):
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

    detail = _lite_matrix(Harness(short_root))
    assert detail.startswith("9 CORE + Lite configurations")
    assert "enforcement or baseline readiness" in detail
    assert "what continues" in detail


# -- the harness may not be aimed at anything under version control -------


def _git_working_tree(path, *, linked=False):
    """A directory that looks like what Git leaves behind: `.git` as a
    directory in an ordinary checkout, as a *file* in a linked worktree."""

    path.mkdir(parents=True, exist_ok=True)
    if linked:
        (path / ".git").write_text("gitdir: /elsewhere/.git/worktrees/w\n")
    else:
        (path / ".git").mkdir()
    return path


def test_this_checkout_is_refused():
    """Where the accident happened: the harness was pointed at the checkout
    somebody was standing in, and the synthetic node it built -- a Core
    reserve record declaring itself measured among it -- was swept into a
    commit by the next `git add -A`."""

    from tools.e2e import refuse_root_in_a_git_working_tree  # noqa: PLC0415

    for inside in (REPO_ROOT, REPO_ROOT / "docs", REPO_ROOT / "does" / "not" / "exist"):
        refusal = refuse_root_in_a_git_working_tree(inside)
        assert refusal is not None, f"{inside} was accepted"
        assert str(REPO_ROOT) in refusal, "the refusal does not say which tree"


@pytest.mark.parametrize("linked", [False, True], ids=["checkout", "worktree"])
@pytest.mark.parametrize("depth", [0, 1, 3], ids=["at", "under", "deep-under"])
def test_any_git_working_tree_is_refused_not_only_this_one(tmp_path, linked, depth):
    """A guard that knew only this checkout would move the accident to the
    next worktree rather than prevent it -- and a linked worktree carries
    `.git` as a file, which a check for a directory does not see."""

    from tools.e2e import refuse_root_in_a_git_working_tree  # noqa: PLC0415

    tree = _git_working_tree(tmp_path / "elsewhere", linked=linked)
    target = tree.joinpath(*[f"level{n}" for n in range(depth)])
    refusal = refuse_root_in_a_git_working_tree(target)
    assert refusal is not None, f"{target} was accepted"
    assert str(tree) in refusal, "the refusal does not name the enclosing tree"


def test_a_directory_outside_version_control_is_accepted(tmp_path):
    """The refusal has to be about version control and not about roots."""

    from tools.e2e import refuse_root_in_a_git_working_tree  # noqa: PLC0415

    assert refuse_root_in_a_git_working_tree(tmp_path) is None


def test_a_sibling_of_a_working_tree_is_not_refused(tmp_path):
    """Narrow enough to be usable: next to a checkout is not inside one."""

    from tools.e2e import refuse_root_in_a_git_working_tree  # noqa: PLC0415

    _git_working_tree(tmp_path / "checkout")
    sibling = tmp_path / "beside"
    sibling.mkdir()
    assert refuse_root_in_a_git_working_tree(sibling) is None


def test_the_default_root_is_a_fresh_directory_outside_version_control():
    """The ordinary way to run the harness must not be able to put a
    synthetic node where a commit could pick it up."""

    from tools.e2e import dedicated_root, refuse_root_in_a_git_working_tree  # noqa: PLC0415

    first = dedicated_root()
    second = dedicated_root()
    try:
        for root in (first, second):
            assert root.is_dir()
            assert not any(root.iterdir()), "the default root is not empty"
            assert refuse_root_in_a_git_working_tree(root) is None
        assert first != second, "two runs would share one root"
    finally:
        for root in (first, second):
            shutil.rmtree(root, ignore_errors=True)


def test_root_is_optional_so_the_default_is_the_easy_path():
    """A required `--root` makes every invocation name a directory, and the
    one nearest to hand is the checkout."""

    from tools.e2e import main  # noqa: PLC0415

    signature = inspect.signature(main)
    assert list(signature.parameters) == ["argv"]
    source = (REPO_ROOT / "tools" / "e2e.py").read_text(encoding="utf-8")
    assert "required=True" not in source, "--root is required again"


def test_the_refusal_happens_before_the_harness_writes_anything():
    """A refusal after the first write is a refusal that leaves the files
    behind -- and in a working tree, files left behind are files a commit
    picks up."""

    from tools.e2e import main  # noqa: PLC0415

    target = REPO_ROOT / "e2e-root-that-should-never-be-created"
    assert not target.exists(), "a previous run left this behind"
    assert main(["--root", str(target)]) == 2
    assert not target.exists(), "the harness wrote to a root it refused"


@pytest.mark.parametrize("root,expected", [(True, (19, 1)), (False, (15, 5))])
def test_stage_privilege_accounting(short_root, monkeypatch, root, expected):
    from tools import e2e_stages as stages

    def accounts(harness):
        if not root:
            raise NotExecuted("root required")
        return "accounts checked"

    monkeypatch.setattr(stages, "_install_accounts", accounts)
    monkeypatch.setattr(stages, "_masked", lambda h: (_ for _ in ()).throw(
        NotExecuted("systemd enforcement is a separate host check")))
    for name in ("_install_files", "_inventory", "_commission", "_generation",
                 "_activation", "_health", "_failure", "_rollback", "_audit",
                 "_lite_matrix", "_edge_package", "_loopback_decoys", "_edge_probe",
                 "_lite_import", "_core_reserve_path", "_mio_entry", "_knowledge_status",
                 "_operator_setup"):
        monkeypatch.setattr(stages, name, lambda h: "executed")
    harness = Harness(short_root)
    stages.run_all(harness)
    passed, skipped = expected
    assert harness.report.summary() == {
        "passed": passed, "not_executed": skipped, "failed": 0, "total": 20}


def test_offline_import_prepares_the_same_store_and_trust_as_setup(short_root):
    from azazel_nexus.lite_import import status_summary
    from tools.e2e_stages import _lite_import, _operator_setup, _setup_snapshot

    harness = Harness(short_root)
    before = _setup_snapshot(harness, "before-install")
    assert "missing:" in before["installed-files"]["reason"]
    wrappers = short_root / "usr/libexec/azazel"
    wrappers.mkdir(parents=True)
    for name in ("az-activated", "az-commissiond", "az-auditd", "az-mio-entryd", "az-knowledge-lited"):
        (wrappers / name).touch()
    _setup_snapshot(harness, "after-install")
    _lite_import(harness)
    summary = status_summary(root=short_root / "var/lib/azazel/knowledge",
                             trust_root=short_root / "var/lib/azazel/lite-trust",
                             query_as_of="2026-10-18T00:00:00Z")
    assert summary["state"] == "available", summary
    assert summary["generation"] is not None
    assert "provider admission blocked" in _operator_setup(harness)


@pytest.mark.parametrize("refused", [False, True])
def test_root_exchange_uses_operator_gid_and_restores_it(monkeypatch, refused):
    import io
    import json
    import struct
    from types import SimpleNamespace

    from tools import e2e_harness as module

    body = json.dumps({"ok": True, "result": {}}).encode()
    reply = io.BytesIO(struct.pack("!I", len(body)) + body)
    groups = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, value):
            pass

        def connect(self, path):
            assert groups == [456]
            if refused:
                raise PermissionError("fixture connection refusal")

        def sendall(self, body):
            pass

        def shutdown(self, mode):
            pass

        def recv(self, size):
            return reply.read(size)

    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module.os, "getegid", lambda: 123)
    monkeypatch.setattr(module.os, "setegid", groups.append)
    monkeypatch.setattr(module.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=456))
    monkeypatch.setattr(module.socket, "socket", lambda *args: Connection())
    if refused:
        with pytest.raises(PermissionError):
            module.request(Path("/fixture.sock"), {})
    else:
        assert module.request(Path("/fixture.sock"), {}) == {"ok": True, "result": {}}
    assert groups == [456, 123]
