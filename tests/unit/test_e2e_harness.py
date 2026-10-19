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
    for name in ("install_profile_fields.py", "stage_runtime_entrypoints.py",
                 "provision_mission_read.py"):
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
    "Integration broker",
    "integrated defensive loop",
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


@pytest.mark.parametrize("root,expected", [(True, (21, 1)), (False, (16, 6))])
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
                 "_operator_setup", "_integration_broker", "_integrated_loop"):
        monkeypatch.setattr(stages, name, lambda h: "executed")
    harness = Harness(short_root)
    stages.run_all(harness)
    passed, skipped = expected
    assert harness.report.summary() == {
        "passed": passed, "not_executed": skipped, "failed": 0, "total": 22}


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


def test_integration_broker_stage_uses_signed_local_fixtures(short_root):
    from tools.e2e_stages import _integration_broker
    detail = _integration_broker(Harness(short_root))
    assert "transport refusal" in detail
    assert "audit verified" in detail
    assert "HIL not covered" in detail


def test_activation_stage_withholds_locald_without_model_admission(short_root):
    from types import SimpleNamespace

    from azazel_nexus.audit import AuditLedger
    from tools.e2e_stages import _activation, _commission, _generation

    (short_root / "etc/azazel/commissioning").mkdir(parents=True)
    (short_root / "var/lib/azazel/state").mkdir(parents=True)
    harness = SimpleNamespace(root=short_root)
    _commission(harness)
    _generation(harness)
    _activation(harness)
    granted = {
        row.event["unit"]
        for row in AuditLedger(short_root / "var/lib/azazel/state/activation.jsonl")
        if row.event["event_type"] == "activation.unit_granted"
    }
    assert "azazel-mio-entryd.service" in granted
    assert "azazel-edge-core.service" not in granted
    assert "azazel-mio-locald.service" not in granted


def test_integrated_loop_requires_import_and_accounts(short_root, monkeypatch):
    from tools import e2e_stages
    harness = Harness(short_root)
    registrations = {}
    monkeypatch.setattr(harness, "stage", lambda name, run, **kw: registrations.update({name: kw}))
    e2e_stages.run_all(harness)
    assert registrations["integrated defensive loop"]["requires"] == (
        "Knowledge Lite offline import", "install accounts")


@pytest.mark.parametrize("binary,policy", [(None, None), ("/tmp/built-edge-core", None),
                                           ("/tmp/built-edge-core", "/tmp/redirect_policy.yaml")])
def test_edge_core_option_reaches_harness(short_root, monkeypatch, binary, policy):
    from tools import e2e, e2e_stages
    found = []
    monkeypatch.setattr(e2e_stages, "run_all", lambda harness: found.append(
        (harness.edge_core, harness.edge_redirect_policy)))
    args = ["--root", str(short_root)] + (["--edge-core", binary] if binary else [])
    args += ["--edge-redirect-policy", policy] if policy else []
    assert e2e.main(args) == 0
    assert found == [(binary and Path(binary), policy and Path(policy))]


@pytest.mark.parametrize("policy", [False, True])
def test_edge_environment_is_the_shipped_profile_with_only_test_paths(short_root, monkeypatch,
                                                                       policy):
    from tools.e2e_loop import edge_environment
    from azazel_nexus_runtime.hardening import PROFILES
    profile = next(p for p in PROFILES if p.unit == "azazel-edge-core.service")
    shipped = dict(v.split("=", 1) for k, v in profile.extra if k == "Environment")
    assert shipped["AZAZEL_DEFENSE_ENFORCE"] == "false"
    assert shipped["AZAZEL_DEFENSE_DRY_RUN"] == "true"
    monkeypatch.setenv("AZAZEL_DEFENSE_ENFORCE", "true")
    monkeypatch.setenv("AZAZEL_FORWARD_LOG", "true")
    state, intake = short_root / "edge", short_root / "intake.sock"
    harness = Harness(short_root, edge_redirect_policy=Path("/elsewhere/p.yaml") if policy else None)
    actual = edge_environment(harness, intake, state)
    relocated = {"AZAZEL_AI_SOCKET": str(intake), "AZAZEL_EVE_PATH": str(state / "eve.json"),
                 "AZAZEL_DEFENSE_RELEASE_LEDGER": str(state / "release-ledger.json"),
                 "AZAZEL_EVE_FROM_START": "true"}
    if policy:
        relocated["AZAZEL_REDIRECT_POLICY_PATH"] = str(state / "redirect_policy.yaml")
    # Any other key added, dropped or changed shows up in this difference.
    changed = {k for k in actual.keys() | shipped.keys() if actual.get(k) != shipped.get(k)}
    assert changed == relocated.keys()
    assert {k: actual[k] for k in changed} == relocated


@pytest.fixture
def replay_artifacts(short_root):
    """Real stores/tracker/explainer + admitted bundle; injected transports.

    No accounts, sockets or daemons. Runs the stage's assertions against actual
    product artifacts; does not claim Linux peer/process evidence.
    """
    import json
    import time
    from azazel_nexus.edge_intake import EvidenceRecord, parse_edge_event
    from azazel_nexus.lite_import import lookup_context_reading
    from azazel_nexus_runtime.auditd import SegmentedLedger
    from azazel_nexus_runtime.edge_intaked import IntakeServer
    from azazel_nexus_runtime.incident_explaind import Explainer
    from tools.e2e_loop import golden_lines
    from tools.e2e_stages import _lite_import

    harness = Harness(short_root)
    _lite_import(harness)
    base = short_root / "var/lib/azazel"
    for leaf in ("run/edge-intake-status", "run/incident-explain-status", "state/audit"):
        (base / leaf).mkdir(parents=True, exist_ok=True)
    server = IntakeServer(path=base / "unused.sock", state=base / "edge-intake",
                          incident_root=base / "edge-incidents", edge_uid=123,
                          status_path=base / "run/edge-intake-status/status.json")
    server._open_storage()
    instant = [time.monotonic()]
    audit = SegmentedLedger(base / "state/audit")
    def knowledge(ids):
        return lookup_context_reading(root=base / "knowledge", trust_root=base / "lite-trust",
                                      technique_ids=ids, query_as_of="2026-10-20T00:00:00Z").refs
    explainer = Explainer(
        incidents=base / "edge-incidents", state=base / "incident-explain",
        status_path=base / "run/incident-explain-status/status.json",
        monotonic=lambda: instant[0], knowledge=knowledge,
        mio=lambda _: {"route": "deterministic handoff", "outcome": "answered",
                       "reason": "no admitted model", "ledger_seq": 1,
                       "reference_status": "unavailable"})
    explainer.prepare()
    for line in golden_lines():
        record = EvidenceRecord.receive(parse_edge_event(line), time.time)
        server.store.append(record)
        server._transitions(server.tracker.add(record))
        server.accepted += 1
        server.last_accepted_at = record.received_at
        server.processed += 1
        server.last_processed_at = record.received_at
        instant[0] += 6
        explainer.poll()
        while not explainer.audit_pending.empty():
            event = explainer.audit_pending.get_nowait()
            audit.append(event, day=event["occurred_at"][:10])
            explainer.audit_pending.task_done()
    server._status()
    assert not explainer.storage_failed
    yield harness


def test_replay_assertions_cover_real_artifacts_and_cli(replay_artifacts):
    from tools.e2e_loop import assert_observations, eve_events, golden_lines
    ident = assert_observations(replay_artifacts, golden_lines(), eve_events(), set())
    assert ident.startswith("inc-")


@pytest.mark.parametrize("damage", ["count", "digest", "decision", "citation", "audit", "privacy"])
def test_replay_assertions_reject_missing_or_changed_evidence(replay_artifacts, damage):
    import json
    from tools.e2e_loop import assert_observations, eve_events, golden_lines
    base = replay_artifacts.root / "var/lib/azazel"
    if damage == "count":
        path = base / "run/edge-intake-status/status.json"
        value = json.loads(path.read_text())
        value["accepted"] -= 1
        path.write_text(json.dumps(value))
    elif damage in {"digest", "decision"}:
        path = next((base / "edge-intake/evidence").glob("*.jsonl"))
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        if damage == "digest":
            rows[0]["digest"] = "sha256:" + "0" * 64
        else:
            rows[0]["event"]["defense"]["action"] = "isolate"
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    elif damage in {"citation", "privacy"}:
        path = base / "run/incident-explain-status/recent.json"
        value = json.loads(path.read_text())
        explanation = value["incidents"][0]["explanation"]
        if damage == "citation":
            explanation["knowledge_refs"] = []
        else:
            explanation["summary"] = eve_events()[0]["src_ip"]
        path.write_text(json.dumps(value))
    else:
        path = next((base / "state/audit").glob("*.jsonl"))
        path.write_text(path.read_text().splitlines()[0] + "\n")
    with pytest.raises(AssertionError):
        assert_observations(replay_artifacts, golden_lines(), eve_events(), set())


@pytest.mark.parametrize("extra", [
    'connect(4, {sa_family=AF_INET, sin_port=htons(80)}, 16) = 0',
    'bind(4, {sa_family=AF_UNIX, sun_path="other.sock"}, 20) = 0',
    'listen(4, 16) = 0',
    'sendto(4, "data", 4, 0, {sa_family=AF_UNIX, sun_path="other.sock"}, 20) = 4',
    'socket(AF_INET, SOCK_STREAM, 0) = 4',
])
def test_edge_connection_trace_refuses_other_channels(extra):
    from tools.e2e_loop import assert_edge_trace
    intake = Path("/tmp/intake.sock")
    trace = ('socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 3\n'
             'connect(3, {sa_family=AF_UNIX, sun_path="/tmp/intake.sock"}, 20) = 0\n')
    assert_edge_trace(trace, intake, 1)
    with pytest.raises(AssertionError):
        assert_edge_trace(trace + extra, intake, 1)


def test_edge_connection_trace_allows_writes_on_the_intake_connection():
    from tools.e2e_loop import assert_edge_trace
    trace = ('socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 3\n'
             'connect(3, {sa_family=AF_UNIX, sun_path="/tmp/intake.sock"}, 20) = 0\n'
             'sendto(3, "{}\\n", 3, MSG_NOSIGNAL, NULL, 0) = 3\n')
    assert_edge_trace(trace, Path("/tmp/intake.sock"), 1)


def test_edge_trace_counts_one_connection_per_forward_report():
    from tools.e2e_loop import assert_edge_trace, forward_reports
    intake = Path("/tmp/intake.sock")
    connect = 'connect(3, {sa_family=AF_UNIX, sun_path="/tmp/intake.sock"}, 20) = 0\n'
    event = 'sendto(3, "{\\"defense\\":{}}\\n", 14, MSG_NOSIGNAL, NULL, 0) = 14\n'
    report = ('sendto(3, "{\\"dropped\\":0,\\"failed\\":0,\\"schema\\":\\"azazel-edge/'
              'forward-stats/v1\\",\\"sent\\":1,\\"since\\":1}\\n", 80, MSG_NOSIGNAL, NULL, 0) = 80\n')
    trace = connect + event + connect + report
    assert forward_reports(trace) == 1
    assert_edge_trace(trace, intake, 1)
    with pytest.raises(AssertionError):
        assert_edge_trace(trace + connect, intake, 1)
    assert forward_reports(connect + event) == 0


def test_forward_stats_assertion_needs_status_only_counts(replay_artifacts, monkeypatch):
    import json
    from azazel_nexus_runtime import edge_intaked
    from azazel_nexus.edge_intake import parse_edge_line
    from tools import e2e_loop
    base = replay_artifacts.root / "var/lib/azazel"
    path = base / "run/edge-intake-status/status.json"
    with pytest.raises(AssertionError, match="not in intake status"):
        e2e_loop.assert_forward_stats(replay_artifacts, 2)
    value = json.loads(path.read_text())
    server = edge_intaked.IntakeServer(path=base / "unused.sock", state=base / "unused",
                                       status_path=path, edge_uid=123)
    server.forward_stats(parse_edge_line(e2e_loop.forward_stats_line(2)))
    value["edge_forward"] = server.edge_forward
    path.write_text(json.dumps(value))
    assert e2e_loop.assert_forward_stats(replay_artifacts, 2)["sent"] == 2
    for change in ({"failed": 1}, {"sent": 3}, {"restarts": 1}):
        path.write_text(json.dumps(dict(value, edge_forward=dict(server.edge_forward, **change))))
        with pytest.raises(AssertionError, match="Edge forward counts"):
            e2e_loop.assert_forward_stats(replay_artifacts, 2)
    # Counted as an event (accepted grew) is a failure too.
    path.write_text(json.dumps(dict(value, accepted=3, processed=3)))
    with pytest.raises(AssertionError, match="taken as an event"):
        e2e_loop.assert_forward_stats(replay_artifacts, 2)


def test_replay_connects_one_line_per_connection_as_child(short_root, monkeypatch):
    import json
    from tools import e2e_loop
    captured = []
    monkeypatch.setattr(e2e_loop, "account_credentials", lambda account: captured.append(account) or {})
    def run(command, **kwargs):
        assert command[:2] == [sys.executable, "-c"]
        assert "with socket.socket" in command[2]
        assert "connection.sendall(line)" in command[2]
        lines = kwargs["input"].splitlines()
        assert lines[:-1] == e2e_loop.golden_lines()
        assert [json.loads(line)["normalized"]["severity"] for line in lines[:-1]] == [4, 1]
        # Then Edge's forward counts for those two, as Edge would report them.
        stats = json.loads(lines[-1])
        assert (stats["schema"], stats["dropped"], stats["failed"], stats["sent"]) == (
            "azazel-edge/forward-stats/v1", 0, 0, 2)
        return type("Result", (), {"returncode": 0, "stderr": b""})()
    monkeypatch.setattr(e2e_loop.subprocess, "run", run)
    import time
    e2e_loop.replay(Harness(short_root), short_root / "intake.sock", time.monotonic() + 1)
    assert captured == ["azedge"]


def test_activation_stage_uses_empty_edge_paths(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from azazel_nexus.edge_package import installed_baseline_state
    from azazel_nexus.generation import GenerationStore
    from tools.e2e_stages import NOW, _activation

    store = GenerationStore(tmp_path / "generations")
    store.create({"config": b"observe-only"}, created_at=NOW,
                 commissioning_digest="sha256:" + "0" * 64)
    harness = SimpleNamespace(root=tmp_path, store=store, record=None)
    seen = []

    def installed(*, now, package_root, probe_path):
        assert package_root.is_relative_to(tmp_path)
        assert probe_path.is_relative_to(tmp_path)
        assert not package_root.exists()
        assert not probe_path.exists()
        state = installed_baseline_state(now=now, package_root=package_root,
                                         probe_path=probe_path)
        assert not state.package_present
        seen.append(state)
        return state

    def host_read(**kwargs):
        pytest.fail("the e2e stage must inject Edge evidence instead of reading host paths")

    monkeypatch.setattr("azazel_nexus.edge_package.installed_baseline_state", installed)
    monkeypatch.setattr("azazel_nexus_runtime.activated.installed_baseline_state", host_read)
    assert "supporting units granted" in _activation(harness)
    assert len(seen) == 1


def test_live_jsonl_is_read_as_complete_lines_only(tmp_path):
    from tools.e2e_loop import complete, json_lines
    assert complete(b"") == b"" and complete(b'{"a": 1') == b""
    assert complete(b'{"a": 1}\n{"b"') == b'{"a": 1}\n'
    (tmp_path / "x.jsonl").write_bytes(b'{"a": 1}\n{"b": ')
    assert json_lines(tmp_path) == [{"a": 1}]


def test_live_ledger_drops_a_torn_append_but_not_a_broken_chain(tmp_path):
    from azazel_nexus.audit import AuditChainBroken
    from azazel_nexus_runtime.auditd import SegmentedLedger
    from tools.e2e_loop import ledger_events
    ledger = SegmentedLedger(tmp_path)
    for n in range(2):
        ledger.append({"event_type": "x", "n": n}, day="2026-10-20")
    segment = tmp_path / "2026-10-20.jsonl"
    whole = segment.read_bytes()
    segment.write_bytes(whole + b'{"sequence": 3, "eve')
    assert [e["n"] for e in ledger_events(tmp_path)] == [0, 1]
    first, second = whole.splitlines(keepends=True)
    segment.write_bytes(second + first)
    with pytest.raises(AuditChainBroken):
        ledger_events(tmp_path)


def test_wait_until_retries_absence_but_raises_a_decode_error_at_once():
    import json
    import time
    from tools.e2e_loop import wait_until
    calls = []
    def check():
        calls.append(1)
        if len(calls) == 1:
            raise FileNotFoundError("not yet")
        raise json.JSONDecodeError("torn", "", 0)
    with pytest.raises(json.JSONDecodeError):
        wait_until(time.monotonic() + 5, check)
    assert len(calls) == 2
    with pytest.raises(AssertionError, match="shutdown close deadline: never"):
        wait_until(time.monotonic() + 0.1, lambda: (_ for _ in ()).throw(AssertionError("never")),
                   what="shutdown close")


def test_socket_scan_ignores_a_path_removed_while_walking(short_root, monkeypatch):
    import socket as sockets_module
    from tools import e2e_loop
    live = short_root / "a.sock"
    with sockets_module.socket(sockets_module.AF_UNIX) as server:
        server.bind(str(live))
        gone = short_root / "gone.sock"
        real = Path.rglob
        monkeypatch.setattr(Path, "rglob", lambda self, pattern: [*real(self, pattern), gone])
        assert e2e_loop.sockets(short_root) == {live}


INTAKE_CONNECT = 'connect(3, {sa_family=AF_UNIX, sun_path="/tmp/intake.sock"}, 20'


def test_edge_connection_trace_joins_calls_strace_split_across_threads():
    from tools.e2e_loop import assert_edge_trace, joined_trace
    trace = ('7 socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 3\n'
             f'7 {INTAKE_CONNECT} <unfinished ...>\n'
             '8 socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0 <unfinished ...>\n'
             '7 <... connect resumed>) = 0\n'
             '8 <... socket resumed>) = 4\n'
             '7 sendto(3, "{}\\n", 3, MSG_NOSIGNAL, NULL, 0 <unfinished ...>\n'
             '7 <... sendto resumed>) = 3\n')
    assert joined_trace(trace)[1] == f"7 {INTAKE_CONNECT}) = 0"
    assert_edge_trace(trace, Path("/tmp/intake.sock"), 1)


@pytest.mark.parametrize("split", [False, True])
def test_edge_connection_trace_names_a_failed_intake_connect(split):
    from tools.e2e_loop import assert_edge_trace
    result = ") = -1 ENOENT (No such file or directory)"
    trace = (f"5 {INTAKE_CONNECT} <unfinished ...>\n5 <... connect resumed>{result}\n"
             if split else f"5 {INTAKE_CONNECT}{result}\n")
    with pytest.raises(AssertionError, match="intake connect failed"):
        assert_edge_trace(trace, Path("/tmp/intake.sock"), 1)


def test_edge_decisions_are_the_fixture_escalation():
    import json
    from tools.e2e_loop import EDGE_DECISIONS, EDGE_SEVERITIES, assert_edge_decisions, golden_lines
    lines = [json.loads(line) for line in golden_lines()]
    assert [line["defense"]["action"] for line in lines] == EDGE_DECISIONS
    assert [line["normalized"]["severity"] for line in lines] == EDGE_SEVERITIES
    for line in lines:
        line["enforcement_status"]["dry_run"] = True
    stdout = b"".join(json.dumps(line).encode() + b"\n" for line in lines)
    assert assert_edge_decisions(stdout + b'{"torn') == 2
    lines.reverse()
    with pytest.raises(AssertionError):
        assert_edge_decisions(b"".join(json.dumps(line).encode() + b"\n" for line in lines))


def test_daemon_startup_reports_its_output_and_the_deadline_that_ran_out(short_root, monkeypatch):
    import time
    from tools import e2e_harness
    real = e2e_harness.subprocess.Popen
    code = []
    monkeypatch.setattr(e2e_harness.subprocess, "Popen",
                        lambda command, **kw: real([sys.executable, "-c", code[0]], **kw))
    harness = Harness(short_root)
    code[:] = ["import sys; print('chatty ' * 20000); sys.exit('broken config')"]
    with pytest.raises(RuntimeError, match="exited before binding: chatty"):
        e2e_harness.Daemon(harness, "auditd", "audit").__enter__()
    code[:] = ["import time; time.sleep(30)"]
    with pytest.raises(RuntimeError, match="before the stage's shared deadline"):
        e2e_harness.Daemon(harness, "auditd", "audit", deadline=time.monotonic() + 0.3).__enter__()
