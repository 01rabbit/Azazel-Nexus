"""The steps of the decoy namespace unit and the body of the network helper (#196, §13).

`az-decoy-netd` runs the fixed step lists of `decoy_network` and nothing
else. The namespace unit runs no Python since the G4 follow-up: its unit file
runs the fixed `ip` command lines of `hardening.DECOY_NAMESPACE_START` and
undoes them with `DECOY_NAMESPACE_UNDO` (`ExecStopPost=`). These tests pin,
with a fake executor for the helper (nothing here starts `ip` or `nft`,
creates a namespace or opens a socket):

* the exact commands of both units, as goldens, and their order;
* the exact nftables ruleset, as a golden, with nothing approved, and that it
  never replaces an existing table (`create table`);
* that the helper changes nothing when the bridge or the table already
  exists;
* that a failed step undoes exactly what the earlier steps made (and, after a
  timeout, what the step itself may have made), in reverse, and exits 1;
* the guard: while cutting the path fails, the rules stay, at start and stop;
* that `stop` runs every undo in reverse; that nothing else is accepted;
* that the process is started with an absolute path, a constant argument
  list from the module, an empty environment, `SIGPIPE` at its default, no
  shell and no pipe, and that the longest start fits in `TimeoutStartSec=`;
* that only the helper's two inspection commands are read back, through one
  pipe onto the child's standard output, bounded in time and size, and that
  the helper records them after it has built, undoing the build when the
  record does not pass (#196 §14; the checks themselves are in
  `test_decoy_isolation_evidence.py`);
* that the names, addresses and ports agree with the decoy (`decoy_netns`,
  `decoyd`), the decoy library and the unit profiles, and that the unit
  renderer takes them from the leaf `decoy_addresses`, never from the module
  that starts processes.

A run in a privileged container (§13) is a mechanism check, not VM or
hardware evidence; it is not part of this suite.
"""

from __future__ import annotations

import ast
import ipaddress
from pathlib import Path

import pytest

from azazel_nexus_runtime import decoy_netd, decoy_netns, decoy_network
from azazel_nexus_runtime.decoy_addresses import (
    BRIDGE,
    BRIDGE_ADDRESS,
    DECOY_ADDRESS,
    DECOY_PORTS,
    DECOY_SUBNET,
    HOST_VETH,
    NAMESPACE,
)
from azazel_nexus_runtime.decoy_network import (
    CAPTURE_LIMIT,
    HELPER_ABSENT,
    HELPER_PLAN,
    HELPER_STEPS,
    HELPER_VERIFY,
    IP,
    NFT,
    NFT_RULESET,
    STEP_SECONDS,
    TIMED_OUT,
)

RUNTIME = Path(__file__).resolve().parents[2] / "runtime" / "src" / "azazel_nexus_runtime"

#: The real read-back; the autouse `recorder` fixture replaces the module's.
REAL_CAPTURE = decoy_network.capture_fixed

# -- goldens --------------------------------------------------------------------

NSD_START = [
    ["/usr/bin/ip", "netns", "add", "azazel-decoy"],
    ["/usr/bin/ip", "link", "add", "name", "az-decoy-host0", "type", "veth",
     "peer", "name", "az-decoy-ns0", "netns", "azazel-decoy"],
    ["/usr/bin/ip", "-n", "azazel-decoy", "link", "set", "dev", "lo", "up"],
    ["/usr/bin/ip", "-n", "azazel-decoy", "address", "add", "10.255.196.2/30",
     "dev", "az-decoy-ns0"],
    ["/usr/bin/ip", "-n", "azazel-decoy", "link", "set", "dev", "az-decoy-ns0", "up"],
    ["/usr/bin/ip", "-n", "azazel-decoy", "route", "add", "default",
     "via", "10.255.196.1", "dev", "az-decoy-ns0"],
]
NSD_STOP = [
    ["/usr/bin/ip", "link", "delete", "az-decoy-host0"],
    ["/usr/bin/ip", "netns", "delete", "azazel-decoy"],
]

NETD_CHECKS = [
    ["/usr/bin/ip", "link", "show", "dev", "az-decoy0"],
    ["/usr/sbin/nft", "list", "table", "inet", "azazel_decoy"],
]
NETD_STEPS = [
    ["/usr/sbin/nft", NFT_RULESET],
    ["/usr/bin/ip", "link", "add", "name", "az-decoy0", "type", "bridge"],
    ["/usr/bin/ip", "address", "add", "10.255.196.1/30", "dev", "az-decoy0"],
    ["/usr/bin/ip", "link", "set", "dev", "az-decoy-host0", "master", "az-decoy0"],
    ["/usr/bin/ip", "link", "set", "dev", "az-decoy0", "up"],
    ["/usr/bin/ip", "link", "set", "dev", "az-decoy-host0", "up"],
]
NETD_START = NETD_CHECKS + NETD_STEPS
HOST_DOWN, BRIDGE_DELETE, TABLE_DELETE = NETD_STOP = [
    ["/usr/bin/ip", "link", "set", "dev", "az-decoy-host0", "down"],
    ["/usr/bin/ip", "link", "delete", "az-decoy0"],
    ["/usr/sbin/nft", "delete", "table", "inet", "azazel_decoy"],
]
#: The helper's read-back after it has built (#196 §14), in order.
NETD_VERIFY = [
    ["/usr/sbin/nft", "-j", "list", "table", "inet", "azazel_decoy"],
    ["/usr/bin/ip", "-j", "-d", "address", "show"],
]

RULESET = """create table inet azazel_decoy
table inet azazel_decoy {
\tset approved_v4 {
\t\ttype ipv4_addr
\t\tflags interval
\t}
\tchain forward {
\t\ttype filter hook forward priority filter; policy accept;
\t\toifname "az-decoy0" ip saddr @approved_v4 ip daddr 10.255.196.2 tcp dport { 2222, 2323, 8080 } accept
\t\toifname "az-decoy0" drop
\t\tiifname "az-decoy0" ip saddr 10.255.196.2 ip daddr @approved_v4 tcp sport { 2222, 2323, 8080 } ct state established accept
\t\tiifname "az-decoy0" drop
\t}
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t\tiifname "az-decoy0" drop
\t}
\tchain output {
\t\ttype filter hook output priority filter; policy accept;
\t\toifname "az-decoy0" drop
\t}
}
"""

#: The one executable left with a body here; the namespace unit's steps are
#: unit-file lines (G4 follow-up), pinned in the section below.
UNITS = [(decoy_netd, NETD_START, NETD_STOP)]
IDS = ["netd"]
UNIT_DIR = Path(__file__).resolve().parents[2] / "packaging" / "systemd"


def _unit_settings(name):
    found = {}
    for line in (UNIT_DIR / name).read_text(encoding="utf-8").splitlines():
        if not line or line.startswith(("#", "[")):
            continue
        key, _, value = line.partition("=")
        found.setdefault(key, []).append(value)
    return found


class FakeRunner:
    """Records every argv. A check finds nothing (exit 1) unless `present`;
    a command listed in `status` returns that status (by argv), else 0."""

    def __init__(self, status=None, present=()):
        self.calls: list[list[str]] = []
        self.status = {tuple(argv): code for argv, code in (status or {}).items()}
        self.present = {tuple(argv) for argv in present}

    def __call__(self, argv):
        assert isinstance(argv, tuple)
        self.calls.append(list(argv))
        if argv in HELPER_ABSENT:
            return 0 if argv in self.present else 1
        return self.status.get(argv, 0)


def _fail(argv, code=1):
    return {tuple(argv): code}


@pytest.fixture(autouse=True)
def _never_spawn(monkeypatch):
    """No test here may start a real process."""

    def refuse(*args, **kwargs):
        raise AssertionError("a test reached posix_spawn")

    monkeypatch.setattr(decoy_network.os, "posix_spawn", refuse)


class FakeRecorder:
    """Stands in for `decoy_isolation_check.Recorder`: records what it was
    asked, and answers each method with the given verdict."""

    def __init__(self, prepare=True, record=True, withdraw=True):
        self.events: list = []
        self.verdicts = {"prepare": prepare, "record": record, "withdraw": withdraw}

    def prepare(self):
        self.events.append("prepare")
        return self.verdicts["prepare"]

    def record(self, outputs, ruleset):
        self.events.append(("record", sorted(outputs)))
        self.ruleset = ruleset
        return self.verdicts["record"]

    def withdraw(self):
        self.events.append("withdraw")
        return self.verdicts["withdraw"]


@pytest.fixture(autouse=True)
def recorder(monkeypatch):
    """The helper's recorder and read-back, faked for every test here."""

    fake = FakeRecorder()
    fake.captured = []

    def capture(argv, *, plan):
        assert tuple(argv) in plan.read_back
        fake.captured.append(list(argv))
        return 0, b"listing"

    monkeypatch.setattr(decoy_netd, "Recorder", lambda: fake)
    monkeypatch.setattr(decoy_network, "capture_fixed", capture)
    return fake


def test_the_ruleset_is_the_golden():
    assert NFT_RULESET == RULESET
    # Never replaces or adds to an existing table: `create` fails if it exists.
    assert NFT_RULESET.splitlines()[0] == "create table inet azazel_decoy"
    assert "delete table" not in NFT_RULESET and "flush" not in NFT_RULESET


@pytest.mark.parametrize(("module", "start", "stop"), UNITS, ids=IDS)
def test_start_runs_exactly_the_golden_commands_in_order(module, start, stop, capsys, recorder):
    run = FakeRunner()
    assert module.main([], run=run) == 0
    assert run.calls == start
    assert "configured" in capsys.readouterr().err
    # Prepared before anything ran, read back and recorded after the build.
    assert recorder.events == ["prepare", ("record", ["host_links", "nft_table"])]
    assert recorder.captured == NETD_VERIFY


@pytest.mark.parametrize(("module", "start", "stop"), UNITS, ids=IDS)
def test_stop_runs_every_undo_in_reverse(module, start, stop, recorder):
    run = FakeRunner()
    assert module.main(["stop"], run=run) == 0
    assert run.calls == stop
    assert recorder.events == ["withdraw"]


# -- the isolation record (#196 §14) --------------------------------------------


def test_the_helper_changes_nothing_when_the_previous_record_cannot_be_cleared(
        recorder, capsys):
    recorder.verdicts["prepare"] = False
    run = FakeRunner()
    assert decoy_netd.main([], run=run) == 1
    assert run.calls == [] and recorder.captured == []
    assert recorder.events == ["prepare"]
    assert "nothing was changed" in capsys.readouterr().err


def test_a_record_that_does_not_pass_undoes_the_whole_build(recorder, capsys):
    recorder.verdicts["record"] = False
    run = FakeRunner()
    assert decoy_netd.main([], run=run) == 1
    assert run.calls == NETD_START + NETD_STOP
    assert recorder.captured == NETD_VERIFY
    assert "did not pass or was not recorded; undoing" in capsys.readouterr().err


@pytest.mark.parametrize("where", ["reader", "record"])
@pytest.mark.parametrize("error", [KeyError("flags"), OSError(5, "EIO"), ValueError("x")])
def test_an_error_while_reading_back_or_recording_undoes_the_build(
        recorder, monkeypatch, capsys, where, error):
    """Review of #274: the exception used to escape with the build in place."""

    def raising(*args):
        raise error

    if where == "reader":
        monkeypatch.setattr(decoy_network, "capture_fixed", raising)
    else:
        monkeypatch.setattr(recorder, "record", raising)
    run = FakeRunner()
    assert decoy_netd.main([], run=run) == 1
    assert run.calls == NETD_START + NETD_STOP
    assert "failed with an error; undoing" in capsys.readouterr().err


def test_a_failed_build_is_not_read_back_or_recorded(recorder):
    run = FakeRunner(status=_fail(NETD_STEPS[3]))
    assert decoy_netd.main([], run=run) == 1
    assert recorder.events == ["prepare"] and recorder.captured == []


def test_a_record_that_cannot_be_withdrawn_fails_the_stop_after_the_tear_down(
        recorder, capsys):
    recorder.verdicts["withdraw"] = False
    run = FakeRunner()
    assert decoy_netd.main(["stop"], run=run) == 1
    assert run.calls == NETD_STOP
    assert "could not be removed" in capsys.readouterr().err


def test_only_the_helper_reads_back_and_only_its_two_inspection_commands():
    assert [list(argv) for _, argv in HELPER_VERIFY] == NETD_VERIFY
    assert [name for name, _ in HELPER_VERIFY] == ["nft_table", "host_links"]
    # The table listing is the helper's second check in nftables' JSON form
    # (#196 G1b: its structure is compared, not its text).
    assert HELPER_VERIFY[0][1] == (NFT, "-j", *HELPER_ABSENT[1][1:])
    assert HELPER_PLAN.read_back == {tuple(argv) for argv in NETD_VERIFY}
    # The namespace unit reads nothing back: it runs no Python at all.
    assert not (RUNTIME / "decoy_nsd.py").exists()


# -- the helper changes nothing that is already there --------------------------


@pytest.mark.parametrize("present", [[NETD_CHECKS[0]], [NETD_CHECKS[1]], NETD_CHECKS],
                         ids=["bridge", "table", "both"])
def test_the_helper_changes_nothing_when_the_bridge_or_the_table_exists(present, capsys):
    run = FakeRunner(present=present)
    assert decoy_netd.main([], run=run) == 1
    # Only checks ran, up to the first that found something; no step, no undo.
    assert run.calls == NETD_CHECKS[:NETD_CHECKS.index(present[0]) + 1]
    assert "already present; nothing was changed" in capsys.readouterr().err


def test_an_existing_table_found_by_the_ruleset_itself_is_left_alone():
    """If the table appears between the check and the load, `create` fails:
    step 1 made nothing, so nothing is undone and the table stays."""

    run = FakeRunner(status=_fail(NETD_STEPS[0]))
    assert decoy_netd.main([], run=run) == 1
    assert run.calls == NETD_START[:3]
    assert TABLE_DELETE not in run.calls


def test_a_bridge_that_exists_at_step_2_does_not_cost_the_running_table():
    """Review of #273: step 2 failing (EEXIST) used to undo step 1 alone and
    leave the bridge without rules. Now the check refuses first; and if the
    bridge appears after it, the table is removed only because step 1 made
    it, and the existing bridge is never deleted."""

    run = FakeRunner(present=[NETD_CHECKS[0]])
    assert decoy_netd.main([], run=run) == 1
    assert TABLE_DELETE not in run.calls and BRIDGE_DELETE not in run.calls
    run = FakeRunner(status=_fail(NETD_STEPS[1]))
    assert decoy_netd.main([], run=run) == 1
    assert run.calls == NETD_START[:4] + [TABLE_DELETE]
    assert BRIDGE_DELETE not in run.calls


# -- failures, undo and the guard -----------------------------------------------


def _expected_after_failure(steps, failed_at, timed_out=False):
    done = list(steps[:failed_at + (1 if timed_out else 0)])
    return ([list(step.argv) for step in steps[:failed_at + 1]]
            + [list(step.undo) for step in reversed(done) if step.undo is not None])


@pytest.mark.parametrize("timed_out", [False, True], ids=["failed", "timed-out"])
@pytest.mark.parametrize("failed_at", range(6))
@pytest.mark.parametrize(("module", "steps", "checks"),
                         [(decoy_netd, HELPER_STEPS, NETD_CHECKS)], ids=IDS)
def test_a_failed_step_undoes_what_was_made_and_exits_1(module, steps, checks, failed_at,
                                                        timed_out, capsys, recorder):
    code = TIMED_OUT if timed_out else 1
    run = FakeRunner(status=_fail(steps[failed_at].argv, code))
    assert module.main([], run=run) == 1
    assert run.calls == checks + _expected_after_failure(steps, failed_at, timed_out)
    assert f"step {failed_at + 1} of 6 failed ({code})" in capsys.readouterr().err


def test_a_timed_out_bridge_is_removed_with_what_came_before():
    run = FakeRunner(status=_fail(NETD_STEPS[1], TIMED_OUT))
    assert decoy_netd.main([], run=run) == 1
    assert run.calls == NETD_START[:4] + [BRIDGE_DELETE, TABLE_DELETE]


def test_while_the_path_may_remain_the_rules_stay_at_start(capsys):
    run = FakeRunner(status={tuple(NETD_STEPS[5]): 1, tuple(BRIDGE_DELETE): 1})
    assert decoy_netd.main([], run=run) == 1
    assert run.calls == NETD_START + [BRIDGE_DELETE]
    assert TABLE_DELETE not in run.calls
    assert "1 undo step(s) failed; 1 guard(s) kept" in capsys.readouterr().err


@pytest.mark.parametrize("failing", [HOST_DOWN, BRIDGE_DELETE], ids=["host-end", "bridge"])
def test_while_the_path_may_remain_the_rules_stay_at_stop(failing, capsys):
    """Review of #273: stop used to delete the table after a failed bridge
    deletion (fail-open). Now the table goes only after the path is gone."""

    run = FakeRunner(status=_fail(failing))
    assert decoy_netd.main(["stop"], run=run) == 1
    assert run.calls == [HOST_DOWN, BRIDGE_DELETE]
    assert TABLE_DELETE not in run.calls
    assert "guard(s) kept" in capsys.readouterr().err


def test_a_failed_table_deletion_at_stop_is_reported():
    run = FakeRunner(status=_fail(TABLE_DELETE))
    assert decoy_netd.main(["stop"], run=run) == 1
    assert run.calls == NETD_STOP


def test_only_the_table_is_a_guard():
    assert [step.guard for step in HELPER_STEPS] == [True] + [False] * 5


@pytest.mark.parametrize("module", [decoy_netd], ids=IDS)
@pytest.mark.parametrize("argv", [["--namespace", "x"], ["/run/netns/other"], ["--force"],
                                  ["stop", "now"], ["start"], ["STOP"], [""]])
def test_anything_but_no_argument_or_stop_is_refused(module, argv, capsys):
    run = FakeRunner()
    assert module.main(argv, run=run) == 2
    assert run.calls == []
    assert "takes no argument" in capsys.readouterr().err


# -- what the commands are made of ---------------------------------------------


def test_every_command_is_ip_or_nft_by_absolute_path_with_constant_arguments():
    from azazel_nexus_runtime.hardening import (
        DECOY_NAMESPACE_IP,
        DECOY_NAMESPACE_START,
        DECOY_NAMESPACE_UNDO,
    )

    assert (IP, NFT) == ("/usr/bin/ip", "/usr/sbin/nft")
    for argv in HELPER_PLAN.allowed:
        assert argv[0] in (IP, NFT)
        assert all(isinstance(arg, str) and arg for arg in argv)
    # The namespace unit runs the same ip, and only ip.
    assert DECOY_NAMESPACE_IP == IP
    for argv in DECOY_NAMESPACE_START + DECOY_NAMESPACE_UNDO:
        assert argv[0] == IP
        assert all(isinstance(arg, str) and arg for arg in argv)
    # Only the namespace unit enters the namespace; the helper never does.
    assert all("-n" not in step.argv and "netns" != step.argv[1] for step in HELPER_STEPS)
    assert DECOY_NAMESPACE_START[0][1:3] == ("netns", "add")


def test_the_helper_loads_the_rules_before_it_makes_any_path():
    assert HELPER_STEPS[0].argv[0] == NFT
    assert all(step.argv[0] == IP for step in HELPER_STEPS[1:])


def test_nothing_is_approved_and_the_decoy_initiates_nothing():
    """Fail closed until the commissioned scope arrives (§7 Q9)."""

    assert "elements" not in NFT_RULESET
    assert "add element" not in NFT_RULESET
    accepts = [line.strip() for line in NFT_RULESET.splitlines() if line.strip().endswith("accept")
               and "policy" not in line]
    assert len(accepts) == 2
    assert all("@approved_v4" in line for line in accepts)
    # Outbound from the decoy: only the established replies to an approved peer.
    assert "ct state established accept" in accepts[1]
    for chain in ("forward", "input", "output"):
        assert f"chain {chain} {{" in NFT_RULESET


def test_the_longest_start_fits_in_the_units_start_timeout():
    """Review of #273: systemd must never kill a start half-undone."""

    from azazel_nexus_runtime.hardening import DECOY_HELPER_SANDBOX

    timeout = dict(DECOY_HELPER_SANDBOX)["TimeoutStartSec"]
    assert timeout == "30s"
    undos = sum(step.undo is not None for step in HELPER_STEPS)
    # The helper reads back after the build, and undoes all of it when the
    # record does not pass (#196 §14).
    commands = len(HELPER_ABSENT) + len(HELPER_STEPS) + len(HELPER_VERIFY) + undos
    # Each command is killed at STEP_SECONDS; the 0.01 s polls add little.
    assert commands * (STEP_SECONDS + 0.1) + 2 < 30, commands


# -- the namespace unit: fixed ip lines in its unit file (G4 follow-up) ----------


def test_the_namespace_unit_runs_exactly_the_golden_commands_in_order():
    from azazel_nexus_runtime.hardening import DECOY_NAMESPACE_START, DECOY_NAMESPACE_UNDO

    assert [list(argv) for argv in DECOY_NAMESPACE_START] == NSD_START
    assert [list(argv) for argv in DECOY_NAMESPACE_UNDO] == NSD_STOP
    settings = _unit_settings("azazel-decoy-nsd.service")
    # Six ExecStart= lines, one per step, in order; a one-shot unit stops at
    # the first that fails and fails the start.
    assert settings["ExecStart"] == [" ".join(argv) for argv in NSD_START]
    assert settings["Type"] == ["oneshot"]


def test_the_namespace_unit_undoes_in_reverse_after_a_stop_and_after_a_failed_start():
    """`ExecStopPost=`, not `ExecStop=`: systemd runs `ExecStop=` only after a
    start that succeeded, and `ExecStopPost=` after every stop and after a
    start that failed or timed out (systemd.service(5), systemd 257). The
    pair first, then the namespace; `-` on the pair only, because a failing
    command skips the ones after it and the pair is absent whenever the start
    failed before step 2."""

    settings = _unit_settings("azazel-decoy-nsd.service")
    assert "ExecStop" not in settings
    assert settings["ExecStopPost"] == ["-" + " ".join(NSD_STOP[0]), " ".join(NSD_STOP[1])]
    # The deadlines that replace the former 2 s per step: 30 s for the
    # start, up to 30 s per undo command (inferred; grant §11 item 4).
    assert settings["TimeoutStartSec"] == ["30s"]
    assert settings["TimeoutStopSec"] == ["30s"]
    # The undo covers every object a step makes: the pair and the namespace;
    # an address, a link state and a route go with their link or namespace.
    made = [argv for argv in NSD_START if argv[1:3] in (["netns", "add"], ["link", "add"])]
    assert len(made) == 2
    assert [argv[1] for argv in reversed(made)] == [argv[1] for argv in NSD_STOP]


@pytest.mark.parametrize("word", ["a b", "%n", "$X", "a;b", "'x'", '"x"', "a\\b", "", "--",
                                  "x\n"])
def test_a_namespace_command_line_takes_only_plain_words(word):
    from azazel_nexus_runtime.hardening import _command_line

    with pytest.raises(ValueError):
        _command_line((IP, "link", "delete", word))
    with pytest.raises(ValueError):
        _command_line(("/usr/sbin/ip", "netns", "add", "azazel-decoy"))
    assert _command_line((IP, "-n", "azazel-decoy", "link")) == "/usr/bin/ip -n azazel-decoy link"


def test_the_runner_starts_only_the_modules_commands_with_an_empty_environment(monkeypatch):
    seen = {}

    def spawn(path, argv, env, **kwargs):
        seen.update(path=path, argv=argv, env=env, kwargs=kwargs)
        return 4242

    monkeypatch.setattr(decoy_network.os, "posix_spawn", spawn)
    monkeypatch.setattr(decoy_network.os, "waitpid", lambda pid, flags: (pid, 0))
    assert decoy_network.run_fixed(tuple(NETD_CHECKS[0]), plan=HELPER_PLAN) == 0
    assert seen == {"path": IP, "argv": NETD_CHECKS[0], "env": {},
                    "kwargs": {"setsigdef": (decoy_network.signal.SIGPIPE,),
                               "file_actions": ()}}
    for plan in (HELPER_PLAN, decoy_network.verify_plan()):
        for argv in [("/bin/sh", "-c", "true"), ("ip", "netns", "add", NAMESPACE),
                     (IP, "netns", "add", "other"), (IP, "netns", "delete", "other"),
                     (NFT, "flush", "ruleset"), (NFT, "list", "ruleset"),
                     (IP, "link", "delete", "eth0")]:
            with pytest.raises(ValueError):
                decoy_network.run_fixed(argv, plan=plan)
    # The helper's plan holds none of the namespace unit's commands (#196
    # G1b: the plan replaced one module-wide allowance).
    for argv in NSD_START + NSD_STOP:
        with pytest.raises(ValueError):
            decoy_network.run_fixed(tuple(argv), plan=HELPER_PLAN)
    with pytest.raises(ValueError):
        decoy_network.run_fixed(tuple(NETD_CHECKS[0]), plan=None)
    assert HELPER_PLAN.allowed == {tuple(a) for a in NETD_START + NETD_STOP + NETD_VERIFY}


def test_the_read_back_refuses_every_other_command_before_a_process(monkeypatch):
    for argv in [NETD_CHECKS[0], NETD_STEPS[1], NSD_START[0], NETD_STOP[2],
                 ("/usr/bin/ip", "-j", "address", "show"),
                 ("/usr/sbin/nft", "list", "ruleset"),
                 ("/usr/sbin/nft", "list", "table", "inet", "azazel_decoy"),
                 ("/usr/bin/ip", "-n", "azazel-decoy", "-j", "-d", "address", "show")]:
        with pytest.raises(ValueError):
            REAL_CAPTURE(tuple(argv), plan=HELPER_PLAN)


class FakeChild:
    """A child process seen through the pipe: what it writes, when it exits."""

    def __init__(self, monkeypatch, *, output=b"", status=0, exits_after=0, clock=None):
        self.spawned, self.killed, self.closed = [], [], []
        self.output, self.status, self.exits_after = output, status, exits_after
        self.polls = 0
        self.read_fds = []

        def pipe():
            return 70, 71

        def spawn(path, argv, env, **kwargs):
            self.spawned.append((path, argv, env, kwargs))
            return 4242

        def read(fd, size):
            assert fd == 70
            self.read_fds.append(fd)
            if self.output:
                chunk, self.output = self.output[:size], self.output[size:]
                return chunk
            if self.polls < self.exits_after and not self.killed:
                raise BlockingIOError
            return b""

        def waitpid(pid, flags):
            self.polls += 1
            if self.killed:
                return pid, 9
            if flags and self.polls <= self.exits_after:
                return 0, 0
            return pid, self.status << 8

        monkeypatch.setattr(decoy_network.os, "pipe", pipe)
        monkeypatch.setattr(decoy_network.os, "posix_spawn", spawn)
        monkeypatch.setattr(decoy_network.os, "read", read)
        monkeypatch.setattr(decoy_network.os, "waitpid", waitpid)
        monkeypatch.setattr(decoy_network.os, "set_blocking", lambda fd, flag: None)
        monkeypatch.setattr(decoy_network.os, "close", self.closed.append)
        monkeypatch.setattr(decoy_network.os, "kill",
                            lambda pid, sig: self.killed.append((pid, sig)))
        monkeypatch.setattr(decoy_network.time, "sleep", lambda seconds: None)
        if clock is not None:
            monkeypatch.setattr(decoy_network.time, "monotonic", lambda: next(clock))


def test_the_read_back_spawns_with_one_pipe_onto_standard_output(monkeypatch):
    child = FakeChild(monkeypatch, output=b"table inet azazel_decoy {\n}\n")
    assert REAL_CAPTURE(tuple(NETD_VERIFY[0]), plan=HELPER_PLAN) == (
        0, b"table inet azazel_decoy {\n}\n")
    [(path, argv, env, kwargs)] = child.spawned
    assert (path, argv, env) == (NFT, NETD_VERIFY[0], {})
    assert kwargs == {"setsigdef": (decoy_network.signal.SIGPIPE,),
                      "file_actions": ((decoy_network.os.POSIX_SPAWN_DUP2, 71, 1),)}
    # The write end is closed right after the spawn, the read end at the end.
    assert child.closed == [71, 70]


def test_a_failed_read_back_returns_no_output(monkeypatch):
    FakeChild(monkeypatch, output=b"partial", status=1)
    assert REAL_CAPTURE(tuple(NETD_VERIFY[1]), plan=HELPER_PLAN) == (1, b"")


def test_a_read_back_past_the_limit_is_killed_and_returns_no_output(monkeypatch):
    child = FakeChild(monkeypatch, output=b"x" * (CAPTURE_LIMIT + 1), exits_after=10 ** 6)
    assert REAL_CAPTURE(tuple(NETD_VERIFY[1]), plan=HELPER_PLAN) == (decoy_network.OVERFLOW, b"")
    assert child.killed == [(4242, decoy_network.signal.SIGKILL)]


def test_a_read_back_past_its_deadline_is_killed(monkeypatch):
    clock = iter([0.0, 0.0, STEP_SECONDS + 1])
    child = FakeChild(monkeypatch, exits_after=10 ** 6, clock=clock)
    assert REAL_CAPTURE(tuple(NETD_VERIFY[0]), plan=HELPER_PLAN) == (TIMED_OUT, b"")
    assert child.killed == [(4242, decoy_network.signal.SIGKILL)]


@pytest.mark.parametrize("error", [OSError(5, "EIO"), KeyboardInterrupt()])
def test_an_error_while_reading_back_kills_and_reaps_the_child(monkeypatch, error):
    """Review of #274: an error inside the read loop left the child behind."""

    child = FakeChild(monkeypatch, exits_after=10 ** 6)
    reaped = []

    def broken_read(fd, size):
        raise error

    monkeypatch.setattr(decoy_network.os, "read", broken_read)
    monkeypatch.setattr(decoy_network.os, "waitpid",
                        lambda pid, flags: reaped.append((pid, flags)) or (pid, 9))
    with pytest.raises(type(error)):
        REAL_CAPTURE(tuple(NETD_VERIFY[0]), plan=HELPER_PLAN)
    assert child.killed == [(4242, decoy_network.signal.SIGKILL)]
    assert reaped == [(4242, 0)]
    assert child.closed == [71, 70]


def test_a_read_back_that_cannot_start_closes_both_ends(monkeypatch):
    child = FakeChild(monkeypatch)

    def missing(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(decoy_network.os, "posix_spawn", missing)
    assert REAL_CAPTURE(tuple(NETD_VERIFY[0]), plan=HELPER_PLAN) == (127, b"")
    assert child.closed == [71, 70]


def test_the_runner_kills_a_command_past_its_deadline(monkeypatch):
    killed = []
    clock = iter([0.0, 0.0, STEP_SECONDS + 1])
    monkeypatch.setattr(decoy_network.os, "posix_spawn", lambda *a, **k: 4242)
    monkeypatch.setattr(decoy_network.os, "waitpid", lambda pid, flags: (0, 0) if flags else (pid, 9))
    monkeypatch.setattr(decoy_network.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    monkeypatch.setattr(decoy_network.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(decoy_network.time, "sleep", lambda seconds: None)
    assert decoy_network.run_fixed(tuple(NETD_CHECKS[1]), plan=HELPER_PLAN) == TIMED_OUT == 124
    assert killed == [(4242, decoy_network.signal.SIGKILL)]


def test_a_program_that_cannot_be_started_is_a_failure(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(decoy_network.os, "posix_spawn", missing)
    assert decoy_network.run_fixed(tuple(NETD_CHECKS[0]), plan=HELPER_PLAN) == 127


def _tree(name):
    return ast.parse((RUNTIME / name).read_text(encoding="utf-8"))


def _imports(tree):
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add(("." * node.level) + (node.module or ""))
    return found


def _names(tree):
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    return names | {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}


def test_the_network_module_runs_one_spawn_with_no_shell_and_reads_no_environment():
    tree = _tree("decoy_network.py")
    # `ipaddress`, `json` and `re` render the scope's table (#196 G1b); the
    # module still imports nothing from the library, so the namespace unit
    # never loads the scope reader.
    assert _imports(tree) <= {"__future__", "ipaddress", "json", "os", "re", "signal",
                              "sys", "time", "dataclasses", "typing", ".decoy_netns",
                              ".decoy_addresses"}
    assert not _names(tree) & {"subprocess", "socket", "environ", "getenv", "environb",
                               "system", "popen", "execv", "execve", "execvp", "fork",
                               "spawnv", "Popen", "ctypes", "open", "setns", "unshare",
                               "sysctl", "pipe2", "dup", "dup2", "POSIX_SPAWN_OPEN",
                               "POSIX_SPAWN_CLOSE"}
    spawns = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
              and isinstance(node.func, ast.Attribute) and node.func.attr == "posix_spawn"]
    assert len(spawns) == 1
    call = spawns[0]
    assert [kw.arg for kw in call.keywords] == ["setsigdef", "file_actions"]
    assert ast.unparse(call.keywords[0].value) == "(signal.SIGPIPE,)"
    assert ast.unparse(call.args[0]) == "argv[0]"
    assert isinstance(call.args[2], ast.Dict) and not call.args[2].keys
    # One pipe, in the read-back only, and its one file action puts the write
    # end on the child's standard output; the steps run with none (#196 §14).
    pipes = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == "pipe"]
    assert len(pipes) == 1
    functions = {node.name: node for node in ast.walk(tree)
                 if isinstance(node, ast.FunctionDef)}
    assert pipes[0] in list(ast.walk(functions["capture_fixed"]))
    spawned = sorted(ast.unparse(node.args[1]) for node in ast.walk(tree)
                     if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                     and node.func.id == "_spawn")
    assert spawned == ["((os.POSIX_SPAWN_DUP2, write_end, 1),)", "()"]


def test_the_addresses_module_is_a_leaf():
    tree = _tree("decoy_addresses.py")
    assert _imports(tree) == {"__future__"}
    assert not any(isinstance(node, ast.Call) for node in ast.walk(tree)
                   if not isinstance(node, ast.Constant))


def test_the_unit_renderer_never_loads_the_module_that_starts_processes():
    """Review of #273: `hardening.py` takes the subnet from the leaf."""

    imports = _imports(_tree("hardening.py"))
    assert ".decoy_addresses" in imports
    assert not {".decoy_network", "azazel_nexus_runtime.decoy_network",
                ".decoy_nsd", ".decoy_netd"} & imports


def test_the_executable_only_chooses_its_step_list():
    tree = _tree("decoy_netd.py")
    # The helper also hands its isolation recorder to the runner (#196 §14),
    # reads its one input, the scope (#196 G1b), and hands `verify` to the
    # watch (#196 G2), choosing it from its arguments.
    extra = {".decoy_isolation_check", "azazel_nexus.decoy_scope", ".decoy_watch", "sys"}
    assert _imports(tree) == {"__future__", "typing", ".decoy_network"} | extra
    assert not _names(tree) & {"os", "subprocess", "socket", "environ", "open"}


# -- agreement with the decoy and the units ------------------------------------


def test_the_decoy_end_is_the_name_the_decoy_checks_for():
    from azazel_nexus_runtime import hardening

    assert hardening.DECOY_VETH is decoy_netns.DECOY_VETH
    assert decoy_netns.DECOY_VETH == "az-decoy-ns0"
    assert decoy_netns._ALLOWED_INTERFACES == {"lo", decoy_netns.DECOY_VETH}
    assert decoy_netns.DECOY_VETH in hardening.DECOY_NAMESPACE_START[1]
    assert f"/run/netns/{NAMESPACE}" == decoy_netns.DECOY_NAMESPACE_PATH
    for name in (BRIDGE, HOST_VETH, decoy_netns.DECOY_VETH):
        assert 0 < len(name.encode("ascii")) <= 15, name


def test_the_bridge_and_ports_are_the_decoys():
    from azazel_nexus.decoy import DECOY_BRIDGE, MIN_PORT
    from azazel_nexus_runtime.decoyd import SERVED

    assert BRIDGE == DECOY_BRIDGE
    assert DECOY_PORTS == tuple(decoy.port for decoy in SERVED)
    assert all(port >= MIN_PORT for port in DECOY_PORTS)


def test_the_addresses_are_the_two_hosts_of_the_fixed_subnet():
    subnet = ipaddress.ip_network(DECOY_SUBNET)
    assert subnet.prefixlen == 30 and subnet.is_private
    assert [str(host) for host in subnet.hosts()] == [BRIDGE_ADDRESS, DECOY_ADDRESS]


def test_the_units_name_the_same_namespace_subnet_and_stop_commands():
    from azazel_nexus_runtime.hardening import (
        DECOY_HELPER_SANDBOX,
        DECOY_NAMESPACE_PATH,
        DECOY_NAMESPACE_SANDBOX,
        PROFILES,
    )

    assert DECOY_NAMESPACE_PATH == decoy_netns.DECOY_NAMESPACE_PATH
    assert ("ExecStopPost", "/usr/bin/ip netns delete azazel-decoy") in DECOY_NAMESPACE_SANDBOX
    assert "ExecStop" not in dict(DECOY_NAMESPACE_SANDBOX)
    assert ("ExecStop", "/usr/libexec/azazel/az-decoy-netd stop") in DECOY_HELPER_SANDBOX
    decoy = next(p for p in PROFILES if p.unit == "azazel-decoyd.service")
    assert [v for k, v in decoy.extra if k == "IPAddressAllow"] == [DECOY_SUBNET]


def test_the_namespace_directory_is_made_traversable_for_the_decoy():
    """Review of #273: under the namespace unit's UMask=0027 `ip netns add`
    would make /run/netns 0750, and azdecoy could not stat the handle."""

    root = Path(__file__).resolve().parents[2]
    rule = (root / "packaging" / "tmpfiles.d" / "azazel-nexus-bootstrap.conf").read_text()
    assert "d /run/netns 0755 root root - -" in rule.splitlines()
    from azazel_nexus_runtime.hardening import NETNS_DIRECTORY, SHARED_HARDENING
    assert NETNS_DIRECTORY == "/run/netns"
    assert dict(SHARED_HARDENING)["UMask"] == "0027"
