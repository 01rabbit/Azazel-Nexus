"""The bodies of the decoy namespace unit and the network helper (#196, §13).

`az-decoy-nsd` and `az-decoy-netd` run the fixed step lists of
`decoy_network` and nothing else. These tests pin, with a fake executor
(nothing here starts `ip` or `nft`, creates a namespace or opens a socket):

* the exact commands, as goldens, and their order;
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

from azazel_nexus_runtime import decoy_netd, decoy_netns, decoy_network, decoy_nsd
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
    HELPER_ABSENT,
    HELPER_STEPS,
    IP,
    NAMESPACE_STEPS,
    NFT,
    NFT_RULESET,
    STEP_SECONDS,
    TIMED_OUT,
)

RUNTIME = Path(__file__).resolve().parents[2] / "runtime" / "src" / "azazel_nexus_runtime"

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

UNITS = [(decoy_nsd, NSD_START, NSD_STOP), (decoy_netd, NETD_START, NETD_STOP)]
IDS = ["nsd", "netd"]


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


def test_the_ruleset_is_the_golden():
    assert NFT_RULESET == RULESET
    # Never replaces or adds to an existing table: `create` fails if it exists.
    assert NFT_RULESET.splitlines()[0] == "create table inet azazel_decoy"
    assert "delete table" not in NFT_RULESET and "flush" not in NFT_RULESET


@pytest.mark.parametrize(("module", "start", "stop"), UNITS, ids=IDS)
def test_start_runs_exactly_the_golden_commands_in_order(module, start, stop, capsys):
    run = FakeRunner()
    assert module.main([], run=run) == 0
    assert run.calls == start
    assert "configured" in capsys.readouterr().err


@pytest.mark.parametrize(("module", "start", "stop"), UNITS, ids=IDS)
def test_stop_runs_every_undo_in_reverse(module, start, stop):
    run = FakeRunner()
    assert module.main(["stop"], run=run) == 0
    assert run.calls == stop


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
                         [(decoy_nsd, NAMESPACE_STEPS, []),
                          (decoy_netd, HELPER_STEPS, NETD_CHECKS)], ids=IDS)
def test_a_failed_step_undoes_what_was_made_and_exits_1(module, steps, checks, failed_at,
                                                        timed_out, capsys):
    code = TIMED_OUT if timed_out else 1
    run = FakeRunner(status=_fail(steps[failed_at].argv, code))
    assert module.main([], run=run) == 1
    assert run.calls == checks + _expected_after_failure(steps, failed_at, timed_out)
    assert f"step {failed_at + 1} of 6 failed ({code})" in capsys.readouterr().err


def test_a_timed_out_bridge_is_removed_with_what_came_before():
    run = FakeRunner(status=_fail(NETD_STEPS[1], TIMED_OUT))
    assert decoy_netd.main([], run=run) == 1
    assert run.calls == NETD_START[:4] + [BRIDGE_DELETE, TABLE_DELETE]


def test_a_failure_after_the_namespace_removes_it_and_nothing_else():
    run = FakeRunner(status=_fail(NSD_START[1]))
    assert decoy_nsd.main([], run=run) == 1
    assert run.calls == NSD_START[:2] + [NSD_STOP[1]]
    run = FakeRunner(status=_fail(NSD_START[5]))
    assert decoy_nsd.main([], run=run) == 1
    assert run.calls == NSD_START + NSD_STOP


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


def test_the_namespace_stop_keeps_going_after_a_failed_link_deletion():
    """Deleting the namespace takes the pair with it; nothing is guarded here."""

    run = FakeRunner(status=_fail(NSD_STOP[0]))
    assert decoy_nsd.main(["stop"], run=run) == 1
    assert run.calls == NSD_STOP


def test_only_the_table_is_a_guard():
    assert [step.guard for step in HELPER_STEPS] == [True] + [False] * 5
    assert not any(step.guard for step in NAMESPACE_STEPS)


@pytest.mark.parametrize("module", [decoy_nsd, decoy_netd], ids=IDS)
@pytest.mark.parametrize("argv", [["--namespace", "x"], ["/run/netns/other"], ["--force"],
                                  ["stop", "now"], ["start"], ["STOP"], [""]])
def test_anything_but_no_argument_or_stop_is_refused(module, argv, capsys):
    run = FakeRunner()
    assert module.main(argv, run=run) == 2
    assert run.calls == []
    assert "takes no argument" in capsys.readouterr().err


# -- what the commands are made of ---------------------------------------------


def test_every_command_is_ip_or_nft_by_absolute_path_with_constant_arguments():
    assert (IP, NFT) == ("/usr/bin/ip", "/usr/sbin/nft")
    for argv in decoy_network._ALLOWED:
        assert argv[0] in (IP, NFT)
        assert all(isinstance(arg, str) and arg for arg in argv)
    # Only the namespace unit enters the namespace; the helper never does.
    assert all("-n" not in step.argv and "netns" != step.argv[1] for step in HELPER_STEPS)
    assert NAMESPACE_STEPS[0].argv[1:3] == ("netns", "add")
    assert decoy_network.NAMESPACE_ABSENT == ()


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

    from azazel_nexus_runtime.hardening import DECOY_HELPER_SANDBOX, DECOY_NAMESPACE_SANDBOX

    for sandbox, steps, checks in ((DECOY_NAMESPACE_SANDBOX, NAMESPACE_STEPS, ()),
                                   (DECOY_HELPER_SANDBOX, HELPER_STEPS, HELPER_ABSENT)):
        timeout = dict(sandbox)["TimeoutStartSec"]
        assert timeout == "30s"
        undos = sum(step.undo is not None for step in steps)
        commands = len(checks) + len(steps) + undos
        # Each command is killed at STEP_SECONDS; the 0.01 s polls add little.
        assert commands * (STEP_SECONDS + 0.1) + 2 < 30, commands


def test_the_runner_starts_only_the_modules_commands_with_an_empty_environment(monkeypatch):
    seen = {}

    def spawn(path, argv, env, **kwargs):
        seen.update(path=path, argv=argv, env=env, kwargs=kwargs)
        return 4242

    monkeypatch.setattr(decoy_network.os, "posix_spawn", spawn)
    monkeypatch.setattr(decoy_network.os, "waitpid", lambda pid, flags: (pid, 0))
    assert decoy_network.run_fixed(tuple(NSD_START[0])) == 0
    assert seen == {"path": IP, "argv": NSD_START[0], "env": {},
                    "kwargs": {"setsigdef": (decoy_network.signal.SIGPIPE,)}}
    for argv in [("/bin/sh", "-c", "true"), ("ip", "netns", "add", NAMESPACE),
                 (IP, "netns", "add", "other"), (IP, "netns", "delete", "other"),
                 (NFT, "flush", "ruleset"), (NFT, "list", "ruleset"),
                 (IP, "link", "delete", "eth0")]:
        with pytest.raises(ValueError):
            decoy_network.run_fixed(argv)
    every = ({tuple(a) for a in NSD_START + NSD_STOP + NETD_START + NETD_STOP})
    assert decoy_network._ALLOWED == every


def test_the_runner_kills_a_command_past_its_deadline(monkeypatch):
    killed = []
    clock = iter([0.0, 0.0, STEP_SECONDS + 1])
    monkeypatch.setattr(decoy_network.os, "posix_spawn", lambda *a, **k: 4242)
    monkeypatch.setattr(decoy_network.os, "waitpid", lambda pid, flags: (0, 0) if flags else (pid, 9))
    monkeypatch.setattr(decoy_network.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    monkeypatch.setattr(decoy_network.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(decoy_network.time, "sleep", lambda seconds: None)
    assert decoy_network.run_fixed(tuple(NETD_CHECKS[1])) == TIMED_OUT == 124
    assert killed == [(4242, decoy_network.signal.SIGKILL)]


def test_a_program_that_cannot_be_started_is_a_failure(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(decoy_network.os, "posix_spawn", missing)
    assert decoy_network.run_fixed(tuple(NSD_START[0])) == 127


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
    assert _imports(tree) <= {"__future__", "os", "signal", "sys", "time", "dataclasses",
                              "typing", ".decoy_netns", ".decoy_addresses"}
    assert not _names(tree) & {"subprocess", "socket", "environ", "getenv", "environb",
                               "system", "popen", "execv", "execve", "execvp", "fork",
                               "spawnv", "Popen", "ctypes", "open", "setns", "unshare",
                               "pipe", "sysctl"}
    spawns = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
              and isinstance(node.func, ast.Attribute) and node.func.attr == "posix_spawn"]
    assert len(spawns) == 1
    call = spawns[0]
    assert [kw.arg for kw in call.keywords] == ["setsigdef"]
    assert ast.unparse(call.keywords[0].value) == "(signal.SIGPIPE,)"
    assert ast.unparse(call.args[0]) == "argv[0]"
    assert isinstance(call.args[2], ast.Dict) and not call.args[2].keys


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


@pytest.mark.parametrize("name", ["decoy_nsd.py", "decoy_netd.py"])
def test_the_executables_only_choose_their_step_list(name):
    tree = _tree(name)
    assert _imports(tree) == {"__future__", "typing", ".decoy_network"}
    assert not _names(tree) & {"os", "subprocess", "socket", "environ", "open"}


# -- agreement with the decoy and the units ------------------------------------


def test_the_decoy_end_is_the_name_the_decoy_checks_for():
    assert decoy_network.DECOY_VETH is decoy_netns.DECOY_VETH
    assert decoy_netns.DECOY_VETH == "az-decoy-ns0"
    assert decoy_netns._ALLOWED_INTERFACES == {"lo", decoy_network.DECOY_VETH}
    assert f"/run/netns/{NAMESPACE}" == decoy_netns.DECOY_NAMESPACE_PATH
    for name in (BRIDGE, HOST_VETH, decoy_network.DECOY_VETH):
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
    assert ("ExecStop", "/usr/libexec/azazel/az-decoy-nsd stop") in DECOY_NAMESPACE_SANDBOX
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
