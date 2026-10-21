"""The bodies of the decoy namespace unit and the network helper (#196, §13).

`az-decoy-nsd` and `az-decoy-netd` run the fixed step lists of
`decoy_network` and nothing else. These tests pin, with a fake executor
(nothing here starts `ip` or `nft`, creates a namespace or opens a socket):

* the exact commands, as goldens, and their order;
* the exact nftables ruleset, as a golden, with nothing approved;
* that a failed step undoes exactly what the earlier steps made, in reverse,
  and exits 1; that `stop` runs every undo in reverse; that nothing else is
  accepted as an argument;
* that the process is started with an absolute path, a constant argument
  list, an empty environment, no shell and no pipe;
* that the names, addresses and ports agree with the decoy (`decoy_netns`,
  `decoyd`), the decoy library and the unit profiles.

A run in a privileged container (§13) is a mechanism check, not VM or
hardware evidence; it is not part of this suite.
"""

from __future__ import annotations

import ast
import ipaddress
from pathlib import Path

import pytest

from azazel_nexus_runtime import decoy_netd, decoy_netns, decoy_network, decoy_nsd
from azazel_nexus_runtime.decoy_network import (
    BRIDGE,
    BRIDGE_ADDRESS,
    DECOY_ADDRESS,
    DECOY_PORTS,
    DECOY_SUBNET,
    HELPER_STEPS,
    HOST_VETH,
    IP,
    NAMESPACE,
    NAMESPACE_STEPS,
    NFT,
    NFT_RULESET,
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

NETD_START = [
    ["/usr/sbin/nft", NFT_RULESET],
    ["/usr/bin/ip", "link", "add", "name", "az-decoy0", "type", "bridge"],
    ["/usr/bin/ip", "address", "add", "10.255.196.1/30", "dev", "az-decoy0"],
    ["/usr/bin/ip", "link", "set", "dev", "az-decoy-host0", "master", "az-decoy0"],
    ["/usr/bin/ip", "link", "set", "dev", "az-decoy0", "up"],
    ["/usr/bin/ip", "link", "set", "dev", "az-decoy-host0", "up"],
]
NETD_STOP = [
    ["/usr/bin/ip", "link", "set", "dev", "az-decoy-host0", "down"],
    ["/usr/bin/ip", "link", "delete", "az-decoy0"],
    ["/usr/sbin/nft", "delete", "table", "inet", "azazel_decoy"],
]

RULESET = """table inet azazel_decoy {}
delete table inet azazel_decoy
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
    """Records every argv; fails the calls whose index is in `failing`."""

    def __init__(self, failing=()):
        self.calls: list[list[str]] = []
        self.failing = set(failing)

    def __call__(self, argv):
        assert isinstance(argv, tuple)
        self.calls.append(list(argv))
        return 1 if len(self.calls) - 1 in self.failing else 0


@pytest.fixture(autouse=True)
def _never_spawn(monkeypatch):
    """No test here may start a real process."""

    def refuse(*args, **kwargs):
        raise AssertionError("a test reached posix_spawn")

    monkeypatch.setattr(decoy_network.os, "posix_spawn", refuse)


def test_the_ruleset_is_the_golden():
    assert NFT_RULESET == RULESET


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


@pytest.mark.parametrize(("module", "start", "stop"), UNITS, ids=IDS)
def test_stop_keeps_going_after_a_failed_undo_and_exits_1(module, start, stop):
    run = FakeRunner(failing={0})
    assert module.main(["stop"], run=run) == 1
    assert run.calls == stop


def _expected_after_failure(steps, failed_at):
    done = steps[:failed_at]
    return ([list(step.argv) for step in steps[:failed_at + 1]]
            + [list(step.undo) for step in reversed(done) if step.undo is not None])


@pytest.mark.parametrize("failed_at", range(6))
@pytest.mark.parametrize(("module", "steps"), [(decoy_nsd, NAMESPACE_STEPS),
                                               (decoy_netd, HELPER_STEPS)], ids=IDS)
def test_a_failed_step_undoes_what_was_made_and_exits_1(module, steps, failed_at, capsys):
    run = FakeRunner(failing={failed_at})
    assert module.main([], run=run) == 1
    assert run.calls == _expected_after_failure(steps, failed_at)
    assert f"step {failed_at + 1} of 6 failed" in capsys.readouterr().err


def test_a_failure_after_the_namespace_removes_it_and_nothing_else():
    run = FakeRunner(failing={1})
    assert decoy_nsd.main([], run=run) == 1
    assert run.calls == NSD_START[:2] + [NSD_STOP[1]]
    run = FakeRunner(failing={5})
    assert decoy_nsd.main([], run=run) == 1
    assert run.calls == NSD_START + NSD_STOP


def test_a_helper_failure_after_the_bridge_cuts_it_before_the_rules_go():
    run = FakeRunner(failing={3})
    assert decoy_netd.main([], run=run) == 1
    assert run.calls == NETD_START[:4] + NETD_STOP[1:]


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
    for step in NAMESPACE_STEPS + HELPER_STEPS:
        for argv in (step.argv, step.undo):
            if argv is None:
                continue
            assert argv[0] in (IP, NFT)
            assert all(isinstance(arg, str) and arg for arg in argv)
    # Only the namespace unit enters the namespace; the helper never does.
    assert all("-n" not in step.argv and "netns" != step.argv[1] for step in HELPER_STEPS)
    assert NAMESPACE_STEPS[0].argv[1:3] == ("netns", "add")


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


def test_the_runner_starts_only_ip_or_nft_with_an_empty_environment(monkeypatch):
    seen = {}

    def spawn(path, argv, env):
        seen.update(path=path, argv=argv, env=env)
        return 4242

    monkeypatch.setattr(decoy_network.os, "posix_spawn", spawn)
    monkeypatch.setattr(decoy_network.os, "waitpid", lambda pid, flags: (pid, 0))
    assert decoy_network.run_fixed(tuple(NSD_START[0])) == 0
    assert seen == {"path": IP, "argv": NSD_START[0], "env": {}}
    with pytest.raises(ValueError):
        decoy_network.run_fixed(("/bin/sh", "-c", "true"))
    with pytest.raises(ValueError):
        decoy_network.run_fixed(("ip", "netns", "add", NAMESPACE))


def test_the_runner_kills_a_command_past_its_deadline(monkeypatch):
    killed = []
    clock = iter([0.0, 0.0, decoy_network.STEP_SECONDS + 1])
    monkeypatch.setattr(decoy_network.os, "posix_spawn", lambda *a: 4242)
    monkeypatch.setattr(decoy_network.os, "waitpid", lambda pid, flags: (0, 0) if flags else (pid, 9))
    monkeypatch.setattr(decoy_network.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    monkeypatch.setattr(decoy_network.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(decoy_network.time, "sleep", lambda seconds: None)
    assert decoy_network.run_fixed((NFT, "list", "ruleset")) == 124
    assert killed == [(4242, decoy_network.signal.SIGKILL)]


def test_a_program_that_cannot_be_started_is_a_failure(monkeypatch):
    def missing(*args):
        raise FileNotFoundError

    monkeypatch.setattr(decoy_network.os, "posix_spawn", missing)
    assert decoy_network.run_fixed((IP, "netns", "add", NAMESPACE)) == 127


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
                              "typing", ".decoy_netns"}
    assert not _names(tree) & {"subprocess", "socket", "environ", "getenv", "environb",
                               "system", "popen", "execv", "execve", "execvp", "fork",
                               "spawnv", "Popen", "ctypes", "open", "setns", "unshare",
                               "pipe", "sysctl", "argv0"}
    spawns = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
              and isinstance(node.func, ast.Attribute) and node.func.attr == "posix_spawn"]
    assert len(spawns) == 1
    call = spawns[0]
    assert not call.keywords
    assert ast.unparse(call.args[0]) == "argv[0]"
    assert isinstance(call.args[2], ast.Dict) and not call.args[2].keys


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
