"""The Deception Lite network, fixed in code (#196 D1, option (a)).

`docs/deception-redirect-prerequisites.md` §5 D1, §10 and §13. Two one-shot
units build it and take it down, in this order, and in reverse on stop:

1. `az-decoy-nsd` (`azazel-decoy-nsd.service`, `NAMESPACE_STEPS`) creates the
   namespace `/run/netns/azazel-decoy`, creates the veth pair with the decoy's
   end (`DECOY_VETH`) placed directly into it, and configures the inside:
   `lo` up, the decoy's fixed address, its link up, its default route. Every
   one of those inside acts needs `CAP_NET_ADMIN` in the namespace, and
   reaching the inside (`ip -n`) needs `setns`, so `CAP_SYS_ADMIN`, and a
   private mount namespace for `ip`'s own `/sys`. Only that unit has both.
2. `az-decoy-netd` (`azazel-decoy-netd.service`, `HELPER_STEPS`), in the
   host namespace with `CAP_NET_ADMIN` only, loads the fixed nftables table
   **first**, then creates the bridge `az-decoy0`, gives it the host's fixed
   address, attaches the host end of the pair and brings both up.

Nobody waits for anybody: the veth pair exists before the helper starts,
because the namespace unit made it, and the helper is `After=` and
`Requires=` the namespace unit.

**What runs.** Only `IP` and `NFT`, by absolute path, with an argument list
that is a constant of this module: no shell, no argument from a caller, an
empty environment (nothing here reads one), no output read back. The process
is started with `os.posix_spawn`, which needs no pipe: the namespace unit's
system call filter denies `@ipc` (pipes), and `subprocess` would need one.

**Fail closed.** A step that fails (or does not finish within
`STEP_SECONDS`) stops the start: what the earlier steps made is undone in
reverse and the executable exits 1. `ExecStop=` runs every undo in reverse.

**What reaches the decoy.** The nftables table (`NFT_RULESET`) lets in only
TCP from a source in `approved_v4` to the decoy's address and its ports, and
lets out only the established replies to them. `approved_v4` is **empty**,
and nothing in this build adds to it: until the commissioned scope arrives
(§7 Q9), everything to and from the decoy is dropped, so a granted tier is
still unreachable from outside. The decoy's own unit adds a second wall:
`IPAddressDeny=any` with `IPAddressAllow=DECOY_SUBNET` only.
"""

from __future__ import annotations

import os
import signal
import sys
import time
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from .decoy_netns import DECOY_VETH

__all__ = [
    "BRIDGE",
    "BRIDGE_ADDRESS",
    "DECOY_ADDRESS",
    "DECOY_PORTS",
    "DECOY_SUBNET",
    "DECOY_VETH",
    "HELPER_STEPS",
    "HOST_VETH",
    "IP",
    "NAMESPACE",
    "NAMESPACE_STEPS",
    "NFT",
    "NFT_RULESET",
    "NFT_TABLE",
    "Runner",
    "STEP_SECONDS",
    "Step",
    "bring_up",
    "main_for",
    "run_fixed",
    "tear_down",
]

#: The two programs this module may start, by absolute path. `/usr/bin/ip`
#: is the file iproute2 installs on Debian 13 (`/usr/sbin/ip` is a link to
#: it); `/usr/sbin/nft` is nftables'.
IP = "/usr/bin/ip"
NFT = "/usr/sbin/nft"

#: The namespace name; its handle is `decoy_netns.DECOY_NAMESPACE_PATH`.
NAMESPACE = "azazel-decoy"

#: The bridge the decoy lives on (`azazel_nexus.decoy.DECOY_BRIDGE`).
BRIDGE = "az-decoy0"

#: The host's end of the veth pair. At most 15 bytes (`IFNAMSIZ`).
HOST_VETH = "az-decoy-host0"

#: The decoy network: a /30, the bridge (host) and the decoy, nothing else.
#: Fixed in code until the commissioned bridge prefix reaches the units.
DECOY_SUBNET = "10.255.196.0/30"
BRIDGE_ADDRESS = "10.255.196.1"
DECOY_ADDRESS = "10.255.196.2"
_PREFIX_LENGTH = "30"

#: The decoy's ports (`decoyd.SERVED`; a test keeps them equal).
DECOY_PORTS: tuple[int, ...] = (2222, 2323, 8080)

#: The host's nftables table, created and deleted whole.
NFT_TABLE = "azazel_decoy"

#: How long one `ip` or `nft` may run.
STEP_SECONDS = 5.0

_PORTS = ", ".join(str(port) for port in DECOY_PORTS)

#: The helper's ruleset, one nftables transaction. The first two lines make
#: it replace a table of the same name instead of adding to it. Every chain
#: has `policy accept` on purpose: this table only ever *drops* (an accept
#: here does not override a drop in another table), so it adds isolation and
#: never opens anything another table closes.
NFT_RULESET = f"""table inet {NFT_TABLE} {{}}
delete table inet {NFT_TABLE}
table inet {NFT_TABLE} {{
\tset approved_v4 {{
\t\ttype ipv4_addr
\t\tflags interval
\t}}
\tchain forward {{
\t\ttype filter hook forward priority filter; policy accept;
\t\toifname "{BRIDGE}" ip saddr @approved_v4 ip daddr {DECOY_ADDRESS} tcp dport {{ {_PORTS} }} accept
\t\toifname "{BRIDGE}" drop
\t\tiifname "{BRIDGE}" ip saddr {DECOY_ADDRESS} ip daddr @approved_v4 tcp sport {{ {_PORTS} }} ct state established accept
\t\tiifname "{BRIDGE}" drop
\t}}
\tchain input {{
\t\ttype filter hook input priority filter; policy accept;
\t\tiifname "{BRIDGE}" drop
\t}}
\tchain output {{
\t\ttype filter hook output priority filter; policy accept;
\t\toifname "{BRIDGE}" drop
\t}}
}}
"""


@dataclass(frozen=True)
class Step:
    """One fixed command, and the fixed command that undoes it (if any).

    A step without an undo is undone by an earlier step's (an address goes
    with its link, a link with its namespace).
    """

    argv: tuple[str, ...]
    undo: Optional[tuple[str, ...]] = None


def _ip(*args: str) -> tuple[str, ...]:
    return (IP, *args)


def _inside(*args: str) -> tuple[str, ...]:
    return (IP, "-n", NAMESPACE, *args)


#: `az-decoy-nsd`: the namespace, the veth pair, and the inside.
NAMESPACE_STEPS: tuple[Step, ...] = (
    Step(_ip("netns", "add", NAMESPACE), _ip("netns", "delete", NAMESPACE)),
    Step(_ip("link", "add", "name", HOST_VETH, "type", "veth",
             "peer", "name", DECOY_VETH, "netns", NAMESPACE),
         _ip("link", "delete", HOST_VETH)),
    Step(_inside("link", "set", "dev", "lo", "up")),
    Step(_inside("address", "add", f"{DECOY_ADDRESS}/{_PREFIX_LENGTH}",
                 "dev", DECOY_VETH)),
    Step(_inside("link", "set", "dev", DECOY_VETH, "up")),
    Step(_inside("route", "add", "default", "via", BRIDGE_ADDRESS,
                 "dev", DECOY_VETH)),
)

#: `az-decoy-netd`: the rules first, then the bridge and the host end.
HELPER_STEPS: tuple[Step, ...] = (
    Step((NFT, NFT_RULESET), (NFT, "delete", "table", "inet", NFT_TABLE)),
    Step(_ip("link", "add", "name", BRIDGE, "type", "bridge"),
         _ip("link", "delete", BRIDGE)),
    Step(_ip("address", "add", f"{BRIDGE_ADDRESS}/{_PREFIX_LENGTH}",
             "dev", BRIDGE)),
    Step(_ip("link", "set", "dev", HOST_VETH, "master", BRIDGE)),
    Step(_ip("link", "set", "dev", BRIDGE, "up")),
    Step(_ip("link", "set", "dev", HOST_VETH, "up"),
         _ip("link", "set", "dev", HOST_VETH, "down")),
)

Runner = Callable[[tuple[str, ...]], int]


def run_fixed(argv: tuple[str, ...]) -> int:
    """Start `argv[0]` with `argv` and an empty environment; its exit status.

    Only `IP` and `NFT`. No shell, no pipe, nothing read back: the program
    writes to the unit's journal stream. Killed after `STEP_SECONDS`.
    """

    if argv[0] not in (IP, NFT):
        raise ValueError("only ip and nft are run")
    try:
        pid = os.posix_spawn(argv[0], list(argv), {})
    except OSError:
        return 127
    deadline = time.monotonic() + STEP_SECONDS
    while True:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            return os.waitstatus_to_exitcode(status)
        if time.monotonic() >= deadline:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            return 124
        time.sleep(0.01)


def _say(prog: str, text: str) -> None:
    print(f"{prog}: {text}", file=sys.stderr)


def bring_up(prog: str, steps: Sequence[Step], run: Runner) -> int:
    """Run every step in order; on the first failure undo the done ones, exit 1."""

    done: list[Step] = []
    for index, step in enumerate(steps):
        status = run(step.argv)
        if status != 0:
            _say(prog, f"step {index + 1} of {len(steps)} failed ({status}); undoing")
            _undo(prog, reversed(done), run)
            return 1
        done.append(step)
    _say(prog, f"configured ({len(steps)} steps)")
    return 0


def tear_down(prog: str, steps: Sequence[Step], run: Runner) -> int:
    """Run every undo in reverse, all of them; exit 1 if any failed."""

    failed = _undo(prog, reversed(tuple(steps)), run)
    if failed:
        _say(prog, f"{failed} undo step(s) failed")
        return 1
    _say(prog, "removed")
    return 0


def _undo(prog: str, steps, run: Runner) -> int:
    failed = 0
    for step in steps:
        if step.undo is not None and run(step.undo) != 0:
            failed += 1
    return failed


def main_for(prog: str, steps: Sequence[Step], argv: Optional[Sequence[str]],
             run: Optional[Runner]) -> int:
    """`prog` takes no argument (start) or exactly `stop` (`ExecStop=`)."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    runner = run_fixed if run is None else run
    if not arguments:
        return bring_up(prog, steps, runner)
    if arguments == ["stop"]:
        return tear_down(prog, steps, runner)
    _say(prog, "takes no argument but `stop`")
    return 2

