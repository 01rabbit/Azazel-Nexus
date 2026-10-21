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
   host namespace with `CAP_NET_ADMIN` only, first checks that neither the
   bridge nor the table exists (`HELPER_ABSENT`), loads the fixed nftables
   table, then creates the bridge `az-decoy0`, gives it the host's fixed
   address, attaches the host end of the pair and brings both up.

Nobody waits for anybody: the veth pair exists before the helper starts,
because the namespace unit made it, and the helper is `After=` and
`Requires=` the namespace unit.

**What runs.** Only `IP` and `NFT`, by absolute path, and only an argument
list that is one of this module's constants (`run_fixed` refuses anything
else): no shell, no argument from a caller, an empty environment (nothing
here reads one), no output read back. The process is started with
`os.posix_spawn`, which needs no pipe: the namespace unit's system call
filter denies `@ipc` (pipes), and `subprocess` would need one. `SIGPIPE` is
reset to its default in the child.

**Fail closed.** Something already present that the helper would replace
stops it before it changes anything. A step that fails (or does not finish
within `STEP_SECONDS`) stops the start: what the earlier steps made is undone
in reverse (and, after a timeout, what the step itself may have made), and
the executable exits 1. `ExecStop=` runs every undo in reverse. In both, a
**guard** step's undo (the nftables table) runs only if every undo after it
succeeded: while the path may still exist, the rules stay.

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

from .decoy_addresses import (
    BRIDGE,
    BRIDGE_ADDRESS,
    DECOY_ADDRESS,
    DECOY_PORTS,
    HOST_VETH,
    NAMESPACE,
    NFT_TABLE,
    PREFIX_LENGTH,
)
from .decoy_netns import DECOY_VETH

__all__ = [
    "HELPER_ABSENT",
    "HELPER_STEPS",
    "IP",
    "NAMESPACE_ABSENT",
    "NAMESPACE_STEPS",
    "NFT",
    "NFT_RULESET",
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

#: How long one `ip` or `nft` may run. Short enough that the longest start
#: (checks, every step, every undo) fits in the units' `TimeoutStartSec=30s`
#: (a test checks it), so systemd never kills a start half-undone.
STEP_SECONDS = 2.0

_PORTS = ", ".join(str(port) for port in DECOY_PORTS)

#: The helper's ruleset, one nftables transaction. `create table` fails if
#: a table of that name exists, and then the whole transaction is refused:
#: an existing table is never replaced or added to. Every chain has
#: `policy accept` on purpose: this table only ever *drops* (an accept here
#: does not override a drop in another table), so it adds isolation and
#: never opens anything another table closes.
NFT_RULESET = f"""create table inet {NFT_TABLE}
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
    with its link, a link with its namespace). A `guard` step's undo runs
    only when every undo after it succeeded.
    """

    argv: tuple[str, ...]
    undo: Optional[tuple[str, ...]] = None
    guard: bool = False


def _ip(*args: str) -> tuple[str, ...]:
    return (IP, *args)


def _inside(*args: str) -> tuple[str, ...]:
    return (IP, "-n", NAMESPACE, *args)


#: `az-decoy-nsd` checks nothing first: `ip netns add` and the veth pair
#: each refuse to replace an existing one.
NAMESPACE_ABSENT: tuple[tuple[str, ...], ...] = ()

#: `az-decoy-nsd`: the namespace, the veth pair, and the inside.
NAMESPACE_STEPS: tuple[Step, ...] = (
    Step(_ip("netns", "add", NAMESPACE), _ip("netns", "delete", NAMESPACE)),
    Step(_ip("link", "add", "name", HOST_VETH, "type", "veth",
             "peer", "name", DECOY_VETH, "netns", NAMESPACE),
         _ip("link", "delete", HOST_VETH)),
    Step(_inside("link", "set", "dev", "lo", "up")),
    Step(_inside("address", "add", f"{DECOY_ADDRESS}/{PREFIX_LENGTH}",
                 "dev", DECOY_VETH)),
    Step(_inside("link", "set", "dev", DECOY_VETH, "up")),
    Step(_inside("route", "add", "default", "via", BRIDGE_ADDRESS,
                 "dev", DECOY_VETH)),
)

#: `az-decoy-netd` changes nothing while either exists (each must fail):
#: a bridge left behind would be one the rules it is about to load could be
#: undone under; a table is never replaced (`create table` is the second
#: line of defence).
HELPER_ABSENT: tuple[tuple[str, ...], ...] = (
    _ip("link", "show", "dev", BRIDGE),
    (NFT, "list", "table", "inet", NFT_TABLE),
)

#: `az-decoy-netd`: the rules first, then the bridge and the host end.
HELPER_STEPS: tuple[Step, ...] = (
    Step((NFT, NFT_RULESET), (NFT, "delete", "table", "inet", NFT_TABLE),
         guard=True),
    Step(_ip("link", "add", "name", BRIDGE, "type", "bridge"),
         _ip("link", "delete", BRIDGE)),
    Step(_ip("address", "add", f"{BRIDGE_ADDRESS}/{PREFIX_LENGTH}",
             "dev", BRIDGE)),
    Step(_ip("link", "set", "dev", HOST_VETH, "master", BRIDGE)),
    Step(_ip("link", "set", "dev", BRIDGE, "up")),
    Step(_ip("link", "set", "dev", HOST_VETH, "up"),
         _ip("link", "set", "dev", HOST_VETH, "down")),
)

#: Every argument list this module may start, and nothing else.
_ALLOWED: frozenset[tuple[str, ...]] = frozenset(
    argv
    for steps, absent in ((NAMESPACE_STEPS, NAMESPACE_ABSENT),
                          (HELPER_STEPS, HELPER_ABSENT))
    for argv in (*absent, *(s.argv for s in steps),
                 *(s.undo for s in steps if s.undo is not None))
)

Runner = Callable[[tuple[str, ...]], int]

#: What `run_fixed` returns for a command it killed, or could not start.
TIMED_OUT = 124
NOT_STARTED = 127


def run_fixed(argv: tuple[str, ...]) -> int:
    """Start one of this module's fixed commands; its exit status.

    Refuses any argument list that is not one of the module's constants.
    Empty environment, `SIGPIPE` at its default, no shell, no pipe, nothing
    read back: the program writes to the unit's journal stream. Killed after
    `STEP_SECONDS`.
    """

    if tuple(argv) not in _ALLOWED:
        raise ValueError("only this module's fixed commands are run")
    try:
        pid = os.posix_spawn(argv[0], list(argv), {}, setsigdef=(signal.SIGPIPE,))
    except OSError:
        return NOT_STARTED
    deadline = time.monotonic() + STEP_SECONDS
    while True:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            return os.waitstatus_to_exitcode(status)
        if time.monotonic() >= deadline:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            return TIMED_OUT
        time.sleep(0.01)


def _say(prog: str, text: str) -> None:
    print(f"{prog}: {text}", file=sys.stderr)


def bring_up(prog: str, steps: Sequence[Step], run: Runner,
             absent: Sequence[tuple[str, ...]] = ()) -> int:
    """Check, then run every step in order; on a failure undo, exit 1."""

    if absent:
        _say(prog, "checking that nothing is present; an ip or nft error just "
             "below is the expected answer")
    for index, argv in enumerate(absent):
        if run(argv) == 0:
            _say(prog, f"check {index + 1} of {len(absent)}: already present; "
                 "nothing was changed")
            return 1
    done: list[Step] = []
    for index, step in enumerate(steps):
        status = run(step.argv)
        if status != 0:
            # A step that timed out may have half-made its object; one that
            # failed outright made nothing (and may have failed because the
            # object already existed, which is not ours to remove).
            if status == TIMED_OUT:
                done.append(step)
            _say(prog, f"step {index + 1} of {len(steps)} failed ({status}); undoing")
            failed, kept = _undo(reversed(done), run)
            if failed or kept:
                _say(prog, f"{failed} undo step(s) failed; {kept} guard(s) kept")
            return 1
        done.append(step)
    _say(prog, f"configured ({len(steps)} steps)")
    return 0


def tear_down(prog: str, steps: Sequence[Step], run: Runner) -> int:
    """Run every undo in reverse; a guard only if all after it succeeded."""

    failed, kept = _undo(reversed(tuple(steps)), run)
    if failed or kept:
        _say(prog, f"{failed} undo step(s) failed; {kept} guard(s) kept")
        return 1
    _say(prog, "removed")
    return 0


def _undo(steps, run: Runner) -> tuple[int, int]:
    failed = kept = 0
    for step in steps:
        if step.undo is None:
            continue
        if step.guard and failed:
            kept += 1
            continue
        if run(step.undo) != 0:
            failed += 1
    return failed, kept


def main_for(prog: str, steps: Sequence[Step], argv: Optional[Sequence[str]],
             run: Optional[Runner], absent: Sequence[tuple[str, ...]] = ()) -> int:
    """`prog` takes no argument (start) or exactly `stop` (`ExecStop=`)."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    runner = run_fixed if run is None else run
    if not arguments:
        return bring_up(prog, steps, runner, absent)
    if arguments == ["stop"]:
        return tear_down(prog, steps, runner)
    _say(prog, "takes no argument but `stop`")
    return 2
