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
here reads one). The process is started with `os.posix_spawn`, which needs
no pipe: the namespace unit's system call filter denies `@ipc` (pipes), and
`subprocess` would need one. `SIGPIPE` is reset to its default in the child.

**What is read back** (#196 §14). Nothing, except the helper's two
inspection commands (`HELPER_VERIFY`), run by `capture_fixed` after the
helper has built the host side: their standard output goes through one pipe
into a bounded buffer (`CAPTURE_LIMIT`), and the helper's isolation recorder
(`decoy_isolation_check`) turns it into fixed results. Only the helper reads
anything back; the namespace unit never does, and its filter keeps denying
pipes. If the inspection does not pass, or its record cannot be written,
the helper undoes what it built and exits 1.

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
from typing import Callable, Optional, Protocol, Sequence

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
    "CAPTURE_LIMIT",
    "Capture",
    "HELPER_ABSENT",
    "HELPER_STEPS",
    "HELPER_VERIFY",
    "IP",
    "NAMESPACE_ABSENT",
    "NAMESPACE_STEPS",
    "NFT",
    "NFT_RULESET",
    "Runner",
    "STEP_SECONDS",
    "Step",
    "bring_up",
    "capture_fixed",
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

#: The helper's inspection after it has built the host side (#196 §14), by
#: fixed name: the table as the kernel holds it (the same argument list as
#: the second `HELPER_ABSENT` check), and every host link with its kind,
#: master, peer namespace and addresses (`-d` adds the link details to the
#: address listing). Two commands, so that the longest start, with the undo
#: after a failed inspection, still fits in `TimeoutStartSec=30s`. The only
#: commands whose output is read (`capture_fixed`).
HELPER_VERIFY: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("nft_table", (NFT, "list", "table", "inet", NFT_TABLE)),
    ("host_links", (IP, "-j", "-d", "address", "show")),
)

#: Every argument list this module may start, and nothing else.
_ALLOWED: frozenset[tuple[str, ...]] = frozenset(
    argv
    for steps, absent, verify in ((NAMESPACE_STEPS, NAMESPACE_ABSENT, ()),
                                  (HELPER_STEPS, HELPER_ABSENT, HELPER_VERIFY))
    for argv in (*absent, *(s.argv for s in steps),
                 *(s.undo for s in steps if s.undo is not None),
                 *(command for _, command in verify))
)

#: The argument lists whose output `capture_fixed` reads back.
_READ_BACK: frozenset[tuple[str, ...]] = frozenset(argv for _, argv in HELPER_VERIFY)

#: The most `capture_fixed` reads from one command. More is not the host
#: side of the decoy network as built; the command is killed and its output
#: counts as unreadable.
CAPTURE_LIMIT = 256 * 1024

Runner = Callable[[tuple[str, ...]], int]
#: `(status, standard output)`; the output is empty unless the status is 0.
Capture = Callable[[tuple[str, ...]], tuple[int, bytes]]

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
        pid = _spawn(tuple(argv), ())
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


def _spawn(argv: tuple[str, ...], actions: tuple) -> int:
    """The module's one process start: no shell, an empty environment."""

    return os.posix_spawn(argv[0], list(argv), {}, setsigdef=(signal.SIGPIPE,),
                          file_actions=actions)


#: What `capture_fixed` returns for output larger than `CAPTURE_LIMIT`.
OVERFLOW = 125


def capture_fixed(argv: tuple[str, ...]) -> tuple[int, bytes]:
    """Run one of `HELPER_VERIFY`'s commands; its status and standard output.

    Refuses any other argument list before a process is made. The output
    goes through one pipe (the child's descriptor 1, nothing else) into a
    buffer of at most `CAPTURE_LIMIT` bytes; standard error stays the unit's
    journal stream. Killed after `STEP_SECONDS`; then, past the limit, or on
    a non-zero exit, the output is empty.
    """

    argv = tuple(argv)
    if argv not in _READ_BACK:
        raise ValueError("only the helper's fixed inspection is read back")
    read_end, write_end = os.pipe()
    try:
        try:
            pid = _spawn(argv, ((os.POSIX_SPAWN_DUP2, write_end, 1),))
        except OSError:
            return NOT_STARTED, b""
        finally:
            os.close(write_end)
        try:
            os.set_blocking(read_end, False)
            return _collect(pid, read_end)
        except BaseException:
            # Never leave the child running or unreaped (review of #274): an
            # error here is a read-back that did not happen.
            _reap(pid)
            raise
    finally:
        os.close(read_end)


def _reap(pid: int) -> None:
    """Kill and reap `pid` if it is still ours; quiet if it is already gone."""

    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass


def _collect(pid: int, read_end: int) -> tuple[int, bytes]:
    """Read until end of file and exit, within the deadline and the limit."""

    deadline = time.monotonic() + STEP_SECONDS
    chunks: list[bytes] = []
    size, eof, status = 0, False, None
    while True:
        progressed = False
        if not eof:
            try:
                chunk: Optional[bytes] = os.read(read_end, 65536)
            except BlockingIOError:
                chunk = None
            if chunk == b"":
                eof = True
            elif chunk:
                progressed = True
                size += len(chunk)
                if size > CAPTURE_LIMIT:
                    if status is None:
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)
                    return OVERFLOW, b""
                chunks.append(chunk)
        if status is None:
            done, raw = os.waitpid(pid, os.WNOHANG)
            if done:
                status = os.waitstatus_to_exitcode(raw)
        if status is not None and eof:
            return (status, b"".join(chunks)) if status == 0 else (status, b"")
        if time.monotonic() >= deadline:
            if status is None:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            return TIMED_OUT, b""
        if not progressed:
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


class Recorder(Protocol):
    """The helper's isolation recorder (`decoy_isolation_check.Recorder`)."""

    def prepare(self) -> bool: ...

    def record(self, outputs: dict[str, tuple[int, bytes]]) -> bool: ...

    def withdraw(self) -> bool: ...


def main_for(prog: str, steps: Sequence[Step], argv: Optional[Sequence[str]],
             run: Optional[Runner], absent: Sequence[tuple[str, ...]] = (),
             *, recorder: Optional[Recorder] = None,
             capture: Optional[Capture] = None) -> int:
    """`prog` takes no argument (start) or exactly `stop` (`ExecStop=`).

    With a `recorder` (the helper only, #196 §14): at start, the previous
    record is removed and this boot's id read **before** anything is checked
    or built (either failing changes nothing, exit 1); after a successful
    build the `HELPER_VERIFY` commands are read back and recorded, and unless
    every check passed and the record was written, what was built is undone
    and the exit is 1. At stop, the record is removed first; a failure to
    remove it is reported and makes the stop exit 1, after the tear-down.
    """

    arguments = list(sys.argv[1:] if argv is None else argv)
    runner = run_fixed if run is None else run
    if not arguments:
        if recorder is not None and not recorder.prepare():
            _say(prog, "the previous isolation record could not be removed or this "
                 "boot's id could not be read; nothing was changed")
            return 1
        status = bring_up(prog, steps, runner, absent)
        if status or recorder is None:
            return status
        reader = capture_fixed if capture is None else capture
        try:
            outputs = {name: reader(command) for name, command in HELPER_VERIFY}
            recorded = recorder.record(outputs)
        except Exception:  # noqa: BLE001 - any error here undoes the build
            # Review of #274: an exception while reading back or recording
            # must not leave the build in place without a passing record.
            _say(prog, "the isolation check failed with an error; undoing")
            tear_down(prog, steps, runner)
            return 1
        if recorded:
            return 0
        _say(prog, "the isolation check did not pass or was not recorded; undoing")
        tear_down(prog, steps, runner)
        return 1
    if arguments == ["stop"]:
        withdrawn = recorder is None or recorder.withdraw()
        if not withdrawn:
            _say(prog, "the isolation record could not be removed")
        status = tear_down(prog, steps, runner)
        return status if withdrawn else 1
    _say(prog, "takes no argument but `stop`")
    return 2
