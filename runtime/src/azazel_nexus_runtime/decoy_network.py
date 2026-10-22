"""The Deception Lite network, fixed in code (#196 D1, option (a)).

`docs/deception-redirect-prerequisites.md` §5 D1, §10 and §13. Two one-shot
units build it and take it down, in this order, and in reverse on stop:

1. `azazel-decoy-nsd.service` creates the namespace `/run/netns/azazel-decoy`,
   creates the veth pair with the decoy's end placed directly into it, and
   configures the inside: `lo` up, the decoy's fixed address, its link up,
   its default route. Every one of those inside acts needs `CAP_NET_ADMIN`
   in the namespace, and reaching the inside (`ip -n`) needs `setns`, so
   `CAP_SYS_ADMIN`, and a private mount namespace for `ip`'s own `/sys`.
   Only that unit has both. It runs no Python and nothing of this module:
   its unit file runs the fixed `ip` commands itself
   (`hardening.DECOY_NAMESPACE_START`, undone by `DECOY_NAMESPACE_UNDO`;
   G4 follow-up, `docs/deception-exposure-grant.md` §11), so that only `ip`
   ever holds its two capabilities.
2. `az-decoy-netd` (`azazel-decoy-netd.service`, `HELPER_STEPS`), in the
   host namespace with `CAP_NET_ADMIN` only, first checks that neither the
   bridge nor the table exists (`HELPER_ABSENT`), loads the fixed nftables
   table, then creates the bridge `az-decoy0`, gives it the host's fixed
   address, attaches the host end of the pair and brings both up.

Nobody waits for anybody: the veth pair exists before the helper starts,
because the namespace unit made it, and the helper is `After=` and
`Requires=` the namespace unit.

**What runs.** Only `IP` and `NFT`, by absolute path, and only an argument
list in the run's `Plan` (`run_fixed` refuses anything else): the module's
constants, and for the helper exactly one more, the ruleset rendered from
the run's scope (#196 G1b). No shell, no argument list from a caller, an
empty environment (nothing here reads one). The process is started with
`os.posix_spawn`, which needs no pipe for a step (`subprocess` would make
one). `SIGPIPE` is reset to its default in the child.

**What is read back** (#196 §14). Nothing, except the helper's two
inspection commands (`HELPER_VERIFY`), run by `capture_fixed` after the
helper has built the host side: their standard output goes through one pipe
into a bounded buffer (`CAPTURE_LIMIT`), and the helper's isolation recorder
(`decoy_isolation_check`) turns it into fixed results. Only the helper (and
its verify unit, #196 G2) reads anything back. If the inspection does not pass, or its record cannot be written,
the helper undoes what it built and exits 1.

**Fail closed.** Something already present that the helper would replace
stops it before it changes anything. A step that fails (or does not finish
within `STEP_SECONDS`) stops the start: what the earlier steps made is undone
in reverse (and, after a timeout, what the step itself may have made), and
the executable exits 1. `ExecStop=` runs every undo in reverse. In both, a
**guard** step's undo (the nftables table) runs only if every undo after it
succeeded: while the path may still exist, the rules stay.

**What reaches the decoy.** The nftables table (`render_ruleset`) lets in
only TCP from a source in `approved_v4` to the decoy's address and its
ports, and lets out only the established replies to them. Without a scope
`approved_v4` is **empty** (`NFT_RULESET`, the table of the first build), so
everything to and from the decoy is dropped. With the scope the helper
receives (`docs/deception-exposure-grant.md` §4.3, §4.4; G1b), the set holds
the approved prefixes, the accept requires an ingress interface, the reply
must leave by one, anything else from an ingress is dropped (reachability
R3), and approved traffic is masqueraded to the bridge address on its way in
(A3). The decoy's own unit adds a second wall: `IPAddressDeny=any` with
`IPAddressAllow=DECOY_SUBNET` only.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol, Sequence

from .decoy_addresses import (
    BRIDGE,
    BRIDGE_ADDRESS,
    DECOY_ADDRESS,
    DECOY_PORTS,
    HOST_VETH,
    NFT_TABLE,
    PREFIX_LENGTH,
)

__all__ = [
    "APPROVED_SET",
    "CAPTURE_LIMIT",
    "Capture",
    "HELPER_ABSENT",
    "HELPER_PLAN",
    "HELPER_STEPS",
    "HELPER_VERIFY",
    "IP",
    "MAX_INGRESS",
    "MAX_PREFIXES",
    "NFT",
    "NFT_RULESET",
    "Plan",
    "Ruleset",
    "Runner",
    "STEP_SECONDS",
    "Step",
    "bring_up",
    "canonical_json",
    "capture_fixed",
    "helper_plan",
    "helper_steps",
    "main_for",
    "render_ruleset",
    "run_fixed",
    "tear_down",
    "verify_plan",
    "WATCH_READS",
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

#: The most approved prefixes and ingress interfaces a scope holds
#: (`azazel_nexus.decoy_scope.MAX_PREFIXES` and `MAX_INGRESS`; a test keeps
#: them equal: this module does not import the library).
MAX_PREFIXES = 16
MAX_INGRESS = 4

#: The renderer's own check repeats the decoder's rules (review of #286 F3),
#: so that nothing the decoder would refuse reaches the nftables text even if
#: a caller hands it something else. The values are copies of
#: `azazel_nexus.decoy_scope`'s (this module does not import the library, so
#: that the helper's closure stays its pinned runtime modules); a test keeps
#: them equal.
#:
#: Interface names: the characters, the decoy network's own prefix, a leading
#: `-`, an all-digit name (an interface index to nftables), and the reserved
#: names, all compared without case.
_IFNAME = re.compile(r"[A-Za-z0-9_.-]{1,15}", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_RESERVED_IFNAME_PREFIX = "az-decoy"
_RESERVED_IFNAMES = frozenset({"lo", "all", "default", ".", ".."})
#: Prefixes: inside RFC 1918, and clear of the decoy network's /24.
_PRIVATE_V4 = tuple(ipaddress.IPv4Network(block)
                    for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_RESERVED_HEADROOM = ipaddress.IPv4Network("10.255.196.0/24")


def _name_allowed(name: object) -> bool:
    return (type(name) is str and _IFNAME.fullmatch(name) is not None
            and name.lower() not in _RESERVED_IFNAMES and not name.startswith("-")
            and not name.isdigit() and not name.lower().startswith(_RESERVED_IFNAME_PREFIX))


def _prefix_allowed(network: object) -> bool:
    return (type(network) is ipaddress.IPv4Network
            and any(network.subnet_of(block) for block in _PRIVATE_V4)
            and not network.overlaps(_RESERVED_HEADROOM))

#: The named set the approved sources live in.
APPROVED_SET = "approved_v4"


class ScopeLike(Protocol):
    """What the renderer reads of `azazel_nexus.decoy_scope.ScopeFile`."""

    approved_v4: tuple[ipaddress.IPv4Network, ...]
    ingress: tuple[str, ...]
    scope_digest: str


@dataclass(frozen=True)
class Ruleset:
    """The helper's table for one scope, as loaded and as listed (#196 G1b).

    `text` is the one `nft` argument (one transaction); `expected` is the
    canonical JSON of what `nft -j list table` must show for it, without
    handles (`decoy_isolation_check` compares the two). Both come from one
    rendering of the same rules, so they cannot differ in what they say.
    """

    text: str
    expected: str
    #: `str(IPv4Network)` of each approved prefix, in order; empty with no scope.
    approved_v4: tuple[str, ...]
    #: The ingress interface names, sorted; empty with no scope.
    ingress: tuple[str, ...]
    #: `sha256:<hex>` of the scope file; `None` with no scope.
    scope_digest: Optional[str]


#: One term of a rule: its nftables text and its `nft -j` expression.
_Term = tuple[str, dict]


def _meta(key: str, value, op: str = "==") -> _Term:
    """`iifname`/`oifname`: one fixed name, or an anonymous set of quoted names.

    Every name is quoted. nftables lists an anonymous set of one element as
    the element itself (container-checked, nftables 1.1.3), so the expected
    listing does too; the text keeps the braces.
    """

    if type(value) is tuple:
        text = f"{key} {{ " + ", ".join(f'"{name}"' for name in value) + " }"
        right = value[0] if len(value) == 1 else {"set": sorted(value)}
    else:
        text = f'{key} != "{value}"' if op == "!=" else f'{key} "{value}"'
        right = value
    return text, {"match": {"op": op, "left": {"meta": {"key": key}}, "right": right}}


def _payload(protocol: str, field: str, value) -> _Term:
    if type(value) is tuple:
        text = f"{protocol} {field} {{ " + ", ".join(str(port) for port in value) + " }"
        right = value[0] if len(value) == 1 else {"set": sorted(value)}
    else:
        text, right = f"{protocol} {field} {value}", value
    return text, {"match": {"op": "==",
                            "left": {"payload": {"protocol": protocol, "field": field}},
                            "right": right}}


_ESTABLISHED: _Term = ("ct state established",
                       {"match": {"op": "in", "left": {"ct": {"key": "state"}},
                                  "right": "established"}})


def _verdict(word: str) -> _Term:
    return word, {word: None}


def _chains(ingress: tuple[str, ...]) -> list[tuple[str, str, str, str, int, list]]:
    """`(name, type, hook, priority, prio, rules)` of every chain, in order.

    With a scope (#196 G1b, grant §4.4, reachability R3): the accept toward
    the decoy also requires an ingress interface; the reply accept also
    requires leaving by one; a packet from an ingress to anywhere but the
    bridge is dropped (K2, the second wall behind the operator's routing
    rules); and approved traffic entering the bridge is masqueraded to the
    bridge's address (A3), so the decoy's own cgroup filter keeps its fixed
    /30. Without a scope, exactly the rules of the first build.
    """

    to_decoy = [_meta("oifname", BRIDGE), _payload("ip", "saddr", f"@{APPROVED_SET}"),
                _payload("ip", "daddr", DECOY_ADDRESS), _payload("tcp", "dport", DECOY_PORTS),
                _verdict("accept")]
    reply = [_meta("iifname", BRIDGE), _payload("ip", "saddr", DECOY_ADDRESS),
             _payload("ip", "daddr", f"@{APPROVED_SET}"), _payload("tcp", "sport", DECOY_PORTS),
             _ESTABLISHED, _verdict("accept")]
    forward = [to_decoy, [_meta("oifname", BRIDGE), _verdict("drop")],
               reply, [_meta("iifname", BRIDGE), _verdict("drop")]]
    if ingress:
        to_decoy.insert(0, _meta("iifname", ingress))
        reply.insert(1, _meta("oifname", ingress))
        forward.append([_meta("iifname", ingress), _meta("oifname", BRIDGE, "!="),
                        _verdict("drop")])
    chains = [
        ("forward", "filter", "forward", "filter", 0, forward),
        ("input", "filter", "input", "filter", 0,
         [[_meta("iifname", BRIDGE), _verdict("drop")]]),
        ("output", "filter", "output", "filter", 0,
         [[_meta("oifname", BRIDGE), _verdict("drop")]]),
    ]
    if ingress:
        chains.append(("postrouting", "nat", "postrouting", "srcnat", 100,
                       [[_meta("oifname", BRIDGE),
                         _payload("ip", "saddr", f"@{APPROVED_SET}"),
                         _verdict("masquerade")]]))
    return chains


def _element(network: ipaddress.IPv4Network):
    """An interval set element as `nft -j` lists it: a /32 as a bare address."""

    if network.prefixlen == 32:
        return str(network.network_address)
    return {"prefix": {"addr": str(network.network_address), "len": network.prefixlen}}


def _checked(scope: ScopeLike) -> tuple[tuple[ipaddress.IPv4Network, ...], tuple[str, ...], str]:
    """The scope's three fields, or `ValueError` (a fixed phrase only)."""

    approved, ingress, digest = scope.approved_v4, scope.ingress, scope.scope_digest
    if (type(approved) is not tuple or not 1 <= len(approved) <= MAX_PREFIXES
            or not all(_prefix_allowed(network) for network in approved)):
        raise ValueError("the scope's prefixes are not 1 to 16 allowed IPv4 networks")
    for before, after in zip(approved, approved[1:]):
        if int(before.broadcast_address) + 1 >= int(after.network_address):
            raise ValueError("the scope's prefixes are not sorted apart")
    if (type(ingress) is not tuple or not 1 <= len(ingress) <= MAX_INGRESS
            or not all(_name_allowed(name) for name in ingress)
            or list(ingress) != sorted(set(ingress))):
        raise ValueError("the scope's ingress names are not 1 to 4 allowed names")
    if type(digest) is not str or not _DIGEST.fullmatch(digest):
        raise ValueError("the scope's digest is not a SHA-256 digest")
    return approved, ingress, digest


def render_ruleset(scope: Optional[ScopeLike] = None) -> Ruleset:
    """The helper's table for `scope`: the one function both sides use.

    `scope` is what `azazel_nexus.decoy_scope.read_scope_file` returned, or
    `None`: no scope, the constant table of the first build, with
    `approved_v4` empty, so nothing reaches the decoy. Only
    `str(IPv4Network)` and the checked names reach the text, every name
    quoted. Raises `ValueError` for anything else.
    """

    if scope is None:
        approved: tuple[ipaddress.IPv4Network, ...] = ()
        ingress: tuple[str, ...] = ()
        digest: Optional[str] = None
    else:
        approved, ingress, digest = _checked(scope)
    lines = [f"create table inet {NFT_TABLE}", f"table inet {NFT_TABLE} {{",
             f"\tset {APPROVED_SET} {{", "\t\ttype ipv4_addr", "\t\tflags interval"]
    the_set = {"family": "inet", "name": APPROVED_SET, "table": NFT_TABLE,
               "type": "ipv4_addr", "flags": ["interval"]}
    if approved:
        lines.append("\t\telements = { " + ", ".join(str(n) for n in approved) + " }")
        the_set["elem"] = [_element(network) for network in approved]
    lines.append("\t}")
    chains, rules = [], []
    for name, kind, hook, priority, prio, chain_rules in _chains(ingress):
        lines += [f"\tchain {name} {{",
                  f"\t\ttype {kind} hook {hook} priority {priority}; policy accept;"]
        chains.append({"chain": {"family": "inet", "table": NFT_TABLE, "name": name,
                                 "type": kind, "hook": hook, "prio": prio,
                                 "policy": "accept"}})
        for terms in chain_rules:
            lines.append("\t\t" + " ".join(text for text, _ in terms))
            rules.append({"rule": {"family": "inet", "table": NFT_TABLE, "chain": name,
                                   "expr": [expression for _, expression in terms]}})
        lines.append("\t}")
    lines.append("}")
    # `nft -j` lists the table, then its chains, then its sets, then the
    # rules chain by chain (container-checked, nftables 1.1.3).
    expected = [{"table": {"family": "inet", "name": NFT_TABLE}}, *chains,
                {"set": the_set}, *rules]
    return Ruleset("\n".join(lines) + "\n", canonical_json(expected),
                   tuple(str(network) for network in approved), ingress, digest)


def canonical_json(document: object) -> str:
    """The one JSON form both the expected and the listed table are compared in."""

    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


#: The helper's ruleset without a scope, one nftables transaction: the table
#: of the first build, with `approved_v4` empty. `create table` fails if a
#: table of that name exists, and then the whole transaction is refused: an
#: existing table is never replaced or added to. Every chain has `policy
#: accept` on purpose: this table only ever *drops* (an accept here does not
#: override a drop in another table), so it adds isolation and never opens
#: anything another table closes; with a scope the same holds, and the
#: masquerade (A3) changes a source address only.
NFT_RULESET = render_ruleset(None).text


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


#: `az-decoy-netd` changes nothing while either exists (each must fail):
#: a bridge left behind would be one the rules it is about to load could be
#: undone under; a table is never replaced (`create table` is the second
#: line of defence).
HELPER_ABSENT: tuple[tuple[str, ...], ...] = (
    _ip("link", "show", "dev", BRIDGE),
    (NFT, "list", "table", "inet", NFT_TABLE),
)

def helper_steps(ruleset: Ruleset) -> tuple[Step, ...]:
    """`az-decoy-netd`: the rules first, then the bridge and the host end.

    Every argument list is a constant but the first, which is the one
    ruleset rendered from the run's scope (`render_ruleset`).
    """

    return (
        Step((NFT, ruleset.text), (NFT, "delete", "table", "inet", NFT_TABLE),
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


#: The helper's steps without a scope (`NFT_RULESET`).
HELPER_STEPS: tuple[Step, ...] = helper_steps(render_ruleset(None))

#: The helper's inspection after it has built the host side (#196 §14, G1b),
#: by fixed name: the table as the kernel holds it, in nftables' JSON form
#: (`-j`; its structure, not its text, is compared, so long element lists
#: that the text listing wraps do not matter), and every host link with its
#: kind, master, peer namespace and addresses (`-d` adds the link details to
#: the address listing). Two commands, so that the longest start, with the
#: undo after a failed inspection, still fits in `TimeoutStartSec=30s`. The
#: only commands whose output is read (`capture_fixed`).
HELPER_VERIFY: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("nft_table", (NFT, "-j", "list", "table", "inet", NFT_TABLE)),
    ("host_links", (IP, "-j", "-d", "address", "show")),
)


@dataclass(frozen=True)
class Plan:
    """Every argument list one run may start, and nothing else (#196 G1b).

    Built once per run: the helper's is the constant argument lists plus
    exactly the one ruleset argument list rendered from the run's scope
    (`helper_plan`); the verify unit's holds the read-backs only
    (`verify_plan`). `run_fixed` and `capture_fixed` refuse anything outside
    it; no caller hands them an argument list of its own.
    """

    steps: tuple[Step, ...]
    absent: tuple[tuple[str, ...], ...] = ()
    verify: tuple[tuple[str, tuple[str, ...]], ...] = ()
    #: The run's table (`None` only for a plan built without one).
    ruleset: Optional[Ruleset] = None
    allowed: frozenset[tuple[str, ...]] = field(init=False, repr=False, compare=False)
    read_back: frozenset[tuple[str, ...]] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        steps = self.steps
        object.__setattr__(self, "allowed", frozenset(
            (*self.absent, *(s.argv for s in steps),
             *(s.undo for s in steps if s.undo is not None),
             *(command for _, command in self.verify))))
        object.__setattr__(self, "read_back",
                           frozenset(command for _, command in self.verify))


def helper_plan(scope: Optional[ScopeLike] = None) -> Plan:
    """The helper's plan for one run, from the decoded scope (or none)."""

    ruleset = render_ruleset(scope)
    return Plan(helper_steps(ruleset), HELPER_ABSENT, HELPER_VERIFY, ruleset)


#: The helper's plan without a scope; also what `stop` runs from, which
#: needs no scope (its undo lists are constants).
HELPER_PLAN = helper_plan(None)

#: The verify unit's read-backs (#196 G2, docs/deception-exposure-grant.md
#: §6.1; reachability R4), by fixed name: the helper's two, then the IPv4
#: routing rules and the routes of the main table, in `ip`'s JSON form. Read
#: only: a dump of rules or routes changes nothing. Four commands of at most
#: `STEP_SECONDS` each fit in the verify unit's `TimeoutStartSec=30s` and in
#: one watch period of 10 s.
WATCH_READS: tuple[tuple[str, tuple[str, ...]], ...] = HELPER_VERIFY + (
    ("host_rules", (IP, "-j", "-4", "rule", "show")),
    ("main_routes", (IP, "-j", "-4", "route", "show", "table", "main")),
)


def verify_plan(scope: Optional[ScopeLike] = None) -> Plan:
    """The verify unit's plan: the read-backs only, nothing that changes state.

    No step, no check of absence, no undo: `run_fixed` refuses every argument
    list (the plan allows only what `capture_fixed` reads back), so the only
    processes the verify can start are the four `WATCH_READS`. The ruleset is
    rendered from the verify unit's own copy of the scope by the same
    function as the helper's, and is only compared, never loaded.
    """

    return Plan((), (), WATCH_READS, render_ruleset(scope))

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


def run_fixed(argv: tuple[str, ...], *, plan: Plan) -> int:
    """Start one of the run's planned commands; its exit status.

    Refuses any argument list outside `plan`. Empty environment, `SIGPIPE`
    at its default, no shell, no pipe, nothing read back: the program writes
    to the unit's journal stream. Killed after `STEP_SECONDS`.
    """

    if type(plan) is not Plan or tuple(argv) not in plan.allowed:
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


def capture_fixed(argv: tuple[str, ...], *, plan: Plan) -> tuple[int, bytes]:
    """Run one of the plan's `HELPER_VERIFY` commands; its status and output.

    Refuses any other argument list before a process is made. The output
    goes through one pipe (the child's descriptor 1, nothing else) into a
    buffer of at most `CAPTURE_LIMIT` bytes; standard error stays the unit's
    journal stream. Killed after `STEP_SECONDS`; then, past the limit, or on
    a non-zero exit, the output is empty.
    """

    argv = tuple(argv)
    if type(plan) is not Plan or argv not in plan.read_back:
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

    def record(self, outputs: dict[str, tuple[int, bytes]], ruleset: Ruleset) -> bool: ...

    def withdraw(self) -> bool: ...


def _runner(plan: Plan, run: Optional[Runner]) -> Runner:
    if run is not None:
        return run
    return lambda argv: run_fixed(argv, plan=plan)


def main_for(prog: str, plan: Plan, argv: Optional[Sequence[str]],
             run: Optional[Runner], *, recorder: Optional[Recorder] = None,
             capture: Optional[Capture] = None,
             start_plan: Optional[Callable[[], Plan]] = None) -> int:
    """`prog` takes no argument (start) or exactly `stop` (`ExecStop=`).

    `plan` is what `stop` runs from. With `start_plan` (the helper only,
    #196 G1b), a start builds its plan from the run's scope, after the
    recorder has removed the previous record (review of #286); a scope that
    cannot be read or rendered (`ValueError`) builds nothing and exits 1,
    with no record left behind.

    With a `recorder` (the helper only, #196 §14): at start, the previous
    record is removed and this boot's id read **before** anything is checked
    or built (either failing changes nothing, exit 1); after a successful
    build the plan's read-back commands are run and recorded against the
    plan's ruleset, and unless every check passed and the record was
    written, what was built is undone and the exit is 1. At stop, the record
    is removed first; a failure to remove it is reported and makes the stop
    exit 1, after the tear-down.
    """

    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        # The previous record goes first, before the scope is read (review
        # of #286): a refused scope must not leave an earlier passing record
        # behind for the decoy to accept.
        if recorder is not None and not recorder.prepare():
            _say(prog, "the previous isolation record could not be removed or this "
                 "boot's id could not be read; nothing was changed")
            return 1
        if start_plan is not None:
            try:
                plan = start_plan()
            except ValueError:
                _say(prog, "the decoy scope could not be read; the previous isolation "
                     "record was removed and nothing was built")
                return 1
        runner = _runner(plan, run)
        status = bring_up(prog, plan.steps, runner, plan.absent)
        if status or recorder is None:
            return status
        try:
            if plan.ruleset is None:
                raise ValueError("a recorded run has a ruleset")
            outputs = {name: (capture_fixed(command, plan=plan) if capture is None
                              else capture(command))
                       for name, command in plan.verify}
            recorded = recorder.record(outputs, plan.ruleset)
        except Exception:  # noqa: BLE001 - any error here undoes the build
            # Review of #274: an exception while reading back or recording
            # must not leave the build in place without a passing record.
            _say(prog, "the isolation check failed with an error; undoing")
            tear_down(prog, plan.steps, runner)
            return 1
        if recorded:
            return 0
        _say(prog, "the isolation check did not pass or was not recorded; undoing")
        tear_down(prog, plan.steps, runner)
        return 1
    if arguments == ["stop"]:
        runner = _runner(plan, run)
        withdrawn = recorder is None or recorder.withdraw()
        if not withdrawn:
            _say(prog, "the isolation record could not be removed")
        status = tear_down(prog, plan.steps, runner)
        return status if withdrawn else 1
    _say(prog, "takes no argument but `stop`")
    return 2
