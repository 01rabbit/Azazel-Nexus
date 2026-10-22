"""The Deception Lite watch: `az-decoy-netd verify` (#196 G2).

`docs/deception-exposure-grant.md` §6.1 (W4, decided as §10 Q6 and Q7) and
`docs/deception-exposure-reachability.md` §6 and §9 R4. The verify unit
(`azazel-decoy-verify.service`) runs the helper's executable with the one
word `verify`, before every decoy start and every 10 s while the decoy runs.
It reads, compares and exits: 0 when everything matches, 1 otherwise. A
non-zero exit fails the unit, and its `OnFailure=` starts the trip unit,
which stops the namespace unit and, through `Requires=`, the helper and the
decoy. It only narrows: it judges no traffic, decides nothing for Edge, and
stops nothing itself.

**What it reads.** Only the four fixed read-backs of
`decoy_network.WATCH_READS`, through `decoy_network.capture_fixed` (its plan,
`decoy_network.verify_plan`, holds no command that changes anything), and
the files under `/proc/sys/net/ipv4/conf` and `/proc/sys/net/ipv6/conf`
that hold `forwarding` and `proxy_arp`. Its scope is its own credential
(`azazel_nexus.decoy_scope.read_verify_scope_credential`: the same source
file as the helper's, by the same rules). Unlike the helper it has no
scope-less mode: no credential directory compares nothing and exits 1.

**What it compares.**

1. The table and the host's links, with the helper's own judgement
   (`decoy_isolation_check.evaluate`) against the ruleset rendered from the
   scope: the same nine checks the helper records, but nothing is written.
   A table that is missing or was flushed is `unreadable`, and fails.
2. Reachability R4, the reads of reachability §6 that a verify can make
   (`reachability_departures`). The verify knows the ingress interfaces from
   the scope, and not the management and observation ones, so "off on those
   roles" is covered by "off on every interface but the ingress and the
   bridge" (`forwarding_other_on`); the pass of G6 reads the roles.
   The routing rules are checked as far as G2 goes: below the main table's
   priority there is exactly the local rule and, per ingress, the K1 pair
   with its defining attributes (destination, table, `suppress_prefixlength`,
   `blackhole`). That no rule carries another selector, and the exact
   attribute set, wait for the dump observed on the VM (reachability §11
   item 8) and are G6's.

**What it says.** One journal line of fixed check names and fixed reason
codes, never an interface name, a prefix, an address or a value.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
from typing import Callable, Optional

from azazel_nexus.decoy_scope import read_verify_scope_credential

from .decoy_addresses import BRIDGE, DECOY_SUBNET
from .decoy_isolation_check import evaluate
from .decoy_network import HELPER_VERIFY, Capture, capture_fixed, verify_plan

__all__ = [
    "DECOY_PREFIX_ROUTED",
    "FORWARDING_HOST_WIDE",
    "FORWARDING_INGRESS_OFF",
    "FORWARDING_IPV6_ON",
    "FORWARDING_OTHER_ON",
    "FORWARDING_UNREADABLE",
    "INGRESS_CONTAINMENT_ABSENT",
    "IPV6_ABSENT",
    "PROXY_ARP_ON",
    "REACHABILITY_CODES",
    "read_sysctls",
    "reachability_departures",
    "verify",
]

#: The reason codes of reachability §6 that the verify gives, in the order
#: they are reported. `forwarding_role_on` is the pass's (G6): the verify
#: has no roles, and `forwarding_other_on` covers those interfaces.
FORWARDING_INGRESS_OFF = "forwarding_ingress_off"
FORWARDING_HOST_WIDE = "forwarding_host_wide"
FORWARDING_OTHER_ON = "forwarding_other_on"
FORWARDING_IPV6_ON = "forwarding_ipv6_on"
PROXY_ARP_ON = "proxy_arp_on"
INGRESS_CONTAINMENT_ABSENT = "ingress_containment_absent"
DECOY_PREFIX_ROUTED = "decoy_prefix_routed"
FORWARDING_UNREADABLE = "forwarding_unreadable"
REACHABILITY_CODES: tuple[str, ...] = (
    FORWARDING_INGRESS_OFF,
    FORWARDING_HOST_WIDE,
    FORWARDING_OTHER_ON,
    FORWARDING_IPV6_ON,
    PROXY_ARP_ON,
    INGRESS_CONTAINMENT_ABSENT,
    DECOY_PREFIX_ROUTED,
    FORWARDING_UNREADABLE,
)


class _Ipv6Absent:
    """`/proc/sys/net/ipv6` does not exist: IPv6 is off at boot, so no forwarding."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "IPV6_ABSENT"


IPV6_ABSENT = _Ipv6Absent()

#: Private test seam: where the `net` sysctl tree is. Production is exactly this.
_NET = "/proc/sys/net"
#: The two names `conf/` holds besides the interfaces (reachability §6).
_HOST_WIDE = ("all", "default")
#: More entries than this under `conf/` is not a host this check reads.
_ENTRY_LIMIT = 4096
#: A value file holds `0\n` or `1\n`; one byte more is enough to see more.
_VALUE_LIMIT = 8
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_ABSENT = (FileNotFoundError, NotADirectoryError)

#: One interface's values: `{"forwarding": 0 | 1 | None, ...}`, None unreadable.
Values = dict[str, Optional[int]]
#: Every `conf/` entry's values, or None when the directory could not be read.
Tree = Optional[dict[str, Values]]


def _value(directory: int, key: str) -> Optional[int]:
    """`0` or `1` from one value file under an open directory, else None."""

    try:
        fd = os.open(key, _FILE_FLAGS, dir_fd=directory)
    except OSError:
        return None
    try:
        data = os.read(fd, _VALUE_LIMIT + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    return {b"0\n": 0, b"1\n": 1}.get(data)


def _tree(path: str, keys: Callable[[str], tuple[str, ...]]) -> Tree:
    """`name -> {key: value}` for every entry of one `conf/` directory.

    Every entry is opened by name relative to the `conf/` directory itself
    (so the path's parent is that directory, compared before anything is
    opened: no `/`, no `.` or `..`), without following a link. An entry that
    vanished between the listing and its opening was an interface that went
    away and is skipped; a value file missing or unreadable in an entry that
    exists is None (unreadable).
    """

    try:
        directory = os.open(path, _DIR_FLAGS)
    except OSError:
        return None
    try:
        try:
            names = os.listdir(directory)
        except OSError:
            return None
        if len(names) > _ENTRY_LIMIT:
            return None
        tree: dict[str, Values] = {}
        for name in names:
            if name in (".", "..") or "/" in name or "\0" in name:
                return None
            try:
                entry = os.open(name, _DIR_FLAGS, dir_fd=directory)
            except FileNotFoundError:
                # Gone since the listing: an interface that went away. A link
                # or anything else that is not a directory is unreadable.
                continue
            except OSError:
                tree[name] = {key: None for key in keys(name)}
                continue
            try:
                tree[name] = {key: _value(entry, key) for key in keys(name)}
            finally:
                os.close(entry)
        return tree
    finally:
        os.close(directory)


def read_sysctls(ingress: tuple[str, ...]):
    """`(ipv4, ipv6)` as read now from the host namespace's `/proc/sys/net`.

    IPv4: `forwarding` of every entry, and `proxy_arp` of `all` and of each
    ingress interface. IPv6: `forwarding` of every entry, or `IPV6_ABSENT`
    when `/proc/sys/net/ipv6` itself does not exist. Read-only, bounded,
    no link followed; nothing here is judged (`reachability_departures`).
    """

    wanted = set(ingress) | {"all"}

    def keys4(name: str) -> tuple[str, ...]:
        return ("forwarding", "proxy_arp") if name in wanted else ("forwarding",)

    ipv4 = _tree(f"{_NET}/ipv4/conf", keys4)
    try:
        os.lstat(f"{_NET}/ipv6")
    except _ABSENT:
        return ipv4, IPV6_ABSENT
    except OSError:
        return ipv4, None
    return ipv4, _tree(f"{_NET}/ipv6/conf", lambda name: ("forwarding",))


#: The main table's rule priority: the rules before it are the ones read.
_MAIN_PRIORITY = 32766
#: A rule's missing (or non-text) `iif`: a sentinel no interface name equals.
_NO_IIF = object()
#: The K1 pair of reachability §5, per ingress interface.
_K1_LOOKUP, _K1_BLACKHOLE = 1960, 1961
_DECOY_NETWORK = ipaddress.IPv4Network(DECOY_SUBNET)
#: The decoy network's /24 (`decoy_scope.RESERVED_HEADROOM`): no route of
#: `main` inside it but the bridge's connected /30.
_HEADROOM = ipaddress.IPv4Network("10.255.196.0/24")


def _json_list(output: bytes) -> Optional[list[dict]]:
    """`ip -j` output as a list of objects, or None. Never partly read."""

    try:
        document = json.loads(output.decode("ascii"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if type(document) is not list or not all(type(item) is dict for item in document):
        return None
    return document


def _rules_contained(rules: list[dict], ingress: tuple[str, ...]) -> Optional[bool]:
    """Below `main`, exactly the local rule and each ingress's K1 pair.

    None when a rule has no integer priority (output this does not read).
    G2's comparison: the priorities, the `iif` of each, the local rule's
    table, and the K1 pair's defining attributes as `ip -j` 6.15 prints them
    (container-checked): the lookup's `dst`/`dstlen`, `table` and
    `suppress_prefixlen`, the discard's `action`. That nothing else is
    selected on, and the exact attribute set, are G6's, fixed from the VM's
    dump (reachability §11 item 8).
    """

    below = []
    for rule in rules:
        priority = rule.get("priority")
        if type(priority) is not int:
            return None
        if priority < _MAIN_PRIORITY:
            below.append(rule)
    local = [rule for rule in below if rule["priority"] == 0]
    if (len(local) != 1 or local[0].get("table") != "local"
            or "iif" in local[0] or "oif" in local[0]):
        return False
    # A rule without `iif`, or with one that is not a name, is never an
    # ingress's (review of #287 F3): it is matched as `_NO_IIF`, which no
    # scope name can equal, never as the text "None".
    pairs = [(rule["priority"], rule["iif"] if type(rule.get("iif")) is str else _NO_IIF)
             for rule in below if rule["priority"] != 0]
    expected = ([(_K1_LOOKUP, name) for name in ingress]
                + [(_K1_BLACKHOLE, name) for name in ingress])
    if (len(pairs) != len(expected) or any(iif is _NO_IIF for _, iif in pairs)
            or sorted(pairs) != sorted(expected)):
        return False
    for rule in below:
        if rule["priority"] == _K1_LOOKUP and not (
                rule.get("dst") == str(_DECOY_NETWORK.network_address)
                and rule.get("dstlen") == _DECOY_NETWORK.prefixlen
                and rule.get("table") == "main"
                and rule.get("suppress_prefixlen") == 29
                and "action" not in rule):
            return False
        if rule["priority"] == _K1_BLACKHOLE and not (
                rule.get("action") == "blackhole" and "table" not in rule):
            return False
    return True


def _routes_clear(routes: list[dict]) -> Optional[bool]:
    """No route of `main` inside the /24 but the bridge's connected /30.

    None when a destination cannot be read. The connected route is accepted
    once, exactly as the kernel makes it for the bridge's address: the /30,
    on the bridge, no gateway, no next hops, unicast.
    """

    connected = 0
    for route in routes:
        destination = route.get("dst")
        if type(destination) is not str:
            return None
        if destination == "default":
            continue
        try:
            network = ipaddress.IPv4Network(
                destination if "/" in destination else f"{destination}/32", strict=True)
        except ValueError:
            return None
        if not network.subnet_of(_HEADROOM):
            continue
        if (network == _DECOY_NETWORK and route.get("dev") == BRIDGE
                and route.get("type", "unicast") == "unicast"
                and not {"gateway", "via", "nexthops"} & set(route)):
            connected += 1
            continue
        return False
    return connected <= 1


def reachability_departures(ipv4: Tree, ipv6, rules: tuple[int, bytes],
                            routes: tuple[int, bytes],
                            ingress: tuple[str, ...]) -> tuple[str, ...]:
    """The reason codes of reachability §6 that hold now, in fixed order.

    Pure. `ipv4` and `ipv6` are `read_sysctls`'s; `rules` and `routes` are
    `(status, output)` of the `host_rules` and `main_routes` read-backs;
    `ingress` is the scope's (empty without a scope). Empty when everything
    holds:

    * every ingress interface forwards (`1`); `all` and `default` do not;
      no other interface does, except the bridge `az-decoy0`, whose
      forwarding the operator turns on for the replies (reachability §7) and
      whose value is not read;
    * no IPv6 forwarding anywhere (or no IPv6 at all);
    * `proxy_arp` off on `all` and on every ingress;
    * the routing rules contain each ingress (K1) and nothing else comes
      before the main table;
    * no route of `main` inside the decoy network's /24 but its own /30.

    Anything not in its closed form (`0\\n` or `1\\n`, an ingress absent, a
    dump that failed or cannot be read) is `forwarding_unreadable`.
    """

    found: set[str] = set()
    if ipv4 is None or any(name not in ipv4 for name in (*_HOST_WIDE, *ingress)):
        found.add(FORWARDING_UNREADABLE)
    else:
        for name, values in ipv4.items():
            forwarding = values.get("forwarding")
            if forwarding is None:
                found.add(FORWARDING_UNREADABLE)
            elif name in _HOST_WIDE:
                if forwarding != 0:
                    found.add(FORWARDING_HOST_WIDE)
            elif name in ingress:
                if forwarding != 1:
                    found.add(FORWARDING_INGRESS_OFF)
            elif name != BRIDGE and forwarding != 0:
                found.add(FORWARDING_OTHER_ON)
        for name in ("all", *ingress):
            proxy_arp = ipv4[name].get("proxy_arp")
            if proxy_arp is None:
                found.add(FORWARDING_UNREADABLE)
            elif proxy_arp != 0:
                found.add(PROXY_ARP_ON)
    if ipv6 is not IPV6_ABSENT:
        if type(ipv6) is not dict or any(name not in ipv6 for name in _HOST_WIDE):
            found.add(FORWARDING_UNREADABLE)
        else:
            for values in ipv6.values():
                forwarding = values.get("forwarding")
                if forwarding is None:
                    found.add(FORWARDING_UNREADABLE)
                elif forwarding != 0:
                    found.add(FORWARDING_IPV6_ON)
    status, output = rules
    listed = _json_list(output) if status == 0 else None
    contained = None if listed is None else _rules_contained(listed, ingress)
    if contained is None:
        found.add(FORWARDING_UNREADABLE)
    elif not contained:
        found.add(INGRESS_CONTAINMENT_ABSENT)
    status, output = routes
    listed = _json_list(output) if status == 0 else None
    clear = None if listed is None else _routes_clear(listed)
    if clear is None:
        found.add(FORWARDING_UNREADABLE)
    elif not clear:
        found.add(DECOY_PREFIX_ROUTED)
    return tuple(code for code in REACHABILITY_CODES if code in found)


def _say(text: str) -> None:
    print(f"az-decoy-netd verify: {text}", file=sys.stderr, flush=True)


#: The names of the helper's two read-backs, which the table checks read.
_TABLE_READS = tuple(name for name, _ in HELPER_VERIFY)


def verify(*, capture: Optional[Capture] = None, read_scope=None,
           sysctls=None) -> int:
    """Read everything, compare, exit 0 when it all matches and 1 otherwise.

    `capture`, `read_scope` and `sysctls` are private test seams;
    `az-decoy-netd verify` passes none of them. Nothing is written, nothing
    is changed, no record is touched: a refused scope, a read-back that
    fails or cannot be read, a table check that does not pass and a
    reachability departure each make the exit 1.
    """

    try:
        scope = (read_verify_scope_credential if read_scope is None else read_scope)()
        if scope is None:
            # No credential directory (review of #287 F1): unlike the
            # helper, the verify has no scope-less mode. Comparing with the
            # table of the first build would let a verify pass with nothing
            # to compare against; it refuses instead.
            _say("the decoy scope is absent; nothing was compared")
            return 1
        plan = verify_plan(scope)
    except ValueError:
        _say("the decoy scope could not be read; nothing was compared")
        return 1
    ruleset = plan.ruleset
    if ruleset is None:  # pragma: no cover - verify_plan always renders one
        return 1
    try:
        outputs = {name: (capture_fixed(command, plan=plan) if capture is None
                          else capture(command))
                   for name, command in plan.verify}
        table = evaluate({name: outputs[name] for name in _TABLE_READS}, ruleset)
        ipv4, ipv6 = (read_sysctls if sysctls is None else sysctls)(ruleset.ingress)
        departures = reachability_departures(ipv4, ipv6, outputs["host_rules"],
                                             outputs["main_routes"], ruleset.ingress)
    except Exception:  # noqa: BLE001 - an error here is a verify that did not pass
        _say("the read-back could not be evaluated")
        return 1
    failed = [f"{name} {result}" for name, result in table.items() if result != "pass"]
    if not failed and not departures:
        _say("the table, the host's links, forwarding, the routing rules and the "
             "routes match")
        return 0
    _say("departed: " + ", ".join(failed + list(departures)))
    return 1
