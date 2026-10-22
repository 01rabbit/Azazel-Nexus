"""How outside peers reach the decoy: the reads and judgements of reachability §6.

`docs/deception-exposure-reachability.md` §6 and §9 (R1, R2, R4, R5).
Two callers share this module, each with its own judgement:

* **the verify** (`decoy_watch.verify`, `az-decoy-netd verify`, #196 G2,
  R4): `reachability_departures`. Its behaviour is G2's, moved out of
  `decoy_watch` (#196 G6 preparation A), but for the rules: since #196 R4's
  remainder they are compared by the pass's one comparison (`_rules_exact`).
* **the activation pass** (G6): `pass_reachability_departures`, the reading
  of condition 6 of grant §5. **Implemented, not wired**: nothing calls it.
  `ActivationController._withholding_reason` still withholds the tier as
  `isolation_evidence_absent` unconditionally, and wiring this in is G6
  (grant §9). `tests/unit/test_decoy_reachability.py` fails the day the
  activation pass, the controller or the library imports this module.

What the pass adds to the verify's judgement, as §6 states it:

* the `management` and `observation` interfaces, resolved from their roles
  and passed in, must not forward (`forwarding_role_on`); the verify has no
  roles and covers them as "every other interface" (`forwarding_other_on`);
* `az-decoy0` is not exempt (it does not exist before the helper runs, so a
  value for it is another interface that forwards);
* no route of `main` inside `10.255.196.0/24` at all (before the bridge
  exists, not even the connected /30);
* every interface name it is given passes `decoy_scope.interface_name_allowed`
  (grant §4.3: `[A-Za-z0-9_.-]{1,15}`, not `az-decoy*`, not `lo`, `all`,
  `default`, `.` or `..`) and its path under `conf/` has that directory as
  its exact parent (`conf_entry_path`), or the reads withhold as
  `forwarding_unreadable`.

**The rules, one comparison for both** (`_rules_exact`, §6 R2 and R4): the
rules before `main` are compared **exactly**, and at priority 32766 there is
exactly the one `from all lookup main`: every rule below priority 32766 must
equal, attribute for attribute as `ip -j -4 rule show` prints it, either the
local rule or one rule of an ingress's K1 pair, with the rule's `protocol`
left out; the K1 discard rule is accepted in two complete forms only, with no
`table` (`ip rule add`) or with `"table":"main"` (networkd 257, observed on
the VM, §11 item 8). Any other key (`not`, `srclen`, `oif`, `fwmark`, `tos`,
`dscp`, `uid_start`, `l3mdev`, `ipproto`, `sport*`, `dport*`, `goto`,
`tun_id`, `suppress_ifgroup`, `flow_to`, ...) or another table fails.

**What it says.** Reason codes only, each a fixed word with a fixed phrase
(`REACHABILITY_PHRASES`); never an interface name, a prefix, an address or a
value.

A leaf apart from `decoy_addresses` (names and addresses) and the library's
standard-library leaf `decoy_scope` (the name rule): no socket, no process,
no environment; it reads only `/proc/sys/net` (`read_sysctls`), opened
without following a link, and its judgements are pure.
"""

from __future__ import annotations

import ipaddress
import json
import os
from typing import Callable, Optional

from azazel_nexus.decoy_scope import MAX_INGRESS, interface_name_allowed

from .decoy_addresses import BRIDGE, DECOY_SUBNET

__all__ = [
    "DECOY_PREFIX_ROUTED",
    "FORWARDING_HOST_WIDE",
    "FORWARDING_INGRESS_OFF",
    "FORWARDING_IPV6_ON",
    "FORWARDING_OTHER_ON",
    "FORWARDING_ROLE_ON",
    "FORWARDING_UNREADABLE",
    "INGRESS_CONTAINMENT_ABSENT",
    "IPV6_ABSENT",
    "PASS_REACHABILITY_CODES",
    "PROXY_ARP_ON",
    "REACHABILITY_CODES",
    "REACHABILITY_PHRASES",
    "conf_entry_path",
    "parse_json_list",
    "pass_reachability_departures",
    "reachability_departures",
    "reachability_refusal",
    "read_sysctls",
]

#: The reason codes of reachability §6.
FORWARDING_INGRESS_OFF = "forwarding_ingress_off"
FORWARDING_ROLE_ON = "forwarding_role_on"
FORWARDING_HOST_WIDE = "forwarding_host_wide"
FORWARDING_OTHER_ON = "forwarding_other_on"
FORWARDING_IPV6_ON = "forwarding_ipv6_on"
PROXY_ARP_ON = "proxy_arp_on"
INGRESS_CONTAINMENT_ABSENT = "ingress_containment_absent"
DECOY_PREFIX_ROUTED = "decoy_prefix_routed"
FORWARDING_UNREADABLE = "forwarding_unreadable"

#: The codes the verify gives, in the order it reports them (G2).
#: `forwarding_role_on` is the pass's: the verify has no roles, and
#: `forwarding_other_on` covers those interfaces.
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

#: The codes the pass gives (G6, not wired), in the fixed order of §6's table.
PASS_REACHABILITY_CODES: tuple[str, ...] = (
    FORWARDING_INGRESS_OFF,
    FORWARDING_ROLE_ON,
    FORWARDING_HOST_WIDE,
    FORWARDING_OTHER_ON,
    FORWARDING_IPV6_ON,
    PROXY_ARP_ON,
    INGRESS_CONTAINMENT_ABSENT,
    DECOY_PREFIX_ROUTED,
    FORWARDING_UNREADABLE,
)

#: Each code's fixed phrase: no name, prefix, address or value.
REACHABILITY_PHRASES: dict[str, str] = {
    FORWARDING_INGRESS_OFF: "forwarding is not on for every ingress interface",
    FORWARDING_ROLE_ON: "forwarding is on for a management or observation interface",
    FORWARDING_HOST_WIDE: "IPv4 forwarding is on for all or for default interfaces",
    FORWARDING_OTHER_ON: "forwarding is on for an interface that is not an ingress",
    FORWARDING_IPV6_ON: "IPv6 forwarding is on",
    PROXY_ARP_ON: "proxy ARP is on host-wide or for an ingress interface",
    INGRESS_CONTAINMENT_ABSENT: ("the routing rules before the main table are not "
                                 "exactly the local rule and each ingress's "
                                 "containment pair"),
    DECOY_PREFIX_ROUTED: "the main table routes inside the decoy network's prefix",
    FORWARDING_UNREADABLE: ("a forwarding, proxy ARP, rule or route read was "
                            "absent or not in its closed form"),
}


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
#: The two `conf/` directories, by address family.
_FAMILIES = ("ipv4", "ipv6")

#: One interface's values: `{"forwarding": 0 | 1 | None, ...}`, None unreadable.
Values = dict[str, Optional[int]]
#: Every `conf/` entry's values, or None when the directory could not be read.
Tree = Optional[dict[str, Values]]


def conf_entry_path(family: str, name: object) -> Optional[str]:
    """`/proc/sys/net/<family>/conf/<name>`, or None when `name` may not be one.

    The one place a role's interface name becomes a path (§6): the name must
    pass `decoy_scope.interface_name_allowed` (so not `.`, `..`, `all`,
    `default` or `lo`, no `/`), and the path built from it must have the
    `conf/` directory as its exact parent and be already normal, both
    compared before anything is opened. Pure: it opens nothing.
    """

    if family not in _FAMILIES or not interface_name_allowed(name):
        return None
    parent = f"{_NET}/{family}/conf"
    path = f"{parent}/{name}"
    if os.path.dirname(path) != parent or os.path.normpath(path) != path:
        return None
    return path


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
    no link followed; nothing here is judged (`reachability_departures`,
    `pass_reachability_departures`).
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
#: The K1 pair of reachability §5, per ingress interface.
_K1_LOOKUP, _K1_BLACKHOLE = 1960, 1961
_DECOY_NETWORK = ipaddress.IPv4Network(DECOY_SUBNET)
#: The decoy network's /24 (`decoy_scope.RESERVED_HEADROOM`): no route of
#: `main` inside it but (in the verify) the bridge's connected /30.
_HEADROOM = ipaddress.IPv4Network("10.255.196.0/24")
#: Who installed a rule: left out of the exact comparison (§6). networkd's
#: rules print `"protocol":"static"` even without `-d` (VM, §11 item 8).
_IGNORED_RULE_KEYS = frozenset({"protocol"})
#: The one table a K1 discard rule may carry: networkd 257 prints its
#: blackhole rule with `"table":"main"`, `ip rule add` without a table
#: (VM, §11 item 8). The two complete forms are accepted, no other table.
_K1_BLACKHOLE_TABLE = "main"
#: The one rule the pass accepts at the main table's own priority: rules of
#: equal priority are tried in the order they were added, so another rule
#: there could still act before `main` (§6, review of #293).
_MAIN_RULE = {"priority": _MAIN_PRIORITY, "src": "all", "table": "main"}


def parse_json_list(output: bytes) -> Optional[list[dict]]:
    """`ip -j` output as a list of objects, or None. Never partly read."""

    try:
        document = json.loads(output.decode("ascii"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if type(document) is not list or not all(type(item) is dict for item in document):
        return None
    return document


def _expected_rules(ingress: tuple[str, ...]) -> list[dict]:
    """The rules below `main` the pass accepts, as `ip -j -4 rule show` prints them."""

    rules: list[dict] = [{"priority": 0, "src": "all", "table": "local"}]
    for name in ingress:
        rules.append({"priority": _K1_LOOKUP, "src": "all",
                      "dst": str(_DECOY_NETWORK.network_address),
                      "dstlen": _DECOY_NETWORK.prefixlen, "iif": name,
                      "table": "main", "suppress_prefixlen": 29})
        rules.append({"priority": _K1_BLACKHOLE, "src": "all", "iif": name,
                      "action": "blackhole"})
    return rules


def _rules_exact(rules: list[dict], ingress: tuple[str, ...]) -> Optional[bool]:
    """Below `main`, exactly the local rule and each ingress's K1 pair, whole.

    The one comparison of the rules, the pass's and the verify's alike (§6
    R2, R4; #196 R4): each rule below priority 32766, with its
    `protocol` left out (and a K1 discard rule's `"table":"main"`, the form
    networkd 257 prints, set aside: the discard rule is accepted with no
    table or with table `main`, no other), must equal one expected rule attribute for
    attribute (keys, values and their JSON types), and the two lists must
    be equal as multisets: no rule missing, none extra, none twice. Any
    other selector or flag is an extra key, so it fails. At priority 32766
    itself there must be exactly one rule, `from all lookup main`, compared
    the same way. None when a rule has no integer priority. The verify
    passes the scope's ingress (none without a scope: then only the local
    rule); its differences from the pass (`az-decoy0`'s forwarding and its
    connected /30) are in the sysctls and the routes, not here.

    `ingress` is distinct by its callers' rules: the scope refuses ingress
    names that are not sorted and distinct (`decoy_scope._ingress_names`),
    and the pass refuses a name in two places (`_names_closed`). Rules of
    the same priority (1960, 1961) do not overlap because each carries a
    different `iif`.
    """

    below, at_main = [], []
    for rule in rules:
        priority = rule.get("priority")
        if type(priority) is not int:
            return None
        stripped = {key: value for key, value in rule.items()
                    if key not in _IGNORED_RULE_KEYS}
        # Only the text "main" equals it: no other JSON value does.
        if (priority == _K1_BLACKHOLE and stripped.get("action") == "blackhole"
                and stripped.get("table") == _K1_BLACKHOLE_TABLE):
            # networkd's form of the discard rule: the expected rule once its
            # `table main` is set aside. Every other key is still compared
            # below, and any other table stays an extra key, so it fails.
            del stripped["table"]
        if priority < _MAIN_PRIORITY:
            below.append(stripped)
        elif priority == _MAIN_PRIORITY:
            at_main.append(stripped)

    def canonical(rule: dict) -> str:
        return json.dumps(rule, sort_keys=True)

    return (at_main == [_MAIN_RULE]
            and sorted(map(canonical, below))
            == sorted(map(canonical, _expected_rules(ingress))))


def _routes_clear(routes: list[dict], *, connected: bool = True) -> Optional[bool]:
    """No route of `main` inside the /24, but (with `connected`) the bridge's /30.

    None when a destination cannot be read. The verify (`connected`) accepts
    the connected route once, exactly as the kernel makes it for the
    bridge's address: the /30, on the bridge, no gateway, no next hops,
    unicast. The pass accepts none: before the helper runs the bridge does
    not exist (§6).
    """

    found = 0
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
        if (connected and network == _DECOY_NETWORK and route.get("dev") == BRIDGE
                and route.get("type", "unicast") == "unicast"
                and not {"gateway", "via", "nexthops"} & set(route)):
            found += 1
            continue
        return False
    return found <= 1


def _sysctl_departures(ipv4: Tree, ipv6, ingress: tuple[str, ...],
                       roles: tuple[str, ...], exempt: tuple[str, ...]) -> set[str]:
    """The forwarding and `proxy_arp` codes of §6 that hold (shared).

    `roles` are the management and observation interfaces (the pass's;
    empty in the verify); `exempt` the interfaces whose forwarding is not
    read (`az-decoy0` in the verify; none at the pass).
    """

    found: set[str] = set()
    if ipv4 is None or any(name not in ipv4 for name in (*_HOST_WIDE, *ingress, *roles)):
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
            elif name in roles:
                if forwarding != 0:
                    found.add(FORWARDING_ROLE_ON)
            elif name not in exempt and forwarding != 0:
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
    return found


def _dump_departures(rules: tuple[int, bytes], routes: tuple[int, bytes],
                     contained: Callable[[list[dict]], Optional[bool]],
                     clear: Callable[[list[dict]], Optional[bool]]) -> set[str]:
    found: set[str] = set()
    status, output = rules
    listed = parse_json_list(output) if status == 0 else None
    result = None if listed is None else contained(listed)
    if result is None:
        found.add(FORWARDING_UNREADABLE)
    elif not result:
        found.add(INGRESS_CONTAINMENT_ABSENT)
    status, output = routes
    listed = parse_json_list(output) if status == 0 else None
    result = None if listed is None else clear(listed)
    if result is None:
        found.add(FORWARDING_UNREADABLE)
    elif not result:
        found.add(DECOY_PREFIX_ROUTED)
    return found


def reachability_departures(ipv4: Tree, ipv6, rules: tuple[int, bytes],
                            routes: tuple[int, bytes],
                            ingress: tuple[str, ...]) -> tuple[str, ...]:
    """The verify's reason codes of reachability §6 that hold now, in fixed order.

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
      before the main table, compared whole as the pass compares them
      (`_rules_exact`: no other selector, exactly one rule at 32766);
    * no route of `main` inside the decoy network's /24 but its own /30.

    Anything not in its closed form (`0\\n` or `1\\n`, an ingress absent, a
    dump that failed or cannot be read) is `forwarding_unreadable`.
    """

    found = _sysctl_departures(ipv4, ipv6, ingress, (), (BRIDGE,))
    found |= _dump_departures(rules, routes,
                              lambda listed: _rules_exact(listed, ingress),
                              _routes_clear)
    return tuple(code for code in REACHABILITY_CODES if code in found)


def _names_closed(ingress: object, management: object, observation: object) -> bool:
    """1 to 4 ingress names, every name allowed, no name in two places.

    Tuples of strings only; anything else is not closed (never an exception).
    """

    if not (type(ingress) is tuple and type(management) is tuple
            and type(observation) is tuple):
        return False
    names = (*ingress, *management, *observation)
    return (all(type(name) is str for name in names)
            and 1 <= len(ingress) <= MAX_INGRESS
            and len(set(names)) == len(names)
            and all(conf_entry_path(family, name) is not None
                    for name in names for family in _FAMILIES))


def _dump_closed(read: object) -> bool:
    """`(status, output)`: an `int` status and `bytes` output."""

    return (type(read) is tuple and len(read) == 2 and type(read[0]) is int
            and type(read[1]) is bytes)


def _tree_closed(tree: object) -> bool:
    """None, or `{str: {str: int | None}}` as `read_sysctls` gives it."""

    return tree is None or (type(tree) is dict and all(
        type(name) is str and type(values) is dict
        and all(type(key) is str and (value is None or type(value) is int)
                for key, value in values.items())
        for name, values in tree.items()))


def _trees_closed(ipv4: object, ipv6: object) -> bool:
    return _tree_closed(ipv4) and (ipv6 is IPV6_ABSENT or _tree_closed(ipv6))


def pass_reachability_departures(ipv4: Tree, ipv6, rules: tuple[int, bytes],
                                 routes: tuple[int, bytes], *,
                                 ingress: tuple[str, ...],
                                 management: tuple[str, ...],
                                 observation: tuple[str, ...]) -> tuple[str, ...]:
    """The pass's reason codes of reachability §6 that hold, in fixed order.

    **Implemented, not wired (#196 G6 preparation A):** nothing calls this,
    and the tier is withheld as `isolation_evidence_absent` whatever it
    would say. Pure. `ipv4` and `ipv6` are `read_sysctls(ingress)`'s;
    `rules` and `routes` are `(status, output)` of `ip -j -4 rule show` and
    `ip -j -4 route show table main`; `ingress`, `management` and
    `observation` are the interface names already resolved from their roles
    (grant §4.3; an ambiguous or missing identity has withheld before this).
    Empty when condition 6's forwarding part holds; otherwise the codes of
    `PASS_REACHABILITY_CODES` that hold:

    * `forwarding_ingress_off`: an ingress does not forward;
    * `forwarding_role_on`: a management or observation interface forwards;
    * `forwarding_host_wide`: IPv4 `all` or `default` forwards (R1);
    * `forwarding_other_on`: any other interface forwards, `az-decoy0`
      included (R1);
    * `forwarding_ipv6_on`: IPv6 forwards on `all`, `default` or any
      interface (R5);
    * `proxy_arp_on`: on `all` or an ingress (R1);
    * `ingress_containment_absent`: the rules below `main` are not exactly
      the local rule and each ingress's K1 pair (`_rules_exact`, R2);
    * `decoy_prefix_routed`: any route of `main` inside `10.255.196.0/24`
      (R2);
    * `forwarding_unreadable`: a read absent or not in its closed form, a
      dump that failed, or a name that is not 1 to 4 ingress names, each
      allowed by grant §4.3 and the rules of §6, in no two places; in that
      case, and for any argument of another shape (a name that is not a
      string, a dump that is not `(int, bytes)`, a tree that is not
      `{str: {str: int | None}}`), nothing else is judged and it is the only
      code: an argument never raises.
    """

    if not (_names_closed(ingress, management, observation)
            and _dump_closed(rules) and _dump_closed(routes)
            and _trees_closed(ipv4, ipv6)):
        return (FORWARDING_UNREADABLE,)
    found = _sysctl_departures(ipv4, ipv6, ingress, (*management, *observation), ())
    found |= _dump_departures(rules, routes,
                              lambda listed: _rules_exact(listed, ingress),
                              lambda listed: _routes_clear(listed, connected=False))
    return tuple(code for code in PASS_REACHABILITY_CODES if code in found)


def reachability_refusal(codes: tuple[str, ...]) -> Optional[str]:
    """`"<code>: <phrase>"` for the first of `codes`, or None when there is none.

    The form the controller's other withholding reasons take; the phrase is
    fixed per code and carries no name, prefix, address or value.
    """

    if not codes:
        return None
    return f"{codes[0]}: {REACHABILITY_PHRASES[codes[0]]}"
