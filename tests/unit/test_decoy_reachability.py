"""#196 G6 preparation A: the pass's reading of reachability §6, and G6 item (a).

`docs/deception-exposure-reachability.md` §6 and §9 (R1, R2, R5), and
`docs/deception-exposure-grant.md` §5 condition 6 and §6.3 "For G6" (a).
These tests pin, with values passed in (nothing here runs `ip` or `nft`,
reads the host's sysctls or talks to the service manager):

* `decoy_reachability.pass_reachability_departures`: each reason code of
  §6, in its fixed order; what the pass adds to the verify (the roles,
  `az-decoy0` not exempt, the rules compared whole, no route in the /24 at
  all); the interface-name rules and `conf_entry_path`;
* that the verify's judgement is the one G2 had but for the rules (its own
  tests are `test_decoy_watch.py`; here, that the two share the reads and
  the one rule comparison, `_rules_exact`, and differ only where §6 says),
  with networkd's K1 and the rehearsal's `ip rule add` K1 as the VM printed
  them (Debian 13, kernel 6.12, iproute2 6.15, networkd 257);
* `decoy_residue.exposure_residue_departures`: a masked unit still running,
  and the leftovers of a definition-less stop while no unit runs, judged on
  the namespace, the veth end and the bridge; the links are names as
  `netlink.read_links` yields them, and no table listing is taken
  (`docs/deception-exposure-wiring.md` §4.4, A1);
* `decoy_residue.read_netns`: the namespace looked up in `/run/netns`
  itself, not through `ip netns list` (#196 L2, H1(c)): no directory is no
  namespace, any other error and a link under the name are unreadable
  (read from a directory under `tmp_path`, never the host's);
* that both are leaves. That **nothing calls either** (no module of the
  product imports them but the verify, the tier is withheld as
  `isolation_evidence_absent` with both made to fail if called, and
  `_withholding_reason` is unchanged) is `test_g6_unwired.py`.

None of this is VM or hardware evidence.
"""

from __future__ import annotations

import ast
import errno
import inspect
import json
import os
import re
import stat
from pathlib import Path

import pytest

from azazel_nexus.activation import (
    DECEPTION_EXPOSURE_UNITS,
)
from azazel_nexus_runtime import decoy_reachability, decoy_residue, decoy_watch
from azazel_nexus_runtime.decoy_reachability import (
    DECOY_PREFIX_ROUTED,
    FORWARDING_HOST_WIDE,
    FORWARDING_INGRESS_OFF,
    FORWARDING_IPV6_ON,
    FORWARDING_OTHER_ON,
    FORWARDING_ROLE_ON,
    FORWARDING_UNREADABLE,
    INGRESS_CONTAINMENT_ABSENT,
    IPV6_ABSENT,
    PASS_REACHABILITY_CODES,
    PROXY_ARP_ON,
    REACHABILITY_CODES,
    REACHABILITY_PHRASES,
    conf_entry_path,
    pass_reachability_departures,
    reachability_departures,
    reachability_refusal,
)
from azazel_nexus_runtime.decoy_residue import (
    EXPOSURE_LEFTOVERS_PRESENT,
    EXPOSURE_STATE_UNREADABLE,
    EXPOSURE_UNIT_MASKED_RUNNING,
    EXPOSURE_UNITS,
    RESIDUE_CODES,
    RESIDUE_PHRASES,
    exposure_residue_departures,
    read_netns,
    residue_refusal,
)

REPO = Path(__file__).resolve().parents[2]
RUNTIME = REPO / "runtime" / "src" / "azazel_nexus_runtime"

INGRESS = ("eth9", "lan0")
MANAGEMENT = ("mgmt0",)
OBSERVATION = ("mon0",)


# -- the pass's reachability (§6) -------------------------------------------------


def _ipv4(**changes):
    """A host as §8 configures it, before the helper runs (no `az-decoy0`)."""

    tree = {
        "all": {"forwarding": 0, "proxy_arp": 0},
        "default": {"forwarding": 0},
        "lo": {"forwarding": 0},
        "eth9": {"forwarding": 1, "proxy_arp": 0},
        "lan0": {"forwarding": 1, "proxy_arp": 0},
        "mgmt0": {"forwarding": 0},
        "mon0": {"forwarding": 0},
        "wlan0": {"forwarding": 0},
    }
    for name, values in changes.items():
        if values is None:
            tree.pop(name)
        else:
            tree[name] = values
    return tree


def _ipv6(**changes):
    tree = {name: {"forwarding": 0}
            for name in ("all", "default", "lo", "eth9", "lan0", "mgmt0", "mon0")}
    for name, value in changes.items():
        tree[name] = {"forwarding": value}
    return tree


def _k1(name):
    return [{"priority": 1960, "src": "all", "dst": "10.255.196.0", "dstlen": 30,
             "iif": name, "table": "main", "suppress_prefixlen": 29},
            {"priority": 1961, "src": "all", "iif": name, "action": "blackhole"}]


def _rule_list(*extra, drop=(), ingress=INGRESS):
    rules = [{"priority": 0, "src": "all", "table": "local"}]
    for name in ingress:
        rules += _k1(name)
    rules = [rule for index, rule in enumerate(rules) if index not in drop]
    rules += list(extra)
    rules += [{"priority": 32766, "src": "all", "table": "main"},
              {"priority": 32767, "src": "all", "table": "default"}]
    return rules


def _rules(*extra, drop=(), ingress=INGRESS):
    return (0, json.dumps(_rule_list(*extra, drop=drop, ingress=ingress)).encode())


def _routes(*extra):
    routes = [
        {"dst": "default", "gateway": "192.168.50.254", "dev": "mgmt0", "flags": []},
        {"dst": "10.0.0.0/8", "gateway": "192.168.50.1", "dev": "mgmt0", "flags": []},
        {"dst": "192.168.50.0/24", "dev": "mgmt0", "protocol": "kernel", "scope": "link",
         "prefsrc": "192.168.50.2", "flags": []},
    ]
    return (0, json.dumps(routes + list(extra)).encode())


def _pass(ipv4=None, ipv6=None, rules=None, routes=None, ingress=INGRESS,
          management=MANAGEMENT, observation=OBSERVATION):
    return pass_reachability_departures(
        _ipv4() if ipv4 is None else ipv4, _ipv6() if ipv6 is None else ipv6,
        _rules() if rules is None else rules, _routes() if routes is None else routes,
        ingress=ingress, management=management, observation=observation)


def test_a_host_configured_as_section_8_says_holds():
    assert _pass() == ()
    assert _pass(ipv6=IPV6_ABSENT) == ()
    assert _pass(management=(), observation=()) == ()
    assert reachability_refusal(()) is None


def test_the_codes_are_the_nine_of_section_6_in_its_order():
    assert PASS_REACHABILITY_CODES == (
        "forwarding_ingress_off", "forwarding_role_on", "forwarding_host_wide",
        "forwarding_other_on", "forwarding_ipv6_on", "proxy_arp_on",
        "ingress_containment_absent", "decoy_prefix_routed", "forwarding_unreadable")
    # The verify's eight, unchanged (G2): the role code is the pass's alone.
    assert REACHABILITY_CODES == tuple(
        code for code in PASS_REACHABILITY_CODES if code != FORWARDING_ROLE_ON)
    assert set(REACHABILITY_PHRASES) == set(PASS_REACHABILITY_CODES)


@pytest.mark.parametrize("ipv4,ipv6,rules,routes,expected", [
    (_ipv4(lan0={"forwarding": 0, "proxy_arp": 0}), None, None, None,
     (FORWARDING_INGRESS_OFF,)),
    (_ipv4(mgmt0={"forwarding": 1}), None, None, None, (FORWARDING_ROLE_ON,)),
    (_ipv4(mon0={"forwarding": 1}), None, None, None, (FORWARDING_ROLE_ON,)),
    (_ipv4(default={"forwarding": 1}), None, None, None, (FORWARDING_HOST_WIDE,)),
    (_ipv4(all={"forwarding": 1, "proxy_arp": 0}), None, None, None,
     (FORWARDING_HOST_WIDE,)),
    (_ipv4(wlan0={"forwarding": 1}), None, None, None, (FORWARDING_OTHER_ON,)),
    (None, _ipv6(mgmt0=1), None, None, (FORWARDING_IPV6_ON,)),
    (None, _ipv6(all=1), None, None, (FORWARDING_IPV6_ON,)),
    (_ipv4(eth9={"forwarding": 1, "proxy_arp": 1}), None, None, None, (PROXY_ARP_ON,)),
    (_ipv4(all={"forwarding": 0, "proxy_arp": 1}), None, None, None, (PROXY_ARP_ON,)),
    (None, None, _rules(drop=(4,)), None, (INGRESS_CONTAINMENT_ABSENT,)),
    (None, None, None, _routes({"dst": "10.255.196.2", "dev": "mgmt0", "flags": []}),
     (DECOY_PREFIX_ROUTED,)),
    (_ipv4(wlan0={"forwarding": None}), None, None, None, (FORWARDING_UNREADABLE,)),
    (_ipv4(mon0=None), None, None, None, (FORWARDING_UNREADABLE,)),
    (_ipv4(eth9=None), None, None, None, (FORWARDING_UNREADABLE,)),
    (None, None, None, None, ()),
])
def test_each_reason_code_alone(ipv4, ipv6, rules, routes, expected):
    assert _pass(ipv4, ipv6, rules, routes) == expected


def test_every_code_at_once_comes_in_the_fixed_order():
    found = _pass(
        _ipv4(all={"forwarding": 1, "proxy_arp": 1}, lan0={"forwarding": 0, "proxy_arp": 0},
              mgmt0={"forwarding": 1}, wlan0={"forwarding": 1}, lo={"forwarding": None}),
        _ipv6(eth9=1), _rules(drop=(1,)),
        _routes({"dst": "10.255.196.0/30", "dev": "az-decoy0", "flags": []}))
    assert found == PASS_REACHABILITY_CODES
    assert reachability_refusal(found) == (
        "forwarding_ingress_off: forwarding is not on for every ingress interface")


def test_a_role_that_forwards_is_the_role_code_not_the_other_code():
    """§6: the roles are their own row; the verify, with no roles, says `other`."""

    ipv4 = _ipv4(mgmt0={"forwarding": 1})
    assert _pass(ipv4) == (FORWARDING_ROLE_ON,)
    assert _pass(ipv4, management=()) == (FORWARDING_OTHER_ON,)


def test_the_bridge_is_not_exempt_at_the_pass():
    """It does not exist before the helper runs; a value for it is another
    interface that forwards. The verify does not read it (G2)."""

    ipv4 = _ipv4(**{"az-decoy0": {"forwarding": 1}})
    assert _pass(ipv4) == (FORWARDING_OTHER_ON,)
    assert reachability_departures(ipv4, _ipv6(), _rules(), _routes(), INGRESS) == ()


def test_no_route_inside_the_slash_24_at_all_at_the_pass():
    """The verify accepts the bridge's connected /30 once; the pass none."""

    connected = {"dst": "10.255.196.0/30", "dev": "az-decoy0", "protocol": "kernel",
                 "scope": "link", "prefsrc": "10.255.196.1", "flags": []}
    assert _pass(routes=_routes(connected)) == (DECOY_PREFIX_ROUTED,)
    ipv4 = _ipv4(**{"az-decoy0": {"forwarding": 1}})
    assert reachability_departures(ipv4, _ipv6(), _rules(), _routes(connected),
                                   INGRESS) == ()
    for route in ({"dst": "10.255.196.0/24", "dev": "mgmt0"},
                  {"dst": "10.255.196.4/30", "dev": "mgmt0"},
                  {"dst": "10.255.196.255", "dev": "lo", "type": "unicast"}):
        assert _pass(routes=_routes(route)) == (DECOY_PREFIX_ROUTED,), route
    # Wider routes are suppressed by K1 and not counted.
    assert _pass(routes=_routes({"dst": "10.255.0.0/16", "dev": "mgmt0"})) == ()


#: Every extra key iproute2 6.15 prints for a selector or action of a rule
#: added by `ip rule` (container-checked): any of them fails the comparison.
_EXTRA_KEYS = [
    {"not": None}, {"srclen": 8}, {"tos": "0x10"}, {"fwmark": "0x5"}, {"fwmask": "0xff"},
    {"oif": "mgmt0"}, {"uid_start": 1, "uid_end": 2}, {"ipproto": "tcp"},
    {"sport_start": 1, "sport_end": 2}, {"dport": 3}, {"l3mdev": None}, {"goto": 1966},
    {"tun_id": 5}, {"suppress_ifgroup": "3"}, {"flow_to": "4"}, {"iif_detached": None},
    # As printed on the VM (Debian 13, kernel 6.12, iproute2 6.15; review of
    # #293): `dscp` is shown there, though not in the container.
    {"dscp": "AF11"}, {"uid_start": 100, "uid_end": 200}, {"dport": 22},
]


@pytest.mark.parametrize("extra", _EXTRA_KEYS, ids=lambda extra: "+".join(extra))
@pytest.mark.parametrize("index", [0, 1, 2])
def test_any_other_selector_on_an_accepted_rule_fails(index, extra):
    rules = _rule_list()
    rules[index] = {**rules[index], **extra}
    assert _pass(rules=(0, json.dumps(rules).encode())) == (INGRESS_CONTAINMENT_ABSENT,)
    # The verify compares the same way (#196 R4, one comparison).
    assert _verify((0, json.dumps(rules).encode())) == (INGRESS_CONTAINMENT_ABSENT,)


def _verify(rules, ingress=INGRESS):
    """The verify's departures with everything else as the verify finds it."""

    connected = {"dst": "10.255.196.0/30", "dev": "az-decoy0", "protocol": "kernel",
                 "scope": "link", "prefsrc": "10.255.196.1", "flags": []}
    return reachability_departures(_ipv4(**{"az-decoy0": {"forwarding": 1}}), _ipv6(),
                                   rules, _routes(connected), ingress)


#: `ip -j -4 rule show` (no `-d`) on the VM (Debian 13, kernel 6.12,
#: iproute2 6.15, systemd-networkd 257; a mechanism check, not hardware
#: evidence), K1 made by networkd from `[RoutingPolicyRule]` on a dummy link,
#: verbatim but for the interface name: the discard rule carries
#: `"table":"main"` and both carry `"protocol":"static"` even without `-d`.
def _networkd_k1(name):
    return [{"priority": 1960, "src": "all", "dst": "10.255.196.0", "dstlen": 30,
             "iif": name, "table": "main", "suppress_prefixlen": 29,
             "protocol": "static"},
            {"priority": 1961, "src": "all", "iif": name, "table": "main",
             "action": "blackhole", "protocol": "static"}]


#: The defaults as the VM prints them (`-d` adds `"protocol":"kernel"`).
_DEFAULTS = [{"priority": 0, "src": "all", "table": "local"},
             {"priority": 32766, "src": "all", "table": "main"},
             {"priority": 32767, "src": "all", "table": "default"}]


def _listing(*k1):
    rules = [_DEFAULTS[0]]
    for pair in k1:
        rules += pair
    return (0, json.dumps(rules + _DEFAULTS[1:]).encode())


def test_networkds_k1_as_the_vm_prints_it_holds_for_the_verify_and_the_pass():
    rules = _listing(*(_networkd_k1(name) for name in INGRESS))
    assert _verify(rules) == ()
    assert _pass(rules=rules) == ()
    # With `-d` the defaults carry `"protocol":"kernel"`: left out too.
    detailed = [{**rule, "protocol": rule.get("protocol", "kernel")}
                for rule in json.loads(rules[1])]
    assert _verify((0, json.dumps(detailed).encode())) == ()
    assert _pass(rules=(0, json.dumps(detailed).encode())) == ()


def test_the_rehearsals_k1_added_by_ip_rule_holds_for_the_verify_and_the_pass():
    """The VM rehearsal: two K1 rules added with `ip rule add` on the test
    ingress, printed as the VM prints them (no table on the discard rule)."""

    plain = [{"priority": 1961, "src": "all", "iif": "azin0", "action": "blackhole"},
             {"priority": 1960, "src": "all", "dst": "10.255.196.0", "dstlen": 30,
              "iif": "azin0", "table": "main", "suppress_prefixlen": 29}]
    rules = _listing(plain)
    ipv4 = _ipv4(azin0={"forwarding": 1, "proxy_arp": 0},
                 eth9={"forwarding": 0}, lan0={"forwarding": 0},
                 **{"az-decoy0": {"forwarding": 1}})
    connected = {"dst": "10.255.196.0/30", "dev": "az-decoy0", "protocol": "kernel",
                 "scope": "link", "prefsrc": "10.255.196.1", "flags": []}
    assert reachability_departures(ipv4, _ipv6(), rules, _routes(connected),
                                   ("azin0",)) == ()
    # One of each form on two ingress is the same containment.
    assert _verify(_listing(_k1("eth9"), _networkd_k1("lan0"))) == ()


@pytest.mark.parametrize("table", ["local", "default", "100", "MAIN", 254, None, ["main"]])
def test_the_discard_rule_takes_no_other_table(table):
    """Two complete forms of the discard rule only: no table, or `main`."""

    for form in (_k1, _networkd_k1):
        pair = form("eth9")
        pair[1] = {**pair[1], "table": table}
        rules = _listing(pair, _k1("lan0"))
        assert _verify(rules) == (INGRESS_CONTAINMENT_ABSENT,), (form, table)
        assert _pass(rules=rules) == (INGRESS_CONTAINMENT_ABSENT,), (form, table)


def test_networkds_form_is_still_compared_whole():
    """`table main` is set aside only on the discard rule, nothing else."""

    for change in ({"fwmark": "0x1"}, {"dscp": "AF11"}, {"iif": "wlan0"},
                   {"action": "unreachable"}, {"priority": 1962}):
        pair = _networkd_k1("eth9")
        pair[1] = {**pair[1], **change}
        rules = _listing(pair, _networkd_k1("lan0"))
        assert _verify(rules) == (INGRESS_CONTAINMENT_ABSENT,), change
        assert _pass(rules=rules) == (INGRESS_CONTAINMENT_ABSENT,), change
    # A `table main` lookup rule at 1961 without the discard is not K1.
    pair = _networkd_k1("eth9")
    del pair[1]["action"]
    assert _verify(_listing(pair, _networkd_k1("lan0"))) == (INGRESS_CONTAINMENT_ABSENT,)


@pytest.mark.parametrize("change", [
    {"src": "10.0.0.0"}, {"dst": "10.255.196.4"}, {"dstlen": 29}, {"table": "local"},
    {"suppress_prefixlen": 28}, {"dstlen": 30.0}, {"suppress_prefixlen": True},
    {"iif": "wlan0"}, {"action": "blackhole"},
])
def test_the_lookup_rule_is_compared_whole(change):
    rules = _rule_list()
    rules[1] = {**rules[1], **change}
    assert _pass(rules=(0, json.dumps(rules).encode())) == (INGRESS_CONTAINMENT_ABSENT,)


def test_the_protocol_is_left_out_and_nothing_else_is():
    rules = [{**rule, "protocol": "static"} if rule["priority"] in (1960, 1961) else rule
             for rule in _rule_list()]
    rules[0] = {**rules[0], "protocol": "kernel"}
    assert _pass(rules=(0, json.dumps(rules).encode())) == ()


@pytest.mark.parametrize("rules", [
    _rules({"priority": 1962, "src": "all", "table": "main"}),
    _rules({"priority": 100, "src": "all", "fwmark": "0xca6c", "table": "52"}),
    _rules(*_k1("eth9")),                              # a pair twice
    _rules(*_k1("wlan0")),                             # a pair for another interface
    _rules(ingress=("eth9",)),                         # an ingress without its pair
    _rules({"priority": 0, "src": "all", "table": "local"}),  # the local rule twice
    _rules(drop=(0,)),                                 # no local rule
])
def test_any_other_rule_before_main_fails(rules):
    assert _pass(rules=rules) == (INGRESS_CONTAINMENT_ABSENT,)


@pytest.mark.parametrize("rules,routes", [
    ((1, b""), None), (None, (2, b"")), ((0, b"not json"), None), ((0, b"{}"), None),
    ((0, b'[{"priority": "0"}]'), None), (None, (0, b'[{"dst": 7}]')),
    (None, (0, b'[{"dst": "10.255.196.1/29"}]')), (None, (0, b'[{"dst": "fe80::/64"}]')),
])
def test_a_dump_that_cannot_be_read_is_unreadable(rules, routes):
    assert _pass(rules=rules, routes=routes) == (FORWARDING_UNREADABLE,)


@pytest.mark.parametrize("ingress,management,observation", [
    ((), (), ()),
    (("eth9", "lan0", "eth1", "eth2", "eth3"), (), ()),
    (("eth9",), ("eth9",), ()),
    (("eth9",), ("mgmt0",), ("mgmt0",)),
    (("eth9", "eth9"), (), ()),
    *[((name,), (), ()) for name in (".", "..", "all", "default", "lo", "LO", "Default",
                                     "az-decoy0", "AZ-DECOY-host0", "a/b", "", "x" * 16,
                                     "eth 0", "-eth0", "123", "eth0\n")],
    *[(("eth9",), (name,), ()) for name in (".", "..", "all", "default", "lo")],
    *[(("eth9",), (), (name,)) for name in (".", "..", "all", "default", "lo")],
])
def test_a_name_outside_the_rules_withholds_and_nothing_else_is_judged(
        ingress, management, observation):
    assert _pass(_ipv4(all={"forwarding": 1, "proxy_arp": 1}), ingress=ingress,
                 management=management, observation=observation) == (FORWARDING_UNREADABLE,)


_MAIN = {"priority": 32766, "src": "all", "table": "main"}


@pytest.mark.parametrize("change", [
    "second",           # another rule at 32766 could act before `main`
    "missing",          # no `lookup main` at all
    "selector",         # `main` itself with a selector
    "other table",      # 32766 pointing elsewhere
])
def test_exactly_one_main_rule_at_its_priority(change):
    """Review of #293 item 4: rules of equal priority run in the order added."""

    rules = [rule for rule in _rule_list() if rule["priority"] != 32766]
    if change == "second":
        rules += [_MAIN, {"priority": 32766, "src": "all", "iif": "eth9", "table": "100"}]
    elif change == "selector":
        rules.append({**_MAIN, "fwmark": "0x1"})
    elif change == "other table":
        rules.append({**_MAIN, "table": "100"})
    assert _pass(rules=(0, json.dumps(rules).encode())) == (INGRESS_CONTAINMENT_ABSENT,)
    # The verify reads priority 32766 the same way (#196 R4).
    assert _verify((0, json.dumps(rules).encode())) == (INGRESS_CONTAINMENT_ABSENT,)


def test_the_main_rules_protocol_is_left_out_too():
    rules = [{**rule, "protocol": "kernel"} if rule["priority"] == 32766 else rule
             for rule in _rule_list()]
    assert _pass(rules=(0, json.dumps(rules).encode())) == ()


_BAD_SHAPES = [
    {"ingress": 7}, {"ingress": "eth9"}, {"ingress": ["eth9"]}, {"ingress": (7,)},
    {"ingress": (None,)}, {"management": None}, {"observation": "mon0"},
    {"management": (b"mgmt0",)},
    {"rules": None}, {"rules": [0, b"[]"]}, {"rules": (0,)}, {"rules": (0, b"[]", 1)},
    {"rules": (0, "[]")}, {"rules": ("0", b"[]")}, {"rules": (None, b"[]")},
    {"routes": None}, {"routes": (0, None)}, {"routes": (0, bytearray(b"[]"))},
    {"routes": b"[]"},
    {"ipv4": []}, {"ipv4": {"all": None}}, {"ipv4": {"all": {"forwarding": "1"}}},
    {"ipv4": {7: {"forwarding": 0}}}, {"ipv4": {"all": {"forwarding": True}}},
    {"ipv6": []}, {"ipv6": {"all": [0]}}, {"ipv6": "absent"},
]


@pytest.mark.parametrize("bad", _BAD_SHAPES, ids=lambda bad: repr(bad)[:40])
def test_an_argument_of_another_shape_is_unreadable_never_an_exception(bad):
    """Review of #293 item 3."""

    arguments = {"ipv4": _ipv4(), "ipv6": _ipv6(), "rules": _rules(), "routes": _routes(),
                 "ingress": INGRESS, "management": MANAGEMENT, "observation": OBSERVATION}
    arguments.update(bad)
    assert pass_reachability_departures(
        arguments.pop("ipv4"), arguments.pop("ipv6"), arguments.pop("rules"),
        arguments.pop("routes"), **arguments) == (FORWARDING_UNREADABLE,)


def test_absent_trees_are_still_judged_as_reads():
    for ipv4, ipv6 in ((_ipv4(), None), (None, IPV6_ABSENT)):
        assert pass_reachability_departures(
            ipv4, ipv6, _rules(), _routes(), ingress=INGRESS, management=MANAGEMENT,
            observation=OBSERVATION) == (FORWARDING_UNREADABLE,)


def test_conf_entry_path_fixes_the_parent_and_refuses_the_reserved_names():
    assert conf_entry_path("ipv4", "eth9") == "/proc/sys/net/ipv4/conf/eth9"
    assert conf_entry_path("ipv6", "eth.9") == "/proc/sys/net/ipv6/conf/eth.9"
    for name in (".", "..", "all", "default", "lo", "ALL", "a/b", "../x", "", None, 7,
                 "az-decoy0", "x" * 16):
        assert conf_entry_path("ipv4", name) is None, name
    for family in ("ipv5", "ipv4/conf", "", "../ipv4"):
        assert conf_entry_path(family, "eth9") is None


def test_the_name_rule_is_the_scopes():
    """One rule for a role's names, the one the scope's ingress names pass."""

    from azazel_nexus import decoy_scope

    assert decoy_reachability.interface_name_allowed is decoy_scope.interface_name_allowed
    for name in ("eth0", "enp1s0", "br-lan.10", "wg_0"):
        assert decoy_scope.interface_name_allowed(name)
    for name in ("lo", "all", "default", ".", "..", "az-decoy9", "-x", "42", "", None):
        assert not decoy_scope.interface_name_allowed(name)


def test_no_phrase_carries_a_name_an_address_or_a_value():
    phrases = list(REACHABILITY_PHRASES.values()) + list(RESIDUE_PHRASES.values())
    for phrase in phrases:
        assert not re.search(r"\d", re.sub("IPv[46]", "", phrase)), phrase
        for word in ("eth", "lan0", "mgmt", "az-decoy", "azazel-decoy", "azazel_decoy",
                     "10.255"):
            assert word not in phrase, phrase


def test_the_verify_judgement_is_g2s_but_for_the_rules():
    """The shared reads did not change the verify (`test_decoy_watch.py` pins it
    in full): the same names are the same objects, and the departures for a
    G2 host are those G2 gave. The rules are the exception (#196 R4): the
    verify compares them with the pass's one comparison."""

    for name in ("reachability_departures", "read_sysctls", "IPV6_ABSENT",
                 "REACHABILITY_CODES", "_rules_exact"):
        assert getattr(decoy_watch, name) is getattr(decoy_reachability, name), name
    assert not hasattr(decoy_reachability, "_rules_contained")
    ipv4 = _ipv4(**{"az-decoy0": {"forwarding": 1}, "mgmt0": {"forwarding": 1}})
    assert reachability_departures(ipv4, _ipv6(), _rules(), _routes(), INGRESS) == (
        FORWARDING_OTHER_ON,)
    # A selector the pass refuses, the verify now refuses too.
    rules = _rule_list()
    rules[1] = {**rules[1], "fwmark": "0x5"}
    assert _verify((0, json.dumps(rules).encode())) == (INGRESS_CONTAINMENT_ABSENT,)
    # The verify's own differences stay: `az-decoy0` forwards, its /30 routed.
    assert _verify(_rules()) == ()
    assert _pass(_ipv4(**{"az-decoy0": {"forwarding": 1}})) == (FORWARDING_OTHER_ON,)


def test_one_function_compares_the_rules_for_both():
    """Neither judgement has a comparison of its own (#196 R4)."""

    source = Path(decoy_reachability.__file__).read_text(encoding="utf-8")
    assert source.count("lambda listed: _rules_exact(listed, ingress)") == 2
    assert "_expected_rules(" in source and source.count("def _rules_") == 1


# -- G6 item (a): a masked unit still running, and leftovers ---------------------


def _units(**changes):
    units = {unit: {"LoadState": "masked", "UnitFileState": "masked",
                    "ActiveState": "inactive"} for unit in EXPOSURE_UNITS}
    for unit, values in changes.items():
        units[unit] = {**units[unit], **values}
    return units


#: `read_netns()`: `/run/netns` read, no `azazel-decoy` in it.
_NONE = (0, None)
#: `read_netns()`: the nsfs bind, a regular file as `lstat` gives it.
_NAMESPACE = (0, stat.S_IFREG | 0o444)
#: `tuple(r.name for r in netlink.read_links())` on a host with no decoy link.
_NO_LINKS = ("lo", "eth9")


def _residue(units=None, netns=_NONE, links=_NO_LINKS):
    return exposure_residue_departures(_units() if units is None else units,
                                       netns, links)


NSD, NETD, DECOYD = EXPOSURE_UNITS


def test_the_units_are_the_exposure_tier():
    assert EXPOSURE_UNITS == DECEPTION_EXPOSURE_UNITS
    assert RESIDUE_CODES == (EXPOSURE_UNIT_MASKED_RUNNING, EXPOSURE_LEFTOVERS_PRESENT,
                             EXPOSURE_STATE_UNREADABLE)


def test_a_clean_host_says_nothing():
    assert _residue() == ()
    unmasked = {unit: {"UnitFileState": "enabled", "LoadState": "loaded"}
                for unit in EXPOSURE_UNITS}
    assert _residue(_units(**unmasked)) == ()
    # No `/run/netns` at all is no namespace.
    assert _residue(netns=(errno.ENOENT, None)) == ()
    assert residue_refusal(()) is None


@pytest.mark.parametrize("masked", [{"LoadState": "masked"},
                                    {"LoadState": "loaded", "UnitFileState": "masked"},
                                    {"LoadState": "loaded",
                                     "UnitFileState": "masked-runtime"}])
@pytest.mark.parametrize("active", ["active", "activating", "deactivating", "reloading",
                                    "refreshing", "maintenance"])
def test_a_masked_unit_still_running_is_refused(masked, active):
    """Second G4 rehearsal: masked and `daemon-reload`ed while running."""

    found = _residue(_units(**{DECOYD: {**masked, "ActiveState": active}}))
    assert found == (EXPOSURE_UNIT_MASKED_RUNNING,)
    assert residue_refusal(found).startswith("exposure_unit_masked_running: ")


@pytest.mark.parametrize("active", ["inactive", "failed"])
def test_a_masked_unit_that_is_stopped_is_not(active):
    assert _residue(_units(**{NETD: {"ActiveState": active}})) == ()


def test_a_running_unit_that_is_not_masked_is_not_this_check():
    running = {"LoadState": "loaded", "UnitFileState": "enabled", "ActiveState": "active"}
    assert _residue(_units(**{DECOYD: running})) == ()


@pytest.mark.parametrize("netns,links", [
    (_NAMESPACE, _NO_LINKS),
    (_NONE, ("az-decoy-host0",)),
    (_NONE, ("lo", "az-decoy0")),
    (_NONE, ("lo", "eth9", "az-decoy-host0", "az-decoy0")),
    (_NAMESPACE, ("lo", "az-decoy-host0", "az-decoy0")),
])
@pytest.mark.parametrize("active", ["inactive", "failed"])
def test_leftovers_while_no_unit_runs_are_refused(netns, links, active):
    """Third G4 rehearsal: two veth links and a namespace left behind."""

    units = _units(**{unit: {"ActiveState": active} for unit in EXPOSURE_UNITS})
    assert _residue(units, netns, links) == (EXPOSURE_LEFTOVERS_PRESENT,)


def test_leftovers_while_a_unit_runs_are_its_own_objects():
    running = {"LoadState": "loaded", "UnitFileState": "enabled", "ActiveState": "active"}
    netns = _NAMESPACE
    assert _residue(_units(**{NSD: running}), netns) == ()
    # Masked and running with leftovers: the running unit is the reason.
    assert _residue(_units(**{NSD: {"ActiveState": "active"}}), netns) == (
        EXPOSURE_UNIT_MASKED_RUNNING,)


_RUNNING = {"LoadState": "loaded", "UnitFileState": "enabled", "ActiveState": "active"}
_STOPPED_UNIT = {"LoadState": "loaded", "UnitFileState": "enabled",
                 "ActiveState": "inactive"}
_HOST_VETH = ("lo", "az-decoy-host0")
_BRIDGE = ("lo", "az-decoy0")


@pytest.mark.parametrize("running,netns,links,expected", [
    # Review of #293 item 2: the decoy running alone, its two owners stopped.
    ((DECOYD,), _NAMESPACE, _NO_LINKS, (EXPOSURE_LEFTOVERS_PRESENT,)),
    ((DECOYD,), _NONE, _HOST_VETH, (EXPOSURE_LEFTOVERS_PRESENT,)),
    ((DECOYD,), _NONE, _BRIDGE, (EXPOSURE_LEFTOVERS_PRESENT,)),
    ((DECOYD,), _NONE, _NO_LINKS, ()),
    # The helper stopped: its bridge left; the namespace unit's are its own.
    ((NSD, DECOYD), _NAMESPACE, _HOST_VETH, ()),
    ((NSD,), _NONE, _BRIDGE, (EXPOSURE_LEFTOVERS_PRESENT,)),
    ((NSD, DECOYD), _NAMESPACE, ("lo", "az-decoy-host0", "az-decoy0"),
     (EXPOSURE_LEFTOVERS_PRESENT,)),
    # The namespace unit stopped: its namespace or veth end left.
    ((NETD, DECOYD), _NONE, _BRIDGE, ()),
    ((NETD,), _NAMESPACE, _BRIDGE, (EXPOSURE_LEFTOVERS_PRESENT,)),
    ((NETD,), _NONE, _HOST_VETH, (EXPOSURE_LEFTOVERS_PRESENT,)),
    # All three running: every object is theirs.
    ((NSD, NETD, DECOYD), _NAMESPACE, ("az-decoy0", "az-decoy-host0"), ()),
])
def test_leftovers_are_judged_per_owner(running, netns, links, expected):
    units = _units(**{unit: (_RUNNING if unit in running else _STOPPED_UNIT)
                      for unit in EXPOSURE_UNITS})
    assert _residue(units, netns, links) == expected


@pytest.mark.parametrize("running", [(), (DECOYD,), (NSD,), (NSD, DECOYD)])
def test_the_table_is_not_judged(running):
    """Wiring §4.4, A1 and §10 item 5: the pass takes no table listing. A
    leftover `inet azazel_decoy` with no leftover bridge passes here and is
    the helper's to refuse (`HELPER_ABSENT`)."""

    units = _units(**{unit: (_RUNNING if unit in running else _STOPPED_UNIT)
                      for unit in EXPOSURE_UNITS})
    assert _residue(units, _NONE, _NO_LINKS) == ()
    assert list(inspect.signature(exposure_residue_departures).parameters) == [
        "units", "netns", "links"]
    source = Path(decoy_residue.__file__).read_text(encoding="utf-8")
    assert "NFT_TABLE" not in source and "_table_present" not in source


@pytest.mark.parametrize("active,expected", [
    ("active", (EXPOSURE_UNIT_MASKED_RUNNING,)),
    ("deactivating", (EXPOSURE_UNIT_MASKED_RUNNING,)),
    ("inactive", ()), ("failed", ()),
])
def test_a_unit_whose_file_is_gone_counts_as_masked(active, expected):
    """Review of #293 item 2: `not-found` while running has no definition either."""

    gone = {"LoadState": "not-found", "UnitFileState": "", "ActiveState": active}
    units = _units(**{unit: _STOPPED_UNIT for unit in EXPOSURE_UNITS})
    units[NETD] = gone
    assert _residue(units) == expected


def test_other_links_are_not_leftovers():
    # `az-decoy-ns0` is the namespace's end: inside it, never in the host's dump.
    assert _residue(links=("az-decoy-ns0", "az-decoy1", "az-decoy0x", "AZ-DECOY0",
                           "azazel_decoy", "")) == ()
    assert _residue(links=()) == ()


@pytest.mark.parametrize("units", [
    {},
    {unit: {} for unit in EXPOSURE_UNITS},
    {**_units(), "azazel-decoy-verify.service": _units()[NSD]},
    _units(**{NSD: {"ActiveState": "running"}}),
    _units(**{NSD: {"LoadState": "Masked"}}),
    _units(**{NSD: {"UnitFileState": None}}),
    {unit: "masked" for unit in EXPOSURE_UNITS},
    None,
])
def test_a_unit_state_not_in_its_closed_form_is_unreadable(units):
    assert exposure_residue_departures(units, _NONE, _NO_LINKS) == (
        EXPOSURE_STATE_UNREADABLE,)


@pytest.mark.parametrize("netns,links", [
    ((errno.EACCES, None), _NO_LINKS),
    ((errno.ENOTDIR, None), _NO_LINKS),
    ((errno.ELOOP, None), _NO_LINKS),
    ((0, stat.S_IFLNK | 0o777), _NO_LINKS),
    ((0, stat.S_IFDIR | 0o755), _NO_LINKS),
    ((errno.ENOENT, stat.S_IFREG | 0o444), _NO_LINKS),
    ((0, b""), _NO_LINKS),
    ((0, b'[{"name":"azazel-decoy"}]'), _NO_LINKS),
    ((True, None), _NO_LINKS),
    ("", _NO_LINKS),
    # The link dump failed (`NetlinkUnavailable`, `NetlinkMalformed`).
    (_NONE, None),
    # A record without a name could be any link, the bridge among them.
    (_NONE, (None,)),
    (_NONE, ("lo", None, "eth9")),
    (_NAMESPACE, ("lo", None)),
    (_NONE, ("lo", None, "az-decoy0")),
    # Not the names as `read_links` yields them.
    (_NONE, ["lo", "eth9"]),
    (_NONE, frozenset({"lo"})),
    (_NONE, "az-decoy0"),
    (_NONE, ("lo", b"az-decoy0")),
    (_NONE, (0, b'[{"ifname":"lo"}]')),
])
def test_an_object_read_that_cannot_be_read_is_unreadable(netns, links):
    assert _residue(None, netns, links) == (EXPOSURE_STATE_UNREADABLE,)
    # The running-mask judgement stands on the unit states alone.
    masked = _units(**{NSD: {"ActiveState": "active"}})
    assert _residue(masked, netns, links) == (
        EXPOSURE_UNIT_MASKED_RUNNING, EXPOSURE_STATE_UNREADABLE)
    assert residue_refusal(_residue(None, netns, links)) == (
        "exposure_state_unreadable: " + RESIDUE_PHRASES[EXPOSURE_STATE_UNREADABLE])


def test_the_links_are_the_names_read_links_yields():
    """The future pass hands `tuple(r.name for r in netlink.read_links())`."""

    from azazel_nexus_runtime.netlink import LinkRecord

    def names(*pairs):
        return tuple(LinkRecord(index, name, None, reason="absent").name
                     for index, name in pairs)

    stopped = _stopped_units()
    assert _residue(stopped, _NONE, names((1, "lo"), (2, "eth9"))) == ()
    assert _residue(stopped, _NONE, names((1, "lo"), (7, "az-decoy-host0"))) == (
        EXPOSURE_LEFTOVERS_PRESENT,)
    assert _residue(stopped, _NONE, names((1, "lo"), (8, "az-decoy0"))) == (
        EXPOSURE_LEFTOVERS_PRESENT,)
    assert _residue(stopped, _NONE, names((1, "lo"), (9, None))) == (
        EXPOSURE_STATE_UNREADABLE,)


# -- the namespace read from /run/netns, not `ip netns list` (#196 L2, H1(c)) ----

def _stopped_units():
    return _units(**{unit: _STOPPED_UNIT for unit in EXPOSURE_UNITS})


@pytest.fixture
def netns_dir(tmp_path, monkeypatch):
    path = tmp_path / "netns"
    monkeypatch.setattr(decoy_residue, "_NETNS", str(path))
    return path


def test_the_netns_directory_is_the_one_the_namespace_unit_writes():
    from azazel_nexus_runtime.hardening import NETNS_DIRECTORY

    assert decoy_residue._NETNS == NETNS_DIRECTORY == "/run/netns"
    assert decoy_residue.NAMESPACE == "azazel-decoy"


def test_no_netns_directory_is_no_namespace(netns_dir):
    """`ENOENT` opening `/run/netns`: nothing was ever created (a clean boot
    before the tmpfiles rule, or a host without it)."""

    assert read_netns() == (errno.ENOENT, None)
    assert _residue(_stopped_units(), read_netns()) == ()


def test_an_empty_or_other_netns_directory_is_no_namespace(netns_dir):
    netns_dir.mkdir()
    assert read_netns() == (0, None)
    (netns_dir / "other").touch()
    (netns_dir / "azazel-decoy2").touch()
    assert read_netns() == (0, None)
    assert _residue(_stopped_units(), read_netns()) == ()


def test_the_namespace_entry_is_a_leftover_while_its_unit_is_stopped(netns_dir):
    """`ip netns add` leaves an empty regular file the nsfs file is bound onto;
    `lstat` sees that regular file, bound or not."""

    netns_dir.mkdir()
    (netns_dir / "azazel-decoy").touch()
    error, mode = read_netns()
    assert error == 0 and stat.S_ISREG(mode)
    assert _residue(_stopped_units(), read_netns()) == (EXPOSURE_LEFTOVERS_PRESENT,)
    running = _units(**{unit: (_RUNNING if unit == NSD else _STOPPED_UNIT)
                        for unit in EXPOSURE_UNITS})
    assert _residue(running, read_netns()) == ()


@pytest.mark.parametrize("target", ["file", "missing", "dir"])
def test_a_namespace_entry_that_is_a_link_is_unreadable(netns_dir, target):
    """Not followed: a link named `azazel-decoy` is not what `ip netns add`
    makes, wherever it points."""

    netns_dir.mkdir()
    pointed = netns_dir.parent / "pointed"
    if target == "file":
        pointed.touch()
    elif target == "dir":
        pointed.mkdir()
    (netns_dir / "azazel-decoy").symlink_to(pointed)
    error, mode = read_netns()
    assert error == 0 and stat.S_ISLNK(mode)
    assert _residue(_stopped_units(), read_netns()) == (EXPOSURE_STATE_UNREADABLE,)


def test_a_namespace_entry_that_is_a_directory_is_unreadable(netns_dir):
    (netns_dir / "azazel-decoy").mkdir(parents=True)
    assert _residue(_stopped_units(), read_netns()) == (EXPOSURE_STATE_UNREADABLE,)


def test_a_netns_path_that_is_not_a_directory_is_unreadable(netns_dir):
    netns_dir.touch()
    assert read_netns() == (errno.ENOTDIR, None)
    assert _residue(_stopped_units(), read_netns()) == (EXPOSURE_STATE_UNREADABLE,)


def test_a_netns_path_that_is_a_link_is_not_followed(netns_dir):
    real = netns_dir.parent / "real"
    real.mkdir()
    (real / "azazel-decoy").touch()
    netns_dir.symlink_to(real)
    error, mode = read_netns()
    assert error in (errno.ELOOP, errno.ENOTDIR) and mode is None
    assert _residue(_stopped_units(), read_netns()) == (EXPOSURE_STATE_UNREADABLE,)


@pytest.mark.parametrize("where", ["directory", "entry"])
@pytest.mark.parametrize("code", [errno.EACCES, errno.EPERM, errno.EIO])
def test_a_netns_read_that_fails_otherwise_is_unreadable(netns_dir, monkeypatch,
                                                         where, code):
    """What `ip netns list` printed nothing for and exited 0 (#196 L2): the
    error is carried, not taken as "no namespace". Raised by a stand-in, so
    that the test does not depend on running as root or not."""

    netns_dir.mkdir()
    (netns_dir / "azazel-decoy").touch()
    real_open, real_stat = os.open, os.stat

    def failing_open(path, *args, **kwargs):
        if where == "directory" and path == str(netns_dir):
            raise OSError(code, os.strerror(code))
        return real_open(path, *args, **kwargs)

    def failing_stat(path, *args, **kwargs):
        if where == "entry" and path == "azazel-decoy":
            raise OSError(code, os.strerror(code))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(decoy_residue.os, "open", failing_open)
    monkeypatch.setattr(decoy_residue.os, "stat", failing_stat)
    assert read_netns() == (code, None)
    assert _residue(_stopped_units(), read_netns()) == (EXPOSURE_STATE_UNREADABLE,)


def test_the_namespace_is_not_read_through_ip_netns_list():
    """No `ip -j netns list` input is left (its empty output was taken as
    "no namespace"); the leaf test above keeps any process out."""

    source = Path(decoy_residue.__file__).read_text(encoding="utf-8")
    assert "empty_allowed" not in source and "_names(netns" not in source
    assert 'os.open(_NETNS, _DIR_FLAGS)' in source
    assert "os.O_DIRECTORY | os.O_NOFOLLOW" in source
    assert "follow_symlinks=False" in source


# -- not wired: nothing calls either ---------------------------------------------
#
# Which files import either module (the verify and the residue check only),
# that the pass-only names and codes appear nowhere else, that the tier is
# withheld with both made to fail if called, and `_withholding_reason`'s
# branch, are `test_g6_unwired.py` (#196 L1), with every other G6 part. What
# stays here is that both are leaves.


def test_both_modules_are_leaves():
    """Cheap for the pass to load in G6: the standard library, the fixed names
    and the scope's name rule; no socket, process, environment or library
    module beyond `decoy_scope`."""

    from test_runtime_boundary import _helper_offences

    def imports(name):
        tree = ast.parse((RUNTIME / name).read_text(encoding="utf-8"))
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                found.add("." * node.level + (node.module or ""))
            elif isinstance(node, ast.Import):
                found |= {alias.name for alias in node.names}
        return found

    assert imports("decoy_reachability.py") == {
        "__future__", "ipaddress", "json", "os", "typing", "azazel_nexus.decoy_scope",
        ".decoy_addresses"}
    # No `ip -j` parser and no nftables JSON since A1: the links are names.
    assert imports("decoy_residue.py") == {
        "__future__", "errno", "os", "stat", "typing", ".decoy_addresses"}
    for name in ("decoy_reachability.py", "decoy_residue.py"):
        assert _helper_offences(RUNTIME / name) == [], name
