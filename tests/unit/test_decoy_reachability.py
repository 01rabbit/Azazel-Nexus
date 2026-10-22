"""#196 G6 preparation A: the pass's reading of reachability §6, and G6 item (a).

`docs/deception-exposure-reachability.md` §6 and §9 (R1, R2, R5), and
`docs/deception-exposure-grant.md` §5 condition 6 and §6.3 "For G6" (a).
These tests pin, with values passed in (nothing here runs `ip` or `nft`,
reads the host's sysctls or talks to the service manager):

* `decoy_reachability.pass_reachability_departures`: each reason code of
  §6, in its fixed order; what the pass adds to the verify (the roles,
  `az-decoy0` not exempt, the rules compared whole, no route in the /24 at
  all); the interface-name rules and `conf_entry_path`;
* that the verify's judgement is the one G2 had (its own tests are
  `test_decoy_watch.py`; here, that the two share the reads and differ only
  where §6 says);
* `decoy_residue.exposure_residue_departures`: a masked unit still running,
  and the leftovers of a definition-less stop while no unit runs;
* that **nothing calls either**: no module of the product imports them but
  the verify (the shared reads), the tier is withheld as
  `isolation_evidence_absent` with both made to fail if called, and
  `_withholding_reason` is unchanged.

None of this is VM or hardware evidence.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from azazel_nexus.activation import (
    ARTIFACT_TRANSPORT,
    DECEPTION_EXPOSURE_UNITS,
    LOCAL_MODEL_PROVIDER,
    REMOTE_INFERENCE_TRANSPORT,
    EdgeBaselineState,
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
]


@pytest.mark.parametrize("extra", _EXTRA_KEYS, ids=lambda extra: "+".join(extra))
@pytest.mark.parametrize("index", [0, 1, 2])
def test_any_other_selector_on_an_accepted_rule_fails(index, extra):
    rules = _rule_list()
    rules[index] = {**rules[index], **extra}
    assert _pass(rules=(0, json.dumps(rules).encode())) == (INGRESS_CONTAINMENT_ABSENT,)


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
    # The verify's comparison is G2's: it does not read priority 32766.
    assert reachability_departures(_ipv4(), _ipv6(), (0, json.dumps(rules).encode()),
                                   _routes(), INGRESS) == ()


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


def test_the_verify_judgement_is_g2s():
    """The shared reads did not change the verify (`test_decoy_watch.py` pins it
    in full): the same names are the same objects, and the departures for a
    G2 host are those G2 gave."""

    for name in ("reachability_departures", "read_sysctls", "IPV6_ABSENT",
                 "REACHABILITY_CODES", "_rules_contained"):
        assert getattr(decoy_watch, name) is getattr(decoy_reachability, name), name
    ipv4 = _ipv4(**{"az-decoy0": {"forwarding": 1}, "mgmt0": {"forwarding": 1}})
    assert reachability_departures(ipv4, _ipv6(), _rules(), _routes(), INGRESS) == (
        FORWARDING_OTHER_ON,)
    # The verify still accepts a selector the pass refuses (G2's comparison;
    # the full attribute set waits for the VM's dump, reachability §11 item 8).
    rules = _rule_list()
    rules[1] = {**rules[1], "fwmark": "0x5"}
    assert reachability_departures(_ipv4(), _ipv6(), (0, json.dumps(rules).encode()),
                                   _routes(), INGRESS) == ()


# -- G6 item (a): a masked unit still running, and leftovers ---------------------


def _units(**changes):
    units = {unit: {"LoadState": "masked", "UnitFileState": "masked",
                    "ActiveState": "inactive"} for unit in EXPOSURE_UNITS}
    for unit, values in changes.items():
        units[unit] = {**units[unit], **values}
    return units


_NONE = (0, b"")
_NO_LINKS = (0, json.dumps([{"ifindex": 1, "ifname": "lo"},
                            {"ifindex": 2, "ifname": "eth9"}]).encode())
_NO_TABLES = (0, json.dumps({"nftables": [{"metainfo": {"version": "1.1.3"}}]}).encode())


def _residue(units=None, netns=_NONE, links=_NO_LINKS, tables=_NO_TABLES):
    return exposure_residue_departures(_units() if units is None else units,
                                       netns, links, tables)


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
    assert _residue(netns=(0, b"[]")) == ()
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


@pytest.mark.parametrize("netns,links,tables", [
    ((0, b'[{"name":"azazel-decoy"}]'), _NO_LINKS, _NO_TABLES),
    (_NONE, (0, b'[{"ifname":"az-decoy-host0"}]'), _NO_TABLES),
    (_NONE, (0, b'[{"ifname":"lo"},{"ifname":"az-decoy0"}]'), _NO_TABLES),
    (_NONE, _NO_LINKS, (0, json.dumps({"nftables": [
        {"metainfo": {}}, {"table": {"family": "inet", "name": "azazel_decoy",
                                     "handle": 1}}]}).encode())),
])
@pytest.mark.parametrize("active", ["inactive", "failed"])
def test_leftovers_while_no_unit_runs_are_refused(netns, links, tables, active):
    """Third G4 rehearsal: two veth links and a namespace left behind."""

    units = _units(**{unit: {"ActiveState": active} for unit in EXPOSURE_UNITS})
    assert _residue(units, netns, links, tables) == (EXPOSURE_LEFTOVERS_PRESENT,)


def test_leftovers_while_a_unit_runs_are_its_own_objects():
    running = {"LoadState": "loaded", "UnitFileState": "enabled", "ActiveState": "active"}
    netns = (0, b'[{"name":"azazel-decoy"}]')
    assert _residue(_units(**{NSD: running}), netns) == ()
    # Masked and running with leftovers: the running unit is the reason.
    assert _residue(_units(**{NSD: {"ActiveState": "active"}}), netns) == (
        EXPOSURE_UNIT_MASKED_RUNNING,)


_RUNNING = {"LoadState": "loaded", "UnitFileState": "enabled", "ActiveState": "active"}
_STOPPED_UNIT = {"LoadState": "loaded", "UnitFileState": "enabled",
                 "ActiveState": "inactive"}
_NAMESPACE = (0, b'[{"name":"azazel-decoy"}]')
_HOST_VETH = (0, b'[{"ifname":"lo"},{"ifname":"az-decoy-host0"}]')
_BRIDGE = (0, b'[{"ifname":"lo"},{"ifname":"az-decoy0"}]')
_TABLE = (0, json.dumps({"nftables": [
    {"table": {"family": "inet", "name": "azazel_decoy", "handle": 1}}]}).encode())


@pytest.mark.parametrize("running,netns,links,tables,expected", [
    # Review of #293 item 2: the decoy running alone, its two owners stopped.
    ((DECOYD,), _NAMESPACE, _NO_LINKS, _NO_TABLES, (EXPOSURE_LEFTOVERS_PRESENT,)),
    ((DECOYD,), _NONE, _HOST_VETH, _NO_TABLES, (EXPOSURE_LEFTOVERS_PRESENT,)),
    ((DECOYD,), _NONE, _BRIDGE, _NO_TABLES, (EXPOSURE_LEFTOVERS_PRESENT,)),
    ((DECOYD,), _NONE, _NO_LINKS, _TABLE, (EXPOSURE_LEFTOVERS_PRESENT,)),
    ((DECOYD,), _NONE, _NO_LINKS, _NO_TABLES, ()),
    # The helper stopped: its bridge or table left; the namespace unit's are its own.
    ((NSD, DECOYD), _NAMESPACE, _HOST_VETH, _NO_TABLES, ()),
    ((NSD,), _NONE, _BRIDGE, _NO_TABLES, (EXPOSURE_LEFTOVERS_PRESENT,)),
    ((NSD, DECOYD), _NAMESPACE, _HOST_VETH, _TABLE, (EXPOSURE_LEFTOVERS_PRESENT,)),
    # The namespace unit stopped: its namespace or veth end left.
    ((NETD, DECOYD), _NONE, _BRIDGE, _TABLE, ()),
    ((NETD,), _NAMESPACE, _BRIDGE, _NO_TABLES, (EXPOSURE_LEFTOVERS_PRESENT,)),
    ((NETD,), _NONE, _HOST_VETH, _NO_TABLES, (EXPOSURE_LEFTOVERS_PRESENT,)),
    # All three running: every object is theirs.
    ((NSD, NETD, DECOYD), _NAMESPACE, (0, b'[{"ifname":"az-decoy0"},'
                                       b'{"ifname":"az-decoy-host0"}]'), _TABLE, ()),
])
def test_leftovers_are_judged_per_owner(running, netns, links, tables, expected):
    units = _units(**{unit: (_RUNNING if unit in running else _STOPPED_UNIT)
                      for unit in EXPOSURE_UNITS})
    assert _residue(units, netns, links, tables) == expected


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


def test_other_namespaces_links_and_tables_are_not_leftovers():
    assert _residue(netns=(0, b'[{"name":"other"}]'),
                    links=(0, b'[{"ifname":"az-decoy-ns0"},{"ifname":"az-decoy1"}]'),
                    tables=(0, json.dumps({"nftables": [
                        {"table": {"family": "ip", "name": "azazel_decoy"}},
                        {"table": {"family": "inet", "name": "filter"}}]}).encode())) == ()


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
    assert exposure_residue_departures(units, _NONE, _NO_LINKS, _NO_TABLES) == (
        EXPOSURE_STATE_UNREADABLE,)


@pytest.mark.parametrize("netns,links,tables", [
    ((1, b""), _NO_LINKS, _NO_TABLES),
    (_NONE, (0, b""), _NO_TABLES),
    (_NONE, (0, b'[{"ifname": 3}]'), _NO_TABLES),
    (_NONE, _NO_LINKS, (0, b"")),
    (_NONE, _NO_LINKS, (0, b'{"nftables": [{"table": {"family": "inet"}}]}')),
    (_NONE, _NO_LINKS, (0, b'{"nftables": {}}')),
    (_NONE, _NO_LINKS, (2, b"")),
    ((0, b"[{]"), _NO_LINKS, _NO_TABLES),
    ("", _NO_LINKS, _NO_TABLES),
])
def test_an_object_read_that_cannot_be_read_is_unreadable(netns, links, tables):
    assert _residue(None, netns, links, tables) == (EXPOSURE_STATE_UNREADABLE,)
    # The running-mask judgement stands on the unit states alone.
    masked = _units(**{NSD: {"ActiveState": "active"}})
    assert _residue(masked, netns, links, tables) == (
        EXPOSURE_UNIT_MASKED_RUNNING, EXPOSURE_STATE_UNREADABLE)


# -- not wired: nothing calls either ---------------------------------------------


def _python_modules():
    for base in (REPO / "src", REPO / "runtime" / "src"):
        yield from sorted(base.rglob("*.py"))


def _imported(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names.add(module.rsplit(".", 1)[-1])
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.Import):
            names |= {alias.name.rsplit(".", 1)[-1] for alias in node.names}
    return names


def test_only_the_verify_and_the_residue_check_import_the_reachability_module():
    """The pass, the controller and the library never call it (G6 does)."""

    importers = {path.relative_to(REPO).as_posix() for path in _python_modules()
                 if "decoy_reachability" in _imported(path)}
    assert importers == {
        "runtime/src/azazel_nexus_runtime/decoy_watch.py",
        "runtime/src/azazel_nexus_runtime/decoy_residue.py",
    }


def test_nothing_imports_the_residue_module():
    assert not any("decoy_residue" in _imported(path) for path in _python_modules())


def test_the_pass_only_names_appear_nowhere_else_in_the_product():
    words = ("pass_reachability_departures", "reachability_refusal", "conf_entry_path",
             FORWARDING_ROLE_ON, "exposure_residue_departures", "residue_refusal",
             *RESIDUE_CODES)
    for path in _python_modules():
        if path.name in ("decoy_reachability.py", "decoy_residue.py"):
            continue
        text = path.read_text(encoding="utf-8")
        for word in words:
            assert word not in text, (path, word)


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
    assert imports("decoy_residue.py") == {
        "__future__", "json", "typing", ".decoy_addresses", ".decoy_reachability"}
    for name in ("decoy_reachability.py", "decoy_residue.py"):
        assert _helper_offences(RUNTIME / name) == [], name


def test_the_tier_is_withheld_with_both_made_to_fail_if_called(tmp_path, monkeypatch):
    """`_withholding_reason` reaches neither: with each judgement and the reader
    replaced by one that raises, the pass runs and the three exposure units are
    withheld as `isolation_evidence_absent`."""

    from test_activation import ACTOR, NOW, _confirmed_role, _controller, _lease, _record

    def called(*args, **kwargs):
        raise AssertionError("a G6 judgement was called before G6")

    for module, name in ((decoy_reachability, "pass_reachability_departures"),
                         (decoy_reachability, "read_sysctls"),
                         (decoy_reachability, "reachability_refusal"),
                         (decoy_residue, "exposure_residue_departures"),
                         (decoy_residue, "residue_refusal")):
        monkeypatch.setattr(module, name, called)
    controller, units, ledger, _ = _controller(tmp_path)
    outcome = controller.activate(
        now=NOW, actor=ACTOR, lease=_lease(),
        edge=EdgeBaselineState(True, True, True, True, True), healthy=True,
        record=_record(roles=(_confirmed_role(),)),
        wired=(ARTIFACT_TRANSPORT, LOCAL_MODEL_PROVIDER, REMOTE_INFERENCE_TRANSPORT),
    )
    for unit in DECEPTION_EXPOSURE_UNITS:
        verdict = next(v for v in outcome.verdicts if v.unit == unit)
        assert not verdict.granted
        assert verdict.reason.startswith("isolation_evidence_absent")
    reasons = [v.reason for v in outcome.verdicts if v.reason] + [
        entry.event.get("reason", "") for entry in ledger]
    codes = (*PASS_REACHABILITY_CODES, *RESIDUE_CODES)
    assert not any(reason.startswith(code) for reason in reasons for code in codes)


def test_withholding_reason_still_returns_isolation_evidence_absent():
    from azazel_nexus import activation

    source = Path(activation.__file__).read_text(encoding="utf-8")
    method = next(node for node in ast.walk(ast.parse(source))
                  if isinstance(node, ast.FunctionDef) and node.name == "_withholding_reason")
    body = ast.get_source_segment(source, method)
    branch = body[body.index("if definition.tier is UnitTier.DECEPTION_EXPOSURE:"):
                  body.index("if definition.tier is UnitTier.EDGE_BASELINE:")]
    assert re.findall(r'return \(\s*"([a-z_]+):', branch) == [
        "exposure_tier_partial", "isolation_evidence_absent"]
    for word in ("reachability", "forwarding", "residue", "leftover", "masked"):
        assert word not in branch.lower(), word
