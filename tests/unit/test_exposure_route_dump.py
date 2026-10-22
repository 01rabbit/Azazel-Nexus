"""The route-netlink reader of the rules and the main routes (#196 G6, B1).

`docs/deception-exposure-wiring.md` §4.4 ("What B1's parser must hold") and
§7 items 10 and 11. Three layers:

* constructed messages (`struct` here) for each attribute, the table names,
  the closed-on-unknown rule, multipath, `RTA_NH_ID`, and the framing of a
  dump (interrupted, truncated, another sequence, an error reply);
* recorded dumps (`tests/fixtures/route_dump/`): raw netlink replies and
  `ip -j` output taken together in one network namespace of the test
  container, read by both readers and required equal;
* a live equivalence check, Linux only, in a fresh network namespace
  (`unshare --net`, as root or in a user namespace): the K1 rule shapes,
  selector-bearing rules and routes into `10.255.196.0/24` are made with
  `ip`, and this module's dump must equal `ip -j`'s after the comparison's
  own normalisation. Skipped where no namespace can be made or `ip` is
  absent; never a pass without having run.
"""

from __future__ import annotations

import ast
import ipaddress
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from azazel_nexus_runtime import decoy_reachability, exposure_route_dump
from azazel_nexus_runtime.exposure_route_dump import (
    RouteDumpUnreadable,
    dump_ipv4_rules,
    dump_main_routes,
    parse_route_dump,
    parse_rule_dump,
    route_dump_request,
    rule_dump_request,
)

REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / "runtime" / "src" / "azazel_nexus_runtime" / "exposure_route_dump.py"
FIXTURES = REPO / "tests" / "fixtures" / "route_dump"

_HEADER = struct.Struct("=IHHII")
_BODY = struct.Struct("=BBBBBBBBI")
RTM_NEWROUTE, RTM_GETROUTE, RTM_NEWRULE, RTM_GETRULE = 24, 26, 32, 34
NLMSG_ERROR, NLMSG_DONE = 2, 3
NLM_F_MULTI, NLM_F_DUMP_INTR = 0x2, 0x10
RULE_SEQ, ROUTE_SEQ = 1, 2

# -- building messages --------------------------------------------------------------


def _attr(kind: int, payload: bytes) -> bytes:
    length = 4 + len(payload)
    return struct.pack("=HH", length, kind) + payload + b"\x00" * (-length % 4)


def _u8(kind, value):
    return _attr(kind, bytes([value]))


def _u32(kind, value):
    return _attr(kind, struct.pack("=I", value))


def _s32(kind, value):
    return _attr(kind, struct.pack("=i", value))


def _ip(kind, text):
    return _attr(kind, ipaddress.IPv4Address(text).packed)


def _name(kind, text):
    return _attr(kind, text.encode() + b"\x00")


def _message(kind: int, payload: bytes, *, seq: int, flags: int = NLM_F_MULTI) -> bytes:
    return _HEADER.pack(_HEADER.size + len(payload), kind, flags, seq, 4242) + payload


def _done(seq: int, error: int = 0) -> bytes:
    return _message(NLMSG_DONE, struct.pack("=i", error), seq=seq)


# FRA_*
DST, SRC, IIF, GOTO, PRIO, FWMARK, FLOW, TUN_ID = 1, 2, 3, 4, 6, 10, 11, 12
SUP_IFGROUP, SUP_PREFIXLEN, TABLE, FWMASK, OIF, PAD, L3MDEV = 13, 14, 15, 16, 17, 18, 19
UID_RANGE, PROTOCOL, IP_PROTO, SPORT, DPORT = 20, 21, 22, 23, 24
DSCP, FLOWLABEL, FLOWLABEL_MASK, SPORT_MASK, DPORT_MASK, DSCP_MASK = 25, 26, 27, 28, 29, 30


def _rule(*attrs, dst_len=0, src_len=0, tos=0, table=0, action=1, flags=0, family=2,
          res=(0, 0), protocol=True, seq=RULE_SEQ) -> bytes:
    body = _BODY.pack(family, dst_len, src_len, tos, table, res[0], res[1], action, flags)
    extra = _u8(PROTOCOL, 3) if protocol else b""
    return _message(RTM_NEWRULE, body + extra + b"".join(attrs), seq=seq)


def _rules(*messages, seq=RULE_SEQ) -> list[dict]:
    return parse_rule_dump(b"".join(messages) + _done(seq))


def _one(*attrs, **header) -> dict:
    (rule,) = _rules(_rule(*attrs, **header))
    return rule


# RTA_*
R_DST, R_OIF, R_GATEWAY, R_PRIORITY, R_PREFSRC, R_METRICS, R_MULTIPATH = 1, 4, 5, 6, 7, 8, 9
R_FLOW, R_TABLE, R_VIA, R_ENCAP_TYPE, R_ENCAP, R_NH_ID = 11, 15, 18, 21, 22, 30
LINKS = {1: "lo", 2: "lan0", 3: "eth9", 4: "az-decoy0"}


def _route(*attrs, dst_len=0, table=254, kind=1, flags=0, src_len=0, tos=0, family=2,
           table_attr=True, seq=ROUTE_SEQ) -> bytes:
    body = _BODY.pack(family, dst_len, src_len, tos, table if table < 256 else 252,
                      3, 0, kind, flags)
    extra = _u32(R_TABLE, table) if table_attr else b""
    return _message(RTM_NEWROUTE, body + extra + b"".join(attrs), seq=seq)


def _routes(*messages, links=LINKS, seq=ROUTE_SEQ) -> list[dict]:
    return parse_route_dump(b"".join(messages) + _done(seq), links)


def _hop(index: int, *attrs, weight: int = 0, flags: int = 0) -> bytes:
    payload = b"".join(attrs)
    return struct.pack("=HBBi", 8 + len(payload), flags, weight, index) + payload


# -- the requests -------------------------------------------------------------------


def test_the_two_requests_are_ipv4_dumps():
    for request, kind, seq in ((rule_dump_request(), RTM_GETRULE, RULE_SEQ),
                               (route_dump_request(), RTM_GETROUTE, ROUTE_SEQ)):
        length, message_type, flags, sequence, pid = _HEADER.unpack_from(request)
        assert (length, message_type, flags, sequence, pid) == (
            len(request), kind, 0x301, seq, 0)
        assert _BODY.unpack_from(request, _HEADER.size) == (2, 0, 0, 0, 0, 0, 0, 0, 0)


def test_the_module_sends_only_the_two_dump_requests():
    """Only `_request` packs a header with a type, and only the two
    GET types are passed to it; no write type is named by number."""

    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    numbers = {node.targets[0].id: node.value.value for node in tree.body
               if isinstance(node, ast.Assign) and len(node.targets) == 1
               and isinstance(node.targets[0], ast.Name)
               and isinstance(node.value, ast.Constant)}
    assert numbers["_RTM_GETRULE"] == RTM_GETRULE
    assert numbers["_RTM_GETROUTE"] == RTM_GETROUTE
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == "_request"]
    assert sorted(ast.unparse(call.args[0]) for call in calls) == [
        "_RTM_GETROUTE", "_RTM_GETRULE"]
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    for word in ("NEWRULE", "DELRULE", "NEWROUTE", "DELROUTE", "SETLINK", "NEWLINK"):
        sent = {name for name in names if word in name and not name.startswith("_RTM_NEW")}
        assert not sent, sent
    # One header is packed, in `_request`, and one `send`, of its result.
    packs = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == "pack"
             and ast.unparse(node.func.value) == "_HEADER"]
    assert len(packs) == 1
    sends = [ast.unparse(node) for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr.startswith("send")]
    assert sends == ["connection.send(request)"]


# -- rules: the K1 shapes -----------------------------------------------------------


def _k1_lookup(name):
    return _rule(_u32(PRIO, 1960), _ip(DST, "10.255.196.0"), _name(IIF, name),
                 _u32(TABLE, 254), _s32(SUP_PREFIXLEN, 29), dst_len=30, table=254)


def _k1_blackhole(name, table=0):
    return _rule(_u32(PRIO, 1961), _name(IIF, name), _u32(TABLE, table),
                 _s32(SUP_PREFIXLEN, -1), table=table, action=6)


def _defaults():
    return (_rule(_u32(TABLE, 255), _s32(SUP_PREFIXLEN, -1), table=255),
            _rule(_u32(PRIO, 32766), _u32(TABLE, 254), _s32(SUP_PREFIXLEN, -1), table=254),
            _rule(_u32(PRIO, 32767), _u32(TABLE, 253), _s32(SUP_PREFIXLEN, -1), table=253))


def test_k1_in_both_forms_reads_as_ip_prints_it_and_holds():
    local, main, default = _defaults()
    rules = _rules(local, _k1_lookup("lan0"), _k1_blackhole("lan0"),
                   _k1_lookup("eth9"), _k1_blackhole("eth9", table=254), main, default)
    assert rules == [
        {"priority": 0, "src": "all", "table": "local"},
        {"priority": 1960, "src": "all", "dst": "10.255.196.0", "dstlen": 30,
         "iif": "lan0", "table": "main", "suppress_prefixlen": 29},
        {"priority": 1961, "src": "all", "iif": "lan0", "action": "blackhole"},
        {"priority": 1960, "src": "all", "dst": "10.255.196.0", "dstlen": 30,
         "iif": "eth9", "table": "main", "suppress_prefixlen": 29},
        {"priority": 1961, "src": "all", "iif": "eth9", "table": "main",
         "action": "blackhole"},
        {"priority": 32766, "src": "all", "table": "main"},
        {"priority": 32767, "src": "all", "table": "default"},
    ]
    assert decoy_reachability._rules_exact(rules, ("eth9", "lan0")) is True
    assert decoy_reachability._rules_exact(rules, ("lan0",)) is False


# -- rules: each attribute ----------------------------------------------------------

_TRANSLATED = [
    ((_ip(SRC, "192.0.2.0"),), {"src_len": 24}, {"src": "192.0.2.0", "srclen": 24}),
    ((_ip(SRC, "192.0.2.9"),), {"src_len": 32}, {"src": "192.0.2.9"}),
    ((), {"src_len": 8}, {"src": "0", "srclen": 8}),
    ((_ip(DST, "198.51.100.7"),), {"dst_len": 32}, {"dst": "198.51.100.7"}),
    ((), {"dst_len": 8}, {"dst": "0", "dstlen": 8}),
    ((), {"tos": 0x10}, {"tos": "0x10"}),
    ((), {"tos": 0x28}, {"tos": "0x28"}),  # `ip` names it AF11 from its file
    ((), {"flags": 0x2}, {"not": None}),
    ((_u32(FWMARK, 5), _u32(FWMASK, 0xFF)), {}, {"fwmark": "0x5", "fwmask": "0xff"}),
    ((_u32(FWMARK, 7), _u32(FWMASK, 0xFFFFFFFF)), {}, {"fwmark": "0x7"}),
    ((_u32(FWMARK, 0), _u32(FWMASK, 0xFF)), {}, {"fwmark": "0", "fwmask": "0xff"}),
    ((_u32(FWMASK, 0xF0),), {}, {"fwmark": "0", "fwmask": "0xf0"}),
    ((_name(IIF, "lan0"),), {}, {"iif": "lan0"}),
    ((_name(IIF, "gone"),), {"flags": 0x8}, {"iif": "gone", "iif_detached": None}),
    ((_name(OIF, "eth9"),), {}, {"oif": "eth9"}),
    ((_name(OIF, "gone"),), {"flags": 0x10}, {"oif": "gone", "oif_detached": None}),
    ((_u8(L3MDEV, 1),), {}, {"l3mdev": None}),
    ((_u8(L3MDEV, 0),), {}, {}),
    ((_attr(UID_RANGE, struct.pack("=II", 100, 200)),), {},
     {"uid_start": 100, "uid_end": 200}),
    ((_u8(IP_PROTO, 253),), {}, {"ipproto": "ipproto-253"}),
    ((_u8(IP_PROTO, 6),), {}, {"ipproto": "ipproto-6"}),  # `ip`: tcp, from /etc/protocols
    ((_attr(SPORT, struct.pack("=HH", 1, 2)),), {}, {"sport_start": 1, "sport_end": 2}),
    ((_attr(DPORT, struct.pack("=HH", 22, 22)),), {}, {"dport": 22}),
    ((_attr(TUN_ID, struct.pack(">Q", 5)), _attr(PAD, b"")), {}, {"tun_id": 5}),
    ((_u32(FLOW, 4),), {}, {"flow_to": "4"}),
    ((_u32(FLOW, (3 << 16) | 5),), {}, {"flow_from": "3", "flow_to": "5"}),
    ((_u32(FLOW, 3 << 16),), {}, {"flow_from": "3", "flow_to": "0"}),  # `ip`: cosmos
]


@pytest.mark.parametrize("attrs,header,expected", _TRANSLATED,
                         ids=[str(i) for i in range(len(_TRANSLATED))])
def test_each_selector_is_the_key_ip_prints(attrs, header, expected):
    rule = _one(_u32(PRIO, 100), *attrs, **header)
    assert rule.pop("priority") == 100
    src = rule.pop("src")
    if "src" not in expected:
        assert src == "all"
    else:
        expected = dict(expected)
        assert src == expected.pop("src")
    assert rule == expected


def test_the_selectors_that_print_only_beside_a_table():
    attrs = (_s32(SUP_PREFIXLEN, 0), _s32(SUP_IFGROUP, 3))
    assert _one(_u32(TABLE, 254), *attrs) == {
        "priority": 0, "src": "all", "table": "main", "suppress_prefixlen": 0,
        "suppress_ifgroup": "3"}
    assert _one(_u32(TABLE, 254), _s32(SUP_PREFIXLEN, -1), _s32(SUP_IFGROUP, -1)) == {
        "priority": 0, "src": "all", "table": "main"}
    # Without a table `ip` prints neither (a blackhole rule's suppressor).
    assert _one(*attrs, action=6) == {"priority": 0, "src": "all", "action": "blackhole"}


@pytest.mark.parametrize("action,expected", [
    (1, {}), (3, {"nop": None}), (6, {"action": "blackhole"}),
    (7, {"action": "unreachable"}), (8, {"action": "prohibit"})])
def test_the_actions_are_named_as_ip_names_them(action, expected):
    assert _one(action=action) == {"priority": 0, "src": "all", **expected}


def test_a_goto_carries_its_target_or_none_and_its_unresolved_flag():
    assert _one(_u32(GOTO, 200), action=2) == {"priority": 0, "src": "all", "goto": 200}
    assert _one(_u32(GOTO, 999), action=2, flags=0x4) == {
        "priority": 0, "src": "all", "goto": 999, "unresolved": None}
    assert _one(action=2) == {"priority": 0, "src": "all", "goto": "none"}


@pytest.mark.parametrize("number,name", [
    (253, "default"), (254, "main"), (255, "local"), (100, "100"), (252, "252"),
    (1000, "1000"), (4294967295, "4294967295")])
def test_tables_are_named_as_ip_names_them_without_rt_tables(number, name):
    header = number if number < 256 else 252
    assert _one(_u32(TABLE, number), table=header)["table"] == name
    if number < 256:
        # Without the attribute the header's table is read.
        assert _one(table=number)["table"] == name


def test_the_table_attribute_wins_over_the_header_and_zero_prints_none():
    assert _one(_u32(TABLE, 1000), table=252)["table"] == "1000"
    assert "table" not in _one(_u32(TABLE, 0), table=0)


def test_the_protocol_is_parsed_and_dropped():
    assert _one(protocol=True) == _one(protocol=False) == {"priority": 0, "src": "all"}
    with pytest.raises(RouteDumpUnreadable):
        _one(_attr(PROTOCOL, b"\x03\x00"), protocol=False)


def test_no_file_is_read_rt_tables_or_any_other():
    """Its imports are the standard library's without `os`, `io` or `pathlib`
    (below), and it calls no `open`: the names cannot depend on a file."""

    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert not names & {"open", "os", "io", "Path", "pathlib", "__import__"}


# -- rules: closed on the unknown ---------------------------------------------------


@pytest.mark.parametrize("attr", [
    _u8(DSCP, 10), _u32(FLOWLABEL, 1), _u32(FLOWLABEL_MASK, 0xF),
    _attr(SPORT_MASK, b"\xff\x00"), _attr(DPORT_MASK, b"\xff\x00"), _u8(DSCP_MASK, 0x3F),
    _u32(5, 0), _u32(7, 0), _u32(8, 0), _u32(9, 0), _u32(31, 0), _u32(0, 0)],
    ids=["dscp", "flowlabel", "flowlabel_mask", "sport_mask", "dport_mask", "dscp_mask",
         "unused2", "unused3", "unused4", "unused5", "future", "unspec"])
def test_an_attribute_not_translated_makes_the_whole_dump_unreadable(attr):
    local, main, default = _defaults()
    with pytest.raises(RouteDumpUnreadable):
        _rules(local, _rule(_u32(PRIO, 5), attr), main, default)


@pytest.mark.parametrize("header", [
    {"flags": 0x20}, {"flags": 0x10000}, {"flags": 0x8}, {"flags": 0x10}, {"flags": 0x4},
    {"res": (1, 0)}, {"res": (0, 1)}, {"action": 0}, {"action": 4}, {"action": 5},
    {"action": 9}, {"action": 10}, {"family": 10}, {"family": 0},
    {"dst_len": 33}, {"src_len": 40}])
def test_a_header_this_reader_does_not_know_is_unreadable(header):
    with pytest.raises(RouteDumpUnreadable):
        _one(**header)


def test_a_goto_target_on_another_action_is_unreadable():
    with pytest.raises(RouteDumpUnreadable):
        _one(_u32(GOTO, 5), action=1)


@pytest.mark.parametrize("attr", [
    _attr(PRIO, b"\x01\x00"), _attr(TABLE, b"\x01"), _attr(SRC, b"\x01\x02\x03"),
    _attr(IIF, b"lan0"), _attr(IIF, b"\xff\xfe\x00"), _attr(UID_RANGE, b"\x00" * 4),
    _attr(SPORT, b"\x00" * 2), _attr(TUN_ID, b"\x00" * 4), _attr(L3MDEV, b"\x01\x00"),
    _attr(SUP_PREFIXLEN, b"\x00"), _attr(FWMARK, b"\x00")])
def test_an_attribute_of_the_wrong_size_is_unreadable(attr):
    with pytest.raises(RouteDumpUnreadable):
        _one(_u32(TABLE, 254), attr, src_len=24)


def test_a_repeated_attribute_is_unreadable():
    with pytest.raises(RouteDumpUnreadable):
        _one(_name(IIF, "lan0"), _name(IIF, "eth9"))


# -- routes -------------------------------------------------------------------------


def test_only_main_is_kept_by_its_table_attribute_or_header():
    routes = _routes(
        _route(_ip(R_DST, "10.0.0.0"), dst_len=8, table=255),
        _route(_ip(R_DST, "10.255.196.4"), dst_len=30, table=100),
        _route(_ip(R_DST, "10.255.196.8"), dst_len=30, table=1000),
        _route(_ip(R_DST, "192.0.2.0"), _u32(R_OIF, 2), dst_len=24, table=254,
               table_attr=False),
        _route(_ip(R_DST, "198.51.100.0"), dst_len=24, table=254))
    assert routes == [{"dst": "192.0.2.0/24"}, {"dst": "198.51.100.0/24"}]
    # The attribute wins over the header.
    body = _BODY.pack(2, 24, 0, 0, 254, 3, 0, 1, 0)
    other = _message(RTM_NEWROUTE, body + _u32(R_TABLE, 100) + _ip(R_DST, "10.255.196.0"),
                     seq=ROUTE_SEQ)
    assert _routes(other) == []


def test_a_cloned_entry_is_skipped_as_ip_skips_it():
    assert _routes(_route(_ip(R_DST, "10.255.196.9"), dst_len=32, flags=0x200)) == []


def test_routes_outside_the_slash_24_are_their_destination_alone():
    routes = _routes(
        _route(_ip(R_GATEWAY, "192.0.2.254"), _u32(R_OIF, 2)),
        _route(_ip(R_DST, "10.0.0.0"), _ip(R_GATEWAY, "192.0.2.3"), _u32(R_OIF, 2),
               _u32(R_PRIORITY, 5), dst_len=8),
        _route(_ip(R_DST, "198.51.100.0"), _u32(R_NH_ID, 9), _u32(R_FLOW, 3),
               _attr(R_ENCAP, b"\x00" * 4), dst_len=24),
        _route(_ip(R_DST, "203.0.113.5"), dst_len=32, kind=6),
        _route(dst_len=8))
    assert routes == [{"dst": "default"}, {"dst": "10.0.0.0/8"}, {"dst": "198.51.100.0/24"},
                      {"dst": "203.0.113.5"}, {"dst": "0/8"}]
    assert decoy_reachability._routes_clear(routes[:4], connected=False) is True


def test_the_bridges_connected_route_reads_as_the_verify_accepts_it():
    route = _route(_ip(R_DST, "10.255.196.0"), _u32(R_OIF, 4), _ip(R_PREFSRC, "10.255.196.1"),
                   dst_len=30)
    routes = _routes(route)
    assert routes == [{"dst": "10.255.196.0/30", "dev": "az-decoy0"}]
    assert decoy_reachability._routes_clear(routes) is True
    assert decoy_reachability._routes_clear(routes, connected=False) is False


def test_routes_inside_the_slash_24_keep_dst_dev_gateway_via_and_type():
    routes = _routes(
        _route(_ip(R_DST, "10.255.196.16"), _ip(R_GATEWAY, "192.0.2.5"), _u32(R_OIF, 2),
               _u32(R_PRIORITY, 7), _ip(R_PREFSRC, "192.0.2.1"),
               _attr(R_METRICS | 0x8000, _u32(2, 1400)), dst_len=30),
        _route(_ip(R_DST, "10.255.196.64"), dst_len=30, kind=6),
        _route(_ip(R_DST, "10.255.196.200"), _u32(R_OIF, 3), dst_len=32),
        _route(_ip(R_DST, "10.255.196.52"), _u32(R_OIF, 2),
               _attr(R_VIA, struct.pack("=H", 10) + ipaddress.IPv6Address("fe80::1").packed),
               dst_len=30),
        _route(_ip(R_DST, "10.255.196.96"), _u32(R_OIF, 2), dst_len=30, kind=99))
    assert routes == [
        {"dst": "10.255.196.16/30", "dev": "lan0", "gateway": "192.0.2.5"},
        {"dst": "10.255.196.64/30", "type": "blackhole"},
        {"dst": "10.255.196.200", "dev": "eth9"},
        {"dst": "10.255.196.52/30", "dev": "lan0",
         "via": {"family": "inet6", "host": "fe80::1"}},
        {"dst": "10.255.196.96/30", "type": "99", "dev": "lan0"},
    ]
    for route in routes:
        assert decoy_reachability._routes_clear([route]) is False


def test_a_multipath_route_carries_its_nexthops():
    hops = _hop(2, _ip(R_GATEWAY, "192.0.2.6"), weight=1) + _hop(3, _ip(R_GATEWAY, "192.0.2.7"))
    (route,) = _routes(_route(_ip(R_DST, "10.255.196.32"), _attr(R_MULTIPATH, hops),
                              dst_len=28))
    assert route == {"dst": "10.255.196.32/28", "nexthops": [
        {"gateway": "192.0.2.6", "dev": "lan0", "weight": 2},
        {"gateway": "192.0.2.7", "dev": "eth9", "weight": 1}]}
    assert decoy_reachability._routes_clear([route]) is False


@pytest.mark.parametrize("attr", [
    _u32(R_NH_ID, 9), _u32(R_FLOW, 3), _attr(R_ENCAP_TYPE, b"\x01\x00"),
    _attr(R_ENCAP, b"\x00" * 4), _u32(2, 0), _u32(3, 1), _u32(16, 1), _u32(31, 0)],
    ids=["nh_id", "flow", "encap_type", "encap", "src", "iif", "mark", "future"])
def test_a_route_in_the_slash_24_with_an_attribute_not_known_is_unreadable(attr):
    with pytest.raises(RouteDumpUnreadable):
        _routes(_route(_ip(R_DST, "10.255.196.80"), _u32(R_OIF, 2), attr, dst_len=30))


@pytest.mark.parametrize("header", [{"src_len": 8}, {"tos": 4}])
def test_a_route_in_the_slash_24_with_a_header_not_known_is_unreadable(header):
    with pytest.raises(RouteDumpUnreadable):
        _routes(_route(_ip(R_DST, "10.255.196.80"), dst_len=30, **header))


@pytest.mark.parametrize("hops", [
    _hop(2, _u32(R_FLOW, 3)), _hop(2, _attr(R_ENCAP, b"\x00" * 4)), b"",
    _hop(2)[:6], struct.pack("=HBBi", 40, 0, 0, 2)])
def test_a_next_hop_this_reader_cannot_read_is_unreadable(hops):
    with pytest.raises(RouteDumpUnreadable):
        _routes(_route(_ip(R_DST, "10.255.196.32"), _attr(R_MULTIPATH, hops), dst_len=28))


@pytest.mark.parametrize("links", [{2: None}, {}, {2: ""}])
def test_a_route_whose_output_link_has_no_name_is_unreadable(links):
    for message in (_route(_ip(R_DST, "10.255.196.8"), _u32(R_OIF, 2), dst_len=30),
                    _route(_ip(R_DST, "10.0.0.0"), _u32(R_OIF, 2), dst_len=8),
                    _route(_ip(R_DST, "10.255.196.32"),
                           _attr(R_MULTIPATH, _hop(2, _ip(R_GATEWAY, "192.0.2.6"))),
                           dst_len=28)):
        with pytest.raises(RouteDumpUnreadable):
            _routes(message, links=links)


@pytest.mark.parametrize("links", [[(2, "lan0")], {"2": "lan0"}, {2: b"lan0"}, None])
def test_link_names_of_another_shape_are_unreadable(links):
    with pytest.raises(RouteDumpUnreadable):
        _routes(_route(_ip(R_DST, "10.0.0.0"), dst_len=8), links=links)


@pytest.mark.parametrize("via", [b"\x0a", struct.pack("=H", 7) + b"\x00" * 4,
                                 struct.pack("=H", 10) + b"\x00" * 4])
def test_a_via_of_another_shape_is_unreadable(via):
    with pytest.raises(RouteDumpUnreadable):
        _routes(_route(_ip(R_DST, "10.255.196.52"), _attr(R_VIA, via), dst_len=30))


# -- the framing of a dump ----------------------------------------------------------


def _ok_rule(seq=RULE_SEQ, flags=NLM_F_MULTI):
    body = _BODY.pack(2, 0, 0, 0, 254, 0, 0, 1, 0)
    return _message(RTM_NEWRULE, body, seq=seq, flags=flags)


@pytest.mark.parametrize("data", [
    _ok_rule(),                                                  # no DONE
    _ok_rule(flags=NLM_F_MULTI | NLM_F_DUMP_INTR) + _done(RULE_SEQ),  # interrupted
    _ok_rule() + _message(NLMSG_DONE, struct.pack("=i", 0), seq=RULE_SEQ,
                          flags=NLM_F_MULTI | NLM_F_DUMP_INTR),
    _ok_rule(seq=7) + _done(RULE_SEQ),                           # another sequence
    _ok_rule() + _done(7),
    _message(NLMSG_ERROR, struct.pack("=i", -1) + b"\x00" * 16, seq=RULE_SEQ),
    _message(NLMSG_ERROR, struct.pack("=i", 0) + b"\x00" * 16, seq=RULE_SEQ) + _done(RULE_SEQ),
    _ok_rule() + _done(RULE_SEQ, error=-16),                     # DONE with an error
    _ok_rule() + _done(RULE_SEQ) + _ok_rule(),                   # after DONE
    _message(RTM_NEWROUTE, _BODY.pack(2, 0, 0, 0, 254, 0, 0, 1, 0), seq=RULE_SEQ)
    + _done(RULE_SEQ),                                           # another type
    _message(1, b"", seq=RULE_SEQ) + _done(RULE_SEQ),            # NOOP
    (_ok_rule() + _done(RULE_SEQ))[:-3],                         # truncated
    _ok_rule()[:10],                                             # header truncated
    struct.pack("=IHHII", 8, RTM_NEWRULE, 2, RULE_SEQ, 0) + _done(RULE_SEQ),
    struct.pack("=IHHII", 200, RTM_NEWRULE, 2, RULE_SEQ, 0) + b"\x00" * 12,
    _message(RTM_NEWRULE, b"\x02\x00\x00", seq=RULE_SEQ) + _done(RULE_SEQ),  # short body
    _message(RTM_NEWRULE, _BODY.pack(2, 0, 0, 0, 254, 0, 0, 1, 0) + struct.pack("=HH", 2, 6),
             seq=RULE_SEQ) + _done(RULE_SEQ),                    # attribute below its header
    _message(RTM_NEWRULE, _BODY.pack(2, 0, 0, 0, 254, 0, 0, 1, 0) + struct.pack("=HH", 40, 6),
             seq=RULE_SEQ) + _done(RULE_SEQ),                    # attribute past its message
    _message(RTM_NEWRULE, _BODY.pack(2, 0, 0, 0, 254, 0, 0, 1, 0) + b"\x08\x00",
             seq=RULE_SEQ) + _done(RULE_SEQ),                    # attribute header cut
    b"",
])
def test_a_dump_that_is_not_whole_is_unreadable(data):
    with pytest.raises(RouteDumpUnreadable):
        parse_rule_dump(data)


def test_a_route_dump_is_framed_the_same_way():
    with pytest.raises(RouteDumpUnreadable):
        parse_route_dump(_route(_ip(R_DST, "10.0.0.0"), dst_len=8, seq=1) + _done(1), LINKS)
    with pytest.raises(RouteDumpUnreadable):
        parse_route_dump(_route(_ip(R_DST, "10.0.0.0"), dst_len=8), LINKS)
    assert parse_route_dump(_done(ROUTE_SEQ), LINKS) == []


def test_too_many_entries_are_unreadable(monkeypatch):
    monkeypatch.setattr(exposure_route_dump, "_MESSAGE_LIMIT", 2)
    with pytest.raises(RouteDumpUnreadable):
        _rules(_ok_rule(), _ok_rule(), _ok_rule())
    assert len(_rules(_ok_rule(), _ok_rule())) == 2


# -- the socket ---------------------------------------------------------------------


class FakeSocket:
    def __init__(self, datagrams, *, fail_send=False):
        self.datagrams = list(datagrams)
        self.sent: list[bytes] = []
        self.closed = False
        self.fail_send = fail_send

    def send(self, data):
        if self.fail_send:
            raise OSError("no")
        self.sent.append(data)
        return len(data)

    def recv(self, size):
        if not self.datagrams:
            raise TimeoutError("timed out")
        return self.datagrams.pop(0)[:size]

    def close(self):
        self.closed = True


def test_the_readers_send_their_request_and_read_until_done():
    local, main, default = _defaults()
    fake = FakeSocket([local + _k1_lookup("lan0"), _k1_blackhole("lan0") + main,
                       default + _done(RULE_SEQ), b"never read"])
    rules = dump_ipv4_rules(open_socket=lambda: fake)
    assert fake.sent == [rule_dump_request()] and fake.closed
    assert decoy_reachability._rules_exact(rules, ("lan0",)) is True
    assert fake.datagrams == [b"never read"]

    fake = FakeSocket([_route(_ip(R_DST, "10.0.0.0"), _u32(R_OIF, 2), dst_len=8),
                       _done(ROUTE_SEQ)])
    assert dump_main_routes(LINKS, open_socket=lambda: fake) == [{"dst": "10.0.0.0/8"}]
    assert fake.sent == [route_dump_request()] and fake.closed


def _unopenable():
    raise PermissionError("denied")


@pytest.mark.parametrize("make", [
    lambda: FakeSocket([_ok_rule()]),                                  # times out
    lambda: FakeSocket([_ok_rule(), b""]),                             # closed early
    lambda: FakeSocket([(_ok_rule() + _done(RULE_SEQ))[:-2]]),         # cut datagram
    lambda: FakeSocket([_ok_rule()[:20], _ok_rule()[20:] + _done(RULE_SEQ)]),
    lambda: FakeSocket([_ok_rule(flags=NLM_F_MULTI | NLM_F_DUMP_INTR), _done(RULE_SEQ)]),
    lambda: FakeSocket([_ok_rule(seq=9), _done(RULE_SEQ)]),
    lambda: FakeSocket([_message(NLMSG_ERROR, struct.pack("=i", -13), seq=RULE_SEQ)]),
    lambda: FakeSocket([], fail_send=True),
])
def test_a_dump_not_received_whole_is_none(make):
    fake = make()
    assert dump_ipv4_rules(open_socket=lambda: fake) is None
    assert fake.closed
    assert dump_main_routes(LINKS, open_socket=_unopenable) is None


def test_a_dump_past_its_bound_is_none(monkeypatch):
    monkeypatch.setattr(exposure_route_dump, "_BYTE_LIMIT", 100)
    fake = FakeSocket([_ok_rule()] * 10 + [_done(RULE_SEQ)])
    assert dump_ipv4_rules(open_socket=lambda: fake) is None
    assert fake.closed


def test_the_socket_is_route_netlink_and_nothing_else():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == "socket"]
    assert [ast.unparse(call) for call in calls] == [
        "_socket.socket(_socket.AF_NETLINK, _socket.SOCK_RAW, _NETLINK_ROUTE)"]


# -- the boundary -------------------------------------------------------------------

_COMMISSIONING = {
    "netlink": REPO / "runtime" / "src" / "azazel_nexus_runtime" / "netlink.py",
    "exposure_interfaces": REPO / "src" / "azazel_nexus" / "exposure_interfaces.py",
    "fabric_boundary": REPO / "src" / "azazel_nexus" / "fabric_boundary.py",
    "commissioning_evidence": REPO / "src" / "azazel_nexus" / "commissioning_evidence.py",
}


def _imports(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            found.add("." * node.level + (node.module or ""))
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
    return found


def test_the_route_dump_imports_the_standard_library_only():
    assert _imports(SOURCE) == {"__future__", "annotations", "ipaddress", "socket",
                                "struct", "collections.abc", "Mapping", "typing",
                                "Callable", "Iterator", "Optional"}
    text = SOURCE.read_text(encoding="utf-8")
    for module in _COMMISSIONING:
        assert f"import {module}" not in text and f".{module}" not in text, module


def test_commissionings_role_judgement_does_not_import_the_route_dump():
    for name, path in _COMMISSIONING.items():
        assert path.is_file(), name
        assert not any("exposure_route_dump" in spelled for spelled in _imports(path)), name
        assert "exposure_route_dump" not in path.read_text(encoding="utf-8"), name


def test_the_route_dump_spawns_nothing():
    text = SOURCE.read_text(encoding="utf-8")
    for word in ("subprocess", "posix_spawn", "os.", "exec", "fork", "popen", "system("):
        assert word not in text, word


# -- recorded dumps -----------------------------------------------------------------

#: Keys a route inside the /24 keeps; each next hop keeps these.
_ROUTE_KEYS = ("dst", "dev", "gateway", "via", "type", "nexthops")
_HOP_KEYS = ("gateway", "via", "dev", "weight")


def _ip_rules(listed: list[dict]) -> list[dict]:
    """`ip -j -4 rule show` with the comparison's own normalisation: the
    `protocol` left out (`decoy_reachability._IGNORED_RULE_KEYS`)."""

    return [{key: value for key, value in rule.items()
             if key not in decoy_reachability._IGNORED_RULE_KEYS} for rule in listed]


def _inside(destination: str) -> bool:
    if destination == "default":
        return False
    network = ipaddress.IPv4Network(
        destination if "/" in destination else f"{destination}/32", strict=False)
    return network.subnet_of(decoy_reachability._HEADROOM)


def _ip_routes(listed: list[dict]) -> list[dict]:
    """`ip -j -4 route show table main` reduced to what `_routes_clear` reads."""

    reduced = []
    for route in listed:
        if not _inside(route["dst"]):
            reduced.append({"dst": route["dst"]})
            continue
        kept = {key: route[key] for key in _ROUTE_KEYS if key in route}
        if "nexthops" in kept:
            kept["nexthops"] = [{key: hop[key] for key in _HOP_KEYS if key in hop}
                                for hop in kept["nexthops"]]
        reduced.append(kept)
    return reduced


def _same_verdicts(mine_rules, ip_rules, mine_routes, ip_routes, ingress):
    exact = decoy_reachability._rules_exact
    clear = decoy_reachability._routes_clear
    assert exact(mine_rules, ingress) == exact(ip_rules, ingress)
    assert clear(mine_routes) == clear(ip_routes)
    assert clear(mine_routes, connected=False) == clear(ip_routes, connected=False)


def _recorded(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("phase", ["k1", "full"])
def test_the_recorded_dumps_read_as_the_recorded_ip_output(phase):
    links = {int(index): name for index, name in _recorded(f"{phase}-links.json").items()}
    rules = parse_rule_dump((FIXTURES / f"{phase}-rules.bin").read_bytes())
    routes = parse_route_dump((FIXTURES / f"{phase}-routes.bin").read_bytes(), links)
    ip_rules = _recorded(f"{phase}-ip-rules.json")
    ip_routes = _recorded(f"{phase}-ip-routes.json")
    assert rules == _ip_rules(ip_rules)
    assert routes == _ip_routes(ip_routes)
    ingress = ("eth9", "lan0")
    _same_verdicts(rules, ip_rules, routes, ip_routes, ingress)
    if phase == "k1":
        assert decoy_reachability._rules_exact(rules, ingress) is True
        assert decoy_reachability._routes_clear(routes, connected=False) is True
    else:
        assert decoy_reachability._rules_exact(rules, ingress) is False
        assert decoy_reachability._routes_clear(routes) is False
        inside = [route for route in routes if _inside(route["dst"])]
        assert {"nexthops", "gateway", "via", "type", "dev"} <= {
            key for route in inside for key in route}
        assert any(rule.get("protocol") == "static" for rule in ip_rules)


# -- the live equivalence check -----------------------------------------------------

#: Run inside a fresh network namespace: build the scene with `ip`, then
#: print this module's dumps and `ip -j`'s, phase by phase, as JSON. With a
#: second argument, also write the raw dumps there (the fixtures).
_CHILD = r'''
import json, os, subprocess, sys
from azazel_nexus_runtime import exposure_route_dump as m, netlink

def ip(*args):
    subprocess.run(["ip", *args], check=True, capture_output=True)

def ip_json(*args):
    return json.loads(subprocess.run(["ip", "-j", "-4", *args], check=True,
                                     capture_output=True).stdout)

try:
    for name in ("lan0", "eth9"):
        ip("link", "add", name, "type", "dummy")
except subprocess.CalledProcessError:
    sys.exit(77)

def snapshot(phase, record):
    links = {r.index: r.name for r in netlink.read_links()}
    raw_rules = m._receive(m.rule_dump_request(), m._RULE_SEQUENCE, None)
    raw_routes = m._receive(m.route_dump_request(), m._ROUTE_SEQUENCE, None)
    ip_rules, ip_routes = ip_json("rule", "show"), ip_json("route", "show", "table", "main")
    if record:
        def write(name, data):
            with open(os.path.join(record, f"{phase}-{name}"), "wb") as out:
                out.write(data)
        write("rules.bin", raw_rules)
        write("routes.bin", raw_routes)
        dump = lambda value: (json.dumps(value, indent=1) + "\n").encode()
        write("links.json", dump({str(k): v for k, v in sorted(links.items())}))
        write("ip-rules.json", dump(ip_rules))
        write("ip-routes.json", dump(ip_routes))
    return {"rules": m.dump_ipv4_rules(), "routes": m.dump_main_routes(links),
            "parsed_rules": m.parse_rule_dump(raw_rules),
            "parsed_routes": m.parse_route_dump(raw_routes, links),
            "ip_rules": ip_rules, "ip_routes": ip_routes}

record = sys.argv[2] if len(sys.argv) > 2 else None
for name in ("lo", "lan0", "eth9"):
    ip("link", "set", name, "up")
ip("addr", "add", "192.0.2.1/24", "dev", "lan0")
# K1 as `ip rule add` makes it (lan0) and as networkd makes it (eth9).
ip("rule", "add", "priority", "1960", "iif", "lan0", "to", "10.255.196.0/30",
   "lookup", "main", "suppress_prefixlen", "29")
ip("rule", "add", "priority", "1961", "iif", "lan0", "blackhole")
ip("rule", "add", "priority", "1960", "iif", "eth9", "to", "10.255.196.0/30",
   "lookup", "main", "suppress_prefixlen", "29", "protocol", "static")
ip("rule", "add", "priority", "1961", "iif", "eth9", "table", "main", "blackhole",
   "protocol", "static")
ip("route", "add", "default", "via", "192.0.2.254")
ip("route", "add", "10.0.0.0/8", "via", "192.0.2.3", "metric", "5")
out = {"k1": snapshot("k1", record)}

# Routes first: the discarding rules below would refuse a gateway's lookup.
ip("addr", "add", "10.255.196.1/30", "dev", "eth9")
ip("route", "add", "10.255.196.16/30", "via", "192.0.2.5")
ip("route", "add", "10.255.196.32/28", "nexthop", "via", "192.0.2.6", "dev", "lan0",
   "weight", "2", "nexthop", "via", "192.0.2.7", "dev", "lan0")
ip("route", "add", "10.255.196.48/30", "via", "192.0.2.5", "dev", "lan0", "metric", "7",
   "src", "192.0.2.1", "mtu", "lock", "1400")
ip("route", "add", "10.255.196.52/30", "dev", "lan0", "onlink", "via", "inet6", "fe80::1")
ip("route", "add", "blackhole", "10.255.196.64/30")
ip("route", "add", "unreachable", "10.255.196.68/30")
ip("route", "add", "throw", "10.255.196.88/30")
ip("route", "add", "local", "10.255.196.96/30", "dev", "lan0", "table", "main")
ip("route", "add", "10.255.196.200", "dev", "eth9")
ip("route", "add", "10.255.196.72/30", "dev", "eth9", "table", "100")
ip("nexthop", "add", "id", "9", "via", "192.0.2.9", "dev", "lan0")
ip("route", "add", "198.51.100.0/24", "nhid", "9")
for rule in (
        "priority 100 from 192.0.2.0/24 to 198.51.100.7 lookup 100",
        "priority 101 not fwmark 0x5/0xff oif eth9 lookup 253",
        "priority 102 tos 0x10 uidrange 1-2 ipproto 253 sport 1-2 dport 3 table 300",
        "priority 103 unreachable", "priority 104 prohibit", "priority 105 goto 200",
        "priority 106 nop", "priority 107 l3mdev", "priority 108 tun_id 5 lookup 5",
        "priority 109 suppress_ifgroup 3 lookup main", "priority 110 realms 4 lookup main",
        "priority 111 realms 3/5 lookup main", "priority 112 goto 999",
        "priority 113 iif lan0 oif eth9 lookup 255", "priority 114 dport 22 sport 1000 lookup 254",
        "priority 115 uidrange 100-200 lookup main", "priority 116 fwmark 7 lookup main",
        "priority 117 iif nosuch lookup main", "priority 118 oif nosuch lookup main",
        "priority 119 fwmark 0/0xff lookup main", "priority 120 from 0.0.0.0/8 lookup main",
        "priority 121 from 1.2.3.4/32 lookup 1000", "priority 122 lookup 252",
        "priority 123 table 253 suppress_prefixlen 0", "priority 200 lookup main"):
    ip("rule", "add", *rule.split())
out["full"] = snapshot("full", record)
json.dump(out, open(sys.argv[1], "w"))
'''


def _run_in_a_namespace(tmp_path: Path, record: str | None = None) -> dict:
    if not sys.platform.startswith("linux"):
        pytest.skip("route netlink is Linux's")
    if shutil.which("ip") is None or shutil.which("unshare") is None:
        pytest.skip("iproute2 or unshare is not installed")
    result_path = tmp_path / "out.json"
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
    child = [sys.executable, "-c", _CHILD, str(result_path), *([record] if record else [])]
    tried = []
    for prefix in (["unshare", "--net"], ["unshare", "--user", "--map-root-user", "--net"]):
        probe = subprocess.run([*prefix, "--", "true"], capture_output=True)
        if probe.returncode != 0:
            tried.append(probe.stderr.decode(errors="replace").strip())
            continue
        done = subprocess.run([*prefix, "--", *child], capture_output=True, env=env)
        if done.returncode == 77:
            tried.append("no dummy link in this namespace")
            continue
        assert done.returncode == 0, done.stderr.decode(errors="replace")
        return json.loads(result_path.read_text(encoding="utf-8"))
    pytest.skip(f"no network namespace could be made: {tried}")


def test_the_dump_equals_ip_j_in_a_fresh_namespace(tmp_path):
    out = _run_in_a_namespace(tmp_path, os.environ.get("AZ_ROUTE_DUMP_RECORD"))
    for phase in ("k1", "full"):
        seen = out[phase]
        assert seen["rules"] == seen["parsed_rules"] == _ip_rules(seen["ip_rules"]), phase
        assert seen["routes"] == seen["parsed_routes"] == _ip_routes(seen["ip_routes"]), phase
        _same_verdicts(seen["rules"], seen["ip_rules"], seen["routes"], seen["ip_routes"],
                       ("eth9", "lan0"))
    k1, full = out["k1"], out["full"]
    assert decoy_reachability._rules_exact(k1["rules"], ("eth9", "lan0")) is True
    assert decoy_reachability._routes_clear(k1["routes"], connected=False) is True
    assert decoy_reachability._rules_exact(full["rules"], ("eth9", "lan0")) is False
    inside = [route for route in full["routes"] if _inside(route["dst"])]
    assert {"nexthops", "gateway", "via", "type", "dev"} <= {
        key for route in inside for key in route}
    assert {"not", "fwmask", "oif", "uid_start", "ipproto", "sport_start", "dport", "goto",
            "unresolved", "nop", "l3mdev", "tun_id", "suppress_ifgroup", "flow_from",
            "flow_to", "iif_detached", "oif_detached", "srclen", "action"} <= {
        key for rule in full["rules"] for key in rule}
