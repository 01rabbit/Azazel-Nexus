"""The rules and the main routes, read from route netlink (#196 G6, B1).

`docs/deception-exposure-wiring.md` §4.4, option B1 (owner decision §9 Q-N).
The activation controller starts no process and holds no `CAP_NET_ADMIN`,
so it cannot print `ip -j -4 rule show` or `ip -j -4 route show table main`
as the verify does. Route netlink dumps need neither: this module sends
`RTM_GETRULE` (IPv4) and `RTM_GETROUTE` (IPv4) as dump requests and parses
the replies into **the dictionaries `ip -j` prints**, so that
`decoy_reachability._rules_exact` and `_routes_clear` stay the one
comparison of the pass and the verify.

**Implemented, not wired**: nothing imports it. The pass will
(`tests/unit/test_g6_unwired.py` lists it with no importer).

## Why a module of its own

`netlink.py` is the commissioning reader of permanent MACs, pinned to one
request, and it drops the routes commissioning §4 forbids it to know. This
module imports nothing of commissioning's role judgement (the MAC reader,
the role resolver, the fabric boundary, the commissioning evidence; wiring
§4.4 names the four) and none of those imports it
(`tests/unit/test_exposure_route_dump.py`). The names of
the routes' output links are the caller's: it passes a mapping of interface
index to name (built by the pass from `netlink.read_links`), and a name
that is None or absent makes the route dump unreadable.

## What it sends, what it keeps

Two messages, each built in one function: `RTM_GETRULE` and `RTM_GETROUTE`,
dump, request, family IPv4. Nothing else; no name here is bound to a
write. The socket is `AF_NETLINK`, `NETLINK_ROUTE`, as `netlink.py` opens
it; no capability is needed to dump.

* **Rules**: every key `ip -j -4 rule show` (iproute2 6.15, no `-d`)
  prints, with `protocol` parsed and dropped (the comparison leaves it
  out). Table numbers are named as `ip` names them by default (253
  `default`, 254 `main`, 255 `local`, any other number as its decimal
  text); `/etc/iproute2/rt_tables` is never read, nor any other iproute2
  or system file. The values `ip` names from such a file (a `tos`, an
  `ipproto`, a `suppress_ifgroup`, a realm) are printed as `ip` prints a
  number its file does not name (`0x10`, `ipproto-6`, `0`, `0`): the key
  is the same, and any of those keys fails the comparison whatever its
  value.
* **Routes**: table 254 only (`RTA_TABLE` when present, else the
  header's); cloned entries are skipped as `ip` skips them. A route
  inside `10.255.196.0/24` is reduced to `dst`, `dev`, `gateway`, `via`,
  `type` and `nexthops` (each hop `gateway`/`via`, `dev`, `weight`); a
  route outside it to `dst`, all `_routes_clear` needs of it.

## Closed on the unknown

A rule attribute, flag or action this module does not translate, a route
in the /24 with a nexthop object (`RTA_NH_ID`) or another attribute it
does not know, a link without a name, an interrupted dump
(`NLM_F_DUMP_INTR`), a reply of another sequence, an error reply, a
truncated or oversized message: each makes the whole dump unreadable
(`RouteDumpUnreadable`; the readers return None), never a key that drops
out of the comparison. The pass maps it to `forwarding_unreadable`.
"""

from __future__ import annotations

import ipaddress
import socket as _socket
import struct
from collections.abc import Mapping
from typing import Callable, Iterator, Optional

__all__ = [
    "RouteDumpUnreadable",
    "dump_ipv4_rules",
    "dump_main_routes",
    "parse_route_dump",
    "parse_rule_dump",
    "route_dump_request",
    "rule_dump_request",
]

_NETLINK_ROUTE = 0

#: The two message types this module sends, both dump requests.
_RTM_GETROUTE = 26
_RTM_GETRULE = 34
#: What the dumps reply with. Received, never sent.
_RTM_NEWROUTE = 24
_RTM_NEWRULE = 32
_NLMSG_ERROR = 2
_NLMSG_DONE = 3

_NLM_F_REQUEST = 0x001
_NLM_F_DUMP = 0x300
_NLM_F_DUMP_INTR = 0x010

#: The IPv4 family as the message headers carry it (not a socket family).
_FAMILY_IPV4 = 2
_HOST_LEN = 32

#: The sequence numbers of the two requests; every reply must carry its own.
_RULE_SEQUENCE = 1
_ROUTE_SEQUENCE = 2

_HEADER = struct.Struct("=IHHII")
#: `struct fib_rule_hdr` and `struct rtmsg` share one layout.
_BODY = struct.Struct("=BBBBBBBBI")
_ATTRIBUTE = struct.Struct("=HH")
_NEXTHOP = struct.Struct("=HBBi")

#: Bounds: a dump larger than this is not one the controller holds.
_BYTE_LIMIT = 1 << 20
_MESSAGE_LIMIT = 16384
_RECEIVE_SIZE = 1 << 16
_TIMEOUT = 5.0

# -- rules -----------------------------------------------------------------------

_FRA_DST, _FRA_SRC, _FRA_IIFNAME, _FRA_GOTO = 1, 2, 3, 4
_FRA_PRIORITY = 6
_FRA_FWMARK, _FRA_FLOW, _FRA_TUN_ID = 10, 11, 12
_FRA_SUPPRESS_IFGROUP, _FRA_SUPPRESS_PREFIXLEN, _FRA_TABLE = 13, 14, 15
_FRA_FWMASK, _FRA_OIFNAME, _FRA_PAD, _FRA_L3MDEV = 16, 17, 18, 19
_FRA_UID_RANGE, _FRA_PROTOCOL, _FRA_IP_PROTO = 20, 21, 22
_FRA_SPORT_RANGE, _FRA_DPORT_RANGE = 23, 24
#: Every rule attribute translated (or, `protocol` and the padding, parsed
#: and dropped). Anything else -- `FRA_DSCP`, the flow label, a port mask, an
#: attribute a later kernel adds -- makes the dump unreadable.
_RULE_ATTRIBUTES = frozenset({
    _FRA_DST, _FRA_SRC, _FRA_IIFNAME, _FRA_GOTO, _FRA_PRIORITY, _FRA_FWMARK,
    _FRA_FLOW, _FRA_TUN_ID, _FRA_SUPPRESS_IFGROUP, _FRA_SUPPRESS_PREFIXLEN,
    _FRA_TABLE, _FRA_FWMASK, _FRA_OIFNAME, _FRA_PAD, _FRA_L3MDEV,
    _FRA_UID_RANGE, _FRA_PROTOCOL, _FRA_IP_PROTO, _FRA_SPORT_RANGE,
    _FRA_DPORT_RANGE,
})

_FIB_RULE_PERMANENT, _FIB_RULE_INVERT, _FIB_RULE_UNRESOLVED = 0x1, 0x2, 0x4
_FIB_RULE_IIF_DETACHED, _FIB_RULE_OIF_DETACHED = 0x8, 0x10
_RULE_FLAGS = (_FIB_RULE_PERMANENT | _FIB_RULE_INVERT | _FIB_RULE_UNRESOLVED
               | _FIB_RULE_IIF_DETACHED | _FIB_RULE_OIF_DETACHED)

_FR_ACT_TO_TBL, _FR_ACT_GOTO, _FR_ACT_NOP = 1, 2, 3
#: The discarding actions, named as `ip` names them (`rtnl_rtntype_n2a`).
_RULE_ACTIONS = {6: "blackhole", 7: "unreachable", 8: "prohibit"}

#: The tables `ip` names without reading a file.
_TABLES = {253: "default", 254: "main", 255: "local"}
_MAIN_TABLE = 254
_ALL_ONES = 0xFFFFFFFF

# -- routes ----------------------------------------------------------------------

_RTA_DST, _RTA_OIF, _RTA_GATEWAY, _RTA_PRIORITY = 1, 4, 5, 6
_RTA_PREFSRC, _RTA_METRICS, _RTA_MULTIPATH = 7, 8, 9
_RTA_TABLE, _RTA_VIA = 15, 18
#: Translated, or (metric, source address, metrics) parsed and dropped, for
#: a route inside the /24. `RTA_NH_ID` and everything else is unreadable.
_ROUTE_ATTRIBUTES = frozenset({
    _RTA_DST, _RTA_OIF, _RTA_GATEWAY, _RTA_PRIORITY, _RTA_PREFSRC,
    _RTA_METRICS, _RTA_MULTIPATH, _RTA_TABLE, _RTA_VIA,
})
_NEXTHOP_ATTRIBUTES = frozenset({_RTA_GATEWAY, _RTA_VIA})
_RTM_F_CLONED = 0x200
_RTN_UNICAST = 1
#: Route types as `ip` names them (`rtnl_rtntype_n2a`); any other number is
#: printed as its decimal text.
_ROUTE_TYPES = {0: "none", 1: "unicast", 2: "local", 3: "broadcast", 4: "anycast",
                5: "multicast", 6: "blackhole", 7: "unreachable", 8: "prohibit",
                9: "throw", 10: "nat", 11: "xresolve"}
_VIA_FAMILIES = {_FAMILY_IPV4: ("inet", 4), 10: ("inet6", 16)}
#: The decoy network's /24 (`decoy_reachability._HEADROOM`).
_HEADROOM = ipaddress.IPv4Network("10.255.196.0/24")


class RouteDumpUnreadable(Exception):
    """The dump cannot be read whole. Nothing of it is reported."""


# -- the two requests ------------------------------------------------------------


def _request(message_type: int, sequence: int) -> bytes:
    body = _BODY.pack(_FAMILY_IPV4, 0, 0, 0, 0, 0, 0, 0, 0)
    return _HEADER.pack(_HEADER.size + len(body), message_type,
                        _NLM_F_REQUEST | _NLM_F_DUMP, sequence, 0) + body


def rule_dump_request(sequence: int = _RULE_SEQUENCE) -> bytes:
    """`RTM_GETRULE`, dump, request, IPv4."""

    return _request(_RTM_GETRULE, sequence)


def route_dump_request(sequence: int = _ROUTE_SEQUENCE) -> bytes:
    """`RTM_GETROUTE`, dump, request, IPv4."""

    return _request(_RTM_GETROUTE, sequence)


# -- walking the replies ---------------------------------------------------------


def _messages(data: bytes) -> Iterator[tuple[int, int, int, bytes]]:
    """`(type, flags, sequence, payload)` of each whole message in `data`."""

    offset = 0
    while offset < len(data):
        if offset + _HEADER.size > len(data):
            raise RouteDumpUnreadable("a message header is truncated")
        length, message_type, flags, sequence, _pid = _HEADER.unpack_from(data, offset)
        if length < _HEADER.size or offset + length > len(data):
            raise RouteDumpUnreadable("a message length is outside its buffer")
        yield message_type, flags, sequence, data[offset + _HEADER.size: offset + length]
        offset += (length + 3) & ~3


def _payloads(data: bytes, expected: int, sequence: int) -> list[bytes]:
    """The payloads of a dump that ends in `NLMSG_DONE` and has nothing else.

    Refused: a message of another sequence, an interrupted dump, an error
    reply (or a `DONE` carrying an error), a message of a type that is
    neither `expected` nor `DONE`, anything after `DONE`, no `DONE`, too
    many messages.
    """

    payloads: list[bytes] = []
    done = False
    for message_type, flags, message_sequence, payload in _messages(data):
        if done:
            raise RouteDumpUnreadable("a message follows the end of the dump")
        if message_sequence != sequence:
            raise RouteDumpUnreadable("a reply carries another sequence number")
        if flags & _NLM_F_DUMP_INTR:
            raise RouteDumpUnreadable("the dump was interrupted")
        if message_type == _NLMSG_ERROR:
            raise RouteDumpUnreadable("the kernel answered with an error")
        if message_type == _NLMSG_DONE:
            if len(payload) >= 4 and struct.unpack_from("=i", payload)[0] != 0:
                raise RouteDumpUnreadable("the dump ended with an error")
            done = True
            continue
        if message_type != expected:
            raise RouteDumpUnreadable("a reply is of another message type")
        payloads.append(payload)
        if len(payloads) > _MESSAGE_LIMIT:
            raise RouteDumpUnreadable("the dump has too many entries")
    if not done:
        raise RouteDumpUnreadable("the dump has no end")
    return payloads


def _attributes(payload: bytes, start: int) -> dict[int, bytes]:
    """Every attribute from `start`, by type; a repeated type is refused."""

    found: dict[int, bytes] = {}
    offset = start
    while offset < len(payload):
        if offset + _ATTRIBUTE.size > len(payload):
            raise RouteDumpUnreadable("an attribute header is truncated")
        length, attribute_type = _ATTRIBUTE.unpack_from(payload, offset)
        if length < _ATTRIBUTE.size or offset + length > len(payload):
            raise RouteDumpUnreadable("an attribute length is outside its message")
        # The nested and byte-order flags are not part of the type here.
        attribute_type &= 0x3FFF
        if attribute_type in found:
            raise RouteDumpUnreadable("an attribute is repeated")
        found[attribute_type] = payload[offset + _ATTRIBUTE.size: offset + length]
        offset += (length + 3) & ~3
    return found


def _body(payload: bytes) -> tuple[int, ...]:
    if len(payload) < _BODY.size:
        raise RouteDumpUnreadable("a message is shorter than its header")
    fields = _BODY.unpack_from(payload, 0)
    if fields[0] != _FAMILY_IPV4:
        raise RouteDumpUnreadable("an entry is not of the IPv4 family")
    return fields


def _u8(value: bytes) -> int:
    if len(value) != 1:
        raise RouteDumpUnreadable("a one-byte attribute has another length")
    return value[0]


def _u32(value: bytes) -> int:
    if len(value) != 4:
        raise RouteDumpUnreadable("a four-byte attribute has another length")
    return struct.unpack("=I", value)[0]


def _s32(value: bytes) -> int:
    if len(value) != 4:
        raise RouteDumpUnreadable("a four-byte attribute has another length")
    return struct.unpack("=i", value)[0]


def _address(value: bytes) -> str:
    if len(value) != 4:
        raise RouteDumpUnreadable("an IPv4 address has another length")
    return str(ipaddress.IPv4Address(value))


def _name(value: bytes) -> str:
    if not value.endswith(b"\x00"):
        raise RouteDumpUnreadable("an interface name is not terminated")
    try:
        return value[:-1].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RouteDumpUnreadable("an interface name is not text") from exc


def _table_name(table: int) -> str:
    return _TABLES.get(table, str(table))


def _hex(value: int) -> str:
    """`%#llx`, as `ip` prints a mark: `0` for zero, `0x5` otherwise."""

    return hex(value) if value else "0"


def _prefix(rule: dict, key: str, value: Optional[bytes], length: int,
            otherwise: Optional[str]) -> None:
    """`src`/`srclen` or `dst`/`dstlen`, as `ip` prints them."""

    if value is not None:
        rule[key] = _address(value)
        if length != _HOST_LEN:
            rule[key + "len"] = length
    elif length:
        rule[key] = "0"
        rule[key + "len"] = length
    elif otherwise is not None:
        rule[key] = otherwise


def _ports(rule: dict, key: str, value: bytes) -> None:
    if len(value) != 4:
        raise RouteDumpUnreadable("a port range has another length")
    start, end = struct.unpack("=HH", value)
    if start == end:
        rule[key] = start
    else:
        rule[key + "_start"] = start
        rule[key + "_end"] = end


def _rule(payload: bytes) -> dict:
    """One rule as `ip -j -4 rule show` prints it, `protocol` left out."""

    _family, dst_len, src_len, tos, header_table, res1, res2, action, flags = _body(payload)
    attributes = _attributes(payload, _BODY.size)
    if set(attributes) - _RULE_ATTRIBUTES:
        raise RouteDumpUnreadable("a rule carries an attribute this reader does not know")
    if flags & ~_RULE_FLAGS or res1 or res2:
        raise RouteDumpUnreadable("a rule carries a flag this reader does not know")
    if dst_len > _HOST_LEN or src_len > _HOST_LEN:
        raise RouteDumpUnreadable("a rule's prefix length is out of range")
    get = attributes.get
    if get(_FRA_PROTOCOL) is not None:
        _u8(attributes[_FRA_PROTOCOL])  # parsed and dropped

    rule: dict = {"priority": _u32(get(_FRA_PRIORITY)) if _FRA_PRIORITY in attributes else 0}
    if flags & _FIB_RULE_INVERT:
        rule["not"] = None
    _prefix(rule, "src", get(_FRA_SRC), src_len, "all")
    _prefix(rule, "dst", get(_FRA_DST), dst_len, None)
    if tos:
        rule["tos"] = f"0x{tos:02x}"
    if _FRA_FWMARK in attributes or _FRA_FWMASK in attributes:
        mark = _u32(attributes[_FRA_FWMARK]) if _FRA_FWMARK in attributes else 0
        mask = _u32(attributes[_FRA_FWMASK]) if _FRA_FWMASK in attributes else _ALL_ONES
        rule["fwmark"] = _hex(mark)
        if mask != _ALL_ONES:
            rule["fwmask"] = _hex(mask)
    if _FRA_IIFNAME in attributes:
        rule["iif"] = _name(attributes[_FRA_IIFNAME])
        if flags & _FIB_RULE_IIF_DETACHED:
            rule["iif_detached"] = None
    elif flags & _FIB_RULE_IIF_DETACHED:
        raise RouteDumpUnreadable("a rule's input link is detached and unnamed")
    if _FRA_OIFNAME in attributes:
        rule["oif"] = _name(attributes[_FRA_OIFNAME])
        if flags & _FIB_RULE_OIF_DETACHED:
            rule["oif_detached"] = None
    elif flags & _FIB_RULE_OIF_DETACHED:
        raise RouteDumpUnreadable("a rule's output link is detached and unnamed")
    if _FRA_L3MDEV in attributes and _u8(attributes[_FRA_L3MDEV]):
        rule["l3mdev"] = None
    if _FRA_UID_RANGE in attributes:
        value = attributes[_FRA_UID_RANGE]
        if len(value) != 8:
            raise RouteDumpUnreadable("a uid range has another length")
        rule["uid_start"], rule["uid_end"] = struct.unpack("=II", value)
    if _FRA_IP_PROTO in attributes:
        rule["ipproto"] = f"ipproto-{_u8(attributes[_FRA_IP_PROTO])}"
    if _FRA_SPORT_RANGE in attributes:
        _ports(rule, "sport", attributes[_FRA_SPORT_RANGE])
    if _FRA_DPORT_RANGE in attributes:
        _ports(rule, "dport", attributes[_FRA_DPORT_RANGE])
    if _FRA_TUN_ID in attributes:
        value = attributes[_FRA_TUN_ID]
        if len(value) != 8:
            raise RouteDumpUnreadable("a tunnel id has another length")
        rule["tun_id"] = struct.unpack(">Q", value)[0]
    table = _u32(attributes[_FRA_TABLE]) if _FRA_TABLE in attributes else header_table
    if table:
        rule["table"] = _table_name(table)
        if _FRA_SUPPRESS_PREFIXLEN in attributes:
            length = _s32(attributes[_FRA_SUPPRESS_PREFIXLEN])
            if length != -1:
                rule["suppress_prefixlen"] = length
        if _FRA_SUPPRESS_IFGROUP in attributes:
            group = _s32(attributes[_FRA_SUPPRESS_IFGROUP])
            if group != -1:
                rule["suppress_ifgroup"] = str(group)
    else:
        # Not printed by `ip` without a table, so not checked by anything:
        # still parsed, so a malformed one is refused.
        for kind in (_FRA_SUPPRESS_PREFIXLEN, _FRA_SUPPRESS_IFGROUP):
            if kind in attributes:
                _s32(attributes[kind])
    if _FRA_FLOW in attributes:
        flow = _u32(attributes[_FRA_FLOW])
        if flow >> 16:
            rule["flow_from"] = str(flow >> 16)
        rule["flow_to"] = str(flow & 0xFFFF)
    if action == _FR_ACT_GOTO:
        rule["goto"] = _u32(attributes[_FRA_GOTO]) if _FRA_GOTO in attributes else "none"
        if flags & _FIB_RULE_UNRESOLVED:
            rule["unresolved"] = None
    elif flags & _FIB_RULE_UNRESOLVED:
        raise RouteDumpUnreadable("a rule other than a goto is marked unresolved")
    elif _FRA_GOTO in attributes:
        raise RouteDumpUnreadable("a rule other than a goto carries a target")
    elif action == _FR_ACT_NOP:
        rule["nop"] = None
    elif action in _RULE_ACTIONS:
        rule["action"] = _RULE_ACTIONS[action]
    elif action != _FR_ACT_TO_TBL:
        raise RouteDumpUnreadable("a rule carries an action this reader does not know")
    return rule


def parse_rule_dump(data: bytes, sequence: int = _RULE_SEQUENCE) -> list[dict]:
    """The rules of an `RTM_GETRULE` dump, in the kernel's order. Raises
    `RouteDumpUnreadable` rather than return part of it."""

    return [_rule(payload) for payload in _payloads(data, _RTM_NEWRULE, sequence)]


# -- routes ----------------------------------------------------------------------


def _link_name(links: Mapping[int, Optional[str]], index: int) -> str:
    name = links.get(index)
    if type(name) is not str or not name:
        raise RouteDumpUnreadable("a route's output link has no name")
    return name


def _via(value: bytes) -> dict:
    if len(value) < 2:
        raise RouteDumpUnreadable("a via address is truncated")
    (family,) = struct.unpack_from("=H", value)
    if family not in _VIA_FAMILIES:
        raise RouteDumpUnreadable("a via address is of an unknown family")
    name, size = _VIA_FAMILIES[family]
    raw = value[2:]
    if len(raw) != size:
        raise RouteDumpUnreadable("a via address has another length")
    return {"family": name, "host": str(ipaddress.ip_address(raw))}


def _nexthops(value: bytes, links: Mapping[int, Optional[str]]) -> list[dict]:
    hops: list[dict] = []
    offset = 0
    while offset < len(value):
        if offset + _NEXTHOP.size > len(value):
            raise RouteDumpUnreadable("a next hop is truncated")
        length, _flags, weight, index = _NEXTHOP.unpack_from(value, offset)
        if length < _NEXTHOP.size or offset + length > len(value):
            raise RouteDumpUnreadable("a next hop's length is outside its route")
        attributes = _attributes(value[offset: offset + length], _NEXTHOP.size)
        if set(attributes) - _NEXTHOP_ATTRIBUTES:
            raise RouteDumpUnreadable("a next hop carries an attribute this reader does not know")
        hop: dict = {}
        if _RTA_GATEWAY in attributes:
            hop["gateway"] = _address(attributes[_RTA_GATEWAY])
        if _RTA_VIA in attributes:
            hop["via"] = _via(attributes[_RTA_VIA])
        hop["dev"] = _link_name(links, index)
        hop["weight"] = weight + 1
        hops.append(hop)
        offset += (length + 3) & ~3
    if not hops:
        raise RouteDumpUnreadable("a multipath route has no next hop")
    return hops


def _destination(value: Optional[bytes], length: int) -> str:
    """`dst` as `ip` prints it: `default`, `a.b.c.d` for a host, else with
    its prefix length."""

    if length > _HOST_LEN:
        raise RouteDumpUnreadable("a route's prefix length is out of range")
    if value is None:
        return f"0/{length}" if length else "default"
    address = _address(value)
    return address if length == _HOST_LEN else f"{address}/{length}"


def _route(payload: bytes, links: Mapping[int, Optional[str]]) -> Optional[dict]:
    """One route of `main` reduced to what `_routes_clear` reads, or None
    for an entry of another table or a cloned one."""

    _family, dst_len, src_len, tos, header_table, _protocol, _scope, kind, flags = _body(payload)
    attributes = _attributes(payload, _BODY.size)
    table = _u32(attributes[_RTA_TABLE]) if _RTA_TABLE in attributes else header_table
    if table != _MAIN_TABLE or flags & _RTM_F_CLONED:
        return None
    destination = _destination(attributes.get(_RTA_DST), dst_len)
    # A named output link is required of every route of `main`, inside the
    # /24 or not (wiring §4.4).
    device = (_link_name(links, _u32(attributes[_RTA_OIF]))
              if _RTA_OIF in attributes else None)
    # Without `RTA_DST` the destination is `default` or `0/n`, outside the
    # /24. `_routes_clear` parses `dst` itself; this only chooses the keys.
    if _RTA_DST not in attributes or not ipaddress.IPv4Network(
            (destination.split("/")[0], dst_len), strict=False).subnet_of(_HEADROOM):
        return {"dst": destination}
    if set(attributes) - _ROUTE_ATTRIBUTES or src_len or tos:
        raise RouteDumpUnreadable(
            "a route inside the decoy network carries what this reader does not know")
    route: dict = {"dst": destination}
    if kind != _RTN_UNICAST:
        route["type"] = _ROUTE_TYPES.get(kind, str(kind))
    if device is not None:
        route["dev"] = device
    if _RTA_GATEWAY in attributes:
        route["gateway"] = _address(attributes[_RTA_GATEWAY])
    if _RTA_VIA in attributes:
        route["via"] = _via(attributes[_RTA_VIA])
    if _RTA_MULTIPATH in attributes:
        route["nexthops"] = _nexthops(attributes[_RTA_MULTIPATH], links)
    for kind_dropped in (_RTA_PRIORITY, _RTA_PREFSRC):
        if kind_dropped in attributes:
            _u32(attributes[kind_dropped])
    return route


def parse_route_dump(data: bytes, links: Mapping[int, Optional[str]],
                     sequence: int = _ROUTE_SEQUENCE) -> list[dict]:
    """The routes of `main` in an `RTM_GETROUTE` dump, in the kernel's order.

    `links` maps an interface index to its name (None when the link dump
    gave none). Raises `RouteDumpUnreadable` rather than return part of it.
    """

    if not isinstance(links, Mapping) or not all(
            type(index) is int and (name is None or type(name) is str)
            for index, name in links.items()):
        raise RouteDumpUnreadable("the link names are not a mapping of index to name")
    routes = (_route(payload, links)
              for payload in _payloads(data, _RTM_NEWROUTE, sequence))
    return [route for route in routes if route is not None]


# -- the socket ------------------------------------------------------------------


def _receive(request: bytes, sequence: int,
             open_socket: Optional[Callable[[], "_socket.socket"]]) -> bytes:
    """Send one dump request; every datagram until the dump's end, whole.

    Each datagram must hold whole messages: one cut short (a receive buffer
    too small, `MSG_TRUNC`) is refused, not joined to the next.
    """

    try:
        connection = (open_socket or _open_route_socket)()
    except OSError as exc:
        raise RouteDumpUnreadable("a netlink socket could not be opened") from exc
    try:
        connection.send(request)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = connection.recv(_RECEIVE_SIZE)
            if not chunk:
                raise RouteDumpUnreadable("the socket closed before the dump ended")
            total += len(chunk)
            if total > _BYTE_LIMIT:
                raise RouteDumpUnreadable("the dump exceeds its bound")
            chunks.append(chunk)
            if any(message_type in (_NLMSG_DONE, _NLMSG_ERROR)
                   or message_sequence != sequence or flags & _NLM_F_DUMP_INTR
                   for message_type, flags, message_sequence, _ in _messages(chunk)):
                break
    except OSError as exc:
        raise RouteDumpUnreadable("the dump could not be received") from exc
    finally:
        connection.close()
    return b"".join(chunks)


def _open_route_socket() -> "_socket.socket":  # pragma: no cover - needs a kernel
    connection = _socket.socket(_socket.AF_NETLINK, _socket.SOCK_RAW, _NETLINK_ROUTE)
    try:
        connection.bind((0, 0))
        connection.settimeout(_TIMEOUT)
    except OSError:
        connection.close()
        raise
    return connection


def dump_ipv4_rules(*, open_socket: Optional[Callable[[], "_socket.socket"]] = None
                    ) -> Optional[list[dict]]:
    """`ip -j -4 rule show`, without `protocol`, from the kernel; None when
    the dump cannot be read whole (`forwarding_unreadable`)."""

    try:
        data = _receive(rule_dump_request(), _RULE_SEQUENCE, open_socket)
        return parse_rule_dump(data)
    except RouteDumpUnreadable:
        return None


def dump_main_routes(links: Mapping[int, Optional[str]], *,
                     open_socket: Optional[Callable[[], "_socket.socket"]] = None
                     ) -> Optional[list[dict]]:
    """`ip -j -4 route show table main`, reduced to what `_routes_clear`
    reads, from the kernel; None when the dump cannot be read whole."""

    try:
        data = _receive(route_dump_request(), _ROUTE_SEQUENCE, open_socket)
        return parse_route_dump(data, links)
    except RouteDumpUnreadable:
        return None
