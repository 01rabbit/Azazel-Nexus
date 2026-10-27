"""A read-only NOC view of this node, with the evidence behind every field.

`docs/noc-observation.md` is the operator page. This module answers "what does
this node's network look like right now" for uplink (the default route),
DNS resolver configuration, DHCP leases, routes, interfaces, and quality and
capacity derived from interface counters. Every field says where it came from,
when it was read on the monotonic and wall clocks, and how fresh it is. A
field that could not be read is `unknown` with a fixed reason code
(`UNKNOWN_REASONS`), never a guess.

## Passive only: what it may open and what it may send

The hard constraint is `docs/commissioning.md` §5: an interface commissioned
to `observation` transmits nothing. The simplest way not to transmit on an
interface is not to transmit on any. So this module:

* opens **one kind of socket**: `AF_NETLINK` / `NETLINK_ROUTE`, in one
  function (`_open_netlink_socket`). An injected socket of any other family
  is refused before anything is sent on it (`socket_not_netlink`).
* sends **three kinds of message**, all to the local kernel and all dump
  requests: `RTM_GETLINK`, `RTM_GETADDR`, `RTM_GETROUTE`
  (`REQUEST_TYPES`). Netlink is a kernel interface; nothing it carries
  leaves the host or is bound to an interface.
* never binds, connects, `sendto`s, `sendmsg`s, resolves a name, pings,
  or starts a process.

What enforces this at run time is the `AF_NETLINK` family check before the
one send and `_request`'s allowlist of the three dump types. The AST scan in
`tests/unit/test_noc_observe.py` is a regression guard over this source, not
a proof: Python can always reach an API by a route a scan does not model.
* reads files: `/sys/class/net/*/statistics/*`, `/sys/class/net/*/speed`,
  `/etc/resolv.conf`, systemd-resolved's upstream file, and DHCP lease
  files. Reading a lease file never talks to a DHCP server. A sysfs read
  can make a driver query its own hardware (an MDIO or USB control
  transfer, for example); that is not a frame on the wire, but it is not
  "touching nothing" either.

**No active check exists here.** Whether a resolver answers, or a gateway
replies to ICMP, is reported as `unknown` with the reason
`active_check_not_performed`. Adding such a check is an owner decision
(`docs/noc-observation.md` §5), including the interface it would use.
Azazel-Edge's `noc_monitor` does send ICMP, DNS, TCP and HTTP probes, which
is why it is not reused here.

## Not an evaluator

`docs/architecture.md` §3.2 puts the NOC Evaluator in Edge's Deterministic
Core. This module reports observations and arithmetic on them (rates,
utilisation); it judges nothing healthy or degraded, drives nothing, and its
output is not an Edge input. An ingestion contract for Edge NOC results needs
owner agreement first.

## What it does not keep

`docs/inventory-confidentiality.md` classes interface names, MAC addresses
and the like as raw identity, which goes to no log, audit or report. The
output therefore carries no interface name, no MAC (the link dump's
`IFLA_ADDRESS` is parsed past, not kept), no IP address, no gateway, no
nameserver and no search domain: interfaces are keyed by kernel ifindex,
and addresses, nameservers and routes are **counted**. Interface names are
used inside one collection to find the interface's sysfs directory and to
match commissioned roles, and every evidence path is written from a template
(`/sys/class/net/{ifname}/...`), never from a real path.

## Roles come from commissioning, never from inference

`docs/commissioning.md` §4: a role is the operator's, resolved by composite
identity. This module does not resolve one and imports nothing that does:
the only resolver in this repository belongs to the G6 exposure tier, which
is deliberately unwired. A caller that holds a verified resolution passes it
as `roles` (kernel name to role, or the resolver's withholding reason, which
stays withheld); without one every interface's role is `unknown`
(`role_evidence_not_provided`). Wiring a resolution in is an owner decision. Fabric's role set has no "uplink" role: the
default route's egress interface is shown as an observation about a route,
not as a role, and nothing here infers a role from it.
"""

from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import os
import re
import secrets
import socket as _socket
import stat
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Optional

__all__ = [
    "FRESH_WITHIN_SECONDS",
    "COLLECTION_FAILED",
    "MAX_INTERVAL_SECONDS",
    "MIN_INTERVAL_SECONDS",
    "WALL_CLOCK_FLOOR_S",
    "REQUEST_TYPES",
    "SCHEMA",
    "UNKNOWN_REASONS",
    "Clock",
    "NetlinkRefused",
    "NetlinkUnavailable",
    "NetlinkMalformed",
    "collect",
    "main",
    "parse_addresses",
    "parse_links",
    "parse_routes",
]

#: Nexus-local operator output. Not a Fabric record and not an Edge input.
SCHEMA = "azazel-nexus/noc-observation-local/v1"

#: A reading older than this, at render time, is `stale`.
FRESH_WITHIN_SECONDS = 10.0

#: The counter interval the command accepts. Every snapshot field is read
#: after the interval, so its age at render does not include it.
MIN_INTERVAL_SECONDS = 0.2
MAX_INTERVAL_SECONDS = 10.0

#: A wall clock earlier than this (2026-10-01T00:00:00Z, before this build)
#: is not trusted for a remaining lease time: a node with no RTC and no NTP
#: yet would report leases as years away from expiry.
WALL_CLOCK_FLOOR_S = 1_790_812_800

#: Every reason a field may be `unknown`, each with a fixed phrase. No value
#: read from the host is ever part of a reason.
UNKNOWN_REASONS: dict[str, str] = {
    "netlink_unavailable": "the netlink dump could not be obtained",
    "netlink_malformed": "the netlink reply was not a whole dump from the kernel",
    "socket_not_netlink": "a socket other than AF_NETLINK was refused",
    "not_reported": "the kernel did not report this attribute",
    "file_absent": "the source file does not exist",
    "read_failed": "the source file could not be read",
    "file_not_regular": "the source is not a regular file",
    "file_unparsable": "the source file could not be parsed",
    "interface_name_unsafe": "the interface name cannot address a sysfs directory",
    "speed_not_reported": "the driver reports no link speed",
    "counters_unavailable": "the two counter reads were not both available",
    "no_lease_file": "no DHCP lease file was found for this interface",
    "role_evidence_not_provided": "no verified commissioning role evidence was supplied",
    "role_withheld": "commissioning role resolution withheld an answer",
    "role_not_in_resolved_set": "the interface holds none of the resolved roles",
    "active_check_not_performed": "answering this needs an active probe, which this build does not send",
    "nexthop_object_not_resolved": "the route uses a nexthop object this reader does not resolve",
    "wall_clock_implausible": "the wall clock is earlier than this build's floor, so a remaining lease time would be wrong",
}

# --- netlink -------------------------------------------------------------

_NETLINK_ROUTE = 0
_RTM_GETLINK = 18
_RTM_GETADDR = 22
_RTM_GETROUTE = 26
#: The only message types this module sends. All are dump requests.
REQUEST_TYPES = frozenset({_RTM_GETLINK, _RTM_GETADDR, _RTM_GETROUTE})
_REQUEST_NAMES = {_RTM_GETLINK: "RTM_GETLINK", _RTM_GETADDR: "RTM_GETADDR",
                  _RTM_GETROUTE: "RTM_GETROUTE"}
#: What each request is answered with. Received, never sent.
_REPLY_FOR = {_RTM_GETLINK: 16, _RTM_GETADDR: 20, _RTM_GETROUTE: 24}
_NLMSG_ERROR = 2
_NLMSG_DONE = 3
_NLM_F_REQUEST = 0x001
_NLM_F_DUMP = 0x300
_NLM_F_DUMP_INTR = 0x010
_KERNEL_ADDRESS = (0, 0)
_RECEIVE_SIZE = 1 << 16
_DUMP_LIMIT = 1 << 22
_TIMEOUT = 5.0
#: The whole dump, however many datagrams, ends within this.
_DUMP_DEADLINE = 10.0

_HEADER = struct.Struct("=IHHII")
_IFINFO = struct.Struct("=BBHiII")
_IFADDR = struct.Struct("=BBBBI")
_RTMSG = struct.Struct("=BBBBBBBBI")
_RTATTR = struct.Struct("=HH")
_RTNH = struct.Struct("=HBBi")

_IFLA_IFNAME = 3
_IFLA_MTU = 4
_IFLA_OPERSTATE = 16
_IFLA_CARRIER = 33
_IFF_UP = 0x1
_IFF_LOOPBACK = 0x8
_IFF_LOWER_UP = 0x10000
#: The kernel's own "unknown" is renamed so it cannot be read as this tool's
#: `unknown` state: the kernel did report it.
_OPERSTATES = {0: "kernel_unknown", 1: "notpresent", 2: "down", 3: "lowerlayerdown",
               4: "testing", 5: "dormant", 6: "up"}

#: Address families as message bodies carry them (not socket families).
_FAMILIES = {2: "ipv4", 10: "ipv6"}
_SCOPES = {0: "global", 200: "site", 253: "link", 254: "host"}

_RTA_OIF = 4
_RTA_GATEWAY = 5
_RTA_MULTIPATH = 9
_RTA_TABLE = 15
_RTA_VIA = 18
_RTA_NH_ID = 30
_RT_TABLE_MAIN = 254
_RTN_UNICAST = 1
_RTM_F_CLONED = 0x200
_RTNH_F_DEAD = 0x1
_RTNH_F_LINKDOWN = 0x10
_ATTRIBUTE_TYPE_MASK = 0x3FFF

try:
    _AF_NETLINK: Optional[int] = _socket.AF_NETLINK
except AttributeError:  # not Linux: no dump is ever attempted
    _AF_NETLINK = None


class NetlinkUnavailable(Exception):
    """The dump could not be obtained."""


class NetlinkMalformed(Exception):
    """The reply is not a whole dump from the kernel for this request."""


class NetlinkRefused(Exception):
    """A socket other than AF_NETLINK was offered. Nothing was sent on it."""


def _request(message_type: int, sequence: int) -> bytes:
    """A dump request of one of `REQUEST_TYPES`, and nothing else."""

    if message_type not in REQUEST_TYPES:
        raise ValueError("only RTM_GETLINK, RTM_GETADDR and RTM_GETROUTE dumps are sent")
    if message_type == _RTM_GETLINK:
        body = _IFINFO.pack(0, 0, 0, 0, 0, 0)
    elif message_type == _RTM_GETADDR:
        body = _IFADDR.pack(0, 0, 0, 0, 0)
    else:
        body = _RTMSG.pack(0, 0, 0, 0, 0, 0, 0, 0, 0)
    return _HEADER.pack(_HEADER.size + len(body), message_type,
                        _NLM_F_REQUEST | _NLM_F_DUMP, sequence, 0) + body


def _messages(data: bytes) -> Iterator[tuple[int, int, int, int, bytes]]:
    offset = 0
    while offset < len(data):
        if offset + _HEADER.size > len(data):
            raise NetlinkMalformed("a message header is cut short")
        length, kind, flags, sequence, port = _HEADER.unpack_from(data, offset)
        if length < _HEADER.size or offset + length > len(data):
            raise NetlinkMalformed("a message declares an impossible length")
        yield kind, flags, sequence, port, data[offset + _HEADER.size: offset + length]
        offset += (length + 3) & ~3


def _attributes(payload: bytes, start: int) -> Iterator[tuple[int, bytes]]:
    offset = start
    while offset < len(payload):
        if offset + _RTATTR.size > len(payload):
            raise NetlinkMalformed("an attribute header is cut short")
        length, kind = _RTATTR.unpack_from(payload, offset)
        if length < _RTATTR.size or offset + length > len(payload):
            raise NetlinkMalformed("an attribute declares an impossible length")
        yield kind & _ATTRIBUTE_TYPE_MASK, payload[offset + _RTATTR.size: offset + length]
        offset += (length + 3) & ~3


def _replies(data: bytes, expected: int, *, sequence: int, port: int) -> list[bytes]:
    """The payloads of `expected` messages, if the dump is whole and ours."""

    payloads: list[bytes] = []
    for kind, flags, message_sequence, message_port, payload in _messages(data):
        if message_sequence != sequence or message_port != port:
            raise NetlinkMalformed("a reply belongs to another request")
        if flags & _NLM_F_DUMP_INTR:
            raise NetlinkMalformed("the dump was interrupted")
        if kind == _NLMSG_DONE:
            if len(payload) >= 4 and struct.unpack_from("=i", payload)[0] != 0:
                raise NetlinkMalformed("the dump ended with an error")
            return payloads
        if kind == _NLMSG_ERROR:
            raise NetlinkMalformed("the kernel answered with an error")
        if kind == expected:
            payloads.append(payload)
    raise NetlinkMalformed("the dump has no end")


def _u32(value: bytes) -> int:
    if len(value) < 4:
        raise NetlinkMalformed("a 32-bit attribute is cut short")
    return struct.unpack_from("=I", value)[0]


def _u8(value: bytes) -> int:
    if len(value) < 1:
        raise NetlinkMalformed("an 8-bit attribute is empty")
    return value[0]


@dataclass(frozen=True)
class _Link:
    index: int
    #: Used to find sysfs and to match roles; never rendered.
    name: Optional[str]
    flags: int
    mtu: Optional[int]
    operstate: Optional[str]
    carrier: Optional[bool]


def parse_links(payloads: list[bytes]) -> list[_Link]:
    """`RTM_NEWLINK` payloads, reduced. The hardware address is not kept."""

    links = []
    for payload in payloads:
        if len(payload) < _IFINFO.size:
            raise NetlinkMalformed("a link message is shorter than its header")
        _family, _pad, _kind, index, flags, _change = _IFINFO.unpack_from(payload)
        name = mtu = operstate = carrier = None
        for kind, value in _attributes(payload, _IFINFO.size):
            if kind == _IFLA_IFNAME:
                name = value.split(b"\x00", 1)[0].decode("utf-8", "replace") or None
            elif kind == _IFLA_MTU:
                mtu = _u32(value)
            elif kind == _IFLA_OPERSTATE:
                operstate = _OPERSTATES.get(_u8(value), "kernel_unrecognised")
            elif kind == _IFLA_CARRIER:
                carrier = bool(_u8(value))
            # IFLA_ADDRESS, IFLA_PERM_ADDRESS and the rest are parsed past.
        links.append(_Link(index, name, flags, mtu, operstate, carrier))
    return links


def parse_addresses(payloads: list[bytes]) -> dict[int, dict[str, dict[str, int]]]:
    """Per ifindex, a count of addresses by family and scope. No address is kept."""

    counts: dict[int, dict[str, dict[str, int]]] = {}
    for payload in payloads:
        if len(payload) < _IFADDR.size:
            raise NetlinkMalformed("an address message is shorter than its header")
        family, _prefix, _flags, scope, index = _IFADDR.unpack_from(payload)
        # Walk the attributes so a malformed message is refused, keep none.
        for _ in _attributes(payload, _IFADDR.size):
            pass
        name = _FAMILIES.get(family)
        if name is None:
            continue
        by_scope = counts.setdefault(index, {}).setdefault(name, {})
        scope_name = _SCOPES.get(scope, "other")
        by_scope[scope_name] = by_scope.get(scope_name, 0) + 1
    return counts


@dataclass(frozen=True)
class _Route:
    family: str
    table: int
    default: bool
    egress: tuple[int, ...]
    via_gateway: bool
    nexthop_object: bool
    #: RTNH_F_LINKDOWN / RTNH_F_DEAD on the route or on any of its nexthops.
    linkdown: bool = False
    dead: bool = False


def _nexthops(value: bytes) -> tuple[list[int], bool, int]:
    indexes, gateway, flags_seen, offset = [], False, 0, 0
    while offset < len(value):
        if offset + _RTNH.size > len(value):
            raise NetlinkMalformed("a nexthop is cut short")
        length, flags, _hops, index = _RTNH.unpack_from(value, offset)
        if length < _RTNH.size or offset + length > len(value):
            raise NetlinkMalformed("a nexthop declares an impossible length")
        indexes.append(index)
        flags_seen |= flags
        nested = value[offset: offset + length]
        for kind, _ in _attributes(nested, _RTNH.size):
            gateway = gateway or kind in (_RTA_GATEWAY, _RTA_VIA)
        offset += (length + 3) & ~3
    return indexes, gateway, flags_seen


def parse_routes(payloads: list[bytes]) -> list[_Route]:
    """IPv4/IPv6 routes of every table, reduced to the table, whether each is
    a default, its egress ifindexes, whether it has a gateway and its
    linkdown/dead flags. No address is kept."""

    routes = []
    for payload in payloads:
        if len(payload) < _RTMSG.size:
            raise NetlinkMalformed("a route message is shorter than its header")
        family, dst_len, _src, _tos, table, _proto, _scope, kind, flags = _RTMSG.unpack_from(payload)
        egress: list[int] = []
        gateway = nexthop_object = False
        nexthop_flags = flags
        for attribute, value in _attributes(payload, _RTMSG.size):
            if attribute == _RTA_TABLE:
                table = _u32(value)
            elif attribute == _RTA_OIF:
                egress.append(_u32(value))
            elif attribute in (_RTA_GATEWAY, _RTA_VIA):
                gateway = True
            elif attribute == _RTA_MULTIPATH:
                hops, hop_gateway, hop_flags = _nexthops(value)
                egress.extend(hops)
                nexthop_flags |= hop_flags
                gateway = gateway or hop_gateway
            elif attribute == _RTA_NH_ID:
                nexthop_object = True
        name = _FAMILIES.get(family)
        if name is None or flags & _RTM_F_CLONED:
            continue
        routes.append(_Route(name, table, dst_len == 0 and kind == _RTN_UNICAST,
                             tuple(sorted(set(egress))), gateway, nexthop_object,
                             bool(nexthop_flags & _RTNH_F_LINKDOWN),
                             bool(nexthop_flags & _RTNH_F_DEAD)))
    return routes


def _open_netlink_socket() -> "_socket.socket":
    """The one socket this module creates: AF_NETLINK, NETLINK_ROUTE."""

    connection = _socket.socket(_socket.AF_NETLINK, _socket.SOCK_RAW, _NETLINK_ROUTE)
    connection.settimeout(_TIMEOUT)
    return connection


def _require_netlink(connection: Any) -> None:
    try:
        family = connection.family
    except AttributeError:
        family = None
    if _AF_NETLINK is None or family != _AF_NETLINK:
        raise NetlinkRefused("only an AF_NETLINK socket is used")


def _sequence() -> int:
    return secrets.randbelow(0xFFFFFFFE) + 1


def _dump(message_type: int, open_socket: Optional[Callable[[], Any]]) -> list[bytes]:
    """One dump of `message_type`, checked as `netlink.py` checks its own."""

    factory = open_socket or _open_netlink_socket
    sequence = _sequence()
    try:
        connection = factory()
    except (OSError, AttributeError) as exc:
        raise NetlinkUnavailable("a netlink socket could not be opened") from exc
    try:
        _require_netlink(connection)
        connection.send(_request(message_type, sequence))
        port = connection.getsockname()[0]
        chunks: list[bytes] = []
        total = 0
        deadline = time.monotonic() + _DUMP_DEADLINE
        while True:
            if time.monotonic() > deadline:
                raise NetlinkUnavailable("the dump did not finish in time")
            chunk, _ancillary, received, sender = connection.recvmsg(_RECEIVE_SIZE)
            if received & _socket.MSG_TRUNC:
                raise NetlinkMalformed("a datagram was cut short")
            if tuple(sender or ()) != _KERNEL_ADDRESS:
                raise NetlinkMalformed("a datagram did not come from the kernel")
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _DUMP_LIMIT:
                raise NetlinkMalformed("the dump is larger than this reader holds")
            if _complete(chunk):
                break
    except OSError as exc:
        raise NetlinkUnavailable("the dump failed") from exc
    finally:
        connection.close()
    return _replies(b"".join(chunks), _REPLY_FOR[message_type], sequence=sequence, port=port)


def _complete(chunk: bytes) -> bool:
    try:
        return any(kind in (_NLMSG_DONE, _NLMSG_ERROR) for kind, *_ in _messages(chunk))
    except NetlinkMalformed:
        return False


# --- evidence ------------------------------------------------------------


@dataclass(frozen=True)
class Clock:
    """Injected so tests decide time; the defaults are the host's clocks."""

    monotonic_ns: Callable[[], int] = time.monotonic_ns
    wall_ns: Callable[[], int] = time.time_ns
    sleep: Callable[[float], None] = time.sleep


@dataclass(frozen=True)
class _Read:
    source: str
    monotonic_ns: int
    wall_ns: int
    extra: dict = field(default_factory=dict)


@dataclass(frozen=True)
class _Field:
    value: Any
    read: _Read
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        if self.reason is not None and self.reason not in UNKNOWN_REASONS:
            raise ValueError("an unknown field must carry a registered reason code")


def _wall_text(wall_ns: int) -> str:
    return datetime.fromtimestamp(wall_ns / 1e9, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ")


def _render(item: Any, now_ns: int) -> Any:
    if isinstance(item, _Field):
        age = max(0.0, (now_ns - item.read.monotonic_ns) / 1e9)
        evidence = {
            "source": item.read.source,
            "read_monotonic_ns": item.read.monotonic_ns,
            "read_wall": _wall_text(item.read.wall_ns),
            "age_s": round(age, 3),
            "freshness": "fresh" if age <= FRESH_WITHIN_SECONDS else "stale",
            **item.read.extra,
        }
        if item.reason is None:
            return {"state": "observed", "value": _render(item.value, now_ns),
                    "evidence": evidence}
        return {"state": "unknown", "value": None, "reason": item.reason,
                "reason_text": UNKNOWN_REASONS[item.reason], "evidence": evidence}
    if isinstance(item, dict):
        return {key: _render(value, now_ns) for key, value in item.items()}
    if isinstance(item, (list, tuple)):
        return [_render(value, now_ns) for value in item]
    return item


# --- files ---------------------------------------------------------------

_NAME = re.compile(r"[A-Za-z0-9_.:@+-]{1,15}")
_COUNTERS = ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
             "rx_errors", "tx_errors", "rx_dropped", "tx_dropped")
_FILE_LIMIT = 1 << 16


def _safe_name(name: Optional[str]) -> bool:
    return bool(name) and _NAME.fullmatch(name) is not None and name not in (".", "..")


def _read_text(path: Path) -> tuple[Optional[str], Optional[str], int]:
    """(text, None, 0) or (None, reason code, errno or 0).

    Opened non-blocking and read only if it is a regular file, so a FIFO or
    device placed at a path cannot stall or feed the collector."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None, "file_absent", errno.ENOENT
    except OSError as exc:
        return None, "read_failed", exc.errno or 0
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return None, "file_not_regular", 0
        data = b""
        while len(data) <= _FILE_LIMIT:
            chunk = os.read(descriptor, _FILE_LIMIT + 1 - len(data))
            if not chunk:
                break
            data += chunk
    except OSError as exc:
        return None, "read_failed", exc.errno or 0
    finally:
        os.close(descriptor)
    if len(data) > _FILE_LIMIT:
        return None, "file_unparsable", 0
    return data.decode("utf-8", "replace"), None, 0


_COUNTER_TEXT = re.compile(r"\d{1,20}")


def _counter_value(text: str) -> Optional[int]:
    """A non-negative decimal of at most 20 digits, or None."""

    text = text.strip()
    return int(text) if _COUNTER_TEXT.fullmatch(text) else None


class _Collector:
    def __init__(self, root: Path, clock: Clock,
                 open_socket: Optional[Callable[[], Any]]) -> None:
        self.root = root
        self.clock = clock
        self.open_socket = open_socket

    def stamp(self, source: str, **extra: Any) -> _Read:
        return _Read(source, self.clock.monotonic_ns(), self.clock.wall_ns(), extra)

    def netlink(self, message_type: int) -> tuple[Optional[list[bytes]], _Read, Optional[str]]:
        read = self.stamp(f"netlink:{_REQUEST_NAMES[message_type]} dump (NETLINK_ROUTE)")
        try:
            return _dump(message_type, self.open_socket), read, None
        except NetlinkRefused:
            return None, read, "socket_not_netlink"
        except NetlinkMalformed:
            return None, read, "netlink_malformed"
        except NetlinkUnavailable:
            return None, read, "netlink_unavailable"

    def counters(self, name: str) -> tuple[Optional[dict[str, int]], _Read, Optional[str]]:
        read = self.stamp("file:/sys/class/net/{ifname}/statistics/{" + ",".join(_COUNTERS) + "}")
        values = {}
        for counter in _COUNTERS:
            text, reason, _ = _read_text(self.root / "sys/class/net" / name / "statistics" / counter)
            if text is None:
                return None, read, reason
            value = _counter_value(text)
            if value is None:
                return None, read, "file_unparsable"
            values[counter] = value
        return values, read, None

    def speed(self, name: str) -> _Field:
        read = self.stamp("file:/sys/class/net/{ifname}/speed")
        text, reason, error = _read_text(self.root / "sys/class/net" / name / "speed")
        if text is None:
            # A down link answers EINVAL: the driver has no speed to report.
            # Any other failure is a failed read, not an absent speed.
            return _Field(None, read, "speed_not_reported" if error == errno.EINVAL else reason)
        text = text.strip()
        if text == "-1":
            return _Field(None, read, "speed_not_reported")
        speed = _counter_value(text)
        if speed is None:
            return _Field(None, read, "file_unparsable")
        if speed == 0:
            return _Field(None, read, "speed_not_reported")
        return _Field(speed, read)


def _quality(first: Optional[dict], first_read: _Read, second: Optional[dict],
             second_read: _Read, speed: _Field) -> _Field:
    read = _Read("derived:delta of two sysfs statistics reads",
                 second_read.monotonic_ns, second_read.wall_ns,
                 {"first_read_monotonic_ns": first_read.monotonic_ns})
    if first is None or second is None:
        return _Field(None, read, "counters_unavailable")
    interval = (second_read.monotonic_ns - first_read.monotonic_ns) / 1e9
    if interval <= 0:
        return _Field(None, read, "counters_unavailable")
    # Each counter on its own: one that went backwards (reset or wrap) has
    # no delta, and the others still do.
    delta: dict[str, Optional[int]] = {
        key: (second[key] - first[key]) if second[key] >= first[key] else None
        for key in _COUNTERS}
    rx_bps = None if delta["rx_bytes"] is None else delta["rx_bytes"] * 8 / interval
    tx_bps = None if delta["tx_bytes"] is None else delta["tx_bytes"] * 8 / interval
    value: dict[str, Any] = {
        "interval_s": round(interval, 3),
        "reset_counters": sorted(key for key in _COUNTERS if delta[key] is None),
        "rx_bps": None if rx_bps is None else round(rx_bps, 1),
        "tx_bps": None if tx_bps is None else round(tx_bps, 1),
        "rx_errors_delta": delta["rx_errors"],
        "tx_errors_delta": delta["tx_errors"],
        "rx_dropped_delta": delta["rx_dropped"],
        "tx_dropped_delta": delta["tx_dropped"],
        # A host counter, shown because an operator will look for it. It is
        # not SO-10 evidence: docs/service-objectives.md requires an
        # independent capture, and DUT counters prove nothing there.
        "tx_packets_delta": delta["tx_packets"],
    }
    if speed.reason is None:
        capacity = speed.value * 1_000_000
        value["rx_utilisation"] = None if rx_bps is None else round(rx_bps / capacity, 6)
        value["tx_utilisation"] = None if tx_bps is None else round(tx_bps / capacity, 6)
    else:
        value["rx_utilisation"] = value["tx_utilisation"] = None
        value["utilisation_unknown_reason"] = speed.reason
    return _Field(value, read)


# --- roles ---------------------------------------------------------------


def _role(link: _Link, roles: Any, read: _Read) -> _Field:
    """The caller's verified resolution, never an inference. A string is a
    withholding reason; it is not shown, only that the answer was withheld."""

    if roles is None:
        return _Field(None, read, "role_evidence_not_provided")
    if isinstance(roles, str) or not isinstance(roles, Mapping):
        return _Field(None, read, "role_withheld")
    role = roles.get(link.name) if link.name else None
    if not isinstance(role, str) or not role:
        return _Field(None, read, "role_not_in_resolved_set")
    return _Field(role, read)


# --- resolver and leases -------------------------------------------------


def _nameserver_counts(text: str) -> dict[str, int]:
    nameservers = loopback = search = 0
    for line in text.splitlines():
        words = line.split("#", 1)[0].split(";", 1)[0].split()
        if not words:
            continue
        if words[0] == "nameserver" and len(words) >= 2:
            nameservers += 1
            try:
                if ipaddress.ip_address(words[1].split("%", 1)[0]).is_loopback:
                    loopback += 1
            except ValueError:
                pass
        elif words[0] in ("search", "domain"):
            search += len(words) - 1
    return {"nameservers": nameservers, "loopback_nameservers": loopback,
            "search_domains": search}


def _dns(collector: _Collector) -> dict:
    path = collector.root / "etc/resolv.conf"
    read = collector.stamp("file:/etc/resolv.conf")
    kind = "regular_file"
    if os.path.islink(path):
        try:
            target = os.readlink(path)
        except OSError:
            target = ""
        if target.endswith("systemd/resolve/stub-resolv.conf"):
            kind = "symlink_systemd_resolved_stub"
        elif target.endswith("systemd/resolve/resolv.conf"):
            kind = "symlink_systemd_resolved_upstream"
        else:
            kind = "symlink_other"
    text, reason, _ = _read_text(path)
    resolv = (_Field(None, read, reason) if text is None
              else _Field({"kind": kind, **_nameserver_counts(text)}, read))

    upstream_read = collector.stamp("file:/run/systemd/resolve/resolv.conf")
    text, reason, _ = _read_text(collector.root / "run/systemd/resolve/resolv.conf")
    upstream = (_Field(None, upstream_read, reason) if text is None
                else _Field({"nameservers": _nameserver_counts(text)["nameservers"]},
                            upstream_read))
    return {
        "resolv_conf": resolv,
        "systemd_resolved_upstream": upstream,
        "resolution": _Field(None, collector.stamp("none:no query is sent"),
                             "active_check_not_performed"),
    }


#: Bounded on purpose: an epoch of thousands of digits is refused by the
#: pattern, not handed to `int()`.
_EXPIRE_EPOCH = re.compile(r"expire\s+epoch\s+(\d{1,12})\s*;")
_EXPIRE_DATE = re.compile(r"expire\s+\d\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s*;")
_EXPIRE_NEVER = re.compile(r"expire\s+never\s*;")
_LEASE_INTERFACE = re.compile(r'interface\s+"([A-Za-z0-9_.:@+-]{1,15})"\s*;')
_LEASE_LIFETIME = re.compile(r"\d{1,10}")
_NEVER = -1


def _lease_expiry(block: str) -> Optional[int]:
    """Wall seconds, `_NEVER`, or None when the block cannot be read."""

    if _EXPIRE_NEVER.search(block):
        return _NEVER
    match = _EXPIRE_EPOCH.search(block)
    if match:
        return int(match.group(1))
    match = _EXPIRE_DATE.search(block)
    if match:
        try:
            return int(datetime.strptime(match.group(1), "%Y/%m/%d %H:%M:%S")
                       .replace(tzinfo=timezone.utc).timestamp())
        except (ValueError, OverflowError):
            return None
    return None


@dataclass
class _DhclientLease:
    read: _Read
    expiry: Optional[int] = None   # the latest; _NEVER beats every date
    unparsable: bool = False


def _dhclient_leases(collector: _Collector) -> dict[str, _DhclientLease]:
    """Kernel name -> the lease with the latest expiry among every lease
    block naming that interface. A block that cannot be read marks only its
    own interface's entry, and only when no readable lease exists for it."""

    found: dict[str, _DhclientLease] = {}
    for directory in ("var/lib/dhcp", "var/lib/dhclient"):
        base = collector.root / directory
        try:
            entries = sorted(entry for entry in os.listdir(base) if entry.endswith(".leases"))
        except OSError:
            continue
        for entry in entries:
            text, _reason, _ = _read_text(base / entry)
            if text is None:
                continue
            read = collector.stamp(f"file:/{directory}/<dhclient lease file>")
            for block in text.split("lease {")[1:]:
                block = block.split("}", 1)[0]
                interface = _LEASE_INTERFACE.search(block)
                if interface is None:
                    continue
                expiry = _lease_expiry(block)
                current = found.setdefault(interface.group(1), _DhclientLease(read))
                if expiry is None:
                    current.unparsable = True
                elif (current.expiry is None
                      or (current.expiry != _NEVER
                          and (expiry == _NEVER or expiry > current.expiry))):
                    current.expiry, current.read = expiry, read
    return found


def _wall_seconds(read: _Read) -> Optional[int]:
    seconds = read.wall_ns // 1_000_000_000
    return seconds if seconds >= WALL_CLOCK_FLOOR_S else None


def _networkd_lease(collector: _Collector, link: _Link) -> Optional[_Field]:
    path = collector.root / "run/systemd/netif/leases" / str(link.index)
    read = collector.stamp("file:/run/systemd/netif/leases/{ifindex}")
    text, reason, _ = _read_text(path)
    if text is None:
        return None if reason == "file_absent" else _Field(None, read, reason)
    values = dict(line.split("=", 1) for line in text.splitlines()
                  if "=" in line and not line.startswith("#"))
    lifetime_text = values.get("LIFETIME", "").strip()
    if _LEASE_LIFETIME.fullmatch(lifetime_text) is None:
        return _Field(None, read, "file_unparsable")
    try:
        mtime = int(os.stat(path).st_mtime)
    except OSError:
        return _Field(None, read, "read_failed")
    now = _wall_seconds(read)
    if now is None:
        return _Field(None, read, "wall_clock_implausible")
    lifetime = int(lifetime_text)
    remaining = mtime + lifetime - now
    return _Field({
        "client": "systemd-networkd",
        "lifetime_s": lifetime,
        "remaining_s": remaining,
        "expired": remaining < 0,
        "remaining_basis": "lease file mtime + LIFETIME, against the wall clock",
    }, read)


def _dhcp(collector: _Collector, link: _Link, dhclient: Mapping[str, _DhclientLease]) -> _Field:
    networkd = _networkd_lease(collector, link)
    if networkd is not None:
        return networkd
    lease = dhclient.get(link.name) if link.name else None
    if lease is not None:
        if lease.expiry is None:
            return _Field(None, lease.read, "file_unparsable")
        if lease.expiry == _NEVER:
            return _Field({"client": "dhclient", "expires_never": True, "remaining_s": None,
                           "expired": False,
                           "remaining_basis": "lease expire line"}, lease.read)
        now = _wall_seconds(lease.read)
        if now is None:
            return _Field(None, lease.read, "wall_clock_implausible")
        remaining = lease.expiry - now
        return _Field({
            "client": "dhclient",
            "expires_never": False,
            "remaining_s": remaining,
            "expired": remaining < 0,
            "remaining_basis": "latest lease expire line, against the wall clock",
        }, lease.read)
    return _Field(None, collector.stamp(
        "file:/run/systemd/netif/leases/{ifindex}, /var/lib/dhcp/*.leases, "
        "/var/lib/dhclient/*.leases"), "no_lease_file")


# --- the collection ------------------------------------------------------


def _defaults_summary(defaults: list[_Route]) -> dict:
    return {
        "default_routes": len(defaults),
        "egress_ifindex": sorted({index for route in defaults for index in route.egress}),
        "via_gateway": any(route.via_gateway for route in defaults),
        "linkdown": any(route.linkdown for route in defaults),
        "dead": any(route.dead for route in defaults),
    }


def _uplink(routes: Optional[list[_Route]], read: _Read, reason: Optional[str]) -> dict:
    """Default routes in the main table and in every other table, kept
    apart. Policy rules are not read, so which default a packet would take is
    not stated: "none in main" does not mean "none at all"."""

    result: dict[str, Any] = {}
    for family in ("ipv4", "ipv6"):
        if routes is None:
            result[family] = _Field(None, read, reason)
            continue
        defaults = [route for route in routes if route.family == family and route.default]
        if any(route.nexthop_object for route in defaults):
            result[family] = _Field(None, read, "nexthop_object_not_resolved")
            continue
        main = [route for route in defaults if route.table == _RT_TABLE_MAIN]
        other = [route for route in defaults if route.table != _RT_TABLE_MAIN]
        result[family] = _Field({
            "table_main": _defaults_summary(main),
            "other_tables": {**_defaults_summary(other),
                             "tables": len({route.table for route in other})},
            "policy_rules_evaluated": False,
        }, read)
    result["reachability"] = _Field(None, _Read("none:no probe is sent", read.monotonic_ns,
                                                read.wall_ns), "active_check_not_performed")
    return result


def _parsed(payloads, reason, parser):
    if payloads is None:
        return None, reason
    try:
        return parser(payloads), reason
    except NetlinkMalformed:
        return None, "netlink_malformed"


def collect(*, root: Path = Path("/"), clock: Clock = Clock(), interval: float = 1.0,
            open_socket: Optional[Callable[[], Any]] = None, roles: Any = None) -> dict:
    """One read-only observation, rendered. `roles` is a verified role
    resolution supplied by the caller (kernel name to role), a withholding
    reason string, or None when no commissioning evidence was supplied.

    Order: a first link dump only to find each interface's counters, the
    first counter read, the interval, and then the whole snapshot. Every
    rendered field is read after the interval, so the interval never makes
    the snapshot stale; the first link dump is not rendered."""

    collector = _Collector(root, clock, open_socket)
    early, _read, early_reason = collector.netlink(_RTM_GETLINK)
    early_links, _ = _parsed(early, early_reason, parse_links)
    first: dict[int, tuple] = {}
    for link in early_links or ():
        if _safe_name(link.name):
            first[link.index] = (link.name, *collector.counters(link.name))
    if first:
        clock.sleep(interval)

    link_payloads, link_read, link_reason = collector.netlink(_RTM_GETLINK)
    address_payloads, address_read, address_reason = collector.netlink(_RTM_GETADDR)
    route_payloads, route_read, route_reason = collector.netlink(_RTM_GETROUTE)
    links, link_reason = _parsed(link_payloads, link_reason, parse_links)
    addresses, address_reason = _parsed(address_payloads, address_reason, parse_addresses)
    routes, route_reason = _parsed(route_payloads, route_reason, parse_routes)

    role_read = collector.stamp("commissioning:caller-supplied verified role resolution"
                                if roles is not None else "commissioning:not supplied")
    dhclient = _dhclient_leases(collector)
    interfaces: Any
    if links is None:
        interfaces = _Field(None, link_read, link_reason)
    else:
        interfaces = []
        for link in sorted(links, key=lambda item: item.index):
            interfaces.append(_interface(collector, link, link_read, addresses, address_read,
                                         address_reason, first, roles, role_read, dhclient))

    if routes is None:
        route_counts: Any = _Field(None, route_read, route_reason)
    else:
        route_counts = _Field({
            where: {family: sum(1 for route in routes if route.family == family
                                and (route.table == _RT_TABLE_MAIN) == (where == "table_main"))
                    for family in ("ipv4", "ipv6")}
            for where in ("table_main", "other_tables")}, route_read)

    observation = {
        "schema": SCHEMA,
        "transmission": {
            "sockets": "AF_NETLINK/NETLINK_ROUTE only",
            "requests": sorted(_REQUEST_NAMES[kind] for kind in REQUEST_TYPES),
            "active_checks": "none",
        },
        "not_evidence_for": [
            "SO-10 zero-transmit (needs an independent capture on the target device)",
            "an Edge NOC evaluation (Edge's Deterministic Core owns that)",
        ],
        "interfaces": interfaces,
        "uplink": _uplink(routes, route_read, route_reason),
        "routes": route_counts,
        "dns": _dns(collector),
    }
    now = clock.monotonic_ns()
    rendered = _render(observation, now)
    rendered["rendered_monotonic_ns"] = now
    rendered["rendered_wall"] = _wall_text(clock.wall_ns())
    return rendered


def _interface(collector: _Collector, link: _Link, link_read: _Read, addresses, address_read,
               address_reason, first, roles, role_read, dhclient) -> dict:
    def known(value: Any) -> _Field:
        return _Field(value, link_read) if value is not None else _Field(None, link_read, "not_reported")

    entry: dict[str, Any] = {
        "ifindex": link.index,
        "role": _role(link, roles, role_read),
        "loopback": known(bool(link.flags & _IFF_LOOPBACK)),
        "admin_up": known(bool(link.flags & _IFF_UP)),
        "lower_up": known(bool(link.flags & _IFF_LOWER_UP)),
        "operstate": known(link.operstate),
        "carrier": known(link.carrier),
        "mtu": known(link.mtu),
    }
    if addresses is None:
        entry["addresses"] = _Field(None, address_read, address_reason)
    else:
        entry["addresses"] = _Field(addresses.get(link.index, {}), address_read)
    if not _safe_name(link.name):
        reason = "interface_name_unsafe" if link.name else "not_reported"
        stamp = collector.stamp("file:/sys/class/net/{ifname}")
        for key in ("speed_mbps", "counters", "quality"):
            entry[key] = _Field(None, stamp, reason)
    else:
        speed = collector.speed(link.name)
        second, second_read, second_reason = collector.counters(link.name)
        # The first read counts only if it was of the same interface: an
        # index that now has another name is another interface's counters.
        first_name, first_values, first_read, _ = first.get(
            link.index, (None, None, second_read, None))
        if first_name != link.name:
            first_values = None
        entry["speed_mbps"] = speed
        entry["counters"] = (_Field(second, second_read) if second is not None
                             else _Field(None, second_read, second_reason))
        entry["quality"] = _quality(first_values, first_read, second, second_read, speed)
    entry["dhcp"] = _dhcp(collector, link, dhclient)
    return entry


#: What the command prints when the collection itself fails: a fixed code,
#: never an exception's text, which could carry host data (a lease line, a
#: path, a name).
COLLECTION_FAILED = "az-nexus-noc: collection_failed\n"


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="az-nexus-noc",
        description="Read-only NOC observation: uplink, DNS, DHCP, routes, interfaces "
                    "and counters, each with its evidence. Sends no packet; opens only "
                    "an AF_NETLINK socket.")
    parser.add_argument("--interval", type=float, default=1.0,
                        help=f"seconds between the two counter reads "
                             f"({MIN_INTERVAL_SECONDS} to {MAX_INTERVAL_SECONDS})")
    arguments = parser.parse_args(argv)
    if not MIN_INTERVAL_SECONDS <= arguments.interval <= MAX_INTERVAL_SECONDS:
        parser.error(f"--interval must be between {MIN_INTERVAL_SECONDS} and "
                     f"{MAX_INTERVAL_SECONDS} seconds")
    try:
        text = json.dumps(collect(interval=arguments.interval), sort_keys=True)
    except Exception:  # noqa: BLE001 - a fixed code, never the exception's text
        sys.stderr.write(COLLECTION_FAILED)
        return 1
    sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
