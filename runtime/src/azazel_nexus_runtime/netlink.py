"""Reading a permanent MAC, and nothing else (#38).

`docs/commissioning.md` §3 is unambiguous: a current or cloned MAC must never
resolve a role assignment. The address that may is the **permanent** one, the
value the device carries rather than the one it is presently using.

## Why netlink, and only netlink

Two ways exist to ask Linux for it:

| Route | Privilege | Address family |
| --- | --- | --- |
| `ETHTOOL_GPERMADDR` ioctl | `CAP_NET_ADMIN`, on an `AF_INET` socket | forces the family restriction open |
| `RTM_GETLINK` → `IFLA_PERM_ADDRESS` | none beyond reading | `AF_NETLINK` alone |

The second is the only one implemented, and the absence of the first is a
decision rather than an omission. Adding the ioctl route would mean giving
this daemon `CAP_NET_ADMIN` and an internet address family, to read a value
the kernel already offers without either. **A driver that does not report
`IFLA_PERM_ADDRESS` is refused**, and `HG-04` stays open for it.

## What this module will not do

It builds exactly one kind of message, in one function: `build_dump_request`,
which hardcodes the dump request's type. No name in this module is bound to a
link-write operation, and `tests/unit/test_runtime_netlink.py` checks that by
parsing the source -- by name and by number, since a write under another name
is still a write this module could send. A daemon that could express one is a
daemon whose read-only-ness is a convention.

It also does not keep what it must not read. `docs/commissioning.md` §4
forbids inferring a role from the interface name, the carrier state, the
default route or an autoconfigured address. The dump contains several of
those. `LinkRecord` carries the index, the name (which an operator never
sees, and which nothing matches on) and the permanent address. The rest is
parsed past and dropped.

## Malformed input

A kernel does not emit a truncated attribute on request, and the parser
refuses one anyway. Two different failures, kept apart:

*The buffer is not a netlink dump* — raises. Something is wrong with the
transport, and continuing would mean reporting interfaces that were never
described.

*One interface has no permanent address* — a record with a reason. That is
the normal state of a bridge, a tunnel or a loopback, and it is not an error.

## Who answered (#310)

A reply is read only if the kernel sent it, whole, for this request. Every
datagram must come from the kernel (sender address `(0, 0)`: port id 0, no
multicast group, read with `recvmsg`) and arrive whole (no `MSG_TRUNC`);
every message up to `NLMSG_DONE` must carry this socket's own port id
(`getsockname`) and the request's sequence number, drawn at random for each
dump, and must not be marked interrupted (`NLM_F_DUMP_INTR`). A dump with no
`NLMSG_DONE` is not whole either. Each of these is `NetlinkMalformed`, as a
malformed buffer is: no interface is reported from it. The request is still
the one `RTM_GETLINK` dump, and nothing new is kept.
"""

from __future__ import annotations

import secrets
import socket as _socket
import struct
from dataclasses import dataclass
from typing import Callable, Iterator, Optional

__all__ = [
    "IFLA_IFNAME",
    "IFLA_PERM_ADDRESS",
    "LinkRecord",
    "NetlinkMalformed",
    "NetlinkUnavailable",
    "build_dump_request",
    "parse_links",
    "read_links",
]

_NETLINK_ROUTE = 0

#: The only message type this module ever sends.
RTM_GETLINK = 18

#: What a dump replies with. Received, never sent.
_RTM_NEWLINK = 16
_NLMSG_ERROR = 2
_NLMSG_DONE = 3

_NLM_F_REQUEST = 0x001
_NLM_F_DUMP = 0x300
_NLM_F_DUMP_INTR = 0x010

#: The only sender a reply is accepted from: the kernel's port id, no group.
_KERNEL_ADDRESS = (0, 0)
_RECEIVE_SIZE = 65536

IFLA_IFNAME = 3
IFLA_PERM_ADDRESS = 54

_HEADER = struct.Struct("IHHII")
_IFINFO = struct.Struct("BBHiII")
_RTATTR = struct.Struct("HH")

#: An address of this length, and no other.
_MAC_BYTES = 6

#: All zeroes is what a driver reports when it has no permanent address to
#: give. It is an absence, not an address: treating it as one would give
#: every such interface the same identity.
_NULL_MAC = b"\x00" * _MAC_BYTES


class NetlinkMalformed(Exception):
    """The buffer is not a dump this module can read. Nothing is reported."""


class NetlinkUnavailable(Exception):
    """The dump could not be obtained at all."""


@dataclass(frozen=True)
class LinkRecord:
    """One interface, reduced to what commissioning may know about it.

    `name` is recorded because an operator's inventory lists interfaces in a
    stable order and something has to key them; it is never shown to an
    operator and nothing matches on it (`docs/commissioning.md` §4).
    """

    index: int
    name: Optional[str]
    permanent_mac: Optional[str]
    #: Why `permanent_mac` is `None`. Empty when it is not.
    reason: str = ""

    def __post_init__(self) -> None:
        if (self.permanent_mac is None) == (not self.reason):
            raise NetlinkMalformed(
                f"link {self.index} reports "
                f"permanent_mac={self.permanent_mac!r} with reason={self.reason!r}; "
                "a record either carries an address or says why it does not"
            )


def build_dump_request(sequence: int) -> bytes:
    """The one message this module sends: `RTM_GETLINK`, dump, request."""

    body = _IFINFO.pack(_socket.AF_UNSPEC, 0, 0, 0, 0, 0)
    header = _HEADER.pack(
        _HEADER.size + len(body),
        RTM_GETLINK,
        _NLM_F_REQUEST | _NLM_F_DUMP,
        sequence,
        0,
    )
    return header + body


def _messages(data: bytes) -> Iterator[tuple[int, int, int, int, bytes]]:
    """Walk the buffer, yielding `(type, flags, sequence, port id, payload)`
    and refusing nonsense."""

    offset = 0
    while offset < len(data):
        if offset + _HEADER.size > len(data):
            raise NetlinkMalformed(
                f"a message header starts at {offset} and the buffer ends at "
                f"{len(data)}"
            )
        length, message_type, flags, sequence, port = _HEADER.unpack_from(data, offset)
        if length < _HEADER.size:
            raise NetlinkMalformed(
                f"a message at {offset} declares length {length}, below the "
                f"{_HEADER.size}-byte header it must contain"
            )
        if offset + length > len(data):
            raise NetlinkMalformed(
                f"a message at {offset} declares {length} bytes and the buffer "
                f"holds {len(data) - offset}"
            )
        yield (message_type, flags, sequence, port,
               data[offset + _HEADER.size : offset + length])
        # Netlink messages are aligned to four bytes.
        offset += (length + 3) & ~3


def _attributes(payload: bytes) -> Iterator[tuple[int, bytes]]:
    offset = _IFINFO.size
    while offset < len(payload):
        if offset + _RTATTR.size > len(payload):
            raise NetlinkMalformed(
                f"an attribute header starts at {offset} and the payload ends "
                f"at {len(payload)}"
            )
        length, attribute_type = _RTATTR.unpack_from(payload, offset)
        if length < _RTATTR.size:
            raise NetlinkMalformed(
                f"an attribute at {offset} declares length {length}, below its "
                "own header"
            )
        if offset + length > len(payload):
            raise NetlinkMalformed(
                f"an attribute at {offset} declares {length} bytes and the "
                f"payload holds {len(payload) - offset}"
            )
        yield attribute_type, payload[offset + _RTATTR.size : offset + length]
        offset += (length + 3) & ~3


def parse_links(data: bytes, *, sequence: int, port: int) -> tuple[LinkRecord, ...]:
    """Every interface the dump describes, in the order the kernel sent them.

    Every message up to `NLMSG_DONE` must carry `sequence` (the request's)
    and `port` (this socket's port id) and not be marked interrupted, and
    `NLMSG_DONE` must come; otherwise `NetlinkMalformed`.

    Order is the kernel's and is presentation only. Nothing downstream
    matches on it -- which is why a commissioning request carries the digest
    of a whole enumeration rather than an index into one.
    """

    records: list[LinkRecord] = []
    done = False
    for message_type, flags, message_sequence, message_port, payload in _messages(data):
        if message_sequence != sequence:
            raise NetlinkMalformed("a reply carries another sequence number")
        if message_port != port:
            raise NetlinkMalformed("a reply is addressed to another port id")
        if flags & _NLM_F_DUMP_INTR:
            raise NetlinkMalformed("the dump was interrupted")
        if message_type == _NLMSG_DONE:
            # A dump that ends in an error (the errno `NLMSG_DONE` carries)
            # is not a whole dump.
            if len(payload) >= 4 and struct.unpack_from("i", payload, 0)[0] != 0:
                (errno,) = struct.unpack_from("i", payload, 0)
                raise NetlinkMalformed(f"the dump ended with errno {-errno}")
            done = True
            break
        if message_type == _NLMSG_ERROR:
            (errno,) = struct.unpack_from("i", payload, 0) if payload else (0,)
            if errno:
                raise NetlinkMalformed(f"the kernel answered with errno {-errno}")
            # errno 0 is an acknowledgement, and the request asks for none
            # (no `NLM_F_ACK`): not part of a dump, so not read as one.
            raise NetlinkMalformed("the kernel acknowledged a request that asked for none")
        if message_type != _RTM_NEWLINK:
            continue
        if len(payload) < _IFINFO.size:
            raise NetlinkMalformed(
                f"a link message carries {len(payload)} bytes, below the "
                f"{_IFINFO.size}-byte interface header"
            )
        _family, _pad, _kind, index, _flags, _change = _IFINFO.unpack_from(payload, 0)

        name: Optional[str] = None
        raw_mac: Optional[bytes] = None
        for attribute_type, value in _attributes(payload):
            if attribute_type == IFLA_IFNAME:
                name = value.rstrip(b"\x00").decode("utf-8", "replace") or None
            elif attribute_type == IFLA_PERM_ADDRESS:
                raw_mac = value
            # Every other attribute is parsed past. Several of them are facts
            # commissioning.md 4 forbids inferring a role from, and the way
            # not to infer from a fact is not to keep it.
        records.append(_record(index, name, raw_mac))
    if not done:
        raise NetlinkMalformed("the dump has no end")
    return tuple(records)


def _record(index: int, name: Optional[str], raw_mac: Optional[bytes]) -> LinkRecord:
    if raw_mac is None:
        return LinkRecord(
            index=index,
            name=name,
            permanent_mac=None,
            reason="the driver reports no permanent address for this interface",
        )
    if len(raw_mac) != _MAC_BYTES:
        return LinkRecord(
            index=index,
            name=name,
            permanent_mac=None,
            reason=(
                f"the permanent address is {len(raw_mac)} bytes and an "
                f"ethernet address is {_MAC_BYTES}"
            ),
        )
    if raw_mac == _NULL_MAC:
        return LinkRecord(
            index=index,
            name=name,
            permanent_mac=None,
            reason=(
                "the permanent address is all zeroes, which is what a driver "
                "reports when it has none; it is an absence, not an address"
            ),
        )
    return LinkRecord(
        index=index,
        name=name,
        permanent_mac=":".join(f"{byte:02x}" for byte in raw_mac),
    )


def read_links(
    *,
    open_socket: Optional[Callable[[], "_socket.socket"]] = None,
    limit: int = 1 << 20,
) -> tuple[LinkRecord, ...]:
    """Dump the link table from the kernel.

    The socket factory is injectable so the daemon's callers can be tested
    without one. What cannot be established in CI is that a given driver
    answers with `IFLA_PERM_ADDRESS` -- that is `HG-04`, and it is about
    hardware, not about this function.
    """

    factory = open_socket or _open_route_socket
    sequence = _sequence()
    try:
        connection = factory()
    except OSError as exc:
        raise NetlinkUnavailable(f"a netlink socket could not be opened: {exc}") from exc
    try:
        port = connection.getsockname()[0]
        connection.send(build_dump_request(sequence))
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk, _ancillary, received, sender = connection.recvmsg(_RECEIVE_SIZE)
            if received & _socket.MSG_TRUNC:
                raise NetlinkMalformed("a datagram was cut short")
            if tuple(sender or ()) != _KERNEL_ADDRESS:
                raise NetlinkMalformed("a datagram did not come from the kernel")
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise NetlinkMalformed(
                    f"the dump exceeded {limit} bytes; a link table this large "
                    "is not one this daemon will hold in memory"
                )
            if _dump_is_complete(chunk, sequence, port):
                break
    except OSError as exc:
        raise NetlinkUnavailable(f"the link dump failed: {exc}") from exc
    finally:
        connection.close()
    return parse_links(b"".join(chunks), sequence=sequence, port=port)


def _sequence() -> int:
    """A sequence number for one dump, drawn at random (never 0)."""

    return secrets.randbelow(0xFFFFFFFE) + 1


def _dump_is_complete(chunk: bytes, sequence: int, port: int) -> bool:
    """Stop at `NLMSG_DONE`, or at a message `parse_links` will refuse:
    any `NLMSG_ERROR` (errno 0 included -- no `NLM_F_ACK` is requested, so an
    acknowledgement is unexpected and refused), another sequence or port id,
    an interrupted dump."""

    try:
        return any(
            message_type in (_NLMSG_DONE, _NLMSG_ERROR)
            or message_sequence != sequence or message_port != port
            or flags & _NLM_F_DUMP_INTR
            for message_type, flags, message_sequence, message_port, _ in _messages(chunk)
        )
    except NetlinkMalformed:
        # An incomplete trailing message means more is coming, not that the
        # dump is over.
        return False


def _open_route_socket() -> "_socket.socket":  # pragma: no cover - needs a kernel
    connection = _socket.socket(_socket.AF_NETLINK, _socket.SOCK_RAW, _NETLINK_ROUTE)
    connection.bind((0, 0))
    connection.settimeout(5.0)
    return connection
