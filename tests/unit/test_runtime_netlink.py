"""Reading a permanent MAC: the half CI can establish, and the half it cannot (#38).

The split is stated here because blurring it is the failure mode:

| | |
| --- | --- |
| **Parsing** a kernel's `RTM_GETLINK` dump | established here, against a real capture and constructed negatives |
| **A driver answering** with `IFLA_PERM_ADDRESS` | `HG-04`. Not established, not closed, and not touched by anything in this file |

`tests/fixtures/netlink/rtm_getlink_dump.bin` is a real dump from the
container this was developed in. It happens to contain both cases — one
interface with a permanent address and three without — which is what makes it
worth capturing rather than constructing.

It is not evidence about the target hardware. One virtualised NIC answering
is not a rugged PC's NICs answering.
"""

from __future__ import annotations

import ast
import socket
import struct
import sys
from pathlib import Path

import pytest

from azazel_nexus_runtime import netlink
from azazel_nexus_runtime.netlink import (
    IFLA_IFNAME,
    IFLA_PERM_ADDRESS,
    LinkRecord,
    NetlinkMalformed,
    NetlinkUnavailable,
    RTM_GETLINK,
    build_dump_request,
    parse_links,
    read_links,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CAPTURE = REPO_ROOT / "tests" / "fixtures" / "netlink" / "rtm_getlink_dump.bin"
NETLINK_SOURCE = (
    REPO_ROOT / "runtime" / "src" / "azazel_nexus_runtime" / "netlink.py"
)

_HEADER = struct.Struct("IHHII")
_IFINFO = struct.Struct("BBHiII")
_RTM_NEWLINK = 16
_NLMSG_ERROR = 2
_NLMSG_DONE = 3
_NLM_F_MULTI = 0x2
_NLM_F_DUMP_INTR = 0x10

#: The capture's sequence number and port id, as recorded.
CAPTURE_SEQ, CAPTURE_PORT = 1, 18036
#: The sequence number and port id the constructed replies carry.
SEQ, PORT = 1, 4242


def _attribute(kind: int, payload: bytes) -> bytes:
    length = 4 + len(payload)
    return struct.pack("HH", length, kind) + payload + b"\x00" * (-length % 4)


def _link(index: int, *attributes: bytes, name: str = "eth9", seq: int = SEQ,
          port: int = PORT, flags: int = _NLM_F_MULTI) -> bytes:
    body = _IFINFO.pack(0, 0, 1, index, 0, 0)
    body += _attribute(IFLA_IFNAME, name.encode() + b"\x00")
    for attribute in attributes:
        body += attribute
    return _HEADER.pack(_HEADER.size + len(body), _RTM_NEWLINK, flags, seq, port) + body


def _done(seq: int = SEQ, port: int = PORT, flags: int = _NLM_F_MULTI) -> bytes:
    return _HEADER.pack(_HEADER.size + 4, _NLMSG_DONE, flags, seq, port) + b"\x00" * 4


def _parse(data: bytes) -> tuple[LinkRecord, ...]:
    return parse_links(data, sequence=SEQ, port=PORT)


def _parse_capture() -> tuple[LinkRecord, ...]:
    return parse_links(CAPTURE.read_bytes(), sequence=CAPTURE_SEQ, port=CAPTURE_PORT)


# -- the real capture ----------------------------------------------------


def test_the_captured_dump_parses():
    records = _parse_capture()
    assert records, "the capture described no interfaces"
    assert all(isinstance(record, LinkRecord) for record in records)


def test_the_capture_contains_both_answers():
    """One interface reports a permanent address and three do not.

    A fixture where every interface answered would leave the refusal path
    exercised only by constructed input -- and the refusal path is the one
    that decides whether a node can be commissioned at all.
    """

    records = _parse_capture()
    with_address = [r for r in records if r.permanent_mac is not None]
    without = [r for r in records if r.permanent_mac is None]
    assert with_address and without
    assert all(r.reason for r in without)
    assert all(not r.reason for r in with_address)


def test_an_interface_without_a_permanent_address_says_why():
    records = _parse_capture()
    absent = next(r for r in records if r.permanent_mac is None)
    assert "no permanent address" in absent.reason


# -- what may not be built -----------------------------------------------


def test_the_only_message_this_module_sends_is_a_getlink_dump():
    request = build_dump_request(SEQ)
    _length, message_type, flags, _seq, _pid = _HEADER.unpack_from(request, 0)
    assert message_type == RTM_GETLINK
    assert flags & 0x001 and flags & 0x300


#: Link operations that change something. None may be nameable here.
WRITE_OPERATIONS = {"RTM_SETLINK": 19, "RTM_DELLINK": 17, "RTM_NEWADDR": 20}


def test_no_write_operation_is_nameable_in_this_module():
    """Checked by parsing, not by searching the file as text.

    The first version searched for the names and matched its own prose: the
    module's docstring explains which writes it refuses to name, so a text
    scan failed on the explanation and on nothing else. Parsing looks at
    bindings, which is what the claim is actually about.

    The numbers are checked as well as the names, because a write bound to
    another identifier is still a write this module could send.
    """

    tree = ast.parse(NETLINK_SOURCE.read_text(encoding="utf-8"))

    bound: dict[str, object] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bound[target.id] = node.value.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if isinstance(node.value, ast.Constant):
                bound[node.target.id] = node.value.value

    for name in bound:
        assert name not in WRITE_OPERATIONS, f"{name} is a link write operation"
    for name, value in bound.items():
        assert value not in set(WRITE_OPERATIONS.values()), (
            f"{name} = {value} is a link write operation under another name"
        )

    referenced = {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    } | {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert not (referenced & set(WRITE_OPERATIONS)), (
        f"{sorted(referenced & set(WRITE_OPERATIONS))} are referenced here"
    )


def test_the_module_opens_only_a_netlink_socket():
    tree = ast.parse(NETLINK_SOURCE.read_text(encoding="utf-8"))
    families = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr.startswith("AF_")
    }
    assert families <= {"AF_NETLINK", "AF_UNSPEC"}, (
        f"{sorted(families)} includes an address family this daemon has no "
        "reason to hold; adding one would mean loosening "
        "RestrictAddressFamilies to match"
    )


# -- an address, or an absence -------------------------------------------


def test_an_all_zero_permanent_address_is_an_absence_not_an_address():
    """It is what a driver reports when it has none.

    Treating it as an address would give every such interface the same
    identity -- and identity is what a role binds to.
    """

    data = _link(1, _attribute(IFLA_PERM_ADDRESS, b"\x00" * 6)) + _done()
    (record,) = _parse(data)
    assert record.permanent_mac is None
    assert "all zeroes" in record.reason


def test_a_permanent_address_of_the_wrong_length_is_refused():
    for length in (0, 5, 7, 16):
        data = _link(1, _attribute(IFLA_PERM_ADDRESS, b"\x11" * length)) + _done()
        (record,) = _parse(data)
        assert record.permanent_mac is None
        assert "bytes" in record.reason


def test_a_well_formed_address_is_rendered_lowercase_and_colon_separated():
    data = _link(1, _attribute(IFLA_PERM_ADDRESS, bytes.fromhex("AABBCCDDEEFF"))) + _done()
    (record,) = _parse(data)
    assert record.permanent_mac == "aa:bb:cc:dd:ee:ff"


def test_a_record_cannot_carry_both_an_address_and_a_reason():
    with pytest.raises(NetlinkMalformed):
        LinkRecord(index=1, name="eth0", permanent_mac="aa:bb:cc:dd:ee:ff", reason="why")
    with pytest.raises(NetlinkMalformed):
        LinkRecord(index=1, name="eth0", permanent_mac=None, reason="")


def test_unknown_attributes_are_parsed_past():
    """A kernel newer than this code sends attributes it does not know.

    Refusing the message would make a kernel upgrade break commissioning.
    """

    data = (
        _link(
            1,
            _attribute(9999, b"\xde\xad\xbe\xef"),
            _attribute(IFLA_PERM_ADDRESS, bytes.fromhex("122233445566")),
            _attribute(8888, b"x" * 33),
        )
        + _done()
    )
    (record,) = _parse(data)
    assert record.permanent_mac == "12:22:33:44:55:66"


# -- malformed buffers ---------------------------------------------------


def test_a_message_longer_than_the_buffer_is_refused():
    data = bytearray(_link(1) + _done())
    struct.pack_into("I", data, 0, len(data) + 64)
    with pytest.raises(NetlinkMalformed):
        _parse(bytes(data))


def test_a_message_shorter_than_its_own_header_is_refused():
    """Refused *as that*, not as whatever it decays into.

    Without the length check the slice simply comes out empty and the next
    check -- "this payload is too small for an interface header" -- raises
    instead. Both raise `NetlinkMalformed`, so a test asserting only the
    exception type passes either way, which is how this one first did.
    """

    data = bytearray(_link(1) + _done())
    struct.pack_into("I", data, 0, 4)
    with pytest.raises(NetlinkMalformed) as refused:
        _parse(bytes(data))
    assert "below the" in str(refused.value)
    assert "header it must contain" in str(refused.value)


def test_a_truncated_header_is_refused():
    with pytest.raises(NetlinkMalformed):
        _parse(_link(1) + b"\x00\x00\x00")


def test_an_attribute_longer_than_its_message_is_refused():
    link = bytearray(_link(1, _attribute(IFLA_PERM_ADDRESS, b"\x11" * 6)))
    # The attribute sits after IFINFO and the name attribute.
    offset = _HEADER.size + _IFINFO.size
    name_length = struct.unpack_from("H", link, offset)[0]
    attribute_at = offset + ((name_length + 3) & ~3)
    struct.pack_into("H", link, attribute_at, 4096)
    with pytest.raises(NetlinkMalformed):
        _parse(bytes(link) + _done())


def test_an_attribute_shorter_than_its_own_header_is_refused():
    """A four-byte header claiming to be two bytes long.

    Built as the *only* attribute so the outcome is unambiguous. The first
    version overwrote one attribute in a longer list, and without the check
    the parser walked into the next attribute's bytes and raised for a
    different reason -- a pass, but not of the thing being tested.

    A declared length below the header is also what makes the four-byte
    alignment step zero, so the loop would not advance at all.
    """

    body = _IFINFO.pack(0, 0, 1, 1, 0, 0) + struct.pack("HH", 2, IFLA_PERM_ADDRESS)
    data = _HEADER.pack(_HEADER.size + len(body), _RTM_NEWLINK, 0, SEQ, PORT) + body
    with pytest.raises(NetlinkMalformed) as refused:
        _parse(data + _done())
    assert "below its own header" in str(refused.value)


def test_a_link_message_too_small_for_its_interface_header_is_refused():
    body = b"\x00" * 4
    data = _HEADER.pack(_HEADER.size + len(body), _RTM_NEWLINK, 0, SEQ, PORT) + body
    with pytest.raises(NetlinkMalformed):
        _parse(data + _done())


def test_a_kernel_error_is_raised_rather_than_reported_as_no_interfaces():
    """An empty answer and a refused one are different facts.

    Reporting the second as the first would tell an operator this host has no
    interfaces, which is a sentence they would act on.
    """

    body = struct.pack("i", -1) + b"\x00" * 16
    data = _HEADER.pack(_HEADER.size + len(body), 2, 0, SEQ, PORT) + body
    with pytest.raises(NetlinkMalformed) as refused:
        _parse(data)
    assert "errno" in str(refused.value)


def test_messages_after_done_are_not_read():
    data = _link(1, _attribute(IFLA_PERM_ADDRESS, b"\x11" * 6)) + _done() + _link(2)
    records = _parse(data)
    assert [record.index for record in records] == [1]


# -- the framing of a dump (#310) ----------------------------------------


def _ok() -> bytes:
    return _link(1, _attribute(IFLA_PERM_ADDRESS, bytes.fromhex("122233445566")))


def test_a_message_of_another_sequence_is_refused():
    with pytest.raises(NetlinkMalformed, match="sequence"):
        _parse(_link(1, seq=SEQ + 1) + _done())
    with pytest.raises(NetlinkMalformed, match="sequence"):
        _parse(_ok() + _done(seq=SEQ + 1))


def test_a_message_addressed_to_another_port_id_is_refused():
    with pytest.raises(NetlinkMalformed, match="port id"):
        _parse(_link(1, port=PORT + 1) + _done())
    with pytest.raises(NetlinkMalformed, match="port id"):
        _parse(_ok() + _done(port=0))


def test_an_interrupted_dump_is_refused():
    with pytest.raises(NetlinkMalformed, match="interrupted"):
        _parse(_link(1, flags=_NLM_F_MULTI | _NLM_F_DUMP_INTR) + _done())
    with pytest.raises(NetlinkMalformed, match="interrupted"):
        _parse(_ok() + _done(flags=_NLM_F_MULTI | _NLM_F_DUMP_INTR))


def test_a_dump_without_its_end_is_refused():
    with pytest.raises(NetlinkMalformed, match="no end"):
        _parse(_ok())
    with pytest.raises(NetlinkMalformed, match="no end"):
        _parse(b"")


def test_the_whole_dump_of_this_request_is_read():
    """The control for the four above: the same messages, framed right."""

    (record,) = _parse(_ok() + _done())
    assert record.permanent_mac == "12:22:33:44:55:66"


# -- the socket wrapper --------------------------------------------------


class FakeSocket:
    """Replies as given. `sender` is the source address `recvmsg` reports,
    `truncated` the indexes of datagrams reported with `MSG_TRUNC`, `port`
    this socket's port id."""

    def __init__(self, datagrams, *, sender=(0, 0), port=PORT, truncated=(),
                 fail_send=False):
        self.datagrams = list(datagrams)
        self.sender = sender
        self.port = port
        self.truncated = set(truncated)
        self.fail_send = fail_send
        self.sent: list[bytes] = []
        self.received = 0
        self.closed = False

    def getsockname(self):
        return (self.port, 0)

    def send(self, payload):
        if self.fail_send:
            raise OSError("no")
        self.sent.append(payload)
        return len(payload)

    def recvmsg(self, size):
        if not self.datagrams:
            raise TimeoutError("timed out")
        flags = socket.MSG_TRUNC if self.received in self.truncated else 0
        self.received += 1
        return self.datagrams.pop(0)[:size], [], flags, self.sender

    def close(self):
        self.closed = True


@pytest.fixture
def fixed_sequence(monkeypatch):
    monkeypatch.setattr(netlink, "_sequence", lambda: SEQ)


def test_an_unopenable_socket_is_reported_as_unavailable():
    def refuse():
        raise OSError("netlink is not available in this namespace")

    with pytest.raises(NetlinkUnavailable):
        read_links(open_socket=refuse)


def test_a_dump_that_exceeds_the_limit_is_refused(fixed_sequence):
    """A link table this large is not one this daemon holds in memory."""

    fake = FakeSocket([b"\x00" * 2048] * 8)
    with pytest.raises(NetlinkMalformed):
        read_links(open_socket=lambda: fake, limit=4096)
    assert fake.closed


def test_a_dump_delivered_in_pieces_is_reassembled(fixed_sequence):
    fake = FakeSocket([_ok(), _done(), b"never read"])
    records = read_links(open_socket=lambda: fake)
    assert [record.permanent_mac for record in records] == ["12:22:33:44:55:66"]
    assert fake.sent == [build_dump_request(SEQ)] and fake.closed
    assert fake.datagrams == [b"never read"]


def test_each_dump_draws_its_own_sequence_number():
    seen = []
    for _ in range(3):
        fake = FakeSocket([])
        with pytest.raises(NetlinkUnavailable):  # times out
            read_links(open_socket=lambda: fake)
        (request,) = fake.sent
        seen.append(_HEADER.unpack_from(request, 0)[3])
    assert len(set(seen)) == 3 and 0 not in seen


@pytest.mark.parametrize("make", [
    # A datagram from another sender than the kernel: a forged dump.
    lambda: FakeSocket([_ok() + _done()], sender=(31337, 0)),
    lambda: FakeSocket([_ok(), _done()], sender=(1, 0)),
    # From the kernel's port id, but through a multicast group.
    lambda: FakeSocket([_ok() + _done()], sender=(0, 1)),
    lambda: FakeSocket([_ok() + _done()], sender=()),
    lambda: FakeSocket([_ok() + _done()], sender=None),
    # Addressed to another port id than this socket's.
    lambda: FakeSocket([_ok() + _done()], port=PORT + 1),
    # Another sequence number than this request's.
    lambda: FakeSocket([_link(1, seq=SEQ + 1) + _done()]),
    lambda: FakeSocket([_ok(), _done(seq=SEQ + 1)]),
    # Interrupted.
    lambda: FakeSocket([_link(1, flags=_NLM_F_MULTI | _NLM_F_DUMP_INTR), _done()]),
    # Cut short by the receive buffer (`MSG_TRUNC`), even if it parses.
    lambda: FakeSocket([_ok() + _done()], truncated={0}),
    lambda: FakeSocket([_ok(), _done()], truncated={1}),
    # Closed before the dump's end.
    lambda: FakeSocket([_ok(), b""]),
])
def test_a_dump_not_received_whole_from_the_kernel_is_malformed(make, fixed_sequence):
    """Refused as a malformed buffer is: no interface is reported."""

    fake = make()
    with pytest.raises(NetlinkMalformed):
        read_links(open_socket=lambda: fake)
    assert fake.closed


@pytest.mark.parametrize("make", [
    lambda: FakeSocket([_ok()]),                   # times out before the end
    lambda: FakeSocket([], fail_send=True),
])
def test_a_dump_that_cannot_be_obtained_is_unavailable(make, fixed_sequence):
    fake = make()
    with pytest.raises(NetlinkUnavailable):
        read_links(open_socket=lambda: fake)
    assert fake.closed


def test_the_kernels_whole_reply_is_read(fixed_sequence):
    """The control: the same fake, from the kernel, whole, to this port."""

    fake = FakeSocket([_ok() + _done()])
    (record,) = read_links(open_socket=lambda: fake)
    assert record.permanent_mac == "12:22:33:44:55:66"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs a Linux kernel")
def test_the_kernel_answers_this_reader():
    """The real socket: this namespace's links, read through every check."""

    try:
        records = read_links()
    except NetlinkUnavailable as exc:  # pragma: no cover - no netlink here
        pytest.skip(f"no route netlink: {exc}")
    assert records and any(record.name == "lo" for record in records)
