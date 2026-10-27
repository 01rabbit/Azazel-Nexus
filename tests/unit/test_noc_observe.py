"""The read-only NOC observation (`docs/noc-observation.md`).

What each group of tests is evidence for, kept apart on purpose:

| group | kind of evidence |
| --- | --- |
| fixture `/sys`, `/etc`, `/run`, `/var` trees and constructed netlink replies | mock: the parser and the evidence/redaction rules |
| `tests/fixtures/route_dump/full-routes.bin` | a recorded kernel dump (container), parsed |
| AST scan of the module | static: what the source can express |
| patched `socket` around a real collection | in-process, real kernel netlink **of the Linux container** |
| `test_container_evidence_*` | a real process **in the Linux container**; not hardware |

None of it is SO-10 evidence. SO-10 needs an independent capture on the
target device (`docs/service-objectives.md`), and no test here can stand in.
"""

from __future__ import annotations

import ast
import json
import os
import socket
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from azazel_nexus_runtime import noc_observe
from azazel_nexus_runtime.noc_observe import (
    FRESH_WITHIN_SECONDS,
    REQUEST_TYPES,
    UNKNOWN_REASONS,
    Clock,
    collect,
    parse_routes,
)

REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / "runtime" / "src" / "azazel_nexus_runtime" / "noc_observe.py"
ROUTE_DUMP = REPO / "tests" / "fixtures" / "route_dump"

AF_NETLINK = getattr(socket, "AF_NETLINK", 16)
LINUX = sys.platform.startswith("linux") and hasattr(socket, "AF_NETLINK")

_HEADER = struct.Struct("=IHHII")
NLM_F_MULTI = 0x2
PORT = 4242

#: Values that must never appear in any output. Documentation ranges only.
SECRET_NAMES = ("eth9", "wan7")
SECRET_MAC = bytes.fromhex("020000000009")
SECRET_STRINGS = ("eth9", "wan7", "02:00:00:00:00:09", "020000000009",
                  "192.0.2.10", "192.0.2.1", "2001:db8::10", "198.51.100.53",
                  "corp.example", "203.0.113.7")


def _attr(kind: int, payload: bytes) -> bytes:
    length = 4 + len(payload)
    return struct.pack("=HH", length, kind) + payload + b"\0" * (-length % 4)


def _message(kind: int, body: bytes, seq: int, port: int = PORT, flags: int = NLM_F_MULTI) -> bytes:
    return _HEADER.pack(_HEADER.size + len(body), kind, flags, seq, port) + body + b"\0" * (-len(body) % 4)


def _done(seq: int, port: int = PORT) -> bytes:
    return _message(3, b"\0" * 4, seq, port)


def _link(index: int, name: str, flags: int, operstate: int, carrier: int, mtu: int) -> bytes:
    body = struct.pack("=BBHiII", 0, 0, 1, index, flags, 0)
    body += _attr(3, name.encode() + b"\0")          # IFLA_IFNAME
    body += _attr(1, SECRET_MAC)                     # IFLA_ADDRESS: must be dropped
    body += _attr(4, struct.pack("=I", mtu))         # IFLA_MTU
    body += _attr(16, bytes([operstate]))            # IFLA_OPERSTATE
    body += _attr(33, bytes([carrier]))              # IFLA_CARRIER
    return body


def _address(index: int, family: int, scope: int, address: bytes) -> bytes:
    return struct.pack("=BBBBI", family, 24, 0, scope, index) + _attr(1, address) + _attr(2, address)


def _route(family: int, dst_len: int, oif: int, gateway: bytes | None, table: int = 254,
           kind: int = 1) -> bytes:
    body = struct.pack("=BBBBBBBBI", family, dst_len, 0, 0, table, 4, 0, kind, 0)
    body += _attr(15, struct.pack("=I", table)) + _attr(4, struct.pack("=I", oif))
    if gateway is not None:
        body += _attr(5, gateway)
    return body


def _standard_replies() -> dict[int, list[bytes]]:
    """Payloads per reply type: loopback 1, eth9 (2), wan7 (3)."""

    up = 0x1 | 0x10000
    return {
        16: [_link(1, "lo", up | 0x8, 0, 1, 65536),
             _link(2, "eth9", up, 6, 1, 1500),
             _link(3, "wan7", 0x1, 2, 0, 1500)],
        20: [_address(1, 2, 254, bytes([127, 0, 0, 1])),
             _address(2, 2, 0, bytes([192, 0, 2, 10])),
             _address(2, 10, 0, bytes.fromhex("20010db8000000000000000000000010")),
             _address(2, 10, 253, bytes.fromhex("fe800000000000000000000000000010"))],
        24: [_route(2, 0, 2, bytes([192, 0, 2, 1])),
             _route(2, 24, 2, None),
             _route(10, 64, 2, None),
             _route(2, 32, 1, None, table=255, kind=2)],
    }


class FakeNetlink:
    """Answers each dump request with the recorded payloads for its type."""

    family = AF_NETLINK

    def __init__(self, replies, *, sender=(0, 0), port=PORT, seq_shift=0, sent=None):
        self.replies = replies
        self.sender = sender
        self.port = port
        self.seq_shift = seq_shift
        self.queue: list[bytes] = []
        self.sent = sent if sent is not None else []
        self.closed = False

    def send(self, data):
        self.sent.append(data)
        _length, kind, _flags, seq, _port = _HEADER.unpack_from(data)
        reply_kind = {18: 16, 22: 20, 26: 24}[kind]
        seq += self.seq_shift
        body = b"".join(_message(reply_kind, payload, seq, self.port)
                        for payload in self.replies.get(reply_kind, []))
        self.queue = [body + _done(seq, self.port)]
        return len(data)

    def getsockname(self):
        return (self.port, 0)

    def recvmsg(self, size):
        if not self.queue:
            raise TimeoutError("nothing more")
        return self.queue.pop(0), [], 0, self.sender

    def close(self):
        self.closed = True


def _factory(replies=None, **kwargs):
    sent: list[bytes] = []
    replies = replies or _standard_replies()

    def factory():
        return FakeNetlink(replies, sent=sent, **kwargs)

    factory.sent = sent
    return factory


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _counters(root: Path, name: str, **values: int) -> None:
    for counter in noc_observe._COUNTERS:
        _write(root / "sys/class/net" / name / "statistics" / counter,
               f"{values.get(counter, 0)}\n")


@pytest.fixture
def host(tmp_path: Path) -> Path:
    root = tmp_path / "host"
    _counters(root, "lo", rx_bytes=100, tx_bytes=100)
    _counters(root, "eth9", rx_bytes=1_000, tx_bytes=2_000, tx_packets=10)
    _counters(root, "wan7")
    _write(root / "sys/class/net/eth9/speed", "1000\n")
    _write(root / "sys/class/net/wan7/speed", "-1\n")
    _write(root / "run/systemd/resolve/stub-resolv.conf",
           "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch corp.example\n")
    _write(root / "run/systemd/resolve/resolv.conf",
           "nameserver 198.51.100.53\nnameserver 203.0.113.7\n")
    (root / "etc").mkdir(parents=True)
    os.symlink("../run/systemd/resolve/stub-resolv.conf", root / "etc/resolv.conf")
    _write(root / "run/systemd/netif/leases/2",
           "# This is private data. Do not parse.\nADDRESS=192.0.2.10\nROUTER=192.0.2.1\n"
           "LIFETIME=3600\n")
    _write(root / "var/lib/dhcp/dhclient.wan7.leases",
           'lease {\n  interface "wan7";\n  fixed-address 192.0.2.10;\n'
           "  expire epoch 4102444800; # 2100\n}\n")
    return root


class FakeClock:
    """Monotonic and wall in step; the interval sleep advances both and
    changes the counters, as a second read on a live host would see."""

    def __init__(self, on_sleep=None, step_ns=1_000_000, wall_origin_ns=1_800_000_000 * 10**9):
        self.mono = 5_000_000_000
        self.wall_origin = wall_origin_ns - self.mono
        self.step = step_ns
        self.on_sleep = on_sleep
        self.slept: list[float] = []

    def monotonic_ns(self):
        self.mono += self.step
        return self.mono

    def wall_ns(self):
        return self.wall_origin + self.mono

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.mono += int(seconds * 1e9)
        if self.on_sleep:
            self.on_sleep()

    def as_clock(self) -> Clock:
        return Clock(monotonic_ns=self.monotonic_ns, wall_ns=self.wall_ns, sleep=self.sleep)


def _run(host: Path, *, on_sleep=None, factory=None, roles=None, interval=1.0, clock=None):
    clock = clock or FakeClock(on_sleep=on_sleep)
    return collect(root=host, clock=clock.as_clock(), interval=interval,
                   open_socket=factory or _factory(), roles=roles)


def _by_index(result, index):
    return next(entry for entry in result["interfaces"] if entry["ifindex"] == index)


def _second_read(host):
    def change():
        _counters(host, "lo", rx_bytes=100, tx_bytes=100)
        _counters(host, "eth9", rx_bytes=126_000, tx_bytes=2_000, rx_errors=2,
                  rx_dropped=1, tx_packets=10)
        _counters(host, "wan7")
    return change


# --- the observation, field by field ------------------------------------


def test_every_item_carries_its_evidence_and_freshness(host):
    result = _run(host, on_sleep=_second_read(host))

    assert result["schema"] == "azazel-nexus/noc-observation-local/v1"
    assert result["transmission"] == {
        "sockets": "AF_NETLINK/NETLINK_ROUTE only",
        "requests": ["RTM_GETADDR", "RTM_GETLINK", "RTM_GETROUTE"],
        "active_checks": "none",
    }
    eth = _by_index(result, 2)
    for key in ("role", "loopback", "admin_up", "lower_up", "operstate", "carrier", "mtu",
                "addresses", "speed_mbps", "counters", "quality", "dhcp"):
        evidence = eth[key]["evidence"]
        assert evidence["source"], key
        assert isinstance(evidence["read_monotonic_ns"], int), key
        assert evidence["read_wall"].endswith("Z"), key
        assert evidence["freshness"] == "fresh", key
        assert 0 <= evidence["age_s"] <= FRESH_WITHIN_SECONDS, key

    assert eth["operstate"] == {**eth["operstate"], "state": "observed", "value": "up"}
    assert eth["operstate"]["evidence"]["source"] == "netlink:RTM_GETLINK dump (NETLINK_ROUTE)"
    assert eth["carrier"]["value"] is True and eth["mtu"]["value"] == 1500
    assert eth["addresses"]["value"] == {"ipv4": {"global": 1}, "ipv6": {"global": 1, "link": 1}}
    assert eth["addresses"]["evidence"]["source"].startswith("netlink:RTM_GETADDR")
    assert eth["speed_mbps"]["value"] == 1000
    assert eth["speed_mbps"]["evidence"]["source"] == "file:/sys/class/net/{ifname}/speed"
    quality = eth["quality"]["value"]
    assert quality["interval_s"] == pytest.approx(1.0, abs=0.01)
    assert quality["rx_bps"] == pytest.approx(1_000_000, rel=0.01)
    assert quality["rx_utilisation"] == pytest.approx(0.001, rel=0.01)
    assert quality["tx_bps"] == 0 and quality["tx_packets_delta"] == 0
    assert (quality["rx_errors_delta"], quality["rx_dropped_delta"]) == (2, 1)
    assert eth["quality"]["evidence"]["source"] == "derived:delta of two sysfs statistics reads"
    assert eth["quality"]["evidence"]["first_read_monotonic_ns"] < \
        eth["quality"]["evidence"]["read_monotonic_ns"]
    assert eth["dhcp"]["value"]["client"] == "systemd-networkd"
    assert eth["dhcp"]["value"]["lifetime_s"] == 3600
    assert eth["dhcp"]["evidence"]["source"] == "file:/run/systemd/netif/leases/{ifindex}"

    lo = _by_index(result, 1)
    assert lo["loopback"]["value"] is True
    assert lo["operstate"]["value"] == "unknown"   # what the kernel reports for lo

    wan = _by_index(result, 3)
    assert wan["operstate"]["value"] == "down" and wan["carrier"]["value"] is False
    assert wan["speed_mbps"]["state"] == "unknown"
    assert wan["speed_mbps"]["reason"] == "speed_not_reported"
    assert wan["quality"]["value"]["rx_utilisation"] is None
    assert wan["quality"]["value"]["utilisation_unknown_reason"] == "speed_not_reported"
    assert wan["dhcp"]["value"] == {"client": "dhclient", "expires_never": False,
                                    "remaining_s": wan["dhcp"]["value"]["remaining_s"],
                                    "remaining_basis": "lease expire line, against the wall clock"}
    assert wan["dhcp"]["value"]["remaining_s"] > 0
    assert wan["dhcp"]["evidence"]["source"] == "file:/var/lib/dhcp/<dhclient lease file>"

    uplink = result["uplink"]
    assert uplink["ipv4"]["value"] == {"default_route_present": True, "default_routes": 1,
                                       "egress_ifindex": [2], "via_gateway": True}
    assert uplink["ipv6"]["value"]["default_route_present"] is False
    assert uplink["reachability"]["state"] == "unknown"
    assert uplink["reachability"]["reason"] == "active_check_not_performed"
    assert result["routes_main_table"]["value"] == {"ipv4": 2, "ipv6": 1}

    dns = result["dns"]
    assert dns["resolv_conf"]["value"] == {"kind": "symlink_systemd_resolved_stub",
                                           "nameservers": 1, "loopback_nameservers": 1,
                                           "search_domains": 1}
    assert dns["systemd_resolved_upstream"]["value"] == {"nameservers": 2}
    assert dns["resolution"]["reason"] == "active_check_not_performed"


def test_no_name_mac_or_address_reaches_the_output(host):
    """`docs/inventory-confidentiality.md`: raw identity is not printed."""

    text = json.dumps(_run(host, on_sleep=_second_read(host)), sort_keys=True)
    for secret in SECRET_STRINGS:
        assert secret not in text, secret
    assert '"lo"' not in text


def test_the_two_counter_reads_are_separated_by_the_interval(host):
    clock = FakeClock(on_sleep=_second_read(host))
    _run(host, clock=clock, interval=0.5)
    assert clock.slept == [0.5]


def test_a_reading_older_than_the_window_is_stale(host):
    """The interval sleep is stretched past the freshness window: the
    netlink reads, taken before it, render stale; the second counter read,
    taken after it, renders fresh."""

    result = _run(host, interval=FRESH_WITHIN_SECONDS + 5)
    eth = _by_index(result, 2)
    assert eth["operstate"]["evidence"]["freshness"] == "stale"
    assert eth["counters"]["evidence"]["freshness"] == "fresh"


def test_unknown_carries_a_fixed_reason_and_never_a_value(host):
    def failing():
        raise OSError("no netlink here")

    result = _run(host, factory=failing)
    assert result["interfaces"]["state"] == "unknown"
    assert result["interfaces"]["reason"] == "netlink_unavailable"
    assert result["interfaces"]["value"] is None
    assert result["interfaces"]["reason_text"] == UNKNOWN_REASONS["netlink_unavailable"]
    assert result["uplink"]["ipv4"]["reason"] == "netlink_unavailable"
    assert result["routes_main_table"]["reason"] == "netlink_unavailable"
    # The files are still read.
    assert result["dns"]["resolv_conf"]["state"] == "observed"


@pytest.mark.parametrize("kwargs", [{"seq_shift": 1}, {"sender": (99, 0)}])
def test_a_reply_that_is_not_ours_is_malformed(host, kwargs):
    factory = _factory(**kwargs)
    result = _run(host, factory=factory)
    assert result["interfaces"]["reason"] == "netlink_malformed"
    assert result["uplink"]["ipv6"]["reason"] == "netlink_malformed"


def test_a_truncated_attribute_is_malformed_not_partial(host):
    replies = _standard_replies()
    # An attribute that declares 40 bytes where 4 remain.
    replies[16] = [replies[16][0] + struct.pack("=HH", 40, 3)]
    result = _run(host, factory=_factory(replies))
    assert result["interfaces"]["reason"] == "netlink_malformed"


def test_a_non_netlink_socket_is_refused_before_anything_is_sent(host):
    sent: list[bytes] = []

    class Internet(FakeNetlink):
        family = 2  # AF_INET's value

    result = _run(host, factory=lambda: Internet(_standard_replies(), sent=sent))
    assert sent == []
    assert result["interfaces"]["reason"] == "socket_not_netlink"
    assert result["uplink"]["ipv4"]["reason"] == "socket_not_netlink"


def test_only_dump_requests_of_the_three_types_are_sent(host):
    factory = _factory()
    _run(host, factory=factory)
    kinds = sorted(_HEADER.unpack_from(message)[1] for message in factory.sent)
    assert kinds == [18, 22, 26]
    for message in factory.sent:
        assert _HEADER.unpack_from(message)[2] == 0x301  # NLM_F_REQUEST | NLM_F_DUMP
    with pytest.raises(ValueError):
        noc_observe._request(19, 1)  # RTM_SETLINK


def test_a_counter_that_goes_backwards_is_a_reset(host):
    def reset():
        _counters(host, "eth9", rx_bytes=5)

    eth = _by_index(_run(host, on_sleep=reset), 2)
    assert eth["quality"]["state"] == "unknown"
    assert eth["quality"]["reason"] == "counter_reset"


def test_missing_sysfs_files_are_unknown(host):
    (host / "sys/class/net/eth9/statistics/rx_errors").unlink()
    (host / "sys/class/net/eth9/speed").unlink()
    eth = _by_index(_run(host), 2)
    assert eth["counters"]["reason"] == "file_absent"
    assert eth["speed_mbps"]["reason"] == "file_absent"
    assert eth["quality"]["reason"] == "counters_unavailable"


def test_an_unsafe_interface_name_is_never_used_as_a_path(host):
    replies = _standard_replies()
    replies[16].append(_link(9, "../x", 0x1, 6, 1, 1500))
    entry = _by_index(_run(host, factory=_factory(replies)), 9)
    for key in ("speed_mbps", "counters", "quality"):
        assert entry[key]["reason"] == "interface_name_unsafe"


def test_no_lease_file_is_unknown(host):
    (host / "run/systemd/netif/leases/2").unlink()
    eth = _by_index(_run(host), 2)
    assert eth["dhcp"]["state"] == "unknown" and eth["dhcp"]["reason"] == "no_lease_file"


def test_absent_resolver_files_are_unknown(host):
    (host / "etc/resolv.conf").unlink()
    (host / "run/systemd/resolve/resolv.conf").unlink()
    dns = _run(host)["dns"]
    assert dns["resolv_conf"]["reason"] == "file_absent"
    assert dns["systemd_resolved_upstream"]["reason"] == "file_absent"


# --- roles ---------------------------------------------------------------


def test_without_commissioning_evidence_every_role_is_unknown(host):
    for entry in _run(host)["interfaces"]:
        assert entry["role"]["state"] == "unknown"
        assert entry["role"]["reason"] == "role_evidence_not_provided"


def test_roles_come_only_from_the_resolved_commissioning_answer(host):
    result = _run(host, roles={"wan7": "management", "eth9": "observation"})
    assert _by_index(result, 2)["role"]["value"] == "observation"
    assert _by_index(result, 3)["role"]["value"] == "management"
    assert _by_index(result, 1)["role"]["reason"] == "role_not_in_resolved_set"
    assert _by_index(result, 2)["role"]["evidence"]["source"] == \
        "commissioning:caller-supplied verified role resolution"
    # A default route on an interface does not make it anything.
    assert result["uplink"]["ipv4"]["value"]["egress_ifindex"] == [2]
    assert "uplink" not in json.dumps([e["role"] for e in result["interfaces"]])


def test_a_withheld_resolution_stays_withheld(host):
    withheld = "role_inventory_changed: this boot's inventory is not the commissioned inventory"
    for entry in _run(host, roles=withheld)["interfaces"]:
        assert entry["role"]["reason"] == "role_withheld"
        assert "inventory" not in json.dumps(entry["role"]["value"])


def test_every_reason_is_registered_and_a_field_refuses_another():
    with pytest.raises(ValueError):
        noc_observe._Field(None, noc_observe._Read("x", 0, 0), "made_up")
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    used = {node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and node.value in UNKNOWN_REASONS}
    assert used == set(UNKNOWN_REASONS)


# --- a recorded kernel dump ------------------------------------------------


def test_a_recorded_kernel_route_dump_parses():
    """`full-routes.bin` is a real `RTM_GETROUTE` dump recorded in a
    container namespace (its README). Every main-table route `ip -j` printed
    is counted, exactly one is a default, and it has a gateway."""

    data = (ROUTE_DUMP / "full-routes.bin").read_bytes()
    payloads = noc_observe._replies(data, 24, sequence=2, port=450)
    routes = parse_routes(payloads)
    printed = json.loads((ROUTE_DUMP / "full-ip-routes.json").read_text())
    assert len([r for r in routes if r.family == "ipv4"]) == len(printed)
    defaults = [r for r in routes if r.default]
    assert len(defaults) == 1 and defaults[0].via_gateway
    assert any(r.nexthop_object for r in routes)


# --- structural: what the source can express ------------------------------

ALLOWED_IMPORTS = {"__future__", "argparse", "ipaddress", "json", "os", "re", "secrets",
                   "socket", "struct", "sys", "time", "dataclasses", "datetime", "pathlib",
                   "typing"}
FORBIDDEN_ATTRIBUTES = {
    "connect", "connect_ex", "sendto", "sendmsg", "sendall", "sendfile", "bind", "listen",
    "accept", "create_connection", "create_server", "getaddrinfo", "gethostbyname",
    "gethostbyname_ex", "gethostbyaddr", "getnameinfo", "setsockopt", "socketpair",
    "fromfd", "AF_INET", "AF_INET6", "AF_PACKET", "SOCK_DGRAM", "SOCK_STREAM",
    "system", "popen", "spawnl", "spawnv", "posix_spawn", "posix_spawnp", "execv",
    "execve", "execvp", "fork", "Popen", "run", "check_output", "urlopen",
}


def _tree():
    return ast.parse(SOURCE.read_text(encoding="utf-8"))


def test_the_module_imports_no_network_sending_or_process_api():
    imported = set()
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "no relative import"
            imported.add(node.module.split(".")[0])
            assert all(alias.name != "*" for alias in node.names)
    assert imported <= ALLOWED_IMPORTS, imported - ALLOWED_IMPORTS
    for banned in ("subprocess", "urllib", "http", "ssl", "asyncio", "ctypes", "selectors",
                   "shutil", "multiprocessing", "azazel_nexus"):
        assert banned not in imported


def test_the_module_names_no_send_connect_bind_resolve_or_spawn():
    found = {node.attr for node in ast.walk(_tree())
             if isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_ATTRIBUTES}
    names = {node.id for node in ast.walk(_tree())
             if isinstance(node, ast.Name) and node.id in FORBIDDEN_ATTRIBUTES | {"exec", "eval",
                                                                                  "__import__"}}
    assert found == set() and names == set()
    for word in ("ping", "dig", "nslookup", "arping", "dhclient -", "resolvectl query"):
        for node in ast.walk(_tree()):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert not node.value.startswith(word + " "), node.value


def _enclosing_functions(tree):
    for function in ast.walk(tree):
        if isinstance(function, ast.FunctionDef):
            for node in ast.walk(function):
                yield function.name, node


def test_send_happens_once_in_the_netlink_dump_and_nowhere_else():
    sends = [name for name, node in _enclosing_functions(_tree())
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
             and node.func.attr == "send"]
    assert sends == ["_dump"]
    # And what it sends is built by `_request`, which admits only the three dumps.
    dump = next(f for f in ast.walk(_tree()) if isinstance(f, ast.FunctionDef) and f.name == "_dump")
    call = next(node for node in ast.walk(dump) if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute) and node.func.attr == "send")
    assert isinstance(call.args[0], ast.Call) and call.args[0].func.id == "_request"
    assert REQUEST_TYPES == {18, 22, 26}


def test_the_only_socket_constructed_is_af_netlink_in_one_function():
    constructions = [(name, node) for name, node in _enclosing_functions(_tree())
                     if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                     and node.func.attr in {"socket", "SocketType"}]
    assert [name for name, _ in constructions] == ["_open_netlink_socket"]
    family = constructions[0][1].args[0]
    assert isinstance(family, ast.Attribute) and family.attr == "AF_NETLINK"
    # The injected-socket path is checked before the send.
    dump = next(f for f in ast.walk(_tree()) if isinstance(f, ast.FunctionDef) and f.name == "_dump")
    calls = [node.func.id if isinstance(node.func, ast.Name) else node.func.attr
             for node in ast.walk(dump) if isinstance(node, ast.Call)]
    assert calls.index("_require_netlink") < calls.index("send")


# --- runtime: a real collection with socket patched -----------------------


@pytest.mark.skipif(not LINUX, reason="AF_NETLINK is Linux-only")
def test_a_real_collection_creates_only_netlink_sockets(monkeypatch):
    """In-process, against this Linux container's kernel. Any non-netlink
    socket, any connect/bind/sendto/sendmsg, any name lookup and any process
    start fails the test."""

    created: list[int] = []
    real = socket.socket

    class Guarded(real):
        def __init__(self, family=-1, type=-1, proto=-1, fileno=None):
            created.append(family)
            assert family == socket.AF_NETLINK, f"non-netlink socket family {family}"
            super().__init__(family, type, proto, fileno)

        def _refuse(self, *args, **kwargs):
            raise AssertionError("a forbidden socket operation was called")

        connect = connect_ex = bind = sendto = sendmsg = sendall = listen = _refuse

    def refuse(*args, **kwargs):
        raise AssertionError("a forbidden API was called")

    monkeypatch.setattr(socket, "socket", Guarded)
    for name in ("create_connection", "getaddrinfo", "gethostbyname", "socketpair"):
        monkeypatch.setattr(socket, name, refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(os, "system", refuse)
    monkeypatch.setattr(os, "posix_spawn", refuse)

    result = collect(interval=0.2)
    assert created and set(created) == {socket.AF_NETLINK}
    assert len(created) == 3
    assert isinstance(result["interfaces"], list)


@pytest.mark.real_process
@pytest.mark.skipif(not LINUX, reason="AF_NETLINK is Linux-only")
def test_container_evidence_the_cli_reads_this_containers_netlink_state():
    """CONTAINER EVIDENCE, NOT HARDWARE. Runs `az-nexus-noc`'s entry point in
    a real process in the Linux test container, with `socket` patched in that
    process to refuse any non-netlink family, and checks it read the
    container's own interfaces and routes. Says nothing about a target
    device's NICs, and nothing about SO-10."""

    guard = (
        "import socket, sys\n"
        "real = socket.socket\n"
        "class G(real):\n"
        "    def __init__(self, family=-1, *a, **k):\n"
        "        if family != socket.AF_NETLINK:\n"
        "            sys.stderr.write('NON-NETLINK SOCKET\\n'); raise SystemExit(70)\n"
        "        super().__init__(family, *a, **k)\n"
        "socket.socket = G\n"
        "from azazel_nexus_runtime.noc_observe import main\n"
        "raise SystemExit(main(['--interval', '0.2']))\n"
    )
    completed = subprocess.run([sys.executable, "-c", guard], capture_output=True,
                               text=True, timeout=60, check=False)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    interfaces = result["interfaces"]
    assert isinstance(interfaces, list) and interfaces
    loopback = [entry for entry in interfaces if entry["loopback"]["value"] is True]
    assert len(loopback) == 1
    assert loopback[0]["counters"]["state"] == "observed"
    assert loopback[0]["role"]["reason"] == "role_evidence_not_provided"
    assert result["uplink"]["ipv4"]["state"] == "observed"
    assert result["routes_main_table"]["state"] == "observed"
    for entry in interfaces:
        assert entry["operstate"]["evidence"]["source"].startswith("netlink:RTM_GETLINK")


def test_the_cli_bounds_the_interval(capsys):
    for value in ("0", "11"):
        with pytest.raises(SystemExit) as exited:
            noc_observe.main(["--interval", value])
        assert exited.value.code == 2


def test_the_cli_is_an_operator_tool_without_a_unit():
    manifest = (REPO / "runtime" / "pyproject.toml").read_text(encoding="utf-8")
    assert 'az-nexus-noc = "azazel_nexus_runtime.noc_observe:main"' in manifest
    units = REPO / "packaging"
    assert not [path for path in units.rglob("*noc*") if path.is_file()]


def test_nothing_imports_the_collector():
    """An operator command, wired into no daemon: a daemon importing it would
    need its own review of the netlink grant (test_runtime_hardening)."""

    importers = []
    for root in (REPO / "src", REPO / "runtime" / "src"):
        for path in root.rglob("*.py"):
            if path == SOURCE:
                continue
            if "noc_observe" in path.read_text(encoding="utf-8"):
                importers.append(path.name)
    assert importers == []

