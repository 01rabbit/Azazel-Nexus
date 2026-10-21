"""Deception Lite exposure, phase P1 (#196, docs/deception-redirect-prerequisites.md).

P1 shipped the unit profiles, the tier and the boundary, not the bodies.
The bodies came later (§12, §13, §14) and are tested in their own files.
These tests pin what is left of P1:

* the helper and decoy executables take no argument;
* the listener module binds and listens on exactly a catalogued address
  inside the commissioned prefix, and is driven here with a fake socket --
  no real socket is opened;
* the exposure units are addressable only through the fixed unit table, and
  no approval can name them.

Nothing here is VM or hardware evidence (`HG-06` stays open).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from azazel_nexus.decoy import Commissioning, DecoyEntry, DecoyRefused
from azazel_nexus_runtime import decoy_listener, decoy_netd, decoyd

RUNTIME = Path(__file__).resolve().parents[2] / "runtime" / "src" / "azazel_nexus_runtime"
DIGEST = "sha256:" + "a" * 64


def _commissioning(prefix="192.0.2.0/24"):
    return Commissioning(record_digest=DIGEST, generation_digest=DIGEST,
                         bridge_prefix=prefix, actor="operator@console")


def _entry(address="192.0.2.10", port=2222):
    return DecoyEntry(name="ssh-banner", image_digest=DIGEST,
                      listen_address=address, port=port)


class FakeSocket:
    def __init__(self, family, kind, *, fail=None):
        self.family, self.kind, self.fail = family, kind, fail
        self.calls = []

    def bind(self, address):
        self.calls.append(("bind", address))
        if self.fail == "bind":
            raise OSError("address unavailable")

    def listen(self, backlog):
        self.calls.append(("listen", backlog))
        if self.fail == "listen":
            raise OSError("listen refused")

    def close(self):
        self.calls.append(("close",))


@pytest.fixture
def made(monkeypatch):
    sockets = []

    def factory(family, kind):
        sock = FakeSocket(family, kind, fail=getattr(factory, "fail", None))
        sockets.append(sock)
        return sock

    monkeypatch.setattr(decoy_listener, "_SOCKET", factory)
    return factory, sockets


# -- the listener -------------------------------------------------------------


def test_the_listener_binds_and_listens_on_exactly_the_catalogued_address(made):
    import socket

    _, sockets = made
    listener = decoy_listener.open_listener(_entry(), _commissioning())
    assert listener is sockets[0]
    assert (listener.family, listener.kind) == (socket.AF_INET, socket.SOCK_STREAM)
    assert listener.calls == [("bind", ("192.0.2.10", 2222)),
                              ("listen", decoy_listener.BACKLOG)]


def test_an_ipv6_entry_gets_an_ipv6_listener(made):
    import socket

    _, sockets = made
    decoy_listener.open_listener(_entry("2001:db8::10"), _commissioning("2001:db8::/64"))
    assert sockets[0].family == socket.AF_INET6


@pytest.mark.parametrize("entry,prefix", [
    (("198.51.100.10", 2222), "192.0.2.0/24"),
    (("2001:db8::10", 2222), "192.0.2.0/24"),
    (("192.0.2.10", 2222), "2001:db8::/64"),
])
def test_an_address_outside_the_commissioned_prefix_is_refused_before_a_socket(
        made, entry, prefix):
    _, sockets = made
    with pytest.raises(DecoyRefused, match="outside the commissioned bridge prefix"):
        decoy_listener.open_listener(_entry(*entry), _commissioning(prefix))
    assert sockets == []


@pytest.mark.parametrize("which", ["entry-tuple", "entry-mapping", "no-commissioning",
                                   "commissioning-prefix-string"])
def test_a_listener_needs_a_catalogued_entry_and_its_commissioning(made, which):
    _, sockets = made
    entry, commissioning = _entry(), _commissioning()
    if which == "entry-tuple":
        entry = ("192.0.2.10", 2222)
    elif which == "entry-mapping":
        entry = {"listen_address": "192.0.2.10", "port": 2222}
    elif which == "no-commissioning":
        commissioning = None
    else:
        commissioning = "192.0.2.0/24"
    with pytest.raises(DecoyRefused):
        decoy_listener.open_listener(entry, commissioning)
    assert sockets == []


@pytest.mark.parametrize("address,port", [
    ("192.0.2.10", 22), ("192.0.2.10", 1023), ("127.0.0.1", 2222), ("0.0.0.0", 2222),
])
def test_the_library_refuses_a_privileged_port_loopback_and_the_unspecified_address(
        address, port):
    with pytest.raises(DecoyRefused):
        _entry(address, port)


@pytest.mark.parametrize("step", ["bind", "listen"])
def test_a_failed_bind_or_listen_closes_the_socket(made, step):
    factory, sockets = made
    factory.fail = step
    with pytest.raises(OSError):
        decoy_listener.open_listener(_entry(), _commissioning())
    assert sockets[0].calls[-1] == ("close",)


def test_the_listener_module_never_initiates():
    """Read from the source, alongside the boundary test's scan."""

    tree = ast.parse((RUNTIME / "decoy_listener.py").read_text(encoding="utf-8"))
    called = {node.func.attr for node in ast.walk(tree)
              if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
    assert {"bind", "listen"} <= called
    assert not called & {"connect", "connect_ex", "create_connection", "sendto",
                         "sendmsg", "send", "sendall", "accept"}
    # The one socket option (#196 decoy body, §12): SO_REUSEADDR, so that a
    # restart is not refused while a closed connection is in TIME_WAIT.
    options = [[ast.unparse(arg) for arg in node.args] for node in ast.walk(tree)
               if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
               and node.func.attr == "setsockopt"]
    assert options == [["socket.SOL_SOCKET", "socket.SO_REUSEADDR", "1"]]
    imported = {alias.name.split(".")[0] for node in ast.walk(tree)
                if isinstance(node, (ast.Import, ast.ImportFrom))
                for alias in node.names}
    imported |= {node.module.split(".")[0] for node in ast.walk(tree)
                 if isinstance(node, ast.ImportFrom) and node.module}
    assert imported <= {"__future__", "annotations", "ipaddress", "socket", "azazel_nexus",
                        "Commissioning", "DecoyEntry", "DecoyRefused", "MIN_PORT",
                        "decoy_netns", "DecoyNamespace"}


# -- the two executables ------------------------------------------------------


# Both bodies are tested elsewhere: the decoy in test_decoy_body.py (§12),
# the helper in test_decoy_network_body.py (§13).
@pytest.mark.parametrize("module", [decoy_netd, decoyd])
@pytest.mark.parametrize("argv", [["--namespace", "x"], ["/run/netns/other"], ["--force"]])
def test_the_executables_take_no_argument(module, argv, capsys):
    assert module.main(argv) == 2
    assert "takes no argument" in capsys.readouterr().err


def test_the_unit_table_addresses_the_exposure_units_by_fixed_key_only():
    from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey, resolve

    assert resolve("decoy-network") == "azazel-decoy-netd.service"
    assert resolve("decoy-listener") == "azazel-decoyd.service"
    assert UNIT_NAMES[UnitKey.DECOY_NETWORK] == "azazel-decoy-netd.service"
    from azazel_nexus_runtime.units import UnitOperationFailed
    with pytest.raises(UnitOperationFailed):
        resolve("azazel-decoyd.service")


def test_no_approval_can_name_an_exposure_unit():
    from azazel_nexus.activation import DECEPTION_EXPOSURE_UNITS
    from azazel_nexus.activation_approval_v2 import _V2_UNITS

    assert not set(DECEPTION_EXPOSURE_UNITS) & set(_V2_UNITS)


def _hg02(attempts):
    from azazel_nexus.hil_records import _gate

    reasons: list[str] = []
    _gate({"gate_id": "HG-02", "observations": {
        "package_created_accounts": True, "controller_only_unmask": True,
        "account_inventory_ref": "inventory.txt", "unmask_attempts_ref": "attempts.txt",
        "attempts": attempts}}, reasons)
    return [reason for reason in reasons if reason.startswith("observations.attempts")]


def _attempt(unit, account):
    return {"daemon": unit, "account": account, "capture_ref": f"{unit}.txt",
            "unmask_refused": True}


def test_hg02_expects_every_non_root_governed_daemon_and_not_the_root_helper():
    """The runbook never runs as root; a pre-P1 record (no azdecoy) is incomplete.

    Since #196 (a) the namespace unit is a second root unit; like the helper
    it is not an HG-02 subject, and a record with an attempt for either is
    refused (the accounts are matched exactly)."""
    from azazel_nexus.activation import CORE_UNITS

    non_root = [d for d in CORE_UNITS if d.account != "root"]
    assert [d.name for d in CORE_UNITS if d.account == "root"] == [
        "azazel-decoy-nsd.service", "azazel-decoy-netd.service"]
    assert _hg02([_attempt(d.name, d.account) for d in non_root]) == []
    before_p1 = [_attempt(d.name, d.account) for d in non_root if d.account != "azdecoy"]
    assert _hg02(before_p1) != []
    with_root = [_attempt(d.name, d.account) for d in CORE_UNITS]
    assert _hg02(with_root) != []
    for root_unit in ("azazel-decoy-nsd.service", "azazel-decoy-netd.service"):
        extra = [_attempt(d.name, d.account) for d in non_root] + [_attempt(root_unit, "root")]
        assert _hg02(extra) != [], root_unit
