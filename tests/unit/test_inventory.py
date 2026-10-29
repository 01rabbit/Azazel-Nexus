"""Read-only inventory, and the identity it is not allowed to invent.

Phase 0b's first row: read-only hardware and interface inventory with composite
identity and fail-closed ambiguity handling (`docs/roadmap.md`,
`docs/commissioning.md` §3).

Two things are under test and they are separable on purpose. The reading is
Nexus-local and works with nothing installed; the *record* and the *matching
rule* are Fabric's, and their tests live in `test_inventory_fabric.py`, which
skips without the optional extra — which the "Fabric extra at the pinned tag"
CI job refuses to let happen there.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from azazel_nexus.inventory import (
    IDENTITY_FIELDS,
    InterfaceReadout,
    no_permanent_mac,
    normalize_permanent_mac,
    read_interfaces,
)

ROOT = Path(__file__).resolve().parents[2]

#: What `/sys/class/net/<name>/address` holds: the address the interface is
#: using *now*. A randomized MAC, a bond, or an attacker changes it. It must
#: never stand in for the permanent one.
CURRENT_MAC = "02:11:22:33:44:55"


def _tree(tmp_path: Path, name: str = "enp4s0") -> Path:
    """A tree whose `device` really is a symlink, as sysfs has it."""

    root = tmp_path / "sys"
    bus = root / "devices" / "pci0000:00" / "0000:04:00.0"
    bus.mkdir(parents=True)
    (bus / "vendor").write_text("0x8086\n")
    (bus / "device").write_text("0x15b7\n")
    (bus / "firmware_version").write_text("0.2-4\n")
    (bus / "label").write_text("LAN1\n")
    driver = root / "bus" / "pci" / "drivers" / "e1000e"
    driver.mkdir(parents=True)

    net = root / "class" / "net"
    interface = net / name
    interface.mkdir(parents=True)
    (interface / "device").symlink_to("../../../devices/pci0000:00/0000:04:00.0")
    (bus / "driver").symlink_to("../../bus/pci/drivers/e1000e")
    # The trap. `address` is the *current* MAC and sits one directory above
    # everything this module reads. A tree without it lets a fallback to it go
    # unnoticed, which is exactly what happened: a mutation substituting it for
    # the permanent MAC passed the whole suite.
    (interface / "address").write_text(CURRENT_MAC + "\n")
    return net


def a_reader(mac: str = "aa:bb:cc:dd:ee:ff"):
    return lambda kernel_name: mac


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------


def test_a_captured_tree_yields_the_composite_identity(tmp_path):
    (readout,) = read_interfaces(_tree(tmp_path), permanent_mac_reader=a_reader())

    assert readout.kernel_name == "enp4s0"
    assert readout.fields["bus_path"] == "devices/pci0000:00/0000:04:00.0"
    assert readout.fields["permanent_mac"] == "aa:bb:cc:dd:ee:ff"
    assert readout.fields["pci_id"] == "0x8086:0x15b7"
    assert readout.fields["physical_label"] == "LAN1"
    assert readout.is_commissionable is True


def test_the_kernel_name_is_recorded_and_is_not_part_of_identity(tmp_path):
    """It moves between boots and driver reloads; matching on it would rebind."""

    (readout,) = read_interfaces(_tree(tmp_path), permanent_mac_reader=a_reader())

    assert readout.kernel_name == "enp4s0"
    assert "kernel_name" not in readout.fields
    assert set(readout.fields) == set(IDENTITY_FIELDS)


def test_the_default_reader_reads_no_permanent_mac_and_says_so(tmp_path):
    """The gap, reported, rather than papered over.

    No sysfs file carries the permanent MAC -- it needs the `ETHTOOL_GPERMADDR`
    ioctl. So the default reads nothing and every interface comes back as
    `COMMISSIONING_REQUIRED`.
    """

    (readout,) = read_interfaces(_tree(tmp_path))

    assert no_permanent_mac("enp4s0") is None
    assert readout.is_commissionable is False
    assert "permanent_mac could not be read" in readout.incomplete_reasons


def test_the_current_mac_is_never_substituted_for_the_permanent_one(tmp_path):
    """The dangerous fallback, refused -- and the test that was missing.

    `/sys/class/net/<name>/address` is sitting right there, it looks like a
    MAC, and reaching for it turns "identity unknown" into "identity
    established". It is the *current* address: a randomized MAC, a bond, or an
    attacker changes it, so an assignment could then be resolved by a cloned
    one. `docs/commissioning.md` §3 rules out MAC-only matching for the same
    reason this rules out the wrong MAC.

    An earlier version of this file did not catch it. The fixture tree had no
    `address` file, so a mutation substituting it produced nothing and the
    whole suite stayed green -- a guard that only works because the trap is
    absent from the fixture is not a guard.
    """

    tree = _tree(tmp_path)
    assert (tree / "enp4s0" / "address").read_text().strip() == CURRENT_MAC

    (readout,) = read_interfaces(tree)

    assert readout.fields["permanent_mac"] is None
    assert CURRENT_MAC not in str(readout.fields.values())
    assert readout.is_commissionable is False


def test_a_real_reader_supplies_the_permanent_mac_and_the_current_one_is_ignored(tmp_path):
    """The positive half: with a real reader, identity comes from the ioctl."""

    (readout,) = read_interfaces(_tree(tmp_path), permanent_mac_reader=a_reader())

    assert readout.fields["permanent_mac"] == "aa:bb:cc:dd:ee:ff"
    assert readout.fields["permanent_mac"] != CURRENT_MAC
    assert readout.is_commissionable is True


def test_a_mac_alone_is_not_an_identity(tmp_path):
    """`docs/commissioning.md` §3: MAC-only matching MUST NOT be accepted."""

    tree = _tree(tmp_path)
    bus = tmp_path / "sys" / "devices" / "pci0000:00" / "0000:04:00.0"
    (bus / "vendor").unlink()
    (bus / "device").unlink()

    (readout,) = read_interfaces(tree, permanent_mac_reader=a_reader())

    assert readout.is_commissionable is False
    assert any("discriminator" in reason for reason in readout.incomplete_reasons)
    assert readout.fields["permanent_mac"] == "aa:bb:cc:dd:ee:ff"


@pytest.mark.parametrize(
    "raw", ["00:00:00:00:00:00", "", None, "not-a-mac", "aa:bb:cc:dd:ee", "AA-BB-CC-DD-EE-FF"]
)
def test_an_absent_or_malformed_permanent_mac_is_not_an_address(raw):
    """All-zero is what a driver reports when it has none to give.

    Accepting it would give every such interface the same identity, which is
    worse than having none: they would all match each other's selectors.
    """

    assert normalize_permanent_mac(raw) is None


def test_an_uppercase_mac_is_normalised_rather_than_refused():
    assert normalize_permanent_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"


def test_a_host_with_no_sysfs_has_nothing_to_commission(tmp_path):
    """A state, not a fault. An exception here would make a container fatal."""

    assert read_interfaces(tmp_path / "absent") == ()


def test_two_reads_of_one_tree_agree(tmp_path):
    tree = _tree(tmp_path)
    for name in ("enp1s0", "wlp2s0"):
        (tree / name).mkdir()

    first = read_interfaces(tree, permanent_mac_reader=a_reader())
    second = read_interfaces(tree, permanent_mac_reader=a_reader())

    assert [r.kernel_name for r in first] == [r.kernel_name for r in second]
    assert [r.kernel_name for r in first] == sorted(r.kernel_name for r in first)


# --------------------------------------------------------------------------
# What this module is not allowed to be
# --------------------------------------------------------------------------


def test_the_inventory_defines_no_record_for_a_shared_identity():
    """`docs/contract-ownership.md` §1: no Nexus-local copy of a Fabric model.

    Azazel-Boot holds an `InterfaceObservation` whose twelve fields are
    name-for-name `InterfaceIdentity`'s, and never imports Fabric. This is what
    stops the same thing growing here: the identity lives in a mapping, and
    `InterfaceReadout` carries only what is genuinely Nexus-local.
    """

    own = set(InterfaceReadout.__dataclass_fields__)

    assert own == {"kernel_name", "fields", "driver_version", "incomplete_reasons"}
    assert own & set(IDENTITY_FIELDS) == set(), (
        f"{sorted(own & set(IDENTITY_FIELDS))} became a field on the Nexus "
        "dataclass; that is the fork this test exists to refuse"
    )


def test_the_inventory_writes_nothing():
    """Read-only, checked against the source rather than promised in prose.

    Every access is a read or a symlink read. A write call here would be a
    change to a machine Nexus has not commissioned an interface on.
    """

    tree = ast.parse(
        (ROOT / "src" / "azazel_nexus" / "inventory.py").read_text(encoding="utf-8")
    )
    forbidden = {
        "write_text", "write_bytes", "mkdir", "touch", "unlink", "rmdir",
        "rename", "replace", "symlink_to", "chmod", "open",
    }
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert called & forbidden == set(), f"inventory.py calls {sorted(called & forbidden)}"


#: A trailing line ending, blank or NUL after a valid value. `$` matches before
#: a final `\n`, so a grammar closed with `$` and used with `match` admitted
#: the first of these (Azazel-Fabric#65). None may survive into an identity.
TRAILING = ("\n", "\r\n", " ", "\x00")


@pytest.mark.parametrize("suffix", TRAILING)
def test_a_permanent_mac_never_keeps_a_trailing_line_ending(suffix: str) -> None:
    """Whitespace is stripped before the grammar; anything else is refused."""

    assert normalize_permanent_mac("aa:bb:cc:dd:ee:ff" + suffix) in (None, "aa:bb:cc:dd:ee:ff")
    assert normalize_permanent_mac("aa:bb:cc:dd:ee:ff\x00") is None
