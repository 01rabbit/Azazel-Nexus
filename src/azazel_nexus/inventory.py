"""Read-only interface inventory: what this host *is*, never what it may do.

Phase 0b's first row. An interface role comes from read-only inventory plus
explicit operator confirmation against a **composite identity**
(`docs/commissioning.md` §3, §4). It never comes from an interface name, its
link state, or the default route -- and nothing in this module could supply one
if it wanted to, because no role appears here at all.

Three properties, each tested rather than asserted:

*Read-only.* Every access opens a file for reading or reads a symlink. Nothing
is written, no process is run, no device is probed into a different state.

*Transmits nothing.* No socket, no name resolution, no networking import. The
package-wide static scan in `tests/unit/test_boundary_static.py` is what holds
this, for this module along with every other.

*Incomplete is never guessed.* An interface whose composite identity cannot be
established comes back with its reasons, and a caller may not commission it.
`docs/commissioning.md` §3 makes zero matches and several matches the same
answer; filling a gap by inference is the failure that rule exists to prevent.

Why there is no record type here
--------------------------------
A composite interface identity is a record that crosses a product boundary, and
`docs/contract-ownership.md` §1 is explicit: Nexus MUST NOT define a local
canonical form for one, and MUST NOT fork a Fabric model into a Nexus-local
copy. `azazel_fabric.provisioning_contracts.InterfaceIdentity` is that record.

So this module reads a **mapping**, not a record. `InterfaceReadout` carries
that mapping plus the one thing that is genuinely Nexus-local -- why an
identity could not be established -- and `azazel_nexus.fabric_boundary` is
where a readout becomes an `InterfaceIdentity`.

That is a deliberate departure from Azazel-Boot, which holds a frozen
`InterfaceObservation` whose twelve fields are name-for-name
`InterfaceIdentity`'s while never importing Fabric. The same shape maintained
in two places drifts, and the series has already paid for it once: Knowledge
and Deception each kept an independent copy of `outcome_contracts`' rules and
both were missing the same two keys Fabric had added. A third copy of this one
is not worth writing.

The kernel name is recorded because an operator sees it on a screen, and is
excluded from identity: it moves between boots and driver reloads. Fabric's
`interface_composite_key` makes the same exclusion.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

__all__ = [
    "DEFAULT_SYSFS_NET",
    "DISCRIMINATOR_FIELDS",
    "IDENTITY_FIELDS",
    "REQUIRED_IDENTITY_FIELDS",
    "InterfaceReadout",
    "no_permanent_mac",
    "normalize_permanent_mac",
    "read_interfaces",
]

#: Where a running Linux exposes its interfaces. Injectable so the parser can
#: be exercised against captured trees without a machine.
DEFAULT_SYSFS_NET = Path("/sys/class/net")

#: The composite identity components, in the order `docs/commissioning.md` §3
#: tabulates them. Deliberately a **local restatement of nothing**: these are
#: the keys this module fills in, and `tests/unit/test_inventory.py` pins them
#: against Fabric's `COMPOSITE_IDENTITY_FIELDS` so the two cannot drift apart
#: unnoticed. A module that imported Fabric to get them would put a second
#: Fabric import site in the CORE path.
IDENTITY_FIELDS = (
    "bus_path",
    "permanent_mac",
    "pci_id",
    "usb_vid_pid",
    "serial",
    "driver",
    "firmware_version",
    "wireless_phy",
    "physical_label",
)

#: An interface must carry both before any role may be confirmed against it.
#: MAC alone is never enough -- a cloned or spoofed MAC must not resolve an
#: assignment (`docs/commissioning.md` §3, last line).
REQUIRED_IDENTITY_FIELDS = ("bus_path", "permanent_mac")

#: And at least one of these, for the same reason.
DISCRIMINATOR_FIELDS = ("pci_id", "usb_vid_pid", "serial")

_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

#: A MAC of all zeroes is what a driver reports when it has **no** permanent
#: address to give. It is an absence, not an address: treating it as one would
#: give every such interface the same identity.
_NULL_MAC = "00:00:00:00:00:00"


@dataclass(frozen=True)
class InterfaceReadout:
    """One interface as read. No role, no judgement, and no record type.

    `fields` is the composite identity as a plain mapping, ready to become an
    `InterfaceIdentity` through `azazel_nexus.fabric_boundary`. It is not a
    record in its own right, on purpose: see this module's docstring.
    """

    #: Recorded because an operator sees it; never part of identity.
    kernel_name: str
    fields: Mapping[str, str | None]
    #: Present only for an operator's screen. Fabric's identity carries the
    #: driver version; nothing matches on it.
    driver_version: str | None = None
    #: Why no role may be confirmed against this identity. Empty when one may.
    incomplete_reasons: tuple[str, ...] = ()

    @property
    def is_commissionable(self) -> bool:
        """True when a role *may* be confirmed against this identity.

        It says the identity is sufficient to be confirmed against. It does not
        say a role was confirmed, and it grants nothing.
        """

        return not self.incomplete_reasons


def _read_text(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    return value or None


def _read_link_name(path: Path) -> str | None:
    """Return the basename a symlink points at, without following into it."""

    try:
        return Path(path.readlink()).name
    except OSError:
        return None


def _bus_path(device_dir: Path) -> str | None:
    """The device's position on its bus, which a physical port keeps.

    `device` is a symlink into the bus tree; its target path *is* the bus
    position. Read relative to the interface directory, so a captured tree
    behaves exactly like a live one.
    """

    try:
        target = device_dir.readlink()
    except OSError:
        return None
    parts = [part for part in Path(target).parts if part not in ("..", "/")]
    return "/".join(parts) or None


def normalize_permanent_mac(raw: str | None) -> str | None:
    """Accept a permanent MAC only in the one form identity may use."""

    if not raw:
        return None
    mac = raw.strip().lower()
    if mac == _NULL_MAC or not _MAC.match(mac):
        return None
    return mac


def no_permanent_mac(kernel_name: str) -> str | None:  # noqa: ARG001
    """The default reader: it reads nothing, and says so.

    The permanent MAC comes from the ``ETHTOOL_GPERMADDR`` ioctl -- what
    ``ethtool -P`` performs. ``/sys/class/net/<name>/address`` is the *current*
    address, which a randomized MAC or a bond changes, so substituting it would
    let a cloned address resolve an assignment. No sysfs file carries the
    permanent one.

    Issuing an ioctl is an operational act against a device, and nothing in
    this package may perform one yet -- no interface has been commissioned.
    So the default reads nothing, every interface comes back incomplete, and
    the answer is `COMMISSIONING_REQUIRED`. That is the correct answer for a
    host whose identity has not actually been read: it is not a gap being
    papered over, it is the gap, reported.

    A component permitted to query drivers injects a real reader, whose result
    passes through :func:`normalize_permanent_mac`.
    """

    return None


def _incomplete_reasons(fields: Mapping[str, str | None]) -> tuple[str, ...]:
    reasons = [
        f"{name} could not be read"
        for name in REQUIRED_IDENTITY_FIELDS
        if not fields.get(name)
    ]
    if not any(fields.get(name) for name in DISCRIMINATOR_FIELDS):
        reasons.append(
            "no discriminator among "
            f"{', '.join(DISCRIMINATOR_FIELDS)}; MAC alone is not an identity"
        )
    return tuple(reasons)


def _observe(
    interface_dir: Path, *, permanent_mac_reader: Callable[[str], str | None]
) -> InterfaceReadout:
    kernel_name = interface_dir.name
    device_dir = interface_dir / "device"

    vendor = _read_text(device_dir / "vendor")
    device = _read_text(device_dir / "device")
    id_vendor = _read_text(device_dir / "idVendor")
    id_product = _read_text(device_dir / "idProduct")

    fields: dict[str, str | None] = {
        "bus_path": _bus_path(device_dir),
        "permanent_mac": normalize_permanent_mac(permanent_mac_reader(kernel_name)),
        "pci_id": f"{vendor}:{device}" if vendor and device else None,
        "usb_vid_pid": f"{id_vendor}:{id_product}" if id_vendor and id_product else None,
        "serial": _read_text(device_dir / "serial"),
        "driver": _read_link_name(device_dir / "driver"),
        "firmware_version": _read_text(device_dir / "firmware_version"),
        "wireless_phy": _read_text(interface_dir / "phy80211" / "name"),
        "physical_label": _read_text(device_dir / "label")
        or _read_text(interface_dir / "phys_port_name"),
    }
    assert set(fields) == set(IDENTITY_FIELDS)  # noqa: S101 - structural, not a check

    return InterfaceReadout(
        kernel_name=kernel_name,
        fields=fields,
        driver_version=_read_text(device_dir / "driver" / "module" / "version"),
        incomplete_reasons=_incomplete_reasons(fields),
    )


def read_interfaces(
    sysfs_net: Path | None = None,
    *,
    permanent_mac_reader: Callable[[str], str | None] = no_permanent_mac,
) -> tuple[InterfaceReadout, ...]:
    """Read every interface the host exposes, in a stable order.

    Sorted by kernel name so two runs over one tree produce the same sequence.
    That is presentation order only -- the kernel name is not identity, and
    nothing downstream may match on it.

    A missing or unreadable `/sys/class/net` yields an empty inventory rather
    than an error: a host that exposes no interfaces is a host with nothing to
    commission, which is a state, not a fault.
    """

    root = DEFAULT_SYSFS_NET if sysfs_net is None else sysfs_net
    try:
        entries = sorted(root.iterdir(), key=lambda p: p.name)
    except OSError:
        return ()
    return tuple(
        _observe(entry, permanent_mac_reader=permanent_mac_reader)
        for entry in entries
        if entry.is_dir()
    )
