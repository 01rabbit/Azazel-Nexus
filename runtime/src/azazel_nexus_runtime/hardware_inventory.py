"""Read-only sysfs observations. Raw results must never be printed or logged.

No /dev access, device probe, mount, network configuration or persistence.
Node identity is deliberately not generated here; the caller must supply its
independently established node binding when projecting a protected record.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from azazel_nexus.inventory import read_interfaces
from azazel_nexus.fabric_boundary import project_hardware_inventory
from azazel_nexus.commissioning import propose


class HardwareUnavailable(Exception):
    """Only a classification; never source paths or hardware identifiers."""


@dataclass(frozen=True, repr=False)
class HardwareObservation:
    collected_at: str
    interfaces: tuple = field(repr=False)
    platform: dict = field(repr=False)
    storage_devices: tuple = field(repr=False)
    limitations: tuple[str, ...]
    excluded_loopbacks: int = 0

    def commissioning_proposal(self):
        """Use exactly this collection scope for subsequent topology review."""
        return propose(self.interfaces)


def _text(path: Path, *, optional=False):
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to("/sys/devices")
        with resolved.open("r", encoding="utf-8") as stream:
            value = stream.read(1025).strip()
    except (OSError, ValueError):
        if optional:
            return None
        raise HardwareUnavailable("required hardware metadata unavailable") from None
    if not value or len(value) > 128 or any(ord(char) < 32 for char in value):
        if optional:
            return None
        raise HardwareUnavailable("invalid hardware metadata")
    return value


def _platform():
    root = Path("/sys/class/dmi/id")
    names = {"vendor": "sys_vendor", "product_name": "product_name",
             "board_serial": "board_serial", "firmware_vendor": "bios_vendor",
             "firmware_version": "bios_version"}
    values = {name: _text(root / source, optional=True) for name, source in names.items()}
    if values["firmware_version"] is not None and len(values["firmware_version"]) > 64:
        values["firmware_version"] = None
    return values


def _storage():
    devices, omitted = [], False
    try:
        paths = sorted(Path("/sys/class/block").iterdir())
        for path in paths:
            resolved = path.resolve(strict=True)
            relative = resolved.relative_to("/sys/devices")
            if relative.parts[0] == "virtual" or (resolved / "partition").exists():
                omitted = True
                continue
            sectors = _text(resolved / "size")
            rotational = _text(resolved / "queue" / "rotational")
            removable = _text(resolved / "removable")
            if (not sectors.isascii() or not sectors.isdecimal()
                    or rotational not in {"0", "1"} or removable not in {"0", "1"}):
                raise HardwareUnavailable("invalid storage metadata")
            size = int(sectors) * 512  # sysfs size is always 512-byte sectors.
            if size <= 0 or len(str(relative)) > 128:
                raise HardwareUnavailable("invalid storage metadata")
            devices.append(dict(bus_path=str(relative), size_bytes=size,
                rotational=rotational == "1", removable=removable == "1",
                model_name=_text(resolved / "device" / "model", optional=True),
                serial=_text(resolved / "device" / "serial", optional=True)))
        if len(devices) > 64:
            raise HardwareUnavailable("hardware inventory exceeds bound")
        return tuple(devices), omitted
    except (OSError, ValueError, UnicodeError):
        raise HardwareUnavailable("storage inventory unavailable") from None


def _is_loopback(name: str) -> bool:
    path = Path("/sys/class/net") / name
    kind = _text(path / "type")
    if not kind.isascii() or not kind.isdecimal():
        raise HardwareUnavailable("network type unavailable")
    if kind != "772":
        return False
    try:
        path.resolve(strict=True).relative_to("/sys/devices/virtual/net")
    except (OSError, ValueError):
        raise HardwareUnavailable("loopback classification inconsistent") from None
    return True


def _interfaces(permanent_mac_reader):
    included, excluded = [], []
    for item in read_interfaces(permanent_mac_reader=permanent_mac_reader, strict_enumeration=True):
        if _is_loopback(item.kernel_name):
            excluded.append(item.kernel_name)
        else:
            included.append(item)
    return tuple(included), tuple(excluded)


def collect_hardware_observations(*, permanent_mac_reader) -> HardwareObservation:
    """Keep even refused NICs for callers to handle; never drop silently."""
    try:
        platform = _platform()
        storage, omitted = _storage()
        interfaces, loopbacks = _interfaces(permanent_mac_reader)
        if (platform != _platform() or (storage, omitted) != _storage()
                or (interfaces, loopbacks) != _interfaces(permanent_mac_reader)):
            raise HardwareUnavailable("hardware changed during collection")
        limitations = ["read-only-snapshot-not-authenticated", "snapshot-not-atomic"]
        if any(value is None for value in platform.values()):
            limitations.append("platform-fields-unavailable")
        if omitted:
            limitations.append("virtual-storage-and-partitions-excluded")
        if loopbacks:
            limitations.append("kernel-loopback-excluded")
        if any(item["serial"] is None or item["model_name"] is None for item in storage):
            limitations.append("storage-optional-identity-unavailable")
        return HardwareObservation(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                   tuple(interfaces), platform, storage, tuple(limitations), len(loopbacks))
    except (OSError, ValueError, UnicodeError):
        raise HardwareUnavailable("hardware inventory unavailable") from None


def collect_hardware_inventory(*, node_id: str, inventory_id: str, permanent_mac_reader):
    """In-memory Fabric snapshot for a caller with independent node binding.

    This function never generates an ID or persists the raw record. A current
    record is not attestation, approval or activation. Callers must refresh any
    cached permanent-address reader before treating it as a current snapshot.
    Refused NICs block the
    complete-record projection rather than disappearing from its interface set.
    """
    observed = collect_hardware_observations(permanent_mac_reader=permanent_mac_reader)
    return project_hardware_inventory(readouts=observed.interfaces, platform=observed.platform,
        storage_devices=observed.storage_devices, limitations=observed.limitations,
        node_id=node_id, inventory_id=inventory_id, collected_at=observed.collected_at)
