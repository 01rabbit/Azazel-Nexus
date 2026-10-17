"""Synthetic sysfs metadata; no physical devices opened."""

import io
import json
from pathlib import Path

import pytest

from azazel_nexus.inventory import InterfaceReadout
from azazel_nexus_runtime import hardware_inventory as hardware, commission_cli


@pytest.fixture
def observations(monkeypatch):
    platform = dict(vendor=None, product_name=None, board_serial=None,
                    firmware_vendor=None, firmware_version=None)
    storage = (dict(bus_path="pci/synthetic", size_bytes=4096, rotational=False,
                    removable=False, model_name=None, serial=None),)
    interfaces = (InterfaceReadout("synthetic", {"permanent_mac": "02:00:00:00:00:01"}),)
    monkeypatch.setattr(hardware, "_platform", lambda: platform)
    monkeypatch.setattr(hardware, "_storage", lambda: (storage, True))
    monkeypatch.setattr(hardware, "read_interfaces", lambda **k: interfaces)
    monkeypatch.setattr(hardware, "_is_loopback", lambda name: False)
    return platform, storage, interfaces


def test_missing_optional_metadata_is_explicit_not_invented(observations):
    result = hardware.collect_hardware_observations(permanent_mac_reader=lambda name: None)
    assert "platform-fields-unavailable" in result.limitations
    assert "virtual-storage-and-partitions-excluded" in result.limitations
    assert "storage-optional-identity-unavailable" in result.limitations
    assert result.interfaces == observations[2]
    assert "permanent_mac" not in repr(result)
    assert "02:00" not in repr(result)


@pytest.mark.parametrize("part", ["platform", "storage", "interfaces"])
def test_changed_hardware_is_refused(observations, monkeypatch, part):
    if part == "platform":
        values = iter((observations[0], dict(vendor="changed")))
        monkeypatch.setattr(hardware, "_platform", lambda: next(values))
    elif part == "storage":
        values = iter(((observations[1], True), ((), False)))
        monkeypatch.setattr(hardware, "_storage", lambda: next(values))
    else:
        values = iter((observations[2], ()))
        monkeypatch.setattr(hardware, "read_interfaces", lambda **k: next(values))
    with pytest.raises(hardware.HardwareUnavailable, match="changed"):
        hardware.collect_hardware_observations(permanent_mac_reader=lambda name: None)


def test_read_error_is_redacted(monkeypatch):
    def fail():
        raise OSError("private-serial")
    monkeypatch.setattr(hardware, "_platform", fail)
    with pytest.raises(hardware.HardwareUnavailable) as error:
        hardware.collect_hardware_observations(permanent_mac_reader=lambda name: None)
    assert "private-serial" not in str(error.value)


@pytest.mark.parametrize("value", ["", "a" * 129, "secret\x00value"])
def test_metadata_bounds(monkeypatch, value):
    monkeypatch.setattr(Path, "resolve", lambda self, **k: Path("/sys/devices/test/value"))
    monkeypatch.setattr(Path, "open", lambda *a, **k: io.StringIO(value))
    with pytest.raises(hardware.HardwareUnavailable):
        hardware._text(Path("/sys/class/test"))
    assert hardware._text(Path("/sys/class/test"), optional=True) is None


def test_metadata_cannot_escape_sysfs(monkeypatch):
    monkeypatch.setattr(Path, "resolve", lambda self, **k: Path("/outside/private"))
    monkeypatch.setattr(Path, "open", lambda *a, **k: pytest.fail("escaped sysfs"))
    with pytest.raises(hardware.HardwareUnavailable):
        hardware._text(Path("/sys/class/test"))


@pytest.mark.parametrize("removable", ["0", "1", "unknown"])
def test_storage_requires_observed_boolean_and_sector_count(monkeypatch, removable):
    monkeypatch.setattr(Path, "iterdir", lambda self: iter((Path("/sys/class/block/example"),)))
    monkeypatch.setattr(Path, "resolve", lambda self, **k: Path("/sys/devices/pci/example"))
    monkeypatch.setattr(Path, "exists", lambda self: False)
    values = {"size": "8", "rotational": "0", "removable": removable}
    monkeypatch.setattr(hardware, "_text", lambda path, **k: values.get(path.name))
    if removable == "unknown":
        with pytest.raises(hardware.HardwareUnavailable):
            hardware._storage()
    else:
        storage, excluded = hardware._storage()
        assert storage[0]["size_bytes"] == 4096
        assert storage[0]["removable"] is (removable == "1")
        assert not excluded


def test_cli_only_emits_counts_and_fixed_limitations(observations, monkeypatch, capsys):
    result = hardware.collect_hardware_observations(permanent_mac_reader=lambda name: None)
    monkeypatch.setattr(commission_cli, "collect_hardware_observations", lambda **k: result)
    monkeypatch.setattr(commission_cli._PermanentAddresses, "unchanged", lambda self: True)
    assert commission_cli.main(["hardware-assess"]) == 0
    text = capsys.readouterr().out
    assert json.loads(text)["interfaces_observed"] == 1
    assert "synthetic" not in text and "02:00" not in text


def test_cli_failure_is_redacted(monkeypatch, capsys):
    def fail(**kwargs):
        raise hardware.HardwareUnavailable("private-identity")
    monkeypatch.setattr(commission_cli, "collect_hardware_observations", fail)
    assert commission_cli.main(["hardware-assess"]) == 1
    output = capsys.readouterr()
    assert not output.out and "private-identity" not in output.err


def test_failed_nic_enumeration_cannot_produce_empty_hardware_snapshot(monkeypatch, tmp_path):
    from azazel_nexus import inventory

    monkeypatch.setattr(inventory, "DEFAULT_SYSFS_NET", tmp_path / "absent")
    monkeypatch.setattr(hardware, "_platform", lambda: {})
    monkeypatch.setattr(hardware, "_storage", lambda: ((), False))
    for _ in range(2):
        with pytest.raises(hardware.HardwareUnavailable):
            hardware.collect_hardware_inventory(node_id="node-test", inventory_id="inventory-test",
                                                permanent_mac_reader=lambda name: None)


def test_strict_nic_enumeration_distinguishes_empty_from_unavailable(tmp_path):
    from azazel_nexus.inventory import read_interfaces

    assert read_interfaces(tmp_path, strict_enumeration=True) == ()
    (tmp_path / "vanished-entry").symlink_to(tmp_path / "missing")
    with pytest.raises(OSError):
        read_interfaces(tmp_path, strict_enumeration=True)


@pytest.mark.parametrize("kind, location, expected", [
    ("772", "/sys/devices/virtual/net/renamed", True),
    ("1", "/sys/devices/virtual/net/lo", False),
    ("1", "/sys/devices/pci/physical", False),
    ("772", "/sys/devices/pci/physical", None),
    ("unknown", "/sys/devices/virtual/net/lo", None),
])
def test_loopback_requires_both_kernel_type_and_location(monkeypatch, kind, location, expected):
    monkeypatch.setattr(hardware, "_text", lambda path: kind)
    monkeypatch.setattr(Path, "resolve", lambda self, **k: Path(location))
    if expected is None:
        with pytest.raises(hardware.HardwareUnavailable):
            hardware._is_loopback("synthetic")
    else:
        assert hardware._is_loopback("synthetic") is expected


def test_exclusion_is_explicit_and_shared_with_proposal(observations, monkeypatch):
    monkeypatch.setattr(hardware, "_is_loopback", lambda name: True)
    result = hardware.collect_hardware_observations(permanent_mac_reader=lambda name: None)
    assert result.interfaces == ()
    assert result.excluded_loopbacks == 1
    assert "kernel-loopback-excluded" in result.limitations
    assert not result.commissioning_proposal().commissionable


def test_loopback_set_changes_cannot_hide_behind_empty_retained_set(observations, monkeypatch):
    batches = iter((((), ("first",)), ((), ("second",))))
    monkeypatch.setattr(hardware, "_interfaces", lambda reader: next(batches))
    with pytest.raises(hardware.HardwareUnavailable, match="changed"):
        hardware.collect_hardware_observations(permanent_mac_reader=lambda name: None)


def test_loopback_exclusion_does_not_hide_incomplete_nonloopback(observations, monkeypatch):
    from dataclasses import replace

    first = observations[2][0]
    second = replace(first, kernel_name="incomplete-nonloopback", incomplete_reasons=("missing identity",))
    monkeypatch.setattr(hardware, "read_interfaces", lambda **kwargs: (first, second))
    monkeypatch.setattr(hardware, "_is_loopback", lambda name: name == first.kernel_name)
    result = hardware.collect_hardware_observations(permanent_mac_reader=lambda name: None)
    assert result.excluded_loopbacks == 1
    assert result.interfaces == (second,)
    assert result.commissioning_proposal().refused
