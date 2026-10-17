"""Collected metadata into pinned Fabric, never an authenticated node."""

from dataclasses import replace

import pytest

from azazel_nexus import fabric_boundary as boundary
from azazel_nexus.inventory import InterfaceReadout
from azazel_nexus_runtime import hardware_inventory as hardware

pytest.importorskip("azazel_fabric")
from azazel_fabric.provisioning_contracts import assert_content_digest


@pytest.fixture
def args():
    readout = InterfaceReadout("synthetic0", dict(bus_path="pci/synthetic",
        permanent_mac="02:00:00:00:00:01", pci_id="8086:15b8", driver="synthetic"))
    return dict(readouts=(readout,), platform=dict(vendor=None, product_name=None,
        board_serial=None, firmware_vendor=None, firmware_version=None),
        storage_devices=(dict(bus_path="pci/storage", size_bytes=4096,
            removable=False, rotational=False, model_name=None, serial=None),),
        limitations=("read-only-snapshot-not-authenticated", "snapshot-not-atomic",
                     "platform-fields-unavailable", "storage-optional-identity-unavailable"),
        node_id="node-synthetic", inventory_id="inventory-synthetic", collected_at="2026-10-13T00:00:00Z")


def test_collected_metadata_becomes_digest_consistent_descriptive_record(args):
    inventory = boundary.project_hardware_inventory(**args)
    assert_content_digest(inventory, digest_field="inventory_digest")
    assert inventory.node_id == args["node_id"]
    assert inventory.authority == "descriptive_only"
    assert inventory.platform.board_serial is None
    assert inventory.storage_devices[0].size_bytes == 4096


@pytest.mark.parametrize("change", ["duplicate-storage", "duplicate-interface", "refused-interface",
                                    "bool-size", "unknown-removable", "unknown-limitation", "missing-limitation"])
def test_incomplete_or_coerced_snapshot_refused(args, change):
    if change == "duplicate-storage":
        args["storage_devices"] *= 2
    elif change == "duplicate-interface":
        args["readouts"] *= 2
    elif change == "refused-interface":
        args["readouts"] = (replace(args["readouts"][0], incomplete_reasons=("unavailable",)),)
    elif change == "bool-size":
        args["storage_devices"][0]["size_bytes"] = True
    elif change == "unknown-removable":
        args["storage_devices"][0]["removable"] = None
    elif change == "unknown-limitation":
        args["limitations"] += ("private-text",)
    else:
        args["limitations"] = ()
    with pytest.raises(boundary.CommissioningRecordUnavailable):
        boundary.project_hardware_inventory(**args)


def test_runtime_collection_connects_to_fabric_projection(args, monkeypatch):
    observation = hardware.HardwareObservation(args["collected_at"], args["readouts"],
        args["platform"], args["storage_devices"], args["limitations"])
    monkeypatch.setattr(hardware, "collect_hardware_observations", lambda **k: observation)
    inventory = hardware.collect_hardware_inventory(node_id=args["node_id"],
        inventory_id=args["inventory_id"], permanent_mac_reader=lambda name: None)
    assert_content_digest(inventory, digest_field="inventory_digest")
    assert inventory.inventory_id == "inventory-synthetic"


@pytest.mark.parametrize("omitted", ["platform-fields-unavailable", "storage-optional-identity-unavailable"])
def test_applicable_omission_cannot_be_hidden(args, omitted):
    args["limitations"] = tuple(item for item in args["limitations"] if item != omitted)
    with pytest.raises(boundary.CommissioningRecordUnavailable):
        boundary.project_hardware_inventory(**args)
