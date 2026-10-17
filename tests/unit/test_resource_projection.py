"""Actual pinned Fabric records, synthetic observations, no admission."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from azazel_nexus import fabric_boundary as boundary
from azazel_nexus_runtime import resource_assessment

pytest.importorskip("azazel_fabric")
from azazel_fabric.provisioning_contracts import HardwareInventory, content_digest
from azazel_fabric.testing.provisioning import golden_hardware_inventory


@pytest.fixture
def inputs(monkeypatch):
    monkeypatch.setattr(resource_assessment, "read_usable_mib", lambda: 16095)
    monkeypatch.setattr(resource_assessment, "_online_cores", lambda: 4)
    monkeypatch.setattr(resource_assessment, "_mission_space", lambda: 10000)
    monkeypatch.setattr(resource_assessment.platform, "machine", lambda: "aarch64")
    return dict(observation=resource_assessment.assess_resources(),
                inventory=HardwareInventory.model_validate(golden_hardware_inventory()),
                profile_id="resource-synthetic")


def test_measured_observations_project_without_capability_or_second_memory_subtraction(inputs):
    profile = boundary.project_resource_profile(**inputs)
    assert profile.usable_memory_mib == 16095
    assert profile.cpu_logical_cores == 4
    assert profile.cpu_architecture == "arm64"
    assert profile.usable_storage_mib == 10000
    assert profile.node_id == inputs["inventory"].node_id
    assert profile.hardware_inventory_digest == inputs["inventory"].inventory_digest
    assert profile.authority == "descriptive_only"
    assert profile.installed_memory_mib is None
    assert profile.measured_core_reserve_mib is None
    assert "storage-is-caller-available-filesystem-space" in profile.limitations
    assert content_digest(profile).startswith("sha256:")


@pytest.mark.parametrize("field", ["usable_memory_mib", "online_logical_cpus", "mission_available_mib"])
@pytest.mark.parametrize("invalid", [None, True, "4", -1])
def test_missing_or_coerced_measurements_refused(inputs, field, invalid):
    inputs["observation"]["measurements"][field] = invalid
    with pytest.raises(boundary.CommissioningRecordUnavailable):
        boundary.project_resource_profile(**inputs)


@pytest.mark.parametrize("change", ["unavailable", "admission", "limitations", "timestamp", "architecture", "extra"])
def test_partial_or_unbounded_observations_refused(inputs, change):
    observation = inputs["observation"]
    if change == "unavailable":
        observation["unavailable"] = ["mission_available_mib"]
    elif change == "admission":
        observation["admission"] = "ready"
    elif change == "limitations":
        observation["limitations"] = []
    elif change == "timestamp":
        observation["observed_at"] = "2026-99-99T00:00:00Z"
    elif change == "architecture":
        observation["architecture"] = None
    else:
        observation["permission"] = "grant"
    with pytest.raises(boundary.CommissioningRecordUnavailable):
        boundary.project_resource_profile(**inputs)


def test_interface_digest_is_not_a_hardware_inventory_digest(inputs):
    inventory = inputs["inventory"]
    forged = inventory.model_copy(update={"inventory_digest": boundary.inventory_digest(inventory.interfaces)})
    with pytest.raises(boundary.CommissioningRecordUnavailable):
        boundary.project_resource_profile(**(inputs | {"inventory": forged}))


def test_modified_hardware_snapshot_cannot_reuse_its_old_digest(inputs):
    forged = inputs["inventory"].model_copy(update={"node_id": "another-node"})
    with pytest.raises(boundary.CommissioningRecordUnavailable):
        boundary.project_resource_profile(**(inputs | {"inventory": forged}))


@pytest.mark.parametrize("value", ["private-unbounded-extension", "gpu-unmeasured"])
def test_unknown_or_duplicate_limitations_are_refused(inputs, value):
    inputs["observation"]["limitations"].append(value)
    with pytest.raises(boundary.CommissioningRecordUnavailable):
        boundary.project_resource_profile(**inputs)


def test_zero_available_space_is_a_measurement_not_missing(inputs):
    inputs["observation"]["measurements"]["mission_available_mib"] = 0
    assert boundary.project_resource_profile(**inputs).usable_storage_mib == 0


def test_input_observations_are_not_modified(inputs):
    before = deepcopy(inputs["observation"])
    boundary.project_resource_profile(**inputs)
    assert inputs["observation"] == before


@pytest.mark.parametrize("fabric", [None, SimpleNamespace(__version__="0.9.0rc5")])
def test_missing_or_wrong_fabric_pin_refused(inputs, monkeypatch, fabric):
    monkeypatch.setattr(boundary, "_import_fabric", lambda: (fabric, "missing or wrong pin"))
    with pytest.raises(boundary.CommissioningRecordUnavailable):
        boundary.project_resource_profile(**inputs)
