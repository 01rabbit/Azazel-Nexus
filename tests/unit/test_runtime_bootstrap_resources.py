"""Synthetic resource observations exercise bootstrap capacity floors only."""

from dataclasses import fields

import pytest

from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_resources as resources


@pytest.fixture
def thresholds():
    return resources.BootstrapResourceThresholds(1024, 2, 512)


def observation(**measurements):
    values = {
        "usable_memory_mib": 1024,
        "online_logical_cpus": 2,
        "mission_available_mib": 512,
    }
    values.update(measurements)
    return {
        "schema": "azazel-nexus/resource-observation/v1",
        "admission": "not-evaluated",
        "unavailable": [],
        "measurements": values,
    }


@pytest.mark.parametrize("field", [
    "min_usable_memory_mib", "min_online_logical_cpus", "min_mission_available_mib",
])
@pytest.mark.parametrize("value", [0, -1, True, 1.5, "1024", None, 2**63])
def test_thresholds_require_positive_exact_bounded_integers(field, value):
    values = {item.name: 1 for item in fields(resources.BootstrapResourceThresholds)}
    values[field] = value

    with pytest.raises(ApprovalRefused):
        resources.BootstrapResourceThresholds(**values)


def test_values_exactly_at_each_floor_succeed(monkeypatch, thresholds):
    monkeypatch.setattr(resources, "assess_resources", lambda: observation())

    assert resources.require_bootstrap_resources(thresholds) is None


@pytest.mark.parametrize(("field", "value"), [
    ("usable_memory_mib", 1023),
    ("online_logical_cpus", 1),
    ("mission_available_mib", 511),
    ("usable_memory_mib", None),
    ("online_logical_cpus", True),
    ("mission_available_mib", False),
    ("usable_memory_mib", 2**63),
])
def test_insufficient_or_malformed_measurement_refuses(monkeypatch, thresholds, field, value):
    monkeypatch.setattr(resources, "assess_resources", lambda: observation(**{field: value}))

    with pytest.raises(ApprovalRefused):
        resources.require_bootstrap_resources(thresholds)


@pytest.mark.parametrize("missing", [
    "usable_memory_mib", "online_logical_cpus", "mission_available_mib",
])
def test_missing_measurement_refuses(monkeypatch, thresholds, missing):
    result = observation()
    del result["measurements"][missing]
    monkeypatch.setattr(resources, "assess_resources", lambda: result)

    with pytest.raises(ApprovalRefused):
        resources.require_bootstrap_resources(thresholds)


@pytest.mark.parametrize("unavailable", [["memory"], ["cpu", "mission"], ["unknown"]])
def test_unavailable_resource_refuses(monkeypatch, thresholds, unavailable):
    result = observation()
    result["unavailable"] = unavailable
    monkeypatch.setattr(resources, "assess_resources", lambda: result)

    with pytest.raises(ApprovalRefused):
        resources.require_bootstrap_resources(thresholds)


def test_consecutive_calls_take_fresh_observations_without_cached_success(
    monkeypatch, thresholds,
):
    results = [observation(), observation(usable_memory_mib=1023)]
    calls = []

    def assess():
        calls.append(None)
        return results.pop(0)

    monkeypatch.setattr(resources, "assess_resources", assess)
    assert resources.require_bootstrap_resources(thresholds) is None
    with pytest.raises(ApprovalRefused):
        resources.require_bootstrap_resources(thresholds)
    assert len(calls) == 2


def test_assessor_exception_is_redacted(monkeypatch, thresholds):
    def fail():
        raise OSError("private host path and diagnostic detail")

    monkeypatch.setattr(resources, "assess_resources", fail)
    with pytest.raises(ApprovalRefused) as caught:
        resources.require_bootstrap_resources(thresholds)

    assert str(caught.value) == "bootstrap capacity prerequisite refused"
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("invalid", [None, object()])
def test_threshold_object_must_be_exact_type(monkeypatch, invalid):
    monkeypatch.setattr(resources, "assess_resources", lambda: pytest.fail("must not assess"))

    with pytest.raises(ApprovalRefused):
        resources.require_bootstrap_resources(invalid)
