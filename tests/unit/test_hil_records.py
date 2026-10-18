"""Fixtures exercise refusals only; software runs never become HIL evidence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from azazel_nexus.core_reserve import REQUIRED_SUBSYSTEMS, RESERVE_SCHEMA
from azazel_nexus.hil_records import (
    BEHAVIOUR_SCHEMA,
    BEHAVIOURS,
    CAMPAIGN_SCHEMA,
    DRILL_SCHEMA,
    DRILLS,
    GATE_SCHEMA,
    GATES,
    SCHEMAS,
    Status,
    Validation,
    validate_record,
)

REPOSITORY = Path(__file__).resolve().parents[2]


def fixture_record(schema=GATE_SCHEMA):
    """Always labelled fixture/synthetic; never upgraded to measured in tests."""
    return {
        "schema": schema,
        "class": "hardware-only",
        "provenance": "fixture",
        "synthetic": True,
        "physical_hardware": False,
        "platform": "rugged-x86_64-linux",
        "dut_id": "dut-" + "a" * 32,
        "dut_fingerprint": "hmac-sha256:" + "b" * 64,
        "hardware_class": "8GiB",
        "capture_method": "fixture-only; no acquisition",
        "operator_attestation_ref": "test-key-reference-only",
        "workload_notes": "fixture; no workload was executed",
        "harness_version": "test-only",
        "observations": {},
    }


def fixture_campaign():
    campaign = fixture_record(CAMPAIGN_SCHEMA)
    campaign["runs"] = []
    for index in range(3):
        run = fixture_record()
        run.pop("schema")
        run["boot_fingerprint"] = "hmac-sha256:" + str(index) * 64
        run["measurement"] = {
            "schema": RESERVE_SCHEMA,
            "provenance": "fixture",
            "profile": "core",
            "host_digest": campaign["dut_fingerprint"],
            "harness_version": "test-only",
            "subsystems_active": list(REQUIRED_SUBSYSTEMS),
            "samples": [
                {"offset_seconds": i * 10, "resident_mib": i + 1} for i in range(31)
            ],
        }
        campaign["runs"].append(run)
    return campaign


def refused(record, attestation=Status.ATTESTED):
    result = validate_record(record, attestation=attestation)
    assert result.status is Status.REFUSED
    assert not result.admissible
    assert result.reserve_mib is None
    assert result.reasons
    return "\n".join(result.reasons)


@pytest.mark.parametrize("schema", SCHEMAS)
@pytest.mark.parametrize(
    "attestation",
    [None, Status.SHAPE_ONLY, Status.REFUSED, Status.ATTESTED, "attested", True],
)
def test_fixture_is_always_refused(schema, attestation):
    assert "fixture/synthetic refused" in refused(fixture_record(schema), attestation)


@pytest.mark.parametrize("gate", GATES)
def test_each_gate_requires_its_observations(gate):
    record = fixture_record()
    record["gate_id"] = gate
    assert "observations." in refused(record)


@pytest.mark.parametrize("behaviour", BEHAVIOURS)
def test_all_six_on_host_behaviours_require_captures_and_invariants(behaviour):
    record = fixture_record(BEHAVIOUR_SCHEMA)
    record["behaviour"] = behaviour
    reasons = refused(record)
    for field in (
        "admission_ref",
        "request_ref",
        "capture_ref",
        "edge_authority_unchanged",
        "activation_lease_unchanged",
        "enforcement_unchanged",
    ):
        assert field in reasons


@pytest.mark.parametrize("drill", DRILLS)
def test_degraded_drills_require_metrics_recovery_and_core_invariants(drill):
    record = fixture_record(DRILL_SCHEMA)
    record["drill"] = drill
    reasons = refused(record)
    for field in (
        "latency_ref",
        "rss_swap_ref",
        "queue_backpressure_ref",
        "watchdog_ref",
        "audit_continuity_ref",
        "lease_expiry_ref",
        "core_available",
        "transitions",
    ):
        assert field in reasons
    if drill in ("uncommissioned", "topology_ineligible", "topology_drift"):
        assert "observe_only" in reasons


@pytest.mark.parametrize(
    "value",
    [
        "aa:bb:cc:dd:ee:ff",
        "AA-BB-CC-DD-EE-FF",
        "aabb.ccdd.eeff",
        "Serial: TEST-ONLY",
        "S/N=TEST-ONLY",
        "asset tag: TEST-ONLY",
    ],
)
def test_raw_identifier_patterns_are_refused_anywhere_without_echo(value):
    record = fixture_record()
    record["extra"] = {"nested": [value]}
    reasons = refused(record)
    assert "raw MAC/serial/asset pattern refused" in reasons
    assert value not in reasons


@pytest.mark.parametrize(
    "key", ["mac", "permanent_mac", "serial", "serial_number", "asset_id", "asset_tag"]
)
def test_raw_identifier_fields_are_refused(key):
    record = fixture_record()
    record["extra"] = {key: "TEST-ONLY"}
    assert "raw identifier field refused" in refused(record)


@pytest.mark.parametrize(
    "field,value",
    [
        ("dut_id", "TEST-HOST"),
        ("dut_fingerprint", "b" * 64),
        ("hardware_class", "standard"),
        ("capture_method", ""),
        ("operator_attestation_ref", None),
        ("workload_notes", " "),
    ],
)
def test_common_fields_required(field, value):
    record = fixture_record()
    record[field] = value
    assert field in refused(record)


def test_campaign_requires_distinct_boots_same_class_harness_dut_and_notes():
    campaign = fixture_campaign()
    runs = campaign["runs"]
    runs[1]["boot_fingerprint"] = runs[0]["boot_fingerprint"]
    runs[2]["hardware_class"] = "16GiB"
    runs[2]["harness_version"] = "other-test-only"
    runs[2]["dut_id"] = "dut-" + "c" * 32
    runs[2]["workload_notes"] = ""
    reasons = refused(campaign)
    for field in (
        "distinct boot",
        "hardware_class",
        "harness_version",
        "dut_id",
        "workload_notes",
    ):
        assert field in reasons


@pytest.mark.parametrize("count", [0, 1, 2])
def test_campaign_needs_three_runs(count):
    campaign = fixture_campaign()
    campaign["runs"] = campaign["runs"][:count]
    assert "at least three per-boot" in refused(campaign)


def test_campaign_checks_every_run_attestation_and_aggregate():
    campaign = fixture_campaign()
    seen = []

    def verifier(record):
        seen.append(record)
        return Status.SHAPE_ONLY

    assert "every campaign run must be externally attested" in refused(
        campaign, verifier
    )
    assert len(seen) == 4
    assert seen[-1] == campaign
    assert seen[:-1] == campaign["runs"]


def test_campaign_reuses_existing_sample_and_duration_floors():
    campaign = fixture_campaign()
    campaign["runs"][0]["measurement"]["samples"] = [
        {"offset_seconds": 0, "resident_mib": 1}
    ]
    reasons = refused(campaign)
    assert "fewer than 30" in reasons
    assert "less than 300" in reasons
    assert "fixture" in reasons


def test_campaign_checks_nested_measurement_identity_and_profile():
    campaign = fixture_campaign()
    measurement = campaign["runs"][0]["measurement"]
    measurement.update(
        profile="standard", harness_version="other-test-only", host_digest="test-only"
    )
    reasons = refused(campaign)
    assert "measurement profile differs" in reasons
    assert "measurement harness differs" in reasons
    assert "measurement host differs" in reasons


@pytest.mark.parametrize("status", ["attested", "shape_only", "fixture", "synthetic"])
def test_in_record_status_cannot_grant_authority(status):
    record = fixture_record()
    record["status"] = status
    refused(record, None)


def test_verification_failure_returns_explicit_refusal():
    def failed(record):
        raise ValueError("TEST-ONLY secret must not be echoed")

    reasons = refused(fixture_record(), failed)
    assert "operator attestation verification failed" in reasons
    assert "secret" not in reasons


@pytest.mark.parametrize(
    "record",
    [
        None,
        [],
        1,
        "fixture",
        {"schema": []},
        {"schema": GATE_SCHEMA, "hardware_class": []},
        {"x": float("nan")},
        {"x": object()},
    ],
)
def test_malformed_input_is_explicitly_refused(record):
    refused(record)


def test_unknown_versions_and_unknown_discriminators_refused():
    for schema in SCHEMAS:
        record = fixture_record(schema + "/unknown")
        assert "unsupported versioned" in refused(record)
    for schema, key in (
        (GATE_SCHEMA, "gate_id"),
        (BEHAVIOUR_SCHEMA, "behaviour"),
        (DRILL_SCHEMA, "drill"),
    ):
        record = fixture_record(schema)
        record[key] = "unknown"
        assert "known " in refused(record)


def test_result_status_invariants():
    assert not Validation(Status.SHAPE_ONLY).admissible
    with pytest.raises(ValueError):
        Validation(Status.REFUSED)
    with pytest.raises(ValueError):
        Validation(Status.ATTESTED, ("cannot pass",))
    with pytest.raises(ValueError):
        Validation(Status.SHAPE_ONLY, reserve_mib=1)


def test_no_committed_json_validates_as_attested():
    """Even a trusted status must not launder committed JSON into HIL evidence.

    Passing ATTESTED deliberately tests *shape and provenance*, rather than
    succeeding trivially because no operator key was supplied to the scan.
    """
    found = []
    for path in sorted(REPOSITORY.rglob("*.json")):
        if any(
            part in {".git", ".venv", "node_modules", "__pycache__"}
            for part in path.parts
        ):
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError):
            continue
        if validate_record(record, attestation=Status.ATTESTED).admissible:
            found.append(str(path.relative_to(REPOSITORY)))
    assert found == [], f"committed JSON accepted as attested HIL evidence: {found}"


@pytest.mark.parametrize(
    "marker",
    [
        {"synthetic": True},
        {"physical_hardware": False},
        {"provenance": "fixture"},
        {"status": "shape_only"},
    ],
)
def test_nested_capture_cannot_hide_fixture_or_shape_only(marker):
    record = fixture_record()
    record["capture"] = marker
    assert "nested fixture/synthetic/shape_only evidence refused" in refused(record)
