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
from azazel_nexus.virtualization import SENSORS

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
        "virtualization_not_observed": True,
        "virtualization_observations": dict.fromkeys(SENSORS, "clear"),
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


def refused(record):
    result = validate_record(record)
    assert result.status is Status.REFUSED
    assert not result.admissible
    assert result.reserve_mib is None
    assert result.reasons
    return "\n".join(result.reasons)


@pytest.mark.parametrize("schema", SCHEMAS)
def test_fixture_is_always_refused(schema):
    assert "fixture/synthetic refused" in refused(fixture_record(schema))


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
        "192.0.2.1",
        "2001:db8::1",
        "node.private",
        "hostname: test-node",
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
    assert "every campaign run must be externally attested" in refused(fixture_campaign())


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
    refused(record)


def test_verification_failure_returns_explicit_refusal(tmp_path):
    result = validate_record(fixture_record(), bundle_directory=tmp_path / "missing",
                             operator_key=tmp_path / "external")
    assert result.status is Status.REFUSED
    assert "operator attestation verification failed" in result.reasons


def test_bare_status_or_callback_cannot_establish_attestation():
    for forged in (Status.ATTESTED, lambda _: Status.ATTESTED):
        with pytest.raises(TypeError):
            validate_record(fixture_campaign(), attestation=forged)



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
    """Committed JSON has no bundle trust anchor and must remain inadmissible."""
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
        if validate_record(record).admissible:
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
    record["acquisition"] = marker
    assert "nested fixture/synthetic/shape_only evidence refused" in refused(record)


def v2_fixture_campaign():
    from azazel_nexus.core_reserve import RESERVE_SCHEMA_V2

    campaign = fixture_campaign()
    for index, run in enumerate(campaign["runs"]):
        run["measurement"].update(
            schema=RESERVE_SCHEMA_V2, boot_fingerprint=run["boot_fingerprint"],
            run_sequence=index + 1, build_commit="c" * 40, kernel_release="6.12.0-test",
        )
    return campaign


def test_v1_campaign_copy_repro_refused():
    campaign = fixture_campaign()
    # Reviewer's invented measured data must not acquire authority from a constant.
    campaign.update(provenance="measured", synthetic=False, physical_hardware=True)
    measurement = dict(campaign["runs"][0]["measurement"], provenance="measured")
    for run in campaign["runs"]:
        run.update(provenance="measured", synthetic=False, physical_hardware=True,
                   measurement=measurement)
    with pytest.raises(TypeError):
        validate_record(campaign, attestation=Status.ATTESTED)
    result = validate_record(campaign)
    assert not result.admissible
    assert result.reserve_mib is None
    assert any("core-reserve/4 required" in r for r in result.reasons)
    assert any("identical measurement payload" in r for r in result.reasons)


@pytest.mark.parametrize("field,value,reason", [
    ("boot_fingerprint", "hmac-sha256:" + "f" * 64, "measurement boot differs"),
    ("run_sequence", 1, "distinct positive run_sequence"),
    ("build_commit", "d" * 40, "must be consistent"),
    ("kernel_release", "6.13.0-test", "must be consistent"),
    ("harness_version", "other-test", "must be consistent"),
])
def test_campaign_v2_identity_and_environment_constraints(field, value, reason):
    campaign = v2_fixture_campaign()
    campaign["runs"][1]["measurement"][field] = value
    assert reason in refused(campaign)


def test_campaign_v2_copy_refused_even_with_distinct_run_envelopes():
    campaign = v2_fixture_campaign()
    campaign["runs"][1]["measurement"] = campaign["runs"][0]["measurement"]
    reasons = refused(campaign)
    assert "identical measurement payload" in reasons
    assert "measurement boot differs" in reasons


# -- the declared platform is compared with what was observed (ADR-0003 R3) --


def baseline_capture(record, **changes):
    """An HG-01 capture as `az-hil-capture` writes it (schema 2). Injected."""
    from azazel_nexus.hil_records.contracts import anonymous_dut

    record["dut_id"] = anonymous_dut(record["dut_fingerprint"])
    capture = {
        "schema": "azazel-nexus/hil-capture/hg-01/2", "gate_id": "HG-01",
        "capture_method": "systemd-system-bus-read-only", "systemd_version": "257 (test)",
        "unit_files": {"test.service": "masked"},
        "units": {"test.service": {"active_state": "inactive", "sub_state": "dead"}},
        "dut_id": record["dut_id"], "dut_fingerprint": record["dut_fingerprint"],
        "boot_fingerprint": "hmac-sha256:" + "c" * 64, "build_commit": "d" * 40,
        "kernel_release": "6.12.0-test", "platform_profile_id": "debian-13-amd64-cp313",
        "uname_machine": "x86_64", "dpkg_architecture": "amd64",
        "virtualization_not_observed": True,
        "virtualization_observations": dict.fromkeys(SENSORS, "clear"),
    }
    capture.update(changes)
    return capture


def platform_reasons(record):
    from azazel_nexus.hil_records import validate_record

    return [r for r in validate_record(record).reasons
            if r.startswith(("acquisition", "measurement", "runs["))]


@pytest.mark.parametrize("gate", ["HG-01", "HG-04"])
def test_captured_gates_require_the_capture(gate):
    record = fixture_record()
    record["gate_id"] = gate
    assert any(f"{gate} requires the az-hil-capture acquisition" in r
               for r in platform_reasons(record))


@pytest.mark.parametrize("gate", ["HG-02", "HG-06", "HG-07"])
def test_gates_without_a_capture_tool_are_not_asked_for_one(gate):
    record = fixture_record()
    record["gate_id"] = gate
    assert not any("requires the az-hil-capture" in r for r in platform_reasons(record))


def test_a_baseline_capture_matches_the_declared_platform():
    record = fixture_record()
    record.update(gate_id="HG-01")
    record["acquisition"] = baseline_capture(record)
    assert platform_reasons(record) == []


@pytest.mark.parametrize(("changes", "reason"), [
    # The arm64 lab VM, honestly observed: never hardware evidence.
    ({"platform_profile_id": "debian-13-arm64-cp313-lab", "uname_machine": "aarch64",
      "dpkg_architecture": "arm64"},
     "observed platform is not the deployment baseline"),
    ({"platform_profile_id": "debian-13-arm64-cp313-lab", "uname_machine": "aarch64",
      "dpkg_architecture": "arm64"},
     "declared platform differs from the observed platform profile"),
    # A capture whose uname contradicts its own profile is malformed.
    ({"uname_machine": "aarch64"}, "acquisition: invalid acquisition shape"),
    ({"platform_profile_id": "debian-13-amd64-cp313-lab"}, "acquisition: invalid acquisition shape"),
    ({"platform_profile_id": None}, "acquisition: invalid acquisition shape"),
    # dpkg must have been read and name the profile's CPU (F1).
    ({"dpkg_architecture": "unavailable"}, "acquisition: invalid acquisition shape"),
    ({"dpkg_architecture": "i386"}, "acquisition: invalid acquisition shape"),
    ({"dpkg_architecture": None}, "acquisition: invalid acquisition shape"),
    # The version 1 capture had no observation to compare with.
    ({"schema": "azazel-nexus/hil-capture/hg-01/1"}, "acquisition: invalid acquisition shape"),
])
def test_a_capture_that_is_not_the_declared_platform_is_refused(changes, reason):
    record = fixture_record()
    record.update(gate_id="HG-01")
    record["acquisition"] = baseline_capture(record, **changes)
    assert any(reason in r for r in platform_reasons(record))


def test_a_declared_platform_other_than_the_baseline_does_not_match_an_observation():
    record = fixture_record()
    record.update(gate_id="HG-01", platform="rugged-aarch64-linux")
    record["acquisition"] = baseline_capture(record)
    assert any("declared platform differs" in r for r in platform_reasons(record))


def test_the_capture_is_read_under_either_key_but_not_both():
    record = fixture_record()
    record.update(gate_id="HG-01")
    capture = baseline_capture(record, platform_profile_id="debian-13-arm64-cp313-lab",
                               uname_machine="aarch64", dpkg_architecture="arm64")
    record["capture"] = capture
    assert any("not the deployment baseline" in r for r in platform_reasons(record))
    record["acquisition"] = capture
    assert any("embed the capture once" in r for r in platform_reasons(record))


def test_a_campaign_run_measured_on_the_lab_profile_is_refused():
    from azazel_nexus.core_reserve import RESERVE_SCHEMA_V4

    campaign = fixture_campaign()
    for index, run in enumerate(campaign["runs"]):
        run["measurement"].update(
            schema=RESERVE_SCHEMA_V4, boot_fingerprint=run["boot_fingerprint"],
            run_sequence=index + 1, build_commit="c" * 40, kernel_release="6.12.0-test",
            host_digest=campaign["dut_fingerprint"], virtualization_not_observed=True,
            virtualization_observations=dict.fromkeys(SENSORS, "clear"),
            architecture="arm64", platform_profile_id="debian-13-arm64-cp313-lab")
    reasons = refused(campaign)
    assert "runs[0]: measurement: observed platform is not the deployment baseline" in reasons
    assert "runs[0]: measurement: declared platform differs" in reasons
    assert "LAB_PROFILE_NOT_FOR_PRODUCTION" in reasons
