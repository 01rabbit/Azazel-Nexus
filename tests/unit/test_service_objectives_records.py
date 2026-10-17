"""Validation of hardware record shapes is not a field measurement.

All objects below are in-memory schema fixtures. None is archived or emitted.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.service_objectives import RULES, SCHEMA, RecordRefused, validate_record


def hardware_shape_only_fixture(objective):
    artifact = {"path": "SCHEMA-TEST-ONLY", "sha256": "a" * 64}
    config = {
        "product_configuration": "SCHEMA TEST ONLY",
        "hardware_class": "test-class",
        "dut_id": "test-dut",
        "os": "test-os",
        "driver": "test-driver",
        "operator": "test-operator",
        "exercise_id": "test-only",
        "physical_hardware": True,
        "coldest_cache_state": "test-cold",
        "commissioned_role": "observation",
        "commissioning_artifact": artifact,
        "commissioned_composite_identifier": {
            "bus_path": "test-bus",
            "permanent_mac": "02:00:00:00:00:01",
            "serial": "test-serial",
        },
    }
    count = 10 if objective == "SO-01" else 3
    samples = []
    for index in range(1, count + 1):
        samples.append(
            {
                "sequence": index,
                "start_ns": 0,
                "end_ns": 120_000_000_000 if count == 10 else 600_000_000_000,
                "capture_artifact": artifact,
                "cold_boot": True,
                "boot_id": f"test-{index}",
                "probe_decision_id": f"test-probe-{index}",
                "durable_audit_artifact": artifact,
                "start_event": "unlock-unit-active-volume-usable"
                if count == 10
                else "independent-capture-stress-start",
                "end_event": "probe-decision-and-audit-durable"
                if count == 10
                else "independent-capture-stress-stop",
                "stress": {
                    "link_up_down": True,
                    "ipv6_ra": True,
                    "dhcp_offer_request": True,
                    "suspend_resume": True,
                },
                "attributed_frames": 0,
            }
        )
    return dict(
        schema=SCHEMA,
        objective_id=objective,
        owner_repository="Azazel-Nexus",
        owner_commit="a" * 40,
        configuration=config,
        samples=samples,
        synthetic=False,
        clock="CLOCK_MONOTONIC",
        **{"class": "hardware-only"},
        hardware_capture={
            "synthetic": False,
            "manifest": artifact,
            "clock_host": "test-dut" if count == 10 else "test-independent",
            "device_id": "test-independent",
            "same_physical_segment": True,
            "method": "tap",
        },
        pass_rule=RULES[objective],
        claimed_verdict="passed",
        evaluation={"maximum_elapsed_ns": 120_000_000_000}
        if count == 10
        else {"attributed_frames": [0, 0, 0]},
    )


@pytest.mark.parametrize("objective", ["SO-01", "SO-10"])
def test_shapes_and_hardware_capture_refusals(objective):
    assert validate_record(hardware_shape_only_fixture(objective)) == "shape_only"
    for field in ("hardware_capture", "synthetic"):
        record = hardware_shape_only_fixture(objective)
        del record[field]
        with pytest.raises(RecordRefused):
            validate_record(record)
    for location in ("record", "capture"):
        record = hardware_shape_only_fixture(objective)
        (record if location == "record" else record["hardware_capture"])[
            "synthetic"
        ] = True
        with pytest.raises(RecordRefused):
            validate_record(record)
    record = hardware_shape_only_fixture(objective)
    record["class"] = "software"
    with pytest.raises(RecordRefused):
        validate_record(record)


@pytest.mark.parametrize("objective", ["SO-01", "SO-10"])
@pytest.mark.parametrize(
    "mutation",
    [
        "sample_count",
        "clock",
        "capture",
        "physical",
        "start",
        "boolean_time",
        "version",
        "rule",
        "verdict",
    ],
)
def test_malformed_hardware_refused(objective, mutation):
    record = hardware_shape_only_fixture(objective)
    if mutation == "sample_count":
        record["samples"].pop()
    elif mutation == "clock":
        record["clock"] = "CLOCK_REALTIME"
    elif mutation == "capture":
        record["samples"][0]["capture_artifact"] = {}
    elif mutation == "physical":
        record["configuration"]["physical_hardware"] = False
    elif mutation == "start":
        record["samples"][0]["start_event"] = "passphrase-entered"
    elif mutation == "boolean_time":
        record["samples"][0]["start_ns"] = True
    elif mutation == "version":
        record["schema"] = "v2"
    elif mutation == "rule":
        record["pass_rule"] = "relaxed"
    else:
        record["claimed_verdict"] = "failed"
    with pytest.raises(RecordRefused):
        validate_record(record)


@pytest.mark.parametrize(
    "mutation",
    [
        "dut_capture",
        "kernel_name",
        "no_identity",
        "no_serial",
        "short",
        "stress",
        "nonzero",
    ],
)
def test_so10_physical_requirements_and_hard_zero(mutation):
    record = hardware_shape_only_fixture("SO-10")
    config = record["configuration"]
    if mutation == "dut_capture":
        record["hardware_capture"]["device_id"] = config["dut_id"]
    elif mutation == "kernel_name":
        config["commissioned_composite_identifier"]["kernel_name"] = "eth0"
    elif mutation == "no_identity":
        del config["commissioned_composite_identifier"]
    elif mutation == "no_serial":
        del config["commissioned_composite_identifier"]["serial"]
    elif mutation == "short":
        record["samples"][0]["end_ns"] -= 1
    elif mutation == "stress":
        record["samples"][0]["stress"]["suspend_resume"] = False
    else:
        record["samples"][0]["attributed_frames"] = 1
    with pytest.raises(RecordRefused):
        validate_record(record)
    if mutation == "nonzero":
        record["claimed_verdict"] = "failed"
        record["evaluation"]["attributed_frames"] = [1, 0, 0]
        validate_record(record)


def test_so01_every_sample_and_maximum():
    record = hardware_shape_only_fixture("SO-01")
    record["samples"][0]["end_ns"] += 1
    with pytest.raises(RecordRefused):
        validate_record(record)
    record["claimed_verdict"] = "failed"
    record["evaluation"]["maximum_elapsed_ns"] += 1
    validate_record(record)


def attested_test_fixture(objective, tmp_path):
    """Test signatures attest only a schema fixture, never a hardware result."""
    import hashlib
    import json

    from nacl.signing import SigningKey

    from tools.service_objectives import attestation_bytes, referenced_artifacts

    record = json.loads(json.dumps(hardware_shape_only_fixture(objective)))
    for index, artifact in enumerate(referenced_artifacts(record)):
        payload = tmp_path / f"test-capture-{index}"
        payload.write_bytes(f"schema fixture only {index}".encode())
        artifact.update(
            path=payload.name, sha256=hashlib.sha256(payload.read_bytes()).hexdigest()
        )
    signing = SigningKey.generate()
    key = tmp_path / "operator-test.pub"
    key.write_text(signing.verify_key.encode().hex())
    record["operator_attestation"] = {
        "signature": signing.sign(attestation_bytes(record)).signature.hex(),
    }
    return record, key, payload, signing


@pytest.mark.parametrize("objective", ["SO-01", "SO-10"])
def test_operator_attestation_and_all_artifact_integrity(objective, tmp_path):
    record, key, payload, _signing = attested_test_fixture(objective, tmp_path)
    assert validate_record(record) == "shape_only"
    assert (
        validate_record(record, operator_key=key, artifact_root=tmp_path) == "attested"
    )
    payload.write_bytes(b"tampered")
    with pytest.raises(RecordRefused, match="digest differs"):
        validate_record(record, operator_key=key, artifact_root=tmp_path)
    payload.unlink()
    with pytest.raises(RecordRefused, match="artifact missing"):
        validate_record(record, operator_key=key, artifact_root=tmp_path)


@pytest.mark.parametrize(
    "mutation", ["wrong_key", "record", "signature", "domain", "missing_signature"]
)
def test_attestation_cannot_be_forged_or_self_authorized(mutation, tmp_path):
    from nacl.signing import SigningKey

    from azazel_nexus.audit import canonical_event_bytes
    from tools.service_objectives import attestation_bytes

    record, key, _payload, signing = attested_test_fixture("SO-01", tmp_path)
    if mutation == "wrong_key":
        key.write_text(SigningKey.generate().verify_key.encode().hex())
        record["operator_attestation"]["public_key"] = signing.verify_key.encode().hex()
    elif mutation == "record":
        record["configuration"]["operator"] = "someone else"
    elif mutation == "signature":
        record["operator_attestation"]["signature"] = "00" * 64
    elif mutation == "domain":
        unsigned = {k: v for k, v in record.items() if k != "operator_attestation"}
        record["operator_attestation"]["signature"] = signing.sign(
            canonical_event_bytes(unsigned)
        ).signature.hex()
        assert attestation_bytes(record) != canonical_event_bytes(unsigned)
    else:
        del record["operator_attestation"]
    with pytest.raises(RecordRefused):
        validate_record(record, operator_key=key, artifact_root=tmp_path)


def test_cli_never_emits_shape_only_verdict(tmp_path, capsys):
    import json

    from tools.service_objectives import main

    record, key, _payload, _signing = attested_test_fixture("SO-10", tmp_path)
    source = tmp_path / "record.json"
    source.write_text(json.dumps(record))
    assert main([str(source)]) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "shape_only"}
    assert main([str(source), "--operator-key", str(key)]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "status": "attested",
        "verdict": "passed",
    }


@pytest.mark.parametrize("objective", ["SO-01", "SO-10"])
def test_every_referenced_file_is_checked(objective, tmp_path):
    from tools.service_objectives import referenced_artifacts

    record, key, _payload, _signing = attested_test_fixture(objective, tmp_path)
    for reference in referenced_artifacts(record):
        path = tmp_path / reference["path"]
        original = path.read_bytes()
        path.write_bytes(b"corruption")
        with pytest.raises(RecordRefused, match="digest differs"):
            validate_record(record, operator_key=key, artifact_root=tmp_path)
        path.write_bytes(original)
