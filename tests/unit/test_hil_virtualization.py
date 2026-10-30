"""Ephemeral protocol fixtures only; no physical observations or real keys."""
import hashlib
import json

import pytest
from azazel_nexus_runtime import hil_capture, virtualization_observation
from azazel_nexus_runtime import model_admission_evidence as loader
from nacl.signing import SigningKey
from test_hil_integration import BASELINE_HOST
from test_hil_records import fixture_record
from test_model_admission_evidence import collected_store

from azazel_nexus.audit import canonical_event_bytes
from azazel_nexus.hil_records import (
    BEHAVIOUR_SCHEMA,
    CAMPAIGN_SCHEMA,
    DRILL_SCHEMA,
    GATE_SCHEMA,
    MIO_CAMPAIGN_SCHEMA,
    SCHEMAS,
    Status,
    validate_record,
)
from azazel_nexus.hil_records.evidence import attestation_bytes
from azazel_nexus.virtualization import SENSORS, virtualization_not_observed

LAB_DOMAIN = b"azazel-nexus-lab/v1\0"


@pytest.fixture(params=["physical", "vmware", "apple", "kvm", "container"])
def observations(request, tmp_path, monkeypatch):
    """Exercise the real file observer with representative guest signatures."""
    files = {}
    for sensor in SENSORS:
        path = tmp_path / sensor
        if sensor not in ("hypervisor_type", "systemd_container", "dockerenv"):
            path.write_text("normal physical observation")
        files[sensor] = str(path)
    # An x86 cpuinfo: the hypervisor flag is read from its flags line.
    (tmp_path / "cpu_hypervisor").write_text("processor\t: 0\nflags\t\t: fpu vme sse2\n")
    values = {
        "vmware": ("dmi_vendor", "VMware, Inc."),
        "apple": ("dmi_product", "Apple Virtualization Generic Platform"),
        "kvm": ("hypervisor_type", "kvm"),
        "container": ("init_cgroup", "0::/docker/test"),
    }
    if request.param in values:
        sensor, text = values[request.param]
        (tmp_path / sensor).write_text(text)
    monkeypatch.setattr(virtualization_observation, "_FILES", files)
    return request.param, virtualization_observation.observe_virtualization()


def signed_bundle(record, *, domain=None, manifest_schema=None):
    records = [record, *record.get("runs", [])]
    files = {f"artifacts/record-{i}.json": canonical_event_bytes(value)
             for i, value in enumerate(records)}
    manifest = {
        "schema": manifest_schema or "azazel-nexus/hil-evidence/v1",
        "run_id": "unit-test", "attestation_ref": "hil-evidence:unit-test",
        "gate_ids": ["HG-01"], "dut_id": record["dut_id"], "B": {"notes": "test only"},
        "A": {"artifacts": {path.removeprefix("artifacts/"): {"path": path, "sha256": hashlib.sha256(raw).hexdigest()}
                            for path, raw in files.items()}},
    }
    key = SigningKey.generate()
    files["manifest.json"] = canonical_event_bytes(manifest)
    message = attestation_bytes(manifest) if domain is None else domain + canonical_event_bytes(manifest)
    files["manifest.sig"] = key.sign(message).signature.hex().encode()
    return {"bundle_files": files, "public_key": bytes(key.verify_key)}


@pytest.fixture
def protocol_record(tmp_path, monkeypatch, private_os):
    private_os(loader)
    collected_store(tmp_path, monkeypatch)
    campaign = json.loads((tmp_path / "etc/azazel/model-admission/evidence/artifacts/campaign.json").read_bytes())

    def make(schema):
        if schema in (CAMPAIGN_SCHEMA, MIO_CAMPAIGN_SCHEMA):
            record = json.loads(json.dumps(campaign))
            record["schema"] = schema
            return record
        record = fixture_record(schema)
        # In-memory protocol acceptance control, never emitted as evidence.
        record.update(provenance="measured", synthetic=False, physical_hardware=True,
                      operator_attestation_ref="hil-evidence:unit-test")
        if schema == GATE_SCHEMA:
            from azazel_nexus.hil_records.contracts import anonymous_dut

            record["dut_id"] = anonymous_dut(record["dut_fingerprint"])
            # The az-hil-capture output an HG-01 record embeds (R3), as the
            # deployment baseline would report it. Injected, not acquired.
            record["acquisition"] = {
                "schema": "azazel-nexus/hil-capture/hg-01/2", "gate_id": "HG-01",
                "capture_method": "systemd-system-bus-read-only",
                "systemd_version": "257 (test)", "unit_files": {"test.service": "masked"},
                "units": {"test.service": {"active_state": "inactive", "sub_state": "dead"}},
                "dut_id": record["dut_id"], "dut_fingerprint": record["dut_fingerprint"],
                "boot_fingerprint": "hmac-sha256:" + "c" * 64, "build_commit": "d" * 40,
                "kernel_release": "6.12.0-test", "platform_profile_id": "debian-13-amd64-cp313",
                "uname_machine": "x86_64", "dpkg_architecture": "amd64",
        "virtualization_not_observed": True,
                "virtualization_observations": dict.fromkeys(SENSORS, "clear"),
            }
            record.update(gate_id="HG-01", observations={
                "systemd_version": "test", "unit_inventory_ref": "test",
                "unit_states_ref": "test", "interface_counts_ref": "test",
                "all_governed_units_masked": True, "all_governed_units_inactive": True,
                "transmitted_frames": 0})
        elif schema == BEHAVIOUR_SCHEMA:
            record.update(behaviour="local_inference", observations={
                **dict.fromkeys(("provider_admitted_after_reserve", "edge_authority_unchanged",
                                "activation_lease_unchanged", "enforcement_unchanged", "local_answered"), True),
                **dict.fromkeys(("admission_ref", "request_ref", "capture_ref", "invariants_ref"), "test")})
        elif schema == DRILL_SCHEMA:
            record.update(drill="restart", observations={
                **dict.fromkeys(("configuration_ref", "hardware_inventory_ref", "software_asset_generations_ref",
                                "os_kernel_driver_ref", "model_runtime_quantization_ref", "replay_corpus_ref",
                                "topology_ref", "latency_ref", "rss_swap_ref", "disk_growth_ref",
                                "queue_backpressure_ref", "voice_operator_responsiveness_ref", "restart_recovery_ref",
                                "rollback_ref", "watchdog_ref", "audit_continuity_ref", "lease_expiry_ref",
                                "key_protection_ref", "safe_rejoin_ref", "transition_reasons_ref"), "test"),
                **dict.fromkeys(("core_available", "edge_authority_unchanged", "activation_lease_unchanged",
                                "enforcement_unchanged", "capability_display_matches", "resource_topology_independent",
                                "x86_specific"), True),
                "pi_equivalence_claimed": False, "repeat_count": 1, "transitions": ["FULL", "CORE"]})
        return record
    return make


@pytest.mark.parametrize("schema", SCHEMAS)
def test_every_hil_kind_negative_filter(schema, observations, protocol_record):
    name, values = observations
    record = protocol_record(schema)
    record.update(virtualization_not_observed=True, virtualization_observations=values)
    result = validate_record(record, **signed_bundle(record))
    assert result.status is (Status.ATTESTED if name == "physical" else Status.REFUSED), result.reasons
    if name != "physical":
        assert result.reasons == ("RESERVE_VIRTUALIZATION_OBSERVED",)


@pytest.mark.parametrize("schema", SCHEMAS)
@pytest.mark.parametrize("mutation", ["missing", "missing_flag", "unknown", "false", "incomplete"])
def test_missing_uncertain_or_false_observations_refused(schema, mutation, protocol_record):
    record = protocol_record(schema)
    if mutation == "missing":
        del record["virtualization_observations"]
    elif mutation == "missing_flag":
        del record["virtualization_not_observed"]
    elif mutation == "unknown":
        record["virtualization_observations"]["dmi_vendor"] = "unknown"
    elif mutation == "false":
        record["virtualization_not_observed"] = False
    else:
        del record["virtualization_observations"]["cpu_hypervisor"]
    assert "RESERVE_VIRTUALIZATION_OBSERVED" in validate_record(record, **signed_bundle(record)).reasons


@pytest.mark.parametrize("schema", [CAMPAIGN_SCHEMA, MIO_CAMPAIGN_SCHEMA])
def test_campaign_checks_each_run_negative_filter(schema, protocol_record):
    record = protocol_record(schema)
    record["runs"][1]["virtualization_observations"]["dockerenv"] = "observed"
    result = validate_record(record, **signed_bundle(record))
    assert result.status is Status.REFUSED
    assert "runs[1]: RESERVE_VIRTUALIZATION_OBSERVED" in result.reasons


@pytest.mark.parametrize("gate", ["hg-01", "hg-04"])
def test_capture_refuses_guests_before_identity_or_acquisition(gate, observations, monkeypatch, capsys):
    name, values = observations
    if name == "physical":
        return  # Successful acquisition is covered in test_hil_integration.
    monkeypatch.setattr(hil_capture, "observe_platform", lambda: BASELINE_HOST)
    monkeypatch.setattr(hil_capture, "observe_virtualization", lambda: values)
    monkeypatch.setattr(hil_capture, "run_identity", lambda: pytest.fail("guest reached acquisition"))
    assert hil_capture.main([gate]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "refused: RESERVE_VIRTUALIZATION_OBSERVED\n"
    assert not virtualization_not_observed(values)


@pytest.mark.parametrize("schema", SCHEMAS)
@pytest.mark.parametrize("mutation", ["record_schema", "manifest_schema", "domain", "lab_schema_and_domain"])
def test_lab_hil_corpus_refused(schema, mutation, protocol_record):
    record = protocol_record(schema)
    kwargs = {}
    if mutation in ("record_schema", "lab_schema_and_domain"):
        record["schema"] = schema.replace("azazel-nexus/", "azazel-nexus-lab/", 1)
    if mutation == "manifest_schema":
        kwargs["manifest_schema"] = "azazel-nexus-lab/hil-evidence/v1"
    if mutation in ("domain", "lab_schema_and_domain"):
        kwargs["domain"] = LAB_DOMAIN
    assert validate_record(record, **signed_bundle(record, **kwargs)).status is Status.REFUSED


@pytest.mark.parametrize("version", ["1", "2", "3", "4"])
def test_lab_core_reserve_parse_and_validate_refused(version, protocol_record):
    from dataclasses import replace

    from azazel_nexus.core_reserve import ReserveRefused, parse_record, validate

    measurement = protocol_record(MIO_CAMPAIGN_SCHEMA)["runs"][0]["measurement"]
    measurement["schema"] = "azazel-nexus/core-reserve/" + version
    parsed = parse_record(json.dumps(measurement))
    # Only v4 records the CPU; older versions parse and are refused for it.
    assert validate(parsed).admissible is (version == "4")
    lab_schema = measurement["schema"].replace("azazel-nexus/", "azazel-nexus-lab/", 1)
    assert not validate(replace(parsed, schema=lab_schema)).admissible
    measurement["schema"] = lab_schema
    with pytest.raises(ReserveRefused):
        parse_record(json.dumps(measurement))


@pytest.mark.parametrize("objective", ["SO-01", "SO-10"])
@pytest.mark.parametrize("mutation", ["schema", "domain", "schema_and_domain"])
def test_lab_service_objectives_refused(objective, mutation, tmp_path):
    from test_service_objectives_records import attested_test_fixture

    from tools.service_objectives import RecordRefused, validate_record

    record, key, _, signing = attested_test_fixture(objective, tmp_path)
    assert validate_record(record, operator_key=key, artifact_root=tmp_path) == "attested"
    if mutation in ("schema", "schema_and_domain"):
        record["schema"] = record["schema"].replace("azazel-nexus/", "azazel-nexus-lab/", 1)
    unsigned = {k: v for k, v in record.items() if k != "operator_attestation"}
    from tools.service_objectives import attestation_bytes

    message = (LAB_DOMAIN + canonical_event_bytes(unsigned) if mutation != "schema"
               else attestation_bytes(record))
    record["operator_attestation"]["signature"] = signing.sign(message).signature.hex()
    with pytest.raises(RecordRefused):
        validate_record(record, operator_key=key, artifact_root=tmp_path)


@pytest.mark.parametrize("gate", ["hg-01", "hg-04"])
@pytest.mark.parametrize("values", [None, {}, dict.fromkeys(SENSORS, "unknown")])
def test_capture_refuses_missing_and_unknown_observations(gate, values, monkeypatch, capsys):
    monkeypatch.setattr(hil_capture, "observe_platform", lambda: BASELINE_HOST)
    monkeypatch.setattr(hil_capture, "observe_virtualization", lambda: values)
    monkeypatch.setattr(hil_capture, "run_identity", lambda: pytest.fail("uncertain capture acquired"))
    assert hil_capture.main([gate]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "refused: RESERVE_VIRTUALIZATION_OBSERVED\n"


@pytest.mark.parametrize(("architecture", "profile_id", "cpu", "refusal"), [
    ("amd64", "debian-13-amd64-cp313", "clear", None),
    ("amd64", "debian-13-amd64-cp313", "unobservable", "RESERVE_VIRTUALIZATION_OBSERVED"),
    # arm64: the x86 flag is unobservable; `clear` is the reading of a flag
    # that does not exist and is refused (H4).
    ("arm64", "debian-13-arm64-cp313-lab", "clear", "RESERVE_VIRTUALIZATION_OBSERVED"),
    ("arm64", "debian-13-arm64-cp313-lab", "unobservable", None),
])
def test_a_v4_reserve_record_reads_the_flag_for_its_cpu(
        architecture, profile_id, cpu, refusal, protocol_record):
    from azazel_nexus.core_reserve import ReserveRefused, parse_record, validate

    measurement = protocol_record(MIO_CAMPAIGN_SCHEMA)["runs"][0]["measurement"]
    assert measurement["schema"] == "azazel-nexus/core-reserve/4"
    measurement.update(architecture=architecture, platform_profile_id=profile_id)
    measurement["virtualization_observations"]["cpu_hypervisor"] = cpu
    if refusal:
        with pytest.raises(ReserveRefused, match=refusal):
            parse_record(json.dumps(measurement))
        return
    result = validate(parse_record(json.dumps(measurement)))
    assert result.admissible is (architecture == "amd64")
    assert not any("VIRTUALIZATION" in reason for reason in result.refusals)
    if architecture == "arm64":
        # Read for its CPU, yet never the reserve: the lab profile is refused.
        assert any("LAB_PROFILE_NOT_FOR_PRODUCTION" in reason for reason in result.refusals)
