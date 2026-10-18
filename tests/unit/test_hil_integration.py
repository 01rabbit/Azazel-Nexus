"""Cross-lane contracts; injected observations are always refused as HIL evidence."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import core_reserve_probe as probe
from azazel_nexus_runtime import hil_capture as capture
from azazel_nexus_runtime import hil_readiness as readiness
from nacl.signing import SigningKey

from azazel_nexus.audit import canonical_event_bytes
from azazel_nexus.core_reserve import record_as_document
from azazel_nexus.hil_records import (
    CAMPAIGN_SCHEMA,
    GATE_SCHEMA,
    MIO_CAMPAIGN_SCHEMA,
    Status,
    validate_acquisition,
    validate_record,
)
from azazel_nexus.hil_records.contracts import anonymous_dut

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.hil_evidence import bundle, lint, lint_text, record_attestation, sign

IDENTITY = {
    "host_digest": "hmac-sha256:" + "a" * 64,
    "boot_fingerprint": "hmac-sha256:" + "b" * 64,
    "build_commit": "c" * 40,
    "kernel_release": "6.12.0-test",
}
DUT = anonymous_dut(IDENTITY["host_digest"])


class Manager:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def unit_files(self):
        return {unit: "masked" for unit in readiness.CAPTURE_UNITS}

    def version(self):
        return "257 (257.9-test)"

    def __call__(self, method, unit):
        return {"ActiveState": "inactive", "SubState": "dead"}


def fixture_envelope(schema):
    # These explicit markers must always prevent admissibility, even with a key.
    return {
        "schema": schema, "class": "fixture", "synthetic": True,
        "physical_hardware": False, "platform": "test-only", "provenance": "fixture",
        "dut_id": DUT, "dut_fingerprint": IDENTITY["host_digest"],
        "hardware_class": "8GiB", "capture_method": "injected-test-only",
        "operator_attestation_ref": "hil-evidence:test-only", "workload_notes": "test-only",
        "harness_version": probe.HARNESS_VERSION,
    }


@pytest.mark.parametrize("gate", ["hg-01", "hg-04"])
def test_capture_stdout_passes_gate_acquisition_shape_and_bundle_lint(
    gate, monkeypatch, capsys, tmp_path
):
    monkeypatch.setattr(capture, "run_identity", lambda: dict(IDENTITY))
    monkeypatch.setattr(capture, "ReadOnlySystemd", Manager)
    links = [SimpleNamespace(index=1, name="private-test-interface",
                             permanent_mac="02:00:00:00:00:01")]
    acquire = capture.capture_hg04
    key = SigningKey.generate().encode()
    monkeypatch.setattr(capture, "capture_hg04", lambda: acquire(
        links_reader=lambda: links, key_reader=lambda: key
    ))
    assert capture.main([gate]) == 0
    payload = capsys.readouterr().out
    assert links[0].name not in payload
    assert links[0].permanent_mac not in payload
    report = json.loads(payload)
    assert "host_digest" not in report
    assert report["dut_id"] == DUT
    assert report["gate_id"] == gate.upper()
    assert validate_acquisition(report).status is Status.SHAPE_ONLY
    assert not validate_acquisition(report).admissible
    assert validate_record(report).status is Status.REFUSED
    lint_text(payload.encode())
    source = tmp_path / "capture.json"
    source.write_text(payload)
    root = tmp_path / "bundle"
    manifest = bundle(root, run_id="test-only", gate_ids=[gate.upper()], dut_id=DUT,
                      artifacts={"capture.json": source}, operator_input={"notes": "test-only"})
    assert lint(root) == manifest
    record = fixture_envelope(GATE_SCHEMA)
    record.update(gate_id=gate.upper(), capture=report, observations={})
    result = validate_record(record)
    assert not result.admissible
    assert not any("capture:" in reason for reason in result.reasons)
    malformed = dict(report, dut_id="dut-" + "f" * 32)
    assert validate_acquisition(malformed).status is Status.REFUSED


def test_probe_v3_is_campaign_measurement_shape_but_unattested_campaign_refused(tmp_path):
    from azazel_nexus.virtualization import SENSORS

    campaign = fixture_envelope(MIO_CAMPAIGN_SCHEMA)
    campaign["runs"] = []
    for index in range(3):
        identity = dict(IDENTITY, boot_fingerprint="hmac-sha256:" + str(index) * 64)
        readers = probe.Readers(
            identity=lambda identity=identity: identity, run_sequence=lambda index=index: index + 1,
            call=lambda *_: {"ActiveState": "active", "SubState": "running"},
            cgroup_current=lambda: 1024 * 1024 * 1000,
            usable_mib=lambda: 8000, sleep=lambda _: None,
            virtualization=lambda: dict.fromkeys(SENSORS, "clear"),
        )
        measurement = record_as_document(probe.measure(readers))
        assert validate_acquisition(measurement).status is Status.SHAPE_ONLY
        lint_text(json.dumps(measurement).encode())
        assert validate_record(measurement).status is Status.REFUSED
        run = fixture_envelope(CAMPAIGN_SCHEMA)
        run.pop("schema")
        run.update(boot_fingerprint=identity["boot_fingerprint"], measurement=measurement)
        campaign["runs"].append(run)
    result = validate_record(campaign)
    assert result.status is Status.REFUSED
    assert result.reserve_mib is None
    assert sum("every campaign run must be externally attested" in r for r in result.reasons) == 3
    assert not any("]: measurement" in r or "mismatch" in r or "distinct boot" in r
                   for r in result.reasons)
    # Even a signed fixture bundle must not turn these injected runs into evidence.
    paths = {}
    for name, record in [("campaign.json", campaign)] + [
        (f"run-{i}.json", run) for i, run in enumerate(campaign["runs"])
    ]:
        path = tmp_path / name
        path.write_bytes(canonical_event_bytes(record))
        paths[name] = path
    root = tmp_path / "bundle"
    manifest = bundle(root, run_id="test-only", gate_ids=["HG-05"], dut_id=DUT,
                      artifacts=paths, operator_input={"notes": "fixture-only"})
    assert manifest["attestation_ref"] == campaign["operator_attestation_ref"]
    key = SigningKey.generate()
    seed, public = tmp_path / "seed", tmp_path / "public"
    seed.write_text(key.encode().hex())
    public.write_text(key.verify_key.encode().hex())
    assert record_attestation(root, campaign) is Status.SHAPE_ONLY
    sign(root, key_file=seed)
    verifier = lambda record: record_attestation(root, record, operator_key=public)
    assert all(verifier(run) is Status.ATTESTED for run in campaign["runs"])
    assert verifier(campaign) is Status.ATTESTED
    assert not validate_record(campaign, bundle_directory=root, operator_key=public).admissible
    assert verifier(dict(campaign, workload_notes="unsigned change")) is Status.REFUSED
    assert verifier(dict(campaign, operator_attestation_ref="hil-evidence:other")) is Status.REFUSED


@pytest.mark.parametrize("gate", ["hg-01", "hg-04"])
def test_capture_confidentiality_guard_refuses_identity_in_platform_reply(
    gate, monkeypatch, capsys
):
    monkeypatch.setattr(capture, "run_identity", lambda: dict(IDENTITY, kernel_release="host.private"))
    monkeypatch.setattr(capture, "ReadOnlySystemd", Manager)
    monkeypatch.setattr(capture, "capture_hg04", lambda: {"interfaces": []})
    assert capture.main([gate]) == 2
    output = capsys.readouterr()
    assert not output.out
    assert "host.private" not in output.err


@pytest.mark.parametrize("length", [16, 31, 33, 64])
def test_export_rejects_other_dut_widths(length):
    with pytest.raises(ValueError):
        lint_text(json.dumps({"dut_id": "dut-" + "a" * length}).encode())


@pytest.mark.parametrize("fingerprint", ["a" * 64, "hmac-sha256:" + "A" * 64])
def test_export_rejects_other_fingerprint_formats(fingerprint):
    with pytest.raises(ValueError):
        lint_text(json.dumps({"boot_fingerprint": fingerprint}).encode())


def test_validator_requires_listed_canonical_record_and_untampered_bundle(tmp_path):
    record = fixture_envelope(GATE_SCHEMA)
    record.update(gate_id="HG-01", observations={})
    source = tmp_path / "record.json"
    source.write_bytes(canonical_event_bytes(record))
    root = tmp_path / "bundle"
    bundle(root, run_id="test-only", gate_ids=["HG-01"], dut_id=DUT,
           artifacts={"record.json": source}, operator_input={"notes": "fixture-only"})
    key = SigningKey.generate()
    seed, public = tmp_path / "seed", tmp_path / "public"
    seed.write_text(key.encode().hex())
    public.write_text(key.verify_key.encode().hex())
    sign(root, key_file=seed)
    result = validate_record(record, bundle_directory=root, operator_key=public)
    assert not result.admissible  # Signed fixture remains inadmissible.
    assert not any("verified bundle" in r or "verification failed" in r for r in result.reasons)
    unlisted = dict(record, workload_notes="unsigned modification")
    result = validate_record(unlisted, bundle_directory=root, operator_key=public)
    assert "record is not a canonical artifact in the verified bundle" in result.reasons
    assert result.reserve_mib is None
    (root / "artifacts" / "record.json").write_text("tampered")
    result = validate_record(record, bundle_directory=root, operator_key=public)
    assert result.reasons == ("operator attestation verification failed",)
    assert not result.admissible
    assert result.reserve_mib is None
