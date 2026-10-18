"""Protected-store and runtime integration with ephemeral test evidence only."""
import ast
import base64
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from admission_helpers import END, NOW, H, _read_at, evidence, inputs
from azazel_nexus_runtime import model_admission_evidence as loader

from azazel_nexus import model_admission as admission
from azazel_nexus.cognition import LocalModelProvider, ResourceEvidence
from azazel_nexus.core_reserve import CoreReserve
from azazel_nexus.model_runtime import (
    LLAMA_EXECUTABLE,
    LLAMA_RUNTIME_ID,
    RuntimeBinary,
    llama_server_record,
)


@pytest.fixture(autouse=True)
def root_without_azmio(monkeypatch):
    """Run as root on a host with no `azmio` group (a CI or test container).

    The fixture trees are created by this process, so as root they carry
    root's primary group, not azmio. The root-only group check is kept and
    bound to that group instead: entries must still carry exactly it, with the
    same modes, so a wrong group is still refused. Elsewhere nothing changes.
    """

    import grp

    if os.getuid() != 0:
        return
    try:
        grp.getgrnam(loader.ProtectedTree.ADMISSION_GROUP)
    except KeyError:
        monkeypatch.setattr(loader.ProtectedTree, "ADMISSION_GROUP", grp.getgrgid(os.getgid()).gr_name)


@pytest.fixture(autouse=True)
def enabled(monkeypatch, request):
    if request.node.name != "test_disabled_is_first_and_does_no_io":
        monkeypatch.setattr(admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)
        from azazel_nexus_runtime import virtualization_observation

        from azazel_nexus.virtualization import SENSORS

        monkeypatch.setattr(virtualization_observation, "observe_virtualization",
                            lambda: dict.fromkeys(SENSORS, "clear"))


def admitted_candidate():
    from test_cognition import COMPONENT, a_catalogue, a_host
    from test_model_catalog import an_entry

    host, tested = a_host(), a_catalogue()
    matched, _ = tested.admits(COMPONENT, host, model_role="embedding")
    binary = RuntimeBinary(LLAMA_RUNTIME_ID, LLAMA_EXECUTABLE, "b11716", COMPONENT, (LLAMA_EXECUTABLE,))
    import tempfile

    # The candidate owns these files until collected; closing on function exit
    # would turn this into a fake-descriptor test rather than a held-fd test.
    binary_file, model_file = tempfile.TemporaryFile(), tempfile.TemporaryFile()  # noqa: SIM115
    model_file.write(b"GGUF" + bytes(32))
    model_file.flush()
    held = SimpleNamespace(recheck=lambda **kw: binary, model_fd=model_file.fileno(),
                           binary_fd=binary_file.fileno(), close=lambda: None,
                           files=(binary_file, model_file))
    record = llama_server_record(binary, model_path=Path("/var/lib/azazel/models/store/test.gguf"),
                                 socket_path=Path("/var/lib/azazel/mio/embedding.sock"), embedding=True)
    proof = evidence(component=COMPONENT, model_id="local-model", version="b11716", need=1000,
                     tuple_digest=admission.digest(admission.canonical(matched.as_record())), descriptors=held,
                     argv_digest=admission.digest(admission.canonical(list(record.argv))))
    entry = an_entry(model_id="local-model", role="embedding", digest=COMPONENT)
    provider = LocalModelProvider("local-model", COMPONENT, "gguf", "gguf", "b11716", "q8", 2048, 1000,
                                  evidence=proof, role="embedding")
    resources = ResourceEvidence(CoreReserve(host.profile, 2000, H, "unit-test", 60, 600), 15000,
                                 proof.context.bindings["reserve"]["campaign_record_digest"])
    return loader.Admitted(proof, entry, provider, host, tested, resources, record)


def store(tmp_path, kwargs):
    directory = tmp_path / "etc/azazel/model-admission"
    directory.mkdir(parents=True, mode=0o750, exist_ok=True)
    wrapper = {"schema": admission.FILE_SCHEMA,
               "payload_b64": base64.b64encode(kwargs["payload"]).decode(),
               "signature_hex": kwargs["signature"].hex()}
    (directory / "embedding.approval").write_bytes(admission.canonical(wrapper))
    (directory / "policy.json").write_bytes(admission.canonical({
        "schema": admission.POLICY_SCHEMA, "operators": ["approver"], "max_seconds": 86400,
        "roles": ["embedding"]}))
    for path in directory.iterdir():
        if path.is_file():
            path.chmod(0o640)
    return directory


def read_test(root, *, trust, now=NOW):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return _read_at(fd, os.getuid(), now=now, trust=trust)
    finally:
        os.close(fd)


def test_disabled_is_first_and_does_no_io(monkeypatch):
    assert admission.LOCAL_MODEL_ADMISSION_ENABLED is False
    monkeypatch.setattr(loader.os, "open", lambda *a, **kw: pytest.fail("disabled loader opened a file"))
    reading = loader.read_admissions(now=NOW)
    assert reading.embedding == loader.Refused("ADMISSION_DISABLED")


def test_absent_unprotected_symlink_and_no_writes(tmp_path, monkeypatch):
    kwargs, _, _ = inputs()
    assert type(read_test(tmp_path, trust=kwargs["trust"]).embedding) is loader.Absent
    directory = store(tmp_path, kwargs)
    (directory / "embedding.approval").chmod(0o666)
    assert read_test(tmp_path, trust=kwargs["trust"]).embedding == loader.Refused("EVIDENCE_UNPROTECTED")
    approval = directory / "embedding.approval"
    approval.unlink()
    approval.symlink_to(directory / "policy.json")
    assert type(read_test(tmp_path, trust=kwargs["trust"]).embedding) is loader.Refused


def test_a_root_owned_store_without_its_admission_group_is_unprotected(tmp_path, monkeypatch):
    monkeypatch.setattr(loader.ProtectedTree, "ADMISSION_GROUP", "az-no-such-group-for-test")
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(admission.ApprovalRefused, match="^EVIDENCE_UNPROTECTED$"):
            loader.ProtectedTree(fd, 0)
    finally:
        os.close(fd)


@pytest.mark.skipif(os.getuid() != 0, reason="the admission group is checked only for root-owned stores")
def test_as_root_an_entry_in_another_group_is_unprotected(tmp_path):
    kwargs, _, _ = inputs()
    directory = store(tmp_path, kwargs)
    assert read_test(tmp_path, trust=kwargs["trust"]).embedding != loader.Refused("EVIDENCE_UNPROTECTED")
    other = next(gid for gid in (65534, 1, 2, 3) if gid != os.getgid())
    os.chown(directory / "policy.json", 0, other)
    assert read_test(tmp_path, trust=kwargs["trust"]).embedding == loader.Refused("EVIDENCE_UNPROTECTED")


def test_protected_signed_wrapper_uses_independent_context_and_ignores_env(tmp_path, monkeypatch):
    kwargs, _, _ = inputs(descriptors=SimpleNamespace(close=lambda: None))
    store(tmp_path, kwargs)
    candidate = admitted_candidate()
    monkeypatch.setattr(loader, "_collect", lambda *a, **kw: (
        kwargs["expected"], kwargs["descriptors"], candidate.entry, candidate.provider,
        candidate.host, candidate.tested, candidate.resources, candidate.record))
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path / "valid-looking-other-root"))
    real_open = os.open
    calls = []

    def readonly(path, flags, *a, **kw):
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        calls.append(path)
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(loader.os, "open", readonly)
    reading = read_test(tmp_path, trust=kwargs["trust"])
    assert type(reading.embedding) is loader.Admitted
    assert "core-reserve.json" not in str(calls)
    event = reading.as_event()
    assert set(event) == {"event_type", "role", "outcome", "refusal", "approval_id", "payload_digest",
                          "model_digest", "generation_id", "catalog_digest", "reserve_record_digest"}
    assert not any("/" in str(v) for k, v in event.items() if k != "event_type")
    reading.close()


@pytest.mark.parametrize("symbol", ["CATALOG_MISMATCH", "GENERATION_MISMATCH", "WRONG_ARCHITECTURE",
                                     "TUPLE_MISMATCH", "RUNTIME_MISMATCH", "SETTINGS_MISMATCH",
                                     "RESERVE_UNATTESTED", "RESERVE_VIRTUALIZATION_OBSERVED",
                                     "RUNTIME_EVIDENCE_MISSING", "RESOURCE_FIT", "ARTIFACT_REFUSED"])
def test_collector_refusals_never_become_success(tmp_path, monkeypatch, symbol):
    kwargs, _, _ = inputs()
    store(tmp_path, kwargs)

    def refuse(*a, **kw):
        raise admission.ApprovalRefused(symbol)

    monkeypatch.setattr(loader, "_collect", refuse)
    assert read_test(tmp_path, trust=kwargs["trust"]).embedding == loader.Refused(symbol)


def test_signature_refused_before_collector(tmp_path, monkeypatch):
    kwargs, _, _ = inputs()
    kwargs["signature"] = bytes(64)
    store(tmp_path, kwargs)
    monkeypatch.setattr(loader, "_collect", lambda *a, **k: pytest.fail("unsigned context collected"))
    assert read_test(tmp_path, trust=kwargs["trust"]).embedding == loader.Refused("SIGNATURE_REFUSED")


def test_holder_withdraws_on_next_request_and_never_adds_on_refresh(monkeypatch):
    candidate = admitted_candidate()
    calls, events = [], []
    monkeypatch.setattr(loader, "read_admissions", lambda **kw: loader.AdmissionReading(candidate))
    monkeypatch.setattr(loader, "fingerprint", lambda paths: (1,))
    monkeypatch.setattr(admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)
    holder = loader.AdmissionHolder(clock=lambda: NOW)
    holder.start(audit=events.append)
    holder.refresh(withdraw=lambda: calls.append("withdraw"), audit=events.append)
    assert not calls
    monkeypatch.setattr(loader, "fingerprint", lambda paths: (2,))
    holder.refresh(withdraw=lambda: calls.append("withdraw"), audit=events.append)
    assert calls == ["withdraw"]
    assert holder.reading.embedding == loader.Refused("EVIDENCE_CHANGED")
    holder.refresh(withdraw=lambda: calls.append("again"), audit=events.append)
    assert calls == ["withdraw"]
    assert loader.POLL_INTERVAL_SECONDS == 1.0


def test_expiry_withdraws_without_file_change(monkeypatch):
    now = [NOW]
    monkeypatch.setattr(loader, "read_admissions", lambda **kw: loader.AdmissionReading(admitted_candidate()))
    monkeypatch.setattr(loader, "fingerprint", lambda paths: (1,))
    monkeypatch.setattr(admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)
    holder = loader.AdmissionHolder(clock=lambda: now[0])
    holder.start(audit=lambda e: None)
    now[0] = END
    stopped = []
    holder.refresh(withdraw=lambda: stopped.append(True), audit=lambda e: None)
    assert stopped == [True]
    assert holder.reading.embedding == loader.Refused("EXPIRED")


def test_private_seam_not_imported_by_production_and_no_legacy_reserve():
    assert not hasattr(loader, "_read_at")
    root = Path(__file__).resolve().parents[2]
    for path in (p for folder in ("src", "runtime/src", "tools") for p in (root / folder).rglob("*.py")):
        tree = ast.parse(path.read_text())
        aliases = {"loader", "model_admission_evidence"}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                aliases.update(alias.asname or alias.name for alias in node.names
                               if alias.name.endswith("model_admission_evidence"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert not ((ast.unparse(node.value).endswith("model_admission_evidence")
                             or isinstance(node.value, ast.Name) and node.value.id in aliases)
                            and node.attr == "_read_at")
            if (isinstance(node, ast.Call) and (isinstance(node.func, ast.Name) and node.func.id == "getattr"
                                              or isinstance(node.func, ast.Attribute) and node.func.attr == "getattr")):
                assert not (len(node.args) > 1 and isinstance(node.args[1], ast.Constant) and node.args[1].value == "_read_at")
            if isinstance(node, ast.ImportFrom) and node.module and node.module.endswith("model_admission_evidence"):
                assert all(alias.name != "_read_at" for alias in node.names)
    source = (root / "runtime/src/azazel_nexus_runtime/model_admission_evidence.py").read_text()
    assert "load_reserve" not in source and "core-reserve.json" not in source
    for name in ("model_admission.py",):
        source = (root / "src/azazel_nexus" / name).read_text()
        assert "environ" not in source and "nacl.signing" not in source


def test_wiring_only_embedding_and_retry_bound(monkeypatch):
    from azazel_nexus_runtime import activated

    from azazel_nexus.activation import LOCAL_MODEL_PROVIDER

    monkeypatch.setattr(activated, "_fetch_commissioned", lambda path: False)
    monkeypatch.setattr(loader, "read_admissions", lambda **kw: loader.AdmissionReading(loader.Refused("ADMISSION_DISABLED")))
    assert LOCAL_MODEL_PROVIDER not in activated.wired_capabilities()
    count = []

    def unstable(**kw):
        count.append(1)
        return loader.AdmissionReading(admitted_candidate(), ("/test",), (1,))

    monkeypatch.setattr(loader, "read_admissions", unstable)
    monkeypatch.setattr(loader, "fingerprint", lambda paths: (2,))
    assert LOCAL_MODEL_PROVIDER not in activated.wired_capabilities()
    assert len(count) == 3
    monkeypatch.setattr(loader, "fingerprint", lambda paths: (1,))
    assert LOCAL_MODEL_PROVIDER in activated.wired_capabilities()


def test_non_procfs_platform_refuses_even_valid_store(tmp_path, monkeypatch):
    kwargs, _, _ = inputs()
    store(tmp_path, kwargs)
    monkeypatch.setattr(loader.sys, "platform", "darwin")
    assert read_test(tmp_path, trust=kwargs["trust"]).embedding == loader.Refused("PROCFS_REQUIRED")


def collected_store(tmp_path, monkeypatch):
    """Synthetic on-disk protocol fixture, built only at test time with test keys.

    It exercises verification mechanics with observations stubbed; it is never
    a hardware result and cannot enable the shipped kill switch.
    """
    from dataclasses import asdict

    from azazel_nexus_runtime import (
        hil_readiness,
        model_identity,
        virtualization_observation,
    )
    from nacl.signing import SigningKey
    from test_cognition import a_catalogue, a_host
    from test_hil_records import fixture_campaign
    from test_model_catalog import an_entry

    from azazel_nexus import model_import, model_runtime
    from azazel_nexus.core_reserve import RESERVE_SCHEMA_V3
    from azazel_nexus.hil_records import MIO_CAMPAIGN_SCHEMA
    from azazel_nexus.hil_records.evidence import attestation_bytes
    from azazel_nexus.model_catalog import (
        CATALOG_DOMAIN,
        artifact_filename,
        catalog_payload,
    )
    from azazel_nexus.model_import import generation_from_bytes
    from azazel_nexus.operator_trust import OperatorTrust
    from azazel_nexus.virtualization import SENSORS

    signer, attester, catalog_key = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    trust = OperatorTrust({"approver": bytes(signer.verify_key), "attester": bytes(attester.verify_key)})
    observations = dict.fromkeys(SENSORS, "clear")
    monkeypatch.setattr(loader, "procfs_available", lambda: True)
    monkeypatch.setattr(loader.os, "uname", lambda: SimpleNamespace(machine="x86_64"))
    monkeypatch.setattr(hil_readiness, "run_identity", lambda: {"host_digest": H})
    monkeypatch.setattr(model_identity, "read_identity", lambda: {"host_digest": H})
    monkeypatch.setattr(virtualization_observation, "observe_virtualization", lambda: observations)
    from azazel_nexus import model_paths
    monkeypatch.setattr(model_paths, "bounded_read", lambda *a: b"MemTotal:       16777216 kB\n")

    def write(name, raw):
        path = tmp_path / name.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o640)
        return path

    weights = b"test inert GGUF weights"
    runtime_bytes = b"test binary bytes never executed"
    component = admission.digest(weights)
    runtime_digest = admission.digest(runtime_bytes)
    monkeypatch.setitem(model_runtime.LLAMA_RUNTIME_DIGESTS, "x86_64", runtime_digest)
    entry = an_entry(model_id="local-model", role="embedding", digest=component,
                     size_bytes=len(weights), declared_min_ram_mib=1000)
    host = a_host()
    tested = a_catalogue(component_digest=component)
    matched, _ = tested.admits(component, host, model_role="embedding")
    commissioning = "sha256:" + "9" * 64
    config_host = asdict(host)
    config_host["profile"] = host.profile.value
    for field in ("cpu_features", "fabric_features", "schema_features"):
        config_host[field] = sorted(config_host[field])
    config = {"schema": "azazel-nexus/mission-pack-config/1", "host": config_host,
              "tested_tuples": [matched.as_record()], "commissioning_digest": commissioning,
              "assets": [{"kind": "model", "id": entry.model_id, "digest": component,
                          "memory_need_mib": 1000}]}
    write("/etc/azazel/mission-pack.json", admission.canonical(config))
    write("/etc/azazel/node.yaml", b"synthetic node declaration\n")
    write("/var/lib/azazel/models/trust/trust.json", admission.canonical({
        "commissioning_digest": commissioning, "catalog_keys": {"catalog": bytes(catalog_key.verify_key).hex()}}))
    payload = catalog_payload(version=1, commissioning_digest=commissioning, entries=[entry])
    write("/var/lib/azazel/models/trust/catalog.signed", catalog_key.sign(CATALOG_DOMAIN + payload).signature + payload)
    write("/var/lib/azazel/models/state/current", b"1")
    generation_doc = {"schema": model_import.MANIFEST_SCHEMA, "generation": 1,
                      "generation_id": model_import._generation_id(1, {entry.model_id: component}),
                      "previous_generation_id": "", "commissioning_digest": commissioning,
                      "installed": {entry.model_id: component}}
    generation_raw = admission.canonical(generation_doc)
    generation_from_bytes(generation_raw, number=1, commissioning_digest=commissioning)
    write("/var/lib/azazel/models/state/generations/1.json", generation_raw)
    write("/var/lib/azazel/models/store/" + artifact_filename(entry), weights)
    binary_path = write(LLAMA_EXECUTABLE, runtime_bytes)
    binary_path.chmod(0o750)
    binary = replace(model_runtime.RUNTIMES[LLAMA_RUNTIME_ID], digest=runtime_digest)
    record = llama_server_record(binary, model_path=Path("/var/lib/azazel/models/store") / artifact_filename(entry),
                                 socket_path=Path("/var/lib/azazel/mio/embedding.sock"), embedding=True)
    campaign = fixture_campaign()
    campaign.update(schema=MIO_CAMPAIGN_SCHEMA, dut_fingerprint=H, hardware_class="16GiB",
                    provenance="measured", synthetic=False, physical_hardware=True,
                    operator_attestation_ref="hil-evidence:unit-test",
                    virtualization_not_observed=True, virtualization_observations=observations,
                    embedding_runtime={"peak_rss_mib": 900, "startup_ms": 100, "retrieval_p50_ms": 10,
                                       "retrieval_p95_ms": 20, "runtime_binary_digest": runtime_digest,
                                       "model_digest": component,
                                       "argv_digest": admission.digest(admission.canonical(list(record.argv)))})
    for index, run in enumerate(campaign["runs"]):
        run.update(provenance="measured", synthetic=False, physical_hardware=True,
                   hardware_class="16GiB", dut_fingerprint=H, operator_attestation_ref="hil-evidence:unit-test")
        measurement = run["measurement"]
        measurement.update(schema=RESERVE_SCHEMA_V3, provenance="measured", profile="lite", host_digest=H,
                           boot_fingerprint=run["boot_fingerprint"], run_sequence=index + 1,
                           build_commit="a" * 40, kernel_release="test-linux",
                           virtualization_not_observed=True, virtualization_observations=observations)
        measurement["samples"][0]["resident_mib"] += index
    files = {"artifacts/campaign.json": admission.canonical(campaign)}
    files.update({f"artifacts/run-{i}.json": admission.canonical(run) for i, run in enumerate(campaign["runs"])})
    manifest = {"schema": "azazel-nexus/hil-evidence/v1", "run_id": "unit-test",
                "attestation_ref": "hil-evidence:unit-test", "gate_ids": ["HG-05"],
                "dut_id": campaign["dut_id"], "B": {"notes": "unit-test-only"},
                "A": {"artifacts": {name.removeprefix("artifacts/"): {"path": name,
                    "sha256": admission.digest(raw).removeprefix("sha256:")} for name, raw in files.items()}}}
    files["manifest.json"] = admission.canonical(manifest)
    files["manifest.sig"] = attester.sign(attestation_bytes(manifest)).signature.hex().encode()
    for name, raw in files.items():
        write(loader.DIRECTORY + "/evidence/" + name, raw)
    for path in (tmp_path / "etc/azazel/model-admission").rglob("*"):
        if path.is_dir():
            path.chmod(0o750)
    (tmp_path / "etc/azazel/model-admission").chmod(0o750)
    return trust, signer, write


def test_full_collector_recomputes_observations_and_holds_verified_inodes(tmp_path, monkeypatch):
    trust, _, write = collected_store(tmp_path, monkeypatch)
    # Demonstrate that even a legacy file accepted by its old reader is not an
    # admission input. This record is created in the temporary test tree only.
    from azazel_nexus.core_reserve import REQUIRED_SUBSYSTEMS, load_reserve

    legacy_path = write("/var/lib/azazel/run/core-reserve.json", admission.canonical({
        "schema": "azazel-nexus/core-reserve/1", "provenance": "measured", "profile": "lite",
        "host_digest": H, "harness_version": "unit-test", "subsystems_active": list(REQUIRED_SUBSYSTEMS),
        "samples": [{"offset_seconds": i * 10, "resident_mib": 1} for i in range(31)]}))
    assert load_reserve(legacy_path).reserve_mib == 1
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        tree = loader.ProtectedTree(fd, os.getuid())
        result = loader._collect(tree, trust=trust, policy=admission.AdmissionPolicy(
            frozenset({"approver"}), 86400, ("embedding",)), operator="approver")
        context, held, entry, *_ = result
        assert context.bindings["runtime_evidence"]["peak_rss_mib"] == 900
        assert context.bindings["reserve"]["reserve_mib"] == 31
        assert context.bindings["node"]["dut_fingerprint"] == H
        assert held.recheck().digest == context.bindings["runtime"]["binary_digest"]
        assert os.pread(held.model_fd, entry.size_bytes, 0) == b"test inert GGUF weights"
        held.close()
    finally:
        os.close(fd)


@pytest.mark.parametrize("mutation,symbol", [
    ("generation", "GENERATION_MISMATCH"), ("catalog", "CATALOG_MISMATCH"),
    ("runtime", "RUNTIME_MISMATCH"), ("artifact", "ARTIFACT_REFUSED"),
    ("architecture", "WRONG_ARCHITECTURE"), ("virtualization", "RESERVE_VIRTUALIZATION_OBSERVED"),
    ("attester_revoked", "RESERVE_UNATTESTED"), ("missing_bundle", "RESERVE_UNATTESTED"),
    ("same_signer", "ATTESTER_IS_APPROVER"),
])
def test_real_collector_refusals(tmp_path, monkeypatch, mutation, symbol):
    from azazel_nexus_runtime import virtualization_observation

    from azazel_nexus.hil_records.evidence import attestation_bytes
    from azazel_nexus.operator_trust import OperatorTrust, approval_message

    trust, signer, write = collected_store(tmp_path, monkeypatch)
    if mutation == "generation":
        write("/var/lib/azazel/models/state/generations/1.json", b"{}")
    elif mutation == "catalog":
        write("/var/lib/azazel/models/trust/catalog.signed", bytes(65))
    elif mutation == "runtime":
        write(LLAMA_EXECUTABLE, b"tampered").chmod(0o750)
    elif mutation == "artifact":
        artifact = next((tmp_path / "var/lib/azazel/models/store").iterdir())
        artifact.write_bytes(b"wrong")
    elif mutation == "architecture":
        monkeypatch.setattr(loader.os, "uname", lambda: SimpleNamespace(machine="aarch64"))
    elif mutation == "virtualization":
        monkeypatch.setattr(virtualization_observation, "observe_virtualization", lambda: {"dockerenv": "observed"})
    elif mutation == "attester_revoked":
        trust = OperatorTrust(trust.public_keys, frozenset({"attester"}))
    elif mutation == "missing_bundle":
        (tmp_path / "etc/azazel/model-admission/evidence/manifest.sig").unlink()
    elif mutation == "same_signer":
        manifest_path = tmp_path / "etc/azazel/model-admission/evidence/manifest.json"
        manifest = admission.decode(manifest_path.read_bytes())
        write(loader.DIRECTORY + "/evidence/manifest.sig", signer.sign(attestation_bytes(manifest)).signature.hex().encode())
    # A legitimate synthetic request is enough to enter the collector. The
    # resulting approval is intentionally unrelated and cannot be admitted.
    kwargs, _, _ = inputs()
    store(tmp_path, kwargs)
    # Use this store's key to attribute the request; only the collector is under test.
    wrapper = admission.decode((tmp_path / "etc/azazel/model-admission/embedding.approval").read_bytes())
    wrapper["signature_hex"] = signer.sign(approval_message(
        admission.ApprovalPurpose.LOCAL_MODEL_ADMISSION, kwargs["payload"])).signature.hex()
    write(loader.DIRECTORY + "/embedding.approval", admission.canonical(wrapper))
    result = read_test(tmp_path, trust=trust)
    assert result.embedding == loader.Refused(symbol)


def test_spawn_uses_both_held_descriptors_and_rehashes_before_popen(tmp_path, monkeypatch):
    from azazel_nexus_runtime import mio_supervisor

    trust, _, write = collected_store(tmp_path, monkeypatch)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        values = loader._collect(loader.ProtectedTree(fd, os.getuid()), trust=trust,
                                  policy=None, operator="approver")
        _context, held, _entry, _provider, _host, _tested, _resources, record = values
        process = mio_supervisor.ServingProcess(record, root=Path("/"), descriptors=held)
        calls = []
        monkeypatch.setattr(mio_supervisor.subprocess, "Popen", lambda argv, **kwargs: calls.append((argv, kwargs)))
        process.start()
        argv, kwargs = calls[0]
        assert argv[0] == kwargs["executable"] == f"/proc/self/fd/{held.binary_fd}"
        assert argv[argv.index("-m") + 1] == f"/proc/self/fd/{held.model_fd}"
        assert kwargs["pass_fds"] == (held.binary_fd, held.model_fd)
        # Tampering the held inode is detected before the next mocked spawn.
        write(LLAMA_EXECUTABLE, b"tampered").chmod(0o750)
        from azazel_nexus.model_runtime import RuntimeRefused

        with pytest.raises(RuntimeRefused, match="RUNTIME_MISMATCH"):
            process.start()
        assert len(calls) == 1
        held.close()
    finally:
        os.close(fd)


@pytest.mark.parametrize("mutation", ["hardlink", "parent_symlink", "wrong_owner"])
def test_protected_walk_refuses_links_and_wrong_owner(tmp_path, mutation):
    kwargs, _, _ = inputs()
    directory = store(tmp_path, kwargs)
    owner = os.getuid()
    if mutation == "hardlink":
        os.link(directory / "embedding.approval", directory / "extra-link")
    if mutation == "parent_symlink":
        directory.rename(directory.parent / "moved")
        directory.symlink_to(directory.parent / "moved", target_is_directory=True)
    if mutation == "wrong_owner":
        owner += 1
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        reading = _read_at(fd, owner, now=NOW, trust=kwargs["trust"])
        assert reading.embedding == loader.Refused("EVIDENCE_UNPROTECTED")
    finally:
        os.close(fd)


def test_public_loader_ignores_environment_root(tmp_path, monkeypatch):
    from azazel_nexus import model_paths

    kwargs, _, _ = inputs()
    store(tmp_path, kwargs)
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(model_paths, "models_root", lambda: pytest.fail("environment model root used"))
    monkeypatch.setattr(admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)
    opened = []

    def check_root(tree, *, now):
        fd, owner = tree.root_fd, tree.owner
        assert os.fstat(fd).st_ino == os.stat("/").st_ino
        assert owner == 0
        opened.append(1)
        return loader.AdmissionReading(loader.Refused("NODE_MISMATCH"))

    monkeypatch.setattr(loader, "ProtectedTree", lambda fd, owner: SimpleNamespace(root_fd=fd, owner=owner))
    monkeypatch.setattr(loader, "_read_tree", check_root)
    assert loader.read_admissions(now=NOW).embedding == loader.Refused("NODE_MISMATCH")
    assert opened == [1]


def test_locald_refuses_record_argv_not_bound_by_evidence(tmp_path, monkeypatch):
    from azazel_nexus_runtime import mio_locald, mio_serve

    candidate = admitted_candidate()
    bad_record = replace(candidate.record, argv=(*candidate.record.argv, "--load-plugin"))
    monkeypatch.setattr(mio_serve, "LocalServer", lambda *a, **kw: pytest.fail("unbound argv reached spawn"))
    assert mio_locald.prepare_local_models([replace(candidate, record=bad_record)],
                                           staging=tmp_path, audit=lambda e: None) == ({}, [])


@pytest.mark.parametrize("failure", [None, "argv", "descriptors", "reserve", "readiness"])
def test_activation_and_locald_share_full_decision(tmp_path, monkeypatch, failure):
    from azazel_nexus_runtime import activated, mio_locald, mio_serve

    from azazel_nexus import model_runtime
    from azazel_nexus.activation import LOCAL_MODEL_PROVIDER

    candidate = admitted_candidate()
    if failure == "argv":
        candidate = replace(candidate, record=replace(candidate.record, argv=(*candidate.record.argv, "bad")))
    elif failure == "descriptors":
        candidate = replace(candidate, evidence=replace(candidate.evidence, descriptors=object()))
    elif failure == "reserve":
        candidate = replace(candidate, resources=replace(candidate.resources, envelope_mib=2000))
    elif failure == "readiness":
        monkeypatch.setattr(model_runtime, "readiness", lambda **kw: SimpleNamespace(readiness=None))
    monkeypatch.setattr(loader, "read_admissions", lambda **kw: loader.AdmissionReading(candidate, ("/test",), (1,)))
    monkeypatch.setattr(loader, "fingerprint", lambda paths: (1,))
    monkeypatch.setattr(activated, "_fetch_commissioned", lambda path: False)

    class TestServer:
        def __init__(self, *args, **kw):
            pass
        def start(self):
            pass
        def stop(self):
            pass

    monkeypatch.setattr(mio_serve, "LocalServer", TestServer)
    wired = LOCAL_MODEL_PROVIDER in activated.wired_capabilities()
    providers, _ = mio_locald.prepare_local_models([candidate], staging=tmp_path, audit=lambda e: None)
    assert wired == bool(providers) == (failure is None)


def test_request_recheck_never_hashes_content(tmp_path, monkeypatch):
    trust, _, _ = collected_store(tmp_path, monkeypatch)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        _, held, *_ = loader._collect(loader.ProtectedTree(fd, os.getuid()), trust=trust,
                                      policy=None, operator="approver")
        monkeypatch.setattr(loader, "runtime_from_fd", lambda *a, **kw: pytest.fail("request hashed binary"))
        monkeypatch.setattr(loader, "verify_artifact_fd", lambda *a, **kw: pytest.fail("request hashed model"))
        assert held.recheck() is held.binary
        os.chmod(held.model_fd, 0o600)
        with pytest.raises(loader.RuntimeRefused, match="EVIDENCE_CHANGED"):
            held.recheck()
        held.close()
    finally:
        os.close(fd)


def test_virtualization_content_changes_with_stable_fingerprint(monkeypatch):
    from azazel_nexus_runtime import virtualization_observation

    assert not any(p.startswith(("/proc", "/sys")) for p in loader._FIXED)
    candidate = admitted_candidate()
    monkeypatch.setattr(loader, "read_admissions", lambda **kw: loader.AdmissionReading(candidate))
    monkeypatch.setattr(loader, "fingerprint", lambda paths: (1,))
    from azazel_nexus.virtualization import SENSORS

    observation = [dict.fromkeys(SENSORS, "clear")]
    monkeypatch.setattr(virtualization_observation, "observe_virtualization", lambda: observation[0])
    holder = loader.AdmissionHolder(clock=lambda: NOW)
    holder.start(audit=lambda e: None)
    stops = []
    holder.refresh(withdraw=lambda: stops.append(True), audit=lambda e: None)
    assert stops == []
    observation[0] = {"sensor": "observed"}
    holder.refresh(withdraw=lambda: stops.append(True), audit=lambda e: None)
    assert stops == [True]


@pytest.mark.parametrize("enabled", [False, True])
def test_production_layers_refuse_disabled_or_missing_descriptors(tmp_path, monkeypatch, enabled):
    from azazel_nexus_runtime import mio_locald, mio_serve, mio_supervisor

    monkeypatch.setattr(admission, "LOCAL_MODEL_ADMISSION_ENABLED", enabled)
    candidate = admitted_candidate()
    candidate = replace(candidate, evidence=replace(candidate.evidence, descriptors=None))
    assert mio_locald.prepare_local_models([candidate], staging=tmp_path, audit=lambda e: None) == ({}, [])
    with pytest.raises(mio_serve.LocalServerRefused):
        mio_serve.LocalServer(candidate.record, root=Path("/"), socket_path=tmp_path / "test.sock")
    with pytest.raises(mio_supervisor.SupervisorRefused):
        mio_supervisor.ServingProcess(candidate.record, root=Path("/")).start()


def test_root_and_locald_collect_same_node_binding(tmp_path, monkeypatch):
    trust, _, _ = collected_store(tmp_path, monkeypatch)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        contexts = []
        for uid in (0, 501):
            monkeypatch.setattr(loader.os, "geteuid", lambda uid=uid: uid)
            context, held, *_ = loader._collect(loader.ProtectedTree(fd, os.getuid()),
                                               trust=trust, policy=None, operator="approver")
            contexts.append(context.bindings["node"])
            held.close()
        assert contexts[0] == contexts[1]
    finally:
        os.close(fd)


def test_e2e_reserve_cases_reach_resource_and_approval_gates(tmp_path):
    from tools.e2e_stages import _core_reserve_path

    assert "resource and approval gates" in _core_reserve_path(SimpleNamespace(root=tmp_path))


def test_local_server_rechecks_kill_switch_after_construction(tmp_path, monkeypatch):
    from azazel_nexus_runtime import mio_serve

    candidate = admitted_candidate()
    server = mio_serve.LocalServer(candidate.record, root=Path("/"), socket_path=tmp_path / "test.sock",
                                   descriptors=candidate.evidence.descriptors)
    monkeypatch.setattr(admission, "LOCAL_MODEL_ADMISSION_ENABLED", False)
    with pytest.raises(mio_serve.LocalServerRefused, match="ADMISSION_DISABLED"):
        server.start()
    with pytest.raises(mio_serve.LocalServerRefused, match="ADMISSION_DISABLED"):
        server._http("GET", "/health", b"", 1)


@pytest.mark.parametrize("root", [False, True])
@pytest.mark.parametrize("failure", [OSError, ValueError, KeyError])
def test_identity_unavailable_agrees_for_live_and_handoff(tmp_path, monkeypatch, root, failure):
    from azazel_nexus_runtime import hil_readiness, model_identity

    trust, _, _ = collected_store(tmp_path, monkeypatch)
    def unavailable():
        raise failure("private identity details")
    monkeypatch.setattr(loader.os, "geteuid", lambda: 0 if root else 999)
    monkeypatch.setattr(hil_readiness, "run_identity", unavailable)
    monkeypatch.setattr(model_identity, "read_identity", unavailable)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        tree = loader.ProtectedTree(fd, os.getuid())
        with pytest.raises(admission.ApprovalRefused, match="^NODE_IDENTITY_UNAVAILABLE$"):
            loader._collect(tree, trust=trust, policy=admission.AdmissionPolicy(
                frozenset({"approver"}), 86400, ("embedding",)), operator="approver")
    finally:
        os.close(fd)


@pytest.mark.parametrize("failure,symbol", [
    ("argv", "SETTINGS_MISMATCH"),
    ("gate", "GATE_RESOURCE_TOPOLOGY_REFUSED"),
    ("gate_symbol", "RESOURCE_FIT"),
    ("descriptor", "EVIDENCE_CHANGED"),
    ("readiness", "ARTIFACT_REFUSED"),
    ("readiness_prose", "READINESS_REFUSED"),
    ("unexpected", "PRECONDITIONS_REFUSED"),
])
def test_complete_decision_preserves_symbols_and_audits_no_prose(monkeypatch, failure, symbol):
    from azazel_nexus import model_runtime

    candidate = admitted_candidate()
    closed = []
    candidate.evidence.descriptors.close = lambda: closed.append(True)
    if failure == "argv":
        candidate = replace(candidate, record=replace(candidate.record, argv=(*candidate.record.argv, "bad")))
    elif failure == "gate":
        candidate = replace(candidate, resources=replace(candidate.resources, envelope_mib=2000))
    elif failure == "gate_symbol":
        from azazel_nexus import cognition
        monkeypatch.setattr(cognition, "admit_local_model", lambda *args, **kw: SimpleNamespace(
            admitted=False, reason="RESOURCE_FIT", failed_gate=cognition.AdmissionGate.RESOURCE_TOPOLOGY))
    elif failure in {"descriptor", "unexpected"}:
        def refuse():
            if failure == "descriptor":
                raise loader.RuntimeRefused("EVIDENCE_CHANGED")
            raise ValueError("private path and key details")
        candidate.evidence.descriptors.recheck = refuse
    else:
        monkeypatch.setattr(model_runtime, "readiness", lambda **kw: SimpleNamespace(
            readiness=model_runtime.ActivationReadiness.REFUSED,
            reason="ARTIFACT_REFUSED" if failure == "readiness" else "private path and key details"))
    reading = loader.decide_embedding_admission(now=NOW, reading=loader.AdmissionReading(candidate))
    assert reading.embedding == loader.Refused(symbol)
    assert closed == [True]
    event = reading.as_event()
    assert event["refusal"] == symbol
    assert "private" not in str(event)
    assert set(event) == {"event_type", "role", "outcome", "refusal", "approval_id", "payload_digest",
                          "model_digest", "generation_id", "catalog_digest", "reserve_record_digest"}
