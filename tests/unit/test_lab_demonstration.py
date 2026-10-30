"""Injected lab lifecycle/boundary checks; no VM or hardware evidence."""
from __future__ import annotations

import ast
import json
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lab/src"))
from azazel_nexus_lab import artifacts, cli, provision, services, unit_relocation

from azazel_nexus import lab_host


@pytest.fixture
def file_owners(monkeypatch):
    from azazel_nexus_lab import safe_files

    monkeypatch.setattr(safe_files, "expected_owner", lambda target: os.getuid())


@pytest.fixture
def marker(tmp_path, monkeypatch):
    path = tmp_path / "LAB-HOST"
    monkeypatch.setattr(lab_host, "LAB_HOST_MARKER", path)
    path.write_text("LAB\n")
    return path


def test_no_production_imports_lab_and_no_packaging_dependency():
    for base in (ROOT / "src", ROOT / "runtime/src"):
        for path in base.rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                assert not any(name.split(".")[0] == "azazel_nexus_lab" for name in names), path
    for path in (ROOT / "pyproject.toml", ROOT / "runtime/pyproject.toml", ROOT / "packaging/install.sh"):
        assert "azazel-nexus-lab" not in path.read_text()
    assert 'az-nexus-lab = "azazel_nexus_lab.cli:main"' in (ROOT / "lab/pyproject.toml").read_text()


def test_loaded_module_allowlist_refuses_lab():
    from azazel_nexus_runtime.loaded_modules import _project_modules
    from test_runtime_loaded_modules import MAIN_PATH, ROOTS, _main_module, _manifest

    from azazel_nexus.operator_trust import ApprovalRefused

    with pytest.raises(ApprovalRefused, match="lab modules refused"):
        _project_modules({"__main__": _main_module(), "azazel_nexus_lab": ModuleType("azazel_nexus_lab")},
                         _manifest(), ROOTS, MAIN_PATH)


def test_marker_is_absolute_and_removal_grants_nothing(marker, monkeypatch):
    monkeypatch.setenv("AZAZEL_ROOT", "/nonexistent/lab-root")
    assert lab_host.is_lab_host()
    marker.unlink()
    assert not lab_host.is_lab_host()
    from azazel_nexus.model_admission import LOCAL_MODEL_ADMISSION_ENABLED
    assert LOCAL_MODEL_ADMISSION_ENABLED is False
    marker.symlink_to(marker.parent / "absent")
    assert lab_host.is_lab_host()


@pytest.mark.parametrize("command", ["hil-preflight", "commission-review", "commission", "model-import-fetched"])
def test_library_cli_marker_refusal_before_inventory(marker, command, capsys):
    from azazel_nexus.cli import main

    arguments = [command]
    if command in {"commission", "commission-review"}:
        arguments += ["--operator", "lab"]
    elif command == "model-import-fetched":
        arguments += ["lab-model"]
    if command == "commission":
        arguments += ["--at", "2026-10-19T00:00:00Z"]
    assert main(arguments) == 2
    assert "LAB_HOST_MARKER" in capsys.readouterr().err


def test_setup_first_line_marks_host(marker, capsys):
    from azazel_nexus.cli import main

    main(["setup", "--next"])
    assert capsys.readouterr().out.splitlines()[0] == "LAB HOST"


def test_setup_json_stays_parseable_on_a_lab_host(marker, capsys):
    from azazel_nexus.cli import main

    main(["setup", "--json"])
    captured = capsys.readouterr()
    json.loads(captured.out)
    assert captured.err.splitlines()[0] == "LAB HOST"


@pytest.mark.parametrize("module,arguments", [
    ("hil_capture", ["hg-01"]), ("core_reserve_probe", []),
    ("model_admission_cli", ["request", "--role", "embedding"]),
])
def test_runtime_cli_marker_refusals(marker, module, arguments, capsys):
    from importlib import import_module

    assert import_module("azazel_nexus_runtime." + module).main(arguments) == 2
    assert "LAB_HOST_MARKER" in capsys.readouterr().err


def test_direct_preflight_and_reserve_refuse(marker):
    from azazel_nexus_runtime.core_reserve_probe import MeasurementRefused, measure

    from azazel_nexus.hil_preflight import evaluate

    assert evaluate(None, None, protection=None, generation=1, key=b"").missing == ("LAB_HOST_MARKER",)
    with pytest.raises(MeasurementRefused, match="LAB_HOST_MARKER"):
        measure()


def test_commission_review_and_bootstrap_publication_refuse(marker, capsys):
    from azazel_nexus_runtime.bootstrap_overlay_files import (
        _publish_verified_approval_at,
    )
    from azazel_nexus_runtime.proposal_review import run

    from azazel_nexus.commissioning_draft import DraftRefused, verify_draft_review
    from azazel_nexus.operator_trust import ApprovalRefused

    with pytest.raises(DraftRefused, match="LAB_HOST_MARKER"):
        verify_draft_review(payload=b"", signature=b"", operator="lab", trust=None, current=None)
    assert run("lab") == 2
    assert "LAB_HOST_MARKER" in capsys.readouterr().err
    with pytest.raises(ApprovalRefused, match="LAB_HOST_MARKER"):
        _publish_verified_approval_at(overlay_fd=-1, masks_fd=-1, higher_priority_fd=-1,
                                     journal_store=None, guard=None, approval=None,
                                     transaction=None, check_publish=None, owner_uid=0)


def test_ephemeral_key_permissions_and_shred(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    artifacts.create_key(key_dir)
    path = key_dir / "ephemeral.key"
    assert path.stat().st_mode & 0o777 == 0o600
    retained = path.open("rb")
    try:
        artifacts.shred_keys(key_dir)
        retained.seek(0)
        assert retained.read() == bytes(32)
        assert not key_dir.exists()
    finally:
        retained.close()


def test_shred_refuses_key_symlink(tmp_path):
    directory = tmp_path / "keys"
    directory.mkdir()
    target = tmp_path / "target"
    target.write_bytes(b"untouched")
    (directory / "key").symlink_to(target)
    with pytest.raises(OSError):
        artifacts.shred_keys(directory)
    assert target.read_bytes() == b"untouched"


def test_lab_envelopes_refused_by_production_pack_and_reserve(tmp_path):
    from azazel_nexus.core_reserve import ReserveRefused, parse_record
    from azazel_nexus.mission_pack import PACK_DOMAIN, PackRefused, inspect_media
    from azazel_nexus.signature import verify_detached

    key = SigningKey.generate()
    payload = artifacts.envelope(b"fixture only", key, "mission-pack")
    tmp_path.joinpath("mission-pack.signed").write_bytes(payload)
    key.verify_key.verify(artifacts.LAB_DOMAIN + payload[64:], payload[:64])
    assert not verify_detached(public_key=bytes(key.verify_key), message=PACK_DOMAIN + payload[64:],
                               signature=payload[:64])
    with pytest.raises(PackRefused):
        inspect_media(tmp_path)
    with pytest.raises(ReserveRefused):
        parse_record(json.dumps(artifacts.output()))


def test_producer_fixture_resigned_with_fresh_lab_key(tmp_path):
    from azazel_nexus.lite_bundle import read_anchors, verify_bundle

    key = SigningKey.generate()
    anchor = tmp_path / "anchors.toml"
    anchor.write_text(f'threshold = 1\n[keys]\n"lab" = "{bytes(key.verify_key).hex()}"\n')
    raw = artifacts.resign_fixture(provision.DATA / "lite.tar.gz", key)
    accepted = verify_bundle(raw, anchors=read_anchors(anchor), last_imported_version=0)
    assert accepted.signers == ("lab",)
    assert (provision.DATA / "lite.tar.gz").read_bytes() == (
        ROOT / "contract/azazel-knowledge-lite/lite.tar.gz").read_bytes()
    assert (provision.DATA / "azazel-baseline.json").read_bytes() == (
        ROOT / "playbooks/baseline/azazel-baseline.json").read_bytes()


def test_fixture_provisioning_has_working_real_lite_import(tmp_path):
    from azazel_nexus.lite_import import status_summary

    key = artifacts.create_key(tmp_path / "keys")
    result = provision.provision(tmp_path, key)
    reading = status_summary(root=tmp_path / "var/lib/azazel/knowledge",
                             trust_root=tmp_path / "var/lib/azazel/lite-trust", query_as_of=provision.now())
    assert result["production_pack_selection"] == "refused"
    assert reading["state"] in {"available", "stale"}, reading
    assert not (tmp_path / "etc/azazel/model-admission").exists()


def test_relocation_preserves_prefix_and_every_write_inside_root(tmp_path):
    source = (ROOT / "packaging/systemd/azazel-mio-locald.service").read_text()
    source = source.replace("ExecStartPre=+/usr/libexec/azazel/az-mio-identity\n", "")
    props = unit_relocation.parse_service(source)
    moved = unit_relocation.relocate(props, tmp_path, "azazel-mio-locald", prefix="azazel-lab-demo-")
    assert dict(moved)["RuntimeDirectory"] == "azazel-lab-demo-azazel-mio-locald"
    for key, value in moved:
        if key in unit_relocation.PATH_KEYS:
            assert Path(value.lstrip("-+")).is_relative_to(tmp_path)


@pytest.mark.parametrize("escape", ["/var/lib/azazel", "/tmp/escape", "/run/lab/../escape"])
def test_effective_relocation_escape_refused(tmp_path, escape):
    with pytest.raises(ValueError, match="outside scratch"):
        unit_relocation.assert_write_isolation(
            {"ProtectSystem": "strict", "RuntimeDirectory": "lab", "ReadWritePaths": escape},
            tmp_path, Path("/run/lab"))


def test_down_stops_before_shredding_and_keeps_marker(tmp_path, monkeypatch):
    marker = tmp_path / "LAB-HOST"
    marker.write_text("LAB")
    root = tmp_path / "demo"
    root.mkdir()
    artifacts.create_key(root / "keys")
    order = []
    monkeypatch.setattr(services, "stop", lambda root: order.append("stop"))
    original = cli.shred_keys
    monkeypatch.setattr(cli, "shred_keys", lambda directory: (order.append("shred"), original(directory)))
    cli.down(root)
    assert order == ["stop", "shred"]
    assert not root.exists()
    assert marker.exists()


def test_down_preserves_keys_if_a_unit_cannot_stop(tmp_path, monkeypatch):
    root = tmp_path / "demo"
    root.mkdir()
    artifacts.create_key(root / "keys")
    monkeypatch.setattr(services, "stop", lambda root: (_ for _ in ()).throw(ValueError("busy")))
    with pytest.raises(ValueError, match="busy"):
        cli.down(root)
    assert (root / "keys/ephemeral.key").exists()


def test_every_command_starts_with_banner_even_parser_error(capsys):
    with pytest.raises(SystemExit):
        cli.main(["unknown"])
    assert capsys.readouterr().out.startswith(artifacts.BANNER)


def test_refusal_json_has_lab_namespace_and_labels(monkeypatch, capsys, private_os):
    private_os(cli)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    assert cli.main(["up"]) == 2
    lines = capsys.readouterr().out.splitlines()
    assert lines[:2] == artifacts.BANNER.splitlines()
    doc = json.loads(lines[-1])
    assert doc["lab"] is True and doc["not_hardware_evidence"] is True
    assert doc["schema"].startswith("azazel-nexus-lab/")


def test_bilingual_scenarios_are_valid_frames():
    from azazel_nexus.local_advisory import read_frame

    paths = list((ROOT / "lab/src/azazel_nexus_lab/scenarios").glob("*.json"))
    assert len(paths) == 5
    for path in paths:
        doc = json.loads(path.read_text())
        assert doc["lab"] and doc["not_hardware_evidence"]
        frame = read_frame(doc["frame"])
        assert " / " in frame["question"]


def test_mocked_up_keeps_real_pack_refusal_visible_and_down_erases_keys(tmp_path, monkeypatch):
    root = tmp_path / "demo"
    monkeypatch.setattr(cli, "BASE", tmp_path)
    monkeypatch.setattr(cli.platform, "system", lambda: "Linux")
    monkeypatch.setattr(cli.platform, "freedesktop_os_release",
                        lambda: {"ID": "debian", "VERSION_ID": "13"})
    monkeypatch.setattr(cli, "masked_snapshot", lambda: {"authority": "unchanged"})
    monkeypatch.setattr(cli, "secure_directory", lambda *args: None)
    monkeypatch.setattr(cli, "mark_host", lambda: None)
    monkeypatch.setattr(cli, "fix_fixture_permissions", lambda root: None)
    monkeypatch.setattr(cli, "worker", lambda *args: {"exit_code": 1, "stdout": "refused lab schema"})
    monkeypatch.setattr(services, "prepare", lambda root: {})
    monkeypatch.setattr(services, "start", lambda *args: [{"unit": "mocked-real-wrapper"}])
    monkeypatch.setattr(services, "stop", lambda root: None)
    result = cli.up(root)
    assert result["state"] == "ready"
    assert result["pack_cli"]["exit_code"] == 1
    assert (root / "keys/ephemeral.key").exists()
    assert (root / "keys/revocation.key").exists()
    assert result["lab"] and result["not_hardware_evidence"]
    cli.down(root)
    assert not root.exists()


def test_partial_start_failure_stops_units_before_key_cleanup(tmp_path, monkeypatch):
    root = tmp_path / "demo"
    monkeypatch.setattr(cli, "BASE", tmp_path)
    monkeypatch.setattr(cli.platform, "system", lambda: "Linux")
    monkeypatch.setattr(cli.platform, "freedesktop_os_release",
                        lambda: {"ID": "debian", "VERSION_ID": "13"})
    monkeypatch.setattr(cli, "masked_snapshot", dict)
    monkeypatch.setattr(cli, "secure_directory", lambda *args: None)
    monkeypatch.setattr(cli, "mark_host", lambda: None)
    monkeypatch.setattr(cli, "fix_fixture_permissions", lambda root: None)
    monkeypatch.setattr(cli, "worker", lambda *args: {"exit_code": 1})
    monkeypatch.setattr(services, "prepare", lambda root: {})
    monkeypatch.setattr(services, "start", lambda *args: (_ for _ in ()).throw(ValueError("failed")))
    stopped = []
    monkeypatch.setattr(services, "stop", lambda root: stopped.append((root / "keys/ephemeral.key").exists()))
    with pytest.raises(ValueError, match="failed"):
        cli.up(root)
    assert stopped == [True]
    assert not root.exists()


@pytest.mark.parametrize("target", ["knowledge-trust", "locald", "pack-expire", "audit-tamper"])
def test_every_break_prints_unchanged_edge_snapshot(tmp_path, monkeypatch, file_owners, capsys, target):
    (tmp_path / "var/lib/azazel/lite-trust").mkdir(parents=True)
    (tmp_path / "var/lib/azazel/state/mio").mkdir(parents=True)
    (tmp_path / "var/lib/azazel/lite-trust/trust.json").write_bytes(b"original")
    (tmp_path / "var/lib/azazel/state/mio/route.jsonl").write_bytes(b"original")
    monkeypatch.setattr(cli, "masked_snapshot", lambda: {"authority": "unobserved", "lease": "unobserved"})
    monkeypatch.setattr(services, "run", lambda argv: "")
    result = cli.break_target(tmp_path, target)
    transcript = json.loads(capsys.readouterr().out)
    assert transcript["unchanged"] is True
    assert transcript["lab"] and transcript["not_hardware_evidence"]
    if target == "pack-expire":
        assert result["result"].startswith("unavailable:")


def test_audit_tamper_targets_and_audits_the_newest_route_segment(tmp_path, file_owners):
    # entryd's route ledger is daily segments (#211 S4); the lab tampers with
    # and verifies the newest one, and the whole retained chain.
    from azazel_nexus_lab.safe_files import lab_file, target_relative
    from azazel_nexus_runtime.mio_route_ledger import RouteLedger

    from azazel_nexus.audit import AuditChainBroken

    state = tmp_path / "var/lib/azazel/state/mio"
    state.mkdir(parents=True)
    assert target_relative(tmp_path, "audit-tamper") == "var/lib/azazel/state/mio/route.jsonl"
    now = [1_800_000_000.0]
    route = RouteLedger(state, clock=lambda: now[0], monotonic=lambda: now[0])
    route.append({"event_type": "a"})
    now[0] += 86400
    route.append({"event_type": "b"})
    newest = route.path
    assert target_relative(tmp_path, "audit-tamper") == (
        "var/lib/azazel/state/mio/route/" + newest.name)
    assert cli.audit(tmp_path)["ledgers"]["route"]["head"][0] == 2
    with lab_file(tmp_path, "audit-tamper", write=True) as stream:
        stream.seek(0, os.SEEK_END)
        stream.write(b'{"tampered":true}\n')
    assert newest.read_text().endswith('{"tampered":true}\n')
    with pytest.raises((AuditChainBroken, KeyError)):
        cli.audit(tmp_path)


def test_audit_tamper_detected(tmp_path):
    from azazel_nexus.audit import AuditChainBroken, AuditLedger

    route = tmp_path / "var/lib/azazel/state/mio/route.jsonl"
    AuditLedger(route).append({"event_type": "test"})
    cli.audit(tmp_path)
    with route.open("a") as stream:
        stream.write('{"tampered":true}\n')
    with pytest.raises((AuditChainBroken, KeyError)):
        cli.audit(tmp_path)


def test_production_pack_refuses_lab_domain_even_for_its_native_schema(tmp_path, monkeypatch):
    from test_mission_pack import NOW, node

    from azazel_nexus.mission_pack import MissionPack, PackRefused

    context, _, media = node.__wrapped__(tmp_path, monkeypatch)
    source = media(domain=artifacts.LAB_DOMAIN)
    with pytest.raises(PackRefused, match="invalid domain-tagged signature"):
        MissionPack(context).verify(source, now=NOW)
    assert not context.root.exists()


@pytest.mark.parametrize("schema", ["azazel-nexus-lab/mission-pack/1", "azazel-nexus-lab/bench/v1"])
def test_production_pack_refuses_lab_schema_with_native_signature(tmp_path, monkeypatch, schema):
    from test_mission_pack import NOW, node

    from azazel_nexus.mission_pack import MissionPack, PackRefused

    context, document, media = node.__wrapped__(tmp_path, monkeypatch)
    document["schema"] = schema
    with pytest.raises(PackRefused):
        MissionPack(context).verify(media(document), now=NOW)
    assert not context.root.exists()


def test_status_first_line_marks_host(marker, tmp_path, capsys):
    from azazel_nexus.cli import main

    assert main(["--sysfs", str(tmp_path), "status"]) == 0
    assert capsys.readouterr().out.splitlines()[0] == "LAB HOST"


@pytest.mark.parametrize("scenario,kind", [
    ("ssh-brute-force", "playbook"), ("port-scan", "playbook"),
    ("phishing", "playbook"), ("ransomware", "playbook"),
    ("out-of-scope", "out_of_scope"),
])
def test_lab_inprocess_real_library_rendering(scenario, kind):
    from azazel_nexus_lab.inprocess import load_frame, reference, render

    frame = load_frame(ROOT / "lab/src/azazel_nexus_lab/scenarios" / (scenario + ".json"))
    result = reference(frame)
    document = result["document"]
    assert result["retrieval"] == "keyword"
    assert "LAB-INPROCESS — 受け入れ外・サービス経路外" in render(result)
    if kind == "out_of_scope":
        assert document["outcome"] == kind
    else:
        assert document["candidate"]["kind"] == kind
        assert document["provenance"]["source"] == "keyword"
        assert document["provenance"]["model_id"] == "deterministic"
        assert any(option["kind"] == "benign" for option in document["alternatives"])
        for name in ("trusted_checks_0", "trusted_first_response_0", "trusted_missing_0"):
            assert document["fields"][name] in render(result)
        assert "テンプレート" in render(result)


def test_ask_service_reply_is_separate_and_unchanged(tmp_path, monkeypatch, capsys, private_os):
    private_os(cli)
    root = tmp_path / "demo"
    root.mkdir()
    (root / "session.json").write_text("{}")
    monkeypatch.setattr(cli, "BASE", tmp_path)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    reply = {"exit_code": 0, "stdout": json.dumps({"outcome": "handoff",
             "reason": "no_provider", "reference_status": "unavailable"}), "stderr": ""}
    monkeypatch.setattr(cli, "worker", lambda *args, **kwargs: reply)
    scenario = ROOT / "lab/src/azazel_nexus_lab/scenarios/ssh-brute-force.json"
    assert cli.main(["ask", str(scenario)]) == 0
    text = capsys.readouterr().out
    assert text.index("SERVICE PATH") < text.index("LAB-INPROCESS")
    result = json.loads(text.splitlines()[-1])
    assert result["service_path"] == reply
    assert result["lab_inprocess"]["document"]["provenance"]["retrieval"] == "keyword"


@pytest.mark.parametrize("command", ["ask", "bench"])
def test_embedding_refuses_before_worker_or_files(tmp_path, monkeypatch, capsys, command, private_os):
    private_os(cli)
    from azazel_nexus_lab.refusal import LabRefused

    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "worker", lambda *a, **k: pytest.fail("worker called"))
    args = [command, "--embedding"] + ([str(tmp_path / "absent.json")] if command == "ask" else [])
    assert cli.main(args) == 2
    refusal = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert refusal["state"] == "refused"
    assert "tests/e2e_local_inference/harness.py" in refusal["message"]
    assert "Production admission remains closed" in refusal["message"]
    assert "not an admission" in refusal["message"]
    with pytest.raises(LabRefused, match="Production admission remains closed"):
        cli.lab_reference(tmp_path, tmp_path / "absent", True)
    assert not list(tmp_path.iterdir())


def test_real_embedding_retriever_composition_uses_library_and_cache(tmp_path):
    from azazel_nexus_lab.inprocess import DATA, load_frame, reference
    from azazel_nexus_runtime.mio_embedding import EmbeddingRetriever, document_text

    from azazel_nexus.reasoning_playbook import read_library

    library = read_library(DATA.read_bytes())
    chosen = next(i for i, entry in enumerate(library.entries) if "ssh" in entry.id)
    class Server:
        calls = 0
        def start(self, **kwargs):
            pass
        def embed(self, texts, **kwargs):
            self.calls += 1
            if len(texts) == 1:
                return [[1., 0.]]
            return [[1., 0.] if text == document_text(library.entries[chosen]) else [0., 1.] for text in texts]
    server = Server()
    retriever = EmbeddingRetriever(server, model_digest="sha256:" + "a" * 64, cache_dir=tmp_path)
    frame = load_frame(ROOT / "lab/src/azazel_nexus_lab/scenarios/ssh-brute-force.json")
    result = reference(frame, retriever=retriever)
    assert result["retrieval"] == "embedding"
    assert result["document"]["candidate"]["option_id"] == library.entries[chosen].id
    assert result["document"]["provenance"]["retrieval"] == "embedding"
    calls = server.calls
    reference(frame, retriever=retriever)
    assert server.calls == calls + 1
    assert list(tmp_path.glob("*.json"))


def test_lab_does_not_edit_production_admission_or_digest_pins():
    from azazel_nexus.model_admission import LOCAL_MODEL_ADMISSION_ENABLED
    from azazel_nexus.model_runtime import LLAMA_RUNTIME_DIGESTS

    assert LOCAL_MODEL_ADMISSION_ENABLED is False
    assert LLAMA_RUNTIME_DIGESTS == {
        "aarch64": "sha256:eca8b1abbd8f7a5b121d2d0b7486829fc191736206cacf8556e878175c4ca8a6",
        "x86_64": "sha256:e1671cd4167b39b29fe34bb906f62d610b289aed19301445c4844764467fb701",
    }
    for name in ("model_admission.py", "model_runtime.py"):
        assert "azazel_nexus_lab" not in (ROOT / "src/azazel_nexus" / name).read_text()


def test_bench_schema_refused_by_production_reserve():
    from azazel_nexus_lab.bench import LABEL, SCHEMA

    from azazel_nexus.core_reserve import ReserveRefused, parse_record
    from azazel_nexus.hil_records import Status, validate_record

    document = {**artifacts.output(), "schema": SCHEMA, "banner": artifacts.BANNER,
                "performance_label": LABEL, "reserve_mib": 512}
    with pytest.raises(ReserveRefused):
        parse_record(json.dumps(document))
    assert validate_record(document).status == Status.REFUSED
    assert "unsupported versioned HIL record schema" in validate_record(document).reasons


def test_bench_measures_and_saves_only_lab_outputs(tmp_path, monkeypatch, capsys):
    from argparse import Namespace

    from azazel_nexus_lab import bench

    root = tmp_path / "demo"
    root.mkdir()
    monkeypatch.setattr(services, "stop", lambda root: None)
    monkeypatch.setattr(services, "prepare", lambda root: {})
    monkeypatch.setattr(services, "start", lambda *args: [
        {"unit": "lab-only", "active_ms": 2., "socket_ready_ms": 3.}])
    memory = {name: {"VmRSS_kib": 10, "VmHWM_kib": 11, "cgroup_memory_peak_bytes": 12000}
              for name in services.UNITS}
    monkeypatch.setattr(bench, "service_memory", lambda root: memory)
    concurrencies = []
    def rounds(root, count, concurrency):
        concurrencies.append(concurrency)
        return {"n": count, "p50_ms": 2., "p95_ms": 4., "concurrency": concurrency, "samples": []}
    monkeypatch.setattr(bench, "roundtrips", rounds)
    monkeypatch.setattr(bench, "recoveries", lambda root: [])
    args = Namespace(requests=2, duration=.001, interval=.1, embedding=False, model=None)
    result = bench.run_bench(root, args)
    assert concurrencies[:3] == [1, 2, 4]
    assert result["schema"] == "azazel-nexus-lab/bench/v1"
    assert result["keyword"]["n"] == 2
    assert result["sustained"]["samples"]
    for key in ("saved_json", "saved_summary"):
        path = Path(result[key])
        assert path.is_relative_to(root / "bench")
        assert bench.LABEL in path.read_text() and "LAB" in path.read_text()
    # main() prints the banner once; the printed summary must not repeat it,
    # while the saved summary still starts with it.
    assert artifacts.BANNER not in capsys.readouterr().out
    assert Path(result["saved_summary"]).read_text().startswith(artifacts.BANNER)
    stored = json.loads(Path(result["saved_json"]).read_text())
    assert stored["not_hardware_evidence"] is True


def test_bench_refuses_symlink_output(tmp_path):
    from argparse import Namespace

    from azazel_nexus_lab.bench import run_bench

    (tmp_path / "bench").symlink_to(tmp_path.parent, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        run_bench(tmp_path, Namespace(requests=1, duration=1, interval=1))


def test_recovery_observes_refusal_and_restores_each_break(tmp_path, monkeypatch, file_owners):
    from azazel_nexus_lab import bench

    paths = [tmp_path / relative for relative in (
        "var/lib/azazel/lite-trust/trust.json", "var/lib/azazel/state/mio/route.jsonl")]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"original")
    monkeypatch.setattr(services, "stop", lambda root: None)
    monkeypatch.setattr(services, "prepare", lambda root: {})
    monkeypatch.setattr(services, "start", lambda *args: [])
    monkeypatch.setattr(cli, "masked_snapshot", dict)
    monkeypatch.setattr(services, "run", lambda argv: "")
    monkeypatch.setattr(cli, "worker", lambda *args: {"exit_code": 0, "stdout": "{}"})
    monkeypatch.setattr(cli, "audit", lambda root: (_ for _ in ()).throw(ValueError("refused")))
    result = bench.recoveries(tmp_path)
    assert [row["target"] for row in result] == ["knowledge-trust", "locald", "audit-tamper"]
    assert [row["state"] for row in result] == ["stable_refused", "stable_handoff_or_refusal", "stable_refused"]
    assert all(path.read_bytes() == b"original" for path in paths)


def test_recovery_ignores_the_advancing_route_ledger_position(tmp_path, monkeypatch, file_owners):
    # entryd's reply carries ledger_seq, which advances on every request. The
    # VM run timed out because otherwise identical handoffs never compared equal.
    import itertools

    from azazel_nexus_lab import bench

    for relative in ("var/lib/azazel/lite-trust/trust.json", "var/lib/azazel/state/mio/route.jsonl"):
        (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / relative).write_bytes(b"original")
    sequence = itertools.count(1)
    monkeypatch.setattr(services, "stop", lambda root: None)
    monkeypatch.setattr(services, "prepare", lambda root: {})
    monkeypatch.setattr(services, "start", lambda *args: [])
    monkeypatch.setattr(cli, "masked_snapshot", dict)
    monkeypatch.setattr(services, "run", lambda argv: "")
    monkeypatch.setattr(cli, "worker", lambda *args: {"exit_code": 0, "stdout": json.dumps(
        {"ledger_seq": next(sequence), "outcome": "refused", "reference_status": "unavailable"})})
    monkeypatch.setattr(cli, "audit", lambda root: (_ for _ in ()).throw(ValueError("refused")))
    monkeypatch.setattr(bench.time, "sleep", lambda seconds: None)
    result = bench.recoveries(tmp_path)
    locald = result[1]
    assert locald["state"] == "stable_handoff_or_refusal"
    assert len(locald["observations"]) == 3
    assert "ledger_seq" in locald["observations"][0]["stdout"]


def test_ask_freezes_frame_before_service_and_inprocess(tmp_path, monkeypatch, capsys, private_os):
    private_os(cli)
    root = tmp_path / "demo"
    root.mkdir()
    (root / "session.json").write_text("{}")
    scenario = tmp_path / "scenario.json"
    source = ROOT / "lab/src/azazel_nexus_lab/scenarios/ssh-brute-force.json"
    scenario.write_bytes(source.read_bytes())
    original = json.loads(source.read_text())["frame"]
    monkeypatch.setattr(cli, "BASE", tmp_path)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    def exchange(root, operation, *, payload):
        assert operation == "ask-frame" and payload == original
        scenario.write_text("{}")
        return {"exit_code": 0, "stdout": "{}", "stderr": ""}
    monkeypatch.setattr(cli, "worker", exchange)
    assert cli.main(["ask", str(scenario)]) == 0
    result = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert result["lab_inprocess"]["document"]["candidate"]["option_id"] == "auth-ssh-brute-force"


def test_bench_roundtrips_keep_errors_as_samples(tmp_path, monkeypatch):
    from azazel_nexus_lab.bench import roundtrips

    rows = [{"ms": 1., "status": {"outcome": "handoff", "reference_status": "unavailable"}},
            {"ms": 4., "status": {"error_type": "TimeoutError"}}]
    def worker(root, operation, *args):
        assert operation == "roundtrips" and args[1:] == (2, 4)
        return {"exit_code": 0, "stdout": json.dumps(rows)}
    monkeypatch.setattr(cli, "worker", worker)
    result = roundtrips(tmp_path, 2, 4)
    assert result["p50_ms"] == 2.5 and result["p95_ms"] == 4.
    assert result["samples"] == rows


def test_bench_knowledge_probe_uses_real_status_socket_contract(tmp_path, monkeypatch, capsys, private_os):
    from types import SimpleNamespace

    from azazel_nexus_lab import worker
    private_os(worker)
    from azazel_nexus_runtime import mio_socket_client

    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["worker", "knowledge-status"])
    monkeypatch.setattr(worker.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=1234))
    gids = []
    monkeypatch.setattr(worker.os, "setegid", gids.append)
    def exchange(socket, owner, verb, arguments, *, deadline_s):
        assert (socket, owner, verb, arguments) == ("knowledge", "azknowledge", "knowledge.status", {})
        assert deadline_s == 3
        return {"state": "unavailable"}
    monkeypatch.setattr(mio_socket_client, "_exchange", exchange)
    assert worker.main() == 0
    assert gids == [1234]
    assert json.loads(capsys.readouterr().out) == {"state": "unavailable"}


def test_bench_refusal_is_still_labelled_software_performance(monkeypatch, capsys, private_os):
    private_os(cli)
    from azazel_nexus_lab.bench import LABEL, SCHEMA

    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    assert cli.main(["bench"]) == 2
    text = capsys.readouterr().out
    assert text.startswith(artifacts.BANNER) and LABEL in text
    refusal = json.loads(text.splitlines()[-1])
    assert refusal["schema"] == SCHEMA
    assert refusal["banner"] == artifacts.BANNER and refusal["performance_label"] == LABEL


def test_lab_has_no_production_serving_adapters_or_admission_callbacks():
    # Permit only refusal exception imports from serving modules. This catches
    # serving aliases/monkeypatches and prevents indirect subclasses as well.
    forbidden = ("azazel_nexus_runtime.mio_serve", "azazel_nexus_runtime.mio_supervisor",
                 "azazel_nexus_runtime.mio_local", "azazel_nexus_runtime.mio_entryd")
    for path in (ROOT / "lab/src/azazel_nexus_lab").rglob("*.py"):
        tree = ast.parse(path.read_text())
        exception_aliases = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if any((node.module or "").startswith(name) for name in forbidden):
                    assert all(alias.name == "SupervisorRefused" for alias in node.names), path
                    exception_aliases.update(alias.asname or alias.name for alias in node.names)
                assert node.module != "azazel_nexus_runtime", path
            elif isinstance(node, ast.Import):
                assert not any(alias.name.startswith(forbidden) or alias.name == "azazel_nexus_runtime"
                               for alias in node.names), path
            elif isinstance(node, ast.keyword) and node.arg and "admi" in node.arg:
                assert not isinstance(node.value, ast.Lambda), path
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                if isinstance(value, ast.Lambda):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    assert not any("admi" in ast.unparse(target) for target in targets), path
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                assert not any(isinstance(base, ast.Name) and base.id in exception_aliases
                               for base in node.bases), path


def test_worker_uses_installed_package_in_isolated_interpreter(tmp_path, monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "hostile"))
    monkeypatch.setenv("PYTHONHOME", str(tmp_path / "hostile"))
    monkeypatch.setenv("LD_PRELOAD", "hostile.so")
    def run(argv, **kwargs):
        assert argv == [sys.executable, "-I", "-B", "-m", "azazel_nexus_lab.worker", "status"]
        assert kwargs["cwd"] == "/"
        assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "AZAZEL_ROOT": str(tmp_path)}
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")
    monkeypatch.setattr(cli.subprocess, "run", run)
    assert cli.worker(tmp_path, "status")["exit_code"] == 0


def test_mark_host_failure_removes_root_and_allows_retry(tmp_path, monkeypatch):
    root = tmp_path / "demo"
    monkeypatch.setattr(cli, "BASE", tmp_path)
    monkeypatch.setattr(cli.platform, "system", lambda: "Linux")
    monkeypatch.setattr(cli.platform, "freedesktop_os_release", lambda: {"ID": "debian", "VERSION_ID": "13"})
    monkeypatch.setattr(cli, "masked_snapshot", dict)
    monkeypatch.setattr(cli, "secure_directory", lambda *a: None)
    def fail_marker():
        assert root.is_dir() and not list(root.iterdir())
        raise ValueError("marker failed")
    monkeypatch.setattr(cli, "mark_host", fail_marker)
    monkeypatch.setattr(services, "prepare", lambda root: pytest.fail("provisioned before marker"))
    for _ in range(2):
        with pytest.raises(ValueError, match="marker failed"):
            cli.up(root)
        assert not root.exists()


@pytest.mark.parametrize("target", ["knowledge-trust", "audit-tamper"])
@pytest.mark.parametrize("attack", ["symlink", "parent-symlink", "hardlink", "owner", "fifo"])
def test_break_refuses_unsafe_file(tmp_path, monkeypatch, file_owners, target, attack):
    from azazel_nexus_lab import safe_files
    from azazel_nexus_lab.refusal import LabRefused

    path = tmp_path / safe_files.FILES[target][0]
    path.parent.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.write_bytes(b"untouched")
    if attack == "symlink":
        path.symlink_to(victim)
    elif attack == "parent-symlink":
        path.parent.rmdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / path.name).write_bytes(b"untouched")
        path.parent.symlink_to(outside, target_is_directory=True)
    elif attack == "hardlink":
        os.link(victim, path)
    elif attack == "fifo":
        os.mkfifo(path)
    else:
        path.write_bytes(b"untouched")
        monkeypatch.setattr(safe_files, "expected_owner", lambda target: os.getuid() + 1)
    monkeypatch.setattr(cli, "masked_snapshot", dict)
    stopped = []
    monkeypatch.setattr(services, "run", lambda argv: stopped.append(argv))
    with pytest.raises(LabRefused, match="LAB:"):
        cli.break_target(tmp_path, target)
    assert victim.read_bytes() == b"untouched"
    if attack in {"owner", "parent-symlink"}:
        assert path.read_bytes() == b"untouched"
    if target == "audit-tamper":
        assert stopped == [["systemctl", "stop", services.prefix(tmp_path) + "azazel-mio-entryd.service"]]


def test_bench_restore_refuses_planted_symlink(tmp_path, monkeypatch, file_owners):
    from azazel_nexus_lab import bench, safe_files
    from azazel_nexus_lab.refusal import LabRefused

    path = tmp_path / safe_files.FILES["knowledge-trust"][0]
    path.parent.mkdir(parents=True)
    path.write_bytes(b"original")
    victim = tmp_path / "victim"
    victim.write_bytes(b"untouched")
    events = []
    monkeypatch.setattr(services, "stop", lambda root: events.append("stop"))
    monkeypatch.setattr(services, "prepare", lambda root: {})
    monkeypatch.setattr(services, "start", lambda *a: events.append("start") or [])
    monkeypatch.setattr(bench, "service_memory", lambda root: {})
    monkeypatch.setattr(cli, "worker", lambda *a: {"exit_code": 0, "stdout": "{}"})
    def plant(root, target):
        path.unlink()
        path.symlink_to(victim)
        print("{}")
    monkeypatch.setattr(cli, "break_target", plant)
    with pytest.raises(LabRefused, match="LAB:"):
        bench.recoveries(tmp_path)
    # The refused restore still restarts the lab rather than leaving it stopped.
    assert events == ["stop", "start", "stop", "start"]
    assert victim.read_bytes() == b"untouched"


def test_mark_host_os_error_is_a_lab_refusal_with_a_reason(monkeypatch):
    from azazel_nexus_lab.refusal import LabRefused

    def denied(*args):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(cli, "secure_directory", denied)
    with pytest.raises(LabRefused, match="LAB: host marker .* could not be written \\(EACCES\\)"):
        cli.mark_host()
