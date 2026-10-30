"""Injected offline lifecycle evidence; no measurement or live activation claim."""
from __future__ import annotations

import ast
import io
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from azazel_nexus import mission_pack as mp
from azazel_nexus.activation import ActivationController, RecordingUnitController
from azazel_nexus.audit import AuditLedger
from azazel_nexus.cli import main
from azazel_nexus.compatibility import HostFacts, TestedTuple, TestedTupleSet
from azazel_nexus.core_reserve import CoreReserve
from azazel_nexus.edge_package import inspect as inspect_edge
from azazel_nexus.generation import GenerationStore
from azazel_nexus.resource_profile import ResourceProfile, ResourceReading

NOW = "2026-10-18T00:00:00Z"
ACTOR = "test-operator"
D = "sha256:" + "a" * 64


@pytest.fixture
def node(tmp_path, monkeypatch):
    key = SigningKey.generate()
    assets = {}
    components = []
    for kind in ("adapter", "policy", "runbook", "reasoning_playbook", "deception_asset"):
        raw = (kind + " installed data").encode()
        path = tmp_path / (kind + ".data")
        path.write_bytes(raw)
        assets[(kind, kind, mp.digest(raw))] = mp.InstalledAsset(path, mp.digest(raw), len(raw), "1.0.0", 5)
        components.append({"kind": kind, "id": kind, "digest": mp.digest(raw), "size_bytes": len(raw),
                               "version": "1.0.0"})
    tested = TestedTuple(
        component_digest=components[1]["digest"], adapter_digest=components[0]["digest"],
        renderer_digest=D, toolchain_digest=D, os_abi="debian13", architecture="x86_64",
        fabric_version="0.9.0", profile=ResourceProfile.LITE, overlay_schema="1.0.0",
        security_epoch=3, max_rollback_version="1.0.0")
    host = HostFacts("debian13", "x86_64", frozenset(), "0.9.0", frozenset(), frozenset(),
                     ResourceProfile.LITE, "1.0.0", 3)
    ctx = mp.PackContext(
        root=tmp_path / "encrypted" / "packs", trusted_keys={"fixture": bytes(key.verify_key)},
        signing_epoch=3, revoked_keys=frozenset(), revoked_packs=frozenset(), host=host,
        tuples=TestedTupleSet.of([tested]), resources=ResourceReading(16095, ResourceProfile.LITE),
        reserve_path=tmp_path / "no-measurement.json", host_digest=D, commissioning_digest=D,
        assets=assets, allowed_features=frozenset({"advice"}))
    # Explicit injected gate result. No measured record is written or packaged.
    reserve = CoreReserve(ResourceProfile.LITE, 2048, D, "injected-test", 1000, 1000)
    monkeypatch.setattr(mp, "load_reserve", lambda path: reserve)
    document = {"schema": mp.MANIFEST_SCHEMA, "pack_version": "1.0.0", "signer": "fixture",
                    "signing_epoch": 3, "issued_at": "2026-10-01T00:00:00Z",
                    "expires_at": "2026-11-01T00:00:00Z", "rollback_predecessor": None,
                    "features": ["advice"], "compatibility": tested.as_record(), "memory_need_mib": 100,
                    "total_size_bytes": sum(c["size_bytes"] for c in components), "components": components}

    def media(doc=None, *, domain=mp.PACK_DOMAIN):
        doc = document if doc is None else doc
        raw = mp.canonical(doc)
        signed = key.sign(domain + raw).signature + raw
        path = tmp_path / ("media-" + mp.digest(signed)[7:])
        path.mkdir(exist_ok=True)
        (path / "mission-pack.signed").write_bytes(signed)
        return path

    return ctx, document, media


def stage_activate(service, media):
    staged = service.stage(media, now=NOW, actor=ACTOR)
    service.activate(staged["staged_generation"], now=NOW, actor=ACTOR, reason="reviewed")
    return staged["staged_generation"]


def second(service, doc, media):
    newer = json.loads(mp.canonical(doc))
    newer.update(pack_version="2.0.0", rollback_predecessor=service.status()["pack_digest"])
    return media(newer)


def test_whole_signed_selection_stage_review_activate_rollback(node):
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    first = media()
    assert mp.inspect_media(first)["verified"] is False
    verified = service.verify(first, now=NOW)
    assert not ctx.root.exists()
    a = stage_activate(service, first)
    b = stage_activate(service, second(service, doc, media))
    assert b > a
    before = service.status()
    service.rollback(now=NOW, actor=ACTOR, reason="operator reversal", dry_run=True)
    assert service.status() == before
    result = service.rollback(now=NOW, actor=ACTOR, reason="operator reversal")
    assert result["generation"] > b
    assert result["pack_digest"] == verified.pack_digest
    assert service.store.verify(result["generation"]).rolled_back_from == b
    events = [e.event for e in service.ledger]
    assert events[-1]["reason"] == "operator reversal"
    assert events[-1]["from_generation"] == b
    assert events[-1]["to_generation"] == result["generation"]
    assert events[-1]["pack_digest"] == verified.pack_digest
    assert "fixture" not in (ctx.root / "audit.jsonl").read_text()
    assert "installed data" not in (ctx.root / "audit.jsonl").read_text()
    service.ledger.verify()


@pytest.mark.parametrize("operation", ["verify", "stage"])
def test_readonly_and_dry_run_write_nothing(node, operation):
    ctx, _, media = node
    service = mp.MissionPack(ctx)
    if operation == "verify":
        service.verify(media(), now=NOW)
    else:
        service.stage(media(), now=NOW, actor=ACTOR, dry_run=True)
    assert not ctx.root.exists()


@pytest.mark.parametrize("change,reason", [
    ({"expires_at": "2026-10-02T00:00:00Z"}, "expired"),
    ({"issued_at": "2026-10-20T00:00:00Z"}, "not yet valid"),
    ({"signing_epoch": 2}, "epoch"),
    ({"rollback_predecessor": D}, "predecessor"),
    ({"features": ["enforcement"]}, "feature"),
    ({"memory_need_mib": 20000}, "envelope"),
    ({"memory_need_mib": 0}, "requirements"),
    ({"total_size_bytes": 1}, "size"),
    ({"schema": "fabric/imaginary/1"}, "schema"),
    ({"network": {}}, "fields"),
    ({"trusted_keys": {}}, "fields"),
    ({"pack_version": "*"}, "version"),
])
def test_preflight_failures_leave_no_staging(node, change, reason):
    ctx, doc, media = node
    bad = dict(doc, **change)
    with pytest.raises(mp.PackRefused, match=reason):
        mp.MissionPack(ctx).stage(media(bad), now=NOW, actor=ACTOR)
    assert not ctx.root.exists()


@pytest.mark.parametrize("kind", ["installer", "systemd_unit", "privileged_container", "shell_hook",
                                 "network_topology", "edge_enforcement", "trust_anchor", "unknown"])
def test_allowlist_rejects_code_and_authority_before_writes(node, kind):
    ctx, doc, media = node
    bad = json.loads(mp.canonical(doc))
    bad["components"].append(dict(bad["components"][0], kind=kind))
    bad["total_size_bytes"] += bad["components"][-1]["size_bytes"]
    with pytest.raises(mp.PackRefused, match="allowlisted"):
        mp.MissionPack(ctx).stage(media(bad), now=NOW, actor=ACTOR)
    assert not ctx.root.exists()


@pytest.mark.parametrize("mode", ["key", "pack", "signature", "domain", "asset_hash", "asset_size",
                                  "adapter", "incompatible", "security_epoch", "oversized", "disk",
                                  "hg05", "profile", "reserve_host", "reserve_profile"])
def test_local_gates_refuse_before_any_staging(node, monkeypatch, mode):
    ctx, doc, media = node
    source = media()
    if mode == "key":
        ctx = replace(ctx, revoked_keys=frozenset({"fixture"}))
    elif mode == "pack":
        ctx = replace(ctx, revoked_packs=frozenset({mp.digest((source / "mission-pack.signed").read_bytes())}))
    elif mode == "signature":
        path = source / "mission-pack.signed"
        raw = path.read_bytes()
        path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
    elif mode == "domain":
        source = media(domain=b"azazel-nexus/model-catalog/v1\x00")
    elif mode in {"asset_hash", "asset_size"}:
        asset = ctx.assets[("policy", "policy", doc["components"][1]["digest"])]
        asset.path.write_bytes(b"x" * (asset.size_bytes + (mode == "asset_size")))
    elif mode == "adapter":
        doc = json.loads(mp.canonical(doc))
        doc["components"][0]["digest"] = D
        source = media(doc)
    elif mode == "incompatible":
        ctx = replace(ctx, host=replace(ctx.host, os_abi="other"))
    elif mode == "security_epoch":
        ctx = replace(ctx, host=replace(ctx.host, security_epoch=2))
    elif mode == "oversized":
        ctx = replace(ctx, max_selected_bytes=1)
    elif mode == "disk":
        ctx = replace(ctx, disk_headroom_bytes=10**30)
    elif mode == "hg05":
        from azazel_nexus.core_reserve import load_reserve
        monkeypatch.setattr(mp, "load_reserve", load_reserve)
    elif mode == "profile":
        ctx = replace(ctx, resources=ResourceReading(32768, ResourceProfile.STANDARD))
    else:
        reserve = CoreReserve(ResourceProfile.CORE if mode == "reserve_profile" else ResourceProfile.LITE,
                              2048, D if mode == "reserve_profile" else "other", "test", 1, 1)
        monkeypatch.setattr(mp, "load_reserve", lambda path: reserve)
    with pytest.raises(mp.PackRefused):
        mp.MissionPack(ctx).stage(source, now=NOW, actor=ACTOR)
    assert not ctx.root.exists()


@pytest.mark.parametrize("step", ["prechecked", "before_generation", "generation_published", "stage_audited",
                                  "before_intent", "intent_durable", "pointer_prepared", "pointer_replaced",
                                  "pointer_durable", "completion_audited"])
@pytest.mark.parametrize("previous", [False, True])
def test_interrupt_at_every_lifecycle_boundary(node, step, previous):
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    old = None
    source = media()
    if previous:
        old = stage_activate(service, source)
        source = second(service, doc, media)

    def interrupt(at):
        if at == step:
            raise KeyboardInterrupt(at)

    service.checkpoint = interrupt
    with pytest.raises(KeyboardInterrupt):
        staged = service.stage(source, now=NOW, actor=ACTOR)
        service.activate(staged["staged_generation"], now=NOW, actor=ACTOR, reason="reviewed")
    recovered = mp.MissionPack(ctx)
    current = recovered.current()
    if current:
        tree = recovered.store.read_tree(current.number)
        assert set(tree) == {"mission-pack.signed", "admission.json"}
        expected = mp.digest((source / "mission-pack.signed").read_bytes())
        assert recovered.status()["pack_digest"] in {expected, mp.digest((media() / "mission-pack.signed").read_bytes())}
        assert current.number == old or step in {"pointer_replaced", "pointer_durable", "completion_audited"}
    else:
        assert not previous
        assert recovered.status()["fallback"] == "CORE (no previous provider)"
    recovered.ledger.verify()


def test_generation_slice_failures_never_move_active_pointer(node, monkeypatch):
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    stage_activate(service, media())
    before = service.status()
    from azazel_nexus import generation
    original = generation._write_private
    calls = 0

    def fail(path, data):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected mid-tree failure")
        original(path, data)

    monkeypatch.setattr(generation, "_write_private", fail)
    with pytest.raises(generation.GenerationRefused):
        service.stage(second(service, doc, media), now=NOW, actor=ACTOR)
    assert service.status() == before


def test_unadmitted_or_tampered_staging_cannot_activate(node):
    ctx, _, media = node
    service = mp.MissionPack(ctx, checkpoint=lambda step: (_ for _ in ()).throw(KeyboardInterrupt())
                             if step == "generation_published" else None)
    with pytest.raises(KeyboardInterrupt):
        service.stage(media(), now=NOW, actor=ACTOR)
    with pytest.raises(mp.PackRefused, match="admission audit"):
        service.activate(1, now=NOW, actor=ACTOR, reason="not admitted")
    assert service.current() is None


def test_activation_rechecks_trust_and_leaves_prior_usable(node):
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    stage_activate(service, media())
    before = service.status()
    staged = service.stage(second(service, doc, media), now=NOW, actor=ACTOR)
    revoked = mp.MissionPack(replace(ctx, revoked_keys=frozenset({"fixture"})))
    with pytest.raises(mp.PackRefused, match="revoked"):
        revoked.activate(staged["staged_generation"], now=NOW, actor=ACTOR, reason="reviewed")
    assert service.status() == before
    service.store.verify(service.current().number)


def test_rollback_revalidates_retained_pack_and_floor(node):
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    stage_activate(service, media())
    predecessor = service.status()["pack_digest"]
    newer = json.loads(mp.canonical(doc))
    newer.update(pack_version="2.0.0", rollback_predecessor=predecessor)
    tested = replace(ctx.tuples.tuples[0], max_rollback_version="2.0.0")
    newer["compatibility"] = tested.as_record()
    service = mp.MissionPack(replace(ctx, tuples=TestedTupleSet.of([*ctx.tuples.tuples, tested])))
    before = service.status()
    with pytest.raises(mp.PackRefused, match="floor"):
        service.stage(media(newer), now=NOW, actor=ACTOR)
    assert service.status() == before
    assert len(service.store.numbers()) == 1
    newer["compatibility"] = ctx.tuples.tuples[0].as_record()
    stage_activate(service, media(newer))
    before = service.status()
    revoked = mp.MissionPack(replace(service.context, revoked_packs=frozenset({predecessor})))
    with pytest.raises(mp.PackRefused, match="revoked"):
        revoked.rollback(now=NOW, actor=ACTOR, reason="revoked target")
    assert service.status() == before


def test_edge_authority_and_activation_controller_unchanged(node, tmp_path):
    ctx, doc, media = node
    units = RecordingUnitController()
    controller = ActivationController(units=units, generations=GenerationStore(tmp_path / "edge-generations"),
                                      ledger=AuditLedger(tmp_path / "edge-audit"))
    root = tmp_path / "absent-edge"
    baseline = inspect_edge(root)
    definitions = controller.definitions
    service = mp.MissionPack(ctx)
    stage_activate(service, media())
    assert inspect_edge(root) == baseline
    stage_activate(service, second(service, doc, media))
    service.rollback(now=NOW, actor=ACTOR, reason="authority stays outside")
    assert inspect_edge(root) == baseline
    assert units.calls == []
    assert controller.definitions == definitions
    assert not controller.generations.root.exists()
    assert not controller.ledger.path.exists()


def test_static_no_network_acquisition_or_runtime_path():
    root = Path(mp.__file__).parent
    banned = {"socket", "ssl", "http", "urllib", "subprocess", "requests", "httpx",
              "azazel_nexus_runtime", "model_acquisition", "model_fetch", "runtime"}
    for path in root.glob("mission_pack*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else (
                [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
            assert not {part for name in names for part in name.split(".")} & banned


@pytest.mark.parametrize("operation", ["inspect", "verify", "stage", "activate", "rollback"])
def test_cli_operations_dry_run(node, monkeypatch, operation):
    ctx, doc, media = node
    from azazel_nexus import mission_pack_cli
    monkeypatch.setattr(mission_pack_cli, "_context", lambda: ctx)
    monkeypatch.setattr("azazel_nexus.cli._now", lambda: NOW)
    source = media()
    service = mp.MissionPack(ctx)
    args = ["pack", operation, "--dry-run"]
    if operation in {"inspect", "verify", "stage"}:
        args.append(str(source))
    else:
        stage_activate(service, source)
        staged = service.stage(second(service, doc, media), now=NOW, actor=ACTOR)
        if operation == "activate":
            args.append(str(staged["staged_generation"]))
        else:
            service.activate(staged["staged_generation"], now=NOW, actor=ACTOR, reason="reviewed")
        args += ["--reason", "test"]
    if operation in {"stage", "activate", "rollback"}:
        args += ["--actor", ACTOR]
    before = {str(p): p.read_bytes() for p in ctx.root.rglob("*") if p.is_file()}
    out = io.StringIO()
    assert main(args, out=out) == 0, out.getvalue()
    assert before == {str(p): p.read_bytes() for p in ctx.root.rglob("*") if p.is_file()}


def test_media_rejects_payloads_symlinks_and_duplicate_manifest_fields(node):
    ctx, _, media = node
    source = media()
    (source / "install.sh").write_text("#!/bin/sh")
    with pytest.raises(mp.PackRefused, match="no payload"):
        mp.MissionPack(ctx).verify(source, now=NOW)
    (source / "install.sh").unlink()
    path = source / "mission-pack.signed"
    original = source.parent / "elsewhere"
    shutil.move(path, original)
    path.symlink_to(original)
    with pytest.raises(OSError):
        mp.MissionPack(ctx).stage(source, now=NOW, actor=ACTOR)
    assert not ctx.root.exists()


@pytest.mark.parametrize("step", ["rollback_generation_published", "before_intent", "intent_durable",
                                  "pointer_prepared", "pointer_replaced", "pointer_durable",
                                  "completion_audited"])
def test_rollback_interruption_keeps_complete_old_or_restored_selection(node, step):
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    stage_activate(service, media())
    original = service.status()["pack_digest"]
    stage_activate(service, second(service, doc, media))
    previous = service.status()["pack_digest"]

    def interrupt(at):
        if at == step:
            raise KeyboardInterrupt(at)

    service.checkpoint = interrupt
    with pytest.raises(KeyboardInterrupt):
        service.rollback(now=NOW, actor=ACTOR, reason="injected reversal")
    recovered = mp.MissionPack(ctx)
    assert recovered.status()["pack_digest"] in {previous, original}
    assert recovered.status()["pack_digest"] == (original if step in {
        "pointer_replaced", "pointer_durable", "completion_audited"} else previous)
    recovered.store.verify(recovered.current().number)
    recovered.ledger.verify()


@pytest.mark.parametrize("field,value", [
    ("expires_at", "2026-10-01T00:00:00Z"), ("signing_epoch", 2),
    ("rollback_predecessor", None), ("features", ["enforcement"]),
    ("memory_need_mib", 20000),
])
def test_rejected_update_retains_exact_previous_selection(node, field, value):
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    stage_activate(service, media())
    before = service.status()
    current_tree = service.store.read_tree(service.current().number)
    newer = json.loads(mp.canonical(doc))
    newer.update(pack_version="2.0.0", rollback_predecessor=before["pack_digest"])
    newer[field] = value
    with pytest.raises(mp.PackRefused):
        service.stage(media(newer), now=NOW, actor=ACTOR)
    assert service.status() == before
    assert service.store.read_tree(service.current().number) == current_tree
    service.store.verify(service.current().number)


@pytest.mark.parametrize("fail_at", [1, 2, 3])
def test_every_generation_file_write_interruption_keeps_first_install_core(node, monkeypatch, fail_at):
    ctx, _, media = node
    from azazel_nexus import generation
    original = generation._write_private
    count = 0

    def interrupt(path, raw):
        nonlocal count
        count += 1
        original(path, raw)
        if count == fail_at:
            raise KeyboardInterrupt("power loss after file sync")

    monkeypatch.setattr(generation, "_write_private", interrupt)
    service = mp.MissionPack(ctx)
    with pytest.raises(KeyboardInterrupt):
        service.stage(media(), now=NOW, actor=ACTOR)
    assert service.store.numbers() == ()
    assert service.status()["fallback"] == "CORE (no previous provider)"


def _lite_slice(tmp_path, *, fixture: bool):
    """A commissioned Lite slice holding one admitted bundle.

    ``fixture`` uses the producer's published fixture (anchor and bundle), a
    commissioned anchor only on a marked lab host (lab_keys). Otherwise the
    bundle is signed by a key generated here, as a site signer would.
    """
    import hashlib

    from test_lite_bundle import _manifest, _tar

    from azazel_nexus.lite_import import CommissionedLite, LiteImport

    lite_root = tmp_path / "lite"
    (lite_root / "trust").mkdir(parents=True)
    (lite_root / "inbox").mkdir()
    if fixture:
        contract = Path(__file__).resolve().parents[2] / "contract" / "azazel-knowledge-lite"
        shutil.copyfile(contract / "anchors.toml", lite_root / "trust" / "anchors.toml")
        shutil.copyfile(contract / "lite.tar.gz", lite_root / "inbox" / "lite.tar.gz")
    else:
        signer = SigningKey.generate()
        (lite_root / "trust" / "anchors.toml").write_text(
            f'threshold = 1\n[keys]\n"site" = "{signer.verify_key.encode().hex()}"\n')
        tables = {"tables/attack_technique.jsonl": json.dumps(
            {"technique_id": "T1110", "name": "Brute Force",
             "agg_next_expiry": "2027-01-01T00:00:00Z"}).encode() + b"\n"}
        manifest = json.dumps({**_manifest(bundle_version=5), "files": {
            path: hashlib.sha256(body).hexdigest() for path, body in tables.items()}},
            indent=2, sort_keys=True).encode()
        signature = signer.sign(manifest).signature.hex()
        (lite_root / "inbox" / "lite.tar.gz").write_bytes(_tar(
            {"manifest.json": manifest, "manifest.sig": f"site:{signature}\n".encode(), **tables}))
    lite = LiteImport(CommissionedLite(lite_root))
    assert lite.import_entry(lite.list_inbox()[0].entry_id, now=NOW).admitted
    accepted = lite._admitted_bundle()
    lite_path = lite.commissioned.admitted / "current.tar.gz"
    asset = mp.InstalledAsset(lite_path, accepted.bundle_digest, lite_path.stat().st_size,
                              str(accepted.bundle_version))
    return lite, asset


def _with_lite(ctx, doc, lite, lite_asset):
    assets = dict(ctx.assets)
    assets[("knowledge_lite", "lite", lite_asset.digest)] = lite_asset
    newer = json.loads(mp.canonical(doc))
    newer["components"].append({"kind": "knowledge_lite", "id": "lite", "digest": lite_asset.digest,
                                "size_bytes": lite_asset.size_bytes, "version": lite_asset.version})
    newer["total_size_bytes"] += lite_asset.size_bytes
    return replace(ctx, assets=assets, lite=lite), newer


def test_real_model_and_lite_slices_are_reused_and_not_reimported(node, tmp_path):
    from azazel_nexus.model_catalog import (
        CATALOG_DOMAIN,
        CATALOG_FILENAME,
        ModelEntry,
        artifact_filename,
        catalog_payload,
    )
    from azazel_nexus.model_import import CommissionedModels, ModelImport, entry_id_for

    ctx, doc, media = node
    key = SigningKey.generate()
    root = tmp_path / "models"
    (root / "trust").mkdir(parents=True)
    (root / "inbox").mkdir()
    weights = b"test-only weights"
    entry = ModelEntry(
        model_id="advisor", format="gguf", digest=mp.digest(weights), size_bytes=len(weights),
        provenance="fixture", license_acknowledgement_required=False, runtime_abi="llama.cpp/1",
        purpose="advice", context_limit=4096, declared_min_ram_mib=4096,
        declared_min_disk_mib=1, declared_profile=ResourceProfile.LITE, rollback_lineage=())
    payload = catalog_payload(version=1, commissioning_digest=D, entries=[entry])
    (root / "trust" / CATALOG_FILENAME).write_bytes(key.sign(CATALOG_DOMAIN + payload).signature + payload)
    models = ModelImport(CommissionedModels(root, {"catalog": bytes(key.verify_key)}, D))
    (root / "inbox" / "weights").write_bytes(weights)
    imported = models.import_entry(entry_id_for(display_name="weights", size=len(weights)),
                                   "advisor", now=NOW, actor=ACTOR)
    assert imported.promoted
    lite, lite_asset = _lite_slice(tmp_path, fixture=False)
    lite_path = lite_asset.path
    model_asset = mp.InstalledAsset(models.commissioned.store / artifact_filename(entry),
                                    entry.digest, entry.size_bytes, "1.0.0", 4096)
    ctx, newer = _with_lite(ctx, doc, lite, lite_asset)
    ctx = replace(ctx, assets={**ctx.assets, ("model", "advisor", model_asset.digest): model_asset},
                  models=models)
    newer["components"].append({"kind": "model", "id": "advisor", "digest": model_asset.digest,
                                "size_bytes": model_asset.size_bytes, "version": model_asset.version})
    newer["total_size_bytes"] += model_asset.size_bytes
    newer["memory_need_mib"] = 5000
    service = mp.MissionPack(ctx)
    before_model = models.current_generation()
    before_lite = lite_path.read_bytes()
    stage_activate(service, media(newer))
    assert models.current_generation() == before_model
    assert lite_path.read_bytes() == before_lite
    # A pack cannot revive missing or unverified installed assets.
    model_asset.path.write_bytes(b"x" * model_asset.size_bytes)
    newer["rollback_predecessor"] = service.status()["pack_digest"]
    with pytest.raises(mp.PackRefused, match="model verification"):
        service.verify(media(newer), now=NOW)


def test_a_marked_lab_host_verifies_no_pack(node, tmp_path, lab_host):
    """H7: the marker that lets a lab pin the published fixture anchor also
    refuses every Pack, so its knowledge_lite slice cannot name a
    fixture-signed bundle; off the marker, that slice refuses the bundle."""

    from azazel_nexus import lab_host as lab_marker

    ctx, doc, media = node
    lite, lite_asset = _lite_slice(tmp_path, fixture=True)  # admitted: the host is marked
    lab_ctx, newer = _with_lite(ctx, doc, lite, lite_asset)
    service = mp.MissionPack(lab_ctx)
    for pack in (media(newer), media()):  # with and without the fixture-signed slice
        with pytest.raises(mp.PackRefused, match="LAB_HOST_MARKER"):
            service.verify(pack, now=NOW)
        with pytest.raises(mp.PackRefused, match="LAB_HOST_MARKER"):
            service.stage(pack, now=NOW, actor=ACTOR, dry_run=True)
    assert not ctx.root.exists()
    # Unmarked, the Pack is verified and its knowledge_lite slice refuses the
    # same fixture-signed bundle (its gate reads the commissioned anchors).
    lab_marker.LAB_HOST_MARKER = tmp_path / "no-lab-marker"
    with pytest.raises(mp.PackRefused, match="Knowledge Lite reference refused"):
        service.verify(media(newer), now=NOW)
    # A generation staged before the host was marked is not activated after.
    staged = mp.MissionPack(ctx).stage(media(), now=NOW, actor=ACTOR)["staged_generation"]
    lab_marker.LAB_HOST_MARKER = lab_host
    with pytest.raises(mp.PackRefused, match="LAB_HOST_MARKER"):
        mp.MissionPack(ctx).activate(staged, now=NOW, actor=ACTOR, reason="reviewed")
    assert mp.MissionPack(ctx).current() is None


def test_audit_failure_prevents_pointer_change(node, monkeypatch):
    from azazel_nexus.audit import AuditUnavailable
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    stage_activate(service, media())
    previous = service.status()
    staged = service.stage(second(service, doc, media), now=NOW, actor=ACTOR)

    def fail(*args, **kwargs):
        raise AuditUnavailable("injected audit failure")

    monkeypatch.setattr(service.ledger, "append", fail)
    with pytest.raises(AuditUnavailable):
        service.activate(staged["staged_generation"], now=NOW, actor=ACTOR, reason="reviewed")
    assert service.status() == previous


def test_stale_review_and_generation_tampering_refuse(node):
    from azazel_nexus.generation import GenerationRefused
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    stage_activate(service, media())
    source = second(service, doc, media)
    first = service.stage(source, now=NOW, actor=ACTOR)["staged_generation"]
    stale = service.stage(source, now=NOW, actor=ACTOR)["staged_generation"]
    service.activate(first, now=NOW, actor=ACTOR, reason="reviewed first candidate")
    before = service.status()
    with pytest.raises(mp.PackRefused, match="predecessor"):
        service.activate(stale, now=NOW, actor=ACTOR, reason="stale review")
    path = service.store.root / str(stale) / "tree" / "mission-pack.signed"
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(GenerationRefused):
        service.activate(stale, now=NOW, actor=ACTOR, reason="tampered candidate")
    assert service.status() == before


def test_duplicate_json_fields_and_fabric_namespace_refuse(node):
    ctx, _, media = node
    source = media()
    path = source / "mission-pack.signed"
    raw = path.read_bytes()
    path.write_bytes(raw[:64] + b'{"schema":"anything",' + raw[65:])
    with pytest.raises(mp.PackRefused, match="duplicate"):
        mp.MissionPack(ctx).stage(source, now=NOW, actor=ACTOR)
    assert not ctx.root.exists()


def test_cli_first_install_failure_explicitly_reports_core(node, monkeypatch):
    ctx, _, media = node
    from azazel_nexus import mission_pack_cli
    monkeypatch.setattr(mission_pack_cli, "_context", lambda: replace(ctx, revoked_keys=frozenset({"fixture"})))
    out = io.StringIO()
    assert main(["pack", "stage", str(media()), "--actor", ACTOR, "--dry-run"], out=out) == 1
    assert json.loads(out.getvalue())["fallback"] == "CORE (no previous provider)"
    assert not ctx.root.exists()


@pytest.mark.parametrize("condition", ["revoked", "expired", "revoked_signer"])
def test_replace_degraded_active_without_reviving_it(node, condition):
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    stage_activate(service, media())
    previous = service.status(now=NOW)["pack_digest"]
    newer = json.loads(mp.canonical(doc))
    newer.update(pack_version="2.0.0", rollback_predecessor=previous,
                 expires_at="2026-12-01T00:00:00Z")
    now = NOW
    if condition == "revoked":
        ctx = replace(ctx, revoked_packs=frozenset({previous}))
    elif condition == "expired":
        now = "2026-11-02T00:00:00Z"
    else:
        # A newly commissioned signing identity can replace a revoked signer.
        newer["signer"] = "replacement"
        ctx = replace(ctx, trusted_keys={**ctx.trusted_keys, "replacement": ctx.trusted_keys["fixture"]},
                      revoked_keys=frozenset({"fixture"}))
    service = mp.MissionPack(ctx)
    status = service.status(now=now)
    assert status["state"] == "degraded"
    assert status["degradation_reasons"] == [{"revoked": "revoked pack", "expired": "expired pack",
                                               "revoked_signer": "revoked signer"}[condition]]
    staged = service.stage(media(newer), now=now, actor=ACTOR)
    result = service.activate(staged["staged_generation"], now=now, actor=ACTOR, reason="recover")
    assert result["state"] == "active"
    with pytest.raises(mp.PackRefused, match="revoked|expired"):
        service.rollback(now=now, actor=ACTOR, reason="must not revive degraded target")


@pytest.mark.parametrize("condition", ["revoked", "expired"])
def test_rollback_away_from_degraded_active(node, condition):
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    first = dict(doc, expires_at="2026-12-01T00:00:00Z")
    stage_activate(service, media(first))
    original = service.status()["pack_digest"]
    stage_activate(service, second(service, doc, media))
    now = NOW
    if condition == "revoked":
        ctx = replace(ctx, revoked_packs=frozenset({service.status()["pack_digest"]}))
    else:
        now = "2026-11-02T00:00:00Z"
    service = mp.MissionPack(ctx)
    assert service.status(now=now)["state"] == "degraded"
    result = service.rollback(now=now, actor=ACTOR, reason="recover to valid predecessor")
    assert result["pack_digest"] == original
    assert result["state"] == "active"


@pytest.mark.parametrize("old_installed", ["present", "inventory_removed", "file_removed"])
def test_changed_asset_pin_upgrade_and_rollback(node, tmp_path, old_installed):
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    stage_activate(service, media())
    original = service.status()["pack_digest"]
    newer = json.loads(mp.canonical(doc))
    newer.update(pack_version="2.0.0", rollback_predecessor=original)
    component = newer["components"][2]  # runbook; exact tested tuple remains unchanged
    old_key = (component["kind"], component["id"], component["digest"])
    raw = b"new installed runbook data"
    path = tmp_path / "runbook-v2.data"
    path.write_bytes(raw)
    newer["total_size_bytes"] += len(raw) - component["size_bytes"]
    component.update(digest=mp.digest(raw), size_bytes=len(raw), version="2.0.0")
    assets = dict(ctx.assets)
    assets[(component["kind"], component["id"], component["digest"])] = mp.InstalledAsset(
        path, mp.digest(raw), len(raw), "2.0.0", 5)
    if old_installed == "inventory_removed":
        del assets[old_key]
    elif old_installed == "file_removed":
        assets[old_key].path.unlink()
    service = mp.MissionPack(replace(ctx, assets=assets))
    stage_activate(service, media(newer))
    if old_installed == "present":
        assert service.rollback(now=NOW, actor=ACTOR, reason="restore old pin")["pack_digest"] == original
    else:
        before = service.status()
        with pytest.raises(mp.PackRefused, match="asset not in commissioned verified inventory|no longer installed"):
            service.rollback(now=NOW, actor=ACTOR, reason="missing old pin")
        assert service.status() == before


@pytest.mark.parametrize("action", ["activation", "rollback"])
@pytest.mark.parametrize("step", ["intent_durable", "pointer_replaced", "pointer_durable"])
def test_recovery_completes_only_published_intent_once(node, action, step):
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    stage_activate(service, media())
    staged = service.stage(second(service, doc, media), now=NOW, actor=ACTOR)
    if action == "rollback":
        service.activate(staged["staged_generation"], now=NOW, actor=ACTOR, reason="reviewed")

    def interrupt(at):
        if at == step:
            raise KeyboardInterrupt(at)

    service.checkpoint = interrupt
    with pytest.raises(KeyboardInterrupt):
        if action == "rollback":
            service.rollback(now=NOW, actor=ACTOR, reason="restore")
        else:
            service.activate(staged["staged_generation"], now=NOW, actor=ACTOR, reason="reviewed")
    service = mp.MissionPack(ctx)
    before = service.status()
    intent = list(service.ledger)[-1]
    assert intent.event["event_type"] == f"mission_pack.{action}.commit_intent"
    service.recover(now=NOW)
    events = list(service.ledger)
    assert service.status() == before
    if step == "intent_durable":
        assert events[-1] == intent
    else:
        completion = events[-1].event
        assert completion["event_type"] == f"mission_pack.{action}.completed"
        assert completion["commit_intent_hash"] == intent.event_hash
        assert all(completion[k] == v for k, v in intent.event.items() if k != "event_type")
    service.recover(now=NOW)
    assert list(service.ledger) == events
    service.ledger.verify()


def test_next_write_recovers_before_staging(node):
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    staged = service.stage(media(), now=NOW, actor=ACTOR)

    def interrupt(at):
        if at == "pointer_replaced":
            raise KeyboardInterrupt(at)

    service.checkpoint = interrupt
    with pytest.raises(KeyboardInterrupt):
        service.activate(staged["staged_generation"], now=NOW, actor=ACTOR, reason="reviewed")
    service = mp.MissionPack(ctx)
    source = second(service, doc, media)
    before = list(service.ledger)
    service.stage(source, now=NOW, actor=ACTOR, dry_run=True)
    assert list(service.ledger) == before
    service.stage(source, now=NOW, actor=ACTOR)
    events = [e.event for e in service.ledger]
    assert events[-2]["event_type"] == "mission_pack.activation.completed"
    assert events[-2]["commit_intent_hash"] == before[-1].event_hash
    assert events[-1]["event_type"] == "mission_pack.staged"


def test_retained_admission_digest_still_checked(node):
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    stage_activate(service, media())
    source = second(service, doc, media)
    tree = service.store.read_tree(service.current().number)
    record = json.loads(tree["admission.json"])
    record["pack_digest"] = D
    tree["admission.json"] = mp.canonical(record)
    source = media(dict(doc, pack_version="2.0.0", rollback_predecessor=D))
    # A valid storage tree cannot substitute an incorrect signed-pack pin.
    substituted = service.store.create(tree, created_at=NOW, commissioning_digest=D)
    (ctx.root / "current").write_text(f"{substituted.number}\n")
    with pytest.raises(mp.PackRefused, match="admission digest mismatch"):
        service.stage(source, now=NOW, actor=ACTOR)


def test_cli_inventory_keeps_distinct_pins_and_refuses_duplicate_triples(node, monkeypatch, tmp_path):
    from dataclasses import asdict
    from types import SimpleNamespace

    from azazel_nexus import mission_pack_cli as cli

    ctx, _, _ = node
    asset = next(iter(ctx.assets.values()))
    entry = {"kind": "runbook", "id": "same-id", "path": str(asset.path),
             "digest": asset.digest, "size_bytes": asset.size_bytes, "version": asset.version,
             "memory_need_mib": 5}
    document = {"schema": "azazel-nexus/mission-pack-config/1", "host": asdict(ctx.host),
                "tested_tuples": [t.as_record() for t in ctx.tuples.tuples],
                "assets": [entry, dict(entry, digest=D)], "trusted_keys": {},
                "signing_epoch": 3, "revoked_keys": [], "revoked_packs": [],
                "host_digest": D, "commissioning_digest": D, "allowed_features": [],
                "reserve_path": str(ctx.reserve_path), "max_pack_bytes": 1024**2,
                "max_selected_bytes": 1024**3, "disk_headroom_bytes": 0}
    monkeypatch.setattr(cli, "CONFIG", SimpleNamespace(lstat=lambda: SimpleNamespace(
        st_mode=0o100600, st_uid=0)))
    monkeypatch.setattr(cli, "STATE", tmp_path)
    monkeypatch.setattr(cli, "luks_backed", lambda path: True)
    monkeypatch.setattr(cli, "take_reading", lambda: ctx.resources)
    monkeypatch.setattr(cli, "_regular", lambda *args: json.dumps(document, default=list).encode())
    monkeypatch.setattr(cli.os, "uname", lambda: SimpleNamespace(machine=ctx.host.architecture))
    assert set(cli._context().assets) == {("runbook", "same-id", asset.digest), ("runbook", "same-id", D)}
    document["assets"].append(entry)
    with pytest.raises(mp.PackRefused, match="duplicate commissioned asset"):
        cli._context()


def test_rollback_records_pointer_active_source_with_newer_staged_generation(node):
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    stage_activate(service, media())
    original = service.status()["pack_digest"]
    active = stage_activate(service, second(service, doc, media))
    staged = service.stage(second(service, doc, media), now=NOW, actor=ACTOR)["staged_generation"]
    assert service.store.current().number == staged > active
    result = service.rollback(now=NOW, actor=ACTOR, reason="restore actual active predecessor")
    generation = service.store.verify(result["generation"])
    assert generation.rolled_back_from == active
    assert generation.supersedes == staged
    assert result["pack_digest"] == original
    assert list(service.ledger)[-1].event["from_generation"] == active


def test_writer_ledger_is_private_with_permissive_umask(node):
    import os
    import stat

    ctx, _, media = node
    ctx.root.mkdir(parents=True, mode=0o2750)
    pack = mp.MissionPack(ctx)
    previous = os.umask(0)
    try:
        pack.stage(media(), now=NOW, actor="test")
    finally:
        os.umask(previous)
    assert stat.S_IMODE(pack.ledger.path.stat().st_mode) == 0o600


@pytest.mark.parametrize(("machine", "declared", "match"), [
    # An arm64 host whose config claims x86_64 (R5): refused, not matched
    # against the x86_64 tested tuples.
    ("aarch64", "x86_64", "differs from the observed arm64 kernel"),
    # Declaring the truth does not help: no tested tuple is arm64.
    ("aarch64", "aarch64", None),
    ("riscv64", "riscv64", "host architecture refused: UNKNOWN_ARCHITECTURE"),
    ("x86_64", "aarch64", "differs from the observed amd64 kernel"),
])
def test_cli_host_architecture_is_observed_not_declared(node, monkeypatch, tmp_path,
                                                         machine, declared, match):
    from dataclasses import asdict
    from types import SimpleNamespace

    from azazel_nexus import mission_pack_cli as cli

    ctx, _, _ = node
    host = dict(asdict(ctx.host), architecture=declared)
    document = {"schema": "azazel-nexus/mission-pack-config/1", "host": host,
                "tested_tuples": [t.as_record() for t in ctx.tuples.tuples],
                "assets": [], "trusted_keys": {},
                "signing_epoch": 3, "revoked_keys": [], "revoked_packs": [],
                "host_digest": D, "commissioning_digest": D, "allowed_features": [],
                "reserve_path": str(ctx.reserve_path), "max_pack_bytes": 1024**2,
                "max_selected_bytes": 1024**3, "disk_headroom_bytes": 0}
    monkeypatch.setattr(cli, "CONFIG", SimpleNamespace(lstat=lambda: SimpleNamespace(
        st_mode=0o100600, st_uid=0)))
    monkeypatch.setattr(cli, "STATE", tmp_path)
    monkeypatch.setattr(cli, "luks_backed", lambda path: True)
    monkeypatch.setattr(cli, "take_reading", lambda: ctx.resources)
    monkeypatch.setattr(cli, "_regular", lambda *args: json.dumps(document, default=list).encode())
    monkeypatch.setattr(cli.os, "uname", lambda: SimpleNamespace(machine=machine))
    if match is not None:
        with pytest.raises(mp.PackRefused, match=match):
            cli._context()
        return
    context = cli._context()
    assert context.host.architecture == machine
    # The tested tuples are x86_64 only; an observed arm64 host matches none.
    assert all(t.architecture != machine for t in context.tuples.tuples)


# -- R387-01: on a marked host nothing is read before the refusal --

def _published(ctx):
    """Generations, selection pointer and audit as bytes: what a write publishes."""
    return {str(p): p.read_bytes() for p in ctx.root.rglob("*") if p.is_file()} if ctx.root.exists() else {}


def _prepared(node):
    """A host with an active generation, a staged successor and a rollback
    predecessor, all prepared before the host is marked."""
    ctx, doc, media = node
    service = mp.MissionPack(ctx)
    stage_activate(service, media())
    stage_activate(service, second(service, doc, media))
    newer = json.loads(mp.canonical(doc))
    newer.update(pack_version="3.0.0", rollback_predecessor=service.status()["pack_digest"])
    staged = service.stage(media(newer), now=NOW, actor=ACTOR)["staged_generation"]
    return ctx, media(newer), staged


def _forbid_reads(monkeypatch):
    def fail(*_args, **_kwargs):
        pytest.fail("media or Mission Pack state read on a marked lab host")
    from azazel_nexus import mission_pack_cli
    from azazel_nexus.generation import GenerationStore

    monkeypatch.setattr(mp, "_media", fail)
    monkeypatch.setattr(mp, "_make_store_root", fail)
    monkeypatch.setattr(mp.MissionPack, "current", fail)
    monkeypatch.setattr(mp.MissionPack, "_candidate", fail)
    monkeypatch.setattr(GenerationStore, "read_tree", fail)
    monkeypatch.setattr(GenerationStore, "verify", fail)
    monkeypatch.setattr(mission_pack_cli, "_context", fail)


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("operation", ["verify", "stage", "activate", "rollback"])
def test_a_marked_host_is_refused_before_media_or_state_is_read(
        node, monkeypatch, tmp_path, operation, dry_run):
    from azazel_nexus import lab_host as lab_marker

    ctx, pack, staged = _prepared(node)
    before = _published(ctx)
    marker = tmp_path / "lab-marker"
    marker.write_text("lab\n")
    monkeypatch.setattr(lab_marker, "LAB_HOST_MARKER", marker)
    _forbid_reads(monkeypatch)
    service = mp.MissionPack(ctx)
    call = {"verify": lambda: service.verify(pack, now=NOW),
            "stage": lambda: service.stage(pack, now=NOW, actor=ACTOR, dry_run=dry_run),
            "activate": lambda: service.activate(staged, now=NOW, actor=ACTOR, reason="r",
                                                 dry_run=dry_run),
            "rollback": lambda: service.rollback(now=NOW, actor=ACTOR, reason="r",
                                                 dry_run=dry_run)}[operation]
    with pytest.raises(mp.PackRefused, match="LAB_HOST_MARKER"):
        call()
    monkeypatch.undo()
    assert _published(ctx) == before


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("operation", ["verify", "stage", "activate", "rollback"])
def test_the_cli_refuses_a_marked_host_before_its_context(
        node, monkeypatch, tmp_path, operation, dry_run):
    from azazel_nexus import lab_host as lab_marker

    if operation == "verify" and dry_run:
        pytest.skip("verify is always read-only")
    ctx, pack, staged = _prepared(node)
    before = _published(ctx)
    marker = tmp_path / "lab-marker"
    marker.write_text("lab\n")
    monkeypatch.setattr(lab_marker, "LAB_HOST_MARKER", marker)
    monkeypatch.setattr("azazel_nexus.cli._now", lambda: NOW)
    monkeypatch.setattr(mp.os, "geteuid", lambda: 0)
    _forbid_reads(monkeypatch)
    args = ["pack", operation, *(["--dry-run"] if dry_run else [])]
    args += {"verify": [str(pack)], "stage": [str(pack), "--actor", ACTOR],
             "activate": [str(staged), "--actor", ACTOR, "--reason", "r"],
             "rollback": ["--actor", ACTOR, "--reason", "r"]}[operation]
    out = io.StringIO()
    assert main(args, out=out) == 1
    assert json.loads(out.getvalue())["refused"] == "LAB_HOST_MARKER"
    monkeypatch.undo()
    assert _published(ctx) == before


# -- R387-02: the marker and a Pack publication are serialized --

def _mark_mid_operation(service, marker, step):
    def checkpoint(name):
        if name == step:
            marker.write_text("lab\n")  # A writer that bypassed the lock.
    service.checkpoint = checkpoint


@pytest.mark.parametrize(("operation", "step"), [
    ("stage", "prechecked"), ("stage", "before_generation"),
    ("activate", "transition_prechecked"), ("activate", "before_intent"),
    ("rollback", "transition_prechecked"),
])
def test_a_marker_appearing_mid_operation_publishes_nothing(
        node, monkeypatch, tmp_path, operation, step):
    from azazel_nexus import lab_host as lab_marker

    ctx, pack, staged = _prepared(node)
    marker = tmp_path / "lab-marker"
    monkeypatch.setattr(lab_marker, "LAB_HOST_MARKER", marker)
    service = mp.MissionPack(ctx)
    before, current = _published(ctx), service.current().number
    _mark_mid_operation(service, marker, step)
    call = {"stage": lambda: service.stage(pack, now=NOW, actor=ACTOR),
            "activate": lambda: service.activate(staged, now=NOW, actor=ACTOR, reason="r"),
            "rollback": lambda: service.rollback(now=NOW, actor=ACTOR, reason="r")}[operation]
    with pytest.raises(mp.PackRefused, match="LAB_HOST_MARKER"):
        call()
    assert marker.exists()
    marker.unlink()
    # No generation, selection pointer or (success) audit was published.
    assert _published(ctx) == before
    assert mp.MissionPack(ctx).current().number == current


def _lab_cli(monkeypatch, marker, wait):
    """The real lab marker entry; only the root-only file write is replaced."""
    import sys

    lab_src = str(Path(__file__).resolve().parents[2] / "lab/src")
    if lab_src not in sys.path:
        sys.path.insert(0, lab_src)
    from azazel_nexus_lab import cli as lab_cli

    monkeypatch.setattr(lab_cli, "_write_marker", lambda: marker.write_text("lab\n"))
    monkeypatch.setattr(lab_cli, "MARKER_LOCK_WAIT_SECONDS", wait)
    return lab_cli


def _other_root(node, tmp_path):
    """Root B: the same commissioning, a different state root."""
    ctx, _doc, _media = node
    return replace(ctx, root=tmp_path / "other-encrypted" / "packs")


@pytest.mark.parametrize("operation", ["stage", "activate", "rollback"])
def test_no_marker_or_other_root_pack_interleaves_with_a_publication(
        node, monkeypatch, tmp_path, operation):
    """R387b-01: the host-wide lock, not the state root, serializes. While the
    Pack on root A is paused mid-publication, the real marker entry (whose
    Mission Pack STATE is root B) and a Pack writer on root B are refused."""
    from azazel_nexus import lab_host as lab_marker
    from azazel_nexus import mission_pack_cli

    ctx, pack, staged = _prepared(node)
    other = _other_root(node, tmp_path)
    marker = tmp_path / "lab-marker"
    monkeypatch.setattr(lab_marker, "LAB_HOST_MARKER", marker)
    monkeypatch.setattr(mission_pack_cli, "STATE", other.root)
    lab_cli = _lab_cli(monkeypatch, marker, 0.2)
    from azazel_nexus_lab.refusal import LabRefused

    service = mp.MissionPack(ctx)
    paused = []

    def checkpoint(name):
        if name in {"generation_published", "intent_durable"}:
            with pytest.raises(LabRefused, match="a Mission Pack writer is active"):
                lab_cli.mark_host()
            with pytest.raises(mp.PackRefused, match="writer already active"):
                mp.MissionPack(other).stage(node[2](), now=NOW, actor=ACTOR)
            paused.append(name)
    service.checkpoint = checkpoint
    {"stage": lambda: service.stage(pack, now=NOW, actor=ACTOR),
     "activate": lambda: service.activate(staged, now=NOW, actor=ACTOR, reason="r"),
     "rollback": lambda: service.rollback(now=NOW, actor=ACTOR, reason="r")}[operation]()
    assert paused and not marker.exists()
    assert not other.root.exists()  # B was refused before its state was created
    # Released: the marker is written, and every Pack writer is then refused.
    lab_cli.mark_host()
    assert marker.exists()
    for service_ in (mp.MissionPack(ctx), mp.MissionPack(other)):
        with pytest.raises(mp.PackRefused, match="LAB_HOST_MARKER"):
            service_.verify(pack, now=NOW)


def test_the_marker_entries_need_no_mission_pack_state(node, monkeypatch, tmp_path):
    """The marker writers take only the /run host lock: a missing, read-only
    or full /data is never created or touched."""
    from azazel_nexus import lab_host as lab_marker
    from azazel_nexus import mission_pack_cli

    marker = tmp_path / "lab-marker"
    monkeypatch.setattr(lab_marker, "LAB_HOST_MARKER", marker)
    state = tmp_path / "read-only" / "data" / "azazel" / "mission-packs"
    state.parent.parent.parent.mkdir()
    state.parent.parent.parent.chmod(0o500)
    monkeypatch.setattr(mission_pack_cli, "STATE", state)
    monkeypatch.setattr(mp, "_make_store_root",
                        lambda *_: pytest.fail("the marker writer created Mission Pack state"))
    try:
        _lab_cli(monkeypatch, marker, 0.2).mark_host()
    finally:
        state.parent.parent.parent.chmod(0o700)
    assert marker.exists() and not state.parent.parent.exists()


_HOLDER = """
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
print("held", flush=True)
sys.stdin.read()
"""


def _hold_in_another_process(path):
    import subprocess
    import sys

    holder = subprocess.Popen([sys.executable, "-c", _HOLDER, str(path)],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    assert holder.stdout.readline().strip() == "held"
    return holder


def _release(holder):
    holder.stdin.close()
    assert holder.wait(10) == 0


def test_another_process_holding_the_host_lock(node, monkeypatch, tmp_path):
    """Pack writers refuse at once; the marker writer waits (bounded) and
    either writes after the release or refuses without writing."""
    import threading
    import time

    from azazel_nexus import lab_host as lab_marker

    ctx, pack, staged = _prepared(node)
    marker = tmp_path / "lab-marker"
    monkeypatch.setattr(lab_marker, "LAB_HOST_MARKER", marker)
    before = _published(ctx)
    holder = _hold_in_another_process(lab_marker.LAB_HOST_LOCK)
    try:
        service = mp.MissionPack(ctx)
        for call in (lambda: service.stage(pack, now=NOW, actor=ACTOR),
                     lambda: service.activate(staged, now=NOW, actor=ACTOR, reason="r"),
                     lambda: service.rollback(now=NOW, actor=ACTOR, reason="r")):
            started = time.monotonic()
            with pytest.raises(mp.PackRefused, match="writer already active"):
                call()
            assert time.monotonic() - started < 1.0  # refused at once, never waits
        assert _published(ctx) == before
        lab_cli = _lab_cli(monkeypatch, marker, 0.3)
        from azazel_nexus_lab.refusal import LabRefused
        with pytest.raises(LabRefused, match="a Mission Pack writer is active"):
            lab_cli.mark_host()  # timed out
        assert not marker.exists()
        monkeypatch.setattr(lab_cli, "MARKER_LOCK_WAIT_SECONDS", 10)
        marking = threading.Thread(target=lab_cli.mark_host)
        marking.start()
        marking.join(0.3)
        assert marking.is_alive() and not marker.exists()  # waiting, not writing
    finally:
        _release(holder)
    marking.join(10)
    assert not marking.is_alive() and marker.exists()  # wrote after the release


@pytest.mark.parametrize("operation", ["activate", "rollback"])
def test_an_interrupted_transition_releases_the_host_lock_and_recovers(
        node, monkeypatch, tmp_path, operation):
    """Interrupted at transition_prechecked (power loss in-process): nothing is
    published, both locks are released, and the next transition succeeds."""
    from azazel_nexus import lab_host as lab_marker

    ctx, pack, staged = _prepared(node)
    marker = tmp_path / "lab-marker"
    monkeypatch.setattr(lab_marker, "LAB_HOST_MARKER", marker)
    service = mp.MissionPack(ctx)
    before, current = _published(ctx), service.current().number

    def interrupt(name):
        if name == "transition_prechecked":
            raise KeyboardInterrupt("power loss")
    service.checkpoint = interrupt
    call = {"activate": lambda s: s.activate(staged, now=NOW, actor=ACTOR, reason="r"),
            "rollback": lambda s: s.rollback(now=NOW, actor=ACTOR, reason="r")}[operation]
    with pytest.raises(KeyboardInterrupt):
        call(service)
    assert _published(ctx) == before
    recovered = mp.MissionPack(ctx)
    recovered.recover(now=NOW)
    assert recovered.current().number == current
    result = call(recovered)
    assert result["generation"] != current and recovered.current().number == result["generation"]
    recovered.ledger.verify()
    # Both locks were released: a marker writer and a later writer get them.
    with lab_marker.marker_lock():
        pass
