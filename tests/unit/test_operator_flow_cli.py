"""Fixture reads, verification delegation, and zero mutation in setup."""

import json
from argparse import Namespace
from dataclasses import replace
from hashlib import sha256
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_model_import import COMMISSIONING, _write_catalog, an_entry, trusted

from azazel_nexus import operator_flow_cli as flow
from azazel_nexus.cli import KNOWLEDGE_LITE_ROOT, main
from azazel_nexus.hil_preflight import ReadonlyInventory
from azazel_nexus.operator_flow import State, evaluate, next_step

NOW = "2026-10-18T00:00:00Z"


def args(**values):
    return Namespace(installed_manifest=None, manifest_digest=None, operator=None,
                     next=False, json=False, **values)


def put(root, name, data=b"fixture"):
    target = root / name.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return target


@pytest.fixture
def fixture_host(monkeypatch):
    inventory = ReadonlyInventory(
        usable_mib=8000, architecture="x86_64", distribution="Debian GNU/Linux 13",
        os_id="debian", os_version_id="13", kernel_release="fixture",
        storage_total_gib=512, storage_free_gib=256, luks_available=True,
        tpm_available=True, interfaces=(object(),), wireless_enumerated=True, link_observed=True,
    )
    assert not inventory.missing
    monkeypatch.setattr(flow, "read_interfaces", lambda: ())
    monkeypatch.setattr(flow, "collect_readonly_inventory", lambda **kw: inventory)
    return inventory


def test_fresh_fixture_reports_install_and_no_claims(tmp_path, fixture_host):
    facts = flow.collect(args(), now=NOW, root=tmp_path)
    steps = evaluate(facts)
    assert next_step(steps).name == "installed-files"
    assert "install.sh" in steps[0].next_command
    assert facts["commissioning"].state is State.MISSING
    assert facts["fetch-commissioning"].state is State.MISSING
    assert "live unit state unobserved" in facts["activation-units"].reason
    assert "missing unit files" in facts["activation-units"].reason


def test_progressive_fixture_delegates_installed_review_and_bootstrap(tmp_path, fixture_host, monkeypatch):
    options = args()
    for name in ("az-activated", "az-commissiond", "az-auditd", "az-mio-entryd", "az-knowledge-lited"):
        put(tmp_path, "/usr/libexec/azazel/" + name)
    assert next_step(evaluate(flow.collect(options, now=NOW, root=tmp_path))).name == "installed-files"
    manifest = put(tmp_path, "/reviewed.json", b"canonical fixture manifest")
    options.installed_manifest = manifest
    options.manifest_digest = "sha256:" + sha256(manifest.read_bytes()).hexdigest()
    measured = []
    def measure(raw, *, expected_digest):
        measured.append((raw, expected_digest))
        return SimpleNamespace(file_count=5)
    monkeypatch.setattr(flow, "measure_installed_files", measure)
    assert next_step(evaluate(flow.collect(options, now=NOW, root=tmp_path))).name == "commissioning"
    assert measured[-1] == (manifest.read_bytes(), options.manifest_digest)
    put(tmp_path, "/etc/azazel/commissioning/commissioning-draft.json")
    assert next_step(evaluate(flow.collect(options, now=NOW, root=tmp_path))).name == "commission-review"
    options.operator = "fixture-operator"
    monkeypatch.setattr(flow, "read_draft_review_inputs", lambda: (b"payload", b"signature"))
    monkeypatch.setattr(flow, "load_operator_trust", lambda: "trust")
    monkeypatch.setattr(flow, "propose", lambda interfaces: "current")
    reviewed = []
    monkeypatch.setattr(flow, "verify_draft_review", lambda **kw: reviewed.append(kw))
    assert next_step(evaluate(flow.collect(options, now=NOW, root=tmp_path))).name == "bootstrap-deployment"
    assert reviewed[-1]["operator"] == options.operator
    assert reviewed[-1]["current"] == "current"
    for name in ("deployment", "selection"):
        put(tmp_path, "/etc/azazel/bootstrap/" + name + ".json")
    monkeypatch.setattr(flow, "load_bootstrap_deployment", lambda: object())
    monkeypatch.setattr(flow, "load_bootstrap_selection", lambda: object())
    facts = flow.collect(options, now=NOW, root=tmp_path)
    assert next_step(evaluate(facts)).name == "knowledge-store"
    assert facts["bootstrap-selection"].state is State.COMPLETE
    put(tmp_path, "/etc/azazel/bootstrap/selection.pending")
    facts = flow.collect(options, now=NOW, root=tmp_path)
    assert facts["bootstrap-selection"].state is State.REFUSED
    assert facts["bootstrap-selection"].command.endswith("bootstrap-selection-recover")


def test_inventory_uses_existing_missing_codes(tmp_path, fixture_host, monkeypatch):
    monkeypatch.setattr(flow, "collect_readonly_inventory", lambda **kw: replace(fixture_host, usable_mib=None))
    observed = flow.collect(args(), now=NOW, root=tmp_path)["host-preflight"]
    assert observed.state is State.MISSING
    assert "A-1" in observed.reason


def test_fetch_presence_is_explicitly_not_verification(tmp_path, fixture_host):
    for name in ("trust.json", "sources.signed", "catalog.signed", "ca.pem", "addresses.json", "consent.json"):
        put(tmp_path, "/var/lib/azazel/fetch/commission/" + name, b"invalid but present")
    facts = flow.collect(args(), now=NOW, root=tmp_path)
    assert facts["fetch-commissioning"].state is State.COMPLETE
    assert "not verified" in facts["fetch-commissioning"].reason
    assert next(step for step in evaluate(facts) if step.name == "provider-admission").status == "blocked"


@pytest.mark.parametrize("license_required", [False, True])
def test_real_signed_catalog_candidate_gets_exact_import_command(tmp_path, fixture_host, license_required):
    root = tmp_path / "var/lib/azazel/models"
    (root / "trust").mkdir(parents=True)
    (root / "trust/trust.json").write_text(json.dumps({
        "catalog_keys": {k: v.hex() for k, v in trusted().items()},
        "commissioning_digest": COMMISSIONING,
    }))
    entry = an_entry(license_acknowledgement_required=license_required)
    _write_catalog(root, [entry])
    from azazel_nexus.model_catalog import artifact_filename
    ready = put(tmp_path, "/var/lib/azazel/fetch/ready/" + artifact_filename(entry))
    facts = flow.collect(args(), now=NOW, root=tmp_path)
    expected = "sudo azazel-nexus model-import-fetched small-advisor"
    if license_required:
        expected += " --acknowledge-license"
        assert "review license" in facts["model-import-fetched"].reason
    assert facts["model-import-fetched"].command == expected
    assert "unverified bytes" in facts["model-import-fetched"].reason
    ready.unlink()
    facts = flow.collect(args(), now=NOW, root=tmp_path)
    assert facts["model-import-fetched"].state is State.OPTIONAL


def snapshot(root):
    return {str(p.relative_to(root)): (p.lstat().st_mode, p.lstat().st_size,
                                       p.lstat().st_mtime_ns, p.read_bytes() if p.is_file() else None)
            for p in root.rglob("*")}


def test_no_writes_with_missing_invalid_and_present_inputs(tmp_path, fixture_host, monkeypatch):
    put(tmp_path, "/etc/azazel/commissioning/commissioning-draft.json", b"sentinel secret identity")
    put(tmp_path, "/etc/azazel/bootstrap/deployment.json", b"invalid")
    put(tmp_path, "/var/lib/azazel/knowledge/state.toml", b"invalid")
    put(tmp_path, "/var/lib/azazel/lite-trust/trust.json", b"invalid")
    put(tmp_path, "/data/azazel/mission-packs/current", b"invalid")
    before = snapshot(tmp_path)
    monkeypatch.setattr(flow, "load_bootstrap_deployment", lambda: (_ for _ in ()).throw(ValueError("secret")))
    output = flow.collect(args(), now=NOW, root=tmp_path)
    assert snapshot(tmp_path) == before
    assert "secret" not in repr(output)
    assert output["bootstrap-deployment"].state is State.REFUSED
    assert output["knowledge-trust"].state is State.REFUSED


def test_json_and_next_registration(tmp_path, fixture_host, monkeypatch):
    original = flow.collect
    monkeypatch.setattr(flow, "collect", lambda args, *, now: original(args, now=now, root=tmp_path))
    for next_only in (False, True):
        out = StringIO()
        assert main(["setup", "--json", *(["--next"] if next_only else [])], out=out) == 0
        doc = json.loads(out.getvalue())
        assert doc["read_only"] is True
        assert doc["hg05"] == "unmeasured"
        assert doc["provider_admission"] == "blocked"
        assert doc["enforcement_readiness"] == "not-established"
        assert len(doc["steps"]) == (1 if next_only else 13)
        assert doc["steps"][0]["name"] == "installed-files"
    out = StringIO()
    assert main(["setup", "--next"], out=out) == 0
    assert "next: sudo env" in out.getvalue()
    assert "Edge retains decision and enforcement authority" in out.getvalue()


def test_manifest_options_are_paired():
    out = StringIO()
    assert main(["setup", "--manifest-digest", "sha256:" + "0" * 64], out=out) == 2
    assert "together" in out.getvalue()


def test_knowledge_default_follows_contract():
    assert KNOWLEDGE_LITE_ROOT == Path("/var/lib/azazel/knowledge")
    assert flow.KNOWLEDGE_ROOT == KNOWLEDGE_LITE_ROOT


def test_no_mutation_or_operational_import_in_adapter():
    import ast
    tree = ast.parse(Path(flow.__file__).read_text())
    imported = [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
    imported += [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not any(name.split(".")[0] in {"socket", "subprocess", "azazel_nexus_runtime"} for name in imported)
    assert not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                   and node.func.attr in {"mkdir", "write_bytes", "write_text", "unlink", "replace", "touch"}
                   for node in ast.walk(tree))


@pytest.mark.parametrize("state,expected", [("active", State.COMPLETE), ("core", State.MISSING),
                                            ("degraded", State.REFUSED)])
def test_pack_status_delegation(tmp_path, fixture_host, monkeypatch, state, expected):
    monkeypatch.setattr(flow, "_context", lambda: "commissioned-context")
    calls = []
    class Pack:
        def __init__(self, context):
            assert context == "commissioned-context"

        def status(self, *, now):
            calls.append(now)
            return {"state": state}
    monkeypatch.setattr(flow, "MissionPack", Pack)
    observed = flow.collect(args(), now=NOW, root=tmp_path)["mission-pack"]
    assert observed.state is expected
    assert calls == [NOW]
    assert "no provider admission" in observed.reason


def test_verified_knowledge_read_and_trust_pin_write_nothing(tmp_path, fixture_host):
    from test_lite_import import CONTRACT, FRESH

    from azazel_nexus.lite_import import CommissionedLite, LiteImport
    from azazel_nexus.lite_trust import TrustStore
    lite_root = tmp_path / "var/lib/azazel/knowledge"
    put(lite_root, "trust/anchors.toml", (CONTRACT / "anchors.toml").read_bytes())
    put(lite_root, "inbox/lite.tar.gz", (CONTRACT / "lite.tar.gz").read_bytes())
    service = LiteImport(CommissionedLite(lite_root))
    assert service.import_entry(service.list_inbox()[0].entry_id, now=FRESH).admitted
    from nacl.signing import SigningKey
    key = SigningKey.generate()
    TrustStore(tmp_path / "var/lib/azazel/lite-trust").pin(
        [bytes(key.verify_key).hex()], commissioning_digest=COMMISSIONING, pinned_at=FRESH, actor="fixture")
    before = snapshot(tmp_path)
    facts = flow.collect(args(), now=FRESH, root=tmp_path)
    assert snapshot(tmp_path) == before
    assert facts["knowledge-store"].state is State.COMPLETE
    assert "integrity: admitted" in facts["knowledge-store"].reason
    assert facts["knowledge-trust"].state is State.COMPLETE
    assert "binding" in facts["knowledge-trust"].reason
    assert next(step for step in evaluate(facts) if step.name == "provider-admission").status == "blocked"


def test_unit_mask_is_observed_without_claiming_active(tmp_path, fixture_host):
    mask = tmp_path / "etc/systemd/system/azazel-commissiond.service"
    mask.parent.mkdir(parents=True)
    mask.symlink_to("/dev/null")
    fact = flow.collect(args(), now=NOW, root=tmp_path)["activation-units"]
    assert fact.state is State.UNKNOWN
    assert "observed masks: azazel-commissiond.service" in fact.reason
    assert fact.command.startswith("systemctl status azazel-activated.service")


def test_manifest_option_error_is_json():
    out = StringIO()
    assert main(["setup", "--json", "--installed-manifest", "/reviewed.json"], out=out) == 2
    assert json.loads(out.getvalue())["error"].endswith("together")


def test_protected_metadata_denied_becomes_blocked_rows(tmp_path, fixture_host, monkeypatch):
    original_file = Path.is_file
    original_exists = Path.exists

    def is_file(path):
        if "commissioning" in path.parts:
            raise PermissionError("private-identity-sentinel")
        return original_file(path)

    def exists(path):
        if path.suffix == ".pending":
            raise PermissionError("private-identity-sentinel")
        return original_exists(path)

    monkeypatch.setattr(Path, "is_file", is_file)
    monkeypatch.setattr(Path, "exists", exists)
    facts = flow.collect(args(), now=NOW, root=tmp_path)
    assert facts["commissioning"].state is State.REFUSED
    assert facts["bootstrap-deployment"].state is State.REFUSED
    assert facts["bootstrap-selection"].state is State.REFUSED
    assert "sentinel" not in repr(facts)
