"""Fixture reads, verification delegation, and zero mutation in setup."""

import json
from argparse import Namespace
from dataclasses import replace
from hashlib import sha256
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_knowledge_lited import DIGEST, admit
from test_knowledge_lited import node as commissioned_node  # noqa: F401 - shared pytest fixture
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
    draft_facts = flow.collect(options, now=NOW, root=tmp_path)
    assert next_step(evaluate(draft_facts)).name == "commissioning"
    step = next(step for step in evaluate(draft_facts) if step.name == "commissioning")
    assert step.status == "needed"
    assert "draft only" in step.reason
    put(tmp_path, "/etc/azazel/commissioning/commissioning.json")
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
        assert len(doc["steps"]) == (1 if next_only else 16)
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


@pytest.mark.parametrize("condition,expected,reason", [
    ("available", State.COMPLETE, "available"),
    ("unpinned", State.REFUSED, "trust_unreadable"),
    ("revocation-role", State.REFUSED, "unverified"),
    ("revoked", State.REFUSED, "revoked"),
    ("no-bundle", State.MISSING, "no_bundle"),
])
def test_setup_and_status_share_daemon_trust(commissioned_node, fixture_host, condition, expected, reason):  # noqa: F811
    from nacl.signing import SigningKey
    from test_lite_bundle import SEED

    from azazel_nexus.cli import _knowledge_reading, _render_knowledge
    from azazel_nexus.lite_trust import TrustStore
    from azazel_nexus.revocation import RevocationList
    from azazel_nexus.revocation_policy import (
        REVOCATION_SIGNING,
        RevocationPolicy,
        commission_policy,
    )

    service, root, trust, revoker = commissioned_node
    if condition != "no-bundle":
        admit(commissioned_node)
    if condition == "unpinned":
        TrustStore(trust).path.unlink()
        TrustStore(trust).pin([SigningKey.generate().verify_key.encode().hex()],
                             commissioning_digest=DIGEST, pinned_at=NOW, actor="fixture")
    elif condition == "revocation-role":
        # A key pinned for bundles must not also act as revocation authority.
        key = SigningKey(SEED).verify_key.encode()
        commission_policy(trust, RevocationPolicy(
            keys={"r": key}, key_roles={"r": REVOCATION_SIGNING}, threshold=1, generation=2),
            commissioning_digest=DIGEST, anchors_key_roles={}, anchors_keys={})
    elif condition == "revoked":
        statement = RevocationList(sequence=1, issued_at=NOW, revoked_generations=frozenset({5}))
        (trust / "revocations.signed").write_bytes(
            revoker.sign(statement.signature_target()).signature + statement.as_payload())
    # The daemon keeps its own clock floor (its state, raised at most once a
    # second); establish it first so the snapshot covers only status reads.
    service.handle(None)
    before = snapshot(root.parent.parent.parent.parent)
    # collect also exercises its AZAZEL_ROOT default; no runtime import in library.
    facts = flow.collect(args(), now=NOW)
    reading = _knowledge_reading(root, as_of=NOW)
    assert reading == service.handle(None)
    assert reading["reason_code"] == reason
    assert facts["knowledge-store"].state is expected
    assert "reason: " + reason in facts["knowledge-store"].reason
    out = StringIO()
    _render_knowledge(reading, out)
    assert "state: " + reading["state"] in out.getvalue()
    assert "reason: " + reason in out.getvalue()
    if reason == "available":
        assert f"bundle: {reading['bundle_digest_short']} (shortened); signing key ids: " in out.getvalue()
        assert "claims: static 0; current 1; nearest expiry: 2027-01-01T00:00:00Z" in out.getvalue()
    else:
        assert "signing key ids" not in out.getvalue()
    status = StringIO()
    assert main(["--sysfs", str(root / "nosysfs"), "--edge-root", str(root / "noedge"),
                 "--knowledge-lite", str(root), "--as-of", NOW, "status"], out=status) == 0
    assert "freshness [knowledge_lite]: " + reading["state"] in status.getvalue()
    assert "reason: " + reason in status.getvalue()
    if expected is not State.COMPLETE:
        assert reading["state"] != "available"
        assert "state: available" not in out.getvalue()
    assert snapshot(root.parent.parent.parent.parent) == before
    assert facts["knowledge-trust"].state is State.COMPLETE


def test_unit_mask_is_observed_without_claiming_active(tmp_path, fixture_host):
    mask = tmp_path / "etc/systemd/system/azazel-commissiond.service"
    mask.parent.mkdir(parents=True)
    mask.symlink_to("/dev/null")
    fact = flow.collect(args(), now=NOW, root=tmp_path)["activation-units"]
    assert fact.state is State.UNKNOWN
    assert "observed masks: azazel-commissiond.service" in fact.reason
    assert fact.command.startswith("systemctl status azazel-activated.service")


def _timer_files(root, *names):
    for name in names:
        unit = root / "usr/lib/systemd/system" / name
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text("[Timer]\n", encoding="utf-8")


def test_operator_observers_step_names_the_enable_command_until_both_timers_are_linked(
        tmp_path, fixture_host):
    """M24: the installer enables neither observer (SPEC 2.3), so setup is
    where an operator enables them; the step is `needed` with the exact
    command until both wants links exist, and reads only links."""
    timers = ("azazel-noc-observe.timer", "azazel-units-observe.timer")
    fact = flow.collect(args(), now=NOW, root=tmp_path)["operator-observers"]
    assert fact.state is State.UNKNOWN and "not installed" in fact.reason
    _timer_files(tmp_path, *timers)
    fact = flow.collect(args(), now=NOW, root=tmp_path)["operator-observers"]
    assert fact.state is State.MISSING
    assert fact.command == "sudo systemctl enable --now " + " ".join(timers)
    assert "not observed (not enabled)" in fact.reason
    wants = tmp_path / "etc/systemd/system/timers.target.wants"
    wants.mkdir(parents=True)
    (wants / timers[0]).symlink_to("/usr/lib/systemd/system/" + timers[0])
    fact = flow.collect(args(), now=NOW, root=tmp_path)["operator-observers"]
    assert fact.state is State.MISSING
    assert fact.command == "sudo systemctl enable --now " + timers[1]
    (wants / timers[1]).symlink_to("/usr/lib/systemd/system/" + timers[1])
    fact = flow.collect(args(), now=NOW, root=tmp_path)["operator-observers"]
    assert fact.state is State.COMPLETE
    steps = {step.name: step for step in flow.evaluate({"operator-observers": fact})}
    assert steps["operator-observers"].status == "done"


def test_manifest_option_error_is_json():
    out = StringIO()
    assert main(["setup", "--json", "--installed-manifest", "/reviewed.json"], out=out) == 2
    assert json.loads(out.getvalue())["error"].endswith("together")


@pytest.mark.parametrize("denied_at", ["record", "pending"])
def test_protected_metadata_denied_becomes_blocked_rows(tmp_path, fixture_host, monkeypatch, denied_at, private_os):
    private_os(flow)
    original_file = Path.is_file
    original_exists = Path.exists

    def is_file(path):
        if "commissioning" in path.parts or (denied_at == "record" and path.name in {"deployment.json", "selection.json"}):
            raise PermissionError("private-identity-sentinel")
        return original_file(path)

    def exists(path):
        if denied_at == "pending" and path.suffix == ".pending":
            raise PermissionError("private-identity-sentinel")
        return original_exists(path)

    monkeypatch.setattr(Path, "is_file", is_file)
    monkeypatch.setattr(Path, "exists", exists)
    monkeypatch.setattr(flow.os, "geteuid", lambda: 1000)
    facts = flow.collect(args(), now=NOW, root=tmp_path)
    assert facts["commissioning"].state is State.REFUSED
    assert facts["bootstrap-deployment"].state is State.REFUSED
    assert facts["bootstrap-selection"].state is State.REFUSED
    assert "sentinel" not in repr(facts)
    for name in ("commissioning", "bootstrap-deployment", "bootstrap-selection"):
        assert facts[name].reason == "not readable by this user (run as root)"
        assert "initialize" not in facts[name].command
        assert "as root" in facts[name].command


def test_vm_lab_stale_boot_hg05_json_is_read_only(tmp_path, fixture_host, monkeypatch):
    from azazel_nexus import lab_host
    from azazel_nexus.bootstrap_selection_store import SelectionReadRefused
    marker = put(tmp_path, "/etc/azazel-lab/LAB-HOST")
    monkeypatch.setattr(lab_host, "LAB_HOST_MARKER", marker)
    monkeypatch.setattr(flow, "is_lab_host", lab_host.is_lab_host)
    put(tmp_path, "/etc/azazel/bootstrap/selection.json")
    def stale():
        raise SelectionReadRefused("boot binding differs from the current boot")
    monkeypatch.setattr(flow, "load_bootstrap_selection", stale)
    original = flow.collect
    monkeypatch.setattr(flow, "collect", lambda args, *, now: original(args, now=now, root=tmp_path))
    before = snapshot(tmp_path)
    out = StringIO()
    assert main(["setup", "--json"], out=out) == 0
    doc = json.loads(out.getvalue())
    assert doc["lab_host"] is True
    steps = {s["name"]: s for s in doc["steps"]}
    assert "boot binding differs" in steps["bootstrap-selection"]["reason"]
    assert all(s["next_command"] != "azazel-nexus setup" for s in steps.values())
    assert steps["host-preflight"]["status"] == "done"
    assert steps["host-preflight"]["next_command"] == "azazel-nexus hil-preflight"
    for name in ("commissioning", "commission-review", "model-import-fetched", "provider-admission"):
        assert steps[name]["next_command"].startswith("none available")
        assert "LAB_HOST_MARKER" in steps[name]["reason"]
    assert doc["mio"]["ceiling"] is None
    assert "route ledger not readable by this user" in doc["mio"]["availability"]
    assert steps["provider-admission"]["status"] == "blocked"
    assert snapshot(tmp_path) == before


def test_setup_reports_recorded_mio_in_text_and_json(tmp_path, fixture_host, monkeypatch):
    from azazel_nexus.audit import AuditLedger
    from azazel_nexus.mio_status import ROUTE_LEDGER
    path = put(tmp_path, ROUTE_LEDGER, b"")
    AuditLedger(path).append({"event_type": "mio.capability.transition", "to": "CORE",
                              "occurred_at": "2026-10-19T00:00:00Z",
                              "reasons": {"profile": "FULL", "resource": "core_reserve_unmeasured",
                                          "trust": "not-checked", "topology": "no_verified_egress",
                                          "health": {"local": "unavailable", "remote": "not_admitted"}}})
    original = flow.collect
    monkeypatch.setattr(flow, "collect", lambda args, *, now: original(args, now=now, root=tmp_path))
    before = snapshot(tmp_path)
    for options in (["setup"], ["setup", "--json"]):
        out = StringIO()
        assert main(options, out=out) == 0
        text = out.getvalue()
        assert "not a grant or admission" in text
        if "--json" in options:
            reading = json.loads(text)["mio"]
            assert reading["ceiling"] == "FULL"
            assert reading["state"] == "CORE"
        else:
            assert "recorded ceiling: FULL; capability state: CORE" in text
        assert "core_reserve_unmeasured" in text
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("complete_host", [True, False])
def test_lab_next_keeps_completed_evidence_and_explains_stop(monkeypatch, complete_host):
    from azazel_nexus.operator_flow import ORDER, Observation
    facts = {name: Observation(State.COMPLETE, "scoped read succeeded", "azazel-nexus status")
             for name in ORDER}
    facts["commissioning"] = Observation(State.MISSING, "record absent", "azazel-nexus commission --help")
    if not complete_host:
        facts["host-preflight"] = Observation(State.MISSING, "inventory incomplete", "azazel-nexus hil-preflight")
    monkeypatch.setattr(flow, "collect", lambda args, *, now: facts)
    monkeypatch.setattr(flow, "is_lab_host", lambda: True)
    for options in (["setup", "--next"], ["setup", "--next", "--json"]):
        out = StringIO()
        assert main(options, out=out) == 0
        text = out.getvalue()
        assert "ordered flow stops here" in text
        assert "unavailable on a lab host (LAB_HOST_MARKER)" in text
        expected = "commissioning" if complete_host else "host-preflight"
        if "--json" in options:
            assert json.loads(text)["steps"][0]["name"] == expected
        else:
            assert expected + ": needed" in text


def test_setup_redacts_malformed_mio_ledger_in_text_and_json(tmp_path, fixture_host, monkeypatch):
    from azazel_nexus.audit import AuditLedger
    from azazel_nexus.mio_status import ROUTE_LEDGER
    path = put(tmp_path, ROUTE_LEDGER, b"")
    AuditLedger(path).append({"event_type": "mio.capability.transition", "to": "CORE",
                              "occurred_at": "2026-10-19T00:00:00Z\x1b[31mprivate",
                              "reasons": {"profile": "FULL", "unexpected": "private\nvalue"}})
    original = flow.collect
    monkeypatch.setattr(flow, "collect", lambda args, *, now: original(args, now=now, root=tmp_path))
    for options in (["setup"], ["setup", "--json"]):
        out = StringIO()
        assert main(options, out=out) == 0
        text = out.getvalue()
        assert "private" not in text and "unexpected" not in text and "\x1b" not in text
        assert "entryd credentials are not read" in text
        if "--json" in options:
            reading = json.loads(text)["mio"]
            assert reading["state"] is None and reading["ceiling"] is None
            assert reading["reasons"] == {} and reading["observed_at"] is None


def test_permission_denied_as_root_does_not_advise_running_as_root(monkeypatch, private_os):
    private_os(flow)
    monkeypatch.setattr(flow.os, "geteuid", lambda: 0)
    observation = flow._permission_denied()
    assert observation.state is State.REFUSED
    assert "as root" not in observation.command
    monkeypatch.setattr(flow.os, "geteuid", lambda: 1000)
    assert "as root" in flow._permission_denied().command
