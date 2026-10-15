"""Bootstrap generations stay separate from normal activation generations."""

from __future__ import annotations

import json

import pytest

from azazel_nexus.activation import (
    CORE_UNITS,
    ActivationController,
    ActivationLease,
    RecordingUnitController,
)
from azazel_nexus.audit import AuditLedger
from azazel_nexus.bootstrap_approval import BOOTSTRAP_UNITS, BootstrapContext
from azazel_nexus.bootstrap_generation import verify_bootstrap_generation
from azazel_nexus.generation import GenerationRefused, GenerationStore, tree_digest

NOW = "2026-10-13T00:00:00Z"
COMMISSIONING = "sha256:" + "a" * 64
POLICY = "sha256:" + "b" * 64
PACKAGE = "sha256:" + "c" * 64
CLOSURE = "sha256:" + "d" * 64


def _context(files: dict[str, bytes] | None = None, **changes) -> BootstrapContext:
    config = _config(policy=changes.get("policy_digest", POLICY),
                     package=changes.get("package_digest", PACKAGE),
                     closure=changes.get("unit_closure_digest", CLOSURE))
    digest = tree_digest(files if files is not None else {"bootstrap.json": config})
    fields = {
        "approval_id": "11111111-1111-4111-8111-111111111111",
        "node_digest": "sha256:" + "1" * 64,
        "boot_id": "22222222-2222-4222-8222-222222222222",
        "generation": 7,
        "generation_digest": digest,
        "package_digest": PACKAGE,
        "unit_closure_digest": CLOSURE,
        "policy_digest": POLICY,
        "approval_policy_digest": "sha256:" + "e" * 64,
        "security_epoch": 3,
        "revocation_digest": "sha256:" + "f" * 64,
    }
    fields.update(changes)
    return BootstrapContext(**fields)


def _config(*, policy=POLICY, package=PACKAGE, closure=CLOSURE) -> bytes:
    return json.dumps({
        "schema": "azazel-nexus/bootstrap-config/v1",
        "variant": "bootstrap/uncommissioned",
        "units": BOOTSTRAP_UNITS,
        "policy_digest": policy,
        "package_digest": package,
        "unit_closure_digest": closure,
    }, sort_keys=True, separators=(",", ":")).encode()


def _bootstrap_metadata(context: BootstrapContext, digest=None) -> bytes:
    document = {
        "schema": "azazel-nexus/bootstrap-generation/v1",
        "variant": "bootstrap/uncommissioned",
        "number": context.generation,
        "digest": digest or context.generation_digest,
        "created_at": NOW,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def _write_bootstrap(store: GenerationStore, *, number=7, package_digest=PACKAGE):
    files = {"bootstrap.json": _config(package=package_digest)}
    context = _context(files, generation=number, package_digest=package_digest)
    directory = store.root / str(number)
    (directory / "tree").mkdir(parents=True)
    (directory / "tree" / "bootstrap.json").write_bytes(files["bootstrap.json"])
    (directory / "generation.json").write_bytes(_bootstrap_metadata(context))
    return context, files


def test_legacy_generation_metadata_remains_readable_verifiable_and_rollbackable(tmp_path):
    store = GenerationStore(tmp_path / "generations")
    first = store.create({"node.yaml": b"one\n"}, created_at=NOW,
                         commissioning_digest=COMMISSIONING)
    # Older metadata omitted the optional evidence-binding member.
    path = store._meta(first.number)
    metadata = json.loads(path.read_text())
    metadata.pop("commissioning_evidence_binding", None)
    path.write_text(json.dumps(metadata))

    assert store.read(1).commissioning_digest == COMMISSIONING
    assert store.verify(1).number == 1
    assert store.current().number == 1
    store.create({"node.yaml": b"two\n"}, created_at=NOW,
                 commissioning_digest=COMMISSIONING)
    rollback = store.roll_back_to(1, created_at=NOW, reason="restore", actor="op")
    assert rollback.number == 3
    assert store.verify(3).commissioning_digest == COMMISSIONING


@pytest.mark.parametrize("reader", ["read", "verify", "current", "rollback"])
def test_normal_generation_paths_reject_bootstrap_metadata(tmp_path, reader):
    store = GenerationStore(tmp_path / "generations")
    store.root.mkdir()
    _write_bootstrap(store, number=1)
    with pytest.raises(GenerationRefused):
        if reader == "read":
            store.read(1)
        elif reader == "verify":
            store.verify(1)
        elif reader == "current":
            store.current()
        else:
            store.roll_back_to(1, created_at=NOW, reason="restore", actor="op")


def test_activation_with_normal_lease_masks_on_bootstrap_generation(tmp_path):
    store = GenerationStore(tmp_path / "generations")
    store.root.mkdir()
    context, _ = _write_bootstrap(store, number=1)
    units = RecordingUnitController(d.name for d in CORE_UNITS)
    controller = ActivationController(
        units=units, generations=store, ledger=AuditLedger(tmp_path / "ledger.jsonl"),
        definitions=CORE_UNITS,
    )
    lease = ActivationLease(
        granted_by="operator", granted_at="2026-10-12T00:00:00Z",
        expires_at="2026-10-14T00:00:00Z", generation_digest=context.generation_digest,
        generation_number=1, commissioning_digest=COMMISSIONING,
    )

    outcome = controller.activate(now=NOW, actor="operator", lease=lease)
    assert outcome.granted == ()
    assert all(operation == "mask" for operation, _ in units.calls)
    assert any(v.reason.startswith("generation_unverified:") for v in outcome.verdicts)


@pytest.mark.parametrize("metadata", [b"{", b"[]", b"null"])
def test_normal_reader_refuses_malformed_metadata(tmp_path, metadata):
    store = GenerationStore(tmp_path / "generations")
    store.root.mkdir()
    directory = store.root / "1"
    directory.mkdir()
    (directory / "generation.json").write_bytes(metadata)
    with pytest.raises(GenerationRefused):
        store.read(1)


def test_normal_reader_refuses_duplicate_metadata_keys_and_boolean_number(tmp_path):
    store = GenerationStore(tmp_path / "generations")
    store.root.mkdir()
    directory = store.root / "1"
    directory.mkdir()
    valid = {"number": 1, "digest": "sha256:" + "0" * 64,
             "created_at": NOW, "commissioning_digest": COMMISSIONING}
    (directory / "generation.json").write_text(
        json.dumps(valid)[:-1] + ',"number":1}'
    )
    with pytest.raises(GenerationRefused):
        store.read(1)
    valid["number"] = True
    (directory / "generation.json").write_text(json.dumps(valid))
    with pytest.raises(GenerationRefused):
        store.read(1)


def test_normal_reader_refuses_directory_number_mismatch(tmp_path):
    store = GenerationStore(tmp_path / "generations")
    store.root.mkdir()
    directory = store.root / "1"
    directory.mkdir()
    (directory / "generation.json").write_text(json.dumps({
        "number": 2, "digest": "sha256:" + "0" * 64,
        "created_at": NOW, "commissioning_digest": COMMISSIONING,
    }))
    with pytest.raises(GenerationRefused):
        store.read(1)


@pytest.mark.parametrize(
    ("field", "value"),
    [("supersedes", 0), ("supersedes", -1),
     ("rolled_back_from", 0), ("rolled_back_from", 1),
     ("rolled_back_from", 2)],
)
def test_normal_reader_refuses_impossible_generation_ancestry(tmp_path, field, value):
    store = GenerationStore(tmp_path / "generations")
    store.root.mkdir()
    directory = store.root / "1"
    directory.mkdir()
    metadata = {
        "number": 1,
        "digest": "sha256:" + "0" * 64,
        "created_at": NOW,
        "commissioning_digest": COMMISSIONING,
        "rollback_reason": "recorded reason",
        "actor": "operator",
        field: value,
    }
    (directory / "generation.json").write_text(json.dumps(metadata))

    with pytest.raises(GenerationRefused):
        store.read(1)


@pytest.mark.parametrize("bad_field", ["rollback_reason", "actor"])
def test_malformed_rollback_metadata_is_refused_and_activation_masks(tmp_path, bad_field):
    store = GenerationStore(tmp_path / "generations")
    store.root.mkdir()
    directory = store.root / "1"
    directory.mkdir()
    metadata = {
        "number": 1,
        "digest": "sha256:" + "0" * 64,
        "created_at": NOW,
        "commissioning_digest": COMMISSIONING,
        "rolled_back_from": 0,
        "rollback_reason": "recovery",
        "actor": "operator",
    }
    metadata[bad_field] = 42 if bad_field == "rollback_reason" else ["operator"]
    (directory / "generation.json").write_text(json.dumps(metadata))

    with pytest.raises(GenerationRefused):
        store.read(1)

    units = RecordingUnitController(d.name for d in CORE_UNITS)
    controller = ActivationController(
        units=units, generations=store, ledger=AuditLedger(tmp_path / "ledger.jsonl"),
        definitions=CORE_UNITS,
    )
    outcome = controller.activate(
        now=NOW,
        actor="operator",
        lease=ActivationLease(
            granted_by="operator", granted_at="2026-10-12T00:00:00Z",
            expires_at="2026-10-14T00:00:00Z",
            generation_digest=metadata["digest"],
        ),
    )
    assert outcome.granted == ()
    assert units.calls
    assert all(operation == "mask" for operation, _ in units.calls)


@pytest.mark.parametrize("commissioning_digest", [None, True, "invalid", "SHA256:" + "a" * 64])
def test_normal_reader_requires_valid_commissioning_digest(tmp_path, commissioning_digest):
    store = GenerationStore(tmp_path / "generations")
    store.root.mkdir()
    directory = store.root / "1"
    directory.mkdir()
    metadata = {
        "number": 1,
        "digest": "sha256:" + "0" * 64,
        "created_at": NOW,
        "commissioning_digest": commissioning_digest,
    }
    if commissioning_digest is None:
        metadata.pop("commissioning_digest")
    (directory / "generation.json").write_text(json.dumps(metadata))
    with pytest.raises(GenerationRefused):
        store.read(1)


def test_bootstrap_verifier_binds_context_tree_and_has_no_commissioning_digest():
    files = {"bootstrap.json": _config()}
    context = _context(files)
    result = verify_bootstrap_generation(
        metadata=_bootstrap_metadata(context), files=files, expected=context,
    )
    assert result.number == context.generation
    assert result.digest == context.generation_digest
    assert not hasattr(result, "commissioning_digest")

    changed_context = _context(files, policy_digest="sha256:" + "9" * 64)
    with pytest.raises(GenerationRefused):
        verify_bootstrap_generation(
            metadata=_bootstrap_metadata(context), files=files, expected=changed_context,
        )


def test_bootstrap_verifier_rejects_extra_executable_file_and_tampering():
    files = {"bootstrap.json": _config()}
    context = _context(files)
    metadata = _bootstrap_metadata(context)
    with pytest.raises(GenerationRefused):
        verify_bootstrap_generation(
            metadata=metadata, files={**files, "start.sh": b"#!/bin/sh\n"},
            expected=context,
        )
    with pytest.raises(GenerationRefused):
        verify_bootstrap_generation(
            metadata=metadata, files={"bootstrap.json": files["bootstrap.json"] + b" "},
            expected=context,
        )


@pytest.mark.parametrize("malformation", ["duplicate", "boolean_number", "extra_field"])
def test_bootstrap_verifier_rejects_noncanonical_or_extended_metadata(malformation):
    files = {"bootstrap.json": _config()}
    context = _context(files)
    document = json.loads(_bootstrap_metadata(context))
    if malformation == "duplicate":
        metadata = _bootstrap_metadata(context)[:-1] + b',"number":7}'
    else:
        if malformation == "boolean_number":
            document["number"] = True
        else:
            document["commissioning_digest"] = COMMISSIONING
        metadata = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(GenerationRefused):
        verify_bootstrap_generation(metadata=metadata, files=files, expected=context)
