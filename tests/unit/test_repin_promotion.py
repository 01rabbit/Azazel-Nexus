"""Staged trust-root promotion, audit minimization and authority invariants (#86)."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import traceback
from dataclasses import FrozenInstanceError

import pytest
from signing_oracle import public_key_for, sign_detached
from test_lite_bundle import _tar

from azazel_nexus import lite_trust
from azazel_nexus.audit import AuditLedger
from azazel_nexus.edge_package import inspect as inspect_edge
from azazel_nexus.lite_bundle import TrustAnchors, verify_bundle
from azazel_nexus.lite_service import KnowledgeLite, LiteState
from azazel_nexus.lite_trust import (
    MAX_ANCHOR_BYTES,
    RepinConfirmation,
    RepinRequest,
    TrustRefused,
    TrustStore,
)

SEED = bytes(range(32))
OLD = public_key_for(SEED).hex()
NEW = public_key_for(bytes(range(32, 64))).hex()
COMMISSIONING = "sha256:" + "a" * 64
NOW = "2026-10-17T00:00:00Z"
CONFIRMATION = RepinConfirmation("test-confirmation-only", NOW)


@pytest.fixture()
def node(tmp_path):
    trust = TrustStore(tmp_path / "lite")
    trust.pin([OLD], commissioning_digest=COMMISSIONING, pinned_at=NOW, actor="op")
    anchor = tmp_path / "anchor.json"
    anchor.write_text(json.dumps({"keys": [NEW]}), encoding="utf-8")
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    return trust, RepinRequest(anchor, "retire previous signer", "root"), ledger


def promote(node, *, confirmation=CONFIRMATION):
    trust, request, ledger = node
    return trust.repin(request, confirmation=confirmation, ledger=ledger, now=NOW)


def old_bundle(trust):
    lite = KnowledgeLite(
        trust.root, COMMISSIONING,
        claims_of=lambda payload: json.loads(payload)["claims"],
    )
    payload = b'{"claims":[{"id":"test-reference"}]}'
    reading = lite.admit(
        artifact=payload, signature=sign_detached(seed=SEED, message=payload), admitted_at=NOW,
    )
    assert reading.state is LiteState.AVAILABLE
    manifest = json.dumps({
        "bundle_format_version": 1, "bundle_version": 7, "kind": "full", "files": {},
    }, sort_keys=True).encode()
    bundle = _tar({
        "manifest.json": manifest,
        "manifest.sig": b"old:" + sign_detached(seed=SEED, message=manifest).hex().encode() + b"\n",
    })
    verify_old_bundle(trust, bundle)
    return lite, bundle


def verify_old_bundle(trust, bundle):
    keys = trust.keys(commissioning_digest=COMMISSIONING)
    accepted = verify_bundle(bundle, anchors=TrustAnchors(
        threshold=1, keys={"old": next(key for key in keys if key.hex() == OLD)},
        revoked=frozenset(), key_roles={},
    ))
    assert accepted.signers == ("old",)


def test_success_has_exact_audit_fields_and_no_confirmation_or_keys(node):
    trust, request, ledger = node
    original = trust.path.read_bytes()
    result = promote(node)
    assert result.promoted is True
    assert result.reason_code == "promoted"
    assert result.generation == trust.current_generation() == 1
    assert trust.keys(commissioning_digest=COMMISSIONING) == (bytes.fromhex(NEW),)
    assert (trust.root / "trust.json").read_bytes() == original
    assert TrustStore(trust.root).path == trust.path  # Works after a restart too.
    entries = list(ledger)
    assert len(entries) == 2
    assert entries[0].event == {
        "event_type": "trust.repin.authorized",
        "generation": 1,
        "old_fingerprint": result.old_fingerprint,
        "new_fingerprint": result.new_fingerprint,
        "principal": request.principal,
        "at": NOW,
        "reason": request.reason,
    }
    assert entries[1].event == {**entries[0].event, "event_type": "trust.repin.promoted"}
    assert set(entries[0].event) == {
        "event_type", "generation", "old_fingerprint", "new_fingerprint", "principal", "at", "reason",
    }
    assert result.old_fingerprint != result.new_fingerprint
    assert result.old_fingerprint == "sha256:" + hashlib.sha256(
        b"azazel-nexus/trust-root/v1\x00" + bytes.fromhex(OLD),
    ).hexdigest()
    assert all(value.startswith("sha256:") and len(value) == 71 for value in (
        result.old_fingerprint, result.new_fingerprint,
    ))
    text = ledger.path.read_text()
    for secret in (OLD, NEW, CONFIRMATION.nonce, "confirmed_at", "nonce"):
        assert secret not in text
    ledger.verify()


@pytest.mark.parametrize("previous_promotion", [False, True])
@pytest.mark.parametrize("failure", ["staging", "validation", "generation", "pointer", "audit"])
def test_each_failed_stage_retains_old_root_generation_and_bundle(
    node, monkeypatch, failure, previous_promotion,
):
    trust, request, ledger = node
    if previous_promotion:
        # Keep OLD admitted in generation 1, then try to remove it.
        request.new_anchor_path.write_text(json.dumps({"keys": [OLD, NEW]}))
        promote(node)
        request.new_anchor_path.write_text(json.dumps({"keys": [NEW]}))
    lite, bundle = old_bundle(trust)
    before_path = trust.path
    before = trust.path.read_bytes()
    generation = trust.current_generation()
    initial_events = len(list(ledger))
    write = lite_trust._atomic_write

    def refused(*args, **kwargs):
        # Deliberately tainted exception text must never reach the caller.
        raise OSError(NEW)

    def write_with_failure(path, payload, **kwargs):
        if failure == "generation" and path.parent.name == "trust-generations":
            refused()
        if failure == "pointer" and path.name == "trust-current":
            refused()
        return write(path, payload, **kwargs)

    if failure == "staging":
        monkeypatch.setattr(lite_trust.os, "fsync", refused)
    elif failure == "validation":
        request.new_anchor_path.write_text('{"keys":["' + NEW + 'bad"]}')
    elif failure == "audit":
        monkeypatch.setattr(ledger, "append", refused)
    else:
        monkeypatch.setattr(lite_trust, "_atomic_write", write_with_failure)
    with pytest.raises(TrustRefused) as caught:
        promote(node)
    assert failure in str(caught.value)
    rendered = "".join(traceback.format_exception(caught.value))
    assert NEW not in rendered and OLD not in rendered
    assert trust.path == before_path
    assert trust.path.read_bytes() == before
    assert trust.current_generation() == generation
    assert bytes.fromhex(OLD) in trust.keys(commissioning_digest=COMMISSIONING)
    assert lite.read(as_of=NOW).state is LiteState.AVAILABLE
    verify_old_bundle(trust, bundle)
    assert not list((trust.root / "trust-staging").iterdir())
    # Audit precedes the pointer, so a failed swap leaves an authorized attempt.
    assert len(list(ledger)) == initial_events + (failure == "pointer")


@pytest.mark.parametrize("payload", [
    b"not-json", b"[]", b"{}", b'{"keys":[]}', b'{"keys":"bad"}',
    b'{"keys":[null]}', b'{"keys":[42]}', b'{"keys":["bad"]}',
    json.dumps({"keys": [OLD, OLD]}).encode(),
    json.dumps({"keys": ["00" * 32]}).encode(),
])
def test_invalid_empty_and_unchanged_roots_are_refused(node, payload):
    trust, request, ledger = node
    request.new_anchor_path.write_bytes(payload)
    with pytest.raises(TrustRefused):
        promote(node)
    assert trust.current_generation() == 0
    assert trust.keys(commissioning_digest=COMMISSIONING) == (bytes.fromhex(OLD),)
    assert list(ledger) == []


@pytest.mark.parametrize("kind", ["symlink", "directory", "fifo", "oversized", "missing"])
def test_source_must_be_bounded_regular_file_without_following_symlinks(node, kind):
    trust, request, ledger = node
    source = request.new_anchor_path
    source.unlink()
    if kind == "symlink":
        target = source.with_suffix(".target")
        target.write_text(json.dumps({"keys": [NEW]}))
        source.symlink_to(target)
    elif kind == "directory":
        source.mkdir()
    elif kind == "fifo":
        os.mkfifo(source)
    elif kind == "oversized":
        source.write_bytes(b" " * (MAX_ANCHOR_BYTES + 1))
    with pytest.raises(TrustRefused, match="staging refused"):
        promote(node)
    assert trust.current_generation() == 0
    assert list(ledger) == []


@pytest.mark.parametrize("confirmation", [None, "yes", object()])
def test_confirmation_object_is_required(node, confirmation):
    with pytest.raises(TrustRefused, match="confirmation"):
        promote(node, confirmation=confirmation)
    assert node[0].current_generation() == 0
    assert list(node[2]) == []


def test_library_does_not_inspect_nonce_or_confirmation_timestamp(node):
    assert promote(node, confirmation=RepinConfirmation("", "")).promoted


def test_request_and_confirmation_are_immutable(node):
    with pytest.raises(FrozenInstanceError):
        node[1].reason = "changed"
    with pytest.raises(FrozenInstanceError):
        CONFIRMATION.nonce = "changed"


@pytest.mark.parametrize("reason", ["", " ", "\n\t", OLD, NEW])
def test_unexplained_or_key_containing_reason_is_refused(node, reason):
    trust, request, ledger = node
    request = RepinRequest(request.new_anchor_path, reason, request.principal)
    with pytest.raises(TrustRefused):
        promote((trust, request, ledger))
    assert trust.current_generation() == 0
    assert list(ledger) == []


def test_unpinned_store_refuses_repin(tmp_path):
    trust = TrustStore(tmp_path / "uncommissioned")
    with pytest.raises(TrustRefused, match="first pinning is `pin`"):
        promote((trust, RepinRequest(tmp_path / "missing", "retirement", "root"),
                 AuditLedger(tmp_path / "ledger")))
    assert not trust.root.exists()


def test_owner_group_and_mode_survive_promotion(node):
    trust, _, _ = node
    trust.path.chmod(0o640)
    before = trust.path.stat()
    root_before = trust.root.stat()
    promote(node)
    root_after = trust.root.stat()
    for path in (trust.path, trust.root / "trust-current",
                 trust.root / "trust-generations", trust.root / "trust-staging"):
        after = path.stat()
        expected_mode = 0o750 if path.is_dir() else 0o640
        assert (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)) == (
            before.st_uid, before.st_gid, expected_mode,
        )
    assert (root_after.st_uid, root_after.st_gid, root_after.st_mode) == (
        root_before.st_uid, root_before.st_gid, root_before.st_mode,
    )


def test_second_promotion_is_monotonic_and_retains_predecessor(node):
    trust, request, ledger = node
    first = promote(node)
    old_path = trust.path
    request.new_anchor_path.write_text(json.dumps({"keys": [NEW, OLD]}))
    second = promote(node)
    assert second.generation == first.generation + 1 == 2
    assert second.old_fingerprint == first.new_fingerprint
    assert old_path.is_file()
    assert len(list(ledger)) == 4
    with pytest.raises(TrustRefused, match="do not carry across"):
        trust.keys(commissioning_digest="other-commissioning")
    with pytest.raises(TrustRefused, match="already pinned"):
        trust.pin([OLD], commissioning_digest=COMMISSIONING, pinned_at=NOW, actor="op")


@pytest.mark.parametrize("with_lease", [False, True])
def test_repin_changes_no_edge_readiness_authority_lease_or_enforcement(node, with_lease):
    from azazel_nexus.activation import (
        ActivationController,
        ActivationLease,
        RecordingUnitController,
        UnitDefinition,
        UnitTier,
    )
    from azazel_nexus.generation import GenerationStore

    trust, _, ledger = node
    edge = trust.root / "no-edge-here"
    generations = GenerationStore(trust.root / "host-generations")
    generation = generations.create(
        {"test-config": b"observation"}, created_at=NOW, commissioning_digest=COMMISSIONING,
    )
    definition = UnitDefinition("test-enforcement.service", UnitTier.ENFORCEMENT,
                                "azenforce", "test enforcement")
    units = RecordingUnitController([definition.name])
    controller = ActivationController(
        units=units, generations=generations, ledger=ledger, definitions=[definition],
    )
    lease = ActivationLease("operator", NOW, "2026-10-18T00:00:00Z", generation.digest) if with_lease else None
    before = inspect_edge(edge).as_event()
    activation_before = controller.activate(now=NOW, actor="root", lease=lease)
    calls_before = list(units.calls)
    promote(node)
    assert controller._lease is lease
    assert units.calls == calls_before  # Repin cannot invoke any authority verb.
    assert generations.current() == generation
    after = inspect_edge(edge).as_event()
    activation_after = controller.activate(now=NOW, actor="root", lease=lease)
    assert before == after
    assert after["ready"] is False
    assert after["presence"] == "absent"
    assert activation_before.granted == activation_after.granted == ()
    assert activation_before.enforcement_ready is activation_after.enforcement_ready is False
    assert activation_before.verdicts == activation_after.verdicts


def test_omitting_confirmation_keyword_is_refused(node):
    trust, request, ledger = node
    with pytest.raises(TypeError, match="confirmation"):
        trust.repin(request, ledger=ledger, now=NOW)
    assert trust.current_generation() == 0
    assert list(ledger) == []


def test_changed_source_size_cannot_bypass_read_bound(node, monkeypatch):
    from types import SimpleNamespace

    trust, request, ledger = node
    request.new_anchor_path.write_bytes(b" " * (MAX_ANCHOR_BYTES + 1))
    monkeypatch.setattr(lite_trust.os, "fstat", lambda fd: SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600, st_size=0,
    ))
    with pytest.raises(TrustRefused, match="staging refused"):
        promote(node)
    assert trust.current_generation() == 0
    assert list(ledger) == []


@pytest.mark.parametrize("pointer", ["../trust.json", "", "0", "9" * 5000, "1"])
def test_broken_pointer_cannot_fall_back_to_commissioning_or_allow_first_pin(node, pointer):
    trust, _, _ = node
    (trust.root / "trust-current").write_text(pointer)
    with pytest.raises(TrustRefused):
        trust.keys(commissioning_digest=COMMISSIONING)
    with pytest.raises(TrustRefused, match="already pinned"):
        trust.pin([NEW], commissioning_digest=COMMISSIONING, pinned_at=NOW, actor="root")


def test_duplicate_order_does_not_disguise_unchanged_root(node):
    trust, request, ledger = node
    request.new_anchor_path.write_text(json.dumps({"keys": [NEW, OLD]}))
    promote(node)
    request.new_anchor_path.write_text(json.dumps({"keys": [OLD, NEW, NEW]}))
    with pytest.raises(TrustRefused, match="validation refused"):
        promote(node)
    assert trust.current_generation() == 1
    assert len(list(ledger)) == 2


@pytest.mark.parametrize("remove_orphan", [False, True])
def test_failed_pointer_swap_then_retry_has_distinct_authorization(node, monkeypatch, remove_orphan):
    trust, _, ledger = node
    replace = lite_trust.os.replace

    def fail_pointer(source, destination):
        if destination.name == "trust-current":
            raise OSError("test failed swap")
        return replace(source, destination)

    with monkeypatch.context() as patch:
        patch.setattr(lite_trust.os, "replace", fail_pointer)
        with pytest.raises(TrustRefused, match="pointer refused"):
            promote(node)
    assert trust.current_generation() == 0
    if remove_orphan:
        (trust.root / "trust-generations" / "1.json").unlink()
    # Reconstruct the store to prove reservation survives process restart.
    result = promote((TrustStore(trust.root), node[1], ledger))
    events = [entry.event for entry in ledger]
    assert [(event["event_type"], event["generation"]) for event in events] == [
        ("trust.repin.authorized", 1),
        ("trust.repin.authorized", 2),
        ("trust.repin.promoted", 2),
    ]
    assert result.generation == trust.current_generation() == 2
    ledger.verify()


@pytest.mark.parametrize("field", ["reason", "principal"])
@pytest.mark.parametrize("key", [OLD, NEW])
@pytest.mark.parametrize("fragment", [slice(None), slice(0, 16), slice(7, 23), slice(-16, None)])
def test_provenance_rejects_case_insensitive_key_fragments(node, field, key, fragment):
    trust, request, ledger = node
    values = {"reason": request.reason, "principal": request.principal}
    values[field] = "prefix " + key[fragment].upper() + " suffix"
    with pytest.raises(TrustRefused):
        promote((trust, RepinRequest(request.new_anchor_path, **values), ledger))
    assert list(ledger) == []
    assert trust.current_generation() == 0


@pytest.mark.parametrize("length", [512, 513])
def test_reason_length_is_bounded(node, length):
    trust, request, ledger = node
    request = RepinRequest(request.new_anchor_path, "r" * length, request.principal)
    if length == 512:
        assert promote((trust, request, ledger)).promoted
    else:
        with pytest.raises(TrustRefused):
            promote((trust, request, ledger))
        assert list(ledger) == []


def test_generation_files_also_determine_next_number(node):
    trust, _, _ = node
    promote(node)
    (trust.root / "trust-generations" / "8.json").write_text("orphan")
    node[1].new_anchor_path.write_text(json.dumps({"keys": [OLD, NEW]}))
    assert promote(node).generation == 9


def test_replace_fsync_and_promoted_audit_order(node, monkeypatch):
    trust, _, ledger = node
    operations = []
    replace = lite_trust.os.replace
    sync = lite_trust._fsync_directory
    append = ledger.append

    def track_replace(source, destination):
        replace(source, destination)
        operations.append(("replace", destination.name))

    def track_sync(path):
        sync(path)
        operations.append(("fsync", path.name))

    def track_append(event):
        append(event)
        operations.append(("audit", event["event_type"]))

    monkeypatch.setattr(lite_trust.os, "replace", track_replace)
    monkeypatch.setattr(lite_trust, "_fsync_directory", track_sync)
    monkeypatch.setattr(ledger, "append", track_append)
    promote(node)
    generation = operations.index(("replace", "1.json"))
    assert operations[generation + 1] == ("fsync", "trust-generations")
    pointer = operations.index(("replace", "trust-current"))
    assert operations[pointer - 1] == ("audit", "trust.repin.authorized")
    assert operations[pointer + 1:pointer + 3] == [
        ("fsync", trust.root.name), ("audit", "trust.repin.promoted"),
    ]


def test_pointer_directory_fsync_failure_never_records_promoted(node, monkeypatch):
    trust, _, ledger = node
    sync = lite_trust._fsync_directory

    def fail_after_pointer(path):
        if (trust.root / "trust-current").exists():
            raise OSError("test directory fsync failure")
        sync(path)

    monkeypatch.setattr(lite_trust, "_fsync_directory", fail_after_pointer)
    with pytest.raises(TrustRefused, match="inspect the active trust pointer"):
        promote(node)
    assert trust.current_generation() == 1
    assert [entry.event["event_type"] for entry in ledger] == ["trust.repin.authorized"]


def test_promoted_audit_failure_does_not_claim_root_unchanged(node, monkeypatch):
    trust, _, ledger = node
    append = ledger.append

    def fail_promoted(event):
        if event["event_type"] == "trust.repin.promoted":
            raise OSError("test ledger failure")
        return append(event)

    monkeypatch.setattr(ledger, "append", fail_promoted)
    with pytest.raises(TrustRefused, match="promotion audit refused; inspect"):
        promote(node)
    assert trust.current_generation() == 1
    assert [entry.event["event_type"] for entry in ledger] == ["trust.repin.authorized"]
