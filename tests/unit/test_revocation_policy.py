"""Commissioning, threshold, cumulative continuity and the real consumer path."""

import ast
import json
from dataclasses import replace
from pathlib import Path

import pytest
from signing_oracle import public_key_for, sign_detached

from azazel_nexus.content_store import digest_bytes
from azazel_nexus.lite_service import KnowledgeLite, LiteReasonCode, LiteState
from azazel_nexus.lite_trust import TrustStore
from azazel_nexus.revocation import (
    REVOCATION_DOMAIN,
    RevocationList,
    RevocationRefused,
    RevocationStore,
    encode_signed,
)
from azazel_nexus.revocation_policy import (
    BUNDLE_SIGNING,
    POLICY_FILENAME,
    REVOCATION_SIGNING,
    RevocationPolicy,
    RevocationPolicyRefused,
    commission_policy,
    read_policy_record,
)

SEEDS = [bytes(range(start, start + 32)) for start in (0, 32, 64, 96)]
KEYS = [public_key_for(seed) for seed in SEEDS]
COMMISSIONING = "sha256:" + "a" * 64
NOW = "2026-10-17T00:00:00Z"


def policy(*, threshold=1, generation=1, keys=None, roles=None):
    return RevocationPolicy(
        keys=keys if keys is not None else dict(zip(("bundle", "r1", "r2", "unassigned"), KEYS, strict=True)),
        key_roles=roles if roles is not None else {
            "bundle": BUNDLE_SIGNING, "r1": REVOCATION_SIGNING, "r2": REVOCATION_SIGNING,
        }, threshold=threshold, generation=generation,
    )


def statement(sequence=1, **kwargs):
    return RevocationList(sequence=sequence, issued_at=NOW, **kwargs)


def signed(item, *indices):
    return encode_signed(item.as_payload(), [
        sign_detached(seed=SEEDS[i], message=item.signature_target()) for i in (indices or (1,))
    ])


def commissioned(root, authority=None, digest=COMMISSIONING):
    commission_policy(root, authority or policy(), commissioning_digest=digest, anchors_key_roles={})
    return reopen(root, digest)


def reopen(root, digest=COMMISSIONING):
    record = read_policy_record(root, digest)
    return RevocationStore(root, RevocationPolicy.from_record(record["policy"]), record)


@pytest.mark.parametrize("already_promoted", [False, True])
def test_revocation_accept_refuses_repin_between_record_read_and_write(
    tmp_path, monkeypatch, already_promoted,
):
    from azazel_nexus import revocation
    from azazel_nexus.audit import AuditLedger
    from azazel_nexus.lite_trust import RepinConfirmation, RepinRequest
    from azazel_nexus.revocation_policy import policy_path

    trust = TrustStore(tmp_path / "lite")
    trust.pin([KEYS[0].hex()], commissioning_digest=COMMISSIONING, pinned_at=NOW, actor="root")
    store = commissioned(trust.root)
    store.accept(signed(statement()))
    anchor = tmp_path / "anchor.json"
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    confirmation = RepinConfirmation("test-only", NOW)
    request = RepinRequest(anchor, "recover authority", "root")
    if already_promoted:
        anchor.write_text(json.dumps({"keys": [KEYS[0].hex(), KEYS[3].hex()]}))
        trust.repin(request, confirmation=confirmation, ledger=ledger, now=NOW)
        store = reopen(trust.root)
    old_path = policy_path(trust.root)
    old_record = old_path.read_bytes()
    old_blob = store.path.read_bytes()
    replacement = policy(generation=2, keys={"new": KEYS[3]}, roles={"new": REVOCATION_SIGNING})
    anchor.write_text(json.dumps({
        "keys": [KEYS[0].hex()], "revocation_policy": replacement.as_record(),
    }))
    read = revocation.read_policy_record
    reads = 0
    promoted = {}

    def read_then_repin(*args, **kwargs):
        nonlocal reads
        record = read(*args, **kwargs)
        reads += 1
        # current() reads first; flip after accept() reads its write checkpoint.
        if reads == 2:
            trust.repin(request, confirmation=confirmation, ledger=ledger, now=NOW)
            promoted["path"] = policy_path(trust.root)
            promoted["record"] = promoted["path"].read_bytes()
        return record

    monkeypatch.setattr(revocation, "read_policy_record", read_then_repin)
    with pytest.raises(RevocationRefused, match="trust generation changed"):
        store.accept(signed(statement(2)))
    assert promoted["path"].read_bytes() == promoted["record"]
    assert old_path.read_bytes() == old_record
    assert store.path.read_bytes() == old_blob
    assert reopen(trust.root).policy == replacement
    assert reopen(trust.root).current() == statement()


@pytest.mark.parametrize("threshold", [None, 0, -1, True, "1", 3])
def test_threshold_is_explicit_positive_and_feasible(threshold):
    with pytest.raises(RevocationPolicyRefused):
        policy(threshold=threshold)


def test_missing_threshold_does_not_inherit_bundle_threshold():
    raw = policy().as_record()
    del raw["threshold"]
    with pytest.raises(RevocationPolicyRefused):
        RevocationPolicy.from_record(raw)


@pytest.mark.parametrize("role", [[BUNDLE_SIGNING, REVOCATION_SIGNING], "release"])
def test_key_cannot_have_multiple_or_unknown_roles(role):
    with pytest.raises(RevocationPolicyRefused):
        policy(roles={"r1": role})


def test_aliases_cannot_give_the_same_key_both_roles():
    with pytest.raises(RevocationPolicyRefused, match="both roles"):
        policy(keys={"bundle": KEYS[1], "r1": KEYS[1]}, roles={
            "bundle": BUNDLE_SIGNING, "r1": REVOCATION_SIGNING,
        })


@pytest.mark.parametrize("index", [0, 3])
def test_bundle_and_unassigned_keys_cannot_revoke(tmp_path, index):
    store = commissioned(tmp_path)
    with pytest.raises(RevocationRefused, match="unverified"):
        store.accept(signed(statement(), index))
    assert store.current().sequence == 0


def test_signer_of_ignores_bundle_and_unassigned_keys(tmp_path):
    store = commissioned(tmp_path)
    item = statement()
    for index in (0, 3):
        sig = sign_detached(seed=SEEDS[index], message=item.signature_target())
        assert store._signer_of(sig, item.as_payload()) is None


def test_distinct_signers_count_not_duplicate_signatures_or_ids(tmp_path):
    store = commissioned(tmp_path, policy(threshold=2))
    for indices in ((1,), (1, 1), (0, 1), (1, 3)):
        with pytest.raises(RevocationRefused, match="unverified.*threshold"):
            store.accept(signed(statement(), *indices))
    store.accept(signed(statement(), 1, 2))
    assert reopen(tmp_path).current().sequence == 1
    with pytest.raises(RevocationPolicyRefused, match="distinct"):
        policy(threshold=2, keys={"r1": KEYS[1], "alias": KEYS[1]}, roles={
            "r1": REVOCATION_SIGNING, "alias": REVOCATION_SIGNING,
        })


def test_policy_is_immutable_after_validation():
    keys, roles = {"r1": KEYS[1]}, {"r1": REVOCATION_SIGNING}
    authority = policy(keys=keys, roles=roles)
    keys.clear()
    roles["r1"] = BUNDLE_SIGNING
    assert authority.revocation_keys == frozenset({KEYS[1]})


def test_conflict_with_anchors_is_refused(tmp_path):
    with pytest.raises(RevocationPolicyRefused, match="conflicts"):
        commission_policy(tmp_path, policy(), commissioning_digest=COMMISSIONING,
                          anchors_key_roles={"r1": BUNDLE_SIGNING})
    assert not (tmp_path / POLICY_FILENAME).exists()
    with pytest.raises(RevocationPolicyRefused, match="conflicts"):
        policy().check_anchors({"alias": BUNDLE_SIGNING}, {"alias": KEYS[1]})


def test_self_revocation_is_refused(tmp_path):
    store = commissioned(tmp_path)
    with pytest.raises(RevocationRefused, match="self-revocation"):
        store.accept(signed(statement(revoked_keys=frozenset({KEYS[1].hex()}))))
    assert store.current().sequence == 0


def test_last_key_revocation_is_refused_even_in_a_signed_blob(tmp_path):
    store = commissioned(tmp_path)
    # Both keys withdrawn: there is no remaining revocation authority.
    with pytest.raises(RevocationRefused, match="last revocation-signing key"):
        store.accept(signed(statement(revoked_keys=frozenset({KEYS[1].hex(), KEYS[2].hex()}))))
    assert store.current().sequence == 0


def test_revoked_signer_and_reenable_are_refused(tmp_path):
    store = commissioned(tmp_path)
    revoked = frozenset({KEYS[2].hex()})
    store.accept(signed(statement(revoked_keys=revoked)))
    with pytest.raises(RevocationRefused, match="itself revoked"):
        store.accept(signed(statement(2, revoked_keys=revoked), 2))
    with pytest.raises(RevocationRefused, match="re-enabled"):
        store.accept(signed(statement(2)))
    store.accept(signed(statement(2, revoked_keys=revoked)))
    assert reopen(tmp_path).current().revoked_keys == revoked


def test_continuity_across_recommissioning_and_new_authority(tmp_path):
    store = commissioned(tmp_path)
    revoked = frozenset({KEYS[2].hex()})
    first = statement(7, revoked_keys=revoked, revoked_digests=frozenset({digest_bytes(b"bad")}))
    store.accept(signed(first))
    new = policy(generation=2, keys={"new": KEYS[3]}, roles={"new": REVOCATION_SIGNING})
    second_digest = "sha256:" + "b" * 64
    changed = commissioned(tmp_path, new, second_digest)
    assert changed.current() == first
    for incoming in (replace(first, generation=2), statement(8, generation=2)):
        with pytest.raises(RevocationRefused):
            changed.accept(signed(incoming, 3))
    changed.accept(signed(replace(first, sequence=8, generation=2), 3))
    assert reopen(tmp_path, second_digest).current().sequence == 8
    with pytest.raises(RevocationRefused):
        changed.accept(signed(replace(first, sequence=9)))
    # An old authority cannot inject a different old-generation stored list.
    changed.path.write_bytes(signed(replace(first, sequence=100)))
    with pytest.raises(RevocationRefused, match="generation"):
        changed.current()


def test_recommission_cannot_reintroduce_revoked_material(tmp_path):
    store = commissioned(tmp_path)
    store.accept(signed(statement(revoked_keys=frozenset({KEYS[2].hex()}))))
    before = (tmp_path / POLICY_FILENAME).read_bytes()
    with pytest.raises(RevocationPolicyRefused, match="re-enable"):
        commissioned(tmp_path, policy(generation=2))
    assert (tmp_path / POLICY_FILENAME).read_bytes() == before
    assert store.current().sequence == 1


def test_missing_checkpoint_list_is_not_empty(tmp_path):
    store = commissioned(tmp_path)
    store.accept(signed(statement()))
    commissioned(tmp_path, policy(generation=2))
    store.path.unlink()
    with pytest.raises(RevocationRefused, match="missing"):
        reopen(tmp_path).current()


def test_invalid_generation_role_and_legacy_payload_are_refused(tmp_path):
    store = commissioned(tmp_path)
    with pytest.raises(RevocationRefused, match="generation"):
        store.accept(signed(statement(generation=2)))
    for raw in ({"sequence": 1, "issued_at": NOW}, {**json.loads(statement().as_payload()), "role": BUNDLE_SIGNING}):
        payload = json.dumps(raw).encode()
        with pytest.raises(RevocationRefused, match="role"):
            store.accept(sign_detached(seed=SEEDS[1], message=REVOCATION_DOMAIN + payload) + payload)


def test_one_changed_separator_byte_is_refused(tmp_path):
    item = statement()
    bad_domain = bytes([REVOCATION_DOMAIN[0] ^ 1]) + REVOCATION_DOMAIN[1:]
    blob = sign_detached(seed=SEEDS[1], message=bad_domain + item.as_payload()) + item.as_payload()
    with pytest.raises(RevocationRefused, match="unverified"):
        commissioned(tmp_path).accept(blob)


def test_separator_has_one_definition_and_both_paths_reference_it():
    import azazel_nexus.revocation as module

    tree = ast.parse(Path(module.__file__).read_text())
    literals = [node for node in ast.walk(tree) if isinstance(node, ast.Constant)
                and node.value == REVOCATION_DOMAIN]
    assert len(literals) == 1
    for name in ("signature_target", "_signer_of"):
        function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name)
        assert any(isinstance(node, ast.Name) and node.id == "REVOCATION_DOMAIN" for node in ast.walk(function))


def test_consumer_reads_revocation_policy_and_withdraws_live_artifact(tmp_path):
    commissioned(tmp_path)
    TrustStore(tmp_path).pin([KEYS[0].hex()], commissioning_digest=COMMISSIONING, pinned_at=NOW, actor="test")
    lite = KnowledgeLite(tmp_path, COMMISSIONING, claims_of=lambda _: [{"id": "a", "expiry": "2027-01-01T00:00:00Z"}])
    artifact = b"test artifact"
    admitted = lite.admit(artifact=artifact, signature=sign_detached(seed=SEEDS[0], message=artifact), admitted_at=NOW)
    assert admitted.state is LiteState.AVAILABLE
    lite.revocations().accept(signed(statement(revoked_digests=frozenset({digest_bytes(artifact)}))))
    reading = lite.read(as_of=NOW)
    assert reading.state is LiteState.QUARANTINED
    assert "revoked by revocation sequence 1" in reading.reason
    assert reading.served == ()


def test_consumer_missing_policy_is_fail_closed(tmp_path):
    lite = KnowledgeLite(tmp_path, COMMISSIONING)
    with pytest.raises(RevocationRefused, match="unverified"):
        lite.revocations()


def test_consumer_checks_anchors_conflicts_at_read_time(tmp_path):
    commissioned(tmp_path)
    path = tmp_path / "trust" / "anchors.toml"
    path.parent.mkdir()
    path.write_text(f'threshold = 1\n[keys]\nr1 = "{KEYS[1].hex()}"\n[key_roles]\nr1 = "bundle-signing"\n')
    with pytest.raises(RevocationRefused, match="conflicts"):
        KnowledgeLite(tmp_path, COMMISSIONING).revocations()


def test_failed_atomic_write_preserves_the_previous_statement(tmp_path, monkeypatch, private_os):
    import azazel_nexus.revocation as module
    private_os(module)

    store = commissioned(tmp_path)
    store.accept(signed(statement()))
    before = store.path.read_bytes()
    def fail(*args):
        raise OSError("full")
    monkeypatch.setattr(module.os, "replace", fail)
    with pytest.raises(OSError):
        store.accept(signed(statement(2)))
    assert store.path.read_bytes() == before
    assert not list(tmp_path.glob(".revocations-*"))


def test_accepted_high_water_survives_disk_rollback_and_deletion(tmp_path):
    store = commissioned(tmp_path)
    old = signed(statement())
    store.accept(old)
    revoked = frozenset({KEYS[2].hex()})
    latest = signed(statement(2, revoked_keys=revoked))
    store.accept(latest)
    store.path.write_bytes(old)
    with pytest.raises(RevocationRefused):
        reopen(tmp_path).current()
    with pytest.raises(RevocationPolicyRefused):
        commissioned(tmp_path, policy(generation=2))
    store.path.unlink()
    with pytest.raises(RevocationRefused, match="missing"):
        reopen(tmp_path).current()
    # Restoring the exact protected statement is safe; a new list cannot
    # bypass the unreadable/rolled-back state by discarding its revocations.
    reopen(tmp_path).accept(latest)
    assert reopen(tmp_path).current().revoked_keys == revoked


def test_interrupted_blob_publication_holds_closed_and_exact_retry_recovers(tmp_path, monkeypatch, private_os):
    import azazel_nexus.revocation as module
    private_os(module)

    store = commissioned(tmp_path)
    store.accept(signed(statement()))
    latest = signed(statement(2, revoked_keys=frozenset({KEYS[2].hex()})))
    replace_file = module.os.replace
    def fail_blob(source, target):
        if target == store.path:
            raise OSError("interrupted publication")
        replace_file(source, target)
    monkeypatch.setattr(module.os, "replace", fail_blob)
    with pytest.raises(OSError):
        store.accept(latest)
    with pytest.raises(RevocationRefused):
        reopen(tmp_path).current()
    with pytest.raises(RevocationRefused):
        reopen(tmp_path).accept(signed(statement(3)))
    monkeypatch.setattr(module.os, "replace", replace_file)
    reopen(tmp_path).accept(latest)
    assert reopen(tmp_path).current().sequence == 2


def test_old_store_cannot_write_after_policy_promotion(tmp_path):
    old = commissioned(tmp_path)
    commissioned(tmp_path, policy(generation=2))
    with pytest.raises(RevocationRefused, match="superseded"):
        old.accept(signed(statement()))


def test_malformed_stored_digest_quarantines_consumer_instead_of_raising(tmp_path):
    commissioned(tmp_path)
    TrustStore(tmp_path).pin([KEYS[0].hex()], commissioning_digest=COMMISSIONING, pinned_at=NOW, actor="test")
    lite = KnowledgeLite(tmp_path, COMMISSIONING, claims_of=lambda _: [{"expiry": "2027-01-01T00:00:00Z"}])
    artifact = b"live"
    assert lite.admit(artifact=artifact, signature=sign_detached(seed=SEEDS[0], message=artifact), admitted_at=NOW).admitted
    raw = json.loads(statement().as_payload())
    raw["revoked_digests"] = ["../../etc/passwd"]
    payload = json.dumps(raw).encode()
    lite.revocations().path.write_bytes(sign_detached(seed=SEEDS[1], message=REVOCATION_DOMAIN + payload) + payload)
    reading = lite.read(as_of=NOW)
    assert reading.state is LiteState.QUARANTINED
    assert reading.served == ()


@pytest.mark.parametrize("indices", [(1,), (0, 1), (0,)])
def test_pinned_revocation_key_cannot_admit_without_anchors(tmp_path, indices):
    commissioned(tmp_path)
    TrustStore(tmp_path).pin([KEYS[i].hex() for i in indices], commissioning_digest=COMMISSIONING, pinned_at=NOW, actor="test")
    assert not (tmp_path / "trust" / "anchors.toml").exists()
    lite = KnowledgeLite(tmp_path, COMMISSIONING, claims_of=lambda _: [{"expiry": "2027-01-01T00:00:00Z"}])
    artifact = b"role separation"
    signer_index = indices[0]
    reading = lite.admit(artifact=artifact, signature=sign_detached(seed=SEEDS[signer_index], message=artifact), admitted_at=NOW)
    if 1 in indices:
        assert not reading.admitted
        assert reading.state is LiteState.UNAVAILABLE
        assert reading.reason_code is LiteReasonCode.UNVERIFIED
        assert "pinned bundle key material has the revocation-signing role" in reading.reason
        assert lite.generations.live() is None
    else:
        assert reading.admitted
        assert reading.state is LiteState.AVAILABLE
        assert reading.reason_code is None


def test_read_rechecks_pinned_key_roles_without_anchors(tmp_path):
    commissioned(tmp_path)
    TrustStore(tmp_path).pin([KEYS[0].hex()], commissioning_digest=COMMISSIONING, pinned_at=NOW, actor="test")
    lite = KnowledgeLite(tmp_path, COMMISSIONING, claims_of=lambda _: [{"expiry": "2027-01-01T00:00:00Z"}])
    artifact = b"previously admitted"
    assert lite.admit(artifact=artifact, signature=sign_detached(seed=SEEDS[0], message=artifact), admitted_at=NOW).admitted
    commissioned(tmp_path, policy(generation=2, keys={"alias": KEYS[0]}, roles={"alias": REVOCATION_SIGNING}))
    reading = lite.read(as_of=NOW)
    assert reading.state is LiteState.QUARANTINED
    assert reading.reason_code is LiteReasonCode.UNVERIFIED
    assert "pinned bundle key material has the revocation-signing role" in reading.reason
    assert reading.served == ()
