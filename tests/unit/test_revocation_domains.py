"""Cross-protocol vectors with valid signatures and valid manifest controls."""

import io
import json
import tarfile
from pathlib import Path

import pytest

from azazel_nexus.lite_bundle import BundleRefused, TrustAnchors, verify_bundle
from azazel_nexus.revocation import (
    REVOCATION_DOMAIN,
    RevocationList,
    RevocationRefused,
    RevocationStore,
)
from azazel_nexus.revocation_policy import REVOCATION_SIGNING, RevocationPolicy
from azazel_nexus.signature import verify_detached

FIXTURES = Path(__file__).parents[1] / "fixtures" / "revocation"


def vector(name):
    raw = json.loads((FIXTURES / f"{name}.json").read_text())
    return bytes.fromhex(raw["public_key"]), raw["payload"].encode(), bytes.fromhex(raw["signature"])


def bundle(payload, signature):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, body in {"manifest.json": payload, "manifest.sig": f"test:{signature.hex()}\n".encode()}.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return output.getvalue()


@pytest.mark.parametrize("name", ["manifest", "manifest-with-sequence"])
def test_real_manifest_signature_cannot_revoke_even_with_revocation_fields(tmp_path, name):
    key, payload, signature = vector(name)
    # The exact fixture passes the actual bundle verifier, not just an oracle.
    assert verify_bundle(bundle(payload, signature), anchors=TrustAnchors(1, {"test": key}))
    assert verify_detached(public_key=key, message=payload, signature=signature)
    authority = RevocationPolicy({"test": key}, {"test": REVOCATION_SIGNING}, 1, 1)
    store = RevocationStore(tmp_path, authority)
    assert store._signer_of(signature, payload) is None
    if name == "manifest-with-sequence":
        parsed = RevocationList.parse(payload)
        assert parsed.sequence == 1 and parsed.issued_at
    refusal = (
        "a revocation list names 'sequence'" if name == "manifest" else
        "unverified: revocation threshold not met by distinct trusted keys; "
        "the cache is out of service rather than unrevoked"
    )
    with pytest.raises(RevocationRefused) as caught:
        store.accept(signature + payload)
    assert str(caught.value) == refusal
    assert store.current().sequence == 0


def test_revocation_signature_is_refused_as_a_manifest_at_the_signature_gate(tmp_path):
    key, payload, signature = vector("revocation")
    assert verify_detached(public_key=key, message=REVOCATION_DOMAIN + payload, signature=signature)
    authority = RevocationPolicy({"test": key}, {"test": REVOCATION_SIGNING}, 1, 1)
    assert RevocationStore(tmp_path, authority).accept(signature + payload).sequence == 1
    with pytest.raises(BundleRefused) as caught:
        verify_bundle(bundle(payload, signature), anchors=TrustAnchors(1, {"test": key}))
    assert caught.value.code == "BUNDLE_SIGNATURE_THRESHOLD_NOT_MET"


@pytest.mark.parametrize("name", ["manifest", "manifest-with-sequence"])
def test_manifest_as_stored_revocation_is_unverified_through_consumer(tmp_path, name):
    from signing_oracle import sign_detached
    from test_integration import a_view
    from test_revocation_policy import COMMISSIONING, KEYS, NOW, SEEDS

    from azazel_nexus.lite_service import KnowledgeLite, LiteReasonCode, LiteState
    from azazel_nexus.lite_trust import TrustStore
    from azazel_nexus.revocation_policy import commission_policy

    key, payload, signature = vector(name)
    authority = RevocationPolicy({"test": key}, {"test": REVOCATION_SIGNING}, 1, 1)
    commission_policy(tmp_path, authority, commissioning_digest=COMMISSIONING, anchors_key_roles={})
    TrustStore(tmp_path).pin([KEYS[0].hex()], commissioning_digest=COMMISSIONING, pinned_at=NOW, actor="test")
    lite = KnowledgeLite(tmp_path, COMMISSIONING, claims_of=lambda _: [{"expiry": "2027-01-01T00:00:00Z"}])
    artifact = b"live artifact"
    assert lite.admit(artifact=artifact, signature=sign_detached(seed=SEEDS[0], message=artifact), admitted_at=NOW).admitted
    lite.revocations().path.write_bytes(signature + payload)
    reading = lite.read(as_of=NOW)
    assert reading.state is LiteState.QUARANTINED
    assert reading.reason_code is LiteReasonCode.UNVERIFIED
    assert reading.reason.startswith("unverified revocation list:")
    assert reading.served == ()
    assert reading.as_event()["reason_code"] == "unverified"
    view = a_view(knowledge=reading)
    assert view.row("freshness", "knowledge_lite").value == "unverified"
    assert view.row("knowledge_supplier", "knowledge").value == "none"


@pytest.mark.parametrize("failure", ["content", "claims"])
def test_other_consumer_quarantines_do_not_render_unverified(tmp_path, failure):
    from signing_oracle import sign_detached
    from test_integration import a_view
    from test_revocation_policy import COMMISSIONING, KEYS, NOW, SEEDS, commissioned

    from azazel_nexus.content_store import ContentRefused
    from azazel_nexus.lite_service import KnowledgeLite, LiteState
    from azazel_nexus.lite_trust import TrustStore

    commissioned(tmp_path)
    TrustStore(tmp_path).pin([KEYS[0].hex()], commissioning_digest=COMMISSIONING, pinned_at=NOW, actor="test")
    fail_claims = False

    def claims(_):
        if fail_claims:
            raise ContentRefused("unverified claim data")
        return [{"expiry": "2027-01-01T00:00:00Z"}]

    lite = KnowledgeLite(tmp_path, COMMISSIONING, claims_of=claims)
    artifact = b"live artifact"
    admitted = lite.admit(artifact=artifact, signature=sign_detached(seed=SEEDS[0], message=artifact), admitted_at=NOW)
    assert admitted.admitted
    if failure == "content":
        lite.content.path_for(admitted.artifact_digest).write_bytes(b"corrupt")
    else:
        fail_claims = True
    reading = lite.read(as_of=NOW)
    assert reading.state is LiteState.QUARANTINED
    assert reading.reason_code is None
    assert reading.served == ()
    assert a_view(knowledge=reading).row("freshness", "knowledge_lite").value == "quarantined"
