"""The only thing the transport believes, and what it takes to forge one (#98).

A `SanitizerDecision` is a Python object: anything that can construct one can
claim its contents. The remote daemon runs behind its own socket under its
own account, so what reaches it is bytes -- and it believes exactly one
shape, a signature over a canonical payload binding five independent facts.

Every test here drives a **forgery or a misuse**, because the value of the
envelope is entirely in what it refuses. A suite that only showed a good
envelope opening would be a suite that passes with every check deleted.

No real sanitizer, no real key, no real frame: the signing key is a fixed
package-owned test seed, used nowhere else.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from nacl import signing as nacl_signing

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "runtime" / "src"))

from azazel_nexus.provider_registry import PROVIDER_DOMAIN  # noqa: E402
from azazel_nexus.model_catalog import CATALOG_DOMAIN  # noqa: E402
from azazel_nexus.remote_envelope import (  # noqa: E402
    ENVELOPE_DOMAIN,
    ENVELOPE_SCHEMA,
    MAX_ENVELOPE_BYTES,
    EnvelopeRefusal,
    EnvelopeRefused,
    NonceLedger,
    REMOTE_ELIGIBLE,
    envelope_payload,
    open_envelope,
)
from azazel_nexus.sanitizer import NEVER_REMOTE, PrivacyClass  # noqa: E402

#: A fixed, test-only seed. It signs nothing outside this file, holds no
#: production role, and is not a commissioned sanitizer key.
_SEED = b"\x31" * 32
_OTHER_SEED = b"\x32" * 32

NOW = "2026-09-21T12:00:00Z"
LATER = "2026-09-21T13:00:00Z"
EARLIER = "2026-09-21T11:00:00Z"
PROVIDER = "vendor-advisory"
REVISION = 7
NONCE = "a" * 48
FRAME = json.dumps({"observed": "scan", "count": "2-5"}, sort_keys=True).encode()


def _key(seed: bytes = _SEED) -> nacl_signing.SigningKey:
    return nacl_signing.SigningKey(seed)


def _public(seed: bytes = _SEED) -> bytes:
    """Thirty-two raw bytes, which is what `verify_detached` takes."""

    return bytes(_key(seed).verify_key)


def _seal(
    *,
    frame: bytes = FRAME,
    privacy_class: PrivacyClass = PrivacyClass.P1_SANITIZED,
    policy_version: str = "2026-09-01",
    policy_revision: int = REVISION,
    provider_id: str = PROVIDER,
    nonce: str = NONCE,
    expires_at: str = LATER,
    frame_bytes: int = None,
    seed: bytes = _SEED,
    domain: bytes = ENVELOPE_DOMAIN,
) -> bytes:
    """Mint an envelope the way a sanitizer boundary would."""

    payload = envelope_payload(
        content_digest="sha256:" + hashlib.sha256(frame).hexdigest(),
        privacy_class=privacy_class,
        policy_version=policy_version,
        policy_revision=policy_revision,
        provider_id=provider_id,
        nonce=nonce,
        expires_at=expires_at,
        frame_bytes=len(frame) if frame_bytes is None else frame_bytes,
    )
    return bytes(_key(seed).sign(domain + payload).signature) + payload


def _open(raw: bytes, *, frame: bytes = FRAME, **overrides):
    kwargs = dict(
        frame=frame,
        sanitizer_keys={"sanitizer-1": _public()},
        provider_id=PROVIDER,
        policy_revision=REVISION,
        now=NOW,
        nonces=NonceLedger(),
    )
    kwargs.update(overrides)
    return open_envelope(raw, **kwargs)


def _refusal(raw: bytes, **overrides) -> EnvelopeRefusal:
    with pytest.raises(EnvelopeRefused) as caught:
        _open(raw, **overrides)
    return caught.value.refusal


# -- it opens at all ------------------------------------------------------


def test_a_well_formed_envelope_opens():
    """So every refusal below is a refusal, not a function that never works."""

    opened = _open(_seal())
    assert opened.privacy_class is PrivacyClass.P1_SANITIZED
    assert opened.provider_id == PROVIDER
    assert opened.policy_revision == REVISION
    assert opened.frame_bytes == len(FRAME)


def test_what_it_reports_carries_no_frame_content():
    """An audit entry that quoted the frame would be an audit entry that
    carried what the sanitizer removed."""

    event = repr(_open(_seal()).as_event())
    assert "observed" not in event and "scan" not in event
    assert "sha256:" in event


# -- 1. it is signed, under this domain, by a sanitizer key ---------------


def test_an_unsigned_envelope_is_refused():
    payload = envelope_payload(
        content_digest="sha256:" + hashlib.sha256(FRAME).hexdigest(),
        privacy_class=PrivacyClass.P1_SANITIZED,
        policy_version="v",
        policy_revision=REVISION,
        provider_id=PROVIDER,
        nonce=NONCE,
        expires_at=LATER,
        frame_bytes=len(FRAME),
    )
    assert _refusal(b"\x00" * 64 + payload) is EnvelopeRefusal.UNSIGNED


def test_another_key_cannot_mint_one():
    assert _refusal(_seal(seed=_OTHER_SEED)) is EnvelopeRefusal.UNSIGNED


@pytest.mark.parametrize(
    "domain", [CATALOG_DOMAIN, PROVIDER_DOMAIN, b"", b"azazel-nexus/sanitized-envelope/v2\x00"],
    ids=["catalog", "provider-registry", "no-domain", "next-version"],
)
def test_a_signature_under_another_domain_does_not_verify(domain):
    """The whole point of domain separation: a key that signs catalogs does
    not thereby authorise egress of a frame."""

    assert _refusal(_seal(domain=domain)) is EnvelopeRefusal.UNSIGNED


def test_no_commissioned_key_means_nothing_opens():
    """The shipped state. No key holds the sanitizer role, so no envelope
    verifies however well formed it is."""

    assert _refusal(_seal(), sanitizer_keys={}) is EnvelopeRefusal.UNSIGNED


# -- 2. the class comes from inside, and never from a caller --------------


@pytest.mark.parametrize("never", sorted(NEVER_REMOTE, key=lambda c: c.value))
def test_a_signed_envelope_cannot_authorise_a_never_remote_class(never):
    """Even correctly signed by a commissioned key. A sanitizer that minted
    one would be a sanitizer that had gone wrong, and this is the component
    that must not go wrong with it."""

    assert (
        _refusal(_seal(privacy_class=never))
        is EnvelopeRefusal.CLASS_NOT_REMOTE_ELIGIBLE
    )


def test_the_eligible_set_is_exactly_the_two_that_may_leave():
    assert REMOTE_ELIGIBLE == {PrivacyClass.P0_PUBLIC, PrivacyClass.P1_SANITIZED}
    assert REMOTE_ELIGIBLE & NEVER_REMOTE == set()
    assert REMOTE_ELIGIBLE | NEVER_REMOTE == set(PrivacyClass)


def test_a_class_outside_the_vocabulary_is_refused():
    payload = json.loads(
        envelope_payload(
            content_digest="sha256:" + hashlib.sha256(FRAME).hexdigest(),
            privacy_class=PrivacyClass.P1_SANITIZED,
            policy_version="v",
            policy_revision=REVISION,
            provider_id=PROVIDER,
            nonce=NONCE,
            expires_at=LATER,
            frame_bytes=len(FRAME),
        )
    )
    payload["privacy_class"] = "P0-public-ish"
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    raw = bytes(_key().sign(ENVELOPE_DOMAIN + body).signature) + body
    assert _refusal(raw) is EnvelopeRefusal.CLASS_NOT_REMOTE_ELIGIBLE


# -- 3. it is bound to the content ---------------------------------------


def test_an_envelope_minted_for_one_frame_does_not_authorise_another():
    """The replay that matters most: a legitimate authorisation reused to
    send something else."""

    assert (
        _refusal(_seal(), frame=b'{"observed":"everything"}')
        is EnvelopeRefusal.CONTENT_MISMATCH
    )


def test_a_frame_of_the_same_length_but_different_bytes_is_refused():
    """Length is not identity. Checked separately so that a digest check
    removed in favour of a length check would fail here."""

    other = bytes(len(FRAME))
    assert len(other) == len(FRAME)
    assert _refusal(_seal(), frame=other) is EnvelopeRefusal.CONTENT_MISMATCH


def test_a_declared_length_that_disagrees_with_the_frame_is_refused():
    assert (
        _refusal(_seal(frame_bytes=len(FRAME) + 1))
        is EnvelopeRefusal.CONTENT_MISMATCH
    )


# -- 4. policy revision, provider binding, expiry ------------------------


def test_a_frame_sanitised_under_a_withdrawn_policy_is_not_sanitised_now():
    assert (
        _refusal(_seal(policy_revision=REVISION - 1))
        is EnvelopeRefusal.POLICY_REVISION_MISMATCH
    )


def test_an_envelope_for_one_provider_does_not_authorise_another():
    """Otherwise an authorisation to tell provider A becomes an authorisation
    to tell anybody."""

    assert (
        _refusal(_seal(provider_id="somebody-else"))
        is EnvelopeRefusal.PROVIDER_MISMATCH
    )


def test_an_expired_envelope_is_refused():
    assert _refusal(_seal(expires_at=EARLIER)) is EnvelopeRefusal.EXPIRED


def test_an_envelope_expiring_exactly_now_is_refused():
    """The boundary belongs on the refusing side of every check here."""

    assert _refusal(_seal(expires_at=NOW)) is EnvelopeRefusal.EXPIRED


def test_expiry_is_judged_against_a_clock_the_caller_supplies():
    """A component that read its own clock would have an expiry nobody can
    reproduce, and an expiry nobody can reproduce is one nobody can test."""

    assert _open(_seal(expires_at=LATER), now=NOW).expires_at == LATER
    with pytest.raises(EnvelopeRefused):
        _open(_seal(expires_at=LATER), now="2026-09-22T00:00:00Z")


# -- 5. one use each ------------------------------------------------------


def test_an_envelope_authorises_exactly_one_request():
    ledger = NonceLedger()
    _open(_seal(), nonces=ledger)
    assert _refusal(_seal(), nonces=ledger) is EnvelopeRefusal.REPLAYED


def test_a_refused_envelope_does_not_burn_its_nonce():
    """Spending the nonce before the other checks would let a malformed
    envelope consume the one a correct request needs."""

    ledger = NonceLedger()
    with pytest.raises(EnvelopeRefused):
        _open(_seal(provider_id="wrong"), nonces=ledger)
    assert len(ledger) == 0
    assert _open(_seal(), nonces=ledger).nonce == NONCE


def test_a_full_ledger_stops_accepting_rather_than_forgetting():
    """An eviction policy is a policy for forgetting that a request was
    already sent, and a forgotten nonce is a replay that succeeds."""

    ledger = NonceLedger(capacity=1)
    _open(_seal(), nonces=ledger)
    assert (
        _refusal(_seal(nonce="b" * 48), nonces=ledger) is EnvelopeRefusal.REPLAYED
    )


def test_a_ledger_that_remembers_nothing_cannot_be_built():
    with pytest.raises(ValueError):
        NonceLedger(capacity=0)


def test_a_short_nonce_is_refused():
    assert _refusal(_seal(nonce="ab")) is EnvelopeRefusal.MALFORMED


# -- 6. the bytes that verified are the bytes that parse -----------------


def test_a_non_canonical_payload_is_refused():
    """A signature over one serialisation presented with a differently
    ordered payload that parses to something else."""

    payload = json.loads(_seal()[64:])
    reordered = json.dumps(payload, sort_keys=False, indent=1).encode()
    raw = bytes(_key().sign(ENVELOPE_DOMAIN + reordered).signature) + reordered
    assert _refusal(raw) is EnvelopeRefusal.NOT_CANONICAL


def test_an_unknown_schema_is_refused_rather_than_read_leniently():
    payload = json.loads(_seal()[64:])
    payload["schema"] = "azazel-nexus/sanitized-envelope/2"
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    raw = bytes(_key().sign(ENVELOPE_DOMAIN + body).signature) + body
    assert _refusal(raw) is EnvelopeRefusal.UNKNOWN_SCHEMA


def test_an_unknown_field_is_refused_rather_than_ignored():
    """A field this reader does not check is a field the signer believed it
    was binding."""

    payload = json.loads(_seal()[64:])
    payload["also_allow"] = "anything"
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    raw = bytes(_key().sign(ENVELOPE_DOMAIN + body).signature) + body
    assert _refusal(raw) is EnvelopeRefusal.MALFORMED


def test_a_missing_field_is_refused():
    payload = json.loads(_seal()[64:])
    del payload["provider_id"]
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    raw = bytes(_key().sign(ENVELOPE_DOMAIN + body).signature) + body
    assert _refusal(raw) is EnvelopeRefusal.MALFORMED


# -- 7. bounds ------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        (b"", EnvelopeRefusal.MALFORMED),
        (b"\x00" * 64, EnvelopeRefusal.MALFORMED),
        (b"\x00" * (MAX_ENVELOPE_BYTES + 1), EnvelopeRefusal.MALFORMED),
    ],
    ids=["empty", "signature-only", "oversized"],
)
def test_a_malformed_envelope_is_refused_before_it_is_parsed(raw, expected):
    assert _refusal(raw) is expected


def test_an_empty_frame_is_refused():
    assert _refusal(_seal(frame=b""), frame=b"") is EnvelopeRefusal.MALFORMED


def test_a_frame_beyond_the_ceiling_is_refused():
    big = b"x" * 4096
    assert (
        _refusal(_seal(frame=big), frame=big, max_frame_bytes=1024)
        is EnvelopeRefusal.FRAME_TOO_LARGE
    )


# -- the module holds nothing it should not -------------------------------


def test_it_signs_nothing_and_reaches_nothing():
    import ast

    import azazel_nexus.remote_envelope as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {"ssl", "socket", "subprocess", "nacl"} == set()
    names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert names & {"sign", "sign_envelope", "mint", "seal"} == set(), (
        "the verifier gained a signer; a component that can mint what it "
        "checks is not a check"
    )
