"""The hand-written verifier against an established one (#70 §5).

Passing RFC 8032's vectors is necessary and not sufficient. The vectors are a
handful of valid signatures; what a verifier has to get right is the much
larger set of inputs that are *almost* valid, and an implementation can be
wrong on every one of them while passing every vector.

So the same inputs go to both this implementation and libsodium, through
PyNaCl, and **any** disagreement is a defect in this implementation. libsodium
is not a specification, but where the two differ the burden is here.

## The signing oracle

Verification needs signatures, and producing them needs a signing key. It is
derived in-process from a **fixed literal string**, exists only for the
duration of a test run, and is shared with nothing: not a production key, not
a commissioned trust anchor, not a release-signing key. Nothing here writes
key material to a file, a fixture, a log or an assertion message.

`azazel_nexus` itself still contains no signing verb --
`test_lite_signature.py` scans for one. The oracle lives here, in the tests,
where PyNaCl is a development dependency.

## Why PyNaCl is allowed to be a dependency of this file

`pyproject.toml` keeps `dependencies = []` so the CORE path cannot fail for a
packaging reason. That argument is about what a **node** needs to verify its
own cache. It says nothing about what a test needs, and a differential test
that cannot be run is a differential test nobody runs -- so PyNaCl is in the
`dev` extra, which CI installs.
"""

from __future__ import annotations

import hashlib
import os
import pathlib

import pytest

from azazel_nexus import signature as sig
from azazel_nexus.signature import SignatureRefused, verify_detached

nacl_signing = pytest.importorskip(
    "nacl.signing",
    reason="PyNaCl is a dev dependency; CI installs it and this file must run there",
)

REPOSITORY = pathlib.Path(__file__).resolve().parents[2]

#: A fixed, test-only seed. Derived from a literal so a run is reproducible
#: and the key is obviously synthetic. Never leaves this process.
_TEST_SEED = hashlib.sha256(b"azazel-nexus/test-only/differential-oracle/0").digest()

#: The eight points of order dividing 8, at their canonical encodings.
SMALL_ORDER = tuple(
    bytes.fromhex(h)
    for h in (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    )
)


def _oracle():
    return nacl_signing.SigningKey(_TEST_SEED)


def _verifying_key() -> bytes:
    return bytes(_oracle().verify_key)


def _sign(message: bytes) -> bytes:
    return bytes(_oracle().sign(message).signature)


def _encode(point: tuple) -> bytes:
    """Compress an extended-coordinate point back to 32 bytes."""

    inverse = sig._modp_inv(point[2])
    x = point[0] * inverse % sig._P
    y = point[1] * inverse % sig._P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _ours(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """`False` for a refusal too: to a caller, refused is not verified."""

    try:
        return verify_detached(
            public_key=public_key, message=message, signature=signature
        )
    except SignatureRefused:
        return False


def _theirs(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        nacl_signing.VerifyKey(public_key).verify(message, signature)
        return True
    except Exception:  # noqa: BLE001 - every rejection is one answer: no
        return False


def _agree(public_key: bytes, message: bytes, signature: bytes) -> None:
    ours, theirs = _ours(public_key, message, signature), _theirs(
        public_key, message, signature
    )
    assert ours == theirs, (
        f"this implementation says {ours} and libsodium says {theirs}; where "
        "the two differ the burden is here"
    )


# -- valid signatures ------------------------------------------------------


@pytest.mark.parametrize("length", [0, 1, 31, 32, 33, 64, 127, 128, 1024])
def test_a_valid_signature_verifies_in_both(length) -> None:
    """Message lengths around the SHA-512 block boundary and the key size."""

    message = hashlib.sha256(b"message/%d" % length).digest() * (length // 32 + 1)
    message = message[:length]
    _agree(_verifying_key(), message, _sign(message))


def test_the_oracle_really_produces_signatures_this_implementation_accepts() -> None:
    """Otherwise every agreement above could be two implementations saying no."""

    message = b"not vacuous"
    assert _ours(_verifying_key(), message, _sign(message)) is True


# -- almost-valid signatures ----------------------------------------------


@pytest.mark.parametrize("index", range(64))
def test_every_flipped_signature_bit_is_rejected_in_both(index) -> None:
    """All 64 bytes, not a sample: R and s fail for different reasons."""

    message = b"the manifest"
    signature = bytearray(_sign(message))
    signature[index] ^= 0x01
    _agree(_verifying_key(), message, bytes(signature))


@pytest.mark.parametrize("delta", [0, 1, -1])
def test_s_at_the_group_order_agrees(delta) -> None:
    """`s = L` is the malleability boundary; `s = L - 1` is still in range."""

    message = b"the manifest"
    signature = _sign(message)
    scalar = (sig._Q + delta) % (2**256)
    _agree(
        _verifying_key(), message, signature[:32] + int.to_bytes(scalar, 32, "little")
    )


def test_a_signature_whose_s_is_the_original_plus_the_order_agrees() -> None:
    """The actual malleability attack, not an approximation of it.

    `s + L` is congruent to `s` modulo the group order, so an implementation
    that reduces instead of refusing would accept a second, different byte
    string over the same message under the same key.
    """

    message = b"the manifest"
    signature = _sign(message)
    original = int.from_bytes(signature[32:], "little")
    malleable = original + sig._Q
    assert malleable < 2**256, "the test vector needs an s that still fits"
    forged = signature[:32] + int.to_bytes(malleable, 32, "little")
    assert forged != signature
    _agree(_verifying_key(), message, forged)
    assert _ours(_verifying_key(), message, forged) is False


@pytest.mark.parametrize("truncated", [0, 1, 31, 32, 63, 65, 128])
def test_a_signature_of_the_wrong_length_agrees(truncated) -> None:
    message = b"the manifest"
    signature = _sign(message)
    _agree(_verifying_key(), message, (signature + signature)[:truncated])


def test_the_message_is_what_was_signed_and_not_merely_present() -> None:
    signature = _sign(b"admit this bundle")
    _agree(_verifying_key(), b"admit this bundle ", signature)
    _agree(_verifying_key(), b"admit this bundl", signature)


# -- non-canonical and small-order encodings -------------------------------


@pytest.mark.parametrize("point", SMALL_ORDER)
def test_a_small_order_public_key_agrees(point) -> None:
    """The divergence this file was written to find, now checked both ways.

    Before #70 this implementation **accepted** a forgery under a small-order
    key that libsodium rejected: with `A` of order 1 the challenge term is the
    neutral element for every challenge, so `[s]B == R` holds for any message
    once an attacker picks `s` and computes `R`. That is a universal forgery
    reported as a successful verification.
    """

    message = b"anything at all"
    scalar = 12345
    forged = _encode(sig._point_mul(scalar, sig._G)) + int.to_bytes(
        scalar, 32, "little"
    )
    assert _theirs(point, message, forged) is False
    _agree(point, message, forged)
    _agree(point, message, _sign(message))


@pytest.mark.parametrize("point", SMALL_ORDER)
def test_a_small_order_r_agrees(point) -> None:
    message = b"the manifest"
    _agree(_verifying_key(), message, point + _sign(message)[32:])


@pytest.mark.parametrize("excess", [0, 1, 18])
def test_a_non_canonical_y_agrees(excess) -> None:
    """`y >= p` has no canonical decoding; both must refuse it, as key and as R."""

    non_canonical = int.to_bytes(sig._P + excess, 32, "little")
    message = b"the manifest"
    signature = _sign(message)
    _agree(non_canonical, message, signature)
    _agree(_verifying_key(), message, non_canonical + signature[32:])


def test_random_inputs_agree() -> None:
    """A wide net for anything the cases above did not think of.

    Random bytes almost never decode to a curve point, so most of these are
    both saying no. That is the point: it is the shape of the refusal that has
    to match, across the malformed inputs nobody enumerated.
    """

    for _ in range(200):
        _agree(os.urandom(32), os.urandom(16), os.urandom(64))


# -- the dependency this file needs ----------------------------------------


def test_pynacl_is_declared_as_a_development_dependency() -> None:
    """So a skip here is a missing install and never a removed dependency.

    Without this, deleting PyNaCl from the extras would turn every test above
    into a silent skip -- a differential test that stopped running and said
    nothing.
    """

    manifest = (REPOSITORY / "pyproject.toml").read_text(encoding="utf-8")
    assert "pynacl" in manifest.lower(), "PyNaCl is not in the dev extra"


def test_the_library_itself_still_depends_on_nothing() -> None:
    """The dev extra must not become a runtime dependency by accident."""

    manifest = (REPOSITORY / "pyproject.toml").read_text(encoding="utf-8")
    body = manifest[manifest.index("[project]") :]
    runtime = body[body.index("dependencies = ") :].split("\n", 1)[0]
    assert runtime.strip() == "dependencies = []", runtime
