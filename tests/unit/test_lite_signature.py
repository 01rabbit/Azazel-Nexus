"""Ed25519 verification, and the absence of a signer (#6, E1).

Two claims are under test and they are different claims.

*The verifier is correct.* RFC 8032 §7.1's vectors pass. A vector passing is
weak evidence on its own -- a routine that returned `True` unconditionally
would pass all four -- so every vector is also run in a mutated form that must
fail, and each mutation targets one specific check.

*Nexus cannot sign.* The product holds no signing key. That is a property of
the whole package, not of one module, so it is checked by scanning the package
rather than by reading `signature.py` and being reassured.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

from azazel_nexus import signature
from azazel_nexus.signature import (
    PUBLIC_KEY_BYTES,
    SIGNATURE_BYTES,
    SignatureRefused,
    parse_public_key,
    verify_detached,
)

# RFC 8032 §7.1, verbatim. (public key, message, signature), all hex.
RFC_8032_VECTORS = [
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da08"
        "5ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18"
        "ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    (
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a21"
        "92992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909"
        "351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    ),
]


def _vector(index: int) -> tuple[bytes, bytes, bytes]:
    key, message, sig = RFC_8032_VECTORS[index]
    return bytes.fromhex(key), bytes.fromhex(message), bytes.fromhex(sig)


@pytest.mark.parametrize("index", range(len(RFC_8032_VECTORS)))
def test_rfc_8032_vectors_verify(index: int) -> None:
    key, message, sig = _vector(index)
    assert verify_detached(public_key=key, message=message, signature=sig) is True


@pytest.mark.parametrize("index", range(len(RFC_8032_VECTORS)))
def test_a_flipped_bit_in_the_signature_does_not_verify(index: int) -> None:
    """The lowest bit of `s`. Nothing about the length or the shape changes."""

    key, message, sig = _vector(index)
    mutated = bytearray(sig)
    mutated[SIGNATURE_BYTES - 32] ^= 0x01
    assert verify_detached(public_key=key, message=message, signature=bytes(mutated)) is False


@pytest.mark.parametrize("index", range(len(RFC_8032_VECTORS)))
def test_a_flipped_bit_in_the_message_does_not_verify(index: int) -> None:
    key, message, sig = _vector(index)
    mutated = bytearray(message) or bytearray(b"\x00")
    mutated[0] ^= 0x01
    assert verify_detached(public_key=key, message=bytes(mutated), signature=sig) is False


def test_a_signature_does_not_verify_under_a_different_admitted_key() -> None:
    """Both keys are valid points. Only the binding to the key is wrong."""

    key, message, sig = _vector(1)
    other_key, _, _ = _vector(2)
    assert key != other_key
    assert verify_detached(public_key=other_key, message=message, signature=sig) is False


@pytest.mark.parametrize("length", [0, 1, SIGNATURE_BYTES - 1, SIGNATURE_BYTES + 1])
def test_a_signature_of_the_wrong_length_is_refused_without_raising(length: int) -> None:
    """Attacker-supplied bytes never raise; the caller gets one answer: no."""

    key, message, sig = _vector(1)
    assert verify_detached(public_key=key, message=message, signature=sig[:length].ljust(length, b"\x00")) is False


def test_a_non_canonical_s_is_refused() -> None:
    """`s + L` is a second, different byte string over the same message.

    RFC 8032 §5.1.7 requires `s < L`. This test exists because an
    implementation without that check verifies *both* strings -- and the cache
    downstream assumes one admitted artifact has one admitted signature.
    """

    key, message, sig = _vector(1)
    order = 2**252 + 27742317777372353535851937790883648493
    scalar_s = int.from_bytes(sig[32:], "little")
    malleable = sig[:32] + (scalar_s + order).to_bytes(32, "little")

    assert len(malleable) == SIGNATURE_BYTES
    # The original still verifies, so the refusal below is about `s`, not about
    # having broken the vector.
    assert verify_detached(public_key=key, message=message, signature=sig) is True
    assert verify_detached(public_key=key, message=message, signature=malleable) is False


def test_an_r_that_is_not_a_curve_point_is_refused() -> None:
    key, message, sig = _vector(1)
    # y = p - 1 + 1 == p is off the field; no x can be recovered.
    not_a_point = (2**255 - 19).to_bytes(32, "little")
    assert verify_detached(public_key=key, message=message, signature=not_a_point + sig[32:]) is False


def test_a_public_key_of_the_wrong_length_raises_rather_than_answering_no() -> None:
    """Trust material is the operator's, not the adversary's.

    A silent `False` here would let a truncated key in the trust store look
    like an artifact that failed verification.
    """

    _, message, sig = _vector(1)
    with pytest.raises(SignatureRefused) as caught:
        verify_detached(public_key=b"\x00" * (PUBLIC_KEY_BYTES - 1), message=message, signature=sig)
    assert "public key" in str(caught.value)


def test_a_public_key_that_is_not_a_curve_point_raises() -> None:
    _, message, sig = _vector(1)
    with pytest.raises(SignatureRefused) as caught:
        verify_detached(public_key=b"\xff" * PUBLIC_KEY_BYTES, message=message, signature=sig)
    assert "curve" in str(caught.value)


# -- parse_public_key ------------------------------------------------------


def test_parse_public_key_accepts_the_canonical_form() -> None:
    text = RFC_8032_VECTORS[0][0]
    assert parse_public_key(text) == bytes.fromhex(text)


@pytest.mark.parametrize(
    "text, expected",
    [
        (RFC_8032_VECTORS[0][0].upper(), "lower-case"),
        (" " + RFC_8032_VECTORS[0][0], "64 hex characters"),
        ("0x" + RFC_8032_VECTORS[0][0], "64 hex characters"),
        (RFC_8032_VECTORS[0][0][:-1], "64 hex characters"),
        ("z" + RFC_8032_VECTORS[0][0][1:], "hex"),
    ],
)
def test_parse_public_key_refuses_every_near_miss(text: str, expected: str) -> None:
    """Each refusal names its own reason, so two of them cannot be one check."""

    with pytest.raises(SignatureRefused) as caught:
        parse_public_key(text)
    assert expected in str(caught.value)


def test_parse_public_key_refuses_hex_that_is_not_on_the_curve() -> None:
    with pytest.raises(SignatureRefused) as caught:
        parse_public_key("ff" * PUBLIC_KEY_BYTES)
    assert "curve" in str(caught.value)


# -- Nexus cannot sign -----------------------------------------------------

_PACKAGE = pathlib.Path(signature.__file__).parent

#: Parameter and attribute names that only exist where a signing key does.
_SIGNING_KEY_NAMES = frozenset(
    {"private_key", "secret_key", "signing_key", "seed", "privkey", "secret_scalar"}
)


def _package_modules() -> list[pathlib.Path]:
    return sorted(path for path in _PACKAGE.rglob("*.py") if "__pycache__" not in path.parts)


def test_the_package_defines_no_signing_key_parameter_or_binding() -> None:
    """A signer needs somewhere to put the key. There is nowhere.

    This is the check that makes "Nexus verifies but does not sign" a property
    rather than a claim, and it scans the whole package because the claim is
    about the product, not about one file.
    """

    offences: list[str] = []
    for path in _package_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.arg) and node.arg in _SIGNING_KEY_NAMES:
                offences.append(f"{path.name}: parameter {node.arg}")
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                if node.id in _SIGNING_KEY_NAMES:
                    offences.append(f"{path.name}: binds {node.id}")
    assert offences == [], f"Nexus holds no signing key: {offences}"


#: `sign`, `sign_detached`, `signing_key`, `signer` -- but not `signature`,
#: which is the noun a verifier needs and the signer's verb does not own.
_SIGNING_VERB = re.compile(r"^(?:sign(?:ing)?(?:_|$)|signer$)")


def test_the_signature_module_exports_no_signing_verb() -> None:
    exported = set(signature.__all__)
    signers = {name for name in exported if _SIGNING_VERB.match(name.lower())}
    assert signers == set(), f"verification only: {signers}"
    # And the module really does export the verifier, so the assertion above is
    # not satisfied by an empty `__all__`.
    assert "verify_detached" in exported
    # The pattern is not vacuous: it does match what it is meant to match.
    assert _SIGNING_VERB.match("sign")
    assert _SIGNING_VERB.match("sign_detached")
    assert _SIGNING_VERB.match("signing_key")
    assert not _SIGNING_VERB.match("signature_bytes")


def test_the_signature_module_never_hashes_a_secret_into_a_scalar() -> None:
    """The one operation a verifier has no use for.

    Ed25519 signing derives the secret scalar by hashing the seed with SHA-512
    and clamping it. `signature.py` calls SHA-512 exactly once, over public
    inputs, and the clamping pattern appears nowhere.
    """

    source = (_PACKAGE / "signature.py").read_text(encoding="utf-8")
    assert source.count("hashlib.sha512") == 1
    for clamp in ("& 248", "& 0xF8", "& 63", "| 64", "& 127"):
        assert clamp not in source, f"scalar clamping is a signer's operation: {clamp}"
