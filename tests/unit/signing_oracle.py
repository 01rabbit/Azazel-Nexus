"""An Ed25519 signer that exists only in the test suite.

Nexus verifies and does not sign. `tests/unit/test_lite_signature.py` scans
`src/azazel_nexus/` and fails if a signing key appears there. This module is
the deliberate counterpart: revocation lists and signed manifests have to come
from somewhere for the tests to have anything to verify, so the signer lives
here, outside the product, where the scan does not reach and where it cannot
be imported by anything that ships.

It is written against RFC 8032 §6 and reuses the field arithmetic from
`azazel_nexus.signature` so that a test fixture is not signed by a second,
subtly different curve implementation -- which would make a verification
failure ambiguous between "the verifier is wrong" and "the oracle is wrong".
"""

from __future__ import annotations

import hashlib

from azazel_nexus.signature import _G, _P, _Q, _modp_inv, _point_mul  # noqa: PLC2701

__all__ = ["public_key_for", "sign_detached"]


def _sha512_modq(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % _Q


def _expand(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def _compress(point: tuple) -> bytes:
    inverse = _modp_inv(point[2])
    x = point[0] * inverse % _P
    y = point[1] * inverse % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def public_key_for(seed: bytes) -> bytes:
    scalar, _ = _expand(seed)
    return _compress(_point_mul(scalar, _G))


def sign_detached(*, seed: bytes, message: bytes) -> bytes:
    scalar, prefix = _expand(seed)
    encoded_a = _compress(_point_mul(scalar, _G))
    nonce = _sha512_modq(prefix + message)
    encoded_r = _compress(_point_mul(nonce, _G))
    challenge = _sha512_modq(encoded_r + encoded_a + message)
    signature_s = (nonce + challenge * scalar) % _Q
    return encoded_r + int.to_bytes(signature_s, 32, "little")
