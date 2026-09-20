"""Ed25519 signature **verification**, and nothing else (#6, E1).

Nexus verifies. It does not sign. There is no signing key anywhere in this
product, and this module is the reason that sentence can be checked rather
than believed: it contains no key expansion, no scalar derivation from a seed,
and no function that returns a signature. `tests/unit/test_lite_signature.py`
scans the package for the shape of a signer and fails if one appears.

**Why a pure-Python implementation rather than a library.**
`pyproject.toml` says `dependencies = []` and says why: "a dependency added
here is a dependency the CORE path can fail on". A Knowledge Lite cache that
cannot verify its artifact when an optional wheel is missing is a cache that
fails open or fails absent for a packaging reason, which is not a reason. So
verification is stdlib arithmetic.

**Why that is acceptable here and would not be for signing.** Verification
touches no secret. The public key, the message and the signature are all
values an adversary already has, so there is no secret whose timing could
leak. A variable-time *signing* routine would be a defect; a variable-time
*verifying* routine is not one. This module only ever verifies, which is the
other reason it must not grow a signing verb.

**Malleability is refused.** RFC 8032 §5.1.7 requires `s < L`. An
implementation that omits that check accepts a second, different signature
over the same message under the same key -- two distinct byte strings that
both verify. Content addressing downstream assumes one artifact has one
admitted signature, so the check is load-bearing, not ceremonial.

The field arithmetic follows the reference implementation in RFC 8032 §6.
"""

from __future__ import annotations

import hashlib

__all__ = [
    "PUBLIC_KEY_BYTES",
    "SIGNATURE_BYTES",
    "SignatureRefused",
    "parse_public_key",
    "verify_detached",
]

#: An Ed25519 public key is 32 bytes -- 64 characters of hex.
PUBLIC_KEY_BYTES = 32
#: A detached Ed25519 signature is 64 bytes: R (32) then s (32).
SIGNATURE_BYTES = 64


class SignatureRefused(Exception):
    """The trust material itself is unusable.

    Raised for a malformed *public key*, which comes from the node's own trust
    store and is therefore a configuration fault the operator must see. Never
    raised for a malformed signature or message: those are attacker-supplied,
    and an exception there would let a caller distinguish failure modes it has
    no business distinguishing. Those return `False`.
    """


# -- field arithmetic (RFC 8032 §6) ---------------------------------------

_P = 2**255 - 19
#: The group order, `L` in RFC 8032. `s` must be reduced below it.
_Q = 2**252 + 27742317777372353535851937790883648493


def _modp_inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = -121665 * _modp_inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _sha512_modq(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % _Q


def _point_add(point: tuple, other: tuple) -> tuple:
    a = (point[1] - point[0]) * (other[1] - other[0]) % _P
    b = (point[1] + point[0]) * (other[1] + other[0]) % _P
    c = 2 * point[3] * other[3] * _D % _P
    e = 2 * point[2] * other[2] % _P
    f, g, h, i = b - a, e - c, e + c, b + a
    return (f * g, h * i, g * h, f * i)


def _point_mul(scalar: int, point: tuple) -> tuple:
    result = (0, 1, 1, 0)  # the neutral element
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _point_equal(point: tuple, other: tuple) -> bool:
    if (point[0] * other[2] - other[0] * point[2]) % _P != 0:
        return False
    return (point[1] * other[2] - other[1] * point[2]) % _P == 0


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _modp_inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_G_Y = 4 * _modp_inv(5) % _P
_G_X = _recover_x(_G_Y, 0)
assert _G_X is not None  # the base point is a constant; this cannot fail
_G = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def _point_decompress(raw: bytes) -> tuple | None:
    if len(raw) != PUBLIC_KEY_BYTES:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


# -- the two things a caller may do ----------------------------------------


def parse_public_key(text: str) -> bytes:
    """Read one 64-character hex public key from the trust store.

    Strict on purpose. A key with surrounding whitespace, an `0x` prefix, an
    odd length or a non-hex character is refused rather than coerced, because
    every coercion is a way for two operators to write what they believe is
    the same key and get two different keys.
    """

    if not isinstance(text, str):
        raise SignatureRefused("a public key is hex text, not bytes")
    if len(text) != PUBLIC_KEY_BYTES * 2:
        raise SignatureRefused(
            f"a public key is {PUBLIC_KEY_BYTES * 2} hex characters; got {len(text)}"
        )
    if text != text.lower():
        raise SignatureRefused(
            "a public key is lower-case hex; mixed case would let the same key "
            "be written two ways and compared as two keys"
        )
    try:
        key = bytes.fromhex(text)
    except ValueError as exc:
        raise SignatureRefused(f"a public key is hex: {exc}") from exc
    if _point_decompress(key) is None:
        raise SignatureRefused(
            "the public key is well-formed hex but is not a point on the curve; "
            "no signature could ever verify under it"
        )
    return key


def verify_detached(*, public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify `signature` over `message` under `public_key`.

    Returns `False` for every content failure, including a signature of the
    wrong length, a non-canonical `s`, and an `R` that is not a curve point.
    Raises only when the *key* is unusable.
    """

    if len(public_key) != PUBLIC_KEY_BYTES:
        raise SignatureRefused(
            f"a public key is {PUBLIC_KEY_BYTES} bytes; got {len(public_key)}"
        )
    point_a = _point_decompress(public_key)
    if point_a is None:
        raise SignatureRefused("the public key is not a point on the curve")

    if len(signature) != SIGNATURE_BYTES:
        return False
    encoded_r = signature[:PUBLIC_KEY_BYTES]
    point_r = _point_decompress(encoded_r)
    if point_r is None:
        return False
    scalar_s = int.from_bytes(signature[PUBLIC_KEY_BYTES:], "little")
    if scalar_s >= _Q:
        # RFC 8032 §5.1.7. Without this, `s + L` is a second signature over the
        # same message under the same key.
        return False

    challenge = _sha512_modq(encoded_r + public_key + message)
    return _point_equal(
        _point_mul(scalar_s, _G),
        _point_add(point_r, _point_mul(challenge, point_a)),
    )
