"""`sha256:` over a certificate's SubjectPublicKeyInfo, and only that (#98).

Two egress boundaries pin a peer's key: the artifact fetcher (#105) and the
remote inference transport (#98). They are separate services with separate
accounts, separate sockets and separate commissioned registries, and they
share nothing that carries authority.

They do share this, and they should: it is a **pure parser**. Two copies of a
certificate-key extraction is one copy that gets a fix and one that does not,
and the one that does not is still pinning -- just to whatever a subtly
different walk produced.

This module imports no `ssl` and no `socket`. Sharing a parser is not sharing
an egress exception, and `tests/unit/test_runtime_boundary.py` still names
exactly the modules that may reach a network.

## Over the key, not the certificate

A server that renews its certificate keeps its key. A pin over the whole
certificate turns every ordinary renewal into an outage indistinguishable
from an attack -- which is how pinning gets switched off.

## A walk, not a parser

A `Certificate` is a SEQUENCE whose first element is the `TBSCertificate`,
and within that the `SubjectPublicKeyInfo` is the element after `subject`.
Nothing here interprets a name, a date or an extension; it counts elements
and re-encodes one. `tests/unit/test_artifact_egress.py` checks the result
against OpenSSL's own extraction rather than against a fixture this file
wrote.
"""

from __future__ import annotations

import hashlib
from typing import Iterator

__all__ = ["CertificateRefused", "spki_pin"]


class CertificateRefused(Exception):
    """A certificate whose key cannot be located. Refused, never guessed at."""


def spki_pin(certificate_der: bytes) -> str:
    """`sha256:` over the certificate's SubjectPublicKeyInfo."""

    tbs = _first_child(_value(certificate_der, expect=0x30), expect=0x30)
    elements = list(_children(tbs))
    # [0] EXPLICIT version is optional; when present it is context tag 0xA0.
    offset = 1 if elements and elements[0][0] == 0xA0 else 0
    # serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    index = offset + 5
    if index >= len(elements):
        raise CertificateRefused(
            "the peer's certificate has no SubjectPublicKeyInfo where one must be"
        )
    tag, body = elements[index]
    if tag != 0x30:
        raise CertificateRefused("the peer's SubjectPublicKeyInfo is not a SEQUENCE")
    return "sha256:" + hashlib.sha256(_reencode(tag, body)).hexdigest()


def _value(data: bytes, *, expect: int) -> bytes:
    tag, body, _end = _read(data, 0)
    if tag != expect:
        raise CertificateRefused("the peer's certificate is not DER as expected")
    return body


def _first_child(body: bytes, *, expect: int) -> bytes:
    tag, child, _end = _read(body, 0)
    if tag != expect:
        raise CertificateRefused("the peer's certificate has no TBSCertificate")
    return child


def _children(body: bytes) -> Iterator[tuple]:
    offset = 0
    while offset < len(body):
        tag, value, offset = _read(body, offset)
        yield tag, value


def _read(data: bytes, offset: int) -> tuple:
    if offset + 2 > len(data):
        raise CertificateRefused("the peer's certificate is truncated")
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise CertificateRefused("the peer's certificate has an unusable length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    end = offset + length
    if end > len(data):
        raise CertificateRefused("the peer's certificate is truncated")
    return tag, data[offset:end], end


def _reencode(tag: int, body: bytes) -> bytes:
    length = len(body)
    if length < 0x80:
        header = bytes((tag, length))
    else:
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes((tag, 0x80 | len(encoded))) + encoded
    return header + body
