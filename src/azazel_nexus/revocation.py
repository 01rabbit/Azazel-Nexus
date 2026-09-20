"""Revocation for the Knowledge Lite cache (#6, E1).

An artifact that was admitted yesterday may be known-bad today. Verification
at admission cannot express that, because the signature over a bad artifact is
still a valid signature. Revocation is the separate statement: *this digest,
this generation, or this signer is no longer to be served.*

Four rules, each of which is a refusal.

**Revocation is consulted at serve time, not only at admission.** A list
accepted after a promotion must stop the current cache from being served
without waiting for a restart. A design that only checked at admission would
leave a revoked artifact live until the next artifact arrived -- which, on a
node whose feed has been cut, is never.

**A list that cannot be verified does not mean nothing is revoked.** The
stored list is verified every time it is read. If it fails, `current()`
raises, and the consumer takes the cache out of service. Falling back to an
empty list would turn tampering with one file into the un-revocation of
everything, which is exactly the move an adversary would make.

**Sequence numbers only increase.** A correctly signed *older* list is a valid
signature over a statement that used to be true. Replaying it is how a revoked
artifact comes back, so a list whose sequence does not exceed the current one
is refused.

**A revoked signer cannot issue the next list.** The list in force is applied
to the key that signed the incoming one, before the incoming one is believed.

The signed file is `revocations.signed`: 64 bytes of detached signature
followed by the payload bytes exactly as they were signed. One file, one
atomic replace, and no canonicalisation step that the verifier and the signer
could disagree about.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .content_store import parse_digest
from .signature import SIGNATURE_BYTES, SignatureRefused, verify_detached

__all__ = [
    "REVOCATION_FILENAME",
    "RevocationList",
    "RevocationRefused",
    "RevocationStore",
]

REVOCATION_FILENAME = "revocations.signed"


class RevocationRefused(Exception):
    """The revocation statement was not accepted, or cannot be read."""


@dataclass(frozen=True)
class RevocationList:
    """What is no longer to be served, and as of which sequence number."""

    sequence: int
    issued_at: str
    revoked_digests: frozenset[str] = frozenset()
    revoked_generations: frozenset[int] = frozenset()
    revoked_keys: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise RevocationRefused("a revocation sequence starts at 0")
        for digest in self.revoked_digests:
            parse_digest(digest)

    def revokes_digest(self, digest: str) -> bool:
        return digest in self.revoked_digests

    def revokes_generation(self, number: int) -> bool:
        return number in self.revoked_generations

    def revokes_key(self, public_key: bytes) -> bool:
        return public_key.hex() in self.revoked_keys

    def reason_for(
        self, *, digest: str | None = None, generation: int | None = None
    ) -> str | None:
        """Why this cache may not be served, or `None`.

        Returns text rather than a bool so the operator plane can say which
        statement withdrew the artifact, and so two different revocations do
        not read as one.
        """

        if digest is not None and self.revokes_digest(digest):
            return f"artifact {digest} is revoked by revocation sequence {self.sequence}"
        if generation is not None and self.revokes_generation(generation):
            return f"generation {generation} is revoked by revocation sequence {self.sequence}"
        return None

    def as_payload(self) -> bytes:
        """The bytes a signer signs. Sorted, so two writers agree."""

        return json.dumps(
            {
                "sequence": self.sequence,
                "issued_at": self.issued_at,
                "revoked_digests": sorted(self.revoked_digests),
                "revoked_generations": sorted(self.revoked_generations),
                "revoked_keys": sorted(self.revoked_keys),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def parse(cls, payload: bytes) -> "RevocationList":
        try:
            raw = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RevocationRefused(f"the revocation payload is not JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise RevocationRefused("a revocation list is an object")
        try:
            sequence = raw["sequence"]
            issued_at = raw["issued_at"]
        except KeyError as exc:
            raise RevocationRefused(f"a revocation list names {exc}") from exc
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            raise RevocationRefused("a revocation sequence is an integer")
        if not isinstance(issued_at, str) or not issued_at.strip():
            raise RevocationRefused("a revocation list records when it was issued")
        return cls(
            sequence=sequence,
            issued_at=issued_at,
            revoked_digests=frozenset(_string_list(raw, "revoked_digests")),
            revoked_generations=frozenset(_int_list(raw, "revoked_generations")),
            revoked_keys=frozenset(_string_list(raw, "revoked_keys")),
        )


#: What is in force on a node that has never accepted a list. Sequence 0, so
#: the first real list (sequence 1 or above) supersedes it.
EMPTY = RevocationList(sequence=0, issued_at="1970-01-01T00:00:00Z")


def _string_list(raw: dict, key: str) -> list[str]:
    values = raw.get(key, [])
    if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
        raise RevocationRefused(f"{key} is a list of strings")
    return values


def _int_list(raw: dict, key: str) -> list[int]:
    values = raw.get(key, [])
    if not isinstance(values, list) or any(
        not isinstance(v, int) or isinstance(v, bool) for v in values
    ):
        raise RevocationRefused(f"{key} is a list of integers")
    return values


@dataclass(frozen=True)
class RevocationStore:
    """The revocation list in force, and the rules for replacing it."""

    root: Path
    trusted_keys: Sequence[bytes]

    @property
    def path(self) -> Path:
        return self.root / REVOCATION_FILENAME

    def current(self) -> RevocationList:
        """The list in force. Raises rather than assuming nothing is revoked."""

        if not self.path.is_file():
            return EMPTY
        try:
            blob = self.path.read_bytes()
        except OSError as exc:
            raise RevocationRefused(
                f"the revocation list is present and unreadable: {exc}; the cache "
                "is out of service rather than unrevoked"
            ) from exc
        signature, payload = _split(blob)
        signer = self._signer_of(signature, payload)
        if signer is None:
            raise RevocationRefused(
                "the stored revocation list does not verify under any trusted key; "
                "the cache is out of service rather than unrevoked"
            )
        return RevocationList.parse(payload)

    def accept(self, blob: bytes) -> RevocationList:
        """Verify, compare sequences, and replace the list in force."""

        signature, payload = _split(blob)
        signer = self._signer_of(signature, payload)
        if signer is None:
            raise RevocationRefused(
                "the revocation list does not verify under any trusted key; the "
                "list in force is unchanged"
            )

        in_force = self.current()
        if in_force.revokes_key(signer):
            raise RevocationRefused(
                f"the key {signer.hex()} that signed this list is itself revoked by "
                f"sequence {in_force.sequence}; a revoked signer cannot lift its own "
                "revocation"
            )

        incoming = RevocationList.parse(payload)
        if incoming.sequence <= in_force.sequence:
            raise RevocationRefused(
                f"revocation sequence {incoming.sequence} does not exceed the "
                f"{in_force.sequence} in force; a correctly signed older list is a "
                "replay, and replaying it would un-revoke what it predates"
            )

        self.root.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(dir=str(self.root), prefix=".revocations-")
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(blob)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        return incoming

    def _signer_of(self, signature: bytes, payload: bytes) -> bytes | None:
        """Which trusted key signed this, or `None`.

        A key that is malformed in the trust store is skipped rather than
        allowed to abort the check -- one unusable key must not make every
        list unverifiable -- but it is skipped only after every other key has
        had its chance, because the result must not depend on ordering.
        """

        for key in _unique(self.trusted_keys):
            try:
                verified = verify_detached(
                    public_key=key, message=payload, signature=signature
                )
            except SignatureRefused:
                continue
            if verified:
                return key
        return None


def _unique(keys: Iterable[bytes]) -> list[bytes]:
    seen: list[bytes] = []
    for key in keys:
        if key not in seen:
            seen.append(key)
    return seen


def _split(blob: bytes) -> tuple[bytes, bytes]:
    if len(blob) <= SIGNATURE_BYTES:
        raise RevocationRefused(
            f"a signed revocation list is {SIGNATURE_BYTES} bytes of signature "
            f"followed by a payload; got {len(blob)} bytes in total"
        )
    return blob[:SIGNATURE_BYTES], blob[SIGNATURE_BYTES:]
