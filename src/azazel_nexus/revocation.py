"""Domain-separated, role-separated cumulative revocation statements.

Single-signature transport is 64 detached signature bytes followed by JSON.
Multi-signature transport is an AZRV1 envelope containing the same exact JSON
payload and detached signatures. Every signature covers REVOCATION_DOMAIN
followed by the payload, never the transport envelope. The product only verifies;
external signers use ``RevocationList.signature_target``.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .content_store import ContentRefused, parse_digest
from .revocation_policy import (
    POLICY_FILENAME,
    REVOCATION_SIGNING,
    RevocationPolicy,
    RevocationPolicyRefused,
    read_policy_record,
)
from .signature import SIGNATURE_BYTES, SignatureRefused, verify_detached

__all__ = [
    "REVOCATION_DOMAIN",
    "REVOCATION_FILENAME",
    "RevocationList",
    "RevocationRefused",
    "RevocationStore",
    "encode_signed",
]

REVOCATION_DOMAIN = b"azazel-nexus/revocation/v1\0"
_MULTISIG = b"AZRV1\n"

REVOCATION_FILENAME = "revocations.signed"


class RevocationRefused(Exception):
    """The revocation statement was not accepted, or cannot be read."""


@dataclass(frozen=True)
class RevocationList:
    """What is no longer to be served, and as of which sequence number."""

    sequence: int
    issued_at: str
    role: str = REVOCATION_SIGNING
    generation: int = 1
    revoked_digests: frozenset[str] = frozenset()
    revoked_generations: frozenset[int] = frozenset()
    revoked_keys: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.role != REVOCATION_SIGNING:
            raise RevocationRefused("payload role must be revocation-signing")
        if type(self.generation) is not int or self.generation < 1:
            raise RevocationRefused("payload generation must be positive")
        if type(self.sequence) is not int or self.sequence < 0:
            raise RevocationRefused("a revocation sequence starts at 0")
        for key in self.revoked_keys:
            if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
                raise RevocationRefused("revoked_keys names full lowercase public-key hex")
        for digest in self.revoked_digests:
            try:
                parse_digest(digest)
            except ContentRefused as exc:
                raise RevocationRefused(f"invalid revoked digest: {exc}") from exc

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
        """The transport payload. Sign ``signature_target()``, including its domain."""

        return json.dumps(
            {
                "role": self.role,
                "generation": self.generation,
                "sequence": self.sequence,
                "issued_at": self.issued_at,
                "revoked_digests": sorted(self.revoked_digests),
                "revoked_generations": sorted(self.revoked_generations),
                "revoked_keys": sorted(self.revoked_keys),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def signature_target(self) -> bytes:
        return REVOCATION_DOMAIN + self.as_payload()

    @classmethod
    def parse(cls, payload: bytes) -> RevocationList:
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
            role=raw.get("role"),
            generation=raw.get("generation"),
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
    """Cumulative revocations and a commissioned, independent authority."""

    root: Path
    policy: RevocationPolicy
    continuity: Mapping | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.policy, RevocationPolicy):
            raise RevocationRefused("unverified: an explicit revocation policy is required")

    @property
    def path(self) -> Path:
        return self.root / REVOCATION_FILENAME

    def _record(self) -> Mapping | None:
        if self.continuity is None:
            return None
        try:
            record = read_policy_record(self.root, self.continuity["commissioning_digest"])
            if record["policy"] != self.policy.as_record():
                raise RevocationRefused("unverified: this store holds a superseded policy")
            return record
        except (RevocationPolicyRefused, KeyError) as exc:
            raise RevocationRefused(f"unverified revocation continuity: {exc}") from exc

    def _floor(self, record: Mapping | None) -> RevocationList:
        if record is None:
            return EMPTY
        try:
            return RevocationList.parse(record["floor"].encode("utf-8"))
        except (KeyError, AttributeError, TypeError) as exc:
            raise RevocationRefused("unverified revocation continuity record") from exc

    def current(self) -> RevocationList:
        record = self._record()
        floor = self._floor(record)
        if not self.path.exists():
            if floor.sequence:
                raise RevocationRefused("unverified: persisted revocation list is missing")
            return EMPTY
        try:
            blob = self.path.read_bytes()
        except OSError as exc:
            raise RevocationRefused(f"unverified: revocations unreadable: {exc}") from exc
        signatures, payload = _split(blob)
        incoming = RevocationList.parse(payload)
        # A locally commissioned checkpoint authorizes only the exact old blob,
        # never arbitrary new statements by an old authority.
        checkpoint = (record or {}).get("previous_blob_sha256")
        if incoming.generation == self.policy.generation or checkpoint != hashlib.sha256(blob).hexdigest():
            self._verify(signatures, payload, incoming, floor)
        _extends(incoming, floor, allow_equal=True)
        return incoming

    def accept(self, blob: bytes) -> RevocationList:
        signatures, payload = _split(blob)
        incoming = RevocationList.parse(payload)
        try:
            in_force = self.current()
        except RevocationRefused:
            record = self._record()
            if (
                record is None
                or record.get("previous_blob_sha256") != hashlib.sha256(blob).hexdigest()
                or incoming.generation != self.policy.generation
            ):
                raise
            # Retry an interrupted publication only with the exact statement
            # already verified and durably checkpointed before the interruption.
            self._verify(signatures, payload, incoming, self._floor(record))
            _atomic_write(self.path, blob)
            return incoming
        self._verify(signatures, payload, incoming, in_force)
        _extends(incoming, in_force)
        record = self._record()
        if record is not None:
            updated = dict(record)
            updated["floor"] = incoming.as_payload().decode("utf-8")
            updated["previous_blob_sha256"] = hashlib.sha256(blob).hexdigest()
            # Persist the high-water mark first: interruption before publishing
            # the blob holds the cache closed rather than losing a revocation.
            _atomic_write(self.root / POLICY_FILENAME, json.dumps(updated, sort_keys=True).encode("utf-8"))
        _atomic_write(self.path, blob)
        return incoming

    def _verify(
        self, signatures: Sequence[bytes], payload: bytes,
        incoming: RevocationList, in_force: RevocationList,
    ) -> None:
        if incoming.generation != self.policy.generation:
            raise RevocationRefused("unverified: payload generation differs from commissioning policy")
        signers = {
            key for signature in signatures
            if (key := self._signer_of(signature, payload)) is not None
        }
        if any(in_force.revokes_key(key) for key in signers):
            raise RevocationRefused("unverified: a signing key is itself revoked")
        if len(signers) < self.policy.threshold:
            raise RevocationRefused(
                "unverified: revocation threshold not met by distinct trusted keys; "
                "the cache is out of service rather than unrevoked"
            )
        remaining = {
            key for key in self.policy.revocation_keys
            if key.hex() not in incoming.revoked_keys
        }
        if not remaining:
            raise RevocationRefused("revoking the last revocation-signing key is refused")
        newly_revoked = incoming.revoked_keys - in_force.revoked_keys
        if any(key.hex() in newly_revoked for key in signers):
            raise RevocationRefused("self-revocation is refused")

    def _signer_of(self, signature: bytes, payload: bytes) -> bytes | None:
        """Only a distinct commissioned revocation-signing key can count."""
        for key in self.policy.revocation_keys:
            try:
                if verify_detached(
                    public_key=key, message=REVOCATION_DOMAIN + payload,
                    signature=signature,
                ):
                    return key
            except SignatureRefused:
                continue
        return None


def _extends(incoming: RevocationList, old: RevocationList, *, allow_equal: bool = False) -> None:
    if incoming.sequence < old.sequence or (incoming.sequence == old.sequence and not allow_equal):
        raise RevocationRefused(
            f"revocation sequence {incoming.sequence} does not exceed the "
            f"{old.sequence} in force; replay refused"
        )
    if not (
        incoming.revoked_keys >= old.revoked_keys
        and incoming.revoked_digests >= old.revoked_digests
        and incoming.revoked_generations >= old.revoked_generations
    ):
        raise RevocationRefused("revoked entries cannot be re-enabled")


def encode_signed(payload: bytes, signatures: Sequence[bytes]) -> bytes:
    """Package externally produced signatures; this function does not sign."""
    if not signatures or any(len(sig) != SIGNATURE_BYTES for sig in signatures):
        raise RevocationRefused("expected detached signatures")
    if len(signatures) == 1:
        return signatures[0] + payload
    return _MULTISIG + json.dumps({
        "payload": payload.hex(), "signatures": [sig.hex() for sig in signatures],
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _split(blob: bytes) -> tuple[tuple[bytes, ...], bytes]:
    if blob.startswith(_MULTISIG):
        try:
            raw = json.loads(blob[len(_MULTISIG):])
            signatures = tuple(bytes.fromhex(sig) for sig in raw["signatures"])
            payload = bytes.fromhex(raw["payload"])
            if not signatures or any(len(sig) != SIGNATURE_BYTES for sig in signatures) or not payload:
                raise ValueError("expected detached signatures and payload")
            return signatures, payload
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise RevocationRefused(f"unverified revocation envelope: {exc}") from exc
    if len(blob) <= SIGNATURE_BYTES:
        raise RevocationRefused(
            f"a signed revocation list is {SIGNATURE_BYTES} bytes of signature "
            f"followed by a payload; got {len(blob)} bytes in total"
        )
    return (blob[:SIGNATURE_BYTES],), blob[SIGNATURE_BYTES:]


def _atomic_write(path: Path, blob: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=".revocations-")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(blob)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
