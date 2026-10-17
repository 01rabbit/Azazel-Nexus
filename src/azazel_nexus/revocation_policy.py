"""Commissioned revocation authority, separate from bundle signing authority.

This is local trust material. The later repin integration must call
``commission_policy`` only after its local authorization and audit ceremony.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from .signature import SignatureRefused, parse_public_key

BUNDLE_SIGNING = "bundle-signing"
REVOCATION_SIGNING = "revocation-signing"
POLICY_FILENAME = "revocation-policy.json"


class RevocationPolicyRefused(ValueError):
    """Missing, contradictory or unusable commissioning policy."""


@dataclass(frozen=True)
class RevocationPolicy:
    keys: Mapping[str, bytes]
    key_roles: Mapping[str, str]
    threshold: int
    generation: int

    def __post_init__(self) -> None:
        try:
            keys = dict(self.keys)
            roles = dict(self.key_roles)
        except (TypeError, ValueError) as exc:
            raise RevocationPolicyRefused("policy keys and roles must be mappings") from exc
        if type(self.generation) is not int or self.generation < 1:
            raise RevocationPolicyRefused("revocation policy generation must be positive")
        if type(self.threshold) is not int or self.threshold < 1:
            raise RevocationPolicyRefused("an explicit positive revocation threshold is required")
        material_roles: dict[bytes, str] = {}
        for key_id, key in keys.items():
            if not isinstance(key_id, str) or not key_id:
                raise RevocationPolicyRefused("a key has a nonempty key_id")
            if not isinstance(key, bytes):
                raise RevocationPolicyRefused("policy key material must be public-key bytes")
            try:
                parse_public_key(key.hex())
            except (AttributeError, SignatureRefused) as exc:
                raise RevocationPolicyRefused(f"unusable policy key: {key_id}") from exc
            role = roles.get(key_id)
            if role is not None:
                if role not in (BUNDLE_SIGNING, REVOCATION_SIGNING):
                    raise RevocationPolicyRefused("a key has exactly one recognized role")
                if key in material_roles and material_roles[key] != role:
                    raise RevocationPolicyRefused("the same key cannot hold both roles")
                material_roles[key] = role
        if set(roles) - set(keys):
            raise RevocationPolicyRefused("a role must name a commissioned key")
        object.__setattr__(self, "keys", MappingProxyType(keys))
        object.__setattr__(self, "key_roles", MappingProxyType(roles))
        if self.threshold > len(self.revocation_keys):
            raise RevocationPolicyRefused("threshold exceeds distinct revocation-signing keys")

    @property
    def revocation_keys(self) -> frozenset[bytes]:
        return frozenset(
            key for key_id, key in self.keys.items()
            if self.key_roles.get(key_id) == REVOCATION_SIGNING
        )

    def check_anchors(
        self, key_roles: Mapping[str, str], keys: Mapping[str, bytes] | None = None,
    ) -> None:
        for key_id, role in key_roles.items():
            if key_id in self.keys and self.key_roles.get(key_id) != role:
                raise RevocationPolicyRefused("revocation policy conflicts with anchors.toml key_roles")

        for key_id, key in (keys or {}).items():
            role = key_roles.get(key_id)
            if role is not None:
                for own_id, own_key in self.keys.items():
                    if own_key == key and self.key_roles.get(own_id) != role:
                        raise RevocationPolicyRefused("key material conflicts with anchors.toml key_roles")

    def as_record(self) -> dict:
        return {
            "keys": {name: key.hex() for name, key in self.keys.items()},
            "key_roles": dict(self.key_roles),
            "threshold": self.threshold,
            "generation": self.generation,
        }

    @classmethod
    def from_record(cls, raw: dict) -> RevocationPolicy:
        try:
            return cls(
                keys={name: parse_public_key(key) for name, key in raw["keys"].items()},
                key_roles=raw["key_roles"], threshold=raw["threshold"],
                generation=raw["generation"],
            )
        except (KeyError, TypeError, AttributeError, SignatureRefused) as exc:
            raise RevocationPolicyRefused("missing or malformed revocation commissioning policy") from exc


def read_policy_record(root: Path, commissioning_digest: str) -> dict:
    try:
        raw = json.loads((root / POLICY_FILENAME).read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw["commissioning_digest"] != commissioning_digest:
            raise RevocationPolicyRefused("revocation policy commissioning mismatch")
        RevocationPolicy.from_record(raw["policy"])
        return raw
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RevocationPolicyRefused(f"unverified revocation policy: {exc}") from exc


def commission_policy(
    root: Path, new_policy: RevocationPolicy, *, commissioning_digest: str,
    anchors_key_roles: Mapping[str, str], anchors_keys: Mapping[str, bytes] | None = None,
) -> None:
    """Integration seam for authorized local commissioning/repin.

    Preserve the verified cumulative floor and the exact previous signed blob.
    This lets a new authority read old revocations without granting old keys
    authority to issue another list. Never remove this record on re-commission.
    """
    from .revocation import EMPTY, RevocationRefused, RevocationStore, _atomic_write

    if not isinstance(commissioning_digest, str) or not commissioning_digest.strip():
        raise RevocationPolicyRefused("a commissioning digest is required")
    new_policy.check_anchors(anchors_key_roles, anchors_keys)
    path = root / POLICY_FILENAME
    floor = EMPTY
    previous_blob = None
    if path.exists():
        try:
            old_record = json.loads(path.read_text(encoding="utf-8"))
            old_policy = RevocationPolicy.from_record(old_record["policy"])
            old_store = RevocationStore(root, old_policy, old_record)
            floor = old_store.current()
            if new_policy.generation <= old_policy.generation:
                raise RevocationPolicyRefused("policy generation must increase")
            if any(key.hex() in floor.revoked_keys for key in new_policy.keys.values()):
                raise RevocationPolicyRefused("re-commissioning cannot re-enable a revoked key")
            if old_store.path.exists():
                previous_blob = hashlib.sha256(old_store.path.read_bytes()).hexdigest()
        except (OSError, ValueError, KeyError, TypeError, RevocationRefused) as exc:
            raise RevocationPolicyRefused(f"cannot preserve revocation history: {exc}") from exc
    elif (root / "revocations.signed").exists():
        raise RevocationPolicyRefused("unverified legacy revocations require local migration")
    record = {
        "commissioning_digest": commissioning_digest,
        "policy": new_policy.as_record(),
        "floor": floor.as_payload().decode("utf-8"),
        "previous_blob_sha256": previous_blob,
    }
    _atomic_write(path, json.dumps(record, sort_keys=True).encode("utf-8"))
