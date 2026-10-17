"""Nexus-local operator approval verification, not service admission.

An administrator supplies an already enrolled key set. Neither a document nor
the installer may enroll its own signer. This module does not read files, sign,
create leases, or contact systemd. Production protected-store loading and
bootstrap composition remain separate work.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from types import MappingProxyType
from typing import Mapping

from .signature import SignatureRefused, parse_public_key, verify_detached

MAX_APPROVAL_BYTES = 65536
_OPERATOR = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")


class ApprovalRefused(Exception):
    """An approval cannot be attributed to a currently enrolled operator."""


class ApprovalPurpose(str, Enum):
    COMMISSIONING = "commissioning"
    ACTIVATION = "activation"
    COMMISSIONING_PROPOSAL = "commissioning-proposal"
    SUPPORTING_BOOTSTRAP = "supporting-bootstrap"


def approval_message(purpose: ApprovalPurpose, payload: bytes) -> bytes:
    """The exact byte transcript an external operator tool must sign.

    Payload semantics are owned by the caller; a signature alone cannot make
    arbitrary bytes into a valid commissioning record or activation lease.
    No Fabric record or canonical form is defined here.
    """
    if type(purpose) is not ApprovalPurpose:
        raise ApprovalRefused("unsupported approval purpose")
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_APPROVAL_BYTES:
        raise ApprovalRefused("approval payload must be bounded nonempty bytes")
    return b"azazel-nexus/operator-approval/v1\x00" + purpose.value.encode("ascii") + b"\x00" + payload


@dataclass(frozen=True)
class OperatorTrust:
    """An immutable snapshot of independently enrolled, active public keys.

    Removal/revocation is supplied afresh by the protected trust-store reader
    on each activation pass. This snapshot is not a revocation service or a
    filesystem permission check. Operator identifiers are labels, not proof
    that the person controlling the key has been identified correctly.
    """

    public_keys: Mapping[str, bytes]
    revoked: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        keys = dict(self.public_keys)
        revoked = frozenset(self.revoked)
        if any(type(name) is not str or not _OPERATOR.fullmatch(name)
               for name in (*keys, *revoked)):
            raise ApprovalRefused("invalid enrolled operator identifier")
        seen: set[bytes] = set()
        for key in keys.values():
            if type(key) is not bytes:
                raise ApprovalRefused("operator public key must be bytes")
            try:
                parse_public_key(key.hex())
            except SignatureRefused as exc:
                raise ApprovalRefused("invalid enrolled operator public key") from exc
            if key in seen:
                raise ApprovalRefused("one operator key cannot have multiple identities")
            seen.add(key)
        object.__setattr__(self, "public_keys", MappingProxyType(keys))
        object.__setattr__(self, "revoked", revoked)

    def verify(
        self, *, operator: str, purpose: ApprovalPurpose,
        payload: bytes, signature: bytes,
    ) -> None:
        """Verify attribution only; return no activation authorization token."""
        message = approval_message(purpose, payload)
        if type(operator) is not str or operator in self.revoked:
            raise ApprovalRefused("operator is not actively enrolled")
        key = self.public_keys.get(operator)
        if key is None:
            raise ApprovalRefused("operator is not actively enrolled")
        if type(signature) is not bytes or not verify_detached(
            public_key=key, message=message, signature=signature
        ):
            raise ApprovalRefused("operator signature refused")
