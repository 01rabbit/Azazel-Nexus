"""Nexus-local signed activation approval; not a Fabric record or a grant.

The verifier compares with independently collected expected context. It must
not be populated from the approval itself. Clock trust, rollback-resistant
epoch/generation storage, health and product admission are separate gates.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import re

from .activation import ActivationLease
from .operator_trust import ApprovalPurpose, ApprovalRefused, OperatorTrust

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_SCHEMA = "azazel-nexus/activation-approval/v1"


def _utc(value):
    if type(value) is not str or not _TIME.fullmatch(value):
        raise ApprovalRefused("approval time must be UTC with whole seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ApprovalRefused("invalid approval time") from exc


@dataclass(frozen=True)
class ActivationContext:
    """Expected observations, never values learned from an untrusted approval."""

    node_digest: str
    boot_id: str
    generation: int
    generation_digest: str
    commissioning_digest: str
    inventory_digest: str
    policy_digest: str
    renderer_digest: str
    security_epoch: int
    commissioning_evidence_binding: str | None = field(default=None, repr=False)

    def __post_init__(self):
        if self.commissioning_evidence_binding is not None and (
            type(self.commissioning_evidence_binding) is not str
            or not re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", self.commissioning_evidence_binding)
        ):
            raise ApprovalRefused("invalid activation commissioning evidence binding")
        for name, value in asdict(self).items():
            if name.endswith("_digest"):
                if type(value) is not str or not _DIGEST.fullmatch(value):
                    raise ApprovalRefused("invalid activation context digest")
        if type(self.boot_id) is not str or not _BOOT.fullmatch(self.boot_id):
            raise ApprovalRefused("invalid activation boot identity")
        if type(self.generation) is not int or self.generation < 1:
            raise ApprovalRefused("invalid activation generation")
        if type(self.security_epoch) is not int or self.security_epoch < 0:
            raise ApprovalRefused("invalid activation security epoch")


def approval_payload(*, context: ActivationContext, operator: str,
                     granted_at: str, expires_at: str) -> bytes:
    """Unsigned proposal bytes; the external operator signs the purpose transcript."""
    if type(context) is not ActivationContext:
        raise ApprovalRefused("activation context required")
    if type(operator) is not str or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", operator):
        raise ApprovalRefused("invalid approval operator")
    if _utc(expires_at) <= _utc(granted_at):
        raise ApprovalRefused("approval expiry must follow its grant time")
    context_document = asdict(context)
    # Preserve previously signed legacy bytes when no new binding is supplied.
    # A bound context includes it and cannot accept an omitted/null substitute.
    if context.commissioning_evidence_binding is None:
        context_document.pop("commissioning_evidence_binding")
    return json.dumps({
        "schema": _SCHEMA, "context": context_document, "operator": operator,
        "granted_at": granted_at, "expires_at": expires_at,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_activation_approval(
    *, trust: OperatorTrust, expected: ActivationContext, operator: str,
    payload: bytes, signature: bytes, now: str, max_lease_seconds: int,
) -> ActivationLease:
    """Verify attribution, exact context, canonical bytes and a bounded UTC lease.

    The duration ceiling comes from local policy, never from this document.
    A valid result remains an input to the controller; it supplies no health,
    product admission, unit selection or authorization mint.
    """
    trust.verify(operator=operator, purpose=ApprovalPurpose.ACTIVATION,
                 payload=payload, signature=signature)
    if type(max_lease_seconds) is not int or max_lease_seconds <= 0:
        raise ApprovalRefused("local lease duration policy required")
    try:
        document = json.loads(payload)
        if type(document) is not dict or set(document) != {
            "schema", "context", "operator", "granted_at", "expires_at"
        }:
            raise ApprovalRefused("invalid activation approval fields")
        # Canonical re-encoding also refuses duplicate/extra fields, bool/int
        # substitutions, alternate representations and a different context.
        canonical = approval_payload(
            context=expected, operator=operator, granted_at=document["granted_at"],
            expires_at=document["expires_at"],
        )
        if payload != canonical:
            raise ApprovalRefused("activation approval does not match expected context")
        start, end, instant = (_utc(document["granted_at"]),
                               _utc(document["expires_at"]), _utc(now))
        if not start <= instant < end or (end - start).total_seconds() > max_lease_seconds:
            raise ApprovalRefused("activation approval outside local time policy")
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ApprovalRefused("activation approval document refused") from exc
    return ActivationLease(granted_by=operator, granted_at=document["granted_at"],
                           expires_at=document["expires_at"], generation_digest=expected.generation_digest,
                           generation_number=expected.generation,
                           commissioning_digest=expected.commissioning_digest,
                           commissioning_evidence_binding=expected.commissioning_evidence_binding)
