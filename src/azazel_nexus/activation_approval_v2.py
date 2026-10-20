"""Boot-free observe-baseline activation approval (schema v2, #206).

`docs/activation-observe-baseline.md` §3.1. A v2 approval names an exact set
of SUPPORTING and EDGE_BASELINE units and carries no `boot_id`, so a grant
made at one pass can enable units for a later boot. It is still not a grant:
the verifier returns a lease that the controller combines with a verified
generation, node health and its own gates, and the lease can only narrow.

Like v1 (`activation_approval.py`, unchanged), the verifier compares with
independently collected expected context and must not be populated from the
approval itself. The activation policy, the epoch and sequence floors and the
current time are supplied by the caller as plain values; their protected
readers are separate work. Neither schema is accepted as the other.

This module reads no file, holds no key, signs nothing and contacts no
service manager.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Iterable

from .activation import CORE_UNITS, ActivationLease, UnitTier
from .activation_approval import _DIGEST, _utc
from .operator_trust import MAX_APPROVAL_BYTES, ApprovalPurpose, ApprovalRefused, OperatorTrust

__all__ = [
    "MAX_LEASE_CEILING_SECONDS",
    "SCHEMA_V2",
    "ActivationApprovalPolicy",
    "ObserveBaselineApproval",
    "ObserveBaselineContext",
    "observe_baseline_payload",
    "verify_observe_baseline_approval",
]

SCHEMA_V2 = "azazel-nexus/activation-approval/v2"

#: The owner's ceiling for a boot-free lease (§6.1: at most 72 hours). A
#: policy may choose less; it cannot choose more.
MAX_LEASE_CEILING_SECONDS = 72 * 3600

_OPERATOR = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_APPROVAL_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_BINDING = re.compile(r"hmac-sha256:[0-9a-f]{64}\Z")
_FIELDS = frozenset({
    "schema", "approval_id", "operator", "node_digest", "generation",
    "generation_digest", "commissioning_digest", "commissioning_evidence_binding",
    "policy_digest", "security_epoch", "approval_seq", "units", "granted_at",
    "expires_at",
})

#: A v2 approval cannot express ENFORCEMENT scope.
_V2_UNITS = frozenset(
    d.name for d in CORE_UNITS if d.tier in (UnitTier.SUPPORTING, UnitTier.EDGE_BASELINE)
)


def _nonnegative(value, message: str) -> int:
    if type(value) is not int or value < 0:
        raise ApprovalRefused(message)
    return value


def _unit_list(units) -> list[str]:
    if isinstance(units, (str, bytes)) or not isinstance(units, (list, tuple, frozenset, set)):
        raise ApprovalRefused("approval units must be a collection of unit names")
    names = list(units)
    if not names or any(type(name) is not str for name in names) or len(set(names)) != len(names):
        raise ApprovalRefused("approval units must be distinct unit names")
    if not set(names) <= _V2_UNITS:
        raise ApprovalRefused("approval units outside the observe-baseline tiers")
    return sorted(names)


@dataclass(frozen=True)
class ActivationApprovalPolicy:
    """The parts of the protected activation policy this verifier consumes.

    Constructed by the caller (in production, the protected policy reader).
    Enrollment in the operator trust store is not enough: the operator must
    also be named here.
    """

    authorized_operators: frozenset[str]
    max_lease_seconds: int
    unit_scope: frozenset[str]

    def __post_init__(self):
        if type(self.authorized_operators) is not frozenset or any(
            type(name) is not str or not _OPERATOR.fullmatch(name)
            for name in self.authorized_operators
        ):
            raise ApprovalRefused("invalid activation policy operators")
        if (type(self.max_lease_seconds) is not int
                or not 0 < self.max_lease_seconds <= MAX_LEASE_CEILING_SECONDS):
            raise ApprovalRefused("invalid activation policy lease duration")
        if type(self.unit_scope) is not frozenset:
            raise ApprovalRefused("invalid activation policy unit scope")
        _unit_list(self.unit_scope)


@dataclass(frozen=True)
class ObserveBaselineContext:
    """Expected observations, never values learned from an untrusted approval."""

    node_digest: str
    generation: int
    generation_digest: str
    commissioning_digest: str
    commissioning_evidence_binding: str = field(repr=False)
    policy_digest: str
    security_epoch: int

    def __post_init__(self):
        for value in (self.node_digest, self.generation_digest,
                      self.commissioning_digest, self.policy_digest):
            if type(value) is not str or not _DIGEST.fullmatch(value):
                raise ApprovalRefused("invalid activation context digest")
        if (type(self.commissioning_evidence_binding) is not str
                or not _BINDING.fullmatch(self.commissioning_evidence_binding)):
            raise ApprovalRefused("invalid activation commissioning evidence binding")
        if type(self.generation) is not int or self.generation < 1:
            raise ApprovalRefused("invalid activation generation")
        _nonnegative(self.security_epoch, "invalid activation security epoch")


@dataclass(frozen=True)
class ObserveBaselineApproval:
    """A verified v2 approval: the lease plus the values its floors advance."""

    lease: ActivationLease
    approval_id: str
    approval_seq: int
    security_epoch: int


def observe_baseline_payload(
    *, context: ObserveBaselineContext, approval_id: str, operator: str,
    approval_seq: int, units: Iterable[str], granted_at: str, expires_at: str,
) -> bytes:
    """Unsigned canonical v2 bytes; the external operator signs the transcript."""
    if type(context) is not ObserveBaselineContext:
        raise ApprovalRefused("observe-baseline activation context required")
    if type(approval_id) is not str or not _APPROVAL_ID.fullmatch(approval_id):
        raise ApprovalRefused("invalid approval identifier")
    if type(operator) is not str or not _OPERATOR.fullmatch(operator):
        raise ApprovalRefused("invalid approval operator")
    _nonnegative(approval_seq, "invalid approval sequence")
    if _utc(expires_at) <= _utc(granted_at):
        raise ApprovalRefused("approval expiry must follow its grant time")
    return json.dumps({
        "schema": SCHEMA_V2,
        "approval_id": approval_id,
        "operator": operator,
        "node_digest": context.node_digest,
        "generation": context.generation,
        "generation_digest": context.generation_digest,
        "commissioning_digest": context.commissioning_digest,
        "commissioning_evidence_binding": context.commissioning_evidence_binding,
        "policy_digest": context.policy_digest,
        "security_epoch": context.security_epoch,
        "approval_seq": approval_seq,
        "units": _unit_list(units),
        "granted_at": granted_at,
        "expires_at": expires_at,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _unique_object(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ApprovalRefused("duplicate activation approval field")
        document[key] = value
    return document


def _parse(payload: bytes) -> dict:
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_APPROVAL_BYTES:
        raise ApprovalRefused("approval payload must be bounded nonempty bytes")
    document = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object)
    if type(document) is not dict or set(document) != _FIELDS or document["schema"] != SCHEMA_V2:
        raise ApprovalRefused("invalid activation approval fields")
    return document


def verify_observe_baseline_approval(
    *, trust: OperatorTrust, expected: ObserveBaselineContext,
    policy: ActivationApprovalPolicy, payload: bytes, signature: bytes, now: str,
    security_epoch_floor: int, approval_seq_floor: int,
) -> ObserveBaselineApproval:
    """Verify attribution, authorization, exact context, canonical bytes and bounds.

    The duration ceiling, the operator set and the unit scope come from local
    policy and the floors from local high water, never from this document.
    A valid result remains an input to the controller; it supplies no health,
    generation, product admission or authorization mint.
    """
    if type(expected) is not ObserveBaselineContext:
        raise ApprovalRefused("observe-baseline activation context required")
    if type(policy) is not ActivationApprovalPolicy:
        raise ApprovalRefused("activation policy required")
    _nonnegative(security_epoch_floor, "local security epoch floor required")
    _nonnegative(approval_seq_floor, "local approval sequence floor required")
    try:
        document = _parse(payload)
        operator = document["operator"]
        if type(operator) is not str or not _OPERATOR.fullmatch(operator):
            raise ApprovalRefused("invalid approval operator")
        trust.verify(operator=operator, purpose=ApprovalPurpose.ACTIVATION,
                     payload=payload, signature=signature)
        if operator not in policy.authorized_operators:
            raise ApprovalRefused("operator is not authorized by the activation policy")
        # Canonical re-encoding refuses extra or missing fields, bool/int
        # substitutions, unsorted or duplicate units, alternate
        # representations and any difference from the expected context.
        canonical = observe_baseline_payload(
            context=expected, approval_id=document["approval_id"], operator=operator,
            approval_seq=document["approval_seq"], units=document["units"],
            granted_at=document["granted_at"], expires_at=document["expires_at"],
        )
        if payload != canonical:
            raise ApprovalRefused("activation approval does not match expected context")
        if expected.security_epoch < security_epoch_floor:
            raise ApprovalRefused("activation security epoch below the local floor")
        if document["approval_seq"] < approval_seq_floor:
            raise ApprovalRefused("activation approval sequence below the local floor")
        units = frozenset(document["units"])
        if not units <= policy.unit_scope:
            raise ApprovalRefused("activation approval units outside the policy scope")
        start, end, instant = (_utc(document["granted_at"]),
                               _utc(document["expires_at"]), _utc(now))
        if (not start <= instant < end
                or (end - start).total_seconds() > policy.max_lease_seconds):
            raise ApprovalRefused("activation approval outside local time policy")
        lease = ActivationLease(
            granted_by=operator, granted_at=document["granted_at"],
            expires_at=document["expires_at"], generation_digest=expected.generation_digest,
            generation_number=expected.generation,
            commissioning_digest=expected.commissioning_digest,
            commissioning_evidence_binding=expected.commissioning_evidence_binding,
            units=units,
        )
    except ApprovalRefused:
        raise
    except Exception as exc:  # noqa: BLE001 - every other failure is the same redacted refusal
        raise ApprovalRefused("activation approval document refused") from exc
    return ObserveBaselineApproval(lease=lease, approval_id=document["approval_id"],
                                   approval_seq=document["approval_seq"],
                                   security_epoch=expected.security_epoch)
