"""Activation approval v3: the strict decoder and verifier, not wired (#196, G6 prep).

`docs/deception-exposure-grant.md` §5 C1, condition 1. A v3 approval carries
everything a v2 approval does (`activation_approval_v2.py`, unchanged) and
may in addition name the three `DECEPTION_EXPOSURE` units
(`activation.DECEPTION_EXPOSURE_UNITS`), **all three or none**: a document
naming only part of the tier cannot be encoded, decoded or verified, so a
partial exposure set never reaches a lease.

**Nothing calls this module.** It is a part for G6 (§9) and grants nothing
on its own:

- the activation pass reads v2 only (`activation_store.
  load_observe_baseline_approval`, `verify_observe_baseline_approval`) and
  requires an `ObserveBaselineApproval`, which this module never returns;
- `tools/operator_sign.py` cannot produce a v3 approval;
- the policy scope cannot name an exposure unit: `ActivationApprovalPolicy`
  refuses one, so a v3 approval naming the tier is refused by this verifier
  at the scope check until G6 changes the policy, the allowlist and
  `_withholding_reason` deliberately and with tests.

Tests pin all three (`tests/unit/test_activation_approval_v3.py`). Neither
schema is accepted as the other. The context, the policy, both floors and the
current time are supplied by the caller from independent readers, never from
the approval. This module reads no file, holds no key, signs nothing and
contacts no service manager.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field

from .activation import DECEPTION_EXPOSURE_UNITS, ActivationLease
from .activation_approval import _utc
from .activation_approval_v2 import (
    _APPROVAL_ID,
    _FIELDS,
    _OPERATOR,
    _V2_UNITS,
    ActivationApprovalPolicy,
    ObserveBaselineContext,
    _nonnegative,
    _unique_object,
)
from .operator_trust import (
    MAX_APPROVAL_BYTES,
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
)

__all__ = [
    "SCHEMA_V3",
    "ActivationApprovalV3",
    "DecodedApprovalV3",
    "activation_approval_v3_payload",
    "decode_activation_approval_v3",
    "verify_activation_approval_v3",
]

SCHEMA_V3 = "azazel-nexus/activation-approval/v3"

_EXPOSURE = frozenset(DECEPTION_EXPOSURE_UNITS)

#: v2's two tiers plus the exposure tier. ENFORCEMENT stays unnameable.
_V3_UNITS = _V2_UNITS | _EXPOSURE


def _unit_list(units) -> list[str]:
    if isinstance(units, (str, bytes)) or not isinstance(units, (list, tuple, frozenset, set)):
        raise ApprovalRefused("approval units must be a collection of unit names")
    names = list(units)
    if not names or any(type(name) is not str for name in names) or len(set(names)) != len(names):
        raise ApprovalRefused("approval units must be distinct unit names")
    if not set(names) <= _V3_UNITS:
        raise ApprovalRefused("approval units outside the v3 tiers")
    exposure = set(names) & _EXPOSURE
    if exposure and exposure != _EXPOSURE:
        raise ApprovalRefused(
            "approval names only part of the Deception Lite exposure tier, "
            "which is approved together or not at all")
    return sorted(names)


def activation_approval_v3_payload(
    *, context: ObserveBaselineContext, approval_id: str, operator: str,
    approval_seq: int, units: Iterable[str], granted_at: str, expires_at: str,
) -> bytes:
    """Unsigned canonical v3 bytes: the v2 fields under the v3 schema name."""
    if type(context) is not ObserveBaselineContext:
        raise ApprovalRefused("activation context required")
    if type(approval_id) is not str or not _APPROVAL_ID.fullmatch(approval_id):
        raise ApprovalRefused("invalid approval identifier")
    if type(operator) is not str or not _OPERATOR.fullmatch(operator):
        raise ApprovalRefused("invalid approval operator")
    _nonnegative(approval_seq, "invalid approval sequence")
    if _utc(expires_at) <= _utc(granted_at):
        raise ApprovalRefused("approval expiry must follow its grant time")
    return json.dumps({
        "schema": SCHEMA_V3,
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


def _parse(payload: bytes) -> dict:
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_APPROVAL_BYTES:
        raise ApprovalRefused("approval payload must be bounded nonempty bytes")
    document = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object)
    if type(document) is not dict or set(document) != _FIELDS or document["schema"] != SCHEMA_V3:
        raise ApprovalRefused("invalid activation approval fields")
    return document


@dataclass(frozen=True)
class DecodedApprovalV3:
    """A well-formed, canonical v3 document. **Not verified**: no signature,
    no expected context, no policy and no floor has been consulted."""

    approval_id: str
    operator: str
    context: ObserveBaselineContext = field(repr=False)
    approval_seq: int
    units: frozenset[str]
    granted_at: str
    expires_at: str


def decode_activation_approval_v3(payload: bytes) -> DecodedApprovalV3:
    """Strictly decode v3 bytes, or `ApprovalRefused`.

    The bytes must re-encode to exactly themselves (field set, schema, types,
    sorted distinct units, all-or-none exposure, key order, separators). The
    context is taken from the document, so this proves shape only.
    """
    try:
        document = _parse(payload)
        context = ObserveBaselineContext(
            node_digest=document["node_digest"], generation=document["generation"],
            generation_digest=document["generation_digest"],
            commissioning_digest=document["commissioning_digest"],
            commissioning_evidence_binding=document["commissioning_evidence_binding"],
            policy_digest=document["policy_digest"],
            security_epoch=document["security_epoch"],
        )
        canonical = activation_approval_v3_payload(
            context=context, approval_id=document["approval_id"],
            operator=document["operator"], approval_seq=document["approval_seq"],
            units=document["units"], granted_at=document["granted_at"],
            expires_at=document["expires_at"],
        )
        if payload != canonical:
            raise ApprovalRefused("activation approval is not canonical")
    except ApprovalRefused:
        raise
    except Exception as exc:  # every other failure is the same redacted refusal
        raise ApprovalRefused("activation approval document refused") from exc
    return DecodedApprovalV3(
        approval_id=document["approval_id"], operator=document["operator"],
        context=context, approval_seq=document["approval_seq"],
        units=frozenset(document["units"]), granted_at=document["granted_at"],
        expires_at=document["expires_at"],
    )


@dataclass(frozen=True)
class ActivationApprovalV3:
    """A verified v3 approval. Deliberately not `ObserveBaselineApproval`:
    the activation pass accepts only that type."""

    lease: ActivationLease
    approval_id: str
    approval_seq: int
    security_epoch: int


def verify_activation_approval_v3(
    *, trust: OperatorTrust, expected: ObserveBaselineContext,
    policy: ActivationApprovalPolicy, payload: bytes, signature: bytes, now: str,
    security_epoch_floor: int, approval_seq_floor: int,
) -> ActivationApprovalV3:
    """Verify a v3 approval the way v2 is verified, with the v3 unit rule.

    Attribution through the existing operator trust and the `ACTIVATION`
    purpose, the policy's operator set, exact context, canonical bytes, both
    floors, the policy's unit scope and the time window. While the policy
    scope cannot name an exposure unit, a v3 approval naming the tier is
    refused here at the scope check.
    """
    if type(expected) is not ObserveBaselineContext:
        raise ApprovalRefused("activation context required")
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
        canonical = activation_approval_v3_payload(
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
    except Exception as exc:  # every other failure is the same redacted refusal
        raise ApprovalRefused("activation approval document refused") from exc
    return ActivationApprovalV3(lease=lease, approval_id=document["approval_id"],
                                approval_seq=document["approval_seq"],
                                security_epoch=expected.security_epoch)
