"""Activation approval v3: the strict decoder and verifier, not wired (#196, G6 prep).

`docs/deception-exposure-grant.md` §5 C1, condition 1. A v3 approval carries
everything a v2 approval does (`activation_approval_v2.py`, unchanged) and
may in addition name the three `DECEPTION_EXPOSURE` units
(`activation.DECEPTION_EXPOSURE_UNITS`), **all three or none**: a document
naming only part of the tier cannot be encoded, decoded or verified, so a
partial exposure set never reaches a lease.

It also carries, always, what the operator reads before signing
(`docs/deception-exposure-wiring.md` §5.1, owner decision Q-V = V2):
`exposure_scope_digest` (`sha256:` and 64 lowercase hex digits, the form of
the generation's exposure section `scope_digest`), `exposure_prefix_count`
(1 to `decoy_scope.MAX_PREFIXES`) and `exposure_ingress_count` (1 to
`decoy_scope.MAX_INGRESS`), the bounds the rendered scope file is held to.
Their **shape only** is checked here; comparing them with the generation's
section and this boot's rendering is the pass's (stage P10), not this
module's.

A v3 approval is attributed only under `ApprovalPurpose.ACTIVATION_EXPOSURE`
(owner decision Q-C): a v3 document signed under `ACTIVATION`, the purpose
of v2, is refused, and v2's verifier refuses the new purpose.

**Nothing calls this module.** It is a part for G6 (§9) and grants nothing
on its own:

- the activation pass reads v2 only (`activation_store.
  load_observe_baseline_approval`, `verify_observe_baseline_approval`) and
  requires an `ObserveBaselineApproval`, which this module never returns;
- `tools/operator_sign.py` cannot produce a v3 approval and does not offer
  the `ACTIVATION_EXPOSURE` purpose;
- the policy scope cannot name an exposure unit: `ActivationApprovalPolicy`
  refuses one, so a v3 approval naming the tier is refused by this verifier
  at the scope check until G6 changes the policy, the allowlist and
  `_withholding_reason` deliberately and with tests.

Tests pin all three (`tests/unit/test_activation_approval_v3.py`). Neither
schema is accepted as the other. The context, the policy, both floors and the
current time are supplied by the caller from independent readers, never from
the approval. This module reads no file, holds no key, signs nothing and
contacts no service manager.

**What it says.** Every refusal is `ApprovalRefused` (the type v2 and the
operator trust share, unchanged) with the message `"<code>: <phrase>"`: a
code of `APPROVAL_V3_CODES` and its one fixed phrase
(`APPROVAL_V3_PHRASES`), the wording this module used before the codes. A
refusal raised by a shared helper (the time parser of
`activation_approval`, `OperatorTrust.verify`) is given the code of its
phrase; one this module does not know is `approval_v3_document_refused`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from .activation import CORE_UNITS, DECEPTION_EXPOSURE_UNITS, ActivationLease, UnitTier
from .activation_approval import _utc
from .activation_approval_v2 import ActivationApprovalPolicy, ObserveBaselineContext
from .decoy_scope import MAX_INGRESS, MAX_PREFIXES
from .operator_trust import (
    MAX_APPROVAL_BYTES,
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
)

__all__ = [
    "APPROVAL_V3_CODES",
    "APPROVAL_V3_PHRASES",
    "SCHEMA_V3",
    "ActivationApprovalV3",
    "DecodedApprovalV3",
    "activation_approval_v3_payload",
    "decode_activation_approval_v3",
    "verify_activation_approval_v3",
]

SCHEMA_V3 = "azazel-nexus/activation-approval/v3"

#: Each refusal's code and its one fixed phrase, the wording v3 used before
#: the codes. The phrases of `_SHARED` are those the shared helpers raise; a
#: test keeps them equal to what those helpers raise.
APPROVAL_V3_PHRASES: dict[str, str] = {
    "approval_v3_trust_required": "operator trust required",
    "approval_v3_context_required": "activation context required",
    "approval_v3_policy_required": "activation policy required",
    "approval_v3_epoch_floor_required": "local security epoch floor required",
    "approval_v3_sequence_floor_required": "local approval sequence floor required",
    "approval_v3_payload_unbounded": "approval payload must be bounded nonempty bytes",
    "approval_v3_field_duplicate": "duplicate activation approval field",
    "approval_v3_fields_invalid": "invalid activation approval fields",
    "approval_v3_identifier_invalid": "invalid approval identifier",
    "approval_v3_operator_invalid": "invalid approval operator",
    "approval_v3_sequence_invalid": "invalid approval sequence",
    "approval_v3_expiry_not_after_grant": "approval expiry must follow its grant time",
    "approval_v3_units_not_collection": "approval units must be a collection of unit names",
    "approval_v3_units_not_distinct": "approval units must be distinct unit names",
    "approval_v3_units_outside_tiers": "approval units outside the v3 tiers",
    "approval_v3_exposure_partial": (
        "approval names only part of the Deception Lite exposure tier, "
        "which is approved together or not at all"),
    "approval_v3_exposure_scope_digest_invalid": "invalid approval exposure scope digest",
    "approval_v3_exposure_prefix_count_invalid": "invalid approval exposure prefix count",
    "approval_v3_exposure_ingress_count_invalid": "invalid approval exposure ingress count",
    "approval_v3_not_canonical": "activation approval is not canonical",
    "approval_v3_operator_unauthorized": "operator is not authorized by the activation policy",
    "approval_v3_context_mismatch": "activation approval does not match expected context",
    "approval_v3_epoch_below_floor": "activation security epoch below the local floor",
    "approval_v3_sequence_below_floor": "activation approval sequence below the local floor",
    "approval_v3_units_outside_scope": "activation approval units outside the policy scope",
    "approval_v3_outside_time_policy": "activation approval outside local time policy",
    "approval_v3_document_refused": "activation approval document refused",
    "approval_v3_time_form": "approval time must be UTC with whole seconds",
    "approval_v3_time_invalid": "invalid approval time",
    "approval_v3_operator_not_enrolled": "operator is not actively enrolled",
    "approval_v3_signature_refused": "operator signature refused",
    "approval_v3_purpose_unsupported": "unsupported approval purpose",
    "approval_v3_context_digest_invalid": "invalid activation context digest",
    "approval_v3_context_binding_invalid": "invalid activation commissioning evidence binding",
    "approval_v3_context_generation_invalid": "invalid activation generation",
    "approval_v3_context_epoch_invalid": "invalid activation security epoch",
}
APPROVAL_V3_CODES: tuple[str, ...] = tuple(APPROVAL_V3_PHRASES)

#: The phrases the shared helpers raise (`activation_approval._utc`,
#: `OperatorTrust.verify`, `ObserveBaselineContext`), to their codes.
_SHARED = {APPROVAL_V3_PHRASES[code]: code for code in (
    "approval_v3_time_form", "approval_v3_time_invalid",
    "approval_v3_operator_not_enrolled", "approval_v3_signature_refused",
    "approval_v3_purpose_unsupported", "approval_v3_payload_unbounded", "approval_v3_context_digest_invalid",
    "approval_v3_context_binding_invalid", "approval_v3_context_generation_invalid",
    "approval_v3_context_epoch_invalid")}
_CODED = frozenset(f"{code}: {phrase}" for code, phrase in APPROVAL_V3_PHRASES.items())


def _refused(code: str) -> ApprovalRefused:
    return ApprovalRefused(f"{code}: {APPROVAL_V3_PHRASES[code]}")


def _shared(exc: ApprovalRefused) -> ApprovalRefused:
    """A shared helper's refusal under the code of its phrase; one already
    coded stays as it is."""
    if str(exc) in _CODED:
        return exc
    return _refused(_SHARED.get(str(exc), "approval_v3_document_refused"))


def _time(value):
    try:
        return _utc(value)
    except ApprovalRefused as exc:
        raise _shared(exc) from None

# v3 keeps its own copies of the rules it shares with v2 rather than v2's
# private names, so a change to v2 cannot silently change v3 (the tests pin
# both sets and both encodings).
_OPERATOR = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_APPROVAL_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_FIELDS = frozenset({
    "schema", "approval_id", "operator", "node_digest", "generation",
    "generation_digest", "commissioning_digest", "commissioning_evidence_binding",
    "policy_digest", "security_epoch", "approval_seq", "units", "granted_at",
    "expires_at",
}) | frozenset({
    # v3's own (wiring §5.1, V2): shape only here, compared by the pass (P10).
    "exposure_scope_digest", "exposure_prefix_count", "exposure_ingress_count",
})

#: The form of the generation's exposure section `scope_digest`
#: (`exposure_generation._DIGEST`; a test keeps them equal).
_SCOPE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")

_EXPOSURE = frozenset(DECEPTION_EXPOSURE_UNITS)

#: v2's two tiers plus the exposure tier. ENFORCEMENT stays unnameable.
_V3_UNITS = frozenset(
    d.name for d in CORE_UNITS
    if d.tier in (UnitTier.SUPPORTING, UnitTier.EDGE_BASELINE, UnitTier.DECEPTION_EXPOSURE)
)
if not _EXPOSURE <= _V3_UNITS:  # pragma: no cover - a definition error, not input
    raise RuntimeError("the exposure units are not in the DECEPTION_EXPOSURE tier")


def _nonnegative(value, code: str) -> int:
    if type(value) is not int or value < 0:
        raise _refused(code)
    return value


def _bounded(value, maximum: int, code: str) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise _refused(code)
    return value


def _unique_object(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise _refused("approval_v3_field_duplicate")
        document[key] = value
    return document


def _unit_list(units) -> list[str]:
    if isinstance(units, (str, bytes)) or not isinstance(units, (list, tuple, frozenset, set)):
        raise _refused("approval_v3_units_not_collection")
    names = list(units)
    if not names or any(type(name) is not str for name in names) or len(set(names)) != len(names):
        raise _refused("approval_v3_units_not_distinct")
    if not set(names) <= _V3_UNITS:
        raise _refused("approval_v3_units_outside_tiers")
    exposure = set(names) & _EXPOSURE
    if exposure and exposure != _EXPOSURE:
        raise _refused("approval_v3_exposure_partial")
    return sorted(names)


def activation_approval_v3_payload(
    *, context: ObserveBaselineContext, approval_id: str, operator: str,
    approval_seq: int, units: Iterable[str], granted_at: str, expires_at: str,
    exposure_scope_digest: str, exposure_prefix_count: int, exposure_ingress_count: int,
) -> bytes:
    """Unsigned canonical v3 bytes: the v2 fields under the v3 schema name,
    and the three exposure fields, checked for shape only."""
    if type(context) is not ObserveBaselineContext:
        raise _refused("approval_v3_context_required")
    if type(approval_id) is not str or not _APPROVAL_ID.fullmatch(approval_id):
        raise _refused("approval_v3_identifier_invalid")
    if type(operator) is not str or not _OPERATOR.fullmatch(operator):
        raise _refused("approval_v3_operator_invalid")
    _nonnegative(approval_seq, "approval_v3_sequence_invalid")
    if _time(expires_at) <= _time(granted_at):
        raise _refused("approval_v3_expiry_not_after_grant")
    if type(exposure_scope_digest) is not str or not _SCOPE_DIGEST.fullmatch(
            exposure_scope_digest):
        raise _refused("approval_v3_exposure_scope_digest_invalid")
    _bounded(exposure_prefix_count, MAX_PREFIXES, "approval_v3_exposure_prefix_count_invalid")
    _bounded(exposure_ingress_count, MAX_INGRESS, "approval_v3_exposure_ingress_count_invalid")
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
        "exposure_scope_digest": exposure_scope_digest,
        "exposure_prefix_count": exposure_prefix_count,
        "exposure_ingress_count": exposure_ingress_count,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _exposure_fields(document: dict) -> dict:
    return {name: document[name] for name in (
        "exposure_scope_digest", "exposure_prefix_count", "exposure_ingress_count")}


def _parse(payload: bytes) -> dict:
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_APPROVAL_BYTES:
        raise _refused("approval_v3_payload_unbounded")
    document = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object)
    if type(document) is not dict or set(document) != _FIELDS or document["schema"] != SCHEMA_V3:
        raise _refused("approval_v3_fields_invalid")
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
    exposure_scope_digest: str
    exposure_prefix_count: int
    exposure_ingress_count: int


def decode_activation_approval_v3(payload: bytes) -> DecodedApprovalV3:
    """Strictly decode v3 bytes, or `ApprovalRefused`.

    The bytes must re-encode to exactly themselves (field set, schema, types,
    sorted distinct units, all-or-none exposure, the exposure fields' shape,
    key order, separators). The context is taken from the document, so this
    proves shape only.
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
            expires_at=document["expires_at"], **_exposure_fields(document),
        )
        if payload != canonical:
            raise _refused("approval_v3_not_canonical")
    except ApprovalRefused as exc:
        coded = _shared(exc)
        if coded is exc:
            raise
        raise coded from None
    except Exception as exc:  # every other failure is the same redacted refusal
        raise _refused("approval_v3_document_refused") from exc
    return DecodedApprovalV3(
        approval_id=document["approval_id"], operator=document["operator"],
        context=context, approval_seq=document["approval_seq"],
        units=frozenset(document["units"]), granted_at=document["granted_at"],
        expires_at=document["expires_at"], **_exposure_fields(document),
    )


@dataclass(frozen=True)
class ActivationApprovalV3:
    """A verified v3 approval. Deliberately not `ObserveBaselineApproval`:
    the activation pass accepts only that type. The exposure fields are as
    signed, checked for shape only: they are for the pass to compare (P10)."""

    lease: ActivationLease
    approval_id: str
    approval_seq: int
    security_epoch: int
    exposure_scope_digest: str
    exposure_prefix_count: int
    exposure_ingress_count: int


def verify_activation_approval_v3(
    *, trust: OperatorTrust, expected: ObserveBaselineContext,
    policy: ActivationApprovalPolicy, payload: bytes, signature: bytes, now: str,
    security_epoch_floor: int, approval_seq_floor: int,
) -> ActivationApprovalV3:
    """Verify a v3 approval the way v2 is verified, with the v3 unit rule.

    Attribution through the existing operator trust and the
    `ACTIVATION_EXPOSURE` purpose (never `ACTIVATION`, v2's), the policy's
    operator set, exact context, canonical bytes (the exposure fields' shape
    included, not their values), both floors, the policy's unit scope and the
    time window. While the policy
    scope cannot name an exposure unit, a v3 approval naming the tier is
    refused here at the scope check.
    """
    if type(trust) is not OperatorTrust:
        raise _refused("approval_v3_trust_required")
    if type(expected) is not ObserveBaselineContext:
        raise _refused("approval_v3_context_required")
    if type(policy) is not ActivationApprovalPolicy:
        raise _refused("approval_v3_policy_required")
    _nonnegative(security_epoch_floor, "approval_v3_epoch_floor_required")
    _nonnegative(approval_seq_floor, "approval_v3_sequence_floor_required")
    try:
        document = _parse(payload)
        operator = document["operator"]
        if type(operator) is not str or not _OPERATOR.fullmatch(operator):
            raise _refused("approval_v3_operator_invalid")
        trust.verify(operator=operator, purpose=ApprovalPurpose.ACTIVATION_EXPOSURE,
                     payload=payload, signature=signature)
        if operator not in policy.authorized_operators:
            raise _refused("approval_v3_operator_unauthorized")
        canonical = activation_approval_v3_payload(
            context=expected, approval_id=document["approval_id"], operator=operator,
            approval_seq=document["approval_seq"], units=document["units"],
            granted_at=document["granted_at"], expires_at=document["expires_at"],
            **_exposure_fields(document),
        )
        if payload != canonical:
            raise _refused("approval_v3_context_mismatch")
        if expected.security_epoch < security_epoch_floor:
            raise _refused("approval_v3_epoch_below_floor")
        if document["approval_seq"] < approval_seq_floor:
            raise _refused("approval_v3_sequence_below_floor")
        units = frozenset(document["units"])
        if not units <= policy.unit_scope:
            raise _refused("approval_v3_units_outside_scope")
        start, end, instant = (_time(document["granted_at"]),
                               _time(document["expires_at"]), _time(now))
        if (not start <= instant < end
                or (end - start).total_seconds() > policy.max_lease_seconds):
            raise _refused("approval_v3_outside_time_policy")
        lease = ActivationLease(
            granted_by=operator, granted_at=document["granted_at"],
            expires_at=document["expires_at"], generation_digest=expected.generation_digest,
            generation_number=expected.generation,
            commissioning_digest=expected.commissioning_digest,
            commissioning_evidence_binding=expected.commissioning_evidence_binding,
            units=units,
        )
    except ApprovalRefused as exc:
        coded = _shared(exc)
        if coded is exc:
            raise
        raise coded from None
    except Exception as exc:  # every other failure is the same redacted refusal
        raise _refused("approval_v3_document_refused") from exc
    return ActivationApprovalV3(lease=lease, approval_id=document["approval_id"],
                                approval_seq=document["approval_seq"],
                                security_epoch=expected.security_epoch,
                                **_exposure_fields(document))
