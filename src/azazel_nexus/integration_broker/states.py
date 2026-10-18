"""Pure adapter lifecycle decisions. No transition dispatches or enables a unit.

Failure states have no activation path: reset to DISABLED and repeat admission.
ACTIVE_BOUNDED requires an already verified, adapter-bound Edge lease. The
routing layer owns signature verification; this module consumes its Protocol.
"""

from __future__ import annotations

import re
from dataclasses import InitVar, dataclass, replace
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from .manifest import is_safe_symbol


class BrokerState(str, Enum):
    DISABLED = "disabled"
    DISCOVERED = "discovered"
    STAGED = "staged"
    ADMITTED = "admitted"
    OBSERVE_ONLY = "observe_only"
    APPROVAL_PENDING = "approval_pending"
    ACTIVE_BOUNDED = "active_bounded"
    WITHDRAWING = "withdrawing"
    DEGRADED = "degraded"
    QUARANTINED = "quarantined"
    FAILED = "failed"


class TransitionRefused(Exception):
    """No mutation occurred; refusal messages contain no supplied payload."""


@runtime_checkable
class Approval(Protocol):
    """Verified Edge lease, exposed by the routing verifier, never raw JSON.

    ``verified`` must be exactly True following commissioned signature and
    validity checks. The broker does not convert external payloads to approvals.
    Expiry is exclusive, and timestamps must be timezone-aware.
    """

    @property
    def verified(self) -> bool: ...

    @property
    def adapter_id(self) -> str: ...

    @property
    def expires_at(self) -> datetime: ...


# Explicit rows, including narrowing paths. No ordering of enum members is a
# permission. WITHDRAWING is mandatory when leaving an active exposure normally.
ALLOWED_TRANSITIONS = MappingProxyType({
    BrokerState.DISABLED: frozenset({BrokerState.DISCOVERED, BrokerState.DEGRADED,
                                   BrokerState.QUARANTINED, BrokerState.FAILED,
                                   BrokerState.WITHDRAWING}),
    BrokerState.DISCOVERED: frozenset({BrokerState.STAGED, BrokerState.DISABLED,
                                     BrokerState.DEGRADED, BrokerState.QUARANTINED,
                                     BrokerState.FAILED, BrokerState.WITHDRAWING}),
    BrokerState.STAGED: frozenset({BrokerState.ADMITTED, BrokerState.DISABLED,
                                 BrokerState.DEGRADED, BrokerState.QUARANTINED,
                                 BrokerState.FAILED, BrokerState.WITHDRAWING}),
    BrokerState.ADMITTED: frozenset({BrokerState.OBSERVE_ONLY, BrokerState.DISABLED,
                                   BrokerState.DEGRADED, BrokerState.QUARANTINED,
                                   BrokerState.FAILED, BrokerState.WITHDRAWING}),
    BrokerState.OBSERVE_ONLY: frozenset({BrokerState.APPROVAL_PENDING, BrokerState.DISABLED,
                                       BrokerState.DEGRADED, BrokerState.QUARANTINED,
                                       BrokerState.FAILED, BrokerState.WITHDRAWING}),
    BrokerState.APPROVAL_PENDING: frozenset({BrokerState.ACTIVE_BOUNDED, BrokerState.OBSERVE_ONLY,
                                           BrokerState.DISABLED, BrokerState.DEGRADED,
                                           BrokerState.QUARANTINED, BrokerState.FAILED,
                                           BrokerState.WITHDRAWING}),
    BrokerState.ACTIVE_BOUNDED: frozenset({BrokerState.WITHDRAWING, BrokerState.DEGRADED,
                                         BrokerState.QUARANTINED, BrokerState.FAILED}),
    BrokerState.DEGRADED: frozenset({BrokerState.WITHDRAWING, BrokerState.QUARANTINED,
                                   BrokerState.FAILED, BrokerState.DISABLED}),
    BrokerState.QUARANTINED: frozenset({BrokerState.WITHDRAWING, BrokerState.FAILED,
                                      BrokerState.DISABLED}),
    BrokerState.FAILED: frozenset({BrokerState.WITHDRAWING, BrokerState.QUARANTINED,
                                 BrokerState.DISABLED}),
    BrokerState.WITHDRAWING: frozenset({BrokerState.DISABLED, BrokerState.QUARANTINED,
                                      BrokerState.FAILED}),
})


def _aware(value: object) -> bool:
    return isinstance(value, datetime) and value.utcoffset() is not None


_CONSTRUCTION = object()
NARROWING = frozenset({BrokerState.WITHDRAWING, BrokerState.DEGRADED,
                       BrokerState.QUARANTINED, BrokerState.FAILED, BrokerState.DISABLED})


@dataclass(frozen=True)
class AdapterRecord:
    adapter_id: str
    state: BrokerState = BrokerState.DISABLED
    manifest_digest: str | None = None
    since: datetime | None = None
    lease_id: str | None = None
    lease_expires_at: datetime | None = None
    _authority: InitVar[object] = None

    def __post_init__(self, _authority) -> None:
        if self.state is not BrokerState.DISABLED and _authority is not _CONSTRUCTION:
            raise TransitionRefused("restore_required")
        if not is_safe_symbol(self.adapter_id) or not isinstance(self.state, BrokerState):
            raise TransitionRefused("invalid_record")
        if self.manifest_digest is not None and (
            not isinstance(self.manifest_digest, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", self.manifest_digest)
        ):
            raise TransitionRefused("invalid_manifest_digest")
        if self.since is not None and not _aware(self.since):
            raise TransitionRefused("invalid_since")


@dataclass(frozen=True)
class Transition:
    from_state: BrokerState
    to_state: BrokerState
    reason: str
    occurred_at: datetime
    adapter_id: str
    manifest_digest: str | None
    lease_id: str | None = None
    lease_expires_at: datetime | None = None

    def as_event(self) -> dict:
        """Only bounded identifiers, digest, reason code, and timestamp."""
        return {
            "event_type": "broker.adapter.transition",
            "adapter_id": self.adapter_id,
            "from": self.from_state.value,
            "to": self.to_state.value,
            "reason": self.reason,
            "occurred_at": self.occurred_at.isoformat(),
            "manifest_digest": self.manifest_digest,
            "lease_id": self.lease_id,
            "lease_expires_at": self.lease_expires_at.isoformat() if self.lease_expires_at else None,
        }


def transition(
    record: AdapterRecord, to: BrokerState, *, reason: str, now: datetime,
    approval: Approval | None = None,
) -> tuple[AdapterRecord, Transition]:
    """Return a new record and audit event; widening never follows a failure.

    Reasons are symbolic codes, not external messages or free-form evidence.
    Narrowing ignores approval, so a bad/expired lease cannot block withdrawal.
    """
    if not isinstance(record, AdapterRecord) or not isinstance(to, BrokerState):
        raise TransitionRefused("invalid_transition")
    narrowing = to in NARROWING
    if not is_safe_symbol(reason):
        if not narrowing:
            raise TransitionRefused("invalid_reason")
        reason = "reason_invalid"
    if not _aware(now) or (not narrowing and record.since is not None and now < record.since):
        raise TransitionRefused("invalid_time")
    if narrowing and record.since is not None:
        now = max(now, record.since)
    if to not in ALLOWED_TRANSITIONS[record.state]:
        raise TransitionRefused("transition_not_allowed")
    if (to in {BrokerState.STAGED, BrokerState.ADMITTED, BrokerState.OBSERVE_ONLY,
               BrokerState.APPROVAL_PENDING, BrokerState.ACTIVE_BOUNDED}
            and record.manifest_digest is None):
        raise TransitionRefused("manifest_required")
    lease_id, expiry = record.lease_id, record.lease_expires_at
    if to is BrokerState.ACTIVE_BOUNDED:
        if not _valid_lease(approval, record.adapter_id, record.manifest_digest, now):
            raise TransitionRefused("invalid_approval")
        lease_id, expiry = approval.lease_id, approval.expires_at
    event = Transition(record.state, to, reason, now, record.adapter_id,
                       record.manifest_digest, lease_id, expiry)
    return replace(record, state=to, since=now, lease_id=lease_id,
                   lease_expires_at=expiry, _authority=_CONSTRUCTION), event


def _valid_lease(lease, adapter_id, manifest_digest, now):
    # Only the signature verifier's concrete result carries activation authority.
    from .routing import EdgeLease

    return (isinstance(lease, EdgeLease) and lease.verified is True
            and lease.adapter_id == adapter_id and lease.manifest_digest == manifest_digest
            and lease.expires_at > now)


def restore_record(adapter_id, state, manifest_digest, since, *, now, lease=None,
                   lease_id=None, lease_expires_at=None):
    """Explicit persistence boundary; pending/active restore fails toward withdrawal."""
    if not _aware(now):
        raise TransitionRefused("invalid_time")
    if state in {BrokerState.ACTIVE_BOUNDED, BrokerState.APPROVAL_PENDING}:
        if not _valid_lease(lease, adapter_id, manifest_digest, now):
            state = BrokerState.WITHDRAWING
        else:
            lease_id, lease_expires_at = lease.lease_id, lease.expires_at
    return AdapterRecord(adapter_id, state, manifest_digest, since, lease_id,
                         lease_expires_at, _authority=_CONSTRUCTION)


def expire_if_lease_lapsed(record, lease, now):
    """Return (record, optional audit event), withdrawing absent or lapsed authority."""
    if record.state is BrokerState.ACTIVE_BOUNDED and (
        not _valid_lease(lease, record.adapter_id, record.manifest_digest, now)
        or record.lease_id != lease.lease_id
        or record.lease_expires_at != lease.expires_at
    ):
        return transition(record, BrokerState.WITHDRAWING, reason="lease_expired", now=now)
    return record, None
