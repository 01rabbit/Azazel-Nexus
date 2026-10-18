"""Pure adapter lifecycle decisions. No transition dispatches or enables a unit.

Failure states have no activation path: reset to DISABLED and repeat admission.
ACTIVE_BOUNDED requires an already verified, adapter-bound Edge lease. The
routing layer owns signature verification; this module consumes its Protocol.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
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


@dataclass(frozen=True)
class AdapterRecord:
    adapter_id: str
    state: BrokerState = BrokerState.DISABLED
    manifest_digest: str | None = None
    since: datetime | None = None

    def __post_init__(self) -> None:
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
    if not is_safe_symbol(reason):
        raise TransitionRefused("invalid_reason")
    if not _aware(now) or (record.since is not None and now < record.since):
        raise TransitionRefused("invalid_time")
    if to not in ALLOWED_TRANSITIONS[record.state]:
        raise TransitionRefused("transition_not_allowed")
    if (to in {BrokerState.STAGED, BrokerState.ADMITTED, BrokerState.OBSERVE_ONLY,
               BrokerState.APPROVAL_PENDING, BrokerState.ACTIVE_BOUNDED}
            and record.manifest_digest is None):
        raise TransitionRefused("manifest_required")
    if to is BrokerState.ACTIVE_BOUNDED:
        if not isinstance(approval, Approval):
            raise TransitionRefused("approval_required")
        if (approval.verified is not True or approval.adapter_id != record.adapter_id
                or not _aware(approval.expires_at) or approval.expires_at <= now):
            raise TransitionRefused("invalid_approval")
    event = Transition(record.state, to, reason, now, record.adapter_id, record.manifest_digest)
    return replace(record, state=to, since=now), event
