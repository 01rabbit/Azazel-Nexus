"""Fail-closed audit composition for M.I.O. route decisions (#5).

The decision modules stay pure so their results replay from the same inputs.
This module is the execution boundary: it makes a decision and appends that
decision to the Nexus audit chain before returning it to the caller. If the
ledger cannot append, the decision is not returned for execution.
"""

from __future__ import annotations

from typing import Mapping, Sequence

from .audit import AuditLedger
from .mio_profile import MioProfile
from .remote_trust import RemoteAdmission
from .route_evidence import Prediction
from .route_selection import (
    FallbackDecision,
    RequestOutcome,
    Selection,
    TerminalEvent,
    fallback_once,
    outcome_for,
    select,
)
from .routing import Route
from .sanitizer import PrivacyClass

__all__ = ["fallback_and_record", "outcome_and_record", "select_and_record"]


def _dated(event: Mapping[str, object], occurred_at: str) -> dict[str, object]:
    if not str(occurred_at).strip():
        raise ValueError("an audited route event records when it occurred")
    return {**event, "occurred_at": occurred_at}


def select_and_record(
    *,
    ledger: AuditLedger,
    occurred_at: str,
    profile: MioProfile,
    privacy_class: PrivacyClass,
    remote: RemoteAdmission,
    local_admitted: bool,
    local_refusal: str,
    predictions: Mapping[Route, Prediction],
    deadline_ms: int,
) -> Selection:
    """Select a route and record the complete decision before returning it."""

    decision = select(
        profile=profile,
        privacy_class=privacy_class,
        remote=remote,
        local_admitted=local_admitted,
        local_refusal=local_refusal,
        predictions=predictions,
        deadline_ms=deadline_ms,
    )
    ledger.append(_dated(decision.as_event(), occurred_at))
    return decision


def fallback_and_record(
    *,
    ledger: AuditLedger,
    occurred_at: str,
    selection: Selection,
    failed: Route,
    already_spent: bool,
    still_permitted: Sequence[Route] = (),
) -> FallbackDecision:
    """Choose the sole fallback and record its origin and destination."""

    decision = fallback_once(
        selection=selection,
        failed=failed,
        already_spent=already_spent,
        still_permitted=still_permitted,
    )
    ledger.append(_dated(decision.as_event(), occurred_at))
    return decision


def outcome_and_record(
    *,
    ledger: AuditLedger,
    occurred_at: str,
    route: Route,
    terminal_event: TerminalEvent,
    fallback_available: bool,
) -> RequestOutcome:
    """Classify and record how one route attempt ended."""

    outcome = outcome_for(terminal_event, fallback_available=fallback_available)
    ledger.append(
        _dated(
            {
                "event_type": "mio.route.terminal",
                "route": route.value,
                "terminal_event": terminal_event.value,
                "outcome": outcome.value,
                "fallback_available": fallback_available,
            },
            occurred_at,
        )
    )
    return outcome
