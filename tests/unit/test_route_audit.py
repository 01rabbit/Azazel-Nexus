"""Route execution records selection, fallback and terminal state (#5)."""

from __future__ import annotations

import pytest

from azazel_nexus.audit import AuditLedger, AuditUnavailable
from azazel_nexus.mio_profile import MioProfile
from azazel_nexus.remote_trust import Exclusion, RemoteAdmission
from azazel_nexus.route_audit import (
    fallback_and_record,
    outcome_and_record,
    select_and_record,
)
from azazel_nexus.route_selection import RequestOutcome, TerminalEvent, outcome_for
from azazel_nexus.routing import Route
from azazel_nexus.sanitizer import PrivacyClass

NOW = "2026-10-08T00:00:00Z"


def remote_refused() -> RemoteAdmission:
    return RemoteAdmission(
        permitted=False,
        excluded_by=Exclusion.PROFILE,
        reason="remote was not commissioned",
    )


def test_selection_fallback_and_terminal_state_form_one_audit_chain(tmp_path) -> None:
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    selection = select_and_record(
        ledger=ledger,
        occurred_at=NOW,
        profile=MioProfile.LOCAL_ONLY,
        privacy_class=PrivacyClass.P2_MISSION,
        remote=remote_refused(),
        local_admitted=True,
        local_refusal="not refused",
        predictions={},
        deadline_ms=1000,
    )
    fallback = fallback_and_record(
        ledger=ledger,
        occurred_at=NOW,
        selection=selection,
        failed=selection.route,
        already_spent=False,
    )
    outcome = outcome_and_record(
        ledger=ledger,
        occurred_at=NOW,
        route=selection.route,
        terminal_event=TerminalEvent.TIMED_OUT,
        fallback_available=True,
    )

    assert fallback.failed is selection.route
    assert outcome is RequestOutcome.FELL_BACK
    ledger.verify()
    events = [entry.event for entry in ledger]
    assert [event["event_type"] for event in events] == [
        "mio.route.selected",
        "mio.route.fallback",
        "mio.route.terminal",
    ]
    assert events[1]["failed_route"] == selection.route.value
    assert all(event["occurred_at"] == NOW for event in events)


def test_a_route_decision_is_not_returned_when_audit_is_unavailable(tmp_path) -> None:
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")

    with pytest.raises(AuditUnavailable):
        select_and_record(
            ledger=AuditLedger(blocked / "audit.jsonl"),
            occurred_at=NOW,
            profile=MioProfile.CORE,
            privacy_class=PrivacyClass.P2_MISSION,
            remote=remote_refused(),
            local_admitted=False,
            local_refusal="HG-05 is open",
            predictions={},
            deadline_ms=1000,
        )


def test_an_audit_event_without_an_instant_is_refused_before_append(tmp_path) -> None:
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    with pytest.raises(ValueError, match="records when"):
        select_and_record(
            ledger=ledger,
            occurred_at=" ",
            profile=MioProfile.CORE,
            privacy_class=PrivacyClass.P2_MISSION,
            remote=remote_refused(),
            local_admitted=False,
            local_refusal="HG-05 is open",
            predictions={},
            deadline_ms=1000,
        )
    assert not ledger.path.exists()


@pytest.mark.parametrize("terminal_event", list(TerminalEvent))
@pytest.mark.parametrize("fallback_available", [False, True])
def test_terminal_records_follow_pure_outcome_invariants(
    tmp_path, terminal_event, fallback_available,
) -> None:
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    outcome = outcome_and_record(
        ledger=ledger,
        occurred_at=NOW,
        route=Route.LOCAL,
        terminal_event=terminal_event,
        fallback_available=fallback_available,
        reason="local_ready_no_answer" if terminal_event is TerminalEvent.NO_ANSWER else None,
    )
    assert outcome is outcome_for(terminal_event, fallback_available=fallback_available)
    ledger.verify()
    event = next(iter(ledger)).event
    assert TerminalEvent(event["terminal_event"]) is terminal_event
    assert event["outcome"] == outcome.value
    assert event["fallback_available"] is fallback_available
    assert event["occurred_at"] == NOW
    if terminal_event is TerminalEvent.NO_ANSWER:
        assert outcome is RequestOutcome.REFUSED
        assert event["reason"] == "local_ready_no_answer"
    else:
        assert "reason" not in event


def test_no_answer_is_not_returned_when_audit_is_unavailable(tmp_path) -> None:
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    with pytest.raises(AuditUnavailable):
        outcome_and_record(
            ledger=AuditLedger(blocked / "audit.jsonl"),
            occurred_at=NOW,
            route=Route.LOCAL,
            terminal_event=TerminalEvent.NO_ANSWER,
            fallback_available=True,
            reason="local_ready_no_answer",
        )
