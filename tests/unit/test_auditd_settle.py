"""auditd settles a write of unknown outcome before it answers a resend (#467, review 1 items 1, 2, 10, 13)."""

from __future__ import annotations

import errno
import os
from datetime import UTC, datetime

import pytest

from azazel_nexus.audit import AuditUnavailable, canonical_event_bytes
from azazel_nexus_runtime.auditd import ACTIONS, AuditService, SegmentedLedger
from azazel_nexus_runtime.principal import Principal, PrincipalClass
from azazel_nexus_runtime.protocol import RequestRefused

from test_runtime_auditd import SERVICE, _append, _event, _request, _service

OTHER = Principal(uid=901, gid=901, pid=8, classes=frozenset({PrincipalClass.SERVICE}))


def fail_next_fsync(monkeypatch):
    real, state = os.fsync, {"n": 0}

    def fsync(fd):
        state["n"] += 1
        if state["n"] == 1:
            raise OSError(errno.EIO, "injected")
        return real(fd)
    monkeypatch.setattr(os, "fsync", fsync)
    return real


def events(service):
    return [entry.event for entry in service.ledger]


def kinds(service):
    return [event["event_type"] for event in events(service)]


def test_a_resend_is_not_answered_until_the_settlement_record_is_written(tmp_path, monkeypatch):
    service = _service(tmp_path)
    real = fail_next_fsync(monkeypatch)
    with pytest.raises(RequestRefused):
        _append(service, day="2026-09-20")
    monkeypatch.setattr(os, "fsync", real)
    # The settlement record cannot be written: the line is seen, but nothing is answered from it.
    internal = service.guard._internal
    service.guard._internal = lambda event: (_ for _ in ()).throw(AuditUnavailable("down"))
    with pytest.raises(RequestRefused) as refused:
        _append(service, day="2026-09-20")
    assert refused.value.detail == "ledger"
    assert kinds(service) == ["activation.unit_granted"]
    service.guard._internal = internal
    answered = _append(service, day="2026-09-20")
    assert answered["sequence"] == 1
    assert kinds(service) == ["activation.unit_granted", "audit.outcome_settled"]


def test_a_resend_is_answered_from_the_settled_line_after_other_appends(tmp_path, monkeypatch):
    service = _service(tmp_path)
    fail_next_fsync(monkeypatch)
    with pytest.raises(RequestRefused):
        _append(service, day="2026-09-20")
    # Another writer's request settles it, then goes on appending.
    other = service.handle(_request("audit.append", {"event_type": "activation.unit_granted"},
                                    _event(day="2026-09-20", unit="watchdog"), principal=OTHER))
    assert other["sequence"] == 3
    again = _append(service, day="2026-09-20")
    assert again["sequence"] == 1
    assert [e["event_type"] for e in events(service)] == [
        "activation.unit_granted", "audit.outcome_settled", "activation.unit_granted"]
    service.ledger.verify()


def test_a_resend_from_another_writer_is_not_answered_from_someone_elses_line(tmp_path, monkeypatch):
    service = _service(tmp_path)
    fail_next_fsync(monkeypatch)
    with pytest.raises(RequestRefused):
        _append(service, day="2026-09-20")
    service.guard.settle_owed()
    other = service.handle(_request("audit.append", {"event_type": "activation.unit_granted"},
                                    _event(day="2026-09-20"), principal=OTHER))
    assert other["sequence"] == 3        # a new line, not the first writer's


def test_the_head_follows_the_settlement_record(tmp_path, monkeypatch):
    service = _service(tmp_path)
    fail_next_fsync(monkeypatch)
    with pytest.raises(RequestRefused):
        _append(service, day="2026-09-20")
    assert service.guard.settle_owed()
    assert (service.head_sequence, service.head_hash) == service.ledger.head()


def test_a_summary_that_landed_is_taken_off_the_pending_counts(tmp_path, monkeypatch):
    service = _service(tmp_path)
    key = (900, "service", "activation.unit_granted", "service", "rate")
    service._summary_pending[key] = 3
    fail_next_fsync(monkeypatch)
    service._summarize(only=key)
    assert service._summary_pending[key] == 3          # not decided yet
    assert service.guard.settle_owed()
    assert key not in service._summary_pending        # it landed: not written again
    day = service._today()
    assert service._summaries_by_day[day] == 1
    service._summary_last.clear()
    service._summarize(only=key)
    assert kinds(service).count("audit.rate_limited") == 1


def test_an_incident_that_landed_counts_against_the_day(tmp_path, monkeypatch):
    service = _service(tmp_path)
    explainer = Principal(uid=902, gid=902, pid=9, classes=frozenset({PrincipalClass.SERVICE}))
    service._explainer_uid = 902
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {"incident_id": "inc-" + "0" * 16, "most_severe": 5, "edge_would": sorted(ACTIONS)[0],
               "count": 1, "technique_count": 0, "occurred_at": now}
    fail_next_fsync(monkeypatch)
    with pytest.raises(RequestRefused):
        service.handle(_request("audit.append", {"event_type": "edge.incident.opened"},
                                payload, principal=explainer))
    assert not service._incidents_by_day.get(now[:10])
    assert service.guard.settle_owed()
    assert sum(service._incidents_by_day[now[:10]][902]) == 1


def test_a_break_found_by_a_diagnostic_stops_the_tick_from_settling(tmp_path, monkeypatch):
    """5.1-1: a break found at any entrance stops the guard; the tick writes nothing."""
    from azazel_nexus.audit import AuditChainBroken
    from test_runtime_auditd import OPERATOR

    service = _service(tmp_path)
    real = fail_next_fsync(monkeypatch)
    with pytest.raises(RequestRefused):
        _append(service, day="2026-09-20")
    monkeypatch.setattr(os, "fsync", real)
    internal = service.guard._internal
    service.guard._internal = lambda event: (_ for _ in ()).throw(AuditUnavailable("down"))
    monkeypatch.setattr(service.ledger, "checkpoint",
                        lambda: (_ for _ in ()).throw(AuditChainBroken("found by the checkpoint")))
    reply = service.handle(_request("audit.verify", {}, principal=OPERATOR))
    assert reply["verified"] is False and service.guard.owed
    service.guard._internal = internal
    size = sum(p.stat().st_size for p in service.ledger.segments())
    service.tick()
    service.handle(_request("audit.verify", {}, principal=OPERATOR))
    assert sum(p.stat().st_size for p in service.ledger.segments()) == size
    assert service.guard.owed and kinds(service) == ["activation.unit_granted"]


def test_a_tick_after_a_failed_settling_does_not_summarize_counts_already_in_the_chain(tmp_path, monkeypatch):
    """5.1-5: the tick settles first; the counts a landed summary carried are not carried again."""
    service = _service(tmp_path)
    key = (900, "service", "activation.unit_granted", "service", "rate")
    service._summary_pending[key] = 3
    real = fail_next_fsync(monkeypatch)
    service._summarize(only=key)
    monkeypatch.setattr(os, "fsync", real)
    assert service.guard.owed and service._summary_pending[key] == 3
    # The window has passed. Settling cannot write its record yet: nothing is summarized.
    service.monotonic = lambda: 10_000_000.0
    internal = service.guard._internal
    service.guard._internal = lambda event: (_ for _ in ()).throw(AuditUnavailable("down"))
    service.tick()
    assert kinds(service) == ["audit.rate_limited"]
    # Back: the tick settles first (the 3 are taken off), then has nothing to summarize.
    service.guard._internal = internal
    service.tick()
    assert kinds(service) == ["audit.rate_limited", "audit.outcome_settled"]
    assert key not in service._summary_pending
