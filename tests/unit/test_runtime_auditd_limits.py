"""auditd's rate and daily limits (#211 S3).

What these must hold together: the limits never bind what the upstream
budgets can legitimately produce, a flood of ordinary records cannot starve a
severe one, a writer over the limit is refused with a final, bounded reason,
and the refusals are visible without becoming the growth they exist to stop.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import auditd
from azazel_nexus_runtime.auditd import (
    EVENT_SCHEMAS,
    INCIDENT_DAILY_CAP,
    INCIDENT_DAILY_RESERVE,
    INCIDENT_RATE,
    REGISTRY,
    SUMMARY_DAILY_CAP,
    SUMMARY_WINDOW_S,
    AuditService,
    RateLimit,
    SegmentedLedger,
    summarized_refusals,
)
from azazel_nexus_runtime.principal import Principal, PrincipalClass
from azazel_nexus_runtime.protocol import Refusal, RequestRefused
from azazel_nexus_runtime.transport import Request

EXPLAINER = Principal(uid=901, gid=901, pid=1, classes=frozenset({PrincipalClass.SERVICE}))
SERVICE = Principal(uid=900, gid=900, pid=7, classes=frozenset({PrincipalClass.SERVICE}))
ROOT = Principal(uid=0, gid=0, pid=1, classes=frozenset({PrincipalClass.ROOT}))
OPERATOR = Principal(uid=1000, gid=1000, pid=8, classes=frozenset({PrincipalClass.OPERATOR}))
#: 2026-10-19T00:00:00Z
START = 1792368000
DIGEST = "sha256:" + "ab" * 32


class Clocks:
    """Wall and monotonic time that move together, under the test's control."""

    def __init__(self, at=START + 3600):
        self.wall, self.mono = float(at), 1000.0

    def advance(self, seconds):
        self.wall += seconds
        self.mono += seconds


def _iso(at):
    return datetime.fromtimestamp(at, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _service(tmp_path, monkeypatch, clocks=None, warnings=None):
    monkeypatch.setattr(auditd.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=EXPLAINER.uid))
    root = tmp_path / "ledger"
    root.mkdir(parents=True, exist_ok=True)
    clocks = clocks or Clocks()
    service = AuditService(SegmentedLedger(root), clock=lambda: clocks.wall,
                           monotonic=lambda: clocks.mono,
                           warn=(warnings.append if warnings is not None else lambda _: None))
    service.start()
    return service, clocks


def _request(verb_name, arguments, payload=None, *, principal=EXPLAINER):
    verb = REGISTRY.resolve(verb_name, principal)
    return Request(verb=verb, arguments=verb.bind(arguments), principal=principal,
                   payload=payload or {})


_COUNTER = iter(range(1, 10**9))


def _incident(service, clocks, kind="opened", severity=5):
    payload = {"incident_id": f"inc-{next(_COUNTER):016x}", "most_severe": severity,
               "edge_would": "isolate" if severity <= 2 else "notify",
               "count": 1, "technique_count": 1, "occurred_at": _iso(clocks.wall)}
    if kind == "closed":
        payload["reason"] = "idle"
    return service.handle(_request("audit.append", {"event_type": "edge.incident." + kind}, payload))


def _refused(call):
    with pytest.raises(RequestRefused) as exc:
        call()
    assert exc.value.refusal is Refusal.RATE_LIMITED
    return exc.value.detail


def _events(service):
    return [entry.event for entry in service.ledger]


def _summaries(service):
    return [e for e in _events(service) if e["event_type"] == "audit.rate_limited"]


# -- never binding what upstream can produce --------------------------------


def test_upstream_maximum_incident_load_is_never_refused(tmp_path, monkeypatch):
    """Ten seconds at every upstream budget at once, then a whole table closing.

    Through the real ledger, so the order of checks in `_append` is covered.
    Openings: 60/min ordinary and 30/min severe (intake's rolling budgets).
    Escalations: 7 a second, the theoretical worst of 420/min (seven ordinary
    levels for each of 60 new incidents a minute). Closes: as many as
    openings, then all 1024 held incidents in one burst.
    """

    service, clocks = _service(tmp_path, monkeypatch)
    for second in range(10):
        _incident(service, clocks, "opened", 5)
        _incident(service, clocks, "closed", 5)
        for _ in range(7):
            _incident(service, clocks, "escalated", 4)
        if second % 2 == 0:
            _incident(service, clocks, "opened", 1)
            _incident(service, clocks, "closed", 1)
        clocks.advance(1)
    for _ in range(768):
        _incident(service, clocks, "closed", 5)
    for _ in range(256):
        _incident(service, clocks, "closed", 2)
    assert service.rate_limited == {}
    assert _summaries(service) == []
    service.ledger.verify()


def test_a_whole_day_at_the_upstream_budgets_is_never_refused(tmp_path, monkeypatch):
    """24 hours of the admission path alone (no ledger I/O, so it is fast).

    Every second: one ordinary opening and close (60/min), a severe opening
    and close every other second (30/min), and an escalation every other
    second. A 1024-close burst every hour (a whole table idling out). The
    rate buckets refill and the daily count stays below the ordinary ceiling.
    """

    service, clocks = _service(tmp_path, monkeypatch)
    pattern = [("edge.incident.opened", 5), ("edge.incident.closed", 5)]
    admitted = 0

    def admit(event_type, severity):
        nonlocal admitted
        day, uid, index = service._admit(EXPLAINER, event_type, {"most_severe": severity},
                                         "2026-10-19")
        service._incidents_by_day.setdefault(day, {}).setdefault(uid, [0, 0])[index] += 1
        admitted += 1

    service._today()
    for second in range(86400 - 3600 - 1):
        for event_type, severity in pattern:
            admit(event_type, severity)
        if second % 2 == 0:
            admit("edge.incident.opened", 1)
            admit("edge.incident.closed", 1)
            admit("edge.incident.escalated", 4)
        if second % 3600 == 0:
            for _ in range(1024):
                admit("edge.incident.closed", 6)
        clocks.advance(1)
        service._today()
    assert service.rate_limited == {}
    assert admitted < INCIDENT_DAILY_CAP - INCIDENT_DAILY_RESERVE


def test_daily_cap_sits_above_a_whole_day_at_the_upstream_budgets():
    """Arithmetic, kept next to the constants it justifies.

    A whole day of ordinary openings at 60/min and their closes, and of severe
    openings at 30/min and theirs, fit; the ordinary ones fit below the
    reserve. The ~10-16 MiB/day normal volume (#211) is far below either.
    """

    day = 24 * 60
    ordinary = 2 * 60 * day
    severe = 2 * 30 * day
    assert ordinary + severe < INCIDENT_DAILY_CAP - INCIDENT_DAILY_RESERVE
    assert severe < INCIDENT_DAILY_RESERVE * 2
    # The normal volume (16 MiB at the ~380 bytes measured below) is an
    # order of magnitude below.
    assert 10 * (16 * 2**20 // 380) < INCIDENT_DAILY_CAP
    # Every upstream rate fits the bucket's refill with room to spare, and a
    # whole incident table (1024) fits its burst.
    assert INCIDENT_RATE.per_second * 60 >= 420 and INCIDENT_RATE.burst >= 2 * 1024


def test_a_capped_day_is_bounded_in_bytes(tmp_path, monkeypatch):
    service, clocks = _service(tmp_path, monkeypatch)
    for kind in ("opened", "escalated", "closed"):
        _incident(service, clocks, kind, 1)
    segment = service.ledger.segments()[-1]
    widest = max(len(line) for line in segment.read_bytes().splitlines())
    # Counts are small here; a real count is up to 20 digits.
    assert (widest + 120) * INCIDENT_DAILY_CAP < 256 * 2**20


# -- the rate limit --------------------------------------------------------


def test_a_writer_over_its_bucket_is_refused_and_recovers(tmp_path, monkeypatch):
    monkeypatch.setattr(auditd, "INCIDENT_RATE", RateLimit(burst=3, per_second=0.5))
    service, clocks = _service(tmp_path, monkeypatch)
    for _ in range(3):
        _incident(service, clocks)
    before = len(_events(service))
    assert _refused(lambda: _incident(service, clocks)) == "rate"
    # The refusal appended no incident record (only the first summary).
    assert [e["event_type"] for e in _events(service)[before:]] == ["audit.rate_limited"]
    clocks.advance(2)
    _incident(service, clocks)
    assert _refused(lambda: _incident(service, clocks)) == "rate"
    assert service.rate_limited == {"rate:edge.incident.opened:ordinary": 2}


def test_an_ordinary_flood_cannot_starve_severe_records(tmp_path, monkeypatch):
    monkeypatch.setattr(auditd, "INCIDENT_RATE", RateLimit(burst=4, per_second=0.01))
    service, clocks = _service(tmp_path, monkeypatch)
    for kind in ("opened", "escalated", "closed"):
        for _ in range(4):
            _incident(service, clocks, kind, 7)
        for _ in range(20):
            _refused(lambda kind=kind: _incident(service, clocks, kind, 7))
    # Severe openings, escalations and closes have their own buckets.
    for kind in ("opened", "escalated", "closed"):
        for _ in range(4):
            _incident(service, clocks, kind, 1)
    # And an exhausted opening bucket does not stop the closes.
    monkeypatch.setattr(auditd, "INCIDENT_RATE", RateLimit(burst=2, per_second=0.01))
    service2, clocks2 = _service(tmp_path / "b", monkeypatch)
    for _ in range(2):
        _incident(service2, clocks2, "opened", 1)
    _refused(lambda: _incident(service2, clocks2, "opened", 1))
    _incident(service2, clocks2, "closed", 1)


def test_buckets_are_per_principal(tmp_path, monkeypatch):
    monkeypatch.setattr(auditd, "SERVICE_RATE", RateLimit(burst=2, per_second=0.01))
    service, clocks = _service(tmp_path, monkeypatch)
    other = Principal(uid=902, gid=902, pid=3, classes=frozenset({PrincipalClass.SERVICE}))

    def grant(principal):
        payload = {"unit": "auditd", "generation": 1, "digest": DIGEST,
                   "occurred_at": _iso(clocks.wall), "actor": "operator@console"}
        return service.handle(_request("audit.append", {"event_type": "activation.unit_granted"},
                                       payload, principal=principal))

    grant(SERVICE)
    grant(SERVICE)
    assert _refused(lambda: grant(SERVICE)) == "rate"
    grant(other)
    grant(other)
    # Root writes the bootstrap records and is not limited.
    for _ in range(10):
        grant(ROOT)
    assert service.rate_limited == {"rate:activation.unit_granted:service": 1}


# -- the daily cap ---------------------------------------------------------


def test_daily_cap_keeps_a_reserve_for_severe_records(tmp_path, monkeypatch):
    monkeypatch.setattr(auditd, "INCIDENT_DAILY_CAP", 6)
    monkeypatch.setattr(auditd, "INCIDENT_DAILY_RESERVE", 2)
    service, clocks = _service(tmp_path, monkeypatch)
    for _ in range(4):
        _incident(service, clocks, "opened", 5)
    assert _refused(lambda: _incident(service, clocks, "closed", 5)) == "daily"
    _incident(service, clocks, "opened", 2)
    _incident(service, clocks, "closed", 2)
    assert _refused(lambda: _incident(service, clocks, "closed", 1)) == "daily"
    assert service.rate_limited == {"daily:edge.incident.closed:ordinary": 1,
                                    "daily:edge.incident.closed:severe": 1}
    # Other writers are not touched by the explainer's daily count.
    payload = {"unit": "auditd", "generation": 1, "digest": DIGEST,
               "occurred_at": _iso(clocks.wall), "actor": "operator@console"}
    service.handle(_request("audit.append", {"event_type": "activation.unit_granted"},
                            payload, principal=SERVICE))
    # A new UTC day starts a new count.
    clocks.advance(86400)
    for _ in range(4):
        _incident(service, clocks, "opened", 5)


def test_a_restart_does_not_reset_the_daily_count(tmp_path, monkeypatch):
    monkeypatch.setattr(auditd, "INCIDENT_DAILY_CAP", 4)
    monkeypatch.setattr(auditd, "INCIDENT_DAILY_RESERVE", 1)
    service, clocks = _service(tmp_path, monkeypatch)
    _incident(service, clocks, "opened", 5)
    _incident(service, clocks, "opened", 1)
    restarted, _ = _service(tmp_path, monkeypatch, clocks)
    assert restarted._incidents_by_day == {"2026-10-19": {EXPLAINER.uid: [1, 1]}}
    _incident(restarted, clocks, "opened", 5)
    assert _refused(lambda: _incident(restarted, clocks, "opened", 5)) == "daily"
    _incident(restarted, clocks, "opened", 1)


# -- visibility, without amplification ------------------------------------


def test_refusals_are_summarized_once_per_window(tmp_path, monkeypatch):
    monkeypatch.setattr(auditd, "INCIDENT_RATE", RateLimit(burst=1, per_second=0.0001))
    service, clocks = _service(tmp_path, monkeypatch)
    _incident(service, clocks)
    for _ in range(500):
        _refused(lambda: _incident(service, clocks))
    first = _summaries(service)
    assert len(first) == 1 and first[0]["refused"] == 1
    assert first[0]["writer_uid"] == EXPLAINER.uid and first[0]["writer_class"] == "service"
    assert first[0]["refused_event_type"] == "edge.incident.opened"
    assert (first[0]["tier"], first[0]["limit"]) == ("ordinary", "rate")
    # Inside the window, ticking writes nothing more.
    clocks.advance(SUMMARY_WINDOW_S - 1)
    service.tick()
    assert len(_summaries(service)) == 1
    # After it, one record carries the rest, even though the flood stopped.
    clocks.advance(1)
    service.tick()
    assert [s["refused"] for s in _summaries(service)] == [1, 499]
    service.tick()
    clocks.advance(SUMMARY_WINDOW_S)
    service.tick()
    assert len(_summaries(service)) == 2
    service.ledger.verify()
    reply = service.handle(_request("audit.verify", {}, principal=OPERATOR))
    assert reply["rate_limited"] == {"rate:edge.incident.opened:ordinary": 500}


def test_summaries_have_a_daily_ceiling(tmp_path, monkeypatch):
    monkeypatch.setattr(auditd, "SUMMARY_DAILY_CAP", 2)
    monkeypatch.setattr(auditd, "SERVICE_RATE", RateLimit(burst=0, per_second=0.0))
    service, clocks = _service(tmp_path, monkeypatch)
    writers = [Principal(uid=950 + n, gid=950, pid=3, classes=frozenset({PrincipalClass.SERVICE}))
               for n in range(5)]
    for writer in writers:
        payload = {"unit": "auditd", "generation": 1, "digest": DIGEST,
                   "occurred_at": _iso(clocks.wall), "actor": "operator@console"}
        for _ in range(3):
            _refused(lambda payload=payload, writer=writer: service.handle(_request(
                "audit.append", {"event_type": "activation.unit_granted"}, payload,
                principal=writer)))
    clocks.advance(SUMMARY_WINDOW_S)
    service.tick()
    assert len(_summaries(service)) == 2
    assert service.summaries_dropped == 3 * 3 + 2 * 2
    # A restart counts today's summaries, so it does not reopen the ceiling.
    restarted, _ = _service(tmp_path, monkeypatch, clocks)
    assert restarted._summaries_by_day == {"2026-10-19": 2}
    assert SUMMARY_DAILY_CAP * 400 < 1 * 2**20


def test_a_summary_cannot_be_written_by_a_caller():
    for principal in (SERVICE, ROOT):
        with pytest.raises(RequestRefused) as exc:
            _request("audit.append", {"event_type": "audit.rate_limited"}, principal=principal)
        assert exc.value.refusal is Refusal.ARGUMENT_RANGE
    assert "audit.rate_limited" in EVENT_SCHEMAS


def test_a_summary_that_cannot_be_appended_is_kept_not_raised(tmp_path, monkeypatch):
    monkeypatch.setattr(auditd, "INCIDENT_RATE", RateLimit(burst=0, per_second=0.0))
    service, clocks = _service(tmp_path, monkeypatch)

    def unavailable(*_, **__):
        raise auditd.AuditUnavailable("disk full")

    monkeypatch.setattr(service.ledger, "append", unavailable)
    assert _refused(lambda: _incident(service, clocks)) == "rate"
    assert sum(service._summary_pending.values()) == 1
    monkeypatch.undo()
    monkeypatch.setattr(auditd.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=EXPLAINER.uid))
    clocks.advance(SUMMARY_WINDOW_S)
    service.tick()
    assert [s["refused"] for s in _summaries(service)] == [1]


def test_a_summary_failing_unexpectedly_still_refuses_as_rate_limited(tmp_path, monkeypatch):
    """Any fault writing the summary keeps the caller's answer `rate_limited`."""

    monkeypatch.setattr(auditd, "INCIDENT_RATE", RateLimit(burst=0, per_second=0.0))
    service, clocks = _service(tmp_path, monkeypatch)

    def broken(*_, **__):
        raise ValueError("unexpected")

    monkeypatch.setattr(service.ledger, "append", broken)
    assert _refused(lambda: _incident(service, clocks)) == "rate"
    bind = auditd._bind_event

    def bind_all_but_summaries(event_type, payload):
        if event_type == "audit.rate_limited":
            raise ValueError("unexpected")
        return bind(event_type, payload)

    monkeypatch.setattr(auditd, "_bind_event", bind_all_but_summaries)
    clocks.advance(SUMMARY_WINDOW_S)
    assert _refused(lambda: _incident(service, clocks)) == "rate"
    assert sum(service._summary_pending.values()) == 2
    service.tick()


# -- the day a count belongs to --------------------------------------------


def test_startup_recounts_in_the_verify_pass(tmp_path, monkeypatch):
    """One read of the chain before READY, not a second scan of today."""

    service, clocks = _service(tmp_path, monkeypatch)
    _incident(service, clocks, "opened", 5)
    _incident(service, clocks, "opened", 1)
    reads = []
    original = auditd.AuditLedger.__iter__

    def counted(self):
        reads.append(self.path.name)
        return original(self)

    monkeypatch.setattr(auditd.AuditLedger, "__iter__", counted)
    observed = []
    verify = SegmentedLedger.verify

    def spy(self, **kwargs):
        observed.append(kwargs.get("observe"))
        return verify(self, **kwargs)

    monkeypatch.setattr(SegmentedLedger, "verify", spy)
    restarted, _ = _service(tmp_path, monkeypatch, clocks)
    assert reads == ["2026-10-19.jsonl"]
    assert len(observed) == 1 and observed[0] is not None
    assert restarted._incidents_by_day == {"2026-10-19": {EXPLAINER.uid: [1, 1]}}


def test_a_recount_fault_fails_open_and_is_logged_once(tmp_path, monkeypatch):
    service, clocks = _service(tmp_path, monkeypatch)
    _incident(service, clocks, "opened", 5)
    _incident(service, clocks, "opened", 5)

    def broken(_):
        raise TypeError("unexpected")

    monkeypatch.setattr(auditd, "_severe", broken)
    warnings = []
    restarted, _ = _service(tmp_path, monkeypatch, clocks, warnings=warnings)
    assert restarted.verified and restarted._incidents_by_day == {}
    assert len(warnings) == 1 and "could not be rebuilt" in warnings[0]
    assert "inc-" not in warnings[0]


def test_counts_follow_the_segment_a_record_lands_in_across_midnight(tmp_path, monkeypatch):
    monkeypatch.setattr(auditd, "INCIDENT_DAILY_CAP", 2)
    monkeypatch.setattr(auditd, "INCIDENT_DAILY_RESERVE", 0)
    clocks = Clocks(at=START + 3)  # 2026-10-19T00:00:03Z
    service, _ = _service(tmp_path, monkeypatch, clocks)

    def late(second):
        payload = {"incident_id": f"inc-{next(_COUNTER):016x}", "most_severe": 5,
                   "edge_would": "notify", "count": 1, "technique_count": 1,
                   "occurred_at": f"2026-10-18T23:59:{second:02d}Z"}
        return service.handle(_request("audit.append", {"event_type": "edge.incident.opened"},
                                       payload))

    # Records from before midnight land in yesterday's segment, and count there.
    late(57)
    late(58)
    assert [p.name for p in service.ledger.segments()] == ["2026-10-18.jsonl"]
    assert _refused(lambda: late(59)) == "daily"
    # Today's segment is a new count, even though the clock day did not change.
    _incident(service, clocks, "opened", 5)
    assert service._incidents_by_day == {"2026-10-18": {EXPLAINER.uid: [2, 0]},
                                         "2026-10-19": {EXPLAINER.uid: [1, 0]}}
    # A restart rebuilds the same counts on the same basis.
    restarted, _ = _service(tmp_path, monkeypatch, clocks)
    assert restarted._incidents_by_day == service._incidents_by_day


def test_a_clock_stepping_backwards_does_not_wipe_the_count(tmp_path, monkeypatch):
    monkeypatch.setattr(auditd, "INCIDENT_DAILY_CAP", 2)
    monkeypatch.setattr(auditd, "INCIDENT_DAILY_RESERVE", 0)
    service, clocks = _service(tmp_path, monkeypatch)  # 2026-10-19T01:00:00Z
    _incident(service, clocks)
    _incident(service, clocks)
    assert _refused(lambda: _incident(service, clocks)) == "daily"
    clocks.wall -= 3 * 86400
    service.tick()
    service._today()
    assert service._incidents_by_day == {"2026-10-19": {EXPLAINER.uid: [2, 0]}}
    clocks.wall += 3 * 86400 + 60
    assert _refused(lambda: _incident(service, clocks)) == "daily"
    # Only days before yesterday go.
    clocks.advance(86400)
    service._today()
    assert "2026-10-19" in service._incidents_by_day
    clocks.advance(86400)
    service._today()
    assert service._incidents_by_day == {}


def test_rate_limited_refusals_do_not_reach_the_refusal_file(tmp_path):
    lines = []
    sink = summarized_refusals(lines.append)
    sink({"event_type": "runtime.request_refused", "reason": "rate_limited"})
    sink({"event_type": "runtime.request_refused", "reason": "argument_range"})
    assert [line["reason"] for line in lines] == ["argument_range"]


def test_rate_limited_is_a_declared_refusal_the_explainers_client_carries():
    from azazel_nexus_runtime import mio_socket_client
    assert Refusal.RATE_LIMITED.value == "rate_limited"
    assert "rate_limited" in mio_socket_client._REFUSALS


# -- capacity: a warning, never a deletion --------------------------------


def test_verify_reports_capacity_and_the_tick_warns_without_deleting(tmp_path, monkeypatch):
    warnings = []
    service, clocks = _service(tmp_path, monkeypatch, warnings=warnings)
    for _ in range(3):
        _incident(service, clocks)
    sizes = sum(p.stat().st_size for p in service.ledger.segments())
    reply = service.handle(_request("audit.verify", {}, principal=OPERATOR))
    assert reply["capacity"]["chain_bytes"] == sizes
    assert reply["capacity"]["segments"] == 1
    assert reply["capacity"]["warning"] in (False, True)  # depends on the host's free space
    assert reply["rate_limited"] == {} and reply["rate_limit_summaries_dropped"] == 0
    json.dumps(reply)
    monkeypatch.setattr(auditd, "CAPACITY_WARN_CHAIN_BYTES", sizes)
    before = [p.read_bytes() for p in service.ledger.segments()]
    service.tick()
    service.tick()
    clocks.advance(auditd.CAPACITY_CHECK_S)
    service.tick()
    assert len(warnings) == 1 and f"chain_bytes={sizes}" in warnings[0]
    assert "nothing is deleted" in warnings[0]
    clocks.advance(auditd.CAPACITY_REWARN_S)
    service.tick()
    assert len(warnings) == 2
    assert [p.read_bytes() for p in service.ledger.segments()] == before


def test_capacity_below_threshold_is_quiet(tmp_path, monkeypatch):
    warnings = []
    monkeypatch.setattr(auditd, "CAPACITY_WARN_FREE_BYTES", 0)
    service, _ = _service(tmp_path, monkeypatch, warnings=warnings)
    service.tick()
    assert warnings == []
    assert service.ledger.capacity()["warning"] is False


def test_the_serve_loop_ticks_and_filters_refusals(tmp_path, monkeypatch):
    calls = {}

    def fake_serve(**kwargs):
        calls.update(kwargs)
        return 0

    from azazel_nexus_runtime import runtime_paths, serve
    monkeypatch.setattr(serve, "serve_forever", fake_serve)
    monkeypatch.setattr(runtime_paths, "ledger_dir", lambda: tmp_path)
    # The explainer's listener needs its installed group and leaf (#213 O1).
    monkeypatch.setattr(runtime_paths, "dedicated_listener",
                        lambda name, registry: (tmp_path / f"{name}.sock", 0, registry))
    ticks = []
    monkeypatch.setattr(AuditService, "tick", lambda self: ticks.append(1))
    monkeypatch.setattr(auditd.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=EXPLAINER.uid))
    from azazel_nexus_runtime import principal
    monkeypatch.setattr(principal.PrincipalPolicy, "resolve", classmethod(lambda cls, **_: None))
    recorded = []
    monkeypatch.setattr(runtime_paths, "audit_sink", lambda _: recorded.append)
    assert auditd.main([], ready=lambda: None) == 0
    assert calls["stop"]() is False and ticks == [1]
    calls["audit"]({"reason": "rate_limited"})
    calls["audit"]({"reason": "malformed_frame"})
    assert recorded == [{"reason": "malformed_frame"}]
