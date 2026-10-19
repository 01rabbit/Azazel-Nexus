"""entryd's route ledger: daily segments, one chain, bounded retention (#211 S4)."""

import json
import os
import stat
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import mio_entryd as entry
from azazel_nexus_runtime import mio_socket_client as client
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.mio_route_ledger import (
    CONTROL_RESERVE,
    REQUEST_HEADROOM,
    RETENTION_BYTES,
    RETENTION_DAYS,
    SEGMENT_BYTES,
    RouteLedger,
    RouteSegmentFull,
)
from azazel_nexus_runtime.principal import Principal, PrincipalClass
from azazel_nexus_runtime.protocol import Refusal, RequestRefused

from azazel_nexus.audit import (
    GENESIS_HASH,
    AuditChainBroken,
    AuditLedger,
    AuditUnavailable,
)
from azazel_nexus.mio_status import status_summary
from azazel_nexus.route_ledger import (
    ARCHIVE,
    BOUNDARY,
    ROUTE_DIR,
    RouteChain,
    read_boundary,
)

DAY = 86400
START = 1_800_000_000.0  # 2027-01-15T08:00:00Z


class Clock:
    """Wall and elapsed time that move together, as on a node that stays up."""

    def __init__(self, now=START):
        self.now, self.elapsed = now, 1000.0

    def wall(self):
        return self.now

    def mono(self):
        return self.elapsed

    def advance(self, seconds):
        self.now += seconds
        self.elapsed += seconds


def ledger(state, clock, **limits):
    return RouteLedger(state, clock=clock.wall, monotonic=clock.mono, **limits)


def day(clock):
    return datetime.fromtimestamp(clock.now, UTC).strftime("%Y-%m-%d")


@pytest.fixture
def state(tmp_path):
    path = tmp_path / "mio"
    path.mkdir()
    return path


def test_defaults_are_bounded_and_cover_the_explainer_day():
    # About 20 MB a day at six advice requests a minute must fit one segment.
    assert SEGMENT_BYTES - CONTROL_RESERVE - REQUEST_HEADROOM > 20 * 1000 * 1000
    assert RETENTION_DAYS == 14
    assert RETENTION_BYTES <= 256 * 1024 * 1024


def test_daily_segments_carry_one_chain(state):
    clock = Clock()
    route = ledger(state, clock)
    first = route.append({"event_type": "a"})
    names = [day(clock)]
    clock.advance(DAY)
    second = route.append({"event_type": "b"})
    names.append(day(clock))
    assert [path.name for path in RouteChain(route.directory).segments()] == [
        name + ".jsonl" for name in names]
    assert (second.sequence, second.previous_hash) == (2, first.event_hash)
    assert RouteChain(route.directory).verify() == (2, second.event_hash)
    assert route.head() == (2, second.event_hash)
    # Each segment's first entry continues the previous file's chain.
    raw = (route.directory / (names[1] + ".jsonl")).read_text().splitlines()[0]
    assert json.loads(raw)["previous_hash"] == first.event_hash
    assert stat.S_IMODE((route.directory / (names[0] + ".jsonl")).stat().st_mode) == 0o600
    assert stat.S_IMODE(route.directory.stat().st_mode) == 0o700


def test_a_deleted_or_edited_segment_breaks_the_chain(state):
    clock = Clock()
    route = ledger(state, clock)
    for _ in range(3):
        route.append({"event_type": "a"})
        clock.advance(DAY)
    segments = RouteChain(route.directory).segments()
    segments[1].unlink()
    with pytest.raises(AuditChainBroken):
        RouteChain(route.directory).verify()

    other = state.parent / "other"
    other.mkdir()
    route = ledger(other, Clock())
    route.append({"event_type": "a"})
    path = route.path
    path.write_text(path.read_text().replace('"a"', '"b"'))
    with pytest.raises(AuditChainBroken):
        RouteChain(route.directory).verify()


def test_backwards_clock_never_writes_before_the_head(state):
    clock = Clock()
    route = ledger(state, clock)
    route.append({"event_type": "a"})
    newest = route.path
    clock.now -= 3 * DAY
    route.append({"event_type": "b"})
    assert RouteChain(route.directory).segments() == (newest,)
    RouteChain(route.directory).verify()


def test_retention_by_age_keeps_today_and_moves_the_boundary(state):
    clock = Clock()
    route = ledger(state, clock, days=3)
    for _ in range(8):
        route.append({"event_type": "a"})
        clock.advance(DAY)
    route.append({"event_type": "a"})
    segments = RouteChain(route.directory).segments()
    assert segments[-1].name == day(clock) + ".jsonl"
    assert len(segments) <= 4
    boundary = read_boundary(route.directory)
    assert boundary["oldest"] == segments[0].name
    assert boundary["retired"] < boundary["oldest"]
    assert RouteChain(route.directory).verify()[0] == 9
    # A fresh writer (a restart) verifies only from the boundary.
    restarted = ledger(state, clock, days=3)
    assert restarted.verify() == route.head()


def test_total_cap_never_deletes_the_current_segment(state):
    clock = Clock()
    route = ledger(state, clock, max_bytes=1)
    for _ in range(3):
        route.append({"event_type": "a", "pad": "x" * 512})
        clock.advance(DAY)
    for _ in range(4):
        route.append({"event_type": "today", "pad": "x" * 512})
    segments = RouteChain(route.directory).segments()
    assert segments == (route.path,)
    assert segments[0].name == day(clock) + ".jsonl"
    assert RouteChain(route.directory).verify()[0] == 7


def test_crash_between_boundary_and_unlink_completes_on_start(state):
    clock = Clock()
    route = ledger(state, clock)
    route.append({"event_type": "a"})
    clock.advance(DAY)
    route.append({"event_type": "b"})
    oldest = RouteChain(route.directory).segments()[0]
    route.before_delete(oldest)  # the boundary is durable; the unlink never ran
    assert oldest.exists()
    # Readers already treat the retired segment as outside the chain.
    assert RouteChain(route.directory).verify()[0] == 2
    restarted = ledger(state, clock)
    restarted.prepare()
    assert not oldest.exists()
    assert restarted.verify()[0] == 2
    # Removing the boundary now leaves a chain that does not start at genesis.
    (route.directory / BOUNDARY).unlink()
    with pytest.raises(AuditChainBroken):
        RouteChain(route.directory).verify()


def test_boundary_must_name_the_oldest_retained_segment(state):
    clock = Clock()
    route = ledger(state, clock, days=1)
    for _ in range(4):
        route.append({"event_type": "a"})
        clock.advance(DAY)
    route.append({"event_type": "a"})
    segments = RouteChain(route.directory).segments()
    assert len(segments) >= 2
    segments[0].unlink()
    with pytest.raises(AuditChainBroken):
        RouteChain(route.directory).verify()


def test_start_verifies_only_retained_segments(state, monkeypatch):
    clock = Clock()
    legacy = AuditLedger(state / "route.jsonl")
    for _ in range(5):
        legacy.append({"event_type": "old"})
    route = ledger(state, clock, days=2)
    for _ in range(6):
        route.append({"event_type": "a"})
        clock.advance(DAY)
    read = []
    original = AuditLedger.__iter__

    def iterate(self):
        read.append(self.path.name)
        return original(self)

    monkeypatch.setattr(AuditLedger, "__iter__", iterate)
    visited = []
    ledger(state, clock, days=2).verify(visited.append)
    retained = {path.name for path in RouteChain(route.directory).segments()}
    assert set(read) == retained
    assert ARCHIVE not in read
    assert len(visited) == sum(1 for name in retained
                               for _ in original(AuditLedger(route.directory / name)))


def test_migration_archives_legacy_and_continues_its_chain(state):
    legacy = AuditLedger(state / "route.jsonl")
    for index in range(3):
        legacy.append({"event_type": "old", "index": index})
    head = legacy.head()
    route = ledger(state, Clock())
    route.prepare()
    archive = route.directory / ARCHIVE
    assert not (state / "route.jsonl").exists()
    assert stat.S_IMODE(archive.stat().st_mode) == 0o400
    AuditLedger(archive).verify()  # still a genesis-rooted chain on its own
    assert AuditLedger(archive).head() == head
    boundary = read_boundary(route.directory)
    assert (boundary["sequence"], boundary["hash"]) == head
    assert boundary["oldest"] is None and boundary["retired"] == "route.jsonl"
    entry_ = route.append({"event_type": "new"})
    assert (entry_.sequence, entry_.previous_hash) == (head[0] + 1, head[1])
    assert route.verify() == (entry_.sequence, entry_.event_hash)
    assert [item.event["event_type"] for item in route] == ["new"]


def test_migration_finishes_after_a_crash_before_the_rename(state):
    legacy = AuditLedger(state / "route.jsonl")
    legacy.append({"event_type": "old"})
    head = legacy.head()
    directory = state / "route"
    directory.mkdir()
    (directory / BOUNDARY).write_text(json.dumps(
        {"sequence": head[0], "hash": head[1], "oldest": None, "retired": "route.jsonl"}))
    route = ledger(state, Clock())
    route.prepare()
    assert (directory / ARCHIVE).exists() and not (state / "route.jsonl").exists()
    assert route.append({"event_type": "new"}).sequence == 2


def test_broken_or_conflicting_legacy_is_refused_without_moving_it(state):
    path = state / "route.jsonl"
    path.write_text("not a ledger\n")
    with pytest.raises(AuditChainBroken):
        ledger(state, Clock()).prepare()
    assert path.exists() and not (state / "route" / ARCHIVE).exists()

    path.unlink()
    route = ledger(state, Clock())
    route.append({"event_type": "new"})
    AuditLedger(path).append({"event_type": "restored old file"})
    with pytest.raises(AuditChainBroken):
        ledger(state, Clock()).prepare()
    assert path.exists()


def test_empty_legacy_migrates_to_a_genesis_boundary(state):
    (state / "route.jsonl").touch()
    route = ledger(state, Clock())
    assert route.append({"event_type": "new"}).previous_hash == GENESIS_HASH
    assert route.verify()[0] == 1


def test_full_segment_refuses_ordinary_records_and_keeps_the_reserve(state):
    clock = Clock()
    route = ledger(state, clock, segment_bytes=REQUEST_HEADROOM + 8192, reserve=4096)
    assert route.room()
    with pytest.raises(RouteSegmentFull):
        for _ in range(1000):
            route.append({"event_type": "a", "pad": "x" * 200})
    assert not route.room()
    size = route.path.stat().st_size
    route.append({"event_type": "control"}, reserved=True)
    assert route.path.stat().st_size > size
    assert route.path.stat().st_size <= REQUEST_HEADROOM + 8192
    route.verify()
    clock.advance(DAY)
    assert route.room()  # a new day is a new budget


def test_absent_state_directory_is_read_as_empty_and_not_created(tmp_path):
    state = tmp_path / "missing"
    route = ledger(state, Clock())
    assert route.verify() == (0, GENESIS_HASH)
    assert list(route) == []
    assert not state.exists()
    with pytest.raises(AuditUnavailable):
        route.prepare()
    assert not state.exists()


# -- entryd ---------------------------------------------------------------


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    runtime_paths.mio_state_dir().mkdir(parents=True)
    clock = Clock()
    from azazel_nexus_runtime.mio_router import MioRouter

    router = MioRouter(clock=lambda: datetime.fromtimestamp(clock.now, UTC).isoformat())
    router.ledger = ledger(runtime_paths.mio_state_dir(), clock, days=2)
    service = entry.MioEntryService(router=router, clock=clock.mono, wall_clock=clock.wall)
    service.local.observe = lambda: "local_unavailable"
    service.remote.observe = lambda: "remote_unavailable"
    return service, clock


def route_request(uid=None):
    principal = None if uid is None else Principal(uid, uid, 1, frozenset({PrincipalClass.OPERATOR}))
    return SimpleNamespace(arguments={"privacy_class": "P0-public", "deadline_ms": 1000},
                           principal=principal)


def test_rate_limit_is_per_principal_and_refills(service):
    svc, clock = service
    for _ in range(entry.RATE_BURST):
        svc.handle(route_request(1001))
    with pytest.raises(RequestRefused) as refused:
        svc.handle(route_request(1001))
    assert refused.value.refusal is Refusal.RATE_LIMITED
    before = svc.router.ledger.head()
    with pytest.raises(RequestRefused):
        svc.handle(route_request(1001))
    assert svc.router.ledger.head() == before  # a refused request writes nothing itself
    svc.handle(route_request(1002))  # another caller has its own bucket
    clock.advance(60 / entry.RATE_PER_MINUTE)
    svc.handle(route_request(1001))
    assert svc.rate_limited["principal_rate"] == 2


def test_sustained_rate_is_above_the_explainers_six_a_minute(service):
    svc, clock = service
    for _ in range(3 * entry.RATE_PER_MINUTE):
        svc.handle(route_request(1003))
        clock.advance(60 / entry.RATE_PER_MINUTE)
    assert not svc.rate_limited


def test_rate_limited_refusal_records_are_aggregated(service):
    svc, clock = service
    refusal = {"event_type": "runtime.request_refused", "reason": "rate_limited",
               "request_bytes": 10, "request_fingerprint": "x", "uid": 1001}
    for _ in range(50):
        svc.record_refusal(dict(refusal))
    clock.advance(entry.REFUSAL_RECORD_INTERVAL_SECONDS)
    svc.record_refusal(dict(refusal))
    records = [item.event for item in svc.router.ledger
               if item.event["event_type"] == "runtime.request_refused"]
    assert len(records) == 2
    assert records[0]["suppressed"] == 0 and records[1]["suppressed"] == 49


def test_spent_route_budget_is_a_bounded_refusal_and_refusals_never_crash(service, monkeypatch):
    svc, _ = service
    monkeypatch.setattr(svc.router.ledger, "room", lambda: False)
    with pytest.raises(RequestRefused) as refused:
        svc.handle(route_request(1001))
    assert refused.value.detail == "route_budget"

    def full(event, **kwargs):
        raise RouteSegmentFull("fixture")

    monkeypatch.setattr(svc.router.ledger, "append", full)
    svc.record_refusal({"event_type": "runtime.request_refused", "reason": "malformed_frame"})
    assert svc.refusals_unrecorded == 1


def test_each_new_segment_opens_with_the_capability_and_status_survives_retention(service, tmp_path):
    svc, clock = service
    svc.reconcile_capability()
    for _ in range(5):
        clock.advance(DAY)
        svc.handle(route_request(1001))
    chain = RouteChain(svc.router.ledger.directory)
    segments = chain.segments()
    assert len(segments) <= 3
    for segment in segments:
        assert next(iter(AuditLedger(segment))).event["event_type"] in {
            "mio.capability.carried", "mio.capability.transition"}
    assert not any(item.event["event_type"] == "mio.capability.transition" for item in chain)
    reading = status_summary(root=tmp_path)
    assert reading["state"] == "CORE"
    assert reading["availability"] == "last recorded observation"
    # A restart restores the carried reading rather than recording a transition.
    restarted = entry.MioEntryService(router=svc.router, clock=clock.mono, wall_clock=clock.wall)
    assert restarted._last_capability == svc._last_capability


def test_status_reads_segments_written_through_the_runtime(tmp_path):
    state = tmp_path / ROUTE_DIR.lstrip("/")
    state.parent.mkdir(parents=True)
    clock = Clock()
    route = ledger(state.parent, clock)
    route.append({"event_type": "mio.capability.transition", "to": "CORE",
                  "occurred_at": "2026-10-19T00:00:00Z",
                  "reasons": {"profile": "LITE", "resource": "core_reserve_unmeasured",
                              "trust": "not-checked", "topology": "no_verified_egress",
                              "health": {"local": "unavailable", "remote": "not_admitted"}}})
    clock.advance(DAY)
    route.append({"event_type": "mio.route"})
    assert status_summary(root=tmp_path)["ceiling"] == "LITE"
    route.path.write_text(route.path.read_text().replace("mio.route", "mio.tampered"))
    assert "unknown" in status_summary(root=tmp_path)["availability"]


def test_explainer_degrades_on_a_rate_limited_entry(tmp_path):
    from azazel_nexus_runtime import incident_explaind as daemon
    from test_incident_explaind import append, make, records

    def refused(_frame):
        raise client.ServiceRefused("rate_limited")

    assert "rate_limited" in client._REFUSALS
    explainer = make(tmp_path)
    explainer.mio = refused
    append(explainer)
    explainer.poll()
    [record] = records(explainer)
    assert record["mio"]["route"] == "unavailable"
    assert "mio_unavailable" in record["failure_codes"]
    assert not explainer.storage_failed and not explainer.chain_broken
    assert explainer.mio_available is False
    # Not a latch: the next explanation asks again and can succeed.
    from test_incident_explain import transition
    explainer.mio = lambda _frame: {"route": "deterministic handoff", "outcome": "answered",
                                    "reason": "no admitted model", "ledger_seq": 1,
                                    "reference_status": "unavailable"}
    append(explainer, transition(incident_id="inc-2222222222222222"))
    explainer.poll()
    assert explainer.mio_available is True
    assert daemon.Explainer is type(explainer)

