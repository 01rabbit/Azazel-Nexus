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
    ARBITER,
    ARBITER_SHARE,
    CALLER_SHARE,
    CALLERS_POOL,
    CONTROL,
    CONTROL_RESERVE,
    EXPLAINER,
    EXPLAINER_SHARE,
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
    verify_archive,
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
    # About 20 MB a day at six advice requests a minute must fit its own share,
    # and the shares never add up to more than one segment.
    assert EXPLAINER_SHARE - REQUEST_HEADROOM > 20 * 1000 * 1000
    assert EXPLAINER_SHARE + ARBITER_SHARE + CALLERS_POOL + CONTROL_RESERVE == SEGMENT_BYTES
    assert SEGMENT_BYTES == 46 * 1024 * 1024  # the documented segment size
    assert CALLER_SHARE < CALLERS_POOL
    assert ARBITER_SHARE >= CALLER_SHARE  # the arbiter loses nothing by leaving the pool
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
    assert boundary["legacy"] == {"state": "legacy_unverified", "sequence": head[0],
                                  "hash": head[1], "size": archive.stat().st_size}
    assert verify_archive(route.directory) == head
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
    size = (state / "route.jsonl").stat().st_size
    (directory / BOUNDARY).write_text(json.dumps(
        {"sequence": head[0], "hash": head[1], "oldest": None, "retired": "route.jsonl",
         "legacy": {"state": "legacy_unverified", "sequence": head[0], "hash": head[1],
                    "size": size}}))
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


SMALL = {"explainer_share": REQUEST_HEADROOM + 16384, "caller_share": REQUEST_HEADROOM + 8192,
         "callers_pool": 2 * REQUEST_HEADROOM + 16384, "reserve": 8192,
         "arbiter_share": REQUEST_HEADROOM + 8192,
         "segment_bytes": 4 * REQUEST_HEADROOM + 49152}


def fill(route, owner):
    route.owner = owner
    with pytest.raises(RouteSegmentFull):
        for _ in range(10_000):
            route.append({"event_type": "a", "pad": "x" * 200})
    route.owner = None


def test_a_spent_share_refuses_only_its_owner(state):
    clock = Clock()
    route = ledger(state, clock, **SMALL)
    fill(route, "uid:1001")
    assert not route.room("uid:1001")
    assert route.room("uid:1002") and route.room(EXPLAINER)
    fill(route, "uid:1002")
    # The callers' pool is spent; the explainer's share is untouched.
    assert not route.room("uid:1003")
    assert route.room(EXPLAINER)
    fill(route, EXPLAINER)
    assert not route.room(EXPLAINER)
    size = route.path.stat().st_size
    route.append({"event_type": "control"}, reserved=True)  # the control reserve is separate
    assert size < route.path.stat().st_size <= SMALL["segment_bytes"]
    route.verify()
    clock.advance(DAY)
    assert route.room("uid:1001") and route.room(EXPLAINER)  # a new day is a new budget


def test_the_arbiter_has_its_own_share_outside_the_callers_pool(state):
    clock = Clock()
    route = ledger(state, clock, **SMALL)
    fill(route, "uid:1001")
    fill(route, "uid:1002")
    assert not route.room("uid:1003")  # the operators have spent the pool
    assert route.room(ARBITER)
    fill(route, ARBITER)
    assert not route.room(ARBITER)
    assert route.room(EXPLAINER)
    assert route.path.stat().st_size <= SMALL["segment_bytes"]


def test_an_empty_segment_left_by_a_crash_still_opens_with_the_carried_reading(state):
    clock = Clock()
    route = ledger(state, clock)
    carried = {"event_type": "mio.capability.carried", "to": "CORE", "reasons": {},
               "observed_at": "x", "occurred_at": "y"}
    route.on_new_segment = lambda: [carried]
    route.append({"event_type": "a"})
    clock.advance(DAY)
    # A crash right after the day's segment was created leaves it empty.
    route.path.touch(mode=0o600)
    route.append({"event_type": "b"})
    events = [item.event["event_type"] for item in AuditLedger(route.path)]
    assert events == ["mio.capability.carried", "b"]
    route.verify()
    route.append({"event_type": "c"})  # a segment with records does not open again
    assert [item.event["event_type"] for item in AuditLedger(route.path)][-1] == "c"
    assert len(list(AuditLedger(route.path))) == 3


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

#: The explainer's and the arbiter's accounts resolve to fixed uids, apart from
#: each other and from the callers the tests name (1001, 1002, ...), whoever
#: runs the tests. Other accounts still resolve to the running user.
ACCOUNT_UIDS = {"azexplain": 4242, "azarbiter": 4343}


def account(name):
    return SimpleNamespace(pw_uid=ACCOUNT_UIDS.get(name, os.getuid()))


def compose(tmp_path, monkeypatch, *, rate=None, **limits):
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(client.pwd, "getpwnam", account)
    monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    runtime_paths.mio_state_dir().mkdir(parents=True, exist_ok=True)
    clock = Clock()
    from azazel_nexus_runtime.mio_router import MioRouter

    router = MioRouter(clock=lambda: datetime.fromtimestamp(clock.now, UTC).isoformat())
    router.ledger = ledger(runtime_paths.mio_state_dir(), clock, days=2, **limits)
    service = entry.MioEntryService(
        router=router, clock=clock.mono, wall_clock=clock.wall,
        rate=rate(clock) if rate else None)
    service.local.observe = lambda **_: "local_unavailable"
    service.remote.observe = lambda **_: "remote_unavailable"
    return service, clock


def restart(svc, clock):
    restarted = entry.MioEntryService(router=svc.router, clock=clock.mono, wall_clock=clock.wall)
    restarted.local.observe = svc.local.observe
    restarted.remote.observe = svc.remote.observe
    return restarted


@pytest.fixture
def service(tmp_path, monkeypatch):
    return compose(tmp_path, monkeypatch)


def unlimited(clock):
    return entry.PrincipalRate(per_minute=10**9, burst=10**9, clock=clock.mono)


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


def test_every_refusal_reason_is_aggregated_per_caller(service):
    svc, clock = service
    refusal = {"event_type": "runtime.request_refused", "request_bytes": 10,
               "request_fingerprint": "x", "uid": 1001}
    for index in range(50):
        reason = ("rate_limited", "malformed_frame", "principal_denied")[index % 3]
        svc.record_refusal({**refusal, "reason": reason})
    svc.record_refusal({**refusal, "reason": "malformed_frame", "uid": 1002})
    clock.advance(entry.REFUSAL_RECORD_INTERVAL_SECONDS)
    svc.record_refusal({**refusal, "reason": "rate_limited"})
    records = [item.event for item in svc.router.ledger
               if item.event["event_type"] == "runtime.request_refused"]
    assert [record["uid"] for record in records] == [1001, 1002, 1001]
    assert records[0]["suppressed"] == {}
    assert records[2]["suppressed"] == {"malformed_frame": 17, "principal_denied": 16,
                                        "rate_limited": 16}
    # Charged to each caller's own share, never to the explainer's or control.
    usage = svc.router.ledger.usage
    assert usage["uid:1001"] > 0 and usage["uid:1002"] > 0
    assert usage[EXPLAINER] == 0


def test_spent_route_budget_is_a_bounded_refusal_and_refusals_never_crash(service, monkeypatch):
    svc, _ = service
    monkeypatch.setattr(svc.router.ledger, "room", lambda key: False)
    with pytest.raises(RequestRefused) as refused:
        svc.handle(route_request(1001))
    assert refused.value.detail == "route_budget"

    def full(event, **kwargs):
        raise RouteSegmentFull("fixture")

    monkeypatch.setattr(svc.router.ledger, "append", full)
    svc.record_refusal({"event_type": "runtime.request_refused", "reason": "malformed_frame"})
    assert svc.refusals_unrecorded == 1


@pytest.mark.parametrize("failure", [RouteSegmentFull, AuditUnavailable])
def test_a_refusal_record_that_fails_keeps_the_suppressed_counts(service, monkeypatch, failure):
    svc, clock = service
    refusal = {"event_type": "runtime.request_refused", "request_bytes": 1,
               "request_fingerprint": "x", "uid": 1001}
    svc.record_refusal({**refusal, "reason": "rate_limited"})
    for _ in range(3):
        svc.record_refusal({**refusal, "reason": "malformed_frame"})
    clock.advance(entry.REFUSAL_RECORD_INTERVAL_SECONDS)
    real = svc.router.ledger.append

    def fail(event, **kwargs):
        raise failure("fixture")

    monkeypatch.setattr(svc.router.ledger, "append", fail)
    if failure is RouteSegmentFull:
        svc.record_refusal({**refusal, "reason": "rate_limited"})
    else:
        with pytest.raises(AuditUnavailable):
            svc.record_refusal({**refusal, "reason": "rate_limited"})
    svc.record_refusal({**refusal, "reason": "principal_denied"})  # suppressed meanwhile
    monkeypatch.setattr(svc.router.ledger, "append", real)
    clock.advance(entry.REFUSAL_RECORD_INTERVAL_SECONDS)
    svc.record_refusal({**refusal, "reason": "rate_limited"})
    records = [item.event for item in svc.router.ledger
               if item.event["event_type"] == "runtime.request_refused"]
    assert len(records) == 2
    assert records[-1]["suppressed"] == {"malformed_frame": 3, "principal_denied": 1}


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


def test_a_flooding_caller_cannot_spend_anothers_room(tmp_path, monkeypatch):
    svc, clock = compose(tmp_path, monkeypatch, rate=unlimited, **SMALL)
    svc._explainer_uid = 4242
    for _ in range(10_000):
        try:
            svc.handle(route_request(1001))
        except RequestRefused as refused:
            assert refused.detail == "route_budget"
            break
    else:
        pytest.fail("the flooding caller was never bounded")
    # Its refusals keep coming; they are charged to it and aggregated.
    for _ in range(500):
        with pytest.raises(RequestRefused):
            svc.handle(route_request(1001))
        svc.record_refusal({"event_type": "runtime.request_refused", "reason": "rate_limited",
                            "request_bytes": 1, "request_fingerprint": "x", "uid": 1001})
        clock.advance(entry.REFUSAL_RECORD_INTERVAL_SECONDS)
        if clock.now - START > DAY / 2:
            break
    svc.handle(route_request(1002))  # another operator still has its own share
    assert svc.router.ledger.room(EXPLAINER)  # and the explainer's share is untouched
    usage = dict(svc.router.ledger.usage)
    # A restart recounts today's shares from today's segment.
    restarted = restart(svc, clock)
    assert dict(restarted.router.ledger.usage) == usage
    assert usage["uid:1001"] <= SMALL["caller_share"]
    assert usage.get(CONTROL, 0) <= SMALL["reserve"]
    with pytest.raises(RequestRefused):
        restarted.handle(route_request(1001))


def test_the_arbiters_route_survives_operators_spending_the_pool(tmp_path, monkeypatch):
    svc, clock = compose(tmp_path, monkeypatch, rate=unlimited, **SMALL)
    svc._explainer_uid, svc._arbiter_uid = 4242, 4343
    svc.handle(route_request(1001))  # opens the day's segment
    fill(svc.router.ledger, "uid:1001")
    fill(svc.router.ledger, "uid:1002")
    with pytest.raises(RequestRefused) as refused:  # the callers' pool is spent
        svc.handle(route_request(1003))
    assert refused.value.detail == "route_budget"
    arbiter = Principal(4343, 4343, 1, frozenset({PrincipalClass.SERVICE}))
    request = SimpleNamespace(arguments={"privacy_class": "P0-public", "deadline_ms": 1000},
                              principal=arbiter)
    assert svc.handle(request)["route"] == "deterministic handoff"
    usage = dict(svc.router.ledger.usage)
    assert 0 < usage[ARBITER] <= SMALL["arbiter_share"]
    # A restart recounts the arbiter's share as its own, not the pool's.
    restarted = restart(svc, clock)
    restarted._arbiter_uid = 4343
    restarted.router.ledger.rebuild_usage(restarted._attribution())
    assert restarted.router.ledger.usage[ARBITER] == usage[ARBITER]


def test_explainer_advice_survives_a_flooding_operator(tmp_path, monkeypatch):
    from test_incident_explain import transition

    from azazel_nexus.incident_explain import build_frame

    svc, _ = compose(tmp_path, monkeypatch, rate=unlimited, **SMALL)
    svc._explainer_uid = 4242
    svc.reference.reference = lambda *a, **kw: (None, "no_pack")
    for _ in range(10_000):
        try:
            svc.handle(route_request(1001))
        except RequestRefused:
            break
    explainer = Principal(4242, 7, 1, frozenset({PrincipalClass.SERVICE}))
    request = SimpleNamespace(verb=entry.ADVISE_VERB, arguments={"deadline_ms": 500},
                              payload=build_frame(transition(), 1), principal=explainer)
    reply = svc.handle(request)
    assert reply["route"] == "deterministic handoff"
    usage = svc.router.ledger.usage
    assert usage[EXPLAINER] > 0 and usage["uid:1001"] <= SMALL["caller_share"]


def flip(svc, monkeypatch):
    """Make the next samples alternate between two capability readings."""
    first = svc._sample()
    second = ({**first[0], "reasons": {**first[0]["reasons"], "health": {
        "local": "local_available", "remote": "remote_unavailable"}}}, first[1])
    readings = {"value": first}
    monkeypatch.setattr(svc, "_sample", lambda *a, **kw: readings["value"])
    return first, second, readings


def last_capability(svc):
    return [item.event for item in svc.router.ledger
            if item.event["event_type"] in entry.CAPABILITY_EVENTS][-1]


@pytest.mark.parametrize("step", ["retain", "fsync", "fsync-unreadable", "not-written"])
def test_a_failure_after_a_capability_record_cannot_refuse_the_next_start(
        service, tmp_path, monkeypatch, step, private_os):
    """#227: whatever the failure, memory follows the ledger's last capability record."""
    from azazel_nexus import audit
    private_os(audit)

    svc, clock = service
    first, second, readings = flip(svc, monkeypatch)
    svc.reconcile_capability()
    clock.advance(entry.CAPABILITY_INTERVAL_SECONDS)
    readings["value"] = second
    failed = []
    real_fsync, real_head = audit.os.fsync, audit.AuditLedger.head
    real_append, real_retain = audit.AuditLedger.append, svc.router.ledger.retain

    def fsync(fd):
        if not failed:
            failed.append("fsync")
            raise OSError("fsync fixture")
        return real_fsync(fd)

    def head(self):
        # The segment cannot be read right after the failed sync.
        if failed == ["fsync"]:
            failed.append("head")
            raise AuditChainBroken("unreadable fixture")
        return real_head(self)

    def append(self, event, **kwargs):
        if not failed and event.get("event_type") == "mio.capability.transition":
            failed.append("append")
            raise AuditUnavailable("nothing written fixture")
        return real_append(self, event, **kwargs)

    def retain():
        if not failed:
            failed.append("retain")
            raise OSError("retain fixture")
        return real_retain()

    if step == "retain":
        monkeypatch.setattr(svc.router.ledger, "retain", retain)
    elif step == "not-written":
        monkeypatch.setattr(audit.AuditLedger, "append", append)
    else:
        monkeypatch.setattr(audit.os, "fsync", fsync)
        if step == "fsync-unreadable":
            monkeypatch.setattr(audit.AuditLedger, "head", head)
    with pytest.raises(AuditUnavailable):
        svc.reconcile_capability()
    assert failed
    last = last_capability(svc)
    landed = step != "not-written"
    assert (last["reasons"] == second[0]["reasons"]) is landed
    if step in {"retain", "fsync"}:
        # Reported by the ledger: memory already follows it.
        assert svc._last_capability == second[0]
        assert svc._observed_at == last["occurred_at"]
        assert not svc._capability_uncertain
    else:
        # Unknown outcome: settled from the ledger before the next comparison.
        assert svc._capability_uncertain
    # The reading flips back. Wherever the ledger ended, the next records agree.
    clock.advance(entry.CAPABILITY_INTERVAL_SECONDS)
    readings["value"] = first
    svc.reconcile_capability()
    assert not svc._capability_uncertain
    assert last_capability(svc)["reasons"] == first[0]["reasons"]
    clock.advance(DAY)
    svc.handle(route_request(1001))
    carried = [item.event for item in svc.router.ledger
               if item.event["event_type"] == "mio.capability.carried"]
    assert carried[-1]["reasons"] == first[0]["reasons"]
    restarted = restart(svc, clock)  # the L4 carried check accepts the history
    assert restarted._last_capability == first[0]
    reading = status_summary(root=tmp_path)
    assert reading["state"] == first[0]["state"]
    assert reading["reasons"] == first[0]["reasons"]
    assert reading["availability"] == "last recorded observation"


def test_a_carried_record_is_never_written_from_an_unsettled_reading(service, monkeypatch):
    svc, clock = service
    svc.reconcile_capability()
    svc._capability_uncertain = True

    def unreadable():
        raise AuditChainBroken("unreadable fixture")

    monkeypatch.setattr(svc, "_settle_capability", unreadable)
    clock.advance(DAY)
    before = svc.router.ledger.head()
    with pytest.raises(AuditChainBroken):
        svc.handle(route_request(1001))
    assert svc.router.ledger.head() == before  # nothing was carried or recorded


def test_a_line_is_reported_only_when_its_hash_matches(state):
    clock = Clock()
    route = ledger(state, clock)
    seen = []
    route.on_written = seen.append
    route.append({"event_type": "a"})
    head = route.head()
    from azazel_nexus import audit

    real = audit.AuditLedger.append

    def foreign(self, event, **kwargs):
        # Another line lands at the expected sequence, then the write fails.
        real(self, {**event, "event_type": "other"}, **kwargs)
        raise AuditUnavailable("fixture")

    audit.AuditLedger.append = foreign
    try:
        with pytest.raises(AuditUnavailable):
            route.append({"event_type": "b"})
    finally:
        audit.AuditLedger.append = real
    assert route.head()[0] == head[0] + 1
    assert [event["event_type"] for event in seen] == ["a"]


def test_carried_reading_keeps_its_original_observation_time(service, tmp_path):
    svc, clock = service
    svc.reconcile_capability()
    first = next(item.event for item in svc.router.ledger
                 if item.event["event_type"] == "mio.capability.transition")
    clock.advance(DAY)
    restarted = restart(svc, clock)
    restarted.handle(route_request(1001))
    carried = [item.event for item in restarted.router.ledger
               if item.event["event_type"] == "mio.capability.carried"]
    assert carried and carried[0]["observed_at"] == first["occurred_at"]
    assert carried[0]["occurred_at"] != first["occurred_at"]
    reading = status_summary(root=tmp_path)
    assert reading["observed_at"] == datetime.fromisoformat(first["occurred_at"]).isoformat()
    # The carried record's own write is entryd's liveness evidence (#358).
    assert reading["recorded_at"] == datetime.fromisoformat(carried[0]["occurred_at"]).isoformat()
    assert reading["recorded_at"] > reading["observed_at"]
    assert restart(restarted, clock)._observed_at == first["occurred_at"]


@pytest.mark.parametrize("field", ["to", "observed_at"])
def test_a_carried_record_that_differs_from_its_reading_is_refused(service, tmp_path, field):
    svc, clock = service
    svc.reconcile_capability()
    clock.advance(DAY)
    value = {"to": "FULL", "observed_at": "2020-01-01T00:00:00+00:00"}[field]
    svc.router.ledger.append({"event_type": "mio.capability.carried",
                              "to": svc._last_capability["state"],
                              "reasons": svc._last_capability["reasons"],
                              "observed_at": svc._observed_at,
                              "occurred_at": "2027-01-16T08:00:00+00:00", field: value},
                             reserved=True)
    with pytest.raises(AuditChainBroken):
        restart(svc, clock)
    assert "unknown" in status_summary(root=tmp_path)["availability"]


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



def test_migration_reads_only_the_legacy_tail(state, monkeypatch):
    legacy = AuditLedger(state / "route.jsonl")
    for index in range(4):
        legacy.append({"event_type": "old", "index": index})
    head = legacy.head()
    # Damage the middle: start-up must not read it, so it must not notice.
    lines = (state / "route.jsonl").read_text().splitlines(keepends=True)
    lines[1] = lines[1].replace('"old"', '"edited"')
    (state / "route.jsonl").write_text("".join(lines))
    monkeypatch.setattr(AuditLedger, "verify", lambda self: pytest.fail("full legacy read"))
    route = ledger(state, Clock())
    route.prepare()
    assert route.append({"event_type": "new"}).previous_hash == head[1]
    monkeypatch.undo()
    # Offline verification finds what start-up deliberately did not read.
    with pytest.raises(AuditChainBroken):
        verify_archive(route.directory)
    route.verify()  # the retained chain itself is intact


def test_boundary_keeps_the_legacy_record_across_retention(state):
    legacy = AuditLedger(state / "route.jsonl")
    legacy.append({"event_type": "old"})
    head = legacy.head()
    clock = Clock()
    route = ledger(state, clock, days=1)
    for _ in range(4):
        route.append({"event_type": "a"})
        clock.advance(DAY)
    route.append({"event_type": "a"})
    boundary = read_boundary(route.directory)
    assert boundary["retired"] != "route.jsonl"
    assert boundary["legacy"]["sequence"] == 1
    assert verify_archive(route.directory) == head
    route.verify()
