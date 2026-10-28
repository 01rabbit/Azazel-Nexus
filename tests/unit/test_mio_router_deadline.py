"""One deadline per request, and a deterministic end when no AI answers.

Every boundary here runs on an injected monotonic clock: a provider "takes"
time by advancing it, so each case is reproducible and nothing sleeps. The
route chain is the real persisted, verified one.
"""

from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import mio_router, runtime_paths

from azazel_nexus.mio_profile import MioProfile
from azazel_nexus.remote_trust import Exclusion, RemoteAdmission
from azazel_nexus.route_evidence import Prediction
from azazel_nexus.route_ledger import RouteChain
from azazel_nexus.route_selection import RequestOutcome, TerminalEvent
from azazel_nexus.routing import Route
from azazel_nexus.sanitizer import PrivacyClass

INFER = SimpleNamespace(name="mio.local.infer")
#: A binary-exact start, so millisecond arithmetic is exact in the asserts.
START = 1024.0


class Clock:
    def __init__(self, now=START):
        self.now = now

    def __call__(self):
        return self.now


class Provider:
    """A provider that spends `cost` seconds and then gives `reply`."""

    def __init__(self, clock, name, reply, cost=0.0):
        self.clock, self.name, self.reply, self.cost = clock, name, reply, cost
        self.calls, self.deadlines = [], []

    def handle(self, request, audit=None, deadline_ms=None):
        self.calls.append(request)
        self.deadlines.append(deadline_ms)
        self.clock.now += self.cost
        return dict(self.reply)


class BlockingRemote(Provider):
    """A remote that never answers on its own: it blocks until the timeout it
    was given (as a socket timeout would), then reports the time-out."""

    def handle(self, request, audit=None, deadline_ms=None):
        self.calls.append(request)
        self.deadlines.append(deadline_ms)
        assert deadline_ms is not None, "a remote attempt without a deadline could block forever"
        self.clock.now += deadline_ms / 1000
        return {"outcome": "timed_out", "refusal": None}


def router(tmp_path, monkeypatch, clock, *, remote, local):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    return mio_router.MioRouter(remote=remote, local=local,
                                clock=lambda: "2026-10-28T00:00:00Z", monotonic=clock)


def local_request(deadline_ms):
    return SimpleNamespace(verb=INFER, arguments={"deadline_ms": deadline_ms}, payload={})


def invoke(target, *, deadline_ms=1000, remote_permitted=True, local_first=False,
           deadline_at=None, request_deadline=None, **extra):
    return target.handle(
        local_request=local_request(request_deadline or deadline_ms),
        remote_request=SimpleNamespace(arguments={}),
        profile=MioProfile.FASTEST_PERMITTED,
        privacy_class=PrivacyClass.P1_SANITIZED if remote_permitted else PrivacyClass.P3_RESTRICTED,
        remote=(RemoteAdmission(True, None, "fixture permitted") if remote_permitted else
                RemoteAdmission(False, Exclusion.PRIVACY_CLASS, "fixture privacy class")),
        local_admitted=True,
        local_refusal="fixture local admitted",
        predictions={
            route: Prediction(route.value, True, ms, 10, 10, False, "fixture observations")
            for route, ms in [(Route.LOCAL, 1 if local_first else 20), (Route.REMOTE, 10)]
        },
        deadline_ms=deadline_ms,
        deadline_at=deadline_at,
        **extra,
    )


def events(target):
    chain = RouteChain(target.ledger.directory)
    chain.verify()
    return [item.event for item in chain]


TIMED_OUT = {"outcome": "timed_out", "refusal": None}
FAILED = {"outcome": "failed", "refusal": "local_unavailable"}
ADVISORY = {"outcome": "advisory", "refusal": None}


def test_the_fallback_gets_what_is_left_not_a_fresh_budget(tmp_path, monkeypatch):
    clock = Clock()
    remote = Provider(clock, "remote", TIMED_OUT, cost=0.5)
    local = Provider(clock, "local", FAILED, cost=0.1)
    target = router(tmp_path, monkeypatch, clock, remote=remote, local=local)
    result = invoke(target, deadline_ms=1000)
    assert len(remote.calls) == 1 and len(local.calls) == 1
    # 1000 ms deadline, 500 ms spent by the first attempt: 500 ms are left,
    # less the handoff reserve. Not the caller's original 1000 ms.
    assert local.calls[0].arguments["deadline_ms"] == 500 - mio_router.HANDOFF_RESERVE_MS
    assert result.route is Route.DETERMINISTIC_HANDOFF


def test_the_first_attempt_already_takes_the_reserve_out(tmp_path, monkeypatch):
    clock = Clock()
    local = Provider(clock, "local", ADVISORY, cost=0.0)
    target = router(tmp_path, monkeypatch, clock, remote=Provider(clock, "r", TIMED_OUT), local=local)
    result = invoke(target, deadline_ms=1000, local_first=True)
    assert result.outcome is RequestOutcome.ANSWERED and result.route is Route.LOCAL
    assert local.calls[0].arguments["deadline_ms"] == 1000 - mio_router.HANDOFF_RESERVE_MS


def test_an_entry_deadline_measured_earlier_is_the_one_used(tmp_path, monkeypatch):
    clock = Clock()
    local = Provider(clock, "local", ADVISORY)
    target = router(tmp_path, monkeypatch, clock, remote=Provider(clock, "r", TIMED_OUT), local=local)
    # The entry started measuring 250 ms ago; the router does not restart it.
    invoke(target, deadline_ms=1000, local_first=True, deadline_at=START + 0.75)
    assert local.calls[0].arguments["deadline_ms"] == 750 - mio_router.HANDOFF_RESERVE_MS
    selected = next(e for e in events(target) if e["event_type"] == "mio.route.selected")
    local_reading = next(c for c in selected["candidates"] if c["candidate"] == "local")
    assert "750 ms deadline" in local_reading["reason"]


@pytest.mark.parametrize("spent_ms,starts", [
    # Exactly the reserve plus the minimum attempt left: the fallback starts.
    (1000 - mio_router.HANDOFF_RESERVE_MS - mio_router.MIN_AI_ATTEMPT_MS, True),
    # One millisecond less: it does not.
    (1000 - mio_router.HANDOFF_RESERVE_MS - mio_router.MIN_AI_ATTEMPT_MS + 1, False),
    (1000, False),
    (1500, False),
])
def test_no_fallback_starts_without_room_for_one(tmp_path, monkeypatch, spent_ms, starts):
    clock = Clock()
    remote = Provider(clock, "remote", TIMED_OUT, cost=spent_ms / 1000)
    local = Provider(clock, "local", FAILED)
    target = router(tmp_path, monkeypatch, clock, remote=remote, local=local)
    result = invoke(target, deadline_ms=1000)
    assert len(local.calls) == (1 if starts else 0)
    recorded = events(target)
    not_started = [e for e in recorded if e["event_type"] == "mio.route.not_started"]
    assert bool(not_started) is not starts
    if not starts:
        assert not_started[0]["route"] == "local"
        assert not_started[0]["reason"] == "deadline_budget_insufficient"
    assert result.route is Route.DETERMINISTIC_HANDOFF
    assert recorded[-1]["route"] == Route.DETERMINISTIC_HANDOFF.value


def test_no_attempt_at_all_when_the_deadline_has_passed(tmp_path, monkeypatch):
    clock = Clock()
    remote = Provider(clock, "remote", ADVISORY)
    local = Provider(clock, "local", ADVISORY)
    target = router(tmp_path, monkeypatch, clock, remote=remote, local=local)
    result = invoke(target, deadline_ms=1000, deadline_at=START)
    assert remote.calls == [] and local.calls == []
    assert result.route is Route.DETERMINISTIC_HANDOFF and result.ai_attempts == 0
    # With no time left, selection itself finds nothing predictable inside it.
    assert result.selection.route is Route.DETERMINISTIC_HANDOFF
    handoff = next(e for e in events(target) if e["event_type"] == "mio.route.handoff")
    assert handoff["ai_attempts"] == 0 and handoff["failures"] == []


@pytest.mark.parametrize("cost", [1.0, 1.2])
def test_an_answer_at_or_after_the_deadline_is_never_success(tmp_path, monkeypatch, cost):
    clock = Clock()
    remote = Provider(clock, "remote", {**ADVISORY, "response_digest": "sha256:" + "0" * 64},
                      cost=cost)
    local = Provider(clock, "local", ADVISORY)
    target = router(tmp_path, monkeypatch, clock, remote=remote, local=local)
    result = invoke(target, deadline_ms=1000)
    assert result.outcome is not RequestOutcome.ANSWERED
    assert result.route is Route.DETERMINISTIC_HANDOFF
    # No time is left, so the permitted fallback does not start either.
    assert local.calls == []
    recorded = events(target)
    late = [e for e in recorded if e["event_type"] == "mio.route.late_reply"]
    assert late == [{"event_type": "mio.route.late_reply", "route": "remote",
                     "discarded": True, "occurred_at": "2026-10-28T00:00:00Z"}]
    terminal = next(e for e in recorded if e["event_type"] == "mio.route.terminal"
                    and e["route"] == "remote")
    assert terminal["terminal_event"] == TerminalEvent.TIMED_OUT.value
    assert not any(e.get("outcome") == "answered" for e in recorded)


def test_an_answer_just_inside_the_deadline_is_accepted(tmp_path, monkeypatch):
    clock = Clock()
    remote = Provider(clock, "remote", {**ADVISORY, "response_digest": "sha256:" + "0" * 64},
                      cost=0.999)
    target = router(tmp_path, monkeypatch, clock, remote=remote, local=Provider(clock, "l", FAILED))
    assert invoke(target, deadline_ms=1000).outcome is RequestOutcome.ANSWERED


def test_both_ai_paths_fail_then_the_deterministic_step_runs(tmp_path, monkeypatch):
    clock = Clock()
    remote = Provider(clock, "remote", TIMED_OUT, cost=0.1)
    local = Provider(clock, "local", FAILED, cost=0.1)
    target = router(tmp_path, monkeypatch, clock, remote=remote, local=local)
    result = invoke(target, deadline_ms=5000)
    # At most two AI attempts, one per provider; no retry to either.
    assert len(remote.calls) == 1 and len(local.calls) == 1
    assert result.ai_attempts == 2
    assert result.route is Route.DETERMINISTIC_HANDOFF
    assert result.outcome is RequestOutcome.REFUSED
    assert result.failures == (
        {"route": "remote", "terminal_event": "timed out"},
        {"route": "local", "terminal_event": "failed", "refusal": "local_unavailable"},
    )
    recorded = events(target)
    handoff = next(e for e in recorded if e["event_type"] == "mio.route.handoff")
    assert handoff["cause"] == "ai_attempts_exhausted"
    assert handoff["ai_attempts"] == 2
    assert handoff["failures"] == [dict(f) for f in result.failures]
    assert recorded[-1]["event_type"] == "mio.route.terminal"
    assert recorded[-1]["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert [e["event_type"] for e in recorded].count("mio.route.fallback") == 1


def test_the_handoff_follows_a_local_first_double_failure_too(tmp_path, monkeypatch):
    clock = Clock()
    remote = Provider(clock, "remote", {"outcome": "tls_failed", "refusal": None})
    local = Provider(clock, "local", {"outcome": "timed_out", "refusal": "deadline"})
    target = router(tmp_path, monkeypatch, clock, remote=remote, local=local)
    result = invoke(target, deadline_ms=5000, local_first=True)
    assert len(local.calls) == 1 and len(remote.calls) == 1
    assert [f["route"] for f in result.failures] == ["local", "remote"]
    assert result.route is Route.DETERMINISTIC_HANDOFF


def test_a_failure_never_falls_back_to_an_unpermitted_route(tmp_path, monkeypatch):
    clock = Clock()
    remote = Provider(clock, "remote", ADVISORY)
    local = Provider(clock, "local", FAILED)
    target = router(tmp_path, monkeypatch, clock, remote=remote, local=local)
    result = invoke(target, deadline_ms=5000, remote_permitted=False)
    assert remote.calls == []
    assert len(local.calls) == 1 and result.ai_attempts == 1
    assert result.route is Route.DETERMINISTIC_HANDOFF
    handoff = next(e for e in events(target) if e["event_type"] == "mio.route.handoff")
    assert handoff["cause"] == "no_permitted_fallback"


def test_a_sanitiser_refusal_ends_the_ai_path_without_another_provider(tmp_path, monkeypatch):
    clock = Clock()
    remote = Provider(clock, "remote", {"outcome": "not_sent", "refusal": "malformed_payload"})
    local = Provider(clock, "local", ADVISORY)
    target = router(tmp_path, monkeypatch, clock, remote=remote, local=local)
    result = invoke(target, deadline_ms=5000)
    assert local.calls == []
    assert result.route is Route.DETERMINISTIC_HANDOFF and result.ai_attempts == 1
    assert result.failures[0]["terminal_event"] == TerminalEvent.SANITIZER_FAILED.value


def test_the_terminal_step_calls_no_provider(tmp_path, monkeypatch):
    clock = Clock()
    remote = Provider(clock, "remote", TIMED_OUT)
    local = Provider(clock, "local", FAILED)
    target = router(tmp_path, monkeypatch, clock, remote=remote, local=local)
    calls_before = []

    def handoff(*args, **kwargs):
        calls_before.append((len(remote.calls), len(local.calls)))
        remote.handle = local.handle = lambda *a, **kw: pytest.fail("AI after the handoff")
        return original(*args, **kwargs)

    original = target._handoff
    monkeypatch.setattr(target, "_handoff", handoff)
    result = invoke(target, deadline_ms=5000)
    assert calls_before == [(1, 1)]
    assert result.route is Route.DETERMINISTIC_HANDOFF


def test_the_router_and_entry_import_no_edge_module():
    """Edge detection, decision and evidence are not inputs of this path."""
    import ast
    import re
    from pathlib import Path

    from azazel_nexus_runtime import mio_entryd, mio_referenced

    for module in (mio_router, mio_entryd, mio_referenced):
        tree = ast.parse(Path(module.__file__).read_text())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                names.add(node.module or "")
            elif isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
        edge = {name for name in names if re.search(r"(^|\.)edge", name)}
        assert not edge, (module.__name__, edge)


def test_a_blocking_remote_is_bounded_by_the_one_deadline(tmp_path, monkeypatch):
    clock = Clock()
    remote = BlockingRemote(clock, "remote", None)
    local = Provider(clock, "local", FAILED, cost=0.0)
    target = router(tmp_path, monkeypatch, clock, remote=remote, local=local)
    result = invoke(target, deadline_ms=1000)
    # The remote got the attempt's share, not an unbounded call.
    assert remote.deadlines == [1000 - mio_router.HANDOFF_RESERVE_MS]
    # It blocked for all of it, so no fallback had room to start ...
    assert local.calls == []
    # ... and the request still ends in the handoff with the reserve intact.
    assert clock.now <= START + 1.0 - mio_router.HANDOFF_RESERVE_MS / 1000
    assert result.route is Route.DETERMINISTIC_HANDOFF
    assert result.failures[0] == {"route": "remote", "terminal_event": "timed out"}


def test_the_remote_service_hands_the_deadline_to_its_transport():
    from test_mio_remoted import FRAME, Request, _seal, _service

    seen = []

    def transport(**kwargs):
        seen.append(kwargs.get("deadline_s"))
        from azazel_nexus_runtime.inference_egress import EgressReport, TransportOutcome
        return EgressReport(TransportOutcome.TIMED_OUT, 0, None, "fixture timeout"), b""

    frame = FRAME
    reply = _service(transport=transport).handle(
        Request(frame=frame, envelope=_seal(frame=frame)), deadline_ms=250)
    assert seen == [0.25]
    assert reply["outcome"] == "timed_out"
    nothing = _service(transport=lambda **kw: pytest.fail("sent with no time left")).handle(
        Request(frame=frame, envelope=_seal(frame=frame)), deadline_ms=0)
    assert nothing["outcome"] == "not_sent" and nothing["refusal"] == "deadline"


def test_remote_recheck_time_comes_out_of_the_same_deadline(tmp_path, monkeypatch):
    clock = Clock()
    remote = Provider(clock, "remote", ADVISORY)
    target = router(tmp_path, monkeypatch, clock, remote=remote,
                    local=Provider(clock, "local", FAILED))

    def slow_recheck():
        clock.now += 0.3
        return RemoteAdmission(True, None, "fixture permitted")

    result = invoke(target, deadline_ms=1000, remote_recheck=slow_recheck)
    assert result.route is Route.REMOTE
    # The recheck took 300 ms of the one deadline; the attempt gets what is left.
    assert remote.deadlines == [1000 - 300 - mio_router.HANDOFF_RESERVE_MS]


def test_a_recheck_that_spends_the_budget_starts_no_attempt(tmp_path, monkeypatch):
    clock = Clock()
    remote = Provider(clock, "remote", ADVISORY)
    local = Provider(clock, "local", ADVISORY)
    target = router(tmp_path, monkeypatch, clock, remote=remote, local=local)

    def slow_recheck():
        clock.now += 0.75
        return RemoteAdmission(True, None, "fixture permitted")

    result = invoke(target, deadline_ms=1000, remote_recheck=slow_recheck)
    assert remote.calls == [] and local.calls == []
    assert result.route is Route.DETERMINISTIC_HANDOFF and result.ai_attempts == 0
    handoff = next(e for e in events(target) if e["event_type"] == "mio.route.handoff")
    assert handoff["cause"] == "deadline_budget_insufficient"


def test_withdrawal_fallback_to_local_gets_what_is_left(tmp_path, monkeypatch):
    clock = Clock()
    remote = Provider(clock, "remote", ADVISORY)
    local = Provider(clock, "local", ADVISORY)
    target = router(tmp_path, monkeypatch, clock, remote=remote, local=local)

    def withdrawn():
        clock.now += 0.1
        return RemoteAdmission(False, Exclusion.CONSENT, "fixture consent withdrawn")

    result = invoke(target, deadline_ms=1000, remote_recheck=withdrawn)
    assert remote.calls == []
    assert result.route is Route.LOCAL and result.outcome is RequestOutcome.ANSWERED
    assert local.calls[0].arguments["deadline_ms"] == 1000 - 100 - mio_router.HANDOFF_RESERVE_MS
    assert mio_router.MAX_AI_ATTEMPTS == 2
