"""Entry composition, actual Unix framing, and fail-closed route evidence."""

import ast
import errno
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import mio_entryd as entry
from azazel_nexus_runtime import mio_socket_client as client
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.principal import Principal, PrincipalClass
from azazel_nexus_runtime.protocol import ArgumentKind, RequestRefused

from azazel_nexus.audit import AuditUnavailable
from azazel_nexus.mio_profile import MioProfile
from azazel_nexus.route_ledger import RouteChain
from azazel_nexus.routing import Route
from azazel_nexus.sanitizer import PrivacyClass


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    runtime_paths.mio_state_dir().mkdir(parents=True)
    return entry.MioEntryService()


def request(privacy=PrivacyClass.P0_PUBLIC, deadline=1000):
    return SimpleNamespace(arguments={"privacy_class": privacy.value, "deadline_ms": deadline})


def recorded(service):
    ledger = RouteChain(service.router.ledger.directory)
    ledger.verify()
    return [item.event for item in ledger]


def test_absent_services_record_handoff_and_reasons(service):
    reply = service.handle(request())
    events = recorded(service)
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert reply["outcome"] != "answered"
    assert reply["reason"]
    assert reply["ledger_seq"] == len(events)
    availability = next(e for e in events if e["event_type"] == "mio.entry.availability")
    assert availability["local"] == "local_unavailable"
    assert availability["remote"] == "remote_unavailable"
    assert "HG-05" in availability["local_refusal"]
    decision = next(event for event in events if event["event_type"] == "mio.route.selected")
    assert decision["profile"] == MioProfile.CORE.value
    assert all(candidate["reason"] for candidate in decision["candidates"])


@pytest.mark.parametrize("profile", [MioProfile.LOCAL_ONLY, MioProfile.FASTEST_PERMITTED])
def test_confirmed_profile_reader_is_used_without_admitting_a_provider(service, profile):
    service._profile_reader = lambda: profile
    assert service._local_admitted() is False
    service.handle(request())
    decision = next(e for e in recorded(service) if e["event_type"] == "mio.route.selected")
    assert decision["profile"] == profile.value
    assert decision["route"] == Route.DETERMINISTIC_HANDOFF.value


@pytest.mark.parametrize("failure", [FileNotFoundError(), ConnectionRefusedError(),
                                       TimeoutError(), ValueError("refused")])
def test_client_failures_are_unavailable(monkeypatch, failure):
    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(client, "_exchange", fail)
    assert client.LocalSocketClient().handle(None)["reason"] == "local_unavailable"
    assert client.RemoteSocketClient().handle(None)["outcome"] == "unavailable"


def test_fixed_probe_never_supplies_payload_or_accepts_response_text(monkeypatch):
    calls = []

    def exchange(*args, **kwargs):
        calls.append((args, kwargs))
        return {"readiness": "refused", "reason": "PROMPT_SENTINEL"}

    monkeypatch.setattr(client, "_exchange", exchange)
    assert client.LocalSocketClient().observe() == "local_not_admitted"
    # A bounded probe: never longer than PROBE_MAX_S, and no payload.
    assert calls == [(("mio", "azmio", "model.activate", {
        "model_id": "uncommissioned", "runtime_id": "uncommissioned",
    }), {"deadline_s": client.PROBE_MAX_S})]


def test_metadata_vocabulary_and_principals():
    assert [arg.kind for arg in entry.ROUTE_VERB.arguments] == [
        ArgumentKind.ENUM, ArgumentKind.ORDINAL,
    ]
    assert not entry.ROUTE_VERB.accepts_payload
    assert entry.ROUTE_VERB.admits == {PrincipalClass.OPERATOR, PrincipalClass.SERVICE}
    for kind in entry.ROUTE_VERB.admits:
        principal = Principal(1000, 1000, 1, frozenset({kind}))
        assert entry.REGISTRY.resolve("mio.route", principal) == entry.ROUTE_VERB
    with pytest.raises(RequestRefused):
        entry.ROUTE_VERB.bind({**request().arguments, "prompt": "PROMPT_SENTINEL"})


def test_zero_deadline_refused_before_ledger(service):
    with pytest.raises(RequestRefused):
        service.handle(request(deadline=0))
    assert recorded(service) == []


def test_main_rejects_arguments_before_composition(monkeypatch):
    monkeypatch.setattr(entry, "MioEntryService", lambda: pytest.fail("composed"))
    with pytest.raises(SystemExit, match="takes no arguments"):
        entry.main(["--prompt"])
    monkeypatch.setattr(entry.sys, "argv", ["az-mio-entryd", "extra"])
    with pytest.raises(SystemExit, match="takes no arguments"):
        entry.main()


def test_main_missing_leaf_does_not_bind(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(entry, "serve_forever", lambda **kw: pytest.fail("bound"))
    with pytest.raises(AuditUnavailable):
        entry.main([])
    assert not runtime_paths.mio_state_dir().exists()


def test_main_unwritable_ledger_does_not_bind(tmp_path, monkeypatch):
    from azazel_nexus_runtime import mio_route_ledger

    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    runtime_paths.mio_state_dir().mkdir(parents=True)
    original = mio_route_ledger.RouteLedger.open_segment

    def denied(self, path, mode):
        if path.parent == runtime_paths.mio_state_dir() / "route":
            raise PermissionError(errno.EACCES, "fixture permission denial")
        return original(self, path, mode)

    monkeypatch.setattr(mio_route_ledger.RouteLedger, "open_segment", denied)
    monkeypatch.setattr(entry, "serve_forever", lambda **kw: pytest.fail("bound"))
    with pytest.raises(AuditUnavailable):
        entry.main([])


def test_selection_audit_failure_propagates(service, monkeypatch):
    monkeypatch.setattr(service.local, "observe", lambda **_: "local_unavailable")
    monkeypatch.setattr(service.remote, "observe", lambda **_: "remote_unavailable")
    original = service.router.ledger.append

    def append(event, **kwargs):
        if event["event_type"] == "mio.route.selected":
            raise AuditUnavailable("fixture full ledger")
        return original(event, **kwargs)

    monkeypatch.setattr(service.router.ledger, "append", append)
    with pytest.raises(AuditUnavailable):
        service.handle(request())
    assert not any(e["event_type"] == "mio.route.terminal" for e in recorded(service))


def test_entry_has_no_network_or_edge_authority_imports():
    for module in (entry, client):
        tree = ast.parse(Path(module.__file__).read_text())
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(item.name.split(".")[0] for item in node.names)
            elif isinstance(node, ast.ImportFrom):
                roots.add(node.module or "")
            if isinstance(node, ast.Attribute):
                assert node.attr not in {"AF_INET", "AF_INET6", "create_connection"}
        assert not roots & {"ssl", "http", "urllib", "subprocess", "edge_control"}


def test_main_uses_shared_socket_and_only_contracted_service_principal(service, monkeypatch):
    captured = {}
    resolved = []
    monkeypatch.setattr(entry, "serve_forever", lambda **kw: captured.update(kw) or 0)
    monkeypatch.setattr(entry.PrincipalPolicy, "resolve", lambda **kw: resolved.append(kw) or "policy")
    runtime_paths.socket_path("mio-advise").parent.mkdir(parents=True)
    assert entry.main([], ready=lambda: None) == 0
    assert captured["path"] == runtime_paths.socket_path("mio-entry")
    # The explainer's advice-only listener, grouped azmio-advise (patched gid).
    assert captured["additional_sockets"] == (
        (runtime_paths.socket_path("mio-advise"), os.getgid(), entry.ADVISE_REGISTRY),)
    ledger = captured["handler"].__self__.router.ledger
    assert ledger.directory == runtime_paths.mio_state_dir() / "route"
    assert ledger.path.parent == ledger.directory and ledger.path.exists()
    # One handler and one refusal recorder serve both listeners, so the
    # per-uid rate limit and shares apply on the operator and the
    # mio-advise listener alike.
    assert captured["audit"] == captured["handler"].__self__.record_refusal
    assert resolved == [{"service_accounts": ("azarbiter", "azexplain")}]


@pytest.mark.parametrize("profile", list(MioProfile))
@pytest.mark.parametrize("local_admitted", [False, True])
def test_explainer_p3_through_handler_never_dispatches_remote(service, monkeypatch, profile, local_admitted):
    from test_incident_explain import transition

    from azazel_nexus.incident_explain import build_frame

    service._explainer_uid = 4242
    principal = Principal(4242, 7, 1, frozenset({PrincipalClass.SERVICE}))
    service._profile_reader = lambda: profile
    service._local_admitted = lambda: local_admitted
    monkeypatch.setattr(service.local, "observe", lambda **_: "local_not_admitted")
    monkeypatch.setattr(service.remote, "observe", lambda **_: "remote_not_admitted")
    monkeypatch.setattr(service.remote, "handle", lambda *a, **kw: pytest.fail("remote request"))
    monkeypatch.setattr(service.reference, "reference", lambda *a, **kw: (None, "no_pack"))
    monkeypatch.setattr(service.local, "handle", lambda *a, **kw: {"outcome": "not_advice", "refusal": "not_advice"})
    frame = build_frame(transition(), 1)
    req = SimpleNamespace(verb=entry.ADVISE_VERB, arguments={"deadline_ms": 500},
                          payload=frame, principal=principal)
    reply = service.handle(req)
    assert reply["route"] in {"local", "deterministic handoff"}
    selected = [event for event in recorded(service) if event["event_type"] == "mio.route.selected"]
    assert selected and all(event["privacy_class"] == "P3-restricted" for event in selected)
    for privacy in PrivacyClass:
        if privacy is PrivacyClass.P3_RESTRICTED:
            continue
        req.payload = {**frame, "privacy_class": privacy.value}
        with pytest.raises(RequestRefused) as refused:
            service.handle(req)
        assert refused.value.refusal.value == "principal_denied"
    req.verb = entry.ROUTE_VERB
    req.arguments["privacy_class"] = "P3-restricted"
    with pytest.raises(RequestRefused):
        service.handle(req)


def test_reserved_edge_transition_context_requires_the_explainer_principal(service):
    from azazel_nexus.incident_explain import build_frame, pending_entry
    from test_incident_explain import transition

    service._explainer_uid = 4242
    frame = build_frame(pending_entry(transition()), 1)
    request = SimpleNamespace(
        verb=entry.ADVISE_VERB, arguments={"deadline_ms": 500}, payload=frame,
        principal=Principal(4243, 7, 1, frozenset({PrincipalClass.SERVICE})),
    )
    with pytest.raises(RequestRefused) as refused:
        service.handle(request)
    assert refused.value.refusal.value == "principal_denied"


def test_edge_sequence_outside_mio_trace_grammar_skips_only_fast_assistance(
        service, monkeypatch):
    from azazel_nexus.incident_explain import (
        MIO_TRACE_SEQUENCE_MAX, build_frame, pending_entry,
    )
    from test_incident_explain import transition

    service._explainer_uid = os.getuid()
    service._local_admitted = lambda *args, **kwargs: False
    monkeypatch.setattr(service.local, "assess",
                        lambda *args, **kwargs: pytest.fail("unsupported fast frame was sent"))
    monkeypatch.setattr(service.local, "observe", lambda **_: "local_not_admitted")
    monkeypatch.setattr(service.remote, "observe", lambda **_: "remote_not_admitted")
    monkeypatch.setattr(service.remote, "handle",
                        lambda *args, **kwargs: pytest.fail("remote request"))
    monkeypatch.setattr(service.reference, "reference", lambda *args, **kwargs: (None, "no_pack"))
    monkeypatch.setattr(service.local, "handle",
                        lambda *args, **kwargs: {"outcome": "not_advice", "refusal": "not_advice"})
    frame = build_frame(pending_entry(transition()), MIO_TRACE_SEQUENCE_MAX + 1)
    request = SimpleNamespace(
        verb=entry.ADVISE_VERB, arguments={"deadline_ms": 2000}, payload=frame,
        principal=Principal(os.getuid(), os.getgid(), 1, frozenset({PrincipalClass.SERVICE})),
    )

    reply = service.handle(request)

    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert "fast_assistance" not in reply


@pytest.mark.parametrize("profile", list(MioProfile))
@pytest.mark.parametrize("privacy", list(PrivacyClass))
def test_entry_rechecks_remote_with_the_same_no_opt_in_reading(service, monkeypatch,
                                                               profile, privacy):
    # This build has no opt-in reader: the recheck entry passes re-reads the
    # same admission, which never permits remote, so nothing changes.
    from azazel_nexus.remote_trust import Exclusion

    service._profile_reader = lambda: profile
    seen = {}
    original = service.router.handle

    def spy(**kwargs):
        seen.update(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(service.router, "handle", spy)
    reply = service.handle(request(privacy=privacy))
    assert seen["remote"].permitted is False
    again = seen["remote_recheck"]()
    assert again == seen["remote"]
    assert again.permitted is False
    if privacy in {PrivacyClass.P0_PUBLIC, PrivacyClass.P1_SANITIZED} and profile in {
        MioProfile.FASTEST_PERMITTED,
    }:
        assert again.excluded_by is Exclusion.CONSENT
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert not any(e.get("terminal_event") == "remote opt-in withdrawn"
                   for e in recorded(service))


def _fast_frame():
    # An ordinary, non-Edge advice frame: no reserved transition context.
    return {"request_id": "fallback-unit", "privacy_class": PrivacyClass.P0_PUBLIC.value,
            "question": "SSH brute-force observations; technique T1110",
            "context": [{"kind": "auth_log", "text": "redacted test fixture"}]}


def _advise_fast(service, monkeypatch, *, assess_result, absent, core):
    """One ordinary advice request; locald's assess and the core are injected."""
    from azazel_nexus.local_advisory import read_fast_assistance

    calls = {"assess": 0, "core": []}

    def assess(frame, *, deadline_s):
        calls["assess"] += 1
        return assess_result

    def run_core(frame, *, deadline_s):
        calls["core"].append((frame, deadline_s))
        if isinstance(core, Exception):
            raise core
        return core

    monkeypatch.setattr(service.local, "assess", assess)
    monkeypatch.setattr(entry, "locald_absent", lambda: absent)
    # The package may be absent; the core is replaced at the module boundary.
    monkeypatch.setitem(sys.modules, "azazel_nexus_runtime.mio_fast_assistance",
                        SimpleNamespace(fast_assistance=run_core))
    monkeypatch.setattr(service, "_local_admitted", lambda *a, **k: False)
    monkeypatch.setattr(service.local, "observe", lambda **_: "local_unavailable")
    monkeypatch.setattr(service.remote, "observe", lambda **_: "remote_unavailable")
    monkeypatch.setattr(service.remote, "handle",
                        lambda *a, **k: pytest.fail("remote request"))
    monkeypatch.setattr(service.reference, "reference", lambda *a, **k: (None, "no_pack"))
    monkeypatch.setattr(service.local, "handle",
                        lambda *a, **k: {"outcome": "not_advice", "refusal": "not_advice"})
    frame = _fast_frame()
    request = SimpleNamespace(verb=entry.ADVISE_VERB, arguments={"deadline_ms": 2000},
                              payload=frame, principal=None)
    reply = service.handle(request)
    return reply, calls, frame, read_fast_assistance


def test_locald_absent_entry_runs_the_shared_core_in_process(service, monkeypatch):
    from azazel_nexus.local_advisory import read_fast_assistance

    degraded = client.fast_assessment_degraded("unavailable")
    core = client.fast_assessment_degraded("rejected")  # a valid, distinct core result
    reply, calls, frame, _ = _advise_fast(
        service, monkeypatch, assess_result=degraded, absent=True, core=core)

    assert calls["assess"] == 1
    assert [item[0] for item in calls["core"]] == [frame]
    assert 0 < calls["core"][0][1] <= entry.FAST_ASSESS_MAX_S
    assert reply["fast_assistance"] == read_fast_assistance(core)
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value


def test_locald_present_entry_keeps_locald_result_and_never_falls_back(service, monkeypatch):
    from azazel_nexus.local_advisory import read_fast_assistance

    # Normal entry: locald answers with the shared core's assessment.
    assessed = client.fast_assessment_degraded("absent")
    reply, calls, _, _ = _advise_fast(service, monkeypatch, assess_result=assessed,
                                      absent=False, core=assessed)
    assert calls["core"] == []
    assert reply["fast_assistance"] == read_fast_assistance(assessed)


@pytest.mark.parametrize("status", ["timeout", "rejected"])
def test_locald_timeout_or_refusal_is_not_replaced_by_local_fallback(
        service, monkeypatch, status):
    from azazel_nexus.local_advisory import read_fast_assistance

    locald = client.fast_assessment_degraded(status)
    reply, calls, _, _ = _advise_fast(service, monkeypatch, assess_result=locald,
                                      absent=True, core=client.fast_assessment_degraded("absent"))
    assert calls["core"] == []
    assert reply["fast_assistance"] == read_fast_assistance(locald)


def test_locald_present_but_unavailable_does_not_fall_back(service, monkeypatch):
    from azazel_nexus.local_advisory import read_fast_assistance

    # A socket that exists but fails (locald running, its core failing) keeps
    # locald's explicit degraded status: only absence selects the fallback.
    locald = client.fast_assessment_degraded("unavailable")
    reply, calls, _, _ = _advise_fast(service, monkeypatch, assess_result=locald,
                                      absent=False, core=client.fast_assessment_degraded("absent"))
    assert calls["core"] == []
    assert reply["fast_assistance"] == read_fast_assistance(locald)


def test_locald_absent_with_missing_or_failing_core_is_explicitly_degraded(
        service, monkeypatch):
    degraded = client.fast_assessment_degraded("unavailable")
    reply, calls, _, _ = _advise_fast(service, monkeypatch, assess_result=degraded,
                                      absent=True, core=ImportError("no package"))
    assert len(calls["core"]) == 1
    assert reply["fast_assistance"]["dependency_outcome"]["knowledge"] == "unavailable"
    assert reply["fast_assistance"]["state"] == "dependency_unavailable"
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value


def test_shared_core_past_budget_is_timeout_busy_is_immediate_and_slot_recovers(
        service, monkeypatch):
    import threading

    started, release = threading.Event(), threading.Event()
    calls = []
    late = client.fast_assessment_degraded("rejected")

    def slow_core(frame, deadline_s):
        calls.append(frame)
        started.set()
        release.wait(5)
        return late

    monkeypatch.setitem(sys.modules, "azazel_nexus_runtime.mio_fast_assistance",
                        SimpleNamespace(fast_assistance=slow_core))
    frame = _fast_frame()
    try:
        # Core still running past the budget: explicit timeout, late result unused.
        first = service._shared_fast_assistance(frame, 0.05)
        assert started.is_set()
        assert first["dependency_outcome"]["knowledge"] == "timeout"
        # Busy: no second worker, no wait, immediate timeout.
        second = service._shared_fast_assistance(frame, 5.0)
        assert second["dependency_outcome"]["knowledge"] == "timeout"
        assert len(calls) == 1
    finally:
        release.set()
    # The slot frees only when the worker really finishes.
    assert service._fast_slot.acquire(timeout=5)
    service._fast_slot.release()
    fast = SimpleNamespace(fast_assistance=lambda f, deadline_s: late)
    monkeypatch.setitem(sys.modules, "azazel_nexus_runtime.mio_fast_assistance", fast)
    assert service._shared_fast_assistance(frame, 1.0) == late
    # A failing core is still explicit unavailability and frees the slot.
    def boom(f, deadline_s):
        raise RuntimeError("core")
    monkeypatch.setitem(sys.modules, "azazel_nexus_runtime.mio_fast_assistance",
                        SimpleNamespace(fast_assistance=boom))
    assert service._shared_fast_assistance(frame, 1.0)["dependency_outcome"][
        "knowledge"] == "unavailable"
    assert service._fast_slot.acquire(timeout=5)
    service._fast_slot.release()


def test_locald_absent_without_budget_runs_no_core(service, monkeypatch):
    calls = []
    monkeypatch.setattr(service.local, "assess",
                        lambda *a, **k: pytest.fail("locald asked without budget"))
    monkeypatch.setitem(sys.modules, "azazel_nexus_runtime.mio_fast_assistance",
                        SimpleNamespace(fast_assistance=lambda *a, **k: calls.append(a)))
    assert service._shared_fast_assistance(_fast_frame(), 0.0)["dependency_outcome"][
        "knowledge"] == "timeout"
    assert calls == []
