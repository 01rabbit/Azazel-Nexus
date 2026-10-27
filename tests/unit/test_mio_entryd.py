"""Entry composition, actual Unix framing, and fail-closed route evidence."""

import ast
import errno
import os
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
    def fail(*args):
        raise failure

    monkeypatch.setattr(client, "_exchange", fail)
    assert client.LocalSocketClient().handle(None)["reason"] == "local_unavailable"
    assert client.RemoteSocketClient().handle(None)["outcome"] == "unavailable"


def test_fixed_probe_never_supplies_payload_or_accepts_response_text(monkeypatch):
    calls = []

    def exchange(*args):
        calls.append(args)
        return {"readiness": "refused", "reason": "PROMPT_SENTINEL"}

    monkeypatch.setattr(client, "_exchange", exchange)
    assert client.LocalSocketClient().observe() == "local_not_admitted"
    assert calls == [("mio", "azmio", "model.activate", {
        "model_id": "uncommissioned", "runtime_id": "uncommissioned",
    })]


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
    monkeypatch.setattr(service.local, "observe", lambda: "local_unavailable")
    monkeypatch.setattr(service.remote, "observe", lambda: "remote_unavailable")
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
    monkeypatch.setattr(service.local, "observe", lambda: "local_not_admitted")
    monkeypatch.setattr(service.remote, "observe", lambda: "remote_not_admitted")
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
