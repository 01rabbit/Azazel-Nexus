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

from azazel_nexus.audit import AuditLedger, AuditUnavailable
from azazel_nexus.mio_profile import MioProfile
from azazel_nexus.routing import Route
from azazel_nexus.sanitizer import PrivacyClass


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    # TODO(Lane A): closed runtime_paths table lacks all three contract leaves.
    def path(name):
        assert name in {"mio-entry", "mio", "remote"}
        return tmp_path / "var/lib/azazel/run" / name / f"{name}.sock"

    monkeypatch.setattr(client, "socket_path", path)
    monkeypatch.setattr(entry, "socket_path", path)
    monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    runtime_paths.mio_state_dir().mkdir(parents=True)
    return entry.MioEntryService()


def request(privacy=PrivacyClass.P0_PUBLIC, deadline=1000):
    return SimpleNamespace(arguments={"privacy_class": privacy.value, "deadline_ms": deadline})


def recorded(service):
    ledger = AuditLedger(service.router.ledger.path)
    ledger.verify()
    return [item.event for item in ledger]


def test_absent_services_record_handoff_and_reasons(service):
    reply = service.handle(request())
    events = recorded(service)
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert reply["outcome"] != "answered"
    assert reply["reason"]
    assert reply["ledger_seq"] == len(events)
    assert events[0]["local"] == "local_unavailable"
    assert events[0]["remote"] == "remote_unavailable"
    assert "HG-05" in events[0]["local_refusal"]
    decision = next(event for event in events if event["event_type"] == "mio.route.selected")
    assert decision["profile"] == MioProfile.CORE.value
    assert all(candidate["reason"] for candidate in decision["candidates"])


def test_confirmed_profile_reader_is_used(service):
    service._profile_reader = lambda: MioProfile.FASTEST_PERMITTED
    service.handle(request())
    decision = next(e for e in recorded(service) if e["event_type"] == "mio.route.selected")
    assert decision["profile"] == MioProfile.FASTEST_PERMITTED.value
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


def test_main_unwritable_ledger_does_not_bind(service, monkeypatch):
    original = Path.open

    def denied(path, *args, **kwargs):
        if path == service.router.ledger.path and args and args[0] == "a":
            raise PermissionError(errno.EACCES, "fixture permission denial")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied)
    monkeypatch.setattr(entry, "serve_forever", lambda **kw: pytest.fail("bound"))
    with pytest.raises(AuditUnavailable):
        entry.main([])


def test_selection_audit_failure_propagates(service, monkeypatch):
    monkeypatch.setattr(service.local, "observe", lambda: "local_unavailable")
    monkeypatch.setattr(service.remote, "observe", lambda: "remote_unavailable")
    original = service.router.ledger.append

    def append(event):
        if event["event_type"] == "mio.route.selected":
            raise AuditUnavailable("fixture full ledger")
        return original(event)

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
