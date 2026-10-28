"""entryd's remote opt-in: operator-only verbs, and the recheck reads the store.

Mock evidence: the service is composed in-process over a temporary state
directory; no socket, no systemd, no transport. Production stays closed:
remote trust is `unchecked` and the allowlist empty, so even a granted
opt-in selects no remote route (asserted below).
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import mio_entryd as entry
from azazel_nexus_runtime import mio_socket_client as client
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.mio_remote_consent import ConsentStore
from azazel_nexus_runtime.principal import Principal, PrincipalClass
from azazel_nexus_runtime.protocol import ArgumentKind, RequestRefused

from azazel_nexus.mio_profile import NO_OPT_IN, PREREQUISITES, MioProfile
from azazel_nexus.route_ledger import RouteChain
from azazel_nexus.routing import Route
from azazel_nexus.sanitizer import PrivacyClass

OPERATOR = Principal(1001, 1001, 1, frozenset({PrincipalClass.OPERATOR}))
SERVICE = Principal(1002, 1002, 1, frozenset({PrincipalClass.SERVICE}))


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    runtime_paths.mio_state_dir().mkdir(parents=True)
    runtime_paths.mio_state_dir().chmod(0o700)
    return entry.MioEntryService()


def verb(service, verb, principal=OPERATOR, **arguments):
    return service.handle(SimpleNamespace(verb=verb, arguments=arguments, principal=principal))


def grant(service):
    reply = None
    for prerequisite in PREREQUISITES:
        reply = verb(service, entry.OPT_IN_SET_VERB, prerequisite=prerequisite.value)
    return reply


def recorded(service):
    ledger = RouteChain(service.router.ledger.directory)
    ledger.verify()
    return [item.event for item in ledger]


def route(principal=OPERATOR):
    return SimpleNamespace(verb=entry.ROUTE_VERB, principal=principal, arguments={
        "privacy_class": PrivacyClass.P0_PUBLIC.value, "deadline_ms": 1000})


# -- the verbs ------------------------------------------------------------


def test_only_the_operator_class_may_call_the_opt_in_verbs():
    for v in (entry.OPT_IN_STATUS_VERB, entry.OPT_IN_SET_VERB, entry.OPT_IN_WITHDRAW_VERB):
        assert v.admits == {PrincipalClass.OPERATOR}
        assert not v.accepts_payload
        assert all(a.kind is ArgumentKind.ENUM for a in v.arguments)
        assert entry.REGISTRY.resolve(v.name, OPERATOR) == v
        for other in (SERVICE, Principal(0, 0, 1, frozenset({PrincipalClass.ROOT}))):
            with pytest.raises(RequestRefused):
                entry.REGISTRY.resolve(v.name, other)
        # Not on the explainer's advice listener at all.
        with pytest.raises(RequestRefused):
            entry.ADVISE_REGISTRY.resolve(v.name, OPERATOR)


def test_the_handler_refuses_a_non_operator_even_past_the_registry(service):
    with pytest.raises(RequestRefused):
        verb(service, entry.OPT_IN_SET_VERB, principal=SERVICE, prerequisite="remote use")
    assert service.consent.reading().status == "absent"


def test_status_set_and_withdraw_through_the_operator_verbs(service):
    assert verb(service, entry.OPT_IN_STATUS_VERB) == {
        "status": "absent", "generation": 0, "granted": [],
        "missing": [p.value for p in PREREQUISITES]}
    reply = grant(service)
    assert reply["status"] == "granted" and reply["generation"] == 4
    reply = verb(service, entry.OPT_IN_WITHDRAW_VERB, reason="privacy_review")
    assert reply["status"] == "withdrawn" and reply["generation"] == 5
    assert reply["drained"] is True

    events = recorded(service)
    sets = [e for e in events if e["event_type"] == "mio.remote.opt_in.set"]
    assert [e["generation"] for e in sets] == [1, 2, 3, 4]
    assert all(e["operator"] == "uid:1001" for e in sets)
    granted = [e for e in events if e["event_type"] == "mio.remote.opt_in"]
    assert len(granted) == 1 and granted[0]["generation"] == 4
    withdrawn = [{k: v for k, v in e.items() if k != "occurred_at"}
                 for e in events if e["event_type"] == "mio.remote.opt_in.withdrawn"]
    assert withdrawn == [{"event_type": "mio.remote.opt_in.withdrawn", "operator": "uid:1001",
                          "at": withdrawn[0]["at"], "reason": "privacy_review",
                          "generation": 5, "drained": True}]


def test_a_grant_is_recorded_before_it_is_committed(service, monkeypatch):
    order = []
    record = service.router._record
    monkeypatch.setattr(service.router, "_record",
                        lambda event, **kw: (order.append(event["event_type"]), record(event, **kw))[1])
    original = service.consent.set_prerequisite
    monkeypatch.setattr(service.consent, "set_prerequisite",
                        lambda *a, **kw: (order.append("commit"), original(*a, **kw))[1])
    verb(service, entry.OPT_IN_SET_VERB, prerequisite="remote use")
    assert order.index("mio.remote.opt_in.set") < order.index("commit")


def test_a_withdrawal_is_committed_even_when_the_ledger_then_fails(service, monkeypatch):
    from azazel_nexus.audit import AuditUnavailable

    grant(service)

    def fail(event, **kw):
        raise AuditUnavailable("ledger down")

    monkeypatch.setattr(service.router, "_record", fail)
    with pytest.raises(AuditUnavailable):
        verb(service, entry.OPT_IN_WITHDRAW_VERB, reason="incident_response")
    assert service.consent.reading().status == "withdrawn"


def test_a_grant_over_an_unreadable_store_is_refused_and_writes_nothing(service):
    grant(service)
    path = runtime_paths.mio_state_dir() / "remote-consent" / "opt-in.json"
    path.write_bytes(b"{")
    with pytest.raises(RequestRefused):
        verb(service, entry.OPT_IN_SET_VERB, prerequisite="remote use")
    with pytest.raises(RequestRefused):
        verb(service, entry.OPT_IN_WITHDRAW_VERB, reason="operator_request")
    assert path.read_bytes() == b"{"
    assert verb(service, entry.OPT_IN_STATUS_VERB)["status"] == "unavailable"


# -- the selection and the recheck read the store --------------------------


@pytest.fixture
def admissions(service, monkeypatch):
    """Every opt-in `remote_admission` is asked with, and the recheck."""
    seen, captured = [], {}
    real = entry.remote_admission

    def spy(**kw):
        seen.append(kw["opt_in"])
        return real(**kw)

    monkeypatch.setattr(entry, "remote_admission", spy)
    handle = service.router.handle

    def capture(**kw):
        captured.update(kw)
        return handle(**kw)

    monkeypatch.setattr(service.router, "handle", capture)
    service._profile_reader = lambda: MioProfile.FASTEST_PERMITTED
    return seen, captured


def test_without_a_store_the_reading_is_no_opt_in(service, admissions):
    seen, captured = admissions
    service.handle(route())
    assert seen == [NO_OPT_IN]
    captured["remote_recheck"]()
    assert seen[-1] is NO_OPT_IN


def test_a_granted_opt_in_is_read_and_still_selects_no_remote_route(service, admissions):
    seen, captured = admissions
    grant(service)
    reply = service.handle(route())
    assert seen[0].active()
    # Trust is unchecked and the allowlist empty: nothing in this build
    # turns an opt-in into a remote route.
    assert captured["remote"].permitted is False
    assert reply["route"] == Route.DETERMINISTIC_HANDOFF.value
    assert captured["remote_request"] is None


def test_a_withdrawal_after_the_selection_is_what_the_recheck_reads(service, admissions):
    seen, captured = admissions
    grant(service)
    service.handle(route())
    assert seen[-1].active()
    verb(service, entry.OPT_IN_WITHDRAW_VERB, reason="operator_request")
    captured["remote_recheck"]()
    assert seen[-1] is NO_OPT_IN


def test_any_change_of_generation_after_the_selection_reads_as_no_opt_in(service, admissions):
    """Even a change that leaves it granted: the recheck only narrows."""
    seen, captured = admissions
    grant(service)
    service.handle(route())
    verb(service, entry.OPT_IN_WITHDRAW_VERB, reason="operator_request")
    grant(service)
    assert service.consent.reading().permits
    captured["remote_recheck"]()
    assert seen[-1] is NO_OPT_IN


@pytest.mark.parametrize("damage", ["corrupt", "rolled_back", "deleted"])
def test_a_store_that_cannot_be_believed_reads_as_no_opt_in(service, admissions, damage):
    seen, captured = admissions
    grant(service)
    path = runtime_paths.mio_state_dir() / "remote-consent" / "opt-in.json"
    older = path.read_bytes()
    verb(service, entry.OPT_IN_SET_VERB, prerequisite="remote use")  # generation 5
    service.handle(route())
    assert seen[-1].active()
    if damage == "corrupt":
        path.write_bytes(b"{}")
    elif damage == "rolled_back":
        path.write_bytes(older)  # generation 4, granted, put back
    else:
        path.unlink()
    captured["remote_recheck"]()
    assert seen[-1] is NO_OPT_IN
    service.handle(route())
    assert seen[-1] is NO_OPT_IN


def test_a_restart_does_not_bring_a_withdrawn_opt_in_back(service, monkeypatch):
    grant(service)
    verb(service, entry.OPT_IN_WITHDRAW_VERB, reason="incident_response")
    restarted = entry.MioEntryService()
    reading = restarted.consent.reading()
    assert reading.status == "withdrawn" and not reading.permits
    seen = []
    real = entry.remote_admission
    monkeypatch.setattr(entry, "remote_admission",
                        lambda **kw: (seen.append(kw["opt_in"]), real(**kw))[1])
    restarted.handle(route())
    assert seen and not any(o.active() for o in seen)


def test_the_default_store_is_entryds_own_leaf(service):
    assert isinstance(service.consent, ConsentStore)
    assert service.consent.directory == runtime_paths.mio_state_dir()
    assert service.consent.owner == os.geteuid()
