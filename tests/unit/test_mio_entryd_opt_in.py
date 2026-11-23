"""entryd's remote opt-in: operator-only verbs, and the recheck reads the store.

Mock evidence: the service is composed in-process over a temporary state
directory; no socket, no systemd, no transport. Production stays closed:
remote trust is `unchecked` and the allowlist empty, so even a granted
opt-in selects no remote route (asserted below).
"""

from __future__ import annotations

import json
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
    assert reply["status"] == "granted" and reply["generation"] == 5
    reply = verb(service, entry.OPT_IN_WITHDRAW_VERB, reason="privacy_review")
    assert reply["status"] == "withdrawn" and reply["generation"] == 6
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
                          "generation": 6, "drained": True}]


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


def test_while_the_chain_is_broken_set_is_refused_and_withdraw_narrows_without_a_record(
        service, monkeypatch):
    from azazel_nexus_runtime.protocol import Refusal

    prerequisites = list(PREREQUISITES)
    for prerequisite in prerequisites[:-1]:
        verb(service, entry.OPT_IN_SET_VERB, prerequisite=prerequisite.value)
    service.ledger_broken = True

    def forbidden(*args, **kwargs):
        raise AssertionError("the ledger was touched while broken")

    monkeypatch.setattr(service.router, "_record", forbidden)
    monkeypatch.setattr(service, "_mark", forbidden)
    before = service.consent.reading()
    with pytest.raises(RequestRefused) as refused:
        verb(service, entry.OPT_IN_SET_VERB, prerequisite=prerequisites[-1].value)
    assert refused.value.refusal is Refusal.VERB_UNAVAILABLE
    after = service.consent.reading()
    assert (after.generation, after.status) == (before.generation, before.status)

    with pytest.raises(RequestRefused) as withdrawn:
        verb(service, entry.OPT_IN_WITHDRAW_VERB, reason="incident_response")
    assert withdrawn.value.refusal is Refusal.VERB_UNAVAILABLE
    assert service.consent.reading().status == "withdrawn"
    assert verb(service, entry.OPT_IN_STATUS_VERB)["status"] == "withdrawn"


@pytest.mark.parametrize("room_fault", ["broken_metadata", "no_room"])
def test_a_withdrawal_on_a_broken_chain_narrows_even_when_room_would_refuse(
        service, monkeypatch, room_fault):
    from azazel_nexus.audit import AuditChainBroken
    from azazel_nexus_runtime.protocol import Refusal

    grant(service)
    assert service.consent.reading().permits
    service.ledger_broken = True

    def room(key):
        if room_fault == "broken_metadata":
            raise AuditChainBroken("fixture damaged boundary metadata")
        return False

    monkeypatch.setattr(service.router.ledger, "room", room)
    monkeypatch.setattr(service.router, "_record",
                        lambda *a, **k: pytest.fail("the ledger was touched"))
    with pytest.raises(RequestRefused) as refused:
        verb(service, entry.OPT_IN_WITHDRAW_VERB, reason="incident_response")
    assert refused.value.refusal is Refusal.VERB_UNAVAILABLE
    assert service.consent.reading().status == "withdrawn"


@pytest.mark.parametrize("failure", ["broken", "unavailable", "oserror"])
def test_a_set_whose_record_fails_after_the_commit_withdraws_the_grant(
        service, monkeypatch, failure):
    from azazel_nexus.audit import AuditChainBroken, AuditUnavailable
    from azazel_nexus_runtime.protocol import Refusal

    for prerequisite in list(PREREQUISITES)[:-1]:
        verb(service, entry.OPT_IN_SET_VERB, prerequisite=prerequisite.value)
    real = service.router._record

    def record(event, **kw):
        if event.get("event_type") == "mio.remote.opt_in":
            raise {"broken": AuditChainBroken, "unavailable": AuditUnavailable,
                   "oserror": OSError}[failure]("fixture")
        return real(event, **kw)

    monkeypatch.setattr(service.router, "_record", record)
    with pytest.raises(RequestRefused) as refused:
        verb(service, entry.OPT_IN_SET_VERB, prerequisite=list(PREREQUISITES)[-1].value)
    assert refused.value.refusal is Refusal.VERB_UNAVAILABLE
    assert service.consent.reading().status == "withdrawn"
    assert not service.consent.reading().permits
    assert service.refusals_unrecorded == 1
    assert service.ledger_broken is (failure == "broken")
    withdrawn = service.consent.reading()
    document = json.loads((runtime_paths.mio_state_dir() / "remote-consent" / "opt-in.json").read_text())
    assert document["withdrawn"]["reason"] == "audit_record_failed"
    assert document["withdrawn"]["operator"] == entry.ENTRYD_ACTOR
    assert withdrawn.status == "withdrawn"


def test_the_operator_verb_does_not_offer_the_internal_withdrawal_reason(service):
    argument = entry.OPT_IN_WITHDRAW_VERB.arguments[0]
    assert "audit_record_failed" not in argument.choices
    with pytest.raises(Exception):
        entry.OPT_IN_WITHDRAW_VERB.bind({"reason": "audit_record_failed"})


# -- a completing grant is closed until its record is confirmed ------------


def _separate_store():
    return ConsentStore(runtime_paths.mio_state_dir(), owner=os.geteuid())


def _set_all_but_last(service):
    for prerequisite in list(PREREQUISITES)[:-1]:
        verb(service, entry.OPT_IN_SET_VERB, prerequisite=prerequisite.value)


def _set_last(service):
    return verb(service, entry.OPT_IN_SET_VERB, prerequisite=list(PREREQUISITES)[-1].value)


@pytest.mark.parametrize("withdraw_failure", ["oserror", "refused"])
@pytest.mark.parametrize("record_failure", ["broken", "unavailable", "oserror"])
def test_w9_1_a_grant_whose_record_and_withdrawal_both_fail_stays_closed(
        service, monkeypatch, record_failure, withdraw_failure):
    from azazel_nexus.audit import AuditChainBroken, AuditUnavailable
    from azazel_nexus_runtime.mio_remote_consent import ConsentRefused
    from azazel_nexus_runtime.mio_remoted import RemoteInferenceService
    from azazel_nexus_runtime.protocol import Refusal

    _set_all_but_last(service)
    real = service.router._record

    def record(event, **kw):
        if event.get("event_type") == "mio.remote.opt_in":
            raise {"broken": AuditChainBroken, "unavailable": AuditUnavailable,
                   "oserror": OSError}[record_failure]("fixture")
        return real(event, **kw)

    def fail(*a, **kw):
        raise {"oserror": OSError, "refused": ConsentRefused}[withdraw_failure]("fixture")

    monkeypatch.setattr(service.router, "_record", record)
    monkeypatch.setattr(service.consent, "withdraw", fail)
    with pytest.raises(RequestRefused) as refused:
        _set_last(service)
    assert refused.value.refusal is Refusal.VERB_UNAVAILABLE
    assert service.unrecorded_withdraw_failed == 1

    other = _separate_store()
    reading = other.reading()
    assert reading.status == "unconfirmed" and not reading.permits
    with other.send_gate() as gated:
        assert not gated.permits
        assert RemoteInferenceService._consent_refusal(gated, gated.generation) is not None
        assert RemoteInferenceService._consent_refusal(gated, gated.generation)[0] == "opt_in_not_granted"


def test_the_grant_is_not_usable_while_its_record_is_being_written(service, monkeypatch):
    _set_all_but_last(service)
    real = service.router._record
    seen = []

    def record(event, **kw):
        if event.get("event_type") == "mio.remote.opt_in":
            seen.append(_separate_store().reading())
        return real(event, **kw)

    monkeypatch.setattr(service.router, "_record", record)
    reply = _set_last(service)
    assert [r.status for r in seen] == ["unconfirmed"] and not seen[0].permits
    assert reply["status"] == "granted" and reply["generation"] == 5
    assert _separate_store().reading().permits


def test_a_confirmation_that_fails_is_withdrawn_and_refused(
        service, monkeypatch):
    from azazel_nexus_runtime.mio_remote_consent import ConsentRefused
    from azazel_nexus_runtime.protocol import Refusal

    _set_all_but_last(service)

    def fail(*a, **kw):
        raise ConsentRefused("fixture: busy")

    monkeypatch.setattr(service.consent, "confirm", fail)
    with pytest.raises(RequestRefused) as refused:
        _set_last(service)
    assert refused.value.refusal is Refusal.VERB_UNAVAILABLE
    assert "opt_in_store" in str(refused.value.args)
    # Refused, so narrowed at once by entryd itself.
    reading = _separate_store().reading()
    assert reading.status == "withdrawn" and not reading.permits
    assert reading.opt_in.withdrawn.reason == "opt_in_not_confirmed"
    events = [e["event_type"] for e in recorded(service)]
    assert events.count("mio.remote.opt_in") == 1
    assert events[-1] == "mio.remote.opt_in.not_committed"


def test_a_confirmation_that_fails_after_publishing_is_withdrawn_before_the_reply(
        service, monkeypatch):
    # The confirmed record is published (rename) and then the confirmation
    # fails (directory sync or read-back): the request is refused, so the
    # grant must not stay usable to another process.
    from azazel_nexus_runtime.mio_remoted import RemoteInferenceService
    from azazel_nexus_runtime.protocol import Refusal

    _set_all_but_last(service)
    real_confirm = service.consent.confirm
    published = []

    def confirm_then_fail(generation, **kw):
        published.append(real_confirm(generation, **kw))
        assert _separate_store().reading().permits  # it really was open
        raise OSError("fixture: directory fsync")

    monkeypatch.setattr(service.consent, "confirm", confirm_then_fail)
    with pytest.raises(RequestRefused) as refused:
        _set_last(service)
    assert refused.value.refusal is Refusal.VERB_UNAVAILABLE and published
    other = _separate_store()
    assert other.reading().status == "withdrawn"
    with other.send_gate() as gated:
        assert RemoteInferenceService._consent_refusal(
            gated, published[0].generation) is not None


@pytest.mark.parametrize("withdraw_failure", ["oserror", "refused"])
def test_a_refusal_after_a_published_confirmation_always_means_closed(
        service, monkeypatch, withdraw_failure):
    # Published, then the confirmation fails, then the narrowing fails too:
    # the grant is in force and already recorded (with `opens_generation`),
    # so the reply must say granted, never a refusal over an open store.
    from azazel_nexus_runtime.mio_remote_consent import ConsentRefused

    _set_all_but_last(service)
    real_confirm = service.consent.confirm

    def confirm_then_fail(generation, **kw):
        real_confirm(generation, **kw)
        raise OSError("fixture: directory fsync")

    def withdraw_fails(*a, **kw):
        raise {"oserror": OSError, "refused": ConsentRefused}[withdraw_failure]("fixture")

    monkeypatch.setattr(service.consent, "confirm", confirm_then_fail)
    monkeypatch.setattr(service.consent, "withdraw", withdraw_fails)
    reply = _set_last(service)
    reading = _separate_store().reading()
    assert reply["status"] == "granted" and reading.permits
    assert reply["generation"] == reading.generation
    grant = [e for e in recorded(service) if e["event_type"] == "mio.remote.opt_in"][-1]
    assert grant["opens_generation"] == reading.generation
    assert service.unrecorded_withdraw_failed == 1


@pytest.mark.parametrize("published", [False, True])
def test_whenever_the_set_is_refused_no_separate_reader_may_send(service, monkeypatch, published):
    # The invariant across every confirm/withdraw failure: refused => closed.
    from azazel_nexus_runtime.mio_remote_consent import ConsentRefused
    from azazel_nexus_runtime.mio_remoted import RemoteInferenceService

    _set_all_but_last(service)
    real_confirm = service.consent.confirm

    def confirm_fails(generation, **kw):
        if published:
            real_confirm(generation, **kw)
        raise OSError("fixture")

    monkeypatch.setattr(service.consent, "confirm", confirm_fails)
    with pytest.raises(RequestRefused):
        _set_last(service)
    other = _separate_store()
    with other.send_gate() as gated:
        for generation in range(1, 8):
            assert RemoteInferenceService._consent_refusal(gated, generation) is not None


def test_the_grant_record_names_the_generation_a_send_is_bound_to(service):
    _set_all_but_last(service)
    reply = _set_last(service)
    grant = [e for e in recorded(service) if e["event_type"] == "mio.remote.opt_in"][-1]
    assert grant["opens_generation"] == grant["generation"] + 1 == reply["generation"]
    assert _separate_store().reading().generation == grant["opens_generation"]


def test_a_withdrawal_reaches_the_store_when_the_callers_share_is_spent(service, monkeypatch):
    grant(service)
    assert _separate_store().reading().permits
    monkeypatch.setattr(service.router.ledger, "room", lambda key: False, raising=False)
    verb(service, entry.OPT_IN_WITHDRAW_VERB, reason="operator_request")
    assert _separate_store().reading().status == "withdrawn"
    # A widening verb is still refused on a spent share.
    with pytest.raises(RequestRefused):
        verb(service, entry.OPT_IN_SET_VERB, prerequisite=list(PREREQUISITES)[0].value)


@pytest.mark.parametrize("fault", ["unavailable", "broken"])
def test_a_confirmation_that_fails_while_the_ledger_is_down_still_refuses(
        service, monkeypatch, fault):
    from azazel_nexus.audit import AuditChainBroken, AuditUnavailable
    from azazel_nexus_runtime.mio_remote_consent import ConsentRefused
    from azazel_nexus_runtime.protocol import Refusal

    _set_all_but_last(service)
    unrecorded = service.refusals_unrecorded

    def confirm_fails(*a, **kw):
        # The ledger goes away (or is found broken) just before the
        # not_committed record.
        def down(event, **kw):
            if fault == "broken":
                raise AuditChainBroken("fixture: chain")
            raise AuditUnavailable("down")
        monkeypatch.setattr(service.router, "_record", down)
        raise ConsentRefused("fixture")

    monkeypatch.setattr(service.consent, "confirm", confirm_fails)
    with pytest.raises(RequestRefused) as refused:
        _set_last(service)
    assert refused.value.refusal is Refusal.VERB_UNAVAILABLE
    assert not _separate_store().reading().permits
    assert service.refusals_unrecorded == unrecorded + 1
    # A break found by this record is the daemon's broken state, not swallowed.
    assert service.ledger_broken is (fault == "broken")


def test_a_set_after_an_unconfirmed_grant_starts_from_the_empty_set(service, monkeypatch):
    from azazel_nexus_runtime.mio_remote_consent import ConsentRefused

    _set_all_but_last(service)
    monkeypatch.setattr(service.consent, "confirm",
                        lambda *a, **kw: (_ for _ in ()).throw(ConsentRefused("x")))
    with pytest.raises(RequestRefused):
        _set_last(service)
    monkeypatch.undo()
    reply = verb(service, entry.OPT_IN_SET_VERB, prerequisite=PREREQUISITES[0].value)
    assert reply["status"] == "incomplete"
    assert reply["granted"] == [PREREQUISITES[0].value]
