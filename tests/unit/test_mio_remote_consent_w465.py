"""#465 after the fix: a refused `set` leaves no valid send, and an unsettled
grant is held shut by entryd. Real subprocesses over the on-disk store (the
reader runs the real `RemoteInferenceService.handle`), plus unit tests of the
new store API and of the unsettled state.

Observations are written to $W465_OUT (default u71/out/w10) as
after-R1.json, after-R2.json and after-controls.json. Order across processes
uses files and FIFOs; the only injected durations are gate-wait bounds.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import mio_entryd as entry
from azazel_nexus_runtime import mio_socket_client as client
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.mio_remote_consent import (
    _UNAVAILABLE, ConsentRefused, ConsentStore)
from azazel_nexus_runtime.principal import Principal, PrincipalClass

from azazel_nexus.audit import AuditChainBroken
from azazel_nexus.mio_profile import PREREQUISITES

pytestmark = pytest.mark.real_process

HERE = Path(__file__).resolve().parent
OPERATOR = Principal(1001, 1001, 1, frozenset({PrincipalClass.OPERATOR}))
OUT = Path(os.environ.get("W465_OUT", HERE.parents[2] / "out" / "w10"))
LAST = list(PREREQUISITES)[-1]


def _env():
    root = HERE.parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(root / "src"), str(root / "runtime" / "src"), env.get("PYTHONPATH", "")])
    return env


def send_in_new_process(state, generation) -> dict:
    done = subprocess.run(
        [sys.executable, str(HERE / "_mio_remote_consent_child.py"), "send",
         str(state), str(generation)],
        capture_output=True, text=True, timeout=60, env=_env(), check=True)
    return json.loads(done.stdout.strip().splitlines()[-1])


def dump(name, data, merge=False):
    try:
        OUT.mkdir(parents=True, exist_ok=True)
        path = OUT / name
        if merge and path.exists():
            data = {**json.loads(path.read_text()), **data}
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    except (OSError, ValueError):
        pass


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    runtime_paths.mio_state_dir().mkdir(parents=True)
    runtime_paths.mio_state_dir().chmod(0o700)
    return entry.MioEntryService()


def call(service, verb, **arguments):
    return service.handle(SimpleNamespace(
        verb=verb, principal=OPERATOR, arguments=arguments))


def set_prerequisite(service, prerequisite):
    return call(service, entry.OPT_IN_SET_VERB, prerequisite=prerequisite.value)


def refusal_of(service, prerequisite):
    try:
        return {"returned": set_prerequisite(service, prerequisite)}
    except entry.RequestRefused as exc:
        return {"refused": {"code": str(exc.refusal), "detail": str(exc.args)}}


def first_three(service):
    for prerequisite in list(PREREQUISITES)[:-1]:
        set_prerequisite(service, prerequisite)


def store_view(state):
    reading = ConsentStore(state).reading()
    return {"generation": reading.generation, "status": reading.status,
            "permits": reading.permits}


def gate_free(state) -> bool:
    try:
        ConsentStore(state).hold_gate_exclusive(0.2).release()
        return True
    except ConsentRefused:
        return False


def inject_publish_then_fail(service, monkeypatch, after_publish=None):
    """confirm: the rename publishes N+1, then the fsync/read-back 'fails'."""
    real_confirm = service.consent.confirm
    seen = {"published": None}

    def confirm(generation, *, operator):
        record = real_confirm(generation, operator=operator)
        seen["published"] = record.generation
        if after_publish is not None:
            after_publish(record)
        raise OSError(5, "fixture: fsync after rename")

    monkeypatch.setattr(service.consent, "confirm", confirm)
    return seen


def test_r1_unsettled_grant_is_held_shut_then_settled(service, monkeypatch):
    first_three(service)
    faults = {"withdraw": True, "reading": True}
    seen = inject_publish_then_fail(service, monkeypatch)
    real_reading, real_withdraw = service.consent.reading, service.consent.withdraw

    def reading():
        # After the failed confirm the re-read hits EIO: `unavailable`.
        if faults["reading"] and seen["published"] is not None:
            return _UNAVAILABLE
        return real_reading()

    def withdraw(*a, **kw):
        if faults["withdraw"]:
            raise ConsentRefused("fixture: withdraw busy")
        return real_withdraw(*a, **kw)

    monkeypatch.setattr(service.consent, "reading", reading)
    monkeypatch.setattr(service.consent, "withdraw", withdraw)
    response = refusal_of(service, LAST)
    state = runtime_paths.mio_state_dir()
    view = store_view(state)
    sent = send_in_new_process(state, view["generation"])
    status = call(service, entry.OPT_IN_STATUS_VERB)  # still unsettled: retry fails
    again = refusal_of(service, PREREQUISITES[0])
    gate_free_while_unsettled = gate_free(state)

    # The retry (tick / next verb) succeeds once the faults clear.
    faults.update(withdraw=False, reading=False)
    service.settle_opt_in()
    after_view = store_view(state)
    after_sent = send_in_new_process(state, view["generation"])
    released = gate_free(state)
    dump("after-R1.json", {
        "case": "R1", "set_response": response, "store_after": view,
        "send_other_process": sent, "status_reply_while_unsettled": status,
        "set_while_unsettled": again,
        "gate_free_while_unsettled": gate_free_while_unsettled,
        "after_retry": {"store": after_view, "send": after_sent,
                        "gate_released": released}})

    # #465-1 fixed: the refusal says unsettled, not opt_in_store ...
    assert "opt_in_unsettled" in response["refused"]["detail"]
    # ... the store still reads granted N+1 (never inferred away) ...
    assert view["generation"] == 5 and view["status"] == "granted" and view["permits"]
    # ... but no other process can send: entryd holds the gate exclusively.
    assert sent["calls"] == 0 and sent["refusal"] == "opt_in_unavailable"
    assert status["unsettled"] is True and status["status"] == "unavailable"
    assert "opt_in_unsettled" in again["refused"]["detail"]
    assert gate_free_while_unsettled is False
    # After the retry: closed, no send, and the gate is released.
    assert after_view["status"] == "withdrawn" and not after_view["permits"]
    assert after_sent["calls"] == 0 and after_sent["refusal"] == "opt_in_not_granted"
    assert released is True and service._unsettled is None


def test_r2_a_sender_cannot_take_the_gate_while_entryd_holds_it(service, monkeypatch):
    first_three(service)
    state = runtime_paths.mio_state_dir()
    held = {}

    def sender_during_publication(record):
        # The grant is published and entryd holds the gate: the sender runs now.
        held["in_flight"] = send_in_new_process(state, record.generation)

    inject_publish_then_fail(service, monkeypatch, after_publish=sender_during_publication)
    real_withdraw = service.consent.withdraw
    drained = {}

    def withdraw(reason, **kw):
        record, ok = real_withdraw(reason, **kw)
        drained.update(drained=ok, withdrawn_generation=record.generation,
                       gate_held_kw=kw.get("gate_held", False))
        return record, ok

    monkeypatch.setattr(service.consent, "withdraw", withdraw)
    response = refusal_of(service, LAST)
    view = store_view(state)
    new = send_in_new_process(state, 5)
    dump("after-R2.json", {
        "case": "R2", "set_response": response, "store_after_response": view,
        "withdraw": drained, "in_flight_sender": held["in_flight"],
        "new_sender_with_N_plus_1_envelope": new,
        "gate_released": gate_free(state)})

    assert "opt_in_store" in response["refused"]["detail"]
    assert view["status"] == "withdrawn" and not view["permits"]
    # #465-2 fixed: the sender that arrived during publication is refused.
    assert held["in_flight"]["calls"] == 0
    assert held["in_flight"]["refusal"] == "opt_in_unavailable"
    assert drained["drained"] is True and drained["gate_held_kw"] is True
    assert new["calls"] == 0 and new["refusal"] == "opt_in_not_granted"
    assert gate_free(state)


def test_control_normal_confirmed_set_is_sent_once(service):
    for prerequisite in PREREQUISITES:
        reply = set_prerequisite(service, prerequisite)
    state = runtime_paths.mio_state_dir()
    sent = send_in_new_process(state, reply["generation"])
    dump("after-controls.json", {"granted": {
        "reply": reply, "send": sent, "gate_released": gate_free(state)}}, merge=True)
    assert reply["status"] == "granted" and "unsettled" not in reply
    assert sent["calls"] == 1 and sent["refusal"] is None
    assert gate_free(state)


def test_control_pending_before_audit_sends_zero(service, monkeypatch):
    first_three(service)
    real = service.router._record

    def record(event, **kw):
        if event.get("event_type") == "mio.remote.opt_in":
            raise AuditChainBroken("fixture")
        return real(event, **kw)

    monkeypatch.setattr(service.router, "_record", record)
    monkeypatch.setattr(service.consent, "withdraw",
                        lambda *a, **k: (_ for _ in ()).throw(ConsentRefused("busy")))
    with pytest.raises(entry.RequestRefused):
        set_prerequisite(service, LAST)
    state = runtime_paths.mio_state_dir()
    view = store_view(state)
    results = [send_in_new_process(state, g)
               for g in (view["generation"], view["generation"] + 1)]
    dump("after-controls.json", {"pending": {"store": view, "sends": results}}, merge=True)
    assert view["status"] == "unconfirmed" and not view["permits"]
    assert all(r["calls"] == 0 and r["refusal"] == "opt_in_not_granted" for r in results)


# -- unit tests ---------------------------------------------------------------

def test_a_busy_gate_means_no_confirm_and_a_pending_refusal(service, monkeypatch):
    first_three(service)
    service.opt_in_gate_wait_s = 0.1
    state = runtime_paths.mio_state_dir()
    called = []
    real_confirm = service.consent.confirm
    monkeypatch.setattr(service.consent, "confirm",
                        lambda *a, **kw: called.append(1) or real_confirm(*a, **kw))
    sender = ConsentStore(state)
    # Set the three more so the gate file exists, then occupy it as a sender.
    with sender.send_gate() as gated:
        assert gated.generation is not None
        response = refusal_of(service, LAST)
    assert "opt_in_store" in response["refused"]["detail"]
    assert called == []
    view = store_view(state)
    assert view["status"] == "unconfirmed" and not view["permits"]
    assert service._unsettled is None and gate_free(state)


def test_an_unsettled_grant_is_withdrawn_without_a_drain_by_the_verb(service, monkeypatch):
    first_three(service)
    state = runtime_paths.mio_state_dir()
    fail = {"withdraw": True}
    inject_publish_then_fail(service, monkeypatch)
    real_withdraw = service.consent.withdraw

    def withdraw(*a, **kw):
        if fail["withdraw"]:
            raise OSError(5, "fixture")
        return real_withdraw(*a, **kw)

    monkeypatch.setattr(service.consent, "withdraw", withdraw)
    assert "opt_in_unsettled" in refusal_of(service, LAST)["refused"]["detail"]
    service.consent._drain_timeout_s = 0.2  # a drain would meet our own lock
    fail["withdraw"] = False
    reply = call(service, entry.OPT_IN_WITHDRAW_VERB, reason="operator_request")
    assert reply["status"] == "withdrawn" and reply["drained"] is True
    assert service._unsettled is None and gate_free(state)
    assert "unsettled" not in call(service, entry.OPT_IN_STATUS_VERB)


def test_a_failed_retry_keeps_the_gate_and_the_state(service, monkeypatch):
    first_three(service)
    state = runtime_paths.mio_state_dir()
    inject_publish_then_fail(service, monkeypatch)
    monkeypatch.setattr(service.consent, "withdraw",
                        lambda *a, **kw: (_ for _ in ()).throw(ConsentRefused("busy")))
    refusal_of(service, LAST)
    for _ in range(3):
        service.settle_opt_in()
        assert service._unsettled is not None and not gate_free(state)
        assert store_view(state)["permits"]  # read as granted, not inferred closed


def test_store_withdraw_with_the_gate_held_skips_the_drain(tmp_path):
    state = tmp_path / "s"
    state.mkdir(mode=0o700)
    store = ConsentStore(state, owner=os.geteuid(), drain_timeout_s=0.2)
    for prerequisite in PREREQUISITES:
        store.set_prerequisite(prerequisite, operator="uid:1")
    store.confirm(store.reading().generation, operator="uid:1")
    hold = store.hold_gate_exclusive(0.2)
    with pytest.raises(ConsentRefused):
        ConsentStore(state, owner=os.geteuid()).hold_gate_exclusive(0.05)
    assert store.withdraw("operator_request", operator="uid:1", gate_held=True)[1] is True
    hold.release()
    assert hold.held is False
    assert gate_free(state)
