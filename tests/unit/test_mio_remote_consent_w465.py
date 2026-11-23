"""#465 after the fix: a refused `set` leaves no valid send, and an unsettled
grant is held shut by entryd. Real subprocesses over the on-disk store (the
reader runs the real `RemoteInferenceService.handle`), plus unit tests of the
new store API and of the unsettled state.

Observations are written to $W465_OUT (default u71/out/w10) as
after4-R1.json, after-R2.json and after-controls.json. Order across processes
uses files and FIFOs; the only injected durations are gate-wait bounds.
"""

from __future__ import annotations

import json
import os
import select
import stat
import sys
import signal
import time
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


def serve_once(service, monkeypatch, verb, arguments):
    """One request through the transport's serve_connection: the bytes a client
    would read from the socket."""
    import socket as _socket

    from azazel_nexus_runtime import transport
    from azazel_nexus_runtime.principal import PrincipalPolicy

    monkeypatch.setattr(transport, "peer_credentials", lambda c: (1, os.getuid(), os.getgid()))
    monkeypatch.setattr(transport, "peer_supplementary_groups", lambda c: ())
    engine = transport.SocketServer(
        registry=entry.REGISTRY, policy=PrincipalPolicy(os.getgid(), frozenset()),
        audit=service.record_refusal)
    left, right = _socket.socketpair()
    with left, right:
        transport.send_frame(left, {"verb": verb, "arguments": arguments})
        left.shutdown(_socket.SHUT_WR)
        engine.serve_connection(right, service.handle)
        right.shutdown(_socket.SHUT_WR)
        return json.loads(transport.read_frame(left))


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


FIFO_WAIT_S = 30.0


def read_notice(path, child):
    """The child's one-byte notice, with a deadline (never an open that blocks)."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        ready, _, _ = select.select([fd], [], [], FIFO_WAIT_S)
        assert ready, "no notice from the sender: " + (
            child.stderr.read() if child.poll() is not None else "still running")
        assert os.read(fd, 1) == b"1"
    finally:
        os.close(fd)


def write_release(path):
    deadline = time.monotonic() + FIFO_WAIT_S
    while True:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
            break
        except OSError:  # ENXIO: the reader is not open yet
            assert time.monotonic() < deadline, "the sender never waited for its release"
            time.sleep(0.01)
    try:
        assert os.write(fd, b"1") == 1
    finally:
        os.close(fd)


def reads_fail(service, monkeypatch, flag):
    """`reading()` hits EIO in `_read_at` while `flag["eio"]` is set (and only
    for the reads `reading()` makes: a write's own read-back still works, so the
    implementation's decisions, not the fixture, decide what is evaluated).
    `flag["once"]` makes it a single failure."""
    real = service.consent._read_at

    def read_at(leaf):
        if flag.get("eio") and sys._getframe(1).f_code.co_name == "reading":
            if flag.get("once"):
                flag["eio"] = False
            raise OSError(5, "fixture: EIO reading the record")
        return real(leaf)

    monkeypatch.setattr(service.consent, "_read_at", read_at)


def make_unsettled(service, monkeypatch):
    """Faults that leave a confirmed grant unsettled: after the seal is removed
    the re-read fails (EIO), and neither closing write (withdraw, re-seal)
    works. Clear `withdraw` / `seal` / `eio` to let a retry through."""
    faults = {"withdraw": True, "seal": True, "eio": False, "seals": 0}
    real = {n: getattr(service.consent, n)
            for n in ("withdraw", "seal", "unseal")}

    def unseal():
        real["unseal"]()
        faults["eio"] = True

    def seal(generation):
        faults["seals"] += 1
        if faults["seals"] > 1 and faults["seal"]:
            raise OSError(5, "fixture: seal write")
        return real["seal"](generation)

    def withdraw(*a, **kw):
        if faults["withdraw"]:
            raise ConsentRefused("fixture: withdraw busy")
        return real["withdraw"](*a, **kw)

    monkeypatch.setattr(service.consent, "unseal", unseal)
    monkeypatch.setattr(service.consent, "seal", seal)
    monkeypatch.setattr(service.consent, "withdraw", withdraw)
    reads_fail(service, monkeypatch, faults)
    return faults


UNSETTLED = {"status": "unsettled", "generation": None, "granted": [],
             "missing": [p.value for p in PREREQUISITES],
             "may_be_in_force_generation": 5}


def inject_dir_fsync_failures(monkeypatch, armed):
    """The directory fsync after a rename fails with EIO *without running*
    (the record is visible but not known to be durable). `armed["n"]` failures
    remain; 0 is off."""
    real = os.fsync

    def fsync(fd):
        if armed["n"] > 0 and stat.S_ISDIR(os.fstat(fd).st_mode):
            armed["n"] -= 1
            armed["failed"] += 1
            # Not executed: the rename is visible, its directory is not synced.
            raise OSError(5, "fixture: directory fsync after rename")
        real(fd)

    monkeypatch.setattr(os, "fsync", fsync)


def inject_publish_then_fail(service, monkeypatch, after_publish=None):
    """confirm: the real `confirm` renames N+1 into place, then the directory
    fsync it calls fails with EIO without running (after_publish runs at that
    point, with the grant visible)."""
    real_confirm = service.consent.confirm
    real_fsync = os.fsync
    seen = {"published": None, "armed": False}

    def fsync(fd):
        if seen["armed"] and stat.S_ISDIR(os.fstat(fd).st_mode):
            seen["armed"] = False
            seen["published"] = seen["opens"]
            if after_publish is not None:
                after_publish(seen["opens"])
            raise OSError(5, "fixture: directory fsync after rename")
        real_fsync(fd)

    def confirm(generation, *, operator):
        seen.update(armed=True, opens=generation + 1)
        try:
            return real_confirm(generation, operator=operator)
        finally:
            seen["armed"] = False

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(service.consent, "confirm", confirm)
    return seen


def set_last_by_socket(service, monkeypatch):
    return serve_once(service, monkeypatch, "mio.remote.opt_in.set",
                      {"prerequisite": LAST.value})


def test_r1_triple_fault_is_closed_by_the_seal(service, monkeypatch):
    first_three(service)
    reads = {"eio": False}
    inject_publish_then_fail(service, monkeypatch,
                             after_publish=lambda g: reads.update(eio=True))
    reads_fail(service, monkeypatch, reads)
    monkeypatch.setattr(service.consent, "withdraw",
                        lambda *a, **kw: (_ for _ in ()).throw(ConsentRefused("busy")))
    response = set_last_by_socket(service, monkeypatch)
    state = runtime_paths.mio_state_dir()
    view = store_view(state)
    sent = send_in_new_process(state, 5)
    dump("after4-R1.json", {
        "case": "R1 (confirm published then fails, withdraw fails, re-read EIO)",
        "set_response_on_socket": response, "store_after": view,
        "send_other_process": sent, "gate_free": gate_free(state)}, merge=True)
    assert response == {"ok": False, "refusal": "verb_unavailable"}
    # #465-1 fixed: N+1 is published, but sealed, so it reads closed.
    assert view == {"generation": 5, "status": "unconfirmed", "permits": False}
    assert sent["calls"] == 0 and sent["refusal"] == "opt_in_not_granted"
    assert gate_free(state)


def test_r1_unsettled_is_a_reading_on_the_socket_and_is_gated_then_settled(
        service, monkeypatch):
    first_three(service)
    state = runtime_paths.mio_state_dir()
    faults = make_unsettled(service, monkeypatch)
    response = set_last_by_socket(service, monkeypatch)
    status = serve_once(service, monkeypatch, "mio.remote.opt_in.status", {})
    view = store_view(state)  # a fresh store: granted N+1, the seal is gone
    sent = send_in_new_process(state, 5)
    again = serve_once(service, monkeypatch, "mio.remote.opt_in.set",
                       {"prerequisite": PREREQUISITES[0].value})
    free_while_unsettled = gate_free(state)

    faults.update(withdraw=False, seal=False, eio=False)
    service.settle_opt_in()  # what a tick does
    after = store_view(state)
    after_sent = send_in_new_process(state, 5)
    dump("after4-R1.json", {"unsettled": {
        "set_response_on_socket": response, "status_on_socket": status,
        "set_while_unsettled": again, "store_while_unsettled": view,
        "send_other_process": sent, "gate_free_while_unsettled": free_while_unsettled,
        "after_retry": {"store": after, "send": after_sent,
                        "gate_free": gate_free(state)}}}, merge=True)
    assert response == {"ok": True, "result": UNSETTLED}
    assert status == {"ok": True, "result": UNSETTLED}
    assert again == {"ok": False, "refusal": "verb_unavailable"}
    assert view["permits"] and view["generation"] == 5  # the store itself reads open
    assert sent["calls"] == 0 and sent["refusal"] == "opt_in_unavailable"  # the gate
    assert free_while_unsettled is False
    assert after["status"] == "withdrawn" and not after["permits"]
    assert after_sent["calls"] == 0 and after_sent["refusal"] == "opt_in_not_granted"
    assert gate_free(state) and service._unsettled is None


def test_r1d_after_the_seal_is_gone_a_read_is_not_a_ground_to_refuse(
        service, monkeypatch):
    # The re-read fails once; the withdrawal renames, then its directory fsync
    # fails (visible, not known durable). A read would say closed. The refusal
    # must wait for a confirmed write: here the re-seal.
    first_three(service)
    state = runtime_paths.mio_state_dir()
    armed = {"n": 0, "failed": 0}
    inject_dir_fsync_failures(monkeypatch, armed)
    seals = []
    real_seal, real_unseal = service.consent.seal, service.consent.unseal
    eio = {"eio": False, "once": True}
    reads_fail(service, monkeypatch, eio)

    def unseal():
        real_unseal()
        armed["n"] = 1  # the next directory fsync is the withdrawal's
        eio["eio"] = True

    monkeypatch.setattr(service.consent, "unseal", unseal)
    monkeypatch.setattr(service.consent, "seal",
                        lambda g: (seals.append(g), real_seal(g))[1])
    response = set_last_by_socket(service, monkeypatch)
    view = store_view(state)
    sent = send_in_new_process(state, 5)
    dump("after4-R1.json", {"dir_fsync_after_withdraw_rename": {
        "set_response_on_socket": response, "dir_fsync_failures": armed["failed"],
        "seal_calls": seals, "store_after": view, "send_other_process": sent,
        "seal_present": _seal_path(state).exists(), "gate_free": gate_free(state)}},
        merge=True)
    assert response == {"ok": False, "refusal": "verb_unavailable"}
    assert armed["failed"] == 1
    assert seals == [5, 5]  # sealed, then re-sealed: ground (c), not a read
    assert _seal_path(state).exists()
    assert sent["calls"] == 0 and view["permits"] is False
    assert gate_free(state) and service._unsettled is None


def test_r1e_dir_fsync_always_failing_leaves_the_grant_unsettled_and_gated(
        service, monkeypatch):
    first_three(service)
    state = runtime_paths.mio_state_dir()
    armed = {"n": 0, "failed": 0}
    inject_dir_fsync_failures(monkeypatch, armed)
    real_unseal = service.consent.unseal
    eio = {"eio": False, "once": True}
    reads_fail(service, monkeypatch, eio)

    def unseal():
        real_unseal()
        armed["n"] = 10 ** 6
        eio["eio"] = True

    monkeypatch.setattr(service.consent, "unseal", unseal)
    response = set_last_by_socket(service, monkeypatch)
    # Visible records read closed from now on, but nothing is confirmed durable.
    for _ in range(3):
        service.settle_opt_in()
        assert service._unsettled is not None and not gate_free(state)
    held_while_failing = service._unsettled is not None
    armed["n"] = 0
    service.settle_opt_in()  # a confirmed write: the gate goes
    dump("after4-R1.json", {"dir_fsync_always_fails": {
        "set_response_on_socket": response, "dir_fsync_failures": armed["failed"],
        "gate_held_across_retries": held_while_failing,
        "released_after_a_confirmed_write": service._unsettled is None,
        "store_after": store_view(state)}}, merge=True)
    # The visible withdrawn record is generation 6; N+1 = 5 may be in force.
    assert response == {"ok": True, "result": {**UNSETTLED, "generation": 6}}
    assert service._unsettled is None and gate_free(state)


def test_r2_a_sender_during_publication_reads_the_seal(service, monkeypatch):
    first_three(service)
    state = runtime_paths.mio_state_dir()
    held = {}
    inject_publish_then_fail(
        service, monkeypatch,
        after_publish=lambda generation: held.update(
            in_flight=send_in_new_process(state, generation)))
    real_withdraw = service.consent.withdraw
    withdrawn = {}

    def withdraw(reason, **kw):
        record, ok = real_withdraw(reason, **kw)
        withdrawn.update(drained=ok, generation=record.generation,
                         drain_requested=kw.get("drain", True))
        return record, ok

    monkeypatch.setattr(service.consent, "withdraw", withdraw)
    response = set_last_by_socket(service, monkeypatch)
    view = store_view(state)
    new = send_in_new_process(state, 5)
    dump("after4-R2.json", {"during_publication": {
        "set_response_on_socket": response, "store_after_response": view,
        "withdraw": withdrawn, "in_flight_sender": held["in_flight"],
        "new_sender_with_N_plus_1_envelope": new, "gate_free": gate_free(state)}},
        merge=True)
    assert response == {"ok": False, "refusal": "verb_unavailable"}
    assert view["status"] == "withdrawn" and not view["permits"]
    # #465-2 fixed: the sender that arrived during publication reads it sealed.
    assert held["in_flight"]["calls"] == 0
    assert held["in_flight"]["refusal"] == "opt_in_not_granted"
    assert withdrawn["drain_requested"] is False and withdrawn["drained"] is True
    assert new["calls"] == 0 and new["refusal"] == "opt_in_not_granted"


def test_r2a_a_real_sender_held_after_its_read_times_the_gate_out(
        service, monkeypatch, tmp_path):
    for prerequisite in PREREQUISITES:
        set_prerequisite(service, prerequisite)  # granted, generation 5
    service.opt_in_gate_wait_s = 0.3  # the injected bound
    state = runtime_paths.mio_state_dir()
    reached, release = tmp_path / "reached.fifo", tmp_path / "release.fifo"
    os.mkfifo(reached)
    os.mkfifo(release)
    sender = subprocess.Popen(
        [sys.executable, str(HERE / "_mio_remote_consent_w465_child.py"), "hold",
         str(state), "5", str(reached), str(release)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=_env())
    try:
        read_notice(reached, sender)
        # The sender holds the gate shared, having read generation 5 granted.
        response = serve_once(service, monkeypatch, "mio.remote.opt_in.set",
                              {"prerequisite": PREREQUISITES[0].value})
        view = store_view(state)
        new = send_in_new_process(state, 7)  # N+1 of the set that was refused
        write_release(release)
        out, _ = sender.communicate(timeout=60)
        resumed = json.loads(out.strip().splitlines()[-1])
    finally:
        if sender.poll() is None:
            sender.kill()
            sender.wait(timeout=10)
    dump("after4-R2.json", {"real_sender_held_at_old_generation": {
        "set_response_on_socket": response, "store_after_response": view,
        "new_sender_with_N_plus_1_envelope": new,
        "resumed_sender_old_generation_5": resumed,
        "gate_free_after": gate_free(state)}}, merge=True)
    assert response == {"ok": False, "refusal": "verb_unavailable"}
    assert view["status"] == "withdrawn" and not view["permits"]
    # No send on N+1 (the seal, then the withdrawal) ...
    assert new["calls"] == 0 and new["refusal"] == "opt_in_not_granted"
    # ... and the sender that had read the old grant before the set sends once:
    # that grant was in force when it read it, not the one this set refused.
    assert resumed["calls"] == 1 and resumed["refusal"] is None


def test_r2b_a_normal_withdraw_with_a_held_old_sender_says_drained_false(
        service, monkeypatch, tmp_path):
    for prerequisite in PREREQUISITES:
        set_prerequisite(service, prerequisite)  # granted, generation 5
    service.consent._drain_timeout_s = 0.3  # the injected bound
    state = runtime_paths.mio_state_dir()
    reached, release = tmp_path / "reached.fifo", tmp_path / "release.fifo"
    os.mkfifo(reached)
    os.mkfifo(release)
    sender = subprocess.Popen(
        [sys.executable, str(HERE / "_mio_remote_consent_w465_child.py"), "hold",
         str(state), "5", str(reached), str(release)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=_env())
    try:
        read_notice(reached, sender)
        reply = serve_once(service, monkeypatch, "mio.remote.opt_in.withdraw",
                           {"reason": "operator_request"})
        view = store_view(state)
        write_release(release)
        out, _ = sender.communicate(timeout=60)
        resumed = json.loads(out.strip().splitlines()[-1])
    finally:
        if sender.poll() is None:
            sender.kill()
            sender.wait(timeout=10)
    dump("after4-R2.json", {"normal_withdraw_with_a_held_old_sender": {
        "withdraw_response_on_socket": reply, "store_after_response": view,
        "resumed_sender_old_generation_5": resumed}}, merge=True)
    assert reply["ok"] is True and reply["result"]["status"] == "withdrawn"
    assert reply["result"]["drained"] is False  # a sender may still be in flight
    assert view["status"] == "withdrawn"
    assert resumed["calls"] == 1  # it read the grant before the withdrawal


def _run_fault_child(tmp_path, mode):
    root, ready = tmp_path / "root", tmp_path / "ready"
    root.mkdir()
    child = subprocess.Popen(
        [sys.executable, str(HERE / "_mio_remote_consent_w465_child.py"),
         "faultset", str(root), str(ready), mode],
        env=_env(), stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 60
        while not ready.exists():
            assert child.poll() is None, child.stderr.read().decode()
            assert time.monotonic() < deadline, "the set never replied"
            time.sleep(0.02)
        result = json.loads(ready.read_text())
        child.send_signal(signal.SIGKILL)  # after the reply, before anything else
        child.wait(timeout=10)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        child.stderr.close()
    assert child.returncode == -signal.SIGKILL
    return result


def test_r1b_a_refused_set_killed_after_its_reply_leaves_no_send(tmp_path):
    result = _run_fault_child(tmp_path, "confirm_fails")
    state = Path(result["state"])
    view = store_view(state)
    sent = send_in_new_process(state, view["generation"])
    dump("after4-R1.json", {"sigkill_after_refusal": {
        "set_response": result["refused"], "store_after_kill": view,
        "send_other_process": sent}}, merge=True)
    assert "opt_in_store" in result["refused"]
    assert view == {"generation": 5, "status": "unconfirmed", "permits": False}
    assert sent["calls"] == 0 and sent["refusal"] == "opt_in_not_granted"


def test_r1c_the_remaining_limit_unsettled_then_killed_can_send(tmp_path):
    # The one case left open (documented): the seal was removed, the read back
    # and the narrowing both failed, and entryd ended. The OS drops its gate,
    # and the published, recorded N+1 reads granted.
    result = _run_fault_child(tmp_path, "unsettled")
    state = Path(result["state"])
    view = store_view(state)
    sent = send_in_new_process(state, view["generation"])
    dump("after4-R1.json", {"remaining_limit_unsettled_then_sigkill": {
        "set_response": result["returned"], "store_after_kill": view,
        "send_other_process": sent}}, merge=True)
    # `unsettled` means: generation 5 may already be in force. It stops sends
    # while entryd runs; once entryd ends, it can be sent on (the sender below).
    assert result["returned"]["status"] == "unsettled"
    assert result["returned"]["may_be_in_force_generation"] == 5
    assert view == {"generation": 5, "status": "granted", "permits": True}
    assert sent["calls"] == 1


def test_control_normal_confirmed_set_is_sent_once(service, monkeypatch):
    for prerequisite in list(PREREQUISITES)[:-1]:
        set_prerequisite(service, prerequisite)
    reply = serve_once(service, monkeypatch, "mio.remote.opt_in.set",
                       {"prerequisite": LAST.value})
    state = runtime_paths.mio_state_dir()
    sent = send_in_new_process(state, 5)
    dump("after4-controls.json", {"granted": {
        "reply": reply, "send": sent, "gate_free": gate_free(state),
        "seal_present": (state / "remote-consent" / "send.seal").exists()}}, merge=True)
    assert reply["result"]["status"] == "granted" and reply["result"]["generation"] == 5
    assert sent["calls"] == 1 and sent["refusal"] is None
    assert gate_free(state) and not (state / "remote-consent" / "send.seal").exists()


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
    dump("after4-controls.json", {"pending": {"store": view, "sends": results}}, merge=True)
    assert view["status"] == "unconfirmed" and not view["permits"]
    assert all(r["calls"] == 0 and r["refusal"] == "opt_in_not_granted" for r in results)


# -- unit tests ---------------------------------------------------------------

def _seal_path(state):
    return state / "remote-consent" / "send.seal"


def test_the_seal_closes_a_granted_record_at_or_below_it_for_every_reader(tmp_path):
    state = tmp_path / "s"
    state.mkdir(mode=0o700)
    store = ConsentStore(state, owner=os.geteuid())
    for prerequisite in PREREQUISITES:
        store.set_prerequisite(prerequisite, operator="uid:1")
    store.confirm(4, operator="uid:1")
    assert store.reading().permits
    store.seal(5)
    for reader in (store, ConsentStore(state, owner=os.geteuid())):
        reading = reader.reading()
        assert reading.status == "unconfirmed" and not reading.permits
        with reader.send_gate() as gated:
            assert gated.status == "unconfirmed" and not gated.permits
    store.seal(4)  # a seal below the record closes nothing
    assert ConsentStore(state, owner=os.geteuid()).reading().permits
    store.seal(5)
    store.unseal()
    assert not _seal_path(state).exists() and store.reading().permits


@pytest.mark.parametrize("damage", [b"{", b"", b'{"schema":"x","generation":5}',
                                    b'{"generation":5,"schema":"azazel-nexus/mio-remote-opt-in-seal/v1","x":1}'])
def test_a_seal_that_exists_but_cannot_be_read_is_unavailable(tmp_path, damage):
    state = tmp_path / "s"
    state.mkdir(mode=0o700)
    store = ConsentStore(state, owner=os.geteuid())
    for prerequisite in PREREQUISITES:
        store.set_prerequisite(prerequisite, operator="uid:1")
    store.confirm(4, operator="uid:1")
    _seal_path(state).write_bytes(damage)
    _seal_path(state).chmod(0o600)
    other = ConsentStore(state, owner=os.geteuid())
    assert other.reading().status == "unavailable"
    with other.send_gate() as gated:
        assert gated.status == "unavailable" and not gated.permits


def test_a_seal_that_cannot_be_written_means_no_confirm(service, monkeypatch):
    first_three(service)
    called = []
    real_confirm = service.consent.confirm
    monkeypatch.setattr(service.consent, "confirm",
                        lambda *a, **kw: called.append(1) or real_confirm(*a, **kw))
    monkeypatch.setattr(service.consent, "seal",
                        lambda g: (_ for _ in ()).throw(OSError(5, "fixture")))
    with pytest.raises(entry.RequestRefused):
        set_prerequisite(service, LAST)
    assert called == []
    view = store_view(runtime_paths.mio_state_dir())
    assert view["status"] == "unconfirmed" and not view["permits"]


def test_a_busy_gate_leaves_the_seal_and_withdraws_without_a_drain(service, monkeypatch):
    first_three(service)
    service.opt_in_gate_wait_s = 0.1
    state = runtime_paths.mio_state_dir()
    drains = []
    monkeypatch.setattr(service.consent, "_drain", lambda: drains.append(1) or True)
    sender = ConsentStore(state)
    with sender.send_gate():
        # The gate file does not exist before the first confirm; make it so.
        pass
    with sender.send_gate() as gated:
        assert gated.generation is not None
        response = refusal_of(service, LAST)
    assert "opt_in_store" in response["refused"]["detail"]
    assert drains == []
    view = store_view(state)
    assert view["status"] == "withdrawn" and not view["permits"]
    assert _seal_path(state).exists()  # left in place: closed whatever happens
    assert service._unsettled is None and gate_free(state)


def test_the_withdraw_verb_on_an_unsettled_grant_skips_the_drain_then_releases(
        service, monkeypatch):
    first_three(service)
    state = runtime_paths.mio_state_dir()
    faults = make_unsettled(service, monkeypatch)
    assert set_prerequisite(service, LAST)["status"] == "unsettled"
    drains = []
    monkeypatch.setattr(service.consent, "_drain", lambda: drains.append(1) or False)
    faults.update(withdraw=False, seal=False)  # eio stays: reads still fail
    # The operator's withdrawal comes first (no automatic settle before it).
    reply = call(service, entry.OPT_IN_WITHDRAW_VERB, reason="operator_request")
    # Written and read back, so the gate goes even though a read still fails.
    assert reply["drained"] is True and reply["status"] == "unavailable"
    assert drains == []
    assert store_view(state)["status"] == "withdrawn"
    assert service._unsettled is None and gate_free(state)
    faults["eio"] = False
    assert call(service, entry.OPT_IN_STATUS_VERB)["status"] == "withdrawn"


def test_a_failed_retry_keeps_the_gate_and_the_state(service, monkeypatch):
    first_three(service)
    state = runtime_paths.mio_state_dir()
    make_unsettled(service, monkeypatch)
    reply = set_prerequisite(service, LAST)
    assert reply["status"] == "unsettled" and reply["may_be_in_force_generation"] == 5
    for _ in range(3):
        service.settle_opt_in()
        assert service._unsettled is not None and not gate_free(state)
        again = call(service, entry.OPT_IN_STATUS_VERB)
        assert again["status"] == "unsettled"
        assert again["may_be_in_force_generation"] == 5
    assert store_view(state)["permits"]  # the store reads open; never inferred closed


def test_settle_releases_only_on_a_confirmed_write_not_on_a_read(service, monkeypatch):
    first_three(service)
    state = runtime_paths.mio_state_dir()
    faults = make_unsettled(service, monkeypatch)
    assert set_prerequisite(service, LAST)["status"] == "unsettled"
    # Reads now say closed (a withdrawn record is visible) ...
    real_withdraw = ConsentStore.withdraw
    faults["eio"] = False
    ConsentStore(state, owner=os.geteuid()).withdraw  # a separate store object
    real_withdraw(service.consent, "operator_request", operator="uid:1", drain=False)
    assert store_view(state)["status"] == "withdrawn"
    # ... but neither closing write of entryd is confirmed: the gate stays.
    service.settle_opt_in()
    assert service._unsettled is not None and not gate_free(state)
    faults["seal"] = False  # a re-seal now succeeds (ground c)
    service.settle_opt_in()
    assert service._unsettled is None and gate_free(state)


def test_an_unexpected_error_after_the_gate_is_taken_never_loses_the_gate(
        service, monkeypatch):
    first_three(service)
    state = runtime_paths.mio_state_dir()
    real_withdraw, real_unseal = service.consent.withdraw, service.consent.unseal
    monkeypatch.setattr(service.consent, "unseal",
                        lambda: (_ for _ in ()).throw(RuntimeError("fixture")))
    monkeypatch.setattr(service.consent, "withdraw",
                        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("fixture")))
    with pytest.raises(RuntimeError):
        set_prerequisite(service, LAST)
    assert service._unsettled is not None and not gate_free(state)
    monkeypatch.setattr(service.consent, "withdraw", real_withdraw)
    monkeypatch.setattr(service.consent, "unseal", real_unseal)
    service.settle_opt_in()  # the seal is still there: closed, so the gate goes
    assert service._unsettled is None and gate_free(state)


def test_a_failure_taking_the_gate_leaks_no_descriptor(tmp_path, monkeypatch):
    state = tmp_path / "s"
    state.mkdir(mode=0o700)
    store = ConsentStore(state, owner=os.geteuid())
    store.set_prerequisite(PREREQUISITES[0], operator="uid:1")
    before = len(os.listdir("/dev/fd"))
    real = store._gate_fd

    def failing(leaf, *, create):
        fd = real(leaf, create=create)
        os.close(fd)
        raise OSError(5, "fixture")

    monkeypatch.setattr(store, "_gate_fd", failing)
    with pytest.raises(OSError):
        store.hold_gate_exclusive(0.1)
    busy = ConsentStore(state, owner=os.geteuid())
    monkeypatch.undo()
    with busy.send_gate():
        with pytest.raises(ConsentRefused):
            store.hold_gate_exclusive(0.05)
    assert len(os.listdir("/dev/fd")) == before


def test_store_withdraw_without_a_drain_does_not_wait(tmp_path):
    state = tmp_path / "s"
    state.mkdir(mode=0o700)
    store = ConsentStore(state, owner=os.geteuid(), drain_timeout_s=0.2)
    for prerequisite in PREREQUISITES:
        store.set_prerequisite(prerequisite, operator="uid:1")
    store.confirm(4, operator="uid:1")
    hold = store.hold_gate_exclusive(0.2)
    assert store.withdraw("operator_request", operator="uid:1", drain=False)[1] is True
    hold.release()
    assert hold.held is False and gate_free(state)
