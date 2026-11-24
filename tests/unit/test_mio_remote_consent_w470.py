"""#470 (plan C): `mio.remote.opt_in.set` names the generation the caller confirmed.

The generation is compared with the record read under the store's write lock,
in the same exclusive section as the write, so a `set` sent before a
`withdraw` and handled after it is refused and counts for nothing. entryd also
compares early, before it writes the `set` ledger line, so a refused set adds
no audit line. A set without the argument is refused by the transport.

Real processes: the stalled set is the real `MioEntryService` of a child; the
withdrawal is made by the parent process; the sender is a third process. Order
is made with FIFOs; nothing is timed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import mio_entryd as entry
from azazel_nexus_runtime import mio_remote_consent as mc
from azazel_nexus_runtime import mio_socket_client as client
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.mio_remote_consent import ConsentStore
from azazel_nexus_runtime.principal import Principal, PrincipalClass

from azazel_nexus.mio_profile import PREREQUISITES
from azazel_nexus.route_ledger import RouteChain

import test_mio_remote_consent_w465 as w465

HERE = Path(__file__).resolve().parent
OPERATOR = Principal(1001, 1001, 1, frozenset({PrincipalClass.OPERATOR}))
LAST = list(PREREQUISITES)[-1]
SET = "mio.remote.opt_in.set"
REFUSED = {"ok": False, "refusal": "verb_unavailable"}


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    runtime_paths.mio_state_dir().mkdir(parents=True)
    runtime_paths.mio_state_dir().chmod(0o700)
    return entry.MioEntryService()


def handle(service, verb, **arguments):
    return service.handle(SimpleNamespace(verb=verb, arguments=arguments, principal=OPERATOR))


def status(service):
    return handle(service, entry.OPT_IN_STATUS_VERB)


def set_one(service, prerequisite, expected):
    return handle(service, entry.OPT_IN_SET_VERB, prerequisite=prerequisite.value,
                  expected_generation=expected)


def set_first_three(service):
    for expected, prerequisite in enumerate(list(PREREQUISITES)[:-1]):
        set_one(service, prerequisite, expected)


def ledger_events(service):
    chain = RouteChain(service.router.ledger.directory)
    chain.verify()
    return [item.event["event_type"] for item in chain]


def wire(service, monkeypatch, verb, **arguments):
    # The per-principal rate limit is not what is measured here.
    service.rate = type("R", (), {"take": lambda self, uid: True})()
    return w465.serve_once(service, monkeypatch, verb, arguments)


def detail_of(service, **arguments):
    with pytest.raises(entry.RequestRefused) as caught:
        handle(service, entry.OPT_IN_SET_VERB, **arguments)
    return caught.value.detail


# -- the argument is required ---------------------------------------------


def test_the_argument_is_declared_a_required_bounded_ordinal():
    arg = {a.name: a for a in entry.OPT_IN_SET_VERB.arguments}["expected_generation"]
    assert arg.kind is entry.ArgumentKind.ORDINAL and arg.maximum == mc._MAX_GENERATION
    assert [a.name for a in entry.OPT_IN_WITHDRAW_VERB.arguments] == ["reason"]
    assert entry.OPT_IN_STATUS_VERB.arguments == ()


def test_a_set_without_a_premise_is_refused_by_the_transport_and_changes_nothing(
        service, monkeypatch):
    set_first_three(service)
    before = (w465.store_view(runtime_paths.mio_state_dir()), ledger_events(service))
    reply = wire(service, monkeypatch, SET, prerequisite=LAST.value)
    assert reply["ok"] is False and reply["refusal"] == "missing_argument"
    for bad, code in ((-1, "argument_range"), (mc._MAX_GENERATION + 1, "argument_range"),
                      ("3", "argument_type"), (True, "argument_type"), (3.0, "argument_type")):
        reply = wire(service, monkeypatch, SET, prerequisite=LAST.value,
                     expected_generation=bad)
        assert reply["ok"] is False and reply["refusal"] == code, (bad, reply)
    assert w465.store_view(runtime_paths.mio_state_dir()) == before[0]
    # Only the transport's own refusal rows were added: no `set` line.
    added = ledger_events(service)[len(before[1]):]
    assert added and set(added) == {"runtime.request_refused"}


def test_the_old_form_is_refused_from_the_first_request_and_audits_nothing(
        service, monkeypatch):
    reply = wire(service, monkeypatch, SET, prerequisite=PREREQUISITES[0].value)
    assert reply["refusal"] == "missing_argument"
    assert status(service)["generation"] == 0
    assert SET not in ledger_events(service)
    assert set(ledger_events(service)) <= {"runtime.request_refused"}


# -- the comparison -------------------------------------------------------


def test_a_matching_premise_writes_and_each_reply_names_the_next_premise(service):
    """One `status`, then four `set`s, each naming what the last reply said."""
    generation = status(service)["generation"]
    assert generation == 0
    for prerequisite in PREREQUISITES:
        reply = set_one(service, prerequisite, generation)
        generation = reply["generation"]
    assert reply["status"] == "granted" and generation == 5
    assert ledger_events(service).count(SET) == 4


@pytest.mark.parametrize("expected", [0, 1, 4, 5, 10])
def test_a_premise_that_is_not_the_generation_in_force_is_refused_before_any_ledger_line(
        service, expected):
    set_first_three(service)
    events = ledger_events(service)
    before = w465.store_view(runtime_paths.mio_state_dir())
    assert before["generation"] == 3
    detail = detail_of(service, prerequisite=LAST.value, expected_generation=expected)
    assert detail == "opt_in_stale"
    assert w465.store_view(runtime_paths.mio_state_dir()) == before
    assert ledger_events(service) == events  # no marker, no `set`, no `not_committed`


def test_the_refusal_on_the_socket_names_no_generation_and_no_reason(service, monkeypatch):
    set_first_three(service)
    reply = wire(service, monkeypatch, SET, prerequisite=LAST.value, expected_generation=1)
    assert reply == REFUSED


def test_the_comparison_under_the_lock_decides_and_leaves_a_not_committed_line(
        service, monkeypatch):
    """The state moves after the early comparison passed (a withdrawal lands
    between it and the lock). The in-lock comparison refuses, nothing is
    written, and the ledger says the set was not committed."""
    set_first_three(service)
    real = service.consent.set_prerequisite

    def moved(*a, **kw):
        service.consent.withdraw("privacy_review", operator="uid:1001")
        return real(*a, **kw)

    monkeypatch.setattr(service.consent, "set_prerequisite", moved)
    with pytest.raises(entry.RequestRefused) as caught:
        set_one(service, LAST, 3)
    assert caught.value.detail == "opt_in_stale"
    view = w465.store_view(runtime_paths.mio_state_dir())
    assert view == {"generation": 4, "status": "withdrawn", "permits": False}
    tail = ledger_events(service)[-2:]
    assert tail == [SET, "mio.remote.opt_in.not_committed"]


def test_the_store_refuses_a_stale_premise_without_writing(tmp_path):
    store = ConsentStore(tmp_path, owner=os.geteuid())
    store.set_prerequisite(PREREQUISITES[0], operator="uid:1", expected_generation=0)
    for expected in (0, 2, 9):
        with pytest.raises(mc.ConsentStale):
            store.set_prerequisite(PREREQUISITES[1], operator="uid:1",
                                   expected_generation=expected)
    assert store.reading().generation == 1
    for bad in (None, "1", True, -1, 1.0):
        with pytest.raises(mc.ConsentRefused):
            store.set_prerequisite(PREREQUISITES[1], operator="uid:1", expected_generation=bad)
    assert store.reading().generation == 1


def test_a_missing_record_is_generation_zero(tmp_path):
    store = ConsentStore(tmp_path, owner=os.geteuid())
    with pytest.raises(mc.ConsentStale):
        store.set_prerequisite(PREREQUISITES[0], operator="uid:1", expected_generation=1)
    assert store.set_prerequisite(PREREQUISITES[0], operator="uid:1",
                                  expected_generation=0).generation == 1


# -- the generation ceiling -----------------------------------------------


def _at(monkeypatch, tmp_path, ceiling, generations):
    monkeypatch.setattr(mc, "_MAX_GENERATION", ceiling)
    store = ConsentStore(tmp_path, owner=os.geteuid())
    for prerequisite in list(PREREQUISITES)[:generations]:
        store.set_prerequisite(prerequisite, operator="uid:1",
                               expected_generation=store.reading().generation)
    return store


def test_a_withdrawal_at_the_ceiling_writes_the_same_generation_and_a_later_set_is_exhausted(
        monkeypatch, tmp_path):
    store = _at(monkeypatch, tmp_path, 3, 3)
    assert store.reading().generation == 3
    record, _ = store.withdraw("privacy_review", operator="uid:1")
    assert record.generation == 3 and store.reading().status == "withdrawn"
    with pytest.raises(mc.ConsentRefused) as caught:
        store.set_prerequisite(PREREQUISITES[0], operator="uid:1", expected_generation=3)
    assert not isinstance(caught.value, mc.ConsentStale)  # the exhausted judgement
    assert "exhausted" in str(caught.value)
    assert store.reading().status == "withdrawn" and not store.reading().permits


def test_a_completing_set_with_two_generations_left_opens_the_grant(monkeypatch, service):
    monkeypatch.setattr(mc, "_MAX_GENERATION", 5)
    set_first_three(service)
    reply = set_one(service, LAST, 3)  # pending at 4, opens at 5: exactly the room left
    assert reply["status"] == "granted" and reply["generation"] == 5
    assert service.consent.reading().permits is True


def test_a_completing_set_with_one_generation_left_writes_pending_and_its_seal_is_refused(
        monkeypatch, service):
    """Pending (4) is written; opening it needs 5, which is above the ceiling.
    The refusal comes from the open path, not from the premise, and the grant
    is not in force."""
    monkeypatch.setattr(mc, "_MAX_GENERATION", 4)
    set_first_three(service)
    seen = {"seal": [], "confirm": []}
    real_seal, real_confirm = service.consent.seal, service.consent.confirm

    def seal(generation):
        try:
            return real_seal(generation)
        except (mc.ConsentRefused, OSError) as exc:
            seen["seal"].append((generation, str(exc)))
            raise

    def confirm(generation, **kw):
        seen["confirm"].append(generation)
        return real_confirm(generation, **kw)

    monkeypatch.setattr(service.consent, "seal", seal)
    monkeypatch.setattr(service.consent, "confirm", confirm)
    with pytest.raises(entry.RequestRefused) as caught:
        set_one(service, LAST, 3)
    assert caught.value.detail == "opt_in_store"  # not `opt_in_stale`
    events = ledger_events(service)
    assert "mio.remote.opt_in" in events  # the pending record was written and recorded
    view = service.consent.reading()
    # The open path refused at the seal of generation 5, above the ceiling;
    # `confirm` was never reached, and the pending record at 4 stays closed.
    assert seen["seal"] == [(5, "a seal names a bounded positive generation")]
    assert seen["confirm"] == []
    assert view.permits is False and view.status == "unconfirmed" and view.generation == 4


def test_a_withdrawal_that_takes_the_last_generation_after_the_early_comparison_is_exhausted_not_stale(
        monkeypatch, service):
    """Early comparison passes at M-1 (3); a withdrawal then writes M (4, the
    ceiling). The store refuses as exhausted before `make`: detail `opt_in_store`,
    and `not_committed` is recorded."""
    monkeypatch.setattr(mc, "_MAX_GENERATION", 4)
    set_first_three(service)
    real = service.consent.set_prerequisite

    def moved(*a, **kw):
        service.consent.withdraw("privacy_review", operator="uid:1001")
        return real(*a, **kw)

    monkeypatch.setattr(service.consent, "set_prerequisite", moved)
    with pytest.raises(entry.RequestRefused) as caught:
        set_one(service, LAST, 3)
    assert caught.value.detail == "opt_in_store"
    assert w465.store_view(runtime_paths.mio_state_dir()) == {
        "generation": 4, "status": "withdrawn", "permits": False}
    assert ledger_events(service)[-2:] == [SET, "mio.remote.opt_in.not_committed"]


# -- real processes: a set stalled before the comparison ------------------


def _stalled(service, tmp_path, where, expected):
    """A starts the completing set naming `expected` and stops at `where`;
    this process withdraws to the end; then A resumes. Returns what A said and
    what a sender in a third process finds."""
    root = Path(os.environ["AZAZEL_ROOT"])
    state = runtime_paths.mio_state_dir()
    reached, release = tmp_path / "reached.fifo", tmp_path / "release.fifo"
    os.mkfifo(reached)
    os.mkfifo(release)
    stalled = subprocess.Popen(
        [sys.executable, str(HERE / "_mio_remote_consent_w470_child.py"), "stalled",
         str(root), str(expected), where, str(reached), str(release)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=w465._env())
    try:
        w465.read_notice(reached, stalled)
        before_withdraw = w465.store_view(state)
        withdrawn = handle(service, entry.OPT_IN_WITHDRAW_VERB, reason="privacy_review")
        w465.write_release(release)
        out, err = stalled.communicate(timeout=60)
    finally:
        if stalled.poll() is None:
            stalled.kill()
            stalled.wait(timeout=10)
    assert stalled.returncode == 0, err
    result = json.loads(out.strip().splitlines()[-1])
    after = w465.store_view(state)
    sends = [w465.send_in_new_process(state, generation) for generation in (4, 5, 6, 7)]
    return result, before_withdraw, withdrawn, after, sends


@pytest.mark.parametrize("where", ["pre_check", "before_lock"])
def test_a_set_stalled_before_the_comparison_is_refused_after_the_withdrawal(
        service, tmp_path, where):
    set_first_three(service)
    assert w465.store_view(runtime_paths.mio_state_dir())["generation"] == 3
    result, before, withdrawn, after, sends = _stalled(service, tmp_path, where, 3)
    w465.dump(f"w470-stalled-{where}.json", {
        "stalled_set": result, "store_before_withdraw": before,
        "withdraw": {k: withdrawn[k] for k in ("status", "generation", "drained")},
        "store_after": after, "sends_from_another_process": sends})
    assert before["generation"] == 3 and withdrawn["status"] == "withdrawn"
    assert result["refused"] == {"code": "verb_unavailable", "detail": "opt_in_stale"}
    # The stale consent is not the fourth: the store is the withdrawal, closed.
    assert after == {"generation": 4, "status": "withdrawn", "permits": False}
    assert [s["calls"] for s in sends] == [0, 0, 0, 0]
    assert all(s["refusal"] == "opt_in_not_granted" for s in sends)
    events = ledger_events(service)
    if where == "pre_check":
        assert result["events"] == [], "an early refusal records nothing"
        assert events.count(SET) == 3  # the three earlier sets only
    else:
        assert result["events"] == ["mio.entry.request", SET,
                                    "mio.remote.opt_in.not_committed"]
        assert events.count(SET) == 3 + 1  # three earlier sets, and this one's line
        # The persisted not_committed line: one, from this operator, for this prerequisite.
        chain = RouteChain(service.router.ledger.directory)
        lines = [i.event for i in chain
                 if i.event["event_type"] == "mio.remote.opt_in.not_committed"]
        assert len(lines) == 1
        assert lines[0]["operator"] == "uid:1001" and lines[0]["prerequisite"] == LAST.value


def test_control_after_the_withdrawal_four_explicit_sets_open_the_grant_and_one_send_goes(
        service, tmp_path, monkeypatch):
    set_first_three(service)
    handle(service, entry.OPT_IN_WITHDRAW_VERB, reason="privacy_review")
    read = wire(service, monkeypatch, "mio.remote.opt_in.status")
    assert read["result"]["status"] == "withdrawn" and read["result"]["generation"] == 4
    generation = read["result"]["generation"]
    for prerequisite in PREREQUISITES:
        reply = wire(service, monkeypatch, SET, prerequisite=prerequisite.value,
                     expected_generation=generation)
        assert reply["ok"] is True, reply
        generation = reply["result"]["generation"]
    state = runtime_paths.mio_state_dir()
    assert w465.store_view(state) == {"generation": 9, "status": "granted", "permits": True}
    sent = w465.send_in_new_process(state, 9)
    w465.dump("w470-control.json", {"store": w465.store_view(state), "send": sent})
    assert sent["calls"] == 1 and sent["refusal"] is None


# -- an automatic resend ---------------------------------------------------


def _naive_client(service, monkeypatch, queue):
    """What a simple client does with a refusal it cannot read the reason of:
    read `status`, and send the same request again with the generation it
    reports. The socket carries only `verb_unavailable`, so it cannot tell a
    stale premise from a busy store."""
    attempts = 0
    for prerequisite, expected in queue:
        for _ in range(3):
            attempts += 1
            reply = wire(service, monkeypatch, SET, prerequisite=prerequisite.value,
                         expected_generation=expected)
            if reply.get("ok"):
                break
            assert reply == REFUSED
            expected = wire(service, monkeypatch,
                            "mio.remote.opt_in.status")["result"]["generation"]
    return attempts


def test_a_client_that_resends_with_the_latest_generation_reopens_the_grant_past_a_withdrawal(
        service, tmp_path, monkeypatch):
    """A fact the product cannot prevent: the premise only refuses a request
    that the caller did not renew. A caller that renews it on every refusal
    gets what it asked for. Holding back is the caller's discipline."""
    set_first_three(service)
    queue = [(p, i) for i, p in enumerate(PREREQUISITES)]  # the four, as first sent
    handle(service, entry.OPT_IN_WITHDRAW_VERB, reason="privacy_review")  # the operator's
    attempts = _naive_client(service, monkeypatch, queue)
    state = runtime_paths.mio_state_dir()
    view = w465.store_view(state)
    sent = w465.send_in_new_process(state, view["generation"])
    w465.dump("w470-auto-resend.json", {"attempts": attempts, "store": view, "send": sent})
    assert view["status"] == "granted" and view["permits"] is True
    assert sent["calls"] == 1
    assert attempts > len(queue)  # it was refused, and it resent


def test_one_resent_set_alone_adds_one_prerequisite_and_does_not_reopen(
        service, monkeypatch):
    set_first_three(service)
    handle(service, entry.OPT_IN_WITHDRAW_VERB, reason="privacy_review")
    attempts = _naive_client(service, monkeypatch, [(LAST, 3)])
    reading = handle(service, entry.OPT_IN_STATUS_VERB)
    assert attempts == 2
    assert reading["granted"] == [LAST.value] and reading["status"] == "incomplete"
    assert service.consent.reading().permits is False


def test_the_set_verb_is_named_only_by_entryd_and_the_store_docs():
    """Only entryd (which declares and serves the verb) and the store's docstring
    name `mio.remote.opt_in.set` in shipped code: no other module is a client of
    it. This is a file-level check; it does not prove that entryd itself never
    sends the verb (that rests on reading entryd: it serves the verb, it does
    not connect to its own socket)."""
    root = HERE.parents[1]
    hits = []
    for base in (root / "src", root / "runtime" / "src", root / "tools", root / "scripts",
                 root / "systemd", root / "deploy"):
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix in {".pyc", ".png"}:
                continue
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            if "opt_in.set" in text or "OPT_IN_SET_VERB" in text:
                hits.append(str(path.relative_to(root)))
    # entryd declares and serves it; the store's module only names it in its docs.
    assert sorted(hits) == ["runtime/src/azazel_nexus_runtime/mio_entryd.py",
                            "runtime/src/azazel_nexus_runtime/mio_remote_consent.py"]
    entryd = (root / "runtime/src/azazel_nexus_runtime/mio_entryd.py").read_text()
    assert "mio_socket_client" in entryd  # clients of entryd are the router's, not an opt-in sender
