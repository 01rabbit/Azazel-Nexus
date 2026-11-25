"""#472: a request that left no result is recorded once as unknown after a restart; the writer is exclusive.

The acceptance cases start the broker's real `main()` in a child process
(`_w472_contextd_child.py`), serve on a real unix socket, kill the process with
SIGKILL at a chosen point and start it again. For each case three things are
told apart: what the observer (the peer stand-in's own fsync'd log) saw, what
the product could establish from the ledger, and what the recovery added.

Observed values are written only when `W472_OUT` names a file:

    W472_OUT=<file> PYTHONPATH=<clone>/src:<clone>/runtime/src python -m pytest tests/unit/test_w472_contextd_recovery.py
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from azazel_nexus.audit import AuditChainBroken, AuditEntry, AuditLedger, AuditOutcomeUnknown
from test_w467_audit_unavailable import STATE, Daemon, request_for

HERE = Path(__file__).resolve().parent
CHILD = HERE / "_w472_contextd_child.py"
OUT = os.environ.get("W472_OUT")
LEDGER = f"{STATE}/knowledge-context/context.jsonl"
RULE = "r/etc/azazel/knowledge-context/observation-query.json"
STATUS = {"verb": "knowledge.context.status", "arguments": {}}
REQUESTED, COMPLETED = "knowledge.context.requested", "knowledge.context.completed"

_TABLE: list = []


def note(case: str, **fields) -> None:
    _TABLE.append({"case": case, **fields})
    if OUT:
        Path(OUT).write_text(json.dumps(_TABLE, indent=1, ensure_ascii=False))


class Ctx(Daemon):
    """The #467 harness with this file's child, kill and restart."""

    def __init__(self) -> None:
        super().__init__("knowledge-contextd")
        (self.run / "stopat").write_text("")

    def stopat(self, where: str) -> None:
        (self.run / "stopat").write_text(where)

    def start(self, timeout: float = 25.0) -> bool:
        self.starts += 1
        for leftover in ("ready", "stop"):
            (self.run / leftover).unlink(missing_ok=True)
        env = {**os.environ, "AZAZEL_ROOT": "r", "PYTHONDONTWRITEBYTECODE": "1"}
        self.stderr_path = self.run / f"log/stderr-{self.starts}.txt"
        self.proc = subprocess.Popen([sys.executable, str(CHILD)], cwd=self.run, env=env,
                                     stdout=subprocess.DEVNULL, stderr=self.stderr_path.open("wb"))
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if (self.run / "ready").exists():
                return True
            if self.proc.poll() is not None:
                return False
            time.sleep(0.05)
        return False

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=10)

    def wait_dead(self, timeout: float = 10.0) -> None:
        """The process ended, and by the SIGKILL the stop point sent, for no other reason."""
        assert self.proc.wait(timeout=timeout) == -signal.SIGKILL

    def rows(self) -> list[AuditEntry]:
        return list(AuditLedger(self.run / LEDGER))

    def kinds(self) -> list[str]:
        return [row.event["event_type"] for row in self.rows()]

    def unknown_rows(self) -> list[AuditEntry]:
        return [row for row in self.rows() if row.event.get("outcome") == "unknown"]

    def calls(self) -> int:
        return len(self.log_lines("calls.log"))

    def status(self) -> dict:
        reply = self.ask(STATUS)
        assert reply["transport"] == "reply", reply
        return reply["reply"]["result"]

    def request(self, variant: int) -> dict:
        return self.ask(request_for("knowledge-contextd", "context", variant))

    def wait_status(self, key: str, value, timeout: float = 12.0) -> dict:
        end = time.monotonic() + timeout
        while True:
            status = self.status()
            if status[key] == value or time.monotonic() > end:
                return status
            time.sleep(0.25)

    def reads(self) -> int:
        """How many whole reads of the ledger this run's processes began (`reads.log`)."""
        path = self.run / "reads.log"
        return len(path.read_text().splitlines()) if path.exists() else 0

    def faults(self) -> int:
        return sum(1 for line in self.log_lines("faults.log") if "fault" in line)


@pytest.fixture
def ctx():
    harness = Ctx()
    try:
        yield harness
    finally:
        harness.cleanup()


def served(reply: dict) -> bool:
    """The peer's answer came back to the caller (not a refusal)."""
    return reply["transport"] == "reply" and "response" in reply["reply"].get("result", {})


def _is_unknown_for(row: AuditEntry, requested: AuditEntry) -> bool:
    event = row.event
    return (event["event_type"] == COMPLETED and event["outcome"] == "unknown"
            and event["reason_code"] == "restart_unconfirmed"
            and event["requested_sequence"] == requested.sequence
            and event["requested_hash"] == requested.event_hash)


def _normalized(rows) -> list:
    """The ledger rows' events, without what differs from run to run.

    Dropped: `elapsed_ms` (a measured time) and the `requested_sequence` /
    `requested_hash` references (sequence and hash of a line, which differ with the
    run). Everything else in each event, in order, is compared.
    """
    drop = {"elapsed_ms", "requested_sequence", "requested_hash"}
    return [{k: v for k, v in dict(row.event).items() if k not in drop} for row in rows]


def _crash_and_recover(ctx: Ctx, stop: str, case: str) -> dict:
    assert ctx.start()
    assert served(ctx.request(0))          # one finished request before the stop
    ctx.stopat(stop)
    sends_before = ctx.calls()
    assert ctx.request(1)["transport"] == "no_reply"
    ctx.wait_dead()
    crashed = ctx.rows()
    observed = ctx.calls() - sends_before
    assert crashed[-1].event["event_type"] == REQUESTED and crashed[-1].event["format"] == 2
    ctx.stopat("")
    rows_before, calls_before = len(crashed), ctx.calls()
    assert ctx.start()
    after = ctx.rows()
    added = after[rows_before:]
    assert [row.event["event_type"] for row in added] == [
        "knowledge.context.commissioning", COMPLETED]
    assert _is_unknown_for(added[1], crashed[-1])
    status = ctx.status()
    assert status["egress"] == "open" and status["unresolved"] == 0 and status["recovered"] == 1
    assert ctx.calls() == calls_before                      # nothing was sent again
    # A second restart finds the line referenced and adds only its own start record.
    ctx.kill()
    assert ctx.start()
    again = ctx.rows()[len(after):]
    assert [row.event["event_type"] for row in again] == ["knowledge.context.commissioning"]
    assert len(ctx.unknown_rows()) == 1
    AuditLedger(ctx.run / LEDGER).verify(require_terminated=True)
    note(case, observed_sends=observed, ledger="requested only; no result; outcome unknown",
         added_rows=len(added), added_sends=ctx.calls() - calls_before, unknown_rows_total=1)
    return {"crashed_kinds": [row.event["event_type"] for row in crashed], "observed": observed,
            "crashed_events": _normalized(crashed)}


@pytest.mark.real_process
def test_stop_before_the_call_is_recorded_once_as_unknown(ctx):
    result = _crash_and_recover(ctx, "a", "stop before the call")
    assert result["observed"] == 0


@pytest.mark.real_process
def test_stop_after_the_call_is_the_same_ledger_and_the_same_record(ctx):
    result = _crash_and_recover(ctx, "b", "stop after the call, before the result")
    assert result["observed"] == 1
    other = Ctx()
    try:
        before = _crash_and_recover(other, "a", "stop before the call (compare)")
    finally:
        other.cleanup()
    # The ledger cannot tell the two stops apart; the observer can.
    assert before["crashed_kinds"] == result["crashed_kinds"]
    assert before["crashed_events"] == result["crashed_events"]     # the rows themselves
    assert before["observed"] == 0


@pytest.mark.real_process
def test_a_finished_request_is_not_recovered(ctx):
    assert ctx.start()
    assert served(ctx.request(0))
    sends = ctx.calls()
    ctx.kill()
    rows_before = len(ctx.rows())
    assert ctx.start()
    added = ctx.rows()[rows_before:]
    assert [row.event["event_type"] for row in added] == ["knowledge.context.commissioning"]
    status = ctx.status()
    assert status["unresolved"] == 0 and status["recovered"] == 0 and status["egress"] == "open"
    assert ctx.unknown_rows() == []
    assert ctx.calls() == sends                     # recovery sent nothing
    note("normal result already recorded", observed_sends=sends,
         ledger="requested and its result refer to each other", added_rows=1,
         added_sends=ctx.calls() - sends)


@pytest.mark.real_process
@pytest.mark.parametrize("fault, record", [("pre", "audit.late_record"),
                                           ("fsync", "audit.outcome_settled")])
def test_a_result_recorded_by_the_469_settlement_is_not_recovered(ctx, fault, record):
    assert ctx.start()
    assert served(ctx.request(0))
    ctx.arm(fault, 2)                              # the 2nd write (the result) fails
    unrecorded = ctx.request(1)["reply"]["result"]
    assert unrecorded["refusal"] == "unavailable" and unrecorded["stage"] == "unrecorded"
    assert ctx.faults() == 1                       # the injection fired, once
    assert ctx.status()["audit"] == "owed"         # and the debt is there
    assert served(ctx.request(2))   # settled first, then served
    assert ctx.status()["audit"] == "ok"
    kinds = ctx.kinds()
    assert record in kinds
    sends = ctx.calls()
    assert sends == 3                              # the unrecorded answer was a real send
    ctx.arm("off")                                 # the next process starts without the fault
    ctx.kill()
    rows_before = len(ctx.rows())
    assert ctx.start()
    added = ctx.rows()[rows_before:]
    assert [row.event["event_type"] for row in added] == ["knowledge.context.commissioning"]
    assert ctx.unknown_rows() == []
    assert ctx.calls() == sends                     # recovery sent nothing
    if record == "audit.late_record":
        late = [row.event for row in ctx.rows() if row.event["event_type"] == record][0]
        assert late["late_event"]["requested_sequence"] and late["late_event"]["requested_hash"]
    note(f"result recorded by #469 ({record})", observed_sends=sends,
         ledger="result found through the settlement record's own reference",
         added_rows=1, added_sends=ctx.calls() - sends)


@pytest.mark.real_process
def test_a_stop_right_after_the_recovery_row_adds_nothing_more(ctx):
    assert ctx.start()
    assert served(ctx.request(0))
    ctx.stopat("a")
    assert ctx.request(1)["transport"] == "no_reply"
    ctx.wait_dead()
    crashed = ctx.rows()
    sends = ctx.calls()
    ctx.stopat("c")                                # dies after `commissioning`, before the row
    assert ctx.start() is False
    ctx.wait_dead()
    assert ctx.unknown_rows() == []
    ctx.stopat("r")                                # dies right after the recovery row
    assert ctx.start() is False
    ctx.wait_dead()
    assert len(ctx.unknown_rows()) == 1
    rows_before = len(ctx.rows())
    ctx.stopat("")
    assert ctx.start()
    added = ctx.rows()[rows_before:]
    assert [row.event["event_type"] for row in added] == ["knowledge.context.commissioning"]
    assert len(ctx.unknown_rows()) == 1 and _is_unknown_for(ctx.unknown_rows()[0], crashed[-1])
    assert ctx.calls() == sends
    note("stop right after the recovery row", observed_sends=0,
         ledger="the recovery row is on the ledger and referenced",
         added_rows=len(ctx.rows()) - len(crashed) - 2, added_sends=0,
         unknown_rows_total=1)


@pytest.mark.real_process
def test_an_old_format_line_is_counted_and_never_filled_in(ctx):
    ledger = AuditLedger(ctx.run / LEDGER)
    ledger.append({"event_type": "knowledge.context.commissioning", "outcome": "commissioned"})
    ledger.append({"event_type": REQUESTED, "outcome": "attempted"})   # no `format`, no result
    assert ctx.start()
    assert ctx.kinds() == ["knowledge.context.commissioning", REQUESTED,
                           "knowledge.context.commissioning"]
    status = ctx.status()
    assert status["legacy_unreferenced"] == 1 and status["unresolved"] == 0
    assert status["egress"] == "open" and ctx.calls() == 0
    note("old-format line", observed_sends=0,
         ledger="no reference; counted as legacy_unreferenced=1; not filled in",
         added_rows=1, added_sends=0)


@pytest.mark.real_process
def test_a_broken_chain_is_not_completed_and_egress_stays_closed(ctx):
    ledger = AuditLedger(ctx.run / LEDGER)
    ledger.append({"event_type": "knowledge.context.commissioning", "outcome": "commissioned"})
    ledger.append({"event_type": REQUESTED, "outcome": "attempted", "format": 2})
    path = ctx.run / LEDGER
    path.write_text(path.read_text().replace("commissioned", "commissionee", 1))
    before = path.read_bytes()
    assert ctx.start()
    status = ctx.status()
    assert status["egress"] == "closed" and status["reason"] == "ledger_broken"
    assert path.read_bytes() == before                  # nothing was added, nothing filled in
    reply = ctx.request(1)
    assert reply["reply"]["result"]["refusal"] == "unavailable" and reply["reply"]["result"]["stage"] == "refused_before_send"
    assert ctx.calls() == 0 and path.read_bytes() == before
    with pytest.raises(AuditChainBroken):
        AuditLedger(path).verify()
    note("broken chain", observed_sends=0, ledger="chain broken; reason ledger_broken in status",
         added_rows=0, added_sends=0)


def _surrogate() -> bytes:
    return ('{"event":{"event_type":"x","t":"\\ud800"},"event_hash":"' + "0" * 64
            + '","previous_hash":"' + "0" * 64 + '","sequence":1}\n').encode()


@pytest.mark.real_process
@pytest.mark.parametrize("label, content", [
    ("broken json", b"{not json\n"),
    ("torn line", b'{"sequence":1,"event'),
    ("lone surrogate", None),
    ("deeply nested json", b'{"sequence":1,"previous_hash":"0","event_hash":"0","event":'
     + b"[" * 30000 + b"]" * 30000 + b"}\n"),
])
def test_a_ledger_that_cannot_be_read_is_broken_not_a_reason_to_exit(ctx, label, content):
    path = ctx.run / LEDGER
    path.write_bytes(_surrogate() if content is None else content)
    before = path.read_bytes()
    assert ctx.start(), ctx.exit_info()                      # it bound and serves
    status = ctx.status()
    assert status["egress"] == "closed" and status["reason"] == "ledger_broken", label
    refused = ctx.request(1)["reply"]["result"]
    assert refused["refusal"] == "unavailable" and refused["stage"] == "refused_before_send"
    assert ctx.calls() == 0 and path.read_bytes() == before, label
    assert ctx.alive()


@pytest.mark.real_process
def test_an_empty_ledger_starts_open(ctx):
    (ctx.run / LEDGER).write_bytes(b"")
    assert ctx.start()
    assert ctx.status()["egress"] == "open" and served(ctx.request(1))


@pytest.mark.real_process
def test_a_second_start_ends_without_touching_the_first(ctx):
    assert ctx.start()
    assert served(ctx.request(0))
    sock = ctx.run / "r/var/lib/azazel/run/knowledge-context/knowledge-context.sock"
    ident = (sock.stat().st_ino, sock.stat().st_dev)
    rows = ctx.rows()
    ledger_bytes = (ctx.run / LEDGER).read_bytes()
    env = {**os.environ, "AZAZEL_ROOT": "r", "PYTHONDONTWRITEBYTECODE": "1"}
    second = subprocess.run([sys.executable, str(CHILD)], cwd=ctx.run, env=env, timeout=30,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    assert second.returncode != 0 and b"another az-knowledge-contextd" in second.stderr
    assert (sock.stat().st_ino, sock.stat().st_dev) == ident
    assert ctx.alive() and ctx.status()["egress"] == "open"
    assert ctx.rows() == rows                       # the second one appended nothing
    assert (ctx.run / LEDGER).read_bytes() == ledger_bytes   # nor touched the file at all
    assert served(ctx.request(1))    # the first still serves
    note("second start", observed_sends=ctx.calls(),
         ledger="lock held by the first; second exits with rc!=0; socket inode unchanged",
         added_rows=0, added_sends=0)


@pytest.mark.real_process
def test_audit_failure_keeps_egress_closed_and_recovery_reopens_it(ctx):
    ctx.arm("persist")                              # every ledger read and write fails
    assert ctx.start()
    status = ctx.status()
    assert status["egress"] == "closed" and status["reason"] == "audit_unavailable"
    assert ctx.faults() >= 1                        # the injection fired
    reply = ctx.request(1)
    assert reply["reply"]["result"]["refusal"] == "unavailable" and reply["reply"]["result"]["stage"] == "refused_before_send"
    assert ctx.calls() == 0
    ctx.arm("off")
    # No retry between requests: the next request recovers the ledger and is served.
    assert ctx.status()["egress"] == "closed"
    ok = ctx.request(2)
    assert served(ok) and ctx.calls() == 1
    status = ctx.status()
    assert status["egress"] == "open" and status["audit"] == "ok"
    assert "knowledge.context.commissioning" in ctx.kinds()
    note("control: audit failure then recovery", observed_sends=0,
         ledger="egress closed while the ledger failed; a new request is served after it recovered",
         added_rows=len(ctx.rows()), added_sends=1)


@pytest.mark.real_process
@pytest.mark.parametrize("nth, missing", [(2, "commissioning"), (3, "recovery row")])
def test_egress_stays_closed_until_commissioning_and_the_recovery_row_are_written(ctx, nth, missing):
    assert ctx.start()
    ctx.stopat("a")
    assert ctx.request(1)["transport"] == "no_reply"
    ctx.wait_dead()
    ctx.stopat("")
    ctx.arm("pre", nth)           # the write-open that fails: 1 is the start check, 2 commissioning, 3 the row
    assert ctx.start()
    assert ctx.faults() == 1      # the injection fired once
    status = ctx.status()
    assert status["egress"] == "closed" and status["reason"] == "audit_unavailable", missing
    assert ctx.calls() == 0       # nothing was sent while it was closed
    assert served(ctx.request(3)) and ctx.calls() == 1     # the next request recovers it
    status = ctx.status()
    assert status["egress"] == "open" and len(ctx.unknown_rows()) == 1


@pytest.mark.real_process
def test_egress_stays_closed_while_commissioning_is_not_recorded(ctx):
    ctx.arm("pre", 2)             # nothing is pending; only `commissioning` fails
    assert ctx.start()
    assert ctx.faults() == 1
    status = ctx.status()
    assert status["egress"] == "closed" and status["unresolved"] == 0
    assert status["reason"] == "audit_unavailable" and ctx.calls() == 0
    assert served(ctx.request(1)) and ctx.status()["egress"] == "open"   # the next request
    assert ctx.kinds().count("knowledge.context.commissioning") == 1


@pytest.mark.real_process
def test_the_latch_and_status_work_while_the_ledger_fails(ctx):
    assert ctx.start()
    assert served(ctx.request(0))
    ctx.kill()
    ctx.arm("persist")
    assert ctx.start()
    assert ctx.status()["egress"] == "closed"
    (ctx.run / RULE).unlink()                       # the rule file is gone
    reply = ctx.request(1)
    assert reply["reply"]["result"]["refusal"] == "unavailable"
    status = ctx.status()
    assert status["observation"] == "latched"       # the gate ran and closed for good
    assert status["egress"] == "closed" and ctx.faults() >= 1
    ctx.arm("off")
    assert ctx.request(2)["reply"]["result"]["refusal"] == "unavailable"   # still latched
    assert ctx.calls() == 1
    note("control: latch and status while the ledger fails", observed_sends=1,
         ledger="latch set and status answered with the ledger unreadable", added_rows=0,
         added_sends=0)


@pytest.mark.real_process
def test_the_latch_and_status_work_after_the_chain_breaks_while_serving(ctx):
    assert ctx.start()
    assert served(ctx.request(0))
    with (ctx.run / LEDGER).open("ab") as handle:
        handle.write(b"not a ledger line\n")       # the chain breaks under the running broker
    broken = ctx.request(1)["reply"]["result"]      # this request finds it
    assert broken["refusal"] == "unavailable" and ctx.status()["audit"] == "broken"
    size, sends = (ctx.run / LEDGER).stat().st_size, ctx.calls()
    (ctx.run / RULE).unlink()
    assert ctx.request(2)["reply"]["result"]["stage"] == "refused_before_send"
    status = ctx.status()
    assert status["observation"] == "latched" and status["egress"] == "closed"
    assert status["reason"] == "ledger_broken"
    assert (ctx.run / LEDGER).stat().st_size == size and ctx.calls() == sends   # nothing written or sent
    note("control: latch after a break while serving", observed_sends=sends,
         ledger="latch set, status answered, nothing written", added_rows=0, added_sends=0)


@pytest.mark.real_process
def test_the_latch_and_status_work_while_a_debt_cannot_be_settled(ctx):
    assert ctx.start()
    assert served(ctx.request(0))
    ctx.arm("fsync", 2)                              # the result is written, its sync fails
    assert ctx.request(1)["reply"]["result"]["stage"] == "unrecorded"
    ctx.arm("persist")                               # and the ledger cannot be read to settle it
    assert ctx.status()["audit"] == "owed"
    sends = ctx.calls()
    (ctx.run / RULE).unlink()
    assert ctx.request(2)["reply"]["result"]["stage"] == "refused_before_send"
    status = ctx.status()
    assert status["observation"] == "latched" and status["audit"] == "owed"
    assert status["egress"] == "closed" and ctx.faults() >= 2 and ctx.calls() == sends


@pytest.mark.real_process
def test_nothing_is_appended_before_start_up_is_done_and_the_latch_still_closes(ctx):
    ctx.arm("persist")
    assert ctx.start()                               # start-up fails: not verified, no commissioning
    ctx.arm("off")                                   # the ledger works again, start-up has not run again
    ctx.ask({"verb": "w467.no.such.verb", "arguments": {}})   # the transport's refusal record
    assert ctx.rows() == []                          # not written before `commissioning`
    (ctx.run / RULE).unlink()
    assert ctx.request(1)["reply"]["result"]["stage"] == "refused_before_send"
    assert ctx.status()["observation"] == "latched"  # the latch is set though its record is dropped
    assert ctx.rows() == []                          # the latch record was not written first
    time.sleep(2.5)                                  # no retry between requests either
    assert ctx.rows() == [] and ctx.status()["egress"] == "closed"


@pytest.mark.real_process
def test_a_parse_failure_while_settling_is_ledger_broken_and_the_latch_still_works(ctx):
    assert ctx.start()
    assert served(ctx.request(0))
    ctx.arm("fsync", 2)                              # the result is written, its sync fails
    assert ctx.request(1)["reply"]["result"]["stage"] == "unrecorded"
    assert ctx.status()["audit"] == "owed"
    sends = ctx.calls()
    with (ctx.run / LEDGER).open("ab") as handle:    # the tail becomes unreadable
        handle.write(b'{"event":' + b"[" * 30000 + b"]" * 30000 + b"}\n")
    ctx.request(3)                                   # the next request meets the tail
    assert ctx.alive()                               # the loop did not end
    status = ctx.status()
    assert status["audit"] == "broken" and status["reason"] == "ledger_broken"
    (ctx.run / RULE).unlink()
    assert ctx.request(2)["reply"]["result"]["stage"] == "refused_before_send"
    assert ctx.status()["observation"] == "latched" and ctx.calls() == sends


@pytest.mark.real_process
def test_a_transport_refusal_met_by_an_unreadable_ledger_ends_nothing(ctx):
    assert ctx.start()
    assert served(ctx.request(0))
    ctx.arm("fsync", 2)
    assert ctx.request(1)["reply"]["result"]["stage"] == "unrecorded"
    sends = ctx.calls()
    with (ctx.run / LEDGER).open("ab") as handle:
        handle.write(b'{"event":' + b"[" * 30000 + b"]" * 30000 + b"}\n")
    # At once, before the between-requests retry: the transport's own refusal record
    # meets the debt and the unreadable tail.
    ctx.ask({"verb": "w467.no.such.verb", "arguments": {}})
    assert ctx.alive()
    status = ctx.status()
    assert status["audit"] == "broken" and status["reason"] == "ledger_broken"
    (ctx.run / RULE).unlink()
    assert ctx.request(2)["reply"]["result"]["stage"] == "refused_before_send"
    assert ctx.status()["observation"] == "latched" and ctx.calls() == sends


@pytest.mark.real_process
def test_a_read_only_state_directory_starts_closed_and_writes_nothing(ctx):
    state = ctx.run / STATE / "knowledge-context"
    state.chmod(0o500)                               # not widened: narrowed, for the owner
    try:
        assert ctx.start(), ctx.exit_info()
        status = ctx.status()
        assert status["egress"] == "closed" and status["reason"] == "audit_unavailable"
        assert sorted(item.name for item in state.iterdir()) == []   # nothing was created
        (ctx.run / RULE).unlink()
        assert ctx.request(1)["reply"]["result"]["stage"] == "refused_before_send"
        assert ctx.status()["observation"] == "latched" and ctx.calls() == 0
    finally:
        state.chmod(0o700)


@pytest.mark.real_process
def test_a_second_start_with_the_ledger_closed_does_not_replace_the_first_socket(ctx):
    state = ctx.run / STATE / "knowledge-context"
    state.chmod(0o500)                               # no ledger lock can be created
    try:
        assert ctx.start()
        assert ctx.status()["reason"] == "audit_unavailable"
        sock = ctx.run / "r/var/lib/azazel/run/knowledge-context/knowledge-context.sock"
        ident = (sock.stat().st_ino, sock.stat().st_dev)
        env = {**os.environ, "AZAZEL_ROOT": "r", "PYTHONDONTWRITEBYTECODE": "1"}
        second = subprocess.run([sys.executable, str(CHILD)], cwd=ctx.run, env=env, timeout=30,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        assert second.returncode != 0 and b"another az-knowledge-contextd" in second.stderr
        assert (sock.stat().st_ino, sock.stat().st_dev) == ident
        assert ctx.alive() and ctx.status()["egress"] == "closed"    # the first still answers
    finally:
        state.chmod(0o700)


@pytest.mark.real_process
def test_lines_dropped_for_an_unsettled_debt_are_counted_as_unrecorded(ctx):
    assert ctx.start()
    assert served(ctx.request(0))
    ctx.arm("fsync", 2)
    assert ctx.request(1)["reply"]["result"]["stage"] == "unrecorded"
    ctx.arm("persist")                               # the debt cannot be settled
    before = ctx.status()["unrecorded"]
    (ctx.run / RULE).unlink()
    assert ctx.request(2)["reply"]["result"]["stage"] == "refused_before_send"
    after = ctx.status()
    assert after["observation"] == "latched"
    assert after["unrecorded"] == before + 2         # the latch's line and the refusal's line


@pytest.mark.real_process
def test_a_slow_look_at_held_lines_does_not_keep_the_gate_from_running(ctx):
    assert ctx.start()
    assert served(ctx.request(0))
    sends = ctx.calls()
    (ctx.run / "slowflush").write_text("1")          # the look at held lines takes 1.5 s
    (ctx.run / RULE).unlink()
    frame = request_for("knowledge-contextd", "context", 1)
    frame["arguments"] = {"deadline_ms": 2000,
                          "deadline_monotonic_ns": time.monotonic_ns() + 1_000_000_000}
    assert ctx.ask(frame)["transport"] == "reply"
    status = ctx.status()
    assert status["observation"] == "latched"         # the gate ran before the slow look
    assert ctx.calls() == sends


def _hold_a_refusal(ctx) -> None:
    """A `requested` line on the ledger whose refusal could not be appended (held)."""
    assert ctx.start()
    assert served(ctx.request(0))
    ctx.arm("pre", 2)                                # the refusal's own append fails (plain)
    (ctx.run / "slowrequested").write_text("1")      # the deadline passes after `requested`
    frame = request_for("knowledge-contextd", "context", 1)
    frame["arguments"] = {"deadline_ms": 500, "deadline_monotonic_ns": 2**62}
    assert ctx.ask(frame)["reply"]["result"]["refusal"] == "timeout"
    assert ctx.faults() == 1
    (ctx.run / "slowrequested").unlink()


def _near_deadline(ctx, variant: int, ms: int = 1000) -> dict:
    frame = request_for("knowledge-contextd", "context", variant)
    frame["arguments"] = {"deadline_ms": 2000,
                          "deadline_monotonic_ns": time.monotonic_ns() + ms * 1_000_000}
    return ctx.ask(frame)


@pytest.mark.real_process
@pytest.mark.parametrize("slow, marker", [("slowappend", "appending"), ("slowverify", "verifying")])
def test_between_requests_the_daemon_touches_no_ledger_and_the_gate_comes_first(ctx, slow, marker):
    if slow == "slowappend":
        _hold_a_refusal(ctx)                         # something is held, waiting to be appended
    else:
        ctx.arm("persist")                           # start-up fails and has to be done again
        assert ctx.start()
        ctx.arm("off")
    sends = ctx.calls()
    (ctx.run / slow).write_text("1")                 # an append / a read of the ledger takes 3 s
    time.sleep(4.5)                                  # longer than any between-requests retry period
    assert not (ctx.run / marker).exists()           # nothing touched the ledger on its own
    (ctx.run / RULE).unlink()
    _near_deadline(ctx, 2)                           # a request with 1 s to live: it reaches the gate
    assert ctx.status()["observation"] == "latched"
    assert ctx.calls() == sends


@pytest.mark.real_process
def test_a_held_refusal_is_written_by_the_retry_in_the_next_request_after_the_gate(ctx):
    _hold_a_refusal(ctx)
    sends = ctx.calls()
    assert served(ctx.request(2))                    # the retry wrote the held line, then it went on
    held = [row for row in ctx.rows() if row.event["event_type"] == COMPLETED
            and row.event.get("reason_code") == "refused_before_send"]
    assert len(held) == 1 and held[0].event["requested_sequence"]    # one result, with its reference
    assert ctx.calls() == sends + 1


@pytest.mark.real_process
def test_a_retry_that_only_appends_a_recovery_line_does_not_read_the_whole_ledger(ctx, monkeypatch):
    import threading

    monkeypatch.chdir(ctx.run)                       # two threads ask; the cwd is the same for both
    assert ctx.start()
    ctx.stopat("a")
    assert ctx.request(1)["transport"] == "no_reply"
    ctx.wait_dead()
    ctx.stopat("")
    ctx.arm("pre", 3)                                # start-up: the recovery line alone fails
    assert ctx.start()
    assert ctx.faults() == 1 and ctx.status()["egress"] == "closed"
    sends, reads = ctx.calls(), ctx.reads()
    (ctx.run / "slowverify").write_text("1")         # a read of the whole ledger would take 3 s
    first = {}
    thread = threading.Thread(target=lambda: first.update(
        reply=ctx.request(2)))                       # A: its retry appends the recovery line
    thread.start()
    time.sleep(0.3)
    (ctx.run / RULE).unlink()
    started = time.monotonic()
    _near_deadline(ctx, 3)                           # B: 1 s to live, the rule file is gone
    thread.join(10)
    assert time.monotonic() - started < 2.5
    assert ctx.status()["observation"] == "latched"  # B reached the gate in time
    assert not (ctx.run / "verifying").exists()      # and no retry read the whole ledger
    assert ctx.reads() == reads
    assert len(ctx.unknown_rows()) == 1 and ctx.status()["unresolved"] == 0
    assert ctx.calls() <= sends + 1                  # only A may have been sent


@pytest.mark.real_process
def test_start_up_reads_the_ledger_once_for_the_chain_and_the_references_together(ctx):
    AuditLedger(ctx.run / LEDGER).append(
        {"event_type": REQUESTED, "outcome": "attempted", "format": 2})
    assert ctx.start()
    assert ctx.reads() == 1                          # one read does both; no state with only one done
    assert len(ctx.unknown_rows()) == 1
    assert served(ctx.request(1))
    assert ctx.reads() == 1                          # and no request reads it again


@pytest.mark.real_process
def test_a_missing_state_directory_ends_the_start_and_makes_nothing(ctx):
    state = ctx.run / STATE / "knowledge-context"
    shutil.rmtree(state)
    assert ctx.start() is False
    assert ctx.proc.wait(timeout=10) != 0
    assert b"does not exist" in ctx.stderr_path.read_bytes()
    assert not state.exists()                        # no directory, so no ledger, no lock


@pytest.mark.real_process
def test_a_missing_socket_directory_ends_the_start_and_is_not_created(ctx):
    run_dir = ctx.run / "r/var/lib/azazel/run/knowledge-context"
    shutil.rmtree(run_dir)
    assert ctx.start() is False
    assert ctx.proc.wait(timeout=10) != 0
    assert b"does not exist" in ctx.stderr_path.read_bytes()
    assert not run_dir.exists()                      # the installer's to create, not the broker's


@pytest.mark.real_process
def test_an_existing_lock_and_a_ledger_that_can_be_appended_start_normally_in_a_read_only_directory(ctx):
    state = ctx.run / STATE / "knowledge-context"
    AuditLedger(state / "context.jsonl").append(
        {"event_type": "knowledge.context.commissioning", "outcome": "commissioned"})
    (state / "context.jsonl.lock").write_bytes(b"")
    state.chmod(0o500)                               # the directory cannot be written, the files can
    try:
        assert ctx.start(), ctx.exit_info()
        status = ctx.status()
        assert status["egress"] == "open" and status["reason"] is None
        assert served(ctx.request(1)) and ctx.calls() == 1
        assert "knowledge.context.commissioning" in ctx.kinds()[1:]    # this start recorded itself
    finally:
        state.chmod(0o700)


@pytest.mark.real_process
def test_a_start_that_cannot_bind_writes_nothing_to_the_ledger(ctx):
    state = ctx.run / STATE / "knowledge-context"
    run_dir = ctx.run / "r/var/lib/azazel/run/knowledge-context"
    ledger = AuditLedger(state / "context.jsonl")
    ledger.append({"event_type": "knowledge.context.commissioning", "outcome": "commissioned"})
    (run_dir / "knowledge-context.lock").write_bytes(b"")     # exists, so it can be opened
    before = (state / "context.jsonl").read_bytes()
    run_dir.chmod(0o500)                                      # but nothing can be bound there
    try:
        assert ctx.start() is False
        assert ctx.proc.wait(timeout=10) != 0
        assert (state / "context.jsonl").read_bytes() == before   # no commissioning, no recovery
    finally:
        run_dir.chmod(0o700)


@pytest.mark.real_process
def test_a_lock_held_by_another_refuses_the_start_and_changes_nothing(ctx):
    import fcntl

    state = ctx.run / STATE / "knowledge-context"
    ledger = AuditLedger(state / "context.jsonl")
    ledger.append({"event_type": "knowledge.context.commissioning", "outcome": "commissioned"})
    sock = ctx.run / "r/var/lib/azazel/run/knowledge-context/knowledge-context.sock"
    sock.write_bytes(b"the first writer's socket")
    before = ((state / "context.jsonl").read_bytes(), sock.read_bytes(), sock.stat().st_ino)
    with open(state / "context.jsonl.lock", "wb") as holder:
        fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert ctx.start() is False
        ctx.wait_exit = ctx.proc.wait(timeout=10)
        assert ctx.proc.returncode != 0
        assert b"another az-knowledge-contextd" in ctx.stderr_path.read_bytes()
    assert ((state / "context.jsonl").read_bytes(), sock.read_bytes(),
            sock.stat().st_ino) == before


@pytest.mark.real_process
def test_a_recovery_line_settled_present_is_counted_once(ctx):
    assert ctx.start()
    ctx.stopat("a")
    assert ctx.request(1)["transport"] == "no_reply"
    ctx.wait_dead()
    ctx.stopat("")
    ctx.arm("fsync", 2)                              # start-up: 1 commissioning, 2 the recovery line
    assert ctx.start()
    assert ctx.faults() == 1
    assert served(ctx.request(2))                    # the next request settles it and is served
    status = ctx.status()
    assert status["egress"] == "open" and status["unresolved"] == 0
    assert len(ctx.unknown_rows()) == 1
    assert status["recovered"] == 1                  # settled `present`, counted once
    assert "audit.outcome_settled" in ctx.kinds()


# -- in-process: the references and the held refusal ---------------------------

def _broker(audit, **kw):
    from stop_helpers import granted_marker
    from test_knowledge_contextd import OPEN_GATE, _policy
    from azazel_nexus_runtime.knowledge_contextd import KnowledgeContextBroker

    class Peer:
        def request_context(self, **kwargs):
            return {"authority": "advisory_only"}

    return KnowledgeContextBroker(
        **OPEN_GATE, grant_marker=granted_marker, client=Peer(), policy=_policy(), mission="lab",
        alias_key=b"x" * 32, enabled=True, audit=audit, **kw)


def _entry(sequence: int, event: dict) -> AuditEntry:
    return AuditEntry(sequence=sequence, previous_hash="0" * 64, event_hash=f"{sequence:064x}",
                      event=event)


def _request():
    from test_knowledge_contextd import _request

    return _request(payload={"frame": {"privacy_class": "P0-public", "techniques": ["T1059"]}})


def test_requested_carries_the_format_and_the_result_refers_to_it():
    events = []

    def audit(event):
        events.append(event)
        return _entry(len(events), event)

    assert _broker(audit).handle(_request())["response"]
    requested, completed = events
    assert requested["format"] == 2 and "requested_sequence" not in requested
    assert (completed["requested_sequence"], completed["requested_hash"]) == (1, f"{1:064x}")


@pytest.mark.parametrize("verdict, refers", [("present", True), ("absent", False)])
def test_a_refusal_after_an_unknown_requested_write_refers_to_it_only_when_present(verdict, refers):
    events = []

    def audit(event):
        if event["event_type"] == REQUESTED:
            raise AuditOutcomeUnknown("x", entry=_entry(7, event), path=Path("p"),
                                      absent_head=(6, "0" * 64))
        events.append(event)

    sent = []
    broker = _broker(audit, request_settled=lambda entry: verdict)
    broker._client.request_context = lambda **kw: sent.append(kw)
    broker.handle(_request())
    assert sent == []                                   # never sent
    (completed,) = events
    assert completed["reason_code"] == "refused_before_send"
    assert ("requested_sequence" in completed) is refers


def test_a_refusal_waits_while_the_unknown_line_is_unsettled_then_is_written_once():
    events, state = [], ["unknown"]

    def audit(event):
        if event["event_type"] == REQUESTED:
            raise AuditOutcomeUnknown("x", entry=_entry(7, event), path=Path("p"),
                                      absent_head=(6, "0" * 64))
        events.append(event)

    broker = _broker(audit, request_settled=lambda entry: state[0])
    broker.handle(_request())
    assert events == [] and len(broker.deferred) == 1       # held, not dropped, not guessed
    broker.flush_deferred()
    assert events == []
    state[0] = "present"
    broker.flush_deferred()
    broker.flush_deferred()
    assert len(events) == 1 and events[0]["requested_sequence"] == 7 and broker.deferred == []


def test_a_closed_ledger_refuses_after_the_gate_and_before_the_client():
    events, order = [], []
    broker = _broker(events.append, send_allowed=lambda: order.append("closed") or False)
    broker._client.request_context = lambda **kw: order.append("client")
    gate = broker._observation_gate
    broker._observation_gate = lambda now: order.append("gate") or gate(now)
    reply = broker.handle(_request())
    assert order == ["gate", "closed"] and reply["stage"] == "refused_before_send"
    assert [event["event_type"] for event in events] == [COMPLETED]   # no `requested`


@pytest.mark.parametrize("verdict, writes", [("present", 1), ("absent", 2)])
def test_a_held_refusal_whose_own_write_is_unknown_is_written_again_only_when_absent(verdict, writes):
    events, verdicts = [], {7: "present", 8: "unknown"}

    def audit(event):
        if event["event_type"] == REQUESTED:
            raise AuditOutcomeUnknown("x", entry=_entry(7, event), path=Path("p"),
                                      absent_head=(6, "0" * 64))
        events.append(event)
        if len(events) == 1:                       # the refusal's own write is of unknown outcome
            raise AuditOutcomeUnknown("x", entry=_entry(8, event), path=Path("p"),
                                      absent_head=(7, "0" * 64))

    broker = _broker(audit, request_settled=lambda entry: verdicts[entry.sequence])
    broker.handle(_request())
    assert len(events) == 1 and len(broker.deferred) == 1       # written once, held for its verdict
    broker.flush_deferred()
    assert len(events) == 1                                     # still unknown: not written again
    verdicts[8] = verdict
    broker.flush_deferred()
    broker.flush_deferred()
    assert len(events) == writes and broker.deferred == []
    assert all(event["requested_sequence"] == 7 for event in events)


def test_a_latch_record_dropped_before_start_up_is_counted_as_unrecorded(monkeypatch, tmp_path):
    """The latch's own line is dropped before `commissioning`; it is counted like the transport's."""
    from azazel_nexus_runtime import knowledge_contextd as kc
    from azazel_nexus_runtime import runtime_paths

    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    runtime_paths.knowledge_context_state_dir().mkdir(parents=True)
    runtime_paths.socket_path("knowledge-context").parent.mkdir(parents=True)
    path = runtime_paths.knowledge_context_state_dir() / "context.jsonl"
    path.write_bytes(b"{not json\n")
    path.chmod(0)                                    # unreadable, not broken: start-up cannot finish
    captured = {}
    monkeypatch.setattr(kc, "serve_forever", lambda **kw: captured.update(kw) or 0)
    monkeypatch.setattr(kc.PrincipalPolicy, "resolve", lambda **kw: "policy")
    assert kc.main([]) == 0
    guard = captured["audit"].__self__
    broker = captured["handler"].__self__
    before = guard.refusals_unrecorded
    broker._record_latch("missing")
    path.chmod(0o600)
    assert guard.refusals_unrecorded == before + 1 and path.read_bytes() == b"{not json\n"


def _request_far():
    from test_knowledge_contextd import _request

    return _request(payload={"frame": {"privacy_class": "P0-public", "techniques": ["T1059"]}},
                    deadline_monotonic_ns=2**62)


@pytest.mark.parametrize("when", ["after_gate", "after_record"])
def test_a_request_whose_deadline_passed_while_the_ledger_was_checked_sends_nothing(when):
    clock, sent, events = [100.0], [], []
    broker = _broker(lambda event: events.append(event) or (
        clock.__setitem__(0, 200.0) if when == "after_record"
        and event["event_type"] == REQUESTED else None),
        send_allowed=lambda: clock.__setitem__(0, 200.0) or True if when == "after_gate" else True,
        monotonic=lambda: clock[0])
    broker._client.request_context = lambda **kw: sent.append(kw)
    reply = broker.handle(_request_far())
    assert sent == [] and reply["refusal"] == "timeout"
    assert [e["event_type"] for e in events][-1] == COMPLETED


def test_the_client_gets_the_time_that_is_left_after_the_record():
    clock, got = [100.0], []
    broker = _broker(lambda event: clock.__setitem__(0, 100.3) if event["event_type"] == REQUESTED
                     else None, monotonic=lambda: clock[0])
    broker._client.request_context = lambda **kw: got.append(kw["deadline_s"]) or {"x": 1}
    broker.handle(_request_far())
    assert got and got[0] < 0.2 + 1e-9               # the request's 0.5 s minus the 0.3 s spent


@pytest.mark.parametrize("verdict, counted", [("present", 0), ("absent", 1)])
def test_a_dropped_line_of_unknown_outcome_is_counted_only_when_absent(verdict, counted):
    drops, state = [], {"verdict": "unknown"}

    def audit(event):
        raise AuditOutcomeUnknown("x", entry=_entry(9, event), path=Path("p"),
                                  absent_head=(8, "0" * 64))

    broker = _broker(audit, request_settled=lambda entry: state["verdict"],
                     dropped=lambda: drops.append(1))
    broker._record_latch("missing")
    broker.flush_deferred()
    assert drops == []                               # not known yet: not counted
    state["verdict"] = verdict
    broker.flush_deferred()
    broker.flush_deferred()
    assert len(drops) == counted                     # once at most, and only if absent


def test_a_dropped_line_that_failed_outright_is_counted_once():
    from azazel_nexus.audit import AuditUnavailable

    drops = []

    def audit(event):
        raise AuditUnavailable("x")

    broker = _broker(audit, dropped=lambda: drops.append(1))
    broker._record_latch("missing")
    broker.flush_deferred()
    assert len(drops) == 1


@pytest.mark.parametrize("verdict, counted", [("present", 0), ("absent", 1)])
def test_a_transport_refusal_line_of_unknown_outcome_is_counted_only_when_absent(verdict, counted):
    from azazel_nexus_runtime.knowledge_contextd import _ContextGuard

    def append(event):
        raise AuditOutcomeUnknown("x", entry=_entry(4, event), path=Path("p"),
                                  absent_head=(3, "0" * 64))

    guard = _ContextGuard(append)
    guard.record_refusal({"event_type": "runtime.request_refused"})
    assert guard.refusals_unrecorded == 0            # not counted before it is settled
    guard.settle_refusals(lambda entry: "unknown")
    assert guard.refusals_unrecorded == 0
    guard.settle_refusals(lambda entry: verdict)
    guard.settle_refusals(lambda entry: verdict)
    assert guard.refusals_unrecorded == counted


def test_a_check_that_fails_after_the_deadline_answers_timeout():
    clock = [100.0]
    broker = _broker(lambda event: None,
                     send_allowed=lambda: clock.__setitem__(0, 200.0) or False,
                     monotonic=lambda: clock[0])
    reply = broker.handle(_request_far())
    assert reply == {"refusal": "timeout", "stage": "refused_before_send"}


def test_a_record_of_unknown_outcome_that_took_the_rest_of_the_time_answers_timeout():
    clock, held = [100.0], []

    def audit(event):
        if event["event_type"] == REQUESTED:
            clock[0] = 200.0
            raise AuditOutcomeUnknown("x", entry=_entry(7, event), path=Path("p"),
                                      absent_head=(6, "0" * 64))

    broker = _broker(audit, request_settled=lambda entry: "unknown", monotonic=lambda: clock[0])
    reply = broker.handle(_request_far())
    assert reply == {"refusal": "timeout", "stage": "refused_before_send"}
    assert len(broker.deferred) == 1                 # the line in doubt is still settled later


def test_a_relocated_harness_without_a_ready_notification_still_starts(monkeypatch, tmp_path):
    """`runtime_ready_callback()` is None off the real root; the start-up records still run."""
    from azazel_nexus_runtime import knowledge_contextd as kc
    from azazel_nexus_runtime import runtime_paths

    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    runtime_paths.knowledge_context_state_dir().mkdir(parents=True)
    runtime_paths.socket_path("knowledge-context").parent.mkdir(parents=True)
    monkeypatch.setattr(kc, "runtime_ready_callback", lambda: None)
    monkeypatch.setattr(kc, "serve_forever", lambda **kw: kw["ready"]() or 0)
    monkeypatch.setattr(kc.PrincipalPolicy, "resolve", lambda **kw: "policy")
    assert kc.main([]) == 0
    state = runtime_paths.knowledge_context_state_dir()
    assert "knowledge.context.commissioning" in (state / "context.jsonl").read_text()


def test_a_requested_line_with_a_refusal_waiting_gets_one_result_only(tmp_path):
    """The scan does not write `restart_unconfirmed` for a line whose refusal is still to be written."""
    from azazel_nexus_runtime.chain_guard import settle_single
    from azazel_nexus_runtime.knowledge_contextd import _ContextGuard, _Recovery

    ledger = AuditLedger(tmp_path / "context.jsonl")
    row = ledger.append({"event_type": REQUESTED, "outcome": "attempted", "format": 2})
    key, held = (row.sequence, row.event_hash), {(row.sequence, row.event_hash)}
    guard = _ContextGuard(ledger.append, settle_single(ledger))
    recovery = _Recovery(ledger, guard, {"event_type": "knowledge.context.commissioning",
                                         "outcome": "absent"}, lock_fd=-1, held=lambda: held)
    recovery.attempt()
    unknown = [r for r in ledger if r.event.get("outcome") == "unknown"]
    assert unknown == [] and recovery.unresolved == 1 and not recovery.open   # waits for its refusal
    # The refusal is written by its own path, with the reference.
    ledger.append({"event_type": COMPLETED, "outcome": "unavailable",
                   "reason_code": "refused_before_send",
                   "requested_sequence": key[0], "requested_hash": key[1]})
    held.clear()
    recovery.attempt()
    results = [r for r in ledger if r.event["event_type"] == COMPLETED]
    assert len(results) == 1 and recovery.unresolved == 0 and recovery.open


def test_a_refusal_that_cannot_be_written_is_held_and_nothing_is_sent_meanwhile():
    from azazel_nexus.audit import AuditUnavailable

    clock, state, events, sent = [100.0], {"fail": True}, [], []

    def audit(event):
        if event["event_type"] == REQUESTED:
            if state["fail"]:
                clock[0] = 200.0                     # the deadline passes right after it
            return _entry(5, event)
        if state["fail"]:
            raise AuditUnavailable("x")
        events.append(event)

    broker = _broker(audit, monotonic=lambda: clock[0])
    broker._client.request_context = lambda **kw: sent.append(kw) or {"x": 1}
    assert broker.handle(_request_far())["refusal"] == "timeout"
    assert len(broker.deferred) == 1 and events == []         # `requested` has no result yet
    clock[0] = 100.0
    broker.handle(_request_far())                             # the next request: not sent
    assert sent == []
    state["fail"] = False
    broker.flush_deferred()
    assert len(events) == 1 and events[0]["requested_sequence"] == 5 and broker.deferred == []
    broker.handle(_request_far())
    assert len(sent) == 1                                     # open again, one result written


def test_a_refusal_held_after_present_is_settled_still_blocks_a_send_until_written():
    from azazel_nexus.audit import AuditUnavailable

    state, events, sent = {"fail": True}, [], []

    def audit(event):
        if event["event_type"] == REQUESTED:
            raise AuditOutcomeUnknown("x", entry=_entry(7, event), path=Path("p"),
                                      absent_head=(6, "0" * 64))
        if state["fail"]:
            raise AuditUnavailable("x")
        events.append(event)

    broker = _broker(audit, request_settled=lambda entry: "present")
    broker._client.request_context = lambda **kw: sent.append(kw)
    broker.handle(_request_far())
    assert len(broker.deferred) == 1 and sent == []
    broker.handle(_request_far())
    assert sent == []                                         # still held: closed
    state["fail"] = False
    broker.flush_deferred()
    assert len(events) == 1 and events[0]["requested_sequence"] == 7
