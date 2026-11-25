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


def _seed(ctx: Ctx, *events: dict) -> None:
    ledger = AuditLedger(ctx.run / LEDGER)
    for event in events:
        ledger.append(event)


COMMISSIONED = {"event_type": "knowledge.context.commissioning", "outcome": "commissioned"}


@pytest.mark.real_process
def test_a_broken_chain_is_not_completed_and_egress_stays_closed(ctx):
    _seed(ctx, COMMISSIONED, {"event_type": REQUESTED, "outcome": "attempted", "format": 2})
    path = ctx.run / LEDGER
    path.write_text(path.read_text().replace("commissioned", "commissionee", 1))
    before = path.read_bytes()
    assert ctx.start()
    status = ctx.status()
    assert status["egress"] == "closed" and status["reason"] == "ledger_broken"
    assert path.read_bytes() == before                  # nothing added, nothing filled in
    refused = ctx.request(1)["reply"]["result"]
    assert refused == {"refusal": "unavailable", "stage": "refused_before_send"}
    assert ctx.calls() == 0 and path.read_bytes() == before
    note("broken chain", observed_sends=0, ledger="chain broken; status reason ledger_broken",
         added_rows=0, added_sends=0)


def _surrogate() -> bytes:
    return ('{"event":{"event_type":"x","t":"\\ud800"},"event_hash":"' + "0" * 64
            + '","previous_hash":"' + "0" * 64 + '","sequence":1}\n').encode()


@pytest.mark.real_process
@pytest.mark.parametrize("label, content", [
    ("broken json", b"{not json\n"),
    ("torn line", b'{"sequence":1,"event'),
    ("lone surrogate", None),
])
def test_a_ledger_that_cannot_be_verified_starts_closed_and_serves_status(ctx, label, content):
    path = ctx.run / LEDGER
    path.write_bytes(_surrogate() if content is None else content)
    before = path.read_bytes()
    assert ctx.start(), ctx.exit_info()                      # it bound and serves
    status = ctx.status()
    assert status["egress"] == "closed" and status["reason"] == "ledger_broken", label
    refused = ctx.request(1)["reply"]["result"]
    assert refused == {"refusal": "unavailable", "stage": "refused_before_send"}
    assert ctx.calls() == 0 and path.read_bytes() == before, label


@pytest.mark.real_process
def test_an_unreadable_ledger_starts_closed_without_writing(ctx):
    path = ctx.run / LEDGER
    path.write_bytes(b"")
    ctx.arm("persist")                                      # every ledger open fails
    assert ctx.start(), ctx.exit_info()
    status = ctx.status()
    assert status["egress"] == "closed" and status["reason"] == "ledger_unreadable"
    assert ctx.faults() >= 1                                # the injection fired
    assert ctx.request(1)["reply"]["result"]["refusal"] == "unavailable"
    assert ctx.calls() == 0 and path.read_bytes() == b""


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
    ledger_bytes = (ctx.run / LEDGER).read_bytes()
    env = {**os.environ, "AZAZEL_ROOT": "r", "PYTHONDONTWRITEBYTECODE": "1"}
    second = subprocess.run([sys.executable, str(CHILD)], cwd=ctx.run, env=env, timeout=30,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    assert second.returncode != 0 and b"another one holds the ledger" in second.stderr
    assert (sock.stat().st_ino, sock.stat().st_dev) == ident     # the socket was not replaced
    assert ctx.alive() and ctx.status()["egress"] == "open"
    assert (ctx.run / LEDGER).read_bytes() == ledger_bytes       # nothing appended
    assert served(ctx.request(1))
    note("second start", observed_sends=ctx.calls(),
         ledger="lock held by the first; the second exits with rc!=0; socket inode and ledger unchanged",
         added_rows=0, added_sends=0)


@pytest.mark.real_process
def test_missing_directories_end_the_start_and_are_not_made(ctx):
    state = ctx.run / STATE / "knowledge-context"
    run_dir = ctx.run / "r/var/lib/azazel/run/knowledge-context"
    shutil.rmtree(run_dir)
    assert ctx.start() is False
    assert b"does not exist" in ctx.stderr_path.read_bytes() and not run_dir.exists()
    assert not (state / "context.jsonl").exists()
    run_dir.mkdir()
    shutil.rmtree(state)
    assert ctx.start() is False
    assert not state.exists() and not (ctx.run / "ready").exists()


@pytest.mark.real_process
def test_a_lock_that_cannot_be_made_ends_the_start_before_bind(ctx):
    state = ctx.run / STATE / "knowledge-context"
    state.chmod(0o500)
    try:
        if os.access(state, os.W_OK):
            pytest.skip("the directory stays writable (running as root)")
        assert ctx.start() is False
        assert b"writer lock" in ctx.stderr_path.read_bytes()
        assert not (ctx.run / "r/var/lib/azazel/run/knowledge-context/knowledge-context.sock").exists()
        assert not (state / "context.jsonl").exists()
    finally:
        state.chmod(0o700)


@pytest.mark.real_process
def test_a_start_that_cannot_bind_writes_nothing(ctx):
    sock = ctx.run / "r/var/lib/azazel/run/knowledge-context/knowledge-context.sock"
    sock.mkdir()                                     # a directory: bind_socket refuses it
    (sock / "x").write_text("x")
    assert ctx.start() is False
    assert not (ctx.run / LEDGER).exists()


@pytest.mark.real_process
def test_start_up_reads_the_ledger_once_and_between_requests_nothing_is_touched(ctx):
    _seed(ctx, COMMISSIONED, {"event_type": REQUESTED, "outcome": "attempted", "format": 2})
    assert ctx.start()
    assert ctx.reads() == 1                          # chain and references in one read
    path = ctx.run / LEDGER
    state = (path.stat().st_mtime_ns, path.stat().st_size)
    ctx.arm("persist")                               # a touch of the ledger would fail and be logged
    faults = ctx.faults()
    time.sleep(1.5)                                  # several poll intervals
    assert ctx.reads() == 1 and ctx.faults() == faults
    assert (path.stat().st_mtime_ns, path.stat().st_size) == state


@pytest.mark.real_process
def test_work_still_waiting_is_not_touched_between_requests(ctx):
    _seed(ctx, COMMISSIONED, {"event_type": REQUESTED, "outcome": "attempted", "format": 2})
    ctx.arm("pre", 1)                                # the first append of start-up fails
    assert ctx.start()
    assert ctx.faults() == 1 and ctx.status()["unresolved"] == 2
    rows, reads = len(ctx.rows()), ctx.reads()
    time.sleep(1.5)                                  # six accept timeouts, no request
    assert (len(ctx.rows()), ctx.reads()) == (rows, reads)
    assert ctx.status()["unresolved"] == 2


@pytest.mark.real_process
def test_each_request_does_one_ledger_step_and_sends_nothing_until_start_up_is_complete(ctx):
    _seed(ctx, COMMISSIONED,
          {"event_type": REQUESTED, "outcome": "attempted", "format": 2},
          {"event_type": REQUESTED, "outcome": "attempted", "format": 2})
    ctx.arm("pre", 1)                                # the first append of start-up fails
    assert ctx.start()
    assert ctx.faults() == 1                         # the injection fired
    status = ctx.status()
    assert status["egress"] == "closed" and status["unresolved"] == 3     # commissioning + 2 rows
    base = len(ctx.rows())
    steps = []
    for variant in (1, 2, 3):
        reply = ctx.request(variant)
        steps.append(len(ctx.rows()) - base)
        assert not served(reply) or variant == 3
        base = len(ctx.rows())
    assert steps[:2] == [1, 1]                       # one append each, and no send
    assert ctx.calls() == 1 and len(ctx.unknown_rows()) == 2
    assert ctx.status()["egress"] == "open" and ctx.status()["recovered"] == 2
    note("control: one step per request", observed_sends=0,
         ledger="3 steps owed after a failed start-up append", added_rows=3, added_sends=0)


@pytest.mark.real_process
def test_the_latch_and_status_work_while_the_ledger_fails_and_nothing_is_sent(ctx):
    assert ctx.start()
    assert served(ctx.request(0))
    ctx.arm("fsync", 2)                              # the 2nd sync after this: the result row of request 1
    unrecorded = ctx.request(1)["reply"]["result"]
    assert unrecorded["stage"] == "unrecorded" and ctx.faults() == 1
    assert ctx.status()["audit"] == "owed" and ctx.status()["egress"] == "closed"
    sends = ctx.calls()
    ctx.arm("persist")
    faults = ctx.faults()
    assert ctx.request(2)["reply"]["result"]["stage"] == "refused_before_send"
    assert ctx.faults() > faults                     # the failure was met
    (ctx.run / RULE).unlink()                        # the observation rule is removed meanwhile
    assert ctx.request(3)["reply"]["result"]["stage"] == "refused_before_send"
    status = ctx.status()
    assert status["egress"] == "closed" and status["audit"] == "owed"
    assert ctx.calls() == sends                      # nothing was sent while it failed
    ctx.arm("off")
    assert ctx.request(4)["reply"]["result"]["stage"] == "refused_before_send"
    assert ctx.calls() == sends                      # the latch held after the ledger came back
    note("control: audit failure, latch and status", observed_sends=ctx.calls() - sends,
         ledger="owed result; status answered; latch closed the gate; 0 sends during the fault",
         added_rows=0, added_sends=0)


@pytest.mark.real_process
def test_after_the_ledger_recovers_a_new_valid_request_is_served(ctx):
    assert ctx.start()
    assert served(ctx.request(0))
    ctx.arm("fsync", 2)
    assert ctx.request(1)["reply"]["result"]["stage"] == "unrecorded" and ctx.faults() == 1
    ctx.arm("persist")
    assert ctx.request(2)["reply"]["result"]["stage"] == "refused_before_send"
    sends = ctx.calls()
    ctx.arm("off")
    assert served(ctx.request(3))                    # settled in this request, then served
    assert ctx.calls() == sends + 1
    status = ctx.status()
    assert status["egress"] == "open" and status["audit"] == "ok" and status["unresolved"] == 0
    AuditLedger(ctx.run / LEDGER).verify(require_terminated=True)
    note("control: recovery then a new request", observed_sends=sends,
         ledger="debt settled by one step; the new request recorded and served",
         added_rows=len(ctx.rows()), added_sends=1)


# ---- in-process: the rules, one at a time -----------------------------------

from types import SimpleNamespace  # noqa: E402

from azazel_nexus.audit import AuditUnavailable  # noqa: E402
from azazel_nexus_runtime import knowledge_contextd as kc  # noqa: E402
from azazel_nexus_runtime.chain_guard import ChainGuard, settle_single  # noqa: E402
from stop_helpers import granted_marker  # noqa: E402
from test_knowledge_contextd import OPEN_GATE, _policy, _request  # noqa: E402


def _duties(tmp_path, commissioning=None):
    ledger = AuditLedger(tmp_path / "context.jsonl")
    holder: list = []
    guard = ChainGuard(ledger.append, settle_single(ledger),
                       on_settled=lambda e, entry: holder[0].on_settled(e, entry))
    duties = kc._Duties(ledger, guard, commissioning or COMMISSIONED)
    holder.append(duties)
    return ledger, guard, duties


def _row(ledger, event):
    return ledger.append(event)


def _unknown_for(ref) -> dict:
    return {"event_type": COMPLETED, "outcome": "unknown", "reason_code": "restart_unconfirmed",
            "requested_sequence": ref.sequence, "requested_hash": ref.event_hash}


def test_a_result_is_matched_by_reference_not_by_position(tmp_path):
    ledger, _, duties = _duties(tmp_path)
    first = _row(ledger, {"event_type": REQUESTED, "outcome": "attempted", "format": 2})
    second = _row(ledger, {"event_type": REQUESTED, "outcome": "attempted", "format": 2})
    # A result that follows both, referring to the second only.
    _row(ledger, {"event_type": COMPLETED, "outcome": "verified_advisory",
                  "requested_sequence": second.sequence, "requested_hash": second.event_hash})
    # A result with the right sequence and a wrong hash closes nothing.
    _row(ledger, {"event_type": COMPLETED, "outcome": "timeout",
                  "requested_sequence": first.sequence, "requested_hash": "0" * 64})
    duties.scan()
    assert duties.verified
    assert duties.queue == [COMMISSIONED, _unknown_for(first)]


def test_a_result_inside_a_469_record_closes_its_request(tmp_path):
    ledger, _, duties = _duties(tmp_path)
    one = _row(ledger, {"event_type": REQUESTED, "outcome": "attempted", "format": 2})
    two = _row(ledger, {"event_type": REQUESTED, "outcome": "attempted", "format": 2})
    for kind, request in (("audit.late_record", one), ("audit.outcome_settled", two)):
        _row(ledger, {"event_type": kind, "performed": True, "late_event": {
            "event_type": COMPLETED, "outcome": "unavailable",
            "requested_sequence": request.sequence, "requested_hash": request.event_hash}})
    duties.scan()
    assert duties.queue == [COMMISSIONED]


def test_old_format_lines_are_counted_and_never_filled_in(tmp_path):
    ledger, _, duties = _duties(tmp_path)
    _row(ledger, {"event_type": REQUESTED, "outcome": "attempted"})
    _row(ledger, {"event_type": REQUESTED, "outcome": "attempted", "format": 1})
    duties.scan()
    assert duties.legacy_unreferenced == 2 and duties.queue == [COMMISSIONED]


def test_the_scan_is_one_read_and_a_broken_chain_adds_nothing(tmp_path, monkeypatch):
    ledger, guard, duties = _duties(tmp_path)
    _row(ledger, {"event_type": REQUESTED, "outcome": "attempted", "format": 2})
    reads = []
    real = AuditLedger.__iter__
    monkeypatch.setattr(AuditLedger, "__iter__", lambda self: reads.append(1) or real(self))
    duties.scan()
    assert len(reads) == 1
    path = tmp_path / "context.jsonl"
    path.write_text(path.read_text().replace("attempted", "attemptee"))
    other_ledger, other_guard, broken = _duties(tmp_path)
    broken.scan()
    assert not broken.verified and broken.queue == []
    assert broken.status(SimpleNamespace(_latched=False))["reason"] == "ledger_broken"
    broken.step()
    assert "commissioning" not in path.read_text()


def test_a_line_of_unknown_outcome_is_settled_before_the_next_append(tmp_path, monkeypatch):
    ledger, guard, duties = _duties(tmp_path)
    duties.scan()
    real_fsync, calls = os.fsync, []

    def fsync(fd):
        calls.append(fd)
        if len(calls) == 1:
            raise OSError("injected")
        return real_fsync(fd)

    monkeypatch.setattr("azazel_nexus.audit.os.fsync", fsync)
    duties.step()                                   # commissioning: written, sync failed
    assert len(calls) == 1                          # the injection fired
    assert guard.owed and duties.queue == [COMMISSIONED]
    duties.step()                                   # settles first; found present
    assert [row.event["event_type"] for row in ledger] == [
        "knowledge.context.commissioning", "audit.outcome_settled"]
    assert duties.queue == [] and duties.commissioned and duties.open


def test_each_step_is_one_unit_and_a_held_result_keeps_egress_closed(tmp_path):
    ledger, guard, duties = _duties(tmp_path)
    request = _row(ledger, {"event_type": REQUESTED, "outcome": "attempted", "format": 2})
    duties.scan()
    result = {"event_type": COMPLETED, "outcome": "timeout",
              "requested_sequence": request.sequence + 5, "requested_hash": "f" * 64}
    duties.hold(result)
    assert len(duties.queue) == 3 and not duties.open
    for expected in (1, 2, 3):
        before = len(list(ledger))
        duties.step()
        assert len(list(ledger)) == before + 1       # exactly one line per step
        assert len(duties.queue) == 3 - expected
    assert duties.open


def _broker(**kwargs):
    events: list = []

    class Entry:
        def __init__(self, n):
            self.sequence, self.event_hash = n, f"h{n}"

    def audit(event):
        events.append(event)
        return Entry(len(events))

    calls = []

    class Client:
        def request_context(self, **kw):
            calls.append(kw)
            return {"authority": "advisory_only"}

    broker = kc.KnowledgeContextBroker(
        client=Client(), policy=_policy(), mission="lab", alias_key=b"x" * 32, enabled=True,
        audit=kwargs.pop("audit", audit), **{**OPEN_GATE, "grant_marker": granted_marker}, **kwargs)
    return broker, events, calls


def test_requested_carries_the_format_and_every_result_refers_to_it():
    broker, events, calls = _broker()
    assert "response" in broker.handle(_request())
    requested, completed = events
    assert requested["event_type"] == REQUESTED and requested["format"] == 2
    assert completed["requested_sequence"] == 1 and completed["requested_hash"] == "h1"
    assert len(calls) == 1


def test_a_refusal_after_a_requested_line_of_unknown_outcome_refers_to_that_line():
    seen = []

    def audit(event):
        seen.append(event)
        if event["event_type"] == REQUESTED:
            raise AuditOutcomeUnknown("x", entry=SimpleNamespace(
                sequence=7, event_hash="abc", event=event), path="p", absent_head=(6, "z"))

    broker, _, calls = _broker(audit=audit)
    assert broker.handle(_request())["refusal"] == "unavailable"
    assert calls == []                                       # nothing was sent
    assert seen[-1]["requested_sequence"] == 7 and seen[-1]["requested_hash"] == "abc"


def test_the_deadline_is_judged_just_before_the_call_after_the_record():
    clock = [0.0]
    seen = []

    def audit(event):
        seen.append(event)
        if event["event_type"] == REQUESTED:
            clock[0] += 5.0                  # the record took the rest of the time

    broker, _, calls = _broker(audit=audit, monotonic=lambda: clock[0])
    assert broker.handle(_request(deadline_ms=2000, deadline_monotonic_ns=2**62)) == {
        "refusal": "timeout", "stage": "refused_before_send"}
    assert calls == [] and seen[-1]["outcome"] == "timeout"


def test_a_result_that_could_not_be_written_before_any_send_is_held_but_not_after():
    held = []
    clock = [0.0]

    def failing(event):
        if event["event_type"] == COMPLETED:
            raise AuditUnavailable("down")
        clock[0] += 5.0 if event.get("slow") else 0.0
        return SimpleNamespace(sequence=1, event_hash="h1")

    broker, _, calls = _broker(audit=failing, hold=held.append, monotonic=lambda: clock[0])
    clock[0] = 0.0
    real_audit = broker._audit
    broker._audit = lambda event: (clock.__setitem__(0, 9.0) if event["event_type"] == REQUESTED
                                   else None) or real_audit(event)
    broker.handle(_request(deadline_ms=2000, deadline_monotonic_ns=2**62))
    assert calls == [] and len(held) == 1 and held[0]["requested_sequence"] == 1
    held.clear()
    clock[0] = 0.0
    broker, _, calls = _broker(audit=failing, hold=held.append, monotonic=lambda: clock[0])
    broker.handle(_request())                        # sent: the guard owes it, not the holder
    assert len(calls) == 1 and held == []


def test_the_gate_is_judged_before_egress_is_closed_for_the_ledger(tmp_path):
    rule = tmp_path / "rule"
    rule.write_text("x")
    from azazel_nexus_runtime.knowledge_context_config import ObservationRule, observation_rule_identity

    identity = observation_rule_identity(rule)
    asked = []
    broker, events, calls = _broker(send_allowed=lambda: asked.append(1) or False)
    broker._observation = (ObservationRule("technique-set/1", 60), identity)
    broker._observation_path = rule
    rule.unlink()                                    # the rule goes away while egress is closed
    assert broker.handle(_request())["refusal"] == "unavailable"
    assert broker._latched and asked == []           # the latch came first; the ledger was not asked
    assert calls == []


def test_a_closed_egress_asks_the_owner_once_and_writes_no_row_of_its_own():
    asked = []
    broker, events, calls = _broker(send_allowed=lambda: asked.append(1) or False)
    assert broker.handle(_request()) == {"refusal": "unavailable", "stage": "refused_before_send"}
    assert asked == [1] and events == [] and calls == []


def test_the_writer_lock_is_exclusive_and_nothing_is_made_for_it(tmp_path):
    state = tmp_path / "state"
    with pytest.raises(SystemExit):
        kc._take_writer_lock(state)                  # a missing directory is not made
    assert not state.exists()
    state.mkdir()
    first = kc._take_writer_lock(state)
    try:
        with pytest.raises(SystemExit) as busy:
            kc._take_writer_lock(state)
        assert "another one holds" in str(busy.value)
    finally:
        os.close(first)
    os.close(kc._take_writer_lock(state))            # released with the descriptor
