"""#467: a write whose outcome is unknown is told apart, settled by line, and guarded."""

from __future__ import annotations

import errno
import os
from types import SimpleNamespace

import pytest

from azazel_nexus.audit import (
    GENESIS_HASH, AuditChainBroken, AuditLedger, AuditOutcomeUnknown, AuditUnavailable,
)
from azazel_nexus_runtime.chain_guard import ChainGuard
from azazel_nexus_runtime.protocol import Refusal, RequestRefused
from azazel_nexus_runtime.transport import SocketServer


def _fail(monkeypatch, what):
    real = {"fsync": os.fsync, "write": None}
    if what == "fsync":
        def broken(fd):
            raise OSError(errno.EIO, "injected")
        monkeypatch.setattr(os, "fsync", broken)
    return real


def test_nothing_written_stays_plain_unavailable(tmp_path):
    ledger = AuditLedger(tmp_path / "no-dir" / "x" / "l.jsonl")
    (tmp_path / "no-dir").write_text("a file, so mkdir fails")
    with pytest.raises(AuditUnavailable) as raised:
        ledger.append({"event_type": "a"})
    assert not isinstance(raised.value, AuditOutcomeUnknown)


def test_a_complete_line_with_failed_fsync_is_unknown_and_settles_present(tmp_path, monkeypatch):
    ledger = AuditLedger(tmp_path / "l.jsonl")
    ledger.append({"event_type": "first"})
    _fail(monkeypatch, "fsync")
    with pytest.raises(AuditOutcomeUnknown) as raised:
        ledger.append({"event_type": "second"})
    monkeypatch.undo()
    unknown = raised.value
    assert unknown.entry.sequence == 2
    assert ledger.settle(unknown.entry, absent_head=unknown.absent_head) == "present"
    ledger.verify()


def test_settle_reports_absent_when_the_line_is_not_there(tmp_path):
    ledger = AuditLedger(tmp_path / "l.jsonl")
    first = ledger.append({"event_type": "first"})
    from azazel_nexus.audit import AuditEntry
    ghost = AuditEntry(2, first.event_hash, "", {"event_type": "ghost"})
    assert ledger.settle(ghost, absent_head=(1, first.event_hash)) == "absent"


def test_a_head_that_only_moved_is_not_present(tmp_path):
    """Another line at the same sequence is not ours: the head moving proves nothing."""
    ledger = AuditLedger(tmp_path / "l.jsonl")
    first = ledger.append({"event_type": "first"})
    other = ledger.append({"event_type": "someone else"})
    from azazel_nexus.audit import AuditEntry
    ours = AuditEntry(2, first.event_hash, "", {"event_type": "ours"})
    with pytest.raises(AuditChainBroken):
        ledger.settle(ours, absent_head=(1, first.event_hash))
    assert other.sequence == 2


def test_settle_on_an_unreadable_file_stays_unknown(tmp_path, monkeypatch):
    ledger = AuditLedger(tmp_path / "l.jsonl")
    first = ledger.append({"event_type": "first"})
    from azazel_nexus.audit import AuditEntry
    ghost = AuditEntry(2, first.event_hash, "", {"event_type": "ghost"})
    real = type(ledger.path).open

    def refuse(self, *a, **k):
        raise OSError(errno.EIO, "injected")
    monkeypatch.setattr(type(ledger.path), "open", refuse)
    with pytest.raises(AuditUnavailable) as raised:
        ledger.settle(ghost, absent_head=(1, first.event_hash))
    assert not isinstance(raised.value, AuditChainBroken)
    monkeypatch.setattr(type(ledger.path), "open", real)


def test_a_partial_line_that_cannot_be_withdrawn_is_unknown(tmp_path, monkeypatch):
    ledger = AuditLedger(tmp_path / "l.jsonl")
    ledger.append({"event_type": "first"})
    calls = {"n": 0}
    real_ftruncate = os.ftruncate

    class Handle:
        def __init__(self, inner):
            self.inner = inner

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.inner.close()

        def fileno(self):
            return self.inner.fileno()

        def write(self, data):
            calls["n"] += 1
            if calls["n"] == 1:
                return self.inner.write(data[:10])
            raise OSError(errno.ENOSPC, "full")

    real_open = type(ledger.path).open
    monkeypatch.setattr(type(ledger.path), "open",
                        lambda self, *a, **k: Handle(real_open(self, *a, **k)) if "ab" in a else real_open(self, *a, **k))
    monkeypatch.setattr(os, "ftruncate", lambda *a: (_ for _ in ()).throw(OSError(errno.EIO, "x")))
    with pytest.raises(AuditOutcomeUnknown) as raised:
        ledger.append({"event_type": "second"})
    monkeypatch.undo()
    # The torn line is a detected break when settled.
    with pytest.raises(AuditChainBroken):
        ledger.settle(raised.value.entry, absent_head=raised.value.absent_head)


def test_a_partial_line_that_is_withdrawn_is_plain_unavailable(tmp_path, monkeypatch):
    ledger = AuditLedger(tmp_path / "l.jsonl")
    ledger.append({"event_type": "first"})
    calls = {"n": 0}
    real_open = type(ledger.path).open

    class Handle:
        def __init__(self, inner):
            self.inner = inner

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.inner.close()

        def fileno(self):
            return self.inner.fileno()

        def write(self, data):
            calls["n"] += 1
            if calls["n"] == 1:
                return self.inner.write(data[:10])
            raise OSError(errno.ENOSPC, "full")

    monkeypatch.setattr(type(ledger.path), "open",
                        lambda self, *a, **k: Handle(real_open(self, *a, **k)) if "ab" in a else real_open(self, *a, **k))
    with pytest.raises(AuditUnavailable) as raised:
        ledger.append({"event_type": "second"})
    assert not isinstance(raised.value, AuditOutcomeUnknown)
    monkeypatch.undo()
    ledger.verify()


# -- the guard ------------------------------------------------------------

class Flaky:
    """A real ledger whose appends can be told to fail."""

    def __init__(self, path):
        self.ledger = AuditLedger(path)
        self.mode = None   # None | "pre" | "sync" | "down"
        self.calls = 0

    def append(self, event):
        self.calls += 1
        if self.mode == "pre":
            raise AuditUnavailable("pre")
        if self.mode == "down":
            raise AuditUnavailable("down")
        if self.mode == "sync":
            entry = self.ledger.append(event, sync=False)
            raise AuditOutcomeUnknown("sync", entry=entry, path=self.ledger.path,
                                      absent_head=(entry.sequence - 1, entry.previous_hash))
        return self.ledger.append(event)

    def settle(self, entry, *, absent_head, path=None):
        if self.mode == "down":
            raise AuditUnavailable("down")
        return self.ledger.settle(entry, absent_head=absent_head)


def _events(flaky):
    return [e.event for e in flaky.ledger]


def test_guard_unknown_line_is_settled_once_and_not_written_again(tmp_path):
    flaky = Flaky(tmp_path / "l.jsonl")
    guard = ChainGuard(flaky.append, flaky.settle)
    flaky.mode = "sync"
    with pytest.raises(AuditOutcomeUnknown):
        guard.append({"event_type": "op"})
    assert guard.state == "owed"
    flaky.mode = "down"
    with pytest.raises(AuditUnavailable):
        guard.append({"event_type": "next"})
    assert guard.state == "owed" and guard.status()["unsettled_sequence"] == 1
    flaky.mode = None
    guard.append({"event_type": "next"})
    kinds = [e["event_type"] for e in _events(flaky)]
    assert kinds == ["op", "audit.outcome_settled", "next"]
    assert _events(flaky)[1]["outcome"] == "present"
    flaky.ledger.verify()
    assert guard.state == "ok"


def test_guard_pre_write_failure_before_the_operation_leaves_no_debt(tmp_path):
    flaky = Flaky(tmp_path / "l.jsonl")
    guard = ChainGuard(flaky.append, flaky.settle)
    flaky.mode = "pre"
    with pytest.raises(AuditUnavailable):
        guard.append({"event_type": "op"})
    assert guard.state == "ok"


def test_guard_performed_operation_without_a_record_is_a_late_record(tmp_path):
    flaky = Flaky(tmp_path / "l.jsonl")
    guard = ChainGuard(flaky.append, flaky.settle)
    flaky.mode = "pre"
    with pytest.raises(AuditUnavailable):
        guard.append({"event_type": "sent"}, performed=True)
    assert guard.state == "owed"
    flaky.mode = None
    assert guard.settle_owed()
    only = _events(flaky)
    assert [e["event_type"] for e in only] == ["audit.late_record"]
    assert only[0]["late_event"] == {"event_type": "sent"} and only[0]["performed"] is True


def test_guard_absent_and_performed_records_the_late_event(tmp_path):
    flaky = Flaky(tmp_path / "l.jsonl")
    guard = ChainGuard(flaky.append, flaky.settle)
    flaky.ledger.append({"event_type": "base"})
    flaky.mode = "sync"
    with pytest.raises(AuditOutcomeUnknown) as raised:
        guard.append({"event_type": "sent"}, performed=True)
    # The line is lost (as after a failed fsync and a power cut).
    path = flaky.ledger.path
    text = path.read_text().splitlines()
    path.write_text(text[0] + "\n")
    flaky.mode = None
    assert guard.settle_owed()
    records = _events(flaky)
    assert records[-1]["outcome"] == "absent" and records[-1]["late_event"] == {"event_type": "sent"}
    flaky.ledger.verify()
    assert raised.value.entry.sequence == 2


def test_guard_absent_and_not_performed_needs_no_record(tmp_path):
    flaky = Flaky(tmp_path / "l.jsonl")
    guard = ChainGuard(flaky.append, flaky.settle)
    flaky.ledger.append({"event_type": "base"})
    flaky.mode = "sync"
    with pytest.raises(AuditOutcomeUnknown):
        guard.append({"event_type": "op"})
    path = flaky.ledger.path
    path.write_text(path.read_text().splitlines()[0] + "\n")
    flaky.mode = None
    assert guard.settle_owed() and guard.state == "ok"
    assert [e["event_type"] for e in _events(flaky)] == ["base"]


def test_guard_settlement_record_with_unknown_outcome_is_settled_not_repeated(tmp_path):
    flaky = Flaky(tmp_path / "l.jsonl")
    guard = ChainGuard(flaky.append, flaky.settle)
    flaky.mode = "sync"
    with pytest.raises(AuditOutcomeUnknown):
        guard.append({"event_type": "op"})
    assert not guard.settle_owed()     # the settlement record is itself unknown
    flaky.mode = None
    assert guard.settle_owed()
    kinds = [e["event_type"] for e in _events(flaky)]
    assert kinds == ["op", "audit.outcome_settled"], kinds
    flaky.ledger.verify()


def test_guard_without_a_settle_stays_owed():
    guard = ChainGuard(lambda e: (_ for _ in ()).throw(AuditUnavailable("x")))
    with pytest.raises(AuditUnavailable):
        guard.append({"event_type": "a"}, performed=True)
    assert not guard.settle_owed() and guard.state == "owed"


def test_guard_record_refusal_and_best_effort_never_raise(tmp_path):
    flaky = Flaky(tmp_path / "l.jsonl")
    guard = ChainGuard(flaky.append, flaky.settle)
    flaky.mode = "sync"
    guard.record_refusal({"event_type": "r"})
    assert guard.refusals_unrecorded == 1 and guard.state == "owed"
    flaky.mode = "down"
    guard.best_effort({"event_type": "released"})
    assert guard.state == "owed"
    flaky.mode = None
    assert guard.settle_owed()
    kinds = [e["event_type"] for e in _events(flaky)]
    assert kinds[0] == "r" and "audit.late_record" in kinds
    flaky.ledger.verify()


def test_guarded_refuses_while_owed_and_does_not_return_a_lost_record(tmp_path):
    flaky = Flaky(tmp_path / "l.jsonl")
    guard = ChainGuard(flaky.append, flaky.settle)
    ran = []

    def handler(request):
        ran.append(1)
        guard.append({"event_type": "x"})
        return "reply"

    refused = lambda: "refused"
    handle = guard.guarded(handler, refused)
    assert handle(None) == "reply"
    flaky.mode = "sync"
    assert handle(None) == "refused"
    flaky.mode = "down"
    before = len(ran)
    assert handle(None) == "refused" and len(ran) == before
    flaky.mode = None
    assert handle(None) == "reply"
    flaky.ledger.verify()


def test_transport_turns_audit_unavailable_into_a_fixed_refusal():
    sent = []

    class Conn:
        def settimeout(self, t): pass
        def sendall(self, data): sent.append(data)

    from azazel_nexus_runtime import transport
    server = SocketServer.__new__(SocketServer)
    server.audit_unavailable = 0
    server.deadline = 1
    refusals = []

    def audit(event):
        refusals.append(event)
        raise AuditUnavailable("down")
    server.audit = audit
    request = SimpleNamespace(verb=SimpleNamespace(name="v"))
    server._record_refusal(RequestRefused(Refusal.VERB_UNAVAILABLE, "ledger"), None, b"", verb="v")
    assert server.audit_unavailable == 1 and refusals


# -- a torn last line (#467, review 1 item 4) ---------------------------------

def test_a_line_missing_only_its_newline_is_not_present_and_is_not_appended_to(tmp_path):
    ledger = AuditLedger(tmp_path / "l.jsonl")
    ledger.append({"event_type": "first"})
    second = ledger.append({"event_type": "second"})
    path = ledger.path
    path.write_bytes(path.read_bytes()[:-1])     # the last byte (the newline) is missing
    with pytest.raises(AuditChainBroken):
        ledger.settle(second, absent_head=(1, second.previous_hash))
    with pytest.raises(AuditChainBroken):
        ledger.append({"event_type": "third"})
    assert not path.read_bytes().endswith(b"\n")     # nothing was joined onto it


def test_a_torn_file_is_also_refused_with_chain_from(tmp_path):
    ledger = AuditLedger(tmp_path / "l.jsonl")
    first = ledger.append({"event_type": "first"})
    ledger.path.write_bytes(ledger.path.read_bytes()[:-1])
    with pytest.raises(AuditChainBroken):
        ledger.append({"event_type": "second"}, chain_from=(1, first.event_hash))


# -- a chain split over files, and a break found by settling (items 3, 5) -----

def _two_segments(tmp_path):
    from azazel_nexus_runtime.auditd import SegmentedLedger
    ledger = SegmentedLedger(tmp_path)
    ledger.append({"event_type": "a"}, day="2026-01-01")
    return ledger


def _unknown_in_second_segment(ledger, monkeypatch):
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError(errno.EIO, "x")))
    try:
        with pytest.raises(AuditOutcomeUnknown) as raised:
            ledger.append({"event_type": "b"}, day="2026-01-02")
    finally:
        monkeypatch.setattr(os, "fsync", real)
    return raised.value


def _segmented_settle(ledger):
    from azazel_nexus_runtime.chain_guard import settle_segmented

    def prior(path):
        for segment in reversed([s for s in ledger.segments() if s.name < path.name]):
            head = AuditLedger(segment).head()
            if head != (0, GENESIS_HASH):
                return head
        return 0, GENESIS_HASH
    return settle_segmented(prior)


def test_a_lost_predecessor_segment_is_a_break_not_a_presence(tmp_path, monkeypatch):
    ledger = _two_segments(tmp_path)
    unknown = _unknown_in_second_segment(ledger, monkeypatch)
    settle = _segmented_settle(ledger)
    assert settle(unknown.entry, absent_head=unknown.absent_head, path=unknown.path) == "present"
    (tmp_path / "2026-01-01.jsonl").unlink()
    with pytest.raises(AuditChainBroken):
        settle(unknown.entry, absent_head=unknown.absent_head, path=unknown.path)


def test_a_lost_predecessor_segment_is_a_break_for_an_absent_line_too(tmp_path, monkeypatch):
    ledger = _two_segments(tmp_path)
    unknown = _unknown_in_second_segment(ledger, monkeypatch)
    unknown.path.unlink()
    settle = _segmented_settle(ledger)
    assert settle(unknown.entry, absent_head=unknown.absent_head, path=unknown.path) == "absent"
    (tmp_path / "2026-01-01.jsonl").unlink()
    with pytest.raises(AuditChainBroken):
        settle(unknown.entry, absent_head=unknown.absent_head, path=unknown.path)


def test_a_break_found_by_settling_stops_the_guard_until_a_restart(tmp_path, monkeypatch):
    ledger = _two_segments(tmp_path)
    unknown = _unknown_in_second_segment(ledger, monkeypatch)
    calls = []
    guard = ChainGuard(lambda e: calls.append(("append", e)) or ledger.append(e, day="2026-01-02"),
                       _segmented_settle(ledger), sticky_break=False)
    guard.owed.append(__import__("azazel_nexus_runtime.chain_guard", fromlist=["Owed"]).Owed(
        unknown.entry.event, unknown.entry, unknown.absent_head, False, path=unknown.path))
    (tmp_path / "2026-01-01.jsonl").unlink()
    assert not guard.settle_owed()
    assert guard.broken and guard.last_break
    size = unknown.path.stat().st_size
    # The damage is repaired on disk; the process still does not touch the ledger.
    ledger.append  # noqa: B018
    with pytest.raises(AuditChainBroken):
        guard.append({"event_type": "later"})
    assert not guard.settle_owed()
    assert calls == [] and unknown.path.stat().st_size == size


def test_route_ledger_cannot_place_a_segment_at_or_before_the_retention_boundary(tmp_path):
    import json
    from azazel_nexus_runtime.mio_route_ledger import RouteLedger
    ledger = RouteLedger(tmp_path / "state")
    ledger.directory.mkdir(parents=True)
    (ledger.directory / "retained-boundary.json").write_text(json.dumps({
        "sequence": 5, "hash": "a" * 64, "oldest": "2026-01-03.jsonl",
        "retired": "2026-01-02.jsonl"}))
    # Beyond the boundary the head is the boundary's anchor; at or before it, unknown.
    assert ledger._prior_head(ledger.directory / "2026-01-03.jsonl") == (5, "a" * 64)
    with pytest.raises(AuditUnavailable) as raised:
        ledger._prior_head(ledger.directory / "2026-01-02.jsonl")
    assert not isinstance(raised.value, AuditChainBroken)


def test_the_owners_break_stops_the_guard_whatever_found_it(tmp_path):
    flaky = Flaky(tmp_path / "l.jsonl")
    guard = ChainGuard(flaky.append, flaky.settle)
    flaky.mode = "sync"
    with pytest.raises(AuditOutcomeUnknown):
        guard.append({"event_type": "op"})
    flaky.mode = None
    broken = {"now": False}
    guard.owner_broken = lambda: broken["now"]
    broken["now"] = True                        # found by the owner's own diagnostic
    calls = flaky.calls
    assert not guard.settle_owed()
    with pytest.raises(AuditChainBroken):
        guard.append({"event_type": "later"})
    guard.record_refusal({"event_type": "r"})
    assert flaky.calls == calls and guard.state == "broken"


def test_a_lost_predecessor_is_a_break_when_the_line_in_doubt_is_not_the_first_of_its_file(
        tmp_path, monkeypatch):
    """5.1-2: N in yesterday's file, N+1 first today, N+2 in doubt; yesterday's file is gone."""
    from azazel_nexus_runtime.auditd import SegmentedLedger
    ledger = SegmentedLedger(tmp_path)
    ledger.append({"event_type": "a"}, day="2026-01-01")
    ledger.append({"event_type": "b"}, day="2026-01-02")
    unknown = _unknown_in_second_segment_third(ledger, monkeypatch)
    settle = _segmented_settle(ledger)
    assert unknown.entry.sequence == 3
    assert settle(unknown.entry, absent_head=unknown.absent_head, path=unknown.path) == "present"
    (tmp_path / "2026-01-01.jsonl").unlink()
    with pytest.raises(AuditChainBroken):
        settle(unknown.entry, absent_head=unknown.absent_head, path=unknown.path)


def _unknown_in_second_segment_third(ledger, monkeypatch):
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError(errno.EIO, "x")))
    try:
        with pytest.raises(AuditOutcomeUnknown) as raised:
            ledger.append({"event_type": "c"}, day="2026-01-02")
    finally:
        monkeypatch.setattr(os, "fsync", real)
    return raised.value


def test_a_boundary_that_cannot_be_read_leaves_the_outcome_unknown(tmp_path):
    from azazel_nexus_runtime.mio_route_ledger import RouteLedger
    ledger = RouteLedger(tmp_path / "state")
    ledger.directory.mkdir(parents=True)
    (ledger.directory / "retained-boundary.json").mkdir()       # reading it is an OSError
    with pytest.raises(AuditUnavailable) as raised:
        ledger._prior_head(ledger.directory / "2026-01-03.jsonl")
    assert not isinstance(raised.value, AuditChainBroken)


def test_a_carried_line_in_doubt_while_settling_is_its_own_debt_and_the_record_is_written_again(tmp_path):
    """5.1-3: the line in doubt while writing the settlement record is not the record."""
    flaky = Flaky(tmp_path / "l.jsonl")
    guard = ChainGuard(flaky.append, flaky.settle)
    flaky.mode = "sync"
    with pytest.raises(AuditOutcomeUnknown):
        guard.append({"event_type": "op"}, performed=True)
    # Writing the settlement record, another line (a carried record) lands first and is in doubt.
    real_internal = guard._internal
    state = {"n": 0}

    def internal(event):
        state["n"] += 1
        if state["n"] == 1:
            carried = flaky.ledger.append({"event_type": "mio.capability.carried"}, sync=False)
            raise AuditOutcomeUnknown("carried", entry=carried, path=flaky.ledger.path,
                                      absent_head=(carried.sequence - 1, carried.previous_hash))
        return real_internal(event)
    guard._internal = internal
    flaky.mode = None
    assert not guard.settle_owed()                 # the carried line first
    assert len(guard.owed) == 2 and guard.owed[0].event == {"event_type": "mio.capability.carried"}
    assert guard.settle_owed()
    kinds = [e["event_type"] for e in _events(flaky)]
    assert kinds == ["op", "mio.capability.carried", "audit.outcome_settled", "audit.outcome_settled"], kinds
    flaky.ledger.verify()
    settled = [e for e in _events(flaky) if e["event_type"] == "audit.outcome_settled"]
    assert {e["settled_sequence"] for e in settled} == {1, 2}
