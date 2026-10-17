"""Genesis prestart observation through first admission to the first receipt."""

from hashlib import sha256
import json

import pytest

from azazel_nexus.audit import GENESIS_HASH
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.bootstrap_audit import AuditObservation
from azazel_nexus_runtime.bootstrap_audit_client import AuditAppendReceipt
from azazel_nexus_runtime.units import UnitKey
from test_runtime_bootstrap import evidence as _harness_evidence
from test_runtime_bootstrap_initial_admission import _harness, _names


@pytest.fixture
def evidence(request):
    return _harness_evidence.__wrapped__(request)

GENESIS = AuditObservation(0, GENESIS_HASH, 0, 0)
POSITIVE = AuditObservation(1, "a" * 64, 1, 100)


class Ledger:
    """Live writer head model: empty ledger is (0, GENESIS_HASH)."""

    def __init__(self, h, *, startup=None):
        self.h = h
        self.startup = startup
        self.reads = 0

    def observe_head(self):
        self.reads += 1
        if self.reads == 1 and self.startup is not None:
            return self.startup
        events = self.h.events
        if not events:
            return 0, GENESIS_HASH
        return len(events), sha256(repr(events[-1]).encode()).hexdigest()


def _genesis_harness(evidence, *, startup=None, prestart=GENESIS):
    holder = {}
    continuation_calls = []

    def continuation(_context, previous):
        continuation_calls.append(previous)
        return previous

    h = _harness(
        evidence,
        prestart=lambda _context: prestart,
        audit_continuation=continuation,
        audit_head_reader=type("R", (), {
            "observe_head": lambda self: holder["ledger"].observe_head()})(),
    )
    # The default prestart wrapper returns HEAD only when none is supplied.
    holder["ledger"] = Ledger(h, startup=startup)
    h.ledger = holder["ledger"]
    h.continuation_calls = continuation_calls

    def record(event):
        h.events.append(event)
        h.timeline.append((event["event_type"], event.get("unit_key")))
        return AuditAppendReceipt(len(h.events), sha256(repr(event).encode()).hexdigest())

    h.supervisor.record = record
    return h


def test_genesis_first_admission_full_order_and_first_receipt_sequence_one(evidence):
    h = _genesis_harness(evidence)
    h.supervisor.run()
    names = _names(h)
    order = ["verify", "admit_generation", "prestart", "retain", "deadline_guard",
             "store.create", "open_pair", "ready", "start"]
    indexes = [names.index(n) for n in order]
    assert indexes == sorted(indexes)
    assert names.count("prestart") == 1 and names.count("retain") == 1
    # Post-retain _check continued from the genesis observation, never positive.
    assert h.continuation_calls and all(p == GENESIS for p in h.continuation_calls)

    grant = next(e for e in h.events if e["event_type"] == "bootstrap.grant_intent")
    assert h.events.index(grant) == 0
    grant_hash = sha256(repr(grant).encode()).hexdigest()
    # Live head after the first (sequence 1) receipt equals the receipt.
    assert h.ledger.reads >= 2
    expected_receipt = json.dumps(
        {"schema": "azazel-nexus/bootstrap-audit-receipt/v1",
         "sequence": 1, "event_hash": grant_hash},
        sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    assert h.grant_journal.audit_receipt_digest == (
        "sha256:" + sha256(expected_receipt).hexdigest())
    assert h.grant_journal.phase == "closed"

    calls = h.manager.calls
    auditd = calls.index(("start_and_wait", UnitKey.AUDITD))
    commissiond = calls.index(("start_and_wait", UnitKey.COMMISSIOND))
    assert auditd < commissiond
    # Grant intent recorded after auditd ready and before commissiond starts.
    assert names.index("bootstrap.grant_intent") < names.index("bootstrap.start_intent")
    assert (h.timeline.index(("bootstrap.grant_intent", None))
            < h.timeline.index(("store.advance", "audit_intent_recorded")))


def test_receipt_sequence_two_after_genesis_is_refused(evidence):
    """A receipt that skips sequence 1 cannot match the live head from genesis."""
    h = _genesis_harness(evidence)

    def skipping(event):
        h.events.append(event)
        return AuditAppendReceipt(2, sha256(repr(event).encode()).hexdigest())

    h.supervisor.record = skipping
    with pytest.raises(ApprovalRefused, match="differs from live writer head"):
        h.supervisor.run()
    assert ("start_and_wait", UnitKey.COMMISSIOND) not in h.manager.calls
    assert all(h.manager.inactive.values()) and all(h.manager.masked.values())


@pytest.mark.parametrize("startup", [(1, "b" * 64), (2, "c" * 64)])
def test_genesis_prestart_with_nongenesis_live_head_refuses(evidence, startup):
    h = _genesis_harness(evidence, startup=startup)
    with pytest.raises(ApprovalRefused, match="startup head differs"):
        h.supervisor.run()
    assert ("start_and_wait", UnitKey.COMMISSIOND) not in h.manager.calls
    assert not h.events
    assert all(h.manager.inactive.values()) and all(h.manager.masked.values())
    assert h.grant_journal.phase == "closed"


def test_positive_stopped_head_with_genesis_live_head_refuses(evidence):
    h = _genesis_harness(evidence, prestart=POSITIVE)
    with pytest.raises(ApprovalRefused, match="startup head differs"):
        h.supervisor.run()
    assert ("start_and_wait", UnitKey.COMMISSIOND) not in h.manager.calls
    assert not h.events
    assert all(h.manager.inactive.values()) and all(h.manager.masked.values())
    assert h.grant_journal.phase == "closed"
