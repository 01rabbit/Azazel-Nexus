"""One daemon's view of its ledger when writing to it fails while serving.

Three states.

`ok`: appends go through.

`broken` (#458): the running chain turned out broken. Requests that need a
record are refused with a fixed reason, the ledger is not touched again, and
nothing clears the state but a restart (which verifies the chain again).

`owed` (#467): a write's outcome is unknown (a complete line was written and
its sync failed, or an operation was done and its record could not be
written). Nothing that needs a record runs, no line is appended and no
operation is repeated, until the debt is settled: the line is looked for by its
sequence and hash (never by the head having moved), and a record of how it
turned out -- `audit.outcome_settled` or `audit.late_record` -- is appended
and read back as the head. A debt that cannot be settled (the ledger cannot be
read) stays, and the daemon keeps refusing and keeps answering diagnostics.

The guard never repeats an operation and never writes the event again.
Kept per daemon boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from azazel_nexus.audit import (
    AuditChainBroken,
    AuditEntry,
    AuditOutcomeUnknown,
    AuditUnavailable,
)

__all__ = ["ChainGuard", "Owed", "settle_by_path", "settle_segmented", "settle_single"]

SETTLED = "audit.outcome_settled"
LATE = "audit.late_record"


@dataclass
class Owed:
    """One record the ledger owes."""

    event: dict
    #: The line that may be in the ledger; None when nothing was written.
    entry: Optional[AuditEntry]
    absent_head: Optional[tuple]
    #: Whether the operation this record belongs to was already done.
    performed: bool
    #: The settlement record being written, and its own unknown line.
    record: Optional[dict] = None
    record_entry: Optional[AuditEntry] = None
    record_absent: Optional[tuple] = None
    path: Any = None
    record_path: Any = None


def settle_single(ledger) -> Callable[..., str]:
    """`settle` for a daemon with one ledger file."""
    return lambda entry, *, absent_head, path=None: ledger.settle(entry, absent_head=absent_head)


def settle_by_path(entry, *, absent_head, path) -> str:
    """`settle` for a ledger split over files: the line is looked for in its own file.

    Only for a file whose predecessors do not matter; a chain split by day uses
    `settle_segmented`.
    """
    from azazel_nexus.audit import AuditLedger

    return AuditLedger(path).settle(entry, absent_head=absent_head)


def settle_segmented(prior_head: Callable[[Any], tuple]) -> Callable[..., str]:
    """`settle` for one chain split over daily files.

    The line is looked for in its own file, and when it is (or would be) the
    first line of that file, the head before the file is derived again the way
    an append derives it (`prior_head(path)`) and must be the head the line
    was written after. A predecessor that was lost shows as a break, and a
    head that cannot be derived (a retention boundary, an unreadable file)
    leaves the outcome unknown (`AuditUnavailable`).
    """
    from azazel_nexus.audit import GENESIS_HASH, AuditLedger

    def settle(entry, *, absent_head, path) -> str:
        ledger = AuditLedger(path)
        before = tuple(prior_head(path))
        outcome = ledger.settle(entry, absent_head=absent_head)
        starts_file = (tuple(absent_head) == (0, GENESIS_HASH) if outcome == "absent"
                       else ledger.first_sequence() == entry.sequence)
        if starts_file and before != (entry.sequence - 1, entry.previous_hash):
            raise AuditChainBroken(
                f"{path} line {entry.sequence} does not follow the head before this file")
        return outcome

    return settle


class ChainGuard:
    def __init__(self, append: Callable[[dict], Any],
                 settle: Callable[..., str] | None = None,
                 append_internal: Callable[[dict], Any] | None = None,
                 sticky_break: bool = True,
                 on_settled: Callable[[dict, AuditEntry], None] | None = None) -> None:
        """`append(event)` writes one line.

        `settle(entry, absent_head=..., path=...)` looks the line up (see
        `settle_single` and `settle_by_path`); without it a line of unknown
        outcome can never be settled and the guard stays owed (it refuses,
        which is the safe side). `append_internal` writes the guard's own
        settlement records (a daemon with budgets charges them to its control
        reserve); it defaults to `append`.
        """
        #: False for a daemon that keeps its own broken state (entryd): a break
        #: still raises, and the owner decides what it means.
        self._sticky = sticky_break
        #: Called once the settlement record of a line found present is written
        #: (never before): `on_settled(event, entry)`. The owner updates what it
        #: counts, and may answer a resend of that event with the line.
        self._on_settled = on_settled
        self._append = append
        self._internal = append_internal or append
        self._settle = settle
        self.broken = False
        #: Memory only; never sent to a caller.
        self.reason: str | None = None
        #: Refusal records that were not written because the ledger could not take them.
        self.refusals_unrecorded = 0
        self.owed: list[Owed] = []
        self.last_break: str | None = None

    # -- state -----------------------------------------------------------

    @property
    def state(self) -> str:
        return "broken" if self.broken else "owed" if self.owed else "ok"

    def status(self) -> dict:
        """For a diagnostic verb: the state and the sequence not yet settled."""
        first = self.owed[0] if self.owed else None
        sequence = first.entry.sequence if first is not None and first.entry is not None else None
        return {"audit": self.state, "unsettled_sequence": sequence}

    def _mark(self, exc: BaseException) -> None:
        #: The latest break found, whether or not this guard keeps it.
        self.last_break = str(exc)
        if not self._sticky:
            return
        self.broken = True
        self.reason = str(exc)

    # -- settling --------------------------------------------------------

    def settle_owed(self) -> bool:
        """Settle what the ledger owes. Never raises; True when nothing is owed."""
        while self.owed:
            if self.broken or not self._settle_first(self.owed[0]):
                return False
            self.owed.pop(0)
        return True

    def _resolved(self, owed: Owed) -> None:
        record = owed.record
        if (self._on_settled is not None and owed.entry is not None and record is not None
                and record.get("event_type") == SETTLED and record.get("outcome") == "present"):
            self._on_settled(owed.event, owed.entry)

    def _settle_first(self, owed: Owed) -> bool:
        try:
            if owed.record_entry is not None:
                if self._settle is None:
                    return False
                outcome = self._settle(owed.record_entry, absent_head=owed.record_absent,
                                       path=owed.record_path)
                owed.record_entry = None
                if outcome == "present":
                    self._resolved(owed)
                    return True
            if owed.record is None:
                if owed.entry is None:
                    owed.record = {"event_type": LATE, "late_event": owed.event,
                                   "performed": True}
                else:
                    if self._settle is None:
                        return False
                    outcome = self._settle(owed.entry, absent_head=owed.absent_head,
                                       path=owed.path)
                    if outcome == "absent" and not owed.performed:
                        return True
                    owed.record = {"event_type": SETTLED,
                                   "settled_sequence": owed.entry.sequence,
                                   "settled_event_hash": owed.entry.event_hash,
                                   "outcome": outcome, "performed": owed.performed}
                    if outcome == "absent":
                        owed.record["late_event"] = owed.event
            self._internal(owed.record)
            self._resolved(owed)
            return True
        except AuditChainBroken as exc:
            # A break found by settling is the break found at start (#458),
            # whatever the owner keeps for itself: no settling, no appending,
            # nothing touches the ledger again until a restart verifies it.
            self._mark(exc)
            self.broken = True
            self.reason = str(exc)
            return False
        except AuditOutcomeUnknown as exc:
            owed.record_entry, owed.record_absent = exc.entry, exc.absent_head
            owed.record_path = exc.path
            return False
        except AuditUnavailable:
            return False

    # -- writing ---------------------------------------------------------

    def append(self, event: dict, *, performed: bool = False) -> Any:
        """The audit callable for a request in flight.

        `performed` says the operation this record belongs to has already
        happened, so a record that cannot be written is a debt. A record that
        precedes its operation (`performed=False`) that fails leaves nothing
        owed: the operation does not run.
        """
        if self.broken:
            raise AuditChainBroken(self.reason or "chain broken")
        if self.owed and not self.settle_owed():
            if self.broken:
                raise AuditChainBroken(self.reason or "chain broken")
            if performed:
                self.owed.append(Owed(event, None, None, True))
            raise AuditUnavailable("audit outcome not settled")
        try:
            return self._append(event)
        except AuditChainBroken as exc:
            self._mark(exc)
            raise
        except AuditOutcomeUnknown as exc:
            written = exc.entry.event
            same = written == dict(event)
            self.owed.append(Owed(written, exc.entry, exc.absent_head,
                                  performed and same, path=exc.path))
            if performed and not same:
                # The line in doubt is another one (a carried record); this
                # event was never written either.
                self.owed.append(Owed(event, None, None, True))
            raise
        except AuditUnavailable:
            if performed:
                self.owed.append(Owed(event, None, None, True))
            raise

    def record_refusal(self, event: dict) -> None:
        """The audit callable of the transport: a refusal is already on its way back.

        Never raises. A record that cannot be written is counted; a line of
        unknown outcome becomes a debt.
        """
        if self.broken:
            self.refusals_unrecorded += 1
            return
        try:
            self.append(event)
        except (AuditChainBroken, AuditUnavailable):
            self.refusals_unrecorded += 1

    def best_effort(self, event: dict) -> None:
        """Record `event` if the ledger allows; a failure is noted and never raised.

        For work that narrows (withdrawal, resource release) and must finish
        whether or not its record can be written. The work is done, so a
        record that cannot be written is a debt.
        """
        try:
            self.append(event, performed=True)
        except (AuditChainBroken, AuditUnavailable):
            pass

    def count_unrecorded(self) -> None:
        """A refusal returned in-band, which the transport never records."""
        self.refusals_unrecorded += 1

    def guarded(self, handler: Callable[[Any], Any], refuse: Callable[[], Any]) -> Callable[[Any], Any]:
        """`handler` that answers `refuse()` instead of serving while the ledger cannot be trusted.

        A result computed while a record was lost is not returned.
        """

        def handle(request: Any) -> Any:
            if self.broken:
                return refuse()
            if self.owed and not self.settle_owed():
                return refuse()
            lost = len(self.owed)
            try:
                reply = handler(request)
            except AuditChainBroken as exc:
                self._mark(exc)
                return refuse()
            except AuditUnavailable:
                return refuse()
            if self.broken or len(self.owed) > lost:
                # A failure swallowed inside the handler: the reply is unrecorded.
                return refuse()
            return reply

        # Callers that inspect the daemon's service through its handler still find it.
        handle.__self__ = getattr(handler, "__self__", None)
        return handle
