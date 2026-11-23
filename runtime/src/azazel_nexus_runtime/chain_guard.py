"""One daemon's view of its ledger once the running chain turned out broken.

A break found while serving is the break found at start, except that the
process stays up: requests that need a record are refused with a fixed reason,
the ledger is not touched again, and nothing clears the state but a restart
(which verifies the chain again). Kept per daemon boundary; the shared
transport and serve loop are unchanged.
"""

from __future__ import annotations

from typing import Any, Callable

from azazel_nexus.audit import AuditChainBroken


class ChainGuard:
    def __init__(self, append: Callable[[dict], Any]) -> None:
        self._append = append
        self.broken = False
        #: Memory only; never sent to a caller.
        self.reason: str | None = None
        #: Refusal records that were not written because the chain is broken.
        self.refusals_unrecorded = 0

    def _mark(self, exc: BaseException) -> None:
        self.broken = True
        self.reason = str(exc)

    def append(self, event: dict) -> Any:
        """The audit callable for a request in flight."""
        if self.broken:
            raise AuditChainBroken(self.reason or "chain broken")
        try:
            return self._append(event)
        except AuditChainBroken as exc:
            self._mark(exc)
            raise

    def record_refusal(self, event: dict) -> None:
        """The audit callable of the transport: a refusal is already on its way back."""
        if self.broken:
            self.refusals_unrecorded += 1
            return
        try:
            self._append(event)
        except AuditChainBroken as exc:
            self._mark(exc)
            self.refusals_unrecorded += 1

    def best_effort(self, event: dict) -> None:
        """Record `event` if the chain allows; a break is noted and never raised.

        For work that narrows (withdrawal, resource release) and must finish
        whether or not its record can be written.
        """
        try:
            self.append(event)
        except AuditChainBroken:
            pass

    def count_unrecorded(self) -> None:
        """A refusal returned in-band, which the transport never records."""
        self.refusals_unrecorded += 1

    def guarded(self, handler: Callable[[Any], Any], refuse: Callable[[], Any]) -> Callable[[Any], Any]:
        """`handler` that answers `refuse()` instead of serving on a broken chain."""

        def handle(request: Any) -> Any:
            if self.broken:
                return refuse()
            try:
                reply = handler(request)
            except AuditChainBroken as exc:
                self._mark(exc)
                return refuse()
            if self.broken:
                # A break swallowed inside the handler: the reply is unrecorded.
                return refuse()
            return reply

        # Callers that inspect the daemon's service through its handler still find it.
        handle.__self__ = getattr(handler, "__self__", None)
        return handle
