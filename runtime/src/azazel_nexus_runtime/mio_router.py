"""In-process M.I.O. route owner; composed by a future entry, never a daemon.

Admission and predictions are supplied readings, not inferred from readiness.
Each decision is durable before its dispatch. Audit failures propagate, including
failures in the remote hook before transport; they are never provider failures.

One request has one deadline on the monotonic clock. The first attempt, the
fallback and the reading of each reply all take what is left of it; nothing is
given a fresh copy of the caller's budget, no AI attempt starts without room
for one, and a reply that arrives after the deadline is discarded. At most two
AI attempts are made. Every request that no AI answered ends in the
deterministic handoff, which calls no AI and records why it was reached.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from azazel_nexus.mio_profile import MioProfile
from azazel_nexus.remote_envelope import EnvelopeRefusal
from azazel_nexus.remote_trust import RemoteAdmission
from azazel_nexus.route_audit import (
    outcome_and_record,
    select_and_record,
)
from azazel_nexus.route_evidence import Prediction
from azazel_nexus.route_selection import (
    RequestOutcome,
    Selection,
    TerminalEvent,
    fallback_once,
)
from azazel_nexus.routing import Route
from azazel_nexus.sanitizer import PrivacyClass

from .mio_locald import LocalRuntimeService
from .mio_remoted import RemoteInferenceService
from .mio_route_ledger import RouteLedger
from .runtime_paths import mio_state_dir


#: At most two AI attempts per request: the selected route and one fallback.
MAX_AI_ATTEMPTS = 2
#: Kept back from every AI attempt for the deterministic terminal step: its
#: ledger records and the entry's validation of the reply. A software budget,
#: not measured hardware latency.
HANDOFF_RESERVE_MS = 50
#: An AI attempt is not started with less than this left after the reserve.
#: Below it a provider cannot even return and validate a bounded reply, so
#: starting one would only spend the time the handoff needs.
MIN_AI_ATTEMPT_MS = 100
_FIXED_REFUSAL = re.compile(r"[a-z][a-z0-9_]{0,63}")


@dataclass(frozen=True)
class RouterReply:
    selection: Selection
    route: Route
    outcome: RequestOutcome
    reply: dict
    #: How many AI attempts this request made (0, 1 or 2).
    ai_attempts: int = 0
    #: One bounded entry per AI attempt that did not answer: the route, its
    #: terminal event and, when the reply carried one, its fixed refusal word.
    failures: tuple[dict, ...] = field(default_factory=tuple)


def terminal_for(reply: Mapping[str, Any]) -> TerminalEvent:
    """Readiness is not an advisory, and received bytes are not an answer."""
    outcome = reply.get("outcome")
    if outcome == "not_sent" and reply.get("refusal") in {
        *(refusal.value for refusal in EnvelopeRefusal),
        "malformed_payload",
        "class_not_remote_eligible",
        "class_not_permitted",
    }:
        return TerminalEvent.SANITIZER_FAILED
    return {
        "advisory": TerminalEvent.ANSWERED,
        "timed_out": TerminalEvent.TIMED_OUT,
        "tls_failed": TerminalEvent.TLS_FAILED,
        "not_advice": TerminalEvent.NOT_ADVICE,
    }.get(outcome, TerminalEvent.FAILED)


class MioRouter:
    """Serialize calls through one owner with its own segmented route chain.

    Requests are separate because the existing local and remote services have
    different verbs. Neither request is copied to an audit record. This owner
    adds no socket, provider, admission override or process launcher.
    """

    def __init__(
        self,
        *,
        remote: RemoteInferenceService | None = None,
        local: LocalRuntimeService | None = None,
        clock: Callable[[], str] = lambda: datetime.now(UTC).isoformat(),
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.ledger = RouteLedger(mio_state_dir())
        self._remote = remote if remote is not None else RemoteInferenceService()
        self._local = local if local is not None else LocalRuntimeService()
        self._clock = clock
        #: The one clock every deadline of a request is measured on.
        self._monotonic = monotonic

    def _record(self, event: dict, *, reserved: bool = False,
                occurred_at: str | None = None) -> None:
        dated = {**event, "occurred_at": occurred_at if occurred_at is not None else self._clock()}
        if reserved:
            # Start, capability and refusal records may use the segment's
            # control reserve; request records may not.
            self.ledger.append(dated, reserved=True)
        else:
            self.ledger.append(dated)

    def remaining_ms(self, deadline_at: float) -> int:
        """Whole milliseconds left before `deadline_at`; never negative."""
        return max(0, int((deadline_at - self._monotonic()) * 1000))

    @staticmethod
    def _bounded(local_request: Any, budget_ms: int) -> Any:
        """The same request with the attempt's share of the one deadline.

        Only a request that carries a `deadline_ms` argument is rewritten; the
        caller's object is never mutated, so nothing downstream can read the
        original budget as its own.
        """
        arguments = getattr(local_request, "arguments", None)
        if type(arguments) is not dict or "deadline_ms" not in arguments:
            return local_request
        fields = dict(vars(local_request))
        fields["arguments"] = {**arguments, "deadline_ms": budget_ms}
        return SimpleNamespace(**fields)

    def _attempt(self, route: Route, local_request: Any, remote_request: Any,
                 budget_ms: int) -> dict:
        if route is Route.REMOTE:
            reply = self._remote.handle(remote_request, audit=self._record)
            self._record({
                "event_type": "mio.remote.response",
                "outcome": reply["outcome"],
                "refusal": reply["refusal"],
                "response_digest": reply.get("response_digest"),
                "advisory_fields": reply.get("advisory_fields", 0),
            })
            return reply
        request = self._bounded(local_request, budget_ms)
        if getattr(getattr(request, "verb", None), "name", None) == "mio.local.infer":
            return self._local.handle(request, audit=self._record)
        return self._local.handle(request)

    def handle(
        self,
        *,
        local_request: Any,
        remote_request: Any,
        profile: MioProfile,
        privacy_class: PrivacyClass,
        remote: RemoteAdmission,
        local_admitted: bool,
        local_refusal: str,
        predictions: Mapping[Route, Prediction],
        deadline_ms: int,
        deadline_at: float | None = None,
    ) -> RouterReply:
        # The request's one deadline. An entry that started measuring earlier
        # passes its own; otherwise it begins here. Nothing below adds to it.
        if deadline_at is None:
            deadline_at = self._monotonic() + deadline_ms / 1000
        selection = select_and_record(
            ledger=self.ledger,
            occurred_at=self._clock(),
            profile=profile,
            privacy_class=privacy_class,
            remote=remote,
            local_admitted=local_admitted,
            local_refusal=local_refusal,
            predictions=predictions,
            # Selection compares predictions with what is left, not with the
            # budget the caller started from.
            deadline_ms=max(1, min(deadline_ms, self.remaining_ms(deadline_at))),
        )
        route = selection.route
        attempts = 0
        failures: list[dict] = []
        cause = "selected"
        # Two AI attempts maximum. There is no retry to the failed provider,
        # and the fallback target comes from the permitted set recorded above.
        while route is not Route.DETERMINISTIC_HANDOFF and attempts < MAX_AI_ATTEMPTS:
            budget = self.remaining_ms(deadline_at) - HANDOFF_RESERVE_MS
            if budget < MIN_AI_ATTEMPT_MS:
                # Not started: an attempt with no room cannot answer, and it
                # would take the time the deterministic step needs.
                self._record({
                    "event_type": "mio.route.not_started",
                    "route": route.value,
                    "reason": "deadline_budget_insufficient",
                    "remaining_ms": max(0, budget + HANDOFF_RESERVE_MS),
                })
                cause = "deadline_budget_insufficient"
                break
            attempts += 1
            reply = self._attempt(route, local_request, remote_request, budget)
            late = self._monotonic() >= deadline_at
            if late:
                # Whatever came back, it came back too late to be the answer.
                self._record({
                    "event_type": "mio.route.late_reply",
                    "route": route.value,
                    "discarded": True,
                })
                reply = {"outcome": "timed_out", "refusal": "deadline"}
            reason = None
            if route is Route.LOCAL and "readiness" in reply:
                self._record({
                    "event_type": "mio.local.readiness",
                    "readiness": reply["readiness"],
                    "reason": reply["reason"],
                })
                if reply["readiness"] != "refused":
                    # Readiness supplies no answer. Only an explicit refusal
                    # justifies falling back; missing assessment is no failure.
                    reason = {
                        "ready": "local_ready_no_answer",
                        "not_assessed": "local_not_assessed_no_answer",
                    }.get(reply["readiness"], "local_unknown_readiness_no_answer")
            terminal = TerminalEvent.NO_ANSWER if reason is not None else terminal_for(reply)
            outcome = outcome_and_record(
                ledger=self.ledger,
                occurred_at=self._clock(),
                route=route,
                terminal_event=terminal,
                fallback_available=reason is None and attempts < MAX_AI_ATTEMPTS,
                **({"reason": reason} if reason is not None else {}),
            )
            if outcome is RequestOutcome.ANSWERED:
                return RouterReply(selection, route, outcome, reply,
                                   ai_attempts=attempts, failures=tuple(failures))
            failure = {"route": route.value, "terminal_event": terminal.value}
            refusal = reason if reason is not None else reply.get("refusal")
            if type(refusal) is str and _FIXED_REFUSAL.fullmatch(refusal):
                failure["refusal"] = refusal
            failures.append(failure)
            if outcome is not RequestOutcome.FELL_BACK:
                # A refusal (a sanitiser that did not hold, no answer, or the
                # second failure) ends the AI path here. It is not retried and
                # nothing wider is tried in its place.
                cause = "ai_attempts_ended"
                break
            fallback = fallback_once(
                selection=selection,
                failed=route,
                already_spent=False,
            )
            event = fallback.as_event()
            if route is Route.LOCAL and "readiness" in reply:
                event["reason"] = "local readiness refused: " + reply["reason"] + "; " + fallback.reason
            self._record(event)
            route = fallback.route
            cause = ("no_permitted_fallback" if route is Route.DETERMINISTIC_HANDOFF
                     else "fallback")
        return self._handoff(selection, attempts, failures, cause)

    def _handoff(self, selection: Selection, attempts: int, failures: list[dict],
                 cause: str) -> RouterReply:
        """The terminal step every unanswered request reaches. It calls no AI.

        It needs nothing from Edge -- no detection, decision or evidence --
        and nothing from a provider: it records why it was reached and hands
        the request to the deterministic path, whose authority stays Edge's.
        """
        if attempts >= MAX_AI_ATTEMPTS and cause in {"fallback", "ai_attempts_ended"}:
            cause = "ai_attempts_exhausted"
        self._record({
            "event_type": "mio.route.handoff",
            "cause": cause,
            "ai_attempts": attempts,
            "failures": list(failures),
        })
        reply = {"outcome": "handoff"}
        outcome = outcome_and_record(
            ledger=self.ledger,
            occurred_at=self._clock(),
            route=Route.DETERMINISTIC_HANDOFF,
            terminal_event=terminal_for(reply),
            fallback_available=False,
        )
        return RouterReply(selection, Route.DETERMINISTIC_HANDOFF, outcome, reply,
                           ai_attempts=attempts, failures=tuple(failures))
