"""In-process M.I.O. route owner; composed by a future entry, never a daemon.

Admission and predictions are supplied readings, not inferred from readiness.
Each decision is durable before its dispatch. Audit failures propagate, including
failures in the remote hook before transport; they are never provider failures.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from azazel_nexus.audit import AuditLedger
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
from .runtime_paths import mio_state_dir


@dataclass(frozen=True)
class RouterReply:
    selection: Selection
    route: Route
    outcome: RequestOutcome
    reply: dict


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
    """Serialize calls through one owner with its own route.jsonl chain.

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
    ) -> None:
        self.ledger = AuditLedger(mio_state_dir() / "route.jsonl")
        self._remote = remote if remote is not None else RemoteInferenceService()
        self._local = local if local is not None else LocalRuntimeService()
        self._clock = clock

    def _record(self, event: dict) -> None:
        self.ledger.append({**event, "occurred_at": self._clock()})

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
    ) -> RouterReply:
        selection = select_and_record(
            ledger=self.ledger,
            occurred_at=self._clock(),
            profile=profile,
            privacy_class=privacy_class,
            remote=remote,
            local_admitted=local_admitted,
            local_refusal=local_refusal,
            predictions=predictions,
            deadline_ms=deadline_ms,
        )
        route = selection.route
        # Two attempts maximum. There is no retry to the failed provider.
        for attempt in range(2):
            if route is Route.REMOTE:
                reply = self._remote.handle(remote_request, audit=self._record)
                self._record({
                    "event_type": "mio.remote.response",
                    "outcome": reply["outcome"],
                    "refusal": reply["refusal"],
                    "response_digest": reply.get("response_digest"),
                    "advisory_fields": reply.get("advisory_fields", 0),
                })
            elif route is Route.LOCAL:
                if getattr(getattr(local_request, "verb", None), "name", None) == "mio.local.infer":
                    reply = self._local.handle(local_request, audit=self._record)
                else:
                    reply = self._local.handle(local_request)
                if "readiness" in reply:
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
                        outcome = outcome_and_record(
                            ledger=self.ledger,
                            occurred_at=self._clock(),
                            route=route,
                            terminal_event=TerminalEvent.NO_ANSWER,
                            fallback_available=False,
                            reason=reason,
                        )
                        return RouterReply(selection, route, outcome, reply)
            else:
                reply = {"outcome": "handoff"}
            outcome = outcome_and_record(
                ledger=self.ledger,
                occurred_at=self._clock(),
                route=route,
                terminal_event=terminal_for(reply),
                fallback_available=attempt == 0 and route is not Route.DETERMINISTIC_HANDOFF,
            )
            if outcome is not RequestOutcome.FELL_BACK:
                return RouterReply(selection, route, outcome, reply)
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
        raise AssertionError("the final attempt cannot offer another fallback")
