"""Metadata routing and bounded advisory entry; providers use separate sockets."""

from __future__ import annotations

import pwd
import sys
import time
from collections.abc import Callable, Sequence
from datetime import datetime
from types import SimpleNamespace

from azazel_nexus.audit import AuditChainBroken, AuditUnavailable
from azazel_nexus.capability import CapabilityState
from azazel_nexus.local_advisory import (
    FrameRefused,
    gate_frame,
    read_frame,
    read_reference,
    request_event,
)
from azazel_nexus.mio_profile import NO_OPT_IN, MioProfile
from azazel_nexus.remote_trust import remote_admission, unchecked_reading
from azazel_nexus.routing import Route
from azazel_nexus.sanitizer import PrivacyClass

from .mio_capability import read_capability
from .mio_commissioning import commissioned_profile
from .mio_locald import INFER_VERB, REFERENCE_DEADLINE_MS
from .mio_router import MioRouter
from .mio_socket_client import LocalSocketClient, RemoteSocketClient
from .principal import PrincipalClass, PrincipalPolicy
from .protocol import (
    Argument,
    ArgumentKind,
    Refusal,
    RequestRefused,
    Verb,
    VerbRegistry,
)
from .runtime_paths import socket_path
from .serve import serve_forever
from .systemd_notify import runtime_ready_callback

SOCKET_NAME = "mio-entry"
ROUTE_VERB = Verb(
    "mio.route",
    arguments=(
        Argument("privacy_class", ArgumentKind.ENUM,
                 choices=tuple(value.value for value in PrivacyClass)),
        Argument("deadline_ms", ArgumentKind.ORDINAL, maximum=60_000),
    ),
    admits=frozenset({PrincipalClass.OPERATOR, PrincipalClass.SERVICE}),
)
ADVISE_VERB = Verb(
    "mio.advise",
    arguments=(Argument("deadline_ms", ArgumentKind.ORDINAL, maximum=60_000),),
    admits=frozenset({PrincipalClass.OPERATOR, PrincipalClass.SERVICE}),
    accepts_payload=True,
    payload_contract="azazel_nexus.local_advisory.read_frame",
)
REGISTRY = VerbRegistry([ROUTE_VERB, ADVISE_VERB])
LOCAL_REFUSAL = "HG-05 Core reserve unmeasured; no local provider admitted"
CAPABILITY_INTERVAL_SECONDS = 10


class MioEntryService:
    def __init__(
        self, *, profile_reader: Callable[[], MioProfile] = commissioned_profile,
        local_admitted: Callable[[], bool] = lambda: False,
        predictions_reader: Callable[[], dict] = dict,
        router: MioRouter | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ):
        try:
            self._explainer_uid = pwd.getpwnam("azexplain").pw_uid
        except KeyError:
            self._explainer_uid = None
        self.local = LocalSocketClient()
        self.remote = RemoteSocketClient()
        self.router = router if router is not None else MioRouter(local=self.local, remote=self.remote)
        self._profile_reader = profile_reader
        self._local_admitted = local_admitted
        self._predictions_reader = predictions_reader
        self._clock = clock
        self._last_capability = None
        self._next_capability_check = 0.0
        # Verify before trusting a historical comparison basis. This happens
        # once per owner, never on the status/profile read path.
        self.router.ledger.verify()
        for item in self.router.ledger:
            event = item.event
            if event.get("event_type") == "mio.capability.transition":
                # A hash-valid but malformed record is a broken history, not a
                # crash: the refusal is the same one a tampered record gets.
                try:
                    state = CapabilityState(event["to"]).value
                    reasons = event["reasons"]
                    if type(reasons) is not dict:
                        raise TypeError("reasons")
                    # Retain the rate bound across restarts too. A future
                    # timestamp (wall-clock correction) delays at most one
                    # sampling interval.
                    stamp = datetime.fromisoformat(event["occurred_at"]).timestamp()
                except (KeyError, TypeError, ValueError, OverflowError) as error:
                    raise AuditChainBroken("invalid capability transition record") from error
                self._last_capability = {"state": state, "reasons": reasons}
                remaining = max(0, min(CAPABILITY_INTERVAL_SECONDS,
                                       stamp + CAPABILITY_INTERVAL_SECONDS - wall_clock()))
                self._next_capability_check = self._clock() + remaining

    @staticmethod
    def _observe(reader):
        try:
            return reader()
        except (AuditUnavailable, AuditChainBroken):
            raise
        except Exception:
            return None

    def _sample(self):
        local, remote = self._observe(self.local.observe), self._observe(self.remote.observe)
        reading = read_capability(self._observe(self._profile_reader), local, remote)
        return reading.as_dict(), (local, remote)

    def capability(self) -> dict:
        """Pure status read: no ledger writes or comparison-state mutation."""
        return self._sample()[0]

    def reconcile_capability(self):
        """Sample at most every ten seconds; append before accepting a change.

        Returns the `(local, remote)` observations taken, or None when no
        sample was due, so a request can reuse them rather than probe twice.
        """
        now = self._clock()
        if now < self._next_capability_check:
            return None
        current, observed = self._sample()
        if current != self._last_capability:
            self.router._record({
                "event_type": "mio.capability.transition",
                "from": self._last_capability["state"] if self._last_capability else None,
                "to": current["state"], "reasons": current["reasons"],
            })
            self._last_capability = current
        self._next_capability_check = self._clock() + CAPABILITY_INTERVAL_SECONDS
        return observed

    def handle(self, request) -> dict:
        if request.arguments["deadline_ms"] == 0:
            raise RequestRefused(Refusal.ARGUMENT_RANGE, "deadline_ms")
        is_advice = getattr(getattr(request, "verb", None), "name", None) == ADVISE_VERB.name
        principal = getattr(request, "principal", None)
        explainer = (principal is not None and self._explainer_uid is not None
                     and principal.uid == self._explainer_uid
                     and PrincipalClass.SERVICE in principal.classes)
        if explainer and not is_advice:
            raise RequestRefused(Refusal.PRINCIPAL_DENIED, "explainer_verb")
        local_request = None
        if is_advice:
            try:
                frame = read_frame(request.payload)
            except FrameRefused:
                raise RequestRefused(Refusal.MALFORMED_FRAME, "situation_frame") from None
            privacy = PrivacyClass(frame["privacy_class"])
            if explainer and privacy is not PrivacyClass.P3_RESTRICTED:
                raise RequestRefused(Refusal.PRINCIPAL_DENIED, "explainer_privacy")
            self.router._record(request_event(frame))
            gated = gate_frame(frame)
            if gated is not None and gated["reason"] == "insufficient_information":
                self.router._record({"event_type": "mio.local.gated", "reason": gated["reason"]})
                return {**gated, "route": Route.DETERMINISTIC_HANDOFF.value,
                        "ledger_seq": self.router.ledger.head()[0]}
            local_request = SimpleNamespace(
                verb=INFER_VERB, arguments=request.arguments, payload=frame,
            )
        else:
            privacy = PrivacyClass(request.arguments["privacy_class"])
        sampled = self.reconcile_capability() or (None, None)
        profile = self._profile_reader()
        # Observations remain separate from admission and prediction. Even a
        # reachable daemon cannot lift HG-05 or establish remote trust. A
        # capability sample taken for this request is reused, so both records
        # describe the same observation and the request probes each daemon once.
        local, remote = sampled
        self.router._record({
            "event_type": "mio.entry.availability",
            "local": local if local is not None else self.local.observe(),
            "remote": remote if remote is not None else self.remote.observe(),
            "local_refusal": LOCAL_REFUSAL,
            "remote_trust": "unchecked",
        })
        result = self.router.handle(
            local_request=local_request, remote_request=None,
            profile=profile, privacy_class=privacy,
            remote=remote_admission(
                profile=profile, opt_in=NO_OPT_IN,
                trust=unchecked_reading(), privacy_class=privacy, sanitised=False,
            ),
            local_admitted=is_advice and self._local_admitted(), local_refusal=LOCAL_REFUSAL,
            predictions=self._predictions_reader() if is_advice else {},
            deadline_ms=request.arguments["deadline_ms"],
        )
        reply = {
            "route": result.route.value, "outcome": result.outcome.value,
            "reason": result.selection.reason,
            "ledger_seq": self.router.ledger.head()[0],
        }
        if is_advice and result.reply.get("outcome") == "advisory":
            reply["advice"] = result.reply.get("advice")
            reply["fields"] = result.reply.get("fields", {})
            if result.route is Route.LOCAL:
                from azazel_nexus.local_advisory import read_delivered

                reply.update(read_delivered(result.reply))
        if is_advice and result.route is Route.DETERMINISTIC_HANDOFF:
            # Optional and bounded by the caller's own budget; never replaces the
            # routing reason (the ledger and the reply keep the true handoff cause).
            budget = min(REFERENCE_DEADLINE_MS, request.arguments["deadline_ms"])
            reference = self.local.reference(frame, deadline_ms=budget)
            try:
                if reference is None:
                    raise ValueError("reference_unavailable")
                reply["reference"] = read_reference(reference)
                reply["reference_status"] = "attached"
            except Exception:  # noqa: BLE001 - an optional reference never fails the request
                reply.pop("reference", None)
                reply["reference_status"] = "unavailable"
        return reply


def main(
    argv: Sequence[str] | None = None, *, stop: Callable[[], bool] = lambda: False,
    ready: Callable[[], None] | None = None,
) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        raise SystemExit("az-mio-entryd takes no arguments")
    service = MioEntryService()
    path = service.router.ledger.path
    # AuditLedger creates parents for general callers. A daemon must instead
    # refuse an absent/unwritable installer-owned leaf before binding.
    try:
        with path.open("a", encoding="utf-8"):
            pass
        service.router._record({"event_type": "mio.entry.started"})
        service.reconcile_capability()
    except OSError as error:
        raise AuditUnavailable("M.I.O. route ledger unavailable") from error

    def tick() -> bool:
        if stop():
            return True
        service.reconcile_capability()
        return False

    return serve_forever(
        path=socket_path(SOCKET_NAME), registry=REGISTRY,
        policy=PrincipalPolicy.resolve(service_accounts=("azarbiter", "azexplain")),
        audit=service.router._record, handler=service.handle, stop=tick,
        ready=ready if ready is not None else runtime_ready_callback(),
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
