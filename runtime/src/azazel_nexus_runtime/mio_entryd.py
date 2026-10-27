"""Metadata routing and bounded advisory entry; providers use separate sockets."""

from __future__ import annotations

import pwd
import sys
import time
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import datetime
from types import SimpleNamespace

from azazel_nexus.audit import AuditChainBroken, AuditUnavailable
from azazel_nexus.capability import CapabilityState
from azazel_nexus.local_advisory import (
    FrameRefused,
    gate_frame,
    handoff_notice,
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
from .mio_locald import INFER_VERB
from .mio_route_ledger import (
    ARBITER,
    CONTROL,
    EXPLAINER,
    UNATTRIBUTED,
    RouteSegmentFull,
)
from .mio_router import HANDOFF_RESERVE_MS, MIN_AI_ATTEMPT_MS, MioRouter
from .mio_socket_client import (
    PROBE_MAX_S,
    LocalSocketClient,
    ReferenceSocketClient,
    RemoteSocketClient,
)
from .principal import PrincipalClass, PrincipalPolicy
from .protocol import (
    Argument,
    ArgumentKind,
    Refusal,
    RequestRefused,
    Verb,
    VerbRegistry,
)
from .runtime_paths import dedicated_listener, socket_path
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
#: The explainer's own listener (`mio-advise`, group azmio-advise): advice
#: only. Its client holds that group and not the operator group (#213 O1).
ADVISE_REGISTRY = VerbRegistry([ADVISE_VERB])
LOCAL_REFUSAL = "HG-05 Core reserve unmeasured; no local provider admitted"
CAPABILITY_INTERVAL_SECONDS = 10
#: Per-principal request rate (#211 S4). The explainer sends at most six
#: advice requests a minute; an operator's interactive use is a few a minute.
#: The rate bounds request bursts; each caller's share of the day's route
#: segment (`mio_route_ledger`) bounds what it can make the ledger grow.
RATE_PER_MINUTE = 30
RATE_BURST = 10
#: Each caller's refusals, whatever the reason, are recorded at most once a
#: minute, carrying the counts suppressed since, and are charged to that
#: caller's share, so a refusal flood cannot spend anyone else's room.
REFUSAL_RECORD_INTERVAL_SECONDS = 60
MAX_TRACKED_PRINCIPALS = 64
CAPABILITY_EVENTS = frozenset({"mio.capability.transition", "mio.capability.carried"})
#: Records charged to the control reserve rather than to a caller.
CONTROL_EVENTS = CAPABILITY_EVENTS | {"mio.entry.started"}
#: Opens each request's records and names whose share they are charged to,
#: so a restart can recount today's shares from today's segment.
REQUEST_MARKER = "mio.entry.request"
#: Kept after the playbook-reference fetch for validating, recording and
#: delivering the handoff reply before the request's deadline. Software budget.
ENTRY_DELIVERY_RESERVE_MS = 30
#: A reference fetch is not started with less than this left of its share;
#: the handoff is then delivered at once with `reference_reason: deadline`.
MIN_REFERENCE_FETCH_MS = 50
#: Ledger writes made before the first AI attempt (request marker, request
#: record, capability record, availability, selection) are accounted for
#: explicitly: this much of the request's deadline is set aside for them.
LEDGER_ALLOWANCE_MS = 50
#: Readiness probes taken for a request come out of its one deadline. The two
#: probes run one after the other and together take at most a quarter of
#: what is left after the handoff reserve, one minimal AI attempt and the
#: ledger allowance (each gets half of that quarter, never more than
#: `PROBE_MAX_S`). Below `MIN_PROBE_S` each, nothing is probed for the request
#: and the availability record says so.
#:
#: The guarantee this gives (software, not measured): with deadline D ms,
#: left = D - HANDOFF_RESERVE_MS - MIN_AI_ATTEMPT_MS - LEDGER_ALLOWANCE_MS, the
#: probes take at most left/4, so the first AI attempt starts (with at least
#: MIN_AI_ATTEMPT_MS) whenever the ledger writes before it take no more than
#: LEDGER_ALLOWANCE_MS + 3*left/4. For the explainer's 500 ms: probes at most
#: 37.5 ms, the first attempt starts while those writes take at most 162.5 ms,
#: and it gets at least 212.5 ms when they take at most 50 ms. A second
#: attempt starts only if the first returns while MIN_AI_ATTEMPT_MS plus the
#: reserve is still left; nothing guarantees it.
MIN_PROBE_S = 0.005


class PrincipalRate:
    """A token bucket per kernel-reported uid; never per client-supplied text."""

    def __init__(self, *, per_minute: int = RATE_PER_MINUTE, burst: int = RATE_BURST,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.rate, self.burst, self.clock = per_minute / 60, burst, clock
        self.buckets: dict = {}

    def take(self, key) -> bool:
        now = self.clock()
        tokens, at = self.buckets.pop(key, (float(self.burst), now))
        tokens = min(float(self.burst), tokens + max(0.0, now - at) * self.rate)
        allowed = tokens >= 1
        # Re-inserted last, so eviction drops the least recently seen caller.
        self.buckets[key] = (tokens - 1 if allowed else tokens, now)
        while len(self.buckets) > MAX_TRACKED_PRINCIPALS:
            del self.buckets[next(iter(self.buckets))]
        return allowed


class MioEntryService:
    def __init__(
        self, *, profile_reader: Callable[[], MioProfile] = commissioned_profile,
        local_admitted: Callable[[], bool] = lambda: False,
        predictions_reader: Callable[[], dict] = dict,
        router: MioRouter | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        rate: PrincipalRate | None = None,
    ):
        self._explainer_uid = self._account_uid("azexplain")
        self._arbiter_uid = self._account_uid("azarbiter")
        self.local = LocalSocketClient()
        self.remote = RemoteSocketClient()
        self.router = router if router is not None else MioRouter(
            local=self.local, remote=self.remote, monotonic=clock)
        #: The model-free reference service. Separate from `local`: a node with
        #: no admitted model still reaches it, and it can reach no model verb.
        #: It reads the router's clock, the one the request's deadline is on.
        self.reference = ReferenceSocketClient(clock=lambda: self.router.monotonic())
        self._profile_reader = profile_reader
        self._local_admitted = local_admitted
        self._predictions_reader = predictions_reader
        self._clock = clock
        self._last_capability = None
        self._next_capability_check = 0.0
        self._wall_clock = wall_clock
        self.rate = rate if rate is not None else PrincipalRate(clock=clock)
        # In memory only: entryd has no status surface, so the aggregated
        # rate-limit refusal records carry these counts into the ledger.
        self.rate_limited = Counter()
        self.refusals_unrecorded = 0
        self._refusal_recorded: dict = {}
        self._refusals_suppressed: dict = {}
        #: When the current capability reading was recorded as a change; a
        #: carried record repeats it rather than claiming a new observation.
        self._observed_at = None
        #: Set when a capability record's write failed in a way that leaves
        #: unknown whether the segment holds it; cleared by re-reading the
        #: chain's last capability record (#227).
        self._capability_uncertain = False
        # Verify before trusting a historical comparison basis. This happens
        # once per owner, never on the status/profile read path. Verification
        # and the scan are one pass over the retained segments only, so start
        # time is bounded by retention, not by the node's age.
        self.router.ledger.verify(self._restore)
        if hasattr(self.router.ledger, "on_new_segment"):
            self.router.ledger.on_new_segment = self._carry
        if hasattr(self.router.ledger, "on_written"):
            # From here on the reading a carried record repeats is whatever
            # capability record the ledger last holds, even when a later step
            # of the append failed (#227).
            self.router.ledger.on_written = self._written
        if hasattr(self.router.ledger, "rebuild_usage"):
            # Today's per-caller shares survive a restart.
            self.router.ledger.rebuild_usage(self._attribution())

    @staticmethod
    def _account_uid(name: str):
        try:
            return pwd.getpwnam(name).pw_uid
        except (KeyError, OSError):
            return None

    def _budget_key(self, uid) -> str:
        if uid is None:
            return UNATTRIBUTED
        if self._explainer_uid is not None and uid == self._explainer_uid:
            return EXPLAINER
        if self._arbiter_uid is not None and uid == self._arbiter_uid:
            return ARBITER
        return f"uid:{uid}"

    def _attribution(self):
        """The rule that charged each of today's records to a share."""
        current = [UNATTRIBUTED]

        def attribute(event) -> str:
            kind = event.get("event_type")
            if kind in CONTROL_EVENTS:
                return CONTROL
            if kind == REQUEST_MARKER:
                caller = event.get("caller")
                current[0] = caller if type(caller) is str else UNATTRIBUTED
                return current[0]
            if kind == "runtime.request_refused":
                uid = event.get("uid")
                return self._budget_key(uid if type(uid) is int else None)
            return current[0]

        return attribute

    def _restore(self, item) -> None:
        event = item.event
        kind = event.get("event_type")
        if kind not in CAPABILITY_EVENTS:
            return
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
            observed = event["occurred_at"]
            if kind == "mio.capability.carried":
                observed = event["observed_at"]
                if type(observed) is not str:
                    raise TypeError("observed_at")
                datetime.fromisoformat(observed)
                # A carried record repeats the reading before it; one that
                # differs is a rewritten history, not a new observation.
                if self._last_capability is not None and (
                        {"state": state, "reasons": reasons} != self._last_capability
                        or observed != self._observed_at):
                    raise ValueError("carried record differs from the reading it carries")
        except (KeyError, TypeError, ValueError, OverflowError) as error:
            raise AuditChainBroken("invalid capability transition record") from error
        self._last_capability = {"state": state, "reasons": reasons}
        self._observed_at = observed
        remaining = max(0, min(CAPABILITY_INTERVAL_SECONDS,
                               stamp + CAPABILITY_INTERVAL_SECONDS - self._wall_clock()))
        self._next_capability_check = self._clock() + remaining

    def _written(self, event) -> None:
        """Remember a capability record the moment the ledger holds it.

        Memory is what the next carried record repeats and what the next
        sample is compared with. Taking it from the written record, rather
        than after the whole append returns, keeps it equal to the ledger's
        last capability record when retention or a directory sync fails
        afterwards; otherwise the next day's carried record could differ
        from the transition before it and refuse every restart.
        """
        kind = event.get("event_type")
        if kind not in CAPABILITY_EVENTS:
            return
        try:
            reading = {"state": event["to"], "reasons": event["reasons"]}
            observed = event["observed_at" if kind == "mio.capability.carried" else "occurred_at"]
        except KeyError:
            # Entryd never writes one; the next start's verification refuses it.
            return
        self._last_capability, self._observed_at = reading, observed

    def _settle_capability(self) -> None:
        """Take the reading from the ledger after a write of unknown outcome.

        Both the next comparison and the next carried record must start from
        the chain's last capability record. When a write failed and the
        segment could not be read to tell whether it holds the record, that
        record is read back here (one pass over the retained segments, only
        after such a failure). If it cannot be read, this raises and nothing
        is compared or carried.
        """
        if not self._capability_uncertain:
            return
        last = None
        for item in self.router.ledger:
            if item.event.get("event_type") in CAPABILITY_EVENTS:
                last = item.event
        self._last_capability = self._observed_at = None
        if last is not None:
            self._written(last)
        self._capability_uncertain = False

    def _carry(self) -> list[dict]:
        """Open each daily segment with the current capability reading.

        Retention deletes whole old segments. Without this, a node whose
        capability never changed would lose its last recorded observation and
        `azazel-nexus status` would read unknown. It is not a transition.
        """
        self._settle_capability()
        if self._last_capability is None or self._observed_at is None:
            return []
        # `observed_at` keeps the original observation time: after a restart
        # or a day boundary the reading is not presented as fresher than it is.
        return [{"event_type": "mio.capability.carried",
                 "to": self._last_capability["state"],
                 "reasons": self._last_capability["reasons"],
                 "observed_at": self._observed_at,
                 "occurred_at": self.router._clock()}]

    def record_refusal(self, event: dict) -> None:
        """The transport's refusal records, bounded per caller.

        Every refusal reason is aggregated per kernel-reported uid: one record
        a minute, carrying the counts suppressed since, charged to that
        caller's share. A refused request did nothing, so a refusal record
        that no longer fits is counted rather than fatal. The suppressed
        counts it would have carried are kept for the next record, so none is
        lost; summed over records they are "at least" counts, since a record
        whose line landed although its write reported failure carries them
        again in the next one.
        """
        uid, now = event.get("uid"), self._clock()
        last = self._refusal_recorded.get(uid)
        if last is not None and now - last < REFUSAL_RECORD_INTERVAL_SECONDS:
            self._refusals_suppressed.setdefault(uid, Counter())[str(event.get("reason"))] += 1
            return
        self._refusal_recorded.pop(uid, None)
        self._refusal_recorded[uid] = now
        while len(self._refusal_recorded) > MAX_TRACKED_PRINCIPALS:
            oldest = next(iter(self._refusal_recorded))
            del self._refusal_recorded[oldest]
            self._refusals_suppressed.pop(oldest, None)
        suppressed = self._refusals_suppressed.pop(uid, Counter())
        event = {**event,
                 "suppressed": dict(sorted(suppressed.items())),
                 "rate_limited": dict(sorted(self.rate_limited.items())),
                 "unrecorded": self.refusals_unrecorded}
        ledger = self.router.ledger
        previous = getattr(ledger, "owner", None)
        ledger.owner = self._budget_key(uid if type(uid) is int else None)
        try:
            self.router._record(event)
        except RouteSegmentFull:
            self.refusals_unrecorded += 1
            self._keep_suppressed(uid, suppressed)
        except BaseException:
            self._keep_suppressed(uid, suppressed)
            raise
        finally:
            ledger.owner = previous

    def _keep_suppressed(self, uid, suppressed: Counter) -> None:
        """Return counts a failed refusal record did not write (#227)."""
        if suppressed and uid in self._refusal_recorded:
            self._refusals_suppressed.setdefault(uid, Counter()).update(suppressed)

    @staticmethod
    def _observe(reader):
        try:
            return reader()
        except (AuditUnavailable, AuditChainBroken):
            raise
        except Exception:
            return None

    def _sample(self, probe_s: float = PROBE_MAX_S):
        local = self._observe(lambda: self.local.observe(deadline_s=probe_s))
        remote = self._observe(lambda: self.remote.observe(deadline_s=probe_s))
        reading = read_capability(self._observe(self._profile_reader), local, remote)
        return reading.as_dict(), (local, remote)

    def capability(self) -> dict:
        """Pure status read: no ledger writes or comparison-state mutation."""
        return self._sample()[0]

    def reconcile_capability(self, probe_s: float = PROBE_MAX_S):
        """Sample at most every ten seconds; append before accepting a change.

        Returns the `(local, remote)` observations taken, or None when no
        sample was due, so a request can reuse them rather than probe twice.
        """
        now = self._clock()
        if now < self._next_capability_check:
            return None
        current, observed = self._sample(probe_s)
        self._settle_capability()
        if current != self._last_capability:
            at = self.router._clock()
            try:
                self.router._record({
                    "event_type": "mio.capability.transition",
                    "from": self._last_capability["state"] if self._last_capability else None,
                    "to": current["state"], "reasons": current["reasons"],
                }, reserved=True, occurred_at=at)
            except RouteSegmentFull:
                # Not recorded, so not accepted: the next sample retries.
                self._next_capability_check = self._clock() + CAPABILITY_INTERVAL_SECONDS
                return observed
            except (AuditUnavailable, OSError):
                # Written or not is unknown unless the ledger reported this
                # very record (a carried record opening the segment may have
                # been reported before it).
                reported = self._last_capability == current and self._observed_at == at
                if not reported and hasattr(self.router.ledger, "on_written"):
                    self._capability_uncertain = True
                raise
            # Already remembered by `_written` for a segmented ledger; set
            # here too for a ledger without that hook.
            self._last_capability = current
            self._observed_at = at
        self._next_capability_check = self._clock() + CAPABILITY_INTERVAL_SECONDS
        return observed

    def handle(self, request) -> dict:
        # Before anything is written: a refused request leaves only the
        # transport's (aggregated) refusal record.
        principal = getattr(request, "principal", None)
        uid = getattr(principal, "uid", None)
        if not self.rate.take(uid):
            self.rate_limited["principal_rate"] += 1
            raise RequestRefused(Refusal.RATE_LIMITED, "principal_rate")
        key = self._budget_key(uid)
        room = getattr(self.router.ledger, "room", None)
        if room is not None and not room(key):
            # This caller's share of today's segment is spent; no other
            # caller's share is touched.
            self.rate_limited["route_budget"] += 1
            raise RequestRefused(Refusal.RATE_LIMITED, "route_budget")
        ledger = self.router.ledger
        previous = getattr(ledger, "owner", None)
        ledger.owner = key
        try:
            return self._handle(request, principal, key)
        finally:
            ledger.owner = previous

    def _handoff(self, frame: dict, result, deadline_at: float) -> dict:
        """The deterministic terminal step's reply: no AI is called here.

        The reference is optional and bounded by what is left of the request's
        deadline; it never replaces the routing reason, and its absence is
        stated with a fixed reason next to a fixed notice. Nothing here
        depends on Edge detection, decision or evidence, and nothing here is
        an AI answer: the reply names its kind.
        """
        # The fetch ends early enough that the reply is still delivered before
        # the deadline the caller is counting down to.
        fetch_deadline = deadline_at - ENTRY_DELIVERY_RESERVE_MS / 1000
        if (fetch_deadline - self.router.monotonic()) * 1000 < MIN_REFERENCE_FETCH_MS:
            document, missing = None, "deadline"
        else:
            document, missing = self.reference.reference(frame, deadline_at=fetch_deadline)
        if document is not None:
            try:
                document = read_reference(document)
            except Exception:  # noqa: BLE001 - an optional reference never fails the request
                document, missing = None, "reference_refused"
        self.router._record({
            "event_type": "mio.entry.handoff",
            "reference_status": "attached" if document is not None else "unavailable",
            "reference_reason": missing,
        })
        handoff = {
            "kind": "deterministic_reference" if document is not None else "deterministic_notice",
            "notice": handoff_notice(frame),
            "ai_attempts": result.ai_attempts,
            "failures": [dict(failure) for failure in result.failures],
        }
        if document is not None:
            return {"reference_status": "attached", "reference": document, "handoff": handoff}
        return {"reference_status": "unavailable", "reference_reason": missing,
                "handoff": handoff}

    def probe_share_s(self, deadline_at: float) -> float:
        """Each probe's bound for this request (see `LEDGER_ALLOWANCE_MS`)."""
        left_ms = ((deadline_at - self.router.monotonic()) * 1000 - HANDOFF_RESERVE_MS
                   - MIN_AI_ATTEMPT_MS - LEDGER_ALLOWANCE_MS)
        return min(PROBE_MAX_S, left_ms / 4 / 2 / 1000)

    def _observe_within(self, deadline_at: float) -> tuple[str, str]:
        each = self.probe_share_s(deadline_at)
        if each < MIN_PROBE_S:
            # No probe fits; the periodic tick keeps the capability record.
            return "not_observed_deadline", "not_observed_deadline"
        # Either the capability sample or the availability probes run, never
        # both for one daemon, so the two probes together stay within 2*each.
        local, remote = self.reconcile_capability(probe_s=each) or (None, None)
        return (local if local is not None else self.local.observe(deadline_s=each),
                remote if remote is not None else self.remote.observe(deadline_s=each))

    def _mark(self, key: str) -> None:
        if hasattr(self.router.ledger, "rebuild_usage"):
            self.router._record({"event_type": REQUEST_MARKER, "caller": key})

    def _handle(self, request, principal, key) -> dict:
        if request.arguments["deadline_ms"] == 0:
            raise RequestRefused(Refusal.ARGUMENT_RANGE, "deadline_ms")
        # The request's one deadline, on the router's monotonic clock. The
        # route, any fallback and the reference all take what is left of it.
        deadline_at = self.router.monotonic() + request.arguments["deadline_ms"] / 1000
        is_advice = getattr(getattr(request, "verb", None), "name", None) == ADVISE_VERB.name
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
            self._mark(key)
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
            self._mark(key)
        # Observations remain separate from admission and prediction. Even a
        # reachable daemon cannot lift HG-05 or establish remote trust. A
        # capability sample taken for this request is reused, so both records
        # describe the same observation and the request probes each daemon once.
        # Probe time comes out of this request's deadline (`MIN_PROBE_S`).
        local, remote = self._observe_within(deadline_at)
        profile = self._profile_reader()
        self.router._record({
            "event_type": "mio.entry.availability",
            "local": local,
            "remote": remote,
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
            deadline_at=deadline_at,
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
            reply.update(self._handoff(frame, result, deadline_at))
        return reply


def main(
    argv: Sequence[str] | None = None, *, stop: Callable[[], bool] = lambda: False,
    ready: Callable[[], None] | None = None,
) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        raise SystemExit("az-mio-entryd takes no arguments")
    # Composition verifies the retained route segments. The ledger refuses an
    # absent/unwritable installer-owned state directory before binding and
    # never creates it; prepare() probes append access to today's segment.
    service = MioEntryService()
    try:
        service.router.ledger.prepare()
        service.router._record({"event_type": "mio.entry.started"}, reserved=True)
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
        additional_sockets=(dedicated_listener("mio-advise", ADVISE_REGISTRY),),
        policy=PrincipalPolicy.resolve(service_accounts=("azarbiter", "azexplain")),
        audit=service.record_refusal, handler=service.handle, stop=tick,
        ready=ready if ready is not None else runtime_ready_callback(),
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
