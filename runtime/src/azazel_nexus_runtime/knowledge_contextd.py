"""Dedicated, optional broker for full-node Knowledge Context.

This daemon is the only component that may hold a commissioned Knowledge
peer client. It has no model, enforcement, or Knowledge store authority. The
factory shipped here is uncommissioned unless a root-owned commissioning
bundle is present; no environment switch or command-line option can enable
egress. Tests may inject an explicitly
commissioned client and synthetic trust material.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import sys
import threading
import time
from collections import deque
from datetime import UTC, datetime
from collections.abc import Callable, Mapping, Sequence
from threading import BoundedSemaphore
from typing import Any

from azazel_nexus.audit import (
    AuditChainBroken, AuditLedger, AuditOutcomeUnknown, AuditUnavailable)
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy
from azazel_nexus.technique_knowledge import request_ids

from .activation_markers import inspect_grant_marker
from .knowledge_context_socket import MAX_CONTEXT_FRAME_BYTES, read_context_frame
from .knowledge_context_config import (
    load_commissioning, load_observation_rule, observation_rule_identity)
from .principal import PrincipalClass, PrincipalPolicy
from .chain_guard import ChainGuard, settle_single
from .protocol import Argument, ArgumentKind, Verb, VerbRegistry
from .runtime_paths import (
    knowledge_context_observation_rule_path, knowledge_context_state_dir, socket_path,
)
from .serve import serve_forever
from .systemd_notify import runtime_ready_callback

__all__ = ["CONTEXT_VERB", "STATUS_VERB", "KnowledgeContextBroker", "main"]

SOCKET_NAME = "knowledge-context"
MAX_RESPONSE_BYTES = 48 * 1024
CONTEXT_VERB = Verb(
    "knowledge.context",
    arguments=(
        Argument("deadline_ms", ArgumentKind.ORDINAL, maximum=10_000),
        Argument("deadline_monotonic_ns", ArgumentKind.ORDINAL,
                 maximum=9_223_372_036_854_775_807),
    ),
    admits=frozenset({PrincipalClass.SERVICE}),
    accepts_payload=True,
    payload_contract="bounded frame; broker constructs a P0-public request",
)
#: Read-only diagnostic (#472). It answers while the ledger cannot be written,
#: with fixed words and counts only.
STATUS_VERB = Verb(
    "knowledge.context.status",
    admits=frozenset({PrincipalClass.ROOT, PrincipalClass.OPERATOR, PrincipalClass.SERVICE}),
)
REGISTRY = VerbRegistry([CONTEXT_VERB, STATUS_VERB])
#: Marks a `requested` row of the form that results refer back to (#472). A row
#: without it is the old form and is never matched to a result by guessing.
REQUEST_FORMAT = 2
UNKNOWN_OUTCOME = "unknown"
RESTART_UNCONFIRMED = "restart_unconfirmed"
_REQUESTED = "knowledge.context.requested"
_COMPLETED = "knowledge.context.completed"
_RATE_WINDOW_S = 60.0
# Fixed request sections a client may name on the refusal it raises.
_CLIENT_STAGES = frozenset({"refused_before_send", "transport", "verification",
                            "technique_verification"})
#: Every word a refusal's `stage` can carry. `withdrawn`: the peer answered and
#: the answer was verified, but the grant marker changed before adoption, so
#: nothing from the peer was used (the ledger reason_code is `withdrawn` too).
#: `unrecorded`: the answer was verified, but the ledger could not record it
#: (broken chain), so it was discarded; adopted nowhere, like `withdrawn`.
_STAGES = _CLIENT_STAGES | {"withdrawn", "unrecorded"}
#: The unit whose grant marker admits a request (the broker's own unit).
_UNIT = "azazel-knowledge-contextd.service"


def _reference(entry) -> dict:
    """The fields that tie a result to the `requested` line it belongs to."""
    sequence = getattr(entry, "sequence", None)
    digest = getattr(entry, "event_hash", None)
    if type(sequence) is not int or type(digest) is not str:
        return {}
    return {"requested_sequence": sequence, "requested_hash": digest}


def _production_grant_marker():
    """The identity of this unit's grant marker as the pass wrote it, or None."""
    return inspect_grant_marker(_UNIT)


class KnowledgeContextBroker:
    """One in-flight broker; disabled unless complete commissioning is injected."""

    def __init__(
        self,
        *,
        client: Any = None,
        policy: SanitizerPolicy | None = None,
        mission: str | None = None,
        alias_key: bytes | None = None,
        enabled: bool = False,
        audit: Callable[[dict], Any] = lambda event: None,
        monotonic: Callable[[], float] = time.monotonic,
        observation_rule: tuple | None = None,
        observation_rule_path: Any = None,
        grant_marker: Callable[[], Any] = _production_grant_marker,
        send_allowed: Callable[[], bool] = lambda: True,
        hold: Callable[..., None] = lambda event, awaiting=None: None,
        request_settled: Callable[[Any], str] = lambda entry: "present",
    ) -> None:
        if type(enabled) is not bool:
            raise ValueError("Knowledge Context enablement must be explicit")
        self._enabled = enabled
        self._client = client
        self._policy = policy
        self._mission = mission
        self._alias_key = alias_key
        self._audit = audit
        self._monotonic = monotonic
        #: Reads the identity of the grant marker (None: no grant). Taken when
        #: a request is accepted and again before the answer is adopted.
        self._grant_marker = grant_marker
        #: Asked after the observation gate and before anything is recorded or
        #: sent: False while the ledger still has work owed (#472).
        self._send_allowed = send_allowed
        #: A result row that could not be written although the operation was
        #: never sent; the owner writes it later.
        self._hold = hold
        #: `present`, `absent` or `unknown` for a `requested` line whose write had
        #: an unknown outcome. The reference to it is kept only when present.
        self._request_settled = request_settled
        #: True once this request called the peer (set just before the call, so
        #: a record written after it belongs to an operation already done).
        self.sent = False
        self._slot = BoundedSemaphore(1)
        self._adoption_lock = threading.Lock()
        # (rule, identity) read once at start-up, or None. Closed for good once
        # the rule file is removed or replaced (latch, until restart).
        self._observation = observation_rule
        self._observation_path = observation_rule_path
        self._latched = False
        self._counted: deque = deque()
        self._observation_lock = threading.Lock()
        self._ready = (enabled is True and client is not None
                       and isinstance(policy, SanitizerPolicy)
                       and type(mission) is str and bool(mission)
                       and type(alias_key) is bytes and len(alias_key) >= 32)

    @staticmethod
    def _latch_cause(path, identity) -> str | None:
        """Why the gate must close for good, or None while the rule is unchanged.

        An identity that is not a (dev, ino, mtime, ctime, digest) tuple can
        never match a read, so it closes instead of comparing None to None.
        """
        if type(identity) is not tuple or len(identity) != 5:
            return "invalid_identity"
        current = observation_rule_identity(path)
        if current == identity:
            return None
        if current is not None:
            return "changed"
        return "unreadable" if os.path.lexists(path) else "missing"

    def _record_latch(self, cause: str) -> None:
        """One ledger event when the gate latches; the sink failing changes nothing."""
        try:
            self._audit({"event_type": "knowledge.context.observation_latched",
                         "outcome": "latched", "reason_code": cause})
        except Exception:
            pass

    def _observation_gate(self, now: float) -> str | None:
        """None to proceed (and count the request), else the reason_code."""
        with self._observation_lock:
            if self._observation is None:
                return "refused_before_send"
            rule, identity = self._observation
            if not self._latched:
                path = self._observation_path or knowledge_context_observation_rule_path()
                cause = self._latch_cause(path, identity)
                if cause is not None:
                    self._latched = True
                    self._record_latch(cause)
            if self._latched:
                return "refused_before_send"
            while self._counted and now - self._counted[0] >= _RATE_WINDOW_S:
                self._counted.popleft()
            if len(self._counted) >= rule.max_requests_per_minute:
                return "rate_limited"
            self._counted.append(now)
            return None

    def handle(self, request) -> dict:
        if getattr(getattr(request, "verb", None), "name", None) != CONTEXT_VERB.name:
            return {"refusal": "unavailable", "stage": "refused_before_send"}
        self.sent = False
        start = self._monotonic()
        deadline_ms = request.arguments["deadline_ms"]
        deadline_monotonic = request.arguments["deadline_monotonic_ns"] / 1_000_000_000
        # Honor both caller deadline representations. The absolute value is a
        # local monotonic bound, not permission to extend deadline_ms.
        deadline = min(start + deadline_ms / 1000, deadline_monotonic)
        deadline_s = deadline - start
        if deadline_s <= 0:
            return {"refusal": "timeout", "stage": "refused_before_send"}
        reason = None
        phase = "frame"
        ref: dict = {}
        doubtful = None
        try:
            # The grant this request is accepted under. A broker whose grant
            # was withdrawn (marker removed) accepts nothing, even in the
            # seconds before the manager has stopped it.
            phase = "admit"  # before anything is sent; "grant" is the adoption recheck
            admitted = self._grant_marker()
            if admitted is None:
                reason = "withdrawn"
                raise ValueError
            phase = "frame"
            wire_frame = read_context_frame(request.payload.get("frame"))
            if set(request.payload) != {"frame"} or not self._ready:
                raise ValueError
            # This required label is a caller assertion, not a content
            # classifier. Production commissioning must restrict which
            # trusted local inputs can make this assertion; the shipped
            # factory has no egress client and cannot use it for network IO.
            # Context arrays and all other fields stay local.
            # Only the observation-origin technique query: 1 to 8 sorted,
            # unique ids. A free-form `question` -- including one in the old
            # observation sentence -- is refused here, before the gate, the
            # slot, the `requested` event and any peer call (#439).
            if (set(wire_frame) != {"privacy_class", "techniques"}
                    or wire_frame["privacy_class"] != PrivacyClass.P0_PUBLIC.value):
                raise ValueError
            frame = {"techniques": request_ids(wire_frame["techniques"])}
            # Judged before the `requested` event and before the slot.
            phase = "gate"
            reason = self._observation_gate(start)
            if reason is not None:
                raise ValueError
            phase = "frame"
            if not self._send_allowed():
                # Judged after the gate, so a latch still closes. The owner has
                # spent this request's one ledger step; no row of its own.
                return {"refusal": "unavailable", "stage": "refused_before_send"}
            if not self._slot.acquire(blocking=False):
                reason = "busy"
                raise TimeoutError
            try:
                # Record the sanitized request attempt before any egress. A
                # failed audit sink must keep the optional network path closed.
                phase = "audit"
                try:
                    ref = _reference(self._audit({
                        "event_type": _REQUESTED, "outcome": "attempted",
                        "format": REQUEST_FORMAT}))
                except AuditOutcomeUnknown as exc:
                    # The line may be there: whatever this request records
                    # next refers to it, whether or not it turns out to be.
                    doubtful = exc.entry
                    raise
                # The time left is judged just before the call, after the record.
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    raise TimeoutError
                deadline_s = remaining
                phase = "client"
                self.sent = True
                verified = self._client.request_context(
                    frame=frame,
                    privacy_class=PrivacyClass.P0_PUBLIC,
                    policy=self._policy,
                    mission=self._mission,
                    alias_key=self._alias_key,
                    deadline_s=deadline_s,
                )
                phase = "verified"
            finally:
                self._slot.release()
            if self._monotonic() >= deadline:
                reason = "late"
                raise TimeoutError
            dump = getattr(verified, "model_dump", None)
            response = dump(mode="json") if callable(dump) else verified
            if type(response) is not dict:
                reason = "verification"
                raise ValueError
            encoded = json.dumps(
                {"ok": True, "result": {"response": response}},
                sort_keys=True, ensure_ascii=True, allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
            if not encoded or len(encoded) > MAX_RESPONSE_BYTES:
                reason = "verification"
                raise ValueError
            # The adoption point. The answer is used only if the marker is
            # still the one this request was accepted under; after the marker
            # was removed (or removed and written again) nothing from the
            # peer is adopted, recorded as verified or returned. An answer
            # adopted before this check may still be on its way to the
            # caller after the marker is gone: delivery is not undone.
            phase = "grant"
            from azazel_nexus.knowledge_clock_validity import VerifiedContext
            with self._adoption_lock:
                # v1 retains its existing behaviour; v2 has a final local proof.
                result = {"response": response}
                def check_grant():
                    nonlocal reason
                    if self._grant_marker() != admitted:
                        reason = "withdrawn"
                        raise ValueError

                if isinstance(verified, VerifiedContext):
                    result["validity"] = verified.adoption_validity(
                        utc_now=lambda: datetime.now(UTC).isoformat(), monotonic=self._monotonic,
                        caller_deadline=deadline)
                    complete = json.dumps({"ok": True, "result": result}, allow_nan=False,
                                          sort_keys=True, separators=(",", ":")).encode("utf-8")
                    if len(complete) > MAX_RESPONSE_BYTES:
                        raise ValueError("clock wrapper size")
                    result["validity"] = verified.adoption_validity(
                        utc_now=lambda: datetime.now(UTC).isoformat(), monotonic=self._monotonic,
                        grant_check=check_grant, caller_deadline=deadline)
                else:
                    check_grant()
                phase = "verified"
                try:
                    self._audit({"event_type": _COMPLETED,
                                 "outcome": "verified_advisory",
                                 "response_bytes": len(encoded),
                                 "elapsed_ms": min(10_000, int((self._monotonic() - start) * 1000)),
                                 **ref})
                except AuditUnavailable:
                    # The peer was called and its answer verified, and the
                    # record could not be written (#467). The answer is not
                    # adopted and no second `completed` is written: the guard
                    # owes this one, and says so with the word for it.
                    return {"refusal": "unavailable", "stage": "unrecorded"}
                return result
        except TimeoutError:
            outcome = "timeout"
        except Exception as exc:  # refusal details may include caller data; never export them
            outcome = "unavailable"
            if phase in ("frame", "audit"):
                reason = "refused_before_send"
            elif phase == "client":
                stage = getattr(exc, "stage", None)
                reason = stage if type(stage) is str and stage in _CLIENT_STAGES else None
        event = {"event_type": _COMPLETED, "outcome": outcome,
                 "elapsed_ms": min(10_000, int((self._monotonic() - start) * 1000)), **ref}
        if reason is not None:
            event["reason_code"] = reason
        if doubtful is not None:
            # The `requested` line may or may not be on the ledger. The result
            # refers to it only once it is found present; found absent, it
            # refers to nothing; not yet known, it waits (with the line it waits for).
            verdict = self._request_settled(doubtful)
            if verdict == "present":
                event.update(_reference(doubtful))
            elif verdict != "absent":
                self._hold(event, doubtful)
                return self._refusal(outcome, phase, reason)
        try:
            self._audit(event)
        except Exception:
            if (ref or doubtful is not None) and not self.sent:
                # Nothing was sent, so the guard owes nothing; the line that
                # stands without a result is written when the ledger allows.
                self._hold(event)
        return self._refusal(outcome, phase, reason)

    @staticmethod
    def _refusal(outcome, phase, reason) -> dict:
        # Every accepted request is a technique query (#439), so every refusal
        # (including the two early returns above) carries how far it got, as a
        # fixed word from _STAGES: the caller can keep transport
        # and verification apart, and a refused question or malformed frame is
        # `refused_before_send` on the caller's side too, not a shape error.
        if phase == "client":
            # The client was called; a failure it does not name happened after
            # the attempt began, so it is never reported as before sending.
            stage = reason if reason in _CLIENT_STAGES else "transport"
        elif phase == "grant":
            stage = "withdrawn"  # received and verified, not adopted
        else:
            stage = {"late": "transport", "verification": "verification"}.get(
                reason, "refused_before_send")
        return {"refusal": outcome, "stage": stage}


def _take_writer_lock(directory):
    """The one writer of this ledger, taken before the socket is bound or a line appended (#472).

    A lock file beside the ledger, held for the life of the process (the kernel
    drops it when the process dies, however it dies). A second daemon ends here,
    so it never reaches the socket path `bind_socket` would replace. A missing
    state directory, a lock that cannot be created and a lock held by another
    all end the start; nothing is created but the lock file itself.
    """
    if not directory.is_dir():
        raise SystemExit(f"az-knowledge-contextd: {directory} does not exist")
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(directory / "context.jsonl.lock", flags, 0o600)
    except OSError as exc:
        raise SystemExit(f"az-knowledge-contextd cannot open its writer lock: {exc.strerror}")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
            raise SystemExit("az-knowledge-contextd: another one holds the ledger")
        raise SystemExit(f"az-knowledge-contextd cannot lock its ledger: {exc.strerror}")
    return fd


class _Guard(ChainGuard):
    """A guard that reconciles at most once for each request (#472).

    One reconciliation is one step: it is the look at the ledger and, when the
    line is found, the `audit.outcome_settled` / `audit.late_record` it writes
    (the #469 contract). Whatever asks for a second one in the same request (the
    latch record, the refusal's record, the step) gets "still owed" without any
    I/O. `new_request` clears the mark, at the entrance of a request and of a
    transport refusal's record, so a failure never carries over to the next one.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._reconciled = False

    def new_request(self) -> None:
        self._reconciled = False

    def settle_owed(self) -> bool:
        if not self.owed:
            return True
        if self._reconciled:
            return False
        self._reconciled = True
        return super().settle_owed()


class _Duties:
    """What the ledger still needs before egress may open (#472).

    Egress is open only when the ledger verified, nothing waits in `queue`
    (`commissioning`, the `unknown` rows for requests with no result, and any
    result row this process could not write) and the guard owes nothing. Each
    request after the observation gate does at most one step: settle what is
    owed, or append the head of the queue. Between requests nothing is read or
    written.
    """

    def __init__(self, ledger, guard, commissioning_event: dict) -> None:
        self.ledger, self.guard = ledger, guard
        self.verified = False
        self.reason: str | None = "ledger_unverified"
        self.commissioned = False
        self._commissioning = commissioning_event
        self.queue: list[dict] = []
        self.legacy_unreferenced = 0
        self.recovered = 0
        #: (sequence, hash) of lines found present after an unknown outcome.
        self.present: set = set()
        #: id of a held event -> the `requested` line whose fate it waits for.
        self._awaiting: dict = {}

    @property
    def started(self) -> bool:
        """The ledger verified and `commissioning` is recorded: other lines may follow."""
        return self.verified and self.commissioned

    @property
    def open(self) -> bool:
        return (self.started and not self.queue and not self.guard.broken
                and not self.guard.owed)

    def scan(self) -> None:
        """Verify the chain and list the `requested` lines without a result, in ONE read."""
        requested: dict = {}
        referenced: set = set()
        legacy = [0]

        def see(entry) -> None:
            event = entry.event
            kind = event.get("event_type")
            holder = event.get("late_event") if kind in (
                "audit.late_record", "audit.outcome_settled") else event
            if kind == _REQUESTED:
                if event.get("format") == REQUEST_FORMAT:
                    requested[(entry.sequence, entry.event_hash)] = True
                else:
                    legacy[0] += 1
            if isinstance(holder, dict) and holder.get("event_type") == _COMPLETED:
                ref = (holder.get("requested_sequence"), holder.get("requested_hash"))
                if type(ref[0]) is int and type(ref[1]) is str:
                    referenced.add(ref)

        try:
            self.ledger.verify(require_terminated=True, on_entry=see)
        except (AuditChainBroken, ValueError, RecursionError) as exc:
            # A line that cannot be recomputed or read (broken JSON, a cut
            # line, a lone surrogate) is a break; nothing is completed on top.
            self.guard._mark(exc)
            self.reason = "ledger_broken"
            return
        except (AuditUnavailable, OSError):
            self.reason = "ledger_unreadable"
            return
        self.verified, self.reason = True, None
        self.legacy_unreferenced = legacy[0]
        self.queue = [self._commissioning] + [
            {"event_type": _COMPLETED, "outcome": UNKNOWN_OUTCOME,
             "reason_code": RESTART_UNCONFIRMED,
             "requested_sequence": sequence, "requested_hash": digest}
            for (sequence, digest) in requested if (sequence, digest) not in referenced]

    def hold(self, event: dict, awaiting=None) -> None:
        """A result row the broker could not write (nothing was sent): written later.

        `awaiting` is a `requested` line of unknown outcome: the row refers to it
        only if it turns out to be present.
        """
        self.queue.append(event)
        if awaiting is not None:
            self._awaiting[id(event)] = (awaiting.sequence, awaiting.event_hash)

    def request_settled(self, entry) -> str:
        """`present`, `absent` or `unknown` for a `requested` line of unknown outcome."""
        if self.guard.broken or (self.guard.owed and not self.guard.settle_owed()):
            return "unknown"
        return "present" if (entry.sequence, entry.event_hash) in self.present else "absent"

    def _done(self, event: dict) -> None:
        for index, item in enumerate(self.queue):
            if item == event:
                del self.queue[index]
                break
        else:
            return
        if event is self._commissioning or event == self._commissioning:
            self.commissioned = True
        elif event.get("reason_code") == RESTART_UNCONFIRMED:
            self.recovered += 1

    def on_settled(self, event, entry) -> None:
        """A line of unknown outcome was found present: it was written."""
        self.present.add((entry.sequence, entry.event_hash))
        self._done(event)

    def step(self) -> None:
        """One ledger unit: settle what is owed, or append the head of the queue."""
        if self.guard.broken or not self.verified:
            return
        if self.guard.owed:
            self.guard.settle_owed()
            return
        if not self.queue:
            return
        event = self.queue[0]
        key = self._awaiting.pop(id(event), None)
        if key is not None and key in self.present:
            event.update({"requested_sequence": key[0], "requested_hash": key[1]})
        try:
            self.guard.append(event, performed=False)
        except (AuditChainBroken, AuditUnavailable):
            return    # an unknown outcome is owed to the guard and settled next
        self._done(event)

    def start(self) -> None:
        """At start-up, after bind: verify, scan, then write what is owed, as far as it goes."""
        self.scan()
        for _ in range(3 * len(self.queue) + 3):
            if not self.queue and not self.guard.owed:
                break
            before = (len(self.queue), len(self.guard.owed))
            self.guard.new_request()
            self.step()
            if (len(self.queue), len(self.guard.owed)) == before:
                break     # no progress: the rest waits for the next requests

    @property
    def unresolved(self) -> int:
        return len(self.queue) + len(self.guard.owed)

    def why_closed(self) -> str | None:
        if self.guard.broken:
            return "ledger_broken"
        if not self.verified:
            return self.reason
        if self.guard.owed:
            return "audit_owed"
        if not self.commissioned:
            return "commissioning_pending"
        if self.queue:
            return "result_pending"
        return None

    def status(self, broker) -> dict:
        reason = self.why_closed()
        if reason is None and not broker._ready:
            reason = "broker_disabled"        # not commissioned: nothing can be sent
        if reason is None and broker._latched:
            reason = "observation_latched"
        audit = self.guard.state
        if audit == "ok" and not self.verified:
            audit = "unverified"
        return {"egress": "open" if reason is None else "closed", "reason": reason,
                "audit": audit, "unresolved": self.unresolved,
                "legacy_unreferenced": self.legacy_unreferenced,
                "recovered": self.recovered}


def main(argv: Sequence[str] | None = None, *, stop=lambda: False, ready=None) -> int:
    """Run the disabled-by-default local endpoint; takes no command-line config."""
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        raise SystemExit("az-knowledge-contextd takes no arguments")
    state_dir = knowledge_context_state_dir()
    sock_path = socket_path(SOCKET_NAME)
    # First: the writer lock, before the socket is bound and before any line is
    # appended. Neither directory is made here; the installer owns them.
    lock_fd = _take_writer_lock(state_dir)   # held until the process ends
    if not sock_path.parent.is_dir():
        raise SystemExit(f"az-knowledge-contextd: {sock_path.parent} does not exist")
    ledger = AuditLedger(state_dir / "context.jsonl")
    # Enablement comes only from the root-owned commissioning bundle; any
    # absence or defect leaves the closed broker. Load performs no I/O to peers.
    commissioning = load_commissioning()
    observation = load_observation_rule()
    event = {"event_type": "knowledge.context.commissioning",
             "outcome": commissioning.status}
    if commissioning.reason_code:
        event["reason_code"] = commissioning.reason_code
    if commissioning.registry_version is not None:
        event["registry_version"] = commissioning.registry_version
    if observation is not None:
        # Written only when a rule was read, so a node without the rule file
        # records exactly what it recorded before.
        event["observation_rule"] = "loaded"
    duties_ref: list = []
    guard = _Guard(ledger.append, settle_single(ledger),
                       on_settled=lambda e, entry: duties_ref[0].on_settled(e, entry))
    duties = _Duties(ledger, guard, event)
    duties_ref.append(duties)
    #: Set when the record of a verified answer could not be written.
    unrecorded = [False]

    def audit(event: dict) -> Any:
        if not duties.started:
            # Nothing but the start-up's own lines may come first.
            raise AuditUnavailable("start-up not finished")
        try:
            # Once the peer was called, a record that cannot be written is a
            # debt of the operation already done, not of one that never ran.
            return guard.append(event, performed=broker.sent)
        except AuditChainBroken:
            if (event["event_type"] == "knowledge.context.completed"
                    and event.get("outcome") == "verified_advisory"):
                unrecorded[0] = True
            raise

    def send_allowed() -> bool:
        """Asked after the gate. Open: no ledger access. Closed: one step, then judged again."""
        if duties.open:
            return True
        duties.step()
        if duties.open:
            return True
        if not guard.broken:
            guard.count_unrecorded()   # (a break is counted once by `handle`)
        return False

    if commissioning.status == "commissioned":
        broker = KnowledgeContextBroker(
            client=commissioning.client, policy=commissioning.policy,
            mission=commissioning.mission, alias_key=commissioning.alias_key,
            enabled=True, audit=audit,
            observation_rule=observation,
            send_allowed=send_allowed, hold=duties.hold,
            request_settled=duties.request_settled,
        )
    else:
        broker = KnowledgeContextBroker(audit=audit, send_allowed=send_allowed, hold=duties.hold,
                                    request_settled=duties.request_settled)

    def handle(request):
        """Record before send; on a broken chain nothing is sent to Knowledge."""
        unrecorded[0] = False
        guard.new_request()
        if getattr(getattr(request, "verb", None), "name", None) == STATUS_VERB.name:
            return duties.status(broker)
        reply = broker.handle(request)
        if not guard.broken:
            return reply
        # Found during this request. A refusal the broker already chose keeps
        # its own stage (the client's, or before send); only a verified answer
        # that could not be recorded gets the word for that.
        guard.count_unrecorded()
        if unrecorded[0] or "refusal" not in reply:
            return {"refusal": "unavailable", "stage": "unrecorded"}
        return reply

    def record_refusal(event: dict) -> None:
        """The transport's refusal record: counted, not written, until start-up is done."""
        guard.new_request()
        if duties.started:
            guard.record_refusal(event)
        else:
            guard.count_unrecorded()

    notify = ready if ready is not None else runtime_ready_callback()

    def started() -> None:
        # The socket is bound; only now does this process touch the ledger.
        duties.start()
        if notify is not None:
            notify()

    handle.__self__ = broker
    record_refusal.__self__ = guard
    try:
        return serve_forever(
            path=sock_path, registry=REGISTRY,
            policy=PrincipalPolicy.resolve(
                operator_group="azknowledge-context-client",
                # The one SERVICE principal (#439, docs/adr/0010-context-observation-unit.md):
                # the model-free context observation service. Never the model host
                # (`azmio`) and never entry (`azmioentry`); root is no SERVICE.
                service_accounts=("azmioctx",),
            ),
            audit=record_refusal,
            handler=handle,
            stop=stop,
            ready=started,
        )
    finally:
        os.close(lock_fd)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
