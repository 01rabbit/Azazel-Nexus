"""Dedicated, optional broker for full-node Knowledge Context.

This daemon is the only component that may hold a commissioned Knowledge
peer client. It has no model, enforcement, or Knowledge store authority. The
factory shipped here is uncommissioned unless a root-owned commissioning
bundle is present; no environment switch or command-line option can enable
egress. Tests may inject an explicitly
commissioned client and synthetic trust material.
"""

from __future__ import annotations

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

__all__ = ["CONTEXT_VERB", "STATUS_VERB", "KnowledgeContextBroker", "WriterBusy", "main"]

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
#: How often a closed ledger is tried again between requests.
_RETRY_INTERVAL_S = 2.0
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
        #: Whether the ledger lets a request go out (#472). Asked after the
        #: observation gate and before anything is recorded or sent.
        self._send_allowed = send_allowed
        #: `present`, `absent` or `unknown` for a `requested` line whose write
        #: had an unknown outcome; decides whether its refusal carries a reference.
        self._request_settled = request_settled
        #: Refusals held back until the line they would refer to is settled:
        #: (event, the `requested` entry in doubt).
        self.deferred: list = []
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

    def _write_refusal(self, event: dict, in_doubt) -> None:
        """A refusal of a request whose `requested` line is in doubt (#472).

        With the line `present` the refusal refers to it; `absent` means it was
        never written, so there is nothing to refer to; unsettled, the refusal
        waits (`flush_deferred`) and is never written without knowing.
        """
        self.deferred.append({"event": event, "line": in_doubt, "written": None, "doubt": None})
        self.flush_deferred()

    def flush_deferred(self) -> None:
        """Write the refusals that waited, once their line is settled. Never raises.

        A refusal whose own write had an unknown outcome is not written again
        until that line is settled: `present` removes it, `absent` writes it again.
        """
        self.sent = False  # these are refusals of requests that never sent
        while self.deferred:
            item = self.deferred[0]
            try:
                if item["doubt"] is not None:
                    verdict = self._request_settled(item["doubt"])
                    if verdict == "present":
                        self.deferred.pop(0)
                        continue
                    if verdict != "absent":
                        return
                    item["doubt"] = None
                if item["written"] is None:
                    verdict = self._request_settled(item["line"])
                    if verdict not in ("present", "absent"):
                        return
                    item["written"] = ({**item["event"], **_reference(item["line"])}
                                       if verdict == "present" else item["event"])
                self._audit(item["written"])
            except AuditOutcomeUnknown as exc:
                item["doubt"] = exc.entry
                return
            except Exception:
                return
            self.deferred.pop(0)

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
        refs: dict = {}
        in_doubt = None
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
            # After the gate (a latch and its record still happen while the
            # ledger is unwell) and before the slot, the record and the client.
            if not self._send_allowed():
                reason = "refused_before_send"
                raise ValueError
            if not self._slot.acquire(blocking=False):
                reason = "busy"
                raise TimeoutError
            try:
                # Record the sanitized request attempt before any egress. A
                # failed audit sink must keep the optional network path closed.
                phase = "audit"
                try:
                    written = self._audit({"event_type": _REQUESTED, "outcome": "attempted",
                                           "format": REQUEST_FORMAT})
                except AuditOutcomeUnknown as exc:
                    in_doubt = exc.entry
                    raise
                refs = _reference(written)
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
                                 **refs})
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
                 "elapsed_ms": min(10_000, int((self._monotonic() - start) * 1000))}
        if reason is not None:
            event["reason_code"] = reason
        if in_doubt is not None:
            self._write_refusal(event, in_doubt)
        else:
            try:
                self._audit({**event, **refs})
            except Exception:
                pass
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


class WriterBusy(Exception):
    """Another process already holds the ledger's writer lock."""


def _take_writer_lock(directory) -> int:
    """The one writer of this ledger, before anything is appended or bound (#472).

    A lock file beside the ledger, held for the life of the process (the kernel
    drops it when the process dies, however it dies). A second daemon stops here,
    so it never reaches the socket path `bind_socket` would replace.
    """
    lock = directory / "context.jsonl.lock"
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise SystemExit(f"az-knowledge-contextd cannot open its writer lock: {exc.strerror}")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise WriterBusy("another az-knowledge-contextd holds the ledger") from None
    return fd


class _Recovery:
    """What this process knows about its ledger, and when egress may open (#472).

    Egress opens only when all three hold: the ledger verified, `commissioning`
    is recorded, and no `requested` line without a result is left unresolved.
    Until then the daemon answers (status, observation latch) and refuses to
    send. Nothing here uses the guard's in-memory `settle` information to decide
    what the ledger holds: the whole ledger is read again each attempt.
    """

    def __init__(self, ledger, guard, commissioning_event: dict) -> None:
        self.ledger, self.guard = ledger, guard
        self._commissioning = commissioning_event
        self.verified = False
        self.commissioned = False
        self._commission_doubt = None
        self.unresolved = 0
        self.legacy_unreferenced = 0
        self.recovered = 0
        self.reason: str | None = "audit_unavailable"
        #: (sequence, hash) of lines found present after an unknown outcome.
        self.present: set = set()

    @property
    def started(self) -> bool:
        """The ledger verified and `commissioning` is recorded: other lines may follow."""
        return self.verified and self.commissioned

    @property
    def open(self) -> bool:
        return (self.verified and self.commissioned and self.unresolved == 0
                and not self.guard.broken and not self.guard.owed)

    def on_settled(self, event, entry) -> None:
        self.present.add((entry.sequence, entry.event_hash))

    def request_verdict(self, entry) -> str:
        """`present`, `absent` or `unknown` for a `requested` line of unknown outcome."""
        if self.guard.broken:
            return "unknown"
        if self.guard.owed and not self.guard.settle_owed():
            return "unknown"
        if self.guard.broken:
            return "unknown"
        return "present" if (entry.sequence, entry.event_hash) in self.present else "absent"

    def attempt(self) -> None:
        """Verify, scan, record commissioning and the missing results. Never raises."""
        if self.guard.broken:
            self.reason = "ledger_broken"
            return
        try:
            if self.guard.owed and not self.guard.settle_owed():
                self.reason = "ledger_broken" if self.guard.broken else "audit_unavailable"
                return
            self.ledger.verify(require_terminated=True)
            with self.ledger.path.open("a", encoding="utf-8"):
                pass
            self.verified = True
            requested, referenced, legacy = {}, set(), 0
            for entry in self.ledger:
                event = entry.event
                kind = event.get("event_type")
                holder = event.get("late_event") if kind in (
                    "audit.late_record", "audit.outcome_settled") else event
                if kind == _REQUESTED:
                    if event.get("format") == REQUEST_FORMAT:
                        requested[(entry.sequence, entry.event_hash)] = entry
                    else:
                        legacy += 1
                if isinstance(holder, dict) and holder.get("event_type") == _COMPLETED:
                    ref = (holder.get("requested_sequence"), holder.get("requested_hash"))
                    if type(ref[0]) is int and type(ref[1]) is str:
                        referenced.add(ref)
            self.legacy_unreferenced = legacy
            missing = [key for key in requested if key not in referenced]
            self.unresolved = len(missing)
            if not self.commissioned:
                if self._commission_doubt is not None:
                    key = (self._commission_doubt.sequence, self._commission_doubt.event_hash)
                    self.commissioned = key in self.present
                    self._commission_doubt = None
                if not self.commissioned:
                    try:
                        self.guard.append(self._commissioning, performed=False)
                    except AuditOutcomeUnknown as exc:
                        self._commission_doubt = exc.entry
                        raise
                    self.commissioned = True
            for sequence, digest in missing:
                self.guard.append({"event_type": _COMPLETED, "outcome": UNKNOWN_OUTCOME,
                                   "reason_code": RESTART_UNCONFIRMED,
                                   "requested_sequence": sequence, "requested_hash": digest},
                                  performed=False)
                self.recovered += 1
                self.unresolved -= 1
            self.reason = None
        except (AuditChainBroken, ValueError) as exc:
            # A line the chain cannot be recomputed or read from (a lone surrogate,
            # broken JSON, a cut line) is a break, not a reason to end before bind.
            # UnicodeError is a ValueError.
            self.verified = False
            self.reason = "ledger_broken"
            if not self.guard.broken:
                self.guard._mark(exc)
        except (AuditUnavailable, OSError):
            self.reason = "ledger_broken" if self.guard.broken else "audit_unavailable"
        if self.reason is None and not self.open:
            self.reason = "audit_unavailable"

    def status(self, broker) -> dict:
        reason = None if self.open else (
            "ledger_broken" if self.guard.broken else self.reason or "audit_unavailable")
        return {"egress": "open" if self.open else "closed", "reason": reason,
                "audit": self.guard.state, "unresolved": self.unresolved,
                "legacy_unreferenced": self.legacy_unreferenced,
                "recovered": self.recovered,
                "observation": "latched" if broker._latched else "open"}


def main(argv: Sequence[str] | None = None, *, stop=lambda: False, ready=None) -> int:
    """Run the disabled-by-default local endpoint; takes no command-line config."""
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        raise SystemExit("az-knowledge-contextd takes no arguments")
    state_dir = knowledge_context_state_dir()
    ledger = AuditLedger(state_dir / "context.jsonl")
    # First, before any append and before the socket is touched.
    try:
        lock_fd = _take_writer_lock(state_dir)
    except WriterBusy as exc:
        raise SystemExit(str(exc))
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
    recovery_ref: list = []
    guard = ChainGuard(ledger.append, settle_single(ledger),
                       on_settled=lambda e, entry: recovery_ref[0].on_settled(e, entry))
    recovery = _Recovery(ledger, guard, event)
    recovery_ref.append(recovery)
    #: Set when the record of a verified answer could not be written.
    unrecorded = [False]

    def audit(event: dict) -> None:
        if not recovery.started:
            # Nothing but the start-up's own lines may be the first (#472): a
            # latch or refusal record before `commissioning` is dropped, the
            # latch itself is not.
            guard.count_unrecorded()
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
        """A debt of unknown outcome is settled first (#467); then the whole of #472."""
        if guard.broken:
            return False
        if guard.owed and not guard.settle_owed():
            if not guard.broken:
                guard.count_unrecorded()
            return False
        if not recovery.open:
            recovery.attempt()
        return recovery.open and not guard.broken

    # The start-up appends are the first ones this process makes; a failure of
    # any of them leaves egress closed and the daemon serving.
    recovery.attempt()
    if commissioning.status == "commissioned":
        broker = KnowledgeContextBroker(
            client=commissioning.client, policy=commissioning.policy,
            mission=commissioning.mission, alias_key=commissioning.alias_key,
            enabled=True, audit=audit,
            observation_rule=observation,
            send_allowed=send_allowed, request_settled=recovery.request_verdict,
        )
    else:
        broker = KnowledgeContextBroker(
            audit=audit, send_allowed=send_allowed, request_settled=recovery.request_verdict)

    def handle(request):
        """Record before send; on a broken chain nothing is sent to Knowledge."""
        unrecorded[0] = False
        if getattr(getattr(request, "verb", None), "name", None) == STATUS_VERB.name:
            return recovery.status(broker)
        broker.flush_deferred()
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
        if recovery.started:
            guard.record_refusal(event)
        else:
            guard.count_unrecorded()

    record_refusal.__self__ = guard
    last_retry = [time.monotonic()]

    def poll() -> bool:
        """Between requests: a closed ledger is retried, and held refusals are written."""
        now = time.monotonic()
        if now - last_retry[0] >= _RETRY_INTERVAL_S:
            last_retry[0] = now
            if not guard.broken:
                if guard.owed:
                    guard.settle_owed()
                if not recovery.open:
                    recovery.attempt()
                broker.flush_deferred()
        return stop()

    handle.__self__ = broker
    try:
        return serve_forever(
            path=socket_path(SOCKET_NAME), registry=REGISTRY,
            policy=PrincipalPolicy.resolve(
                operator_group="azknowledge-context-client",
                # The one SERVICE principal (#439, docs/adr/0010-context-observation-unit.md):
                # the model-free context observation service. Never the model host
                # (`azmio`) and never entry (`azmioentry`); root is no SERVICE.
                service_accounts=("azmioctx",),
            ),
            audit=record_refusal,
            handler=handle,
            stop=poll,
            ready=ready if ready is not None else runtime_ready_callback(),
        )
    finally:
        os.close(lock_fd)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
