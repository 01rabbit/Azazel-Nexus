"""Dedicated, optional broker for full-node Knowledge Context.

This daemon is the only component that may hold a commissioned Knowledge
peer client. It has no model, enforcement, or Knowledge store authority. The
factory shipped here is uncommissioned unless a root-owned commissioning
bundle is present; no environment switch or command-line option can enable
egress. Tests may inject an explicitly
commissioned client and synthetic trust material.
"""

from __future__ import annotations

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

from azazel_nexus.audit import AuditChainBroken, AuditLedger, AuditUnavailable
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy
from azazel_nexus.technique_knowledge import request_ids

from .activation_markers import inspect_grant_marker
from .knowledge_context_socket import MAX_CONTEXT_FRAME_BYTES, read_context_frame
from .knowledge_context_config import (
    load_commissioning, load_observation_rule, observation_rule_identity)
from .principal import PrincipalClass, PrincipalPolicy
from .chain_guard import ChainGuard
from .protocol import Argument, ArgumentKind, Verb, VerbRegistry
from .runtime_paths import (
    knowledge_context_observation_rule_path, knowledge_context_state_dir, socket_path,
)
from .serve import serve_forever
from .systemd_notify import runtime_ready_callback

__all__ = ["CONTEXT_VERB", "KnowledgeContextBroker", "main"]

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
REGISTRY = VerbRegistry([CONTEXT_VERB])
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
            if not self._slot.acquire(blocking=False):
                reason = "busy"
                raise TimeoutError
            try:
                # Record the sanitized request attempt before any egress. A
                # failed audit sink must keep the optional network path closed.
                phase = "audit"
                self._audit({"event_type": "knowledge.context.requested",
                             "outcome": "attempted"})
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
                    self._audit({"event_type": "knowledge.context.completed",
                                 "outcome": "verified_advisory",
                                 "response_bytes": len(encoded),
                                 "elapsed_ms": min(10_000, int((self._monotonic() - start) * 1000))})
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
        event = {"event_type": "knowledge.context.completed", "outcome": outcome,
                 "elapsed_ms": min(10_000, int((self._monotonic() - start) * 1000))}
        if reason is not None:
            event["reason_code"] = reason
        try:
            self._audit(event)
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


def main(argv: Sequence[str] | None = None, *, stop=lambda: False, ready=None) -> int:
    """Run the disabled-by-default local endpoint; takes no command-line config."""
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        raise SystemExit("az-knowledge-contextd takes no arguments")
    ledger = AuditLedger(knowledge_context_state_dir() / "context.jsonl")
    try:
        ledger.verify()
        with ledger.path.open("a", encoding="utf-8"):
            pass
    except OSError as exc:
        raise AuditUnavailable("Knowledge Context ledger unavailable") from exc
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
    ledger.append(event)
    guard = ChainGuard(ledger.append, ledger.settle)
    #: Set when the record of a verified answer could not be written.
    unrecorded = [False]

    def audit(event: dict) -> None:
        try:
            # Once the peer was called, a record that cannot be written is a
            # debt of the operation already done, not of one that never ran.
            guard.append(event, performed=broker.sent)
        except AuditChainBroken:
            if (event["event_type"] == "knowledge.context.completed"
                    and event.get("outcome") == "verified_advisory"):
                unrecorded[0] = True
            raise

    if commissioning.status == "commissioned":
        broker = KnowledgeContextBroker(
            client=commissioning.client, policy=commissioning.policy,
            mission=commissioning.mission, alias_key=commissioning.alias_key,
            enabled=True, audit=audit,
            observation_rule=observation,
        )
    else:
        broker = KnowledgeContextBroker(audit=audit)
    def handle(request):
        """Record before send; on a broken chain nothing is sent to Knowledge."""
        unrecorded[0] = False
        if guard.broken or (guard.owed and not guard.settle_owed()):
            # Broken, or a write's outcome is still unknown (#467): nothing is
            # sent until the ledger says where it stands.
            guard.count_unrecorded()
            return {"refusal": "unavailable", "stage": "refused_before_send"}
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

    handle.__self__ = broker
    return serve_forever(
        path=socket_path(SOCKET_NAME), registry=REGISTRY,
        policy=PrincipalPolicy.resolve(
            operator_group="azknowledge-context-client",
            # The one SERVICE principal (#439, docs/adr/0010-context-observation-unit.md):
            # the model-free context observation service. Never the model host
            # (`azmio`) and never entry (`azmioentry`); root is no SERVICE.
            service_accounts=("azmioctx",),
        ),
        audit=guard.record_refusal,
        handler=handle,
        stop=stop,
        ready=ready if ready is not None else runtime_ready_callback(),
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
