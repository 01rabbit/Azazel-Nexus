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
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from threading import BoundedSemaphore
from typing import Any

from azazel_nexus.audit import AuditLedger, AuditUnavailable
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy

from .knowledge_context_socket import MAX_CONTEXT_FRAME_BYTES, read_context_frame
from .knowledge_context_config import load_commissioning
from .principal import PrincipalClass, PrincipalPolicy
from .protocol import Argument, ArgumentKind, Verb, VerbRegistry
from .runtime_paths import knowledge_context_state_dir, socket_path
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
# Fixed request sections a client may name on the refusal it raises.
_CLIENT_STAGES = frozenset({"refused_before_send", "transport", "verification"})


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
        self._slot = BoundedSemaphore(1)
        self._ready = (enabled is True and client is not None
                       and isinstance(policy, SanitizerPolicy)
                       and type(mission) is str and bool(mission)
                       and type(alias_key) is bytes and len(alias_key) >= 32)

    def handle(self, request) -> dict:
        if getattr(getattr(request, "verb", None), "name", None) != CONTEXT_VERB.name:
            return {"refusal": "unavailable"}
        start = self._monotonic()
        deadline_ms = request.arguments["deadline_ms"]
        deadline_monotonic = request.arguments["deadline_monotonic_ns"] / 1_000_000_000
        # Honor both caller deadline representations. The absolute value is a
        # local monotonic bound, not permission to extend deadline_ms.
        deadline = min(start + deadline_ms / 1000, deadline_monotonic)
        deadline_s = deadline - start
        if deadline_s <= 0:
            return {"refusal": "timeout"}
        reason = None
        phase = "frame"
        try:
            wire_frame = read_context_frame(request.payload.get("frame"))
            if set(request.payload) != {"frame"} or not self._ready:
                raise ValueError
            # This required label is a caller assertion, not a content
            # classifier. Production commissioning must restrict which
            # trusted local inputs can make this assertion; the shipped
            # factory has no egress client and cannot use it for network IO.
            # Context arrays and all other fields stay local.
            if (set(wire_frame) != {"privacy_class", "question"}
                    or wire_frame["privacy_class"] != PrivacyClass.P0_PUBLIC.value
                    or type(wire_frame["question"]) is not str
                    or not wire_frame["question"]
                    or len(wire_frame["question"]) > 2048):
                raise ValueError
            frame = {"question": wire_frame["question"]}
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
            self._audit({"event_type": "knowledge.context.completed",
                         "outcome": "verified_advisory",
                         "response_bytes": len(encoded),
                         "elapsed_ms": min(10_000, int((self._monotonic() - start) * 1000))})
            return {"response": response}
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
        return {"refusal": outcome}


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
    event = {"event_type": "knowledge.context.commissioning",
             "outcome": commissioning.status}
    if commissioning.reason_code:
        event["reason_code"] = commissioning.reason_code
    if commissioning.registry_version is not None:
        event["registry_version"] = commissioning.registry_version
    ledger.append(event)
    if commissioning.status == "commissioned":
        broker = KnowledgeContextBroker(
            client=commissioning.client, policy=commissioning.policy,
            mission=commissioning.mission, alias_key=commissioning.alias_key,
            enabled=True, audit=ledger.append,
        )
    else:
        broker = KnowledgeContextBroker(audit=ledger.append)
    return serve_forever(
        path=socket_path(SOCKET_NAME), registry=REGISTRY,
        policy=PrincipalPolicy.resolve(
            operator_group="azknowledge-context-client",
            service_accounts=("azmio",),
        ),
        audit=ledger.append, handler=broker.handle, stop=stop,
        ready=ready if ready is not None else runtime_ready_callback(),
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
