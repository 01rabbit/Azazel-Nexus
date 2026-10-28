"""Read-only Knowledge Lite status and bounded advisory lookup."""

from __future__ import annotations

import grp
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from azazel_nexus.lite_import import (
    TECHNIQUE_ID,
    lookup_context_reading,
    status_summary,
)

from .knowledge_clock_floor import ClockFloor, FloorUnavailable
from .principal import PrincipalClass, PrincipalPolicy
from .protocol import (
    Argument,
    ArgumentKind,
    Refusal,
    RequestRefused,
    Verb,
    VerbRegistry,
)

SOCKET_NAME = "knowledge"
STATUS_VERB = Verb(
    "knowledge.status",
    admits=frozenset({PrincipalClass.OPERATOR, PrincipalClass.SERVICE}),
)


class TechniqueIdsArgument(Argument):
    """Local bounded list grammar; no new general-purpose protocol kind."""

    def coerce(self, value):
        if type(value) is not list:
            raise RequestRefused(Refusal.ARGUMENT_TYPE, self.name)
        if len(value) > 8 or any(type(item) is not str or not TECHNIQUE_ID.fullmatch(item)
                                 for item in value):
            raise RequestRefused(Refusal.ARGUMENT_RANGE, self.name)
        return value


LOOKUP_VERB = Verb(
    "knowledge.lookup",
    arguments=(TechniqueIdsArgument("technique_ids", ArgumentKind.IDENTIFIER),),
    admits=frozenset({PrincipalClass.SERVICE}),
)
REGISTRY = VerbRegistry([STATUS_VERB, LOOKUP_VERB])
READ_REGISTRY = VerbRegistry([LOOKUP_VERB])

#: The fixed reply when the wall clock is behind the persisted floor, or the
#: floor cannot be read or kept. Existing vocabulary: local state that guards
#: serving cannot be trusted, so nothing (dated or static) is served.
CLOCK_UNTRUSTED = "state_untrusted"


class KnowledgeLiteService:
    """Only bounded status and context leave the store. Trust is rechecked."""

    def __init__(self, *, root: Path, trust_root: Path, clock_floor: ClockFloor,
                 now: Callable[[], str] | None = None,
                 audit: Callable[[dict], None] = lambda event: None) -> None:
        if type(clock_floor) is not ClockFloor:
            raise TypeError("a persisted clock floor is required")
        self.audit = audit
        self.root = root
        self.trust_root = trust_root
        self.clock_floor = clock_floor
        self.now = now or (lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z"))
        self._clock_refused: str | None = None

    def _query_as_of(self) -> str | None:
        """The wall clock, only if it is not behind the persisted floor.

        None means serve nothing. The audit records the transition into a
        refusal once, with a fixed cause and no instant or path.
        """
        query_as_of = self.now()
        try:
            cause = None if self.clock_floor.admit(query_as_of) else "regressed"
        except FloorUnavailable:
            cause = "floor_unavailable"
        if cause is not None and cause != self._clock_refused:
            self.audit({"event_type": "knowledge.clock_untrusted", "cause": cause})
        self._clock_refused = cause
        return None if cause is not None else query_as_of

    def handle(self, request) -> dict:
        if getattr(getattr(request, "verb", None), "name", None) == LOOKUP_VERB.name:
            arguments = LOOKUP_VERB.bind(request.arguments)
            if getattr(request, "payload", None):
                raise RequestRefused(Refusal.UNDECLARED_ARGUMENT, "event")
            ids = tuple(arguments["technique_ids"])
            query_as_of = self._query_as_of()
            if query_as_of is None:
                self.audit({"event_type": "knowledge.lookup", "technique_ids": list(ids),
                            "count": 0})
                return {"refs": [], "reason_code": CLOCK_UNTRUSTED}
            reading = lookup_context_reading(root=self.root, trust_root=self.trust_root,
                                             technique_ids=ids, query_as_of=query_as_of)
            result = {"refs": [asdict(ref) for ref in reading.refs],
                      "reason_code": reading.reason_code}
            # JSON escaping can cost twelve bytes per non-BMP character.
            # Retain a deterministic prefix that fits the 64 KiB transport.
            while len(json.dumps({"ok": True, "result": result}).encode()) > 60 * 1024:
                result["refs"].pop()
            self.audit({"event_type": "knowledge.lookup", "technique_ids": list(ids),
                        "count": len(result["refs"])})
            return result
        query_as_of = self._query_as_of()
        if query_as_of is None:
            return {"state": "unavailable", "reason_code": CLOCK_UNTRUSTED,
                    "generation": None, "freshness": "absent"}
        return status_summary(root=self.root, trust_root=self.trust_root,
                              query_as_of=query_as_of)


def main(
    argv: Sequence[str] | None = None,
    *,
    stop: Callable[[], bool] = lambda: False,
    ready: Callable[[], None] | None = None,
) -> int:
    """Serve diagnostics even when store or commissioned trust is unreadable."""
    from .runtime_paths import (
        audit_sink,
        knowledge_state_dir,
        knowledge_store_root,
        lite_trust_root,
        socket_path,
    )
    from .serve import serve_forever
    from .systemd_notify import runtime_ready_callback

    if argv is None:
        argv = sys.argv[1:]
    if argv:
        raise SystemExit("az-knowledge-lited takes no arguments")
    audit = audit_sink(SOCKET_NAME)
    service = KnowledgeLiteService(root=knowledge_store_root(),
                                   trust_root=lite_trust_root(),
                                   clock_floor=ClockFloor(knowledge_state_dir()), audit=audit)
    return serve_forever(
        path=socket_path(SOCKET_NAME), registry=REGISTRY,
        additional_sockets=((socket_path("knowledge-read"),
                             grp.getgrnam("azknowledge-read").gr_gid, READ_REGISTRY),),
        policy=PrincipalPolicy.resolve(service_accounts=("azmioentry", "azarbiter", "azmio", "azexplain")),
        audit=audit, handler=service.handle, stop=stop,
        ready=ready if ready is not None else runtime_ready_callback(),
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
