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


class KnowledgeLiteService:
    """Only bounded status and context leave the store. Trust is rechecked."""

    def __init__(self, *, root: Path, trust_root: Path,
                 now: Callable[[], str] | None = None,
                 audit: Callable[[dict], None] = lambda event: None) -> None:
        self.audit = audit
        self.root = root
        self.trust_root = trust_root
        self.now = now or (lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z"))

    def handle(self, request) -> dict:
        if getattr(getattr(request, "verb", None), "name", None) == LOOKUP_VERB.name:
            arguments = LOOKUP_VERB.bind(request.arguments)
            if getattr(request, "payload", None):
                raise RequestRefused(Refusal.UNDECLARED_ARGUMENT, "event")
            ids = tuple(arguments["technique_ids"])
            reading = lookup_context_reading(root=self.root, trust_root=self.trust_root,
                                             technique_ids=ids, query_as_of=self.now())
            result = {"refs": [asdict(ref) for ref in reading.refs],
                      "reason_code": reading.reason_code}
            # JSON escaping can cost twelve bytes per non-BMP character.
            # Retain a deterministic prefix that fits the 64 KiB transport.
            while len(json.dumps({"ok": True, "result": result}).encode()) > 60 * 1024:
                result["refs"].pop()
            self.audit({"event_type": "knowledge.lookup", "technique_ids": list(ids),
                        "count": len(result["refs"])})
            return result
        return status_summary(root=self.root, trust_root=self.trust_root,
                              query_as_of=self.now())


def main(
    argv: Sequence[str] | None = None,
    *,
    stop: Callable[[], bool] = lambda: False,
    ready: Callable[[], None] | None = None,
) -> int:
    """Serve diagnostics even when store or commissioned trust is unreadable."""
    from .runtime_paths import (
        audit_sink,
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
                                   trust_root=lite_trust_root(), audit=audit)
    return serve_forever(
        path=socket_path(SOCKET_NAME), registry=REGISTRY,
        additional_sockets=((socket_path("knowledge-read"),
                             grp.getgrnam("azknowledge-read").gr_gid, READ_REGISTRY),),
        policy=PrincipalPolicy.resolve(service_accounts=("azmioentry", "azarbiter", "azmio")),
        audit=audit, handler=service.handle, stop=stop,
        ready=ready if ready is not None else runtime_ready_callback(),
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
