"""Read-only Knowledge Lite status endpoint; no supply or authority verbs."""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from azazel_nexus.lite_import import status_summary

from .principal import PrincipalClass, PrincipalPolicy
from .protocol import Verb, VerbRegistry

SOCKET_NAME = "knowledge"
STATUS_VERB = Verb(
    "knowledge.status",
    admits=frozenset({PrincipalClass.OPERATOR, PrincipalClass.SERVICE}),
)
REGISTRY = VerbRegistry([STATUS_VERB])


class KnowledgeLiteService:
    """Only bounded status leaves the store. Each request rechecks trust."""

    def __init__(self, *, root: Path, trust_root: Path,
                 now: Callable[[], str] | None = None) -> None:
        self.root = root
        self.trust_root = trust_root
        self.now = now or (lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z"))

    def handle(self, request) -> dict:
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
    service = KnowledgeLiteService(root=knowledge_store_root(),
                                   trust_root=lite_trust_root())
    return serve_forever(
        path=socket_path(SOCKET_NAME), registry=REGISTRY,
        policy=PrincipalPolicy.resolve(service_accounts=("azmioentry", "azarbiter")),
        audit=audit_sink(SOCKET_NAME), handler=service.handle, stop=stop,
        ready=ready if ready is not None else runtime_ready_callback(),
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
