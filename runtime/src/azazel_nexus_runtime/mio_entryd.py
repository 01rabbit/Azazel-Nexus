"""Metadata-only M.I.O. entry; providers remain separate socket services."""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence

from azazel_nexus.audit import AuditUnavailable
from azazel_nexus.mio_profile import NO_OPT_IN, MioProfile, profile_in_force
from azazel_nexus.remote_trust import remote_admission, unchecked_reading
from azazel_nexus.sanitizer import PrivacyClass

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
REGISTRY = VerbRegistry([ROUTE_VERB])
LOCAL_REFUSAL = "HG-05 Core reserve unmeasured; no local provider admitted"


def commissioned_profile() -> MioProfile:
    # The existing reader requires a confirmed selection. No persisted M.I.O.
    # commissioning reader exists in this build: absence must remain CORE.
    # Resource observations cannot substitute for a confirmed selection.
    return profile_in_force(commissioned=False, selected=None)


class MioEntryService:
    def __init__(self, *, profile_reader: Callable[[], MioProfile] = commissioned_profile):
        self.local = LocalSocketClient()
        self.remote = RemoteSocketClient()
        self.router = MioRouter(local=self.local, remote=self.remote)
        self._profile_reader = profile_reader

    def handle(self, request) -> dict:
        if request.arguments["deadline_ms"] == 0:
            raise RequestRefused(Refusal.ARGUMENT_RANGE, "deadline_ms")
        profile = self._profile_reader()
        privacy = PrivacyClass(request.arguments["privacy_class"])
        # Observations remain separate from admission and prediction. Even a
        # reachable daemon cannot lift HG-05 or establish remote trust.
        self.router._record({
            "event_type": "mio.entry.availability",
            "local": self.local.observe(),
            "remote": self.remote.observe(),
            "local_refusal": LOCAL_REFUSAL,
            "remote_trust": "unchecked",
        })
        result = self.router.handle(
            local_request=None, remote_request=None,
            profile=profile, privacy_class=privacy,
            remote=remote_admission(
                profile=profile, opt_in=NO_OPT_IN,
                trust=unchecked_reading(), privacy_class=privacy, sanitised=False,
            ),
            local_admitted=False, local_refusal=LOCAL_REFUSAL,
            predictions={}, deadline_ms=request.arguments["deadline_ms"],
        )
        return {
            "route": result.route.value, "outcome": result.outcome.value,
            "reason": result.selection.reason,
            "ledger_seq": self.router.ledger.head()[0],
        }


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
        service.router.ledger.verify()
        with path.open("a", encoding="utf-8"):
            pass
        service.router._record({"event_type": "mio.entry.started"})
    except OSError as error:
        raise AuditUnavailable("M.I.O. route ledger unavailable") from error
    return serve_forever(
        path=socket_path(SOCKET_NAME), registry=REGISTRY,
        policy=PrincipalPolicy.resolve(service_accounts=("azarbiter",)),
        audit=service.router._record, handler=service.handle, stop=stop,
        ready=ready if ready is not None else runtime_ready_callback(),
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
