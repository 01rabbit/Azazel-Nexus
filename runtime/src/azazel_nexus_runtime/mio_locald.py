"""Local runtime service: admission and reserve checks precede inference.

Production has no admitted model or wired runtime. The payload verb accepts
only the entry service principal; model paths and runtime options are never
caller supplied. Advisory bodies return to the caller, never to the ledger.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from azazel_nexus.advisory_response import AdvisoryRefused
from azazel_nexus.audit import AuditLedger, AuditUnavailable
from azazel_nexus.local_advisory import (
    FrameRefused,
    build_prompt,
    read_frame,
    read_local_advisory,
    request_event,
)
from azazel_nexus.model_runtime import (
    ActivationReadiness,
    RuntimeRefused,
    inspect_artifact,
    readiness,
    resolve_runtime,
)

from .principal import PrincipalClass, PrincipalPolicy
from .protocol import Argument, ArgumentKind, Verb, VerbRegistry
from .runtime_paths import mio_state_dir, socket_path
from .serve import serve_forever
from .systemd_notify import runtime_ready_callback

__all__ = [
    "ACTIVATE_VERB",
    "INFER_VERB",
    "LocalRuntimeService",
    "REGISTRY",
    "SOCKET_NAME",
    "STAGING",
    "main",
]

#: Its own socket, not the operator plane's and not the fetcher's. A service
#: that could start a process, answering where everything else answers, would
#: be reachable by everything that can reach anything.
SOCKET_NAME = "mio"

#: The one directory this service reads models from and the only path it may
#: write. Fixed here: a staging directory supplied by a caller is a caller
#: choosing which file is the model.
STAGING = Path("/var/lib/azazel/mio")

ACTIVATE_VERB = Verb(
    name="model.activate",
    arguments=(
        Argument("model_id", ArgumentKind.IDENTIFIER),
        Argument("runtime_id", ArgumentKind.IDENTIFIER),
    ),
    # Not `OPERATOR`. An operator asks the component that owns the admission
    # decision; they do not reach past it to the thing that would start a
    # process.
    admits=frozenset({PrincipalClass.ROOT, PrincipalClass.SERVICE}),
)

INFER_VERB = Verb(
    name="mio.local.infer",
    arguments=(Argument("deadline_ms", ArgumentKind.ORDINAL, maximum=60_000),),
    admits=frozenset({PrincipalClass.SERVICE}),
    accepts_payload=True,
    payload_contract="azazel_nexus.local_advisory.read_frame",
)
REGISTRY = VerbRegistry([ACTIVATE_VERB, INFER_VERB])


@dataclass(frozen=True)
class ActivationReply:
    """What the service says back. Symbols and a reason, never a path."""

    model_id: str
    runtime_id: str
    readiness: str
    reason: str

    def as_document(self) -> dict:
        return {
            "model_id": self.model_id,
            "runtime_id": self.runtime_id,
            "readiness": self.readiness,
            "reason": self.reason,
        }


class LocalRuntimeService:
    """Check readiness or read advice through an explicitly supplied server."""

    def __init__(
        self,
        *,
        staging: Path = STAGING,
        reserve: Optional[Any] = None,
        admitted: Callable[[str], bool] = lambda model_id: False,
        model_id: str = "uncommissioned",
        runtime_id: str = "uncommissioned",
        server: Any = None,
        runtime: Callable = resolve_runtime,
    ) -> None:
        self._staging = staging
        # Supplied, never discovered. The library reads the record; this
        # service is handed the result, so that a node whose reserve record
        # was removed becomes a node that refuses rather than one that
        # remembers.
        self._reserve = reserve
        self._admitted = admitted
        self._model_id = model_id
        self._runtime_id = runtime_id
        self._server = server
        self._runtime = runtime

    def handle(self, request: Any, *, audit: Callable[[dict], None] = lambda e: None) -> dict:
        if getattr(getattr(request, "verb", None), "name", None) == INFER_VERB.name:
            return self._infer(request, audit=audit)
        arguments = request.arguments
        model_id = arguments["model_id"]
        runtime_id = arguments["runtime_id"]

        # The artifact path is derived from the symbol, inside the directory
        # this service owns. `model_id` is an `IDENTIFIER`, whose grammar has
        # no `/` and no `.` run that could climb -- but the join is still done
        # here and nowhere else, and the result is never echoed back.
        artifact = None
        try:
            resolve_runtime(runtime_id)
        except RuntimeRefused:
            pass
        else:
            artifact = inspect_artifact(self._staging / f"{model_id}.model")

        verdict = readiness(
            admitted=self._admitted(model_id),
            runtime_id=runtime_id,
            artifact=artifact,
            reserve=self._reserve,
        )
        return ActivationReply(
            model_id=model_id,
            runtime_id=runtime_id,
            readiness=verdict.readiness.value,
            reason=verdict.reason,
        ).as_document()

    def _infer(self, request: Any, *, audit: Callable[[dict], None]) -> dict:
        def refuse(reason, outcome="failed"):
            audit({"event_type": "mio.local.refused", "refusal": reason})
            return {"outcome": outcome, "refusal": reason}

        try:
            frame = read_frame(request.payload)
        except FrameRefused:
            return refuse("malformed_frame")
        deadline_ms = request.arguments["deadline_ms"]
        if not 0 < deadline_ms <= 60_000:
            return refuse("invalid_deadline")
        audit(request_event(frame))
        if not self._admitted(self._model_id):
            return refuse("not_admitted")
        if self._reserve is None:
            return refuse("reserve_unmeasured")
        try:
            self._runtime(self._runtime_id)
        except RuntimeRefused:
            return refuse("runtime_unavailable")
        artifact = inspect_artifact(self._staging / f"{self._model_id}.model")
        if not artifact.is_data or self._server is None:
            return refuse("provider_unavailable")
        # Runtime dependency stays in the runtime distribution. Tests inject a
        # fake server; the request contract is shared with the serving lane.
        try:
            from .mio_serve import LocalInferenceRequest

            inference = LocalInferenceRequest(
                prompt_messages=build_prompt(frame), max_tokens=512, temperature=0.0,
            )
            result = self._server.infer(inference, deadline_s=deadline_ms / 1000)
        except TimeoutError:
            return refuse("deadline", "timed_out")
        except Exception as error:
            # Provider failures become fixed metadata. Audit failures must
            # remain fatal even when raised inside a composed runtime.
            if isinstance(error, AuditUnavailable):
                raise
            return refuse("runtime_failed")
        try:
            advisory = read_local_advisory(result.text)
        except AdvisoryRefused as exc:
            return refuse(exc.refusal.value, "not_advice")
        audit(advisory.as_event(local=True))
        return {
            "outcome": "advisory", "refusal": None,
            "response_digest": advisory.digest,
            "advice": advisory.text.text if advisory.text else None,
            "fields": dict(advisory.data.fields) if advisory.data else {},
        }


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stop: Callable[[], bool] = lambda: False,
    ready: Optional[Callable[[], None]] = None,
) -> int:
    """Serve. Takes no arguments, by design.

    `argv` is accepted and **refused if it carries anything**, matching every
    other daemon here: an argument vector is readable by every user on the
    host, so a service that took a model path, a runtime path or an option on
    its command line would publish it to all of them.
    """

    if argv is None:
        argv = sys.argv[1:]
    if argv:
        raise SystemExit(
            "az-mio-locald takes no arguments. Which model, which runtime and "
            "what it may consume are decided from commissioned state and this "
            "package's own allowlist, not from a command line"
        )
    ledger = AuditLedger(mio_state_dir() / "local.jsonl")
    try:
        ledger.verify()
        with ledger.path.open("a", encoding="utf-8"):
            pass
    except OSError as error:
        raise AuditUnavailable("M.I.O. local ledger unavailable") from error
    service = LocalRuntimeService()
    return serve_forever(
        path=socket_path(SOCKET_NAME), registry=REGISTRY,
        policy=PrincipalPolicy.resolve(service_accounts=("azmioentry",)),
        audit=ledger.append,
        handler=lambda request: service.handle(request, audit=ledger.append),
        stop=stop, ready=ready if ready is not None else runtime_ready_callback(),
    )


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
