"""Local runtime service: admission and reserve checks precede inference.

Production has one pinned runtime and no admitted model. The payload verb accepts
only the entry service principal; model paths and runtime options are never
caller supplied. Advisory bodies return to the caller, never to the ledger.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from azazel_nexus import model_admission
from azazel_nexus.advisory_response import AdvisoryRefused
from azazel_nexus.audit import AuditLedger, AuditUnavailable
from azazel_nexus.lite_import import KnowledgeRef
from azazel_nexus.local_advisory import (
    DELIVERED_MAX_BYTES,
    FrameRefused,
    build_options,
    delivered_document,
    delivered_event,
    explanation_prompt,
    explanation_response_format,
    gate_frame,
    read_delivered,
    read_explanation,
    read_frame,
    request_event,
    retrieval_decision,
)
from azazel_nexus.model_runtime import (
    LLAMA_RUNTIME_ID,
    RuntimeRefused,
    inspect_artifact,
    inspect_artifact_fd,
    readiness,
    resolve_runtime,
)
from azazel_nexus.reasoning_playbook import Library, technique_ids

from .knowledge_client import KnowledgeUnavailable, lookup_context
from .mio_playbooks import PlaybookSelectionHolder
from .principal import PrincipalClass, PrincipalPolicy
from .protocol import Argument, ArgumentKind, Verb, VerbRegistry
from .runtime_paths import (
    mio_local_state_dir,
    mission_pack_config,
    mission_pack_root,
    socket_path,
)
from .serve import serve_forever
from .systemd_notify import runtime_ready_callback
from .transport import MAX_FRAME_BYTES

__all__ = [
    "ACTIVATE_VERB",
    "ADMISSION_VERB",
    "INFER_VERB",
    "REGISTRY",
    "SOCKET_NAME",
    "STAGING",
    "LocalRuntimeService",
    "main",
]

#: Its own socket, not the operator plane's and not the fetcher's. A service
#: that could start a process, answering where everything else answers, would
#: be reachable by everything that can reach anything.
SOCKET_NAME = "mio"

#: The one directory this service reads models from and, with its own socket
#: leaf under /var/lib/azazel/run/mio, the only path it may write. Fixed here: a staging directory supplied by a caller is a caller
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
FAST_ASSESS_VERB = Verb(
    name="mio.local.assess",
    arguments=(Argument("deadline_ms", ArgumentKind.ORDINAL, maximum=60_000),),
    admits=frozenset({PrincipalClass.SERVICE}), accepts_payload=True,
    payload_contract="azazel_nexus.local_advisory.read_frame",
)
GENERATION_RESULT_VERB = Verb(
    name="mio.local.generation.result",
    arguments=tuple(Argument(name, ArgumentKind.IDENTIFIER) for name in
                    ("result_handle", "generation_id", "trace_id")),
    admits=frozenset({PrincipalClass.SERVICE}),
)
#: Read-only: whether this service now holds an admitted local model, as the
#: result of its own `AdmissionHolder` (refreshed before every request). No
#: arguments, no payload, SERVICE only -- the same principal set as the
#: inference verb, so it reaches no one `mio.local.infer` does not. It grants
#: nothing: entry reads it to decide whether LOCAL may be *selected*, and
#: every gate in `_infer` still runs on the request that follows.
ADMISSION_VERB = Verb(
    name="mio.local.admission",
    admits=frozenset({PrincipalClass.SERVICE}),
)
#: No reference verb: verified playbook references are served by the
#: model-free `azazel-mio-referenced.service` (`mio_referenced`), which runs
#: on a node with no admitted model. This host serves only model verbs.
REGISTRY = VerbRegistry([ACTIVATE_VERB, ADMISSION_VERB, INFER_VERB, FAST_ASSESS_VERB, GENERATION_RESULT_VERB])


def _read_assessment_payload(payload: Any) -> tuple[dict, dict | None]:
    """Read the usual frame and an optional, bounded Fabric response.

    The response remains untrusted advisory content. MIO performs its own
    schema, freshness, redaction and no-action projection. The frame uses the
    existing reader; the nested response cannot exceed the AF_UNIX message cap.
    """
    if type(payload) is dict and "frame" in payload:
        if set(payload) != {"frame", "fabric_knowledge_context_response"}:
            raise FrameRefused("malformed_assessment_payload")
        frame = read_frame(payload["frame"])
        response = payload["fabric_knowledge_context_response"]
        if type(response) is not dict:
            raise FrameRefused("malformed_assessment_payload")
        try:
            encoded = json.dumps(
                response, ensure_ascii=False, allow_nan=False, separators=(",", ":")
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise FrameRefused("malformed_assessment_payload") from None
        if len(encoded) > MAX_FRAME_BYTES:
            raise FrameRefused("malformed_assessment_payload")
        return frame, response
    return read_frame(payload), None


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


class KnowledgeLookup(Protocol):
    def __call__(self, technique_ids: tuple[str, ...], *,
                 deadline_s: float) -> Sequence[KnowledgeRef]: ...


class LocalRuntimeService:
    """Check readiness or read advice through an explicitly supplied server."""

    def __init__(
        self,
        *,
        staging: Path = STAGING,
        retriever=None,
        artifact_path: Path | None = None,
        reserve: Any | None = None,
        admitted: Callable[[str], bool] = lambda model_id: False,
        model_id: str = "uncommissioned",
        runtime_id: str = "uncommissioned",
        server: Any = None,
        runtime: Callable = resolve_runtime,
        playbooks: Library | None = None,
        knowledge_lookup: KnowledgeLookup | None = None,
        generation_lane=None,
        generation_id: str = "uncommissioned",
    ) -> None:
        # The deterministic MIO lane must not pay the shared-package import
        # cost inside the first request's short deadline. Importing this
        # adapter is side-effect-free; model/runtime admission remains a
        # separate, per-request gate below.
        try:
            from . import mio_fast_assistance as _mio_fast_assistance  # noqa: F401
        except Exception:  # noqa: BLE001 - the shared package is optional
            pass
        self._artifact_path = artifact_path
        self._retriever = retriever
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
        self._playbooks = playbooks
        # The injected runtime client owns its socket deadline.
        self._knowledge_lookup = knowledge_lookup
        from .mio_generation import GenerationLane
        self._generation_lane = generation_lane if generation_lane is not None else GenerationLane()
        self._generation_id = generation_id

    def set_playbooks(self, library: Library | None) -> None:
        self._playbooks = library

    def admission(self) -> dict:
        """The admission verb's reply: `{"admitted": bool}`, nothing else.

        True only while the feature constant is on, the admission result this
        service was handed still names its model, and a provider is held.
        A withdrawal (`main`'s `withdraw`) clears the latter two first, so an
        expired or changed approval reads False from the next request on.
        """
        admitted = (model_admission.LOCAL_MODEL_ADMISSION_ENABLED is True
                    and self._admitted(self._model_id) is True
                    and (self._retriever is not None or self._server is not None))
        return {"admitted": admitted}

    def handle(self, request: Any, *, audit: Callable[[dict], None] = lambda e: None) -> dict:
        name = getattr(getattr(request, "verb", None), "name", None)
        if name == GENERATION_RESULT_VERB.name:
            return {"outcome": "generation_result", "slow_analysis":
                    self._generation_lane.poll(**request.arguments)}
        if name == INFER_VERB.name:
            return self._infer(request, audit=audit)
        if name == FAST_ASSESS_VERB.name:
            try:
                frame, fabric_context_response = _read_assessment_payload(request.payload)
            except FrameRefused:
                return {"outcome": "failed", "refusal": "malformed_frame"}
            # The shared package is an integration dependency, not a reason
            # for the local service process to exit. Keep a typed, fixed
            # degradation at this boundary when it is absent or broken.
            try:
                from .mio_fast_assistance import fast_assistance, _frame
                situation = _frame(frame)
                result = fast_assistance(
                    frame, deadline_s=max(0.0, request.arguments["deadline_ms"] / 1000
                                          - DELIVERY_RESERVE_S),
                    knowledge_lookup=self._knowledge_lookup, knowledge_max_s=KNOWLEDGE_MAX_S,
                    core_reserve_s=FAST_CORE_RESERVE_S, situation_frame=situation,
                    fabric_knowledge_context_response=fabric_context_response)
            except Exception:
                from .mio_socket_client import fast_assessment_degraded
                result = fast_assessment_degraded("unavailable")
            slow = {"state": "closed", "usage": "unknown"}
            try:
                slow = self._generation_lane.submit(frame, situation, self._generation_id)
            except Exception:
                pass
            return {"outcome": "assessed", "fast_assistance": result, "slow_analysis": slow}
        if name == ADMISSION_VERB.name:
            return self.admission()
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
        began = time.monotonic()

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
        # Embeddings may only run after the existing admission gates. Lexical
        # insufficient-information checks remain available without a provider.
        initial_gate = gate_frame(frame)
        gated = initial_gate if self._retriever is None or (
            initial_gate and initial_gate['reason'] == 'insufficient_information') else None
        if gated is not None:
            audit({"event_type": "mio.local.gated", "reason": gated["reason"]})
            return gated
        if not self._admitted(self._model_id):
            if self._playbooks is None:
                return refuse("not_admitted")
            from .mio_embedding import retrieve


            playbooks, similarities, method, embed_ms = retrieve(
                frame, self._playbooks, None, end=began + deadline_ms / 1000)
            reply, telemetry = retrieval_pipeline(
                None, frame, playbooks, (), "deterministic",
                end=began + deadline_ms / 1000, audit=audit, similarities=similarities,
                retrieval=method, embed_ms=embed_ms)
            audit({"event_type": "mio.local.retrieval", "method": method})
            audit(delivered_event(reply))
            return {"outcome": "advisory", "refusal": None, **reply}
        if self._reserve is None:
            return refuse("reserve_unmeasured")
        try:
            self._runtime(self._runtime_id)
        except RuntimeRefused:
            return refuse("runtime_unavailable")
        if self._artifact_path is not None and str(self._artifact_path).startswith("/proc/self/fd/"):
            artifact = inspect_artifact_fd(int(self._artifact_path.name))
        else:
            artifact = inspect_artifact(self._artifact_path or self._staging / f"{self._model_id}.model")
        if not artifact.is_data or (self._server is None and self._retriever is None):
            return refuse("provider_unavailable")
        from .mio_embedding import retrieve

        playbooks, similarities, retrieval, embed_ms = retrieve(
            frame, self._playbooks, self._retriever, end=began + deadline_ms / 1000)
        audit({'event_type': 'mio.local.retrieval', 'method': retrieval})
        gated = gate_frame(frame, max(similarities, default=-1.0))
        if gated is not None:
            audit({'event_type': 'mio.local.gated', 'reason': gated['reason']})
            return gated
        knowledge = ()
        knowledge_state = "unused"
        ids = technique_ids(frame)
        if self._knowledge_lookup is not None and ids:
            # Optional context gets a capped share and leaves the deterministic
            # pipeline its time afterwards, so a silent Knowledge service costs
            # at most KNOWLEDGE_MAX_S and never turns playbook advice into a
            # timeout. It may cost the optional explanation in a tight budget.
            budget = min(KNOWLEDGE_MAX_S, began + deadline_ms / 1000 - time.monotonic()
                         - DELIVERY_RESERVE_S - PIPELINE_RESERVE_S)
            if budget <= 0:
                knowledge_state = "skipped_budget_exhausted"
            else:
                try:
                    knowledge = tuple(self._knowledge_lookup(ids, deadline_s=budget))
                    knowledge_state = "available" if knowledge else "no_context"
                except Exception as error:  # noqa: BLE001 - optional context
                    if isinstance(error, AuditUnavailable):
                        raise
                    knowledge, knowledge_state = (), "unavailable"
        audit({"event_type": "mio.local.reference", "playbook_ids": [p.id for p in playbooks],
               "playbook_count": len(playbooks), "knowledge": knowledge_state,
               "knowledge_count": len(knowledge)})
        try:
            reply, telemetry = retrieval_pipeline(
                self._server, frame, playbooks, knowledge, self._model_id,
                end=began + deadline_ms / 1000, audit=audit, similarities=similarities,
                retrieval=retrieval, embed_ms=embed_ms,
            )
        except TimeoutError:
            return refuse("deadline", "timed_out")
        except Exception as error:
            if isinstance(error, AuditUnavailable):
                raise
            return refuse("runtime_failed")
        audit({"event_type": "mio.local.selection", **telemetry})
        audit(delivered_event(reply))
        return {"outcome": "advisory", "refusal": None, **reply}


# Keep 20 ms for bounded document validation, audit and socket delivery after
# optional I/O; this is a software budget, not measured hardware latency.
DELIVERY_RESERVE_S = 0.02
EXPLANATION_MIN_S = 1.0
# Knowledge is a local socket read of at most 64 KiB; a healthy service answers
# well inside this, and an unhealthy one must not take the request with it.
KNOWLEDGE_MAX_S = 0.25
# Preserve the pre-existing clean 500ms route's maximum shared-core budget.
# Optional Knowledge may use only slack beyond this; no measured reduction.
FAST_CORE_RESERVE_S = 0.025
# Deterministic selection, validation and audit after the optional lookup.
PIPELINE_RESERVE_S = 0.05


def retrieval_pipeline(server, frame, playbooks=(), knowledge=(), model_id="bench", *,
                           end, audit=lambda event: None, similarities=(), retrieval="keyword", embed_ms=0):
    """Shared runtime/bench orchestration, with one absolute deadline."""
    from .mio_serve import LocalInferenceRequest

    def remaining():
        budget = end - time.monotonic() - DELIVERY_RESERVE_S
        if budget <= 0:
            raise TimeoutError("local pipeline deadline")
        return budget

    remaining()
    options = build_options(frame, playbooks)
    candidate, state, support, record = retrieval_decision(frame, playbooks, similarities)
    ranked = list(options)
    guard = None
    explanation = None
    dropped = None
    explanation_began = time.monotonic()
    if state != "none" and server is not None:
        if remaining() < EXPLANATION_MIN_S:
            dropped = "deadline_short"
        else:
            chosen = next(o for o in options if o["option_id"] == candidate["option_id"])
            messages = explanation_prompt(frame, chosen, playbooks, knowledge)
            try:
                result = server.infer(LocalInferenceRequest(
                    messages, max_tokens=512, temperature=0,
                    response_format=explanation_response_format()), deadline_s=remaining())
                remaining()
                explanation = read_explanation(result.text, frame, candidate, messages[1][1])
            except TimeoutError:
                dropped = "deadline"
            except (ValueError, AdvisoryRefused) as exc:
                dropped = str(exc) if type(exc) is ValueError else exc.refusal.value
                if dropped not in {"explanation_schema", "duplicate_key", "reason_without_quote",
                                   "opposite_class", "degenerate", "ungrounded_facts",
                                   "language_mismatch", "looks_like_an_instruction", "not_text",
                                   "control_characters", "empty"}:
                    dropped = "explanation_schema"
            except Exception as error:
                if isinstance(error, AuditUnavailable):
                    raise
                dropped = "runtime_failed"
    if dropped:
        audit({"event_type": "mio.local.explanation", "reason": "explanation_dropped:" + dropped})
    reply = delivered_document(frame, playbooks, options, candidate, ranked, guard, model_id, explanation,
                               similarities=similarities, state=state, retrieval=retrieval,
                               benign_evidence=support, system_record=record,
                               provenance="model" if explanation else retrieval)
    # Only verified Knowledge Lite references carry the provenance the reader
    # checks. Offline evaluation fixtures may inform the prompt but are never
    # delivered as if they had been verified.
    delivered_refs = [asdict(ref) for ref in knowledge if isinstance(ref, KnowledgeRef)]
    # Optional references are dropped from the end rather than letting them
    # push a valid advisory over the delivered-size bound.
    while delivered_refs:
        reply['knowledge'] = delivered_refs
        if len(json.dumps(reply, ensure_ascii=False).encode('utf-8')) <= DELIVERED_MAX_BYTES:
            break
        delivered_refs = delivered_refs[:-1]
    else:
        reply.pop('knowledge', None)
    read_delivered(reply)
    return reply, {"explanation_dropped": dropped, "embed_ms": embed_ms,
                   "explanation_ms": (time.monotonic() - explanation_began) * 1000,
                   "retrieval": retrieval, "benign_evidence": support}


def prepare_local_models(candidates, *, staging, audit):
    """Only loader-minted embedding evidence can reach a supervised process."""
    from azazel_nexus.runtime_lifecycle import BudgetLedger

    from .mio_embedding import EmbeddingRetriever
    from .mio_serve import LocalServer
    from .model_admission_evidence import (
        AdmissionReading,
        Admitted,
        decide_embedding_admission,
    )

    handles = []
    for candidate in candidates:
        if type(candidate) is not Admitted:
            audit({"event_type": "mio.local.refused", "refusal": "unverified_candidate"})
            continue
        evidence = candidate.evidence
        server = None
        try:
            decision = decide_embedding_admission(
                now=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                reading=AdmissionReading(candidate))
            if type(decision.embedding) is not Admitted:
                audit(decision.as_event())
                continue
            held = evidence.descriptors
            binary = held.recheck()
            endpoint = staging / "embedding.sock"
            ledger = BudgetLedger(staging / "embedding-budget.json")
            generation = evidence.context.bindings["generation"]["number"]
            budget = ledger.load(generation=generation, runtime_id=binary.runtime_id)
            server = LocalServer(candidate.record, root=Path("/"), socket_path=endpoint,
                                 start_deadline_s=120, ledger=ledger, budget=budget,
                                 descriptors=held)
            server.start()
            handles.append(server)
            return {"retriever": EmbeddingRetriever(server, model_digest=candidate.entry.digest,
                                                     cache_dir=staging / "embedding-cache"),
                    "artifact_path": Path(f"/proc/self/fd/{held.model_fd}"),
                    "staging": staging, "model_id": candidate.entry.model_id,
                    "runtime_id": LLAMA_RUNTIME_ID, "reserve": candidate.resources.reserve,
                    "admitted": lambda model_id, selected=candidate.entry.model_id: model_id == selected,
                    "runtime": lambda runtime_id, descriptors=held: descriptors.recheck(), "server": None}, handles
        except Exception as error:
            if isinstance(error, AuditUnavailable):
                raise
            if server is not None:
                server.stop()
            audit({"event_type": "mio.local.refused", "role": "embedding",
                   "refusal": "provider_unavailable"})
    return {}, []


def main(
    argv: Sequence[str] | None = None,
    *,
    stop: Callable[[], bool] = lambda: False,
    ready: Callable[[], None] | None = None,
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
    ledger = AuditLedger(mio_local_state_dir() / "local.jsonl")
    try:
        ledger.verify()
        with ledger.path.open("a", encoding="utf-8"):
            pass
    except OSError as error:
        raise AuditUnavailable("M.I.O. local ledger unavailable") from error
    selection = PlaybookSelectionHolder(config=mission_pack_config(), root=mission_pack_root())
    library = selection.refresh(audit=ledger.append)
    from .model_admission_evidence import (
        POLL_INTERVAL_SECONDS,
        AdmissionHolder,
        Admitted,
    )

    admissions = AdmissionHolder()
    reading = admissions.start(audit=ledger.append)
    candidates = [reading.embedding] if type(reading.embedding) is Admitted else []
    if not candidates:
        ledger.append({"event_type": "mio.local.refused", "refusal": "not_admitted"})
    providers, handles = prepare_local_models(candidates, staging=STAGING, audit=ledger.append)
    service = LocalRuntimeService(playbooks=library, knowledge_lookup=lookup_context, **providers)

    def withdraw():
        service._retriever = None
        service._server = None
        service._admitted = lambda model_id: False
        for server in handles:
            try:
                server.stop()
            except Exception:  # noqa: BLE001 - disconnect first; never restore a withdrawn retriever
                ledger.append({"event_type": "mio.local.refused", "role": "embedding",
                               "refusal": "withdrawal_stop_failed"})

    next_poll = time.monotonic()

    def poll():
        nonlocal next_poll
        if time.monotonic() >= next_poll:
            admissions.refresh(withdraw=withdraw, audit=ledger.append)
            next_poll = time.monotonic() + POLL_INTERVAL_SECONDS
        return stop()

    def handle(request):
        admissions.refresh(withdraw=withdraw, audit=ledger.append)
        service.set_playbooks(selection.refresh(audit=ledger.append))
        return service.handle(request, audit=ledger.append)

    try:
        return serve_forever(
            path=socket_path(SOCKET_NAME), registry=REGISTRY,
            policy=PrincipalPolicy.resolve(service_accounts=("azmioentry",)),
            audit=ledger.append,
            handler=handle,
            stop=poll, ready=ready if ready is not None else runtime_ready_callback(),
        )
    finally:
        for server in handles:
            server.stop()
        admissions.close()


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
