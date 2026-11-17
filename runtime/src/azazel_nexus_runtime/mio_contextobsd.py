"""Model-free observation-origin Knowledge Context service (B5, #439).

`azazel-mio-contextobsd.service` answers one verb, `mio.contextobs.observe`,
for the entry service alone. It takes the explainer's observation-origin
frame (relayed by entry as `mio.context.observe`), asks the Knowledge
Context broker (`azazel-knowledge-contextd.service`) about the frame's 1 to
8 ATT&CK technique ids, and re-runs the fast core as for an unavailable Full
lookup, with the technique record beside its result.

Why it is its own unit (docs/adr/0010-context-observation-unit.md): the
broker is the one component that may reach the network, and the account that
may ask it must hold nothing else. Before this unit that account was `azmio`,
the model host, which is not grantable. Now it is `azmioctx`, which:

* **runs no model.** It imports no model runtime, model host, admission
  evidence, embedding, Mission Pack or Knowledge Lite client module, holds no
  model or mission path and starts no process
  (`tests/unit/test_mio_contextobsd.py`). The frame reader it imports on a
  request (`incident_explain`, as entryd does) reaches the `model_admission`
  library through `activation`; that grants and starts nothing.
* **reaches nothing but two sockets.** AF_UNIX only, no network namespace,
  and its one client group is `azknowledge-context-client`.
* **writes no record of a request.** The handler appends nothing; the ledger
  holds only the socket layer's refusals, as locald's ledger did for the verb
  this replaces.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable, Sequence
from typing import Any

from azazel_nexus.audit import AuditLedger, AuditUnavailable
from azazel_nexus.local_advisory import FrameRefused, read_frame
from azazel_nexus.sanitizer import PrivacyClass
from azazel_nexus.technique_knowledge import (
    TechniqueVerificationFailed, not_run_projection, project_technique_response, request_ids,
)

from .knowledge_context_socket import (
    FullNodeContextStatus, KnowledgeContextUnavailable, request_context,
)
from .mio_fast_degraded import fast_assessment_degraded
from .principal import PrincipalClass, PrincipalPolicy
from .protocol import Argument, ArgumentKind, Verb, VerbRegistry
from .runtime_paths import mio_contextobs_state_dir, socket_path
from .serve import serve_forever
from .systemd_notify import runtime_ready_callback

__all__ = [
    "ACCOUNT",
    "CONTEXT_OBSERVE_DEADLINE_MAX_MS",
    "CONTEXT_OBSERVE_VERB",
    "REGISTRY",
    "SOCKET_NAME",
    "ContextObservationService",
    "main",
    "observation_technique_ids",
]

SOCKET_NAME = "mio-contextobs"
#: Its own non-login account: never the model host's (`azmio`), never the
#: entry's (`azmioentry`) and never the reference service's (`azmioref`).
#: The only SERVICE principal the Knowledge Context broker admits.
ACCOUNT = "azmioctx"
#: The only caller.
ENTRY_ACCOUNT = "azmioentry"
#: The T1 policy ceiling (350 ms); 0 is refused in the handler.
CONTEXT_OBSERVE_DEADLINE_MAX_MS = 350
CONTEXT_OBSERVE_VERB = Verb(
    name="mio.contextobs.observe",
    arguments=(Argument("deadline_ms", ArgumentKind.ORDINAL,
                        maximum=CONTEXT_OBSERVE_DEADLINE_MAX_MS),),
    admits=frozenset({PrincipalClass.SERVICE}), accepts_payload=True,
    payload_contract="azazel_nexus.local_advisory.read_frame",
)
REGISTRY = VerbRegistry([CONTEXT_OBSERVE_VERB])

#: The same reserves the model host used for this verb, so the timing a
#: caller measures does not move with the unit.
DELIVERY_RESERVE_S = 0.02
KNOWLEDGE_MAX_S = 0.25
FAST_CORE_RESERVE_S = 0.025

def _refusal_projection(stage) -> dict:
    """The record of a refused or failed technique query, from the broker's stage word."""
    transport, verification = {
        "refused_before_send": ("refused", "not_run"),
        "transport": ("unavailable", "not_run"),
        "verification": ("refused", "failed"),
        "technique_verification": ("received", "failed"),
        # Answered and verified, then discarded because the grant was withdrawn
        # before adoption: received, and not accepted. The stored pairs have no
        # "received, not adopted", so it is recorded with the failed ones; the
        # broker ledger keeps reason_code=withdrawn to tell them apart.
        "withdrawn": ("received", "failed"),
    }.get(stage, ("unavailable", "not_run"))
    return not_run_projection(transport, verification)


def observation_technique_ids(ids) -> list[str]:
    """The sorted, unique ids of the observation-origin technique query (1 to 8)."""
    try:
        return request_ids(sorted(set(ids)))
    except (TypeError, ValueError):
        raise ValueError("invalid_technique_set") from None


class ContextObservationService:
    """Query Full Node Context for an observed technique set, then re-run the core."""

    def __init__(self, *, context: Callable[..., Any] | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        # Looked up at call time by default, so a test may replace the
        # module's `request_context`.
        self._context = context
        self._clock = clock

    def handle(self, request: Any) -> dict:
        """Nothing is written to the ledger and no generation is submitted.

        The only thing sent to the broker is a P0 frame of `{privacy_class,
        techniques}` whose techniques are 1 to 8 technique codes. The answer
        never reaches M.I.O.: it is validated and projected into
        `technique_knowledge`, and the core runs as it does when Full Node
        Context is unavailable. `timing` has fixed keys (ints in ms, no
        incident data, and the fixed word `core`) so the success, delay and
        refusal cases can be measured.

        The broker's outcome and the core's are reported apart: the
        technique record rides on the result whether or not the core ran, and
        `timing.core` says which (`ran`, or `failed` when the core raised and
        the result is the fixed degraded payload).
        """
        if getattr(getattr(request, "verb", None), "name", None) != CONTEXT_OBSERVE_VERB.name:
            return {"outcome": "failed", "refusal": "unknown_verb"}
        started = self._clock()
        budget_ms = request.arguments["deadline_ms"]
        if type(budget_ms) is not int or not 0 < budget_ms <= CONTEXT_OBSERVE_DEADLINE_MAX_MS:
            return {"outcome": "failed", "refusal": "deadline"}
        deadline = started + budget_ms / 1000
        try:
            from azazel_nexus.incident_explain import read_fast_transition
            frame = read_frame(request.payload)
            transition = read_fast_transition(frame)
            if (transition is None
                    or frame["privacy_class"] != PrivacyClass.P3_RESTRICTED.value):
                raise ValueError("fast_transition_refused")
            technique_ids_asked = observation_technique_ids(transition["technique_ids"])
            query = {"privacy_class": PrivacyClass.P0_PUBLIC.value,
                     "techniques": technique_ids_asked}
        except (FrameRefused, ValueError):
            return {"outcome": "failed", "refusal": "malformed_frame"}
        technique_knowledge = not_run_projection("unavailable", "not_run")
        broker_started = self._clock()
        context = self._context or request_context
        try:
            budget = deadline - broker_started - DELIVERY_RESERVE_S - FAST_CORE_RESERVE_S
            if budget > 0:
                try:
                    technique_knowledge = project_technique_response(
                        context(query, deadline_s=min(KNOWLEDGE_MAX_S, budget)),
                        technique_ids_asked)
                except TechniqueVerificationFailed:
                    technique_knowledge = not_run_projection("received", "failed")
        except KnowledgeContextUnavailable as exc:
            technique_knowledge = _refusal_projection(getattr(exc, "stage", None))
        except Exception:  # noqa: BLE001 - any failure is an unavailable Full lookup
            technique_knowledge = not_run_projection("unavailable", "not_run")
        # The technique answer is never handed to M.I.O.: the core is run as for
        # an unavailable Full lookup, and the record rides next to its result.
        context_status = FullNodeContextStatus.UNAVAILABLE
        broker_ms = int((self._clock() - broker_started) * 1000)
        try:
            from .mio_fast_assistance import _frame, fast_assistance
            situation, _ = _frame(frame, with_selection=True)
            result = fast_assistance(
                frame, deadline_s=max(0.0, deadline - self._clock() - DELIVERY_RESERVE_S),
                knowledge_lookup=None, knowledge_max_s=KNOWLEDGE_MAX_S,
                core_reserve_s=FAST_CORE_RESERVE_S, situation_frame=situation,
                fabric_knowledge_context_response=None,
                full_node_context_status=context_status)
            core = "ran"
        except Exception:  # noqa: BLE001
            # The broker's answer is not lost with the core: the degraded payload
            # carries the same record, beside the status the reader requires.
            result = fast_assessment_degraded("unavailable")
            result["full_node_context_status"] = context_status.value
            core = "failed"
        result["technique_knowledge"] = technique_knowledge
        return {"outcome": "context_observed", "fast_assistance": result,
                "timing": {"context": technique_knowledge["transport"], "broker_ms": broker_ms,
                           "total_ms": int((self._clock() - started) * 1000), "core": core}}


def main(
    argv: Sequence[str] | None = None,
    *,
    stop: Callable[[], bool] = lambda: False,
    ready: Callable[[], None] | None = None,
) -> int:
    """Serve. Takes no arguments: who may ask and what is asked are fixed here."""

    if argv is None:
        argv = sys.argv[1:]
    if argv:
        raise SystemExit(
            "az-mio-contextobsd takes no arguments. Its caller, its broker and "
            "the shape of what it asks are fixed by this package"
        )
    ledger = AuditLedger(mio_contextobs_state_dir() / "contextobs.jsonl")
    try:
        ledger.verify()
        with ledger.path.open("a", encoding="utf-8"):
            pass
    except OSError as error:
        raise AuditUnavailable("M.I.O. context observation ledger unavailable") from error
    # Paid before READY, not inside the first request's 350 ms.
    try:
        from . import mio_fast_assistance as _mio_fast_assistance  # noqa: F401
    except Exception:  # noqa: BLE001 - the shared package is optional
        pass
    service = ContextObservationService()
    return serve_forever(
        path=socket_path(SOCKET_NAME), registry=REGISTRY,
        # The socket's own group; the entry account is the one SERVICE
        # principal, so a member of the group who is not entry (or root)
        # holds no class that reaches the verb.
        # Literal, as at every daemon (the explainer-privilege scan reads it):
        # the socket's own group (`socket_group(SOCKET_NAME)`) and ENTRY_ACCOUNT.
        policy=PrincipalPolicy.resolve(operator_group="azmio-contextobs",
                                       service_accounts=("azmioentry",)),
        audit=ledger.append, handler=service.handle, stop=stop,
        ready=ready if ready is not None else runtime_ready_callback(),
    )


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
