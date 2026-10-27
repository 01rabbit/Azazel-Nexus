"""Model-free playbook reference service for the deterministic handoff.

`azazel-mio-referenced.service` answers one verb, `mio.reference`, from the
verified reasoning playbooks of the active Mission Pack. It exists so that a
node with no admitted model -- every CORE node, and every node while model
admission is closed -- can still hand an operator the reviewed playbook text
when no AI answers.

What it is not, by construction:

* **Not a model host.** It imports no runtime, admission, embedding, serving
  or Knowledge module, holds no model path and starts no process. Model
  execution stays with `azazel-mio-locald.service`, which keeps its own
  `local_model_provider` wiring gate and its own admission; nothing here
  reads, satisfies or relaxes either (`tests/unit/test_mio_referenced.py`).
* **Not an answer.** The reply is a reference: keyword-matched, deterministic,
  `provenance.source == "keyword"`, `model_id == "deterministic"`, and it
  carries a fixed banner instead of advice (`local_advisory.read_reference`).
  The entry service revalidates it and labels it as a reference.
* **Not an authority.** It reads verified prose and returns it. It decides
  nothing Edge's deterministic control plane decides, and its absence removes
  only the reference, never the handoff.

When nothing can be referenced it says why, with a fixed reason word, so the
operator sees the missing reason next to the fixed handoff notice.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable, Sequence
from typing import Any

from azazel_nexus.audit import AuditLedger, AuditUnavailable
from azazel_nexus.local_advisory import (
    FrameRefused,
    build_options,
    delivered_document,
    gate_frame,
    read_frame,
    read_reference,
    retrieval_decision,
)
from azazel_nexus.reasoning_playbook import Library, match

from .mio_playbooks import PlaybookSelectionHolder
from .principal import PrincipalClass, PrincipalPolicy
from .protocol import Argument, ArgumentKind, Verb, VerbRegistry
from .runtime_paths import (
    mio_reference_state_dir,
    mission_pack_config,
    mission_pack_root,
    socket_path,
)
from .serve import serve_forever
from .systemd_notify import runtime_ready_callback

__all__ = [
    "ACCOUNT",
    "REFERENCE_DEADLINE_MS",
    "REFERENCE_REASONS",
    "REFERENCE_VERB",
    "REGISTRY",
    "SOCKET_NAME",
    "ReferenceService",
    "main",
]

SOCKET_NAME = "mio-reference"
#: Its own non-login account: never the model host's (`azmio`) and never the
#: entry's (`azmioentry`), so a fault here runs with neither's access.
ACCOUNT = "azmioref"
#: A ceiling the caller cannot extend; the entry passes what is left of the
#: request's one deadline, capped by this.
REFERENCE_DEADLINE_MS = 500
#: Kept back for validating and delivering the reference document.
DELIVERY_RESERVE_S = 0.02
REFERENCE_VERB = Verb(
    name="mio.reference",
    arguments=(Argument("deadline_ms", ArgumentKind.ORDINAL, maximum=REFERENCE_DEADLINE_MS),),
    admits=frozenset({PrincipalClass.SERVICE}),
    accepts_payload=True,
    payload_contract="azazel_nexus.local_advisory.read_frame",
)
REGISTRY = VerbRegistry([REFERENCE_VERB])

#: Every reason a reference can be missing. Fixed words, never situation data.
#: The playbook-selection words are `PlaybookSelection.reason` values.
REFERENCE_REASONS = frozenset({
    # Playbook selection (`playbook_selection.active_playbooks`, holder).
    "no_pack", "store_unreadable", "pack_degraded", "asset_missing",
    "digest_mismatch", "invalid_library", "none_selected", "multiple_baselines",
    # The request.
    "malformed_frame", "out_of_scope", "insufficient_information",
    "no_matching_playbook", "invalid_deadline", "deadline",
    # Seen by the entry rather than by this service.
    "reference_service_unavailable", "reference_refused",
})


def _unavailable(reason: str) -> dict:
    if reason not in REFERENCE_REASONS:
        reason = "pack_degraded"
    return {"outcome": "unavailable", "reason": reason}


class ReferenceService:
    """Build a reference from verified playbooks; nothing else is reachable."""

    def __init__(self, *, playbooks: Library | None = None, selection_reason: str = "no_pack",
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._playbooks = playbooks
        self._selection_reason = selection_reason
        self._clock = clock

    def set_playbooks(self, library: Library | None, reason: str) -> None:
        self._playbooks = library
        self._selection_reason = reason

    def handle(self, request: Any) -> dict:
        began = self._clock()
        deadline_ms = request.arguments["deadline_ms"]
        if type(deadline_ms) is not int or not 0 < deadline_ms <= REFERENCE_DEADLINE_MS:
            return _unavailable("invalid_deadline")
        end = began + deadline_ms / 1000
        try:
            frame = read_frame(request.payload)
        except FrameRefused:
            return _unavailable("malformed_frame")
        if self._playbooks is None:
            return _unavailable(self._selection_reason)
        try:
            gated = gate_frame(frame)
            if gated is not None:
                return _unavailable(gated["reason"])
            books = match(frame, self._playbooks)
            if not books:
                return _unavailable("no_matching_playbook")
            if self._clock() >= end - DELIVERY_RESERVE_S:
                return _unavailable("deadline")
            options = build_options(frame, books)
            candidate, state, support, record = retrieval_decision(frame, books, ())
            body = delivered_document(
                frame, books, options, candidate, options, None, "deterministic",
                state=state, benign_evidence=support, system_record=record,
                provenance="keyword",
            )
            document = read_reference({"banner": body.pop("advice"), **body})
        except (FrameRefused, ValueError):
            return _unavailable("pack_degraded")
        if self._clock() >= end - DELIVERY_RESERVE_S:
            return _unavailable("deadline")
        return {"outcome": "reference", "reference": document}


def main(
    argv: Sequence[str] | None = None,
    *,
    stop: Callable[[], bool] = lambda: False,
    ready: Callable[[], None] | None = None,
) -> int:
    """Serve. Takes no arguments; which playbooks exist is commissioned state."""

    if argv is None:
        argv = sys.argv[1:]
    if argv:
        raise SystemExit(
            "az-mio-referenced takes no arguments. Which playbooks it may "
            "reference is the verified Mission Pack, not a command line"
        )
    ledger = AuditLedger(mio_reference_state_dir() / "reference.jsonl")
    try:
        ledger.verify()
        with ledger.path.open("a", encoding="utf-8"):
            pass
    except OSError as error:
        raise AuditUnavailable("M.I.O. reference ledger unavailable") from error
    selection = PlaybookSelectionHolder(config=mission_pack_config(), root=mission_pack_root())
    service = ReferenceService()

    def refresh() -> None:
        library = selection.refresh(audit=ledger.append)
        service.set_playbooks(library, selection.selection.reason)

    refresh()

    def handle(request):
        refresh()
        reply = service.handle(request)
        # Only the outcome and the fixed reason; never the frame or the text.
        ledger.append({"event_type": "mio.reference.reply", "outcome": reply["outcome"],
                       "reason": reply.get("reason")})
        return reply

    return serve_forever(
        path=socket_path(SOCKET_NAME), registry=REGISTRY,
        policy=PrincipalPolicy.resolve(service_accounts=("azmioentry",)),
        audit=ledger.append, handler=handle, stop=stop,
        ready=ready if ready is not None else runtime_ready_callback(),
    )


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
