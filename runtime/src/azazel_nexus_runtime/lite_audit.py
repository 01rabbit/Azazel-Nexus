"""Knowledge Lite import and revocation records, appended to `az-auditd`.

The two daemons that change Knowledge Lite state record each transition in
the production audit chain: `az-knowledge-lited` for an import (as
`azknowledge`) and `az-commissiond` for an accepted revocation (as
`azcommission`). Both reach auditd only through its append-only `audit-submit`
listener (group `azaudit-submit`), which serves `audit.append` and nothing
else; auditd binds each event type to its one writer account
(`auditd.BOUND_WRITERS`).

What is recorded: entry ids, digests, generations, counts and fixed codes.
Never a claim body, key material, a path or exception text.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from azazel_nexus.lite_import import Transition

__all__ = [
    "AUDIT_DEADLINE_S",
    "ImportAudit",
    "append_event",
    "import_event",
]

#: The same bound the explainer gives its own appends.
AUDIT_DEADLINE_S = 2


def append_event(event: Mapping) -> None:
    """One typed append; raises on anything but auditd's receipt."""

    from .bootstrap_audit_client import AuditAppendReceipt
    from .mio_socket_client import _exchange

    result = _exchange(
        "audit-submit", "azaudit", "audit.append", {"event_type": event["event_type"]},
        payload={key: value for key, value in event.items() if key != "event_type"},
        deadline_s=AUDIT_DEADLINE_S)
    if set(result) != {"sequence", "event_hash"}:
        raise ValueError("audit_receipt_refused")
    AuditAppendReceipt(**result)


def import_event(transition: Transition, event: Mapping) -> dict:
    """The auditd record for one `LiteImport` transition, field by field."""

    common = {"entry_id": event["entry_id"], "occurred_at": event["at"]}
    if transition is Transition.IMPORT_STARTED:
        return {"event_type": "knowledge.lite.import_started", **common}
    if transition is Transition.STORE_TIGHTENED:
        return {"event_type": "knowledge.lite.import_store_tightened", **common,
                "directories": len(event["directories"])}
    if transition is Transition.STATE_UNTRUSTED:
        return {"event_type": "knowledge.lite.import_refused", **common,
                "code": "state_untrusted"}
    if transition is Transition.REFUSED:
        return {"event_type": "knowledge.lite.import_refused", **common,
                "code": event["code"]}
    if transition is Transition.QUARANTINED:
        return {"event_type": "knowledge.lite.import_quarantined", **common,
                "bundle_digest": event["bundle_digest"], "gate": event["gate"],
                "code": event["code"]}
    if transition is Transition.ADMITTED:
        return {"event_type": "knowledge.lite.import_admitted", **common,
                "bundle_digest": event["bundle_digest"],
                "bundle_version": event["bundle_version"], "served": event["served"],
                "withheld": event["withheld"], "static_reference": event["static_reference"]}
    raise ValueError("an import does not record this transition")


class ImportAudit:
    """A `LiteImport` recorder that makes the start of an import durable first.

    The start is appended before anything is tightened, verified or moved, and
    a failure there propagates: the import does not begin without its record.
    A later record that fails cannot undo what already happened, so it is
    counted (`complete` turns False) and the caller reports it.
    """

    def __init__(self, append: Callable[[Mapping], None] = append_event) -> None:
        self.append = append
        self.complete = True
        #: Whether the start record is durable, i.e. the import may have
        #: changed the store from here on.
        self.started = False

    def __call__(self, transition: Transition, event: Mapping) -> None:
        record = import_event(transition, event)
        if transition is Transition.IMPORT_STARTED:
            self.append(record)
            self.started = True
            return
        try:
            self.append(record)
        except Exception:  # noqa: BLE001 - reported as an incomplete audit
            self.complete = False
