"""Read-only historical entryd capability evidence; never provider admission."""

import json
import os
from pathlib import Path

from .audit import AuditLedger

NOTICE = "The commissioned ceiling is not a grant or admission; provider admission remains closed."
ROUTE_LEDGER = "/var/lib/azazel/state/mio/route.jsonl"


class _Snapshot(AuditLedger):
    def __init__(self, entries):
        self.entries = entries

    def __iter__(self):
        return iter(self.entries)


def status_summary(*, root=None):
    root = Path(os.environ.get("AZAZEL_ROOT", "/")) if root is None else Path(root)
    result = {"ceiling": None, "state": None, "reasons": {}, "source": "route-ledger",
              "observed_at": None, "notice": NOTICE}
    try:
        path = root / ROUTE_LEDGER.lstrip("/")
        # AuditLedger treats a missing file as an empty chain. Distinguish it here.
        path.stat()
        entries = tuple(AuditLedger(path))
        _Snapshot(entries).verify()
        transitions = [entry.event for entry in entries
                       if entry.event.get("event_type") == "mio.capability.transition"]
        if not transitions:
            result["availability"] = "unknown (no recorded capability transition)"
            return result
        event = transitions[-1]
        reasons = event["reasons"]
        if (event["to"] not in {"CORE", "LITE", "FULL"} or type(reasons) is not dict
                or reasons.get("profile") not in {"CORE", "LITE", "FULL"}):
            raise ValueError("invalid transition")
        result.update(ceiling=reasons["profile"], state=event["to"], reasons=reasons,
                      observed_at=event.get("occurred_at"), availability="last recorded observation")
    except Exception:  # noqa: BLE001 - no paths, identities or raw exceptions in diagnostics
        result["availability"] = "unknown (route ledger unreadable or verification refused)"
    return result


def describe(reading):
    return ("M.I.O.: commissioned ceiling: " + (reading["ceiling"] or "unknown")
            + "; capability state: " + (reading["state"] or "unknown")
            + "; " + reading["availability"]
            + ("; observed at: " + str(reading["observed_at"]) if reading["state"] else "")
            + ("; reasons: " + json.dumps(reading["reasons"], sort_keys=True) if reading["reasons"] else "")
            + ". " + NOTICE)
