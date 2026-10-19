"""Read-only historical entryd capability evidence; never provider admission."""

import json
import os
from datetime import datetime
from pathlib import Path

from .audit import AuditLedger
from .capability import CapabilityState
from .edge_package import Evidence

NOTICE = "The recorded ceiling is not a grant or admission; provider admission remains closed."
# CORE-side copies, pinned to runtime mio_capability enums by unit tests.
RESOURCE_REASONS = frozenset({"core_reserve_unmeasured"})
TOPOLOGY_REASONS = frozenset({"no_verified_egress"})
HEALTH_REASONS = frozenset({"unavailable", "not_admitted", "no_admission_evidence", "invalid_observation"})
UNKNOWN = ("unknown (route ledger not readable by this user, missing, or verification refused; "
           "entryd credentials are not read)")
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
        levels = {state.value for state in CapabilityState}
        if (event["to"] not in levels or type(reasons) is not dict
                or set(reasons) != {"profile", "resource", "trust", "health", "topology"}
                or reasons["profile"] not in levels
                or reasons["resource"] not in RESOURCE_REASONS
                or reasons["trust"] not in {value.value for value in Evidence}
                or reasons["topology"] not in TOPOLOGY_REASONS
                or type(reasons["health"]) is not dict
                or set(reasons["health"]) != {"local", "remote"}
                or any(value not in HEALTH_REASONS for value in reasons["health"].values())):
            raise ValueError("invalid transition")
        # Never echo the raw timestamp: fromisoformat accepts arbitrary date/time
        # separators, including control characters. isoformat emits a safe form.
        observed_at = datetime.fromisoformat(event["occurred_at"]).isoformat()
        result.update(ceiling=reasons["profile"], state=event["to"], reasons=reasons,
                      observed_at=observed_at, availability="last recorded observation")
    except Exception:  # noqa: BLE001 - no paths, identities or raw exceptions in diagnostics
        result["availability"] = UNKNOWN
    return result


def describe(reading):
    return ("M.I.O.: recorded ceiling: " + (reading["ceiling"] or "unknown")
            + "; capability state: " + (reading["state"] or "unknown")
            + "; source: entryd route ledger; " + reading["availability"]
            + ("; observed at: " + str(reading["observed_at"]) if reading["state"] else "")
            + ("; reasons: " + json.dumps(reading["reasons"], sort_keys=True) if reading["reasons"] else "")
            + ". " + NOTICE)
