"""Read-only historical entryd capability evidence; never provider admission."""

import json
import os
from datetime import datetime
from pathlib import Path

from .audit import AuditLedger
from .capability import CapabilityState
from .edge_package import Evidence
from .route_ledger import LEGACY, ROUTE_DIR, RouteChain

NOTICE = "The recorded ceiling is not a grant or admission; provider admission remains closed."
# CORE-side copies, pinned to runtime mio_capability enums by unit tests.
RESOURCE_REASONS = frozenset({"core_reserve_unmeasured"})
TOPOLOGY_REASONS = frozenset({"no_verified_egress"})
HEALTH_REASONS = frozenset({"unavailable", "not_admitted", "no_admission_evidence", "invalid_observation"})
UNKNOWN = ("unknown (route ledger not readable by this user, missing, or verification refused; "
           "entryd credentials are not read)")
#: The pre-segment single file, read only until entryd migrates it (#211 S4).
ROUTE_LEDGER = LEGACY
#: entryd's daily route segments, read whenever the directory exists.
ROUTE_SEGMENTS = ROUTE_DIR
CAPABILITY_EVENTS = frozenset({"mio.capability.transition", "mio.capability.carried"})


def _last_capability(root):
    """Verify the retained chain once, keeping only the newest capability record."""
    found = []

    def visit(entry):
        if entry.event.get("event_type") in CAPABILITY_EVENTS:
            found[:] = [entry.event]

    directory = root / ROUTE_SEGMENTS.lstrip("/")
    if directory.is_dir():
        RouteChain(directory).verify(visit)
    else:
        path = root / ROUTE_LEDGER.lstrip("/")
        # AuditLedger treats a missing file as an empty chain. Distinguish it here.
        path.stat()
        ledger = AuditLedger(path)
        ledger.verify()
        for entry in ledger:
            visit(entry)
    return found[0] if found else None


def status_summary(*, root=None):
    root = Path(os.environ.get("AZAZEL_ROOT", "/")) if root is None else Path(root)
    result = {"ceiling": None, "state": None, "reasons": {}, "source": "route-ledger",
              "observed_at": None, "notice": NOTICE}
    try:
        event = _last_capability(root)
        if event is None:
            result["availability"] = "unknown (no recorded capability transition)"
            return result
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
