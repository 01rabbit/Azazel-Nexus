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


def _observed(event):
    """When a reading was observed: a carried record keeps the original time."""
    if event.get("event_type") == "mio.capability.carried":
        return event["observed_at"]
    return event["occurred_at"]


def _recorded(event):
    """When entryd wrote the record: evidence that it was alive then (#358).

    For a transition this is the observation time; for the carried record
    that opens a daily segment it is the day's write, later than the
    observation it repeats. Only a time with a zone is returned, in
    `isoformat`'s safe form; anything else is `None` (the reader then falls
    back to `observed_at`, never to a fresher time).
    """
    try:
        when = datetime.fromisoformat(event["occurred_at"])
    except (KeyError, TypeError, ValueError):
        return None
    return when.isoformat() if when.tzinfo is not None else None


def _last_capability(root):
    """Verify the retained chain once, keeping only the newest capability record."""
    found = []

    def visit(entry):
        event = entry.event
        kind = event.get("event_type")
        if kind not in CAPABILITY_EVENTS:
            return
        # A carried record repeats the reading before it, with that reading's
        # own observation time; one that differs is refused.
        if kind == "mio.capability.carried" and found and (
                found[0]["to"], found[0]["reasons"], _observed(found[0])) != (
                event.get("to"), event.get("reasons"), event.get("observed_at")):
            raise ValueError("carried record differs from the reading it carries")
        found[:] = [event]

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
              "observed_at": None, "recorded_at": None, "notice": NOTICE}
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
        observed_at = datetime.fromisoformat(_observed(event)).isoformat()
        result.update(ceiling=reasons["profile"], state=event["to"], reasons=reasons,
                      observed_at=observed_at, availability="last recorded observation",
                      recorded_at=_recorded(event))
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
