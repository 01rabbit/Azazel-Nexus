"""auditd's operator-readable capacity snapshot (#211); reader and health line.

`azazel-nexus status` does not talk to auditd's socket and cannot read the
`0700` ledger. auditd therefore writes a small, closed-shape snapshot into its
own `2750 azaudit:azazel-operator` leaf (`run/audit-status/status.json`), the
same pattern as the intake and explainer liveness snapshots. It carries sizes,
counts and fixed reason codes only: no record content, no uid, no incident id.

The reader here is pure and refuses anything outside the declared shape, so a
damaged or foreign file is shown as "refused", never as health. Freshness is
the caller's: a snapshot older than `STATUS_STALE_S` describes an auditd that
may no longer be running.
"""

from __future__ import annotations

import json
import math
import re

STATUS_SCHEMA = "azazel-nexus/audit-status/v1"
#: The file never legitimately reaches this; anything larger is refused.
STATUS_BYTES = 8192
#: auditd writes the snapshot at start and then this often; a capacity
#: warning turning on or off therefore reaches status within one interval.
STATUS_INTERVAL_S = 60
#: Five missed rewrites: older than this, auditd is not known to be running.
STATUS_STALE_S = 300
#: A snapshot dated this far after the reader's clock is not believed either.
STATUS_FUTURE_S = 5
#: Fixed reason codes for `warning_reasons`, in this order.
WARNING_REASONS = ("chain_size", "filesystem_free")
#: The most `rate_limited` keys a snapshot carries; auditd keeps the largest.
RATE_LIMITED_KEYS = 48
_RATE_KEY = re.compile(r"(?:daily|rate):[a-z][a-z0-9_.]{0,63}:(?:ordinary|service|severe)")
_KEYS = ("schema", "written_at", "chain_verified", "chain_bytes", "segments",
         "filesystem_free_bytes", "warning", "warning_reasons", "warn_chain_bytes",
         "warn_free_bytes", "rate_limited", "rate_limit_summaries_dropped")
_MAX = 2**63 - 1


def warning_reasons(chain_bytes, free_bytes, warn_chain_bytes, warn_free_bytes) -> list:
    """The reason codes a capacity reading implies; writer and reader share it."""

    reasons = []
    if chain_bytes >= warn_chain_bytes:
        reasons.append("chain_size")
    if free_bytes is not None and free_bytes < warn_free_bytes:
        reasons.append("filesystem_free")
    return reasons


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _int(value, maximum=_MAX):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("integer")


def read_audit_status(raw) -> dict | None:
    """Decode the snapshot, or `None` for anything outside its closed shape."""

    try:
        if type(raw) is not bytes or len(raw) > STATUS_BYTES:
            return None
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
        if type(value) is not dict or set(value) != set(_KEYS):
            return None
        if value["schema"] != STATUS_SCHEMA:
            return None
        at = value["written_at"]
        if type(at) not in (int, float) or not math.isfinite(at) or at < 0:
            return None
        for key in ("chain_verified", "warning"):
            if type(value[key]) is not bool:
                return None
        for key in ("chain_bytes", "segments", "warn_chain_bytes", "warn_free_bytes",
                    "rate_limit_summaries_dropped"):
            _int(value[key])
        if value["filesystem_free_bytes"] is not None:
            _int(value["filesystem_free_bytes"])
        # The reasons must be exactly what the numbers imply, so a snapshot
        # cannot say "no warning" next to a chain over its own threshold.
        implied = warning_reasons(value["chain_bytes"], value["filesystem_free_bytes"],
                                  value["warn_chain_bytes"], value["warn_free_bytes"])
        if value["warning_reasons"] != implied or value["warning"] is not bool(implied):
            return None
        limited = value["rate_limited"]
        if type(limited) is not dict or len(limited) > RATE_LIMITED_KEYS:
            return None
        for key, count in limited.items():
            if not _RATE_KEY.fullmatch(key):
                return None
            _int(count)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        return None


def _size(value) -> str:
    for unit, scale in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if value >= scale:
            return f"{value / scale:.1f} {unit}"
    return f"{value} B"


def audit_health(value, now) -> tuple:
    """`(healthy, detail, advisory)` for the status `audit` line.

    `healthy` is `None` when nothing current is known (no snapshot, a refused
    one, a stale one, or no clock), `False` only when the chain did not verify
    at auditd's start, `True` otherwise. A capacity warning is **not** a
    failure: the line stays `ok`, its detail starts with `WARNING:`, and
    `advisory` carries it to the next actions. A warning never deletes
    anything; both say so, because the obvious reaction to "disk filling" is
    the one this node refuses to take on the owner's behalf.
    """

    if value is None:
        return None, ("no readable auditd status snapshot (auditd not running, "
                      "install.sh not re-run since the upgrade, or this user cannot read "
                      "run/audit-status: that needs the azazel-operator group); audit "
                      "capacity unknown; audit ledger not inspected"), None
    free = value["filesystem_free_bytes"]
    facts = (f"chain {_size(value['chain_bytes'])} in {value['segments']} segment(s); "
             + ("filesystem free unknown" if free is None else f"{_size(free)} free on its filesystem")
             + f"; warns at >= {_size(value['warn_chain_bytes'])} chain or "
             f"< {_size(value['warn_free_bytes'])} free")
    if value["warning"]:
        facts += "; capacity warning (" + ", ".join(value["warning_reasons"]) + ")"
    total = sum(value["rate_limited"].values())
    top = sorted(value["rate_limited"].items(), key=lambda kv: (-kv[1], kv[0]))[:3]
    limited = ("rate_limited: none" if not total else
               f"rate_limited: {total} (" + ", ".join(f"{k}={v}" for k, v in top) + ")")
    if value["rate_limit_summaries_dropped"]:
        limited += f"; summaries dropped: {value['rate_limit_summaries_dropped']}"
    if type(now) not in (int, float):
        return None, f"current time unknown, so snapshot age unknown; last snapshot: {facts}", None
    age = now - value["written_at"]
    if age > STATUS_STALE_S or age < -STATUS_FUTURE_S:
        when = (f"written {int(age)}s ago" if age > 0 else "dated in the future")
        return None, (f"auditd status snapshot is stale ({when}; auditd rewrites it every "
                      f"{STATUS_INTERVAL_S}s while running); last snapshot: {facts}"), None
    tail = f"{facts}; {limited} (snapshot {max(0, int(age))}s old)"
    advisory = None
    if value["warning"]:
        advisory = ("capacity warning (" + ", ".join(value["warning_reasons"]) + "): "
                    "nothing is deleted (retention policy: never delete, warn only); "
                    "see docs/operations.md (Audit chain retention)")
    if not value["chain_verified"]:
        return False, ("chain did not verify at auditd start; appends are refused; "
                       "inspect with audit.verify; " + tail), advisory
    if advisory:
        return True, ("WARNING: " + advisory + "; chain verified at auditd start; "
                      + tail), advisory
    return True, "chain verified at auditd start; " + tail, None
