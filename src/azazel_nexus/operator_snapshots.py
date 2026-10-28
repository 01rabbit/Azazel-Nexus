"""Operator-readable snapshots for status and the read-only UI (U2).

`azazel-nexus status` runs as an operator, and the UI will run as its own
unprivileged account. Neither may read Knowledge Lite's commissioned trust
(`2750 azcommission:azknowledge`), entryd's route ledger (`0700
azmioentry`), or ask systemd through a daemon's socket. So each source writes
a small, closed-shape snapshot into its own operator-readable leaf, the same
pattern as auditd's capacity snapshot (#211, `audit_status`):

| Snapshot | Writer | Leaf (`install.sh`) |
| --- | --- | --- |
| `knowledge-status/v1` | `az-knowledge-lited` | `2750 azknowledge:azazel-operator` |
| `mio-status/v1` | `az-mio-entryd` | `2750 azmioentry:azazel-operator` |
| `units-status/v1` | `az-units-observe` (oneshot, timer) | `2750 azprobe:azazel-operator` |

Writer and reader share the builders and readers here, so a writer cannot
put a shape on disk that the reader would refuse, and the reader refuses
anything else: a foreign schema, a missing or extra key, a duplicate key, a
value outside the fixed vocabulary, an oversized file. A refused snapshot is
shown as refused, never as health. Freshness is the reader's: every snapshot
carries `written_at` (wall-clock seconds), and one older than its
`*_STALE_S`, or dated more than `FUTURE_S` ahead, says nothing about now.

Nothing here decides anything. A snapshot repeats what its writer already
reports on its own socket or ledger, as fixed codes and counts: no path, no
key, no digest, no interface identity, no exception text.

**Extending a snapshot.** A field is added by adding it to the builder and
the reader together and bumping the schema (`.../v2`); the reader then
accepts exactly the versions it lists. Knowledge Lite's signer, digest and
expiry fields (P2) are not in `knowledge.status` yet and therefore not here.

Storage space needs no snapshot: `statvfs` of a directory needs only search
permission on its parents, which every account has under the `0711` layout,
so `read_storage` measures it at read time under fixed labels and never
reports a path.
"""

from __future__ import annotations

import json
import math
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

__all__ = [
    "FUTURE_S",
    "KNOWLEDGE_SCHEMA",
    "MIO_SCHEMA",
    "OBSERVED_UNITS",
    "STORAGE_LOCATIONS",
    "UNITS_SCHEMA",
    "freshness",
    "knowledge_snapshot",
    "mio_snapshot",
    "read_knowledge_status",
    "read_mio_status",
    "read_storage",
    "read_units_status",
    "units_snapshot",
]

#: A snapshot dated this far after the reader's clock is not believed.
FUTURE_S = 5
_MAX = 2**63 - 1

# -- shared strict decoding -------------------------------------------------


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _decode(raw, limit: int, keys: tuple, schema: str) -> dict:
    if type(raw) is not bytes or len(raw) > limit:
        raise ValueError("size")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
    if type(value) is not dict or set(value) != set(keys) or value["schema"] != schema:
        raise ValueError("shape")
    at = value["written_at"]
    if type(at) not in (int, float) or not math.isfinite(at) or at < 0:
        raise ValueError("written_at")
    return value


def _guard(read: Callable[[], dict]) -> Optional[dict]:
    try:
        return read()
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        return None


def freshness(written_at, now, stale_after) -> tuple[str, Optional[str], Optional[int]]:
    """`(status, reason_code, age_s)` of one snapshot against the reader's clock."""

    if type(now) not in (int, float):
        return "unknown", "clock_unknown", None
    age = now - written_at
    if written_at > now + FUTURE_S:
        return "stale", "snapshot_dated_in_future", int(age)
    if age > stale_after:
        return "stale", "snapshot_expired", int(age)
    return "fresh", None, max(0, int(age))


# -- Knowledge Lite -----------------------------------------------------------

KNOWLEDGE_SCHEMA = "azazel-nexus/knowledge-status/v1"
KNOWLEDGE_BYTES = 4096
#: knowledge-lited rewrites the snapshot after READY and then this often.
#: Short, because `freshness` is evaluated when written: a dated claim that
#: expires between two writes reads `current` until the next one.
KNOWLEDGE_INTERVAL_S = 30
KNOWLEDGE_STALE_S = 150
#: `lite_bundle.ReadingSummary.overall`, the words `knowledge.status` answers.
KNOWLEDGE_STATES = ("available", "stale", "unavailable", "quarantined")
#: Every `reason_code` `lite_import.status_summary` returns today, plus this
#: module's own two for a summary it could not take or did not recognise.
KNOWLEDGE_REASONS = frozenset({
    "available", "stale", "unavailable", "quarantined", "trust_unreadable",
    "unverified", "no_bundle", "store_unreadable", "bundle_refused", "revoked",
    "state_untrusted", "status_unrecognised", "internal_error",
})
#: `lite_bundle.TimeBound`.
KNOWLEDGE_FRESHNESS = ("current", "stale", "absent")
KNOWLEDGE_FIELDS = ("state", "reason_code", "generation", "freshness")
_KNOWLEDGE_KEYS = ("schema", "written_at", *KNOWLEDGE_FIELDS)


def _check_knowledge(value: dict) -> None:
    if (value["state"] not in KNOWLEDGE_STATES
            or value["reason_code"] not in KNOWLEDGE_REASONS
            or value["freshness"] not in KNOWLEDGE_FRESHNESS):
        raise ValueError("vocabulary")
    generation = value["generation"]
    if generation is not None and (type(generation) is not int
                                   or not 0 <= generation <= _MAX):
        raise ValueError("generation")


def knowledge_snapshot(summary, written_at: float, *, reason: str = "status_unrecognised") -> dict:
    """The snapshot for one `status_summary` answer, copied field by field.

    An answer outside the vocabulary above is not copied: the snapshot then
    says `unavailable` with `reason` (`status_unrecognised`, or the caller's
    `internal_error` when the summary itself raised).
    """

    value = {"schema": KNOWLEDGE_SCHEMA, "written_at": written_at}
    try:
        if type(summary) is not dict:
            raise ValueError("summary")
        value.update({key: summary[key] for key in KNOWLEDGE_FIELDS})
        _check_knowledge(value)
    except (ValueError, TypeError, KeyError):
        value.update(state="unavailable", reason_code=reason, generation=None,
                     freshness="absent")
    return value


def read_knowledge_status(raw) -> Optional[dict]:
    """Decode knowledge-lited's snapshot, or `None` outside its closed shape."""

    def read():
        value = _decode(raw, KNOWLEDGE_BYTES, _KNOWLEDGE_KEYS, KNOWLEDGE_SCHEMA)
        _check_knowledge(value)
        return value
    return _guard(read)


# -- M.I.O. capability --------------------------------------------------------

MIO_SCHEMA = "azazel-nexus/mio-status/v1"
MIO_BYTES = 4096
#: entryd rewrites the snapshot at start and then this often (its serve
#: loop ticks every accept timeout; the capability itself is sampled at most
#: every ten seconds and recorded on change).
MIO_INTERVAL_S = 60
MIO_STALE_S = 300
_MIO_KEYS = ("schema", "written_at", "recorded", "state", "ceiling", "reasons",
             "observed_at", "record_uncertain")
_ISO = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?"
                  r"(?:[+-][0-9]{2}:[0-9]{2})?")


def _check_reasons(state, reasons) -> None:
    """The route ledger's transition shape, exactly as `mio_status` checks it."""

    from .capability import CapabilityState
    from .edge_package import Evidence
    from .mio_status import HEALTH_REASONS, RESOURCE_REASONS, TOPOLOGY_REASONS

    levels = {item.value for item in CapabilityState}
    if (state not in levels or type(reasons) is not dict
            or set(reasons) != {"profile", "resource", "trust", "health", "topology"}
            or reasons["profile"] not in levels
            or reasons["resource"] not in RESOURCE_REASONS
            or reasons["trust"] not in {item.value for item in Evidence}
            or reasons["topology"] not in TOPOLOGY_REASONS
            or type(reasons["health"]) is not dict
            or set(reasons["health"]) != {"local", "remote"}
            or any(value not in HEALTH_REASONS for value in reasons["health"].values())):
        raise ValueError("reasons")


def _iso(text) -> str:
    """A timestamp as `datetime.isoformat` writes it; anything else refused."""

    if type(text) is not str or len(text) > 40 or not _ISO.fullmatch(text):
        raise ValueError("observed_at")
    if datetime.fromisoformat(text).isoformat() != text:
        raise ValueError("observed_at")
    return text


def _check_mio(value: dict) -> None:
    if type(value["recorded"]) is not bool or type(value["record_uncertain"]) is not bool:
        raise ValueError("flags")
    if not value["recorded"]:
        if any(value[key] is not None for key in ("state", "ceiling", "observed_at")) \
                or value["reasons"] != {}:
            raise ValueError("unrecorded")
        return
    _check_reasons(value["state"], value["reasons"])
    if value["ceiling"] != value["reasons"]["profile"]:
        raise ValueError("ceiling")
    _iso(value["observed_at"])


def mio_snapshot(reading, observed_at, *, uncertain: bool, written_at: float) -> dict:
    """entryd's last **recorded** capability reading, as its ledger holds it.

    `reading` is `{"state", "reasons"}` (or `None` before the first record);
    `observed_at` is the record's time. It is the same reading `status`
    reads from the ledger, not a fresh sample, and it is not a grant.
    """

    value = {"schema": MIO_SCHEMA, "written_at": written_at, "recorded": False,
             "state": None, "ceiling": None, "reasons": {}, "observed_at": None,
             "record_uncertain": bool(uncertain)}
    try:
        if reading is not None:
            candidate = dict(value, recorded=True, state=reading["state"],
                             ceiling=reading["reasons"]["profile"],
                             reasons=json.loads(json.dumps(reading["reasons"])),
                             observed_at=datetime.fromisoformat(observed_at).isoformat())
            _check_mio(candidate)
            value = candidate
    except (ValueError, TypeError, KeyError):
        pass
    return value


def read_mio_status(raw) -> Optional[dict]:
    """Decode entryd's snapshot, or `None` outside its closed shape."""

    def read():
        value = _decode(raw, MIO_BYTES, _MIO_KEYS, MIO_SCHEMA)
        _check_mio(value)
        return value
    return _guard(read)


# -- systemd unit states ------------------------------------------------------

UNITS_SCHEMA = "azazel-nexus/units-status/v1"
UNITS_BYTES = 16384
#: `azazel-units-observe.timer` runs the observer this often.
UNITS_INTERVAL_S = 30
UNITS_STALE_S = 120
#: The packaged services, by name. Fixed here so the reader refuses any
#: other name; `tests/unit/test_operator_snapshots.py` keeps it equal to
#: `hardening.ALL_PROFILES`. The observer asks for these and nothing else.
OBSERVED_UNITS = (
    "azazel-activated.service",
    "azazel-auditd.service",
    "azazel-commissiond.service",
    "azazel-decoy-netd.service",
    "azazel-decoy-nsd.service",
    "azazel-decoy-verify.service",
    "azazel-decoyd.service",
    "azazel-edge-core.service",
    "azazel-edge-intaked.service",
    "azazel-edge-probe-preflight.service",
    "azazel-edge-probed.service",
    "azazel-incident-explaind.service",
    "azazel-knowledge-lited.service",
    "azazel-mio-entryd.service",
    "azazel-mio-locald.service",
    "azazel-mio-referenced.service",
    "azazel-mio-remoted.service",
    "azazel-model-fetchd.service",
    "azazel-units-observe.service",
    "azazel-watchdog.service",
)
#: systemd's LoadState words, plus the reader's `not-loaded` for a unit
#: systemd holds no object for (`GetUnit` never loads one).
LOAD_STATES = frozenset({"stub", "loaded", "not-found", "bad-setting", "error", "merged",
                         "masked", "not-loaded"})
ACTIVE_STATES = frozenset({"active", "reloading", "inactive", "failed", "activating",
                           "deactivating", "maintenance", "refreshing"})
_SUB_STATE = re.compile(r"[a-z][a-z-]{0,31}")
#: Why one unit's state is unknown: the bus could not be reached at all, or
#: this unit's reply was refused by the reader.
UNIT_REASONS = ("bus_unavailable", "read_refused")
_UNITS_KEYS = ("schema", "written_at", "units")
_UNIT_KEYS = ("unit", "status", "load_state", "active_state", "sub_state", "reason_code")


def _check_units(value: dict) -> None:
    units = value["units"]
    if type(units) is not list or [u.get("unit") if type(u) is dict else None
                                   for u in units] != list(OBSERVED_UNITS):
        raise ValueError("units")
    for item in units:
        if set(item) != set(_UNIT_KEYS):
            raise ValueError("unit")
        if item["status"] == "read":
            if (item["load_state"] not in LOAD_STATES
                    or item["active_state"] not in ACTIVE_STATES
                    or type(item["sub_state"]) is not str
                    or not _SUB_STATE.fullmatch(item["sub_state"])
                    or item["reason_code"] is not None):
                raise ValueError("state")
        elif item["status"] == "unknown":
            if (item["reason_code"] not in UNIT_REASONS
                    or any(item[key] is not None
                           for key in ("load_state", "active_state", "sub_state"))):
                raise ValueError("unknown")
        else:
            raise ValueError("status")


def units_snapshot(states: dict, written_at: float) -> dict:
    """One entry per `OBSERVED_UNITS` name, in that order.

    `states` maps a unit name to `{"LoadState", "ActiveState", "SubState"}`
    as the read-only reader returned them, or to one of `UNIT_REASONS`. A
    name missing from `states`, or a value outside the vocabulary, is
    `unknown` / `read_refused`.
    """

    units = []
    for name in OBSERVED_UNITS:
        state = states.get(name, "read_refused")
        entry = {"unit": name, "status": "unknown", "load_state": None,
                 "active_state": None, "sub_state": None,
                 "reason_code": state if state in UNIT_REASONS else "read_refused"}
        if type(state) is dict:
            candidate = {"unit": name, "status": "read",
                         "load_state": state.get("LoadState"),
                         "active_state": state.get("ActiveState"),
                         "sub_state": state.get("SubState"), "reason_code": None}
            if (candidate["load_state"] in LOAD_STATES
                    and candidate["active_state"] in ACTIVE_STATES
                    and type(candidate["sub_state"]) is str
                    and _SUB_STATE.fullmatch(candidate["sub_state"])):
                entry = candidate
        units.append(entry)
    return {"schema": UNITS_SCHEMA, "written_at": written_at, "units": units}


def read_units_status(raw) -> Optional[dict]:
    """Decode the unit-state snapshot, or `None` outside its closed shape."""

    def read():
        value = _decode(raw, UNITS_BYTES, _UNITS_KEYS, UNITS_SCHEMA)
        _check_units(value)
        return value
    return _guard(read)


# -- storage ------------------------------------------------------------------

#: Fixed labels and the directories they measure. Only the label leaves.
STORAGE_LOCATIONS = (
    ("state_root", "var/lib/azazel"),
    ("audit", "var/lib/azazel/state/audit"),
    ("edge_incidents", "var/lib/azazel/edge-incidents"),
    ("models", "var/lib/azazel/models"),
    ("mission_data", "data/azazel"),
)
#: Why a location could not be measured.
STORAGE_REASONS = ("absent", "not_permitted", "read_failed")


def read_storage(root=None, *, statvfs: Callable = os.statvfs,
                 stat: Callable = os.stat) -> list:
    """Free and total space per fixed label, measured now. Never raises.

    `same_filesystem_as` names the first earlier label on the same device,
    so a reader does not add one filesystem's free space twice. The device
    number itself is not reported.
    """

    base = Path(os.environ.get("AZAZEL_ROOT", "/")) if root is None else Path(root)
    entries, devices = [], {}
    for label, relative in STORAGE_LOCATIONS:
        path = base / relative
        entry = {"label": label, "status": "unknown", "total_bytes": None,
                 "free_bytes": None, "available_bytes": None, "read_only": None,
                 "same_filesystem_as": None, "reason_code": None}
        try:
            usage = statvfs(path)
            device = stat(path).st_dev
            entry.update(
                status="measured",
                total_bytes=int(usage.f_blocks) * int(usage.f_frsize),
                free_bytes=int(usage.f_bfree) * int(usage.f_frsize),
                available_bytes=int(usage.f_bavail) * int(usage.f_frsize),
                read_only=bool(usage.f_flag & getattr(os, "ST_RDONLY", 1)),
                same_filesystem_as=devices.get(device))
            devices.setdefault(device, label)
        except FileNotFoundError:
            entry["reason_code"] = "absent"
        except PermissionError:
            entry["reason_code"] = "not_permitted"
        except (OSError, ValueError, TypeError, AttributeError):
            entry["reason_code"] = "read_failed"
        entries.append(entry)
    return entries
