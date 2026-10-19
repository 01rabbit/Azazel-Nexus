"""Where a running daemon finds things, and how the tests move it (#43).

Every path here comes from `azazel_nexus.layout`. The only thing this module
adds is a root, taken from `AZAZEL_ROOT` when it is set.

That variable exists for the integration harness, which cannot write to
`/var/lib` on a machine it does not own, and it is read **once at import**
rather than per call: a daemon whose paths changed while it was running would
be a daemon serving two ledgers.

A root is not a configuration knob. The units set none, so a daemon under
systemd uses the declared absolute paths and nothing else.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from azazel_nexus.audit import AuditUnavailable
from azazel_nexus import runtime_paths as observation_paths

__all__ = [
    "ROOT",
    "audit_sink",
    "incident_segments_dir",
    "incident_explain_state_dir",
    "incident_explain_status_path",
    "incident_recent_path",
    "edge_intake_state_dir",
    "edge_intake_status_path",
    "commission_ledger_path",
    "fetch_commission_dir",
    "fetch_dir",
    "fetch_partial_dir",
    "fetch_ready_dir",
    "knowledge_state_dir",
    "knowledge_store_root",
    "ledger_dir",
    "lite_trust_root",
    "mio_local_state_dir",
    "mio_state_dir",
    "mission_pack_config",
    "mission_pack_root",
    "models_root",
    "socket_group",
    "socket_path",
    "state_dir",
    "watchdog_state_dir",
]

#: Empty unless the harness sets it. Read once, on purpose.
ROOT = Path(os.environ.get("AZAZEL_ROOT", "/"))
_SOCKET_LEAVES = {
    "audit": "audit",
    "audit-submit": "audit-submit",
    "commission": "commission",
    "watchdog": "watchdog",
    "fetch": "fetch",
    "mio-entry": "mio-entry",
    "mio-advise": "mio-advise",
    "mio": "mio",
    "remote": "remote",
    "knowledge": "knowledge",
    "knowledge-read": "knowledge-read",
    "edge-intake": "edge-intake",
}
#: Leaves whose socket inherits a dedicated client group instead of the
#: operator group. Each one is a second, verb-restricted listener of a daemon
#: that also serves the operator leaf; a daemon client is given the dedicated
#: group alone, so it never reaches an operator socket (#213 O1).
_SOCKET_GROUPS = {
    "audit-submit": "azaudit-submit",
    "mio-advise": "azmio-advise",
    "knowledge-read": "azknowledge-read",
    "edge-intake": "azedge",
}
_STATE_LEAVES = {
    "mio-entry": "mio",
    "knowledge": "knowledge",
    "mio": "mio",
    "audit": "auditd",
    "commission": "commission",
    "watchdog": "watchdog",
    "fetch": "fetch",
}


def _under(absolute: str) -> Path:
    return ROOT / absolute.lstrip("/")


def socket_group(name: str) -> str:
    """The group a declared socket leaf hands its socket (setgid inheritance)."""

    if name not in _SOCKET_LEAVES:
        raise ValueError("socket name is not declared by this runtime")
    return _SOCKET_GROUPS.get(name, "azazel-operator")


def socket_path(name: str) -> Path:
    """Return the fixed daemon-owned leaf socket path under the root.

    The mapping is deliberately closed and installation-owned. Do not create
    missing parents here: doing so would apply ambient umask/ownership instead
    of the reviewed service-specific mode and group.
    """

    try:
        leaf = _SOCKET_LEAVES[name]
    except (KeyError, TypeError):
        raise ValueError(
            "socket name is not declared by this runtime"
        ) from None
    return _under(f"/var/lib/azazel/run/{leaf}/{name}.sock")


def state_dir() -> Path:
    """Return the installer-created state root; never create it as a daemon."""
    return _under("/var/lib/azazel/state")


def ledger_dir() -> Path:
    """Return auditd's installer-owned chain directory."""
    return state_dir() / "audit"


def watchdog_state_dir() -> Path:
    """Return the watchdog-only installer-owned state directory."""
    return state_dir() / _STATE_LEAVES["watchdog"]


def mio_state_dir() -> Path:
    """Return the M.I.O. entry service's separate chain directory."""
    return state_dir() / _STATE_LEAVES["mio"]


def mio_local_state_dir() -> Path:
    """The locald-owned cache/socket/ledger leaf, separate from entryd."""
    return _under("/var/lib/azazel/mio")


def knowledge_state_dir() -> Path:
    """Return the Knowledge Lite daemon's private state directory."""
    return state_dir() / _STATE_LEAVES["knowledge"]


def knowledge_store_root() -> Path:
    """Return the Lite store, readable by operators and owned by azknowledge."""
    return _under("/var/lib/azazel/knowledge")


def audit_sink(service: str) -> Callable[[dict], None]:
    """Where a daemon's own refusals go.

    A daemon records its refusals directly rather than through `az-auditd`:
    the events that matter most are the ones a daemon produces when something
    is already wrong, and routing them through another socket makes them
    depend on that socket being well.

    These are *not* chain entries. The chain is `az-auditd`'s and has one
    writer; this is a per-daemon record, and it is labelled so by living in a
    different file.
    """

    try:
        leaf = _STATE_LEAVES[service]
    except (KeyError, TypeError):
        raise ValueError("service state name is not declared by this runtime") from None
    # Fetch has no writable state tree; keep its refusals alongside partials.
    directory = fetch_partial_dir() if service == "fetch" else state_dir() / leaf
    path = directory / "refusals.jsonl"

    def record(event: dict) -> None:
        import json

        try:
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
                )
        except OSError as exc:
            raise AuditUnavailable(f"{path} could not be appended to: {exc}") from exc

    return record


def fetch_dir() -> Path:
    return _under("/var/lib/azazel/fetch")


def fetch_commission_dir() -> Path:
    return fetch_dir() / "commission"


def fetch_partial_dir() -> Path:
    return fetch_dir() / "partial"


def fetch_ready_dir() -> Path:
    return fetch_dir() / "ready"


def models_root() -> Path:
    return _under("/var/lib/azazel/models")


def lite_trust_root() -> Path:
    """Commissioner-written public trust records; Lite has group read access."""
    return _under("/var/lib/azazel/lite-trust")


def commission_ledger_path() -> Path:
    """Commissiond's own append-only chain, separate from auditd and refusals."""
    return state_dir() / "commission" / "commission.jsonl"


def mission_pack_config() -> Path:
    """Existing operator-commissioned Mission Pack trust and inventory."""
    return _under("/etc/azazel/mission-pack.json")


def mission_pack_root() -> Path:
    """Existing encrypted Mission Pack store; optional read access for locald."""
    return _under("/data/azazel/mission-packs")


def edge_intake_state_dir() -> Path:
    """Private evidence, outside the separate incident and liveness leaves."""
    return _under("/var/lib/azazel/edge-intake")


def edge_intake_status_path() -> Path:
    """Only the dedicated status leaf is operator-readable."""
    return observation_paths.edge_intake_status_path(ROOT)


def incident_segments_dir() -> Path:
    return _under("/var/lib/azazel/edge-incidents")


def incident_explain_state_dir() -> Path:
    return _under("/var/lib/azazel/incident-explain")


def incident_explain_status_path() -> Path:
    return observation_paths.incident_explain_status_path(ROOT)


def incident_recent_path() -> Path:
    return observation_paths.incident_recent_path(ROOT)
