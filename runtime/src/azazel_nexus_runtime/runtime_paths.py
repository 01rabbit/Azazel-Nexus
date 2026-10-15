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
from pathlib import Path
from typing import Callable

from azazel_nexus.audit import AuditUnavailable

__all__ = [
    "ROOT",
    "audit_sink",
    "ledger_dir",
    "socket_path",
    "state_dir",
    "watchdog_state_dir",
]

#: Empty unless the harness sets it. Read once, on purpose.
ROOT = Path(os.environ.get("AZAZEL_ROOT", "/"))
_SOCKET_LEAVES = {
    "audit": "audit",
    "commission": "commission",
    "watchdog": "watchdog",
}
_STATE_LEAVES = {
    "audit": "auditd",
    "commission": "commission",
    "watchdog": "watchdog",
}


def _under(absolute: str) -> Path:
    return ROOT / absolute.lstrip("/")


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
    path = state_dir() / leaf / "refusals.jsonl"

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
