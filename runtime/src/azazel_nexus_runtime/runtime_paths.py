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

from azazel_nexus.audit import AuditLedger, AuditUnavailable

__all__ = ["ROOT", "audit_sink", "ledger_dir", "socket_path", "state_dir"]

#: Empty unless the harness sets it. Read once, on purpose.
ROOT = Path(os.environ.get("AZAZEL_ROOT", "/"))


def _under(absolute: str) -> Path:
    return ROOT / absolute.lstrip("/")


def socket_path(name: str) -> Path:
    """`/var/lib/azazel/run/<name>.sock`, under the root.

    `name` is a literal from this package, never a caller's string: the
    daemons each know their own socket, and a path assembled from input would
    be the one thing the protocol spent its design refusing.
    """

    if not name.isalnum():
        raise ValueError(
            f"{name!r} is not a socket name this package declares; socket "
            "names are literals here, not values"
        )
    directory = _under("/var/lib/azazel/run")
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{name}.sock"


def state_dir() -> Path:
    directory = _under("/var/lib/azazel/state")
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def ledger_dir() -> Path:
    directory = state_dir() / "audit"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def audit_sink() -> Callable[[dict], None]:
    """Where a daemon's own refusals go.

    A daemon records its refusals directly rather than through `az-auditd`:
    the events that matter most are the ones a daemon produces when something
    is already wrong, and routing them through another socket makes them
    depend on that socket being well.

    These are *not* chain entries. The chain is `az-auditd`'s and has one
    writer; this is a per-daemon record, and it is labelled so by living in a
    different file.
    """

    path = state_dir() / "refusals.jsonl"

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
