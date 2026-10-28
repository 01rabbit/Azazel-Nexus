"""Root's two Knowledge Lite operations, each one request to an existing daemon.

`az-nexus-commission knowledge-import --entry ID` asks `az-knowledge-lited`
(operator socket, ROOT-only `knowledge.import`) to import one inbox entry.
`az-nexus-commission knowledge-revocation-accept` asks `az-commissiond`
(ROOT-only `trust.revocation.accept`) to accept the signed list root put at
the fixed leaf. Neither command takes a path, a key, a policy or an override,
and neither does the work itself: the daemon that owns the store does it and
records it in `az-auditd`. Both print fixed words and numbers only.
"""

from __future__ import annotations

import json
import os
import re
import sys

from .lite_revocation_accept import REVOCATION_INPUT

__all__ = ["run_import", "run_revocation_accept"]

#: An import verifies the whole bounded archive inside the daemon.
IMPORT_DEADLINE_S = 60

_IMPORT_FIELDS = {"outcome", "refused", "state", "bundle_version", "gate", "code",
                  "audit_complete"}
_WORD = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z", re.ASCII)


def _word(value) -> bool:
    return value is None or (type(value) is str and _WORD.fullmatch(value) is not None)


def _print(result: dict) -> None:
    print(json.dumps(result, sort_keys=True))


def run_import(entry_id: str) -> int:
    if os.geteuid() != 0:
        print("knowledge-import runs as root.", file=sys.stderr)
        return 1
    if re.fullmatch(r"[0-9a-f]{64}", entry_id, re.ASCII) is None:
        print("The entry id is the artifact's SHA-256 as 64 lowercase hex digits.", file=sys.stderr)
        return 2
    from .mio_socket_client import _exchange

    try:
        result = _exchange("knowledge", "azknowledge", "knowledge.import",
                           {"entry_id": entry_id}, deadline_s=IMPORT_DEADLINE_S)
        # Validate every displayed field; never render arbitrary daemon text.
        if (set(result) != _IMPORT_FIELDS
                or result["outcome"] not in {"admitted", "quarantined", "refused", "failed"}
                or not all(_word(result[key]) for key in ("refused", "state", "gate", "code"))
                or not (result["bundle_version"] is None or type(result["bundle_version"]) is int)
                or type(result["audit_complete"]) is not bool):
            raise ValueError("reply refused")
    except Exception:  # noqa: BLE001 - fixed words only
        print("Knowledge Lite import refused or unavailable; nothing is reported as done.",
              file=sys.stderr)
        return 1
    _print(result)
    return 0 if result["outcome"] == "admitted" and result["audit_complete"] else 1


def run_revocation_accept() -> int:
    if os.geteuid() != 0:
        print("knowledge-revocation-accept runs as root.", file=sys.stderr)
        return 1
    from .mio_socket_client import _exchange

    try:
        # The commissioning socket, authenticated as azcommission.
        result = _exchange("commission", "azcommission", "trust.revocation.accept",
                           {"revocation_file": REVOCATION_INPUT}, deadline_s=10)
        if (set(result) != {"accepted", "code", "sequence", "audit_complete"}
                or type(result["accepted"]) is not bool or not _word(result["code"])
                or not (result["sequence"] is None or type(result["sequence"]) is int)
                or type(result["audit_complete"]) is not bool):
            raise ValueError("reply refused")
    except Exception:  # noqa: BLE001 - fixed words only
        print("Revocation acceptance refused or unavailable; nothing is reported as done.",
              file=sys.stderr)
        return 1
    _print(result)
    return 0 if result["accepted"] and result["audit_complete"] else 1
