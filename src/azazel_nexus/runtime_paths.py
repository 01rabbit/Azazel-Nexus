"""Shared read-only loop snapshot paths; no runtime dependency or authority.

Each snapshot has two places (ADR-0007):

* the **operator leaf** (`reader="operator"`, the default):
  `/var/lib/azazel/run/<leaf>/`, `2750 <writer>:azazel-operator`, which
  `azazel-nexus status` reads for a member of the operator group;
* the **UI read leaf** (`reader="ui"`): `/var/lib/azazel/run/ui-read/<leaf>/`,
  `2750 <writer>:azui`, where the same writer puts a byte-identical copy of
  the same snapshot for the read-only UI's account. Only the snapshots listed
  in `UI_COPIES` have one; every one of them is already a closed shape of
  codes and counts (no interface identity, no path, no key, no free text from
  a terminal-only source), so the copy carries nothing the UI must not show.

The reader is chosen by the caller and never by an environment variable; a
reader that cannot open a file sees it as absent or refused, whichever leaf
it asked for.
"""
from __future__ import annotations

import os
from pathlib import Path

__all__ = [
    "READERS", "UI_COPIES", "UI_READ_DIRECTORY",
    "audit_status_path", "edge_intake_status_path", "incident_explain_status_path",
    "incident_recent_path", "knowledge_status_path", "mio_status_path", "noc_status_path",
    "snapshot_path", "ui_copy_path", "units_status_path",
]

#: Who a read is for: the operator group's leaves, or the UI's copies.
READERS = ("operator", "ui")

#: The parent of the UI read leaves: traversal only, like `run/` itself.
UI_READ_DIRECTORY = "/var/lib/azazel/run/ui-read"

#: Snapshot -> (operator leaf, UI read leaf, file name). One writer per leaf.
UI_COPIES = {
    "audit_status": ("audit-status", "audit", "status.json"),
    "edge_intake_status": ("edge-intake-status", "edge-intake", "status.json"),
    "incident_explain_status": ("incident-explain-status", "incident-explain", "status.json"),
    "incident_recent": ("incident-explain-status", "incident-explain", "recent.json"),
    "knowledge_status": ("knowledge-status", "knowledge", "status.json"),
    "mio_status": ("mio-status", "mio", "status.json"),
    "units_status": ("units-status", "units", "status.json"),
    "noc_status": ("noc-status", "noc", "status.json"),
}


def _root(root):
    return Path(os.environ.get("AZAZEL_ROOT", "/")) if root is None else Path(root)


def snapshot_path(name: str, root=None, *, reader: str = "operator") -> Path:
    """Where snapshot `name` is read by `reader` (`operator` or `ui`)."""

    if reader not in READERS:
        raise ValueError("reader must be 'operator' or 'ui'")
    operator_leaf, ui_leaf, file_name = UI_COPIES[name]
    if reader == "ui":
        return _root(root) / UI_READ_DIRECTORY.lstrip("/") / ui_leaf / file_name
    return _root(root) / "var/lib/azazel/run" / operator_leaf / file_name


def ui_copy_path(name: str, root=None) -> Path:
    """Where the writer of snapshot `name` puts the UI's copy."""

    return snapshot_path(name, root, reader="ui")


def edge_intake_status_path(root=None, *, reader: str = "operator") -> Path:
    return snapshot_path("edge_intake_status", root, reader=reader)


def incident_explain_status_path(root=None, *, reader: str = "operator") -> Path:
    return snapshot_path("incident_explain_status", root, reader=reader)


def incident_recent_path(root=None, *, reader: str = "operator") -> Path:
    return snapshot_path("incident_recent", root, reader=reader)


def audit_status_path(root=None, *, reader: str = "operator") -> Path:
    return snapshot_path("audit_status", root, reader=reader)


def knowledge_status_path(root=None, *, reader: str = "operator") -> Path:
    return snapshot_path("knowledge_status", root, reader=reader)


def mio_status_path(root=None, *, reader: str = "operator") -> Path:
    return snapshot_path("mio_status", root, reader=reader)


def units_status_path(root=None, *, reader: str = "operator") -> Path:
    return snapshot_path("units_status", root, reader=reader)


def noc_status_path(root=None, *, reader: str = "operator") -> Path:
    return snapshot_path("noc_status", root, reader=reader)
