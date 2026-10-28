"""Shared read-only loop snapshot paths; no runtime dependency or authority."""
from __future__ import annotations

import os
from pathlib import Path


def _root(root):
    return Path(os.environ.get("AZAZEL_ROOT", "/")) if root is None else Path(root)


def edge_intake_status_path(root=None) -> Path:
    return _root(root) / "var/lib/azazel/run/edge-intake-status/status.json"


def incident_explain_status_path(root=None) -> Path:
    return _root(root) / "var/lib/azazel/run/incident-explain-status/status.json"


def incident_recent_path(root=None) -> Path:
    return incident_explain_status_path(root).with_name("recent.json")


def audit_status_path(root=None) -> Path:
    return _root(root) / "var/lib/azazel/run/audit-status/status.json"


def knowledge_status_path(root=None) -> Path:
    return _root(root) / "var/lib/azazel/run/knowledge-status/status.json"


def mio_status_path(root=None) -> Path:
    return _root(root) / "var/lib/azazel/run/mio-status/status.json"


def units_status_path(root=None) -> Path:
    return _root(root) / "var/lib/azazel/run/units-status/status.json"


def noc_status_path(root=None) -> Path:
    return _root(root) / "var/lib/azazel/run/noc-status/status.json"
