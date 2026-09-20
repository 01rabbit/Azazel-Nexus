"""Static scans that keep the Fabric boundary mechanical, not aspirational.

`docs/contract-ownership.md` §1 says Nexus consumes Fabric behind an exact
release pin and owns only what it performs on the host. A rule stated in prose
is one review away from being gone, so it is also enforced against the source.
"""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "src" / "azazel_nexus"

#: The one module allowed to import Fabric. Containing it is what makes
#: Fabric's absence a bounded condition instead of an ImportError wherever the
#: interpreter happens to reach first -- and Fabric is an optional extra, so
#: its absence is a supported state, not an accident.
FABRIC_BOUNDARY = "fabric_boundary.py"


def _imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_only_the_boundary_module_imports_fabric():
    offenders = [
        path.name
        for path in sorted(PACKAGE_ROOT.rglob("*.py"))
        if path.name != FABRIC_BOUNDARY and "azazel_fabric" in _imported_roots(path)
    ]
    assert offenders == [], (
        f"{offenders} import azazel_fabric; only {FABRIC_BOUNDARY} may, so that "
        "a missing optional extra fails in one known place instead of anywhere"
    )


def test_the_boundary_module_defers_its_fabric_import():
    """A module-level import would make Fabric's absence an import error.

    The whole point of the boundary is that `CORE` works with nothing
    installed. If `fabric_boundary` imported Fabric at module scope, importing
    the boundary would be the crash it exists to prevent.
    """

    tree = ast.parse((PACKAGE_ROOT / FABRIC_BOUNDARY).read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        else:
            continue
        assert not any(name.split(".")[0] == "azazel_fabric" for name in names), (
            f"{FABRIC_BOUNDARY} imports Fabric at module scope: {names}"
        )


#: Names whose presence would mean Nexus had grown an operational surface it
#: has not commissioned. Nothing in this package may reach the network, run a
#: process, or touch host storage yet.
OPERATIONAL_MODULES = {
    "socket", "ssl", "http", "urllib", "ftplib", "smtplib",
    "subprocess", "ctypes", "multiprocessing", "asyncio",
    "requests", "httpx", "docker", "paramiko",
}


def test_the_package_contains_no_operational_code():
    offenders: dict[str, list[str]] = {}
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        found = sorted(_imported_roots(path) & OPERATIONAL_MODULES)
        if found:
            offenders[path.name] = found
    assert offenders == {}, (
        f"operational imports found: {offenders}. No interface has been "
        "commissioned, so nothing here may reach the network or the host"
    )
