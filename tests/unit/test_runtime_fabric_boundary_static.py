"""The runtime reaches Fabric only through the library's boundary (ADR-0001, ADR-0011).

`test_boundary_static.py` scans the library. The runtime package is a second
place a direct import could grow, so it is scanned here the same way.
"""

from __future__ import annotations

import ast
from pathlib import Path

RUNTIME = Path(__file__).resolve().parents[2] / "runtime" / "src" / "azazel_nexus_runtime"


def _fabric_imports(path: Path) -> list[int]:
    lines = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            hit = any(alias.name.split(".")[0] == "azazel_fabric" for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            hit = node.level == 0 and (node.module or "").split(".")[0] == "azazel_fabric"
        else:
            continue
        if hit:
            lines.append(node.lineno)
    return lines


def test_no_runtime_module_imports_azazel_fabric():
    offenders = {path.name: lines for path in sorted(RUNTIME.rglob("*.py"))
                 if (lines := _fabric_imports(path))}
    assert offenders == {}, (
        f"{offenders} import azazel_fabric directly; go through "
        "azazel_nexus.fabric_boundary so a missing or wrong Fabric fails in one place")


def test_the_scan_sees_a_planted_import(tmp_path):
    planted = tmp_path / "planted.py"
    planted.write_text("def f():\n    from azazel_fabric.x import y\n", encoding="utf-8")
    assert _fabric_imports(planted) == [2]
