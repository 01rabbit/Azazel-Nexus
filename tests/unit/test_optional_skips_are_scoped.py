"""A skip for an optional extra must not take unrelated tests with it.

`pytest.importorskip` at module level skips the whole module, including every
test defined above the call. `test_commissioning.py` once held its check on
Nexus's own role vocabulary above a Fabric import guard: without the Fabric
extra the check never ran, and two retired role words reached `main` while
every run without the extra reported success. Tests that need an optional
extra live in a module of their own, or import it inside the test.
"""

from __future__ import annotations

import ast
from pathlib import Path

TESTS = Path(__file__).resolve().parent


def _is_importorskip(node: ast.stmt) -> bool:
    call = getattr(node, "value", None)
    return (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "importorskip"
    )


def test_no_module_level_importorskip_follows_a_test():
    hidden = []
    for path in sorted(TESTS.glob("test_*.py")):
        defined = []
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
                "test_"
            ):
                defined.append(node.name)
            elif _is_importorskip(node) and defined:
                hidden.append(f"{path.name}:{node.lineno} hides {len(defined)} test(s)")
    assert hidden == [], hidden
