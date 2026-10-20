"""Phase P2 readers exist but production activation does not use them (#206).

`docs/activation-observe-baseline.md` §4: P0-P3 do not change production
behaviour; the pass keeps `lease=None` and `healthy=False`. The four inert
readers and the P3 operator tool (`az-activation`) must not reach
`az-activated` until P4 wires them with its own tests.
"""

import ast
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
ACTIVATED = REPO / "runtime/src/azazel_nexus_runtime/activated.py"
INERT = {
    "azazel_nexus.activation_policy": "activation_policy",
    "azazel_nexus.observe_baseline": "observe_baseline",
    "azazel_nexus_runtime.activation_high_water": "activation_high_water",
    "azazel_nexus_runtime.activation_health": "activation_health",
    "azazel_nexus_runtime.activation_cli": "activation_cli",
    "azazel_nexus_runtime.activation_unit_files": "activation_unit_files",
}
PUBLIC = {
    "load_activation_policy", "decode_activation_policy", "build_observe_baseline",
    "verify_observe_baseline", "read_high_water", "raise_high_water",
    "initialize_high_water", "require_high_water_for_pass", "activation_ledger_present",
    "collect_node_health", "read_watchdog_fences",
    "run_generation_publish", "run_request", "run_install", "installed_package_digest",
    "evidence_commissioning_digest", "measure_scoped_unit_files",
    "require_no_unit_overrides",
}


def test_activated_neither_imports_nor_names_the_p2_readers():
    tree = ast.parse(ACTIVATED.read_text(encoding="utf-8"))
    imported = set()
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(("." * node.level) + (node.module or ""))
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
    for module, leaf in INERT.items():
        assert module not in imported and "." + leaf not in imported, module
    assert not names & (PUBLIC | set(INERT.values()))


def test_importing_activated_loads_none_of_the_p2_readers():
    code = (
        "import sys, azazel_nexus_runtime.activated\n"
        f"print(sorted(m for m in {sorted(INERT)!r} if m in sys.modules))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True,
        env={"PYTHONPATH": f"{REPO / 'src'}:{REPO / 'runtime/src'}",
             "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert result.stdout.strip() == "[]"


def test_production_pass_still_composes_without_lease_or_health():
    source = ACTIVATED.read_text(encoding="utf-8")
    run_once = source[source.index("def _run_once("):source.index("def _narrow_bootstrap_core_units")]
    assert "lease=None" in run_once
    assert "healthy=False" in run_once
