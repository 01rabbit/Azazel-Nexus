"""Phase P4 wires the P2 readers into the pass, lazily and after narrowing (#206).

`docs/activation-observe-baseline.md` §3.6 and §4. The readers reach
`az-activated` only through `activation_pass`, which the controller imports
inside its pass after the preflight remask: importing the controller must
still load none of them, so a broken reader can never keep the controller
from its mandatory narrowing.
"""

import ast
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
ACTIVATED = REPO / "runtime/src/azazel_nexus_runtime/activated.py"
PASS = REPO / "runtime/src/azazel_nexus_runtime/activation_pass.py"
READERS = (
    "azazel_nexus.activation_policy",
    "azazel_nexus.observe_baseline",
    "azazel_nexus_runtime.activation_high_water",
    "azazel_nexus_runtime.activation_health",
    "azazel_nexus_runtime.activation_cli",
    "azazel_nexus_runtime.activation_unit_files",
    "azazel_nexus_runtime.activation_pass",
)


def _imports(path: Path) -> set[str]:
    imported = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            imported.add(("." * node.level) + (node.module or ""))
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    return imported


def test_importing_activated_loads_none_of_the_readers():
    code = (
        "import sys, azazel_nexus_runtime.activated\n"
        f"print(sorted(m for m in {sorted(READERS)!r} if m in sys.modules))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True,
        env={"PYTHONPATH": f"{REPO / 'src'}:{REPO / 'runtime/src'}",
             "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert result.stdout.strip() == "[]"


def test_activated_reaches_the_readers_only_through_the_pass_module():
    imported = _imports(ACTIVATED)
    assert ".activation_pass" in imported
    for module in READERS[:-1]:
        leaf = module.rsplit(".", 1)[1]
        assert module not in imported and "." + leaf not in imported, module


def test_production_producers_are_the_fixed_protected_readers():
    source = PASS.read_text(encoding="utf-8")
    body = source[source.index("def production_producers("):]
    for reader in ("load_activation_policy", "load_observe_baseline_approval",
                   "load_bootstrap_deployment", "collect_node_health",
                   "raise_high_water", "require_high_water_for_pass",
                   "load_declared_node", "measure_scoped_unit_files",
                   "verify_loaded_units"):
        assert reader in body, reader
    # No producer is taken from the environment or a command line.
    assert "environ" not in source and "argv" not in source


def test_the_pass_never_calls_a_start_verb():
    for path in (ACTIVATED, PASS, REPO / "runtime/src/azazel_nexus_runtime/activation_markers.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        literals = {node.value for node in ast.walk(tree)
                    if isinstance(node, ast.Constant) and isinstance(node.value, str)}
        attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        assert not {"StartUnit", "RestartUnit", "ReloadOrRestartUnit"} & literals
        assert not {"start", "start_unit", "restart"} & attributes


def test_the_pass_hands_its_own_bus_session_to_the_loaded_unit_check():
    """#251 H-1, M-3: the session that masks is the one whose loaded units are read."""
    source = ACTIVATED.read_text(encoding="utf-8")
    body = source[source.index("def _run_once("):source.index("def _narrow_bootstrap_core_units(")]
    assert 'systemd=getattr(manager, "call", None)' in body
    assert "systemd_loaded_units" in source[source.index("_ALL_PRODUCERS"):]
