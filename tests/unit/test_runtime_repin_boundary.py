"""Enumerate all repin call sites; operator status and network cannot reach it."""

import ast
import hashlib
import tomllib
from pathlib import Path

import pytest
from azazel_nexus_runtime.commissiond import REGISTRY, REPIN_VERBS

REPO = Path(__file__).resolve().parents[2]
RUNTIME = REPO / "runtime/src/azazel_nexus_runtime"
LIBRARY = REPO / "src/azazel_nexus"


def test_all_repin_wire_references_are_local_commissioning():
    # Exact inventory, including library audit events, dispatch and client calls. No
    # egress, remote M.I.O., operator status or generic forwarding call site.
    sites = {}
    for directory in (RUNTIME, LIBRARY):
        for path in directory.rglob("*.py"):
            tree = ast.parse(path.read_text())
            values = [node.value for node in ast.walk(tree)
                      if isinstance(node, ast.Constant) and isinstance(node.value, str)
                      and node.value.startswith("trust.repin")]
            if values:
                sites[str(path.relative_to(REPO))] = sorted(values)
    assert sites == {
        "runtime/src/azazel_nexus_runtime/commissiond.py": [
            "trust.repin.challenge", "trust.repin.challenge",
            "trust.repin.confirm", "trust.repin.confirm"],
        "src/azazel_nexus/lite_trust.py": [
            "trust.repin.authorized", "trust.repin.promoted"],
    }
    assert {verb.name for verb in REPIN_VERBS} <= set(REGISTRY.names())


def _imports(path, source=None):
    result = set()
    for node in ast.walk(ast.parse(path.read_text() if source is None else source)):
        if isinstance(node, ast.Import):
            result.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            package = "azazel_nexus_runtime" if path.is_relative_to(RUNTIME) else "azazel_nexus"
            module = package + "." + (node.module or "") if node.level else node.module or ""
            result.add(module.rstrip("."))
            result.update(module.rstrip(".") + "." + alias.name for alias in node.names)
    return result


def _sources():
    return {path: path.read_text() for directory in (RUNTIME, LIBRARY)
            for path in directory.rglob("*.py")}


def _module(path):
    directory, package = ((RUNTIME, "azazel_nexus_runtime") if path.is_relative_to(RUNTIME)
                          else (LIBRARY, "azazel_nexus"))
    parts = list(path.relative_to(directory).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join([package, *parts])


def _graph_roots(graph):
    scripts = tomllib.loads((REPO / "runtime/pyproject.toml").read_text())["project"]["scripts"]
    # Include every shipped daemon except commissioning itself. The three
    # local operator tools have no daemon unit (test_runtime_boundary pins
    # that inventory). Bootstrap imports commissiond's inventory bound, so
    # including that local administration CLI would claim a false boundary.
    operator_tools = {"az-nexus-commission", "az-nexus-bootstrap", "az-core-reserve-probe"}
    roots = {target.split(":")[0] for name, target in scripts.items()
             if name not in operator_tools and name != "az-commissiond"}
    roots |= {"azazel_nexus.cli", "azazel_nexus_runtime.artifact_egress",
              "azazel_nexus_runtime.inference_egress"}
    roots |= {module for module in graph if module.rsplit(".", 1)[-1] in {
        "operator", "operator_view", "status", "remote_trust", "remote_envelope",
        "mio_locald", "mio_remoted", "model_fetchd", "auditd", "watchdog"}}
    return roots


def _check_graph(sources):
    graph = {_module(path): _imports(path, source) for path, source in sources.items()}
    # activated's existing evidence loader imports only this read-only helper.
    # Pin the helper source so this exception cannot acquire a repin/main call.
    # This is a symbol-specific edge, not an exemption for either whole module.
    loader = ast.parse(sources[RUNTIME / "commissioning_input.py"])
    cli_imports = [node for node in ast.walk(loader) if isinstance(node, ast.ImportFrom)
                   and node.module in {"commission_cli", "azazel_nexus_runtime.commission_cli"}]
    assert len(cli_imports) == 1
    assert [(alias.name, alias.asname) for alias in cli_imports[0].names] == [
        ("_PermanentAddresses", None)]
    cli = ast.parse(sources[RUNTIME / "commission_cli.py"])
    helper = next(node for node in cli.body if isinstance(node, ast.ClassDef)
                  and node.name == "_PermanentAddresses")
    assert hashlib.sha256(ast.get_source_segment(
        sources[RUNTIME / "commission_cli.py"], helper).encode()).hexdigest() == (
        "697a828c9cdd56092251df27fdcf378fb7660ffc7345e353e28b1448206e9575")
    # Repin imports must stay deferred inside main; importing the helper alone
    # must never load the confirmation module.
    assert all(not (isinstance(node, ast.ImportFrom)
                    and "repin_confirmation" in (node.module or "")) for node in cli.body)
    graph["azazel_nexus_runtime.commissioning_input"] -= {
        "azazel_nexus_runtime.commission_cli",
        "azazel_nexus_runtime.commission_cli._PermanentAddresses"}

    # activated's bootstrap inventory decoder also imports the existing
    # commissioning inventory limit. Pin this exact constant-only edge.
    inventory = ast.parse(sources[RUNTIME / "bootstrap_commission_inventory.py"])
    bound_imports = [node for node in ast.walk(inventory) if isinstance(node, ast.ImportFrom)
                     and node.module in {"commissiond", "azazel_nexus_runtime.commissiond"}]
    assert len(bound_imports) == 1
    assert [(alias.name, alias.asname) for alias in bound_imports[0].names] == [
        ("MAX_INTERFACES", None)]
    daemon = ast.parse(sources[RUNTIME / "commissiond.py"])
    bounds = [node for node in daemon.body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == "MAX_INTERFACES"
                      for target in node.targets)]
    assert len(bounds) == 1 and isinstance(bounds[0].value, ast.Constant)
    assert type(bounds[0].value.value) is int and bounds[0].value.value == 255
    graph["azazel_nexus_runtime.bootstrap_commission_inventory"] -= {
        "azazel_nexus_runtime.commissiond",
        "azazel_nexus_runtime.commissiond.MAX_INTERFACES"}
    seen = set()
    todo = list(_graph_roots(graph))
    while todo:
        module = todo.pop()
        if module in seen:
            continue
        seen.add(module)
        todo.extend(graph.get(module, set()) - seen)
    assert "azazel_nexus_runtime.repin_confirmation" not in seen
    assert "azazel_nexus_runtime.commission_cli" not in seen


def test_network_and_status_import_graph_never_reaches_repin():
    _check_graph(_sources())


REPIN_FILES = {
    "runtime/src/azazel_nexus_runtime/commissiond.py",
    "runtime/src/azazel_nexus_runtime/commission_cli.py",
    # Root's narrowed maintenance transaction (ADR 0008), the CLI's repin.
    "runtime/src/azazel_nexus_runtime/lite_trust_ops.py",
    "runtime/src/azazel_nexus_runtime/repin_confirmation.py",
    "src/azazel_nexus/lite_trust.py",
}
REPIN_NAMES = {"repin_confirmation", "RepinConfirmation", "production_repin"}


def _check_repin_names(sources):
    offenders = set()
    for path, source in sources.items():
        relative = path.relative_to(REPO)
        if relative.as_posix() in REPIN_FILES or relative.parts[0] == "tests":
            continue
        for node in ast.walk(ast.parse(source)):
            names = set()
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
            elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                names.add(node.name)
            elif isinstance(node, (ast.arg, ast.keyword)):
                names.add(node.arg)
            elif isinstance(node, ast.alias):
                names.update(node.name.split("."))
                names.add(node.asname)
            elif isinstance(node, ast.ImportFrom):
                names.update((node.module or "").split("."))
            if names & REPIN_NAMES or (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute) and node.func.attr == "repin"):
                offenders.add(relative.as_posix())
    assert offenders == set(), offenders


def _check_importers(sources):
    target = "azazel_nexus_runtime.repin_confirmation"
    importers = {_module(path) for path, source in sources.items()
                 if target in _imports(path, source)}
    assert importers == {"azazel_nexus_runtime.commissiond",
                         "azazel_nexus_runtime.lite_trust_ops"}


def test_repin_names_and_calls_have_an_exact_file_allowlist():
    _check_repin_names(_sources())


def test_exact_modules_import_repin_confirmation():
    _check_importers(_sources())


@pytest.mark.parametrize("source", [
    "from .repin_confirmation import RepinConfirmation as Hidden",
    "from . import repin_confirmation as hidden",
    "import azazel_nexus_runtime.repin_confirmation as hidden",
])
def test_the_scans_would_notice_a_planted_importer(source):
    sources = _sources()
    path = RUNTIME / "mio_locald.py"
    sources[path] += "\n" + source + "\n"
    for check in (_check_graph, _check_repin_names, _check_importers):
        with pytest.raises(AssertionError):
            check(sources)


@pytest.mark.parametrize("source", ["store.repin(request)", "production_repin(request)",
                                    "RepinConfirmation()", "repin_confirmation.confirm()"])
def test_the_scans_would_notice_a_planted_caller(source):
    sources = _sources()
    sources[LIBRARY / "operator.py"] += "\n" + source + "\n"
    with pytest.raises(AssertionError):
        _check_repin_names(sources)


def test_only_commission_cli_calls_interactive_client():
    callers = []
    for path in RUNTIME.glob("*.py"):
        tree = ast.parse(path.read_text())
        if any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
               and node.func.id in {"run_repin", "run_enroll", "run_revocation_accept"}
               for node in ast.walk(tree)):
            callers.append(path.name)
    assert callers == ["commission_cli.py"]
    # The socket client the CLI used before ADR 0008 is gone, not kept unused.
    assert not hasattr(__import__("azazel_nexus_runtime.repin_confirmation",
                                  fromlist=["x"]), "run_interactive")


@pytest.mark.parametrize("change", ["helper", "import"])
def test_the_scans_would_notice_widened_read_only_cli_edge(change):
    sources = _sources()
    if change == "helper":
        path = RUNTIME / "commission_cli.py"
        sources[path] = sources[path].replace("return self.snapshot is not None", "return main() and self.snapshot is not None")
    else:
        path = RUNTIME / "commissioning_input.py"
        sources[path] += "\nfrom .commission_cli import main\n"
    with pytest.raises(AssertionError):
        _check_graph(sources)


def test_the_scans_would_notice_widened_inventory_constant_edge():
    sources = _sources()
    sources[RUNTIME / "bootstrap_commission_inventory.py"] += (
        "\nfrom .commissiond import CommissionService\n")
    with pytest.raises(AssertionError):
        _check_graph(sources)
