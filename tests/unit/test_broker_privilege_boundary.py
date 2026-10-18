"""Content-plane privilege guard, including imported local helper modules.

This is a conservative source scan, not a proof for arbitrary dynamic Python.
The runtime profile complements it on the concrete connector/advisory paths.
There is no Fabric Deception report transport yet: its opaque report enters
through route_advisory, and does not acquire a separate operational surface.
"""

import ast
import hashlib
import importlib.util
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from types import FunctionType

import pytest

# Fixtures are lane-owned and contain only ephemeral/test keys.
import test_broker_routing as fixtures
from test_broker_routing import EXPIRES, ISSUED, NOW, Manifest

from azazel_nexus.advisory_response import AdvisoryRefused, read_advisory
from azazel_nexus.integration_broker import routing
from azazel_nexus.knowledge_peer import (
    RESPONSE_DOMAIN,
    SCHEMA,
    KnowledgePeer,
    canonical,
    read_context,
)
from azazel_nexus.provider_registry import ProviderRecord
from azazel_nexus.sanitizer import PrivacyClass

data_args = fixtures.data_args

ROOT = Path(__file__).resolve().parents[2]
LIBRARY = ROOT / "src"
ENTRY_MODULES = {
    "azazel_nexus.mio_profile",
    "azazel_nexus.operator_view",
    "azazel_nexus.fabric_boundary",
    "azazel_nexus.provider_registry",
    "azazel_nexus.broker_cli",
    "azazel_nexus.integration_broker",
    "azazel_nexus.integration_broker.manifest",
    "azazel_nexus.integration_broker.confinement",
    "azazel_nexus.integration_broker.states",
    "azazel_nexus.integration_broker.broker",
    "azazel_nexus.integration_broker.routing",  # connector + Deception data
    "azazel_nexus.advisory_response",  # M.I.O. response
    "azazel_nexus.knowledge_peer",  # signed Knowledge advisory
    "azazel_nexus.lite_bundle",  # Lite claims
    "azazel_nexus.lite_service",  # local + peer advisory context
}
PRIVILEGED_MODULES = {
    "activation",
    "activation_approval",
    "activation_store",
    "activated",
    "units",
    "confinement",
    "states",
    "broker",
    "credentials",
    "credential_store",
}
PRIVILEGED_CALLS = {
    "UnitManager",
    "DbusUnitManager",
    "ManagedUnitController",
    "ActivationController",
    "SystemdUnitController",
    "UnitController",
    "start",
    "stop",
    "restart",
    "mask",
    "unmask_and_enable",
    "activate",
    "unmask",
    "enable",
    "disable",
    "dispatch_exposure",
    "exposure_dispatch",
    "gate_exposure_proposal",
    "deliver",
    "get_credential",
    "retrieve_credential",
    "resolve_credential",
    "load_credential",
    "rotate_credential",
    "transition",
    "widen",
    "set_state",
    "eval",
    "exec",
    "__import__",
    "import_module",
}


def _local_imports(module, tree, packages=()):
    """Resolve both relative imports and `from package import module` edges."""
    parent = module if module in packages else module.rsplit(".", 1)[0]
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            target = (
                importlib.util.resolve_name(
                    "." * node.level + (node.module or ""), parent
                )
                if node.level
                else node.module or ""
            )
            names.add(target)
            names.update(target + "." + alias.name for alias in node.names)
    return names


# Existing fixed-field validators and Fabric model projections are pure. Pin
# their complete AST bodies: changing any statement invalidates this exception.
# The only importlib use is find_spec over PLANNED_FABRIC_MODULES; no dynamic
# module execution is authorized. Privileged names/calls remain scanned here.
REVIEWED_PURE_BODIES = {'33fbaff835f33066544564df181cfdac1a84c790c04277f6f46c90c64816a4de': 'mio_profile.__post_init__',
 '579fd732d0649db3a7e06cf946dba96cde0748545077dfb62282c8ca505c363b': 'mio_profile.__post_init__',
 '7ace2b97884230200c3ff06ed376ff682cf7eaeaca91bd8b69f45932f9ae4170': 'fabric_boundary._missing_planned',
 'b06b058cee681cb88d520e89c80c5d21d457cf768cbd4b5c4cca3fe388f7fa0c': 'fabric_boundary.confirm_role',
 'bd70432970c734d9b1b36b9508cf5b06f8ce358c63fa8c690a51ace7e408c49e': 'fabric_boundary.project_hardware_inventory',
 'bff8b4c3e8a4245fc398dbb0cdf0b53d4d1be294a089d99249a6de44485b211a': 'model_catalog.__post_init__',
 'c252c16599a660a85ef64afa8c264ee3234a3763658b0510a84949c1a2e664d1': 'fabric_boundary.assert_local_record_matches_full_proposal',
 'f9274719bde04288a876b319b669fc26a61e867e41ef21198de9b7b67afa1664': 'mio_profile.__post_init__'}


def _reviewed_node(tree, node, source):
    return any(isinstance(owner, ast.FunctionDef)
               and owner.lineno <= node.lineno <= owner.end_lineno
               and hashlib.sha256("\n".join(source.splitlines()[owner.lineno - 1:owner.end_lineno]).encode()).hexdigest() in REVIEWED_PURE_BODIES
               for owner in ast.walk(tree))


def scan(sources, entries=ENTRY_MODULES):
    pending = list(entries)
    visited = set()
    offenders = []
    while pending:
        module = pending.pop()
        if module in visited or module not in sources:
            continue
        visited.add(module)
        tree = ast.parse(sources[module])
        packages = {name for name in sources if any(other.startswith(name + ".") for other in sources)}
        imports = _local_imports(module, tree, packages)
        for name in imports:
            # Pure control-plane edges are explicit and module-scoped. Content
            # entries still cannot import the broker, confinement or transitions.
            internal = module in {
                "azazel_nexus.integration_broker", "azazel_nexus.integration_broker.broker",
                "azazel_nexus.broker_cli",
            } and name.startswith("azazel_nexus.integration_broker")
            types_only = module == "azazel_nexus.integration_broker.routing" and name in {
                "azazel_nexus.integration_broker.states",
                "azazel_nexus.integration_broker.states.AdapterRecord",
                "azazel_nexus.integration_broker.states.BrokerState",
            }
            fabric_helper = module in {"azazel_nexus.fabric_boundary", "azazel_nexus.commissioning_draft"} and name in {
                "azazel_nexus.activation", "azazel_nexus.activation.ActivationRefused",
                "azazel_nexus.activation._utc_lease_time",
            }
            if fabric_helper:
                # Permit named pure helpers, never an activation module alias.
                fabric_helper = all(
                    isinstance(n, ast.ImportFrom)
                    and {alias.name for alias in n.names} <= {"ActivationRefused", "_utc_lease_time"}
                    for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                    and name in _local_imports(module, n, packages)
                )
            if internal or types_only or fabric_helper:
                if name in sources and not fabric_helper:
                    pending.append(name)
                continue
            if (
                name.startswith(("azazel_nexus_runtime", "azazel_nexus.integration_broker.Broker"))
                or set(name.split(".")) & (PRIVILEGED_MODULES | PRIVILEGED_CALLS)
                or name == "azazel_nexus.integration_broker"
            ):
                offenders.append((module, "import", name))
            if name.startswith("os.") and (name.rsplit(".", 1)[-1] == "system" or name.rsplit(".", 1)[-1].startswith("exec")):
                offenders.append((module, "dangerous_import", name))
            if (name.split(".")[0] in {"subprocess", "ctypes", "importlib", "runpy", "socket"}
                    and not (module == "azazel_nexus.fabric_boundary" and name == "importlib.util"
                        and all(_reviewed_node(tree, n, sources[module])
                                for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                                and name in _local_imports(module, n, packages)))):
                offenders.append((module, "dangerous_import", name))
            if name in sources and not set(name.split(".")) & PRIVILEGED_MODULES:
                pending.append(name)
        allowed_refs = {
            "azazel_nexus.integration_broker": {"rotate_credential", "transition", "gate_exposure_proposal", "deliver"},
            "azazel_nexus.integration_broker.broker": {"transition", "gate_exposure_proposal", "deliver"},
            "azazel_nexus.integration_broker.states": {"transition"},
            "azazel_nexus.operator_view": {"transition"},  # immutable view field
        }.get(module, set())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
                name = node.id if isinstance(node, ast.Name) else node.attr
                if name in PRIVILEGED_CALLS - allowed_refs or (
                    isinstance(node, ast.Attribute) and node.attr in {"execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe"}
                ) or (isinstance(node, ast.Attribute) and node.attr == "system"):
                    offenders.append((module, node.lineno, name))
            if isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else (
                    node.func.attr if isinstance(node.func, ast.Attribute) else "")
                if name in {"getattr", "__getattribute__"}:
                    index = 1 if name == "getattr" else 0
                    if len(node.args) <= index or not isinstance(node.args[index], ast.Constant):
                        if not _reviewed_node(tree, node, sources[module]):
                            offenders.append((module, node.lineno, "dynamic_attribute"))
                    elif node.args[index].value in PRIVILEGED_CALLS:
                        offenders.append((module, node.lineno, "privileged_attribute"))
    return offenders, visited


def source_map():
    result = {}
    for path in (LIBRARY / "azazel_nexus").rglob("*.py"):
        parts = path.relative_to(LIBRARY).with_suffix("").parts
        if parts[-1] == "__init__":
            parts = parts[:-1]
        result[".".join(parts)] = path.read_text()
    return result


def test_content_plane_and_all_local_imports_have_no_privileged_edges():
    offenders, visited = scan(source_map())
    assert ENTRY_MODULES <= visited
    assert {name for name in source_map() if name.startswith("azazel_nexus.integration_broker")} <= visited
    assert "azazel_nexus.sanitizer" in visited  # not a vacuous root-only scan
    assert offenders == [], repr(offenders)


@pytest.mark.parametrize(
    "planted",
    [
        "getattr(manager, supplied_name)(payload)",
        "manager.__getattribute__(supplied_name)",
        "alias = manager.activate",
        "alias = get_credential",
        "import subprocess",
        "import ctypes",
        "import importlib",
        "import runpy",
        "import socket",
        "alias = os.system",
        "import os as harmless\nalias = harmless.system",
        "from os import system as harmless",
        "from os import execve as harmless",
        "from azazel_nexus.integration_broker.routing import gate_exposure_proposal as harmless",
        "from azazel_nexus.integration_broker import Broker as harmless",
        "alias = os.execve",
        "getattr(manager, 'activate')",
        "from azazel_nexus.activation import innocuous_name",
        "manager.unmask_and_enable('evil.service')",
        "controller.activate(payload)",
        "dispatch_exposure(payload)",
        "get_credential(payload)",
        "transition(record, 'ACTIVE_BOUNDED')",
        "gate_exposure_proposal(payload)",
        "from azazel_nexus.activation import ActivationController as Innocent\nInnocent()",
        "from azazel_nexus.integration_broker.states import transition as t\nt(record, state)",
    ],
)
def test_scan_notices_a_planted_call_even_in_an_imported_helper(planted):
    sources = source_map()
    sources["azazel_nexus.advisory_response"] += "\nfrom . import planted_helper\n"
    sources["azazel_nexus.planted_helper"] = planted
    offenders, visited = scan(sources)
    assert "azazel_nexus.planted_helper" in visited
    assert offenders


@contextmanager
def runtime_scan():
    """Observe actual Python and C calls, without replacing the code under test."""
    seen = []
    forbidden = []

    def profile(frame, event, arg):
        if event == "call":
            module = frame.f_globals.get("__name__", "")
            name = frame.f_code.co_name
            if module.startswith(("azazel_nexus.", "azazel_nexus_runtime.")):
                seen.append((module, name))
                if (
                    set(module.split(".")) & PRIVILEGED_MODULES
                    or name in PRIVILEGED_CALLS
                ):
                    forbidden.append((module, name))
        elif event == "c_call" and getattr(arg, "__name__", "") in {"eval", "exec"}:
            forbidden.append(("builtins", arg.__name__))

    previous = sys.getprofile()
    sys.setprofile(profile)
    try:
        yield seen, forbidden
    finally:
        sys.setprofile(previous)


def test_runtime_scan_self_check_detects_planted_privileged_call(monkeypatch):
    def get_credential(payload):
        return "planted-test-value"

    namespace = {"__name__": "azazel_nexus.planted"}
    planted = FunctionType(get_credential.__code__, namespace)
    monkeypatch.setattr(routing, "route_advisory", planted)
    with runtime_scan() as (_, forbidden):
        routing.route_advisory({})
    assert forbidden == [("azazel_nexus.planted", "get_credential")]


@pytest.mark.parametrize(
    "origin",
    [
        "external connector",
        "M.I.O. response",
        "Knowledge advisory",
        "Deception capability report",
    ],
)
@pytest.mark.parametrize(
    "attack",
    [
        "UnitManager.unmask_and_enable('evil.service')",
        "ActivationController.activate(payload)",
        "dispatch_exposure(payload); get_credential('admin')",
        "transition(record, 'ACTIVE_BOUNDED'); gate_exposure_proposal(payload)",
    ],
)
def test_external_content_stays_data_at_runtime(data_args, origin, attack):
    before = data_args["adapter_record"]
    if origin != "external connector":
        data_args["manifest"] = Manifest(capability_set=frozenset({"advisory_read"}))
    route = (
        routing.route_telemetry
        if origin == "external connector"
        else routing.route_advisory
    )
    with runtime_scan() as (seen, forbidden):
        record = route({"text": attack}, **data_args)
        if origin == "M.I.O. response":
            try:
                read_advisory(json.dumps({"advice": attack}).encode())
            except AdvisoryRefused:
                pass
    assert isinstance(record, routing.DataRecord)
    assert record.trust == "untrusted data"
    assert forbidden == []
    assert ("azazel_nexus.integration_broker.routing", "_route") in seen
    assert data_args["adapter_record"] == before


def test_verified_knowledge_response_also_has_no_privileged_calls():
    from nacl.signing import SigningKey

    key = SigningKey.generate()
    endpoint = ProviderRecord(
        provider_id="knowledge-test",
        host="knowledge.example.test",
        port=443,
        path_template="/knowledge/v1",
        model_id="knowledge-v1",
        certificate_pin="sha256:" + "a" * 64,
        client_identity="knowledge-test",
        max_request_bytes=4096,
        max_response_bytes=8192,
        deadline_seconds=1,
        allowed_privacy_classes=(PrivacyClass.P1_SANITIZED,),
    )
    peer = KnowledgePeer(endpoint, ("127.0.0.1",), bytes(key.verify_key), 1)
    doc = {
        "schema": SCHEMA,
        "peer_id": endpoint.provider_id,
        "correlation": "c" * 32,
        "issued_at": ISSUED,
        "expires_at": EXPIRES,
        "bundle_version": "test-1",
        "facts": ["get_credential('admin')"],
        "inferences": ["transition(record, 'ACTIVE_BOUNDED')"],
    }
    payload = canonical(doc)
    raw = key.sign(RESPONSE_DOMAIN + payload).signature + payload
    with runtime_scan() as (seen, forbidden):
        context = read_context(raw, peer=peer, correlation="c" * 32, now=NOW)
    assert context.facts == tuple(doc["facts"])
    assert forbidden == []
    assert ("azazel_nexus.knowledge_peer", "read_context") in seen


def test_broker_and_cli_control_plane_has_no_host_privilege_or_transport():
    """Control-plane entry points can persist/audit and render, never execute.

    Content-plane scan above still forbids reaching these entry points. Unlike
    content routing, the broker must call states.transition to record lifecycle
    changes, and the read-only CLI must call the pure confinement renderer.
    """
    sources = source_map()
    for module in ("azazel_nexus.integration_broker.broker", "azazel_nexus.broker_cli"):
        tree = ast.parse(sources[module])
        imports = _local_imports(module, tree)
        assert not any(name.startswith("azazel_nexus_runtime") for name in imports)
        assert not any(set(name.split(".")) & {"activation", "activation_store", "units"}
                       for name in imports)
        calls = {node.func.attr if isinstance(node.func, ast.Attribute) else
                 node.func.id if isinstance(node.func, ast.Name) else ""
                 for node in ast.walk(tree) if isinstance(node, ast.Call)}
        assert not calls & (PRIVILEGED_CALLS - {"transition", "gate_exposure_proposal", "deliver"})
        if module.endswith("broker_cli"):
            assert not calls & {"admit", "withdraw_all", "gate", "deliver", "transition"}


def test_package_init_relative_import_reaches_helper():
    sources = {"demo": "from . import helper", "demo.helper": "alias = manager.activate"}
    offenders, visited = scan(sources, entries={"demo"})
    assert visited == {"demo", "demo.helper"} and offenders


def test_runtime_scan_checks_module_even_with_innocent_function_name():
    def innocuous(payload):
        return payload
    planted = FunctionType(innocuous.__code__, {"__name__": "azazel_nexus.activation"})
    with runtime_scan() as (_, forbidden):
        planted({})
    assert forbidden == [("azazel_nexus.activation", "innocuous")]


def test_reviewed_pure_body_exception_is_invalidated_by_a_change():
    sources = source_map()
    sources["azazel_nexus.mio_profile"] = sources["azazel_nexus.mio_profile"].replace(
        "getattr(self, field)", "getattr(self, supplied_name)")
    assert any(item[0] == "azazel_nexus.mio_profile" and item[2] == "dynamic_attribute"
               for item in scan(sources)[0])


@pytest.mark.parametrize("planted", ["import importlib.util", "import azazel_nexus.activation as harmless"])
def test_pure_fabric_exceptions_do_not_allow_a_new_import(planted):
    sources = source_map()
    sources["azazel_nexus.fabric_boundary"] += "\n" + planted + "\n"
    assert scan(sources)[0]
