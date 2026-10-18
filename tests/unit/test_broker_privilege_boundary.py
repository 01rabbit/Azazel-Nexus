"""Content-plane privilege guard, including imported local helper modules.

This is a conservative source scan, not a proof for arbitrary dynamic Python.
The runtime profile complements it on the concrete connector/advisory paths.
There is no Fabric Deception report transport yet: its opaque report enters
through route_advisory, and does not acquire a separate operational surface.
"""

import ast
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


def _local_imports(module, tree):
    """Resolve both relative imports and `from package import module` edges."""
    parent = module.rsplit(".", 1)[0]
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
        imports = _local_imports(module, tree)
        for name in imports:
            # Lane D shares the pure lifecycle data types. This grants no
            # transition call: widening and aliased transition imports remain
            # forbidden, including the planted-call checks below.
            if module == "azazel_nexus.integration_broker.routing" and name in {
                "azazel_nexus.integration_broker.states",
                "azazel_nexus.integration_broker.states.AdapterRecord",
                "azazel_nexus.integration_broker.states.BrokerState",
            }:
                continue
            if (
                name.startswith("azazel_nexus_runtime")
                or set(name.split(".")) & PRIVILEGED_MODULES
            ):
                offenders.append((module, "import", name))
            if name in sources:
                pending.append(name)
        # Bare imported aliases and attribute calls are both checked. Imports
        # from privileged modules are independently refused, even if aliased.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else (node.func.attr if isinstance(node.func, ast.Attribute) else "")
            )
            if name in PRIVILEGED_CALLS:
                offenders.append((module, node.lineno, name))
    return offenders, visited


def source_map():
    return {
        ".".join(path.relative_to(LIBRARY).with_suffix("").parts): path.read_text()
        for path in (LIBRARY / "azazel_nexus").rglob("*.py")
    }


def test_content_plane_and_all_local_imports_have_no_privileged_edges():
    offenders, visited = scan(source_map())
    assert ENTRY_MODULES <= visited
    assert "azazel_nexus.sanitizer" in visited  # not a vacuous root-only scan
    assert offenders == []


@pytest.mark.parametrize(
    "planted",
    [
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
