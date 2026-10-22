"""#196 G6 preparation D: this boot's names of the role interfaces, not wired.

`docs/deception-exposure-grant.md` §4.3, `docs/commissioning.md` §3 and §8,
`docs/deception-exposure-reachability.md` §6 "Interfaces". Pins that
`exposure_interfaces.resolve_role_interfaces` resolves the
`deception_bridge`, `management` and `observation` roles of a signed v3
proposal to this boot's kernel names by composite identity only; that an
ambiguous, missing or changed identity, or a name outside §4.3, withholds
with a fixed reason that carries no name or identity; that its output is
what `decoy_scope.render_scope_file` and
`decoy_reachability.pass_reachability_departures` take; and that nothing
calls it, so the tier is still withheld as `isolation_evidence_absent`.
"""

from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
import re

import pytest

from azazel_nexus import exposure_interfaces, fabric_boundary
from azazel_nexus.decoy_scope import DeceptionScope, parse_scope_file, render_scope_file
from azazel_nexus.exposure_interfaces import (
    ROLE_EVIDENCE_UNAVAILABLE,
    ROLE_INTERFACE_AMBIGUOUS,
    ROLE_INTERFACE_CODES,
    ROLE_INTERFACE_NAME_REFUSED,
    ROLE_INTERFACE_PHRASES,
    ROLE_INTERFACE_UNRESOLVED,
    ROLE_INVENTORY_CHANGED,
    ROLE_SCOPE_MISMATCH,
    RoleInterfaces,
    resolve_role_interfaces,
)

REPO = Path(__file__).resolve().parents[2]

needs_fabric = pytest.mark.skipif(importlib.util.find_spec("azazel_fabric") is None,
                                  reason="the pinned Fabric is not installed")

SCOPE = {"approved_v4": ["10.20.0.0/24", "192.168.10.0/24"],
         "bridge_prefix": "10.255.196.0/30", "ingress_role": "deception_bridge"}
CONFIRMED_AT = "2026-10-13T00:00:00Z"

#: Every identity value of the fixture's interfaces, none of which may
#: appear in a reason.
_THIRD = dict(interface_key="if-c", bus_path="pci-0000:04:00.0",
              permanent_mac="02:00:00:00:00:0c", pci_id="8086:15b8", serial="NIC-C-0003",
              driver="e1000e", driver_version="3.2.6-k", firmware_version="0.8-4",
              physical_label="LAN3")
_FOURTH = dict(_THIRD, interface_key="if-d", bus_path="pci-0000:05:00.0",
               permanent_mac="02:00:00:00:00:0d", serial="NIC-D-0004", physical_label="LAN4")

#: if-a observation, if-b deception_bridge, if-c management (as `_node` assigns).
NAMES = {"if-a": "mon0", "if-b": "lan0", "if-c": "mgmt0"}
ROLES = {"if-a": "observation", "if-b": "deception_bridge", "if-c": "management"}


def _refusal(code):
    return f"{code}: {ROLE_INTERFACE_PHRASES[code]}"


# -- the fixture: a three-NIC node commissioned with a v3 proposal ---------------


def _inventory(interfaces, *, inventory_id="inv-golden-1",
               collected_at="2026-09-01T00:00:00+00:00"):
    from azazel_fabric.provisioning_contracts import HardwareInventory, content_digest
    from azazel_fabric.testing.provisioning import golden_hardware_inventory

    document = golden_hardware_inventory()
    document.update(interfaces=interfaces, inventory_id=inventory_id,
                    collected_at=collected_at, inventory_digest="sha256:" + "0" * 64)
    draft = HardwareInventory.model_validate(document)
    digest = content_digest(draft, digest_field="inventory_digest")
    return HardwareInventory.model_validate(dict(document, inventory_digest=digest))


def _interfaces(names=NAMES, extra=()):
    from azazel_fabric.testing.provisioning import golden_hardware_inventory

    interfaces = [*golden_hardware_inventory()["interfaces"], dict(_THIRD)]
    for interface in interfaces:
        interface["kernel_name_observed"] = names.get(interface["interface_key"])
    return [*interfaces, *(dict(item) for item in extra)]


def _node(names=NAMES, roles=ROLES, extra=()):
    """The retained context: inventory, resource and topology, and the roles."""

    from azazel_fabric.provisioning_contracts import (
        InterfaceAssignment, InterfaceIdentitySelector, ResourceProfile, TopologyProfile)
    from azazel_fabric.testing.provisioning import (
        golden_interface_assignment, golden_resource_profile, golden_topology_profile)

    inventory = _inventory(_interfaces(names, extra))
    digest = inventory.inventory_digest
    template = InterfaceAssignment.model_validate(golden_interface_assignment())
    assignments = []
    for identity in inventory.interfaces:
        role = roles.get(identity.interface_key)
        if role is None:
            continue
        selector = InterfaceIdentitySelector(**{
            name: getattr(identity, name) for name in InterfaceIdentitySelector.model_fields
            if name != "schema_version"})
        assignments.append(template.model_copy(update={
            "assignment_id": f"assign-{identity.interface_key}", "role": role,
            "selector": selector, "inventory_digest": digest}))
    topology = golden_topology_profile()
    topology = TopologyProfile.model_validate(dict(
        topology, hardware_inventory_digest=digest,
        commissioned_assignments=[a.model_dump(mode="json") for a in assignments],
        unassigned_interface_keys=sorted(
            i.interface_key for i in inventory.interfaces if i.interface_key not in roles)))
    resource = golden_resource_profile()
    resource = ResourceProfile.model_validate(dict(resource, hardware_inventory_digest=digest))
    return dict(inventory=inventory, resource_profile=resource, topology_profile=topology,
                record_id="record-synthetic", operator="operator-a", confirmed_at=CONFIRMED_AT)


def _proposal(context, scope=SCOPE):
    from azazel_nexus.commissioning_approval import commissioning_proposal_payload

    return json.loads(commissioning_proposal_payload(
        **context, mio_profile="FULL", deception_scope=json.loads(json.dumps(scope))))


def _scope(context, scope=SCOPE):
    from azazel_nexus.decoy_scope import decode_deception_scope

    return decode_deception_scope(json.loads(json.dumps(scope)),
                                  assignments=fabric_boundary.deception_scope_assignments(
                                      context["inventory"], context["topology_profile"]))


def _current(names=NAMES, extra=(), **changes):
    """This boot's inventory: a later snapshot of the same hardware."""

    interfaces = _interfaces(names, extra)
    for key, update in changes.items():
        for interface in interfaces:
            if interface["interface_key"] == key.replace("_", "-"):
                interface.update(update)
    return _inventory(interfaces, inventory_id="inv-boot-2",
                      collected_at="2026-10-22T00:00:00+00:00")


_DEFAULT = object()


def _resolve(context=None, *, proposal=_DEFAULT, current=_DEFAULT, scope=_DEFAULT):
    context = context or _node()
    return resolve_role_interfaces(
        proposal=_proposal(context) if proposal is _DEFAULT else proposal,
        current_inventory=_current() if current is _DEFAULT else current,
        scope=_scope(context) if scope is _DEFAULT else scope)


# -- what it resolves -------------------------------------------------------------


@needs_fabric
def test_each_role_resolves_to_this_boots_name_by_identity():
    assert _resolve() == RoleInterfaces(ingress=("lan0",), management=("mgmt0",),
                                        observation=("mon0",))


@needs_fabric
def test_the_snapshot_metadata_of_this_boot_is_not_compared():
    context = _node()
    assert _resolve(context, current=context["inventory"]) == _resolve(context)


@needs_fabric
def test_several_ingress_interfaces_come_sorted_for_the_scope_file():
    names = {"if-a": "mon0", "if-b": "lan9", "if-c": "lan1"}
    context = _node(names, {"if-a": "observation", "if-b": "deception_bridge",
                            "if-c": "deception_bridge"})
    assert _resolve(context, current=_current(names)) == RoleInterfaces(
        ingress=("lan1", "lan9"), management=(), observation=("mon0",))


@needs_fabric
def test_no_management_role_is_empty_not_refused():
    context = _node(roles={"if-a": "observation", "if-b": "deception_bridge"})
    assert _resolve(context) == RoleInterfaces(("lan0",), (), ("mon0",))


@needs_fabric
def test_an_interface_of_no_role_is_neither_named_nor_checked():
    names = dict(NAMES, **{"if-c": "az-decoy0"})
    context = _node(names, roles={"if-a": "observation", "if-b": "deception_bridge"})
    assert _resolve(context, current=_current(names)) == RoleInterfaces(
        ("lan0",), (), ("mon0",))


@needs_fabric
def test_the_ingress_renders_the_scope_file():
    context = _node()
    resolved = _resolve(context)
    scope_file = parse_scope_file(render_scope_file(_scope(context), resolved.ingress))
    assert scope_file.ingress == ("lan0",)


@needs_fabric
def test_the_roles_are_what_the_pass_judgement_takes():
    from azazel_nexus_runtime.decoy_reachability import pass_reachability_departures
    import test_decoy_reachability as reach

    resolved = _resolve()
    args = dict(ingress=resolved.ingress, management=resolved.management,
                observation=resolved.observation)
    ipv4, ipv6 = reach._ipv4(eth9=None), reach._ipv6()
    rules, routes = reach._rules(ingress=resolved.ingress), reach._routes()
    assert pass_reachability_departures(ipv4, ipv6, rules, routes, **args) == ()
    ipv4["mgmt0"] = {"forwarding": 1}
    assert pass_reachability_departures(ipv4, ipv6, rules, routes, **args) == (
        "forwarding_role_on",)


# -- what it refuses ---------------------------------------------------------------


@needs_fabric
@pytest.mark.parametrize("proposal", [None, [], "proposal", 3, {}, {"schema": None}])
def test_evidence_that_cannot_be_restored_withholds(proposal):
    context = _node()
    reason = resolve_role_interfaces(proposal=proposal, current_inventory=_current(),
                                     scope=_scope(context))
    assert reason == _refusal(ROLE_EVIDENCE_UNAVAILABLE)


@needs_fabric
def test_a_v2_proposal_has_no_scope_and_withholds():
    from azazel_nexus.commissioning_approval import commissioning_proposal_payload

    context = _node()
    v2 = json.loads(commissioning_proposal_payload(**context, mio_profile="FULL"))
    assert _resolve(context, proposal=v2) == _refusal(ROLE_EVIDENCE_UNAVAILABLE)


@needs_fabric
def test_one_interface_in_two_roles_never_reaches_a_name():
    context = _node()
    proposal = _proposal(context)
    assignments = proposal["topology"]["commissioned_assignments"]
    management = next(a for a in assignments if a["role"] == "management")
    bridge = next(a for a in assignments if a["role"] == "deception_bridge")
    management["selector"] = bridge["selector"]
    assert _resolve(context, proposal=proposal) == _refusal(ROLE_EVIDENCE_UNAVAILABLE)


@needs_fabric
def test_another_scope_withholds():
    context = _node()
    other = dict(SCOPE, approved_v4=["10.20.0.0/24"])
    assert _resolve(context, scope=_scope(context, other)) == _refusal(ROLE_SCOPE_MISMATCH)
    scope = _scope(context)
    for changed in (DeceptionScope(scope.approved_v4, ("if-c",)),
                    DeceptionScope(scope.approved_v4, ("if-b", "if-c")),
                    DeceptionScope(scope.approved_v4, ()),
                    None, {"approved_v4": SCOPE["approved_v4"]}, "scope"):
        assert _resolve(context, scope=changed) == _refusal(ROLE_SCOPE_MISMATCH)


@needs_fabric
@pytest.mark.parametrize("current", [
    lambda: _current(dict(NAMES, **{"if-b": "lan7"})),            # renamed: no rebinding
    lambda: _current(if_b={"serial": "NIC-B-9999"}),               # adapter swapped
    lambda: _current(if_c={"firmware_version": "0.9-1"}),          # firmware changed
    lambda: _current(if_a={"bus_path": "pci-0000:09:00.0"}),       # slot moved
    lambda: _current(extra=(dict(_FOURTH, kernel_name_observed="eth4"),)),  # added
    lambda: _inventory(_interfaces()[:2], inventory_id="inv-boot-2",
                       collected_at="2026-10-22T00:00:00+00:00"),  # removed
    lambda: _current().model_dump(mode="json"),                    # not a record
    lambda: None,
])
def test_an_inventory_that_is_not_the_commissioned_one_withholds(current):
    assert _resolve(current=current()) == _refusal(ROLE_INVENTORY_CHANGED)


@needs_fabric
def test_an_earlier_snapshot_withholds():
    current = _inventory(_interfaces(), inventory_id="inv-boot-0",
                         collected_at="2026-08-01T00:00:00+00:00")
    assert _resolve(current=current) == _refusal(ROLE_INVENTORY_CHANGED)


@needs_fabric
@pytest.mark.parametrize("role", ["deception_bridge", "management", "observation"])
def test_a_role_interface_without_a_name_withholds(role):
    key = next(k for k, r in ROLES.items() if r == role)
    names = {k: v for k, v in NAMES.items() if k != key}
    context = _node(names)
    assert _resolve(context, current=_current(names)) == _refusal(ROLE_INTERFACE_UNRESOLVED)


@needs_fabric
def test_an_identity_resolving_to_several_interfaces_withholds(monkeypatch):
    """Fabric's rule, not restated: several matches are refused as zero are."""

    from azazel_fabric.provisioning_contracts import InterfaceResolutionError

    def several(identities, selector):
        raise InterfaceResolutionError("2 inventory interfaces match")

    monkeypatch.setattr(exposure_interfaces, "identify_interface", several)
    assert _resolve() == _refusal(ROLE_INTERFACE_UNRESOLVED)


@needs_fabric
@pytest.mark.parametrize("names, extra", [
    ({"if-a": "mon0", "if-b": "lan0", "if-c": "lan0"}, ()),        # two roles, one name
    ({"if-a": "lan0", "if-b": "lan0", "if-c": "mgmt0"}, ()),
    (NAMES, (dict(_FOURTH, kernel_name_observed="lan0"),)),        # a roleless twin
    (NAMES, (dict(_FOURTH, kernel_name_observed="mgmt0"),)),
])
def test_a_name_of_more_than_one_interface_withholds(names, extra):
    context = _node(names, extra=extra)
    assert (_resolve(context, current=_current(names, extra))
            == _refusal(ROLE_INTERFACE_AMBIGUOUS))


@needs_fabric
@pytest.mark.parametrize("name", [
    "az-decoy0", "AZ-DECOY1", "az-decoyx", "lo", "LO", "all", "default", ".", "..",
    "-eth0", "1234", "eth0 ", "eth0;", "a" * 16, "ethé", "",
])
@pytest.mark.parametrize("key", ["if-a", "if-b", "if-c"])
def test_a_role_interface_name_outside_section_4_3_withholds(name, key):
    names = dict(NAMES, **{key: name})
    context = _node(names)
    expected = ROLE_INTERFACE_UNRESOLVED if name == "" else ROLE_INTERFACE_NAME_REFUSED
    assert _resolve(context, current=_current(names)) == _refusal(expected)


@needs_fabric
def test_no_reason_carries_a_name_or_an_identity():
    reasons = {
        _resolve(proposal={}),
        _resolve(scope=None),
        _resolve(current=_current(dict(NAMES, **{"if-b": "lan7"}))),
        _resolve(_node({"if-a": "mon0", "if-c": "mgmt0"}),
                 current=_current({"if-a": "mon0", "if-c": "mgmt0"})),
        _resolve(_node({"if-a": "mon0", "if-b": "lan0", "if-c": "lan0"}),
                 current=_current({"if-a": "mon0", "if-b": "lan0", "if-c": "lan0"})),
        _resolve(_node(dict(NAMES, **{"if-b": "az-decoy0"})),
                 current=_current(dict(NAMES, **{"if-b": "az-decoy0"}))),
    }
    assert reasons == {_refusal(code) for code in ROLE_INTERFACE_CODES}
    identity = [value for interface in _interfaces(extra=(_FOURTH,))
                for value in interface.values() if isinstance(value, str)]
    forbidden = {*identity, *NAMES.values(), "lan7", "az-decoy0", "if-", "sha256", ":0"}
    forbidden -= {"interface-identity/v0.1"}
    for reason in reasons:
        for value in forbidden:
            assert value not in reason, (reason, value)


def test_every_reason_is_a_fixed_code_and_phrase():
    assert set(ROLE_INTERFACE_PHRASES) == set(ROLE_INTERFACE_CODES)
    for code, phrase in ROLE_INTERFACE_PHRASES.items():
        assert re.fullmatch(r"role_[a-z_]+", code)
        assert re.fullmatch(r"[a-z' ,.]+", phrase), phrase


def test_without_the_pinned_fabric_it_withholds(monkeypatch):
    monkeypatch.setattr(fabric_boundary, "_import_fabric", lambda: (None, "absent"))
    reason = resolve_role_interfaces(proposal={"schema": "x"}, current_inventory=None,
                                     scope=None)
    assert reason == _refusal(ROLE_EVIDENCE_UNAVAILABLE)


@pytest.mark.parametrize("bad", [None, 0, "x", b"x", [], (), {}, object()])
def test_an_argument_of_any_shape_gives_a_reason_never_an_exception(bad):
    for kwargs in (dict(proposal=bad, current_inventory=None, scope=None),
                   dict(proposal={}, current_inventory=bad, scope=bad)):
        reason = resolve_role_interfaces(**kwargs)
        assert reason in {_refusal(code) for code in ROLE_INTERFACE_CODES}


# -- not wired -------------------------------------------------------------------
#
# As preparation C (`test_exposure_g6_parts.py`): a static layer (no product
# module imports or names the part; its own imports are pure) and a dynamic
# one (a pass with the part replaced by one that fails when called still
# withholds the tier and calls it not). G6 replaces these, not loosens them.


def _product_modules():
    for base in (REPO / "src", REPO / "runtime" / "src"):
        yield from sorted(base.rglob("*.py"))


def _imported(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            names.add((node.module or "").rsplit(".", 1)[-1])
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            names.update(alias.name.rsplit(".", 1)[-1] for alias in node.names)
    return names


def test_no_product_module_imports_or_names_it():
    for path in _product_modules():
        if path.name == "exposure_interfaces.py":
            continue
        assert "exposure_interfaces" not in _imported(path), path
        text = path.read_text(encoding="utf-8")
        for name in ("exposure_interfaces", "resolve_role_interfaces", "RoleInterfaces",
                     *ROLE_INTERFACE_CODES):
            assert not re.search(rf"\b{name}\b", text), (path, name)


def test_it_reads_writes_and_runs_nothing():
    source = (REPO / "src" / "azazel_nexus" / "exposure_interfaces.py").read_text(
        encoding="utf-8")
    tree = ast.parse(source)
    imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                 for alias in node.names}
    assert imported == {"__future__", "dataclasses", "typing", "decoy_scope",
                        "fabric_boundary"}
    calls = {node.func.id for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert not calls & {"open", "exec", "eval", "__import__", "print"}
    code = source.replace(ast.get_docstring(tree, clean=False), "")
    assert "/run/" not in code and "environ" not in code and "getenv" not in code


def test_the_tier_is_still_withheld_unconditionally():
    from azazel_nexus import activation
    from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST

    source = Path(activation.__file__).read_text(encoding="utf-8")
    method = next(node for node in ast.walk(ast.parse(source))
                  if isinstance(node, ast.FunctionDef) and node.name == "_withholding_reason")
    body = ast.get_source_segment(source, method)
    branch = body[body.index("if definition.tier is UnitTier.DECEPTION_EXPOSURE:"):
                  body.index("if definition.tier is UnitTier.EDGE_BASELINE:")]
    assert re.findall(r'return \(\s*"([a-z_]+):', branch) == [
        "exposure_tier_partial", "isolation_evidence_absent"]
    for unit in activation.DECEPTION_EXPOSURE_UNITS:
        assert unit not in ACTIVATION_UNIT_ALLOWLIST


def test_a_pass_with_the_part_poisoned_still_withholds_the_tier(tmp_path, monkeypatch):
    import test_activation as ta
    from azazel_nexus.activation import (
        ARTIFACT_TRANSPORT,
        DECEPTION_EXPOSURE_UNITS,
        LOCAL_MODEL_PROVIDER,
        REMOTE_INFERENCE_TRANSPORT,
        EdgeBaselineState,
    )

    calls = []

    def poisoned(*args, **kwargs):
        calls.append("resolve_role_interfaces")
        raise AssertionError("resolve_role_interfaces was called")

    monkeypatch.setattr(exposure_interfaces, "resolve_role_interfaces", poisoned)
    monkeypatch.setattr(exposure_interfaces, "_resolve", poisoned)
    controller, _, _, _ = ta._controller(tmp_path)
    outcome = controller.activate(
        now=ta.NOW, actor=ta.ACTOR, lease=ta._lease(),
        edge=EdgeBaselineState(True, True, True, True, True), healthy=True,
        record=ta._record(roles=(ta._confirmed_role(),)),
        wired=(ARTIFACT_TRANSPORT, LOCAL_MODEL_PROVIDER, REMOTE_INFERENCE_TRANSPORT),
    )
    assert calls == []
    for unit in DECEPTION_EXPOSURE_UNITS:
        verdict = next(v for v in outcome.verdicts if v.unit == unit)
        assert not verdict.granted
        assert verdict.reason.startswith("isolation_evidence_absent")
