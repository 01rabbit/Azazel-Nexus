"""#196 G6: who reaches each G6 part, and what stays unwired.

`docs/deception-exposure-grant.md` §9 (the G6 row and its preparations A, C
and D, and the v3 decoder row), preparation K's record decoder
(`apparmor_compiled`, wiring §5.2) and B1's route-netlink dumps
(`exposure_route_dump`, wiring §4.4). Before G6 this file pinned that none
of the parts was reached; G6 (`docs/deception-exposure-wiring.md` §4 to §6)
wired them, so it now pins, from one table, **exactly** who reaches each:

* `IMPORTERS`: each part's module and the exact set of files that may
  import it, statically (`import`, `from ... import`, relative or not) or
  dynamically (a string naming it inside an `importlib`, `__import__` or
  `runpy` call);
* `NAME_FILES`: each public name of a part (functions, types, reason codes,
  the v3 schema's spellings) and the exact set of files that may contain it.

Both are compared, as sets, with what one scan finds in every file
`git ls-files` lists outside `tests/` and `docs/` (the names in every such
file, the imports in every `.py`). Without git, or with an empty listing,
the tests fail rather than skip: the property is not established without
the listing.

**What stays unwired** is guarded here too: the composed LSM helpers
(`exposure_lsm_withholding`, `read_exposure_lsm_policy`; the pass asks the
three judgements at P3 and P11 apart), the record's encoder (the
installer's tool alone) and the route dump's parsers (inside their module).

And a dynamic layer, replacing the old "poisoned pass" (§7 item 11: the
tests of the preparations are replaced by tests of the order, not deleted):

* the library half of the tier reads the pass's evidence only, in the
  order L1 to L5, and names no part's reading;
* a pass whose lease does not name the tier, with every part replaced by
  one that fails when called, calls none of them and withholds the tier;
* a full exposure grant (`test_runtime_exposure_pass.ExposureWorld`) with
  the still-unwired helpers poisoned calls none of them.
The order of the stages themselves is `test_runtime_exposure_pass.py`.
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import inspect
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from azazel_nexus import exposure_exclusivity, exposure_interfaces
from azazel_nexus.activation import (
    ARTIFACT_TRANSPORT,
    CORE_UNITS,
    DECEPTION_EXPOSURE_UNITS,
    LOCAL_MODEL_PROVIDER,
    REMOTE_INFERENCE_TRANSPORT,
    ActivationLease,
    EdgeBaselineState,
)
from azazel_nexus_runtime import (
    activation_unit_files,
    decoy_apparmor,
    decoy_reachability,
    decoy_residue,
    exposure_generation,
    exposure_withholding,
)

REPO = Path(__file__).resolve().parents[2]

_LIB = "src/azazel_nexus/"
_RT = "runtime/src/azazel_nexus_runtime/"
V3 = _LIB + "activation_approval_v3.py"
EXCLUSIVITY = _LIB + "exposure_exclusivity.py"
INTERFACES = _LIB + "exposure_interfaces.py"
ACTIVATION = _LIB + "activation.py"
STORE = _LIB + "activation_store.py"
OBSERVE = _LIB + "observe_baseline.py"
TRUST = _LIB + "operator_trust.py"
APPARMOR = _RT + "decoy_apparmor.py"
GENERATION = _RT + "exposure_generation.py"
WITHHOLDING = _RT + "exposure_withholding.py"
REACHABILITY = _RT + "decoy_reachability.py"
RESIDUE = _RT + "decoy_residue.py"
UNIT_FILES = _RT + "activation_unit_files.py"
WATCH = _RT + "decoy_watch.py"
COMPILED = _RT + "apparmor_compiled.py"
RECORD_TOOL = "tools/record_apparmor_compiled.py"
ROUTE_DUMP = _RT + "exposure_route_dump.py"
#: The wiring (#196 G6): step 10, the pass, the controller, the CLI, the bus.
EXPOSURE_PASS = _RT + "exposure_pass.py"
PASS = _RT + "activation_pass.py"
ACTIVATED = _RT + "activated.py"
CLI = _RT + "activation_cli.py"
BUS = _RT + "systemd_bus.py"
SIGNER = "tools/operator_sign.py"

# -- the table: every edit of it is a reviewed change of who reaches a part ---

#: Part module -> the files that may import it.
IMPORTERS: dict[str, frozenset[str]] = {
    # v3 (wiring §5.1): read by the store's one loader, accepted by the pass
    # and its tripwire, requested and installed by `az-activation`, signed by
    # the signer under its own purpose, checked by step 10's P1.
    "azazel_nexus.activation_approval_v3": frozenset({
        STORE, PASS, ACTIVATED, CLI, EXPOSURE_PASS, SIGNER}),
    # L2 (Q-E): the controller's exposure branch, lazily.
    "azazel_nexus.exposure_exclusivity": frozenset({ACTIVATION}),
    # P6 only.
    "azazel_nexus.exposure_interfaces": frozenset({EXPOSURE_PASS}),
    "azazel_nexus_runtime.exposure_withholding": frozenset({EXPOSURE_PASS}),
    # P9 and `generation-publish`.
    "azazel_nexus_runtime.exposure_generation": frozenset({EXPOSURE_PASS, CLI}),
    "azazel_nexus_runtime.decoy_residue": frozenset({EXPOSURE_PASS}),
    # The verify shares the reads and the R4 judgement (preparation A); P7.
    "azazel_nexus_runtime.decoy_reachability": frozenset({WATCH, EXPOSURE_PASS}),
    # The unit renderer, the install plan and the wrapper check use the
    # profile names; `exposure_generation` takes the four from here; P3, P11.
    "azazel_nexus_runtime.decoy_apparmor": frozenset({
        _RT + "hardening.py", _RT + "install_platform.py", GENERATION, EXPOSURE_PASS,
        "tools/check_decoy_apparmor_wrappers.py"}),
    # Preparation K: written by the installer's tool, read by
    # `generation-publish` (and `request`, `install`); never by the pass.
    "azazel_nexus_runtime.apparmor_compiled": frozenset({RECORD_TOOL, CLI}),
    # B1 (wiring §4.4, §9 Q-N): only step 10 imports the route dumps.
    "azazel_nexus_runtime.exposure_route_dump": frozenset({EXPOSURE_PASS}),
}


def _only(files, *names):
    return dict.fromkeys(names, frozenset(files))


#: Public name of a part -> the files that may contain it (as a substring).
NAME_FILES: dict[str, frozenset[str]] = {
    # v3 (wiring §5.1).
    **_only({V3, STORE, PASS, ACTIVATED, CLI, EXPOSURE_PASS, SIGNER},
            "activation_approval_v3"),
    **_only({V3, STORE, CLI, SIGNER}, "activation-approval/v3"),
    **_only({V3, STORE, PASS, ACTIVATED, CLI, EXPOSURE_PASS}, "ApprovalV3"),
    **_only({V3, SIGNER}, "decode_activation_approval_v3"),
    **_only({V3, STORE}, "verify_activation_approval_v3"),
    **_only({V3, CLI}, "activation_approval_v3_payload"),
    # v3's fields (V2): requested, printed by the signer, compared at P10.
    **_only({V3, CLI, EXPOSURE_PASS, SIGNER}, "exposure_scope_digest",
            "exposure_prefix_count", "exposure_ingress_count"),
    # Its purpose (Q-C): the trust defines it, v3 verifies under it, the
    # signer offers it; `az-activation request` names it in its hint.
    **_only({V3, TRUST, SIGNER}, "ACTIVATION_EXPOSURE"),
    **_only({V3, TRUST, SIGNER, CLI}, "activation-exposure"),
    # Preparation C.
    **_only({UNIT_FILES, GENERATION}, "measure_exposure_unit_files"),
    # Composed helpers the pass does not use: stay unwired.
    **_only({APPARMOR, GENERATION, WITHHOLDING}, "exposure_lsm_withholding"),
    **_only({APPARMOR}, "read_exposure_lsm_policy"),
    **_only({APPARMOR, GENERATION, EXPOSURE_PASS}, "policy_hash_refusal",
            "expected_policy_hashes"),
    **_only({APPARMOR, EXPOSURE_PASS, BUS}, "loaded_unit_profile_refusal"),
    **_only({APPARMOR, EXPOSURE_PASS}, "read_policy_hashes", "exposure_lsm_refusal",
            "read_exposure_lsm"),
    **_only({APPARMOR}, *decoy_apparmor.LSM_REASON_CODES),
    **_only({APPARMOR}, *(set(decoy_apparmor.LSM_LOADED_REASON_CODES)
                          - {decoy_apparmor.LSM_POLICY_UNVERIFIABLE})),
    # P11 names its refusal for a section that is not closed; the
    # section's reader says which code that becomes.
    **_only({APPARMOR, GENERATION}, decoy_apparmor.LSM_POLICY_UNVERIFIABLE),
    **_only({WITHHOLDING, EXPOSURE_PASS, BUS}, "host_firewall_refusal"),
    **_only({WITHHOLDING, EXPOSURE_PASS}, "fb_tunnels_refusal", "read_fb_tunnels"),
    **_only({WITHHOLDING}, *exposure_withholding.HOST_FIREWALL_REASON_CODES,
            *exposure_withholding.FB_TUNNELS_REASON_CODES),
    **_only({EXCLUSIVITY, ACTIVATION}, "exposure_enforcement_conflict"),
    **_only({EXCLUSIVITY}, *exposure_exclusivity.EXPOSURE_ENFORCEMENT_CODES),
    **_only({GENERATION, CLI, OBSERVE}, "build_exposure_section"),
    **_only({GENERATION, EXPOSURE_PASS, OBSERVE}, "verify_exposure_section"),
    **_only({GENERATION, CLI, UNIT_FILES, EXPOSURE_PASS}, "measure_exposure_section_inputs"),
    **_only({GENERATION}, "measure_apparmor_profile_files",
            *exposure_generation.EXPOSURE_SECTION_CODES),
    # Preparation D. CI names the test file `test_exposure_interfaces.py`.
    **_only({EXPOSURE_PASS, ".github/workflows/ci.yml"}, "exposure_interfaces"),
    **_only({INTERFACES, EXPOSURE_PASS}, "resolve_role_interfaces", "RoleInterfaces"),
    **_only({INTERFACES}, *exposure_interfaces.ROLE_INTERFACE_CODES),
    # Preparation A: what only the pass uses (the rest is the verify's).
    **_only({REACHABILITY, EXPOSURE_PASS}, "pass_reachability_departures",
            "reachability_refusal"),
    **_only({REACHABILITY}, "conf_entry_path", decoy_reachability.FORWARDING_ROLE_ON),
    **_only({RESIDUE, EXPOSURE_PASS, BUS}, "exposure_residue_departures"),
    **_only({RESIDUE, EXPOSURE_PASS}, "residue_refusal", "read_netns"),
    **_only({RESIDUE}, *decoy_residue.RESIDUE_CODES),
    # Preparation K: the record's encoder stays the tool's.
    **_only({COMPILED, RECORD_TOOL, CLI}, "decode_apparmor_compiled"),
    **_only({COMPILED, RECORD_TOOL}, "encode_apparmor_compiled", "normalize_parser_version",
            "ApparmorCompiled"),
    **_only({COMPILED}, "azazel-nexus/apparmor-compiled/v1"),
    **_only({COMPILED, RECORD_TOOL, CLI, "packaging/install.sh"}, "apparmor-compiled.json"),
    **_only({COMPILED, RECORD_TOOL, CLI, APPARMOR, "packaging/install.sh",
             "tools/build_offline_bundle.py"}, "apparmor_compiled"),
    **_only({COMPILED, APPARMOR, GENERATION, RECORD_TOOL, CLI, OBSERVE},
            "apparmor_policy_hashes"),
    # B1: step 10 alone; the reachability module's docstring names its source.
    **_only({ROUTE_DUMP, EXPOSURE_PASS, REACHABILITY}, "exposure_route_dump",
            "dump_ipv4_rules", "dump_main_routes"),
    **_only({ROUTE_DUMP}, "parse_rule_dump", "parse_route_dump", "rule_dump_request",
            "route_dump_request", "RouteDumpUnreadable"),
}

#: The reason codes of the parts.
REASON_CODES = (
    *decoy_apparmor.LSM_REASON_CODES, *decoy_apparmor.LSM_LOADED_REASON_CODES,
    *exposure_withholding.HOST_FIREWALL_REASON_CODES,
    *exposure_withholding.FB_TUNNELS_REASON_CODES,
    *exposure_exclusivity.EXPOSURE_ENFORCEMENT_CODES,
    *exposure_generation.EXPOSURE_SECTION_CODES, *exposure_interfaces.ROLE_INTERFACE_CODES,
    *decoy_reachability.PASS_REACHABILITY_CODES, *decoy_residue.RESIDUE_CODES,
)

#: Not public, or shared with code that runs today, so not in `NAME_FILES`;
#: replaced in the poisoned pass all the same.
ALSO_POISONED = {
    activation_unit_files: ("require_watch_unit_files",),
    decoy_reachability: ("read_sysctls",),
}

#: What stays unwired (#196 G6): never called by a pass, granting or not.
STILL_UNWIRED = (
    (decoy_apparmor, "exposure_lsm_withholding"),
    (decoy_apparmor, "read_exposure_lsm_policy"),
)

# -- the one scan ----------------------------------------------------------------


def _tracked() -> list[str]:
    """Every tracked path outside tests/ and docs/. Fails without git.

    The `.py` files under the two product trees are added even when not yet
    tracked, as the per-file scans this replaces read them from the disk."""
    listed = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"],
                            capture_output=True, check=True).stdout
    names = [name for name in listed.decode("utf-8").split("\0") if name]
    assert names, "git ls-files listed nothing"
    kept = [name for name in names if not name.startswith(("tests/", "docs/"))]
    on_disk = {path.relative_to(REPO).as_posix()
               for base in (REPO / "src", REPO / "runtime" / "src")
               for path in base.rglob("*.py")}
    kept = sorted(set(kept) | on_disk)
    for root in ("src/", "runtime/", "tools/", "bench/"):
        assert any(name.startswith(root) for name in kept), root
    listed_in_the_table = {_part_file(module) for module in IMPORTERS}
    listed_in_the_table |= {f for files in (*IMPORTERS.values(), *NAME_FILES.values())
                            for f in files}
    for path in listed_in_the_table:
        assert path in kept, path
    return kept


def _part_file(module: str) -> str:
    package, short = module.split(".")
    return (_RT if package == "azazel_nexus_runtime" else _LIB) + short + ".py"


_DYNAMIC = {"import_module", "__import__", "find_spec", "spec_from_file_location",
            "module_from_spec", "reload", "run_module", "run_path"}
#: The approval family: a dynamic string or a file importing dynamically may
#: not name it at all (v2 included), so no name assembled from pieces reaches v3.
_FAMILY = ("activation_approval", "approval_v")


def _static_imports(tree: ast.AST) -> set[str]:
    """Every module and alias name an import statement spells."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            found.add(node.module or "")
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
    return found


def _dynamic_strings(tree: ast.AST) -> list[str]:
    """Every string constant inside an importlib, `__import__` or runpy call."""
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name in _DYNAMIC:
            found.extend(sub.value for sub in ast.walk(node)
                         if isinstance(sub, ast.Constant) and isinstance(sub.value, str))
    return found


def _names_part(spelled: str, short: str) -> bool:
    """`decoy_apparmor`, `pkg.decoy_apparmor`, `.decoy_apparmor` and the like."""
    return spelled.rsplit(".", 1)[-1].endswith(short)


def _scan():
    """(importers per part, files per name, dynamic findings) of the tree."""
    importers = {module: set() for module in IMPORTERS}
    found = {name: set() for name in NAME_FILES}
    dynamic: list[tuple[str, str]] = []
    for rel in _tracked():
        path = REPO / rel
        if not path.is_file():
            continue
        raw = path.read_bytes()
        for name in NAME_FILES:
            if name.encode() in raw:
                found[name].add(rel)
        if path.suffix != ".py":
            continue
        text = raw.decode("utf-8")
        tree = ast.parse(text)
        spelled = _static_imports(tree)
        strings = _dynamic_strings(tree)
        uses_dynamic = any(f"{name}(" in text for name in _DYNAMIC)
        for module, allowed in IMPORTERS.items():
            short = module.rsplit(".", 1)[1]
            own = rel == _part_file(module)
            if any(_names_part(s, short) for s in spelled) and not own:
                importers[module].add(rel)
            if any(short in s for s in strings):
                importers[module].add(rel)
            # A name assembled from pieces would escape the line above, so
            # a file importing dynamically may not mention a part it may not
            # import.
            if uses_dynamic and short in text and not own and rel not in allowed:
                dynamic.append((rel, short))
        for value in strings:
            for word in _FAMILY:
                if word in value:
                    dynamic.append((rel, value))
        if uses_dynamic and rel != V3 and any(word in text for word in _FAMILY):
            dynamic.append((rel, "approval family named beside a dynamic import"))
    return importers, found, dynamic


@pytest.fixture(scope="module")
def scanned():
    return _scan()


def test_each_part_is_imported_by_exactly_its_listed_files(scanned):
    importers, _, _ = scanned
    assert {m: frozenset(f) for m, f in importers.items()} == IMPORTERS


def test_each_public_name_appears_in_exactly_its_listed_files(scanned):
    _, found, _ = scanned
    assert {n: frozenset(f) for n, f in found.items()} == NAME_FILES


def test_no_dynamic_import_reaches_a_part(scanned):
    _, _, dynamic = scanned
    assert dynamic == []


def test_the_table_names_real_parts():
    """A renamed part cannot leave a stale row passing vacuously."""
    for module in IMPORTERS:
        assert importlib.util.find_spec(module) is not None, module
    for module, names in ALSO_POISONED.items():
        for name in names:
            assert callable(getattr(module, name)), name


# -- the tier ------------------------------------------------------------------


def test_the_library_half_reads_the_evidence_only_in_the_order_l1_to_l5():
    """`_withholding_reason`'s branch for the tier (wiring §4.2): L1 the
    partial lease, L2 exclusivity, L3 the evidence's type, L4 its generation,
    L5 its refusal and stages; it names no reading of the host."""

    from azazel_nexus import activation

    source = Path(activation.__file__).read_text(encoding="utf-8")
    method = next(node for node in ast.walk(ast.parse(source))
                  if isinstance(node, ast.FunctionDef) and node.name == "_withholding_reason")
    body = ast.get_source_segment(source, method)
    branch = body[body.index("if definition.tier is UnitTier.DECEPTION_EXPOSURE:"):
                  body.index("if definition.tier is UnitTier.EDGE_BASELINE:")]
    order = ["exposure_tier_partial", "exposure_enforcement_conflict(",
             "EXPOSURE_EVIDENCE_ABSENT", "EXPOSURE_EVIDENCE_MISMATCH", "evidence.refusal",
             "EXPOSURE_STAGE_UNREADABLE", "return None"]
    positions = [branch.index(word) for word in order]
    assert positions == sorted(positions)
    assert "isolation_evidence_absent" not in source
    for word in ("reachability", "forwarding", "residue", "leftover", "lsm", "apparmor",
                 "firewall", "fb_tunnels", "netns", "scope_file", "read_"):
        assert word not in branch.lower(), word


#: What the five per-file poisoned passes replaced before they were merged
#: here (#196 L1): the merged one replaces at least these.
_POISONED_BEFORE = {
    "exposure_lsm_withholding", "loaded_unit_profile_refusal", "policy_hash_refusal",
    "read_policy_hashes", "read_exposure_lsm_policy", "exposure_lsm_refusal",
    "read_exposure_lsm", "host_firewall_refusal", "fb_tunnels_refusal", "read_fb_tunnels",
    "build_exposure_section", "verify_exposure_section", "measure_exposure_section_inputs",
    "measure_apparmor_profile_files", "expected_policy_hashes",
    "measure_exposure_unit_files", "require_watch_unit_files",
    "exposure_enforcement_conflict", "resolve_role_interfaces", "_resolve",
    "pass_reachability_departures", "read_sysctls", "reachability_refusal",
    "exposure_residue_departures", "read_netns", "residue_refusal",
}
#: Added since (#196 G6 preparation K and B1).
_POISONED_SINCE = {
    "decode_apparmor_compiled", "encode_apparmor_compiled", "normalize_parser_version",
    "dump_ipv4_rules", "dump_main_routes", "parse_rule_dump", "parse_route_dump",
}

#: Modules whose every function is a part (the others are shared and only
#: their names of the table are parts).
_WHOLE = {
    "azazel_nexus.exposure_exclusivity", "azazel_nexus.exposure_interfaces",
    "azazel_nexus_runtime.exposure_withholding", "azazel_nexus_runtime.exposure_generation",
    "azazel_nexus_runtime.decoy_residue", "azazel_nexus_runtime.apparmor_compiled",
    "azazel_nexus_runtime.exposure_route_dump",
}


def _poison(monkeypatch, originals: dict[int, str]) -> list[str]:
    calls: list[str] = []

    def poisoned(label):
        def call(*args, **kwargs):
            calls.append(label)
            raise AssertionError(f"{label} was called")
        return call

    for loaded in list(sys.modules.values()):
        if not getattr(loaded, "__name__", "").startswith("azazel_nexus"):
            continue
        for name, value in list(vars(loaded).items()):
            if id(value) in originals and inspect.isfunction(value):
                monkeypatch.setattr(loaded, name, poisoned(originals[id(value)]))
    return calls


def _poison_every_part(monkeypatch) -> list[str]:
    """Replace every function of every part module (the shared ones: their
    names of the table) and `ALSO_POISONED`, wherever a loaded module holds them."""

    originals: dict[int, str] = {}
    for module_name in IMPORTERS:
        module = importlib.import_module(module_name)
        for name, value in vars(module).items():
            if not inspect.isfunction(value) or value.__module__ != module_name:
                continue
            if module_name in _WHOLE or name in NAME_FILES:
                originals[id(value)] = f"{module_name}.{name}"
    for name in NAME_FILES:
        value = getattr(activation_unit_files, name, None)
        if inspect.isfunction(value):
            originals[id(value)] = f"activation_unit_files.{name}"
    for module, names in ALSO_POISONED.items():
        for name in names:
            originals[id(getattr(module, name))] = f"{module.__name__}.{name}"
    labels = {label.rsplit(".", 1)[1] for label in originals.values()}
    assert labels >= _POISONED_BEFORE, sorted(_POISONED_BEFORE - labels)
    assert labels >= _POISONED_SINCE, sorted(_POISONED_SINCE - labels)
    return _poison(monkeypatch, originals)


def test_a_pass_whose_lease_does_not_name_the_tier_reaches_no_part(tmp_path, monkeypatch):
    """The library's controller and the runtime pass, each with every part
    replaced by one that fails when called: a lease without the tier calls
    none of them (step 10 reads nothing, `not_in_scope`), the tier is
    withheld, and no part's reason code reaches a verdict or the ledger."""

    import test_activation as ta
    import test_runtime_activation_pass as trap

    calls = _poison_every_part(monkeypatch)

    (tmp_path / "library").mkdir()
    controller, units, ledger, _ = ta._controller(tmp_path / "library")
    lease = ta._lease()
    scoped = ActivationLease(
        granted_by=lease.granted_by, granted_at=lease.granted_at, expires_at=lease.expires_at,
        generation_digest=lease.generation_digest,
        units=frozenset(d.name for d in CORE_UNITS) - set(DECEPTION_EXPOSURE_UNITS))
    outcome = controller.activate(
        now=ta.NOW, actor=ta.ACTOR, lease=scoped,
        edge=EdgeBaselineState(True, True, True, True, True), healthy=True,
        record=ta._record(roles=(ta._confirmed_role(),)),
        wired=(ARTIFACT_TRANSPORT, LOCAL_MODEL_PROVIDER, REMOTE_INFERENCE_TRANSPORT),
    )
    for unit in DECEPTION_EXPOSURE_UNITS:
        verdict = next(v for v in outcome.verdicts if v.unit == unit)
        assert not verdict.granted and verdict.reason.startswith("outside_lease_scope")
        assert ("unmask_and_enable", unit) not in units.calls
    assert "azazel-edge-core.service" in outcome.granted
    reasons = [v.reason for v in outcome.verdicts if v.reason] + [
        entry.event.get("reason", "") for entry in ledger]
    assert not any(reason.startswith(code) for reason in reasons for code in REASON_CODES)

    (tmp_path / "runtime").mkdir()
    monkeypatch.setattr(trap.activation_markers, "_OWNER", os.getuid())
    monkeypatch.setattr(trap.activated, "_collect_input_status", lambda _root: {})
    trap._owned_by_the_test(monkeypatch)
    world = trap.World(tmp_path / "runtime")
    outcome = world.run()
    assert sorted(outcome.granted) == list(trap.SCOPE)
    for unit in DECEPTION_EXPOSURE_UNITS:
        assert unit in outcome.withheld
        assert world.manager.state(unit) is trap.UnitState.MASKED
    assert not set(DECEPTION_EXPOSURE_UNITS) & set(world.markers())
    assert world.inputs_event()["observed_inputs"]["exposure_evidence"] == "not_in_scope"

    assert calls == []


@pytest.mark.skipif(importlib.util.find_spec("azazel_fabric") is None,
                    reason="the pinned Fabric is not installed")
def test_a_full_exposure_grant_calls_none_of_the_still_unwired_helpers(tmp_path, monkeypatch):
    import test_runtime_activation_pass as trap
    import test_runtime_exposure_pass as tex

    originals = {id(getattr(module, name)): f"{module.__name__}.{name}"
                 for module, name in STILL_UNWIRED}
    calls = _poison(monkeypatch, originals)
    monkeypatch.setattr(trap.activation_markers, "_OWNER", os.getuid())
    monkeypatch.setattr(trap.activated, "_collect_input_status", lambda _root: {})
    trap._owned_by_the_test(monkeypatch)
    world = tex.ExposureWorld(tmp_path)
    outcome = world.run()
    assert set(DECEPTION_EXPOSURE_UNITS) <= set(outcome.granted)
    assert calls == []
