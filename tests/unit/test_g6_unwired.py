"""#196 G6 preparation, all parts at once: built and not wired.

`docs/deception-exposure-grant.md` §9 (the G6 row and its preparations A, C
and D, and the v3 decoder row), and preparation K's record decoder
(`apparmor_compiled`, wiring §5.2). The parts G6 is prepared with are each
tested on their own (`test_activation_approval_v3.py`,
`test_exposure_g6_parts.py`, `test_exposure_interfaces.py`,
`test_decoy_reachability.py`, `test_decoy_apparmor.py`); that **none of
them is reached** is pinned here once, from one table:

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

And a dynamic layer: a pass (the library's controller and the runtime
activation pass) with every part replaced by one that fails when called
calls none of them and withholds the tier as `isolation_evidence_absent`;
`_withholding_reason`'s branch for the tier is unchanged.

**G6 changes only the table.** Wiring a part in is an edit of `IMPORTERS`
and `NAME_FILES` (the pass, the controller or the library added to the
files of what it now calls), reviewed as such; the scan, the poisoned pass
and the branch check below change only when the tier itself is granted,
and then they are replaced, not loosened.
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
    DECEPTION_EXPOSURE_UNITS,
    LOCAL_MODEL_PROVIDER,
    REMOTE_INFERENCE_TRANSPORT,
    EdgeBaselineState,
)
from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST
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
APPARMOR = _RT + "decoy_apparmor.py"
GENERATION = _RT + "exposure_generation.py"
WITHHOLDING = _RT + "exposure_withholding.py"
REACHABILITY = _RT + "decoy_reachability.py"
RESIDUE = _RT + "decoy_residue.py"
UNIT_FILES = _RT + "activation_unit_files.py"
WATCH = _RT + "decoy_watch.py"
COMPILED = _RT + "apparmor_compiled.py"
RECORD_TOOL = "tools/record_apparmor_compiled.py"

# -- the table: the only thing G6 edits ------------------------------------------

#: Part module -> the files that may import it. Empty: nothing may.
IMPORTERS: dict[str, frozenset[str]] = {
    "azazel_nexus.activation_approval_v3": frozenset(),
    "azazel_nexus.exposure_exclusivity": frozenset(),
    "azazel_nexus.exposure_interfaces": frozenset(),
    "azazel_nexus_runtime.exposure_withholding": frozenset(),
    "azazel_nexus_runtime.exposure_generation": frozenset(),
    "azazel_nexus_runtime.decoy_residue": frozenset(),
    # The verify shares the reads and the R4 judgement (preparation A).
    "azazel_nexus_runtime.decoy_reachability": frozenset({WATCH, RESIDUE}),
    # The unit renderer, the install plan and the wrapper check use the
    # profile names; `exposure_generation` takes the four from here.
    "azazel_nexus_runtime.decoy_apparmor": frozenset({
        _RT + "hardening.py", _RT + "install_platform.py", GENERATION,
        "tools/check_decoy_apparmor_wrappers.py"}),
    # Preparation K: the installer's compiled-policy record. Only the
    # installer's tool writes it (and checks its output with the decoder);
    # G6's `generation-publish` is to read it, never the pass.
    "azazel_nexus_runtime.apparmor_compiled": frozenset({RECORD_TOOL}),
}


def _only(files, *names):
    return dict.fromkeys(names, frozenset(files))


#: Public name of a part -> the files that may contain it (as a substring).
#: The pass (`activation_pass.py`), the daemon, the controller and the
#: library's `activation.py` are in none of them.
NAME_FILES: dict[str, frozenset[str]] = {
    # The v3 decoder (G6 prep). Its module name too: it is named nowhere.
    **_only({V3}, "activation_approval_v3", "activation-approval/v3", "ApprovalV3",
            "decode_activation_approval_v3", "verify_activation_approval_v3",
            "activation_approval_v3_payload"),
    # Preparation C.
    **_only({UNIT_FILES, GENERATION}, "measure_exposure_unit_files"),
    **_only({APPARMOR, GENERATION, WITHHOLDING}, "exposure_lsm_withholding"),
    **_only({APPARMOR, GENERATION}, "policy_hash_refusal", "expected_policy_hashes"),
    **_only({APPARMOR}, "loaded_unit_profile_refusal", "read_policy_hashes",
            "read_exposure_lsm_policy", "exposure_lsm_refusal", "read_exposure_lsm",
            *decoy_apparmor.LSM_REASON_CODES, *decoy_apparmor.LSM_LOADED_REASON_CODES),
    **_only({WITHHOLDING}, "host_firewall_refusal", "fb_tunnels_refusal", "read_fb_tunnels",
            *exposure_withholding.HOST_FIREWALL_REASON_CODES,
            *exposure_withholding.FB_TUNNELS_REASON_CODES),
    **_only({EXCLUSIVITY}, "exposure_enforcement_conflict",
            *exposure_exclusivity.EXPOSURE_ENFORCEMENT_CODES),
    **_only({GENERATION}, "build_exposure_section", "verify_exposure_section",
            "measure_exposure_section_inputs", "measure_apparmor_profile_files",
            *exposure_generation.EXPOSURE_SECTION_CODES),
    # Preparation D. CI names the test file `test_exposure_interfaces.py`.
    **_only({INTERFACES, ".github/workflows/ci.yml"}, "exposure_interfaces"),
    **_only({INTERFACES}, "resolve_role_interfaces", "RoleInterfaces",
            *exposure_interfaces.ROLE_INTERFACE_CODES),
    # Preparation A: what only the pass would use (the rest is the verify's).
    **_only({REACHABILITY}, "pass_reachability_departures", "reachability_refusal",
            "conf_entry_path", decoy_reachability.FORWARDING_ROLE_ON),
    **_only({RESIDUE}, "exposure_residue_departures", "residue_refusal", "read_netns",
            *decoy_residue.RESIDUE_CODES),
    # Preparation K. The record's field is the section's (`exposure_generation`)
    # and the LSM judgement's (`decoy_apparmor`); the pass names none of these.
    **_only({COMPILED, RECORD_TOOL}, "decode_apparmor_compiled", "encode_apparmor_compiled",
            "normalize_parser_version", "ApparmorCompiled"),
    **_only({COMPILED}, "azazel-nexus/apparmor-compiled/v1"),
    **_only({COMPILED, RECORD_TOOL, "packaging/install.sh"}, "apparmor-compiled.json"),
    **_only({COMPILED, RECORD_TOOL, "packaging/install.sh", "tools/build_offline_bundle.py"},
            "apparmor_compiled"),
    **_only({COMPILED, APPARMOR, GENERATION, RECORD_TOOL}, "apparmor_policy_hashes"),
}

#: The reason codes of the parts: none may start a verdict's or the ledger's
#: reason before G6.
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


def test_the_tier_is_still_withheld_unconditionally():
    """`_withholding_reason` returns `isolation_evidence_absent` for the tier,
    with nothing before it that reads any part; the allowlist names none of
    the tier's units."""

    from azazel_nexus import activation

    source = Path(activation.__file__).read_text(encoding="utf-8")
    method = next(node for node in ast.walk(ast.parse(source))
                  if isinstance(node, ast.FunctionDef) and node.name == "_withholding_reason")
    body = ast.get_source_segment(source, method)
    branch = body[body.index("if definition.tier is UnitTier.DECEPTION_EXPOSURE:"):
                  body.index("if definition.tier is UnitTier.EDGE_BASELINE:")]
    assert re.findall(r'return \(\s*"([a-z_]+):', branch) == [
        "exposure_tier_partial", "isolation_evidence_absent"]
    for word in ("reachability", "forwarding", "residue", "leftover", "masked", "lsm",
                 "apparmor", "interface", "firewall", "fb_tunnels", "enforcement",
                 "exposure_section"):
        assert word not in branch.lower(), word
    for unit in DECEPTION_EXPOSURE_UNITS:
        assert unit not in ACTIVATION_UNIT_ALLOWLIST


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
#: Added since (#196 G6 preparation K): the record's decoder and encoder.
_POISONED_SINCE = {
    "decode_apparmor_compiled", "encode_apparmor_compiled", "normalize_parser_version",
}


def _poison_every_part(monkeypatch) -> list[str]:
    """Replace every function of every part module, the public names of the
    shared ones and `ALSO_POISONED`, wherever a loaded module holds them."""

    originals: dict[int, str] = {}
    for module_name, allowed in IMPORTERS.items():
        module = importlib.import_module(module_name)
        # A module nothing may import is a part as a whole; of a shared one,
        # the names of the table.
        whole = not allowed
        for name, value in vars(module).items():
            if not inspect.isfunction(value) or value.__module__ != module_name:
                continue
            if whole or name in NAME_FILES:
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

    calls: list[str] = []

    def poisoned(label):
        def call(*args, **kwargs):
            calls.append(label)
            raise AssertionError(f"{label} was called before G6")
        return call

    for loaded in list(sys.modules.values()):
        if not getattr(loaded, "__name__", "").startswith("azazel_nexus"):
            continue
        for name, value in list(vars(loaded).items()):
            if id(value) in originals and inspect.isfunction(value):
                monkeypatch.setattr(loaded, name, poisoned(originals[id(value)]))
    return calls


def test_a_pass_with_every_part_poisoned_still_withholds_the_tier(tmp_path, monkeypatch):
    """The library's controller and the runtime activation pass, each with
    every part replaced by one that fails when called: none is called, the
    tier is withheld as `isolation_evidence_absent`, and no part's reason code
    reaches a verdict or the ledger."""

    import test_activation as ta
    import test_runtime_activation_pass as trap

    calls = _poison_every_part(monkeypatch)
    codes = REASON_CODES

    (tmp_path / "library").mkdir()
    controller, units, ledger, _ = ta._controller(tmp_path / "library")
    outcome = controller.activate(
        now=ta.NOW, actor=ta.ACTOR, lease=ta._lease(),
        edge=EdgeBaselineState(True, True, True, True, True), healthy=True,
        record=ta._record(roles=(ta._confirmed_role(),)),
        wired=(ARTIFACT_TRANSPORT, LOCAL_MODEL_PROVIDER, REMOTE_INFERENCE_TRANSPORT),
    )
    for unit in DECEPTION_EXPOSURE_UNITS:
        verdict = next(v for v in outcome.verdicts if v.unit == unit)
        assert not verdict.granted
        assert verdict.reason.startswith("isolation_evidence_absent")
        assert ("unmask_and_enable", unit) not in units.calls
    assert "azazel-edge-core.service" in outcome.granted
    reasons = [v.reason for v in outcome.verdicts if v.reason] + [
        entry.event.get("reason", "") for entry in ledger]
    assert not any(reason.startswith(code) for reason in reasons for code in codes)

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

    assert calls == []
