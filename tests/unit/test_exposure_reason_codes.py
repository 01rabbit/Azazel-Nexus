"""The reason codes of the G6 parts, as one set (#196, review of the G6 preparation, M1).

Every part built ahead of G6 says why it refuses in one form,
`"<code>: <phrase>"`: a fixed code and that code's one fixed phrase, from a
`*_PHRASES` dictionary of the part. No count, name, address or value is in a
phrase; a value that could not be read has a code of its own. This file pins,
in one place:

* each part's codes and its phrase dictionary are the same set, and every
  phrase is a constant string with no digit (but `IPv4`, `IPv6` and `v3`)
  and no format field;
* the union of all the parts' codes has no code twice, and no code of a part
  is a string anywhere else in the product (the activation reason codes,
  `exposure_tier_partial` and `isolation_evidence_absent` among them);
* what each part returns or raises, for inputs that refuse, is exactly
  `"<code>: <phrase>"` of one of its codes;
* approval v3's phrases are the wording it used before the codes, and the
  phrases it borrows from shared helpers are those the helpers raise.
"""

from __future__ import annotations

import ast
from pathlib import Path
import re

import pytest

from azazel_nexus import activation_approval_v3 as v3
from azazel_nexus.exposure_exclusivity import (
    EXPOSURE_ENFORCEMENT_CODES,
    EXPOSURE_ENFORCEMENT_PHRASES,
    exposure_enforcement_conflict,
)
from azazel_nexus.exposure_interfaces import ROLE_INTERFACE_CODES, ROLE_INTERFACE_PHRASES
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus.generation import GenerationRefused
from azazel_nexus_runtime import decoy_apparmor, exposure_generation, exposure_withholding
from azazel_nexus_runtime.decoy_reachability import (
    PASS_REACHABILITY_CODES,
    REACHABILITY_PHRASES,
)
from azazel_nexus_runtime.decoy_residue import RESIDUE_CODES, RESIDUE_PHRASES

ROOT = Path(__file__).resolve().parents[2]

#: Each part: its file, its codes and its phrases.
PARTS = {
    "exposure_interfaces.py": (ROLE_INTERFACE_CODES, ROLE_INTERFACE_PHRASES),
    "decoy_reachability.py": (PASS_REACHABILITY_CODES, REACHABILITY_PHRASES),
    "decoy_residue.py": (RESIDUE_CODES, RESIDUE_PHRASES),
    "exposure_withholding.py": (
        exposure_withholding.HOST_FIREWALL_REASON_CODES
        + exposure_withholding.FB_TUNNELS_REASON_CODES,
        {**exposure_withholding.HOST_FIREWALL_PHRASES,
         **exposure_withholding.FB_TUNNELS_PHRASES}),
    "decoy_apparmor.py": (
        decoy_apparmor.LSM_REASON_CODES + decoy_apparmor.LSM_LOADED_REASON_CODES,
        decoy_apparmor.LSM_PHRASES),
    "exposure_exclusivity.py": (EXPOSURE_ENFORCEMENT_CODES, EXPOSURE_ENFORCEMENT_PHRASES),
    "exposure_generation.py": (exposure_generation.EXPOSURE_SECTION_CODES,
                               exposure_generation.EXPOSURE_SECTION_PHRASES),
    "activation_approval_v3.py": (v3.APPROVAL_V3_CODES, v3.APPROVAL_V3_PHRASES),
}
ALL_CODES = [code for codes, _ in PARTS.values() for code in codes]
REFUSALS = {f"{code}: {phrase}" for _, phrases in PARTS.values()
            for code, phrase in phrases.items()}


def _refusal(phrases: dict[str, str], code: str) -> str:
    return f"{code}: {phrases[code]}"


def test_each_part_has_one_constant_phrase_per_code():
    for name, (codes, phrases) in PARTS.items():
        assert type(codes) is tuple and len(set(codes)) == len(codes), name
        assert type(phrases) is dict and set(phrases) == set(codes), name
        for code, phrase in phrases.items():
            assert re.fullmatch(r"[a-z][a-z0-9]*(_[a-z0-9]+)+", code), (name, code)
            assert type(phrase) is str and phrase == phrase.strip() and phrase, (name, code)
            bare = re.sub(r"IPv[46]|\bv3\b", "", phrase)
            assert not re.search(r"[\d{}%]", bare), (name, phrase)
            assert ":" not in phrase, (name, phrase)


def test_the_codes_of_all_parts_are_distinct_and_new_to_the_product():
    assert len(set(ALL_CODES)) == len(ALL_CODES)
    # The activation reason codes, by name, and every snake_case string
    # anywhere else in the product (the activation pass's codes, the
    # controller's, the verify's check names, ...).
    # Python: every snake_case word inside any string constant (`\b`, so a
    # code embedded in a longer message counts too), over the product, the
    # tools, the lab and the bench. The part modules themselves are skipped.
    elsewhere: dict[str, Path] = {}
    word = re.compile(r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b")
    for base in (ROOT / "src", ROOT / "runtime" / "src", ROOT / "tools",
                 ROOT / "lab" / "src", ROOT / "bench"):
        assert base.is_dir(), base
        for path in sorted(base.rglob("*.py")):
            if path.name in PARTS:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            # Docstrings and other bare string statements are prose that may
            # name a code; only strings a program can emit count.
            prose = {id(node.value) for node in ast.walk(tree) if isinstance(node, ast.Expr)}
            for node in ast.walk(tree):
                if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                        and id(node) not in prose):
                    for found in word.findall(node.value):
                        elsewhere.setdefault(found, path)
    for known in ("exposure_tier_partial", "isolation_evidence_absent", "lease_absent",
                  "outside_lease_scope", "wiring_absent", "edge_not_ready"):
        assert known in elsewhere, known
    for code in ALL_CODES:
        assert code not in elsewhere, (code, elsewhere.get(code))
    # packaging/: a plain search of every file (shell, units, profiles).
    for path in sorted((ROOT / "packaging").rglob("*")):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            for code in ALL_CODES:
                assert not re.search(rf"\b{code}\b", text), (path, code)


def _withholding_reasons():
    units = exposure_withholding.HOST_FIREWALL_UNITS
    yield exposure_withholding.host_firewall_refusal(None)
    yield exposure_withholding.host_firewall_refusal(
        {unit: {"UnitFileState": "enabled", "ActiveState": "active"} for unit in units})
    yield exposure_withholding.host_firewall_refusal(
        {unit: {"UnitFileState": "masked", "ActiveState": "failed"} for unit in units})
    for value in (None, exposure_withholding.UNREADABLE, b"0\n", b"1\n"):
        yield exposure_withholding.fb_tunnels_refusal(value)


def _apparmor_reasons():
    enforced = b"".join(name.encode() + b" (enforce)\n"
                        for name in decoy_apparmor.REQUIRED_ENFORCED_PROFILES)
    lsm = b"capability,apparmor\n"
    yield decoy_apparmor.exposure_lsm_refusal(b"capability\n", enforced)
    yield decoy_apparmor.exposure_lsm_refusal(decoy_apparmor.UNREADABLE, enforced)
    yield decoy_apparmor.exposure_lsm_refusal(lsm, b"")
    yield decoy_apparmor.exposure_lsm_refusal(lsm, enforced.replace(b"enforce", b"complain"))
    yield decoy_apparmor.exposure_lsm_refusal(lsm, enforced + b"azazel-decoyd//x (enforce)\n")
    yield decoy_apparmor.loaded_unit_profile_refusal({})
    yield decoy_apparmor.policy_hash_refusal((), None)
    hashes = {name: "0" * 64 for name in decoy_apparmor.REQUIRED_ENFORCED_PROFILES}
    entries = tuple((name.encode() + b"\n", b"1" * 64 + b"\n")
                    for name in decoy_apparmor.REQUIRED_ENFORCED_PROFILES)
    yield decoy_apparmor.policy_hash_refusal(entries, hashes)


def _generation_reasons():
    for call in (lambda: exposure_generation.expected_policy_hashes({}),
                 lambda: exposure_generation.build_exposure_section(
                     unit_files={}, watch_unit_files={}, apparmor_profiles={},
                     apparmor_policy_hashes={}, scope_file=b"")):
        with pytest.raises(GenerationRefused) as caught:
            call()
        yield str(caught.value)


def _approval_reasons():
    for payload in (b"", b"{}", b"x", b'{"a":1,"a":2}'):
        with pytest.raises(ApprovalRefused) as caught:
            v3.decode_activation_approval_v3(payload)
        yield str(caught.value)
    with pytest.raises(ApprovalRefused) as caught:
        v3.verify_activation_approval_v3(
            trust=None, expected=None, policy=None, payload=b"", signature=b"",
            now="2026-10-20T00:00:00Z", security_epoch_floor=0, approval_seq_floor=0)
    yield str(caught.value)


def test_what_each_part_says_is_one_code_and_its_phrase():
    reasons = [
        *_withholding_reasons(), *_apparmor_reasons(), *_generation_reasons(),
        *_approval_reasons(),
        exposure_enforcement_conflict(None),
    ]
    assert None not in reasons
    for reason in reasons:
        assert reason in REFUSALS, reason
    # The unreadable codes are told apart from the judgements they could not make.
    assert {reason.split(":", 1)[0] for reason in reasons} >= {
        "host_firewall_unreadable", "host_firewall_enabled", "host_firewall_active",
        "fb_tunnels_unreadable", "fb_tunnels_not_init_net_only",
        "lsm_apparmor_disabled", "lsm_profiles_unreadable", "lsm_profiles_absent",
        "lsm_profiles_not_enforced", "lsm_profile_child_present", "lsm_unit_profile_differs",
        "lsm_policy_unverifiable", "lsm_policy_differs", "exposure_section_unverifiable",
        "exposure_enforcement_unreadable", "approval_v3_payload_unbounded",
        "approval_v3_fields_invalid", "approval_v3_document_refused",
        "approval_v3_field_duplicate", "approval_v3_trust_required"}


#: The wording each v3 refusal had before the codes (#196 G6 preparation),
#: kept as its phrase.
_V3_WORDING = {
    "operator trust required", "activation context required", "activation policy required",
    "local security epoch floor required", "local approval sequence floor required",
    "approval payload must be bounded nonempty bytes", "duplicate activation approval field",
    "invalid activation approval fields", "invalid approval identifier",
    "invalid approval operator", "invalid approval sequence",
    "approval expiry must follow its grant time",
    "approval units must be a collection of unit names",
    "approval units must be distinct unit names", "approval units outside the v3 tiers",
    "approval names only part of the Deception Lite exposure tier, which is approved "
    "together or not at all",
    "activation approval is not canonical",
    "operator is not authorized by the activation policy",
    "activation approval does not match expected context",
    "activation security epoch below the local floor",
    "activation approval sequence below the local floor",
    "activation approval units outside the policy scope",
    "activation approval outside local time policy",
    "activation approval document refused",
}
#: The phrases v3 gained after the codes, with its exposure fields (wiring
#: §5.1, V2): v3's own, raised by no shared helper.
_V3_EXPOSURE_FIELD_WORDING = {
    "invalid approval exposure scope digest", "invalid approval exposure prefix count",
    "invalid approval exposure ingress count",
}


def _string_constants(relative: str) -> set[str]:
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    return {node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)}


#: What v3 calls in the shared modules, by (file, class or function, method).
#: Nothing else of theirs raises inside v3: the trust and the policy are built
#: by the caller, and v3 only type-checks the policy and reads its fields.
_V3_CALLS = (
    ("src/azazel_nexus/operator_trust.py", "approval_message", None),
    ("src/azazel_nexus/operator_trust.py", "OperatorTrust", "verify"),
    ("src/azazel_nexus/activation_approval.py", "_utc", None),
    ("src/azazel_nexus/activation_approval_v2.py", "ObserveBaselineContext", "__post_init__"),
)


def _raised_in(relative: str, outer: str, inner: str | None) -> set[str]:
    """Every message an `ApprovalRefused(...)` or `_nonnegative(..., msg)` in
    that function (or method) passes, as written."""

    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    node = next(n for n in tree.body
                if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == outer)
    if inner is not None:
        node = next(n for n in node.body if isinstance(n, ast.FunctionDef) and n.name == inner)
    found = set()
    for call in ast.walk(node):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
            continue
        if call.func.id == "ApprovalRefused":
            found.add(call.args[0].value)
        elif call.func.id == "_nonnegative":
            found.add(call.args[1].value)
    return found


def test_approval_v3_keeps_its_wording_and_the_helpers_phrases():
    phrases = set(v3.APPROVAL_V3_PHRASES.values())
    assert _V3_WORDING <= phrases
    assert _V3_EXPOSURE_FIELD_WORDING <= phrases
    shared = set(v3._SHARED)
    assert not shared & _V3_EXPOSURE_FIELD_WORDING
    assert shared == phrases - _V3_WORDING - _V3_EXPOSURE_FIELD_WORDING | {
        "approval payload must be bounded nonempty bytes"}
    # v2 and the operator trust raise the same type with their own wording.
    assert v3.ApprovalRefused is ApprovalRefused


def test_approval_v3_codes_every_phrase_the_helpers_it_calls_raise():
    """Finding 1 of the review of #303, both ways: every message the shared
    helpers v3 calls can raise has its code in `_SHARED`, and `_SHARED`
    holds nothing they do not raise."""

    raised = set().union(*(_raised_in(*call) for call in _V3_CALLS))
    assert raised == set(v3._SHARED)
    # v3 calls nothing else of those modules that could raise.
    tree = ast.parse((ROOT / "src/azazel_nexus/activation_approval_v3.py").read_text(
        encoding="utf-8"))
    imported = {(node.module, alias.name) for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) for alias in node.names}
    assert {name for module, name in imported if module in (
        "activation_approval", "activation_approval_v2", "operator_trust")} == {
        "_utc", "ActivationApprovalPolicy", "ObserveBaselineContext", "MAX_APPROVAL_BYTES",
        "ApprovalPurpose", "ApprovalRefused", "OperatorTrust"}
