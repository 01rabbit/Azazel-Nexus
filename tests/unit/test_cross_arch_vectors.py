"""Shared vectors: the same digest on every CPU (ADR-0003 D6, goal principle 4).

Each vector in `tests/vectors/cross_arch.py` runs product code on fixed
inputs and hashes the canonical JSON of what it decided. The digests are
pinned in `tests/vectors/digests.json`. This suite runs on aarch64 and on
x86_64 alike, so a pass on a CPU is that CPU reproducing the pinned meaning
byte for byte; `tools/cross_arch_vectors.py` runs the vectors on both CPUs and
compares them directly.

A failing digest is a finding, not a pin to refresh. `docs/cross-arch-vectors.md`
§5 says when a pin may change and how the reason is recorded.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "cross-arch-vectors.md"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


vectors = _load("cross_arch_vectors_under_test", ROOT / "tests" / "vectors" / "cross_arch.py")
tool = _load("cross_arch_vectors_tool", ROOT / "tools" / "cross_arch_vectors.py")
DOCUMENT = json.loads(vectors.DIGESTS.read_text(encoding="utf-8"))


# -- the pins ----------------------------------------------------------------


def test_every_vector_has_a_pin_and_every_pin_a_vector():
    assert set(DOCUMENT["vectors"]) == set(vectors.VECTORS)


@pytest.mark.parametrize("name", sorted(vectors.VECTORS))
def test_the_vector_reproduces_its_pinned_digest(name):
    computed = vectors.digest(vectors.build(name))
    pinned = DOCUMENT["vectors"][name]["sha256"]
    assert computed == pinned, (
        f"{name}: {computed} differs from the pin {pinned}. If the product's "
        "meaning changed on purpose, follow docs/cross-arch-vectors.md §5; "
        "otherwise this CPU or interpreter disagrees with the pinned meaning"
    )


@pytest.mark.parametrize("name", sorted(vectors.VECTORS))
def test_each_pin_says_what_it_covers_and_why_it_last_changed(name):
    entry = DOCUMENT["vectors"][name]
    assert set(entry) == {"sha256", "covers", "history"}
    assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
    assert entry["covers"].strip()
    history = entry["history"]
    assert history, "a pin without a recorded reason"
    for change in history:
        assert set(change) == {"date", "sha256", "commit_note", "reason"}
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", change["date"])
        assert change["reason"].strip() and change["commit_note"].strip()
    # The newest recorded change is the pin in force.
    assert history[-1]["sha256"] == entry["sha256"]
    assert [c["date"] for c in history] == sorted(c["date"] for c in history)


def test_the_canonical_form_recorded_beside_the_pins_is_the_one_used():
    assert DOCUMENT["canonical_form"] == {
        "json": {"sort_keys": True, "separators": [",", ":"], "ensure_ascii": False,
                 "allow_nan": False},
        "encoding": "utf-8",
        "hash": "sha256",
        "types": ["object", "array", "string", "integer", "true", "false", "null"],
    }


# -- the canonical form --------------------------------------------------------


def test_canonical_bytes_are_sorted_compact_utf8():
    value = {"b": [1, True, None], "a": "決定 é", "c": {"y": -1, "x": " "}}
    assert vectors.canonical_bytes(value) == (
        '{"a":"決定 é","b":[1,true,null],"c":{"x":" ","y":-1}}'.encode("utf-8"))
    assert vectors.digest(value) == vectors.hashlib.sha256(vectors.canonical_bytes(value)).hexdigest()


@pytest.mark.parametrize("value", [
    1.0, {"a": 0.5}, [float("nan")], (1, 2), {1: "x"}, {"a": {1, 2}}, b"bytes",
    {"a": frozenset()},
])
def test_a_float_or_a_foreign_type_is_refused_rather_than_coerced(value):
    with pytest.raises(vectors.NotCanonical):
        vectors.canonical_bytes(value)


def test_without_floats_removes_floats_and_names_where_they_were():
    kept, removed = vectors.without_floats(
        {"a": 1, "b": 2.5, "c": [{"d": 1.0, "e": "x"}, 3], "f": {"g": float("inf")}})
    assert kept == {"a": 1, "c": [{"e": "x"}, 3], "f": {}}
    assert removed == ["$.b", "$.c[].d", "$.f.g"]


def test_golden_floats_are_integral_and_no_other_float_is_in_the_input():
    lines = vectors._golden_lines()
    assert len(lines) == 6
    for line in lines:
        assert vectors.without_floats(json.loads(line))[1] == []


# -- the documentation ---------------------------------------------------------


def test_the_document_names_every_vector_and_every_exclusion():
    text = DOC.read_text(encoding="utf-8")
    for name in vectors.VECTORS:
        assert f"`{name}`" in text, f"{name} is not described"
    for field in vectors.GOLDEN_FLOAT_FIELDS:
        assert f"`{field}`" in text
    for name in ("knowledge_lite.verify", "status.read_model"):
        for path in _excluded_floats(vectors.build(name)):
            assert f"`{path}`" in text, f"{name}: excluded float {path} is not listed"
    # Principle 5 lives in ADR-0003 D7; the document links it.
    assert "adr/0003-arm-software-verification-profile.md#" in text


def _excluded_floats(document):
    found = set()

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "excluded_floats":
                    found.update(item)
                else:
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(document)
    return found


# -- the cross-CPU comparison (tools/cross_arch_vectors.py) -------------------------


def _report(machine, digests):
    return {"host": {"machine": machine, "python": "3.12.0"}, "digests": digests}


def test_comparison_reports_agreement_and_pin_matches():
    pins = {"a": "1" * 64, "b": "2" * 64}
    result = tool.compare({"aarch64": _report("aarch64", dict(pins)),
                           "amd64": _report("x86_64", dict(pins))}, pins)
    assert result["all_equal"] is True and result["all_match_pins"] is True
    assert result["vectors"]["a"] == {"aarch64": "1" * 64, "amd64": "1" * 64,
                                      "equal": True, "pinned": "1" * 64,
                                      "matches_pin": True}


def test_comparison_names_a_disagreement_and_never_fills_a_missing_cpu():
    pins = {"a": "1" * 64, "b": "2" * 64}
    result = tool.compare({"aarch64": _report("aarch64", {"a": "1" * 64, "b": "3" * 64}),
                           "amd64": _report("x86_64", {"a": "1" * 64})}, pins)
    assert result["all_equal"] is False and result["all_match_pins"] is False
    assert result["vectors"]["b"]["amd64"] is None  # not run there: never inferred
    assert result["vectors"]["b"]["equal"] is False
    assert result["differing"] == ["b"]


def test_comparison_refuses_a_report_from_the_wrong_cpu():
    with pytest.raises(ValueError):
        tool.compare({"aarch64": _report("x86_64", {}), "amd64": _report("x86_64", {})}, {})


def test_the_targets_are_one_native_aarch64_and_one_emulated_amd64():
    assert tool.TARGETS["aarch64"]["context"] == "colima"
    assert tool.TARGETS["aarch64"]["platform"] == "linux/arm64"
    assert tool.TARGETS["amd64"]["context"] == "colima-rosetta"
    assert tool.TARGETS["amd64"]["platform"] == "linux/amd64"
    assert "Rosetta" in tool.TARGETS["amd64"]["execution"]
