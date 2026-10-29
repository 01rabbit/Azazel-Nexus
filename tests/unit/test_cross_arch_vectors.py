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
import subprocess
import sys
import unicodedata
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


@pytest.mark.parametrize("name", sorted(vectors.VECTORS))
def test_each_recorded_change_is_a_different_digest(name):
    """A history entry that repeats a digest records no change, only a reason."""
    digests = [change["sha256"] for change in DOCUMENT["vectors"][name]["history"]]
    assert len(digests) == len(set(digests))


def _committed(ref):
    """`digests.json` as committed at `ref`, or None where git or the ref is absent."""
    try:
        shown = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{ref}:tests/vectors/digests.json"],
            capture_output=True, text=True, check=False, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return json.loads(shown.stdout) if shown.returncode == 0 else None


def test_history_is_append_only_against_main_and_the_last_commit():
    """Recorded reasons are never rewritten or dropped: every committed history
    (on `origin/main`, and at `HEAD` for uncommitted edits) is a prefix of the
    one in the working tree, vector by vector. A vector may be added; none is
    removed without its history going with a deliberate change to this test."""
    compared = []
    for ref in ("origin/main", "HEAD"):
        committed = _committed(ref)
        if committed is None:
            continue
        compared.append(ref)
        for name, entry in committed["vectors"].items():
            assert name in DOCUMENT["vectors"], f"{name} was removed since {ref}"
            current = DOCUMENT["vectors"][name]["history"]
            assert current[:len(entry["history"])] == entry["history"], (
                f"{name}: the history committed at {ref} was rewritten")
    if not compared:
        pytest.skip("no git checkout with origin/main or HEAD to compare the history with")


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


def test_canonical_bytes_do_not_normalise_unicode():
    """NFC and NFD are different text to the canonical form, as to the product."""
    nfc, nfd = unicodedata.normalize("NFC", "é"), unicodedata.normalize("NFD", "é")
    assert nfc != nfd
    assert vectors.canonical_bytes({"v": nfc}) == b'{"v":"\xc3\xa9"}'
    assert vectors.canonical_bytes({"v": nfd}) == b'{"v":"e\xcc\x81"}'
    assert vectors.digest({"v": nfc}) != vectors.digest({"v": nfd})
    # As keys, both are kept, each where its code points sort.
    assert vectors.canonical_bytes({nfc: 1, nfd: 2}) == '{"e\u0301":2,"\u00e9":1}'.encode("utf-8")


def test_keys_sort_by_code_point_not_by_utf16_as_rfc_8785_does():
    """U+FF71 sorts before U+1F512 by code point; by UTF-16 code unit (RFC 8785
    JCS) the surrogate 0xD83D would come first. The canonical form here is
    Python's `sort_keys`, i.e. code point order."""
    value = {"\U0001f512": 1, "\uff71": 2, "z": 3, "Z": 4, "é": 5}
    assert list(json.loads(vectors.canonical_bytes(value))) == [
        "Z", "z", "é", "\uff71", "\U0001f512"]
    assert vectors.canonical_bytes(value) == (
        '{"Z":4,"z":3,"é":5,"\uff71":2,"\U0001f512":1}'.encode("utf-8"))


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


def test_a_failed_run_is_reported_as_failed_and_never_as_agreeing():
    pins = {"a": "1" * 64}
    failed = {"target": "amd64", "error": "exit 1", "stderr_tail": ["boom"]}
    result = tool.compare({"aarch64": _report("aarch64", dict(pins)), "amd64": failed}, pins)
    assert result["failed_runs"] == ["amd64"]
    assert result["vectors"]["a"]["amd64"] is None
    assert result["vectors"]["a"]["equal"] is False
    assert result["all_equal"] is False and result["all_match_pins"] is False
    missing = tool.compare({"aarch64": _report("aarch64", dict(pins))}, pins)
    assert missing["failed_runs"] == ["amd64"] and missing["all_equal"] is False


def test_the_report_is_written_and_the_exit_is_nonzero_when_a_cpu_fails(tmp_path, monkeypatch):
    pins = tool.pins()

    def run_target(name, **_):
        if name == "amd64":
            return {"target": name, "error": "exit 125", "stderr_tail": []}
        return {"target": name, **_report("aarch64", dict(pins))}

    monkeypatch.setattr(tool, "run_target", run_target)
    monkeypatch.setattr(tool, "_commit", lambda: "test")
    out = tmp_path / "report.json"
    assert tool.main(["--out", str(out)]) == 1
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["comparison"]["failed_runs"] == ["amd64"]
    assert report["runs"]["amd64"]["error"] == "exit 125"


def test_mounts_are_resolved_binds_and_separator_paths_are_refused(tmp_path):
    (tmp_path / "cache").mkdir()
    link = tmp_path / "via"
    link.symlink_to(tmp_path / "cache")
    assert tool.bind(link, "/pipcache") == [
        "--mount", f"type=bind,source={(tmp_path / 'cache').resolve()},target=/pipcache"]
    assert tool.bind(tmp_path / "cache", "/src", readonly=True)[1].endswith(",readonly")
    for bad in ("a:b", "a,b"):
        (tmp_path / bad).mkdir()
        with pytest.raises(ValueError):
            tool.bind(tmp_path / bad, "/pipcache")
    with pytest.raises(ValueError):
        tool.bind(tmp_path / "absent", "/pipcache")
    with pytest.raises(ValueError):
        tool.main(["--pip-cache", str(tmp_path / "a:b"), "--compare", "x", "y"])


def test_the_targets_are_one_native_aarch64_and_one_emulated_amd64():
    assert tool.TARGETS["aarch64"]["context"] == "colima"
    assert tool.TARGETS["aarch64"]["platform"] == "linux/arm64"
    assert tool.TARGETS["amd64"]["context"] == "colima-rosetta"
    assert tool.TARGETS["amd64"]["platform"] == "linux/amd64"
    assert "Rosetta" in tool.TARGETS["amd64"]["execution"]
