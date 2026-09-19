"""The vendored fixtures are Knowledge's bytes, and must stay that way.

Forging broken artifacts locally was rejected: Knowledge ADR-0015 D7 assigns
the consumer fixtures to Knowledge because a locally forged artifact differs
from what Knowledge emits in ways nobody can enumerate. That argument is only
worth anything while the copy really is Knowledge's output, so the copy is
checked rather than trusted.
"""

from __future__ import annotations

import hashlib
import json

import pytest


def _sha256(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_every_vendored_file_matches_the_recorded_digest(fixture_root):
    provenance = json.loads((fixture_root / "PROVENANCE.json").read_text(encoding="utf-8"))
    recorded = provenance["sha256"]

    on_disk = {
        str(path.relative_to(fixture_root))
        for path in fixture_root.rglob("*")
        if path.is_file() and path.name != "PROVENANCE.json"
    }
    assert on_disk == set(recorded), (
        "the vendored fixture set no longer matches what PROVENANCE.json records"
    )
    for relative, digest in recorded.items():
        assert _sha256(fixture_root / relative) == digest, f"vendored file drifted: {relative}"


def test_the_digests_agree_with_knowledges_own_index(fixture_root, negative_cases):
    """Two independent statements of the same bytes must not disagree.

    `negative.json` carries Knowledge's own digest for each negative fixture.
    If the copy here matched our manifest but not Knowledge's index, the copy
    would be internally consistent and still wrong.
    """

    checked = 0
    for case in negative_cases.values():
        if case["sha256"] is None:
            continue
        assert _sha256(fixture_root / case["path"]) == case["sha256"], (
            f"{case['name']} does not match the digest Knowledge recorded for it"
        )
        checked += 1
    assert checked >= 4, f"only cross-checked {checked} fixtures against Knowledge's index"


def test_the_provenance_record_names_where_the_bytes_came_from(fixture_root):
    provenance = json.loads((fixture_root / "PROVENANCE.json").read_text(encoding="utf-8"))
    assert provenance["source_repository"] == "01rabbit/Azazel-Knowledge"
    assert len(provenance["source_revision"]) == 40
    assert "lite_fixture.py" in provenance["emitter"]
    # The drift limit is stated, not discovered later by someone debugging.
    assert "stale" in provenance["drift"]


def test_the_absent_fixture_is_genuinely_absent(fixture_root, negative_cases):
    """Knowledge guarantees it does not write this path. Trust, then verify."""
    absent = negative_cases["absent"]
    assert absent["exists"] is False
    assert not (fixture_root / absent["path"]).exists()


def test_the_trust_anchor_beside_the_absent_artifact_does_exist(fixture_root, negative_index):
    """Otherwise a fail-open test would be testing a missing anchor instead."""
    assert (fixture_root / negative_index["anchors"]).is_file()
