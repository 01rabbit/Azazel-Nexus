"""The Knowledge-vs-Nexus Lite verifier differential, as far as CI can run it.

`tools/knowledge_lite_differential.py` judges each case with Knowledge's own
verifier and with Nexus's, and records both verdicts in `EXPECTED`. CI cannot
fetch Azazel-Knowledge, so here the same cases are built from the
Knowledge-emitted contract fixture, re-signed with keys generated in this
test, and judged by Nexus alone against the recorded Nexus column. The
Knowledge column is re-measured locally (`docs/knowledge-lite-differential.md`).
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from azazel_nexus.lite_bundle import BundleRefused, TrustAnchors, verify_bundle
from signing_oracle import public_key_for, sign_detached
from tools import knowledge_lite_differential as diff

SIGNER = diff.Signer(
    sign=lambda seed, message: sign_detached(seed=seed, message=message),
    public=public_key_for,
)


@pytest.fixture(scope="module")
def keys() -> diff.LabKeys:
    return diff.LabKeys.generate(SIGNER)


@pytest.fixture(scope="module")
def cases(keys) -> list[diff.Case]:
    return diff.build_cases(diff.contract_bases(keys), keys)


@pytest.fixture(scope="module")
def rows(cases, tmp_path_factory) -> list[diff.Row]:
    work = tmp_path_factory.mktemp("differential")
    return diff.compare(cases, {c.name: diff.nexus_verdict(c, work) for c in cases}, None)


def test_every_case_has_a_recorded_verdict(cases):
    assert {c.name for c in cases} == set(diff.EXPECTED)


def test_nexus_judges_every_case_as_recorded(rows):
    wrong = [(r.case, r.nexus, r.expected[1]) for r in rows if r.nexus != r.expected[1]]
    assert not wrong


def test_every_divergence_says_which_side_and_why():
    divergent = {name for name, (k, n) in diff.EXPECTED.items() if k != n}
    assert divergent == set(diff.DIVERGENCES)
    for side, reason in diff.DIVERGENCES.values():
        assert side in {"nexus", "knowledge", "both refuse"} and reason.strip()


def test_nexus_accepts_nothing_knowledge_refuses_without_an_open_owner_decision():
    # A divergence is not a pass by being recorded: every case where the
    # producer's verifier refuses and Nexus accepts names the owner-decisions
    # row that keeps it open, and one without a row fails here.
    looser = {name for name, (k, n) in diff.EXPECTED.items() if n == diff.ACCEPTED != k}
    assert looser == set(diff.NEXUS_LOOSER)
    decisions = (diff.REPO / "docs" / "owner-decisions.md").read_text(encoding="utf-8")
    for row in diff.NEXUS_LOOSER.values():
        assert f"| {row} |" in decisions


def _role_holders(anchor: str) -> tuple[int, int]:
    doc = tomllib.loads(anchor)
    active = set(doc["keys"]) - set(doc["revoked"])
    holders = {k for k in active if doc["key_roles"].get(k) == doc["required_signer_role"]}
    return len(holders), doc["threshold"]


@pytest.mark.parametrize("name", ["signer_revoked", "threshold2_one_signature",
                                  "threshold2_one_holds_role"])
def test_the_gate_cases_use_an_anchor_the_producer_would_load(cases, name):
    # Since Azazel-Knowledge#110 an anchor with fewer non-revoked role holders
    # than its threshold is refused at load; these cases exist to reach the
    # revoked-signer, threshold and role gates, so their anchors must not be one.
    holders, threshold = _role_holders(next(c for c in cases if c.name == name).anchors)
    assert holders >= threshold


@pytest.mark.parametrize("name", ["anchor_revoked_leaves_no_role_holder",
                                  "anchor_role_holders_below_threshold"])
def test_the_unsatisfiable_anchor_cases_are_unsatisfiable(cases, name):
    holders, threshold = _role_holders(next(c for c in cases if c.name == name).anchors)
    assert holders < threshold


def test_the_record_has_cases_both_sides_accept_and_refuse():
    # A table that only ever agreed on refusals would not show the valid
    # production-anchored bundle passes on both sides.
    both = [k for k, n in diff.EXPECTED.values() if k == n]
    assert diff.ACCEPTED in both and len(set(both)) > 10


def test_the_production_anchor_sets_every_gate_the_producer_defines(cases):
    anchor = tomllib.loads(next(c for c in cases if c.name == "valid").anchors)
    assert anchor["required_signer_role"] == diff.ROLE
    assert anchor["minimum_security_epoch"] >= 1
    assert len(anchor["accepted_export_policy_digests"]) == 1
    assert set(anchor["key_roles"].values()) == {diff.ROLE, diff.OTHER_ROLE}


def test_the_published_fixture_key_is_in_no_anchor_and_signs_nothing(cases):
    fixture = tomllib.loads((diff.CONTRACT / "anchors.toml").read_text(encoding="utf-8"))
    (fixture_id, fixture_key), = fixture["keys"].items()
    for case in cases:
        assert fixture_key not in case.anchors and fixture_id not in case.anchors
        try:
            members = dict(diff.unpack(case.bundle))
        except Exception:  # noqa: BLE001 - the truncated case does not unpack
            continue
        assert not members.get("manifest.sig", b"").startswith(fixture_id.encode()), case.name


def test_the_valid_case_delivers_the_knowledge_emitted_content(keys):
    bases = diff.contract_bases(keys)
    fixture = dict(diff.unpack((diff.CONTRACT / "lite.tar.gz").read_bytes()))
    anchors = TrustAnchors(threshold=1, keys={keys.key_id("A"): bytes.fromhex(keys.public_hex("A"))})
    accepted = verify_bundle(bases["valid"], anchors=anchors)
    assert dict(accepted.members) == {n: b for n, b in fixture.items()
                                      if n not in {"manifest.json", "manifest.sig"}}
    assert json.loads(fixture["manifest.json"]) == accepted.manifest


def test_role_threshold_counts_only_the_role_holders(keys):
    base = diff.Base(diff.contract_bases(keys)["valid"], keys)
    two = base.signed(signers=("A", "B"))
    material = {label: bytes.fromhex(keys.public_hex(label)) for label in ("A", "B")}

    def anchors(roles):
        return TrustAnchors(threshold=2, keys={keys.key_id(k): v for k, v in material.items()},
                            key_roles={keys.key_id(k): r for k, r in roles.items()},
                            required_signer_role="lite")

    with pytest.raises(BundleRefused) as caught:
        verify_bundle(two, anchors=anchors({"A": "lite", "B": "full"}))
    assert caught.value.code == "BUNDLE_SIGNER_ROLE_NOT_PERMITTED"
    assert verify_bundle(two, anchors=anchors({"A": "lite", "B": "lite"})).signers


def test_lab_seeds_are_written_private_and_destroyed(tmp_path: Path):
    path = tmp_path / "lab.seed"
    diff.write_seed(path, b"\x01" * 32)
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        diff.write_seed(path, b"\x02" * 32)
    diff.destroy([path, tmp_path / "never-written.seed"])
    assert not path.exists()


def test_the_local_tool_refuses_to_run_without_a_knowledge_checkout(tmp_path, capsys):
    with pytest.raises(SystemExit) as caught:
        diff.main(["--knowledge", str(tmp_path)])
    assert caught.value.code == 2
