"""Official ATT&CK corpus through the Nexus technique validator and projector (work unit 51).

The fixture is the output of Knowledge's `attack_stix.flatten` over the official
Enterprise ATT&CK 20.1 bundle (706 techniques; sha256 and commit are recorded in the
file). Names and tactics are verbatim. Knowledge's own test checks the extract
against the raw file when AZAZEL_ATTACK_CORPUS is set.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from _technique_fixture import make_response
from azazel_nexus import technique_knowledge as tk

EXTRACT = json.loads((Path(__file__).resolve().parents[1] / "fixtures"
                      / "attack-enterprise-20.1-extract.json").read_text("utf-8"))
TECHNIQUES = EXTRACT["techniques"]
#: Official names whose projection hides the label (display deterrent, word screen):
#: coverage stays `found`; only `name` is withheld. Reported to the owner, not a validator rule.
WITHHELD_BY_WORD_SCREEN = {
    "T1489": "Service Stop", "T1547.001": "Registry Run Keys / Startup Folder",
    "T1564.011": "Ignore Process Interrupts", "T1564.006": "Run Virtual Instance",
    "T1578.003": "Delete Cloud Instance",
}


def test_extract_identity():
    assert EXTRACT["attack_version"] == "20.1" and len(TECHNIQUES) == 706
    assert EXTRACT["source_sha256"] == "539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5"


def test_every_official_name_and_tactic_passes_the_validator_grammar():
    assert [t["id"] for t in TECHNIQUES if not tk.name_grammar_ok(t["name"])] == []
    assert {x for t in TECHNIQUES for x in t["tactics"]} <= set(tk.TACTICS)
    assert {"stealth", "defense-impairment"} <= set(tk.TACTICS)


def test_the_whole_official_corpus_is_accepted_and_projected():
    withheld = {}
    for i in range(0, len(TECHNIQUES), 8):
        chunk = TECHNIQUES[i:i + 8]
        ids = [t["id"] for t in chunk]
        content = {t["id"]: (t["name"], ",".join(sorted(t["tactics"])), "20.1") for t in chunk}
        response = make_response(ids, content=content, version="20.1")
        checked = tk.validate_technique_response(response, ids)
        for item, t in zip(checked["techniques"], chunk):
            assert (item["coverage"], item["name"], item["tactics"], item["attack_version"]) == (
                "found", t["name"], sorted(t["tactics"]), "20.1")
        projected = tk.read_projection(tk.project_technique_response(response, ids))
        for row, t in zip(projected["techniques"], chunk):
            assert row["coverage"] == "found" and row["useful_content"] is True
            if row["name_withheld"]:
                withheld[t["id"]] = t["name"]
            else:
                assert row["name"] == t["name"]
    assert withheld == WITHHELD_BY_WORD_SCREEN


def test_old_defense_evasion_name_is_still_accepted_for_older_corpora():
    assert "defense-evasion" in tk.TACTICS
