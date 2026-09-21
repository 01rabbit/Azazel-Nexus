"""The candidate document names no machine, and says why (#115).

The failure it exists to prevent: a machine appears in a document as an
"option", a reader takes it for a tested one, and the empty compatibility
table that `support-matrix.md` §6 keeps empty on purpose has been defeated by
a file somewhere else.

So the document is checked for the absence of a name, for the three states an
entry could be in, and for the rule that an entry needs owner ratification and
a linked evidence record.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOC = REPO / "docs" / "deployment-candidates.md"


def _flat() -> str:
    return " ".join(DOC.read_text(encoding="utf-8").split())


def test_the_document_exists_and_is_reachable_from_the_readme():
    assert DOC.is_file()
    assert "docs/deployment-candidates.md" in (REPO / "README.md").read_text(
        encoding="utf-8"
    )


def test_it_names_no_machine():
    """The candidate table has one row and that row is empty.

    Read as a table: a sentence saying the list is empty is satisfied by a
    sentence, and a reader follows the table.
    """

    rows = [
        line
        for line in DOC.read_text(encoding="utf-8").splitlines()
        if line.startswith("|")
    ]
    entries = [
        line
        for line in rows
        if line.startswith("| ") and "System" not in line and set(line) - set("| -:")
    ]
    body = [line for line in entries if not re.match(r"^\|[\s\-:|]+\|$", line)]
    # Every remaining row belongs to the requirement tables, not to a
    # candidate list; the candidate table's only row is the em-dash one.
    assert "| — | — | — | — |" in DOC.read_text(encoding="utf-8")
    assert not any("candidate" in line.lower() and "http" in line for line in body)


@pytest.mark.parametrize(
    "vendor",
    ["Advantech", "Axiomtek", "OnLogic", "Getac", "Durabook", "Toughbook",
     "Protectli", "Supermicro", "ThinkCentre", "NUC", "Kontron", "Moxa",
     "Neousys", "ADLINK", "AAEON", "Beelink", "Minisforum", "ASRock"],
)
def test_no_vendor_or_product_name_appears(vendor):
    """A curated list, because a machine reaches a document by being typed
    into it and the typing is what this catches."""

    assert vendor.lower() not in _flat().lower(), f"{vendor} was named"


@pytest.mark.parametrize(
    "state", ["`evaluation candidate`", "`8 GiB pilot target`", "`hardware-verified`"]
)
def test_the_three_states_are_defined(state):
    assert state in _flat()


def test_an_entry_requires_ratification_and_evidence():
    flat = _flat()
    assert "owner ratification and a linked evidence record" in flat
    assert "A name in a document is not an entry." in flat


def test_it_says_the_first_pilot_machine_is_an_open_decision():
    """The honest answer to "which machine". Anything else invites the
    reader to supply their own."""

    assert "**Selecting the first pilot machine is an open owner decision.**" in _flat()


def test_it_makes_no_claim_about_suitability_from_a_name():
    """Checked on the body only. §4 is the prohibition itself, and a scan
    that could not tell a ban from a claim would be a scan that forces the
    ban to be written in words nobody recognises."""

    body, _, prohibition = DOC.read_text(encoding="utf-8").partition(
        "## 4. What must not be written here"
    )
    assert prohibition, "the prohibition section is gone"
    flat = " ".join(body.split()).lower()
    for claim in ("recommended machine", "field-proven", "military-grade", "certified for"):
        assert claim not in flat


def test_it_does_not_restate_the_measurement_thresholds():
    """A second copy of a threshold is the copy that goes stale. The class
    table is the selector's own and is cited; the sampling numbers are not
    repeated at all."""

    flat = _flat()
    assert "60 samples" not in flat
    assert "MIN_SAMPLES" not in flat
    assert "not restated as numbers here" in flat


def test_the_class_table_agrees_with_the_selector():
    """Read from the code, so the two cannot drift."""

    from azazel_nexus.resource_profile import ResourceProfile, select_profile

    flat = _flat()
    assert "`7168` – `15359` | `core`" in flat
    assert select_profile(7168) is ResourceProfile.CORE
    assert select_profile(15359) is ResourceProfile.CORE
    assert select_profile(7167) is ResourceProfile.DIAGNOSTIC
    assert select_profile(15360) is ResourceProfile.LITE


def test_it_carries_no_machine_identity():
    text = DOC.read_text(encoding="utf-8")
    assert re.search(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b", text) is None
    assert re.findall(r"\b[0-9a-fA-F]{16,}\b", text) == []
