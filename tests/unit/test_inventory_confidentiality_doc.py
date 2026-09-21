"""The inventory confidentiality rule says what it says, and holds no value
from any machine (#115).

Three failure modes, all of them quiet:

- the rule acquires an example -- a MAC, a serial, an interface name --
  because somebody found it clearer with one, and the file written to stop
  identifiers travelling becomes one that carries them
- the audit's admissible list stops being closed, so the next writer adds a
  field to it and nothing says no
- a later edit softens the fingerprint rule into a bare hash, which reads like
  anonymisation and is an encoding

The storage table is read as a table rather than as prose: a test that
searched the text for "the audit must not hold raw identity" is satisfied by a
sentence, and the sentence is not what an implementer follows.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[2] / "docs"
DOC = DOCS / "inventory-confidentiality.md"


def _text() -> str:
    return DOC.read_text(encoding="utf-8")


def _flat(text: str | None = None) -> str:
    """Whitespace-normalised. These sentences are wrapped in the source, and
    a test that broke on a reflow would be a test about line lengths."""

    return " ".join((_text() if text is None else text).split())


def _table_after(heading_fragment: str) -> dict[str, list[str]]:
    """Return {first cell: remaining cells} for the first table following a
    line containing `heading_fragment`."""

    rows: dict[str, list[str]] = {}
    lines = _text().splitlines()
    start = next(
        i for i, line in enumerate(lines) if heading_fragment in line
    )
    seen_table = False
    for line in lines[start + 1 :]:
        if not line.startswith("|"):
            if seen_table:
                break
            continue
        seen_table = True
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if set("".join(cells)) <= set("-: "):
            continue
        rows[cells[0]] = cells[1:]
    return rows


def test_the_document_exists():
    assert DOC.is_file(), "the inventory confidentiality rule is missing"


def test_it_carries_no_hardware_address():
    """A MAC in the file that exists to keep MACs out of files."""

    found = re.findall(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b", _text())
    assert found == [], f"the document carries hardware addresses: {found}"


def test_it_carries_no_serial_or_digest_shaped_value():
    """Any long run of hex is a serial, a digest or a fingerprint -- none of
    which this document has a reason to hold."""

    found = re.findall(r"\b[0-9a-fA-F]{12,}\b", _text())
    assert found == [], f"the document carries identifier-shaped values: {found}"


def test_it_names_no_network_interface():
    """An interface name identifies a machine's layout, and naming one here
    would also be this product selecting a role it must never select."""

    found = re.findall(r"\b(?:enp|wlp|ens|eno|eth|wlan)\d[0-9a-z]*\b", _text())
    assert found == [], f"the document names interfaces: {found}"


@pytest.mark.parametrize(
    "value",
    [
        "MAC address",
        "serial",
        "TPM identity",
        "detailed NIC inventory",
        "kernel inventory",
        "asset ID",
    ],
)
def test_raw_identity_names_every_value_the_rule_covers(value):
    """An unnamed value is one the next campaign classifies for itself."""

    raw = _table_after("| class | what it holds |")["**raw identity**"][0]
    assert value in raw, f"raw identity no longer names {value!r}"


def test_the_encrypted_commissioning_record_is_the_only_home_for_raw_identity():
    rows = _table_after("| destination | raw identity |")
    record = next(key for key in rows if "commissioning record" in key)
    assert rows[record][0].startswith("**yes"), rows[record]
    assert "only here" in rows[record][0], rows[record]


@pytest.mark.parametrize(
    "destination", ["append-only audit", "journal", "external report"]
)
def test_no_other_destination_may_hold_raw_identity(destination):
    rows = _table_after("| destination | raw identity |")
    row = next(key for key in rows if destination in key)
    assert rows[row][0].strip("*") == "no", f"{destination} now admits raw identity"


def test_it_says_why_the_audit_is_not_a_confidentiality_boundary():
    """The reason has to be in the file. Without it the row reads as a
    preference, and a preference is what gets traded away."""

    text = _flat()
    assert "Append-only means nobody can erase what is written" in text
    assert "writing a secret somewhere unerasable makes the disclosure permanent" in text


@pytest.mark.parametrize(
    "admissible",
    [
        "the anonymous host ID",
        "the record generation",
        "inventory captured, inventory verified, node commissioned",
        "the approval ID of the responsible operator",
        "a key-protected HMAC fingerprint",
        "the **classification** of a refusal reason",
    ],
)
def test_the_audit_list_keeps_every_admissible_entry(admissible):
    assert admissible in _flat(), f"the audit list lost {admissible!r}"


def test_the_audit_list_is_closed():
    """An open list is a list that grows by the next person's judgement."""

    assert "**Anything not named here does not go in the audit.**" in _flat()


def test_the_fingerprint_is_bound_to_a_secret():
    assert "HMAC bound to the TPM or to the commissioning secret" in _flat().replace(
        "**", ""
    )


def test_a_bare_hash_is_refused_by_name_and_with_its_reason():
    """Refusing it without the arithmetic invites the argument back."""

    text = _flat()
    assert "A bare hash of a MAC address is not an anonymisation." in text.replace(
        "**", ""
    )
    assert "48 bits" in text
    assert "known OUI" in text


@pytest.mark.parametrize(
    "destination", ["audit", "journal", "issue", "pull request", "chat"]
)
def test_the_key_material_is_refused_every_outward_destination(destination):
    """Named individually, because a destination left unlisted is the one
    somebody uses."""

    sentence = next(
        line
        for line in _flat().split(".")
        if "does not appear in the audit" in line
    )
    assert destination in sentence, f"key material may reach {destination!r}"


def test_sharing_defaults_closed():
    text = _flat()
    assert "**The default is closed.**" in text
    assert "treated as raw identity until the" in text


def test_the_approved_host_id_is_the_operator_s_and_not_the_campaign_s():
    assert "An ID nobody approved is not an approved ID" in _flat()


def test_the_document_authorises_nothing():
    text = _flat()
    assert "It does not authorise a measurement, a commissioning, or a connection." in text
    assert "It does not select an interface role." in text


@pytest.mark.parametrize(
    "document", ["core-reserve-measurement.md", "commissioning.md"]
)
def test_the_procedures_reach_the_rule(document):
    """A rule nothing links to is a rule nobody reads at the moment it
    applies."""

    text = (DOCS / document).read_text(encoding="utf-8")
    assert "inventory-confidentiality.md" in text, f"{document} does not link the rule"
