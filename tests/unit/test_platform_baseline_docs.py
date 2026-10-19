"""One baseline, cited in one place, said the same way everywhere (#115).

The failure this guards against is the one `Azazel-Boot/docs/compatibility.md`
§2.1 already records once: a product assumption laundered into an inherited
decision by a citation to a document that did not say it. So every place that
states the platform cites the program finding, and the code and the documents
are compared against each other rather than against a number typed here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from azazel_nexus import hil_preflight

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs"
FINDING = "OF-07"


def _flat(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


BASELINE_DOCUMENTS = (
    REPO / "README.md",
    DOCS / "support-matrix.md",
    DOCS / "IMPLEMENTATION_SPEC.md",
    DOCS / "hil-preflight.md",
    DOCS / "deployment-candidates.md",
    DOCS / "core-reserve-measurement.md",
    DOCS / "adr" / "0002-debian-13-baseline.md",
)


@pytest.mark.parametrize("path", BASELINE_DOCUMENTS, ids=lambda p: p.name)
def test_every_document_that_states_the_baseline_cites_the_finding(path):
    """Cite the record; do not copy it. A restatement with no citation is a
    second statement of somebody else's decision with nothing to keep it
    honest."""

    text = _flat(path)
    assert "Debian 13" in text, f"{path.name} no longer states the baseline"
    assert FINDING in text, f"{path.name} states the baseline without citing {FINDING}"


def test_the_code_and_the_documents_agree_about_which_platform():
    """Read from the module, so a constant changed without the documents
    fails here rather than on a host."""

    assert hil_preflight.BASELINE_OS_ID == "debian"
    assert hil_preflight.BASELINE_OS_VERSION_ID == "13"
    assert hil_preflight.BASELINE_ARCHITECTURE == "x86_64"

    for path in BASELINE_DOCUMENTS:
        flat = _flat(path)
        version = f"{hil_preflight.BASELINE_OS_ID.capitalize()} {hil_preflight.BASELINE_OS_VERSION_ID}"
        assert version in flat, f"{path.name} does not name {version}"


def test_the_support_matrix_no_longer_carries_the_declared_rows_as_undeclared():
    """§7's own rule: a row leaves it by an owner decision, never by a
    contributor choosing a plausible value. These left by OF-07."""

    text = _flat(DOCS / "support-matrix.md")
    undeclared = text.split("## 7. Undeclared")[1].split("## 8.")[0]
    assert "OS distribution and release" not in undeclared
    assert "Firmware/boot path requirements" not in undeclared


def test_the_kernel_series_is_still_undeclared():
    """Debian 13 ships a series; naming one here would be a number nobody
    measured, and a point release changes it without changing the baseline."""

    text = _flat(DOCS / "support-matrix.md")
    undeclared = text.split("## 7. Undeclared")[1].split("## 8.")[0]
    assert "Kernel series" in undeclared
    assert re.search(r"\b6\.\d+\b", undeclared) is None, "a kernel series was named"


@pytest.mark.parametrize(
    "claim",
    ["Ubuntu", "Fedora", "RHEL", "Rocky", "AlmaLinux", "CentOS", "openSUSE", "Arch"],
)
def test_no_other_distribution_is_named_as_a_support_target(claim):
    """They are kept in one comparison document in the umbrella repository,
    as a future evaluation profile. A Nexus document that named one would be
    the second place they live."""

    for path in BASELINE_DOCUMENTS:
        text = path.read_text(encoding="utf-8")
        # Word boundaries: "Architecture" is not a distribution named "Arch".
        if re.search(rf"\b{re.escape(claim)}\b", text) is None:
            continue
        # Only the README's pointer at the future-profile document may say it,
        # and it says it as a non-target.
        assert path.name == "README.md", f"{path.name} names {claim}"
        assert "not a v1 support target" in " ".join(text.split())


def test_the_preflight_document_explains_why_one_platform():
    flat = _flat(DOCS / "hil-preflight.md")
    assert "a record taken on another is a record of another platform" in flat
    assert "never on `PRETTY_NAME`" in flat


def test_the_luks_refusal_names_the_disposition_it_produces():
    """A host that cannot protect raw identity is refused for HIL and for
    operational deployment, and is diagnostics-only. Stating the refusal
    without the disposition leaves an operator asking what the machine is
    still good for."""

    for path in (DOCS / "hil-preflight.md", DOCS / "support-matrix.md",
                 DOCS / "adr" / "0002-debian-13-baseline.md"):
        flat = _flat(path)
        assert "diagnostic" in flat.lower(), f"{path.name} does not say what is left"


def test_the_adr_records_rather_than_re_decides():
    """The umbrella owns the frame; a product ADR adopts it. An ADR that
    restated it more strongly would be a second decision."""

    flat = _flat(DOCS / "adr" / "0002-debian-13-baseline.md")
    assert "adopts the OF-07 frame unchanged" in flat
    assert "does not re-decide it, restate it more strongly, or extend it" in flat


def test_the_fabric_pin_is_untouched_by_the_baseline():
    """The baseline is recorded per entry in a field that already exists at
    the pinned tag. No re-pin follows from it."""

    flat = _flat(DOCS / "adr" / "0002-debian-13-baseline.md")
    assert "The Fabric pin does not move" in flat
    assert "v0.9.0rc5" in (REPO / "pyproject.toml").read_text(encoding="utf-8")
