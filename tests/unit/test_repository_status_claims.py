"""Every document's status sentence, checked against the repository it describes.

Five documents opened with some form of "this repository has no package, no
dependency manifest, and no automated check beyond the documentation link
check". All three had stopped being true: the package, the manifest and the
unit suite arrived with the Knowledge Lite consumer (#18) and no sentence
moved. Only the fourth claim -- no Azazel-Fabric pin -- survived.

A stale status sentence is worse than an absent one. A reader deciding what to
build next reads it, plans around a repository that no longer exists, and has
no way to tell. So the claims are checked rather than maintained.

The check is keyed on the **fact**, not on the sentence. Each pattern below is
refused only while the repository contradicts it, so this file also works in
the other direction: when Nexus adopts a Fabric pin, "no Fabric pin" becomes a
banned phrase and these documents have to say what is true instead.

What this file cannot do
------------------------
It checks claims about **this repository**, because those are the ones it can
measure. A claim about another repository -- "`mio_contracts` is not released",
"Azazel-Gadget is on `v0.4.0`" -- is unreachable from here: Nexus declares no
Fabric dependency and has no view of any sibling. Both of those claims were
stale too, and neither would be caught by anything below.

Two different answers, because they are two different kinds of claim. A pin
another product holds is a fact somebody else already records, so
`test_the_support_matrix_does_not_restate_another_products_pin` refuses the
copy and the document cites Fabric's table instead. A one-off observation of
another repository cannot be cited away, so it is **dated against a named tag**
and checked for that dating
(`test_the_fabric_observation_is_written_against_a_named_tag`). Neither makes
the underlying claim verifiable here; they make an unverifiable claim visible
as one.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

#: Documents that open by describing the state of this repository.
#:
#: Listed literally. Deriving the list by scanning for "Status:" would stop
#: covering a document the moment someone reworded its opening, which is the
#: rewording most likely to carry a stale claim with it.
STATUS_DOCUMENTS = (
    "README.md",
    "docs/IMPLEMENTATION_SPEC.md",
    "docs/architecture.md",
    "docs/contract-ownership.md",
    "docs/inheritance-ledger.md",
    # Added after the first pass missed them. The roadmap carried the same
    # stale bootstrap claim in a different shape ("Still absent: the package
    # layout and dependency manifest; CI covers documentation links only"),
    # and the support matrix carried it as a table row. A list of documents
    # that only covers the ones written in the house phrasing catches the
    # claims that were easy to find.
    "docs/roadmap.md",
    "docs/support-matrix.md",
)


def _text(relative: str) -> str:
    """Whitespace-normalized, so a claim split across lines is still one claim."""

    return re.sub(r"\s+", " ", (ROOT / relative).read_text(encoding="utf-8"))


def _has_package() -> bool:
    return (ROOT / "pyproject.toml").is_file() and (
        ROOT / "src" / "azazel_nexus" / "__init__.py"
    ).is_file()


def _has_dependency_manifest() -> bool:
    if not (ROOT / "pyproject.toml").is_file():
        return False
    # An empty list is a declared dependency set, not an absent manifest: the
    # emptiness is the deliberate statement that CORE depends on nothing.
    return bool(
        re.search(
            r"^dependencies\s*=", (ROOT / "pyproject.toml").read_text("utf-8"), re.M
        )
    )


def _has_fabric_pin() -> bool:
    if not (ROOT / "pyproject.toml").is_file():
        return False
    return "azazel-fabric" in (ROOT / "pyproject.toml").read_text("utf-8")


def _has_automated_tests() -> bool:
    return any((ROOT / "tests").rglob("test_*.py"))


def _has_implemented_modules() -> bool:
    """Code with focused tests behind it -- this repository's own definition.

    A module with no test is not implemented in the sense the status
    vocabulary uses, so the pairing is what is counted rather than the file.
    """

    package = ROOT / "src" / "azazel_nexus"
    tests = {path.name for path in (ROOT / "tests" / "unit").glob("test_*.py")}
    return any(
        path.stem != "__init__" and f"test_{path.stem}.py" in tests
        for path in package.glob("*.py")
    )


#: (what the repository has, the phrasing that denies it, a human name).
#:
#: Patterns rather than sentences: "no package" catches "contains no package",
#: "has no package" and "still has no package" alike, so a rewrite cannot
#: quietly reintroduce the claim in a new shape.
#: Ways of saying a thing is missing. Kept as one alternation so every claim
#: below inherits the same vocabulary: the roadmap said "still absent" where
#: five other documents said "no", and a check that only knew "no" passed it.
_MISSING = r"(?:\bno\b|\babsent\b|\blacks?\b|\bwithout\b)"

CLAIMS = (
    (
        _has_package,
        re.compile(rf"\bno package\b(?! manager)|{_MISSING}[^.]{{0,60}}\bpackage layout\b", re.I),
        "a package",
    ),
    (
        _has_dependency_manifest,
        re.compile(rf"{_MISSING}[^.]{{0,60}}\bdependency manifest\b", re.I),
        "a dependency manifest",
    ),
    (
        _has_fabric_pin,
        re.compile(rf"{_MISSING}[^.]{{0,80}}\b(?:Azazel-)?Fabric pin\b|\bno pin\b", re.I),
        "an Azazel-Fabric pin",
    ),
    (
        _has_implemented_modules,
        # Narrow on purpose. This repository legitimately says of its
        # *documents* that none of them is implemented, and that stays true.
        # What went stale was the blanket sentence about the repository.
        re.compile(
            r"\bnothing (?:here|in this repository) is implemented\b", re.I
        ),
        "implemented modules",
    ),
    (
        _has_automated_tests,
        re.compile(
            r"\b(?:only|no)\b[^.]{0,90}\bautomated check"
            r"|\bdocumentation links? only\b"
            r"|\bonly automated check\b",
            re.I,
        ),
        "an automated test suite",
    ),
)


@pytest.mark.parametrize("relative", STATUS_DOCUMENTS)
@pytest.mark.parametrize("fact,pattern,name", CLAIMS, ids=lambda value: getattr(value, "__name__", None) or (value if isinstance(value, str) else ""))
def test_no_document_denies_something_this_repository_has(relative, fact, pattern, name):
    if not fact():
        pytest.skip(f"the repository still has no {name}; denying it is accurate")

    match = pattern.search(_text(relative))
    assert match is None, (
        f"{relative} says {match.group(0)!r}, but this repository has {name}. "
        "A status sentence nothing checks goes stale silently, and a reader "
        "planning work from it plans around a repository that no longer exists."
    )


def test_fabric_and_mio_are_optional_extras_and_not_core_dependencies():
    """The successor to a guard that has now fired.

    This file used to assert that Nexus had **no** Fabric pin. That assertion
    did its job: adopting the pin turned seven tests red at once and named
    every document carrying a sentence that had just stopped being true. A
    guard whose event has happened is replaced by one for the invariant that
    matters next, not deleted.

    What matters next is the *shape* of the dependency. Nexus must be useful as
    `CORE` with no external Knowledge, no Deception, no remote cognition and no
    cloud connectivity (ADR-0001). Fabric or MIO moving from
    `[project.optional-dependencies]` into `dependencies` would end that quietly -- an import
    line, no document touched -- so it ends loudly here instead.
    """

    text = (ROOT / "pyproject.toml").read_text("utf-8")
    required = text.split("[project.optional-dependencies]", 1)[0]

    assert "azazel-fabric" not in required, (
        "azazel-fabric appears in the required dependency list. Nexus declares "
        "it as the optional `fabric` extra so that CORE works with nothing "
        "installed; making it required is a change of product posture and "
        "needs its own ADR (see docs/adr/0001-fabric-pin.md §Consequences) "
        "plus a revision of docs/inheritance-ledger.md §4.1."
    )
    assert "azazel-mio" not in required, (
        "azazel-mio appears in the required dependency list. Nexus declares "
        "it as the optional `mio` extra so CORE remains independently usable."
    )
    assert "azazel-fabric" in text, (
        "the Fabric pin has disappeared from pyproject.toml; "
        "src/azazel_nexus/fabric_boundary.py names a tag that nothing installs"
    )
    assert ("azazel-mio @ git+https://github.com/01rabbit/Azazel-MIO.git@"
            "9fedb01bc9936531407a5181aa8fa5553ec19d55") in text


def test_the_fabric_observation_is_written_against_a_named_tag():
    """§2 records an observation Nexus cannot re-check, so it must be dated.

    Nexus declares no Fabric dependency, so nothing here can verify which
    modules Fabric ships. An observation that names no tag is a standing claim
    about a moving repository, and that is exactly how §2 came to assert that
    `provisioning_contracts` and `mio_contracts` do not exist after they did.
    """

    text = _text("docs/contract-ownership.md")
    section = text.split("## 2. Observed Fabric state", 1)
    assert len(section) == 2, "contract-ownership.md lost its observation section"
    observation = section[1].split("## 3.", 1)[0]

    # The *first* sentence -- the one that says when and where the observation
    # was made. The section legitimately names later tags further down, so
    # "a tag appears somewhere in it" passed a mutation that deleted the tag
    # the observation itself was dated with.
    first_sentence = re.split(r"\.(?=\s)", observation.strip(), maxsplit=1)[0]

    assert re.search(r"`v\d+\.\d+\.\d+(?:rc\d+)?`", first_sentence), (
        f"the Fabric observation opens with {first_sentence!r} and dates itself "
        "against no tag. Nexus cannot re-check it, so an undated observation is "
        "a claim about whatever Fabric happens to be."
    )


#: The table in `support-matrix.md` that used to copy other products' pins.
_FABRIC_FACTS_HEADING = "| Fact | State |"


def test_the_support_matrix_does_not_restate_another_products_pin():
    """Cite the record; do not copy it.

    This table said the Edge, Deception, Knowledge and Boot pins all agreed on
    `v0.8.0`, and that Azazel-Gadget was on `v0.4.0`. By the time anyone read
    it, four of the five had moved. Nexus cannot check another repository's
    pin, so a version literal for another product here is a second statement
    of somebody else's record with nothing to keep it honest -- the same
    failure as the undated Fabric observation in contract-ownership.md §2.

    Nexus's *own* pin is exempt, because that is a fact this repository holds.
    """

    text = _text("docs/support-matrix.md")
    start = text.find(_FABRIC_FACTS_HEADING)
    assert start != -1, "support-matrix.md lost its Fabric facts table"
    table = text[start:].split("A release will additionally pin", 1)[0]

    offenders = []
    for row in re.findall(r"\|[^|]*\|[^|]*\|", table):
        if "Nexus's Fabric pin" in row:
            continue
        for product, version in re.findall(
            r"(Azazel-[A-Za-z]+|Azazel-Gadget)[^|]{0,120}?`(v\d+\.\d+\.\d+[^`]*)`", row
        ):
            offenders.append(f"{product} pinned at {version}")

    assert offenders == [], (
        f"the Fabric facts table states another product's version: {offenders}. "
        "Link to Azazel-Fabric's release-compatibility table instead; a copy "
        "here is a second statement of a record this repository cannot check."
    )
