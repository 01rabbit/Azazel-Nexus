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


#: (what the repository has, the phrasing that denies it, a human name).
#:
#: Patterns rather than sentences: "no package" catches "contains no package",
#: "has no package" and "still has no package" alike, so a rewrite cannot
#: quietly reintroduce the claim in a new shape.
CLAIMS = (
    (_has_package, re.compile(r"\bno package\b", re.I), "a package"),
    (
        _has_dependency_manifest,
        re.compile(r"\bno\b[^.]{0,60}\bdependency manifest\b", re.I),
        "a dependency manifest",
    ),
    (
        _has_fabric_pin,
        re.compile(r"\bno\b[^.]{0,80}\b(?:Azazel-)?Fabric pin\b|\bno pin\b", re.I),
        "an Azazel-Fabric pin",
    ),
    (
        _has_automated_tests,
        re.compile(r"\b(?:only|no)\b[^.]{0,90}\bautomated check", re.I),
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


def test_the_repository_still_has_no_fabric_pin():
    """The one original claim that is still true, pinned as a fact.

    Not decoration. It is what makes the skip above meaningful: without it, a
    Fabric pin could be added and every claim check would simply start
    skipping, reporting nothing. This turns that same event into a failure
    that names the documents to revisit.
    """

    assert not _has_fabric_pin(), (
        "Nexus now declares an azazel-fabric dependency. Update the status "
        f"sentence in each of {list(STATUS_DOCUMENTS)}, and revisit "
        "docs/contract-ownership.md §3, whose mappings were written as design "
        "assertions precisely because no pin bound them."
    )


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
