"""The interpreter floor, stated in five places and checked to be one number.

CPython **3.11**, declared 2026-09-21 by owner decision
([#67](https://github.com/01rabbit/Azazel-Nexus/issues/67)). It is a
**software support baseline**, not one of the `hardware-unverified` gates: it
is a capability the interpreter must have for this code to be correct at all,
and unlike a gate it is checkable here and now.

The reason it is 3.11 and not 3.10 is `tomllib`. It is the canonical reader
for the `anchors.toml` a Knowledge Lite bundle is verified against, and
shipping a hand-written partial TOML parser to read the trust anchor of a
signed artifact would trade a dependency for an attack surface.

A floor written in five places is a floor that disagrees with itself the first
time one of them is edited, so it is written once here and compared.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

#: The one number. Everything below is compared against it.
FLOOR = (3, 11)
FLOOR_TEXT = "3.11"


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


@pytest.mark.parametrize("manifest", ["pyproject.toml", "runtime/pyproject.toml"])
def test_both_distributions_declare_the_floor(manifest: str) -> None:
    assert f'requires-python = ">={FLOOR_TEXT}"' in _read(manifest)


def test_the_ci_matrix_runs_the_floor_and_does_not_run_below_it() -> None:
    """A floor no job exercises is a floor nobody finds out about."""

    workflow = _read(".github/workflows/ci.yml")
    matrix = re.search(r"python-version: \[(.*?)\]", workflow)
    assert matrix, "the unit-test job declares no python-version matrix"
    versions = [v.strip().strip('"') for v in matrix.group(1).split(",")]
    assert FLOOR_TEXT in versions, f"no job runs the floor {FLOOR_TEXT}"
    for version in versions:
        parts = tuple(int(part) for part in version.split("."))
        assert parts >= FLOOR, f"the matrix runs {version}, which is below the floor"


def test_the_installer_refuses_below_the_floor_before_writing_anything() -> None:
    """An explicit failure, not a fallback and not a partial install."""

    installer = _read("packaging/install.sh")
    assert f"(3, 11)" in installer
    assert "requires Python 3.11 or newer" in installer
    assert "no fallback parser" in installer

    # Before anything is written. The check has to precede the first `install`
    # command, or a refused node is a half-installed node.
    check_at = installer.index("version_info >= (3, 11)")
    first_write = installer.index("install -d")
    assert check_at < first_write, (
        "the interpreter check runs after the installer has started writing"
    )


def test_the_support_matrix_declares_it_as_a_software_baseline() -> None:
    matrix = _read("docs/support-matrix.md")
    assert "software support baseline" in matrix
    assert f"CPython **≥ {FLOOR_TEXT}**" in matrix
    assert "Language and runtime matrix | Nothing." not in matrix, (
        "the runtime row is still listed as undeclared in §7"
    )


def test_the_baseline_is_not_recorded_as_a_hardware_gate() -> None:
    """The two registers say different kinds of thing, and must stay apart.

    A gate is a claim about behaviour on a machine nothing has run on. A
    baseline is checkable here and now. Recording the interpreter floor among
    the gates would put something already settled into a register of things
    that are not.
    """

    gates = _read("docs/hardware-gates.md")
    assert "tomllib" not in gates
    assert "3.11" not in gates
    assert "HG-07" in gates, "a vacuous check: the gate register was not read"


def test_tomllib_is_importable_on_every_interpreter_this_runs_on() -> None:
    """The capability the floor exists for, exercised rather than described."""

    assert sys.version_info >= FLOOR
    import tomllib

    assert tomllib.loads('threshold = 1\n') == {"threshold": 1}


def test_no_hand_written_toml_parser_was_shipped_instead():
    """The trade the floor exists to avoid.

    A partial parser for the trust anchor of a signed artifact is an attack
    surface bought with a dependency's worth of convenience.
    """

    import ast

    package = ROOT / "src" / "azazel_nexus"
    offenders = []
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and "toml" in node.name.lower():
                offenders.append(f"{path.name}:{node.name}")
    assert offenders == [], (
        f"{offenders} look like a hand-written TOML reader; tomllib is the "
        "canonical one and the floor exists so that it is available"
    )


def test_the_target_hardware_is_named_rather_than_left_to_the_reader() -> None:
    """A gate that says "the target hardware" and never says what it is.

    That phrase appears in every gate, in the measurement procedure and in the
    README, and until it was written down a reader could supply their own
    answer -- a Pi, a laptop, whatever was to hand. A reserve measured on the
    wrong machine is not a weaker measurement; it is a measurement of a
    different machine, offered for an admission decision on this one.

    `inheritance-ledger.md` §1 already drew the line: constrained,
    Raspberry-Pi-class hardware is Azazel-Edge's proving ground and Nexus is
    the rugged x86_64 integration product. This pins the gates to it.
    """

    # Whitespace-normalised: these sentences are wrapped in the source, and a
    # test that broke on a reflow would be a test about line lengths.
    def flat(name):
        return " ".join(_read(name).split())

    gates = flat("docs/hardware-gates.md")
    assert "generic rugged x86_64 Linux PC, at the resource class actually deployed" in gates
    assert "Raspberry-Pi-class devices are Azazel-Edge's proving ground" in gates
    assert "never evidence for a provider admission" in gates

    procedure = flat("docs/core-reserve-measurement.md")
    assert "generic rugged x86_64 Linux PC at the resource class being measured" in procedure
    assert "is not admissible as this class's reserve" in procedure

    readme = flat("README.md")
    assert "generic rugged x86_64 Linux PC at the resource class deployed" in readme


def test_the_reserve_classes_and_the_target_classes_do_not_read_as_a_contradiction() -> None:
    """Three classes in one document and four in another, a few files apart.

    Both are right -- the reserve is keyed by the selected profile and the
    selector has three floors, while performance and retention targets are
    recorded per memory class and 64 GB is one -- but `support-matrix.md`
    forbids restating these numbers differently anywhere, so the difference
    has to be explained where it is visible rather than left to be discovered.
    """

    gates = " ".join(_read("docs/hardware-gates.md").split())
    assert "8, 16 and 32 GB classes" in gates
    assert "a 64 GB host selects `standard` exactly as a 32 GB host does" in gates
    assert "counting different measurements" in gates


def test_the_two_version_numbers_are_explained_where_people_read() -> None:
    """The domain/schema rule lives in the contract document, not only in a
    docstring a reader has to go looking for.

    It is the kind of rule that gets re-derived wrongly the first time
    somebody adds a field under time pressure, and the cheapest place to
    settle it is where they will already be reading.
    """

    contract = " ".join(_read("docs/model-catalog.md").split())
    assert "The domain version and the schema version are different numbers" in contract
    assert "canonical signing protocol" in contract
    assert "the domain did not" in contract
    # And the three things verification checks, named together.
    assert "the domain, the schema version and the canonical bytes all hold" in contract


def test_a_null_source_is_documented_as_terminal() -> None:
    """Not a slot, not a search. Stated in both documents that touch it."""

    for name in ("docs/model-catalog.md", "docs/model-acquisition.md"):
        text = " ".join(_read(name).split())
        assert "no source usable for online acquisition" in text, name
        assert "not** a slot for an endpoint to be supplied later" in text or (
            "no endpoint may be supplied later to fill it" in text
        ), name
        assert "importable offline" in text or "import of such an artifact is permitted" in text, name
