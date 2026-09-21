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
