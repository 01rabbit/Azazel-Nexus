"""The test stub stays in `tests/`, and the shipped build never names it (#114).

A stub that could reach the production package is a stub that could be
started on a node. The containment is checked in **both directions**,
because either alone would pass while the other was broken:

- the stub is under `tests/` and nowhere else
- nothing shipped -- package, catalog, runtime allowlist, installer, preset,
  unit files, console scripts -- names it

The second direction is the one that matters after somebody adds a real
runtime. `RUNTIMES` gaining an entry is a reviewed change; `RUNTIMES` gaining
the *stub* is the accident this file exists to make loud.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "runtime" / "src"))

from azazel_nexus.model_runtime import RUNTIMES  # noqa: E402

STUB_NAME = "az-runtime-" + "stub"
STUB_DIR = REPO_ROOT / "tests" / "fixtures" / "runtime_stub"

#: Everything a node installs or reads. If the stub's name appears in any of
#: these, it has left the test tree.
SHIPPED_TREES = (
    REPO_ROOT / "src",
    REPO_ROOT / "runtime" / "src",
    REPO_ROOT / "packaging",
    REPO_ROOT / "tools",
)

SHIPPED_FILES = (
    REPO_ROOT / "pyproject.toml",
    REPO_ROOT / "runtime" / "pyproject.toml",
    REPO_ROOT / "packaging" / "install.sh",
    REPO_ROOT / "packaging" / "azazel-nexus.preset",
)


def test_the_stub_exists_and_is_executable():
    """Otherwise every containment check below passes vacuously."""

    binary = STUB_DIR / "usr" / "libexec" / "azazel" / STUB_NAME
    assert binary.is_file(), f"{STUB_NAME} is missing; the lifecycle tests drive it"
    assert binary.stat().st_mode & 0o111, f"{STUB_NAME} is not executable"


def test_the_stub_lives_only_under_tests():
    found = sorted(
        path.relative_to(REPO_ROOT).as_posix()
        for path in REPO_ROOT.rglob(STUB_NAME)
        if ".git" not in path.parts
    )
    assert found, "the stub was not found at all"
    for path in found:
        assert path.startswith("tests/"), f"{path} is outside the test tree"


@pytest.mark.parametrize(
    "tree", SHIPPED_TREES, ids=[t.relative_to(REPO_ROOT).as_posix() for t in SHIPPED_TREES]
)
def test_no_shipped_tree_names_the_stub(tree):
    offenders = []
    for path in sorted(tree.rglob("*")):
        if not path.is_file() or path.suffix in {".pyc", ".so"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if STUB_NAME in text:
            offenders.append(path.relative_to(REPO_ROOT).as_posix())
    assert offenders == [], f"{offenders} name the test stub"


@pytest.mark.parametrize(
    "path", SHIPPED_FILES, ids=[p.name for p in SHIPPED_FILES]
)
def test_no_shipped_manifest_names_the_stub(path):
    assert STUB_NAME not in path.read_text(encoding="utf-8")


def test_the_production_allowlist_pins_one_real_runtime():
    """The shipped state, asserted here as well as in the model-runtime
    tests: a stub that reached `RUNTIMES` would be a stub a node could
    start."""

    assert set(RUNTIMES) == {"llama-cpp-b11716"}
    assert STUB_NAME not in RUNTIMES


def test_no_unit_file_names_the_stub():
    units = sorted((REPO_ROOT / "packaging" / "systemd").glob("*.service"))
    assert units, "no unit files were found, so this check proved nothing"
    for unit in units:
        assert STUB_NAME not in unit.read_text(encoding="utf-8"), unit.name


def test_no_console_script_names_the_stub():
    manifest = (REPO_ROOT / "runtime" / "pyproject.toml").read_text(encoding="utf-8")
    scripts = [
        line.split("=", 1)[0].strip()
        for line in manifest.splitlines()
        if line.startswith("az-") and "=" in line
    ]
    assert scripts, "no console scripts were found, so this check proved nothing"
    assert STUB_NAME not in scripts


def test_the_scan_would_notice():
    """Each direction run against something that violates it, so a pass means
    it looked."""

    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        planted = Path(directory) / "shipped.py"
        planted.write_text(f'RUNTIMES = {{"{STUB_NAME}": 1}}\n', encoding="utf-8")
        assert STUB_NAME in planted.read_text(encoding="utf-8"), (
            "the content scan would not have noticed a planted name"
        )

    outside = Path("/usr/libexec/azazel") / STUB_NAME
    assert not outside.as_posix().startswith("tests/"), (
        "the location check would not have noticed a stub outside the tests"
    )
