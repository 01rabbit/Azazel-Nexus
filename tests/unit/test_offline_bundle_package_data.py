"""The offline source bundle ships the package data the pyprojects declare.

Found during u45 official-wheel acceptance: the bundle kept only `.py` files from
the source trees, so `azazel_nexus_runtime/ui_static/*` (declared in
runtime/pyproject.toml `[tool.setuptools.package-data]`) was missing from the
bundle and from the wheel built from it, and the installed `az-ui` refused with
`source_or_assets_unreadable`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

from tools.build_offline_bundle import _inputs, build_bundle, package_data_files

from test_offline_bundle import _members, _repo

REAL = Path(__file__).resolve().parents[2]
UI = "runtime/src/azazel_nexus_runtime/ui_static/"
DECLARED_UI = {UI + "index.html", UI + "app.js", UI + "app.css", UI + "labels.json"}


def _declared(root: Path) -> set[str]:
    """The package data declared by the pyprojects, matched against the tree."""
    names = set()
    for pyproject, source in ((("pyproject.toml",), ("src",)),
                              (("runtime", "pyproject.toml"), ("runtime", "src"))):
        data = tomllib.loads(root.joinpath(*pyproject).read_text(encoding="utf-8"))
        declared = data.get("tool", {}).get("setuptools", {}).get("package-data", {})
        for package, patterns in declared.items():
            base = root.joinpath(*source, *package.split("."))
            for pattern in patterns:
                names |= {item.relative_to(root).as_posix() for item in base.glob(pattern)}
    return names


def _with_package_data(root: Path, extra: dict[str, bytes] | None = None) -> Path:
    runtime = root / "runtime/pyproject.toml"
    runtime.write_text(
        "[project]\nname='azazel-nexus-runtime'\n"
        "[tool.setuptools.package-data]\n"
        'azazel_nexus_runtime = ["ui_static/*.html", "ui_static/*.js"]\n',
        encoding="utf-8")
    files = {UI + "index.html": b"<html>", UI + "app.js": b"1;",
             UI + "notes.txt": b"not declared", UI + "secret.bin": b"not declared"}
    files.update(extra or {})
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "-c", "user.name=T", "-c", "user.email=t@example.invalid",
                    "commit", "-qm", "package data"], cwd=root, check=True)
    return root


def test_the_declared_package_data_is_in_the_real_bundle_inputs():
    names = {name for _, name in _inputs(REAL)}
    assert DECLARED_UI <= names


def test_the_bundle_selection_and_the_declaration_cannot_diverge():
    """Every non-.py file taken from the source trees is a declared package-data file
    (or the native source the build recipe names): nothing wider, nothing missing."""
    names = {name for _, name in _inputs(REAL)}
    from_sources = {name for name in names
                    if name.startswith(("src/", "runtime/src/")) and not name.endswith(".py")}
    expected = _declared(REAL) | {"runtime/src/azazel_nexus_runtime/_bootstrap_deadline.c"}
    assert from_sources == expected
    assert _declared(REAL) and DECLARED_UI <= _declared(REAL)


def test_a_new_package_data_declaration_is_followed_by_the_bundle(tmp_path):
    root = _repo(tmp_path / "repo")
    _with_package_data(root)
    shipped = set(_members(_build(root, tmp_path)))
    assert UI + "index.html" in shipped and UI + "app.js" in shipped


def _build(root: Path, tmp_path: Path) -> Path:
    output = tmp_path / "source.tar.gz"
    build_bundle(root, output)
    return output


def test_files_that_are_not_declared_are_not_added(tmp_path):
    root = _repo(tmp_path / "repo")
    _with_package_data(root)
    shipped = set(_members(_build(root, tmp_path)))
    assert UI + "notes.txt" not in shipped and UI + "secret.bin" not in shipped


def test_a_pattern_that_matches_nothing_is_an_error(tmp_path):
    root = _repo(tmp_path / "repo")
    (root / "runtime/pyproject.toml").write_text(
        "[project]\nname='x'\n[tool.setuptools.package-data]\n"
        'azazel_nexus_runtime = ["ui_static/*.html"]\n', encoding="utf-8")
    with pytest.raises(ValueError, match="matches no file"):
        package_data_files(root)


def test_a_symlinked_package_data_file_is_refused(tmp_path):
    root = _repo(tmp_path / "repo")
    _with_package_data(root)
    target = root / UI / "index.html"
    target.unlink()
    (root / "elsewhere.html").write_text("x")
    target.symlink_to(root / "elsewhere.html")
    with pytest.raises(ValueError, match="symlink"):
        package_data_files(root)


@pytest.mark.parametrize("pattern", ["/etc/passwd", "../../x", "ui_static/../../x"])
def test_a_pattern_that_leaves_the_package_is_refused(tmp_path, pattern):
    root = _repo(tmp_path / "repo")
    (root / "runtime/pyproject.toml").write_text(
        "[project]\nname='x'\n[tool.setuptools.package-data]\n"
        f'azazel_nexus_runtime = ["{pattern}"]\n', encoding="utf-8")
    with pytest.raises(ValueError, match="relative path"):
        package_data_files(root)


def test_the_selection_is_byte_identical_between_runs(tmp_path):
    root = _repo(tmp_path / "repo")
    _with_package_data(root)
    first = _build(root, tmp_path).read_bytes()
    second_dir = tmp_path / "again"
    second_dir.mkdir()
    assert _build(root, second_dir).read_bytes() == first


def test_a_wheel_built_from_the_bundle_selection_contains_ui_static(tmp_path):
    """Built offline from exactly the selected inputs. Skipped where the build tools
    (setuptools, wheel, a C compiler for the native extension) are not available."""
    tree = tmp_path / "tree"
    for source, name in _inputs(REAL):
        destination = tree / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    out = tmp_path / "wheel"
    result = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-build-isolation", "--no-deps",
         "-q", "-w", str(out), str(tree / "runtime")],
        capture_output=True, text=True, env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"})
    if result.returncode != 0:
        pytest.skip("the offline wheel build is not available here")
    [wheel] = list(out.glob("azazel_nexus_runtime-*.whl"))
    members = set(zipfile.ZipFile(wheel).namelist())
    assert {name.removeprefix("runtime/src/") for name in DECLARED_UI} <= members
