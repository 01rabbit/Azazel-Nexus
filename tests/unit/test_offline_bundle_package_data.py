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
import zipfile
from pathlib import Path

import pytest

from tools import check_wheel_package_data as oracle
from tools.build_offline_bundle import _inputs, build_bundle, package_data_files

from test_offline_bundle import _members, _repo

REAL = Path(__file__).resolve().parents[2]
UI = "runtime/src/azazel_nexus_runtime/ui_static/"
DECLARED_UI = {UI + "index.html", UI + "app.js", UI + "app.css", UI + "labels.json"}


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


# -- Codex 13: symlinks at any component, and setuptools glob semantics -------------------------------------------


def _declare(root: Path, patterns: str = '"ui_static/*.html", "ui_static/*.js"') -> None:
    (root / "runtime/pyproject.toml").write_text(
        "[project]\nname='azazel-nexus-runtime'\n[tool.setuptools.package-data]\n"
        f"azazel_nexus_runtime = [{patterns}]\n", encoding="utf-8")


def test_a_symlinked_intermediate_directory_is_refused(tmp_path):
    root = _repo(tmp_path / "repo")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "index.html").write_text("secret")
    package = root / "runtime/src/azazel_nexus_runtime"
    (package / "ui_static").symlink_to(outside, target_is_directory=True)
    _declare(root)
    with pytest.raises(ValueError, match="symlink"):
        package_data_files(root)


def test_a_symlinked_package_directory_is_refused(tmp_path):
    root = _repo(tmp_path / "repo")
    outside = tmp_path / "outside_pkg"
    (outside / "ui_static").mkdir(parents=True)
    (outside / "ui_static" / "index.html").write_text("secret")
    package = root / "runtime/src/azazel_nexus_runtime"
    shutil.rmtree(package)
    package.symlink_to(outside, target_is_directory=True)
    _declare(root)
    with pytest.raises(ValueError, match="symlink"):
        package_data_files(root)


def test_a_symlink_in_an_ancestor_of_the_package_is_refused(tmp_path):
    root = _repo(tmp_path / "repo")
    real = tmp_path / "real_src"
    shutil.copytree(root / "runtime/src", real)
    (real / "azazel_nexus_runtime/ui_static").mkdir()
    (real / "azazel_nexus_runtime/ui_static/index.html").write_text("x")
    shutil.rmtree(root / "runtime/src")
    (root / "runtime/src").symlink_to(real, target_is_directory=True)
    _declare(root)
    with pytest.raises(ValueError, match="symlink"):
        package_data_files(root)


def test_a_dangling_symlink_match_is_refused_not_skipped(tmp_path):
    root = _repo(tmp_path / "repo")
    _with_package_data(root)
    (root / UI / "dangling.html").symlink_to(root / "nowhere.html")
    _declare(root)
    with pytest.raises(ValueError, match="symlink"):
        package_data_files(root)


def test_a_symlink_refusal_is_a_non_zero_failure_of_the_build(tmp_path):
    root = _repo(tmp_path / "repo")
    _with_package_data(root)
    (root / UI / "index.html").unlink()
    (root / "elsewhere.html").write_text("x")
    (root / UI / "index.html").symlink_to(root / "elsewhere.html")
    with pytest.raises(ValueError, match="symlink"):
        build_bundle(root, tmp_path / "source.tar.gz")
    assert not (tmp_path / "source.tar.gz").exists()


def test_hidden_files_are_not_matched_by_a_wildcard_but_a_named_one_is(tmp_path):
    root = _repo(tmp_path / "repo")
    _with_package_data(root, {UI + ".hidden.html": b"h", UI + ".hidden.js": b"h"})
    names = {item.relative_to(root).as_posix() for item in package_data_files(root)}
    assert UI + ".hidden.html" not in names and UI + ".hidden.js" not in names
    _declare(root, '"ui_static/.hidden.js"')
    named = {item.relative_to(root).as_posix() for item in package_data_files(root)}
    assert named == {UI + ".hidden.js"}


def test_the_selection_is_sorted(tmp_path):
    root = _repo(tmp_path / "repo")
    _with_package_data(root, {UI + "b.html": b"b", UI + "a.html": b"a"})
    names = [item.relative_to(root).as_posix() for item in package_data_files(root)]
    assert names == sorted(names)


def _wheel_of_checkout(source_runtime: Path, out: Path) -> Path:
    """A wheel built straight from a checkout's runtime directory, offline. The
    build is the oracle: nothing here uses the bundler's selection code."""
    result = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-build-isolation", "--no-deps",
         "-q", "-w", str(out), str(source_runtime)],
        capture_output=True, text=True, env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"})
    if result.returncode != 0:
        pytest.skip("the offline wheel build is not available here")
    [wheel] = list(out.glob("azazel_nexus_runtime-*.whl"))
    return wheel


def _copy_runtime(destination: Path) -> Path:
    shutil.copytree(REAL / "runtime", destination, ignore=shutil.ignore_patterns(
        "__pycache__", "build", "*.egg-info", "*.pyc", "dist"))
    return destination


def test_the_real_bundle_selection_equals_the_package_data_of_a_wheel_built_from_the_checkout(
        tmp_path):
    """Independent oracle: the RECORD of a wheel built from the checkout lists the
    package data; the bundle's selected non-code files must be exactly those."""
    wheel = _wheel_of_checkout(_copy_runtime(tmp_path / "runtime"), tmp_path / "wheel")
    in_wheel = oracle.wheel_package_data(wheel, "azazel_nexus_runtime")
    assert in_wheel  # the oracle found package data at all
    selected = {name.removeprefix("runtime/src/azazel_nexus_runtime/")
                for _, name in _inputs(REAL)
                if name.startswith("runtime/src/azazel_nexus_runtime/")
                and not name.endswith(".py")}
    assert selected == in_wheel


def test_the_bundle_archive_equals_the_wheel_record_through_the_check_script(tmp_path):
    """The same comparison as the standalone script, on an archive built from a copy
    of the checkout (git is not needed: the archive is made from `_inputs`)."""
    import tarfile as tarlib
    wheel = _wheel_of_checkout(_copy_runtime(tmp_path / "runtime"), tmp_path / "wheel")
    archive = tmp_path / "source.tar.gz"
    with tarlib.open(archive, "w:gz") as handle:
        for source, name in _inputs(REAL):
            handle.add(source, arcname=name)
    assert oracle.compare(wheel, archive, "azazel_nexus_runtime", "runtime/src") == (set(), set())
    assert oracle.main(["--wheel", str(wheel), "--bundle", str(archive)]) == 0


def test_the_check_script_reports_a_dropped_and_an_added_file(tmp_path, capsys):
    import tarfile as tarlib
    wheel = _wheel_of_checkout(_copy_runtime(tmp_path / "runtime"), tmp_path / "wheel")
    archive = tmp_path / "source.tar.gz"
    with tarlib.open(archive, "w:gz") as handle:
        for source, name in _inputs(REAL):
            if name.endswith("ui_static/labels.json"):
                continue  # dropped
            handle.add(source, arcname=name)
        extra = tmp_path / "extra.txt"
        extra.write_text("x")
        handle.add(extra, arcname="runtime/src/azazel_nexus_runtime/ui_static/extra.txt")
    assert oracle.main(["--wheel", str(wheel), "--bundle", str(archive)]) == 1
    out = capsys.readouterr().out
    assert "missing from the bundle: ui_static/labels.json" in out
    assert "not in the wheel: ui_static/extra.txt" in out
    assert oracle.main(["--wheel", str(tmp_path / "missing.whl"), "--bundle", str(archive)]) == 2


def test_hidden_files_are_in_neither_the_selection_nor_the_wheel(tmp_path):
    """Setuptools does not match a leading-dot name with a wildcard; the selection must
    agree with what the build actually shipped, hidden files present in the tree."""
    runtime = _copy_runtime(tmp_path / "tree" / "runtime")
    shutil.copy2(REAL / "pyproject.toml", tmp_path / "tree" / "pyproject.toml")
    ui = runtime / "src/azazel_nexus_runtime/ui_static"
    (ui / ".hidden.js").write_text("hidden")
    (ui / ".hidden.html").write_text("hidden")
    wheel = _wheel_of_checkout(runtime, tmp_path / "wheel")
    in_wheel = oracle.wheel_package_data(wheel, "azazel_nexus_runtime")
    selected = {item.relative_to(runtime / "src/azazel_nexus_runtime").as_posix()
                for item in package_data_files(tmp_path / "tree")}
    assert not any(".hidden" in name for name in in_wheel | selected)
    # The native extension's source is a fixed bundle input that MANIFEST.in also
    # ships in the wheel; everything else the wheel lists is declared package data.
    assert selected == in_wheel - {"_bootstrap_deadline.c"}


# -- nothing outside the repository can enter the bundle ---------------------------------------------------------

SENTINEL_NAME = "sentinel-outside-the-repository.html"
SENTINEL_BYTES = b"SENTINEL-BYTES-MUST-NEVER-BE-ARCHIVED"


def _outside(tmp_path: Path) -> Path:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / SENTINEL_NAME).write_bytes(SENTINEL_BYTES)
    (outside / "index.html").write_bytes(SENTINEL_BYTES)
    return outside


def _nothing_leaked(tmp_path: Path) -> None:
    """No archive or manifest was produced, and none holds the sentinel."""
    for path in tmp_path.rglob("*"):
        if path.is_file() and not path.is_symlink() and "repo" not in path.parts:
            if path.name.endswith((".tar.gz", ".json")) and path.name != SENTINEL_NAME:
                assert SENTINEL_BYTES not in path.read_bytes(), path
    assert not (tmp_path / "source.tar.gz").exists()


@pytest.mark.parametrize("shape", ["package-data-dir", "package-dir", "ancestor"])
def test_no_file_outside_the_repository_can_enter_the_bundle(tmp_path, shape):
    root = _repo(tmp_path / "repo")
    outside = _outside(tmp_path)
    package = root / "runtime/src/azazel_nexus_runtime"
    _declare(root, '"ui_static/*.html"')
    if shape == "package-data-dir":
        (package / "ui_static").symlink_to(outside, target_is_directory=True)
    elif shape == "package-dir":
        holder = tmp_path / "outside_pkg_holder"
        shutil.move(str(package), str(holder))
        (holder / "ui_static").mkdir(parents=True)
        (holder / "ui_static" / SENTINEL_NAME).write_bytes(SENTINEL_BYTES)
        (holder / "ui_static" / "index.html").write_bytes(SENTINEL_BYTES)
        package.symlink_to(holder, target_is_directory=True)
    else:
        real_src = tmp_path / "real_src"
        shutil.copytree(root / "runtime/src", real_src)
        (real_src / "azazel_nexus_runtime/ui_static").mkdir(exist_ok=True)
        (real_src / "azazel_nexus_runtime/ui_static" / SENTINEL_NAME).write_bytes(SENTINEL_BYTES)
        (real_src / "azazel_nexus_runtime/ui_static" / "index.html").write_bytes(SENTINEL_BYTES)
        shutil.rmtree(root / "runtime/src")
        (root / "runtime/src").symlink_to(real_src, target_is_directory=True)
    output = tmp_path / "source.tar.gz"
    with pytest.raises(ValueError, match="symlink|unsafe"):
        build_bundle(root, output)
    _nothing_leaked(tmp_path)


@pytest.mark.parametrize("shape", ["package-data-dir", "ancestor"])
def test_the_command_fails_non_zero_and_leaks_nothing_for_a_symlinked_directory(
        tmp_path, monkeypatch, capsys, shape):
    from tools import build_offline_bundle as module
    root = _repo(tmp_path / "repo")
    outside = _outside(tmp_path)
    _declare(root, '"ui_static/*.html"')
    package = root / "runtime/src/azazel_nexus_runtime"
    if shape == "package-data-dir":
        (package / "ui_static").symlink_to(outside, target_is_directory=True)
    else:
        real_src = tmp_path / "real_src"
        shutil.copytree(root / "runtime/src", real_src)
        (real_src / "azazel_nexus_runtime/ui_static").mkdir(exist_ok=True)
        (real_src / "azazel_nexus_runtime/ui_static/index.html").write_bytes(SENTINEL_BYTES)
        shutil.rmtree(root / "runtime/src")
        (root / "runtime/src").symlink_to(real_src, target_is_directory=True)
    real = module.build_bundle
    monkeypatch.setattr(module, "build_bundle", lambda _root, output: real(root, output))
    with pytest.raises(SystemExit) as raised:
        module.main(["--output", str(tmp_path / "source.tar.gz")])
    assert raised.value.code == 2
    err = capsys.readouterr().err
    assert "symlink" in err or "unsafe" in err
    _nothing_leaked(tmp_path)
