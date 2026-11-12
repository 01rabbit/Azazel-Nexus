"""The offline source bundle ships the package data the pyprojects declare.

Found during u45 official-wheel acceptance: the bundle kept only `.py` files from
the source trees, so `azazel_nexus_runtime/ui_static/*` (declared in
runtime/pyproject.toml `[tool.setuptools.package-data]`) was missing from the
bundle and from the wheel built from it, and the installed `az-ui` refused with
`source_or_assets_unreadable`.
"""

from __future__ import annotations

import os
import re
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
    """Built offline from exactly the selected inputs."""
    tree = tmp_path / "tree"
    for source, name in _inputs(REAL):
        destination = tree / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    wheel = _build_wheel(tree / "runtime", tmp_path / "wheel", "azazel_nexus_runtime")
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
    output = _out(tmp_path)
    with pytest.raises(ValueError, match="symlink"):
        build_bundle(root, output)
    _nothing_leaked(output)


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


#: What a build prints when it has no compiler or no Python headers.
_NO_COMPILER = re.compile(
    r"(command '[^']*(?:gcc|cc|clang|c\+\+)[^']*' failed: No such file"
    r"|unable to execute '[^']*(?:gcc|cc|clang)[^']*': No such file"
    r"|error: command '[^']*(?:gcc|cc|clang)[^']*' not found"
    r"|No such file or directory: '[^']*(?:gcc|cc|clang)'"
    r"|Python\.h: No such file or directory"
    r"|[Uu]nable to find a (?:C )?compiler)")


def _build_wheel(source: Path, out: Path, name: str) -> Path:
    """Build a wheel offline from `source`. The test is skipped only when a build
    prerequisite is demonstrably missing: setuptools or wheel cannot be imported, or
    the build itself reports a missing compiler or Python headers in a message this
    test recognises. Any other failure is a test failure with the build's stderr; the
    mere absence of `cc`/`gcc` on PATH proves nothing (CC, sysconfig, other names)."""
    import importlib.util
    missing = [module for module in ("setuptools", "wheel")
               if importlib.util.find_spec(module) is None]
    if missing:
        pytest.skip("the offline wheel build is not possible here: " + ", ".join(missing))
    result = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-build-isolation", "--no-deps",
         "-w", str(out), str(source)],
        capture_output=True, text=True, env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"})
    if result.returncode != 0:
        output = result.stdout + result.stderr
        if _NO_COMPILER.search(output):
            pytest.skip("the build reports a missing compiler or Python headers")
        pytest.fail("the offline wheel build failed:\n" + output[-3000:])
    [wheel] = list(out.glob(f"{name}-*.whl"))
    return wheel


def test_the_missing_compiler_patterns_recognise_real_messages_and_nothing_else():
    for message in ("error: command '/usr/bin/gcc' failed: No such file or directory",
                    "error: unable to execute 'gcc': No such file or directory",
                    "fatal error: Python.h: No such file or directory",
                    "error: Microsoft Visual C++ 14.0 or greater is required "
                    "Unable to find a compiler"):
        assert _NO_COMPILER.search(message), message
    for message in ("error: invalid command 'bdist_wheel'",
                    "SyntaxError: invalid syntax", "ModuleNotFoundError: No module named 'x'",
                    "ERROR: Failed building wheel for azazel-nexus-runtime"):
        assert not _NO_COMPILER.search(message), message


def _wheel_of_checkout(source_runtime: Path, out: Path) -> Path:
    return _build_wheel(source_runtime, out, "azazel_nexus_runtime")


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


def _out(tmp_path: Path) -> Path:
    """A dedicated output directory; the designated archive is `out/source.tar.gz`."""
    directory = tmp_path / "out"
    directory.mkdir(exist_ok=True)
    return directory / "source.tar.gz"


def _contents_of(path: Path):
    """`(member names, byte strings)` of a file, looking INSIDE archives."""
    if tarfile.is_tarfile(path):
        names, blobs = [], []
        with tarfile.open(path, "r:*") as archive:
            for member in archive.getmembers():
                names.append(member.name)
                if member.isfile():
                    blobs.append(archive.extractfile(member).read())
        return names, blobs
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            return archive.namelist(), [archive.read(name) for name in archive.namelist()]
    return [], [path.read_bytes()]


def _nothing_leaked(output: Path) -> None:
    """Neither designated output exists, and nothing else in the output directory
    holds the sentinel's NAME or BYTES: archives are opened and their member names
    and decompressed contents searched, not their compressed bytes. Each kind of
    finding has its own message, so a control can pin the one path it exercises."""
    manifest = Path(f"{output}.manifest.json")
    assert not output.exists(), "the archive was produced"
    assert not manifest.exists(), "the manifest was produced"
    for path in output.parent.rglob("*"):
        if not path.is_file():
            continue
        names, blobs = _contents_of(path)
        assert SENTINEL_NAME not in path.name, f"a file name carries the sentinel: {path}"
        assert all(SENTINEL_NAME not in name for name in names), \
            f"a member name carries the sentinel: {path} {names}"
        assert all(SENTINEL_NAME.encode() not in blob and SENTINEL_BYTES not in blob
                   for blob in blobs), f"decompressed content carries the sentinel: {path}"


def _gz_tar(path: Path, member: str, content: bytes) -> None:
    import io
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo(member)
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))


def _zip(path: Path, member: str, content: bytes) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(member, content)


@pytest.mark.parametrize("writer", [_gz_tar, _zip], ids=["gzip-tar", "zip"])
def test_the_leak_check_finds_sentinel_bytes_only_inside_a_compressed_archive(
        tmp_path, writer):
    """Isolated path: a differently named archive, an innocuous member name, the
    sentinel only in the DECOMPRESSED content. The designated archive and the manifest
    are absent, so only the content search can fire; the raw compressed bytes do not
    hold the sentinel, so a scan of those would pass."""
    output = _out(tmp_path)
    other = output.with_name("other.bin")
    writer(other, "x/inner.txt", SENTINEL_BYTES * 20)
    raw = other.read_bytes()
    assert SENTINEL_BYTES not in raw and SENTINEL_NAME.encode() not in raw
    assert not output.exists() and not Path(f"{output}.manifest.json").exists()
    with pytest.raises(AssertionError, match="decompressed content carries the sentinel"):
        _nothing_leaked(output)
    # the same archive without the sentinel is clean (the control is not trivially red)
    writer(other, "x/inner.txt", b"harmless")
    _nothing_leaked(output)


@pytest.mark.parametrize("writer", [_gz_tar, _zip], ids=["gzip-tar", "zip"])
def test_the_leak_check_finds_a_sentinel_member_name_only(tmp_path, writer):
    output = _out(tmp_path)
    other = output.with_name("other.bin")
    writer(other, f"deep/{SENTINEL_NAME}", b"harmless")
    assert not output.exists() and not Path(f"{output}.manifest.json").exists()
    with pytest.raises(AssertionError, match="a member name carries the sentinel"):
        _nothing_leaked(output)


def test_the_leak_check_finds_a_sentinel_file_name(tmp_path):
    output = _out(tmp_path)
    output.with_name(SENTINEL_NAME).write_bytes(b"harmless")
    with pytest.raises(AssertionError, match="a file name carries the sentinel"):
        _nothing_leaked(output)


def test_the_leak_check_finds_sentinel_bytes_in_a_plain_file(tmp_path):
    output = _out(tmp_path)
    output.with_name("notes.txt").write_bytes(b"prefix " + SENTINEL_BYTES)
    with pytest.raises(AssertionError, match="decompressed content carries the sentinel"):
        _nothing_leaked(output)


def test_the_leak_check_finds_a_produced_archive_and_a_produced_manifest(tmp_path):
    output = _out(tmp_path)
    Path(f"{output}.manifest.json").write_bytes(b"{}")
    with pytest.raises(AssertionError, match="the manifest was produced"):
        _nothing_leaked(output)
    Path(f"{output}.manifest.json").unlink()
    _gz_tar(output, "x/inner.txt", b"harmless")
    with pytest.raises(AssertionError, match="the archive was produced"):
        _nothing_leaked(output)


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
    output = _out(tmp_path)
    with pytest.raises(ValueError, match="symlink|unsafe"):
        build_bundle(root, output)
    _nothing_leaked(output)


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
    output = _out(tmp_path)
    with pytest.raises(SystemExit) as raised:
        module.main(["--output", str(output)])
    assert raised.value.code == 2
    err = capsys.readouterr().err
    assert "symlink" in err or "unsafe" in err
    _nothing_leaked(output)


# -- Codex 14: the checker needs the package on BOTH sides ------------------------------------------------------


def _archive(tmp_path: Path, name: str, prefix: str = "") -> Path:
    path = tmp_path / name
    with tarfile.open(path, "w:gz") as handle:
        for source, member in _inputs(REAL):
            handle.add(source, arcname=prefix + member)
    return path


def _library_wheel(tmp_path: Path) -> Path:
    tree = tmp_path / "library"
    tree.mkdir()
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copy2(REAL / name, tree / name)
    shutil.copytree(REAL / "src", tree / "src", ignore=shutil.ignore_patterns(
        "__pycache__", "*.egg-info", "*.pyc"))
    return _build_wheel(tree, tmp_path / "library_wheel", "azazel_nexus")


@pytest.fixture(scope="module")
def runtime_wheel(tmp_path_factory):
    base = tmp_path_factory.mktemp("runtime_wheel")
    return _wheel_of_checkout(_copy_runtime(base / "runtime"), base / "wheel")


def test_a_package_that_does_not_exist_is_exit_2_not_a_match(tmp_path, runtime_wheel, capsys):
    archive = _archive(tmp_path, "source.tar.gz")
    assert oracle.main(["--wheel", str(runtime_wheel), "--bundle", str(archive),
                        "--package", "azazel_nexus_runtim"]) == 2
    assert "no default source prefix" in capsys.readouterr().err
    assert oracle.main(["--wheel", str(runtime_wheel), "--bundle", str(archive),
                        "--package", "azazel_nexus_runtim", "--source", "runtime/src"]) == 2
    err = capsys.readouterr().err
    assert "no such package" in err or "__init__.py" in err


def test_a_wrong_source_prefix_is_exit_2_not_a_match(tmp_path, runtime_wheel, capsys):
    archive = _archive(tmp_path, "source.tar.gz")
    assert oracle.main(["--wheel", str(runtime_wheel), "--bundle", str(archive),
                        "--source", "runtime/srcx"]) == 2
    assert "__init__.py" in capsys.readouterr().err


def test_the_install_bundle_layout_is_detected_and_checked(tmp_path, runtime_wheel):
    archive = _archive(tmp_path, "install.tar.gz", prefix="source/")
    assert oracle.main(["--wheel", str(runtime_wheel), "--bundle", str(archive)]) == 0
    assert oracle.detect_source(archive, "azazel_nexus_runtime", None) == "source/runtime/src"
    assert oracle.main(["--wheel", str(runtime_wheel), "--bundle", str(archive),
                        "--source", "runtime/src"]) == 2  # not that layout


def test_both_layouts_at_once_or_neither_is_ambiguous(tmp_path, runtime_wheel):
    both = tmp_path / "both.tar.gz"
    with tarfile.open(both, "w:gz") as handle:
        for source, member in _inputs(REAL):
            handle.add(source, arcname=member)
            handle.add(source, arcname="source/" + member)
    assert oracle.main(["--wheel", str(runtime_wheel), "--bundle", str(both)]) == 2
    assert oracle.main(["--wheel", str(runtime_wheel), "--bundle", str(both),
                        "--source", "source/runtime/src"]) == 0  # explicit is fine
    empty = tmp_path / "empty.tar.gz"
    with tarfile.open(empty, "w:gz"):
        pass
    assert oracle.main(["--wheel", str(runtime_wheel), "--bundle", str(empty)]) == 2


def test_a_package_with_no_data_files_passes_when_it_exists_on_both_sides(tmp_path, capsys):
    wheel = _library_wheel(tmp_path)
    for prefix in ("", "source/"):
        archive = _archive(tmp_path, f"lib{len(prefix)}.tar.gz", prefix=prefix)
        assert oracle.main(["--wheel", str(wheel), "--bundle", str(archive),
                            "--package", "azazel_nexus"]) == 0
    assert "(0 files)" in capsys.readouterr().out
    assert oracle.wheel_package_data(wheel, "azazel_nexus") == set()


def test_a_wheel_without_the_package_is_exit_2(tmp_path, runtime_wheel, capsys):
    archive = _archive(tmp_path, "source.tar.gz")
    assert oracle.main(["--wheel", str(runtime_wheel), "--bundle", str(archive),
                        "--package", "azazel_nexus"]) == 2  # the library is not in this wheel
    assert "no such package" in capsys.readouterr().err


def test_record_is_parsed_as_csv(tmp_path):
    """A RECORD path containing a comma is quoted, which `split(",")` would break."""
    wheel = tmp_path / "x-1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("pkg/__init__.py", "")
        archive.writestr("pkg/data,odd.json", "{}")
        archive.writestr("x-1.dist-info/RECORD",
                         'pkg/__init__.py,sha256=a,0\n"pkg/data,odd.json",sha256=b,2\n')
    assert oracle.wheel_package_data(wheel, "pkg") == {"data,odd.json"}
