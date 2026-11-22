"""The lab clock candidate is pinned by wheel hash in its own file (ADR-0011)."""
import hashlib
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "packaging/offline/lab"
HASH = "9f9926bcb03ec50ae6feac2185041c07cb4b83a1cb28df7e68ff5fb102317e6e"


def test_the_lab_lock_pins_one_wheel_by_hash():
    text = (LAB / "requirements-clocklab-candidate.lock").read_text(encoding="utf-8")
    assert re.findall(r"(?m)^azazel-fabric==([^ ]+) \\$", text) == ["0.10.1.dev0"]
    assert re.findall(r"--hash=sha256:([0-9a-f]{64})", text) == [HASH]
    assert "a4fa5535d3d0a0c9ed2694ea15b4b474ed587aa1" in text


def test_the_candidate_is_absent_from_every_stable_path():
    stable = [ROOT / "pyproject.toml", ROOT / "uv.lock", ROOT / "tools/build_wheelhouse.py",
              ROOT / "packaging/offline/requirements-aarch64-cp313.lock",
              ROOT / "packaging/offline/requirements-x86_64-cp313.lock"]
    for path in stable:
        text = path.read_text(encoding="utf-8")
        assert HASH not in text and "a4fa553" not in text and "0.10.1.dev0" not in text, path


def test_the_installer_refuses_a_wheel_with_another_hash(tmp_path):
    (tmp_path / "azazel_fabric-0.10.1.dev0-py3-none-any.whl").write_bytes(b"not the candidate")
    assert hashlib.sha256(b"not the candidate").hexdigest() != HASH
    result = subprocess.run([str(LAB / "install-clocklab-candidate.sh"), str(tmp_path)],
                            capture_output=True, text=True)
    assert result.returncode == 1 and "refused" in result.stderr


# -- acceptance and replacement, with a synthetic wheel under its own lock -------

import base64
import os
import shutil
import sys
import venv
import zipfile

import pytest


def _wheel(directory: Path, body: str) -> Path:
    """A minimal azazel_fabric-0.10.1.dev0 wheel whose module holds `body`."""
    name = "azazel_fabric-0.10.1.dev0-py3-none-any.whl"
    files = {
        "azazel_fabric/__init__.py": body,
        "azazel_fabric-0.10.1.dev0.dist-info/METADATA":
            "Metadata-Version: 2.1\nName: azazel-fabric\nVersion: 0.10.1.dev0\n",
        "azazel_fabric-0.10.1.dev0.dist-info/WHEEL":
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record = "".join(
        f"{n},sha256={base64.urlsafe_b64encode(hashlib.sha256(c.encode()).digest()).rstrip(b'=').decode()},{len(c)}\n"
        for n, c in files.items())
    files["azazel_fabric-0.10.1.dev0.dist-info/RECORD"] = record + "azazel_fabric-0.10.1.dev0.dist-info/RECORD,,\n"
    path = directory / name
    with zipfile.ZipFile(path, "w") as archive:
        for n, c in files.items():
            archive.writestr(n, c)
    return path


@pytest.fixture
def lab(tmp_path):
    """The real installer script beside a lock of the test's own, and a scratch venv."""
    directory = tmp_path / "lab"
    directory.mkdir()
    shutil.copy(LAB / "install-clocklab-candidate.sh", directory)
    venv_dir = tmp_path / "venv"
    venv.create(venv_dir, with_pip=True)
    return SimpleNamespace(directory=directory, python=str(venv_dir / "bin" / "python"),
                            wheels=tmp_path / "wheels")


def _lock(lab, wheel: Path):
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    (lab.directory / "requirements-clocklab-candidate.lock").write_text(
        f"azazel-fabric==0.10.1.dev0 \\\n    --hash=sha256:{digest}\n", encoding="utf-8")


def _install(lab):
    return subprocess.run([str(lab.directory / "install-clocklab-candidate.sh"), str(lab.wheels), lab.python],
                          capture_output=True, text=True)


def _installed_body(lab):
    return subprocess.run([lab.python, "-c", "import azazel_fabric;print(open(azazel_fabric.__file__).read())"],
                          capture_output=True, text=True).stdout.strip()


def test_the_installer_accepts_the_locked_wheel_and_verifies_the_files(lab):
    lab.wheels.mkdir()
    _lock(lab, _wheel(lab.wheels, "BUILD = 'locked'"))
    result = _install(lab)
    assert result.returncode == 0, result.stderr
    assert "verified" in result.stdout and _installed_body(lab) == "BUILD = 'locked'"


def test_the_installer_replaces_an_installed_build_of_the_same_version(lab, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    old = _wheel(other, "BUILD = 'another build, same version'")
    assert subprocess.run([lab.python, "-m", "pip", "install", "--no-index", "--no-deps", str(old)],
                          capture_output=True, text=True).returncode == 0
    assert _installed_body(lab) == "BUILD = 'another build, same version'"
    lab.wheels.mkdir()
    _lock(lab, _wheel(lab.wheels, "BUILD = 'locked'"))
    result = _install(lab)
    assert result.returncode == 0, result.stderr
    assert _installed_body(lab) == "BUILD = 'locked'"


# -- files that are not in the locked wheel's RECORD ----------------------------

def _site(lab) -> Path:
    out = subprocess.run([lab.python, "-c", "import azazel_fabric,os;print(os.path.dirname(os.path.dirname(azazel_fabric.__file__)))"],
                         capture_output=True, text=True).stdout.strip()
    return Path(out)


def _installed(lab):
    lab.wheels.mkdir()
    _lock(lab, _wheel(lab.wheels, "BUILD = 'locked'"))
    result = _install(lab)
    assert result.returncode == 0, result.stderr
    return _site(lab)


def test_an_unlisted_py_in_the_package_fails_and_is_left_in_place(lab):
    site = _installed(lab)
    stale = site / "azazel_fabric" / "_stale_left_over.py"
    stale.write_text("OLD = 1\n")
    result = _install(lab)
    assert result.returncode != 0
    assert "azazel_fabric/_stale_left_over.py" in result.stderr
    assert stale.exists()


def test_an_unlisted_file_in_the_dist_info_fails(lab):
    site = _installed(lab)
    extra = site / "azazel_fabric-0.10.1.dev0.dist-info" / "extra.txt"
    extra.write_text("x")
    result = _install(lab)
    assert result.returncode != 0 and "dist-info/extra.txt" in result.stderr and extra.exists()


def test_the_cache_python_writes_on_import_does_not_fail_the_check(lab):
    site = _installed(lab)
    cache = site / "azazel_fabric" / "__pycache__"
    # pip may byte-compile on install; clear it so the import below is what creates the cache.
    shutil.rmtree(cache, ignore_errors=True)
    assert not cache.exists()
    assert subprocess.run([lab.python, "-c", "import azazel_fabric"]).returncode == 0
    assert list(cache.glob("*.pyc"))
    # the check alone, on the tree as the import left it (no reinstall in between)
    result = _check(lab)
    assert result.returncode == 0, result.stderr


def test_a_stray_file_in_another_package_does_not_fail_the_check(lab):
    site = _installed(lab)
    (site / "otherpkg").mkdir()
    (site / "otherpkg" / "stale.py").write_text("x = 1\n")
    (site / "loose_module.py").write_text("x = 1\n")
    result = _install(lab)
    assert result.returncode == 0, result.stderr


def _check(lab):
    """Run the installer's own embedded verification (the PYCHECK block) alone against the
    installed tree. A full installer run lets pip's reinstall stash or drop some injected
    entries (a directory link, an unreadable directory) before the check ever sees them."""
    script = (lab.directory / "install-clocklab-candidate.sh").read_text(encoding="utf-8")
    code = script.split("<<'PYCHECK'\n", 1)[1].split("\nPYCHECK", 1)[0]
    wheel = next(lab.wheels.glob("*.whl"))
    return subprocess.run([lab.python, "-", str(wheel)], input=code, capture_output=True, text=True)


def test_a_link_to_a_directory_inside_the_package_fails_with_its_path(lab, tmp_path):
    site = _installed(lab)
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "old.py").write_text("OLD = 1\n")
    (site / "azazel_fabric" / "linked").symlink_to(target, target_is_directory=True)
    result = _check(lab)
    assert result.returncode != 0
    assert "azazel_fabric/linked is a symbolic link" in result.stderr


def test_a_scan_root_that_is_a_link_fails_and_is_not_followed(lab, tmp_path):
    site = _installed(lab)
    moved = tmp_path / "moved_dist_info"
    info = site / "azazel_fabric-0.10.1.dev0.dist-info"
    info.rename(moved)
    info.symlink_to(moved, target_is_directory=True)
    result = _check(lab)
    assert result.returncode != 0
    assert "azazel_fabric-0.10.1.dev0.dist-info is a symbolic link" in result.stderr


def test_an_unreadable_directory_fails_the_check_with_its_path(lab):
    site = _installed(lab)
    sub = site / "azazel_fabric" / "sealed"
    sub.mkdir()
    (sub / "old.py").write_text("OLD = 1\n")
    sub.chmod(0)
    try:
        if os.access(sub, os.R_OK):
            pytest.skip("directory permissions are not enforced for this user (root)")
        result = _check(lab)
        assert result.returncode != 0
        assert "cannot scan azazel_fabric/sealed" in result.stderr
    finally:
        sub.chmod(0o755)


def test_a_linked_scan_root_is_refused_before_any_installed_file_is_read(lab, tmp_path):
    site = _installed(lab)
    package = site / "azazel_fabric"
    moved = tmp_path / "moved_package"
    package.rename(moved)
    (moved / "__init__.py").write_text("BUILD = 'something else'\n")
    package.symlink_to(moved, target_is_directory=True)
    result = _check(lab)
    assert result.returncode != 0
    assert "azazel_fabric is a symbolic link" in result.stderr
    assert "differs" not in result.stderr and "missing" not in result.stderr
    (moved / "__init__.py").unlink()
    result = _check(lab)
    assert result.returncode != 0
    assert "azazel_fabric is a symbolic link" in result.stderr and "missing" not in result.stderr


def test_a_linked_dist_info_with_other_content_is_refused_first(lab, tmp_path):
    site = _installed(lab)
    info = site / "azazel_fabric-0.10.1.dev0.dist-info"
    moved = tmp_path / "moved_dist_info"
    info.rename(moved)
    (moved / "WHEEL").write_text("changed\n")
    info.symlink_to(moved, target_is_directory=True)
    result = _check(lab)
    assert result.returncode != 0
    assert "dist-info is a symbolic link" in result.stderr and "differs" not in result.stderr
