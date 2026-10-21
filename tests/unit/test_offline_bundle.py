from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from tools.build_offline_bundle import build_bundle, repository_identity


def _repo(root: Path) -> Path:
    files = {
        "pyproject.toml": b"[project]\nname='azazel-nexus'\n",
        "README.md": b"Nexus package readme\n",
        "LICENSE": b"Nexus license\n",
        "runtime/pyproject.toml": b"[project]\nname='azazel-nexus-runtime'\n",
        "runtime/README.md": b"Nexus runtime package readme\n",
        "runtime/setup.py": b"# fixed native extension build recipe\n",
        "runtime/MANIFEST.in": b"include src/azazel_nexus_runtime/_bootstrap_deadline.c\n",
        "runtime/src/azazel_nexus_runtime/_bootstrap_deadline.c": b"/* native source */\n",
        "src/azazel_nexus/__init__.py": b"VERSION = 1\n",
        "src/azazel_nexus/module.py": b"def run(): return 1\n",
        "runtime/src/azazel_nexus_runtime/__init__.py": b"\n",
        "runtime/src/azazel_nexus_runtime/daemon.py": b"def main(): pass\n",
        "runtime/src/azazel_nexus_runtime/install_platform.py": b"def install(): pass\n",
        "packaging/install.sh": b"#!/bin/sh\nexit 0\n",
        "packaging/azazel-nexus.preset": b"enable azazel-activated.service\n",
        "packaging/tmpfiles.d/azazel-nexus-bootstrap.conf": b"d /run/systemd/system.control :0755 :root :root - -\n",
        "tools/stage_runtime_entrypoints.py": b"def stage(): return 0\n",
        "tools/install_profile_fields.py": b"def install_profile(): return 0\n",
        "tools/purge_mio_profile_copies.py": b"def purge(): return []\n",
        "tools/provision_mission_read.py": b"def provision(): return 0\n",
        "tools/install_llama_runtime.py": b"def install(): return 0\n",
        "packaging/systemd/azazel-activated.service": b"[Service]\nExecStart=/bin/true\n",
        "src/azazel_nexus/tests/test_leak.py": b"must not ship\n",
        "src/azazel_nexus/__pycache__/stale.py": b"must not ship\n",
        "src/azazel_nexus/azazel.egg-info/PKG-INFO": b"must not ship\n",
        "build/generated.py": b"must not ship\n",
    }
    for name, contents in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
    (root / "packaging/install.sh").chmod(0o755)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Bundle Test",
            "-c",
            "user.email=bundle-test@example.invalid",
            "commit",
            "-qm",
            "fixture baseline",
        ],
        cwd=root,
        check=True,
    )
    return root


def _members(bundle: Path) -> dict[str, tuple[bytes, tarfile.TarInfo]]:
    with tarfile.open(bundle, "r:gz") as archive:
        result = {}
        for info in archive.getmembers():
            stream = archive.extractfile(info)
            assert stream is not None
            result[info.name] = (stream.read(), info)
        return result


def test_same_inputs_make_identical_archive_bytes(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"

    build_bundle(root, first)
    # Source mtimes and non-executable permission bits are not bundle inputs.
    for path in root.rglob("*"):
        if path.is_file():
            os.utime(path, (1_700_000_000, 1_700_000_000))
            if path.name != "install.sh":
                path.chmod(0o600)
    build_bundle(root, second)

    assert first.read_bytes() == second.read_bytes()
    first_manifest = json.loads(Path(f"{first}.manifest.json").read_text())
    second_manifest = json.loads(Path(f"{second}.manifest.json").read_text())
    assert first_manifest["bundle_sha256"] == second_manifest["bundle_sha256"]
    assert first_manifest["archive_size"] == first.stat().st_size
    assert first_manifest["repository_identity"] == second_manifest["repository_identity"]


def test_manifest_matches_bundle_contents_and_normalized_metadata(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    output = tmp_path / "bundle.tar.gz"
    manifest = build_bundle(root, output)
    members = _members(output)

    assert hashlib.sha256(output.read_bytes()).hexdigest() == manifest["bundle_sha256"]
    assert set(members) == {item["path"] for item in manifest["files"]}
    assert not any("tests" in name or "__pycache__" in name or "egg-info" in name for name in members)
    assert members["packaging/install.sh"][1].mode == 0o755
    assert members["packaging/tmpfiles.d/azazel-nexus-bootstrap.conf"][0] == (
        b"d /run/systemd/system.control :0755 :root :root - -\n"
    )
    assert members["README.md"][0] == b"Nexus package readme\n"
    assert members["LICENSE"][0] == b"Nexus license\n"
    assert members["runtime/README.md"][0] == b"Nexus runtime package readme\n"
    assert members["runtime/setup.py"][0] == b"# fixed native extension build recipe\n"
    assert members["runtime/MANIFEST.in"][0] == b"include src/azazel_nexus_runtime/_bootstrap_deadline.c\n"
    assert members["runtime/src/azazel_nexus_runtime/_bootstrap_deadline.c"][0] == b"/* native source */\n"
    assert members["tools/stage_runtime_entrypoints.py"][0] == b"def stage(): return 0\n"
    assert members["tools/install_profile_fields.py"][0] == b"def install_profile(): return 0\n"
    assert members["tools/purge_mio_profile_copies.py"][0] == b"def purge(): return []\n"
    assert members["tools/provision_mission_read.py"][0] == b"def provision(): return 0\n"
    assert members["tools/install_llama_runtime.py"][0] == b"def install(): return 0\n"
    assert members["runtime/src/azazel_nexus_runtime/install_platform.py"][0] == b"def install(): pass\n"
    for item in manifest["files"]:
        data, info = members[item["path"]]
        assert item["sha256"] == hashlib.sha256(data).hexdigest()
        assert item["size"] == len(data) == info.size
        assert item["mode"] == f"{info.mode:04o}"
        assert (info.uid, info.gid, info.uname, info.gname, info.mtime) == (
            0,
            0,
            "",
            "",
            0,
        )

    assert int.from_bytes(output.read_bytes()[4:8], "little") == 0


def test_source_mutation_changes_archive_and_file_digest(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    before = tmp_path / "before.tar.gz"
    after = tmp_path / "after.tar.gz"
    first = build_bundle(root, before)
    (root / "src/azazel_nexus/module.py").write_text("def run(): return 2\n")
    second = build_bundle(root, after)

    assert before.read_bytes() != after.read_bytes()
    assert first["bundle_sha256"] != second["bundle_sha256"]
    first_entry = next(item for item in first["files"] if item["path"].endswith("module.py"))
    second_entry = next(item for item in second["files"] if item["path"].endswith("module.py"))
    assert first_entry["sha256"] != second_entry["sha256"]


def test_manifest_checkout_identity_matches_prepare_inputs_shape(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    before = repository_identity(root)
    output = tmp_path / "bundle.tar.gz"
    manifest = build_bundle(root, output)
    assert manifest["repository_identity"] == before
    assert set(before) == {
        "commit",
        "worktree_state",
        "worktree_status_sha256",
        "selected_inputs_sha256",
    }
    assert before["worktree_state"] == "clean"

    (root / "src/azazel_nexus/module.py").write_text("dirty content must not be disclosed\n")
    dirty = repository_identity(root)
    assert dirty["commit"] == before["commit"]
    assert dirty["worktree_state"] == "dirty"
    assert dirty["worktree_status_sha256"] != before["worktree_status_sha256"]
    assert "dirty content must not be disclosed" not in json.dumps(dirty)


def test_identity_detects_rewrite_of_already_dirty_source(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    source = root / "src/azazel_nexus/module.py"
    source.write_text("already dirty A\n")
    first = repository_identity(root)
    first_status_digest = first["worktree_status_sha256"]

    source.write_text("already dirty B, same status path\n")
    second = repository_identity(root)

    assert second["worktree_status_sha256"] == first_status_digest
    assert second["selected_inputs_sha256"] != first["selected_inputs_sha256"]


def test_symlink_input_is_rejected(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    target = root / "src/azazel_nexus/module.py"
    target.unlink()
    target.symlink_to(root / "src/azazel_nexus/__init__.py")

    with pytest.raises(ValueError, match="symlink is not allowed"):
        build_bundle(root, tmp_path / "unsafe.tar.gz")


def test_special_file_input_is_rejected(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is unavailable on this platform")
    root = _repo(tmp_path / "repo")
    os.mkfifo(root / "runtime/src/azazel_nexus_runtime/unexpected.fifo")

    with pytest.raises(ValueError, match="non-regular file is not allowed"):
        build_bundle(root, tmp_path / "unsafe.tar.gz")


def test_missing_profile_install_helper_is_rejected(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    (root / "tools/install_profile_fields.py").unlink()

    with pytest.raises(FileNotFoundError):
        build_bundle(root, tmp_path / "incomplete.tar.gz")


def test_real_bundle_profile_resolver_runs_without_checkout_or_installed_packages(tmp_path):
    root = Path(__file__).resolve().parents[2]
    output = tmp_path / "source.tar.gz"
    build_bundle(root, output)
    extracted = tmp_path / "extracted"
    for name, (data, _info) in _members(output).items():
        relative = Path(name)
        assert not relative.is_absolute() and ".." not in relative.parts
        destination = extracted / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)

    release = tmp_path / "os-release"
    release.write_text('ID=debian\nVERSION_ID="13"\n', encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable, "-I", "-S", "-c",
            "import runpy, sys; from pathlib import Path; "
            "resolve = runpy.run_path(sys.argv[1])['resolve']; "
            "print(resolve(field='profile_id', os_release_path=Path(sys.argv[2])))",
            str(extracted / "tools/install_profile_fields.py"), str(release),
        ],
        cwd=tmp_path, capture_output=True, text=True, check=False, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "debian-13-systemd-installer-v1"


def test_real_bundle_contains_every_file_the_installer_runs(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    script = (root / "packaging/install.sh").read_text(encoding="utf-8")
    # Quotes and braces around the variable are optional, so a respelling of a
    # reference cannot hide it from this check.
    path = r'"?/((?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_-]+\.[A-Za-z0-9]+)'
    referenced = {
        name for name in re.findall(r'\$\{?REPO_ROOT\}?' + path, script)
    } | {
        "packaging/" + name for name in re.findall(r'\$\{?HERE\}?' + path, script)
    }
    assert "tools/provision_mission_read.py" in referenced
    assert "packaging/tmpfiles.d/azazel-nexus-bootstrap.conf" in referenced
    output = tmp_path / "source.tar.gz"
    build_bundle(root, output)
    shipped = set(_members(output))

    assert sorted(referenced - shipped) == []
