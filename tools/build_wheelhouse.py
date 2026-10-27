"""Build the hash-pinned wheelhouse for an offline Azazel-Nexus bundle.

This is the **online, build-host** half of the offline path. It must run with
the target's interpreter on the target's architecture -- Debian 13's CPython
3.13 on x86_64 -- because ``azazel-nexus-runtime`` carries a native extension
(``_bootstrap_deadline``) that is compiled against that ABI. It refuses any
other host rather than producing a wheel the target cannot load.

Steps, each with no resolver latitude:

1. Install the build backend from ``packaging/offline/build-backend.lock``
   with ``--require-hashes`` into a private venv.
2. Download the third-party wheels named by
   ``packaging/offline/requirements-x86_64-cp313.lock`` with
   ``--require-hashes --only-binary=:all: --no-deps``. pip refuses any file
   whose sha256 is not in the lock.
3. Build both Nexus distributions from the deterministic source bundle
   (``build_offline_bundle.build_bundle``), not from the checkout, with
   ``--no-build-isolation --no-index`` so only the pinned backend is used.
4. Write ``wheelhouse.json``: each wheel's sha256, size, requirement and
   source. The two locally built wheels are recorded by the hash this build
   produced; reproducibility across builders is **not** established.

The output is unsigned. ``tools/build_offline_bundle.py --wheelhouse`` carries
it into a bundle; ``tools/offline_bundle.py install`` installs it offline.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path

try:  # imported as tools.build_wheelhouse by the tests, run as a script otherwise
    from tools import offline_bundle
    from tools.build_offline_bundle import build_bundle
except ImportError:  # pragma: no cover - script execution
    import offline_bundle  # type: ignore[no-redef]
    from build_offline_bundle import build_bundle  # type: ignore[no-redef]


WHEELHOUSE_SCHEMA = "azazel-nexus-wheelhouse@1"
TARGET = "debian-13-x86_64-cp313"
LOCK = Path("packaging/offline/requirements-x86_64-cp313.lock")
BACKEND_LOCK = Path("packaging/offline/build-backend.lock")


#: One lock parser, shared with the offline verifier that checks installs.
parse_lock = offline_bundle.parse_lock


def declared_runtime_dependencies(root: Path) -> set[str]:
    """Third-party ``name==version`` pins the two pyproject files declare."""

    library = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    runtime = tomllib.loads((root / "runtime" / "pyproject.toml").read_text(encoding="utf-8"))
    declared = set(library["project"].get("dependencies", [])) | set(runtime["project"]["dependencies"])
    pins = set()
    for requirement in declared:
        match = offline_bundle._REQUIREMENT.match(requirement.replace(" ", ""))
        if match is None:
            name = offline_bundle.canonical_name(requirement)
            if name in offline_bundle.OWN_DISTRIBUTIONS:
                continue
            raise ValueError(f"{requirement!r} is not an exact pin; an offline wheelhouse cannot carry a range")
        pins.add(f"{offline_bundle.canonical_name(match.group('name'))}=={match.group('version')}")
    return pins


def own_versions(root: Path) -> dict[str, str]:
    versions = {}
    for path in (root / "pyproject.toml", root / "runtime" / "pyproject.toml"):
        project = tomllib.loads(path.read_text(encoding="utf-8"))["project"]
        versions[offline_bundle.canonical_name(project["name"])] = project["version"]
    return versions


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _build_env() -> dict[str, str]:
    """A fixed environment for every builder subprocess: no inherited PIP_* or config."""

    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
           "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INPUT": "1",
           "SOURCE_DATE_EPOCH": "315532800"}
    if "HOME" in os.environ:
        env["HOME"] = os.environ["HOME"]
    return env


def _run(argv: list[str]) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, check=False, env=_build_env())
    if result.returncode != 0:
        raise RuntimeError(f"{argv[:5]} exited {result.returncode}:\n{result.stderr[-4000:]}")
    return result.stdout


def build_wheelhouse(root: Path, output: Path, *, python: str = sys.executable) -> dict:
    root = root.resolve(strict=True)
    target = offline_bundle.TARGETS[TARGET]
    if os.path.lexists(output):
        raise ValueError(f"{output} already exists")
    host = _run([python, "-I", "-c",
                 "import platform, sys; print(platform.machine(), *sys.version_info[:2])"]).split()
    if host != [target["architecture"], *map(str, target["python_version"])]:
        raise ValueError(
            f"this host is {host}; the {TARGET} wheelhouse must be built on "
            f"{target['architecture']} with CPython {target['python_version']}, because the "
            "runtime's native extension is compiled for the build host's ABI"
        )
    lock = parse_lock(root / LOCK)
    declared = declared_runtime_dependencies(root)
    if set(lock) != declared:
        raise ValueError(f"{LOCK} pins {sorted(lock)}; the pyproject files declare {sorted(declared)}")

    with tempfile.TemporaryDirectory(prefix="azazel-wheelhouse-") as scratch_name:
        scratch = Path(scratch_name)
        staging = scratch / "wheels"
        staging.mkdir()
        backend = scratch / "backend"
        _run([python, "-I", "-m", "venv", str(backend)])
        backend_python = str(backend / "bin" / "python")
        pip = [backend_python, "-I", "-m", "pip", "--disable-pip-version-check", "--no-cache-dir"]
        _run([*pip, "install", "--require-hashes", "--only-binary=:all:", "--no-deps",
              "-r", str(root / BACKEND_LOCK)])
        _run([*pip, "download", "--require-hashes", "--only-binary=:all:", "--no-deps",
              "-d", str(staging), "-r", str(root / LOCK)])
        downloaded = sorted(p.name for p in staging.iterdir())

        source_archive = scratch / "source.tar.gz"
        source = build_bundle(root, source_archive)
        tree = scratch / "source"
        tree.mkdir()
        with tarfile.open(source_archive, "r:gz") as archive:
            for member in archive.getmembers():
                offline_bundle.safe_member_path(member.name)
                if not member.isreg():
                    raise ValueError(f"source bundle member {member.name!r} is not a regular file")
                destination = tree / member.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                assert stream is not None
                destination.write_bytes(stream.read())
                destination.chmod(member.mode)
        _run([*pip, "wheel", "--no-build-isolation", "--no-deps", "--no-index",
              "-w", str(staging), str(tree), str(tree / "runtime")])
        backend_versions = _run([backend_python, "-I", "-c",
                                 "import pip, setuptools; print(pip.__version__, setuptools.__version__)"]).split()

        versions = own_versions(root)
        wheels = []
        for path in sorted(staging.iterdir(), key=lambda p: p.name):
            parts = offline_bundle.parse_wheel_name(path.name)
            name = offline_bundle.canonical_name(parts["name"])
            requirement = f"{name}=={parts['version']}"
            digest = _sha256(path)
            if path.name in downloaded:
                if digest not in lock.get(requirement, []):
                    raise ValueError(f"{path.name} is not a locked file")
                origin = f"pypi:{requirement} (hash-pinned in {LOCK.as_posix()})"
            else:
                if versions.get(name) != parts["version"]:
                    raise ValueError(f"{path.name} is not a distribution this repository builds")
                origin = (
                    f"built:{source['repository_identity']['commit']} "
                    f"source-bundle-sha256:{source['bundle_sha256']}"
                )
            if not offline_bundle.wheel_fits_target(path.name, target):
                raise ValueError(f"{path.name} does not fit {TARGET}")
            wheels.append({
                "file": path.name,
                "requirement": requirement,
                "sha256": digest,
                "size": path.stat().st_size,
                "source": origin,
            })
        names = {w["requirement"].partition("==")[0] for w in wheels}
        if names != set(versions) | {r.partition("==")[0] for r in lock}:
            raise ValueError(f"the wheelhouse holds {sorted(names)}; it is incomplete or has extras")
        record = {
            "schema": WHEELHOUSE_SCHEMA,
            "target": TARGET,
            "repository_identity": source["repository_identity"],
            "source_bundle_sha256": source["bundle_sha256"],
            "builder": {
                "python": ".".join(host[1:]),
                "machine": host[0],
                "pip": backend_versions[0],
                "setuptools": backend_versions[1],
                "reproducibility": "not measured",
                "signed": False,
            },
            "wheels": wheels,
        }
        (staging / "wheelhouse.json").write_bytes(offline_bundle.manifest_bytes(record))
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(staging), str(output))
    return record


def load_wheelhouse(directory: Path) -> dict:
    """Read ``wheelhouse.json`` and re-derive every listed wheel's sha256 and size."""

    record = json.loads((directory / "wheelhouse.json").read_text(encoding="utf-8"))
    if record.get("schema") != WHEELHOUSE_SCHEMA or record.get("target") != TARGET:
        raise ValueError("wheelhouse.json is not a wheelhouse for the declared target")
    listed = {w["file"] for w in record["wheels"]}
    present = {p.name for p in directory.iterdir()} - {"wheelhouse.json"}
    if listed != present:
        raise ValueError(f"the wheelhouse directory holds {sorted(present)}; the record lists {sorted(listed)}")
    for wheel in record["wheels"]:
        path = directory / wheel["file"]
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"{wheel['file']} is not a regular file")
        if _sha256(path) != wheel["sha256"] or path.stat().st_size != wheel["size"]:
            raise ValueError(f"{wheel['file']} does not match wheelhouse.json")
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--output", required=True, type=Path, help="wheelhouse directory; must not exist")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    try:
        record = build_wheelhouse(root, args.output)
    except (OSError, ValueError, RuntimeError) as error:
        parser.error(str(error))
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
