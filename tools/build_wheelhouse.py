"""Build the hash-pinned wheelhouse for an offline Azazel-Nexus bundle.

This is the **online, build-host** half of the offline path. It must run with
the target's interpreter on the target's architecture -- Debian 13's CPython
3.13 on x86_64 for the deployment-baseline target -- because
``azazel-nexus-runtime`` carries a native extension (``_bootstrap_deadline``)
that is compiled against that ABI. It refuses any other host rather than
producing a wheel the target cannot load.

``--target`` selects one of ``offline_bundle.TARGETS``; the default is the
deployment baseline, ``debian-13-x86_64-cp313``. ``debian-13-aarch64-cp313``
is the Arm **lab-software-verification** target (ADR-0005): it is built on
Debian 13 aarch64 with its own lock, and its ``wheelhouse.json`` records the
target's purpose. It never becomes a deployment-baseline wheelhouse.

Steps, each with no resolver latitude:

1. Install the build backend from ``packaging/offline/build-backend.lock``
   with ``--require-hashes`` into a private venv.
2. Download the third-party wheels named by the target's lock
   (``packaging/offline/requirements-<arch>-cp313.lock``) with
   ``--require-hashes --only-binary=:all: --no-deps``. pip refuses any file
   whose sha256 is not in the lock. The source-built ``azazel-fabric`` and
   ``azazel-mio`` entries (``SOURCE_BUILDS``) are not downloaded from an index.
2a. Build each source-built package from its immutable source pin: Fabric's
   exact tag/commit pair (ADR-0004) or MIO's exact commit. A bare ``git clone``
   must resolve the declared pin to that commit, then ``git archive`` of the
   commit (modes normalised with ``tar.umask=0022``), and the same pinned
   backend with ``--no-build-isolation --no-index``. The wheel must reproduce
   its target lock sha256 or the build is refused.
3. Build both Nexus distributions from the deterministic source bundle
   (``build_offline_bundle.build_bundle``), not from the checkout, with
   ``--no-build-isolation --no-index`` so only the pinned backend is used.
4. Write ``wheelhouse.json``: each wheel's sha256, size, requirement and
   source. The two locally built wheels are recorded by the hash this build
   produced; their reproducibility across builders is **not** established.
   A source-built third-party wheel (step 2a) is different: it must equal
   its locked sha256, so ``builder.reproducibility`` says both.

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
#: The default target: the deployment baseline (ADR-0002).
TARGET = offline_bundle.BASELINE_TARGET
#: The default target's lock. Every target's own is ``offline_bundle.target_lock``.
LOCK = offline_bundle.target_lock(TARGET)
BACKEND_LOCK = Path("packaging/offline/build-backend.lock")
UV_LOCK = Path("uv.lock")
BUILD_UMASK = 0o022

#: The library extras the wheelhouse carries, with their uv.lock closure.
#: Fabric supports production commissioning; MIO is the shared advisory core
#: used by the full runtime bundle. Both remain optional to standalone CORE.
BUNDLED_EXTRAS = ("fabric", "mio")

#: Third-party distributions with no published wheel, built here from an
#: exact commit. The lock pins each one's built wheel by sha256, so the build
#: must reproduce it bit for bit. Tagged entries bind tag -> commit; commit
#: entries have no tag or release. Tests hold pyproject.toml, uv.lock, this
#: table and both target locks together.
SOURCE_BUILDS = {
    "azazel-fabric": {
        "version": "0.9.0rc5",
        "repository": "https://github.com/01rabbit/Azazel-Fabric.git",
        "tag": "v0.9.0rc5",
        "commit": "450d9502884ba533653210056a6fb85012b96b84",
    },
    "azazel-mio": {
        "version": "0.1.0",
        "repository": "https://github.com/01rabbit/Azazel-MIO.git",
        "commit": "97c58f92f3be68e48e99e3c837e7d535f0bd4051",
    },
}


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


def bundled_extra_closure(root: Path) -> set[str]:
    """``name==version`` for each bundled extra and everything it pulls in.

    The extra's own requirement must be a ``SOURCE_BUILDS`` entry named by
    its exact tag or immutable commit; its version and every transitive dependency come from
    ``uv.lock``, which is the reviewed resolution of the library's extras.
    A dependency with an environment marker, a second version, or a source
    other than the registry (or the pinned commit) is refused rather than
    guessed at.
    """

    library = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    extras = library["project"].get("optional-dependencies", {})
    lock = tomllib.loads((root / UV_LOCK).read_text(encoding="utf-8"))
    packages: dict[str, dict] = {}
    for package in lock.get("package", []):
        name = offline_bundle.canonical_name(package["name"])
        if name in packages:
            raise ValueError(f"{UV_LOCK} resolves {name} more than once; an offline lock cannot choose")
        packages[name] = package
    pins: set[str] = set()
    pending: list[str] = []
    for extra in BUNDLED_EXTRAS:
        requirements = extras.get(extra)
        if not requirements or len(requirements) != 1:
            raise ValueError(f"the {extra!r} extra must name exactly one requirement")
        name, _, url = requirements[0].replace(" ", "").partition("@")
        name = offline_bundle.canonical_name(name)
        build = SOURCE_BUILDS.get(name)
        reference = (build.get("tag", build["commit"]) if build else None)
        if build is None or url != f"git+{build['repository']}@{reference}":
            raise ValueError(f"the {extra!r} extra {requirements[0]!r} is not a pinned source build")
        package = packages.get(name)
        expected = f"{build['repository']}?rev={reference}#{build['commit']}"
        if package is None or package.get("source") != {"git": expected}:
            raise ValueError(f"{UV_LOCK} does not resolve {name} to {reference} at {build['commit']}")
        if package["version"] != build["version"]:
            raise ValueError(f"{UV_LOCK} resolves {name} {package['version']}, not {build['version']}")
        pending.append(name)
    seen: set[str] = set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        package = packages.get(name)
        if package is None:
            raise ValueError(f"{UV_LOCK} does not resolve {name}")
        if name not in SOURCE_BUILDS and package.get("source") != {"registry": "https://pypi.org/simple"}:
            raise ValueError(f"{UV_LOCK} resolves {name} from {package.get('source')!r}, not PyPI")
        pins.add(f"{name}=={package['version']}")
        for dependency in package.get("dependencies", []):
            if set(dependency) != {"name"}:
                raise ValueError(f"{name} depends on {dependency!r}; markers and extras are not resolved here")
            pending.append(offline_bundle.canonical_name(dependency["name"]))
    return pins


def bundled_requirements(root: Path) -> set[str]:
    """Everything the third-party lock must pin: declared pins plus the bundled extras."""

    return declared_runtime_dependencies(root) | bundled_extra_closure(root)


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


def _git_env() -> dict[str, str]:
    """The builder environment, with no user or system git configuration and no prompt."""

    return {**_build_env(), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0"}


def _run(argv: list[str], *, env: dict[str, str] | None = None) -> str:
    # A fixed umask, whatever the caller's: setuptools copies sources into its
    # build tree with the process umask and the wheel records those modes, so
    # a builder at umask 077 would otherwise produce a different Fabric wheel
    # and be refused against the locked sha256.
    result = subprocess.run(argv, capture_output=True, text=True, check=False,
                            env=_build_env() if env is None else env, umask=BUILD_UMASK)
    if result.returncode != 0:
        raise RuntimeError(f"{argv[:5]} exited {result.returncode}:\n{result.stderr[-4000:]}")
    return result.stdout


def _extract_regular_tar(archive: Path, tree: Path, *, directories: bool) -> None:
    """Extract only regular files (and, if allowed, directories) with their recorded modes."""

    with tarfile.open(archive, "r:*") as stream:
        for member in stream.getmembers():
            parts = member.name.split("/")
            if member.name.startswith("/") or any(part in ("", ".", "..") for part in parts):
                raise ValueError(f"{archive.name} member {member.name!r} is not a plain relative path")
            if directories and member.isdir():
                (tree / member.name).mkdir(parents=True, exist_ok=True)
                continue
            if not member.isreg():
                raise ValueError(f"{archive.name} member {member.name!r} is not a regular file")
            destination = tree / member.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            extracted = stream.extractfile(member)
            assert extracted is not None
            destination.write_bytes(extracted.read())
            destination.chmod(member.mode)


def fetch_source_build(name: str, scratch: Path, *, source_checkout: Path | None = None) -> Path:
    """A clean archived tree at the source pin, or refuse.

    ``source_checkout`` supports local-only builds of unpublished commits.
    Its HEAD must match the pin and the archive always comes from that commit,
    never from uncommitted checkout bytes.
    """

    build = SOURCE_BUILDS[name]
    git = ["git", "-c", "protocol.file.allow=never", "-c", "tar.umask=0022"]
    if source_checkout is None:
        repository = scratch / f"{name}.git"
        _run([*git, "clone", "--quiet", "--bare", "--", build["repository"], str(repository)],
             env=_git_env())
    else:
        repository = source_checkout.resolve(strict=True)
        if not repository.is_dir():
            raise ValueError(f"{name} source checkout is not a directory")
        dirty = _run([*git, "-C", str(repository), "status", "--porcelain", "--untracked-files=all"],
                     env=_git_env()).strip()
        if dirty:
            raise ValueError(f"{name} source checkout is dirty")
    tag = build.get("tag")
    revision = ("HEAD^{commit}" if source_checkout is not None else
                f"refs/tags/{tag}^{{commit}}" if tag else f"{build['commit']}^{{commit}}")
    resolved = _run([*git, "-C", str(repository), "rev-parse", "--verify", revision],
                    env=_git_env()).strip()
    if resolved != build["commit"]:
        label = f"tag {tag}" if tag else "commit pin"
        raise ValueError(f"{build['repository']} {label} resolves to {resolved}, not the pinned {build['commit']}")
    archive = scratch / f"{name}.tar"
    _run([*git, "-C", str(repository), "archive", "--format=tar", f"--output={archive}",
          build["commit"]], env=_git_env())
    tree = scratch / f"{name}-source"
    tree.mkdir()
    _extract_regular_tar(archive, tree, directories=True)
    return tree


def source_build_origin(filename: str, digest: str, lock: dict[str, list[str]],
                        lock_path: Path = LOCK) -> str:
    """The wheelhouse ``source`` of a source-built wheel, if it reproduced the locked sha256."""

    parts = offline_bundle.parse_wheel_name(filename)
    name = offline_bundle.canonical_name(parts["name"])
    build = SOURCE_BUILDS.get(name)
    if build is None or build["version"] != parts["version"]:
        raise ValueError(f"{filename} is not a pinned source build")
    if digest not in lock.get(f"{name}=={parts['version']}", []):
        raise ValueError(
            f"{filename} built from {build['commit']} has sha256 {digest}, which "
            f"{lock_path.as_posix()} does not pin; the build did not reproduce the locked wheel"
        )
    pin = (f"tag {build['tag']} = {build['commit']}" if "tag" in build
           else f"commit {build['commit']}")
    return (f"built:{build['repository']}@{build['commit']} ({pin}; "
            f"hash-pinned in {lock_path.as_posix()})")


def build_wheelhouse(root: Path, output: Path, *, python: str = sys.executable,
                     target_name: str = TARGET,
                     mio_source: Path | None = None) -> dict:
    root = root.resolve(strict=True)
    lock_path = offline_bundle.target_lock(target_name)
    target = offline_bundle.TARGETS[target_name]
    if os.path.lexists(output):
        raise ValueError(f"{output} already exists")
    host = _run([python, "-I", "-c",
                 "import platform, sys; print(platform.machine(), *sys.version_info[:2])"]).split()
    if host != [target["architecture"], *map(str, target["python_version"])]:
        raise ValueError(
            f"this host is {host}; the {target_name} wheelhouse must be built on "
            f"{target['architecture']} with CPython {target['python_version']}, because the "
            "runtime's native extension is compiled for the build host's ABI"
        )
    lock = parse_lock(root / lock_path)
    declared = bundled_requirements(root)
    if set(lock) != declared:
        raise ValueError(f"{lock_path} pins {sorted(lock)}; the pyproject files and the bundled "
                         f"extras' uv.lock closure need {sorted(declared)}")
    source_built = {f"{name}=={build['version']}" for name, build in SOURCE_BUILDS.items()}
    if not source_built <= set(lock):
        raise ValueError(f"{lock_path} does not pin the source-built {sorted(source_built - set(lock))}")

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
        index_requirements = scratch / "index.requirements.txt"
        index_requirements.write_text("".join(
            f"{requirement} " + " ".join(f"--hash=sha256:{digest}" for digest in hashes) + "\n"
            for requirement, hashes in sorted(lock.items()) if requirement not in source_built
        ), encoding="utf-8")
        _run([*pip, "download", "--require-hashes", "--only-binary=:all:", "--no-deps",
              "-d", str(staging), "-r", str(index_requirements)])
        downloaded = sorted(p.name for p in staging.iterdir())
        for name in sorted(SOURCE_BUILDS):
            source_checkout = mio_source if name == "azazel-mio" else None
            _run([*pip, "wheel", "--no-build-isolation", "--no-deps", "--no-index",
                  "-w", str(staging), str(fetch_source_build(
                      name, scratch, source_checkout=source_checkout))])
        from_source = sorted(set(p.name for p in staging.iterdir()) - set(downloaded))

        source_archive = scratch / "source.tar.gz"
        source = build_bundle(root, source_archive)
        tree = scratch / "source"
        tree.mkdir()
        _extract_regular_tar(source_archive, tree, directories=False)
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
                origin = f"pypi:{requirement} (hash-pinned in {lock_path.as_posix()})"
            elif path.name in from_source:
                origin = source_build_origin(path.name, digest, lock, lock_path)
            else:
                if versions.get(name) != parts["version"]:
                    raise ValueError(f"{path.name} is not a distribution this repository builds")
                origin = (
                    f"built:{source['repository_identity']['commit']} "
                    f"source-bundle-sha256:{source['bundle_sha256']}"
                )
            if not offline_bundle.wheel_fits_target(path.name, target):
                raise ValueError(f"{path.name} does not fit {target_name}")
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
            "target": target_name,
            **offline_bundle.target_purpose(target_name),
            "repository_identity": source["repository_identity"],
            "source_bundle_sha256": source["bundle_sha256"],
            "builder": {
                "python": ".".join(host[1:]),
                "machine": host[0],
                "pip": backend_versions[0],
                "setuptools": backend_versions[1],
                "reproducibility": (
                    "not measured for the two Nexus wheels; each source-built third-party "
                    "wheel reproduced its locked sha256 (checked)"
                ),
                "signed": False,
            },
            "wheels": wheels,
        }
        (staging / "wheelhouse.json").write_bytes(offline_bundle.manifest_bytes(record))
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(staging), str(output))
    return record


def load_wheelhouse(directory: Path, target_name: str = TARGET) -> dict:
    """Read ``wheelhouse.json`` and re-derive every listed wheel's sha256 and size.

    ``target_name`` is the caller's, never the record's: a lab wheelhouse is
    refused where the deployment-baseline one is expected, and the other way round.
    """

    offline_bundle.target_lock(target_name)
    record = json.loads((directory / "wheelhouse.json").read_text(encoding="utf-8"))
    if record.get("schema") != WHEELHOUSE_SCHEMA or record.get("target") != target_name:
        raise ValueError(f"wheelhouse.json is not a wheelhouse for the {target_name} target")
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
    parser.add_argument("--target", choices=sorted(offline_bundle.TARGETS), default=TARGET,
                        help=f"declared bundle target (default: the deployment baseline, {TARGET}); "
                        "debian-13-aarch64-cp313 is a lab-software-verification target")
    parser.add_argument("--mio-source", type=Path,
                        help="local clean Azazel-MIO checkout at the pinned commit (for unpublished source)")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    try:
        record = build_wheelhouse(root, args.output, target_name=args.target, mio_source=args.mio_source)
    except (OSError, ValueError, RuntimeError) as error:
        parser.error(str(error))
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
