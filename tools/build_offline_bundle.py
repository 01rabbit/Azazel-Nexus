"""Build Azazel-Nexus offline bundles.

Two outputs, both deterministic for the same inputs and both unsigned:

* the **source bundle** (``--output`` alone): the library and runtime Python
  sources, their packaging metadata, and the installer/systemd packaging
  contract, with a JSON sidecar. It is not a wheel builder and does not
  include tests or generated build output.
* the **install bundle** (``--output --wheelhouse``): one ``.tar.gz`` whose
  first member is ``MANIFEST.json`` (``tools/offline_bundle.py``), carrying
  the same source files, the hash-pinned wheelhouse from
  ``tools/build_wheelhouse.py``, and the optional Edge package, Debian
  package, model and Knowledge slots. Every member is listed with its sha256,
  size, kind and source; ``tools/offline_bundle.py`` refuses anything else.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Iterable, Optional, Sequence

try:  # imported as tools.build_offline_bundle by the tests, run as a script otherwise
    from tools import offline_bundle
except ImportError:  # pragma: no cover - script execution
    import offline_bundle  # type: ignore[no-redef]


SCHEMA = "azazel-nexus-offline-source-bundle@1"
EXCLUDED_PARTS = {".git", "tests", "__pycache__", "build", "dist"}


def _excluded(path: Path) -> bool:
    return any(
        part in EXCLUDED_PARTS
        or (part.endswith(".egg-info") or part.endswith(".pyc"))
        for part in path.parts
    )


def _regular_file(path: Path) -> os.stat_result:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise ValueError(f"symlink is not allowed in bundle inputs: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"non-regular file is not allowed in bundle inputs: {path}")
    return info


def _walk(root: Path, directory: Path, *, python_only: bool) -> Iterable[Path]:
    """Yield regular input files in lexical order, rejecting unsafe entries."""
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        relative = path.relative_to(root)
        if _excluded(relative):
            continue
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"symlink is not allowed in bundle inputs: {path}")
        if stat.S_ISDIR(info.st_mode):
            yield from _walk(root, path, python_only=python_only)
        elif stat.S_ISREG(info.st_mode):
            if not python_only or path.suffix == ".py":
                yield path
        else:
            raise ValueError(f"non-regular file is not allowed in bundle inputs: {path}")


def _inputs(root: Path) -> list[tuple[Path, str]]:
    candidates: list[tuple[Path, str]] = []
    fixed = (
        (root / "pyproject.toml", "pyproject.toml"),
        (root / "README.md", "README.md"),
        (root / "LICENSE", "LICENSE"),
        (root / "runtime" / "pyproject.toml", "runtime/pyproject.toml"),
        (root / "runtime" / "README.md", "runtime/README.md"),
        (root / "runtime" / "setup.py", "runtime/setup.py"),
        (root / "runtime" / "MANIFEST.in", "runtime/MANIFEST.in"),
        (root / "runtime" / "src" / "azazel_nexus_runtime" / "_bootstrap_deadline.c",
         "runtime/src/azazel_nexus_runtime/_bootstrap_deadline.c"),
        (root / "packaging" / "install.sh", "packaging/install.sh"),
        (root / "packaging" / "azazel-nexus.preset", "packaging/azazel-nexus.preset"),
        (root / "packaging" / "tmpfiles.d" / "azazel-nexus-bootstrap.conf",
         "packaging/tmpfiles.d/azazel-nexus-bootstrap.conf"),
        (
            root / "tools" / "stage_runtime_entrypoints.py",
            "tools/stage_runtime_entrypoints.py",
        ),
        (
            root / "tools" / "install_profile_fields.py",
            "tools/install_profile_fields.py",
        ),
        (
            root / "tools" / "purge_mio_profile_copies.py",
            "tools/purge_mio_profile_copies.py",
        ),
        (
            root / "tools" / "provision_mission_read.py",
            "tools/provision_mission_read.py",
        ),
        (
            root / "tools" / "install_llama_runtime.py",
            "tools/install_llama_runtime.py",
        ),
        (
            root / "tools" / "check_decoy_apparmor_wrappers.py",
            "tools/check_decoy_apparmor_wrappers.py",
        ),
        (
            root / "tools" / "record_apparmor_compiled.py",
            "tools/record_apparmor_compiled.py",
        ),
        # The offline bundle verifier/installer, so an extracted tree can show
        # what it was checked with. Run the reviewed checkout's copy, not this.
        (root / "tools" / "offline_bundle.py", "tools/offline_bundle.py"),
    )
    for source, archive_name in fixed:
        _regular_file(source)
        candidates.append((source, archive_name))

    for source_dir, python_only in (
        (root / "src" / "azazel_nexus", True),
        (root / "runtime" / "src" / "azazel_nexus_runtime", True),
        (root / "packaging" / "systemd", False),
        # The Deception Lite AppArmor profiles install.sh places (#196 G3).
        (root / "packaging" / "apparmor", False),
    ):
        if not source_dir.is_dir() or source_dir.is_symlink():
            raise ValueError(f"required input directory is missing or unsafe: {source_dir}")
        for source in _walk(root, source_dir, python_only=python_only):
            candidates.append((source, source.relative_to(root).as_posix()))

    candidates.sort(key=lambda item: item[1])
    names = [name for _, name in candidates]
    if len(names) != len(set(names)):
        raise ValueError("duplicate archive path in selected inputs")
    if not any(name.endswith(".service") for name in names if name.startswith("packaging/systemd/")):
        raise ValueError("no systemd unit files found under packaging/systemd")
    return candidates


def repository_identity(root: Path) -> dict[str, str]:
    """Bind checkout metadata and exact selected source bytes, without paths.

    Git's porcelain status does not change when a file that was already dirty
    is edited again.  The selected-input digest closes that gap and is checked
    both before and after the archive is read.
    """
    status = subprocess.check_output(
        ["git", "status", "--porcelain=v2", "--untracked-files=all"],
        cwd=root,
        text=True,
    ).strip()
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    content = hashlib.sha256()
    for source, archive_name in _inputs(root):
        data = source.read_bytes()
        content.update(archive_name.encode("utf-8") + b"\0")
        content.update(hashlib.sha256(data).hexdigest().encode("ascii") + b"\n")
    return {
        "commit": commit,
        "worktree_state": "dirty" if status else "clean",
        "worktree_status_sha256": hashlib.sha256(status.encode()).hexdigest(),
        "selected_inputs_sha256": content.hexdigest(),
    }


def _tar_gz(root: Path, inputs: list[tuple[Path, str]]) -> tuple[bytes, list[dict[str, object]]]:
    archive_buffer = io.BytesIO()
    manifest_files: list[dict[str, object]] = []
    with gzip.GzipFile(
        fileobj=archive_buffer, mode="wb", filename="", mtime=0, compresslevel=9
    ) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for source, archive_name in inputs:
                source_info = _regular_file(source)
                data = source.read_bytes()
                mode = 0o755 if source_info.st_mode & 0o111 else 0o644
                info = tarfile.TarInfo(PurePosixPath(archive_name).as_posix())
                info.size = len(data)
                info.mode = mode
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.type = tarfile.REGTYPE
                info.devmajor = 0
                info.devminor = 0
                archive.addfile(info, io.BytesIO(data))
                manifest_files.append(
                    {
                        "path": archive_name,
                        "mode": f"{mode:04o}",
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
    return archive_buffer.getvalue(), manifest_files


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as stream:
            temporary_name = stream.name
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    finally:
        if temporary_name is not None and os.path.exists(temporary_name):
            os.unlink(temporary_name)


def build_bundle(root: Path, output: Path) -> dict[str, object]:
    """Write ``output`` and its JSON sidecar; return the sidecar document."""
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"repository root is not a directory: {root}")
    output = output.absolute()
    source_identity_start = repository_identity(root)
    inputs = _inputs(root)
    archive_bytes, files = _tar_gz(root, inputs)
    source_identity_end = repository_identity(root)
    if source_identity_end != source_identity_start:
        raise RuntimeError("source checkout changed while the bundle was being built")
    document: dict[str, object] = {
        "schema": SCHEMA,
        "repository_identity": source_identity_start,
        "archive": output.name,
        "archive_size": len(archive_bytes),
        "bundle_sha256": hashlib.sha256(archive_bytes).hexdigest(),
        "files": files,
    }
    manifest_bytes = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode()
    _atomic_write(output, archive_bytes)
    _atomic_write(Path(f"{output}.manifest.json"), manifest_bytes)
    return document



def _hash_file(path: Path) -> tuple[str, int]:
    _regular_file(path)
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _entry(source: Path, path: str, kind: str, origin: str, *, mode: str = "0644",
           **extra: str) -> tuple[dict[str, object], Path]:
    digest, size = _hash_file(source)
    entry: dict[str, object] = {
        "path": path, "kind": kind, "sha256": digest, "size": size, "mode": mode,
        "source": origin, **extra,
    }
    return entry, source


def _slot_files(directory: Path, *, suffix: Optional[str] = None) -> list[Path]:
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError(f"{directory} is not a directory")
    files = []
    for path in sorted(directory.iterdir(), key=lambda p: p.name):
        _regular_file(path)
        if suffix is not None and not path.name.endswith(suffix):
            raise ValueError(f"{path.name} in {directory} is not a {suffix} file")
        files.append(path)
    return files


class _HashingReader(io.RawIOBase):
    """Re-hash a file while it is archived, so a change after hashing is caught."""

    def __init__(self, stream) -> None:
        self._stream = stream
        self.digest = hashlib.sha256()

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        data = self._stream.read(size)
        self.digest.update(data)
        return data


def build_install_bundle(
    root: Path,
    output: Path,
    *,
    wheelhouse: Path,
    edge_package: Optional[Path] = None,
    edge_source: Optional[str] = None,
    debs: Optional[Path] = None,
    deb_source: Optional[str] = None,
    models: Sequence[Path] = (),
    knowledge: Sequence[Path] = (),
    assets_source: Optional[str] = None,
    target: str = offline_bundle.BASELINE_TARGET,
) -> dict[str, object]:
    """Write the single-file offline install bundle and return its manifest.

    ``target`` must be named by the caller for anything but the deployment
    baseline, and the wheelhouse must have been built for it: a lab
    (aarch64) wheelhouse never becomes a baseline bundle by default.
    """

    try:
        from tools.build_wheelhouse import load_wheelhouse
    except ImportError:  # pragma: no cover - script execution
        from build_wheelhouse import load_wheelhouse  # type: ignore[no-redef]

    root = root.resolve(strict=True)
    output = output.absolute()
    identity = repository_identity(root)
    origin = f"git:{identity['commit']} worktree:{identity['worktree_state']}"
    entries: list[tuple[dict[str, object], Path]] = []
    for source, name in _inputs(root):
        mode = "0755" if _regular_file(source).st_mode & 0o111 else "0644"
        entries.append(_entry(source, "source/" + name, "source", origin, mode=mode))

    record = load_wheelhouse(wheelhouse, target)
    if record["repository_identity"]["commit"] != identity["commit"]:
        raise ValueError("the wheelhouse was built from a different commit than this source")
    # A wheelhouse built before a lock entry was added (say, before Fabric was
    # bundled, ADR-0004) must not become a bundle the target then refuses.
    offline_bundle.check_lock_is_carried(
        [w for w in record["wheels"]
         if offline_bundle.canonical_name(w["requirement"].partition("==")[0])
         not in offline_bundle.OWN_DISTRIBUTIONS],
        offline_bundle.parse_lock(root / offline_bundle.target_lock(target)),
    )
    for wheel in record["wheels"]:
        entry, path = _entry(wheelhouse / wheel["file"], "wheels/" + wheel["file"], "wheel",
                             wheel["source"], requirement=wheel["requirement"])
        if entry["sha256"] != wheel["sha256"]:
            raise ValueError(f"{wheel['file']} changed after wheelhouse.json was written")
        entries.append((entry, path))

    slots = {kind: "empty" for kind in offline_bundle.SLOT_KINDS}
    if edge_package is not None:
        offline_bundle.refuse_edge_slot_unless_allowed(target)
        if not edge_source:
            raise ValueError("--edge-package needs --edge-source naming where it came from")
        offline_bundle.verify_edge_slot(edge_package, target)
        for path in _slot_files(edge_package):
            entries.append(_entry(path, "edge/" + path.name, "edge-package", edge_source))
        slots["edge-package"] = "filled"
    if debs is not None:
        if not deb_source:
            raise ValueError("--deb needs --deb-source naming the pinned apt source")
        for path in _slot_files(debs, suffix=".deb"):
            fields = offline_bundle.deb_control_fields(path)
            entries.append(_entry(path, "deb/" + path.name, "deb", deb_source, **fields))
        slots["deb"] = "filled" if any(e["kind"] == "deb" for e, _ in entries) else "empty"
    for kind, files in (("model", models), ("knowledge", knowledge)):
        if files and not assets_source:
            raise ValueError("model and Knowledge assets need --assets-source")
        for path in files:
            entries.append(_entry(path, offline_bundle.KIND_PREFIX[kind] + path.name, kind,
                                  str(assets_source)))
        if files:
            slots[kind] = "filled"

    entries.sort(key=lambda item: str(item[0]["path"]))
    artifacts = [entry for entry, _ in entries]
    document: dict[str, object] = {
        "schema": offline_bundle.SCHEMA,
        "target": target,
        "repository_identity": identity,
        "slots": slots,
        "artifacts": artifacts,
        "totals": {"count": len(artifacts), "bytes": sum(int(e["size"]) for e in artifacts)},
    }
    offline_bundle.validate_manifest(document)
    manifest = offline_bundle.manifest_bytes(document)

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=f".{output.name}.", delete=False) as raw:
            temporary_name = raw.name
            with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=6) as compressed:
                # Strict POSIX ustar: tools/offline_bundle.py refuses pax and GNU
                # extensions, and tarfile raises ValueError for a path that does
                # not fit the ustar name/prefix fields -- a build error.
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                    archive.addfile(_tar_info(offline_bundle.MANIFEST_NAME, len(manifest), 0o644),
                                    io.BytesIO(manifest))
                    for entry, path in entries:
                        info = _tar_info(str(entry["path"]), int(entry["size"]), int(str(entry["mode"]), 8))
                        with open(path, "rb") as stream:
                            reader = _HashingReader(stream)
                            archive.addfile(info, reader)
                        if reader.digest.hexdigest() != entry["sha256"]:
                            raise RuntimeError(f"{path} changed while the bundle was being built")
            raw.flush()
            os.fchmod(raw.fileno(), 0o644)
            os.fsync(raw.fileno())
        if repository_identity(root) != identity:
            raise RuntimeError("source checkout changed while the bundle was being built")
        os.replace(temporary_name, output)
        temporary_name = None
    finally:
        if temporary_name is not None and os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return document


def _tar_info(name: str, size: int, mode: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(PurePosixPath(name).as_posix())
    info.size = size
    info.mode = mode
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    info.type = tarfile.REGTYPE
    return info


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="destination .tar.gz path")
    parser.add_argument("--wheelhouse", type=Path,
                        help="build the install bundle from this tools/build_wheelhouse.py output")
    parser.add_argument("--edge-package", type=Path, help="directory holding the pinned Edge manifest and artifact")
    parser.add_argument("--edge-source", help="where the Edge package came from")
    parser.add_argument("--deb", type=Path, help="directory of .deb files to carry (not installed)")
    parser.add_argument("--deb-source", help="the pinned apt source the .deb files came from")
    parser.add_argument("--model", type=Path, action="append", default=[])
    parser.add_argument("--knowledge", type=Path, action="append", default=[])
    parser.add_argument("--assets-source", help="where the model/Knowledge files came from")
    parser.add_argument("--target", choices=sorted(offline_bundle.TARGETS),
                        default=offline_bundle.BASELINE_TARGET,
                        help="the wheelhouse's declared target (default: the deployment baseline); "
                        "debian-13-aarch64-cp313 is a lab-software-verification target")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    slot_args = (args.edge_package, args.deb, args.model, args.knowledge)
    try:
        if args.wheelhouse is None:
            if any(slot_args):
                parser.error("slot options need --wheelhouse; the source bundle carries no slots")
            document = build_bundle(root, args.output)
        else:
            document = build_install_bundle(
                root, args.output, wheelhouse=args.wheelhouse,
                edge_package=args.edge_package, edge_source=args.edge_source,
                debs=args.deb, deb_source=args.deb_source,
                models=args.model, knowledge=args.knowledge, assets_source=args.assets_source,
                target=args.target,
            )
    except (OSError, ValueError, RuntimeError, tarfile.TarError, offline_bundle.BundleRefused) as error:
        parser.error(str(error))
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
