"""Build a deterministic, source-only Azazel-Nexus offline bundle.

The bundle contains the library and runtime Python sources, their packaging
metadata, and the installer/systemd packaging contract.  It is intentionally
not a wheel builder and does not include tests or generated build output.
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
from typing import Iterable


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
    )
    for source, archive_name in fixed:
        _regular_file(source)
        candidates.append((source, archive_name))

    for source_dir, python_only in (
        (root / "src" / "azazel_nexus", True),
        (root / "runtime" / "src" / "azazel_nexus_runtime", True),
        (root / "packaging" / "systemd", False),
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="destination .tar.gz path")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    try:
        document = build_bundle(root, args.output)
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.error(str(error))
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
