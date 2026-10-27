"""Verify, extract and install an Azazel-Nexus offline install bundle.

The bundle is one gzip-compressed tar whose first member is ``MANIFEST.json``.
The manifest lists every other member -- source files, hash-pinned wheels, and
the optional Edge package, Debian package, model and Knowledge slots -- with
its sha256, size, kind and source. ``tools/build_offline_bundle.py`` writes it.

What this module establishes, and what it does not
==================================================

* **Integrity against the manifest.** Extraction refuses absolute paths,
  ``..``, links of any kind, device files, FIFOs and directory members; a
  member count or byte total above the caps; a member that the manifest does
  not declare, or a declared one that is missing; and any size or sha256
  mismatch. It writes into a private staging directory beside the destination
  and renames it into place only after every check passed.
* **Not authenticity.** Nothing here is signed. The manifest can be rewritten
  together with the files it describes, so a bundle that passes every check
  above is exactly as trustworthy as the medium it arrived on.
  ``verify_bundle_signature`` is the integration point for the issuer/operator
  signature; until a verifier is wired in there, every report carries
  ``bundle_authenticated: false``.
* **Not admission.** Carrying an Edge package, a Debian package, a model or a
  Knowledge bundle on the medium admits none of them. Each has its own
  admission path (``edge_package`` checks, model import, Knowledge Lite trust),
  and nothing here substitutes for it.

Run the copy of this file from a reviewed checkout, not the one inside the
bundle: a verifier taken from the thing it verifies checks nothing.

This module uses only the standard library so that it runs with the target's
system interpreter before any virtual environment exists.
"""

from __future__ import annotations

import argparse
import dataclasses
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterable, Optional


SCHEMA = "azazel-nexus-offline-bundle@1"
MANIFEST_NAME = "MANIFEST.json"
#: The detached signature member the signing hook will read. Optional; when it
#: is present it is carried to ``verify_bundle_signature`` and nothing else.
SIGNATURE_NAME = "MANIFEST.sig"
SIGNATURE_MAX_BYTES = 64 << 10

#: Each kind lives under exactly one prefix, so a wheel cannot be smuggled in
#: as a source file or the other way round.
KIND_PREFIX = {
    "source": "source/",
    "wheel": "wheels/",
    "edge-package": "edge/",
    "deb": "deb/",
    "model": "assets/models/",
    "knowledge": "assets/knowledge/",
}
REQUIRED_KINDS = ("source", "wheel")
SLOT_KINDS = ("edge-package", "deb", "model", "knowledge")
SLOT_STATES = ("empty", "filled")
MODES = ("0644", "0755")

#: The only target this bundle format declares: the reference OS and
#: architecture of docs/support-matrix.md §3, with Debian 13's system CPython.
#: Defined here, never read from the manifest, so a bundle cannot name its own
#: target into acceptance.
TARGETS = {
    "debian-13-x86_64-cp313": {
        "os": "debian-13",
        "architecture": "x86_64",
        "deb_architectures": ("amd64", "all"),
        "python_tag": "cp313",
        "python_version": (3, 13),
        # Debian 13 ships glibc 2.41; a manylinux wheel needing more is refused.
        "glibc_max": (2, 41),
    },
}

# `%` because apt names an epoch `1%3a` in a .deb file name.
_COMPONENT = re.compile(r"[A-Za-z0-9_+~=%-][A-Za-z0-9._+~=%-]*\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_WHEEL = re.compile(
    r"(?P<name>[A-Za-z0-9_.]+)-(?P<version>[A-Za-z0-9_.!+]+)"
    r"(?:-(?P<build>\d[A-Za-z0-9_]*))?-(?P<py>[A-Za-z0-9_.]+)-(?P<abi>[A-Za-z0-9_.]+)"
    r"-(?P<plat>[A-Za-z0-9_.]+)\.whl\Z"
)
_REQUIREMENT = re.compile(r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[A-Za-z0-9.!+_-]+)\Z")
_MANYLINUX = re.compile(r"manylinux_(\d+)_(\d+)_(?P<arch>[a-z0-9_]+)\Z")
_LEGACY_MANYLINUX = {"manylinux1": (2, 5), "manylinux2010": (2, 12), "manylinux2014": (2, 17)}

#: The two distributions this repository builds; every bundle carries both.
OWN_DISTRIBUTIONS = ("azazel-nexus", "azazel-nexus-runtime")


class BundleRefused(Exception):
    """The bundle, or one of its members, is refused. Nothing was promoted."""


@dataclass(frozen=True)
class Limits:
    """Extraction caps. A caller may lower them (``tighter``), never raise them."""

    max_members: int = 20_000
    max_total_bytes: int = 16 << 30
    max_member_bytes: int = 8 << 30
    max_manifest_bytes: int = 8 << 20
    max_depth: int = 16
    max_path_bytes: int = 240

    def tighter(self, **overrides: int) -> "Limits":
        for key, value in overrides.items():
            current = getattr(self, key)
            if type(value) is not int or value < 1 or value > current:
                raise BundleRefused(
                    f"{key}={value!r} is refused: a cap can be lowered from {current}, "
                    "never raised"
                )
        return dataclasses.replace(self, **overrides)


DEFAULT_LIMITS = Limits()


# --------------------------------------------------------------------------
# The signing hook.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SignatureVerdict:
    authenticated: bool
    signature_present: bool
    reason: str


def verify_bundle_signature(manifest_bytes: bytes, signature: Optional[bytes]) -> SignatureVerdict:
    """Bundle signing hook: verify the issuer/operator signature over ``MANIFEST.json``.

    This is the one integration point for the bundle signature that the
    issuer/operator signing work defines. It receives the exact manifest bytes
    and the bytes of the optional ``MANIFEST.sig`` member. No verifier is
    integrated yet, so it authenticates nothing: an absent signature and a
    present one both yield ``authenticated=False``. A present signature is not
    checked and is never read as evidence of anything.

    Whatever replaces this body MUST NOT change the acceptance of an unsigned
    bundle as a side effect; that is a release-admission decision
    (docs/update-channel.md §3), not a property of the extractor.
    """

    del manifest_bytes  # bound by the future verifier; unused until then
    if signature is None:
        return SignatureVerdict(
            authenticated=False,
            signature_present=False,
            reason="unsigned: the bundle carries no MANIFEST.sig and no bundle signature is defined",
        )
    return SignatureVerdict(
        authenticated=False,
        signature_present=True,
        reason=(
            "MANIFEST.sig is present, but no issuer/operator bundle verifier is integrated; "
            "it was not checked and authenticates nothing"
        ),
    )


# --------------------------------------------------------------------------
# Paths, names and the manifest.
# --------------------------------------------------------------------------


def safe_member_path(name: object, limits: Limits = DEFAULT_LIMITS) -> str:
    """``name`` if it is a plain relative POSIX path inside the bundle, else refuse."""

    if type(name) is not str or not name:
        raise BundleRefused("a member path is empty or not a string")
    if "\0" in name or "\\" in name:
        raise BundleRefused(f"member path {name!r} contains a NUL or a backslash")
    if name.startswith("/"):
        raise BundleRefused(f"member path {name!r} is absolute")
    if len(name.encode("utf-8")) > limits.max_path_bytes:
        raise BundleRefused(f"member path {name!r} is longer than {limits.max_path_bytes} bytes")
    parts = name.split("/")
    if ".." in parts:
        raise BundleRefused(f"member path {name!r} contains '..'")
    if len(parts) > limits.max_depth:
        raise BundleRefused(f"member path {name!r} is deeper than {limits.max_depth}")
    for part in parts:
        if not _COMPONENT.match(part):
            raise BundleRefused(f"member path {name!r} has a refused component {part!r}")
    if PurePosixPath(name).as_posix() != name:
        raise BundleRefused(f"member path {name!r} is not in normal form")
    return name


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_wheel_name(filename: str) -> dict[str, str]:
    match = _WHEEL.match(filename)
    if not match:
        raise BundleRefused(f"{filename!r} is not a wheel file name")
    return match.groupdict()


def _glibc_of(tag: str, architecture: str) -> Optional[tuple[int, int]]:
    if tag == f"linux_{architecture}":
        return (0, 0)
    legacy, _, arch = tag.partition("_")
    if legacy in _LEGACY_MANYLINUX and arch == architecture:
        return _LEGACY_MANYLINUX[legacy]
    match = _MANYLINUX.match(tag)
    if match and match.group("arch") == architecture:
        return (int(match.group(1)), int(match.group(2)))
    return None


def wheel_fits_target(filename: str, target: dict) -> bool:
    """Whether a wheel's compatibility tags admit the declared target at all."""

    parts = parse_wheel_name(filename)
    pythons = set(parts["py"].split("."))
    abis = set(parts["abi"].split("."))
    platforms = parts["plat"].split(".")
    if not pythons & {"py3", target["python_tag"]}:
        return False
    if not abis & {"none", "abi3", target["python_tag"]}:
        return False
    if "abi3" in abis and not pythons & {"cp3" + str(m) for m in range(2, target["python_version"][1] + 1)}:
        return False
    if platforms == ["any"]:
        return True
    for platform in platforms:
        glibc = _glibc_of(platform, target["architecture"])
        if glibc is not None and glibc <= target["glibc_max"]:
            return True
    return False


def _exact_keys(document: dict, required: set[str], optional: set[str], what: str) -> None:
    keys = set(document)
    missing = required - keys
    extra = keys - required - optional
    if missing or extra:
        raise BundleRefused(f"{what}: missing {sorted(missing)}, unexpected {sorted(extra)}")


_ARTIFACT_KEYS = {"path", "kind", "sha256", "size", "mode", "source"}
_KIND_KEYS = {
    "source": set(),
    "wheel": {"requirement"},
    "edge-package": set(),
    "deb": {"package", "version", "architecture"},
    "model": set(),
    "knowledge": set(),
}


def validate_manifest(document: object, limits: Limits = DEFAULT_LIMITS) -> dict:
    """Return ``document`` if it is a well-formed bundle manifest, else refuse."""

    if type(document) is not dict:
        raise BundleRefused("the manifest is not a JSON object")
    _exact_keys(
        document,
        {"schema", "target", "repository_identity", "slots", "artifacts", "totals"},
        set(),
        "manifest",
    )
    if document["schema"] != SCHEMA:
        raise BundleRefused(f"manifest schema {document['schema']!r} is not {SCHEMA!r}")
    if document["target"] not in TARGETS:
        raise BundleRefused(f"manifest target {document['target']!r} is not a declared target")
    identity = document["repository_identity"]
    if type(identity) is not dict or not all(type(v) is str for v in identity.values()):
        raise BundleRefused("manifest repository_identity is not a string map")
    slots = document["slots"]
    if type(slots) is not dict or set(slots) != set(SLOT_KINDS):
        raise BundleRefused(f"manifest slots must be exactly {list(SLOT_KINDS)}")
    artifacts = document["artifacts"]
    if type(artifacts) is not list or not artifacts:
        raise BundleRefused("manifest lists no artifacts")
    if len(artifacts) > limits.max_members:
        raise BundleRefused(f"manifest lists {len(artifacts)} artifacts; the cap is {limits.max_members}")

    seen: set[str] = set()
    kinds_present: set[str] = set()
    total = 0
    reserved = {MANIFEST_NAME, SIGNATURE_NAME}
    for entry in artifacts:
        if type(entry) is not dict:
            raise BundleRefused("a manifest artifact is not an object")
        kind = entry.get("kind")
        if kind not in KIND_PREFIX:
            raise BundleRefused(f"artifact kind {kind!r} is not declared")
        _exact_keys(entry, _ARTIFACT_KEYS | _KIND_KEYS[kind], set(), f"artifact {entry.get('path')!r}")
        path = safe_member_path(entry["path"], limits)
        if path in reserved or path in seen:
            raise BundleRefused(f"artifact path {path!r} is reserved or duplicated")
        if not path.startswith(KIND_PREFIX[kind]):
            raise BundleRefused(f"{kind} artifact {path!r} is not under {KIND_PREFIX[kind]}")
        if type(entry["sha256"]) is not str or not _SHA256.match(entry["sha256"]):
            raise BundleRefused(f"artifact {path!r} has a malformed sha256")
        size = entry["size"]
        if type(size) is not int or size < 0 or size > limits.max_member_bytes:
            raise BundleRefused(f"artifact {path!r} declares a refused size {size!r}")
        if entry["mode"] not in MODES:
            raise BundleRefused(f"artifact {path!r} declares a refused mode {entry['mode']!r}")
        if type(entry["source"]) is not str or not entry["source"]:
            raise BundleRefused(f"artifact {path!r} names no source")
        if kind == "wheel":
            _validate_wheel_entry(entry, TARGETS[document["target"]])
        if kind == "deb":
            for key in ("package", "version", "architecture"):
                if type(entry[key]) is not str or not entry[key]:
                    raise BundleRefused(f"deb artifact {path!r} has no {key}")
            if entry["architecture"] not in TARGETS[document["target"]]["deb_architectures"]:
                raise BundleRefused(f"deb artifact {path!r} is for {entry['architecture']!r}")
        seen.add(path)
        kinds_present.add(kind)
        total += size
    if total > limits.max_total_bytes:
        raise BundleRefused(f"manifest declares {total} bytes; the cap is {limits.max_total_bytes}")
    for kind in REQUIRED_KINDS:
        if kind not in kinds_present:
            raise BundleRefused(f"manifest carries no {kind} artifact")
    for kind in SLOT_KINDS:
        state = slots[kind]
        if state not in SLOT_STATES:
            raise BundleRefused(f"slot {kind} has a refused state {state!r}")
        if (state == "filled") != (kind in kinds_present):
            raise BundleRefused(f"slot {kind} is {state!r} but the artifacts say otherwise")
    if document["totals"] != {"count": len(artifacts), "bytes": total}:
        raise BundleRefused("manifest totals do not match its artifacts")
    if [entry["path"] for entry in artifacts] != sorted(seen):
        raise BundleRefused("manifest artifacts are not in path order")
    wheels = {canonical_name(e["requirement"].partition("==")[0]) for e in artifacts if e["kind"] == "wheel"}
    for own in OWN_DISTRIBUTIONS:
        if own not in wheels:
            raise BundleRefused(f"manifest carries no {own} wheel")
    return document


def _validate_wheel_entry(entry: dict, target: dict) -> None:
    filename = PurePosixPath(entry["path"]).name
    if entry["path"] != KIND_PREFIX["wheel"] + filename:
        raise BundleRefused(f"wheel {entry['path']!r} is not directly under wheels/")
    parts = parse_wheel_name(filename)
    requirement = entry["requirement"]
    match = _REQUIREMENT.match(requirement) if type(requirement) is str else None
    if not match:
        raise BundleRefused(f"wheel {filename!r} has a refused requirement {requirement!r}")
    if canonical_name(match.group("name")) != canonical_name(parts["name"]):
        raise BundleRefused(f"wheel {filename!r} does not carry {requirement!r}")
    if match.group("version") != parts["version"]:
        raise BundleRefused(f"wheel {filename!r} is not version {match.group('version')!r}")
    if not wheel_fits_target(filename, target):
        raise BundleRefused(f"wheel {filename!r} does not fit the declared target")


def manifest_bytes(document: dict) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")


def load_manifest(data: bytes, limits: Limits = DEFAULT_LIMITS) -> dict:
    if len(data) > limits.max_manifest_bytes:
        raise BundleRefused("the manifest is larger than its cap")
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise BundleRefused(f"the manifest is not JSON ({exc})") from exc
    return validate_manifest(document, limits)


def wheel_requirements(document: dict) -> str:
    """A ``--require-hashes`` requirements file naming exactly the bundled wheels."""

    lines = []
    for entry in document["artifacts"]:
        if entry["kind"] == "wheel":
            lines.append(f"{entry['requirement']} --hash=sha256:{entry['sha256']}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Safe extraction.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Extracted:
    root: Path
    manifest: dict
    manifest_bytes: bytes
    signature: Optional[bytes]


def _member_type_refusal(member: tarfile.TarInfo) -> Optional[str]:
    if member.issym():
        return f"member {member.name!r} is a symlink (to {member.linkname!r}); links are refused"
    if member.islnk():
        return f"member {member.name!r} is a hardlink (to {member.linkname!r}); links are refused"
    if member.ischr() or member.isblk():
        return f"member {member.name!r} is a device file"
    if member.isfifo():
        return f"member {member.name!r} is a FIFO"
    if member.isdir():
        return f"member {member.name!r} is a directory entry; only declared regular files are carried"
    if not member.isreg() or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
        return f"member {member.name!r} is not a plain regular file"
    return None


def _read_bounded(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size + 1)
    if len(data) != size:
        raise BundleRefused("a member's data does not match its header size")
    return data


def _write_member(staging: Path, path: str, stream: BinaryIO, entry: dict) -> None:
    destination = staging.joinpath(*path.split("/"))
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(destination, flags, 0o600)
    digest = hashlib.sha256()
    written = 0
    try:
        while True:
            chunk = stream.read(1 << 20)
            if not chunk:
                break
            written += len(chunk)
            if written > entry["size"]:
                raise BundleRefused(f"member {path!r} is larger than the manifest declares")
            digest.update(chunk)
            _write_all(fd, chunk)
        os.fsync(fd)
        os.fchmod(fd, int(entry["mode"], 8))
    finally:
        os.close(fd)
    if written != entry["size"]:
        raise BundleRefused(f"member {path!r} is {written} bytes; the manifest declares {entry['size']}")
    if digest.hexdigest() != entry["sha256"]:
        raise BundleRefused(f"member {path!r} does not match its manifest sha256")


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _fsync_tree(root: Path) -> None:
    for directory, _dirs, _files in os.walk(root):
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def extract_bundle(archive: Path, destination: Path, *, limits: Limits = DEFAULT_LIMITS) -> Extracted:
    """Extract ``archive`` into ``destination`` atomically, or refuse and leave nothing.

    ``destination`` must not exist. Members are written into a private staging
    directory beside it; the staging directory is renamed to ``destination``
    only after every member was declared, sized and hashed as the manifest
    says and no declared member is missing.
    """

    destination = Path(os.path.abspath(destination))
    if os.path.lexists(destination):
        raise BundleRefused(f"{destination} already exists; extraction never merges into a tree")
    parent = destination.parent
    if not parent.is_dir() or parent.is_symlink():
        raise BundleRefused(f"{parent} is not a directory")
    info = os.lstat(archive)
    if not stat.S_ISREG(info.st_mode):
        raise BundleRefused(f"{archive} is not a regular file")
    if info.st_size > limits.max_total_bytes + limits.max_manifest_bytes + (64 << 20):
        raise BundleRefused(f"{archive} is larger than the extraction cap")

    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.staging-", dir=parent))
    try:
        result = _extract_into(archive, staging, limits)
        _fsync_tree(staging)
        if os.path.lexists(destination):
            raise BundleRefused(f"{destination} appeared during extraction")
        os.rename(staging, destination)
        fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return dataclasses.replace(result, root=destination)


def _extract_into(archive: Path, staging: Path, limits: Limits) -> Extracted:
    try:
        with open(archive, "rb") as raw, tarfile.open(fileobj=raw, mode="r|gz") as tar:
            members = iter(tar)
            first = next(members, None)
            if first is None or first.name != MANIFEST_NAME:
                raise BundleRefused(f"the first member is not {MANIFEST_NAME}")
            refusal = _member_type_refusal(first)
            if refusal:
                raise BundleRefused(refusal)
            if first.size > limits.max_manifest_bytes:
                raise BundleRefused("the manifest is larger than its cap")
            stream = tar.extractfile(first)
            assert stream is not None
            raw_manifest = _read_bounded(stream, first.size)
            document = load_manifest(raw_manifest, limits)
            declared = {entry["path"]: entry for entry in document["artifacts"]}
            seen: set[str] = set()
            signature: Optional[bytes] = None
            count = 1
            total = 0
            for member in members:
                count += 1
                if count > limits.max_members + 2:
                    raise BundleRefused(f"the archive has more than {limits.max_members} members")
                name = safe_member_path(member.name, limits)
                refusal = _member_type_refusal(member)
                if refusal:
                    raise BundleRefused(refusal)
                if name == SIGNATURE_NAME:
                    if signature is not None or seen or member.size > SIGNATURE_MAX_BYTES:
                        raise BundleRefused(f"{SIGNATURE_NAME} is duplicated, misplaced or too large")
                    stream = tar.extractfile(member)
                    assert stream is not None
                    signature = _read_bounded(stream, member.size)
                    continue
                if name not in declared:
                    raise BundleRefused(f"member {name!r} is not declared in the manifest")
                if name in seen:
                    raise BundleRefused(f"member {name!r} appears twice")
                entry = declared[name]
                if member.size != entry["size"]:
                    raise BundleRefused(
                        f"member {name!r} is {member.size} bytes; the manifest declares {entry['size']}"
                    )
                total += member.size
                if total > limits.max_total_bytes:
                    raise BundleRefused(f"the archive exceeds {limits.max_total_bytes} bytes")
                stream = tar.extractfile(member)
                assert stream is not None
                _write_member(staging, name, stream, entry)
                seen.add(name)
            missing = sorted(set(declared) - seen)
            if missing:
                raise BundleRefused(f"declared members are missing from the archive: {missing[:5]}")
    except BundleRefused:
        raise
    except (OSError, EOFError, tarfile.TarError, gzip.BadGzipFile, zlib.error) as exc:
        raise BundleRefused(f"the archive could not be read ({exc})") from exc
    (staging / MANIFEST_NAME).write_bytes(raw_manifest)
    os.chmod(staging / MANIFEST_NAME, 0o644)
    return Extracted(root=staging, manifest=document, manifest_bytes=raw_manifest, signature=signature)


# --------------------------------------------------------------------------
# Slot verification.
# --------------------------------------------------------------------------


def _edge_package_module():
    """The reviewed ``azazel_nexus.edge_package`` beside this file (stdlib-only)."""

    source = str(Path(__file__).resolve().parents[1] / "src")
    if source not in sys.path:
        sys.path.insert(0, source)
    from azazel_nexus import edge_package  # noqa: PLC0415

    return edge_package


def verify_edge_slot(directory: Path) -> dict[str, Any]:
    """Run the existing Edge package checks over a carried Edge package.

    Requires ``package_present``, ``version_matches`` and ``digest_matches`` to
    pass and the manifest's bound-component digests to match the archive.
    Health and running are not observable from a medium and stay
    ``not-checked``; nothing here makes the package admitted or ready.
    """

    edge = _edge_package_module()
    names = sorted(p.name for p in directory.iterdir()) if directory.is_dir() else []
    expected = sorted((edge.PIN.manifest_name, edge.PIN.artifact_name))
    if names != expected:
        raise BundleRefused(f"the Edge slot holds {names}; it must hold exactly {expected}")
    inspection = edge.inspect(directory)
    findings = {f.check: f for f in inspection.findings}
    for check in ("package_present", "version_matches", "digest_matches"):
        finding = findings[check]
        if finding.evidence is not edge.Evidence.PASSED:
            raise BundleRefused(f"Edge {check} is {finding.evidence.value}: {finding.reason}")
    manifest = json.loads((directory / edge.PIN.manifest_name).read_text(encoding="utf-8"))
    try:
        declared = edge._manifest_components(manifest)
        archived = edge._archive_components((directory / edge.PIN.artifact_name).read_bytes())
    except edge.EdgePackageRefused as exc:
        raise BundleRefused(f"Edge components: {exc}") from exc
    if declared != archived:
        raise BundleRefused("the Edge archive's bound components do not match its manifest")
    return {
        "state": "verified-integrity",
        "checks": {check: findings[check].evidence.value for check in edge.CHECKS},
        "caveat": edge.UNSIGNED_CAVEAT,
        "admitted": False,
    }


_AR_MAGIC = b"!<arch>\n"
_CONTROL_MAX_BYTES = 16 << 20


def deb_control_fields(path: Path) -> dict[str, str]:
    """Package/Version/Architecture from a .deb's control file, read with bounds."""

    with open(path, "rb") as stream:
        if stream.read(8) != _AR_MAGIC:
            raise BundleRefused(f"{path.name} is not an ar archive")
        index = 0
        control: Optional[tuple[str, bytes]] = None
        while control is None:
            header = stream.read(60)
            if len(header) != 60 or header[58:60] != b"`\n":
                raise BundleRefused(f"{path.name} has a malformed ar header")
            name = header[0:16].decode("ascii", "replace").strip().rstrip("/")
            try:
                size = int(header[48:58].decode("ascii").strip())
            except ValueError as exc:
                raise BundleRefused(f"{path.name} has a malformed ar member size") from exc
            if index == 0:
                if name != "debian-binary" or size > 64 or stream.read(size).strip() != b"2.0":
                    raise BundleRefused(f"{path.name} is not a format 2.0 Debian package")
            elif name.startswith("control.tar"):
                if size > _CONTROL_MAX_BYTES:
                    raise BundleRefused(f"{path.name} has an oversized control archive")
                control = (name, stream.read(size))
            elif index > 2:
                raise BundleRefused(f"{path.name} has no control archive")
            else:
                stream.seek(size, os.SEEK_CUR)
            if size % 2 and control is None:
                stream.seek(1, os.SEEK_CUR)
            index += 1
    name, data = control
    try:
        if name == "control.tar.gz":
            data = gzip.decompress(data)
        elif name == "control.tar.xz":
            data = lzma.decompress(data, memlimit=64 << 20)
        elif name != "control.tar":
            raise BundleRefused(f"{path.name} uses {name}; this verifier cannot read it")
        if len(data) > _CONTROL_MAX_BYTES:
            raise BundleRefused(f"{path.name} has an oversized control archive")
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
            text = None
            for member in tar:
                if member.name in ("control", "./control") and member.isreg() and member.size <= 1 << 20:
                    stream = tar.extractfile(member)
                    assert stream is not None
                    text = stream.read().decode("utf-8")
                    break
    except BundleRefused:
        raise
    except (OSError, EOFError, lzma.LZMAError, tarfile.TarError, UnicodeDecodeError) as exc:
        raise BundleRefused(f"{path.name} control archive could not be read ({exc})") from exc
    if text is None:
        raise BundleRefused(f"{path.name} has no control file")
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if line[:1] in (" ", "\t") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        if key in ("Package", "Version", "Architecture"):
            fields[key.lower()] = value.strip()
    if set(fields) != {"package", "version", "architecture"}:
        raise BundleRefused(f"{path.name} control lacks Package/Version/Architecture")
    return fields


def verify_deb_slot(root: Path, document: dict) -> dict[str, Any]:
    packages = []
    for entry in document["artifacts"]:
        if entry["kind"] != "deb":
            continue
        fields = deb_control_fields(root.joinpath(*entry["path"].split("/")))
        declared = {key: entry[key] for key in ("package", "version", "architecture")}
        if fields != declared:
            raise BundleRefused(f"{entry['path']} control says {fields}; the manifest says {declared}")
        packages.append({**declared, "source": entry["source"]})
    return {
        "state": "verified-integrity",
        "packages": packages,
        "installed": False,
        "note": "carried and checked against the manifest only; the apt source is not authenticated here",
    }


def verify_extracted(extracted: Extracted) -> dict[str, Any]:
    """Slot checks over an extracted tree, and the report the installer prints."""

    document = extracted.manifest
    root = extracted.root
    slots: dict[str, Any] = {}
    if document["slots"]["edge-package"] == "filled":
        slots["edge-package"] = verify_edge_slot(root / "edge")
    else:
        slots["edge-package"] = {"state": "empty"}
    if document["slots"]["deb"] == "filled":
        slots["deb"] = verify_deb_slot(root, document)
    else:
        slots["deb"] = {"state": "empty"}
    for kind in ("model", "knowledge"):
        carried = [e["path"] for e in document["artifacts"] if e["kind"] == kind]
        slots[kind] = (
            {"state": "carried", "files": carried, "admitted": False}
            if carried
            else {"state": "empty"}
        )
    verdict = verify_bundle_signature(extracted.manifest_bytes, extracted.signature)
    return {
        "schema": "azazel-nexus-offline-bundle-report@1",
        "target": document["target"],
        "manifest_sha256": hashlib.sha256(extracted.manifest_bytes).hexdigest(),
        "integrity": "every declared member matched its manifest size and sha256",
        "bundle_authenticated": verdict.authenticated,
        "signature": {"present": verdict.signature_present, "reason": verdict.reason},
        "counts": {kind: sum(1 for e in document["artifacts"] if e["kind"] == kind) for kind in KIND_PREFIX},
        "slots": slots,
    }


# --------------------------------------------------------------------------
# Offline install of the two distributions.
# --------------------------------------------------------------------------


_FIXED_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
              "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INPUT": "1"}


def _run(argv: list[str]) -> None:
    result = subprocess.run(argv, env=_FIXED_ENV, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise BundleRefused(
            f"{' '.join(argv[:4])} ... exited {result.returncode}: {result.stderr.strip()[-2000:]}"
        )


def pip_install_offline(python: Path, wheels: Path, requirements: Path) -> None:
    """``pip install`` with no index, only the given wheels, and every hash required."""

    _run([
        str(python), "-I", "-m", "pip", "install",
        "--no-index", "--find-links", str(wheels),
        "--require-hashes", "--only-binary=:all:", "--no-cache-dir",
        "--disable-pip-version-check", "-r", str(requirements),
    ])


def install(bundle: Path, into: Path, venv: Path, python: Path, *, limits: Limits = DEFAULT_LIMITS) -> dict:
    """Extract, verify, then install both distributions into a fresh venv, offline."""

    if os.path.lexists(venv):
        raise BundleRefused(f"{venv} already exists; the offline install creates a fresh venv")
    extracted = extract_bundle(bundle, into, limits=limits)
    report = verify_extracted(extracted)
    target = TARGETS[extracted.manifest["target"]]
    probe = subprocess.run(
        [str(python), "-I", "-c",
         "import platform, sys; print(platform.machine(), sys.implementation.name, *sys.version_info[:2])"],
        env=_FIXED_ENV, capture_output=True, text=True, check=False,
    )
    expected = f"{target['architecture']} cpython {target['python_version'][0]} {target['python_version'][1]}"
    if probe.returncode != 0 or probe.stdout.strip() != expected:
        raise BundleRefused(
            f"{python} reports {probe.stdout.strip()!r}; the bundle targets {expected!r}"
        )
    _run([str(python), "-I", "-m", "venv", str(venv)])
    venv_python = venv / "bin" / "python"
    with tempfile.TemporaryDirectory(prefix="azazel-offline-req-") as scratch:
        requirements = Path(scratch) / "wheels.requirements.txt"
        requirements.write_text(wheel_requirements(extracted.manifest), encoding="utf-8")
        pip_install_offline(venv_python, into / "wheels", requirements)
    _run([str(venv_python), "-I", "-m", "pip", "check", "--disable-pip-version-check"])
    _run([str(venv_python), "-I", "-c",
          "import azazel_nexus, azazel_nexus_runtime, azazel_nexus_runtime._bootstrap_deadline, "
          "yaml, dbus_next"])
    report["install"] = {
        "venv": str(venv),
        "distributions": sorted(
            e["requirement"] for e in extracted.manifest["artifacts"] if e["kind"] == "wheel"
        ),
        "pip": "--no-index --find-links --require-hashes --only-binary=:all:",
        "pip_check": "pass",
        "imports": "pass",
        "next": (
            f"sudo env PYTHON={venv_python} sh {into / 'source' / 'packaging' / 'install.sh'}"
        ),
        "not_done": "accounts, units and activation are packaging/install.sh's and the operator's steps",
    }
    return report


# --------------------------------------------------------------------------
# CLI.
# --------------------------------------------------------------------------


def _limits_from(args: argparse.Namespace) -> Limits:
    overrides = {
        key: getattr(args, key)
        for key in ("max_members", "max_total_bytes")
        if getattr(args, key) is not None
    }
    return DEFAULT_LIMITS.tighter(**overrides) if overrides else DEFAULT_LIMITS


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("verify", "install"):
        command = sub.add_parser(name)
        command.add_argument("--bundle", required=True, type=Path)
        command.add_argument("--into", required=True, type=Path,
                             help="destination directory; must not exist")
        command.add_argument("--max-members", type=int)
        command.add_argument("--max-total-bytes", type=int)
        if name == "install":
            command.add_argument("--venv", required=True, type=Path)
            command.add_argument("--python", type=Path, default=Path("/usr/bin/python3"))
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        limits = _limits_from(args)
        if args.command == "verify":
            report = verify_extracted(extract_bundle(args.bundle, args.into, limits=limits))
        else:
            report = install(args.bundle, args.into, args.venv, args.python, limits=limits)
    except (BundleRefused, OSError) as exc:
        print(json.dumps({"refused": str(exc), "bundle_authenticated": False}), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
