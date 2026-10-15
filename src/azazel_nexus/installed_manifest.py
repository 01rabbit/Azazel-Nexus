"""Canonical, pinned manifests of selected installed files.

This data model does not read files, establish a complete dependency closure,
or grant admission. A separate bounded reader measures selected paths.
"""

from dataclasses import dataclass, field
from hashlib import sha256
import json
import re

from .operator_store import _unique_object
from .operator_trust import ApprovalRefused

_SCHEMA_V1 = "azazel-nexus/selected-installed-files/v1"
_SCHEMA_V2 = "azazel-nexus/selected-installed-files/v2"
_SCHEMA_V3 = "azazel-nexus/selected-installed-files/v3"
_SCHEMA_V4 = "azazel-nexus/selected-installed-files/v4"
_MAX_RAW_BYTES = 1 << 20
_MAX_FILES = 4096
_MAX_DIRECTORIES = 1024
_MAX_LINKS = 1024
_MAX_LINK_DEPTH = 8
_MAX_FILE_SIZE = 64 << 20
_MAX_TOTAL_SIZE = 512 << 20
_MAX_PATH = 512
_MAX_DEPTH = 32
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_PINNED_HEX = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMPONENT = re.compile(r"[A-Za-z0-9_.+-]+\Z")


_ROOTS_V3 = ("usr/", "opt/")
_ROOTS_V4 = ("usr/", "opt/", "etc/")
_PRELOAD = "etc/ld.so.preload"


def _validate_path(path, roots=_ROOTS_V3):
    if (type(path) is not str or not path.isascii() or not 1 <= len(path) <= _MAX_PATH
            or not path.startswith(roots)):
        raise ApprovalRefused("installed manifest path refused")
    components = path.split("/")
    if (len(components) > _MAX_DEPTH
            or any(component in {"", ".", ".."}
                   or _COMPONENT.fullmatch(component) is None for component in components)):
        raise ApprovalRefused("installed manifest path refused")


def _validate_file(value, version=3):
    if type(value) is not InstalledFile:
        raise ApprovalRefused("installed manifest file entry required")
    _validate_path(value.path, _ROOTS_V4 if version == 4 else _ROOTS_V3)
    if type(value.mode) is not int or value.mode not in {0o644, 0o755}:
        raise ApprovalRefused("installed manifest mode refused")
    if type(value.size) is not int or not 0 <= value.size <= _MAX_FILE_SIZE:
        raise ApprovalRefused("installed manifest file size refused")
    if type(value.sha256) is not str or _HEX.fullmatch(value.sha256) is None:
        raise ApprovalRefused("installed manifest file digest refused")


def _validate_directory(value, version=3):
    if type(value) is not InstalledDirectory:
        raise ApprovalRefused("installed manifest directory entry required")
    _validate_path(value.path, _ROOTS_V4 if version == 4 else _ROOTS_V3)
    if type(value.mode) is not int or value.mode != 0o755:
        raise ApprovalRefused("installed manifest directory mode refused")


def _validate_link(value, version=3):
    if type(value) is not InstalledLink:
        raise ApprovalRefused("installed manifest link entry required")
    roots = _ROOTS_V4 if version == 4 else _ROOTS_V3
    _validate_path(value.path, roots)
    target = value.target
    if (type(target) is not str or not target.isascii() or not 1 <= len(target) <= _MAX_PATH
            or any(ord(char) < 32 or ord(char) == 127 for char in target)):
        raise ApprovalRefused("installed manifest link target refused")
    if version == 4:
        if target.startswith("/"):
            _validate_path(target[1:], roots)
        else:
            _normalize_relative(value.path, target)
    elif target.startswith(("/usr/", "/opt/")):
        _validate_path(target[1:])
    elif ("/" in target or target in {".", ".."}
          or _COMPONENT.fullmatch(target) is None):
        raise ApprovalRefused("installed manifest link target refused")


def _normalize_relative(link_path, target):
    """Join a v4 relative target to the link's parent; stay in roots.

    Grammar: (".." "/")* name ("/" name)*. No "." component, and no ".."
    after a normal component, so the lexical join equals kernel resolution
    (no intermediate component can be an undeclared symlink).
    """
    parts = link_path.split("/")[:-1]
    components = target.split("/")
    if any(component in {"", "."} or _COMPONENT.fullmatch(component) is None
           for component in components):
        raise ApprovalRefused("installed manifest link target refused")
    ups = 0
    while ups < len(components) and components[ups] == "..":
        ups += 1
    names = components[ups:]
    if not names or any(component == ".." for component in names):
        raise ApprovalRefused("installed manifest link target refused")
    if ups > len(parts):
        raise ApprovalRefused("installed manifest link target escapes root")
    resolved = "/".join(parts[:len(parts) - ups] + names)
    # The result must itself be a valid manifest path (allowed root, bounds).
    _validate_path(resolved, _ROOTS_V4)
    return resolved


@dataclass(frozen=True, repr=False)
class InstalledFile:
    path: str
    mode: int
    size: int
    sha256: str
    # Schema 4 entry rules (etc/ roots, nested link targets); ignored by equality.
    v4: bool = field(default=False, compare=False)

    def __post_init__(self):
        _validate_file(self, 4 if self.v4 is True else 3)


@dataclass(frozen=True, repr=False)
class InstalledDirectory:
    path: str
    mode: int = 0o755
    v4: bool = field(default=False, compare=False)

    def __post_init__(self):
        _validate_directory(self, 4 if self.v4 is True else 3)


@dataclass(frozen=True, repr=False)
class InstalledLink:
    path: str
    target: str
    v4: bool = field(default=False, compare=False)

    def __post_init__(self):
        _validate_link(self, 4 if self.v4 is True else 3)


@dataclass(frozen=True, repr=False)
class InstalledManifest:
    files: tuple[InstalledFile, ...]
    directories: tuple[InstalledDirectory, ...] = ()
    version: int = 1
    links: tuple[InstalledLink, ...] = ()

    def __post_init__(self):
        _validate_manifest(self)


def _validate_manifest(manifest):
    if (type(manifest) is not InstalledManifest or type(manifest.files) is not tuple
            or type(manifest.directories) is not tuple or type(manifest.links) is not tuple
            or type(manifest.version) is not int
            or manifest.version not in {1, 2, 3, 4}):
        raise ApprovalRefused("installed manifest required")
    if not 0 < len(manifest.files) <= _MAX_FILES:
        raise ApprovalRefused("installed manifest file count refused")
    for entry in manifest.files:
        _validate_file(entry, manifest.version)
    paths = tuple(entry.path for entry in manifest.files)
    if paths != tuple(sorted(set(paths))):
        raise ApprovalRefused("installed manifest paths must be sorted and unique")
    if sum(entry.size for entry in manifest.files) > _MAX_TOTAL_SIZE:
        raise ApprovalRefused("installed manifest total size refused")
    if manifest.version == 1:
        if manifest.directories or manifest.links:
            raise ApprovalRefused("version one installed manifests cannot declare directories or links")
        return
    if len(manifest.directories) > _MAX_DIRECTORIES:
        raise ApprovalRefused("installed manifest directory count refused")
    for entry in manifest.directories:
        _validate_directory(entry, manifest.version)
    directory_paths = tuple(entry.path for entry in manifest.directories)
    if directory_paths != tuple(sorted(set(directory_paths))):
        raise ApprovalRefused("installed manifest directory paths must be sorted and unique")
    if manifest.version == 2 and manifest.links:
        raise ApprovalRefused("version two installed manifests cannot declare links")
    if len(manifest.links) > _MAX_LINKS:
        raise ApprovalRefused("installed manifest link count refused")
    for entry in manifest.links:
        _validate_link(entry, manifest.version)
    link_paths = tuple(entry.path for entry in manifest.links)
    if link_paths != tuple(sorted(set(link_paths))):
        raise ApprovalRefused("installed manifest link paths must be sorted and unique")
    file_paths = set(paths)
    directory_set = set(directory_paths)
    link_set = set(link_paths)
    if (file_paths & directory_set or file_paths & link_set or directory_set & link_set):
        raise ApprovalRefused("installed manifest entry paths collide")
    all_paths = file_paths | directory_set | link_set
    non_directory_paths = file_paths | link_set
    for path in all_paths:
        components = path.split("/")
        parents = ["/".join(components[:index])
                   for index in range(2, len(components))]
        if any(parent in non_directory_paths for parent in parents):
            raise ApprovalRefused("installed manifest file or link is an ancestor of another entry")
        declared_ancestors = [
            index for index, parent in enumerate(parents, start=2)
            if parent in directory_set
        ]
        for ancestor_depth in declared_ancestors:
            required = {
                "/".join(components[:index])
                for index in range(ancestor_depth + 1, len(components))
            }
            if not required <= directory_set:
                raise ApprovalRefused(
                    "installed manifest intermediate directory is not declared"
                )
    if manifest.version == 4 and (
            _PRELOAD in all_paths or _PRELOAD in {
                entry.target[1:] for entry in manifest.links
                if entry.target.startswith("/")}):
        raise ApprovalRefused("dynamic loader preload must remain absent")
    if manifest.version in {3, 4}:
        link_map = {entry.path: entry.target for entry in manifest.links}
        for path in link_paths:
            if _resolve_link_path(path, file_paths, directory_set, link_map,
                                  manifest.version) == _PRELOAD:
                raise ApprovalRefused("dynamic loader preload must remain absent")


def _resolve_link_path(path, file_paths, directory_paths, link_map, version=3):
    seen = set()
    current = path
    depth = 0
    while True:
        if current in file_paths:
            return current
        if current in directory_paths or current not in link_map:
            raise ApprovalRefused("installed manifest link does not resolve to a file")
        if current in seen:
            raise ApprovalRefused("installed manifest link cycle refused")
        seen.add(current)
        depth += 1
        if depth > _MAX_LINK_DEPTH:
            raise ApprovalRefused("installed manifest link depth exceeded")
        target = link_map[current]
        if target.startswith("/"):
            current = target[1:]
        elif version == 4:
            current = _normalize_relative(current, target)
        else:
            parent = current.rpartition("/")[0]
            current = f"{parent}/{target}" if parent else target


def _document(manifest):
    document = {
        "schema": {
            1: _SCHEMA_V1, 2: _SCHEMA_V2, 3: _SCHEMA_V3, 4: _SCHEMA_V4,
        }[manifest.version],
        "files": [
            {"path": entry.path, "mode": entry.mode, "size": entry.size,
             "sha256": entry.sha256}
            for entry in manifest.files
        ],
    }
    if manifest.version == 2:
        document["directories"] = [
            {"path": entry.path, "mode": entry.mode}
            for entry in manifest.directories
        ]
    elif manifest.version in {3, 4}:
        document["directories"] = [
            {"path": entry.path, "mode": entry.mode}
            for entry in manifest.directories
        ]
        document["links"] = [
            {"path": entry.path, "target": entry.target}
            for entry in manifest.links
        ]
    return document


def encode_installed_manifest(manifest: InstalledManifest) -> bytes:
    """Return canonical bytes for a nonempty, bounded selected-file manifest."""
    try:
        _validate_manifest(manifest)
        raw = json.dumps(_document(manifest), sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(raw) > _MAX_RAW_BYTES:
            raise ApprovalRefused("installed manifest encoding exceeds bound")
        return raw
    except Exception:
        raise ApprovalRefused("installed manifest encoding refused") from None


def decode_installed_manifest(raw: bytes, *, expected_digest: str) -> InstalledManifest:
    """Decode canonical bytes only when their independently pinned hash matches."""
    try:
        if (type(raw) is not bytes or not 0 < len(raw) <= _MAX_RAW_BYTES
                or type(expected_digest) is not str
                or _PINNED_HEX.fullmatch(expected_digest) is None
                or sha256(raw).hexdigest() != expected_digest[7:]):
            raise ApprovalRefused("installed manifest digest or size refused")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        if type(document) is not dict:
            raise ApprovalRefused("installed manifest fields refused")
        schema = document.get("schema")
        if schema == _SCHEMA_V1:
            if set(document) != {"schema", "files"}:
                raise ApprovalRefused("installed manifest fields refused")
            version = 1
        elif schema == _SCHEMA_V2:
            if set(document) != {"schema", "files", "directories"}:
                raise ApprovalRefused("installed manifest fields refused")
            version = 2
        elif schema == _SCHEMA_V3:
            if set(document) != {"schema", "files", "directories", "links"}:
                raise ApprovalRefused("installed manifest fields refused")
            version = 3
        elif schema == _SCHEMA_V4:
            if set(document) != {"schema", "files", "directories", "links"}:
                raise ApprovalRefused("installed manifest fields refused")
            version = 4
        else:
            raise ApprovalRefused("installed manifest schema refused")
        if type(document["files"]) is not list:
            raise ApprovalRefused("installed manifest schema refused")
        if not 0 < len(document["files"]) <= _MAX_FILES:
            raise ApprovalRefused("installed manifest file count refused")
        entries = []
        for item in document["files"]:
            if type(item) is not dict or set(item) != {"path", "mode", "size", "sha256"}:
                raise ApprovalRefused("installed manifest entry fields refused")
            entries.append(InstalledFile(**item, v4=version == 4))
        directories = []
        if version in {2, 3, 4}:
            if type(document["directories"]) is not list:
                raise ApprovalRefused("installed manifest directory list refused")
            if len(document["directories"]) > _MAX_DIRECTORIES:
                raise ApprovalRefused("installed manifest directory count refused")
            for item in document["directories"]:
                if type(item) is not dict or set(item) != {"path", "mode"}:
                    raise ApprovalRefused("installed manifest directory fields refused")
                directories.append(InstalledDirectory(**item, v4=version == 4))
        links = []
        if version in {3, 4}:
            if type(document["links"]) is not list:
                raise ApprovalRefused("installed manifest link list refused")
            if len(document["links"]) > _MAX_LINKS:
                raise ApprovalRefused("installed manifest link count refused")
            for item in document["links"]:
                if type(item) is not dict or set(item) != {"path", "target"}:
                    raise ApprovalRefused("installed manifest link fields refused")
                links.append(InstalledLink(**item, v4=version == 4))
        manifest = InstalledManifest(tuple(entries), tuple(directories), version,
                                     tuple(links))
        if encode_installed_manifest(manifest) != raw:
            raise ApprovalRefused("installed manifest is not canonical")
        return manifest
    except Exception:
        raise ApprovalRefused("installed manifest decoding refused") from None


def installed_link_resolver(manifest: InstalledManifest):
    """Validate the manifest once; return a path resolver over its data only.

    The returned function validates each path and resolves it exactly like
    resolve_installed_link, with the same refusals. It holds no state beyond
    maps derived from this one validation; callers must not keep it across
    observations.
    """
    try:
        _validate_manifest(manifest)
        version = manifest.version
        roots = _ROOTS_V4 if version == 4 else _ROOTS_V3
        file_paths = frozenset(entry.path for entry in manifest.files)
        directory_paths = frozenset(entry.path for entry in manifest.directories)
        link_map = {entry.path: entry.target for entry in manifest.links}
    except Exception:
        raise ApprovalRefused("installed manifest link resolution refused") from None

    def resolve(path: str) -> str:
        try:
            _validate_path(path, roots)
            if path in file_paths:
                return path
            if path not in link_map:
                raise ApprovalRefused("installed manifest path is not a file or link")
            return _resolve_link_path(path, file_paths, directory_paths, link_map,
                                      version)
        except Exception:
            raise ApprovalRefused("installed manifest link resolution refused") from None

    return resolve


def resolve_installed_link(manifest: InstalledManifest, path: str) -> str:
    """Resolve a selected regular file or declared link using manifest data only."""
    return installed_link_resolver(manifest)(path)
