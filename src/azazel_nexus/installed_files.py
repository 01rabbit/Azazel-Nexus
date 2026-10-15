"""Read-only selected installed bytes; NOT transitive closure or admission.

The manifest pin must come from independently reviewed deployment inputs, not
the installation being measured. Version 2 also measures exact membership for
explicit declared directories. Unlisted roots, Python resolution, interpreter
dependencies and loaded systemd configuration remain outside this measurement.
"""

from dataclasses import dataclass
from hashlib import sha256
import os
import stat

from .installed_manifest import InstalledManifest, decode_installed_manifest
from .operator_trust import ApprovalRefused

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


@dataclass(frozen=True)
class SelectedInstalledFiles:
    manifest_digest: str
    file_count: int
    total_bytes: int
    directory_count: int = 0
    link_count: int = 0


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory(fd, owner):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
        raise ApprovalRefused("installed ancestor is not protected")
    return _identity(info)


def _membership_at(root_fd, manifest, *, owner):
    """Bounded immediate membership and named identity for declared directories.

    Schema validation requires explicit intermediate directories below each
    declared root. No implicit recursive discovery or symlink following occurs.
    Repeated observations are not a filesystem freeze or hostile-root defense.
    """
    identities = {"": _directory(root_fd, owner)}
    children = {entry.path: set() for entry in manifest.directories}
    for entry in (*manifest.files, *manifest.directories, *manifest.links):
        parent, _, name = entry.path.rpartition("/")
        if parent in children:
            children[parent].add(name)
    for entry in manifest.directories:
        parent_fd = os.dup(root_fd)
        try:
            components = entry.path.split("/")
            prefix = []
            for component in components[:-1]:
                child = os.open(component, _DIR, dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = child
                prefix.append(component)
                path = "/".join(prefix)
                identity = _directory(parent_fd, owner)
                if path in identities and identities[path] != identity:
                    raise ApprovalRefused("installed directory ancestor changed")
                identities[path] = identity
            before = os.stat(components[-1], dir_fd=parent_fd, follow_symlinks=False)
            fd = os.open(components[-1], _DIR, dir_fd=parent_fd)
            try:
                identity = _directory(fd, owner)
                if (_identity(before) != identity
                        or stat.S_IMODE(before.st_mode) != entry.mode
                        or (entry.path in identities and identities[entry.path] != identity)):
                    raise ApprovalRefused("installed directory identity or mode differs")
                identities[entry.path] = identity
                expected = children[entry.path]
                seen = set()
                # Unlike listdir, stop enumeration at the first unknown entry.
                # Accepted names are bounded by the validated manifest itself.
                with os.scandir(fd) as entries:
                    for observed in entries:
                        if observed.name not in expected or observed.name in seen:
                            raise ApprovalRefused("installed directory membership differs")
                        seen.add(observed.name)
                if (seen != expected or _directory(fd, owner) != identity
                        or _identity(os.stat(components[-1], dir_fd=parent_fd,
                                             follow_symlinks=False)) != identity):
                    raise ApprovalRefused("installed directory changed or differs")
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)
    return identities


def _links_at(root_fd, manifest, *, owner):
    """Inspect pinned leaf link text without opening or following the link."""
    identities = {"": _directory(root_fd, owner)}
    for entry in manifest.links:
        fd = os.dup(root_fd)
        try:
            components = entry.path.split("/")
            prefix = []
            for component in components[:-1]:
                child = os.open(component, _DIR, dir_fd=fd)
                os.close(fd)
                fd = child
                prefix.append(component)
                name = "/".join(prefix)
                identity = _directory(fd, owner)
                if name in identities and identities[name] != identity:
                    raise ApprovalRefused("installed link ancestor changed")
                identities[name] = identity
            before = os.stat(components[-1], dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISLNK(before.st_mode) or before.st_uid != owner
                    or before.st_nlink != 1 or not 0 < before.st_size <= 512):
                raise ApprovalRefused("installed leaf link metadata refused")
            if (os.readlink(components[-1], dir_fd=fd) != entry.target
                    or _identity(os.stat(components[-1], dir_fd=fd,
                                         follow_symlinks=False)) != _identity(before)):
                raise ApprovalRefused("installed leaf link changed or differs")
            identities[entry.path] = _identity(before)
        finally:
            os.close(fd)
    return identities


def _snapshot_at(root_fd, manifest, *, owner, contents=None):
    identities = {"": _directory(root_fd, owner)}
    if manifest.directories:
        identities = _membership_at(root_fd, manifest, owner=owner)
    if manifest.links:
        for path, identity in _links_at(root_fd, manifest, owner=owner).items():
            if path in identities and identities[path] != identity:
                raise ApprovalRefused("installed link ancestry differs")
            identities[path] = identity
    for entry in manifest.files:
        fd = os.dup(root_fd)
        try:
            components = entry.path.split("/")
            prefix = []
            for component in components[:-1]:
                child = os.open(component, _DIR, dir_fd=fd)
                os.close(fd)
                fd = child
                prefix.append(component)
                name = "/".join(prefix)
                identity = _directory(fd, owner)
                if name in identities and identities[name] != identity:
                    raise ApprovalRefused("installed ancestor changed")
                identities[name] = identity
            # Refuse nonregular entries before opening. Protected ancestors and
            # the second fstat are also required; hostile root is not defended.
            before = os.stat(components[-1], dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner
                    or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != entry.mode
                    or before.st_size != entry.size):
                raise ApprovalRefused("installed file metadata differs")
            file_fd = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW
                              | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
            try:
                if _identity(os.fstat(file_fd)) != _identity(before):
                    raise ApprovalRefused("installed file replaced")
                digest = sha256()
                count = 0
                chunks = [] if contents is not None and entry.path in contents else None
                while count <= entry.size:
                    chunk = os.read(file_fd, min(65536, entry.size + 1 - count))
                    if not chunk:
                        break
                    count += len(chunk)
                    digest.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
                if (count != entry.size or digest.hexdigest() != entry.sha256
                        or _identity(os.fstat(file_fd)) != _identity(before)
                        or _identity(os.stat(components[-1], dir_fd=fd,
                                             follow_symlinks=False)) != _identity(before)):
                    raise ApprovalRefused("installed file contents changed or differ")
                identities[entry.path] = _identity(before)
                if chunks is not None:
                    contents[entry.path] = b"".join(chunks)
            finally:
                os.close(file_fd)
        finally:
            os.close(fd)
    if manifest.links:
        after = _links_at(root_fd, manifest, owner=owner)
        if any(identities.get(path) != identity for path, identity in after.items()):
            raise ApprovalRefused("installed leaf link changed during file measurement")
    if manifest.directories:
        after = _membership_at(root_fd, manifest, owner=owner)
        if any(identities.get(path) != identity for path, identity in after.items()):
            raise ApprovalRefused("installed directory changed during file measurement")
    return identities


def _measure_at(root_fd, raw, *, expected_digest, owner):
    """Ordinary-file test seam; no arbitrary root exposed to production runtime."""
    manifest = decode_installed_manifest(raw, expected_digest=expected_digest)
    first = _snapshot_at(root_fd, manifest, owner=owner)
    if _snapshot_at(root_fd, manifest, owner=owner) != first:
        raise ApprovalRefused("installed selection changed between observations")
    return SelectedInstalledFiles(expected_digest, len(manifest.files),
                                  sum(entry.size for entry in manifest.files),
                                  len(manifest.directories), len(manifest.links))


def _read_pinned_at(root_fd, raw, *, expected_digest, paths, owner):
    """Private regular-tree seam for bounded, pinned content inspection.

    This reads only the explicitly requested manifest entries, not directory
    membership or the full installation. No bytes are returned on any failure.
    """
    manifest = decode_installed_manifest(raw, expected_digest=expected_digest)
    if (type(paths) is not tuple or not 0 < len(paths) <= 3
            or any(type(path) is not str for path in paths)
            or paths != tuple(sorted(set(paths)))):
        raise ApprovalRefused("bounded sorted pinned file selection required")
    entries = {entry.path: entry for entry in manifest.files}
    if any(path not in entries or entries[path].size > 65536 for path in paths):
        raise ApprovalRefused("pinned content selection missing or exceeds bound")
    selected = InstalledManifest(tuple(entries[path] for path in paths))
    first_content = dict.fromkeys(paths, b"")
    first = _snapshot_at(root_fd, selected, owner=owner, contents=first_content)
    second_content = dict.fromkeys(paths, b"")
    if (_snapshot_at(root_fd, selected, owner=owner, contents=second_content) != first
            or second_content != first_content):
        raise ApprovalRefused("pinned content changed between observations")
    return tuple(first_content[path] for path in paths)


def read_pinned_installed_files(
    raw: bytes, *, expected_digest: str, paths: tuple[str, ...],
) -> tuple[bytes, ...]:
    """Read at most three listed 64-KiB regular files under the fixed root.

    The complete canonical manifest must match its independent pin. Content
    passes the existing protected no-follow metadata/hash and repeated identity
    checks. This is not full manifest measurement, approval or code execution.
    """
    try:
        decode_installed_manifest(raw, expected_digest=expected_digest)
        fd = os.open("/", _DIR)
        try:
            return _read_pinned_at(
                fd, raw, expected_digest=expected_digest, paths=paths, owner=0,
            )
        finally:
            os.close(fd)
    except Exception:
        raise ApprovalRefused("pinned installed content refused") from None


def measure_installed_files(raw: bytes, *, expected_digest: str) -> SelectedInstalledFiles:
    """Compare pinned files and v2 directory membership under /usr or /opt.

    All ancestors/files must be root-owned and protected. V3 explicitly pins
    leaf symlink text and its complete declared chain to a selected regular
    file. Links are never opened or followed by this reader; directory aliases
    (including merged-/usr aliases) and unlisted links remain refused.
    Declared directories bracket file hashing with exact immediate membership checks for
    each explicitly declared directory; descendants require explicit records.
    This does not establish completeness of the chosen import roots or freeze
    them against later changes. No generation, execution, policy update or start.
    """
    try:
        decode_installed_manifest(raw, expected_digest=expected_digest)
        fd = os.open("/", _DIR)
        try:
            return _measure_at(fd, raw, expected_digest=expected_digest, owner=0)
        finally:
            os.close(fd)
    except Exception:
        raise ApprovalRefused("selected installed files refused") from None
