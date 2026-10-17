"""Read-only candidates for explicit regular files, directories and leaf links.

Observed bytes are not independent approval, package provenance or transitive
execution closure. No manifests, pins, policies or files are installed here.
"""

from hashlib import sha256
import os
import stat

from .installed_files import _DIR, _directory, _identity, _snapshot_at
from .installed_manifest import (
    InstalledDirectory, InstalledFile, InstalledLink, InstalledManifest,
    encode_installed_manifest, _validate_link, _validate_path, _ROOTS_V3, _ROOTS_V4,
    _MAX_DIRECTORIES, _MAX_FILES,
    _MAX_LINKS, _MAX_FILE_SIZE, _MAX_TOTAL_SIZE,
)
from .operator_trust import ApprovalRefused


def _selection(paths, roots=_ROOTS_V3):
    if type(paths) is not tuple or not 0 < len(paths) <= _MAX_FILES:
        raise ApprovalRefused("bounded explicit file selection required")
    for path in paths:
        _validate_path(path, roots)
    if paths != tuple(sorted(set(paths))):
        raise ApprovalRefused("sorted unique file selection required")


def _directory_selection(directories, roots=_ROOTS_V3):
    if type(directories) is not tuple or len(directories) > _MAX_DIRECTORIES:
        raise ApprovalRefused("bounded explicit directory selection required")
    for path in directories:
        _validate_path(path, roots)
    if directories != tuple(sorted(set(directories))):
        raise ApprovalRefused("sorted unique directory selection required")


def _link_selection(links, roots=_ROOTS_V3):
    if type(links) is not tuple or len(links) > _MAX_LINKS:
        raise ApprovalRefused("bounded explicit link selection required")
    for path in links:
        _validate_path(path, roots)
    if links != tuple(sorted(set(links))):
        raise ApprovalRefused("sorted unique link selection required")


def _candidate_at(root_fd, paths, *, owner, directories=(), links=(), allow_etc=False):
    """Private ordinary-tree test seam; production root is fixed.

    ``allow_etc`` admits the schema 4 etc/ root; the public generator sets it.
    """
    roots = _ROOTS_V4 if allow_etc else _ROOTS_V3
    _selection(paths, roots)
    _directory_selection(directories, roots)
    _link_selection(links, roots)
    identities = {"": _directory(root_fd, owner)}
    entries = []
    link_entries = []
    total = 0
    for path in paths:
        parent = os.dup(root_fd)
        try:
            components = path.split("/")
            prefix = []
            for component in components[:-1]:
                child = os.open(component, _DIR, dir_fd=parent)
                os.close(parent)
                parent = child
                prefix.append(component)
                name = "/".join(prefix)
                identity = _directory(parent, owner)
                if name in identities and identities[name] != identity:
                    raise ApprovalRefused("candidate ancestor changed")
                identities[name] = identity
            before = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
            mode = stat.S_IMODE(before.st_mode)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner
                    or before.st_nlink != 1 or mode not in {0o644, 0o755}
                    or not 0 <= before.st_size <= _MAX_FILE_SIZE):
                raise ApprovalRefused("candidate file metadata refused")
            total += before.st_size
            if total > _MAX_TOTAL_SIZE:
                raise ApprovalRefused("candidate total size refused")
            fd = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                         | os.O_CLOEXEC, dir_fd=parent)
            try:
                if _identity(os.fstat(fd)) != _identity(before):
                    raise ApprovalRefused("candidate file replaced")
                digest, count = sha256(), 0
                while count <= before.st_size:
                    chunk = os.read(fd, min(65536, before.st_size + 1 - count))
                    if not chunk:
                        break
                    digest.update(chunk)
                    count += len(chunk)
                if (count != before.st_size or _identity(os.fstat(fd)) != _identity(before)
                        or _identity(os.stat(components[-1], dir_fd=parent,
                                             follow_symlinks=False)) != _identity(before)):
                    raise ApprovalRefused("candidate file changed")
                entries.append(InstalledFile(path, mode, count, digest.hexdigest(), True))
                identities[path] = _identity(before)
            finally:
                os.close(fd)
        finally:
            os.close(parent)
    for path in links:
        parent = os.dup(root_fd)
        try:
            components = path.split("/")
            prefix = []
            for component in components[:-1]:
                child = os.open(component, _DIR, dir_fd=parent)
                os.close(parent)
                parent = child
                prefix.append(component)
                name = "/".join(prefix)
                identity = _directory(parent, owner)
                if name in identities and identities[name] != identity:
                    raise ApprovalRefused("candidate link ancestor changed")
                identities[name] = identity
            before = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISLNK(before.st_mode) or before.st_uid != owner
                    or before.st_nlink != 1 or not 0 < before.st_size <= 512):
                raise ApprovalRefused("candidate link metadata refused")
            target = os.readlink(components[-1], dir_fd=parent)
            link_entry = InstalledLink(path, target, True)
            after = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
            if _identity(after) != _identity(before):
                raise ApprovalRefused("candidate link changed during observation")
            link_entries.append(link_entry)
            identities[path] = _identity(before)
        finally:
            os.close(parent)
    # Schema 4 only when some selected entry cannot be expressed in schema 3
    # (an etc/ path or a link target outside the v3 rules); otherwise the
    # schema 1/2/3 bytes are unchanged.
    needs_v4 = any(entry.path.startswith("etc/") for entry in entries)
    needs_v4 = needs_v4 or any(path.startswith("etc/") for path in (*directories, *links))
    for link_entry in link_entries:
        try:
            _validate_link(link_entry, 3)
        except ApprovalRefused:
            needs_v4 = True
    manifest = InstalledManifest(
        tuple(entries),
        tuple(InstalledDirectory(path, 0o755, True) for path in directories),
        4 if needs_v4 else (3 if links else (2 if directories else 1)),
        tuple(link_entries),
    )
    first = _snapshot_at(root_fd, manifest, owner=owner)
    if (not set(identities) <= set(first)
            or any(first[path] != identity for path, identity in identities.items())
            or (not directories and first != identities)):
        raise ApprovalRefused("candidate selection changed between observations")
    if (directories or links) and _snapshot_at(root_fd, manifest, owner=owner) != first:
        raise ApprovalRefused("candidate selection changed between observations")
    return encode_installed_manifest(manifest)


def generate_installed_candidate(
    paths: tuple[str, ...], *, directories: tuple[str, ...] = (),
    links: tuple[str, ...] = (),
) -> bytes:
    """Observe explicit /usr, /opt or (schema 4) /etc regular files under protected root only.

    Unlisted links, directory aliases, implicit discovery and device paths refuse.
    An operator must review selection completeness and independently admit pins.
    """
    try:
        _selection(paths, _ROOTS_V4)
        _directory_selection(directories, _ROOTS_V4)
        _link_selection(links, _ROOTS_V4)
        fd = os.open("/", _DIR)
        try:
            return _candidate_at(
                fd, paths, owner=0, directories=directories, links=links,
                allow_etc=True,
            )
        finally:
            os.close(fd)
    except Exception:
        raise ApprovalRefused("installed candidate generation refused") from None
