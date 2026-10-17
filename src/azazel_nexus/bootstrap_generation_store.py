"""Read the pinned bootstrap variant from its separate protected namespace.

No generation publication, latest-number selection, semantic admission or
rollback authorization occurs here. The independently admitted context pins
the number, content and policy/closure measurements. Ordinary operational
generation readers continue to reject this variant.
"""

from contextlib import contextmanager
import os

from .activation_store import _private_directory, _read_file_at
from .bootstrap_approval import BootstrapContext
from .bootstrap_generation import VerifiedBootstrapGeneration, verify_bootstrap_generation
from .generation import GenerationRefused
from .operator_store import _protected

_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_LIMIT = 65536
_COMPONENTS = ("var", "lib", "azazel", "bootstrap-generations")


def _stamp(fd):
    info = os.fstat(fd)
    return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)


def _exact_entries(fd, names):
    # Enumerate only enough to reject an extra entry, not an unbounded list.
    found = set()
    with os.scandir(fd) as entries:
        for entry in entries:
            if entry.name not in names:
                raise GenerationRefused("bootstrap generation has extra content")
            found.add(entry.name)
    if found != names:
        raise GenerationRefused("bootstrap generation is incomplete")


def _snapshot(fd, *, owner):
    _private_directory(fd, owner=owner)
    generation_identity = _stamp(fd)
    _exact_entries(fd, {"generation.json", "tree"})
    metadata = _read_file_at(fd, "generation.json", owner=owner, limit=_LIMIT)
    metadata_info = os.stat("generation.json", dir_fd=fd, follow_symlinks=False)
    tree = os.open("tree", _FLAGS, dir_fd=fd)
    try:
        _private_directory(tree, owner=owner)
        tree_identity = _stamp(tree)
        _exact_entries(tree, {"bootstrap.json"})
        config = _read_file_at(tree, "bootstrap.json", owner=owner, limit=_LIMIT)
        config_info = os.stat("bootstrap.json", dir_fd=tree, follow_symlinks=False)
        _exact_entries(tree, {"bootstrap.json"})
        if _stamp(tree) != tree_identity:
            raise GenerationRefused("bootstrap tree changed")
        canonical_tree = os.open("tree", _FLAGS, dir_fd=fd)
        try:
            if _stamp(canonical_tree) != tree_identity:
                raise GenerationRefused("bootstrap tree path changed")
        finally:
            os.close(canonical_tree)
    finally:
        os.close(tree)
    _exact_entries(fd, {"generation.json", "tree"})
    if _stamp(fd) != generation_identity:
        raise GenerationRefused("bootstrap generation changed")
    identities = tuple((info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)
                       for info in (metadata_info, config_info))
    return metadata, config, generation_identity, tree_identity, identities


def _load_at(fd, *, owner, expected):
    """Private descriptor seam for ordinary-file tests, never a public path."""
    try:
        if type(expected) is not BootstrapContext:
            raise GenerationRefused("independent bootstrap context required")
        _private_directory(fd, owner=owner)
        name = str(expected.generation)
        _refuse_pending(fd, expected.generation)
        generation = os.open(name, _FLAGS, dir_fd=fd)
        try:
            first = _snapshot(generation, owner=owner)
            result = verify_bootstrap_generation(
                metadata=first[0], files={"bootstrap.json": first[1]}, expected=expected
            )
            if _snapshot(generation, owner=owner) != first:
                raise GenerationRefused("bootstrap generation changed during verification")
            current = os.open(name, _FLAGS, dir_fd=fd)
            try:
                if _stamp(current) != first[2]:
                    raise GenerationRefused("bootstrap generation path replaced")
            finally:
                os.close(current)
            _private_directory(fd, owner=owner)
            _refuse_pending(fd, expected.generation)
            return result
        finally:
            os.close(generation)
    except Exception:
        raise GenerationRefused("protected bootstrap generation refused") from None


def _refuse_pending(fd, number):
    try:
        os.stat(f".bootstrap-{number}.pending", dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise GenerationRefused("bootstrap generation publication is unfinished")


@contextmanager
def _generation_directory():
    fd = os.open("/", _FLAGS)
    try:
        for component in _COMPONENTS:
            _protected(fd, owner=0, directory=True)
            child = os.open(component, _FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        _private_directory(fd, owner=0)
        yield fd
    finally:
        os.close(fd)


def load_bootstrap_generation(*, expected: BootstrapContext) -> VerifiedBootstrapGeneration:
    """Fixed /var/lib/azazel/bootstrap-generations layout, pinned generation only.

    Reinspection detects observed replacement, not hostile-root modifications
    or changes after return. Controller transaction, current epoch and semantic
    admission are separate required dependencies; this reader grants nothing.
    """
    try:
        with _generation_directory() as fd:
            identity = _stamp(fd)[:2]
            result = _load_at(fd, owner=0, expected=expected)
            with _generation_directory() as current:
                if _stamp(current)[:2] != identity:
                    raise GenerationRefused("generation store path changed")
            return result
    except Exception:
        raise GenerationRefused("protected bootstrap generation refused") from None
