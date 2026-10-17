"""Explicit new bootstrap generation publication, never operational admission.

No latest-number selection, overwrite, implicit recovery or service operation.
Incomplete publication leaves a marker which the bootstrap reader rejects.
"""

import fcntl
from hashlib import sha256
import json
import os

from .activation_store import _private_directory, _read_file_at
from .bootstrap_generation import verify_bootstrap_generation
from .bootstrap_generation_store import (
    _FLAGS, _generation_directory, _snapshot, _stamp,
)
from .generation import GenerationRefused

_PENDING = b"bootstrap generation publication pending\n"


class BootstrapGenerationDurabilityUncertain(GenerationRefused):
    """Generation may be visible but final directory fsync failed."""


def publication_digest(*, metadata: bytes, config: bytes) -> str:
    """Confirmation transcript binds both exact byte sequences, not admission."""
    if any(type(raw) is not bytes or not 0 < len(raw) <= 65536
           for raw in (metadata, config)):
        raise GenerationRefused("bounded bootstrap publication bytes required")
    raw = json.dumps({"schema": "azazel-nexus/bootstrap-publication/v1",
                      "metadata_sha256": sha256(metadata).hexdigest(),
                      "config_sha256": sha256(config).hexdigest()},
                     sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + sha256(raw).hexdigest()


def _exists(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _write(fd, name, raw):
    output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        remaining = memoryview(raw)
        while remaining:
            count = os.write(output, remaining)
            if count <= 0:
                raise OSError("short generation write")
            remaining = remaining[count:]
        os.fsync(output)
    finally:
        os.close(output)


def _publish_at(fd, *, metadata, config, expected, owner,
                confirmed_digest, confirmed_publish, recheck):
    result = verify_bootstrap_generation(metadata=metadata,
                                        files={"bootstrap.json": config}, expected=expected)
    if (confirmed_publish is not True or type(confirmed_digest) is not str
            or confirmed_digest != publication_digest(metadata=metadata, config=config)):
        raise GenerationRefused("separate digest and publication confirmation required")
    _private_directory(fd, owner=owner)
    name = str(expected.generation)
    pending = f".bootstrap-{name}.pending"
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        recheck()
        if any(_exists(fd, item) for item in (name, pending)):
            raise GenerationRefused("existing or interrupted generation cannot be replaced")
        _write(fd, pending, _PENDING)
        os.fsync(fd)
        os.mkdir(name, 0o700, dir_fd=fd)
        os.fsync(fd)
        generation = os.open(name, _FLAGS, dir_fd=fd)
        try:
            _private_directory(generation, owner=owner)
            os.mkdir("tree", 0o700, dir_fd=generation)
            tree = os.open("tree", _FLAGS, dir_fd=generation)
            try:
                _private_directory(tree, owner=owner)
                _write(tree, "bootstrap.json", config)
                os.fsync(tree)
            finally:
                os.close(tree)
            _write(generation, "generation.json", metadata)
            os.fsync(generation)
            snapshot = _snapshot(generation, owner=owner)
            if snapshot[:2] != (metadata, config):
                raise GenerationRefused("retained generation bytes differ")
            current = os.open(name, _FLAGS, dir_fd=fd)
            try:
                if _stamp(current) != snapshot[2]:
                    raise GenerationRefused("published generation path changed")
            finally:
                os.close(current)
        finally:
            os.close(generation)
        recheck()
        current = os.open(name, _FLAGS, dir_fd=fd)
        try:
            if _snapshot(current, owner=owner) != snapshot:
                raise GenerationRefused("generation changed before publication completion")
        finally:
            os.close(current)
        if _read_file_at(fd, pending, owner=owner, limit=128) != _PENDING:
            raise GenerationRefused("publication marker changed")
        os.unlink(pending, dir_fd=fd)
        try:
            os.fsync(fd)
        except OSError:
            raise BootstrapGenerationDurabilityUncertain("generation durability unconfirmed") from None
        return result
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)


def publish_bootstrap_generation(*, metadata: bytes, config: bytes, expected,
                                 confirmed_digest: str, confirmed_publish: bool,
                                 revalidate_selection=None):
    """Fixed protected layout, independently selected context, explicit consent.

    No creation of parent directories or selection of a generation number.
    Returned evidence proves shape/bytes only, not semantic admission. Failure
    may leave retained private files requiring explicit administrator review.
    revalidate_selection is a trusted composition callback, never candidate data;
    when supplied it must raise on stale inputs and return exactly None otherwise.
    """
    try:
        if revalidate_selection is not None and not callable(revalidate_selection):
            raise GenerationRefused("selection revalidation callback required")
        with _generation_directory() as fd:
            identity = _stamp(fd)[:2]

            def recheck():
                if revalidate_selection is not None and revalidate_selection() is not None:
                    raise GenerationRefused("selection revalidation did not complete")
                with _generation_directory() as current:
                    if _stamp(current)[:2] != identity:
                        raise GenerationRefused("generation root changed")

            return _publish_at(fd, metadata=metadata, config=config, expected=expected,
                               owner=0, confirmed_digest=confirmed_digest,
                               confirmed_publish=confirmed_publish, recheck=recheck)
    except BootstrapGenerationDurabilityUncertain:
        raise
    except Exception:
        raise GenerationRefused("bootstrap publication refused; inspect retained state") from None
