"""Read the fixed administrator-owned operator trust store; never enroll.

Production traverses from / with directory descriptors and refuses symlinks
at every component. No caller-supplied path or owner override is public.
The private descriptor seam permits ordinary-file tests without root access.
"""

import json
import os
import stat
from contextlib import contextmanager

from .operator_trust import ApprovalRefused, OperatorTrust
from .signature import SignatureRefused, parse_public_key

_COMPONENTS = ("etc", "azazel", "operator-trust")
_MAX_STORE_BYTES = 65536


def _protected(fd: int, *, owner: int, directory: bool) -> os.stat_result:
    info = os.fstat(fd)
    correct_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not correct_type or info.st_uid != owner or info.st_mode & 0o022:
        raise ApprovalRefused("operator trust storage is not protected")
    if not directory and info.st_nlink != 1:
        raise ApprovalRefused("operator trust file must have one link")
    return info


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ApprovalRefused("duplicate operator trust field")
        result[key] = value
    return result


def _decode(raw: bytes) -> OperatorTrust:
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        if type(document) is not dict or set(document) != {"schema", "keys", "revoked"}:
            raise ApprovalRefused("invalid operator trust fields")
        if document["schema"] != "azazel-nexus/operator-trust/v1":
            raise ApprovalRefused("unsupported operator trust schema")
        keys, revoked = document["keys"], document["revoked"]
        if type(keys) is not dict or type(revoked) is not list:
            raise ApprovalRefused("invalid operator trust key set")
        if any(type(name) is not str for name in revoked) or len(set(revoked)) != len(revoked):
            raise ApprovalRefused("invalid operator revocations")
        return OperatorTrust(
            {name: parse_public_key(key) for name, key in keys.items()}, frozenset(revoked)
        )
    except (ValueError, UnicodeError, SignatureRefused, RecursionError) as exc:
        raise ApprovalRefused("operator trust document refused") from exc


def _read_at(directory_fd: int, *, owner: int) -> OperatorTrust:
    _protected(directory_fd, owner=owner, directory=True)
    fd = os.open(
        "operators.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=directory_fd,
    )
    try:
        before = _protected(fd, owner=owner, directory=False)
        if not 0 < before.st_size <= _MAX_STORE_BYTES:
            raise ApprovalRefused("operator trust file size refused")
        chunks = bytearray()
        while len(chunks) <= _MAX_STORE_BYTES:
            data = os.read(fd, min(8192, _MAX_STORE_BYTES + 1 - len(chunks)))
            if not data:
                break
            chunks.extend(data)
        after = _protected(fd, owner=owner, directory=False)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or len(chunks) != before.st_size:
            raise ApprovalRefused("operator trust file changed while reading")
        return _decode(bytes(chunks))
    finally:
        os.close(fd)


@contextmanager
def _trust_directory():
    """Open only the fixed protected directory; never create it implicitly."""
    fd = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open("/", flags)
        for component in _COMPONENTS:
            _protected(fd, owner=0, directory=True)
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        _protected(fd, owner=0, directory=True)
        yield fd
    except (OSError, AttributeError) as exc:
        raise ApprovalRefused("protected operator trust store unavailable") from exc
    finally:
        if fd is not None:
            os.close(fd)


def load_operator_trust() -> OperatorTrust:
    """Fresh protected snapshot; a missing/malformed store is never permissive."""
    with _trust_directory() as fd:
        return _read_at(fd, owner=0)


def operator_trust_bytes(raw: bytes) -> OperatorTrust:
    """Decode a bounded snapshot already read through protected descriptors."""
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_STORE_BYTES:
        raise ApprovalRefused("operator trust file size refused")
    return _decode(raw)
