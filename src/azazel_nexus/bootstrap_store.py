"""Read protected bootstrap approval evidence; never create a grant or key.

Fixed root-owned input directory, no public path/owner overrides. This reader
is not wired into production activation. Its result still needs semantic
admission, trusted time, retained deadlines and reviewed lifetime enforcement.
"""

from contextlib import contextmanager
import fcntl
import json
import os

from .activation_store import _private_directory, _read_file_at
from .bootstrap_approval import (
    BOOTSTRAP_UNITS,
    BootstrapApprovalPolicy,
    BootstrapContext,
    VerifiedBootstrapApproval,
    verify_bootstrap_approval,
)
from .operator_store import _protected, _unique_object
from .operator_trust import MAX_APPROVAL_BYTES, ApprovalRefused

_COMPONENTS = ("etc", "azazel", "bootstrap")
_INSTALLED_MANIFEST = "installed-files.json"


def _decode_policy(raw: bytes) -> BootstrapApprovalPolicy:
    document = json.loads(raw, object_pairs_hook=_unique_object)
    if type(document) is not dict or set(document) != {
        "schema", "operators", "max_seconds", "units"
    } or document["schema"] != "azazel-nexus/bootstrap-approval-policy/v1":
        raise ApprovalRefused("invalid bootstrap approval policy")
    operators = document["operators"]
    if type(operators) is not list or any(type(item) is not str for item in operators):
        raise ApprovalRefused("invalid bootstrap operator set")
    policy = BootstrapApprovalPolicy(frozenset(operators), document["max_seconds"])
    canonical = json.dumps({
        "schema": "azazel-nexus/bootstrap-approval-policy/v1",
        "operators": sorted(policy.operators), "max_seconds": policy.max_seconds,
        "units": BOOTSTRAP_UNITS,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if raw != canonical:
        raise ApprovalRefused("bootstrap policy is not canonical or has another scope")
    return policy


def _read_at(directory_fd: int, *, owner: int) -> tuple[bytes, bytes, bytes]:
    _private_directory(directory_fd, owner=owner)
    policy = _read_file_at(directory_fd, "policy.json", owner=owner, limit=MAX_APPROVAL_BYTES)
    payload = _read_file_at(directory_fd, "approval.json", owner=owner, limit=MAX_APPROVAL_BYTES)
    signature = _read_file_at(directory_fd, "approval.sig", owner=owner, limit=64)
    if len(signature) != 64:
        raise ApprovalRefused("invalid bootstrap signature size")
    return policy, payload, signature


@contextmanager
def _bootstrap_directory():
    fd = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open("/", flags)
        for component in _COMPONENTS:
            _protected(fd, owner=0, directory=True)
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        _private_directory(fd, owner=0)
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        yield fd
    finally:
        if fd is not None:
            os.close(fd)


@contextmanager
def _optional_bootstrap_directory(*, root_fd=None, owner=0):
    """Inspect only whether the final fixed directory is absent.

    The protected parent walk is identical in spirit to ``_bootstrap_directory``.
    Only ENOENT while opening the final ``bootstrap`` component means absence;
    missing parents, permission errors, symlinks and protection failures refuse.
    Yields (directory fd or None, parent identity, directory identity or None).
    """
    fd = None
    child_fd = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open("/", flags) if root_fd is None else os.dup(root_fd)
        for component in _COMPONENTS[:-1]:
            _protected(fd, owner=owner, directory=True)
            child_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd, child_fd = child_fd, None
        _protected(fd, owner=owner, directory=True)
        parent_info = os.fstat(fd)
        parent_identity = (parent_info.st_dev, parent_info.st_ino)
        try:
            child_fd = os.open(_COMPONENTS[-1], flags, dir_fd=fd)
        except FileNotFoundError:
            yield None, parent_identity, None
            return
        _private_directory(child_fd, owner=owner)
        fcntl.flock(child_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        info = os.fstat(child_fd)
        yield child_fd, parent_identity, (info.st_dev, info.st_ino)
    finally:
        if child_fd is not None:
            os.close(child_fd)
        if fd is not None:
            os.close(fd)


def _load_trust():
    from .operator_store import load_operator_trust

    return load_operator_trust()


def read_bootstrap_installed_manifest() -> bytes:
    """Read the fixed installed-file manifest from its protected directory.

    The runtime may measure these selected files, but it must not reach into
    this library's private directory/file primitives. Re-open and compare the
    protected directory and exact bytes around the read so a replacement
    during observation fails closed. No path or owner override is exposed.
    """
    try:
        with _bootstrap_directory() as directory_fd:
            original = os.fstat(directory_fd)
            raw = _read_file_at(
                directory_fd, _INSTALLED_MANIFEST, owner=0, limit=1 << 20
            )
            with _bootstrap_directory() as current_fd:
                current = os.fstat(current_fd)
                if (
                    (original.st_dev, original.st_ino)
                    != (current.st_dev, current.st_ino)
                    or _read_file_at(
                        current_fd, _INSTALLED_MANIFEST, owner=0, limit=1 << 20
                    )
                    != raw
                ):
                    raise ApprovalRefused("bootstrap installed manifest changed")
            return raw
    except Exception:
        raise ApprovalRefused("protected bootstrap installed manifest refused") from None


def read_bootstrap_loaded_policy() -> bytes:
    """Read fixed protected loaded-unit policy bytes, never manager observations."""
    try:
        with _bootstrap_directory() as directory_fd:
            original = os.fstat(directory_fd)
            raw = _read_file_at(directory_fd, "loaded-units.json", owner=0, limit=65_536)
            with _bootstrap_directory() as current_fd:
                current = os.fstat(current_fd)
                if ((original.st_dev, original.st_ino) != (current.st_dev, current.st_ino)
                        or _read_file_at(current_fd, "loaded-units.json", owner=0,
                                         limit=65_536) != raw):
                    raise ApprovalRefused("loaded bootstrap policy changed")
            return raw
    except Exception:
        raise ApprovalRefused("protected loaded bootstrap policy refused") from None


def read_bootstrap_approval_policy() -> BootstrapApprovalPolicy:
    """Read and decode the fixed protected purpose policy for request previews.

    This is the same stable protected read and canonical decoder the approval
    verifier uses for `policy.json`; it confers no approval or enrollment.
    """
    try:
        with _bootstrap_directory() as directory_fd:
            original = os.fstat(directory_fd)
            raw = _read_file_at(directory_fd, "policy.json", owner=0,
                                limit=MAX_APPROVAL_BYTES)
            with _bootstrap_directory() as current_fd:
                current = os.fstat(current_fd)
                if ((original.st_dev, original.st_ino) != (current.st_dev, current.st_ino)
                        or _read_file_at(current_fd, "policy.json", owner=0,
                                         limit=MAX_APPROVAL_BYTES) != raw):
                    raise ApprovalRefused("bootstrap approval policy changed")
            return _decode_policy(raw)
    except Exception:
        raise ApprovalRefused("protected bootstrap approval policy refused") from None


def load_bootstrap_approval(*, expected: BootstrapContext, operator: str,
                            now: str) -> VerifiedBootstrapApproval:
    """Read one stable protected snapshot; all public refusals are redacted.

    The expected context and trusted time cannot come from the candidate.
    Cooperative locking and reinspection do not defend against a hostile root
    or provide freshness beyond this observation. The controller must recheck
    all independent inputs under its own admission transaction before use.
    """
    try:
        if type(expected) is not BootstrapContext:
            raise ApprovalRefused("independent bootstrap context required")
        with _bootstrap_directory() as directory_fd:
            original = os.fstat(directory_fd)
            raw_policy, payload, signature = _read_at(directory_fd, owner=0)
            policy = _decode_policy(raw_policy)
            trust = _load_trust()
            evidence = verify_bootstrap_approval(
                trust=trust, expected=expected, policy=policy, operator=operator,
                payload=payload, signature=signature, now=now,
            )
            with _bootstrap_directory() as current_fd:
                current = os.fstat(current_fd)
                if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
                    raise ApprovalRefused("bootstrap directory replaced")
                if _read_at(current_fd, owner=0) != (raw_policy, payload, signature):
                    raise ApprovalRefused("bootstrap inputs changed during verification")
            if _load_trust() != trust:
                raise ApprovalRefused("bootstrap operator trust changed")
            return evidence
    except Exception:
        raise ApprovalRefused("protected bootstrap approval refused") from None
