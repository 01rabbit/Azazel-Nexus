"""Read one protected, signed activation approval from its fixed location.

This module supplies a verified lease to a caller. It does not produce the
expected activation context, establish trusted time, or grant activation.
"""

from contextlib import contextmanager
import fcntl
import os
import stat

from .activation import ActivationLease
from .activation_approval import (
    ActivationContext,
    verify_activation_approval,
)
from .operator_store import _protected
from .operator_trust import MAX_APPROVAL_BYTES, ApprovalRefused

_COMPONENTS = ("etc", "azazel", "activation")
_MAX_SIGNATURE_BYTES = 64


def _private_directory(fd: int, *, owner: int) -> None:
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner
            or info.st_mode & 0o077):
        raise ApprovalRefused("activation approval directory is not private")


def _read_file_at(directory_fd: int, name: str, *, owner: int, limit: int) -> bytes:
    fd = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=directory_fd,
    )
    try:
        before = _protected(fd, owner=owner, directory=False)
        if before.st_mode & 0o077 or not 0 < before.st_size <= limit:
            raise ApprovalRefused("activation approval file permissions or size refused")
        chunks = bytearray()
        while len(chunks) <= limit:
            part = os.read(fd, min(8192, limit + 1 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
        after = _protected(fd, owner=owner, directory=False)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(chunks) != before.st_size:
            raise ApprovalRefused("activation approval file changed while reading")
        return bytes(chunks)
    finally:
        os.close(fd)


def _read_at(directory_fd: int, *, owner: int) -> tuple[bytes, bytes]:
    """Private descriptor seam for ordinary temporary-file tests."""
    _private_directory(directory_fd, owner=owner)
    payload = _read_file_at(
        directory_fd, "approval.json", owner=owner, limit=MAX_APPROVAL_BYTES
    )
    signature = _read_file_at(
        directory_fd, "approval.sig", owner=owner, limit=_MAX_SIGNATURE_BYTES
    )
    if len(signature) != _MAX_SIGNATURE_BYTES:
        raise ApprovalRefused("activation approval signature size refused")
    return payload, signature


@contextmanager
def _approval_directory():
    """Traverse only /etc/azazel/activation without following symlinks."""
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
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except (OSError, BlockingIOError):
            raise ApprovalRefused("activation approval store is busy") from None
        yield fd
    except ApprovalRefused:
        raise
    except (OSError, AttributeError) as exc:
        raise ApprovalRefused("protected activation approval unavailable") from exc
    finally:
        if fd is not None:
            os.close(fd)


def load_activation_approval(
    *, expected: ActivationContext, operator: str, now: str,
    max_lease_seconds: int,
) -> ActivationLease:
    """Load and verify the fixed approval against independently supplied inputs."""
    try:
        if type(expected) is not ActivationContext:
            raise ApprovalRefused("independent activation context required")
        with _approval_directory() as directory_fd:
            payload, signature = _read_at(directory_fd, owner=0)
            trust = _load_trust()
            lease = verify_activation_approval(
                trust=trust, expected=expected, operator=operator,
                payload=payload, signature=signature, now=now,
                max_lease_seconds=max_lease_seconds,
            )
            original = os.fstat(directory_fd)
            with _approval_directory() as current_fd:
                current = os.fstat(current_fd)
                if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
                    raise ApprovalRefused("activation approval directory changed")
                if _read_at(current_fd, owner=0) != (payload, signature):
                    raise ApprovalRefused("activation approval changed during verification")
            if _load_trust() != trust:
                raise ApprovalRefused("operator trust changed during verification")
            return lease
    except Exception:
        raise ApprovalRefused("protected activation approval refused") from None


def _load_trust():
    # Import at call time so tests can replace the fresh protected reader.
    from .operator_store import load_operator_trust

    return load_operator_trust()


def load_observe_baseline_approval(
    *, expected, policy, now: str, security_epoch_floor: int, approval_seq_floor: int,
):
    """Load and verify the fixed v2 (observe-baseline) approval (#206 §3.1).

    Same files and protections as the v1 reader above; only the verifier
    differs. `expected`, `policy`, `now` and both floors are supplied by the
    caller from independent local readers, never from the approval. The
    bytes and the operator trust are re-read after verification; any change
    refuses. Every failure is the same redacted refusal.
    """
    from .activation_approval_v2 import (
        ActivationApprovalPolicy,
        ObserveBaselineContext,
        verify_observe_baseline_approval,
    )

    try:
        if type(expected) is not ObserveBaselineContext:
            raise ApprovalRefused("independent observe-baseline context required")
        if type(policy) is not ActivationApprovalPolicy:
            raise ApprovalRefused("activation policy required")
        with _approval_directory() as directory_fd:
            payload, signature = _read_at(directory_fd, owner=0)
            trust = _load_trust()
            approved = verify_observe_baseline_approval(
                trust=trust, expected=expected, policy=policy, payload=payload,
                signature=signature, now=now,
                security_epoch_floor=security_epoch_floor,
                approval_seq_floor=approval_seq_floor,
            )
            original = os.fstat(directory_fd)
            with _approval_directory() as current_fd:
                current = os.fstat(current_fd)
                if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
                    raise ApprovalRefused("activation approval directory changed")
                if _read_at(current_fd, owner=0) != (payload, signature):
                    raise ApprovalRefused("activation approval changed during verification")
            if _load_trust() != trust:
                raise ApprovalRefused("operator trust changed during verification")
            return approved
    except Exception:
        raise ApprovalRefused("protected activation approval refused") from None


#: The two schemas the one approval pair may hold (wiring §5.1).
_SCHEMA_V2 = "azazel-nexus/activation-approval/v2"
_SCHEMA_V3 = "azazel-nexus/activation-approval/v3"


def approval_schema(payload: bytes) -> str:
    """Exactly one of the two schema names, read from `payload`, or refused.

    Decodes only enough to read `schema`: a JSON object with a string
    `schema` equal to v2's or v3's name. The bytes are then handed to that
    schema's own strict verifier, which parses everything again; this
    choice proves nothing about the document.
    """
    import json

    try:
        if type(payload) is not bytes or not 0 < len(payload) <= MAX_APPROVAL_BYTES:
            raise ValueError
        document = json.loads(payload.decode("utf-8"))
        schema = document["schema"] if type(document) is dict else None
    except Exception:  # noqa: BLE001 - every failure is the same refusal
        raise ApprovalRefused("activation approval schema refused") from None
    if type(schema) is not str or schema not in {_SCHEMA_V2, _SCHEMA_V3}:
        raise ApprovalRefused("activation approval schema refused")
    return schema


def verify_activation_approval_v2_or_v3(
    *, trust, expected, policy, exposure_policy, payload: bytes, signature: bytes,
    now: str, security_epoch_floor: int, approval_seq_floor: int,
):
    """One approval pair to its schema's verifier (#196 G6, wiring §5.1).

    v2 (`verify_observe_baseline_approval`) under `policy`, v3
    (`verify_activation_approval_v3`) under `exposure_policy`; a v3 payload
    with `exposure_policy` None (a policy that does not name the exposure
    tier) is refused. Neither schema is accepted as the other: `schema` is
    inside the signed bytes, and each verifier refuses the other's name,
    purpose and unit rule.
    """
    from .activation_approval_v2 import verify_observe_baseline_approval
    from .activation_approval_v3 import verify_activation_approval_v3

    schema = approval_schema(payload)
    common = dict(trust=trust, expected=expected, payload=payload, signature=signature,
                  now=now, security_epoch_floor=security_epoch_floor,
                  approval_seq_floor=approval_seq_floor)
    if schema == _SCHEMA_V2:
        return verify_observe_baseline_approval(policy=policy, **common)
    if exposure_policy is None:
        raise ApprovalRefused("activation approval v3 needs a policy naming the exposure tier")
    return verify_activation_approval_v3(policy=exposure_policy, **common)


def load_activation_approval_v2_or_v3(
    *, expected, policy, exposure_policy=None, now: str, security_epoch_floor: int,
    approval_seq_floor: int,
):
    """Load the fixed approval pair once and verify it under its own schema (#196 G6).

    The same files, protections and re-reads as `load_observe_baseline_approval`.
    `policy` is the v2 policy (the policy's units without the exposure tier),
    `exposure_policy` the v3 policy (all of them) or None when the policy
    does not name the tier, in which case a v3 approval is refused. Returns
    an `ObserveBaselineApproval` or an `ActivationApprovalV3`. Every failure
    is the same redacted refusal.
    """
    from .activation_approval_v2 import ActivationApprovalPolicy, ObserveBaselineContext
    from .activation_approval_v3 import ActivationApprovalPolicyV3

    try:
        if type(expected) is not ObserveBaselineContext:
            raise ApprovalRefused("independent observe-baseline context required")
        if type(policy) is not ActivationApprovalPolicy:
            raise ApprovalRefused("activation policy required")
        if exposure_policy is not None and type(exposure_policy) is not ActivationApprovalPolicyV3:
            raise ApprovalRefused("activation policy required")
        with _approval_directory() as directory_fd:
            payload, signature = _read_at(directory_fd, owner=0)
            trust = _load_trust()
            approved = verify_activation_approval_v2_or_v3(
                trust=trust, expected=expected, policy=policy,
                exposure_policy=exposure_policy, payload=payload, signature=signature,
                now=now, security_epoch_floor=security_epoch_floor,
                approval_seq_floor=approval_seq_floor,
            )
            original = os.fstat(directory_fd)
            with _approval_directory() as current_fd:
                current = os.fstat(current_fd)
                if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
                    raise ApprovalRefused("activation approval directory changed")
                if _read_at(current_fd, owner=0) != (payload, signature):
                    raise ApprovalRefused("activation approval changed during verification")
            if _load_trust() != trust:
                raise ApprovalRefused("operator trust changed during verification")
            return approved
    except Exception:
        raise ApprovalRefused("protected activation approval refused") from None
