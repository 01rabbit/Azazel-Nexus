"""Explicit private export of a Nexus-local wizard draft, never approval.

Reuses the existing local record representation, not a replacement Fabric
contract. No generation number is invented and no measured profile is claimed.
"""

import fcntl
import json
import os
from pathlib import Path
import stat

from .commissioning import (
    CommissioningRecord, CommissioningRefused, ConfirmedRole, Proposal,
    REQUIRED_PROFILES, confirm_roles,
)
from .activation import ActivationRefused, _utc_lease_time
from .hil_preflight import (
    COMMISSIONING_DIR, PROTECTION_KEY, luks_backed, read_protection_key, record_as_document,
)
from .operator_trust import MAX_APPROVAL_BYTES, ApprovalPurpose, ApprovalRefused, OperatorTrust


class DraftRefused(Exception):
    """Draft export failed; no signature or activation was attempted."""


def draft_bytes(record: CommissioningRecord) -> bytes:
    document = dict(record_as_document(record))
    # record_as_document is also used by an unrelated HIL workflow whose
    # default generation must not become this unsigned draft's generation.
    document.pop("generation")
    payload = json.dumps({
        "schema": "azazel-nexus/commissioning-draft/v1",
        "status": "unsigned-draft",
        "profiles_are": "operator-assertions-not-measurements",
        "record": document,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > MAX_APPROVAL_BYTES:
        raise DraftRefused("commissioning draft exceeds the bounded export size")
    return payload


def _decode_draft(payload: bytes) -> CommissioningRecord:
    """Strict local draft parsing; never a measured or authenticated record."""
    try:
        if type(payload) is not bytes or not 0 < len(payload) <= MAX_APPROVAL_BYTES:
            raise ValueError
        document = json.loads(payload)
        body = document["record"]
        _utc_lease_time(body["created_at"])
        profiles = body["profiles_present"]
        if (type(profiles) is not list or any(type(p) is not str for p in profiles)
                or len(set(profiles)) != len(profiles)
                or not set(profiles).issubset(REQUIRED_PROFILES)):
            raise ValueError
        entries = body["roles"]
        if type(entries) is not list or len(entries) > 255:
            raise ValueError
        roles = []
        for entry in entries:
            pairs = entry["composite"]
            if type(pairs) is not list or any(
                type(pair) is not list or len(pair) != 2 or
                type(pair[0]) is not str or
                (pair[1] is not None and type(pair[1]) is not str) for pair in pairs
            ):
                raise ValueError
            if len({pair[0] for pair in pairs}) != len(pairs):
                raise ValueError
            for field in ("role", "confirmed_by", "confirmed_at"):
                if type(entry[field]) is not str:
                    raise ValueError
            _utc_lease_time(entry["confirmed_at"])
            roles.append(ConfirmedRole(
                composite=tuple(tuple(pair) for pair in pairs), role=entry["role"],
                confirmed_by=entry["confirmed_by"], confirmed_at=entry["confirmed_at"],
            ))
        record = CommissioningRecord(tuple(roles), tuple(profiles), body["created_at"])
        # Also rejects duplicate JSON fields, extra fields, altered digest,
        # wrong schema/status, and alternate serialization.
        if draft_bytes(record) != payload:
            raise ValueError
        return record
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError,
            CommissioningRefused, ActivationRefused):
        raise DraftRefused("invalid commissioning draft") from None


def verify_draft_review(*, payload: bytes, signature: bytes, operator: str,
                        trust: OperatorTrust, current: Proposal) -> None:
    """Verify operator review against a fresh local proposal, not admission.

    Success returns no record or authorization token. Profile names remain
    assertions. Boot/node/policy binding, measured profiles and activation
    approval must be established separately before operational use.
    """
    try:
        trust.verify(operator=operator, purpose=ApprovalPurpose.COMMISSIONING,
                     payload=payload, signature=signature)
        record = _decode_draft(payload)
        if current.commissioning_required:
            raise DraftRefused("current inventory cannot support commissioning")
        confirmations = []
        for role in record.roles:
            if role.confirmed_by != operator or role.confirmed_at != record.created_at:
                raise DraftRefused("draft confirmation identity or time mismatch")
            matches = [readout for readout in current.commissionable
                       if tuple(sorted(readout.fields.items())) == role.composite]
            if len(matches) != 1:
                raise DraftRefused("draft does not match current inventory")
            confirmations.append((matches[0], role.role))
        rebuilt = confirm_roles(current, tuple(confirmations), operator=operator,
                                at=record.created_at, profiles_present=record.profiles_present)
        if rebuilt.digest() != record.digest():
            raise DraftRefused("draft bindings are inconsistent")
    except (ApprovalRefused, CommissioningRefused):
        raise DraftRefused("commissioning review refused") from None


def _check_protection(directory_fd: int) -> None:
    info = os.fstat(directory_fd)
    # The installed layout is 0750 root:azcommission. Group read/search may
    # expose fixed file names/metadata, but never owner-only payload bytes.
    # Do not permit group writes or any other-user permission.
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o027:
        raise DraftRefused("draft directory ownership or access refused")
    if not luks_backed(COMMISSIONING_DIR, stat=lambda _: os.fstat(directory_fd)):
        raise DraftRefused("encrypted commissioning storage is required")
    if not read_protection_key(PROTECTION_KEY):
        raise DraftRefused("commissioning protection key is unavailable")


def _read_private(directory_fd: int, name: str, *, maximum: int) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_mode & 0o077 or before.st_nlink != 1
                or not 0 < before.st_size <= maximum):
            raise DraftRefused("private draft input refused")
        result = bytearray()
        while len(result) <= maximum:
            chunk = os.read(fd, min(8192, maximum + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or len(result) != before.st_size:
            raise DraftRefused("draft input changed while reading")
        return bytes(result)
    finally:
        os.close(fd)


def read_draft_review_inputs() -> tuple[bytes, bytes]:
    """Read only the fixed protected draft and raw 64-byte signature sidecar."""
    directory_fd = None
    try:
        directory_fd = os.open(COMMISSIONING_DIR, os.O_RDONLY | os.O_DIRECTORY |
                               os.O_NOFOLLOW | os.O_CLOEXEC)
        _check_protection(directory_fd)
        payload = _read_private(directory_fd, "commissioning-draft.json", maximum=MAX_APPROVAL_BYTES)
        signature = _read_private(directory_fd, "commissioning-draft.sig", maximum=64)
        if len(signature) != 64:
            raise DraftRefused("draft signature must have exactly 64 bytes")
        return payload, signature
    except OSError:
        raise DraftRefused("protected draft input unavailable") from None
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def _create_private_at(directory_fd: int, filename: str, payload: bytes) -> None:
    fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise DraftRefused("commissioning destination must be a new ordinary file")
        offset = 0
        while offset < len(payload):
            count = os.write(fd, payload[offset:])
            if count <= 0:
                raise OSError("commissioning write made no progress")
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory_fd)


def _export_private_bytes(payload: bytes, destination: Path, *, filename: str) -> None:
    """Write bounded private bytes to one fixed name in protected storage."""
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_APPROVAL_BYTES:
        raise DraftRefused("invalid or oversized commissioning payload")
    if destination.parent != COMMISSIONING_DIR or destination.name != filename:
        raise DraftRefused("commissioning payload belongs only in the protected record directory")
    directory_fd = None
    try:
        directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY |
                               os.O_NOFOLLOW | os.O_CLOEXEC)
        _check_protection(directory_fd)
        _create_private_at(directory_fd, destination.name, payload)
    except OSError as exc:
        raise DraftRefused("commissioning export failed; inspect destination before retrying") from exc
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def export_draft(record: CommissioningRecord, destination: Path) -> None:
    """Create one protected unsigned draft without overwriting an existing file."""
    _export_private_bytes(draft_bytes(record), destination, filename="commissioning-draft.json")


def export_proposal(payload: bytes) -> None:
    """Legacy unsigned export only; cannot create retained review expectations."""
    _export_private_bytes(
        payload, COMMISSIONING_DIR / "commissioning-proposal.json",
        filename="commissioning-proposal.json",
    )


_PROPOSAL_FILES = ("commissioning-proposal.expected.json", "commissioning-proposal.json",
                   "commissioning-proposal.sig")


def retain_proposal_context(*, inventory, resource_profile, topology_profile,
                            record_id: str, operator: str, confirmed_at: str) -> None:
    """Retain validated local model inputs, never imported payload bytes.

    Two copies separate local expectations from the signing view. Their common
    privileged owner remains trusted. Failure leaves evidence for inspection;
    no automatic cleanup/migration/overwrite or rollback guarantee is offered.
    """
    from .commissioning_approval import commissioning_proposal_payload

    payload = commissioning_proposal_payload(inventory=inventory,
        resource_profile=resource_profile, topology_profile=topology_profile,
        record_id=record_id, operator=operator, confirmed_at=confirmed_at)
    directory_fd = None
    try:
        directory_fd = os.open(COMMISSIONING_DIR, os.O_RDONLY | os.O_DIRECTORY |
                               os.O_NOFOLLOW | os.O_CLOEXEC)
        _check_protection(directory_fd)
        fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for filename in _PROPOSAL_FILES:
            try:
                os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise DraftRefused("existing proposal state requires inspection")
        _create_private_at(directory_fd, _PROPOSAL_FILES[0], payload)
        _create_private_at(directory_fd, _PROPOSAL_FILES[1], payload)
    except OSError:
        raise DraftRefused("proposal retention incomplete; inspect protected storage") from None
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def read_proposal_review_inputs() -> tuple[bytes, bytes, bytes]:
    """Read retained expectations, signing view and detached signature only.

    Missing expectations are never reconstructed from existing exported bytes.
    """
    directory_fd = None
    try:
        directory_fd = os.open(COMMISSIONING_DIR, os.O_RDONLY | os.O_DIRECTORY |
                               os.O_NOFOLLOW | os.O_CLOEXEC)
        _check_protection(directory_fd)
        fcntl.flock(directory_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        expected = _read_private(directory_fd, _PROPOSAL_FILES[0], maximum=MAX_APPROVAL_BYTES)
        payload = _read_private(directory_fd, _PROPOSAL_FILES[1], maximum=MAX_APPROVAL_BYTES)
        signature = _read_private(directory_fd, _PROPOSAL_FILES[2], maximum=64)
        if expected != payload or len(signature) != 64:
            raise DraftRefused("proposal review inputs inconsistent")
        return expected, payload, signature
    except OSError:
        raise DraftRefused("protected proposal review inputs unavailable") from None
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
