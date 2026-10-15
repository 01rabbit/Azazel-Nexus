"""Complete approved evidence for an additional gate, never an activation grant."""

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
import re

from .commissioning_approval import verify_retained_commissioning_proposal
from .fabric_boundary import (
    CommissioningRecordUnavailable, assert_current_inventory_matches,
    assert_local_record_matches_full_proposal, restore_commissioning_inputs,
)
from .operator_store import _protected
from .operator_trust import ApprovalRefused, MAX_APPROVAL_BYTES


@dataclass(frozen=True, repr=False)
class CommissioningEvidence:
    """Trusted-loader output retaining all signed content and limitations.

    The constructor does not establish provenance. The runtime must call the
    verifier below on every pass. This value supplies no health, policy,
    renderer, trusted-time or authoritative local commissioning record.
    """

    payload: bytes = field(repr=False)
    signature: bytes = field(repr=False)
    current_inventory: bytes = field(repr=False)
    binding: str = field(repr=False)

    def __post_init__(self):
        if (type(self.payload) is not bytes or not 0 < len(self.payload) <= MAX_APPROVAL_BYTES
                or type(self.current_inventory) is not bytes
                or not 0 < len(self.current_inventory) <= MAX_APPROVAL_BYTES
                or type(self.signature) is not bytes or len(self.signature) != 64
                or type(self.binding) is not str
                or not re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", self.binding)):
            raise ApprovalRefused("commissioning evidence shape refused")

    def matches_record(self, record) -> bool:
        try:
            assert_local_record_matches_full_proposal(document=json.loads(self.payload), record=record)
            return True
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError,
                CommissioningRecordUnavailable):
            return False


def verify_commissioning_evidence(*, trust, expected_payload: bytes, payload: bytes,
                                  signature: bytes, node_id: str, current_inventory,
                                  protection_key: bytes) -> CommissioningEvidence:
    """Verify full evidence; bind it without exposing a raw identity digest."""
    if type(protection_key) is not bytes or not 32 <= len(protection_key) <= 4096:
        raise ApprovalRefused("commissioning binding key unavailable")
    try:
        if type(expected_payload) is not bytes or not 0 < len(expected_payload) <= MAX_APPROVAL_BYTES:
            raise ValueError
        context = restore_commissioning_inputs(json.loads(expected_payload))
        verify_retained_commissioning_proposal(trust=trust, payload=payload,
            signature=signature, expected_payload=expected_payload,
            operator=context["operator"], node_id=node_id)
        assert_current_inventory_matches(retained=context["inventory"], current=current_inventory)
        current = json.dumps(current_inventory.model_dump(mode="json"), sort_keys=True,
                             separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        binding = "hmac-sha256:" + hmac.new(protection_key,
            b"azazel-nexus/commissioning-evidence/v1\x00" + payload, hashlib.sha256).hexdigest()
        return CommissioningEvidence(payload, signature, current, binding)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError,
            CommissioningRecordUnavailable):
        raise ApprovalRefused("complete commissioning evidence refused") from None


def _read_key_at(directory_fd: int, *, owner: int) -> bytes:
    directory = _protected(directory_fd, owner=owner, directory=True)
    if directory.st_mode & 0o077:
        raise ApprovalRefused("private commissioning key directory required")
    fd = os.open("commissioning.key", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                 os.O_CLOEXEC, dir_fd=directory_fd)
    try:
        before = _protected(fd, owner=owner, directory=False)
        if before.st_mode & 0o077 or not 32 <= before.st_size <= 4096:
            raise ApprovalRefused("private bounded commissioning key required")
        data = bytearray()
        while len(data) <= 4096:
            chunk = os.read(fd, 4097 - len(data))
            if not chunk:
                break
            data.extend(chunk)
        after = _protected(fd, owner=owner, directory=False)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_mode) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode
        ) or len(data) != before.st_size:
            raise ApprovalRefused("commissioning key changed while reading")
        return bytes(data)
    finally:
        os.close(fd)


def load_commissioning_binding_key() -> bytes:
    """Fixed root-owned secret; no generation, import or caller-supplied path."""
    fd = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open("/", flags)
        for name in ("var", "lib", "azazel", "secrets"):
            _protected(fd, owner=0, directory=True)
            child = os.open(name, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return _read_key_at(fd, owner=0)
    except (OSError, AttributeError):
        raise ApprovalRefused("protected commissioning binding key unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)
