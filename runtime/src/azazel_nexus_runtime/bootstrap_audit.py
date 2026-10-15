"""Read existing audit continuity before bootstrap; never establish genesis.

The one exception is ``inspect_first_install_audit``: it takes no expected head,
adopts nothing it observes, and accepts only a correctly owned, writer-protected,
empty ledger directory. Genesis is established only by an admitted v5 policy.

The independent expected head must come from admitted provisioning/anchor state,
not from this reader or an unsigned local checkpoint. Matching bytes proves
continuity to that expectation, not anchor authenticity or complete health.
No service, directory, ledger or key is created by this module.
"""

from dataclasses import dataclass
from datetime import date
import json
import math
import os
import pwd
import re
import stat

from azazel_nexus.audit import AuditEntry, GENESIS_HASH
from azazel_nexus.operator_trust import ApprovalRefused

_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_HEX = re.compile(r"[0-9a-f]{64}")


def _protected(fd, *, owner, directory):
    info = os.fstat(fd)
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not valid_type or info.st_uid != owner or info.st_mode & 0o022
            or (not directory and info.st_nlink != 1)):
        raise ApprovalRefused("audit storage protection refused")
    return info


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ApprovalRefused("duplicate audit record field")
        result[key] = value
    return result


@dataclass(frozen=True)
class AuditObservation:
    sequence: int
    digest: str
    segments: int
    total_bytes: int

    def __post_init__(self):
        if (type(self.sequence) is not int or type(self.segments) is not int
                or type(self.total_bytes) is not int or type(self.digest) is not str):
            raise ValueError("invalid audit observation")
        if (self.sequence == 0) != (self.digest == GENESIS_HASH) or (
                self.sequence == 0 and (self.segments != 0 or self.total_bytes != 0)):
            raise ValueError("invalid audit observation")

    @property
    def assurance(self) -> str:
        """This reader checks continuity, not an independent anchor receipt."""
        return "LOCAL_CONTINUITY_ONLY"


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)


def _names(fd, maximum, allow_empty=False):
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            if len(names) >= maximum:
                raise ApprovalRefused("audit segment count exceeds observation bound")
            names.append(entry.name)
    if not names:
        if allow_empty:
            return []
        raise ApprovalRefused("existing bounded audit history required")
    for name in names:
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\.jsonl", name):
            raise ApprovalRefused("audit segment set refused")
        date.fromisoformat(name[:-6])
    return sorted(names)


def _snapshot(fd, *, owner, max_total_bytes, max_segments, allow_empty=False):
    before = _protected(fd, owner=owner, directory=True)
    names = _names(fd, max_segments, allow_empty)
    remaining = max_total_bytes
    result = []
    for name in names:
        # Existing ledger writer may create owner/group-readable files. Write
        # protection is checked below; do not silently change its on-disk format.
        identity, raw = _read_segment(fd, name, owner=owner, limit=remaining)
        result.append((name, identity, raw))
        remaining -= len(raw)
    if names != _names(fd, max_segments, allow_empty) or _stamp(before) != _stamp(
        _protected(fd, owner=owner, directory=True)
    ):
        raise ApprovalRefused("audit directory changed during observation")
    return tuple(result)


def _read_segment(fd, name, *, owner, limit):
    # Unlike approval files, audit segments are not required to be owner-only.
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                         | os.O_CLOEXEC, dir_fd=fd)
    try:
        before = _protected(descriptor, owner=owner, directory=False)
        if not 0 < before.st_size <= limit:
            raise ApprovalRefused("audit segment exceeds observation bounds")
        chunks = bytearray()
        while len(chunks) <= before.st_size:
            part = os.read(descriptor, min(8192, before.st_size + 1 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
        after = _protected(descriptor, owner=owner, directory=False)
        named = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if (_stamp(before) != _stamp(after) or _stamp(after) != _stamp(named)
                or len(chunks) != before.st_size or after.st_size != before.st_size):
            raise ApprovalRefused("audit segment changed during observation")
        return _stamp(after), bytes(chunks)
    finally:
        os.close(descriptor)


def _constant_refused(_value):
    raise ApprovalRefused("nonfinite audit value refused")


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ApprovalRefused("nonfinite audit value refused")
    return result


def _inspect_at(fd, *, owner, expected_head, max_total_bytes, max_segments, allow_extension=False):
    """Private ordinary-file seam; expected head is never learned from files."""
    try:
        if (type(allow_extension) is not bool
                or type(expected_head) is not tuple or len(expected_head) != 2
                or type(expected_head[0]) is not int or expected_head[0] < 0
                or type(expected_head[1]) is not str or not _HEX.fullmatch(expected_head[1])
                or (expected_head[0] == 0) != (expected_head[1] == GENESIS_HASH)
                or (expected_head[0] == 0 and not allow_extension)
                or any(type(value) is not int or value <= 0
                       for value in (max_total_bytes, max_segments))):
            raise ApprovalRefused("independent non-genesis audit expectation required")
        genesis = expected_head[0] == 0  # Extension-only continuation from empty.
        first = _snapshot(fd, owner=owner, max_total_bytes=max_total_bytes,
                          max_segments=max_segments, allow_empty=genesis)
        sequence, digest = 0, GENESIS_HASH
        anchored = genesis
        for _name, _identity, raw in first:
            segment_start = sequence
            if not raw.endswith(b"\n"):
                raise ApprovalRefused("unfinished audit record")
            # Match AuditLedger's UTF-8/text line interpretation. json.loads
            # on bytes alone also accepts UTF-16/32, which auditd cannot read.
            for line in raw.decode("utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line, object_pairs_hook=_unique_object,
                                    parse_constant=_constant_refused, parse_float=_finite_float)
                if (type(record) is not dict or set(record) != {
                    "sequence", "previous_hash", "event_hash", "event"
                } or type(record["sequence"]) is not int
                        or record["sequence"] != sequence + 1
                        or record["previous_hash"] != digest
                        or type(record["event_hash"]) is not str
                        or not _HEX.fullmatch(record["event_hash"])
                        or type(record["event"]) is not dict):
                    raise ApprovalRefused("audit record refused")
                entry = AuditEntry(**record)
                if entry.recomputed() != entry.event_hash:
                    raise ApprovalRefused("audit chain integrity refused")
                sequence, digest = entry.sequence, entry.event_hash
                if sequence == expected_head[0]:
                    if digest != expected_head[1]:
                        raise ApprovalRefused("previously verified audit prefix differs")
                    anchored = True
            if sequence == segment_start:
                raise ApprovalRefused("empty audit segment refused")
        if not anchored or (not allow_extension and (sequence, digest) != expected_head):
            raise ApprovalRefused("audit anchor differs")
        if first != _snapshot(fd, owner=owner, max_total_bytes=max_total_bytes,
                              max_segments=max_segments, allow_empty=genesis):
            raise ApprovalRefused("audit history changed during verification")
        return AuditObservation(sequence, digest, len(first),
                                sum(len(raw) for _, _, raw in first))
    except Exception:
        raise ApprovalRefused("existing bootstrap audit continuity refused") from None


def _scan_entries(fd):
    with os.scandir(fd) as entries:
        return [entry.name for entry in entries]


def _inspect_genesis_at(fd, *, owner, max_total_bytes, max_segments):
    """Private seam: an empty, protected, stable directory; no head is taken."""
    try:
        if any(type(value) is not int or value <= 0 for value in (max_total_bytes, max_segments)):
            raise ApprovalRefused("bounded audit observation required")
        before = _protected(fd, owner=owner, directory=True)
        if stat.S_IMODE(before.st_mode) != 0o700:
            raise ApprovalRefused("first-install audit directory mode refused")
        if _scan_entries(fd):
            raise ApprovalRefused("first-install audit directory is not empty")
        after = _protected(fd, owner=owner, directory=True)
        if _stamp(before) != _stamp(after) or _scan_entries(fd) or _stamp(after) != _stamp(
            _protected(fd, owner=owner, directory=True)
        ):
            raise ApprovalRefused("audit directory changed during observation")
        return AuditObservation(0, GENESIS_HASH, 0, 0)
    except Exception:
        raise ApprovalRefused("first-install bootstrap audit refused") from None


def _open_ledger(owner):
    fd = os.open("/", _FLAGS)
    try:
        # Fixed existing auditd path, not runtime_paths.ledger_dir(), which
        # creates missing directories and supports relocated test roots.
        for component in ("var", "lib", "azazel", "state", "audit"):
            # fd names the parent, not the component about to be opened.
            # Installer state/ is root-owned with group azaudit, not UID azaudit.
            _protected(fd, owner=0, directory=True)
            child = os.open(component, _FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        _protected(fd, owner=owner, directory=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def inspect_existing_audit(*, expected_head, max_total_bytes, max_segments):
    """Fixed-path read-only producer, not a bootstrap admission decision.

    The audit writer must be independently confirmed stopped for pre-start use.
    Two matching observations do not lock out a writer or defend hostile root.
    Empty first-install history requires a separate admitted provisioning path.
    """
    return _inspect_protected(expected_head=expected_head, max_total_bytes=max_total_bytes,
                              max_segments=max_segments, allow_extension=False)


def inspect_first_install_audit(*, max_total_bytes, max_segments):
    """Fixed-path read-only genesis producer; takes and adopts no head.

    Accepts only an existing, correctly owned, writer-protected, empty ledger
    directory. Whether genesis is expected is decided by the admitted v5 policy.
    """
    return _inspect_protected(expected_head=None, max_total_bytes=max_total_bytes,
                              max_segments=max_segments, allow_extension=False, genesis=True)


def inspect_audit_extension(*, expected_head, max_total_bytes, max_segments):
    """Verify an unchanged or extended prefix of previously verified history.

    Local in-session continuity only. A concurrent writer may cause refusal;
    no retry, cached success, rotation pruning or rollback anchor is invented.
    """
    return _inspect_protected(expected_head=expected_head, max_total_bytes=max_total_bytes,
                              max_segments=max_segments, allow_extension=True)


def _inspect_protected(*, expected_head, max_total_bytes, max_segments, allow_extension,
                       genesis=False):
    try:
        owner = pwd.getpwnam("azaudit").pw_uid
        if type(owner) is not int or owner <= 0:
            raise ApprovalRefused("audit service account unavailable")
        fd = _open_ledger(owner)
        try:
            identity = os.fstat(fd)
            if genesis:
                result = _inspect_genesis_at(fd, owner=owner, max_total_bytes=max_total_bytes,
                                             max_segments=max_segments)
            else:
                result = _inspect_at(fd, owner=owner, expected_head=expected_head,
                                     max_total_bytes=max_total_bytes, max_segments=max_segments,
                                     allow_extension=allow_extension)
            current = _open_ledger(owner)
            try:
                if _stamp(identity) != _stamp(os.fstat(current)):
                    raise ApprovalRefused("audit path changed")
            finally:
                os.close(current)
            return result
        finally:
            os.close(fd)
    except Exception:
        raise ApprovalRefused("existing bootstrap audit continuity refused") from None
