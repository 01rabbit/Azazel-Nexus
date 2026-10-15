"""Journaled publication and closing of the exact bootstrap helper pair.

This is a private file-transaction primitive, not a grant or start fence. It
has no production path opener and is not wired to the supervisor or CLI. A
Publication requires independent admission and a deployment start fence.
Closing preserves ownership while narrowing on-disk files; it does not prove
the loaded fence. The adapter must separately reload and inspect systemd.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
from contextlib import contextmanager
from dataclasses import asdict
from hashlib import sha256

from azazel_nexus.bootstrap_approval import BootstrapContext, VerifiedBootstrapApproval
from azazel_nexus.bootstrap_lock import BootstrapTransactionGuard
from azazel_nexus.bootstrap_grant_transaction import GrantTransaction
from azazel_nexus.bootstrap_overlay_journal import (
    OverlayIntent,
    OverlayJournal,
    OverlayJournalDurabilityUncertain,
    advance_overlay,
    new_overlay_journal,
)
from azazel_nexus.operator_trust import ApprovalRefused

from .hardening import PROFILES, render_unit
from .bootstrap_directory_paths import AbsentBootstrapDirectory

_PAIR = ("azazel-auditd.service", "azazel-commissiond.service")
_CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_LIMIT = 64 * 1024


class OverlayPublicationUncertain(ApprovalRefused):
    """A candidate was created but its complete state could not be confirmed."""


class OverlayClosureUncertain(ApprovalRefused):
    """Closing intent or empty-file durability needs inspection before retry."""


def _fixed_payloads() -> dict[str, bytes]:
    profiles = [profile for profile in PROFILES if profile.unit in _PAIR]
    if len(profiles) != len(_PAIR) or {profile.unit for profile in profiles} != set(_PAIR):
        raise ApprovalRefused("bootstrap overlay profile pair changed")
    by_unit = {profile.unit: profile for profile in profiles}
    payloads = {unit: render_unit(by_unit[unit]).encode("utf-8") for unit in _PAIR}
    if any(not 0 < len(raw) <= _LIMIT for raw in payloads.values()):
        raise ApprovalRefused("bootstrap overlay payload size refused")
    return payloads


def new_overlay_intent(approval: VerifiedBootstrapApproval) -> OverlayIntent:
    """Bind an attributed approval context to the fixed rendered payloads.

    This does not itself verify a signature, freshness, admission or authority;
    the trusted supervisor must supply a freshly verified object.
    """
    return _intent_from_approval(approval, grant_id=secrets.token_hex(16))


def _intent_from_approval(approval, *, grant_id):
    if type(approval) is not VerifiedBootstrapApproval:
        raise ApprovalRefused("verified bootstrap approval required")
    if type(approval.context) is not BootstrapContext:
        raise ApprovalRefused("verified bootstrap context required")
    payloads = _fixed_payloads()
    context_raw = json.dumps(asdict(approval.context), sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
    return OverlayIntent(
        boot_id=approval.context.boot_id,
        context_digest=sha256(context_raw).hexdigest(),
        grant_id=grant_id,
        payload_digests=tuple(
            (unit, sha256(payloads[unit]).hexdigest()) for unit in _PAIR
        ),
    )


def _directory(fd: int, *, owner_uid: int) -> os.stat_result:
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid
            or info.st_mode & 0o022):
        raise ApprovalRefused("bootstrap overlay directory refused")
    return info


def _present(fd: int, name: str) -> bool:
    if type(fd) is AbsentBootstrapDirectory:
        fd.check()
        return False
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        raise ApprovalRefused("bootstrap overlay entry inspection refused") from None


def _mask_paths(*, overlay_fd, masks_fd, higher_priority_fd, owner_uid):
    def stamp(info):
        return (info.st_dev, info.st_ino, info.st_uid, info.st_mode,
                info.st_mtime_ns, info.st_ctime_ns)

    stamps = []
    for fd in (overlay_fd, masks_fd):
        info = _directory(fd, owner_uid=owner_uid)
        stamps.append((info.st_dev, info.st_ino, info.st_uid, info.st_mode))
    if type(higher_priority_fd) is AbsentBootstrapDirectory:
        stamps.append(higher_priority_fd.stamp(owner_uid))
    else:
        info = _directory(higher_priority_fd, owner_uid=owner_uid)
        stamps.append((info.st_dev, info.st_ino, info.st_uid, info.st_mode))
    for unit in _PAIR:
        try:
            mask = os.stat(unit, dir_fd=masks_fd, follow_symlinks=False)
            target = os.readlink(unit, dir_fd=masks_fd)
        except OSError:
            raise ApprovalRefused("bootstrap persistent helper mask unavailable") from None
        if (not stat.S_ISLNK(mask.st_mode) or mask.st_uid != owner_uid
                or target != "/dev/null"):
            raise ApprovalRefused("bootstrap persistent helper mask changed")
        current = os.stat(unit, dir_fd=masks_fd, follow_symlinks=False)
        if stamp(current) != stamp(mask):
            raise ApprovalRefused("bootstrap persistent helper mask changed")
        stamps.append(stamp(mask))

        if (_present(higher_priority_fd, unit)
                or _present(higher_priority_fd, f"{unit}.d")):
            raise ApprovalRefused("higher-priority helper unit input exists")
        if _present(overlay_fd, f"{unit}.d"):
            raise ApprovalRefused("helper drop-in conflicts with candidate")
    return tuple(stamps)


def _validate_inputs(*, overlay_fd: int, masks_fd: int,
                     higher_priority_fd: int, owner_uid: int,
                     journal: OverlayJournal, payloads: dict[str, bytes]) -> None:
    _mask_paths(overlay_fd=overlay_fd, masks_fd=masks_fd,
                higher_priority_fd=higher_priority_fd, owner_uid=owner_uid)
    if type(journal) is not OverlayJournal:
        raise ApprovalRefused("bootstrap overlay journal required")
    expected = dict(journal.intent.payload_digests)
    if expected != {unit: sha256(payloads[unit]).hexdigest() for unit in _PAIR}:
        raise ApprovalRefused("bootstrap overlay payload changed from intent")
    owned = {unit: (device, inode, digest)
             for unit, device, inode, digest in journal.owned_files}
    for unit in _PAIR:
        if unit in owned:
            device, inode, digest = owned[unit]
            if digest != expected[unit]:
                raise ApprovalRefused("journaled helper digest changed")
            _read_candidate(overlay_fd, unit, payloads[unit], owner_uid=owner_uid,
                            expected_identity=(device, inode))
        elif _present(overlay_fd, unit):
            raise ApprovalRefused("unowned helper candidate already exists")


def _read_candidate(directory_fd: int, name: str, expected: bytes, *,
                    owner_uid: int, expected_identity: tuple[int, int]):
    fd = os.open(name, _READ, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner_uid
                or stat.S_IMODE(before.st_mode) != 0o644 or before.st_nlink != 1
                or (before.st_dev, before.st_ino) != expected_identity
                or before.st_size != len(expected)):
            raise ApprovalRefused("bootstrap helper candidate identity refused")
        chunks = bytearray()
        while len(chunks) <= _LIMIT:
            data = os.read(fd, min(8192, _LIMIT + 1 - len(chunks)))
            if not data:
                break
            chunks.extend(data)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)

        def stamp(info):
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                    info.st_ctime_ns, info.st_mode, info.st_uid, info.st_nlink)

        if (stamp(before) != stamp(after) or stamp(after) != stamp(named)
                or bytes(chunks) != expected):
            raise ApprovalRefused("bootstrap helper candidate bytes changed")
        return after
    finally:
        os.close(fd)


def _write_all(fd: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(fd, remaining)
        if written <= 0:
            raise OSError("bootstrap helper candidate short write")
        remaining = remaining[written:]


def _create_candidate(directory_fd: int, unit: str, payload: bytes, *,
                      owner_uid: int) -> tuple[int, int]:
    created = False
    fd = None
    try:
        fd = os.open(unit, _CREATE, 0o644, dir_fd=directory_fd)
        created = True
        os.fchmod(fd, 0o644)
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != owner_uid
                or stat.S_IMODE(opened.st_mode) != 0o644 or opened.st_nlink != 1):
            raise ApprovalRefused("new helper candidate attributes refused")
        identity = opened.st_dev, opened.st_ino
        _write_all(fd, payload)
        os.fsync(fd)
        descriptor, fd = fd, None
        try:
            os.close(descriptor)
        except OSError:
            raise OverlayPublicationUncertain(
                "bootstrap helper candidate close outcome uncertain"
            ) from None
        _read_candidate(directory_fd, unit, payload, owner_uid=owner_uid,
                        expected_identity=identity)
        os.fsync(directory_fd)
        return identity
    except (ApprovalRefused, OSError) as error:
        if created:
            raise OverlayPublicationUncertain(
                "bootstrap helper candidate publication outcome uncertain"
            ) from None
        if isinstance(error, ApprovalRefused):
            raise
        raise ApprovalRefused("bootstrap helper candidate creation refused") from None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _publish_candidates_at(*, overlay_fd: int, masks_fd: int,
                           higher_priority_fd: int,
                           journal_store, guard: BootstrapTransactionGuard,
                           intent: OverlayIntent, owner_uid: int,
                           check_publish=None) -> OverlayJournal:
    """Publish exact files to supplied descriptors; private synthetic-test seam.

    It does not reload systemd, establish a start fence or grant either unit.
    Callers supply a preconstructed intent only for the fake-descriptor tests;
    production composition must use `_publish_verified_approval_at` and must
    remain unreachable until independent systemd gates are implemented/reviewed.
    """
    if type(guard) is not BootstrapTransactionGuard:
        raise ApprovalRefused("bootstrap transaction guard required")
    if type(intent) is not OverlayIntent:
        raise ApprovalRefused("verified overlay intent required")
    if check_publish is not None and not callable(check_publish):
        raise ApprovalRefused("publication admission checkpoint required")

    def checkpoint():
        guard()
        if check_publish is not None and check_publish() is not None:
            raise ApprovalRefused("publication admission checkpoint refused")

    checkpoint()
    payloads = _fixed_payloads()
    current = new_overlay_journal(intent)
    _validate_inputs(overlay_fd=overlay_fd, masks_fd=masks_fd,
                     higher_priority_fd=higher_priority_fd,
                     owner_uid=owner_uid, journal=current, payloads=payloads)
    checkpoint()
    journal_store.create(current)  # Durable intent always precedes O_EXCL.
    for unit in _PAIR:
        checkpoint()
        _validate_inputs(overlay_fd=overlay_fd, masks_fd=masks_fd,
                         higher_priority_fd=higher_priority_fd,
                         owner_uid=owner_uid, journal=current, payloads=payloads)
        identity = _create_candidate(overlay_fd, unit, payloads[unit],
                                     owner_uid=owner_uid)
        try:
            updated = advance_overlay(
                current, "create-file", unit=unit,
                device=identity[0], inode=identity[1]
            )
            checkpoint()
            journal_store.replace(current, updated)
        except (ApprovalRefused, OverlayJournalDurabilityUncertain):
            raise OverlayPublicationUncertain(
                "bootstrap helper ownership record outcome uncertain"
            ) from None
        current = updated
        checkpoint()
    _validate_inputs(overlay_fd=overlay_fd, masks_fd=masks_fd,
                     higher_priority_fd=higher_priority_fd,
                     owner_uid=owner_uid, journal=current, payloads=payloads)
    checkpoint()
    if journal_store.load() != current or current.phase != "published":
        raise ApprovalRefused("bootstrap helper file publication incomplete")
    return current


def _publish_verified_approval_at(*, overlay_fd: int, masks_fd: int,
                                  higher_priority_fd: int,
                                  journal_store, guard: BootstrapTransactionGuard,
                                  approval: VerifiedBootstrapApproval,
                                  transaction: GrantTransaction, check_publish,
                                  owner_uid: int) -> OverlayJournal:
    """Publish the already-journaled grant identity, never allocate another.

    The caller remains responsible for obtaining this approval from the
    verifier and proving freshness, admission, and the real systemd start fence.
    """
    if (type(approval) is not VerifiedBootstrapApproval
            or type(approval.context) is not BootstrapContext):
        raise ApprovalRefused("freshly verified bootstrap approval required")
    if (type(transaction) is not GrantTransaction
            or transaction.phase != "pair_grant_intent"
            or not callable(check_publish)):
        raise ApprovalRefused("retained pair intent and publication admission required")
    intent = _intent_from_approval(approval, grant_id=transaction.grant_id)
    if (transaction.boot_id != intent.boot_id
            or transaction.context_digest != "sha256:" + intent.context_digest
            or transaction.approval_digest != approval.payload_digest
            or transaction.generation != approval.context.generation
            or transaction.generation_digest != approval.context.generation_digest
            or transaction.unit_payload_digests != intent.payload_digests):
        raise ApprovalRefused("publication differs from retained grant transaction")
    return _publish_candidates_at(
        overlay_fd=overlay_fd,
        masks_fd=masks_fd,
        higher_priority_fd=higher_priority_fd,
        journal_store=journal_store,
        guard=guard,
        intent=intent,
        owner_uid=owner_uid,
        check_publish=check_publish,
    )


def _check_published_pair_at(*, overlay_fd, masks_fd, higher_priority_fd,
                             journal_store, guard, expected, retained_mask_stamps,
                             owner_uid):
    """Check a captured published journal, never adopt later journal contents.

    The caller retains directory bindings and the pre-publication mask stamps.
    This is a file observation, not loaded-systemd admission or a start grant.
    """
    if (type(guard) is not BootstrapTransactionGuard
            or type(expected) is not OverlayJournal or expected.phase != "published"):
        raise ApprovalRefused("owned published pair required")
    guard()
    paths = dict(overlay_fd=overlay_fd, masks_fd=masks_fd,
                 higher_priority_fd=higher_priority_fd, owner_uid=owner_uid)
    if (journal_store.load() != expected
            or _mask_paths(**paths) != retained_mask_stamps):
        raise ApprovalRefused("published pair ownership or mask baseline changed")
    try:
        _validate_inputs(**paths, journal=expected, payloads=_fixed_payloads())
    except OSError:
        raise ApprovalRefused("published pair file observation unavailable") from None
    if (journal_store.load() != expected
            or _mask_paths(**paths) != retained_mask_stamps):
        raise ApprovalRefused("published pair changed during observation")
    guard()


def _close_attributes(info, identity, owner_uid):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
            or stat.S_IMODE(info.st_mode) != 0o644 or info.st_nlink != 1
            or (info.st_dev, info.st_ino) != identity
            or not 0 <= info.st_size <= _LIMIT):
        raise ApprovalRefused("owned closing candidate identity refused")


def _check_close_fd(fd, *, directory_fd, unit, identity, digest,
                    owner_uid, allow_empty):
    before = os.fstat(fd)
    _close_attributes(before, identity, owner_uid)
    os.lseek(fd, 0, os.SEEK_SET)
    content = bytearray()
    while len(content) <= _LIMIT:
        data = os.read(fd, min(8192, _LIMIT + 1 - len(content)))
        if not data:
            break
        content.extend(data)
    after = os.fstat(fd)
    named = os.stat(unit, dir_fd=directory_fd, follow_symlinks=False)

    def stamp(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    if (stamp(before) != stamp(after) or stamp(after) != stamp(named)
            or len(content) != after.st_size
            or (not content and not allow_empty)
            or (content and sha256(content).hexdigest() != digest)):
        raise ApprovalRefused("owned closing candidate bytes changed")
    return not content


@contextmanager
def _closing_candidate(directory_fd, unit, identity, digest, *,
                       owner_uid, allow_empty, writable=False):
    # Reject non-regular entries before a writable open as well as after it.
    try:
        _close_attributes(os.stat(unit, dir_fd=directory_fd, follow_symlinks=False),
                          identity, owner_uid)
        flags = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        fd = os.open(unit, flags | (os.O_RDWR if writable else os.O_RDONLY),
                     dir_fd=directory_fd)
        try:
            _check_close_fd(fd, directory_fd=directory_fd, unit=unit,
                            identity=identity, digest=digest, owner_uid=owner_uid,
                            allow_empty=allow_empty)
            yield fd
        finally:
            os.close(fd)
    except OSError:
        raise ApprovalRefused("owned closing candidate IO refused") from None


def _close_candidates_at(*, overlay_fd: int, masks_fd: int,
                         higher_priority_fd: int, journal_store,
                         guard: BootstrapTransactionGuard,
                         owner_uid: int) -> OverlayJournal:
    """Durably empty only owned files; no reload, job or process operation.

    An empty unit file is systemd mask syntax. Its loaded effect is NOT proved
    here. Closing intent precedes writable opens and truncation. Keeping the
    inode lets recovery accept the original digest or an empty file without
    adopting replacement files. The private directory and held controller lock
    exclude untrusted writers; this does not resist arbitrary privileged writes
    or malicious inode reuse. Descriptors have no production path opener here.
    """
    if type(guard) is not BootstrapTransactionGuard:
        raise ApprovalRefused("bootstrap transaction guard required")
    guard()
    current = journal_store.load()
    if (type(current) is not OverlayJournal
            or current.phase not in {"intent", "partial", "published", "closing"}):
        raise ApprovalRefused("close requires retained overlay ownership")
    owned = {unit: (device, inode, digest)
             for unit, device, inode, digest in current.owned_files}
    path_args = dict(overlay_fd=overlay_fd, masks_fd=masks_fd,
                     higher_priority_fd=higher_priority_fd, owner_uid=owner_uid)
    original_paths = _mask_paths(**path_args)

    def check_paths():
        guard()
        if journal_store.load() != current or _mask_paths(**path_args) != original_paths:
            raise ApprovalRefused("closing journal or mask paths changed")
        if any(_present(overlay_fd, unit) for unit in _PAIR if unit not in owned):
            raise ApprovalRefused("unowned closing candidate present")

    # Validate all owned and unowned paths before committing closing intent.
    check_paths()
    for unit, (device, inode, digest) in owned.items():
        with _closing_candidate(overlay_fd, unit, (device, inode), digest,
                                owner_uid=owner_uid,
                                allow_empty=current.phase == "closing"):
            pass
    uncertain = current.phase == "closing"
    try:
        check_paths()
        if current.phase != "closing":
            closing = advance_overlay(current, "close-starts")
            uncertain = True
            journal_store.replace(current, closing)
            current = closing
        else:
            # A previous rename may have become visible while its directory
            # fsync failed. Reading that phase is not proof of durability;
            # re-publish/fsync the retained intent before recovery mutates files.
            journal_store.replace(current, current)
        # The dependant helper is closed first. Each iteration is recoverable
        # from the original digest or empty bytes on the SAME retained inode.
        for unit in reversed(_PAIR):
            if unit not in owned:
                continue
            check_paths()
            device, inode, digest = owned[unit]
            with _closing_candidate(overlay_fd, unit, (device, inode), digest,
                                    owner_uid=owner_uid, allow_empty=True,
                                    writable=True) as fd:
                check_paths()
                empty = _check_close_fd(fd, directory_fd=overlay_fd, unit=unit,
                                       identity=(device, inode), digest=digest,
                                       owner_uid=owner_uid, allow_empty=True)
                # Rechecking a closed candidate must not change mtime and
                # spuriously invalidate systemd's later loaded-mask snapshot.
                if not empty:
                    os.ftruncate(fd, 0)
                os.fsync(fd)
                if not _check_close_fd(fd, directory_fd=overlay_fd, unit=unit,
                                       identity=(device, inode), digest=digest,
                                       owner_uid=owner_uid, allow_empty=True):
                    raise ApprovalRefused("owned candidate is not empty")
            os.fsync(overlay_fd)
        check_paths()
        for unit, (device, inode, digest) in owned.items():
            with _closing_candidate(overlay_fd, unit, (device, inode), digest,
                                    owner_uid=owner_uid, allow_empty=True) as fd:
                if os.fstat(fd).st_size != 0:
                    raise ApprovalRefused("closing pair is not empty")
        check_paths()
        return current
    except (ApprovalRefused, OSError):
        if uncertain:
            raise OverlayClosureUncertain(
                "overlay closing incomplete; retained ownership requires inspection"
            ) from None
        raise
