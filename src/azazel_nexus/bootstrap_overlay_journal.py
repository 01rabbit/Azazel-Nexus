"""Crash-recoverable intent records for the two-unit volatile overlay.

This journal proves only the recorded file-transaction phase. It is not a
systemd start fence, grant, authorization, service stop receipt, or proof that
the volatile `/run` files match disk. A lost or ambiguous owner record refuses
instead of inferring ownership from unit contents.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import uuid
from contextlib import contextmanager
from dataclasses import dataclass

from .bootstrap_lock import BootstrapTransactionGuard, bootstrap_transaction
from .operator_store import _protected
from .operator_trust import ApprovalRefused

_UNITS = ("azazel-auditd.service", "azazel-commissiond.service")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_GRANT = re.compile(r"[0-9a-f]{32}\Z")
_SCHEMA = "azazel-nexus/bootstrap-overlay-journal/v1"
_JOURNAL_NAME = "overlay-journal.json"
_MAX_JOURNAL_BYTES = 4096
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_OVERLAY_COMPONENTS = ("var", "lib", "azazel", "state", "bootstrap-overlay")


class OverlayJournalDurabilityUncertain(ApprovalRefused):
    """A rename/unlink became visible but directory durability was not proven."""


def _dir_info(fd: int, *, owner_uid: int):
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ApprovalRefused("bootstrap overlay journal directory refused")
    return info


def _file_info(fd: int, *, owner_uid: int):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or not 0 < info.st_size <= _MAX_JOURNAL_BYTES):
        raise ApprovalRefused("bootstrap overlay journal file refused")
    return info


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_nlink)


def _write_all(fd: int, raw: bytes) -> None:
    remaining = memoryview(raw)
    while remaining:
        written = os.write(fd, remaining)
        if written <= 0:
            raise OSError("bootstrap overlay journal short write")
        remaining = remaining[written:]


def _read_fd(fd: int, *, owner_uid: int) -> tuple[bytes, os.stat_result]:
    before = _file_info(fd, owner_uid=owner_uid)
    chunks = bytearray()
    while len(chunks) <= _MAX_JOURNAL_BYTES:
        data = os.read(fd, min(8192, _MAX_JOURNAL_BYTES + 1 - len(chunks)))
        if not data:
            break
        chunks.extend(data)
    after = _file_info(fd, owner_uid=owner_uid)
    if _stamp(before) != _stamp(after) or len(chunks) != before.st_size:
        raise ApprovalRefused("bootstrap overlay journal changed while reading")
    return bytes(chunks), after


def _open_overlay_directory_at(root_fd: int, *, owner_uid: int) -> int:
    """Traverse only the fixed bootstrap state path beneath a root descriptor."""
    if type(root_fd) is not int or type(owner_uid) is not int or owner_uid < 0:
        raise ApprovalRefused("bootstrap overlay directory root refused")
    current = os.dup(root_fd)
    try:
        for component in _OVERLAY_COMPONENTS:
            _protected(current, owner=owner_uid, directory=True)
            child = os.open(component, _DIR_FLAGS, dir_fd=current)
            os.close(current)
            current = child
        _dir_info(current, owner_uid=owner_uid)
        return current
    except ApprovalRefused:
        os.close(current)
        raise
    except OSError:
        os.close(current)
        raise ApprovalRefused("bootstrap overlay directory traversal refused") from None


def _open_production_overlay_directory() -> int:
    root_fd = os.open("/", _DIR_FLAGS)
    try:
        return _open_overlay_directory_at(root_fd, owner_uid=0)
    finally:
        os.close(root_fd)


@contextmanager
def _production_overlay_directory():
    """Open the fixed installed location and detect path replacement on exit."""
    fd = _open_production_overlay_directory()
    identity = OverlayJournalStore._identity(os.fstat(fd))
    try:
        yield fd
        fresh = _open_production_overlay_directory()
        try:
            if OverlayJournalStore._identity(os.fstat(fresh)) != identity:
                raise ApprovalRefused("bootstrap overlay directory path changed")
        finally:
            os.close(fresh)
    finally:
        os.close(fd)


@contextmanager
def _overlay_store_under_guard(guard, directory_fd, *, owner_uid, reopen):
    """Descriptor seam; only a trusted in-process held-lock guard is valid."""
    if type(guard) is not BootstrapTransactionGuard:
        raise ApprovalRefused("held bootstrap transaction guard required")
    guard()
    store = OverlayJournalStore(directory_fd, owner_uid=owner_uid, reopen=reopen)
    failed = False
    try:
        yield store
    except BaseException:
        failed = True
        raise
    finally:
        try:
            guard()
        except Exception:
            if not failed:
                raise
        finally:
            store.close()


@contextmanager
def overlay_journal_store_in_transaction(guard: BootstrapTransactionGuard):
    """Fixed production store under a supervisor-held lock guard.

    This serializes cooperating controllers only; it does not fence external
    systemd clients or convert the journal into a unit-start authorization.
    No path, owner, filename or bus endpoint is caller-selectable.
    """
    if type(guard) is not BootstrapTransactionGuard:
        raise ApprovalRefused("held bootstrap transaction guard required")
    with _production_overlay_directory() as directory_fd, _overlay_store_under_guard(
        guard, directory_fd, owner_uid=0,
        reopen=_open_production_overlay_directory,
    ) as store:
        yield store


@contextmanager
def overlay_journal_transaction():
    """Standalone fixed-path store; obtains the shared lock exactly once."""
    with bootstrap_transaction() as guard, overlay_journal_store_in_transaction(
        guard
    ) as store:
        yield store


class OverlayJournalStore:
    """Descriptor-only CAS store for one protected journal in a private dir.

    `reopen` is an internal fixed-location opener supplied by the production
    composition. The store never accepts a pathname or a journal filename.
    This is a filesystem transaction primitive, not a systemd start fence or
    authenticated evidence source. Callers must serialize it under the
    bootstrap transaction lock.
    """

    def __init__(self, directory_fd: int, *, owner_uid: int, reopen):
        if (type(directory_fd) is not int or type(owner_uid) is not int
                or owner_uid < 0 or not callable(reopen)):
            raise ApprovalRefused("bootstrap overlay journal store configuration refused")
        try:
            self._directory_fd = os.dup(directory_fd)
            self._owner_uid = owner_uid
            self._reopen = reopen
            pinned = os.fstat(self._directory_fd)
            if not stat.S_ISDIR(pinned.st_mode):
                raise ApprovalRefused("bootstrap overlay journal directory required")
            self._directory_identity = self._identity(pinned)
        except (OSError, ApprovalRefused):
            if hasattr(self, "_directory_fd"):
                os.close(self._directory_fd)
            raise ApprovalRefused("bootstrap overlay journal store unavailable") from None

    @staticmethod
    def _identity(info):
        return info.st_dev, info.st_ino

    def close(self):
        fd = getattr(self, "_directory_fd", None)
        if fd is not None:
            self._directory_fd = None
            os.close(fd)

    def _check_directory(self):
        if self._directory_fd is None:
            raise ApprovalRefused("bootstrap overlay journal store is closed")
        held = _dir_info(self._directory_fd, owner_uid=self._owner_uid)
        current_fd = self._reopen()
        try:
            current = _dir_info(current_fd, owner_uid=self._owner_uid)
        finally:
            os.close(current_fd)
        if (self._identity(held) != self._directory_identity
                or self._identity(current) != self._directory_identity):
            raise ApprovalRefused("bootstrap overlay journal directory changed")
        return held

    def _check_entries(self, *, allowed_temp: str | None = None):
        names = set(os.listdir(self._directory_fd))
        allowed = {_JOURNAL_NAME}
        if allowed_temp is not None:
            allowed.add(allowed_temp)
        if not names <= allowed:
            raise ApprovalRefused("unexpected bootstrap overlay journal entry")

    def _read_current(self):
        self._check_directory()
        self._check_entries()
        try:
            fd = os.open(_JOURNAL_NAME, _READ_FLAGS, dir_fd=self._directory_fd)
        except OSError:
            raise ApprovalRefused("bootstrap overlay journal unavailable") from None
        try:
            raw, opened = _read_fd(fd, owner_uid=self._owner_uid)
            named = os.stat(_JOURNAL_NAME, dir_fd=self._directory_fd,
                            follow_symlinks=False)
            if _stamp(opened) != _stamp(named):
                raise ApprovalRefused("bootstrap overlay journal name changed")
            return decode_overlay_journal(raw), raw, opened
        finally:
            os.close(fd)

    def load(self) -> OverlayJournal:
        try:
            journal, _raw, _info = self._read_current()
            self._check_directory()
            return journal
        except ApprovalRefused:
            raise
        except OSError:
            raise ApprovalRefused("bootstrap overlay journal refused") from None

    def load_optional(self) -> OverlayJournal | None:
        """Observe a genuinely absent journal, never a malformed/unsafe record.

        This does not initialize ownership or prove a prior journal never
        existed. Callers must independently require an empty overlay and
        account for any retained grant transaction before treating it as an
        initial mask baseline.
        """
        try:
            self._check_directory()
            self._check_entries()
            try:
                os.stat(_JOURNAL_NAME, dir_fd=self._directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                self._check_directory()
                self._check_entries()
                try:
                    os.stat(_JOURNAL_NAME, dir_fd=self._directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    return None
                raise ApprovalRefused("bootstrap overlay journal appeared")
            return self.load()
        except OSError:
            raise ApprovalRefused("bootstrap optional journal observation refused") from None

    def create(self, journal: OverlayJournal) -> None:
        raw = encode_overlay_journal(journal)
        created = False
        try:
            self._check_directory()
            self._check_entries()
            fd = os.open(_JOURNAL_NAME, _WRITE_FLAGS, 0o600,
                         dir_fd=self._directory_fd)
            created = True
            try:
                _write_all(fd, raw)
                os.fsync(fd)
            finally:
                os.close(fd)
            current, current_raw, _info = self._read_current()
            if current != journal or current_raw != raw:
                raise ApprovalRefused("bootstrap overlay journal creation changed")
            try:
                os.fsync(self._directory_fd)
            except OSError:
                raise OverlayJournalDurabilityUncertain(
                    "bootstrap overlay journal creation durability uncertain"
                ) from None
            self._check_directory()
        except OverlayJournalDurabilityUncertain:
            raise
        except ApprovalRefused:
            if created:
                raise OverlayJournalDurabilityUncertain(
                    "bootstrap overlay journal creation outcome uncertain"
                ) from None
            raise
        except OSError:
            if created:
                raise OverlayJournalDurabilityUncertain(
                    "bootstrap overlay journal creation outcome uncertain"
                ) from None
            raise ApprovalRefused("bootstrap overlay journal create refused") from None

    def replace(self, expected: OverlayJournal, next_journal: OverlayJournal) -> None:
        expected_raw = encode_overlay_journal(expected)
        next_raw = encode_overlay_journal(next_journal)
        temp_name = f".overlay-journal.{secrets.token_hex(16)}.tmp"
        temp_fd = None
        temp_identity = None
        renamed = False
        try:
            self._check_directory()
            current, current_raw, current_info = self._read_current()
            if current != expected or current_raw != expected_raw:
                raise ApprovalRefused("bootstrap overlay journal compare-and-swap refused")
            self._check_entries(allowed_temp=None)
            temp_fd = os.open(temp_name, _WRITE_FLAGS, 0o600,
                              dir_fd=self._directory_fd)
            temp_identity = self._identity(os.fstat(temp_fd))
            _write_all(temp_fd, next_raw)
            os.fsync(temp_fd)
            temp_after = _file_info(temp_fd, owner_uid=self._owner_uid)
            if temp_after.st_size != len(next_raw):
                raise ApprovalRefused("bootstrap overlay journal temporary changed")
            named = os.stat(_JOURNAL_NAME, dir_fd=self._directory_fd,
                            follow_symlinks=False)
            if _stamp(named) != _stamp(current_info):
                raise ApprovalRefused("bootstrap overlay journal changed before replace")
            self._check_entries(allowed_temp=temp_name)
            self._check_directory()
            os.replace(temp_name, _JOURNAL_NAME,
                       src_dir_fd=self._directory_fd, dst_dir_fd=self._directory_fd)
            renamed = True
            if temp_fd is not None:
                descriptor, temp_fd = temp_fd, None
                try:
                    os.close(descriptor)
                except OSError:
                    raise OverlayJournalDurabilityUncertain(
                        "bootstrap overlay journal replacement close uncertain"
                    ) from None
            visible, visible_raw, _info = self._read_current()
            if visible != next_journal or visible_raw != next_raw:
                raise OverlayJournalDurabilityUncertain(
                    "bootstrap overlay journal replacement visibility uncertain"
                )
            try:
                os.fsync(self._directory_fd)
            except OSError:
                raise OverlayJournalDurabilityUncertain(
                    "bootstrap overlay journal replacement durability uncertain"
                ) from None
            self._check_directory()
        except (ApprovalRefused, OverlayJournalDurabilityUncertain) as exc:
            if renamed and not isinstance(exc, OverlayJournalDurabilityUncertain):
                raise OverlayJournalDurabilityUncertain(
                    "bootstrap overlay journal replacement outcome uncertain"
                ) from None
            raise
        except OSError:
            if renamed:
                raise OverlayJournalDurabilityUncertain(
                    "bootstrap overlay journal replacement outcome uncertain"
                ) from None
            raise ApprovalRefused("bootstrap overlay journal replacement refused") from None
        finally:
            if temp_fd is not None:
                descriptor, temp_fd = temp_fd, None
                try:
                    os.close(descriptor)
                except OSError:
                    # A failed close must not hide the transaction error or
                    # skip the inode-checked cleanup below.
                    pass
            if not renamed:
                try:
                    info = os.stat(temp_name, dir_fd=self._directory_fd,
                                   follow_symlinks=False)
                    if (self._identity(info) == temp_identity
                            and stat.S_ISREG(info.st_mode)
                            and info.st_uid == self._owner_uid
                            and stat.S_IMODE(info.st_mode) == 0o600
                            and info.st_nlink == 1):
                        os.unlink(temp_name, dir_fd=self._directory_fd)
                except OSError:
                    pass

    def remove(self, expected: OverlayJournal) -> None:
        expected_raw = encode_overlay_journal(expected)
        removed = False
        try:
            self._check_directory()
            current, raw, info = self._read_current()
            if current != expected or raw != expected_raw:
                raise ApprovalRefused("bootstrap overlay journal removal compare refused")
            named = os.stat(_JOURNAL_NAME, dir_fd=self._directory_fd,
                            follow_symlinks=False)
            if _stamp(named) != _stamp(info):
                raise ApprovalRefused("bootstrap overlay journal changed before removal")
            self._check_directory()
            os.unlink(_JOURNAL_NAME, dir_fd=self._directory_fd)
            removed = True
            try:
                os.fsync(self._directory_fd)
            except OSError:
                raise OverlayJournalDurabilityUncertain(
                    "bootstrap overlay journal removal durability uncertain"
                ) from None
            self._check_directory()
        except (ApprovalRefused, OverlayJournalDurabilityUncertain) as exc:
            if removed and not isinstance(exc, OverlayJournalDurabilityUncertain):
                raise OverlayJournalDurabilityUncertain(
                    "bootstrap overlay journal removal outcome uncertain"
                ) from None
            raise
        except OSError:
            if removed:
                raise OverlayJournalDurabilityUncertain(
                    "bootstrap overlay journal removal outcome uncertain"
                ) from None
            raise ApprovalRefused("bootstrap overlay journal removal refused") from None


@dataclass(frozen=True)
class OverlayIntent:
    """Immutable identity and exact expected bytes for one boot's candidate."""

    boot_id: str
    context_digest: str
    grant_id: str
    payload_digests: tuple[tuple[str, str], ...]

    def __post_init__(self):
        try:
            if (type(self.boot_id) is not str
                    or str(uuid.UUID(self.boot_id)) != self.boot_id):
                raise ValueError
            if (type(self.context_digest) is not str
                    or not _HEX.fullmatch(self.context_digest)
                    or type(self.grant_id) is not str
                    or not _GRANT.fullmatch(self.grant_id)
                    or type(self.payload_digests) is not tuple
                    or len(self.payload_digests) != 2
                    or tuple(name for name, _digest in self.payload_digests) != _UNITS
                    or any(type(digest) is not str or not _HEX.fullmatch(digest)
                           for _name, digest in self.payload_digests)):
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise ApprovalRefused("bootstrap overlay intent malformed") from None


@dataclass(frozen=True)
class OverlayStopEvidence:
    """Typed result required before a pending file withdrawal may be recorded."""

    start_fence_closed: bool
    stopped_pair: tuple[str, ...]
    inactive_pair: tuple[str, ...]
    withdrawn_pair: tuple[str, ...]
    persistent_masks_restored: bool
    loaded_masks_confirmed: bool

    def __post_init__(self):
        if (type(self.start_fence_closed) is not bool
                or self.start_fence_closed is not True
                or type(self.persistent_masks_restored) is not bool
                or self.persistent_masks_restored is not True
                or type(self.loaded_masks_confirmed) is not bool
                or self.loaded_masks_confirmed is not True
                or any(type(pair) is not tuple or pair != _UNITS for pair in
                       (self.stopped_pair, self.inactive_pair, self.withdrawn_pair))):
            raise ApprovalRefused("bootstrap overlay withdrawal evidence incomplete")


@dataclass(frozen=True)
class OverlayJournal:
    """Validated transition record; phase never grants permission by itself."""

    intent: OverlayIntent
    phase: str
    owned_files: tuple[tuple[str, int, int, str], ...] = ()

    def __post_init__(self):
        if (type(self.intent) is not OverlayIntent or type(self.phase) is not str
                or self.phase not in {
                    "intent", "partial", "published", "closing", "withdrawing", "closed",
                }):
            raise ApprovalRefused("bootstrap overlay journal state refused")
        expected = dict(self.intent.payload_digests)
        if type(self.owned_files) is not tuple or len(self.owned_files) > 2:
            raise ApprovalRefused("bootstrap overlay ownership record refused")
        names = []
        for item in self.owned_files:
            if (type(item) is not tuple or len(item) != 4):
                raise ApprovalRefused("bootstrap overlay ownership record refused")
            name, device, inode, digest = item
            if (name not in _UNITS or name in names
                    or type(device) is not int or not 0 <= device < 2**64
                    or type(inode) is not int or not 0 < inode < 2**64
                    or type(digest) is not str or digest != expected[name]):
                raise ApprovalRefused("bootstrap overlay file identity refused")
            names.append(name)
        ordered = tuple(sorted(names, key=_UNITS.index))
        if tuple(names) != ordered:
            raise ApprovalRefused("bootstrap overlay ownership order refused")
        identities = {(device, inode) for _name, device, inode, _digest in self.owned_files}
        if len(identities) != len(self.owned_files):
            raise ApprovalRefused("bootstrap overlay files share an identity")
        if (self.phase == "intent" and self.owned_files
                or self.phase == "partial" and len(self.owned_files) != 1
                or self.phase == "published" and len(self.owned_files) != 2
                or self.phase == "closed" and self.owned_files):
            raise ApprovalRefused("bootstrap overlay phase disagrees with ownership")


def new_overlay_journal(intent: OverlayIntent) -> OverlayJournal:
    if type(intent) is not OverlayIntent:
        raise ApprovalRefused("bootstrap overlay intent required")
    return OverlayJournal(intent, "intent")


def advance_overlay(journal: OverlayJournal, action: str, *,
                    unit: str | None = None, device: int | None = None,
                    inode: int | None = None, evidence=None) -> OverlayJournal:
    """Validate one ordered update; callers persist it atomically and fsync.

    The caller must write and fsync the intent before `create-file`, then write
    and fsync this result after successful O_EXCL creation/stat. A crash in the
    gap is intentionally ambiguous and cannot be repaired by digest matching.
    """
    if type(journal) is not OverlayJournal or type(action) is not str:
        raise ApprovalRefused("bootstrap overlay journal/action required")
    if action == "create-file":
        if (journal.phase not in {"intent", "partial"}
                or type(unit) is not str or unit not in _UNITS
                or any(item[0] == unit for item in journal.owned_files)
                or type(device) is not int or not 0 <= device < 2**64
                or type(inode) is not int or not 0 < inode < 2**64):
            raise ApprovalRefused("bootstrap overlay creation transition refused")
        files = tuple(sorted((*journal.owned_files,
                              (unit, device, inode,
                               dict(journal.intent.payload_digests)[unit])),
                             key=lambda item: _UNITS.index(item[0])))
        phase = "published" if len(files) == 2 else "partial"
        return OverlayJournal(journal.intent, phase, files)
    if action == "close-starts":
        if journal.phase not in {"intent", "partial", "published"}:
            raise ApprovalRefused("bootstrap overlay close transition refused")
        # Closing is durable intent, not a loaded start fence. A file adapter
        # must also verify every unowned pair path is absent before mutation.
        # This permits narrowing an interrupted publication without adopting
        # an unjournaled file, even when its bytes happen to match.
        return OverlayJournal(journal.intent, "closing", journal.owned_files)
    if action == "begin-withdrawal":
        if journal.phase != "closing":
            raise ApprovalRefused("bootstrap overlay withdrawal intent refused")
        return OverlayJournal(journal.intent, "withdrawing", journal.owned_files)
    if action == "withdraw":
        if journal.phase != "withdrawing" or type(evidence) is not OverlayStopEvidence:
            raise ApprovalRefused("bootstrap overlay withdrawal transition refused")
        # The files have been removed and the effective persistent masks
        # independently confirmed. Journal removal is a separate fsynced step.
        return OverlayJournal(journal.intent, "closed")
    raise ApprovalRefused("bootstrap overlay journal action refused")


def encode_overlay_journal(journal: OverlayJournal) -> bytes:
    if type(journal) is not OverlayJournal:
        raise ApprovalRefused("bootstrap overlay journal required")
    value = {
        "schema": _SCHEMA,
        "boot_id": journal.intent.boot_id,
        "context_digest": journal.intent.context_digest,
        "grant_id": journal.intent.grant_id,
        "payload_digests": dict(journal.intent.payload_digests),
        "phase": journal.phase,
        "owned_files": [
            {"unit": unit, "device": device, "inode": inode, "sha256": digest}
            for unit, device, inode, digest in journal.owned_files
        ],
    }
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def decode_overlay_journal(raw: bytes) -> OverlayJournal:
    """Strict canonical decoder; never infer a missing owner from file bytes."""
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 4096 or not raw.endswith(b"\n"):
            raise ValueError

        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        value = json.loads(raw, object_pairs_hook=pairs)
        expected = {"schema", "boot_id", "context_digest", "grant_id",
                    "payload_digests", "phase", "owned_files"}
        if type(value) is not dict or set(value) != expected or value["schema"] != _SCHEMA:
            raise ValueError
        digests = value["payload_digests"]
        if type(digests) is not dict or tuple(sorted(digests)) != tuple(sorted(_UNITS)):
            raise ValueError
        intent = OverlayIntent(
            value["boot_id"], value["context_digest"], value["grant_id"],
            tuple((unit, digests[unit]) for unit in _UNITS),
        )
        raw_files = value["owned_files"]
        if type(raw_files) is not list:
            raise ValueError
        files = tuple((item["unit"], item["device"], item["inode"], item["sha256"])
                      for item in raw_files if type(item) is dict and set(item) == {
                          "unit", "device", "inode", "sha256"
                      })
        if len(files) != len(raw_files):
            raise ValueError
        journal = OverlayJournal(intent, value["phase"], files)
        if encode_overlay_journal(journal) != raw:
            raise ValueError
        return journal
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise ApprovalRefused("bootstrap overlay journal refused") from None
