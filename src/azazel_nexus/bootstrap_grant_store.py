"""Protected per-boot persistence for the exact bootstrap grant transaction.

The record is crash-recovery evidence, not authorization or an audit chain.
An unfinished marker, ambiguous durability result, or unknown boot-bound record
refuses; this module never repairs, resets, deletes, or opens a systemd grant.
`archive_prior` only renames another, finished boot's record into the
same-filesystem archive after a confirmed ledger record (Nexus#324).
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
import uuid
from contextlib import contextmanager

from .bootstrap_grant_transaction import (
    GrantTransaction,
    advance_transaction,
    decode_transaction,
    encode_transaction,
)
from .bootstrap_lock import BootstrapTransactionGuard
from .bootstrap_deadline_store import _exists, _open_archive, _state_directory
from .activation_store import _private_directory
from .operator_trust import ApprovalRefused

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_OWNER = 0
_MARKER = b"bootstrap grant transaction pending\n"
_LIMIT = 4096
_GRANT_NAME = re.compile(r"grant-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.json")


class GrantTransactionDurabilityUncertain(ApprovalRefused):
    """A grant transaction may be visible but its directory durability failed."""


def _filename(boot_id: str) -> str:
    try:
        if type(boot_id) is not str or str(uuid.UUID(boot_id)) != boot_id:
            raise ValueError
    except (ValueError, AttributeError):
        raise ApprovalRefused("canonical bootstrap boot identity required") from None
    return f"grant-{boot_id}.json"


def _stamp(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
        info.st_ctime_ns, info.st_mode, info.st_uid, info.st_nlink,
    )


def _write_all(fd: int, raw: bytes) -> None:
    remaining = memoryview(raw)
    while remaining:
        count = os.write(fd, remaining)
        if count <= 0:
            raise OSError("short bootstrap transaction write")
        remaining = remaining[count:]


def _write_new(directory_fd: int, name: str, raw: bytes, *, owner: int) -> None:
    fd = os.open(name, _CREATE, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ApprovalRefused("bootstrap transaction file attributes refused")
        _write_all(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)


def _read(directory_fd: int, name: str, *, owner: int) -> bytes:
    fd = os.open(name, _READ, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 0 < before.st_size <= _LIMIT):
            raise ApprovalRefused("bootstrap transaction file refused")
        chunks = bytearray()
        while len(chunks) <= _LIMIT:
            part = os.read(fd, min(8192, _LIMIT + 1 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (_stamp(before) != _stamp(after) or _stamp(after) != _stamp(named)
                or len(chunks) != before.st_size):
            raise ApprovalRefused("bootstrap transaction changed while reading")
        return bytes(chunks)
    finally:
        os.close(fd)


class GrantTransactionStore:
    """Descriptor-based create/CAS store; caller also holds the shared bootstrap lock."""

    def __init__(self, directory_fd: int, *, owner_uid: int, reopen):
        if (type(directory_fd) is not int or type(owner_uid) is not int
                or owner_uid < 0 or not callable(reopen)):
            raise ApprovalRefused("bootstrap transaction store configuration refused")
        try:
            self._fd = os.dup(directory_fd)
            self._owner = owner_uid
            self._reopen = reopen
            held = os.fstat(self._fd)
            _private_directory(self._fd, owner=owner_uid)
            self._identity = held.st_dev, held.st_ino
        except Exception:
            if getattr(self, "_fd", None) is not None:
                os.close(self._fd)
            raise ApprovalRefused("bootstrap transaction store unavailable") from None

    def close(self) -> None:
        fd = getattr(self, "_fd", None)
        if fd is not None:
            self._fd = None
            os.close(fd)

    def _check_directory(self) -> None:
        if self._fd is None:
            raise ApprovalRefused("bootstrap transaction store closed")
        _private_directory(self._fd, owner=self._owner)
        current = self._reopen()
        try:
            _private_directory(current, owner=self._owner)
            info = os.fstat(current)
            if (info.st_dev, info.st_ino) != self._identity:
                raise ApprovalRefused("bootstrap transaction directory changed")
        finally:
            os.close(current)

    @contextmanager
    def _locked(self, boot_id: str):
        name = _filename(boot_id)
        pending, next_name = f".{name}.pending", f".{name}.next"
        self._check_directory()
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ApprovalRefused("bootstrap transaction store busy") from None
        try:
            self._check_directory()
            for marker in (pending, next_name):
                try:
                    os.stat(marker, dir_fd=self._fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise ApprovalRefused("unfinished bootstrap transaction requires review")
            yield name, pending, next_name
        finally:
            fcntl.flock(self._fd, fcntl.LOCK_UN)

    def load_optional(self, *, boot_id: str) -> GrantTransaction | None:
        """Load this boot's record, distinguishing absence from ambiguity."""
        try:
            with self._locked(boot_id) as (name, _pending, _next):
                try:
                    os.stat(name, dir_fd=self._fd, follow_symlinks=False)
                except FileNotFoundError:
                    self._check_directory()
                    return None
                raw = _read(self._fd, name, owner=self._owner)
                journal = decode_transaction(raw)
                if journal.boot_id != boot_id:
                    raise ApprovalRefused("bootstrap transaction boot binding differs")
                self._check_directory()
                return journal
        except ApprovalRefused:
            raise
        except Exception:
            raise ApprovalRefused("bootstrap transaction unavailable") from None

    def load(self, *, boot_id: str) -> GrantTransaction:
        journal = self.load_optional(boot_id=boot_id)
        if journal is None:
            raise ApprovalRefused("bootstrap transaction unavailable")
        return journal

    def create(self, journal: GrantTransaction) -> None:
        if type(journal) is not GrantTransaction or journal.phase != "prepared":
            raise ApprovalRefused("prepared bootstrap transaction required")
        raw = encode_transaction(journal)
        try:
            with self._locked(journal.boot_id) as (name, pending, _next):
                try:
                    os.stat(name, dir_fd=self._fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ApprovalRefused("bootstrap transaction already exists")
                _write_new(self._fd, pending, _MARKER, owner=self._owner)
                try:
                    os.fsync(self._fd)
                except OSError:
                    raise GrantTransactionDurabilityUncertain(
                        "bootstrap transaction durability uncertain"
                    ) from None
                _write_new(self._fd, name, raw, owner=self._owner)
                if _read(self._fd, name, owner=self._owner) != raw:
                    raise ApprovalRefused("bootstrap transaction publication changed")
                # Make the transaction directory entry durable while the
                # refusing marker is still present.  If this sync fails, a
                # restart must observe the marker rather than mistake a lost
                # transaction name for an unused boot.
                try:
                    os.fsync(self._fd)
                except OSError:
                    raise GrantTransactionDurabilityUncertain(
                        "bootstrap transaction durability uncertain"
                    ) from None
                os.unlink(pending, dir_fd=self._fd)
                try:
                    os.fsync(self._fd)
                except OSError:
                    raise GrantTransactionDurabilityUncertain(
                        "bootstrap transaction durability uncertain"
                    ) from None
                self._check_directory()
        except (ApprovalRefused, GrantTransactionDurabilityUncertain):
            raise
        except Exception:
            raise ApprovalRefused("bootstrap transaction publication refused; inspect retained state") from None

    def advance(self, expected: GrantTransaction, action: str, *, evidence_digest=None) -> GrantTransaction:
        if type(expected) is not GrantTransaction:
            raise ApprovalRefused("bootstrap transaction compare value required")
        updated = advance_transaction(expected, action, evidence_digest=evidence_digest)
        raw = encode_transaction(updated)
        try:
            with self._locked(expected.boot_id) as (name, pending, next_name):
                current = _read(self._fd, name, owner=self._owner)
                if decode_transaction(current) != expected:
                    raise ApprovalRefused("bootstrap transaction compare-and-swap refused")
                _write_new(self._fd, pending, _MARKER, owner=self._owner)
                try:
                    os.fsync(self._fd)
                except OSError:
                    raise GrantTransactionDurabilityUncertain(
                        "bootstrap transaction durability uncertain"
                    ) from None
                _write_new(self._fd, next_name, raw, owner=self._owner)
                if _read(self._fd, name, owner=self._owner) != current:
                    raise ApprovalRefused("bootstrap transaction changed during update")
                if _read(self._fd, next_name, owner=self._owner) != raw:
                    raise ApprovalRefused("bootstrap transaction candidate changed")
                os.replace(next_name, name, src_dir_fd=self._fd, dst_dir_fd=self._fd)
                if _read(self._fd, name, owner=self._owner) != raw:
                    raise ApprovalRefused("bootstrap transaction replacement changed")
                try:
                    os.fsync(self._fd)
                except OSError:
                    raise GrantTransactionDurabilityUncertain(
                        "bootstrap transaction durability uncertain"
                    ) from None
                os.unlink(pending, dir_fd=self._fd)
                try:
                    os.fsync(self._fd)
                except OSError:
                    raise GrantTransactionDurabilityUncertain(
                        "bootstrap transaction durability uncertain"
                    ) from None
                self._check_directory()
                return updated
        except (ApprovalRefused, GrantTransactionDurabilityUncertain):
            raise
        except Exception:
            raise ApprovalRefused("bootstrap transaction update refused; inspect retained state") from None

    def _prior_candidates(self, current_boot_id: str, referenced_boot_id):
        """Other boots' finished records, each proven or skipped (never refused)."""
        found = []
        for entry in sorted(os.listdir(self._fd)):
            match = _GRANT_NAME.fullmatch(entry)
            if match is None:
                continue
            boot_id = match.group(1)
            if (boot_id in (current_boot_id, referenced_boot_id)
                    or _exists(self._fd, f".{entry}.pending")
                    or _exists(self._fd, f".{entry}.next")):
                continue
            try:
                raw = _read(self._fd, entry, owner=self._owner)
                journal = decode_transaction(raw)
            except Exception:
                continue  # Not provable: stays where it is.
            if journal.boot_id != boot_id:
                continue
            found.append((boot_id, entry, raw, journal.phase))
        return found

    def archive_prior(self, *, current_boot_id: str, referenced_boot_id, record) -> tuple[str, ...]:
        """Move earlier boots' grant records into ``archive/``; never delete.

        Only a ``grant-<boot>.json`` whose name is another boot than
        `current_boot_id` and than `referenced_boot_id` (the boot the retained
        overlay journal still names, or None), with no ``.pending``/``.next``
        marker, that decodes with the same boot id, is moved. Anything else
        is left in place. `record` (a durable ledger append) is called once
        with the identities before any rename and must return exactly True;
        otherwise nothing changes. Returns the archived boot ids.
        """
        _filename(current_boot_id)
        if referenced_boot_id is not None:
            _filename(referenced_boot_id)
        if not callable(record):
            raise ApprovalRefused("prior boot grant archive record required")
        try:
            return self._archive_prior_locked(current_boot_id, referenced_boot_id, record)
        except ApprovalRefused:
            raise
        except Exception:
            raise ApprovalRefused("prior boot grant archive refused") from None

    def _archive_prior_locked(self, current_boot_id, referenced_boot_id, record):
        self._check_directory()
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ApprovalRefused("bootstrap transaction store busy") from None
        try:
            self._check_directory()
            candidates = self._prior_candidates(current_boot_id, referenced_boot_id)
            archive = _open_archive(self._fd, owner=self._owner, create=False)
            if archive is not None:
                try:
                    candidates = [row for row in candidates if not _exists(archive, row[1])]
                finally:
                    os.close(archive)
            if not candidates:
                return ()
            summary = {
                "current_boot_id": current_boot_id,
                "grants": [{"boot_id": boot_id, "phase": phase,
                            "sha256": hashlib.sha256(raw).hexdigest()}
                           for boot_id, _name, raw, phase in candidates],
            }
            if record(summary) is not True:
                raise ApprovalRefused("prior boot grant archive record unconfirmed")
            archive = _open_archive(self._fd, owner=self._owner, create=True)
            try:
                for _boot, name, raw, _phase in candidates:
                    if _read(self._fd, name, owner=self._owner) != raw:
                        raise ApprovalRefused("prior boot grant changed before archive")
                    if _exists(archive, name):
                        raise ApprovalRefused("prior boot record already archived")
                    os.rename(name, name, src_dir_fd=self._fd, dst_dir_fd=archive)
                os.fsync(archive)
                if any(_read(archive, name, owner=self._owner) != raw
                       for _boot, name, raw, _phase in candidates):
                    raise ApprovalRefused("archived prior boot grant changed")
            finally:
                os.close(archive)
            os.fsync(self._fd)
            self._check_directory()
            return tuple(boot_id for boot_id, _name, _raw, _phase in candidates)
        finally:
            fcntl.flock(self._fd, fcntl.LOCK_UN)


@contextmanager
def grant_transaction_store_in_transaction(guard: BootstrapTransactionGuard):
    """Open only the fixed protected state directory under the supervisor lock."""
    if type(guard) is not BootstrapTransactionGuard:
        raise ApprovalRefused("held bootstrap transaction guard required")
    guard()
    with _state_directory() as directory_fd:
        store = GrantTransactionStore(
            directory_fd,
            owner_uid=_OWNER,
            reopen=lambda: os.open("/var/lib/azazel/state/bootstrap", _DIR),
        )
        try:
            yield store
        finally:
            try:
                guard()
            finally:
                store.close()
