"""Fail-closed retained bootstrap deadlines, not admission or activation.

Only an independently admitted controller may initialize this store. Neither
missing state nor an unfinished transaction is a reason to initialize again.
Local files are not an independent rollback anchor. The bootstrap entrypoint
composes this store; private descriptor seams exist for ordinary-file tests.

A deadline retained by an earlier boot is not a reason to initialize either.
Only a first admission that already holds a freshly verified approval for the
current boot (and passed prestart) may move such a record aside, and only when
it provably belongs to another boot and another approval (Nexus#324). The
record is renamed into ``archive/`` on the same filesystem, never deleted, and
only after the caller's durable ledger record is confirmed. The current
boot's deadline is still never extended or replaced.
"""

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import re

from .activation_store import _private_directory, _read_file_at
from .bootstrap_approval import VerifiedBootstrapApproval
from .bootstrap_deadline import BootstrapDeadline, revalidate_deadline
from .operator_store import _protected, _unique_object
from .operator_trust import ApprovalRefused

_COMPONENTS = ("var", "lib", "azazel", "state", "bootstrap")
_LIMIT = 4096
_INITIAL = "initial.json"
_CURRENT = "checkpoint.json"
_PENDING = "transaction.pending"
_NEXT = "checkpoint.next"
_ARCHIVE = "archive"
_SCHEMA = "azazel-nexus/bootstrap-deadline/v1"
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FIELDS = ("admitted_at", "admitted_boottime_ns", "deadline_boottime_ns",
           "last_utc", "last_boottime_ns")


def _encode(state: BootstrapDeadline) -> bytes:
    if type(state) is not BootstrapDeadline:
        raise ApprovalRefused("retained deadline value required")
    document = {name: getattr(state, name) for name in _FIELDS}
    document.update(schema=_SCHEMA,
                    approval_digest=state.approval.payload_digest,
                    boot_id=state.approval.context.boot_id)
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > _LIMIT:
        raise ApprovalRefused("retained deadline exceeds bound")
    return raw


def _decode(raw: bytes, approval: VerifiedBootstrapApproval) -> BootstrapDeadline:
    if type(approval) is not VerifiedBootstrapApproval:
        raise ApprovalRefused("freshly verified bootstrap approval required")
    document = json.loads(raw, object_pairs_hook=_unique_object)
    if type(document) is not dict or set(document) != set(_FIELDS) | {
        "schema", "approval_digest", "boot_id"
    }:
        raise ApprovalRefused("invalid retained deadline fields")
    state = BootstrapDeadline(approval, **{name: document[name] for name in _FIELDS})
    if raw != _encode(state):
        raise ApprovalRefused("retained deadline binding or canonical form changed")
    return state


def _exists(fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _assert_clean(fd: int) -> None:
    if _exists(fd, _PENDING) or _exists(fd, _NEXT):
        raise ApprovalRefused("bootstrap state has an unfinished transaction")


@contextmanager
def _locked(fd: int, *, owner: int):
    _private_directory(fd, owner=owner)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        _assert_clean(fd)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)


def _write_new(fd: int, name: str, raw: bytes) -> None:
    output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=fd)
    try:
        remaining = memoryview(raw)
        while remaining:
            written = os.write(output, remaining)
            if written <= 0:
                raise OSError("retained deadline short write")
            remaining = remaining[written:]
        os.fsync(output)
    finally:
        os.close(output)


def _begin_transaction(fd: int) -> None:
    _write_new(fd, _PENDING, b"bootstrap transaction pending\n")
    os.fsync(fd)


def _finish_transaction(fd: int) -> None:
    os.fsync(fd)
    os.unlink(_PENDING, dir_fd=fd)
    os.fsync(fd)


def _read_state(fd: int, name: str, *, owner: int) -> bytes:
    return _read_file_at(fd, name, owner=owner, limit=_LIMIT)


def _initial_fields(state: BootstrapDeadline):
    return (state.approval, state.admitted_at, state.admitted_boottime_ns,
            state.deadline_boottime_ns)


def _prior_identity(raw: bytes) -> tuple[str, str]:
    """(boot id, approval digest) of a canonical record of any approval.

    Structure and canonical bytes only: the earlier approval is not
    re-verified (it cannot be; its boot is gone), so nothing here is trusted
    beyond deciding that the record is not the current boot's.
    """
    try:
        document = json.loads(raw, object_pairs_hook=_unique_object)
        canonical = (type(document) is dict and set(document) == set(_FIELDS) | {
            "schema", "approval_digest", "boot_id"
        } and json.dumps(document, sort_keys=True, separators=(",", ":")).encode() == raw)
    except Exception:
        canonical = False
    if not canonical or document["schema"] != _SCHEMA:
        raise ApprovalRefused("prior boot deadline is not canonical")
    boot_id, digest = document["boot_id"], document["approval_digest"]
    if (type(boot_id) is not str or not _UUID.fullmatch(boot_id)
            or type(digest) is not str or not _DIGEST.fullmatch(digest)
            or any(type(document[name]) is not str for name in ("admitted_at", "last_utc"))
            or any(type(document[name]) is not int or document[name] < 0 for name in (
                "admitted_boottime_ns", "deadline_boottime_ns", "last_boottime_ns"))):
        raise ApprovalRefused("prior boot deadline is not canonical")
    return boot_id, digest


def _archive_names(boot_id: str) -> tuple[str, str]:
    return f"initial-{boot_id}.json", f"checkpoint-{boot_id}.json"


def _open_archive(fd: int, *, owner: int, create: bool) -> int | None:
    """The private same-filesystem archive directory, or None when absent."""
    if create:
        try:
            os.mkdir(_ARCHIVE, 0o700, dir_fd=fd)
        except FileExistsError:
            pass
        else:
            os.fsync(fd)
    try:
        archive = os.open(_ARCHIVE, _DIR_FLAGS, dir_fd=fd)
    except FileNotFoundError:
        if create:
            raise ApprovalRefused("bootstrap archive unavailable") from None
        return None
    try:
        _private_directory(archive, owner=owner)
        if os.fstat(archive).st_dev != os.fstat(fd).st_dev:
            raise ApprovalRefused("bootstrap archive is not on the state filesystem")
    except BaseException:
        os.close(archive)
        raise
    return archive


def _prepare_archive(fd: int, names, *, owner: int) -> None:
    """Create and validate the archive before any record or marker.

    mkdir, privacy, filesystem and name collisions are checked here, outside
    the transaction, so a preventable failure never leaves
    `transaction.pending` behind (which would refuse until reviewed). The only
    change it can make is an empty private directory.
    """
    archive = _open_archive(fd, owner=owner, create=True)
    try:
        if any(_exists(archive, name) for name in names):
            raise ApprovalRefused("prior boot record already archived")
    finally:
        os.close(archive)


def _prior_boot_deadline(fd: int, state: BootstrapDeadline, *, owner: int) -> dict:
    """Prove the retained pair belongs to another boot and approval, or refuse.

    Called under the lock with no unfinished transaction. Same boot (also a
    soft reboot, which keeps the kernel boot id), a missing half, records
    that differ, a non-canonical record or the same approval digest refuse.
    """
    if not (_exists(fd, _INITIAL) and _exists(fd, _CURRENT)):
        raise ApprovalRefused("prior boot deadline is incomplete")
    initial_raw = _read_state(fd, _INITIAL, owner=owner)
    current_raw = _read_state(fd, _CURRENT, owner=owner)
    boot_id, digest = _prior_identity(initial_raw)
    if _prior_identity(current_raw) != (boot_id, digest):
        raise ApprovalRefused("prior boot deadline records differ")
    if boot_id == state.approval.context.boot_id:
        raise ApprovalRefused("bootstrap deadline was already initialized")
    if digest == state.approval.payload_digest:
        raise ApprovalRefused("prior boot deadline has the same approval")
    _prepare_archive(fd, _archive_names(boot_id), owner=owner)
    return {
        "boot_id": boot_id,
        "approval_digest": digest,
        "initial_sha256": hashlib.sha256(initial_raw).hexdigest(),
        "checkpoint_sha256": hashlib.sha256(current_raw).hexdigest(),
        "current_boot_id": state.approval.context.boot_id,
        "_raw": (initial_raw, current_raw),
    }


def _archive_prior_deadline(fd: int, prior: dict, *, owner: int) -> None:
    """Rename both records into the archive inside the open transaction."""
    raws = prior["_raw"]
    if (_read_state(fd, _INITIAL, owner=owner), _read_state(fd, _CURRENT, owner=owner)) != raws:
        raise ApprovalRefused("prior boot deadline changed before archive")
    archive = _open_archive(fd, owner=owner, create=False)
    if archive is None:
        raise ApprovalRefused("bootstrap archive unavailable")
    try:
        targets = _archive_names(prior["boot_id"])
        if any(_exists(archive, name) for name in targets):
            raise ApprovalRefused("prior boot record already archived")
        for source, target in zip((_INITIAL, _CURRENT), targets):
            os.rename(source, target, src_dir_fd=fd, dst_dir_fd=archive)
        os.fsync(archive)
        if tuple(_read_state(archive, name, owner=owner) for name in targets) != raws:
            raise ApprovalRefused("archived prior boot deadline changed")
    finally:
        os.close(archive)
    os.fsync(fd)


def _retain_initial_at(fd: int, state: BootstrapDeadline, *, owner: int,
                       record_prior_boot=None) -> BootstrapDeadline:
    """No overwrites, even when a previous initialization was incomplete.

    `record_prior_boot` is the caller's durable ledger append, called once
    with the retiring record's identity; anything other than ``True`` (or
    an exception) leaves every file as it was. Without it an existing record
    always refuses, as before.
    """
    raw = _encode(state)
    if (state.last_utc, state.last_boottime_ns) != (state.admitted_at, state.admitted_boottime_ns):
        raise ApprovalRefused("initial deadline must be its admission observation")
    with _locked(fd, owner=owner):
        prior = None
        if _exists(fd, _INITIAL) or _exists(fd, _CURRENT):
            if record_prior_boot is None:
                raise ApprovalRefused("bootstrap deadline was already initialized")
            prior = _prior_boot_deadline(fd, state, owner=owner)
            summary = {key: value for key, value in prior.items() if key != "_raw"}
            if record_prior_boot(summary) is not True:
                raise ApprovalRefused("prior boot deadline retirement record unconfirmed")
        _begin_transaction(fd)
        if prior is not None:
            _archive_prior_deadline(fd, prior, owner=owner)
        _write_new(fd, _INITIAL, raw)
        _write_new(fd, _CURRENT, raw)
        if any(_read_state(fd, name, owner=owner) != raw for name in (_INITIAL, _CURRENT)):
            raise ApprovalRefused("initial bootstrap state changed during publication")
        _finish_transaction(fd)
    return state


def _advance_at(fd: int, *, owner: int, approval: VerifiedBootstrapApproval,
                boot_id: str, now: str, boottime_ns: int,
                clock_trusted: bool) -> BootstrapDeadline:
    with _locked(fd, owner=owner):
        initial_raw = _read_state(fd, _INITIAL, owner=owner)
        previous_raw = _read_state(fd, _CURRENT, owner=owner)
        initial, previous = _decode(initial_raw, approval), _decode(previous_raw, approval)
        if _initial_fields(initial) != _initial_fields(previous) or (
            initial.last_utc, initial.last_boottime_ns
        ) != (initial.admitted_at, initial.admitted_boottime_ns):
            raise ApprovalRefused("original bootstrap deadline changed")
        advanced = revalidate_deadline(previous, approval=approval, boot_id=boot_id,
                                       now=now, boottime_ns=boottime_ns,
                                       clock_trusted=clock_trusted)
        raw = _encode(advanced)
        _begin_transaction(fd)
        _write_new(fd, _NEXT, raw)
        if (_read_state(fd, _INITIAL, owner=owner), _read_state(fd, _CURRENT, owner=owner)) != (
            initial_raw, previous_raw
        ):
            raise ApprovalRefused("bootstrap state changed during transaction")
        os.replace(_NEXT, _CURRENT, src_dir_fd=fd, dst_dir_fd=fd)
        if _read_state(fd, _CURRENT, owner=owner) != raw:
            raise ApprovalRefused("bootstrap checkpoint publication changed")
        _finish_transaction(fd)
    return advanced


def _open_directory() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for component in _COMPONENTS:
            _protected(fd, owner=0, directory=True)
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        _private_directory(fd, owner=0)
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def _state_directory():
    fd = _open_directory()
    try:
        original = os.fstat(fd)
        yield fd
        current_fd = _open_directory()
        try:
            current = os.fstat(current_fd)
            if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
                raise ApprovalRefused("bootstrap state directory replaced")
        finally:
            os.close(current_fd)
    finally:
        os.close(fd)


def retain_initial_deadline(state: BootstrapDeadline, *,
                            record_prior_boot=None) -> BootstrapDeadline:
    """Persist before first start; does not establish eligibility to start.

    `record_prior_boot` (the first-admission composition's ledger append) is
    what lets a provably earlier boot's record be archived; see
    `_retain_initial_at`. It is never an approval or a selection.
    """
    try:
        with _state_directory() as fd:
            return _retain_initial_at(fd, state, owner=0,
                                      record_prior_boot=record_prior_boot)
    except Exception:
        raise ApprovalRefused("protected bootstrap state refused") from None


def advance_deadline(*, approval: VerifiedBootstrapApproval, boot_id: str,
                     now: str, boottime_ns: int, clock_trusted: bool) -> BootstrapDeadline:
    """Persist a revalidated observation; absent state never creates a deadline."""
    try:
        with _state_directory() as fd:
            return _advance_at(fd, owner=0, approval=approval, boot_id=boot_id,
                               now=now, boottime_ns=boottime_ns, clock_trusted=clock_trusted)
    except Exception:
        raise ApprovalRefused("protected bootstrap state refused") from None
