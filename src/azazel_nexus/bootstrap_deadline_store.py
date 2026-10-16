"""Fail-closed retained bootstrap deadlines, not admission or activation.

Only an independently admitted controller may initialize this store. Neither
missing state nor an unfinished transaction is a reason to initialize again.
Local files are not an independent rollback anchor. The bootstrap entrypoint
composes this store; private descriptor seams exist for ordinary-file tests.
"""

from contextlib import contextmanager
import fcntl
import json
import os

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
_FIELDS = ("admitted_at", "admitted_boottime_ns", "deadline_boottime_ns",
           "last_utc", "last_boottime_ns")


def _encode(state: BootstrapDeadline) -> bytes:
    if type(state) is not BootstrapDeadline:
        raise ApprovalRefused("retained deadline value required")
    document = {name: getattr(state, name) for name in _FIELDS}
    document.update(schema="azazel-nexus/bootstrap-deadline/v1",
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


def _retain_initial_at(fd: int, state: BootstrapDeadline, *, owner: int) -> BootstrapDeadline:
    """No overwrites, even when a previous initialization was incomplete."""
    raw = _encode(state)
    if (state.last_utc, state.last_boottime_ns) != (state.admitted_at, state.admitted_boottime_ns):
        raise ApprovalRefused("initial deadline must be its admission observation")
    with _locked(fd, owner=owner):
        if _exists(fd, _INITIAL) or _exists(fd, _CURRENT):
            raise ApprovalRefused("bootstrap deadline was already initialized")
        _begin_transaction(fd)
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


def retain_initial_deadline(state: BootstrapDeadline) -> BootstrapDeadline:
    """Persist before first start; does not establish eligibility to start."""
    try:
        with _state_directory() as fd:
            return _retain_initial_at(fd, state, owner=0)
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
