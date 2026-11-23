"""The remote opt-in store: written only by an operator, withdrawn by generation.

`docs/mio-route-policy.md` §2 ("Opt-in is revocable"). Before this module the
entry service read the constant `NO_OPT_IN` on every selection and recheck,
so a withdrawal had nowhere to be recorded and nothing to be reflected in.
This is the one place a remote opt-in lives on the node.

## One record, one counter

`remote-consent/opt-in.json` under entryd's own state leaf
(`/var/lib/azazel/state/mio`, `azmioentry`, `0700`) holds one canonical
record: which of the four prerequisites (`mio_profile.PREREQUISITES`) the
operator explicitly set, who and when, whether it was withdrawn and why, and
a **generation**. Every change -- setting a prerequisite or withdrawing --
writes the next generation (so does `confirm`, below). Nothing lowers it
and there is no reset verb.

The generation is what a send is bound to. The sanitizer boundary puts the
generation it read into the signed envelope (`remote_envelope`), and
`mio_remoted` compares it with the generation in force immediately before
the transport, under the send gate below. A withdrawal moves the generation,
so an envelope minted before it never matches again -- not after a
re-grant, which moves it once more.

## A grant is pending until its audit record is confirmed

`set_prerequisite` writes the record that completes the four prerequisites
with `pending: true` (the key exists only then; older records decode
unchanged). Its reading is `unconfirmed` and `permits` is False, for the
recheck and for the send gate alike, so no sender can use a grant whose audit
record is not yet known to be written. Only `confirm(generation)` -- which
entryd calls after the record is written -- writes the next generation without
`pending`. A crash anywhere before it leaves the pending record on disk, which
stays closed after a restart. `withdraw` over a pending record writes a
withdrawn record without `pending`, and a later set starts from the empty
set: the unrecorded prerequisite is never carried over. Only the completing
set is pending; an incomplete set grants nothing, so it has nothing to close.

## Written only through the operator verbs

The only writer is `mio_entryd`'s `mio.remote.opt_in.set` /
`mio.remote.opt_in.withdraw`, admitted to the `OPERATOR` principal class
alone (the kernel-reported operator group, not `SERVICE`, not the explainer's
advice listener). There is no file, flag or environment variable that grants
an opt-in, and absence of the record is `NO_OPT_IN`.

## Fail-closed reading

`reading()` never raises. Absent is `NO_OPT_IN` at generation 0. A pending
record reads `unconfirmed`, which is also `NO_OPT_IN`. A record
that is malformed, not canonical, oversized, linked, mis-owned, group or
other accessible, changing while read, or **lower than a generation this
process has already seen** (including absent after present: a rolled-back or
deleted store) is `unavailable`, which is also `NO_OPT_IN`.

The in-process high-water catches a store rolled back under a running
daemon. Across a restart the record itself is the floor: like
`activation_high_water`, this is local trust, and root replacing the file is
out of its reach.

## The send gate

A withdrawal is *confirmed* when `withdraw` returns. Two steps make that
mean "no send passes after this":

1. the withdrawn record is committed (private temporary file, fsync, rename,
   directory fsync, read back) without waiting for any sender, so every
   check that starts after it reads the new generation;
2. it then takes the gate file exclusively, which waits for each sender that
   read the old generation before step 1 and is still inside its transport
   call (a sender holds the gate shared from its check until the transport
   returns). Only then does it return.

A sender that finds the gate held exclusively refuses rather than waits.
The drain is bounded (`DRAIN_TIMEOUT_S`, above the longest request
deadline); if it ever expires the withdrawal stands and the reply says the
drain was not confirmed. This build has no transport, so nothing holds the
gate in production.

Entryd opens a grant under two further guards:

* **The seal** (`send.seal`, `seal()` / `unseal()`): entryd durably seals the
  generation `confirm` will write, before it confirms. A record at or below the
  sealed generation reads `unconfirmed` (closed) in `reading()` and
  `send_gate()`; a seal that exists but cannot be read or decoded reads
  `unavailable`; no seal reads as before. So a refusal stays true if entryd
  ends at any point after the seal.
* **The exclusive gate** (`hold_gate_exclusive`, bounded): taken after
  `confirm`, held while the seal is removed and the grant read back as open.
  A sender inside its transport holds the gate shared, so the exclusive hold
  waits for it; a sender that arrives meanwhile refuses `unavailable`.

When the seal's removal or the read back cannot be confirmed, a read is no
ground (a record that reads closed may be a rename whose directory sync
failed). Entryd closes by a confirmed write under the gate: `withdraw`
(`drain=False`: it holds the gate itself or the generation is sealed, so the
drain counts as confirmed) -- `_write_at` fsyncs the file and the directory and
reads back, or raises -- else a re-seal. A refusal is returned, and the gate
released, only after one of them returned (or while the seal is provably still
in place). Otherwise the grant is *unsettled*: it is not a refusal; the audited
generation may already be in force, entryd keeps the gate (sends refuse while it
runs) and names `may_be_in_force_generation`. Remaining limit: if entryd ends
in that state, or after the seal's removal and before its reply is written, the
OS drops the `flock` and that generation can be sent on.
Nothing here infers a grant from an unreadable store.

## Separate from Knowledge

This is consent to route a sanitised question to an online AI provider.
It is not, and does not read, the Knowledge peer authorisation
(`knowledge_peer`, `knowledge-peer.md`); neither store grants the other.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
import fcntl
import json
import os
from pathlib import Path
import stat
import threading
import time
from typing import Callable, Iterator, Optional

from azazel_nexus.mio_profile import (
    NO_OPT_IN,
    PREREQUISITES,
    RemoteOptIn,
    RemotePrerequisite,
    Withdrawal,
)

__all__ = [
    "ConsentReading",
    "ConsentRecord",
    "ConsentRefused",
    "ConsentStore",
    "DRAIN_TIMEOUT_S",
    "GateHold",
    "SEAL_FILENAME",
    "LEAF",
    "RECORD_FILENAME",
    "SCHEMA",
    "WITHDRAWAL_REASONS",
    "INTERNAL_WITHDRAWAL_REASONS",
    "decode_record",
    "encode_record",
]

SCHEMA = "azazel-nexus/mio-remote-opt-in/v1"
LEAF = "remote-consent"
RECORD_FILENAME = "opt-in.json"
GATE_FILENAME = "send.gate"
SEAL_FILENAME = "send.seal"
SEAL_SCHEMA = "azazel-nexus/mio-remote-opt-in-seal/v1"
_SEAL_PARTIAL = ".send.seal.partial"
_PARTIAL = ".opt-in.json.partial"
_LIMIT = 4096
_MAX_GENERATION = 2**63 - 1
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
#: Longer than the longest request deadline entryd accepts (60 s), so a
#: sender inside its transport call has finished before the drain gives up.
DRAIN_TIMEOUT_S = 65.0
_DRAIN_POLL_S = 0.005

#: Why an operator withdrew. A fixed vocabulary: the protocol has no free-text
#: argument, and a withdrawal records a reason (`mio_profile.Withdrawal`).
WITHDRAWAL_REASONS = (
    "operator_request",
    "privacy_review",
    "provider_change",
    "incident_response",
)
#: Reasons only entryd itself records (never an operator verb argument): the
#: automatic withdrawal of a grant whose record could not be written, or
#: whose confirmation failed (possibly after it was already published).
INTERNAL_WITHDRAWAL_REASONS = ("audit_record_failed", "opt_in_not_confirmed")


class ConsentRefused(Exception):
    """The store is unavailable, malformed, rolled back, or busy."""


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class ConsentRecord:
    generation: int
    granted: tuple[str, ...]
    operator: str
    at: str
    withdrawn: Optional[tuple[str, str, str]] = None  # operator, at, reason
    pending: bool = False

    def __post_init__(self) -> None:
        if type(self.generation) is not int or not 1 <= self.generation <= _MAX_GENERATION:
            raise ConsentRefused("generation must be a bounded positive integer")
        values = [p.value for p in PREREQUISITES]
        if (type(self.granted) is not tuple
                or any(v not in values for v in self.granted)
                or list(self.granted) != sorted(set(self.granted), key=values.index)):
            raise ConsentRefused("granted must be known prerequisites in asking order")
        for text in (self.operator, self.at):
            if type(text) is not str or not text.strip() or len(text) > 64:
                raise ConsentRefused("operator and time are bounded non-empty text")
        if type(self.pending) is not bool:
            raise ConsentRefused("pending is a boolean")
        if self.pending and self.withdrawn is not None:
            raise ConsentRefused("a withdrawn record is not pending")
        if self.withdrawn is not None:
            if (type(self.withdrawn) is not tuple or len(self.withdrawn) != 3
                    or any(type(v) is not str or not v.strip() or len(v) > 64
                           for v in self.withdrawn)
                    or self.withdrawn[2] not in WITHDRAWAL_REASONS + INTERNAL_WITHDRAWAL_REASONS):
                raise ConsentRefused("a withdrawal records operator, time and a known reason")

    def opt_in(self) -> RemoteOptIn:
        withdrawn = None
        if self.withdrawn is not None:
            withdrawn = Withdrawal(*self.withdrawn)
        return RemoteOptIn(
            granted=frozenset(RemotePrerequisite(v) for v in self.granted),
            operator=self.operator, at=self.at, withdrawn=withdrawn,
        )


def encode_record(record: ConsentRecord) -> bytes:
    if type(record) is not ConsentRecord:
        raise ConsentRefused("a consent record is required")
    withdrawn = None
    if record.withdrawn is not None:
        operator, at, reason = record.withdrawn
        withdrawn = {"operator": operator, "at": at, "reason": reason}
    document = {
        "schema": SCHEMA, "generation": record.generation,
        "granted": list(record.granted), "operator": record.operator,
        "at": record.at, "withdrawn": withdrawn,
    }
    if record.pending:
        # Only a pending record carries the key, so every record written
        # before it existed still decodes, and encodes, unchanged.
        document["pending"] = True
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


_FIELDS = {"schema", "generation", "granted", "operator", "at", "withdrawn"}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConsentRefused("duplicate field")
        result[key] = value
    return result


def decode_record(raw: bytes) -> ConsentRecord:
    """Exactly one canonical record, or a refusal. Never repaired."""
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= _LIMIT:
            raise ConsentRefused("size")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
        if (type(document) is not dict
                or set(document) not in (_FIELDS, _FIELDS | {"pending"})
                or document["schema"] != SCHEMA
                or type(document["granted"]) is not list):
            raise ConsentRefused("fields")
        if "pending" in document and document["pending"] is not True:
            raise ConsentRefused("pending is present only as true")
        withdrawn = document["withdrawn"]
        if withdrawn is not None:
            if type(withdrawn) is not dict or set(withdrawn) != {"operator", "at", "reason"}:
                raise ConsentRefused("withdrawal fields")
            withdrawn = (withdrawn["operator"], withdrawn["at"], withdrawn["reason"])
        record = ConsentRecord(
            generation=document["generation"], granted=tuple(document["granted"]),
            operator=document["operator"], at=document["at"], withdrawn=withdrawn,
            pending="pending" in document,
        )
        if encode_record(record) != raw:
            raise ConsentRefused("not canonical")
        return record
    except Exception:
        raise ConsentRefused("opt-in record refused") from None


def encode_seal(generation: int) -> bytes:
    if type(generation) is not int or not 1 <= generation <= _MAX_GENERATION:
        raise ConsentRefused("a seal names a bounded positive generation")
    return json.dumps({"schema": SEAL_SCHEMA, "generation": generation},
                      sort_keys=True, separators=(",", ":")).encode()


def decode_seal(raw: bytes) -> int:
    """Exactly one canonical seal, or a refusal. Never repaired."""
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= _LIMIT:
            raise ConsentRefused("size")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
        if (type(document) is not dict or set(document) != {"schema", "generation"}
                or document["schema"] != SEAL_SCHEMA):
            raise ConsentRefused("fields")
        generation = document["generation"]
        if encode_seal(generation) != raw:
            raise ConsentRefused("not canonical")
        return generation
    except Exception:
        raise ConsentRefused("opt-in seal refused") from None


@dataclass(frozen=True)
class ConsentReading:
    """What a selection, a recheck or a send reads. Never an exception.

    `generation` is 0 for no record and `None` when the store could not be
    believed; both read as `NO_OPT_IN`.
    """

    opt_in: RemoteOptIn
    generation: Optional[int]
    status: str  # absent | incomplete | unconfirmed | granted | withdrawn | unavailable

    @property
    def permits(self) -> bool:
        return self.status == "granted" and self.opt_in.active()


_UNAVAILABLE = ConsentReading(NO_OPT_IN, None, "unavailable")
_ABSENT = ConsentReading(NO_OPT_IN, 0, "absent")


def _reading_of(record: ConsentRecord, sealed: Optional[int] = None) -> ConsentReading:
    """`sealed` is the generation entryd sealed while it opens a grant: a record
    at or below it is closed (`unconfirmed`) whatever it says."""
    opt_in = record.opt_in()
    if record.withdrawn is not None:
        status = "withdrawn"
    elif record.pending or (sealed is not None and record.generation <= sealed):
        status = "unconfirmed"
    elif opt_in.complete:
        status = "granted"
    else:
        status = "incomplete"
    return ConsentReading(opt_in, record.generation, status)


class GateHold:
    """An exclusive hold on the send gate, taken by entryd (the single writer).

    While it is held every sender in another process reads `unavailable` and
    refuses at once (it never waits). It is released by `release()` or, if the
    process ends, by the OS: the lock is on this open file description.
    """

    def __init__(self, fd: int) -> None:
        self._fd: Optional[int] = fd

    @property
    def held(self) -> bool:
        return self._fd is not None

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            os.close(fd)


class ConsentStore:
    """The single writer (entryd) and every reader of the opt-in record.

    `directory` is entryd's state leaf; it must be a real directory (not a
    link) owned by `owner` and not group or other writable. `owner` defaults
    to this process's effective uid: entryd owns the leaf, and any other
    reader must name `azmioentry` explicitly.
    """

    def __init__(
        self, directory: Path, *, owner: Optional[int] = None,
        clock: Callable[[], str] = _utc_now,
        monotonic: Callable[[], float] = time.monotonic,
        drain_timeout_s: float = DRAIN_TIMEOUT_S,
    ) -> None:
        self.directory = Path(directory)
        self.owner = os.geteuid() if owner is None else owner
        self._clock = clock
        self._monotonic = monotonic
        self._drain_timeout_s = drain_timeout_s
        #: Test seam only: called in `send_gate` right after the generation
        #: is read, while the gate is held. Lets a test commit a withdrawal
        #: between a sender's read and its transport, deterministically.
        self._after_send_read: Optional[Callable[[], None]] = None
        #: The highest generation this process has read or written. A lower
        #: one (or none) afterwards is a rolled-back store.
        self._seen = 0
        self._lock = threading.Lock()

    # -- filesystem ------------------------------------------------------

    def _protected(self, fd: int, *, directory: bool, private: bool) -> os.stat_result:
        info = os.fstat(fd)
        kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        mask = 0o077 if private else 0o022
        if (not kind or info.st_uid != self.owner or info.st_mode & mask
                or (not directory and info.st_nlink != 1)):
            raise ConsentRefused("opt-in storage protection refused")
        return info

    @contextmanager
    def _leaf(self, *, create: bool) -> Iterator[Optional[int]]:
        base = os.open(self.directory, _DIR_FLAGS)
        try:
            self._protected(base, directory=True, private=False)
            try:
                fd = os.open(LEAF, _DIR_FLAGS, dir_fd=base)
            except FileNotFoundError:
                if not create:
                    yield None
                    return
                os.mkdir(LEAF, 0o700, dir_fd=base)
                fd = os.open(LEAF, _DIR_FLAGS, dir_fd=base)
                os.fchmod(fd, 0o700)
                os.fsync(base)
            try:
                self._protected(fd, directory=True, private=True)
                yield fd
            finally:
                os.close(fd)
        finally:
            os.close(base)

    def _read_at(self, leaf: int) -> Optional[ConsentRecord]:
        """`None` only for a missing file; anything else a record or a refusal."""
        try:
            fd = os.open(RECORD_FILENAME,
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=leaf)
        except FileNotFoundError:
            return None
        try:
            before = self._protected(fd, directory=False, private=True)
            if not 0 < before.st_size <= _LIMIT:
                raise ConsentRefused("opt-in record size refused")
            chunks = bytearray()
            while len(chunks) <= _LIMIT:
                part = os.read(fd, _LIMIT + 1 - len(chunks))
                if not part:
                    break
                chunks.extend(part)
            after = self._protected(fd, directory=False, private=True)
            named = os.stat(RECORD_FILENAME, dir_fd=leaf, follow_symlinks=False)
            stamp = (before.st_dev, before.st_ino, before.st_size,
                     before.st_mtime_ns, before.st_ctime_ns)
            if (stamp != (after.st_dev, after.st_ino, after.st_size,
                          after.st_mtime_ns, after.st_ctime_ns)
                    or (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino)
                    or len(chunks) != before.st_size):
                raise ConsentRefused("opt-in record changed while reading")
            return decode_record(bytes(chunks))
        finally:
            os.close(fd)

    def _checked(self, record: Optional[ConsentRecord]) -> Optional[ConsentRecord]:
        """Refuse a generation below one this process already saw."""
        generation = 0 if record is None else record.generation
        if generation < self._seen:
            raise ConsentRefused("opt-in generation rolled back")
        self._seen = generation
        return record

    def _write_at(self, leaf: int, record: ConsentRecord) -> None:
        data = encode_record(record)
        try:
            stale = os.stat(_PARTIAL, dir_fd=leaf, follow_symlinks=False)
        except FileNotFoundError:
            stale = None
        if stale is not None:
            if not stat.S_ISREG(stale.st_mode):
                raise ConsentRefused("opt-in partial entry is not a regular file")
            os.unlink(_PARTIAL, dir_fd=leaf)
        fd = os.open(_PARTIAL,
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=leaf)
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(_PARTIAL, RECORD_FILENAME, src_dir_fd=leaf, dst_dir_fd=leaf)
        os.fsync(leaf)
        if self._read_at(leaf) != record:
            raise ConsentRefused("opt-in read-back differs")
        self._seen = record.generation

    def _gate_fd(self, leaf: int, *, create: bool) -> Optional[int]:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        try:
            fd = os.open(GATE_FILENAME, flags, dir_fd=leaf)
        except FileNotFoundError:
            if not create:
                return None
            fd = os.open(GATE_FILENAME, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=leaf)
            try:
                os.fchmod(fd, 0o600)
            except BaseException:
                os.close(fd)
                raise
        try:
            self._protected(fd, directory=False, private=True)
        except BaseException:
            os.close(fd)
            raise
        return fd

    # -- reading ---------------------------------------------------------

    def reading(self) -> ConsentReading:
        """The opt-in in force now. Fail-closed; never raises."""
        try:
            with self._lock, self._leaf(create=False) as leaf:
                record = None if leaf is None else self._read_at(leaf)
                record = self._checked(record)
                sealed = None if leaf is None else self._read_seal(leaf)
        except Exception:
            return _UNAVAILABLE
        return _ABSENT if record is None else _reading_of(record, sealed)

    @contextmanager
    def send_gate(self) -> Iterator[ConsentReading]:
        """Hold the gate shared from the check until the transport returns.

        Yields the reading taken under the gate. A gate held exclusively (a
        withdrawal draining) or any failure to take it yields `unavailable`
        rather than waiting.
        """
        reading, fd = _UNAVAILABLE, None
        try:
            with self._leaf(create=False) as leaf:
                if leaf is None:
                    reading = _ABSENT if self._seen == 0 else _UNAVAILABLE
                else:
                    fd = self._gate_fd(leaf, create=False)
                    if fd is not None:
                        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                        with self._lock:
                            record = self._checked(self._read_at(leaf))
                            sealed = self._read_seal(leaf)
                        if self._after_send_read is not None:
                            self._after_send_read()
                        reading = _ABSENT if record is None else _reading_of(record, sealed)
                    elif self._seen == 0 and self._read_at(leaf) is None:
                        reading = _ABSENT
        except Exception:
            reading = _UNAVAILABLE
            if fd is not None:
                os.close(fd)
                fd = None
        try:
            yield reading
        finally:
            if fd is not None:
                os.close(fd)  # releases the shared lock

    # -- writing (entryd's operator verbs only) ---------------------------

    def _change(self, make: Callable[[Optional[ConsentRecord], int], ConsentRecord],
                *, over_rollback: bool) -> ConsentRecord:
        with self._lock, self._leaf(create=True) as leaf:
            try:
                fcntl.flock(leaf, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise ConsentRefused("opt-in store is busy") from None
            current = self._read_at(leaf)
            generation = 0 if current is None else current.generation
            if generation < self._seen:
                if not over_rollback:
                    raise ConsentRefused("opt-in generation rolled back")
                generation = self._seen
            else:
                self._seen = generation
            if generation >= _MAX_GENERATION:
                # A grant can no longer move the generation, so it is refused.
                # A withdrawal is always possible: it is written at the same
                # (highest) generation, which is never a rollback, and a
                # withdrawn record permits nothing whatever its generation --
                # the send gate and the recheck both require a granted one.
                if not over_rollback:
                    raise ConsentRefused("opt-in generation exhausted")
                record = make(current, _MAX_GENERATION)
            else:
                record = make(current, generation + 1)
            fd = self._gate_fd(leaf, create=True)
            os.close(fd)
            self._write_at(leaf, record)
            return record

    def set_prerequisite(self, prerequisite: RemotePrerequisite, *, operator: str) -> ConsentRecord:
        """Record one prerequisite the operator explicitly set; next generation.

        After a withdrawal the set starts empty again: a withdrawn opt-in is
        not resumed by setting one of its four prerequisites. The same holds
        over a pending record: the unrecorded prerequisite is not carried.
        A set that completes the four is written pending (`confirm`).
        """
        if type(prerequisite) is not RemotePrerequisite:
            raise ConsentRefused("a known prerequisite is required")

        def make(current, generation):
            granted = set()
            if current is not None and current.withdrawn is None and not current.pending:
                granted = set(current.granted)
            granted.add(prerequisite.value)
            order = [p.value for p in PREREQUISITES]
            return ConsentRecord(generation=generation,
                                 granted=tuple(sorted(granted, key=order.index)),
                                 operator=operator, at=self._clock(),
                                 pending=len(granted) == len(order))

        return self._change(make, over_rollback=False)

    def confirm(self, generation: int, *, operator: str) -> ConsentRecord:
        """Open a pending grant once its record is confirmed; next generation.

        Succeeds only if the record in force is exactly `generation`, pending
        and not withdrawn. The written record has the same granted set, the
        confirming operator and time, and no `pending`. Anything else (moved,
        withdrawn, already confirmed, generation exhausted, busy, unreadable)
        is `ConsentRefused` and the store is left as it was: a pending record
        stays closed.
        """
        if type(generation) is not int:
            raise ConsentRefused("a generation is required")

        def make(current, next_generation):
            if (current is None or current.generation != generation
                    or not current.pending or current.withdrawn is not None):
                raise ConsentRefused("no such pending grant to confirm")
            return ConsentRecord(generation=next_generation, granted=current.granted,
                                 operator=operator, at=self._clock())

        return self._change(make, over_rollback=False)

    def hold_gate_exclusive(self, timeout_s: float) -> GateHold:
        """Take the send gate exclusively, waiting at most `timeout_s`.

        Entryd takes it before it opens a grant (`confirm`) and keeps it until
        the grant is read back as open, or the store is read as closed. A
        sender holding the gate shared (inside its transport call) makes this
        wait; past the bound it raises `ConsentRefused` and holds nothing.
        """
        deadline = self._monotonic() + timeout_s
        fd = None
        try:
            with self._leaf(create=True) as leaf:
                fd = self._gate_fd(leaf, create=True)
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    held, fd = GateHold(fd), None
                    return held
                except OSError:
                    if self._monotonic() >= deadline:
                        raise ConsentRefused("send gate is busy") from None
                    time.sleep(_DRAIN_POLL_S)
        finally:
            if fd is not None:
                os.close(fd)

    # -- the seal (entryd only) -------------------------------------------

    def _read_seal(self, leaf: int) -> Optional[int]:
        """`None` only for a missing file; anything else a generation or a refusal."""
        try:
            fd = os.open(SEAL_FILENAME,
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=leaf)
        except FileNotFoundError:
            return None
        try:
            info = self._protected(fd, directory=False, private=True)
            if not 0 < info.st_size <= _LIMIT:
                raise ConsentRefused("opt-in seal size refused")
            data = os.read(fd, _LIMIT + 1)
            if len(data) != info.st_size:
                raise ConsentRefused("opt-in seal changed while reading")
            return decode_seal(data)
        finally:
            os.close(fd)

    def seal(self, generation: int) -> None:
        """Durably close every record at or below `generation` (written like a
        record: private temporary file, fsync, rename, directory fsync, read
        back). Raises `ConsentRefused` or `OSError` if that is not confirmed."""
        data = encode_seal(generation)
        with self._lock, self._leaf(create=True) as leaf:
            try:
                stale = os.stat(_SEAL_PARTIAL, dir_fd=leaf, follow_symlinks=False)
            except FileNotFoundError:
                stale = None
            if stale is not None:
                if not stat.S_ISREG(stale.st_mode):
                    raise ConsentRefused("opt-in seal partial entry is not a regular file")
                os.unlink(_SEAL_PARTIAL, dir_fd=leaf)
            fd = os.open(_SEAL_PARTIAL,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=leaf)
            try:
                os.fchmod(fd, 0o600)
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(_SEAL_PARTIAL, SEAL_FILENAME, src_dir_fd=leaf, dst_dir_fd=leaf)
            os.fsync(leaf)
            if self._read_seal(leaf) != generation:
                raise ConsentRefused("opt-in seal read-back differs")

    def unseal(self) -> None:
        """Remove the seal and read that it is gone, or raise. Called only
        under the exclusive send gate, on the success path."""
        with self._lock, self._leaf(create=False) as leaf:
            if leaf is None:
                return
            try:
                os.unlink(SEAL_FILENAME, dir_fd=leaf)
            except FileNotFoundError:
                pass
            os.fsync(leaf)
            if self._read_seal(leaf) is not None:
                raise ConsentRefused("opt-in seal still present")

    def withdraw(self, reason: str, *, operator: str,
                 drain: bool = True) -> tuple[ConsentRecord, bool]:
        """Commit the withdrawal, then drain senders on the old generation.

        Returns the record and whether the drain was confirmed. Allowed over
        a store rolled back under this process (the withdrawal is written
        above the generation seen), never over one that cannot be read.

        `drain=False` is for the caller that holds the gate exclusively
        (`hold_gate_exclusive`) or that has sealed the generation: no sender
        can be in flight on it, so the drain is skipped and counts as
        confirmed (waiting would meet its own lock, or a sender it is not
        waiting on).
        """
        if reason not in WITHDRAWAL_REASONS + INTERNAL_WITHDRAWAL_REASONS:
            raise ConsentRefused("a known withdrawal reason is required")

        def make(current, generation):
            granted = () if current is None else current.granted
            at = self._clock()
            return ConsentRecord(generation=generation, granted=granted,
                                 operator=operator if current is None else current.operator,
                                 at=at if current is None else current.at,
                                 withdrawn=(operator, at, reason))

        record = self._change(make, over_rollback=True)
        return record, (self._drain() if drain else True)

    def _drain(self) -> bool:
        """Wait for senders that read the previous generation. Bounded."""
        deadline = self._monotonic() + self._drain_timeout_s
        with self._leaf(create=False) as leaf:
            fd = self._gate_fd(leaf, create=False)
            if fd is None:
                return True
            try:
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        return True
                    except OSError:
                        if self._monotonic() >= deadline:
                            return False
                        time.sleep(_DRAIN_POLL_S)
            finally:
                os.close(fd)
