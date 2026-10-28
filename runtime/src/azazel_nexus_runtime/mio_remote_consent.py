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
writes the next generation. Nothing lowers it and there is no reset verb.

The generation is what a send is bound to. The sanitizer boundary puts the
generation it read into the signed envelope (`remote_envelope`), and
`mio_remoted` compares it with the generation in force immediately before
the transport, under the send gate below. A withdrawal moves the generation,
so an envelope minted before it never matches again -- not after a
re-grant, which moves it once more.

## Written only through the operator verbs

The only writer is `mio_entryd`'s `mio.remote.opt_in.set` /
`mio.remote.opt_in.withdraw`, admitted to the `OPERATOR` principal class
alone (the kernel-reported operator group, not `SERVICE`, not the explainer's
advice listener). There is no file, flag or environment variable that grants
an opt-in, and absence of the record is `NO_OPT_IN`.

## Fail-closed reading

`reading()` never raises. Absent is `NO_OPT_IN` at generation 0. A record
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
    "LEAF",
    "RECORD_FILENAME",
    "SCHEMA",
    "WITHDRAWAL_REASONS",
    "decode_record",
    "encode_record",
]

SCHEMA = "azazel-nexus/mio-remote-opt-in/v1"
LEAF = "remote-consent"
RECORD_FILENAME = "opt-in.json"
GATE_FILENAME = "send.gate"
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
        if self.withdrawn is not None:
            if (type(self.withdrawn) is not tuple or len(self.withdrawn) != 3
                    or any(type(v) is not str or not v.strip() or len(v) > 64
                           for v in self.withdrawn)
                    or self.withdrawn[2] not in WITHDRAWAL_REASONS):
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
    return json.dumps({
        "schema": SCHEMA, "generation": record.generation,
        "granted": list(record.granted), "operator": record.operator,
        "at": record.at, "withdrawn": withdrawn,
    }, sort_keys=True, separators=(",", ":")).encode()


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
                or set(document) != {"schema", "generation", "granted", "operator",
                                     "at", "withdrawn"}
                or document["schema"] != SCHEMA
                or type(document["granted"]) is not list):
            raise ConsentRefused("fields")
        withdrawn = document["withdrawn"]
        if withdrawn is not None:
            if type(withdrawn) is not dict or set(withdrawn) != {"operator", "at", "reason"}:
                raise ConsentRefused("withdrawal fields")
            withdrawn = (withdrawn["operator"], withdrawn["at"], withdrawn["reason"])
        record = ConsentRecord(
            generation=document["generation"], granted=tuple(document["granted"]),
            operator=document["operator"], at=document["at"], withdrawn=withdrawn,
        )
        if encode_record(record) != raw:
            raise ConsentRefused("not canonical")
        return record
    except Exception:
        raise ConsentRefused("opt-in record refused") from None


@dataclass(frozen=True)
class ConsentReading:
    """What a selection, a recheck or a send reads. Never an exception.

    `generation` is 0 for no record and `None` when the store could not be
    believed; both read as `NO_OPT_IN`.
    """

    opt_in: RemoteOptIn
    generation: Optional[int]
    status: str  # absent | incomplete | granted | withdrawn | unavailable

    @property
    def permits(self) -> bool:
        return self.status == "granted" and self.opt_in.active()


_UNAVAILABLE = ConsentReading(NO_OPT_IN, None, "unavailable")
_ABSENT = ConsentReading(NO_OPT_IN, 0, "absent")


def _reading_of(record: ConsentRecord) -> ConsentReading:
    opt_in = record.opt_in()
    if record.withdrawn is not None:
        status = "withdrawn"
    elif opt_in.complete:
        status = "granted"
    else:
        status = "incomplete"
    return ConsentReading(opt_in, record.generation, status)


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
            os.fchmod(fd, 0o600)
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
        except Exception:
            return _UNAVAILABLE
        return _ABSENT if record is None else _reading_of(record)

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
                        reading = _ABSENT if record is None else _reading_of(record)
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
                raise ConsentRefused("opt-in generation exhausted")
            record = make(current, generation + 1)
            fd = self._gate_fd(leaf, create=True)
            os.close(fd)
            self._write_at(leaf, record)
            return record

    def set_prerequisite(self, prerequisite: RemotePrerequisite, *, operator: str) -> ConsentRecord:
        """Record one prerequisite the operator explicitly set; next generation.

        After a withdrawal the set starts empty again: a withdrawn opt-in is
        not resumed by setting one of its four prerequisites.
        """
        if type(prerequisite) is not RemotePrerequisite:
            raise ConsentRefused("a known prerequisite is required")

        def make(current, generation):
            granted = set()
            if current is not None and current.withdrawn is None:
                granted = set(current.granted)
            granted.add(prerequisite.value)
            order = [p.value for p in PREREQUISITES]
            return ConsentRecord(generation=generation,
                                 granted=tuple(sorted(granted, key=order.index)),
                                 operator=operator, at=self._clock())

        return self._change(make, over_rollback=False)

    def withdraw(self, reason: str, *, operator: str) -> tuple[ConsentRecord, bool]:
        """Commit the withdrawal, then drain senders on the old generation.

        Returns the record and whether the drain was confirmed. Allowed over
        a store rolled back under this process (the withdrawal is written
        above the generation seen), never over one that cannot be read.
        """
        if reason not in WITHDRAWAL_REASONS:
            raise ConsentRefused("a known withdrawal reason is required")

        def make(current, generation):
            granted = () if current is None else current.granted
            at = self._clock()
            return ConsentRecord(generation=generation, granted=granted,
                                 operator=operator if current is None else current.operator,
                                 at=at if current is None else current.at,
                                 withdrawn=(operator, at, reason))

        record = self._change(make, over_rollback=True)
        return record, self._drain()

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
