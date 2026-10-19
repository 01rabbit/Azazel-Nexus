"""An append-only hash chain, and a refusal to continue a broken one (#27).

`docs/IMPLEMENTATION_SPEC.md` §6.4 divides this cleanly: **Fabric defines the
audit event envelope and its canonical bytes; Nexus owns chain enforcement.**
Whether a chain is continuous, anchored, or broken is a product-local trust
decision, and the specification says Fabric MUST NOT make it.

So the chaining here is Nexus-local and uses the standard library only. That
is not a shortcut around the boundary — it is the boundary. The CORE path must
work with nothing installed (ADR-0001), and a ledger that could not be written
without an optional extra would be a ledger that stops existing exactly when a
node is least able to explain itself. `azazel_nexus.fabric_boundary` is where a
record becomes a Fabric envelope for export; the chain does not wait for it.

    sequence | event_hash = SHA-256(previous_hash || canonical_event_bytes)

Two refusals are the whole point of the module:

*A gap is refused, not repaired.* An entry whose `previous_hash` does not match
the chain's current head is rejected. A ledger that healed itself would be a
ledger that cannot report the one thing it exists to report.

*A write that fails leaves nothing.* The record is appended to the file or it
is not; there is no state in which the caller is told the event was recorded
and the chain does not carry it. Partial success here would be worse than
failure, because the next entry would chain onto something no reader can see.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional

__all__ = [
    "GENESIS_HASH",
    "AuditChainBroken",
    "AuditEntry",
    "AuditUnavailable",
    "AuditLedger",
    "canonical_event_bytes",
]

#: What the first entry chains onto.
#:
#: 64 zeros rather than an empty string, so that every entry in the file has a
#: `previous_hash` of the same shape. A reader cannot then tell "first entry"
#: from "field missing" by length, which is the kind of difference that gets
#: lost in a transcription.
GENESIS_HASH = "0" * 64

#: How far back `AuditLedger.head` reads at a time while looking for the last record.
_TAIL_CHUNK = 64 * 1024


class AuditChainBroken(Exception):
    """The chain does not continue from where the caller thinks it does."""


class AuditUnavailable(Exception):
    """The event could not be recorded, so it was not recorded.

    Raised rather than returned. A caller that carried on after a failed audit
    write would be operating in a state the ledger does not describe, and
    `IMPLEMENTATION_SPEC.md` §8 makes audit failure fail-closed.
    """


def canonical_event_bytes(event: Mapping[str, Any]) -> bytes:
    """One byte sequence per event, whoever serializes it.

    Sorted keys, no insignificant whitespace, UTF-8 without escaping. The
    chain's hash is taken over these bytes, so two processes that disagree
    about them would produce two different chains from the same events.
    """

    return json.dumps(
        event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _chain(previous_hash: str, payload: bytes) -> str:
    return hashlib.sha256(previous_hash.encode("ascii") + payload).hexdigest()


@dataclass(frozen=True)
class AuditEntry:
    """One link. The hash is derived, never supplied."""

    sequence: int
    previous_hash: str
    event_hash: str
    event: Mapping[str, Any]

    def recomputed(self) -> str:
        return _chain(self.previous_hash, canonical_event_bytes(self.event))


class AuditLedger:
    """A file of entries, one JSON object per line, append-only.

    The head is read from the file rather than held in memory across calls, so
    that two writers cannot both believe they are appending to the same head.
    The second one finds the chain has moved and is refused.

    `private=True` creates/restricts the file to 0600 and refuses symlinks;
    other callers retain their existing open and permission semantics.
    """

    def __init__(self, path: Path, *, private: bool = False) -> None:
        self.path = path
        self.private = private

    # -- reading ---------------------------------------------------------

    def __iter__(self) -> Iterator[AuditEntry]:
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return
        except UnicodeDecodeError as exc:
            raise AuditChainBroken(f"{self.path} is not UTF-8: {exc}") from exc
        except OSError as exc:  # pragma: no cover - surfaced by callers
            raise AuditUnavailable(f"{self.path} could not be read: {exc}") from exc

        # Split on the newline `append` writes and nothing else. `splitlines`
        # also breaks on U+2028 and friends, which `ensure_ascii=False` leaves
        # raw inside a string, so one valid record would read as two halves.
        for number, line in enumerate(text.split("\n"), start=1):
            if not line.strip():
                continue
            yield self._parse(line, f"line {number}")

    def head(self) -> tuple[int, str]:
        """`(last sequence, last hash)`, or `(0, GENESIS_HASH)` for an empty chain.

        Only the last record is read, from the end of the file, so the cost of
        asking does not grow with the ledger. It is still read from the file on
        every call rather than remembered, for the reason the class gives.
        Whether the records before it chain is `verify`'s question, not this one.
        """

        try:
            with self.path.open("rb") as handle:
                position = handle.seek(0, os.SEEK_END)
                tail = b""
                while True:
                    stripped = tail.rstrip()
                    cut = stripped.rfind(b"\n")
                    if cut >= 0 or position == 0:
                        last = stripped[cut + 1:]
                        break
                    step = min(_TAIL_CHUNK, position)
                    position -= step
                    handle.seek(position)
                    tail = handle.read(step) + tail
        except FileNotFoundError:
            return 0, GENESIS_HASH
        except OSError as exc:  # pragma: no cover - surfaced by callers
            raise AuditUnavailable(f"{self.path} could not be read: {exc}") from exc

        if not last.strip():
            return 0, GENESIS_HASH
        try:
            line = last.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AuditChainBroken(f"{self.path} last record is not UTF-8: {exc}") from exc
        entry = self._parse(line, "last record")
        return entry.sequence, entry.event_hash

    def _parse(self, line: str, where: str) -> AuditEntry:
        """One record, or `AuditChainBroken`. Never a `KeyError`.

        Callers refuse on `AuditChainBroken`; a record missing a field is the
        same broken chain and must reach them as the same refusal.
        """

        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditChainBroken(f"{self.path} {where} is not a record: {exc}") from exc
        if not isinstance(raw, dict):
            raise AuditChainBroken(f"{self.path} {where} is not a JSON object")
        try:
            entry = AuditEntry(
                sequence=raw["sequence"],
                previous_hash=raw["previous_hash"],
                event_hash=raw["event_hash"],
                event=raw["event"],
            )
        except KeyError as exc:
            raise AuditChainBroken(f"{self.path} {where} has no {exc.args[0]!r}") from None
        if (type(entry.sequence) is not int or not isinstance(entry.previous_hash, str)
                or not isinstance(entry.event_hash, str) or not isinstance(entry.event, dict)):
            raise AuditChainBroken(f"{self.path} {where} has a field of the wrong type")
        return entry

    def verify(self) -> None:
        """Walk the chain. Raise on the first link that does not hold.

        Checks both halves of each link: that the recorded hash is what the
        event actually hashes to, and that the next entry chains onto it. A
        check of only the first would pass on a correctly-hashed record spliced
        into the wrong place; a check of only the second would pass on an
        edited event whose neighbours were re-linked around it.
        """

        expected_sequence, expected_previous = 1, GENESIS_HASH
        for entry in self:
            if entry.sequence != expected_sequence:
                raise AuditChainBroken(
                    f"expected sequence {expected_sequence}, found {entry.sequence}"
                )
            if entry.previous_hash != expected_previous:
                raise AuditChainBroken(
                    f"entry {entry.sequence} chains onto {entry.previous_hash!r}, "
                    f"but the previous entry hashed to {expected_previous!r}"
                )
            recomputed = entry.recomputed()
            if entry.event_hash != recomputed:
                raise AuditChainBroken(
                    f"entry {entry.sequence} records hash {entry.event_hash!r} "
                    f"but its event hashes to {recomputed!r}"
                )
            expected_sequence, expected_previous = entry.sequence + 1, entry.event_hash

    # -- writing ---------------------------------------------------------

    def append(
        self,
        event: Mapping[str, Any],
        *,
        expected_head: Optional[str] = None,
        chain_from: Optional[tuple[int, str]] = None,
    ) -> AuditEntry:
        """Add one entry, or add nothing and raise.

        `expected_head` lets a caller say which chain state it believed it was
        extending. Supplying it turns a concurrent append from silent
        interleaving into a refusal, which is the behaviour a ledger owes a
        reader who will later be asked whether the order is real.

        `chain_from` says the chain's head is somewhere this file cannot see.
        It exists for a ledger split across daily segments, where the head of
        the chain lives in the previous file and reading this one would make
        every segment restart at sequence one -- a set of short chains that
        each verify, which is the property an attacker deleting a file would
        rely on.

        It is the one way to write an entry at a position this file did not
        derive, so the caller supplying it is the caller responsible for
        having derived it from the whole chain.
        `azazel_nexus_runtime.auditd.SegmentedLedger` is that caller: its
        service verifies every segment at start and refuses while broken, and
        each append then takes the head from the latest segment's last record.
        """

        sequence, previous_hash = (
            chain_from if chain_from is not None else self.head()
        )
        if expected_head is not None and expected_head != previous_hash:
            raise AuditChainBroken(
                f"the chain head is {previous_hash!r}, not {expected_head!r}; "
                "the ledger moved under this writer and the event was not recorded"
            )

        payload = canonical_event_bytes(event)
        entry = AuditEntry(
            sequence=sequence + 1,
            previous_hash=previous_hash,
            event_hash=_chain(previous_hash, payload),
            event=dict(event),
        )
        line = json.dumps(
            {
                "sequence": entry.sequence,
                "previous_hash": entry.previous_hash,
                "event_hash": entry.event_hash,
                "event": entry.event,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Opened append-only and flushed to the device before returning.
            # A caller is told the event is recorded only once it survives the
            # process, because "recorded" is the claim the next entry's hash
            # will depend on.
            def opener(path, flags):
                fd = os.open(path, flags | os.O_NOFOLLOW, 0o600)
                try:
                    os.fchmod(fd, 0o600)
                except BaseException:
                    os.close(fd)
                    raise
                return fd

            with (open(self.path, "a", encoding="utf-8", opener=opener)
                  if self.private else self.path.open("a", encoding="utf-8")) as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise AuditUnavailable(
                f"{self.path} could not be appended to ({exc}); the event was "
                "not recorded and the caller must not proceed as though it was"
            ) from exc

        return entry
