"""`az-auditd`: one writer, typed events, and a chain that spans segments (#40).

## Why a daemon owns the chain

`azazel_nexus.audit.AuditLedger` handles one process appending fail-closed.
In the runtime layer three daemons record to the same chain, and a chain with
several writers is a chain that forks: two processes read the same head,
compute the same next sequence, and both write. **Both branches then report
themselves intact**, because each is internally consistent and neither knows
about the other.

So every other daemon sends events here, and this one appends. The sequence
and the `previous_hash` are assigned by this daemon and are not fields a
caller may supply -- a writer that could claim its own position in the chain
could claim a position that is already taken, or one that is not yet reached.

## Why events are typed

The chain's contents would otherwise be whatever any caller sent. An audit
chain whose entries are arbitrary is one nobody can write a reader for, and
one where anything reaching the socket can write unbounded text into the
record of what happened.

`EVENT_SCHEMAS` declares each event type and its fields, using the same
bounded kinds as every other request. An event type that is not declared is
refused; a declared one with an undeclared field is refused too.

## Segments and checkpoints

`IMPLEMENTATION_SPEC.md` §3 puts daily segments under `audit/ledger/`. The
chain runs **across** them: a segment's first entry chains onto the previous
segment's last hash, so rotating a file is not a place the chain restarts.

The checkpoints written here are **not signed**. The specification calls for
signed ones and this node has no signing key; writing an unsigned file and
calling it a checkpoint would be the weaker artifact wearing the stronger
name. What `checkpoint()` produces is an index -- where each segment ends and
what its last hash was -- and it is labelled as such. It makes verification
cheaper. It anchors nothing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Mapping, Optional, Sequence

from azazel_nexus.audit import (
    GENESIS_HASH,
    AuditChainBroken,
    AuditEntry,
    AuditLedger,
    AuditUnavailable,
)

from .principal import PrincipalClass
from .protocol import (
    Argument,
    ArgumentKind,
    Refusal,
    RequestRefused,
    Verb,
    VerbRegistry,
)

__all__ = [
    "EVENT_SCHEMAS",
    "REGISTRY",
    "AuditService",
    "Checkpoint",
    "SegmentedLedger",
    "VERBS",
]

#: Fields no caller may supply. The daemon assigns all three.
#:
#: A writer that could claim its own position in the chain could claim one
#: that is already taken, or one that has not been reached.
ASSIGNED_BY_THE_DAEMON = ("sequence", "previous_hash", "event_hash")


#: Every event type this chain accepts, and the fields each one carries.
#:
#: Declared rather than open. The alternative is a ledger whose contents are
#: whatever reached the socket, which is both unreadable and a place to write
#: unbounded text.
EVENT_SCHEMAS: Mapping[str, tuple[Argument, ...]] = {
    "activation.unit_granted": (
        Argument("unit", ArgumentKind.ENUM, choices=("commissiond", "auditd", "watchdog")),
        Argument("generation", ArgumentKind.ORDINAL, maximum=1_000_000),
        Argument("digest", ArgumentKind.DIGEST),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
        Argument("actor", ArgumentKind.IDENTIFIER),
    ),
    "activation.unit_withheld": (
        Argument("unit", ArgumentKind.ENUM, choices=("commissiond", "auditd", "watchdog")),
        Argument("generation", ArgumentKind.ORDINAL, maximum=1_000_000),
        Argument("reason", ArgumentKind.ENUM, choices=(
            "lease_absent",
            "lease_expired",
            "health_not_established",
            "edge_unknown",
            "edge_not_ready",
            "commissioning_absent",
            "commissioning_incomplete",
            "commissioning_observe_only",
            "generation_unverified",
            "no_generation",
        )),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
        Argument("actor", ArgumentKind.IDENTIFIER),
    ),
    "commissioning.permanent_mac_read": (
        Argument("ordinal", ArgumentKind.ORDINAL, maximum=255),
        Argument("snapshot", ArgumentKind.DIGEST),
        Argument("readable", ArgumentKind.FLAG),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
        Argument("actor", ArgumentKind.IDENTIFIER),
    ),
    "watchdog.fenced": (
        Argument("unit", ArgumentKind.ENUM, choices=("commissiond", "auditd", "watchdog")),
        Argument("reason", ArgumentKind.ENUM, choices=(
            "deadline_exceeded",
            "unhealthy",
            "generation_mismatch",
            "restart_interrupted",
        )),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
}


VERBS = (
    Verb(
        "audit.append",
        arguments=(
            Argument("event_type", ArgumentKind.ENUM, choices=tuple(sorted(EVENT_SCHEMAS))),
        ),
        admits=frozenset({PrincipalClass.ROOT, PrincipalClass.SERVICE}),
        accepts_payload=True,
        payload_contract="EVENT_SCHEMAS[event_type]",
    ),
    Verb(
        "audit.verify",
        admits=frozenset({PrincipalClass.ROOT, PrincipalClass.OPERATOR}),
    ),
)

REGISTRY = VerbRegistry(VERBS)


@dataclass(frozen=True)
class Checkpoint:
    """Where a segment ended. **Not a trust anchor.**

    The specification calls for signed checkpoints and this node has no
    signing key. What this is: an index that makes verification cheaper by
    saying where to look. What it is not: evidence that a segment was not
    rewritten, which is what a signature would give and what nothing here
    does.
    """

    segment: str
    last_sequence: int
    last_hash: str
    entries: int
    signed: bool = False


class SegmentedLedger:
    """Daily files, one chain running through all of them.

    A segment boundary is a place the file changes, not a place the chain
    restarts: the first entry of a segment chains onto the last hash of the
    one before it. A chain that restarted per file would be a set of short
    chains that each verify, which is the property an attacker deleting a
    file would rely on.
    """

    def __init__(self, root: Path) -> None:
        self.root = root

    def segments(self) -> tuple[Path, ...]:
        """Every segment, in the order the chain runs through them.

        Sorted by name, which for `YYYY-MM-DD.jsonl` is chronological. A
        directory listing order would make the chain's shape depend on the
        filesystem.
        """

        if not self.root.is_dir():
            return ()
        return tuple(sorted(self.root.glob("*.jsonl")))

    def current_segment(self, *, day: str) -> Path:
        if not day or len(day) != 10 or day.count("-") != 2:
            raise AuditUnavailable(
                f"{day!r} is not a YYYY-MM-DD segment name; a segment whose "
                "name does not sort chronologically breaks the chain's order"
            )
        return self.root / f"{day}.jsonl"

    def __iter__(self) -> Iterator[AuditEntry]:
        for segment in self.segments():
            yield from AuditLedger(segment)

    def head(self) -> tuple[int, str]:
        sequence, digest = 0, GENESIS_HASH
        for entry in self:
            sequence, digest = entry.sequence, entry.event_hash
        return sequence, digest

    def verify(self) -> None:
        """Walk every segment in order. A boundary is not an exception.

        Each segment is verified against the head the previous one left, so a
        deleted or reordered file shows up as a break rather than as a chain
        that happens to start later.
        """

        expected_sequence, expected_hash = 0, GENESIS_HASH
        for segment in self.segments():
            for entry in AuditLedger(segment):
                if entry.sequence != expected_sequence + 1:
                    raise AuditChainBroken(
                        f"{segment.name} entry {entry.sequence} follows "
                        f"{expected_sequence}; the chain skips or repeats here"
                    )
                if entry.previous_hash != expected_hash:
                    raise AuditChainBroken(
                        f"{segment.name} entry {entry.sequence} chains onto "
                        f"{entry.previous_hash[:12]}... and the chain is at "
                        f"{expected_hash[:12]}..."
                    )
                if entry.recomputed() != entry.event_hash:
                    raise AuditChainBroken(
                        f"{segment.name} entry {entry.sequence} does not hash "
                        "to what it records"
                    )
                expected_sequence, expected_hash = entry.sequence, entry.event_hash

    def append(self, event: Mapping, *, day: str) -> AuditEntry:
        """One entry, at the head this ledger currently has.

        The head is read across every segment, so an append to a new file
        continues the chain rather than starting one.
        """

        head = self.head()
        segment = self.current_segment(day=day)
        return AuditLedger(segment).append(event, chain_from=head)

    def checkpoint(self) -> tuple[Checkpoint, ...]:
        """An index of where each segment ends. Unsigned, and labelled so."""

        marks = []
        for segment in self.segments():
            entries = list(AuditLedger(segment))
            if not entries:
                continue
            marks.append(
                Checkpoint(
                    segment=segment.name,
                    last_sequence=entries[-1].sequence,
                    last_hash=entries[-1].event_hash,
                    entries=len(entries),
                )
            )
        return tuple(marks)


class AuditService:
    """The handler behind the socket. Verifies once at startup, then appends.

    While verification has not succeeded, appends are refused: appending to a
    head nobody has checked means the next entry's hash depends on something
    that may already be broken.
    """

    def __init__(self, ledger: SegmentedLedger) -> None:
        self.ledger = ledger
        self.verified = False
        self.break_reason: Optional[str] = None

    def start(self) -> None:
        """Verify the whole chain. Report a break; never repair one.

        A ledger that healed itself could not report the one thing it exists
        to report.
        """

        try:
            self.ledger.verify()
        except AuditChainBroken as exc:
            self.verified = False
            self.break_reason = str(exc)
            return
        self.verified = True
        self.break_reason = None

    def handle(self, request) -> dict:
        if request.verb.name == "audit.verify":
            return {
                "verified": self.verified,
                "break": self.break_reason,
                "checkpoints": [c.__dict__ for c in self.ledger.checkpoint()],
            }
        return self._append(request)

    def _append(self, request) -> dict:
        if not self.verified:
            raise RequestRefused(
                Refusal.ARGUMENT_RANGE,
                "chain",
            )
        payload = getattr(request, "payload", None) or {}
        event_type = request.arguments["event_type"]
        event = _bind_event(event_type, payload)
        # Every declared schema carries `occurred_at`, and `_bind_event` has
        # already refused a payload missing it. The segment a record lands in
        # is the day it happened, not the day it arrived.
        day = event["occurred_at"][:10]
        try:
            entry = self.ledger.append(event, day=day)
        except AuditUnavailable:
            # Fail closed. Telling a caller the event is recorded when it is
            # not would make the next entry's hash depend on that claim.
            raise
        return {"sequence": entry.sequence, "event_hash": entry.event_hash}


def _bind_event(event_type: str, payload: Mapping) -> dict:
    """Validate a payload against its declared schema, and add nothing.

    The three chaining fields are refused with their own reason rather than
    as undeclared keys: an attempt to claim a position in the chain should be
    visible in the record as that.
    """

    claimed = sorted(set(payload) & set(ASSIGNED_BY_THE_DAEMON))
    if claimed:
        raise RequestRefused(Refusal.UNDECLARED_ARGUMENT, claimed[0])

    # No `is None` branch here, and that is deliberate. The `audit.append`
    # verb declares `event_type` as an ENUM over exactly these keys, so a type
    # that is not declared is refused during argument binding and never
    # reaches this function. A guard for it would read like the check that
    # keeps undeclared events out and would never once execute --
    # `test_the_append_verbs_event_types_are_exactly_the_declared_schemas` is
    # what keeps the reachable guarantee true.
    schema = EVENT_SCHEMAS[event_type]
    declared = {argument.name: argument for argument in schema}
    undeclared = sorted(set(payload) - set(declared))
    if undeclared:
        raise RequestRefused(Refusal.UNDECLARED_ARGUMENT, "payload")
    missing = sorted(set(declared) - set(payload))
    if missing:
        raise RequestRefused(Refusal.MISSING_ARGUMENT, missing[0])

    event = {name: declared[name].coerce(payload[name]) for name in declared}
    event["event_type"] = event_type
    return event


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stop: Callable[[], bool] = lambda: False,
    ready: Optional[Callable[[], None]] = None,
) -> int:
    """Verify the chain, then serve. Refusing to serve a broken one."""

    from .principal import PrincipalPolicy
    from .runtime_paths import audit_sink, ledger_dir, socket_path
    from .serve import serve_forever

    service = AuditService(SegmentedLedger(ledger_dir()))
    service.start()
    return serve_forever(
        path=socket_path("audit"),
        registry=REGISTRY,
        policy=PrincipalPolicy.resolve(),
        audit=audit_sink(),
        handler=service.handle,
        stop=stop,
        ready=ready,
    )


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
