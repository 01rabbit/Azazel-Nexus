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

import pwd
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Iterator, Mapping, Optional, Sequence

from azazel_nexus.audit import (
    GENESIS_HASH,
    AuditChainBroken,
    AuditEntry,
    AuditLedger,
    AuditUnavailable,
)
from azazel_nexus.edge_intake import ACTIONS
from azazel_nexus.incident_explain import CLOSE_REASONS

from .principal import PrincipalClass
from .protocol import (
    Argument,
    ArgumentKind,
    Refusal,
    RequestRefused,
    Verb,
    VerbRegistry,
)
from .units import UNIT_NAMES
from .watchdog import DETAIL_MAX_LENGTH, FenceReason

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


class _WatchdogDetail(Argument):
    """Bounded printable ASCII for watchdog diagnostics, never a verb argument."""

    def coerce(self, value):
        if not isinstance(value, str):
            raise RequestRefused(Refusal.ARGUMENT_TYPE, self.name)
        if len(value) > DETAIL_MAX_LENGTH or any(not 32 <= ord(c) <= 126 for c in value):
            raise RequestRefused(Refusal.ARGUMENT_RANGE, self.name)
        return value


class _PreviousFenceReason(Argument):
    """The initial transition has no previous reason; subsequent ones enumerate it."""

    def coerce(self, value):
        return None if value is None else super().coerce(value)


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
        Argument("unit", ArgumentKind.ENUM, choices=tuple(UNIT_NAMES.values())),
        Argument("reason", ArgumentKind.ENUM, choices=tuple(reason.value for reason in FenceReason)),
        _WatchdogDetail("detail", ArgumentKind.IDENTIFIER),
        Argument("previous_state", ArgumentKind.ENUM, choices=("in_service", "fenced")),
        _PreviousFenceReason("previous_reason", ArgumentKind.ENUM,
                             choices=tuple(reason.value for reason in FenceReason)),
        Argument("state", ArgumentKind.ENUM, choices=("fenced",)),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
    "bootstrap.controller_ready_intent": (
        Argument("approval_digest", ArgumentKind.DIGEST),
        Argument("generation", ArgumentKind.ORDINAL, maximum=2**63 - 1),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
    "bootstrap.grant_intent": (
        Argument("approval_digest", ArgumentKind.DIGEST),
        Argument("generation", ArgumentKind.ORDINAL, maximum=2**63 - 1),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
    "bootstrap.start_intent": (
        Argument("approval_digest", ArgumentKind.DIGEST),
        Argument("generation", ArgumentKind.ORDINAL, maximum=2**63 - 1),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
        Argument("unit_key", ArgumentKind.ENUM, choices=("auditd", "commissiond")),
    ),
    "bootstrap.ready": (
        Argument("approval_digest", ArgumentKind.DIGEST),
        Argument("generation", ArgumentKind.ORDINAL, maximum=2**63 - 1),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
        Argument("unit_key", ArgumentKind.ENUM, choices=("auditd", "commissiond")),
    ),
    "bootstrap.stopped": (
        Argument("approval_digest", ArgumentKind.DIGEST),
        Argument("generation", ArgumentKind.ORDINAL, maximum=2**63 - 1),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
    "bootstrap.stopping": (
        Argument("approval_digest", ArgumentKind.DIGEST),
        Argument("generation", ArgumentKind.ORDINAL, maximum=2**63 - 1),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
}


class _IncidentId(Argument):
    def coerce(self, value):
        if type(value) is not str or not re.fullmatch(r"inc-[0-9a-f]{16}", value):
            raise RequestRefused(Refusal.ARGUMENT_RANGE, self.name)
        return value


_INCIDENT_FIELDS = (
    _IncidentId("incident_id", ArgumentKind.IDENTIFIER),
    Argument("most_severe", ArgumentKind.ORDINAL, maximum=10),
    Argument("edge_would", ArgumentKind.ENUM, choices=tuple(sorted(ACTIONS))),
    Argument("count", ArgumentKind.ORDINAL, maximum=2**64-1),
    Argument("technique_count", ArgumentKind.ORDINAL, maximum=8),
    Argument("occurred_at", ArgumentKind.TIMESTAMP),
)
#: An incident record's day names its segment, and segments only move
#: forward: one far-future record would refuse every later writer, and a
#: replayed old one can never land. Incident times are the intake's
#: transition times, so a record outside this window is refused outright.
INCIDENT_CLOCK_SKEW_S = 600
#: Incident times come from the same host's clock and only age in transit, so
#: the future side is a few seconds, never past auditd's own UTC day: a record
#: dated tomorrow would open tomorrow's segment and refuse every writer's
#: records for today until midnight.
INCIDENT_FUTURE_SKEW_S = 5

for _kind in ("opened", "escalated", "closed"):
    EVENT_SCHEMAS["edge.incident." + _kind] = _INCIDENT_FIELDS + (
        (Argument("reason", ArgumentKind.ENUM, choices=CLOSE_REASONS),) if _kind == "closed" else ())


VERBS = (
    Verb(
        "audit.append",
        arguments=(
            Argument("event_type", ArgumentKind.ENUM,
                     choices=tuple(sorted(name for name in EVENT_SCHEMAS
                                           if not name.startswith("bootstrap.")))),
        ),
        admits=frozenset({PrincipalClass.ROOT, PrincipalClass.SERVICE}),
        accepts_payload=True,
        payload_contract="EVENT_SCHEMAS[event_type]",
    ),
    Verb(
        "audit.bootstrap.append",
        arguments=(
            Argument("event_type", ArgumentKind.ENUM,
                     choices=tuple(sorted(name for name in EVENT_SCHEMAS
                                           if name.startswith("bootstrap.")))),
        ),
        admits=frozenset({PrincipalClass.ROOT}),
        accepts_payload=True,
        payload_contract="EVENT_SCHEMAS[event_type]",
    ),
    Verb(
        "audit.verify",
        admits=frozenset({PrincipalClass.ROOT, PrincipalClass.OPERATOR}),
    ),
    Verb(
        "audit.bootstrap.observe",
        admits=frozenset({PrincipalClass.ROOT}),
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
        """The last record of the latest segment that has one.

        Read from the end, like `AuditLedger.head`, so an append does not
        re-read every segment. Continuity across files is `verify`'s check.
        """

        for segment in reversed(self.segments()):
            head = AuditLedger(segment).head()
            if head != (0, GENESIS_HASH):
                return head
        return 0, GENESIS_HASH

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

        segment = self.current_segment(day=day)
        segments = self.segments()
        if segments and segment.name < segments[-1].name:
            raise AuditUnavailable(
                f"{segment.name} precedes the latest audit segment "
                f"{segments[-1].name}; appending would reorder the chain"
            )
        head = self.head()
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

    def __init__(self, ledger: SegmentedLedger, *,
                 clock: Callable[[], float] = time.time) -> None:
        self.ledger = ledger
        self.clock = clock
        try:
            self._explainer_uid = pwd.getpwnam("azexplain").pw_uid
        except KeyError:
            self._explainer_uid = None
        self.verified = False
        self.break_reason: Optional[str] = None
        self.head_sequence = 0
        self.head_hash = GENESIS_HASH

    def start(self) -> None:
        """Verify the whole chain. Report a break; never repair one.

        A ledger that healed itself could not report the one thing it exists
        to report.
        """

        try:
            self.ledger.verify()
            self.head_sequence, self.head_hash = self.ledger.head()
        except AuditChainBroken as exc:
            self.verified = False
            self.break_reason = str(exc)
            return
        self.verified = True
        self.break_reason = None

    def handle(self, request) -> dict:
        # No principal is never the explainer, so an incident event without
        # one is refused below: the absent case fails closed.
        principal = getattr(request, "principal", None)
        is_explainer = (principal is not None and self._explainer_uid is not None
                        and principal.uid == self._explainer_uid)
        arguments = getattr(request, "arguments", None) or {}
        incident = str(arguments.get("event_type", "")).startswith("edge.incident.")
        if ((is_explainer and (request.verb.name != "audit.append" or not incident))
                or (incident and not is_explainer)):
            raise RequestRefused(Refusal.PRINCIPAL_DENIED, "incident_writer")
        if request.verb.name == "audit.bootstrap.observe":
            if not self.verified:
                raise RequestRefused(Refusal.ARGUMENT_RANGE, "chain")
            return {
                "verified": True,
                "head_sequence": self.head_sequence,
                "head_hash": self.head_hash,
            }
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
        if (event_type.startswith("bootstrap.")
                != (request.verb.name == "audit.bootstrap.append")):
            raise RequestRefused(Refusal.PRINCIPAL_DENIED, "event writer")
        event = _bind_event(event_type, payload)
        if event_type.startswith("edge.incident."):
            now = self.clock()
            try:
                skew = datetime.fromisoformat(event["occurred_at"]).timestamp() - now
                today = datetime.fromtimestamp(now, UTC).strftime("%Y-%m-%d")
            except (ValueError, OverflowError, OSError):
                skew = today = None
            # TIMESTAMP admits only `Z`, so the first ten characters are the
            # UTC day of the segment the record would open. A record from
            # before midnight that arrives after another writer opened
            # today's segment cannot be placed either; it is refused here
            # rather than failing the ledger append.
            segments = self.ledger.segments()
            if (skew is None or not -INCIDENT_CLOCK_SKEW_S <= skew <= INCIDENT_FUTURE_SKEW_S
                    or event["occurred_at"][:10] > today
                    or segments and event["occurred_at"][:10] + ".jsonl" < segments[-1].name):
                raise RequestRefused(Refusal.ARGUMENT_RANGE, "occurred_at")
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
        self.head_sequence = entry.sequence
        self.head_hash = entry.event_hash
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
    """Verify the chain, then serve diagnostics and verified writes.

    A broken chain is intentionally served without systemd readiness so an
    operator can inspect ``audit.verify``.  It must never be represented as a
    ready audit service; ``AuditService`` continues to refuse appends.
    """

    from .principal import PrincipalPolicy, SERVICE_ACCOUNTS
    from .runtime_paths import audit_sink, ledger_dir, socket_path
    from .serve import serve_forever
    from .systemd_notify import runtime_ready_callback

    service = AuditService(SegmentedLedger(ledger_dir()))
    service.start()
    # ``start`` reports a broken ledger as ``verified=False`` rather than
    # raising, preserving the read-only diagnostic endpoint.  Do not pass a
    # READY callback in that case: serve_forever binds the listener before
    # notifying systemd, so readiness is the boundary we must withhold.
    startup_ready = (
        ready if ready is not None else runtime_ready_callback()
    ) if service.verified else None
    return serve_forever(
        path=socket_path("audit"),
        registry=REGISTRY,
        policy=PrincipalPolicy.resolve(service_accounts=SERVICE_ACCOUNTS + ("azexplain",)),
        audit=audit_sink("audit"),
        handler=service.handle,
        stop=stop,
        ready=startup_ready,
    )


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
