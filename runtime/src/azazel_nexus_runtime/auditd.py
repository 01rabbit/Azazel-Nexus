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

## Rate and daily limits (#211 S3)

Nothing here deletes a segment: the retention policy (#211) is never to
delete and only to warn on capacity (docs/operations.md, Audit chain
retention). What this daemon does bound is how fast any one writer
can make it grow. Every append from a non-root principal spends a token from
a bucket keyed on the kernel-derived uid and the event type; incident records
additionally spend from a per-uid daily count. A request over either limit is
refused with `rate_limited` (detail `rate` or `daily`), which is final for that
request and appends nothing.

The defaults sit far above what the upstream budgets can produce (see
`docs/integration-loop.md`, "Audit chain limits"), so they bind only a writer
that has stopped behaving like the explainer. Incident records whose
`most_severe` is 2 or below have their own buckets and the last
`INCIDENT_DAILY_RESERVE` records of the day, so a legitimate flood of ordinary
incidents cannot crowd out a severe opening, escalation or close. Severity is
the writer's claim: a compromised explainer can label everything severe, and
the reserve then protects nothing -- the total daily cap is what bounds it.

Refusals are summarized, not recorded one by one: per-request refusal lines
would let a flood fill `refusals.jsonl` instead of the chain. At most one
`audit.rate_limited` chain record per (uid, event type, tier, limit) per
`SUMMARY_WINDOW_S`, and at most `SUMMARY_DAILY_CAP` of them a day, carry the
counts; summaries are not themselves rate-limited writers' records, so they
cannot feed back into the limiter.

## Capacity snapshot for operators (#211)

`azazel-nexus status` neither talks to this socket nor reads the `0700`
ledger, so the serve loop also writes `run/audit-status/status.json` into its
own `2750 azaudit:azazel-operator` leaf: at start and every
`STATUS_INTERVAL_S` seconds, by temp file and rename. It holds the capacity
reading, whether the chain verified at start, and the `rate_limited` totals --
sizes, counts and fixed reason codes, never record content or a uid. The leaf
is optional for this daemon: auditd is bootstrap-critical, so a missing or
unwritable leaf (a runtime upgraded without re-running install.sh) is logged
once and serving continues without the snapshot.
"""

from __future__ import annotations

import json
import os
import pwd
import re
import sys
import tempfile
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
from azazel_nexus.audit_status import (
    RATE_LIMITED_KEYS,
    STATUS_INTERVAL_S,
    STATUS_SCHEMA,
    warning_reasons,
)
from azazel_nexus.edge_intake import ACTIONS
from azazel_nexus.incident_explain import CLOSE_REASONS
from azazel_nexus.lite_bundle import Gate
from azazel_nexus.lite_enrollment import ENROLLMENT_REFUSAL_CODES
from azazel_nexus.lite_import import IMPORT_REFUSAL_CODES, REVOCATION_REFUSAL_CODES

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
from .status_snapshot import UiCopy
from .watchdog import DETAIL_MAX_LENGTH, FenceReason

__all__ = [
    "EVENT_SCHEMAS",
    "REGISTRY",
    "AuditService",
    "Checkpoint",
    "SegmentedLedger",
    "VERBS",
    "summarized_refusals",
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

#: Knowledge Lite import and revocation acceptance (assess-c P4). Each type is
#: bound to the one account whose daemon performs that transition
#: (`BOUND_WRITERS`); no other principal, root included, may write it, and that
#: account may write no other event type (both directions, as the explainer's
#: incident binding). Digests, counts and fixed codes only: never a claim body,
#: a key or a path.
_ENTRY_ID = Argument("entry_id", ArgumentKind.IDENTIFIER)
_LITE_GENERATION = Argument("bundle_version", ArgumentKind.ORDINAL, maximum=2**63 - 1)
_COUNT = 2**63 - 1
EVENT_SCHEMAS.update({
    "knowledge.lite.import_started": (
        _ENTRY_ID, Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
    "knowledge.lite.import_store_tightened": (
        _ENTRY_ID, Argument("directories", ArgumentKind.ORDINAL, maximum=3),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
    "knowledge.lite.import_refused": (
        _ENTRY_ID, Argument("code", ArgumentKind.ENUM, choices=IMPORT_REFUSAL_CODES),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
    "knowledge.lite.import_quarantined": (
        _ENTRY_ID, Argument("bundle_digest", ArgumentKind.DIGEST),
        Argument("gate", ArgumentKind.ENUM, choices=tuple(gate.value for gate in Gate)),
        Argument("code", ArgumentKind.IDENTIFIER),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
    "knowledge.lite.import_admitted": (
        _ENTRY_ID, Argument("bundle_digest", ArgumentKind.DIGEST), _LITE_GENERATION,
        Argument("served", ArgumentKind.ORDINAL, maximum=_COUNT),
        Argument("withheld", ArgumentKind.ORDINAL, maximum=_COUNT),
        Argument("static_reference", ArgumentKind.ORDINAL, maximum=_COUNT),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
    "knowledge.lite.revocation_requested": (
        Argument("statement_digest", ArgumentKind.DIGEST),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
    "knowledge.lite.revocation_refused": (
        Argument("statement_digest", ArgumentKind.DIGEST),
        Argument("code", ArgumentKind.ENUM, choices=REVOCATION_REFUSAL_CODES),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
    "knowledge.lite.revocation_accepted": (
        Argument("statement_digest", ArgumentKind.DIGEST),
        # The list's own sequence number. Not `sequence`: that is the chain
        # position this daemon assigns (`ASSIGNED_BY_THE_DAEMON`), and a
        # payload naming it is refused, so every accepted list went
        # unrecorded until 2026-10-30 (`test_every_lite_schema_can_be_appended`).
        Argument("list_sequence", ArgumentKind.ORDINAL, maximum=_COUNT),
        Argument("generation", ArgumentKind.ORDINAL, maximum=_COUNT),
        Argument("revoked_digests", ArgumentKind.ORDINAL, maximum=_COUNT),
        Argument("revoked_generations", ArgumentKind.ORDINAL, maximum=_COUNT),
        Argument("revoked_keys", ArgumentKind.ORDINAL, maximum=_COUNT),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
})

#: The Knowledge Lite trust maintenance transactions (ADR 0008): the first
#: enrollment and a repin, run by root's `az-nexus-commission` as the
#: commissioning account. The request is recorded before anything is written
#: (`..._requested`); the outcome follows. Digests, counts and fixed codes only.
_REPIN_REASONS = ("compromise", "recovery", "rotation")
EVENT_SCHEMAS.update({
    "knowledge.lite.trust_enroll_requested": (
        Argument("request_digest", ArgumentKind.DIGEST),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
    "knowledge.lite.trust_enroll_refused": (
        Argument("request_digest", ArgumentKind.DIGEST),
        Argument("code", ArgumentKind.ENUM, choices=ENROLLMENT_REFUSAL_CODES),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
    "knowledge.lite.trust_enrolled": (
        Argument("request_digest", ArgumentKind.DIGEST),
        Argument("trust_fingerprint", ArgumentKind.DIGEST),
        Argument("revocation_policy_fingerprint", ArgumentKind.DIGEST),
        Argument("bundle_keys", ArgumentKind.ORDINAL, maximum=64),
        Argument("threshold", ArgumentKind.ORDINAL, maximum=64),
        Argument("revocation_keys", ArgumentKind.ORDINAL, maximum=64),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
    "knowledge.lite.trust_repin_requested": (
        Argument("anchor_digest", ArgumentKind.DIGEST),
        Argument("reason", ArgumentKind.ENUM, choices=_REPIN_REASONS),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
    "knowledge.lite.trust_repin_refused": (
        Argument("anchor_digest", ArgumentKind.DIGEST),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
    "knowledge.lite.trust_repin_promoted": (
        Argument("anchor_digest", ArgumentKind.DIGEST),
        Argument("generation", ArgumentKind.ORDINAL, maximum=_COUNT),
        Argument("occurred_at", ArgumentKind.TIMESTAMP),
    ),
})

#: Event-type prefix -> the only account that may append it, and the only
#: prefix that account may append.
BOUND_WRITERS: Mapping[str, str] = {
    "knowledge.lite.import_": "azknowledge",
    "knowledge.lite.revocation_": "azcommission",
    "knowledge.lite.trust_": "azcommission",
}

#: What `audit.append` may carry, fixed before the daemon's own summary type
#: is declared below: a caller that could write `audit.rate_limited` could
#: forge or bury it.
_LIMITED_TYPES =tuple(sorted(name for name in EVENT_SCHEMAS if not name.startswith("bootstrap.")))
EVENT_SCHEMAS["audit.rate_limited"] = (
    Argument("writer_uid", ArgumentKind.ORDINAL, maximum=2**32 - 1),
    Argument("writer_class", ArgumentKind.ENUM,
             choices=tuple(sorted(c.value for c in PrincipalClass))),
    Argument("refused_event_type", ArgumentKind.ENUM, choices=_LIMITED_TYPES),
    Argument("tier", ArgumentKind.ENUM, choices=("ordinary", "service", "severe")),
    Argument("limit", ArgumentKind.ENUM, choices=("daily", "rate")),
    Argument("refused", ArgumentKind.ORDINAL, maximum=2**63 - 1),
    Argument("occurred_at", ArgumentKind.TIMESTAMP),
)


@dataclass(frozen=True)
class RateLimit:
    """A token bucket: `burst` at once, refilled at `per_second`."""

    burst: int
    per_second: float


#: Incident severities at or below this are Edge's isolate/redirect range and
#: get their own buckets and the daily reserve, as they do in the intake.
INCIDENT_SEVERE_AT_MOST = 2
#: Per (uid, incident event type, tier). Upstream, openings are at most 60/min
#: ordinary and 30/min severe; closes follow openings (plus at most 1024 held
#: incidents closing at once); a fall in severity happens at most ten times an
#: incident. 2048 absorbs a whole table (1024) closing at once with room for
#: the routine closes around it; 600/min is a wide margin over every rate.
INCIDENT_RATE = RateLimit(burst=2048, per_second=10.0)
#: Per (uid, event type) for every other non-root writer. These are rare
#: transitions (commissioning reads, unit grants); 256 covers every ordinal a
#: commissioning read can name at once.
SERVICE_RATE = RateLimit(burst=256, per_second=0.1)
#: Incident records one uid may append to one daily segment (the UTC day of
#: `occurred_at`, the segment the record lands in). A whole
#: day with every upstream budget saturated (60/min ordinary and 30/min severe
#: openings and their closes, hourly whole-table closes, an escalation every
#: other second) is about 330,000; normal operation is a tenth of that. At
#: about 450-500 bytes a record (20-digit counts, long close reasons) this
#: bounds a writer to roughly 250 MiB a day.
INCIDENT_DAILY_CAP = 524_288
#: The last records of that day that only severe records may use.
INCIDENT_DAILY_RESERVE = 65_536
#: One summary per key per window, and a hard ceiling a day.
SUMMARY_WINDOW_S = 300.0
SUMMARY_DAILY_CAP = 1024
#: Warn (journal and `audit.verify`) at this chain size or this little free
#: space on the ledger's filesystem. A warning, never a deletion.
CAPACITY_WARN_CHAIN_BYTES = 1 << 30
CAPACITY_WARN_FREE_BYTES = 1 << 30
#: How often the serve loop re-reads capacity, and re-warns while above it.
CAPACITY_CHECK_S = 3600.0
CAPACITY_REWARN_S = 86400.0


VERBS = (
    Verb(
        "audit.append",
        arguments=(
            Argument("event_type", ArgumentKind.ENUM,
                     choices=_LIMITED_TYPES),
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
#: The explainer's own listener (`audit-submit`, group azaudit-submit): append
#: only, selected by name. Its client holds that group and not the operator
#: group, so it reaches no other daemon socket; `handle` still admits only
#: edge.incident.* from it. The verb's admission is unchanged (ROOT and
#: SERVICE), so root -- which already reaches every socket -- gains nothing
#: here; no operator reaches this leaf at all.
SUBMIT_REGISTRY = VerbRegistry([verb for verb in VERBS if verb.name == "audit.append"])


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

    def verify(self, *, observe: Callable[[Path, AuditEntry], None] | None = None) -> None:
        """Walk every segment in order. A boundary is not an exception.

        Each segment is verified against the head the previous one left, so a
        deleted or reordered file shows up as a break rather than as a chain
        that happens to start later.

        `observe`, if given, sees each verified entry with its segment, so a
        caller that needs to count something does it in this one pass instead
        of reading the chain again.
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
                if observe is not None:
                    observe(segment, entry)

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

    def capacity(self) -> dict:
        """How much the chain holds, and what is left where it lives.

        Sizes are read with `stat`, never by parsing, so this is cheap enough
        to answer on every `audit.verify` and from the serve loop's tick.
        """

        chain_bytes = 0
        segments = self.segments()
        for segment in segments:
            try:
                chain_bytes += segment.stat().st_size
            except OSError:
                continue
        try:
            stats = os.statvfs(self.root)
            free = stats.f_bavail * stats.f_frsize
        except OSError:
            free = None
        return {
            "chain_bytes": chain_bytes,
            "segments": len(segments),
            "filesystem_free_bytes": free,
            "warning": chain_bytes >= CAPACITY_WARN_CHAIN_BYTES
            or (free is not None and free < CAPACITY_WARN_FREE_BYTES),
            "warn_chain_bytes": CAPACITY_WARN_CHAIN_BYTES,
            "warn_free_bytes": CAPACITY_WARN_FREE_BYTES,
        }

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
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic,
                 warn: Callable[[str], None] = lambda line: print(line, file=sys.stderr, flush=True),
                 status_path: Optional[Path] = None,
                 ui_status_path: Optional[Path] = None,
                 ) -> None:
        self.ledger = ledger
        #: Where the operator-readable snapshot goes; `None` writes none.
        self.status_path = status_path
        #: The read-only UI's byte-identical copy (ADR-0007); `None` writes none.
        self.ui_status = UiCopy(ui_status_path, name="azazel-auditd", warn=warn)
        self._status_written = float("-inf")
        self._status_failing = False
        self._status_swept = False
        self.clock = clock
        self.monotonic = monotonic
        self.warn = warn
        #: (uid, event_type, tier) -> [tokens, monotonic time of last refill]
        self._buckets: dict[tuple, list] = {}
        #: segment day -> uid -> [ordinary, severe] incident records in it.
        #: Keyed on the day a record is appended to (its segment), the same
        #: basis the startup recount uses; days before yesterday are dropped.
        self._incidents_by_day: dict[str, dict[int, list]] = {}
        #: segment day -> `audit.rate_limited` records in it.
        self._summaries_by_day: dict[str, int] = {}
        self._recount_failed = False
        #: (uid, class, event_type, tier, limit) -> refusals not yet summarized.
        self._summary_pending: dict[tuple, int] = {}
        self._summary_last: dict[tuple, float] = {}
        #: Totals since start, for `audit.verify`: "<limit>:<event_type>:<tier>".
        self.rate_limited: dict[str, int] = {}
        self.summaries_dropped = 0
        self._capacity_checked = float("-inf")
        self._capacity_warned = float("-inf")
        try:
            self._explainer_uid = pwd.getpwnam("azexplain").pw_uid
        except KeyError:
            self._explainer_uid = None
        #: prefix -> uid of its one writer, or None (then nobody may write it).
        self._bound_writer_uids: dict[str, Optional[int]] = {}
        for prefix, account in BOUND_WRITERS.items():
            try:
                self._bound_writer_uids[prefix] = pwd.getpwnam(account).pw_uid
            except KeyError:
                self._bound_writer_uids[prefix] = None
        self.verified = False
        self.break_reason: Optional[str] = None
        self.head_sequence = 0
        self.head_hash = GENESIS_HASH

    def start(self) -> None:
        """Verify the whole chain. Report a break; never repair one.

        A ledger that healed itself could not report the one thing it exists
        to report.
        """

        self._incidents_by_day, self._summaries_by_day = {}, {}
        self._recount_failed = False
        try:
            self.ledger.verify(observe=self._recount)
            self.head_sequence, self.head_hash = self.ledger.head()
        except AuditChainBroken as exc:
            self.verified = False
            self.break_reason = str(exc)
            return
        self.verified = True
        self.break_reason = None
        if self._recount_failed:
            # Fail open, and say so: the chain itself verified, so refusing
            # every writer over a counting fault would turn a bookkeeping
            # error into an audit outage. The token buckets still bound the
            # rest of the day. No record content is logged.
            self._incidents_by_day, self._summaries_by_day = {}, {}
            self.warn("azazel-auditd: daily rate-limit counts could not be rebuilt "
                      "at startup; they start from zero for this run")
        self._today()

    # -- limits -----------------------------------------------------------

    def _recount(self, segment: Path, entry: AuditEntry) -> None:
        """Rebuild the daily counts during the startup verify pass. Never raises.

        Only the explainer may write incident records, so every one of them is
        its. A segment's name is the day its records were appended to, which
        is the basis the running counts use too.
        """

        if self._recount_failed:
            return
        try:
            day = segment.stem
            kind = entry.event.get("event_type", "")
            if kind == "audit.rate_limited":
                self._summaries_by_day[day] = self._summaries_by_day.get(day, 0) + 1
            elif kind.startswith("edge.incident.") and self._explainer_uid is not None:
                counts = self._incidents_by_day.setdefault(day, {}).setdefault(
                    self._explainer_uid, [0, 0])
                counts[1 if _severe(entry.event) else 0] += 1
        except Exception:  # noqa: BLE001 - reported once by start()
            self._recount_failed = True

    def _today(self) -> str:
        """auditd's current UTC day. Drops counts for days before yesterday.

        Only days strictly older than yesterday go, so a clock stepping
        backwards keeps the counts of the day it stepped back from rather
        than silently wiping them.
        """

        now = self.clock()
        day = datetime.fromtimestamp(now, UTC).strftime("%Y-%m-%d")
        oldest = datetime.fromtimestamp(now - 86400, UTC).strftime("%Y-%m-%d")
        for counts in (self._incidents_by_day, self._summaries_by_day):
            for stale in [d for d in counts if d < oldest]:
                del counts[stale]
        return day

    def _admit(self, principal, event_type: str, event: Mapping, day: str) -> tuple | None:
        """Spend a token and, for an incident, a place in `day`'s count.

        `day` is the segment the record is about to be appended to. Returns
        the daily-count slot to increment once the append succeeds, or
        `None`. Root is not limited: it writes the bootstrap records, which are
        a handful per start, and a root that wanted to fill the disk would not
        need this socket to do it.
        """

        if principal is None or PrincipalClass.ROOT in principal.classes:
            return None
        incident = event_type.startswith("edge.incident.")
        tier = ("severe" if _severe(event) else "ordinary") if incident else "service"
        limit = INCIDENT_RATE if incident else SERVICE_RATE
        if incident:
            counts = self._incidents_by_day.get(day, {}).get(principal.uid, (0, 0))
            ceiling = (INCIDENT_DAILY_CAP if tier == "severe"
                       else INCIDENT_DAILY_CAP - INCIDENT_DAILY_RESERVE)
            if counts[0] + counts[1] >= ceiling:
                self._refuse(principal, event_type, tier, "daily")
        now = self.monotonic()
        key = (principal.uid, event_type, tier)
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = self._buckets[key] = [float(limit.burst), now]
        bucket[0] = min(float(limit.burst),
                        bucket[0] + max(0.0, now - bucket[1]) * limit.per_second)
        bucket[1] = now
        if bucket[0] < 1.0:
            self._refuse(principal, event_type, tier, "rate")
        bucket[0] -= 1.0
        if incident:
            return (day, principal.uid, 1 if tier == "severe" else 0)
        return None

    def _refuse(self, principal, event_type: str, tier: str, limit: str) -> None:
        name = f"{limit}:{event_type}:{tier}"
        self.rate_limited[name] = self.rate_limited.get(name, 0) + 1
        key = (principal.uid, _principal_class(principal), event_type, tier, limit)
        self._summary_pending[key] = self._summary_pending.get(key, 0) + 1
        self._summarize(only=key)
        raise RequestRefused(Refusal.RATE_LIMITED, limit)

    def _summarize(self, *, only: tuple | None = None) -> None:
        """Write the pending counts whose window has passed. Never raises.

        Bounded twice: one record per key per window, and a daily ceiling.
        Past the ceiling the counts stay in `rate_limited` and are not
        written; a writer cannot turn its refusals into chain growth.
        """

        if not self.verified:
            return
        now = self.monotonic()
        keys = (only,) if only is not None else tuple(self._summary_pending)
        for key in keys:
            count = self._summary_pending.get(key, 0)
            if not count or now - self._summary_last.get(key, float("-inf")) < SUMMARY_WINDOW_S:
                continue
            try:
                at = self.clock()
                day = self._today()
                if self._summaries_by_day.get(day, 0) >= SUMMARY_DAILY_CAP:
                    self.summaries_dropped += count
                    del self._summary_pending[key]
                    continue
                uid, principal_class, event_type, tier, limit = key
                occurred_at = datetime.fromtimestamp(at, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                event = _bind_event("audit.rate_limited", {
                    "writer_uid": uid, "writer_class": principal_class,
                    "refused_event_type": event_type, "tier": tier, "limit": limit,
                    "refused": count, "occurred_at": occurred_at,
                })
                entry = self.ledger.append(event, day=day)
            except Exception:  # noqa: BLE001 - never turn the caller's refusal into an error
                # Keep the count; a later tick tries again after the window.
                self._summary_last[key] = now
                continue
            self.head_sequence, self.head_hash = entry.sequence, entry.event_hash
            self._summaries_by_day[day] = self._summaries_by_day.get(day, 0) + 1
            self._summary_last[key] = now
            del self._summary_pending[key]

    def tick(self) -> None:
        """Called by the serve loop between connections. Never raises.

        Flushes rate-limit summaries whose window has passed, so a flood that
        stops is still summarized, rewrites the status snapshot every
        `STATUS_INTERVAL_S` (so a capacity warning turning on or off reaches
        status within that), and re-reads capacity for the journal hourly.
        """

        try:
            self._summarize()
            now = self.monotonic()
            if now - self._status_written >= STATUS_INTERVAL_S:
                self.write_status()
            if now - self._capacity_checked < CAPACITY_CHECK_S:
                return
            self._capacity_checked = now
            capacity = self.ledger.capacity()
            if capacity["warning"] and now - self._capacity_warned >= CAPACITY_REWARN_S:
                self._capacity_warned = now
                self.warn(
                    "azazel-auditd: audit chain capacity warning: "
                    f"chain_bytes={capacity['chain_bytes']} segments={capacity['segments']} "
                    f"filesystem_free_bytes={capacity['filesystem_free_bytes']}; "
                    "nothing is deleted, see docs/integration-loop.md (Audit chain limits)"
                )
        except Exception:  # noqa: BLE001 - housekeeping must not stop serving
            return

    def status_snapshot(self) -> dict:
        """The operator-readable snapshot: sizes, counts and codes only."""

        capacity = self.ledger.capacity()
        reasons = warning_reasons(capacity["chain_bytes"], capacity["filesystem_free_bytes"],
                                  capacity["warn_chain_bytes"], capacity["warn_free_bytes"])
        # Bounded however many keys exist: the largest counts are kept.
        limited = sorted(self.rate_limited.items(), key=lambda kv: (-kv[1], kv[0]))
        return {
            "schema": STATUS_SCHEMA,
            "written_at": self.clock(),
            "chain_verified": self.verified,
            "chain_bytes": capacity["chain_bytes"],
            "segments": capacity["segments"],
            "filesystem_free_bytes": capacity["filesystem_free_bytes"],
            "warning": bool(reasons),
            "warning_reasons": reasons,
            "warn_chain_bytes": capacity["warn_chain_bytes"],
            "warn_free_bytes": capacity["warn_free_bytes"],
            "rate_limited": dict(sorted(limited[:RATE_LIMITED_KEYS])),
            "rate_limit_summaries_dropped": self.summaries_dropped,
        }

    def write_status(self) -> None:
        """Replace the snapshot by temp file and rename. Never raises.

        A failure is logged once until a write succeeds again; the daemon
        keeps serving, because the chain matters more than its status line.
        """

        if self.status_path is None:
            return
        self._status_written = self.monotonic()
        if not self._status_swept:
            self._sweep_status_temp()
        name = None
        try:
            body = json.dumps(self.status_snapshot(), sort_keys=True,
                              separators=(",", ":")).encode() + b"\n"
            fd, name = tempfile.mkstemp(dir=self.status_path.parent, prefix=".status-")
            with os.fdopen(fd, "wb") as stream:
                stream.write(body)
                os.fchmod(stream.fileno(), 0o640)
            os.replace(name, self.status_path)
            name = None
            self._status_failing = False
            # The same bytes for the UI; never raises, never fails this write.
            self.ui_status.write(body)
        except Exception as exc:  # noqa: BLE001 - the snapshot is optional
            if not self._status_failing:
                self._status_failing = True
                self.warn(
                    f"azazel-auditd: cannot write {self.status_path} ({type(exc).__name__}); "
                    "auditd continues and `azazel-nexus status` shows audit capacity as "
                    "unknown. Re-run install.sh, then systemctl daemon-reload and restart "
                    "azazel-auditd.service (docs/operations.md)"
                )
        finally:
            if name is not None:
                try:
                    os.unlink(name)
                except OSError:
                    pass

    def _sweep_status_temp(self) -> None:
        """Remove `.status-*` temp files a killed predecessor left. Never raises.

        Only this daemon writes in the leaf, and only its own temp files start
        with `.status-`; a live write of this process cannot be among them.
        """

        try:
            for leftover in self.status_path.parent.glob(".status-*"):
                try:
                    if leftover.is_file() and not leftover.is_symlink():
                        leftover.unlink()
                except OSError:
                    pass
            self._status_swept = True
        except OSError:
            pass

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
        event_type = str(arguments.get("event_type", ""))
        # Both directions, as for the explainer above. Only the account that
        # performed the transition may record it (a missing account means
        # nobody may: the absent case fails closed), and a bound account may
        # record nothing but the prefixes bound to it: it reaches this chain
        # only to record its own Knowledge Lite transitions. One account may
        # hold several prefixes (azcommission: revocations and trust changes).
        uid = principal.uid if principal is not None else None
        bound_to = [writer for prefix, writer in self._bound_writer_uids.items()
                    if event_type.startswith(prefix)]
        is_bound_writer = uid is not None and uid in {
            writer for writer in self._bound_writer_uids.values() if writer is not None}
        if ((bound_to and (uid is None or any(writer != uid for writer in bound_to)))
                or (is_bound_writer and not bound_to)
                or (is_bound_writer and request.verb.name != "audit.append")):
            raise RequestRefused(Refusal.PRINCIPAL_DENIED, "bound_writer")
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
                "capacity": self.ledger.capacity(),
                "rate_limited": dict(sorted(self.rate_limited.items())),
                "rate_limit_summaries_dropped": self.summaries_dropped,
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
        # Last, so only a record that would otherwise be appended spends a
        # token or a place in the day. The day is the segment it lands in.
        self._today()
        slot = self._admit(getattr(request, "principal", None), event_type, event, day)
        try:
            entry = self.ledger.append(event, day=day)
        except AuditUnavailable:
            # Fail closed. Telling a caller the event is recorded when it is
            # not would make the next entry's hash depend on that claim.
            raise
        if slot is not None:
            slot_day, uid, index = slot
            self._incidents_by_day.setdefault(slot_day, {}).setdefault(uid, [0, 0])[index] += 1
        self.head_sequence = entry.sequence
        self.head_hash = entry.event_hash
        return {"sequence": entry.sequence, "event_hash": entry.event_hash}


def _severe(event: Mapping) -> bool:
    severity = event.get("most_severe")
    return type(severity) is int and severity <= INCIDENT_SEVERE_AT_MOST


def _principal_class(principal) -> str:
    for candidate in (PrincipalClass.ROOT, PrincipalClass.SERVICE, PrincipalClass.OPERATOR):
        if candidate in principal.classes:
            return candidate.value
    return PrincipalClass.SERVICE.value


def summarized_refusals(sink: Callable[[dict], None]) -> Callable[[dict], None]:
    """auditd's refusal sink, without one line per rate-limited request.

    Those refusals are counted and summarized in the chain instead; writing
    each one to `refusals.jsonl` would move a flood from the chain to that
    file rather than bounding it.
    """

    def record(event: dict) -> None:
        if event.get("reason") == Refusal.RATE_LIMITED.value:
            return
        sink(event)

    # The bounded log's window flush and counters stay reachable (#211).
    for name in ("flush_due", "counters"):
        if callable(getattr(sink, name, None)):
            setattr(record, name, getattr(sink, name))
    return record


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


class SecondWriterRefused(RuntimeError):
    """Another az-auditd holds the chain."""


def hold_instance_lock(directory: Path) -> int:
    """Take the one-writer lock on the chain directory itself, or refuse.

    The bootstrap helper `azazel-auditd.service` and the ordinary path's
    `azazel-auditd-loop.service` (ADR 0008) run this same program on the same
    chain and sockets and are never meant to run together. Two would fork the
    chain (the module docstring), so the second refuses before it reads,
    binds or appends anything. The lock is an exclusive `flock` on the ledger
    directory's own descriptor: no file is added to a directory whose every
    entry the bootstrap check requires to be a segment. The descriptor is
    returned and must stay open for the life of the process; the kernel
    releases the lock when the process ends, so a crash never leaves the chain
    locked.
    """

    import fcntl
    import stat

    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise SecondWriterRefused("the audit chain is not a directory")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SecondWriterRefused("another az-auditd holds the chain") from None
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


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

    Before anything else it takes the one-writer lock (`hold_instance_lock`):
    a second instance exits 1 without reading the chain or binding a socket.
    """

    from .principal import PrincipalPolicy, SERVICE_ACCOUNTS
    from .runtime_paths import (
        audit_sink, audit_status_path, dedicated_listener, ledger_dir, socket_path,
        ui_copy_path,
    )
    from .serve import serve_forever
    from .systemd_notify import runtime_ready_callback

    try:
        lock = hold_instance_lock(ledger_dir())
    except (OSError, SecondWriterRefused):
        print("az-auditd: another audit writer holds the chain, or its lock is "
              "unusable; this instance writes nothing.", file=sys.stderr, flush=True)
        return 1
    del lock  # held, deliberately, until the process ends

    service = AuditService(SegmentedLedger(ledger_dir()), status_path=audit_status_path(),
                           ui_status_path=ui_copy_path("audit_status"))
    service.start()
    # Before serving, so status reflects this start (and a broken chain) at
    # once. Never raises: a missing leaf is logged and serving continues.
    service.write_status()
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
        additional_sockets=(dedicated_listener("audit-submit", SUBMIT_REGISTRY),),
        policy=PrincipalPolicy.resolve(service_accounts=SERVICE_ACCOUNTS + ("azexplain",)),
        audit=summarized_refusals(audit_sink("audit")),
        handler=service.handle,
        stop=lambda: (service.tick(), stop())[1],
        ready=startup_ready,
    )


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
