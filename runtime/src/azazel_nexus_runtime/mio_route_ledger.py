"""entryd's route ledger: daily segments, one chain, bounded retention (#211 S4).

The reading and verification rules are `azazel_nexus.route_ledger`'s; this
module adds the single writer. Rotation, ageing and the wall-clock guards are
`edge_intaked.DailySegments`', the same ones the explainer's store and the
incident ledger use: whole oldest segments are deleted, the newest and the
active segment never are, and a forward clock jump during a run cannot age
the ledger out.

Bounds:

* one segment per UTC day, at most `SEGMENT_BYTES`, divided into budgets
  that no other caller can spend: `EXPLAINER_SHARE` for the explainer,
  `ARBITER_SHARE` for the arbiter, `CALLER_SHARE` for each other caller
  within `CALLERS_POOL` for all of them together, and `CONTROL_RESERVE` for
  start and capability records. A caller's refusal records are charged to
  that caller;
* at most `RETENTION_DAYS` days and `RETENTION_BYTES` in total, so start-up
  verification reads at most `RETENTION_BYTES` whatever the node's age.

Before a segment is deleted its last link is written durably to
`retained-boundary.json`; verification starts there. A crash between that
write and the unlink leaves a segment the boundary already retired, which the
next start removes.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

from azazel_nexus.audit import (
    GENESIS_HASH,
    AuditChainBroken,
    AuditEntry,
    AuditLedger,
    AuditUnavailable,
    canonical_event_bytes,
)
from azazel_nexus.route_ledger import (
    ARCHIVE,
    BOUNDARY,
    LEGACY_UNVERIFIED,
    RouteChain,
    read_boundary,
    segment_paths,
)
from azazel_nexus.store_dirs import fsync_directory

from .edge_intaked import ELAPSED, DailySegments

#: The explainer's six advice requests a minute write about 20 MB a day
#: (about 2.3 KB a request). Its share holds that with headroom. A caller at
#: the 30-a-minute rate limit would write about 100 MB a day, so each share,
#: not the rate limit, is what bounds one caller's daily growth.
EXPLAINER_SHARE = 28 * 1024 * 1024
#: The arbiter (`azarbiter`) has its own share, so operators spending the
#: callers' pool cannot refuse its `mio.route` (#227). It is carved out of
#: what was one pool, so the segment stays 46 MiB.
ARBITER_SHARE = 4 * 1024 * 1024
CALLER_SHARE = 4 * 1024 * 1024
CALLERS_POOL = 12 * 1024 * 1024
CONTROL_RESERVE = 2 * 1024 * 1024
SEGMENT_BYTES = EXPLAINER_SHARE + ARBITER_SHARE + CALLERS_POOL + CONTROL_RESERVE
RETENTION_DAYS = 14
RETENTION_BYTES = 192 * 1024 * 1024
#: Budget keys. Any other key is one ordinary caller.
EXPLAINER = "explainer"
ARBITER = "arbiter"
CONTROL = "control"
UNATTRIBUTED = "unattributed"
#: What one request may write after admitting it. A request admitted with
#: less room than this could fail half-recorded.
REQUEST_HEADROOM = 64 * 1024
#: The envelope around an event's canonical bytes (sequence and two hashes).
_ENVELOPE = 256


class RouteSegmentFull(AuditUnavailable):
    """Today's segment, or this caller's share of it, has no room; nothing was written."""


def line_bytes(entry: AuditEntry) -> int:
    """The bytes `AuditLedger.append` wrote for `entry`, newline included."""

    return len(json.dumps(
        {"sequence": entry.sequence, "previous_hash": entry.previous_hash,
         "event_hash": entry.event_hash, "event": entry.event},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")) + 1


class RouteLedger(DailySegments):
    """The single writer of entryd's segmented route chain.

    Composition does no I/O: the directory is created, a legacy file is
    migrated and retention runs on first use. Reading an absent state
    directory is an empty chain and creates nothing, so the daemon's explicit
    `prepare()` refuses an absent installer-owned directory before binding.
    An in-process append (tests, harnesses) creates parents, as
    `AuditLedger.append` did for the single file.
    """

    def __init__(
        self, state_dir: Path, *, clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = ELAPSED, max_bytes: int = RETENTION_BYTES,
        days: int = RETENTION_DAYS, segment_bytes: int = SEGMENT_BYTES,
        reserve: int = CONTROL_RESERVE, explainer_share: int = EXPLAINER_SHARE,
        caller_share: int = CALLER_SHARE, callers_pool: int = CALLERS_POOL,
        arbiter_share: int = ARBITER_SHARE,
    ) -> None:
        # DailySegments.__init__ would create the directory at composition.
        self.state_dir = state_dir
        self.directory = state_dir / "route"
        self.max_bytes, self.days = max_bytes, days
        self.segment_bytes, self.reserve = segment_bytes, reserve
        self.explainer_share, self.caller_share = explainer_share, caller_share
        self.callers_pool, self.arbiter_share = callers_pool, arbiter_share
        #: Who ordinary records are charged to; set by the request owner.
        self.owner: str | None = None
        #: Bytes each budget key has written to `usage_segment`.
        self.usage: Counter = Counter()
        self.usage_segment: str | None = None
        self.monotonic, self.clock = monotonic, clock
        self.current = None
        self.age_anchor = self.clock_anchor = self.last_now = None
        self.future_segment = False
        self.chain = RouteChain(self.directory)
        self.legacy = state_dir / "route.jsonl"
        #: Called when an append opens a new segment; returns control events
        #: written first, so each segment carries what readers need.
        self.on_new_segment: Callable[[], list[Mapping[str, Any]]] | None = None
        #: Called with each event once the segment holds it, before any later
        #: step (directory sync, retention) that may still fail, so an owner's
        #: memory of what it recorded follows the ledger exactly (#227).
        self.on_written: Callable[[Mapping[str, Any]], None] | None = None
        self._prepared = False

    # -- preparation -----------------------------------------------------

    def _ensure(self, *, create: bool = False) -> None:
        if self._prepared:
            return
        if not os.path.lexists(self.state_dir):
            if not create:
                return
            try:
                self.state_dir.mkdir(mode=0o700, parents=True)
            except OSError as exc:
                raise AuditUnavailable("M.I.O. route ledger unavailable") from exc
        self.prepare()

    def prepare(self) -> None:
        """Create the segment directory, migrate, complete retention, probe."""

        try:
            info = os.lstat(self.state_dir)
            if not stat.S_ISDIR(info.st_mode):
                raise AuditUnavailable("M.I.O. state directory refused")
            try:
                os.mkdir(self.directory, 0o700)
                fsync_directory(self.state_dir)
            except FileExistsError:
                pass
            if not stat.S_ISDIR(os.lstat(self.directory).st_mode):
                raise AuditUnavailable("M.I.O. route segment directory refused")
            self._migrate()
            self._complete_retirement()
            path = self._target()
            existed = path.exists()
            os.close(self.open_segment(path, 0o600))
            if not existed:
                path.unlink()
            self.current = path
            self.retain()
        except OSError as exc:
            raise AuditUnavailable("M.I.O. route ledger unavailable") from exc
        self._prepared = True

    def _migrate(self) -> None:
        """Move a pre-segment `route.jsonl` aside, unchanged, in bounded time.

        Only the legacy file's last record is read (from the end, as
        `AuditLedger.head` does), so a start does not depend on its size.
        Order: durably write the boundary at that head, marked
        `legacy_unverified` with the file's size, then rename the file into
        the segment directory. A crash between the two leaves the legacy file
        and a boundary that names it; the next start finishes the rename.
        Full verification of the archive is offline
        (`azazel_nexus.route_ledger.verify_archive`, lab `audit`). A legacy
        file beside a segment chain is refused.
        """

        if not os.path.lexists(self.legacy):
            return
        info = os.lstat(self.legacy)
        if not stat.S_ISREG(info.st_mode):
            raise AuditUnavailable("legacy route ledger refused")
        # An unreadable last record refuses the start: there is no head to
        # continue from, and repairing the tail is the operator's decision.
        head = AuditLedger(self.legacy).head()
        boundary = read_boundary(self.directory)
        archive = self.directory / ARCHIVE
        if boundary is None:
            if segment_paths(self.directory) or os.path.lexists(archive):
                raise AuditChainBroken("legacy route ledger beside a segment chain")
            self._write_boundary({
                "sequence": head[0], "hash": head[1], "oldest": None,
                "retired": self.legacy.name,
                "legacy": {"state": LEGACY_UNVERIFIED, "sequence": head[0],
                           "hash": head[1], "size": info.st_size},
            })
        elif (boundary["retired"] != self.legacy.name
              or (boundary["sequence"], boundary["hash"]) != head
              or boundary.get("legacy", {}).get("size") != info.st_size
              or os.path.lexists(archive)):
            raise AuditChainBroken("legacy route ledger beside a segment chain")
        os.chmod(self.legacy, 0o400)
        os.rename(self.legacy, archive)
        fsync_directory(self.directory)
        fsync_directory(self.state_dir)

    def _complete_retirement(self) -> None:
        boundary = read_boundary(self.directory)
        if boundary is None or boundary["oldest"] is None:
            return
        for path in segment_paths(self.directory):
            if path.name <= boundary["retired"]:
                path.unlink()
        fsync_directory(self.directory)

    def _write_boundary(self, value: Mapping[str, Any]) -> None:
        fd, name = tempfile.mkstemp(dir=self.directory, prefix=".boundary-")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(canonical_event_bytes(value) + b"\n")
                os.fchmod(stream.fileno(), 0o600)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.directory / BOUNDARY)
            fsync_directory(self.directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def before_delete(self, path: Path) -> None:
        """Make the retired segment's last link the chain's durable anchor."""

        boundary = read_boundary(self.directory)
        paths = self.chain.segments(boundary)
        following = paths[paths.index(path) + 1]
        head = AuditLedger(path).head()
        if head == (0, GENESIS_HASH):
            head = self.chain.anchor(boundary)
        value = {"sequence": head[0], "hash": head[1],
                 "oldest": following.name, "retired": path.name}
        if boundary is not None and "legacy" in boundary:
            # The archive's identity outlives the segment that continued it.
            value["legacy"] = boundary["legacy"]
        self._write_boundary(value)

    # -- reading ---------------------------------------------------------

    def _target(self) -> Path:
        """Today's segment, never one before the newest (the chain only moves on)."""

        path = self.path_at(self.bounded(self.clock()))
        segments = self.chain.segments(read_boundary(self.directory))
        if segments and path < segments[-1]:
            return segments[-1]
        return path

    @property
    def path(self) -> Path:
        """The segment the next record goes to (for diagnostics and tests)."""

        return self._target()

    def __iter__(self) -> Iterator[AuditEntry]:
        self._ensure()
        return iter(self.chain)

    def head(self) -> tuple[int, str]:
        self._ensure()
        return self.chain.head()

    def verify(self, visit: Callable[[AuditEntry], None] | None = None) -> tuple[int, str]:
        """Verify the retained chain once; bounded by `RETENTION_BYTES`."""

        self._ensure()
        return self.chain.verify(visit)

    def _usage_for(self, name: str) -> Counter:
        return self.usage if self.usage_segment == name else Counter()

    def _fits(self, usage: Counter, key: str, size: int) -> bool:
        """Whether `size` more bytes stay inside `key`'s budget for the day."""

        if key == CONTROL:
            return usage[CONTROL] + size <= self.reserve
        if key == EXPLAINER:
            return usage[EXPLAINER] + size <= self.explainer_share
        if key == ARBITER:
            return usage[ARBITER] + size <= self.arbiter_share
        callers = sum(value for name, value in usage.items()
                      if name not in {CONTROL, EXPLAINER, ARBITER})
        return (usage[key] + size <= self.caller_share
                and callers + size <= self.callers_pool)

    def room(self, key: str | None = None) -> bool:
        """Whether `key` can make one more whole request in today's segment.

        Each caller spends only its own share, so a flooding caller exhausts
        itself, never the explainer's, the arbiter's or another caller's
        budget.
        """

        self._ensure()
        path = self._target()
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            size = 0
        return (size + REQUEST_HEADROOM <= self.segment_bytes
                and self._fits(self._usage_for(path.name), key or UNATTRIBUTED,
                               REQUEST_HEADROOM))

    def rebuild_usage(self, attribute: Callable[[Mapping[str, Any]], str]) -> None:
        """Recount today's budgets from today's segment (one bounded read).

        `attribute` names the budget key of each event in order; it is the
        request owner's rule, since only the owner knows its records.
        """

        self._ensure()
        path = self._target()
        usage: Counter = Counter()
        for entry in AuditLedger(path):
            usage[attribute(entry.event)] += line_bytes(entry)
        self.usage, self.usage_segment = usage, path.name

    # -- writing ---------------------------------------------------------

    def append(self, event: Mapping[str, Any], *, reserved: bool = False) -> AuditEntry:
        """Add one entry at the chain head, or add nothing and raise.

        `reserved` charges the record to `CONTROL_RESERVE` (start and
        capability records); otherwise it is charged to `owner`'s share.
        """

        self._ensure(create=True)
        path = self._target()
        # A segment opens when it holds no record yet, not when this call
        # creates it: a crash right after creating it leaves it empty, and
        # the next record must still carry the reading in (#227).
        try:
            opening = path.stat().st_size == 0
        except FileNotFoundError:
            opening = True
        head = self.chain.head()
        if opening and self.on_new_segment is not None:
            for carried in self.on_new_segment():
                written = self._write(path, carried, head, reserved=True)
                head = (written.sequence, written.event_hash)
        entry = self._write(path, event, head, reserved=reserved)
        self.current = path
        try:
            self.retain()
        except OSError as exc:
            raise AuditUnavailable("M.I.O. route retention failed") from exc
        return entry

    def _write(self, path: Path, event: Mapping[str, Any], head: tuple[int, str],
               *, reserved: bool) -> AuditEntry:
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            size = 0
        if self.usage_segment != path.name:
            self.usage, self.usage_segment = Counter(), path.name
        key = CONTROL if reserved else (self.owner or UNATTRIBUTED)
        need = len(canonical_event_bytes(event)) + _ENVELOPE
        if size + need > self.segment_bytes or not self._fits(self.usage, key, need):
            raise RouteSegmentFull("today's route budget is spent; the event was not recorded")
        created = size == 0 and not path.exists()
        try:
            entry = AuditLedger(path, private=True).append(event, chain_from=head)
        except AuditUnavailable:
            # The line may be in the file although its sync failed; if so,
            # the segment holds it and the owner must know.
            try:
                landed = AuditLedger(path).head()[0] == head[0] + 1
            except (OSError, AuditUnavailable, AuditChainBroken):
                landed = False
            if landed and self.on_written is not None:
                self.on_written(event)
            raise
        self.usage[key] += line_bytes(entry)
        if self.on_written is not None:
            self.on_written(entry.event)
        if created:
            try:
                fsync_directory(self.directory)
            except OSError as exc:
                raise AuditUnavailable("M.I.O. route segment not durable") from exc
        return entry
