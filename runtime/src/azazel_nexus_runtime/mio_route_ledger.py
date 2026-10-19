"""entryd's route ledger: daily segments, one chain, bounded retention (#211 S4).

The reading and verification rules are `azazel_nexus.route_ledger`'s; this
module adds the single writer. Rotation, ageing and the wall-clock guards are
`edge_intaked.DailySegments`', the same ones the explainer's store and the
incident ledger use: whole oldest segments are deleted, the newest and the
active segment never are, and a forward clock jump during a run cannot age
the ledger out.

Bounds:

* one segment per UTC day, at most `SEGMENT_BYTES`; ordinary records stop
  `CONTROL_RESERVE` short of that so start, capability and refusal records
  still fit on a day the request budget is spent;
* at most `RETENTION_DAYS` days and `RETENTION_BYTES` in total, so start-up
  verification reads at most `RETENTION_BYTES` whatever the node's age.

Before a segment is deleted its last link is written durably to
`retained-boundary.json`; verification starts there. A crash between that
write and the unlink leaves a segment the boundary already retired, which the
next start removes.
"""

from __future__ import annotations

import os
import stat
import tempfile
import time
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
    RouteChain,
    read_boundary,
    segment_paths,
)
from azazel_nexus.store_dirs import fsync_directory

from .edge_intaked import ELAPSED, DailySegments

#: About 20 MB a day at the explainer's six advice requests a minute; the
#: per-principal rate limit bounds a misbehaving caller to the same ceiling.
SEGMENT_BYTES = 32 * 1024 * 1024
RETENTION_DAYS = 14
RETENTION_BYTES = 192 * 1024 * 1024
CONTROL_RESERVE = 1024 * 1024
#: What one request may write after admitting it. A request admitted with
#: less room than this could fail half-recorded.
REQUEST_HEADROOM = 64 * 1024
#: The envelope around an event's canonical bytes (sequence and two hashes).
_ENVELOPE = 256


class RouteSegmentFull(AuditUnavailable):
    """Today's segment has no room for this record; nothing was written."""


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
        reserve: int = CONTROL_RESERVE,
    ) -> None:
        # DailySegments.__init__ would create the directory at composition.
        self.state_dir = state_dir
        self.directory = state_dir / "route"
        self.max_bytes, self.days = max_bytes, days
        self.segment_bytes, self.reserve = segment_bytes, reserve
        self.monotonic, self.clock = monotonic, clock
        self.current = None
        self.age_anchor = self.clock_anchor = self.last_now = None
        self.future_segment = False
        self.chain = RouteChain(self.directory)
        self.legacy = state_dir / "route.jsonl"
        #: Called when an append opens a new segment; returns control events
        #: written first, so each segment carries what readers need.
        self.on_new_segment: Callable[[], list[Mapping[str, Any]]] | None = None
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
        """Move a pre-segment `route.jsonl` aside, verified and unchanged.

        Order: verify it, durably write the boundary at its head, then rename
        it into the segment directory. A crash between the two leaves the
        legacy file and a boundary that names it, and the next start finishes
        the rename. A legacy file beside a segment chain is refused.
        """

        if not os.path.lexists(self.legacy):
            return
        if not stat.S_ISREG(os.lstat(self.legacy).st_mode):
            raise AuditUnavailable("legacy route ledger refused")
        legacy = AuditLedger(self.legacy)
        legacy.verify()
        head = legacy.head()
        boundary = read_boundary(self.directory)
        archive = self.directory / ARCHIVE
        if boundary is None:
            if segment_paths(self.directory) or os.path.lexists(archive):
                raise AuditChainBroken("legacy route ledger beside a segment chain")
            self._write_boundary({"sequence": head[0], "hash": head[1],
                                  "oldest": None, "retired": self.legacy.name})
        elif (boundary["retired"] != self.legacy.name
              or (boundary["sequence"], boundary["hash"]) != head
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
        self._write_boundary({"sequence": head[0], "hash": head[1],
                              "oldest": following.name, "retired": path.name})

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

    def room(self) -> bool:
        """Whether today's segment can take one more whole request."""

        self._ensure()
        path = self._target()
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            size = 0
        return size + REQUEST_HEADROOM <= self.segment_bytes - self.reserve

    # -- writing ---------------------------------------------------------

    def append(self, event: Mapping[str, Any], *, reserved: bool = False) -> AuditEntry:
        """Add one entry at the chain head, or add nothing and raise.

        `reserved` lets start, capability and refusal records use the last
        `CONTROL_RESERVE` bytes of the day's segment.
        """

        self._ensure(create=True)
        path = self._target()
        segments = self.chain.segments(read_boundary(self.directory))
        opening = not segments or path != segments[-1]
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
        limit = self.segment_bytes if reserved else self.segment_bytes - self.reserve
        if size + len(canonical_event_bytes(event)) + _ENVELOPE > limit:
            raise RouteSegmentFull("today's route segment is full; the event was not recorded")
        created = size == 0 and not path.exists()
        entry = AuditLedger(path, private=True).append(event, chain_from=head)
        if created:
            try:
                fsync_directory(self.directory)
            except OSError as exc:
                raise AuditUnavailable("M.I.O. route segment not durable") from exc
        return entry
