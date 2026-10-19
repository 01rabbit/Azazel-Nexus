"""Read and verify M.I.O. entry's daily route ledger segments (#211 S4).

entryd's route ledger was one `route.jsonl`, verified in full at every start,
and grew by about 20 MB a day under the explainer's advice load. It is now a
directory of daily `YYYY-MM-DD.jsonl` segments with one chain running through
all of them: a segment's first entry chains onto the last hash of the segment
before it, so a deleted or reordered file is a break, not a shorter chain.

Retention deletes whole oldest segments only. Before it does, the writer
durably records the deleted segment's last link in `retained-boundary.json`;
verification then starts from that link rather than from genesis, so the
cost of verifying is bounded by what retention keeps, not by node age.

Migration of a pre-segment `route.jsonl` moves the file, unchanged, to
`route/legacy-route.jsonl` and anchors the first segment on its head. Only its
last record is read at start, so a start never depends on its size; the
boundary records it as `legacy_unverified` with that head and its size. The
archive is kept read-only and is not deleted by retention. It remains a
genesis-rooted chain; `verify_archive` checks it in full, offline, against
the head the first segment continued from.

This module only reads. The writer is `azazel_nexus_runtime.mio_route_ledger`;
`azazel-nexus status`, the lab and the E2E harness read through this one.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from pathlib import Path

from .audit import GENESIS_HASH, AuditChainBroken, AuditEntry, AuditLedger

__all__ = [
    "ARCHIVE",
    "BOUNDARY",
    "LEGACY",
    "LEGACY_UNVERIFIED",
    "ROUTE_DIR",
    "RouteChain",
    "read_boundary",
    "segment_paths",
    "verify_archive",
]

#: Installed locations, relative to the filesystem root (`AZAZEL_ROOT` in harnesses).
ROUTE_DIR = "/var/lib/azazel/state/mio/route"
#: The pre-segment single file, beside the segment directory.
LEGACY = "/var/lib/azazel/state/mio/route.jsonl"
#: The migrated legacy file, inside the segment directory.
ARCHIVE = "legacy-route.jsonl"
BOUNDARY = "retained-boundary.json"
#: How a migrated archive is described until someone verifies it offline.
LEGACY_UNVERIFIED = "legacy_unverified"

_SEGMENT = re.compile(r"\A\d{4}-\d{2}-\d{2}\.jsonl\Z")
_HASH = re.compile(r"\A[0-9a-f]{64}\Z")


def segment_paths(directory: Path) -> tuple[Path, ...]:
    """Daily segments in chain order. A name sorts chronologically."""

    if not directory.is_dir():
        return ()
    return tuple(sorted(path for path in directory.iterdir() if _SEGMENT.match(path.name)))


def read_boundary(directory: Path) -> dict | None:
    """The retained left boundary, or None when the chain starts at genesis."""

    path = directory / BOUNDARY
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise AuditChainBroken("route boundary is not a record") from exc
    legacy = value.get("legacy") if type(value) is dict else None
    if legacy is not None and (
            type(legacy) is not dict or set(legacy) != {"state", "sequence", "hash", "size"}
            or legacy["state"] != LEGACY_UNVERIFIED
            or type(legacy["sequence"]) is not int or legacy["sequence"] < 0
            or not isinstance(legacy["hash"], str) or not _HASH.match(legacy["hash"])
            or type(legacy["size"]) is not int or legacy["size"] < 0):
        raise AuditChainBroken("route boundary is malformed")
    if (type(value) is not dict
            or set(value) - {"legacy"} != {"sequence", "hash", "oldest", "retired"}
            or type(value["sequence"]) is not int or value["sequence"] < 0
            or not isinstance(value["hash"], str) or not _HASH.match(value["hash"])
            or not (value["oldest"] is None or (isinstance(value["oldest"], str)
                                                and _SEGMENT.match(value["oldest"])))
            or not isinstance(value["retired"], str)
            or not (_SEGMENT.match(value["retired"]) or value["retired"] == Path(LEGACY).name)
            or (value["oldest"] is not None and _SEGMENT.match(value["retired"])
                and value["retired"] >= value["oldest"])):
        raise AuditChainBroken("route boundary is malformed")
    return value


class RouteChain:
    """Retained segments of one chain, read-only.

    A segment named at or before the boundary's `retired` segment was retired
    by a retention pass that crashed before its unlink; it is outside the
    retained chain and is ignored here (the writer removes it).
    """

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def boundary(self) -> dict | None:
        return read_boundary(self.directory)

    def segments(self, boundary: dict | None = None) -> tuple[Path, ...]:
        paths = segment_paths(self.directory)
        if boundary is not None and _SEGMENT.match(boundary["retired"]):
            paths = tuple(path for path in paths if path.name > boundary["retired"])
        return paths

    def anchor(self, boundary: dict | None = None) -> tuple[int, str]:
        if boundary is None:
            return 0, GENESIS_HASH
        return boundary["sequence"], boundary["hash"]

    def __iter__(self) -> Iterator[AuditEntry]:
        for segment in self.segments(self.boundary()):
            yield from AuditLedger(segment)

    def head(self) -> tuple[int, str]:
        """The newest record's link, read from the end of the newest segment."""

        boundary = self.boundary()
        for segment in reversed(self.segments(boundary)):
            head = AuditLedger(segment).head()
            if head != (0, GENESIS_HASH):
                return head
        return self.anchor(boundary)

    def verify(self, visit: Callable[[AuditEntry], None] | None = None) -> tuple[int, str]:
        """Walk every retained segment from the boundary; return the head.

        `visit` sees each verified entry in order, so a caller that needs to
        scan the history reads it once.
        """

        boundary = self.boundary()
        segments = self.segments(boundary)
        if boundary is not None and boundary["oldest"] is not None and (
                not segments or segments[0].name != boundary["oldest"]):
            raise AuditChainBroken("route boundary does not match the oldest segment")
        expected_sequence, expected_hash = self.anchor(boundary)
        for segment in segments:
            for entry in AuditLedger(segment):
                if entry.sequence != expected_sequence + 1:
                    raise AuditChainBroken(
                        f"{segment.name} entry {entry.sequence} follows {expected_sequence}")
                if entry.previous_hash != expected_hash:
                    raise AuditChainBroken(
                        f"{segment.name} entry {entry.sequence} does not chain onto the head")
                if entry.recomputed() != entry.event_hash:
                    raise AuditChainBroken(
                        f"{segment.name} entry {entry.sequence} does not hash to what it records")
                expected_sequence, expected_hash = entry.sequence, entry.event_hash
                if visit is not None:
                    visit(entry)
        return expected_sequence, expected_hash


def verify_archive(directory: Path) -> tuple[int, str] | None:
    """Verify a migrated legacy archive in full; offline, never at start.

    Returns its head, or None when there is no archive. The archive must be a
    genesis-rooted chain whose head and size are those the boundary recorded
    at migration, which is the link the first segment continued from.
    """

    archive = directory / ARCHIVE
    if not archive.is_file():
        return None
    boundary = read_boundary(directory)
    legacy = boundary.get("legacy") if boundary is not None else None
    if legacy is None:
        raise AuditChainBroken("route archive has no recorded migration head")
    ledger = AuditLedger(archive)
    ledger.verify()
    head = ledger.head()
    if head != (legacy["sequence"], legacy["hash"]) or archive.stat().st_size != legacy["size"]:
        raise AuditChainBroken("route archive does not match its recorded migration head")
    return head


def main(argv: list[str] | None = None) -> int:
    """`python3 -m azazel_nexus.route_ledger [ROUTE_DIR]`: verify offline.

    Verifies the retained segment chain and, when present, the migrated
    legacy archive in full. Read-only; run as root (the directory is 0700).
    """

    import sys

    args = sys.argv[1:] if argv is None else argv
    directory = Path(args[0]) if args else Path(ROUTE_DIR)
    head = RouteChain(directory).verify()
    print(f"segments verified: head sequence {head[0]}")
    archive = verify_archive(directory)
    print("legacy archive: absent" if archive is None
          else f"legacy archive verified: head sequence {archive[0]}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
