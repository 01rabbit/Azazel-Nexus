"""Offline operator import of a Knowledge Lite bundle (#67, E1-F).

The only supply route. There is no download, no peer connection and no
scheduler: an operator puts an artifact in a fixed directory and this reads
it. `tests/unit/test_lite_import.py` scans this module for the absence of
every verb that could fetch one.

## The caller chooses an entry, and chooses nothing else

An import takes **one inbox entry id** and nothing more. Not a cache root,
not a trust key, not a policy, not a generation number, not a quarantine
path. Every one of those comes from `CommissionedLite`, which is built once
from the commissioned configuration and is the only thing that knows where
anything lives.

That is the difference between a service and a general file-moving
primitive. A caller that could name the quarantine directory could name the
admitted directory; a caller that could supply a trust key could supply its
own.

## The inbox is enumerated, never passed through

`list_inbox()` returns the entries it found, each with an id derived from the
file's own content. `import_entry(entry_id)` looks that id up in a fresh
enumeration and refuses anything it does not find. **No path a caller
supplies ever reaches the filesystem.** An id that is not in the listing is a
refusal, not a path to try.

## A bundle's own trust material is subject matter, not input

A Lite bundle may contain whatever its author put in it. None of it updates
this node's trust root. The anchor is read from the commissioned location,
and a member named like a trust or state file is **refused** rather than
ignored -- something that tried is worth reporting.

Trust keys, permitted signer role, security epoch and accepted export
policies are derived from commissioned configuration only.

## Quarantine holds, and does nothing else

A refused bundle is moved into the quarantine directory under its digest. It
is never executed, never extracted, never served and never retried
automatically. The audit entry records the digest, the instant and a
structured reason -- **never the bundle's content, a claim's body, or key
material.**

## The audit records transitions, not reads

`import started`, `admitted`, `quarantined`, `rolled back`, and
`serving stopped by revocation`. A status read writes nothing: a ledger that
grew every time somebody looked at a screen would be a ledger nobody can
read, and looking is not a transition.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Callable, Iterator, Mapping, Optional, Sequence

from .lite_bundle import (
    BundleAccepted,
    BundleRefused,
    Claims,
    Gate,
    Integrity,
    KnowledgeReading,
    StaticReference,
    TimeBound,
    TrustAnchors,
    absent_reading,
    iter_served,
    read_anchors,
    read_claims,
    reading_for,
    refused_reading,
    verify_bundle,
)

__all__ = [
    "CommissionedLite",
    "ImportOutcome",
    "InboxEntry",
    "LiteImport",
    "MAX_INBOX_BYTES",
    "MAX_INBOX_ENTRIES",
    "Transition",
    "status_summary",
    "KnowledgeRef",
    "LookupContext",
    "lookup_context",
    "lookup_context_reading",
]

#: Members a bundle may not carry whatever its manifest says. A bundle does
#: not get to ship this node's trust root or its watermark.
REFUSED_MEMBERS = ("anchors.toml", "state.toml", "trust.toml", "revocations.json")

#: The most entries an inbox listing will consider, and the largest artifact
#: it will read. A directory somebody else fills is a directory whose size is
#: not this node's choice.
MAX_INBOX_ENTRIES = 32
MAX_INBOX_BYTES = 256 * 1024 * 1024

#: An entry id is a content digest, so it names the bytes rather than a
#: location. A caller cannot spell a path with one.
_ENTRY_ID = re.compile(r"^[0-9a-f]{64}$")


class Transition(str, Enum):
    """The only things written to the audit. A read is not among them."""

    IMPORT_STARTED = "lite.import.started"
    ADMITTED = "lite.import.admitted"
    QUARANTINED = "lite.import.quarantined"
    ROLLED_BACK = "lite.import.rolled_back"
    REVOKED = "lite.serving.stopped_by_revocation"


class ImportRefused(Exception):
    """The import did not happen, and nothing was changed."""


@dataclass(frozen=True)
class InboxEntry:
    """One artifact an operator placed in the inbox."""

    entry_id: str
    size: int
    #: The name the operator gave it, for the operator's benefit only. It is
    #: never used to locate anything: the id is.
    display_name: str

    def __post_init__(self) -> None:
        if not _ENTRY_ID.fullmatch(self.entry_id):
            raise ImportRefused(f"{self.entry_id!r} is not an entry id")

    def as_event(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "size": self.size,
            "display_name": self.display_name,
        }


@dataclass(frozen=True)
class CommissionedLite:
    """Where everything lives, and what this node trusts. Built once.

    Every path is derived from `root`. Nothing here is a caller's argument at
    import time, which is the whole point: an import chooses an entry and
    chooses nothing else.
    """

    root: Path

    @property
    def inbox(self) -> Path:
        """Where an operator puts an artifact. The only supply route."""

        return self.root / "inbox"

    @property
    def anchors_path(self) -> Path:
        """The commissioned trust root. Never taken from a bundle."""

        return self.root / "trust" / "anchors.toml"

    @property
    def admitted(self) -> Path:
        return self.root / "admitted"

    @property
    def quarantine(self) -> Path:
        return self.root / "quarantine"

    @property
    def state_path(self) -> Path:
        """The anti-rollback watermark this node holds."""

        return self.root / "state" / "watermark"

    def anchors(self) -> TrustAnchors:
        return read_anchors(self.anchors_path)

    def watermark(self) -> int:
        try:
            text = self.state_path.read_text(encoding="utf-8").strip()
        except OSError:
            return 0
        try:
            return int(text)
        except ValueError:
            return 0


@dataclass(frozen=True)
class ImportOutcome:
    """What one import did. Never raises for the node."""

    entry_id: str
    admitted: bool
    reading: KnowledgeReading
    #: The refusal, when there was one. Carries the gate and the code.
    refusal: Optional[BundleRefused] = None
    bundle_digest: str = ""

    def as_event(self) -> dict:
        """Provenance and outcome. Never content."""

        event = {
            "entry_id": self.entry_id,
            "admitted": self.admitted,
            "bundle_digest": self.bundle_digest,
            **self.reading.as_event(),
        }
        if self.refusal is not None:
            event["gate"] = self.refusal.gate.value
            event["code"] = self.refusal.code
        return event


class LiteImport:
    """The import service. One entry id in, one outcome out."""

    def __init__(
        self,
        commissioned: CommissionedLite,
        *,
        recorder: Optional[Callable[[Transition, Mapping], None]] = None,
    ) -> None:
        self.commissioned = commissioned
        self._record = recorder or (lambda transition, event: None)

    # -- enumeration -------------------------------------------------------

    def list_inbox(self) -> tuple[InboxEntry, ...]:
        """What is in the inbox, by content id. Reads nothing else.

        Sorted by id so that two nodes given the same inbox enumerate it the
        same way. A directory somebody else fills is bounded before it is
        walked.
        """

        inbox = self.commissioned.inbox
        entries: list[InboxEntry] = []
        try:
            names = sorted(path.name for path in inbox.iterdir() if path.is_file())
        except OSError:
            return ()
        for name in names[:MAX_INBOX_ENTRIES]:
            path = inbox / name
            try:
                size = path.stat().st_size
                if size > MAX_INBOX_BYTES:
                    continue
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                continue
            entries.append(InboxEntry(entry_id=digest, size=size, display_name=name))
        return tuple(sorted(entries, key=lambda entry: entry.entry_id))

    # -- the one verb a caller has ----------------------------------------

    def import_entry(self, entry_id: str, *, now: str) -> ImportOutcome:
        """Import one enumerated entry. Never raises for the node.

        `entry_id` is looked up in a fresh enumeration. A caller cannot name
        a path, and an id that is not in the listing is refused rather than
        tried.
        """

        if not _ENTRY_ID.fullmatch(str(entry_id)):
            raise ImportRefused(
                f"{entry_id!r} is not an entry id. An import selects an "
                "enumerated entry; it does not take a path"
            )
        listing = {entry.entry_id: entry for entry in self.list_inbox()}
        entry = listing.get(entry_id)
        if entry is None:
            raise ImportRefused(
                f"{entry_id} is not in the inbox. It is refused rather than "
                "looked for somewhere else"
            )

        self._record(Transition.IMPORT_STARTED, {"entry_id": entry_id, "at": now})
        raw = (self.commissioned.inbox / entry.display_name).read_bytes()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()

        try:
            anchors = self.commissioned.anchors()
            accepted = verify_bundle(
                raw,
                anchors=anchors,
                last_imported_version=self.commissioned.watermark(),
            )
            _refuse_trust_shaped_members(accepted)
        except BundleRefused as refusal:
            self._quarantine(raw, digest, refusal, now=now, entry_id=entry_id)
            return ImportOutcome(
                entry_id=entry_id,
                admitted=False,
                reading=refused_reading(refusal),
                refusal=refusal,
                bundle_digest=digest,
            )

        self._promote(raw, accepted, now=now)
        claims = read_claims(accepted, query_as_of=now)
        reading = reading_for(claims, query_as_of=now)
        self._record(
            Transition.ADMITTED,
            {
                "entry_id": entry_id,
                "at": now,
                "bundle_digest": digest,
                "bundle_version": accepted.bundle_version,
                "signers": list(accepted.signers),
                "served": claims.served_count,
                "withheld": claims.withheld_count,
                "static_reference": claims.timeless_count,
            },
        )
        return ImportOutcome(
            entry_id=entry_id,
            admitted=True,
            reading=reading,
            bundle_digest=digest,
        )

    # -- serving -----------------------------------------------------------

    def read(self, *, query_as_of: str) -> KnowledgeReading:
        """What the admitted bundle currently is. **Writes nothing.**

        A status read is not a transition, and a ledger that grew every time
        somebody looked at a screen would be a ledger nobody can read.
        """

        accepted = self._admitted_bundle()
        if accepted is None:
            held = self._quarantined()
            if held:
                # "We do not have it" and "we had it and it is not
                # trustworthy" are the two facts this vocabulary exists to
                # keep apart. A node that quarantined an artifact and then
                # reported `unavailable` has told its operator that nothing
                # happened.
                return KnowledgeReading(
                    integrity=Integrity.QUARANTINED,
                    time_bound=TimeBound.ABSENT,
                    static_reference=StaticReference.ABSENT,
                    reason=(
                        f"{held} artifact(s) are held in "
                        f"{self.commissioned.quarantine} and nothing is "
                        "admitted. They are isolated: not executed, not "
                        "extracted, not served and not retried. The "
                        "deterministic path is untouched"
                    ),
                )
            return absent_reading(str(self.commissioned.admitted))
        return reading_for(
            read_claims(accepted, query_as_of=query_as_of), query_as_of=query_as_of
        )

    def serve(self, *, query_as_of: str) -> Iterator[Mapping]:
        """The claims this node may serve right now, one at a time.

        Read-only, and a generator: nothing here builds a list of every claim
        in the bundle.
        """

        accepted = self._admitted_bundle()
        if accepted is None:
            return iter(())
        return iter_served(accepted, query_as_of=query_as_of)

    # -- internals ---------------------------------------------------------

    def _quarantined(self) -> int:
        """How many artifacts are held. Counted, never opened."""

        try:
            return sum(1 for path in self.commissioned.quarantine.iterdir() if path.is_file())
        except OSError:
            return 0

    def _admitted_bundle(self) -> Optional[BundleAccepted]:
        path = self.commissioned.admitted / "current.tar.gz"
        try:
            raw = path.read_bytes()
        except OSError:
            return None
        try:
            return verify_bundle(
                raw,
                anchors=self.commissioned.anchors(),
                last_imported_version=0,
            )
        except BundleRefused:
            # Re-verified on every read. A bundle that stopped verifying --
            # a revoked key, a rotated anchor -- stops being served without
            # waiting for the next import.
            return None

    def _promote(self, raw: bytes, accepted: BundleAccepted, *, now: str) -> None:
        """Atomic. A reader never sees half an artifact."""

        self.commissioned.admitted.mkdir(parents=True, exist_ok=True)
        target = self.commissioned.admitted / "current.tar.gz"
        _atomic_write(target, raw)
        self.commissioned.state_path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(
            self.commissioned.state_path, f"{accepted.bundle_version}\n".encode("utf-8")
        )

    def _quarantine(
        self, raw: bytes, digest: str, refusal: BundleRefused, *, now: str, entry_id: str
    ) -> None:
        """Hold it. Do not run it, extract it, serve it, or retry it."""

        self.commissioned.quarantine.mkdir(parents=True, exist_ok=True)
        _atomic_write(self.commissioned.quarantine / f"{entry_id}.tar.gz", raw)
        self._record(
            Transition.QUARANTINED,
            {
                # Digest, instant, structured reason. Nothing from inside.
                "entry_id": entry_id,
                "at": now,
                "bundle_digest": digest,
                "gate": refusal.gate.value,
                "code": refusal.code,
                "deterministic_path_affected": False,
            },
        )


def _refuse_trust_shaped_members(accepted: BundleAccepted) -> None:
    """A bundle does not get to ship this node's trust root."""

    for member in sorted(accepted.members):
        name = member.rsplit("/", 1)[-1]
        if name in REFUSED_MEMBERS:
            raise BundleRefused(
                Gate.MANIFEST,
                "BUNDLE_CARRIES_TRUST_MATERIAL",
                f"{member!r} is named like this node's trust or state material. "
                "A bundle is subject matter, not an input to the trust root, "
                "and something that tried is worth reporting rather than "
                "ignoring",
            )


def _atomic_write(path: Path, payload: bytes) -> None:
    """Write through a temporary in the same directory, then move."""

    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=".lite.")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _read_trusted(*, root: Path, trust_root: Path,
                  reader: Callable[[BundleAccepted], dict]) -> dict:
    """Read the imported tar store using separate commissioner-owned trust.

    The legacy import root's anchors are deliberately not consulted. Anchor
    metadata (key IDs, threshold, role, epoch and export policy) lives under
    ``trust_root/trust/anchors.toml``; its keys must also be currently pinned
    by TrustStore. KnowledgeLite supplies the same revocation-policy reader
    used by the content-generation cache, without treating a tar as that cache.
    The callback sees only the verified admitted bundle. Failures return fixed
    status symbols; no input or exception text leaves this adapter.
    """
    from .lite_service import KnowledgeLite
    from .lite_trust import TrustRefused, TrustStore
    from .model_paths import bounded_read
    from .revocation import RevocationRefused
    from .signature import SignatureRefused

    def summary(state, reason, generation=None, freshness="absent"):
        return {"state": state, "reason_code": reason,
                "generation": generation, "freshness": freshness}

    try:
        trust = TrustStore(trust_root)
        trust_path = trust.path
        trust_bytes = bounded_read(trust_path, 65536)
        digest = json.loads(trust_bytes)["commissioning_digest"]
        if not isinstance(digest, str) or not digest.strip():
            raise ValueError("commissioning binding required")
        keys = trust.keys(commissioning_digest=digest)
        anchors = CommissionedLite(trust_root).anchors()
        anchors = replace(anchors, keys={name: key for name, key in anchors.keys.items()
                                         if key in keys})
    except (OSError, ValueError, KeyError, TypeError, TrustRefused, BundleRefused, SignatureRefused):
        return summary("unavailable", "trust_unreadable")

    try:
        revocations = KnowledgeLite(trust_root, digest).revocations(bundle_keys=keys).current()
    except RevocationRefused:
        return summary("unavailable", "unverified")

    try:
        # Enumerating distinguishes an unreadable/missing store from absence.
        with os.scandir(root) as entries:
            next(entries, None)
        try:
            raw = bounded_read(root / "admitted" / "current.tar.gz", MAX_INBOX_BYTES)
        except FileNotFoundError:
            try:
                with os.scandir(root / "quarantine") as entries:
                    held = any(entry.is_file() for entry in entries)
            except FileNotFoundError:
                held = False
            return summary("quarantined" if held else "unavailable",
                           "quarantined" if held else "no_bundle")
    except (OSError, ValueError):
        return summary("unavailable", "store_unreadable")

    try:
        accepted = verify_bundle(raw, anchors=anchors, last_imported_version=0)
        _refuse_trust_shaped_members(accepted)
        generation = accepted.bundle_version
        if not 0 <= generation <= 2**63 - 1:
            return summary("quarantined", "bundle_refused")
        if (revocations.reason_for(digest=accepted.bundle_digest, generation=generation)
                or any(revocations.revokes_key(anchors.keys[name])
                       for name in accepted.signers)):
            return summary("quarantined", "revoked", generation)
        result = reader(accepted)
        # A repin observed during the read cannot yield an available answer.
        if trust.path != trust_path or bounded_read(trust_path, 65536) != trust_bytes:
            return summary("unavailable", "trust_unreadable")
        return result
    except BundleRefused:
        return summary("quarantined", "bundle_refused")
    except (OSError, ValueError, KeyError, TypeError, TrustRefused):
        return summary("unavailable", "store_unreadable")


def status_summary(*, root: Path, trust_root: Path, query_as_of: str) -> dict:
    """Bounded diagnostics, with exactly the existing status response shape."""
    def read(accepted):
        reading = reading_for(read_claims(accepted, query_as_of=query_as_of),
                              query_as_of=query_as_of)
        return {"state": reading.overall, "reason_code": reading.overall,
                "generation": accepted.bundle_version,
                "freshness": reading.time_bound.value}

    return _read_trusted(root=root, trust_root=trust_root, reader=read)


TECHNIQUE_ID = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?", re.ASCII)


@dataclass(frozen=True)
class KnowledgeRef:
    """Bounded advisory reference; the technique primary key is its claim id."""

    technique_id: str
    name: str
    summary: str
    claim_id: str
    bundle_digest: str
    freshness: str


@dataclass(frozen=True)
class LookupContext:
    refs: tuple[KnowledgeRef, ...]
    reason_code: str


def _plain_text(value, limit: int) -> str:
    # Strip HTML and Markdown links/formatting from producer descriptions.
    # Never interpret markup, follow a URL, or execute the resulting prose.
    import html

    if not isinstance(value, str):
        return ""
    value = html.unescape(value)
    value = re.sub(r"<[^>]*>", " ", value)
    value = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", value)
    value = re.sub(r"https?://\S+|www\.\S+", " ", value)
    value = value.translate(str.maketrans("", "", "`*_#"))
    return " ".join("".join(c if c.isprintable() else " " for c in value).split())[:limit]


def lookup_context_reading(*, root: Path, trust_root: Path,
                           technique_ids: tuple[str, ...], query_as_of: str) -> LookupContext:
    """Stream only served rows; failures expose a fixed reason, never input.

    Input and retained output are bounded independently of bundle size. The
    existing verifier still bounds and authenticates the complete archive.
    Order is the existing sorted-member/row order; duplicate queries are inert.
    """
    if (type(technique_ids) is not tuple or len(technique_ids) > 8
            or any(type(item) is not str or not TECHNIQUE_ID.fullmatch(item)
                   for item in technique_ids)):
        return LookupContext((), "invalid_technique_ids")
    wanted = frozenset(technique_ids)

    def read(accepted):
        if not wanted:
            return {"refs": (), "reason_code": "no_context"}
        refs = []
        for row in iter_served(accepted, query_as_of=query_as_of):
            technique = row.get("technique_id")
            if not isinstance(technique, str) or technique not in wanted:
                continue
            name = _plain_text(row.get("name"), 120)
            if not name:
                continue
            refs.append(KnowledgeRef(
                technique, name, _plain_text(row.get("description"), 240),
                technique, accepted.bundle_digest,
                "static" if row.get("agg_next_expiry") is None else "current",
            ))
            if len(refs) == 16:
                break
        return {"refs": tuple(refs), "reason_code": "available" if refs else "no_context"}

    result = _read_trusted(root=root, trust_root=trust_root, reader=read)
    return LookupContext(result.get("refs", ()), result["reason_code"])


def lookup_context(*, root: Path, trust_root: Path,
                   technique_ids: tuple[str, ...], query_as_of: str) -> tuple[KnowledgeRef, ...]:
    """No usable context is an empty tuple. See lookup_context_reading for why."""
    return lookup_context_reading(root=root, trust_root=trust_root,
                                  technique_ids=technique_ids, query_as_of=query_as_of).refs
