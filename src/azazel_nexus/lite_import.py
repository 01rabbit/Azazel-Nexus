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

`import started`, `admitted`, `quarantined`, `rolled back`, `state untrusted`,
`store tightened`, and `serving stopped by revocation`. A status read writes
nothing: a ledger that grew every time somebody looked at a screen would be
a ledger nobody can read, and looking is not a transition.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
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
    iter_served_with_member,
    read_anchors,
    read_claims,
    reading_for,
    refused_reading,
    verify_bundle,
)
from .store_dirs import fsync_directory, store_directory

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
    "read_knowledge_refs",
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
    STATE_UNTRUSTED = "lite.import.state_untrusted"
    STORE_TIGHTENED = "lite.import.store_tightened"
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

    def watermark(self) -> Optional[int]:
        return _read_watermark(self.state_path)


class _StateUntrusted(ValueError):
    """Fixed codes keep filesystem details out of audit and replies."""

    def __init__(self, code: str) -> None:
        super().__init__("anti-rollback state untrusted")
        self.code = code


def _read_watermark(path: Path) -> Optional[int]:
    """Absence is distinct from corrupt state; never follow a replacement link."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except PermissionError:
        # Unreadable says nothing about tampering; status reports it as an
        # unreadable store. Every caller still fails closed.
        raise
    except OSError:
        raise _StateUntrusted("WATERMARK_MALFORMED") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 32:
            raise _StateUntrusted("WATERMARK_MALFORMED")
        raw = os.read(fd, 33)
        if len(raw) > 32 or re.fullmatch(rb"[0-9]+\n?", raw) is None:
            raise _StateUntrusted("WATERMARK_MALFORMED")
        return int(raw)
    except OSError:
        raise _StateUntrusted("WATERMARK_MALFORMED") from None
    finally:
        os.close(fd)


def _inspect_store_file(path: Path) -> bool:
    """Import may replace only private, operator-owned regular files."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise _StateUntrusted("STORE_FILE_UNSAFE") from None
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or info.st_mode & 0o022):
        raise _StateUntrusted("STORE_FILE_UNSAFE")
    return True


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
        tightened = []
        try:
            try:
                for role in ("admitted", "state", "quarantine"):
                    directory = self.commissioned.root / role
                    try:
                        directory.lstat()
                    except FileNotFoundError:
                        continue
                    if _store_directory(directory):
                        tightened.append(role)
            finally:
                if tightened:
                    self._record(Transition.STORE_TIGHTENED,
                                 {"entry_id": entry_id, "at": now, "directories": tightened})
            current_exists = _inspect_store_file(
                self.commissioned.admitted / "current.tar.gz")
            _inspect_store_file(self.commissioned.state_path)
            try:
                floor = self.commissioned.watermark()
            except PermissionError:
                raise _StateUntrusted("WATERMARK_UNREADABLE") from None
            if floor is None and current_exists:
                raise _StateUntrusted("WATERMARK_MISSING")
        except (OSError, _StateUntrusted) as exc:
            code = exc.code if isinstance(exc, _StateUntrusted) else "STORE_FILE_UNSAFE"
            self._record(Transition.STATE_UNTRUSTED,
                         {"entry_id": entry_id, "at": now, "code": code})
            raise ImportRefused(
                "The anti-rollback state cannot be trusted. An operator must restore "
                "it (for example from backup) before importing; see "
                "docs/knowledge-lite-consumer.md section 7. No bundle was changed."
            ) from None
        raw = (self.commissioned.inbox / entry.display_name).read_bytes()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()

        try:
            anchors = self.commissioned.anchors()
            accepted = verify_bundle(
                raw,
                anchors=anchors,
                last_imported_version=floor if floor is not None else 0,
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

        accepted, reason = self._admitted_state()
        if accepted is None:
            if reason == "state_untrusted":
                return KnowledgeReading(
                    integrity=Integrity.QUARANTINED,
                    time_bound=TimeBound.ABSENT,
                    static_reference=StaticReference.ABSENT,
                    reason=("The admitted bundle is not served: it is older than "
                            "the anti-rollback watermark, or the "
                            "watermark is missing/malformed."),
                )
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
        return self._admitted_state()[0]

    def _admitted_state(self) -> tuple[Optional[BundleAccepted], str]:
        path = self.commissioned.admitted / "current.tar.gz"
        try:
            raw = path.read_bytes()
        except OSError:
            return None, ""
        try:
            accepted = verify_bundle(
                raw,
                anchors=self.commissioned.anchors(),
                last_imported_version=0,
            )
        except BundleRefused:
            # Re-verification makes revocation effective before the next import.
            return None, ""
        try:
            watermark = self.commissioned.watermark()
        except (_StateUntrusted, OSError):
            return None, "state_untrusted"
        if watermark is None or accepted.bundle_version < watermark:
            return None, "state_untrusted"
        return accepted, ""

    def _promote(self, raw: bytes, accepted: BundleAccepted, *, now: str) -> None:
        """Atomic. A reader never sees half an artifact."""

        _store_directory(self.commissioned.admitted)
        target = self.commissioned.admitted / "current.tar.gz"
        _atomic_write(target, raw)
        _store_directory(self.commissioned.state_path.parent)
        _atomic_write(
            self.commissioned.state_path, f"{accepted.bundle_version}\n".encode("utf-8")
        )

    def _quarantine(
        self, raw: bytes, digest: str, refusal: BundleRefused, *, now: str, entry_id: str
    ) -> None:
        """Hold it. Do not run it, extract it, serve it, or retry it."""

        _store_directory(self.commissioned.quarantine)
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


def _store_directory(path: Path) -> bool:
    return store_directory(path)


def _atomic_write(path: Path, payload: bytes) -> None:
    """Write through a temporary in the same directory, then move."""

    _store_directory(path.parent)
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=".lite.")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        # The bundle's rename must reach the disk before the watermark's:
        # otherwise a power loss can leave an old bundle under a new watermark.
        fsync_directory(path.parent)
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
        return status_refused(state, reason, generation, freshness)

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
        try:
            watermark = CommissionedLite(root).watermark()
        except _StateUntrusted:
            return summary("quarantined", "state_untrusted")
        if watermark is None or generation < watermark:
            return summary("quarantined", "state_untrusted")
        result = reader(accepted)
        # A repin observed during the read cannot yield an available answer.
        if trust.path != trust_path or bounded_read(trust_path, 65536) != trust_bytes:
            return summary("unavailable", "trust_unreadable")
        return result
    except BundleRefused:
        return summary("quarantined", "bundle_refused")
    except (OSError, ValueError, KeyError, TypeError, TrustRefused):
        return summary("unavailable", "store_unreadable")


#: The display keys `knowledge.status` adds to the four diagnostic ones. Each
#: is null unless a verified, trusted bundle was read. None of them carries a
#: claim body, key material, a path, an address or exception text.
STATUS_DISPLAY_KEYS = ("signer_key_ids", "bundle_digest_short", "static_count",
                       "current_count", "next_expiry")
STATUS_KEYS = ("state", "reason_code", "generation", "freshness", *STATUS_DISPLAY_KEYS)


def short_digest(digest: str) -> str:
    """`sha256:` and the first twelve hex digits: for display, never for checking."""
    if type(digest) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("digest refused")
    return digest[:19]


def status_refused(state: str, reason: str, generation=None, freshness="absent") -> dict:
    """The status shape when no trusted bundle can be described."""
    return {"state": state, "reason_code": reason, "generation": generation,
            "freshness": freshness, **{key: None for key in STATUS_DISPLAY_KEYS}}


def status_summary(*, root: Path, trust_root: Path, query_as_of: str) -> dict:
    """Bounded diagnostics: the four status keys plus fixed display facts."""
    def read(accepted):
        claims = read_claims(accepted, query_as_of=query_as_of)
        reading = reading_for(claims, query_as_of=query_as_of)
        return {"state": reading.overall, "reason_code": reading.overall,
                "generation": accepted.bundle_version,
                "freshness": reading.time_bound.value,
                "signer_key_ids": sorted(accepted.signers)[:8],
                "bundle_digest_short": short_digest(accepted.bundle_digest),
                "static_count": claims.timeless_count,
                "current_count": claims.served_count,
                "next_expiry": claims.next_expiry}

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
    source_kind: str
    generation: int
    trust_check: str
    #: The lookup's own `query_as_of`, RFC3339 UTC truncated to seconds: the
    #: instant against which this row was current (or static).
    as_of: str
    #: The bundle's signed dataset citation (manifest
    #: `profile.provenance.<dataset>.dataset.citation`) as plain text, or ""
    #: when the bundle declares none. Producer text: display data only.
    citation: str


KNOWLEDGE_REF_FIELDS = frozenset({
    "technique_id", "name", "summary", "claim_id", "bundle_digest", "freshness",
    "source_kind", "generation", "trust_check", "as_of", "citation"})
AS_OF = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", re.ASCII)


def as_of_text(query_as_of: str) -> str:
    """One RFC3339 instant as UTC seconds with `Z`; refuses a naive time."""
    from datetime import datetime, timezone

    raw = str(query_as_of)
    moment = datetime.fromisoformat(raw[:-1] + "+00:00" if raw.endswith("Z") else raw)
    if moment.tzinfo is None:
        raise ValueError("as_of refused")
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z")


def read_knowledge_refs(rows: list) -> tuple[KnowledgeRef, ...]:
    """Validate cited context again at each process boundary, never as authority."""
    fields = KNOWLEDGE_REF_FIELDS
    if type(rows) is not list or len(rows) > 16:
        raise ValueError("invalid_knowledge_refs")
    refs = []
    for row in rows:
        if (type(row) is not dict or set(row) != fields
                or any(type(row[key]) is not str for key in fields - {"generation"})):
            raise ValueError("invalid_knowledge_refs")
        try:
            if not AS_OF.fullmatch(row["as_of"]) or as_of_text(row["as_of"]) != row["as_of"]:
                raise ValueError
        except ValueError:
            raise ValueError("invalid_knowledge_refs") from None
        if (len(row["citation"]) > 160
                or _plain_text(row["citation"], 160, markup="`*#") != row["citation"]
                or any(not c.isprintable() for c in row["citation"])):
            raise ValueError("invalid_knowledge_refs")
        if (not TECHNIQUE_ID.fullmatch(row["technique_id"])
                or row["claim_id"] != row["technique_id"]
                or not 0 < len(row["name"]) <= 120 or len(row["summary"]) > 240
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", row["bundle_digest"])
                or row["freshness"] not in {"current", "static"}
                or row["source_kind"] != "knowledge_lite"
                or type(row["generation"]) is not int or not 0 <= row["generation"] < 2**63
                or row["trust_check"] != "verified"
                or any(not c.isprintable() for key in ("name", "summary") for c in row[key])):
            raise ValueError("invalid_knowledge_refs")
        refs.append(KnowledgeRef(**row))
    return tuple(refs)


@dataclass(frozen=True)
class LookupContext:
    refs: tuple[KnowledgeRef, ...]
    reason_code: str


#: Producer text is cut to this many characters before it is cleaned.
PLAIN_TEXT_INPUT_LIMIT = 1024


def _plain_text(value, limit: int, *, markup: str = "`*_#") -> str:
    # Strip HTML and Markdown links/formatting from producer descriptions.
    # Never interpret markup, follow a URL, or execute the resulting prose.
    import html

    if not isinstance(value, str):
        return ""
    # Bound the work before any pattern runs: the link and tag patterns are
    # quadratic on unclosed brackets, and no output keeps more than 240.
    value = html.unescape(value[:PLAIN_TEXT_INPUT_LIMIT])
    value = re.sub(r"<[^>]*>", " ", value)
    value = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", value)
    value = re.sub(r"https?://\S+|www\.\S+", " ", value)
    value = value.translate(str.maketrans("", "", markup))
    return " ".join("".join(c if c.isprintable() else " " for c in value).split())[:limit]


def _dataset_citation(manifest: Mapping, path: str) -> str:
    """The signed manifest's citation for the member's dataset, as plain text.

    `tables/<dataset>.jsonl` names the dataset, as Knowledge writes it. A
    missing or malformed provenance block is no citation (""), not a refusal:
    the bundle already passed every gate and citation is display data.
    """
    match = re.fullmatch(r"tables/([a-z0-9_]{1,64})\.jsonl", path, re.ASCII)
    if match is None:
        return ""
    value = manifest.get("profile")
    for key in ("provenance", match.group(1), "dataset", "citation"):
        value = value.get(key) if isinstance(value, Mapping) else None
    if not isinstance(value, str):
        return ""
    # Underscores are kept: dataset names such as `intel.attack_technique`.
    # Readers require a fixed point of the same cleaning (double-escaped
    # entities, a cut that ends in a space); a text that does not settle
    # quickly is no citation.
    text = _plain_text(value, 160, markup="`*#")
    for _ in range(4):
        again = _plain_text(text, 160, markup="`*#")
        if again == text:
            return text
        text = again
    return ""


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
        try:
            as_of = as_of_text(query_as_of)
        except ValueError:
            # The same refusal the expiry comparison gives this instant.
            raise BundleRefused(Gate.CONTENT, "BUNDLE_EXPIRY_INVALID",
                                "query_as_of is not RFC3339 UTC") from None
        refs = []
        citations: dict[str, str] = {}
        for path, row in iter_served_with_member(accepted, query_as_of=query_as_of):
            technique = row.get("technique_id")
            if not isinstance(technique, str) or technique not in wanted:
                continue
            name = _plain_text(row.get("name"), 120)
            if not name:
                continue
            if path not in citations:
                citations[path] = _dataset_citation(accepted.manifest, path)
            refs.append(KnowledgeRef(
                technique, name, _plain_text(row.get("description"), 240),
                technique, accepted.bundle_digest,
                "static" if row.get("agg_next_expiry") is None else "current",
                "knowledge_lite", accepted.bundle_version, "verified",
                as_of, citations[path],
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
