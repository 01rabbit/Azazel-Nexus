"""Offline operator import of a model artifact (#95; the model slice of #3).

```
inbox --> capacity precheck --> staging --> atomic promotion
                                     \\--> quarantine
                              rollback <--/
```

This is not a second supply route. #3 describes the Mission Pack lifecycle --
offline removable-media ingestion, staged verification, explicit operator
review, atomic activation, retained rollback -- and this module implements
that lifecycle for **model artifacts only**, in #3's vocabulary, so that the
rest of a Mission Pack composes with it later rather than routing around it.

What may be offered at all, and what offering it does not mean, is fixed by
`model_catalog` (#94). This module moves bytes; it decides nothing about
whether an artifact is permitted, and nothing at all about whether a model
may run.

## The seven boundaries hold, and are not reimplemented

The discipline established for the Knowledge Lite import (#67) applies
unchanged: the caller picks an entry and nothing else, every stage is
bounded, quarantine holds and does nothing else, the audit carries digests
and structured reasons rather than content, promotion is atomic, and a
status read writes nothing.

What is **not** carried over is the implementation. A Lite bundle is at most
512 MiB of JSON claims; a model artifact is tens of gibibytes of weights.
Three differences follow, and each one changes the code rather than the
prose:

| | Knowledge Lite | model artifact |
| --- | --- | --- |
| size | bounded by memory | never fits in memory; every read is chunked |
| enumeration | id is the content digest | hashing the inbox to list it would cost as much as importing from it |
| failure | advice goes stale | the disk fills, and a half-written file in the store is a file something may later run |

## Enumeration does not hash

A Lite entry id is the digest of the file's bytes, which is affordable
because the bytes fit. Hashing forty gibibytes to draw a listing would make
looking at the inbox as expensive as importing from it, and an operator
would stop looking.

So an entry id here is a digest over the entry's **identity** -- its name and
its size -- not its content. The property that matters is unchanged: a
caller cannot spell a path with one, and an id that a fresh enumeration does
not produce is a refusal rather than something to try. The integrity a
content id would have given is given instead by the catalog digest, checked
against the staged copy before anything is promoted. Including the size has
a second effect worth having: a file swapped between the listing and the
import no longer answers to the id it was listed under.

## The import never consumes the inbox

Nothing is moved out of the inbox and nothing is deleted from it. It is the
operator's media, and an import that failed halfway through would otherwise
have eaten the only copy.

The inbox is the node's **supply directory**, not only the operator's. An
operator places a file there; acquisition (#96) may place one there too. What
matters is what follows, and nothing follows differently: bytes that arrived
over a socket take the same enumeration, the same capacity precheck and the
same `verify_artifact` as bytes from a USB stick. **There is no shortcut for
downloaded bytes** -- if anything they deserve the stricter path, and they get
the identical one.

## Atomic promotion is a property of the filesystem, not of intent

Promotion is one `os.replace` from staging into the store, which is atomic
only **within one filesystem**. Across devices a move is a copy followed by
an unlink, and there is a window in which the store holds a partial file.
So staging and the store being on one device is checked, and an import
refuses when they are not. That is not a budget question; no amount of free
space makes a cross-device move atomic.

## Every interrupt window leaks rather than loses

Ordering is chosen so that a process killed at any point leaves a file
nobody references -- which the next import sweeps -- and never a generation
that references a file that is not there. Cleanup runs after the pointer
moves, never before.

## Importing is not admitting, and neither is installing

An artifact in the store is an artifact that is present. It is not admitted,
it is not activated, and nothing here can run it. Admission is decided
against a measured Core reserve (HG-05) and every gate after it; launching
is #97. `ModelReading.admitted` is `False` by construction, and this module
has no verb that could change that.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence

from .model_catalog import (
    CATALOG_FILENAME,
    CatalogRefused,
    CatalogState,
    ModelCatalog,
    ModelEntry,
    ModelReading,
    Refusal,
    absent_reading,
    artifact_filename,
    read_catalog,
    verify_artifact,
)

__all__ = [
    "CommissionedModels",
    "Generation",
    "ImportOutcome",
    "ImportRefusal",
    "ImportRefused",
    "InboxEntry",
    "MAX_ARTIFACT_BYTES",
    "MAX_INBOX_ENTRIES",
    "MAX_RETAINED_GENERATIONS",
    "MIN_FREE_HEADROOM_BYTES",
    "ModelImport",
    "Transition",
]

#: The largest artifact this node will take in. Tens of gibibytes is the
#: expected scale, so the ceiling is generous -- but a ceiling nonetheless:
#: a directory somebody else fills is a directory whose size is not this
#: node's choice.
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024 * 1024

#: The most inbox entries a listing will consider.
MAX_INBOX_ENTRIES = 32

#: Free space the node keeps for itself after an import. A node that imports
#: a model and can no longer write its own audit chain has not gained
#: anything.
MIN_FREE_HEADROOM_BYTES = 2 * 1024 * 1024 * 1024

#: Generations kept so that a rollback has somewhere to go. Retention is
#: what makes rollback possible, and what makes it cost disk.
MAX_RETAINED_GENERATIONS = 4

#: Chunk size for every read. Nothing here ever holds an artifact in memory.
CHUNK_BYTES = 8 * 1024 * 1024

MANIFEST_SCHEMA = "azazel-nexus/installed-models/1"

#: An entry id is a digest, so a caller cannot spell a path with one.
_ENTRY_ID = re.compile(r"^[0-9a-f]{64}$")


class Transition(str, Enum):
    """The only things written to the audit. A read is not among them."""

    IMPORT_STARTED = "mio.model.import.started"
    PROMOTED = "mio.model.import.promoted"
    QUARANTINED = "mio.model.import.quarantined"
    ROLLED_BACK = "mio.model.import.rolled_back"


class ImportRefusal(str, Enum):
    """Why an import did not reach the store.

    These are the import's own refusals -- what happens around the artifact.
    Why an *artifact* was refused is `model_catalog.Refusal`, reported on the
    reading, and the two vocabularies are kept apart: mixing them would put
    "there was not enough disk" and "the digest did not match" in one list,
    and only one of those is a statement about the model.
    """

    NOT_IN_INBOX = "not_in_inbox"
    INBOX_OVERFULL = "inbox_overfull"
    NOT_IN_CATALOG = "not_in_catalog"
    CATALOG_UNREADABLE = "catalog_unreadable"
    TOO_LARGE = "too_large"
    INSUFFICIENT_DISK = "insufficient_disk"
    PROMOTION_NOT_ATOMIC = "promotion_not_atomic"
    ARTIFACT_REFUSED = "artifact_refused"


class ImportRefused(Exception):
    """The import did not happen, and nothing was changed."""


@dataclass(frozen=True)
class InboxEntry:
    """One artifact an operator placed in the inbox."""

    entry_id: str
    size: int
    #: The name the operator gave it, for the operator's benefit only. It is
    #: never used to locate anything: the id is, and the id is looked up in a
    #: fresh enumeration.
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


def entry_id_for(*, display_name: str, size: int) -> str:
    """The id an inbox entry answers to.

    Over identity, not content -- see the module docstring.

    The encoding is unambiguous twice over, and both are load-bearing. The
    name's length is declared up front, and the size trails at a fixed eight
    bytes -- so the name is recoverable either by reading its length or by
    taking everything before the last eight bytes.

    Either alone would do today, which is the point: remove the fixed width
    and `("a", 11)` would otherwise encode as `("a1", 1)` does, and the
    length prefix is what stops it. Both are kept so that changing one does
    not silently spend the margin the other is holding.
    """

    name = display_name.encode("utf-8")
    body = b"azazel-nexus/model-inbox/v1\x00" + len(name).to_bytes(8, "big") + name
    body += size.to_bytes(8, "big")
    return hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class Generation:
    """One installed set, and the one before it."""

    number: int
    generation_id: str
    #: `model_id` -> the artifact digest installed for it.
    installed: Mapping[str, str]
    previous_generation_id: str = ""

    def digests(self) -> frozenset:
        return frozenset(self.installed.values())

    def as_event(self) -> dict:
        return {
            "generation": self.number,
            "generation_id": self.generation_id,
            "previous_generation_id": self.previous_generation_id,
            "installed": dict(sorted(self.installed.items())),
        }


@dataclass(frozen=True)
class ImportOutcome:
    """What one import did. Never raises for the node."""

    entry_id: str
    model_id: Optional[str]
    transition: Optional[Transition]
    reading: ModelReading
    refused_by: Optional[ImportRefusal] = None
    detail: str = ""
    generation: Optional[Generation] = None

    @property
    def promoted(self) -> bool:
        return self.transition is Transition.PROMOTED

    def as_event(self) -> dict:
        """Provenance and outcome. Never content, never key material."""

        event = {
            "entry_id": self.entry_id,
            "model_id": self.model_id,
            "transition": self.transition.value if self.transition else None,
            "refused_by": self.refused_by.value if self.refused_by else None,
            "detail": self.detail,
            **self.reading.as_event(),
        }
        if self.generation is not None:
            event.update(self.generation.as_event())
        return event


@dataclass(frozen=True)
class CommissionedModels:
    """Where everything lives, and what this node trusts. Built once.

    Every path is derived from `root`. Nothing here is a caller's argument at
    import time, which is the whole point: an import chooses an entry and a
    model id, and chooses nothing else. A caller that could name the staging
    directory could name the store.
    """

    root: Path
    #: Keys holding the **catalog-signing role**, from commissioned
    #: configuration. This module does not read a trust store, for the same
    #: reason `model_catalog` does not: the role model lives in one place.
    trusted_keys: Mapping[str, bytes]
    commissioning_digest: str

    @property
    def inbox(self) -> Path:
        """The operator's media. Read from, never written to, never emptied."""

        return self.root / "inbox"

    @property
    def staging(self) -> Path:
        return self.root / "staging"

    @property
    def store(self) -> Path:
        return self.root / "store"

    @property
    def quarantine(self) -> Path:
        return self.root / "quarantine"

    @property
    def catalog_path(self) -> Path:
        return self.root / "trust" / CATALOG_FILENAME

    @property
    def generations(self) -> Path:
        return self.root / "state" / "generations"

    @property
    def current_path(self) -> Path:
        return self.root / "state" / "current"

    def catalog(self) -> ModelCatalog:
        return read_catalog(
            self.catalog_path,
            trusted_keys=self.trusted_keys,
            commissioning_digest=self.commissioning_digest,
        )


class ModelImport:
    """The import service. One entry id and one model id in, one outcome out."""

    def __init__(
        self,
        commissioned: CommissionedModels,
        *,
        recorder: Optional[Callable[[Transition, Mapping], None]] = None,
    ) -> None:
        self.commissioned = commissioned
        self._record = recorder or (lambda transition, event: None)

    # -- enumeration -------------------------------------------------------

    def list_inbox(self) -> tuple:
        """What the operator has placed, bounded and sorted.

        Reads no artifact. The listing is what an operator looks at, and
        looking must not cost what importing costs.
        """

        inbox = self.commissioned.inbox
        try:
            names = sorted(child.name for child in inbox.iterdir())
        except OSError:
            return ()
        entries = []
        for name in names:
            if len(entries) >= MAX_INBOX_ENTRIES:
                break
            path = inbox / name
            try:
                status = os.lstat(path)
            except OSError:
                continue
            if not stat.S_ISREG(status.st_mode):
                # `lstat`, so a symlink is never sized by its target. A link
                # in the inbox names a file the operator may not have meant to
                # hand over, and following one would read outside the media
                # entirely. The same check drops directories and devices.
                continue
            entries.append(
                InboxEntry(
                    entry_id=entry_id_for(display_name=name, size=status.st_size),
                    size=status.st_size,
                    display_name=name,
                )
            )
        return tuple(entries)

    # -- the current installed set ----------------------------------------

    def current_generation(self) -> Optional[Generation]:
        """What is installed now. Reading this writes nothing."""

        number = self._current_number()
        if number is None:
            return None
        return self._read_generation(number)

    def reading_for(self, model_id: str) -> ModelReading:
        """Whether `model_id` is present on this node -- and nothing more.

        `present` here means the artifact is installed and verifies against
        its catalog entry. It does not mean admitted, and there is no call on
        this object that would make it so.
        """

        try:
            catalog = self.commissioned.catalog()
        except CatalogRefused as refused:
            return absent_reading(str(refused))
        entry = catalog.entry(model_id)
        if entry is None:
            # `EMPTY` is about this model, not about the file: the
            # catalog was read, it is trusted, and it offers this model
            # nothing. That is a different answer from never having read one.
            return ModelReading(
                model_id=model_id,
                state=CatalogState.EMPTY,
                refused_by=Refusal.UNKNOWN_MODEL,
                reason=f"{Refusal.UNKNOWN_MODEL.value}: the catalog does not name it",
            )
        generation = self.current_generation()
        if generation is None or model_id not in generation.installed:
            return ModelReading(
                model_id=model_id,
                state=CatalogState.DECLARED,
                refused_by=Refusal.ARTIFACT_ABSENT,
                reason=(
                    f"{Refusal.ARTIFACT_ABSENT.value}. The catalog offers it; "
                    "no generation installs it"
                ),
            )
        return verify_artifact(entry, artifact_root=self.commissioned.store)

    # -- import ------------------------------------------------------------

    def import_entry(
        self,
        entry_id: str,
        model_id: str,
        *,
        now: str,
        actor: str,
        license_acknowledged: bool = False,
    ) -> ImportOutcome:
        """Take one inbox entry in as `model_id`. Refuses; never repairs.

        `license_acknowledged` is the operator's, and defaults to withheld. An
        import that supplied it on the operator's behalf would be a licence
        gate that the only caller always satisfies, which is not a gate.
        """

        self._sweep_staging()
        self._record(
            Transition.IMPORT_STARTED,
            {"entry_id": entry_id, "model_id": model_id, "at": now, "actor": actor},
        )

        listing = self.list_inbox()
        if len(listing) >= MAX_INBOX_ENTRIES:
            return self._refused(
                entry_id, model_id, ImportRefusal.INBOX_OVERFULL,
                f"the inbox holds at least {MAX_INBOX_ENTRIES} entries; a "
                "listing that had to stop is a listing that may not contain "
                "the entry asked for",
            )
        found = [entry for entry in listing if entry.entry_id == entry_id]
        if not found:
            return self._refused(
                entry_id, model_id, ImportRefusal.NOT_IN_INBOX,
                "no entry in a fresh listing answers to that id. An id the "
                "inbox does not produce is a refusal, not a path to try",
            )
        entry = found[0]

        try:
            catalog = self.commissioned.catalog()
        except CatalogRefused as refused:
            return self._refused(
                entry_id, model_id, ImportRefusal.CATALOG_UNREADABLE, str(refused)
            )
        declared = catalog.entry(model_id)
        if declared is None:
            return self._refused(
                entry_id, model_id, ImportRefusal.NOT_IN_CATALOG,
                "an operator selects a model the catalog names. A model id "
                "that was never verified cannot be selected",
            )

        if entry.size > MAX_ARTIFACT_BYTES or declared.size_bytes > MAX_ARTIFACT_BYTES:
            return self._refused(
                entry_id, model_id, ImportRefusal.TOO_LARGE,
                f"{max(entry.size, declared.size_bytes)} bytes against a "
                f"ceiling of {MAX_ARTIFACT_BYTES}",
            )
        if entry.size != declared.size_bytes:
            # Free to check and absolute, so it is checked before any byte is
            # copied. Reported as the artifact's refusal, because it is one.
            return self._artifact_refused(
                entry_id,
                ModelReading(
                    model_id=model_id,
                    state=CatalogState.DECLARED,
                    refused_by=Refusal.SIZE_MISMATCH,
                    reason=(
                        f"{Refusal.SIZE_MISMATCH.value}: the inbox entry is "
                        f"{entry.size} bytes against {declared.size_bytes} declared"
                    ),
                ),
                now=now,
                actor=actor,
                staged=None,
            )

        self._prepare_directories()
        atomic, detail = self._promotion_is_atomic()
        if not atomic:
            return self._refused(
                entry_id, model_id, ImportRefusal.PROMOTION_NOT_ATOMIC, detail
            )
        room, detail = self._room_for(declared.size_bytes)
        if not room:
            return self._refused(
                entry_id, model_id, ImportRefusal.INSUFFICIENT_DISK, detail
            )

        try:
            staged = self._stage(entry, declared)
        except ImportRefused as refused:
            return self._artifact_refused(
                entry_id,
                ModelReading(
                    model_id=model_id,
                    state=CatalogState.DECLARED,
                    refused_by=Refusal.SIZE_MISMATCH,
                    reason=str(refused),
                ),
                now=now,
                actor=actor,
                staged=None,
            )

        reading = verify_artifact(
            declared,
            artifact_root=self.commissioned.staging,
            installed_lineage=self._installed_lineage(catalog),
            license_acknowledged=license_acknowledged,
            read_bytes=CHUNK_BYTES,
        )
        if reading.state is not CatalogState.PRESENT:
            return self._artifact_refused(
                entry_id, reading, now=now, actor=actor, staged=staged
            )

        generation = self._promote(declared, staged, now=now, actor=actor)
        self._record(
            Transition.PROMOTED,
            {
                "entry_id": entry_id,
                "model_id": model_id,
                "digest": declared.digest,
                "at": now,
                "actor": actor,
                **generation.as_event(),
            },
        )
        return ImportOutcome(
            entry_id=entry_id,
            model_id=model_id,
            transition=Transition.PROMOTED,
            reading=reading,
            generation=generation,
        )

    # -- rollback ----------------------------------------------------------

    def rollback(self, *, reason: str, actor: str, now: str) -> Generation:
        """Restore the generation before the current one.

        Refuses when there is none. A rollback that invented a predecessor
        would be an install wearing a rollback's name.
        """

        if not str(reason).strip():
            raise ImportRefused("a rollback records why it happened")
        number = self._current_number()
        if number is None or number <= 1:
            raise ImportRefused(
                "there is no earlier generation to restore. Retention is what "
                "makes a rollback possible, and this node has none"
            )
        target = self._read_generation(number - 1)
        if target is None:
            raise ImportRefused(
                f"generation {number - 1} is not retained; it cannot be restored"
            )
        leaving = self._read_generation(number)
        for digest in target.digests():
            if not self._store_holds(digest):
                raise ImportRefused(
                    "the earlier generation names an artifact the store no "
                    "longer holds; restoring it would activate a generation "
                    "that is not complete"
                )
        _atomic_write(self.commissioned.current_path, str(number - 1).encode("utf-8"))
        self._record(
            Transition.ROLLED_BACK,
            {
                "at": now,
                "actor": actor,
                "reason": reason,
                "from_generation": number,
                "from_generation_id": leaving.generation_id if leaving else "",
                "to_generation": target.number,
                "to_generation_id": target.generation_id,
                "digests": sorted(target.digests()),
            },
        )
        # After the pointer, never before: an interrupt here leaves a file
        # nobody references rather than a generation missing one.
        self._sweep_store()
        return target

    # -- internals ---------------------------------------------------------

    def _prepare_directories(self) -> None:
        for path in (
            self.commissioned.staging,
            self.commissioned.store,
            self.commissioned.quarantine,
            self.commissioned.generations,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def _promotion_is_atomic(self) -> tuple:
        """Staging and the store must share a filesystem."""

        try:
            staging = self.commissioned.staging.stat().st_dev
            store = self.commissioned.store.stat().st_dev
        except OSError as exc:
            return False, f"the staging and store devices could not be read: {exc}"
        if staging != store:
            return False, (
                "staging and the store are on different filesystems, so a "
                "promotion would be a copy and an unlink rather than a rename. "
                "No amount of free space makes that atomic, and the window it "
                "opens is one where the store holds a partial artifact"
            )
        return True, ""

    def _room_for(self, size: int) -> tuple:
        """Free space is checked before staging begins, never during.

        The predecessor stays where it is -- that is what rollback is -- so
        the store must hold both, plus what the node keeps for itself.
        """

        try:
            status = os.statvfs(self.commissioned.staging)
        except OSError as exc:
            return False, f"free space could not be read: {exc}"
        free = status.f_bavail * status.f_frsize
        needed = size + MIN_FREE_HEADROOM_BYTES
        if free < needed:
            return False, (
                f"{free} bytes free against {needed} needed ({size} for the "
                f"artifact, {MIN_FREE_HEADROOM_BYTES} kept for the node). The "
                "predecessor is retained so that a rollback has somewhere to "
                "go, so the store holds both"
            )
        return True, ""

    def _stage(self, entry: InboxEntry, declared: ModelEntry) -> Path:
        """Copy the artifact into staging, chunked and bounded.

        Never `shutil`: importing it would put `unpack_archive` one attribute
        away from a module whose contract is that it unpacks nothing.
        """

        source = self.commissioned.inbox / entry.display_name
        destination = self.commissioned.staging / artifact_filename(declared)
        handle, temporary = tempfile.mkstemp(
            dir=str(self.commissioned.staging), prefix=".model."
        )
        written = 0
        try:
            with os.fdopen(handle, "wb") as sink, open(source, "rb") as tap:
                while True:
                    chunk = tap.read(CHUNK_BYTES)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > declared.size_bytes:
                        raise ImportRefused(
                            f"{Refusal.SIZE_MISMATCH.value}: the artifact "
                            f"yielded more than the {declared.size_bytes} "
                            "bytes it declared. A file that grows while it is "
                            "read is not the file that was listed"
                        )
                    sink.write(chunk)
                sink.flush()
                os.fsync(sink.fileno())
            if written != declared.size_bytes:
                raise ImportRefused(
                    f"{Refusal.SIZE_MISMATCH.value}: {written} bytes read "
                    f"against {declared.size_bytes} declared"
                )
            os.replace(temporary, destination)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
        return destination

    def _artifact_refused(
        self,
        entry_id: str,
        reading: ModelReading,
        *,
        now: str,
        actor: str,
        staged: Optional[Path],
    ) -> ImportOutcome:
        """Quarantine holds the staged copy. It does nothing else with it."""

        held = ""
        if staged is not None:
            held = self._quarantine(staged, reading)
        self._record(
            Transition.QUARANTINED,
            {
                "entry_id": entry_id,
                "model_id": reading.model_id,
                "at": now,
                "actor": actor,
                "held_as": held,
                **reading.as_event(),
            },
        )
        return ImportOutcome(
            entry_id=entry_id,
            model_id=reading.model_id,
            transition=Transition.QUARANTINED,
            reading=reading,
            refused_by=ImportRefusal.ARTIFACT_REFUSED,
            detail=reading.reason,
        )

    def _quarantine(self, staged: Path, reading: ModelReading) -> str:
        """Move it aside under a name derived from what was observed.

        It is never executed, never extracted, never served and never retried.
        """

        self.commissioned.quarantine.mkdir(parents=True, exist_ok=True)
        observed = _digest_of(staged)
        held = self.commissioned.quarantine / f"{observed}.held"
        try:
            os.replace(staged, held)
        except OSError:
            return ""
        return held.name

    def _promote(
        self, declared: ModelEntry, staged: Path, *, now: str, actor: str
    ) -> Generation:
        """One rename into the store, then one rename of the pointer."""

        destination = self.commissioned.store / artifact_filename(declared)
        os.replace(staged, destination)

        current = self.current_generation()
        installed = dict(current.installed) if current else {}
        for superseded in declared.rollback_lineage:
            installed.pop(superseded, None)
        installed[declared.model_id] = declared.digest
        number = (current.number + 1) if current else 1
        generation = Generation(
            number=number,
            generation_id=_generation_id(number, installed),
            installed=installed,
            previous_generation_id=current.generation_id if current else "",
        )
        document = {
            "schema": MANIFEST_SCHEMA,
            "generation": generation.number,
            "generation_id": generation.generation_id,
            "previous_generation_id": generation.previous_generation_id,
            "commissioning_digest": self.commissioned.commissioning_digest,
            "recorded_at": now,
            "actor": actor,
            "installed": dict(sorted(installed.items())),
        }
        _atomic_write(
            self.commissioned.generations / f"{number}.json",
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
        # The generation file lands before the pointer moves. An interrupt
        # between them leaves a generation nothing points at, which the next
        # import overwrites -- not a pointer to a generation that is not there.
        _atomic_write(self.commissioned.current_path, str(number).encode("utf-8"))
        self._sweep_generations()
        self._sweep_store()
        return generation

    def _installed_lineage(self, catalog: ModelCatalog) -> tuple:
        """The ids the installed generation supersedes.

        Not the installed ids themselves: `verify_artifact` refuses an entry
        whose id appears here, so passing what *is* installed would refuse
        every reinstall and no actual rollback.
        """

        current = self.current_generation()
        if current is None:
            return ()
        superseded = set()
        for model_id in current.installed:
            entry = catalog.entry(model_id)
            if entry is not None:
                superseded.update(entry.rollback_lineage)
        return tuple(sorted(superseded))

    def _current_number(self) -> Optional[int]:
        try:
            text = self.commissioned.current_path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        try:
            number = int(text)
        except ValueError:
            return None
        return number if number >= 1 else None

    def _read_generation(self, number: int) -> Optional[Generation]:
        try:
            raw = (self.commissioned.generations / f"{number}.json").read_bytes()
        except OSError:
            return None
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        if not isinstance(document, dict) or document.get("schema") != MANIFEST_SCHEMA:
            return None
        installed = document.get("installed")
        if not isinstance(installed, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in installed.items()
        ):
            return None
        return Generation(
            number=number,
            generation_id=str(document.get("generation_id", "")),
            installed=dict(installed),
            previous_generation_id=str(document.get("previous_generation_id", "")),
        )

    def _retained(self) -> tuple:
        """The generations kept, newest last."""

        current = self._current_number()
        if current is None:
            return ()
        lowest = max(1, current - MAX_RETAINED_GENERATIONS + 1)
        kept = []
        for number in range(lowest, current + 1):
            generation = self._read_generation(number)
            if generation is not None:
                kept.append(generation)
        return tuple(kept)

    def _sweep_generations(self) -> None:
        """Drop generation files past the retention window."""

        current = self._current_number()
        if current is None:
            return
        lowest = current - MAX_RETAINED_GENERATIONS + 1
        for child in sorted(self.commissioned.generations.glob("*.json")):
            try:
                number = int(child.stem)
            except ValueError:
                continue
            if number < lowest:
                try:
                    child.unlink()
                except OSError:
                    pass

    def _sweep_store(self) -> None:
        """Remove artifacts no retained generation names.

        Runs only after the pointer has moved. An artifact nothing references
        is disk; an artifact a live generation references and that is missing
        is a node that cannot start.
        """

        referenced = set()
        for generation in self._retained():
            referenced.update(generation.digests())
        wanted = {digest.split(":", 1)[-1] for digest in referenced}
        try:
            children = sorted(self.commissioned.store.iterdir())
        except OSError:
            return
        for child in children:
            if child.name.split(".", 1)[0] in wanted:
                continue
            try:
                child.unlink()
            except OSError:
                pass

    def _sweep_staging(self) -> None:
        """Clear what an interrupted import left behind.

        Staging holds nothing between imports by design, so anything found
        here is debris. Sweeping at the start rather than in a handler means
        it also survives a process that was killed outright.
        """

        try:
            children = sorted(self.commissioned.staging.iterdir())
        except OSError:
            return
        for child in children:
            try:
                child.unlink()
            except OSError:
                pass

    def _store_holds(self, digest: str) -> bool:
        bare = digest.split(":", 1)[-1]
        try:
            return any(
                child.name.split(".", 1)[0] == bare
                for child in self.commissioned.store.iterdir()
            )
        except OSError:
            return False

    def _refused(
        self,
        entry_id: str,
        model_id: str,
        cause: ImportRefusal,
        detail: str,
    ) -> ImportOutcome:
        """Refused before anything was staged. Nothing was changed."""

        return ImportOutcome(
            entry_id=entry_id,
            model_id=model_id,
            transition=None,
            reading=ModelReading(
                model_id=model_id,
                state=CatalogState.DECLARED,
                refused_by=None,
                reason=f"{cause.value}: {detail}",
            ),
            refused_by=cause,
            detail=detail,
        )


def _generation_id(number: int, installed: Mapping[str, str]) -> str:
    document = {
        "generation": number,
        "installed": dict(sorted(installed.items())),
    }
    body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(
        b"azazel-nexus/installed-models/v1\x00" + body
    ).hexdigest()


def _digest_of(path: Path) -> str:
    """Chunked, because the thing being digested does not fit in memory."""

    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return "unreadable"
    return digest.hexdigest()


def _atomic_write(path: Path, payload: bytes) -> None:
    """Write through a temporary in the same directory, then move."""

    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=".model.")
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
