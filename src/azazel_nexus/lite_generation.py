"""Generations of the Knowledge Lite cache, and rollback (#6, E1).

`generation.py` holds the same doctrine for *configuration*: numbers only
increase, a rollback is a new generation rather than a moved pointer, and a
digest is re-derived rather than remembered. This module is the Knowledge Lite
counterpart. It is separate rather than shared because the two describe
different things -- a configuration generation owns a tree of files and a
commissioning digest, while a Lite generation owns nothing at all: it *names*
an artifact that lives in the content store, and records who signed it.

That indirection is what makes rollback possible rather than aspirational.
The previous `StagedReader` replaced `live` by rename and then deleted the
directory it displaced, so there was nothing to go back to; the structure, not
an omission, is what prevented rollback. Here the artifact bytes are addressed
by digest and shared, a generation record is a few hundred bytes of metadata,
and going back is a matter of naming an address that is still there.

Three refusals carry the weight:

*A rollback target is re-verified, not trusted.* `roll_back_to` reads the
artifact through the content store, which re-derives its digest. Rolling back
to an artifact that has since been altered is the one rollback that must fail.

*Pruning may not orphan a retained generation.* A blob is removed only when no
retained generation names it, and the generation `live` points at is retained
whatever the retention count says.

*A rollback records why and who.* An unexplained reversal is indistinguishable
from a mistake about to be repeated.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from .content_store import ContentStore, ContentTampered, parse_digest
from .signature import PUBLIC_KEY_BYTES
from .store_dirs import store_directory

__all__ = [
    "LiteGeneration",
    "LiteGenerationRefused",
    "LiteGenerationStore",
]


class LiteGenerationRefused(Exception):
    """The generation was not created, promoted, or rolled back to."""


@dataclass(frozen=True)
class LiteGeneration:
    """One admitted Knowledge Lite artifact, named rather than held."""

    number: int
    artifact_digest: str
    signature_digest: str
    signer_key: str
    admitted_at: str
    supersedes: Optional[int] = None
    rolled_back_from: Optional[int] = None
    rollback_reason: Optional[str] = None
    actor: Optional[str] = None

    def __post_init__(self) -> None:
        if self.number < 1:
            raise LiteGenerationRefused("generation numbers start at 1")
        parse_digest(self.artifact_digest)
        parse_digest(self.signature_digest)
        if len(self.signer_key) != PUBLIC_KEY_BYTES * 2:
            raise LiteGenerationRefused(
                f"a signer key is {PUBLIC_KEY_BYTES * 2} hex characters; a "
                "generation that cannot name its signer cannot be audited"
            )
        if not self.admitted_at.strip():
            raise LiteGenerationRefused("a generation records when it was admitted")
        if self.supersedes is not None and self.supersedes >= self.number:
            raise LiteGenerationRefused(
                f"generation {self.number} claims to supersede {self.supersedes}; "
                "generations only move forward"
            )
        if self.rolled_back_from is not None:
            if not (self.rollback_reason or "").strip():
                raise LiteGenerationRefused(
                    "a rollback must record why; an unexplained reversal is "
                    "indistinguishable from a mistake repeated later"
                )
            if not (self.actor or "").strip():
                raise LiteGenerationRefused("a rollback must record who performed it")

    @property
    def is_rollback(self) -> bool:
        return self.rolled_back_from is not None

    def as_event(self) -> dict:
        """The audit event for this generation. Provenance, never content."""

        event = {
            "event_type": "lite.generation.rolled_back"
            if self.is_rollback
            else "lite.generation.promoted",
            "generation": self.number,
            "artifact_digest": self.artifact_digest,
            "signature_digest": self.signature_digest,
            "signer_key": self.signer_key,
            "admitted_at": self.admitted_at,
            "supersedes": self.supersedes,
        }
        if self.is_rollback:
            event["rolled_back_from"] = self.rolled_back_from
            event["rollback_reason"] = self.rollback_reason
            event["actor"] = self.actor
        return event


@dataclass(frozen=True)
class LiteGenerationStore:
    """The generations on disk, the live pointer, and the rules for both."""

    root: Path
    content: ContentStore

    @property
    def generations(self) -> Path:
        return self.root / "generations"

    @property
    def live_pointer(self) -> Path:
        return self.root / "live"

    # -- reading -----------------------------------------------------------

    def numbers(self) -> tuple[int, ...]:
        if not self.generations.is_dir():
            return ()
        return tuple(
            sorted(
                int(child.name)
                for child in self.generations.iterdir()
                if child.is_dir() and child.name.isdigit()
            )
        )

    def read(self, number: int) -> LiteGeneration:
        path = self.generations / str(number) / "generation.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise LiteGenerationRefused(
                f"generation {number} has no readable metadata: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise LiteGenerationRefused(
                f"generation {number} has unreadable metadata: {exc}"
            ) from exc
        try:
            return LiteGeneration(**raw)
        except TypeError as exc:
            raise LiteGenerationRefused(
                f"generation {number} is not a generation record: {exc}"
            ) from exc

    def live(self) -> Optional[LiteGeneration]:
        """The generation being served, or `None` if nothing was promoted.

        Read from the pointer rather than taken as "the highest number",
        because after a prune those are the same and after a failed promotion
        they are not -- and the difference is which artifact is being served.
        """

        try:
            raw = self.live_pointer.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if not raw.isdigit():
            raise LiteGenerationRefused(
                f"the live pointer holds {raw!r}, which is not a generation number"
            )
        return self.read(int(raw))

    def artifact_of(self, generation: LiteGeneration) -> bytes:
        """The artifact bytes, re-derived from their address on the way out."""

        return self.content.get(generation.artifact_digest)

    def signature_of(self, generation: LiteGeneration) -> bytes:
        """The detached signature that admitted this artifact.

        Kept so that the signature can be checked **again** at serve time. The
        content address already binds the bytes to the digest, but nothing
        else binds the digest in a generation record to a key: a tampered
        record could name a different admitted artifact. Re-verifying is what
        makes `signer_key` a proven fact rather than a recorded claim -- and it
        is how revoking a key stops the cache it signed.
        """

        return self.content.get(generation.signature_digest)

    # -- writing -----------------------------------------------------------

    def promote(
        self,
        *,
        artifact_digest: str,
        signature_digest: str,
        signer_key: str,
        admitted_at: str,
        rolled_back_from: Optional[int] = None,
        rollback_reason: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> LiteGeneration:
        """Record a new generation and make it live.

        The artifact must already be in the content store: a generation names
        an address, and naming one that holds nothing would produce a live
        pointer to an artifact that cannot be served.
        """

        for label, digest in (("artifact", artifact_digest), ("signature", signature_digest)):
            if not self.content.has(digest):
                raise LiteGenerationRefused(
                    f"no content addressed {digest}; a generation names an "
                    f"{label} that is already stored, never one that might arrive"
                )

        numbers = self.numbers()
        number = (numbers[-1] + 1) if numbers else 1
        generation = LiteGeneration(
            number=number,
            artifact_digest=artifact_digest,
            signature_digest=signature_digest,
            signer_key=signer_key,
            admitted_at=admitted_at,
            supersedes=numbers[-1] if numbers else None,
            rolled_back_from=rolled_back_from,
            rollback_reason=rollback_reason,
            actor=actor,
        )

        directory = self.generations / str(number)
        if directory.exists():
            raise LiteGenerationRefused(
                f"generation {number} already exists; a generation is promoted "
                "once and never edited in place"
            )
        store_directory(self.generations)
        directory.mkdir(mode=0o750, exist_ok=False)
        store_directory(directory)
        fd = os.open(directory / "generation.json",
                     os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o640)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o640)
            stream.write(json.dumps(asdict(generation), sort_keys=True, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        _atomic_write(self.live_pointer, f"{number}\n".encode("utf-8"))
        return generation

    def roll_back_to(
        self, number: int, *, admitted_at: str, reason: str, actor: str
    ) -> LiteGeneration:
        """Promote an older generation's artifact as a **new** generation.

        The pointer never moves backwards. What was rolled back keeps its own
        number and stays on disk, so the history reads as a reversal rather
        than as an absence.
        """

        target = self.read(number)
        current = self.live()
        if current is None:
            raise LiteGenerationRefused("there is nothing to roll back")
        if number == current.number:
            raise LiteGenerationRefused(
                f"generation {number} is already live; a rollback to the live "
                "generation would record a reversal that did not happen"
            )

        for digest in (target.artifact_digest, target.signature_digest):
            try:
                self.content.get(digest)
            except ContentTampered as exc:
                raise LiteGenerationRefused(
                    f"generation {number} names {digest}, which no longer hashes "
                    f"to it ({exc.actual}); rolling back to an altered artifact "
                    "is the one rollback that must fail"
                ) from exc

        return self.promote(
            artifact_digest=target.artifact_digest,
            signature_digest=target.signature_digest,
            signer_key=target.signer_key,
            admitted_at=admitted_at,
            rolled_back_from=current.number,
            rollback_reason=reason,
            actor=actor,
        )

    def prune(self, *, retain: int) -> tuple[int, ...]:
        """Drop all but the `retain` newest generations. Returns what went.

        The live generation is retained regardless, because pruning what is
        being served would turn a disk-space policy into an outage. A blob is
        removed only when nothing retained names it.
        """

        if retain < 1:
            raise LiteGenerationRefused(
                "retaining nothing leaves no generation to roll back to; "
                "retention starts at 1"
            )
        numbers = self.numbers()
        if len(numbers) <= retain:
            return ()

        live = self.live()
        keep = set(numbers[-retain:])
        if live is not None:
            keep.add(live.number)

        removed = tuple(number for number in numbers if number not in keep)
        still_named: set[str] = set()
        for number in numbers:
            if number in keep:
                retained = self.read(number)
                still_named.add(retained.artifact_digest)
                still_named.add(retained.signature_digest)
        for number in removed:
            generation = self.read(number)
            _remove_tree(self.generations / str(number))
            for digest in (generation.artifact_digest, generation.signature_digest):
                if digest not in still_named:
                    self.content.path_for(digest).unlink(missing_ok=True)
        return removed


def _atomic_write(path: Path, data: bytes) -> None:
    store_directory(path.parent)
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=".live-")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _remove_tree(path: Path) -> None:
    for child in sorted(path.rglob("*"), reverse=True):
        if child.is_file() or child.is_symlink():
            child.unlink()
        else:
            child.rmdir()
    path.rmdir()
