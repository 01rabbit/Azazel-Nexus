"""Versioned configuration that is promoted, never edited in place (#27).

`docs/IMPLEMENTATION_SPEC.md` §3 says the staging tree is "promoted, never
edited in place", and §2.3 says no operational unit runs before the activation
controller validates a **verified generation**. This module is what makes
"verified" mean something: a generation carries a digest of its own contents,
names the generation it replaces, and can be checked again later by anyone
holding the tree.

Three properties, each of which is a refusal rather than a convention:

*Monotonic.* Generation numbers only increase. A rollback creates a **new**
generation whose contents are the old one's, rather than moving a pointer
backwards — so the ledger reads forwards and the thing that was rolled back
is still there to be looked at.

*Self-describing.* The digest covers the file contents and their paths, so
moving a file between two names changes it. A digest over contents alone would
call two different configurations the same one.

*Deterministic.* The same tree produces the same digest in any process, on any
run. Nothing here reads a clock, a random source, or the order a filesystem
happens to return names in.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional

__all__ = [
    "Generation",
    "GenerationRefused",
    "GenerationStore",
    "tree_digest",
]


class GenerationRefused(Exception):
    """The generation was not created, or is not what it claims to be."""


def tree_digest(files: Mapping[str, bytes]) -> str:
    """A digest over paths *and* contents.

    Each entry contributes its path and its content hash, in sorted path
    order. Sorting rather than trusting iteration order is what makes the
    digest the same on two machines whose filesystems enumerate differently --
    the property `IMPLEMENTATION_SPEC.md` §2.1's sibling rule calls out for
    scoring and which applies equally here.
    """

    digest = hashlib.sha256()
    for path in sorted(files):
        if not path or path.startswith("/") or ".." in Path(path).parts:
            raise GenerationRefused(
                f"{path!r} is not a path inside the generation tree; a "
                "generation describes its own contents and nothing outside them"
            )
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(files[path]).hexdigest().encode("ascii"))
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


@dataclass(frozen=True)
class Generation:
    """One promoted configuration tree.

    `supersedes` is the generation this one replaces, or `None` for the first.
    `rolled_back_from` is set when this generation exists because an operator
    went back: it records which generation was abandoned and why, so that the
    history reads as what happened rather than as a sequence of equal states.
    """

    number: int
    digest: str
    created_at: str
    commissioning_digest: str
    supersedes: Optional[int] = None
    rolled_back_from: Optional[int] = None
    rollback_reason: Optional[str] = None
    actor: Optional[str] = None

    def __post_init__(self) -> None:
        if self.number < 1:
            raise GenerationRefused("generation numbers start at 1")
        if self.supersedes is not None and self.supersedes >= self.number:
            raise GenerationRefused(
                f"generation {self.number} claims to supersede {self.supersedes}; "
                "generations only move forward"
            )
        if self.rolled_back_from is not None:
            if self.rollback_reason is None or not self.rollback_reason.strip():
                raise GenerationRefused(
                    "a rollback must record why; an unexplained reversal is "
                    "indistinguishable from a mistake repeated later"
                )
            if self.actor is None or not self.actor.strip():
                raise GenerationRefused("a rollback must record who performed it")

    def as_event(self) -> dict:
        """The audit event for this generation's creation."""

        event = {
            "event_type": "generation.rolled_back"
            if self.rolled_back_from is not None
            else "generation.created",
            "generation": self.number,
            "digest": self.digest,
            "created_at": self.created_at,
            "commissioning_digest": self.commissioning_digest,
            "supersedes": self.supersedes,
        }
        if self.rolled_back_from is not None:
            event["rolled_back_from"] = self.rolled_back_from
            event["rollback_reason"] = self.rollback_reason
            event["actor"] = self.actor
        return event


class GenerationStore:
    """The generations on disk, and the rules for adding one."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _meta(self, number: int) -> Path:
        return self.root / str(number) / "generation.json"

    def numbers(self) -> tuple[int, ...]:
        if not self.root.is_dir():
            return ()
        return tuple(
            sorted(
                int(child.name)
                for child in self.root.iterdir()
                if child.is_dir() and child.name.isdigit()
            )
        )

    def current(self) -> Optional[Generation]:
        numbers = self.numbers()
        return self.read(numbers[-1]) if numbers else None

    def read(self, number: int) -> Generation:
        try:
            raw = json.loads(self._meta(number).read_text(encoding="utf-8"))
        except OSError as exc:
            raise GenerationRefused(
                f"generation {number} has no readable metadata: {exc}"
            ) from exc
        return Generation(**raw)

    def create(
        self,
        files: Mapping[str, bytes],
        *,
        created_at: str,
        commissioning_digest: str,
        rolled_back_from: Optional[int] = None,
        rollback_reason: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> Generation:
        """Write a new generation. Never edits an existing one."""

        numbers = self.numbers()
        number = (numbers[-1] + 1) if numbers else 1
        generation = Generation(
            number=number,
            digest=tree_digest(files),
            created_at=created_at,
            commissioning_digest=commissioning_digest,
            supersedes=numbers[-1] if numbers else None,
            rolled_back_from=rolled_back_from,
            rollback_reason=rollback_reason,
            actor=actor,
        )

        directory = self.root / str(number)
        if directory.exists():
            raise GenerationRefused(
                f"generation {number} already exists; a generation is promoted "
                "once and never edited in place"
            )
        directory.mkdir(parents=True)
        for path in sorted(files):
            target = directory / "tree" / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(files[path])
        self._meta(number).write_text(
            json.dumps(generation.__dict__, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return generation

    def read_tree(self, number: int) -> dict[str, bytes]:
        base = self.root / str(number) / "tree"
        if not base.is_dir():
            raise GenerationRefused(f"generation {number} has no tree")
        return {
            str(path.relative_to(base)): path.read_bytes()
            for path in sorted(base.rglob("*"))
            if path.is_file()
        }

    def verify(self, number: int) -> Generation:
        """Re-derive the digest from the tree on disk.

        Called on every boot by the activation controller (§2.3). A generation
        that was verified once and never again is a generation that describes
        whatever the tree has since become.
        """

        generation = self.read(number)
        actual = tree_digest(self.read_tree(number))
        if actual != generation.digest:
            raise GenerationRefused(
                f"generation {number} records {generation.digest} but its tree "
                f"hashes to {actual}; it is not the configuration that was verified"
            )
        return generation

    def roll_back_to(
        self, number: int, *, created_at: str, reason: str, actor: str
    ) -> Generation:
        """Promote an older generation's contents as a *new* generation.

        The pointer does not move backwards. What was rolled back stays on
        disk with its own number, so an operator reading the history sees the
        reversal rather than an absence.
        """

        target = self.verify(number)
        latest = self.current()
        if latest is None:  # pragma: no cover - verify() would have raised
            raise GenerationRefused("there is nothing to roll back")
        if number == latest.number:
            raise GenerationRefused(
                f"generation {number} is already current; a rollback to the "
                "current generation would record a reversal that did not happen"
            )
        return self.create(
            self.read_tree(number),
            created_at=created_at,
            commissioning_digest=target.commissioning_digest,
            rolled_back_from=latest.number,
            rollback_reason=reason,
            actor=actor,
        )
