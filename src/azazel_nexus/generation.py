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
import fcntl
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional

__all__ = [
    "Generation",
    "GenerationRefused",
    "GenerationCommitUncertain",
    "GenerationStore",
    "tree_digest",
]


class GenerationRefused(Exception):
    """The generation was not created, or is not what it claims to be."""


class GenerationCommitUncertain(GenerationRefused):
    """Complete tree became visible, but directory durability was not confirmed.

    Do not automatically retry: inspect this number and current state first.
    This exception is not permission to activate the visible generation.
    """

    def __init__(self, number: int):
        self.number = number
        super().__init__(f"generation {number} published; durability unconfirmed; inspect before retry")


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _make_store_root(path: Path) -> None:
    # Each newly created directory also needs its entry synced in its parent.
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)
        _sync_directory(directory.parent)


def _unique_metadata(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GenerationRefused("duplicate generation metadata field")
        result[key] = value
    return result


def tree_digest(files: Mapping[str, bytes]) -> str:
    """A digest over paths *and* contents.

    Each entry contributes its path and its content hash, in sorted path
    order. Sorting rather than trusting iteration order is what makes the
    digest the same on two machines whose filesystems enumerate differently --
    the property `IMPLEMENTATION_SPEC.md` §2.1's sibling rule calls out for
    scoring and which applies equally here.
    """

    for path in files:
        if (type(path) is not str or not path or path.startswith("/")
                or any(part in {"", ".", ".."} for part in path.split("/"))
                or "\x00" in path):
            raise GenerationRefused(
                f"{path!r} is not a path inside the generation tree; a "
                "generation describes its own contents and nothing outside them"
            )
    digest = hashlib.sha256()
    for path in sorted(files):
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
    commissioning_evidence_binding: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.number) is not int:
            raise GenerationRefused("generation number must be an integer")
        for value in (self.supersedes, self.rolled_back_from):
            if value is not None and type(value) is not int:
                raise GenerationRefused("generation ancestry must be an integer or null")
        for value in (self.rollback_reason, self.actor):
            if value is not None and type(value) is not str:
                raise GenerationRefused("generation rollback attribution must be text or null")
        if type(self.created_at) is not str:
            raise GenerationRefused("generation creation time must be text")
        if self.number < 1:
            raise GenerationRefused("generation numbers start at 1")
        if any(value is not None and value < 1 for value in (self.supersedes, self.rolled_back_from)):
            raise GenerationRefused("generation ancestry numbers start at 1")
        if self.rolled_back_from is not None and self.rolled_back_from >= self.number:
            raise GenerationRefused("rollback ancestry must precede its generation")
        if self.commissioning_evidence_binding is not None:
            binding = self.commissioning_evidence_binding
            if type(binding) is not str or re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", binding) is None:
                raise GenerationRefused(
                    "commissioning evidence binding must match hmac-sha256:[0-9a-f]{64}"
                )
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
        numbers = []
        for child in self.root.iterdir():
            if not child.name.isdigit():
                continue  # Includes all hidden partial staging directories.
            if (not re.fullmatch(r"[1-9][0-9]*", child.name)
                    or child.is_symlink() or not child.is_dir()):
                raise GenerationRefused("noncanonical generation entry; inspect store before retry")
            numbers.append(int(child.name))
        return tuple(sorted(numbers))

    def current(self) -> Optional[Generation]:
        numbers = self.numbers()
        return self.read(numbers[-1]) if numbers else None

    def read(self, number: int) -> Generation:
        try:
            raw = json.loads(self._meta(number).read_text(encoding="utf-8"),
                             object_pairs_hook=_unique_metadata)
            if type(raw) is not dict:
                raise GenerationRefused("ordinary generation metadata must be an object")
            # This reader owns only the existing operational format. A
            # bootstrap schema/purpose must never inherit its normal lease.
            if any(name in raw for name in ("schema", "purpose", "variant")):
                raise GenerationRefused("non-operational generation format refused")
            generation = Generation(**raw)
            if type(generation.number) is not int or generation.number != number:
                raise GenerationRefused("generation number does not match its directory")
            if (type(generation.commissioning_digest) is not str or
                    re.fullmatch(r"sha256:[0-9a-f]{64}", generation.commissioning_digest) is None):
                raise GenerationRefused("ordinary generation needs a commissioning digest")
            return generation
        except (OSError, ValueError, TypeError, RecursionError):
            raise GenerationRefused("generation metadata unreadable or malformed") from None

    def create(
        self,
        files: Mapping[str, bytes],
        *,
        created_at: str,
        commissioning_digest: str,
        rolled_back_from: Optional[int] = None,
        rollback_reason: Optional[str] = None,
        actor: Optional[str] = None,
        commissioning_evidence_binding: str | None = None,
    ) -> Generation:
        """Stage privately, read back, then publish once under a writer lock.

        Hidden partial staging stays for explicit inspection; it is never a
        numbered/current generation. The root must be trusted local storage;
        advisory locking is not protection against its privileged owner.
        """

        # Freeze caller-owned mappings before deriving the digest or writing.
        snapshot = dict(files)
        if any(type(value) is not bytes for value in snapshot.values()):
            raise GenerationRefused("generation file contents must be immutable bytes")
        digest = tree_digest(snapshot)
        _make_store_root(self.root)
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise GenerationRefused("generation writer already active") from None
            return self._create_locked(snapshot, digest=digest, root_fd=root_fd,
                created_at=created_at, commissioning_digest=commissioning_digest,
                rolled_back_from=rolled_back_from, rollback_reason=rollback_reason,
                actor=actor, commissioning_evidence_binding=commissioning_evidence_binding)
        finally:
            os.close(root_fd)

    def _create_locked(self, files, *, digest, root_fd, created_at, commissioning_digest,
                       rolled_back_from, rollback_reason, actor, commissioning_evidence_binding):

        numbers = self.numbers()
        number = (numbers[-1] + 1) if numbers else 1
        if rolled_back_from is not None and (not numbers or rolled_back_from != numbers[-1]):
            raise GenerationRefused("current generation changed before rollback publication")
        if rolled_back_from is not None and self.read(rolled_back_from).commissioning_evidence_binding is not None:
            raise GenerationRefused("bound rollback requires a validated forward render and approval")
        generation = Generation(
            number=number,
            digest=digest,
            created_at=created_at,
            commissioning_digest=commissioning_digest,
            supersedes=numbers[-1] if numbers else None,
            rolled_back_from=rolled_back_from,
            rollback_reason=rollback_reason,
            actor=actor,
            commissioning_evidence_binding=commissioning_evidence_binding,
        )

        directory = self.root / str(number)
        if directory.exists() or directory.is_symlink():
            raise GenerationRefused(
                f"generation {number} already exists; a generation is promoted "
                "once and never edited in place"
            )
        metadata = dict(generation.__dict__)
        if generation.commissioning_evidence_binding is None:
            metadata.pop("commissioning_evidence_binding")
        stage = Path(tempfile.mkdtemp(prefix=".staging-", dir=self.root))
        published = False
        try:
            tree = stage / "tree"
            tree.mkdir(mode=0o700)
            for path in sorted(files):
                target = tree / path
                # mkdir(parents=True) applies mode only to the last directory.
                parent = tree
                for part in Path(path).parts[:-1]:
                    parent = parent / part
                    parent.mkdir(mode=0o700, exist_ok=True)
                _write_private(target, files[path])
            _write_private(stage / "generation.json",
                (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode("utf-8"))
            observed = {str(p.relative_to(tree)): p.read_bytes()
                        for p in sorted(tree.rglob("*")) if p.is_file()}
            try:
                observed_metadata = json.loads((stage / "generation.json").read_bytes())
            except (ValueError, UnicodeError):
                raise GenerationRefused("staged generation metadata read-back refused") from None
            if observed != files or observed_metadata != metadata:
                raise GenerationRefused("staged generation read-back mismatch")
            for child in sorted(tree.rglob("*"), key=lambda p: len(p.parts), reverse=True):
                if child.is_dir():
                    _sync_directory(child)
            _sync_directory(tree)
            _sync_directory(stage)
            if directory.exists() or directory.is_symlink():
                raise GenerationRefused("generation already exists; never edited in place")
            stage.rename(directory)
            published = True
            os.fsync(root_fd)
        except OSError:
            if published:
                raise GenerationCommitUncertain(number) from None
            raise GenerationRefused("generation staging failed; inspect hidden partial state") from None
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
        if (
            target.commissioning_evidence_binding is not None
            or latest.commissioning_evidence_binding is not None
        ):
            raise GenerationRefused(
                "rollback is refused for generations with commissioning evidence binding; "
                "a new validated forward render and approval are required"
            )
        return self.create(
            self.read_tree(number),
            created_at=created_at,
            commissioning_digest=target.commissioning_digest,
            rolled_back_from=latest.number,
            rollback_reason=reason,
            actor=actor,
        )
