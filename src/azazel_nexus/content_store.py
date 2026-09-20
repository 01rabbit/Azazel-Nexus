"""Content addressing for the Knowledge Lite cache (#6, E1).

A blob is named by the digest of its own bytes, so the name is a claim the
store can check rather than a label it has to trust.

**The digest is re-derived on every read.** A store that hashes on write and
trusts the filename afterwards detects nothing: the whole failure it exists to
catch is bytes changing after they were written. Re-deriving costs a hash per
read of a bounded artifact, which is the price of the property.

**A mismatch is reported, never repaired.** The store does not re-write a blob
whose contents no longer match its name, because a silent repair turns the one
moment corruption was visible into no moment at all. `ContentTampered` names
both digests and the caller decides -- in this product, by quarantining.

**A digest is never a path.** `parse_digest` refuses anything that is not
`sha256:` followed by 64 lower-case hex characters, before any of it reaches
the filesystem. `sha256:../../etc/passwd` is not a near-miss to be sanitised;
it is refused.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "DIGEST_ALGORITHM",
    "DIGEST_HEX_LENGTH",
    "ContentRefused",
    "ContentStore",
    "ContentTampered",
    "digest_bytes",
    "parse_digest",
]

DIGEST_ALGORITHM = "sha256"
DIGEST_HEX_LENGTH = 64

_HEX = frozenset("0123456789abcdef")


class ContentRefused(Exception):
    """The digest, or the request made with it, is not admissible."""


class ContentTampered(ContentRefused):
    """A stored blob no longer hashes to the name it is stored under.

    Separate from `ContentRefused` because the operator response differs: a
    malformed digest is a caller fault, and this is an integrity failure of
    data already admitted.
    """

    def __init__(self, expected: str, actual: str) -> None:
        super().__init__(
            f"content addressed as {expected} hashes to {actual}; it is not the "
            "content that was admitted, and it is reported rather than repaired"
        )
        self.expected = expected
        self.actual = actual


def digest_bytes(data: bytes) -> str:
    """The canonical address of `data`."""

    return f"{DIGEST_ALGORITHM}:{hashlib.sha256(data).hexdigest()}"


def parse_digest(digest: str) -> str:
    """Return the hex part of a well-formed digest, or refuse.

    Every rejection names its own reason. Two rejections that share one
    message are two rejections that could have been one check.
    """

    if not isinstance(digest, str):
        raise ContentRefused("a digest is text")
    algorithm, separator, hex_part = digest.partition(":")
    if not separator:
        raise ContentRefused(
            f"a digest is algorithm-qualified, as {DIGEST_ALGORITHM}:<hex>; got {digest!r}"
        )
    if algorithm != DIGEST_ALGORITHM:
        raise ContentRefused(
            f"only {DIGEST_ALGORITHM} is addressable here; got algorithm {algorithm!r}"
        )
    if len(hex_part) != DIGEST_HEX_LENGTH:
        raise ContentRefused(
            f"a {DIGEST_ALGORITHM} digest is {DIGEST_HEX_LENGTH} hex characters; "
            f"got {len(hex_part)}"
        )
    if not set(hex_part) <= _HEX:
        raise ContentRefused(
            "a digest is lower-case hex; anything else could name a path rather "
            f"than content: {hex_part!r}"
        )
    return hex_part


@dataclass(frozen=True)
class ContentStore:
    """Immutable blobs under `root`, addressed by their own digest."""

    root: Path

    @property
    def objects(self) -> Path:
        return self.root / "objects" / DIGEST_ALGORITHM

    def path_for(self, digest: str) -> Path:
        """The location of `digest`, whether or not anything is there.

        The digest is parsed first, so this never composes attacker-supplied
        text into a path.
        """

        hex_part = parse_digest(digest)
        return self.objects / hex_part[:2] / hex_part[2:]

    def has(self, digest: str) -> bool:
        """Whether a blob is present. Says nothing about whether it is intact."""

        return self.path_for(digest).is_file()

    def put(self, data: bytes) -> str:
        """Store `data` and return its address.

        Idempotent for identical content. If a blob is already present under
        this address and does not hash to it, that is `ContentTampered`: the
        write is refused rather than allowed to overwrite the evidence.
        """

        digest = digest_bytes(data)
        target = self.path_for(digest)
        if target.is_file():
            existing = target.read_bytes()
            actual = digest_bytes(existing)
            if actual != digest:
                raise ContentTampered(digest, actual)
            return digest

        target.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(dir=str(target.parent), prefix=".incoming-")
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        return digest

    def get(self, digest: str) -> bytes:
        """Read a blob, re-deriving its digest before returning it.

        Raises `ContentRefused` when nothing is stored there and
        `ContentTampered` when something is stored there and is not it.
        """

        target = self.path_for(digest)
        try:
            data = target.read_bytes()
        except OSError as exc:
            raise ContentRefused(f"no content addressed {digest}: {exc}") from exc
        actual = digest_bytes(data)
        if actual != digest:
            raise ContentTampered(digest, actual)
        return data
