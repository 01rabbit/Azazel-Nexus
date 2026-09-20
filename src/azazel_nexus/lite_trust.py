"""The keys Knowledge Lite artifacts must be signed by (#6, E1).

A verifier without a trust store verifies against whatever it is handed, which
is not verification. This module is the other half: the set of public keys a
node will accept a Lite artifact under, fixed at commissioning and not
afterwards.

**Keys are bound to a commissioning, not to a node.** The file records the
commissioning digest it was pinned under, and reading it requires naming that
same digest. Re-commissioning a node changes what it is and who runs it; keys
pinned for the previous commissioning are refused rather than silently carried
across, because "these were the right keys for the node this used to be" is
not an argument for trusting them now.

**Pinning happens once.** `pin` refuses to overwrite an existing trust store.
Replacing the pinned set is `repin`, which records why and who -- the same rule
`lite_generation.py` applies to a rollback, for the same reason: an unexplained
change to the trust set is indistinguishable from a compromise.

**An empty trust set is refused at pin time.** A node with no admitted keys
admits no artifact, which is fail-closed and correct as a *consequence*; as a
*configuration* it is almost always a mistake, and a mistake that presents as
"Knowledge Lite never works" rather than as an error.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from .signature import SignatureRefused, parse_public_key

__all__ = ["TRUST_FILENAME", "TrustRefused", "TrustStore"]

TRUST_FILENAME = "trust.json"


class TrustRefused(Exception):
    """The trust store was not written, or may not be read as asked."""


@dataclass(frozen=True)
class TrustStore:
    """The admitted signing keys, as pinned at commissioning."""

    root: Path

    @property
    def path(self) -> Path:
        return self.root / TRUST_FILENAME

    def is_pinned(self) -> bool:
        return self.path.is_file()

    def keys(self, *, commissioning_digest: str) -> tuple[bytes, ...]:
        """The admitted keys, or a refusal.

        `commissioning_digest` is required rather than optional: a caller that
        could omit it would, and the binding would stop being checked on the
        one path that matters.
        """

        record = self._read()
        pinned_under = record.get("commissioning_digest")
        if pinned_under != commissioning_digest:
            raise TrustRefused(
                f"these keys were pinned under commissioning {pinned_under}, and "
                f"this node is commissioned as {commissioning_digest}; keys do "
                "not carry across a re-commissioning"
            )
        return tuple(parse_public_key(text) for text in record["keys"])

    def pinned_at(self) -> str:
        return str(self._read()["pinned_at"])

    def pin(
        self,
        keys: Sequence[str],
        *,
        commissioning_digest: str,
        pinned_at: str,
        actor: str,
    ) -> tuple[bytes, ...]:
        """Write the trust store. Refuses if one is already there."""

        if self.is_pinned():
            raise TrustRefused(
                "a trust store is already pinned here; replacing the admitted "
                "keys is `repin`, which records why and who"
            )
        return self._write(
            keys,
            commissioning_digest=commissioning_digest,
            pinned_at=pinned_at,
            actor=actor,
        )

    def repin(
        self,
        keys: Sequence[str],
        *,
        commissioning_digest: str,
        pinned_at: str,
        reason: str,
        actor: str,
    ) -> tuple[bytes, ...]:
        """Replace the admitted keys, recording why and who."""

        if not reason.strip():
            raise TrustRefused(
                "a repin must record why; an unexplained change to the admitted "
                "keys is indistinguishable from a compromise"
            )
        if not self.is_pinned():
            raise TrustRefused(
                "nothing is pinned here; a first pinning is `pin`, which is a "
                "commissioning step rather than a correction"
            )
        return self._write(
            keys,
            commissioning_digest=commissioning_digest,
            pinned_at=pinned_at,
            actor=actor,
            reason=reason,
        )

    # -- internals ---------------------------------------------------------

    def _write(
        self,
        keys: Sequence[str],
        *,
        commissioning_digest: str,
        pinned_at: str,
        actor: str,
        reason: Optional[str] = None,
    ) -> tuple[bytes, ...]:
        if not str(commissioning_digest).strip():
            raise TrustRefused("keys are pinned under a commissioning, never loose")
        if not pinned_at.strip():
            raise TrustRefused("a trust store records when it was pinned")
        if not actor.strip():
            raise TrustRefused("a trust store records who pinned it")

        ordered = sorted(set(keys))
        if not ordered:
            raise TrustRefused(
                "a trust store with no keys admits no artifact; that is correct "
                "as a consequence and almost never correct as a configuration"
            )
        # Parsed before anything is written, so a malformed key is an error
        # here rather than a cache that mysteriously never admits anything.
        try:
            parsed = tuple(parse_public_key(text) for text in ordered)
        except SignatureRefused as exc:
            raise TrustRefused(f"a key in the proposed trust set is unusable: {exc}") from exc

        record = {
            "commissioning_digest": commissioning_digest,
            "pinned_at": pinned_at,
            "actor": actor,
            "keys": ordered,
        }
        if reason is not None:
            record["repin_reason"] = reason
        _atomic_write(
            self.path,
            (json.dumps(record, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        )
        return parsed

    def _read(self) -> dict:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise TrustRefused(
                f"no trust store at {self.path}; nothing is admitted until keys "
                f"are pinned: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise TrustRefused(f"the trust store is unreadable: {exc}") from exc
        if not isinstance(raw, dict) or not isinstance(raw.get("keys"), list):
            raise TrustRefused("a trust store is an object naming a list of keys")
        return raw


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=".trust-")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
