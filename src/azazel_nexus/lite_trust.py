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

import hashlib
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from .audit import AuditChainBroken, AuditLedger, AuditUnavailable
from .lab_keys import refuse_public_fixture_keys
from .lite_bundle import BundleRefused, parse_anchors, read_anchors
from .revocation import RevocationList, RevocationRefused
from .revocation_policy import (
    BUNDLE_SIGNING,
    RevocationPolicy,
    policy_path,
    prepare_policy_record,
    read_policy_record,
)
from .signature import SignatureRefused, parse_public_key

__all__ = [
    "MAX_ANCHOR_BYTES",
    "TRUST_FILENAME",
    "RepinConfirmation",
    "RepinOutcome",
    "RepinRequest",
    "TrustRefused",
    "TrustStore",
]

TRUST_FILENAME = "trust.json"
MAX_ANCHOR_BYTES = 64 * 1024
_FINGERPRINT_DOMAIN = b"azazel-nexus/trust-root/v1\x00"


class TrustRefused(Exception):
    """The trust store was not written, or may not be read as asked."""


@dataclass(frozen=True)
class RepinRequest:
    """A local commissioning request; key material is read from the file."""

    new_anchor_path: Path
    reason: str
    principal: str


@dataclass(frozen=True)
class RepinConfirmation:
    """Evidence supplied by runtime; this library does not inspect the nonce."""

    nonce: str
    confirmed_at: str


@dataclass(frozen=True)
class RepinOutcome:
    promoted: bool
    generation: int
    old_fingerprint: str
    new_fingerprint: str
    reason_code: str


@dataclass(frozen=True)
class TrustStore:
    """The admitted signing keys, as pinned at commissioning."""

    root: Path

    @property
    def path(self) -> Path:
        number = self.current_generation()
        if number:
            return self.root / "trust-generations" / f"{number}.json"
        return self.root / TRUST_FILENAME

    def current_generation(self) -> int:
        """Zero is the original commissioning pin; a bad pointer fails closed."""

        try:
            value = (self.root / "trust-current").read_text(encoding="ascii")
        except FileNotFoundError:
            return 0
        except (OSError, UnicodeError):
            raise TrustRefused("the trust generation pointer is unreadable") from None
        if len(value) > 20 or not value.isascii() or not value.isdecimal() or int(value) < 1:
            raise TrustRefused("the trust generation pointer is invalid")
        return int(value)

    def anchors_path_for(self, trust_path: Path, record: dict) -> Path:
        """The anchors.toml that goes with one trust record (ADR 0007).

        A repin that replaced the anchor with the keys wrote it beside its
        generation record (`trust-generations/N.anchors.toml`) and marked the
        record `"anchors": true`; the pointer move then switches keys and
        anchor together. Every other record -- the enrollment's `trust.json`
        and a repin that kept the anchor -- uses `trust/anchors.toml`.
        """
        if (trust_path.parent == self.root / "trust-generations"
                and record.get("anchors") is True):
            return trust_path.with_suffix(".anchors.toml")
        return self.root / "trust" / "anchors.toml"

    @property
    def anchors_path(self) -> Path:
        """The anchors.toml in force with the current trust record."""
        path = self.path
        return self.anchors_path_for(path, self._read())

    def is_pinned(self) -> bool:
        return (self.root / TRUST_FILENAME).is_file() or (self.root / "trust-current").exists()

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
        request: RepinRequest,
        *,
        confirmation: RepinConfirmation,
        ledger: AuditLedger,
        now: str,
    ) -> RepinOutcome:
        """Stage, validate, record authorization, then atomically move the pointer.

        Refusals raise TrustRefused with fixed messages. The ledger is durable
        before the pointer moves: authorization audit failure prevents activation.
        A pointer failure can leave authorization without promotion.
        A durable reservation prevents authorized generation reuse. Runtime
        serializes local commissioning requests.
        """

        if not isinstance(confirmation, RepinConfirmation):
            raise TrustRefused("a repin requires local commissioning confirmation")
        if not isinstance(request, RepinRequest):
            raise TrustRefused("a repin requires a RepinRequest")
        if (not isinstance(request.reason, str) or not request.reason.strip()
                or len(request.reason) > 512):
            raise TrustRefused("a repin must record why")
        if not isinstance(request.principal, str) or not request.principal.strip():
            raise TrustRefused("a repin must record its principal")
        if not isinstance(now, str) or not now.strip():
            raise TrustRefused("a repin must record when it happened")
        if not self.is_pinned():
            raise TrustRefused("nothing is pinned here; a first pinning is `pin`")

        staged = None
        stage = "staging"
        try:
            old = self._read()
            old_keys = _validated_keys(old)
            old_fingerprint = _fingerprint(old_keys)
            metadata = (self.root / TRUST_FILENAME).stat()
            staged = self._stage_anchor(request.new_anchor_path)
            stage = "validation"
            document = json.loads(staged.read_bytes())
            proposed = _validated_keys(document)
            # A published test key is never a production anchor (lab_keys).
            refuse_public_fixture_keys((bytes.fromhex(key) for key in proposed), TrustRefused)
            # The anchor in force now, and the one the new generation carries:
            # the document's own `anchors` (key ids, roles, threshold, epoch,
            # export policies; ADR 0007), or the current one unchanged.
            current_anchors_path = self.anchors_path_for(self.path, old)
            new_anchors_bytes = None
            if "anchors" in document:
                from .lite_enrollment import EnrollmentRefused, decode_anchor_spec

                try:
                    spec = decode_anchor_spec(document["anchors"])
                except EnrollmentRefused:
                    raise TrustRefused("the proposed anchor is refused") from None
                if sorted(key.hex() for key in spec.keys.values()) != list(proposed):
                    raise TrustRefused("the proposed anchor must name exactly the proposed keys")
                new_anchors_bytes = spec.render()
                new_anchors = parse_anchors(new_anchors_bytes)
            elif current_anchors_path.exists():
                new_anchors = read_anchors(current_anchors_path)
                usable = [key for key in new_anchors.keys.values() if key.hex() in proposed]
                if len(usable) < new_anchors.threshold:
                    # The kept anchor would name no key set this pin can meet:
                    # every bundle would then fail. Change keys and anchor together.
                    raise TrustRefused("the kept anchor cannot be met by the proposed keys")
                if current_anchors_path != self.root / "trust" / "anchors.toml":
                    # Kept means the anchor in force, which an earlier repin put
                    # beside its generation: it goes with the new one too.
                    new_anchors_bytes = current_anchors_path.read_bytes()
            else:
                new_anchors = None
            old_policy = None
            if old.get("revocation_policy") is True or policy_path(self.root).exists():
                old_policy = read_policy_record(self.root, old["commissioning_digest"])
            new_policy = old_policy
            if "revocation_policy" in document:
                authority = RevocationPolicy.from_record(document["revocation_policy"])
                new_policy = prepare_policy_record(
                    self.root, authority, commissioning_digest=old["commissioning_digest"],
                    anchors_key_roles={key: BUNDLE_SIGNING for key in proposed},
                    anchors_keys={key: bytes.fromhex(key) for key in proposed},
                )
            if new_policy is not None:
                authority = RevocationPolicy.from_record(new_policy["policy"])
                refuse_public_fixture_keys(authority.revocation_keys, TrustRefused)
                if new_anchors is not None:
                    authority.check_anchors(new_anchors.key_roles, new_anchors.keys)
                if authority.revocation_keys.intersection(bytes.fromhex(key) for key in proposed):
                    raise TrustRefused("the same key cannot hold both roles")
                floor = RevocationList.parse(new_policy["floor"].encode("utf-8"))
                if set(proposed).intersection(floor.revoked_keys):
                    raise TrustRefused("repin cannot re-enable a revoked bundle key")
            old_policy_fingerprint = _policy_fingerprint(old_policy)
            new_policy_fingerprint = _policy_fingerprint(new_policy)
            new_fingerprint = _fingerprint(proposed)
            if (new_fingerprint == old_fingerprint
                    and new_policy_fingerprint == old_policy_fingerprint
                    and (new_anchors_bytes is None
                         or (current_anchors_path.exists()
                             and current_anchors_path.read_bytes() == new_anchors_bytes))):
                raise TrustRefused("the proposed trust root is unchanged")
            # Human-entered provenance must not become a key-material side
            # channel to the ledger. The nonce and its timestamp are not read.
            policy_keys = tuple(
                key for policy in (old_policy, new_policy) if policy is not None
                for key in policy["policy"]["keys"].values()
            )
            for text in (request.reason, request.principal, now):
                if any(
                    key.lower()[offset:offset + 16] in text.lower()
                    for key in (*old_keys, *proposed, *policy_keys)
                    for offset in range(len(key) - 15)
                ):
                    raise TrustRefused("repin provenance must not contain key material")
            record = {
                "commissioning_digest": old["commissioning_digest"],
                "keys": list(proposed),
                "pinned_at": now,
                "actor": request.principal,
                "repin_reason": request.reason,
            }
            stage = "generation"
            generations = self.root / "trust-generations"
            _commissioned_directory(generations, metadata)
            reservation = self.root / "trust-reserved"
            highest = max(
                (int(path.stem) for path in generations.glob("*.json")
                 if path.stem.isascii() and path.stem.isdecimal()),
                default=0,
            )
            try:
                reserved = reservation.read_text(encoding="ascii")
            except FileNotFoundError:
                reserved = "0"
            if not reserved.isascii() or not reserved.isdecimal():
                raise TrustRefused("the trust reservation is invalid")
            number = max(highest, int(reserved), self.current_generation()) + 1
            record["generation"] = number
            if new_policy is not None:
                record["revocation_policy"] = True
            if new_anchors_bytes is not None:
                record["anchors"] = True
            # Persist the high-water mark before authorization. Even removal
            # of an orphaned generation must never make its number reusable.
            _atomic_write(reservation, str(number).encode("ascii"), metadata=metadata)
            destination = generations / f"{number}.json"
            if new_policy is not None:
                _atomic_write(destination.with_suffix(".revocation.json"),
                              _document_bytes(new_policy), metadata=metadata)
            if new_anchors_bytes is not None:
                _atomic_write(destination.with_suffix(".anchors.toml"), new_anchors_bytes,
                              metadata=metadata)
            _atomic_write(destination, _document_bytes(record), metadata=metadata)
            stage = "audit"
            event = {
                "generation": number,
                "old_fingerprint": old_fingerprint,
                "new_fingerprint": new_fingerprint,
                "old_revocation_policy_fingerprint": old_policy_fingerprint,
                "new_revocation_policy_fingerprint": new_policy_fingerprint,
                "principal": request.principal,
                "at": now,
                "reason": request.reason,
            }
            ledger.append({"event_type": "trust.repin.authorized", **event})
            stage = "pointer"
            _atomic_write(self.root / "trust-current", str(number).encode("ascii"),
                          metadata=metadata)
            stage = "promotion audit"
            ledger.append({"event_type": "trust.repin.promoted", **event})
        except (
            AuditChainBroken, AuditUnavailable, OSError, ValueError, TypeError,
            KeyError, SignatureRefused, TrustRefused, RevocationRefused, BundleRefused,
        ):
            # Do not interpolate file names, parser diagnostics or exception
            # chains: an untrusted input can put key bytes in any of them.
            state = ("inspect the active trust pointer" if stage in ("pointer", "promotion audit")
                     else "the active trust root is unchanged")
            raise TrustRefused(f"repin {stage} refused; {state}") from None
        finally:
            if staged is not None:
                try:
                    staged.unlink(missing_ok=True)
                except OSError:
                    pass
        return RepinOutcome(True, number, old_fingerprint, new_fingerprint, "promoted")

    def _stage_anchor(self, source: Path) -> Path:
        """Read a bounded regular file without following its final symlink."""

        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_ANCHOR_BYTES:
                raise TrustRefused("the proposed trust root must be a bounded regular file")
            payload = stream.read(MAX_ANCHOR_BYTES + 1)
        if len(payload) > MAX_ANCHOR_BYTES:
            raise TrustRefused("the proposed trust root exceeds the size limit")
        staging = self.root / "trust-staging"
        _commissioned_directory(staging, (self.root / TRUST_FILENAME).stat())
        handle, temporary = tempfile.mkstemp(dir=staging, prefix=".anchor-")
        staged = Path(temporary)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            staged.unlink(missing_ok=True)
            raise
        return staged

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
        # A published test key signs whatever anybody wants (lab_keys).
        refuse_public_fixture_keys(parsed, TrustRefused)

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


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _apply_metadata(descriptor: int, metadata: os.stat_result, *, directory: bool = False) -> None:
    observed = os.fstat(descriptor)
    if (observed.st_uid, observed.st_gid) != (metadata.st_uid, metadata.st_gid):
        os.fchown(descriptor, metadata.st_uid, metadata.st_gid)
    mode = stat.S_IMODE(metadata.st_mode)
    if directory:
        mode |= (mode & 0o444) >> 2  # Search permission for every readable class.
    os.fchmod(descriptor, mode)


def _commissioned_directory(path: Path, metadata: os.stat_result) -> None:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        _apply_metadata(descriptor, metadata, directory=True)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _atomic_write(path: Path, data: bytes, *, metadata: os.stat_result | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=".trust-")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            if metadata is not None:
                _apply_metadata(stream.fileno(), metadata)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _validated_keys(document: object) -> tuple[str, ...]:
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise TrustRefused("a trust root is a JSON object naming keys")
    keys = document["keys"]
    if not keys:
        raise TrustRefused("an empty trust root is refused")
    return tuple(sorted({parse_public_key(key).hex() for key in keys}))


def _document_bytes(document: dict) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _fingerprint(keys: tuple[str, ...]) -> str:
    payload = b"".join(bytes.fromhex(key) for key in keys)
    return "sha256:" + hashlib.sha256(_FINGERPRINT_DOMAIN + payload).hexdigest()


def _policy_fingerprint(record: dict | None) -> str | None:
    if record is None:
        return None
    payload = json.dumps(record["policy"], sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(b"azazel-nexus/revocation-policy/v1\x00" + payload).hexdigest()
