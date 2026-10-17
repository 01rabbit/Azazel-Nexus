"""What Knowledge Lite currently is, in four words (#6, E1).

`docs/knowledge-lite-trust.md` describes the primitives. This module is the
one place that puts them together and answers the only question an operator
actually asks: *can this node use its Knowledge Lite cache right now, and if
not, why not?*

The answer is one of four, and the four are not interchangeable.

| state | means | operator response |
| --- | --- | --- |
| `available` | verified, unrevoked, and something in it may be served | none |
| `stale` | verified and unrevoked; nothing in it may be served **now** | refresh the artifact |
| `unavailable` | nothing has been admitted | install an artifact |
| `quarantined` | something was admitted and may not be trusted | investigate, then roll back or re-admit |

**`stale` never serves a claim.** An expired claim is withheld, not labelled
and passed along. The freshness label exists so the operator plane can say
which claims were withheld; it is not a disclaimer attached to data that is
served anyway.

**`unavailable` and `quarantined` are different facts.** "We do not have it"
and "we had it and it is not trustworthy" call for different actions, and a
node that reports the first when the second is true has told the operator that
nothing happened.

**None of the four blocks the deterministic path.** `blocks_core()` returns
`False` in every state, and the tests assert it in every state rather than in
the convenient one. Losing Lite is a capability change; authority does not
move (`docs/capability-model.md` §7).

**Verification happens again on every read.** The content address already
binds bytes to a digest, but nothing else binds the digest in a generation
record to a key -- a tampered record could name a different admitted artifact
under a signer that never signed it. Re-verifying makes `signer_key` a proven
fact, and it is what makes revoking a key stop the cache that key signed
without waiting for the next artifact to arrive.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .content_store import ContentRefused, ContentStore, digest_bytes
from .knowledge_peer import PeerContext
from .lite_cache import split_by_freshness
from .lite_generation import LiteGeneration, LiteGenerationRefused, LiteGenerationStore
from .lite_trust import TrustRefused, TrustStore
from .revocation import RevocationRefused, RevocationStore
from .revocation_policy import (
    RevocationPolicy,
    RevocationPolicyRefused,
    read_policy_record,
)
from .signature import SignatureRefused, verify_detached

__all__ = [
    "KnowledgeLite",
    "KnowledgeReading",
    "LiteReading",
    "LiteReasonCode",
    "LiteState",
    "knowledge_context",
    "no_claim_reader",
]


class LiteState(str, Enum):
    """What the cache is. Never what the node is permitted to decide."""

    AVAILABLE = "available"
    STALE = "stale"
    UNAVAILABLE = "unavailable"
    QUARANTINED = "quarantined"


class LiteReasonCode(str, Enum):
    """Machine-readable causes independent of human-readable explanations."""

    UNVERIFIED = "unverified"


def no_claim_reader(artifact: bytes) -> Sequence[Mapping]:
    """The default reader: reads nothing, and says so.

    Azazel-Knowledge owns the artifact format. A caller that forgets to supply
    a reader gets a cache that reports `quarantined` with this reason -- never
    one that reports `available` because it found nothing to object to.
    """

    raise ContentRefused(
        "no claim reader was supplied; this service does not parse Knowledge's "
        "artifact format and will not report an artifact it cannot read as usable"
    )


@dataclass(frozen=True)
class LiteReading:
    """The whole answer, including what the operator plane must be told."""

    state: LiteState
    reason: str
    generation: int | None = None
    artifact_digest: str | None = None
    signer_key: str | None = None
    admitted_at: str | None = None
    served: tuple[Mapping, ...] = ()
    withheld: tuple[Mapping, ...] = ()
    #: Set by `admit` only. `False` on a read, and on an admission that was
    #: refused -- so "nothing changed" and "something was admitted" cannot be
    #: read as the same outcome.
    admitted: bool = False
    reason_code: LiteReasonCode | None = None

    def blocks_core(self) -> bool:
        """Always False, in every state, and asserted as such by the tests."""

        return False

    @property
    def sources_capability(self) -> bool:
        """Whether `knowledge_lite` is a capability this node currently has.

        Only `available` sources it. A `stale` cache serves nothing, and a
        `quarantined` one must not: a capability that is present in name while
        serving nothing is the kind of claim this product does not make.
        """

        return self.state is LiteState.AVAILABLE

    def as_event(self) -> dict:
        """Provenance and outcome. Never the content of a claim."""

        return {
            "event_type": "lite.read",
            "state": self.state.value,
            "reason": self.reason,
            "reason_code": self.reason_code.value if self.reason_code else None,
            "generation": self.generation,
            "artifact_digest": self.artifact_digest,
            "signer_key": self.signer_key,
            "admitted_at": self.admitted_at,
            "served": len(self.served),
            "withheld": len(self.withheld),
        }


@dataclass(frozen=True)
class KnowledgeLite:
    """The embedded read-only cache, as a service rather than as parts."""

    root: Path
    commissioning_digest: str
    claims_of: Callable[[bytes], Sequence[Mapping]] = field(default=no_claim_reader)

    @property
    def content(self) -> ContentStore:
        return ContentStore(root=self.root)

    @property
    def trust(self) -> TrustStore:
        return TrustStore(root=self.root)

    @property
    def generations(self) -> LiteGenerationStore:
        return LiteGenerationStore(root=self.root, content=self.content)

    def revocations(self, *, bundle_keys: Sequence[bytes] = ()) -> RevocationStore:
        try:
            record = read_policy_record(self.root, self.commissioning_digest)
            policy = RevocationPolicy.from_record(record["policy"])
            if policy.revocation_keys.intersection(bundle_keys):
                raise RevocationPolicyRefused(
                    "pinned bundle key material has the revocation-signing role"
                )
            anchors_path = self.root / "trust" / "anchors.toml"
            if anchors_path.exists():
                from .lite_bundle import BundleRefused, read_anchors

                try:
                    anchors = read_anchors(anchors_path)
                except BundleRefused as exc:
                    raise RevocationRefused(f"unverified revocation anchors: {exc}") from exc
                policy.check_anchors(anchors.key_roles, anchors.keys)
            return RevocationStore(root=self.root, policy=policy, continuity=record)
        except RevocationPolicyRefused as exc:
            raise RevocationRefused(f"unverified revocation policy: {exc}") from exc

    # -- admission ---------------------------------------------------------

    def admit(
        self, *, artifact: bytes, signature: bytes, admitted_at: str
    ) -> LiteReading:
        """Verify and promote an artifact. Never raises for the node.

        On refusal nothing is promoted and the reading describes the state the
        node is still in, with the refusal as its reason -- so a caller cannot
        mistake a refused admission for a successful one that produced a poor
        state.
        """

        try:
            keys = self.trust.keys(commissioning_digest=self.commissioning_digest)
        except TrustRefused as exc:
            return self._unchanged(f"no admitted keys: {exc}")

        signer = _first_key_that_verifies(keys, artifact, signature)
        if signer is None:
            return self._unchanged(
                "the artifact does not verify under any admitted key; nothing was "
                "promoted and the cache is unchanged"
            )

        try:
            revocations = self.revocations(bundle_keys=keys).current()
        except RevocationRefused as exc:
            return self._unchanged(
                f"unverified revocation list: {exc}",
                reason_code=LiteReasonCode.UNVERIFIED,
            )

        if revocations.revokes_key(signer):
            return self._unchanged(
                f"the key {signer.hex()} that signed this artifact is revoked by "
                f"revocation sequence {revocations.sequence}"
            )
        incoming_digest = digest_bytes(artifact)
        if revocations.revokes_digest(incoming_digest):
            return self._unchanged(
                f"{incoming_digest} is revoked by revocation sequence "
                f"{revocations.sequence}; a revoked artifact is not admitted again"
            )

        artifact_digest = self.content.put(artifact)
        signature_digest = self.content.put(signature)
        self.generations.promote(
            artifact_digest=artifact_digest,
            signature_digest=signature_digest,
            signer_key=signer.hex(),
            admitted_at=admitted_at,
        )
        reading = self.read(as_of=admitted_at)
        return _with_admitted(reading)

    # -- reading -----------------------------------------------------------

    def read(self, *, as_of: str) -> LiteReading:
        """What the cache is right now. Never raises for the node."""

        try:
            live = self.generations.live()
        except LiteGenerationRefused as exc:
            return LiteReading(
                state=LiteState.QUARANTINED,
                reason=(
                    f"a generation was promoted and cannot be read back: {exc}; "
                    "the cache is held rather than served"
                ),
            )
        if live is None:
            return LiteReading(
                state=LiteState.UNAVAILABLE,
                reason=(
                    "no Knowledge Lite artifact has been admitted; absence of "
                    "knowledge is not a fault and the deterministic path continues"
                ),
            )

        try:
            keys = self.trust.keys(commissioning_digest=self.commissioning_digest)
        except TrustRefused as exc:
            return _quarantined(live, f"the admitted keys cannot be read: {exc}")

        try:
            revocations = self.revocations(bundle_keys=keys).current()
        except RevocationRefused as exc:
            return _quarantined(
                live, f"unverified revocation list: {exc}",
                reason_code=LiteReasonCode.UNVERIFIED,
            )

        withdrawn = revocations.reason_for(
            digest=live.artifact_digest, generation=live.number
        )
        if withdrawn is not None:
            return _quarantined(live, withdrawn)
        if revocations.revokes_key(bytes.fromhex(live.signer_key)):
            return _quarantined(
                live,
                f"the key {live.signer_key} that signed this artifact is revoked "
                f"by revocation sequence {revocations.sequence}",
            )

        try:
            artifact = self.generations.artifact_of(live)
            signature = self.generations.signature_of(live)
        except ContentRefused as exc:
            return _quarantined(live, str(exc))

        signer = _first_key_that_verifies(keys, artifact, signature)
        if signer is None:
            return _quarantined(
                live,
                "the live artifact does not verify under any admitted key; it was "
                "admitted once and cannot be admitted now",
            )
        if signer.hex() != live.signer_key:
            return _quarantined(
                live,
                f"generation {live.number} records {live.signer_key} as its signer "
                f"and verifies under {signer.hex()}; the record does not describe "
                "the artifact it names",
            )

        try:
            claims = list(self.claims_of(artifact))
        except Exception as exc:  # noqa: BLE001 - any failure to read is a refusal
            return _quarantined(
                live, f"the artifact is present and cannot be read: {exc}"
            )

        served, withheld = split_by_freshness(claims, as_of=as_of)
        if served:
            return _reading(
                live,
                LiteState.AVAILABLE,
                f"{len(served)} claim(s) current as of {as_of}, {len(withheld)} withheld",
                served=served,
                withheld=withheld,
            )
        if claims:
            return _reading(
                live,
                LiteState.STALE,
                (
                    f"all {len(claims)} claim(s) have expired as of {as_of}; they "
                    "are withheld rather than served with a label"
                ),
                withheld=withheld,
            )
        return _reading(
            live,
            LiteState.STALE,
            "the artifact carries no claim to serve",
        )

    # -- internals ---------------------------------------------------------

    def _unchanged(
        self, reason: str, *, reason_code: LiteReasonCode | None = None,
    ) -> LiteReading:
        """The state the node is still in, plus why an admission was refused."""

        current = self.read(as_of="1970-01-01T00:00:00Z")
        return LiteReading(
            state=current.state,
            reason_code=reason_code or current.reason_code,
            reason=f"nothing was admitted: {reason}",
            generation=current.generation,
            artifact_digest=current.artifact_digest,
            signer_key=current.signer_key,
            admitted_at=current.admitted_at,
        )


def _first_key_that_verifies(
    keys: Sequence[bytes], message: bytes, signature: bytes
) -> bytes | None:
    """A malformed key is skipped, never allowed to end the search early."""

    for key in keys:
        try:
            if verify_detached(public_key=key, message=message, signature=signature):
                return key
        except SignatureRefused:
            continue
    return None


def _reading(
    live: LiteGeneration,
    state: LiteState,
    reason: str,
    *,
    served: Sequence[Mapping] = (),
    withheld: Sequence[Mapping] = (),
    reason_code: LiteReasonCode | None = None,
) -> LiteReading:
    return LiteReading(
        state=state,
        reason_code=reason_code,
        reason=reason,
        generation=live.number,
        artifact_digest=live.artifact_digest,
        signer_key=live.signer_key,
        admitted_at=live.admitted_at,
        served=tuple(served),
        withheld=tuple(withheld),
    )


def _quarantined(
    live: LiteGeneration, reason: str, *, reason_code: LiteReasonCode | None = None,
) -> LiteReading:
    """Held, and named. A quarantined cache still reports what it was."""

    return _reading(live, LiteState.QUARANTINED, reason, reason_code=reason_code)


def _with_admitted(reading: LiteReading) -> LiteReading:
    return LiteReading(
        state=reading.state,
        reason_code=reading.reason_code,
        reason=reading.reason,
        generation=reading.generation,
        artifact_digest=reading.artifact_digest,
        signer_key=reading.signer_key,
        admitted_at=reading.admitted_at,
        served=reading.served,
        withheld=reading.withheld,
        admitted=True,
    )


@dataclass(frozen=True)
class KnowledgeReading:
    """Advisory supply only. Contains no Edge action or authority field."""

    source_class: str
    correlation: str
    reason: str
    asset_version: str | None = None
    freshness: str = "unavailable"
    trust: str = "unavailable"
    peer_context: PeerContext | None = None
    embedded_claims: tuple[Mapping, ...] = ()

    def blocks_core(self) -> bool:
        return False

    def as_event(self) -> dict:
        return {"event_type": "knowledge.context", "source_class": self.source_class,
                "correlation": self.correlation, "reason": self.reason,
                "asset_version": self.asset_version, "freshness": self.freshness,
                "trust": self.trust}


def knowledge_context(local: LiteReading, *, correlation: str,
                      peer: PeerContext | None = None, reason: str = "local-first embedded cache") -> KnowledgeReading:
    """Full-node context -> usable embedded cache -> explicit no-context.

    PeerContext is the pure signed-response reader's result, never raw bytes.
    This selection does not change readiness, leases, actions or enforcement.
    """
    if isinstance(peer, PeerContext):
        return KnowledgeReading("full-node context", correlation, "verified AZ-04 advisory",
                                peer.bundle_version, peer.expires_at, peer.trust, peer)
    if local.sources_capability and local.served:
        return KnowledgeReading("embedded cache", correlation, reason,
                                local.artifact_digest, "current", "verified",
                                embedded_claims=local.served)
    return KnowledgeReading("no-context", correlation, reason)
