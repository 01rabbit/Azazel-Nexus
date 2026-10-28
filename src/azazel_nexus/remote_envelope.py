"""The only thing the remote transport will accept as proof of sanitisation (#98).

A `SanitizerDecision` is a Python object. Anything that can construct one can
claim its contents, and "the caller told us this frame is `P1-sanitized`" is
not a sanitisation -- it is a caller saying so. The remote daemon runs under
its own account behind its own socket, and what arrives there has crossed a
process boundary: whatever the sender *is* on the other side, what the daemon
receives is bytes.

So the daemon accepts **one shape only**: a detached Ed25519 signature over a
canonical payload, produced by the sanitizer boundary, binding six things
that a forged or replayed request would have to get right together.

| bound | what a mismatch would otherwise allow |
| --- | --- |
| `content_digest` | an envelope minted for one frame reused to send another |
| `privacy_class` | a caller asserting its own class |
| `policy_revision` | a frame sanitised under a policy since withdrawn |
| `expires_at` | an envelope kept and used later, under conditions nobody re-checked |
| `nonce` + `provider_id` | the same authorised request replayed, or sent to a provider it was never authorised for |
| `opt_in_generation` | a frame authorised under a remote opt-in the operator has since withdrawn |

Each is checked here except the last, which only `mio_remoted` can check: it
compares it with the generation in force (`mio_remote_consent`) immediately
before the transport, under the send gate. None is inferable from another,
which is why they are six fields rather than one token.

## What this module is not

It does not sanitise. `sanitizer.py` decides what may leave and builds the
frame; this decides whether a **thing claiming to be such a frame** may be
believed by a component that did not watch it being built.

It holds no key material, signs nothing, and reaches nothing.
`verify_detached` is the package's own verifier, so this works on a node with
no wheel installed.

## This build mints no envelope

There is no signer here and no commissioned sanitizer key, so no envelope can
be produced and none would verify. That is the shipped state: the transport
accepts only what this module admits, and this module admits nothing without
a commissioned key.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional, Sequence

from .sanitizer import NEVER_REMOTE, PrivacyClass
from .signature import SIGNATURE_BYTES, SignatureRefused, verify_detached

__all__ = [
    "ENVELOPE_DOMAIN",
    "ENVELOPE_SCHEMA",
    "EnvelopeRefusal",
    "EnvelopeRefused",
    "MAX_ENVELOPE_BYTES",
    "MAX_FRAME_BYTES",
    "MAX_OPT_IN_GENERATION",
    "NonceLedger",
    "OpenedEnvelope",
    "REMOTE_ELIGIBLE",
    "envelope_payload",
    "open_envelope",
]

#: The signing domain. A **different kind of signing target** from a catalog
#: or a registry: those authorise a *document*, this authorises *one request,
#: once*. A key that signs catalogs must not thereby authorise egress of a
#: frame, so the domain separates them even when the same key is held.
#:
#: It moves for the same three reasons `model_catalog.CATALOG_DOMAIN` states
#: -- the kind of target, the canonicalisation, or cross-protocol separation
#: -- and for no field that is added to the payload.
ENVELOPE_DOMAIN = b"azazel-nexus/sanitized-envelope/v1\x00"

#: The payload shape. Moves when a field is added or changes meaning, which
#: is the thing the domain deliberately does not do.
ENVELOPE_SCHEMA = "azazel-nexus/sanitized-envelope/2"

#: The largest opt-in generation an envelope may name (`mio_remote_consent`).
MAX_OPT_IN_GENERATION = 2**63 - 1

#: An envelope larger than this is refused before it is parsed. It carries
#: digests and symbols, never content, so it is small by construction; a
#: large one is a malformed one.
MAX_ENVELOPE_BYTES = 4096

#: The largest sanitised frame an envelope may authorise. The provider record
#: carries its own, lower, ceiling; this one exists so that a frame is bounded
#: before any provider is consulted.
MAX_FRAME_BYTES = 256 * 1024

#: The only classes that may ever appear in a valid envelope.
#:
#: `P2-mission` and `P3-restricted` are absent rather than checked against a
#: list somebody could edit -- and they are checked against `NEVER_REMOTE` as
#: well, below, because two statements of the same refusal is what survives
#: one of them being rewritten.
REMOTE_ELIGIBLE = frozenset({PrivacyClass.P0_PUBLIC, PrivacyClass.P1_SANITIZED})


class EnvelopeRefusal(str, Enum):
    """Why an envelope was not believed. One value per condition, never merged.

    Structured so that an audit entry can say what happened without carrying
    what was in the frame. A free-text reason would eventually carry content,
    because the easiest way to explain a rejection is to quote the thing.
    """

    MALFORMED = "malformed"
    UNSIGNED = "unsigned"
    UNKNOWN_SCHEMA = "unknown_schema"
    NOT_CANONICAL = "not_canonical"
    CONTENT_MISMATCH = "content_mismatch"
    CLASS_NOT_REMOTE_ELIGIBLE = "class_not_remote_eligible"
    POLICY_REVISION_MISMATCH = "policy_revision_mismatch"
    PROVIDER_MISMATCH = "provider_mismatch"
    EXPIRED = "expired"
    REPLAYED = "replayed"
    FRAME_TOO_LARGE = "frame_too_large"


class EnvelopeRefused(Exception):
    """An envelope that may not be believed. Refused, never repaired.

    Carries the structured refusal and a reason naming **symbols and
    quantities only**. There is no path by which frame content reaches this
    message.
    """

    def __init__(self, refusal: EnvelopeRefusal, reason: str) -> None:
        super().__init__(f"{refusal.value}: {reason}")
        self.refusal = refusal
        self.reason = reason


@dataclass(frozen=True)
class OpenedEnvelope:
    """A believed envelope. Holding one is not having sent anything."""

    content_digest: str
    privacy_class: PrivacyClass
    policy_version: str
    policy_revision: int
    provider_id: str
    nonce: str
    expires_at: str
    frame_bytes: int
    #: The remote opt-in generation the sanitizer boundary read. Believed as
    #: signed; whether it is still the generation in force is the sender's
    #: check, made under the send gate.
    opt_in_generation: int

    def as_event(self) -> dict:
        """Audit metadata: digests, symbols and counts. Never the frame."""

        return {
            "event_type": "mio.remote.envelope.opened",
            "content_digest": self.content_digest,
            "privacy_class": self.privacy_class.value,
            "policy_version": self.policy_version,
            "policy_revision": self.policy_revision,
            "provider_id": self.provider_id,
            "nonce": self.nonce,
            "expires_at": self.expires_at,
            "frame_bytes": self.frame_bytes,
            "opt_in_generation": self.opt_in_generation,
        }


class NonceLedger:
    """The nonces this node has already honoured. One use each.

    Bounded, and it refuses rather than evicting. An eviction policy is a
    policy for forgetting that a request was already sent, and a forgotten
    nonce is a replay that succeeds. When it is full the node stops accepting
    envelopes, which is the safe direction: a node that cannot remember what
    it has sent must not send more.
    """

    def __init__(self, *, capacity: int = 65536) -> None:
        if capacity < 1:
            raise ValueError("a ledger that remembers nothing accepts every replay")
        self._capacity = capacity
        self._seen: set = set()

    def __contains__(self, nonce: object) -> bool:
        return nonce in self._seen

    def __len__(self) -> int:
        return len(self._seen)

    def remember(self, nonce: str) -> None:
        """Record a nonce as spent. Refuses a repeat and refuses when full."""

        if nonce in self._seen:
            raise EnvelopeRefused(
                EnvelopeRefusal.REPLAYED,
                "this nonce has already authorised a request",
            )
        if len(self._seen) >= self._capacity:
            raise EnvelopeRefused(
                EnvelopeRefusal.REPLAYED,
                f"the nonce ledger holds its limit of {self._capacity}; a node "
                "that cannot remember what it has sent does not send more",
            )
        self._seen.add(nonce)


def _canonical(document: Mapping) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def envelope_payload(
    *,
    content_digest: str,
    privacy_class: PrivacyClass,
    policy_version: str,
    policy_revision: int,
    provider_id: str,
    nonce: str,
    expires_at: str,
    frame_bytes: int,
    opt_in_generation: int,
) -> bytes:
    """The exact bytes a sanitizer boundary signs.

    Here so that the signer and the verifier cannot disagree about what was
    signed, which is the disagreement every canonicalisation bug is.
    """

    return _canonical(
        {
            "schema": ENVELOPE_SCHEMA,
            "content_digest": content_digest,
            "privacy_class": privacy_class.value,
            "policy_version": policy_version,
            "policy_revision": policy_revision,
            "provider_id": provider_id,
            "nonce": nonce,
            "expires_at": expires_at,
            "frame_bytes": frame_bytes,
            "opt_in_generation": opt_in_generation,
        }
    )


def _refuse(refusal: EnvelopeRefusal, reason: str):
    raise EnvelopeRefused(refusal, reason)


def open_envelope(
    raw: bytes,
    *,
    frame: bytes,
    sanitizer_keys: Mapping[str, str],
    provider_id: str,
    policy_revision: int,
    now: str,
    nonces: NonceLedger,
    max_frame_bytes: int = MAX_FRAME_BYTES,
) -> OpenedEnvelope:
    """Believe an envelope, or refuse. Every check, every time, in one place.

    `now` is passed in. A component that read its own clock here would be a
    component whose expiry check depends on a clock the caller cannot see --
    and an expiry nobody can reproduce is an expiry nobody can test.

    The nonce is spent **last**, after every other check has passed. Spending
    it earlier would let a malformed envelope burn a nonce that a correct
    retry of the same request would then be refused for.
    """

    if not isinstance(raw, (bytes, bytearray)):
        _refuse(EnvelopeRefusal.MALFORMED, "an envelope is bytes")
    if len(raw) > MAX_ENVELOPE_BYTES:
        _refuse(
            EnvelopeRefusal.MALFORMED,
            f"{len(raw)} bytes is larger than {MAX_ENVELOPE_BYTES}; an envelope "
            "carries digests and symbols, never content",
        )
    if len(raw) <= SIGNATURE_BYTES:
        _refuse(
            EnvelopeRefusal.MALFORMED,
            "too short to carry a signature and a payload",
        )

    signature, payload = bytes(raw[:SIGNATURE_BYTES]), bytes(raw[SIGNATURE_BYTES:])
    signed = ENVELOPE_DOMAIN + payload
    signer = None
    unusable = []
    for key_id, material in sorted(sanitizer_keys.items()):
        try:
            if verify_detached(public_key=material, message=signed, signature=signature):
                signer = key_id
                break
        except SignatureRefused:
            # The **key** is unusable, which is not the same fact as "nobody
            # signed this" -- and an operator sent to look at the sender when
            # the problem is their own commissioned key has been sent to the
            # wrong place. Collected rather than raised, so one bad key among
            # several does not stop a good one verifying.
            unusable.append(key_id)
            continue
    if signer is None:
        if unusable and len(unusable) == len(sanitizer_keys):
            _refuse(
                EnvelopeRefusal.UNSIGNED,
                f"every key commissioned for the sanitizer role ({sorted(unusable)}) "
                "is unusable as a public key, so nothing could be verified "
                "against them. This is a fault in this node's commissioning, "
                "not in what it was sent",
            )
        _refuse(
            EnvelopeRefusal.UNSIGNED,
            "no key holding the sanitizer role signed these bytes under the "
            "envelope domain. A catalog or registry signature does not verify "
            "here, whatever key made it",
        )

    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        _refuse(EnvelopeRefusal.MALFORMED, f"the payload is not JSON: {exc}")
    if not isinstance(document, dict):
        _refuse(EnvelopeRefusal.MALFORMED, "the payload is JSON that is not an object")
    if document.get("schema") != ENVELOPE_SCHEMA:
        _refuse(
            EnvelopeRefusal.UNKNOWN_SCHEMA,
            f"the envelope names schema {document.get('schema')!r} and this "
            f"reader knows {ENVELOPE_SCHEMA!r}",
        )

    required = (
        "content_digest",
        "privacy_class",
        "policy_version",
        "policy_revision",
        "provider_id",
        "nonce",
        "expires_at",
        "frame_bytes",
        "opt_in_generation",
    )
    missing = sorted(set(required) - set(document))
    if missing:
        _refuse(EnvelopeRefusal.MALFORMED, f"the envelope omits {missing}")
    extra = sorted(set(document) - set(required) - {"schema"})
    if extra:
        # Refused rather than ignored: a field this reader does not check is a
        # field the signer believed it was binding.
        _refuse(EnvelopeRefusal.MALFORMED, f"the envelope carries unknown {extra}")

    # The bytes that verified must be the canonical form of what was read.
    # Without this a signature over one serialisation could be presented with
    # a differently-ordered payload that parses to something else.
    if _canonical(document) != payload:
        _refuse(
            EnvelopeRefusal.NOT_CANONICAL,
            "the signed bytes are not the canonical form of the document they "
            "parse to",
        )

    try:
        privacy_class = PrivacyClass(document["privacy_class"])
    except ValueError:
        _refuse(
            EnvelopeRefusal.CLASS_NOT_REMOTE_ELIGIBLE,
            f"{document['privacy_class']!r} is not a privacy class this product "
            "defines",
        )
    # Two statements of one refusal, on purpose. `REMOTE_ELIGIBLE` says what
    # may appear; `NEVER_REMOTE` says what may not. Either alone would be a
    # single line whose deletion opens the path.
    if privacy_class not in REMOTE_ELIGIBLE or privacy_class in NEVER_REMOTE:
        _refuse(
            EnvelopeRefusal.CLASS_NOT_REMOTE_ELIGIBLE,
            f"{privacy_class.value} does not leave this node, whatever signed "
            "an envelope saying it may",
        )

    frame_bytes = document["frame_bytes"]
    if not isinstance(frame_bytes, int) or isinstance(frame_bytes, bool):
        _refuse(EnvelopeRefusal.MALFORMED, "frame_bytes is an integer")
    if frame_bytes != len(frame):
        _refuse(
            EnvelopeRefusal.CONTENT_MISMATCH,
            f"the envelope authorises {frame_bytes} bytes and the frame is "
            f"{len(frame)}",
        )
    if frame_bytes < 1:
        # Not "too large". A refusal whose name misdescribes the condition is
        # a refusal an operator acts on wrongly.
        _refuse(
            EnvelopeRefusal.MALFORMED,
            "the envelope authorises an empty frame, so there is nothing to "
            "authorise",
        )
    if frame_bytes > max_frame_bytes:
        _refuse(
            EnvelopeRefusal.FRAME_TOO_LARGE,
            f"{frame_bytes} bytes is larger than {max_frame_bytes}",
        )

    digest = "sha256:" + hashlib.sha256(frame).hexdigest()
    if document["content_digest"] != digest:
        _refuse(
            EnvelopeRefusal.CONTENT_MISMATCH,
            "the envelope was minted for a different frame; an authorisation "
            "that does not name its content authorises anything",
        )

    if document["policy_revision"] != policy_revision:
        _refuse(
            EnvelopeRefusal.POLICY_REVISION_MISMATCH,
            f"the envelope was minted under policy revision "
            f"{document['policy_revision']!r} and this node is commissioned at "
            f"{policy_revision!r}. A frame sanitised under a withdrawn policy "
            "is not sanitised under this one",
        )
    if document["provider_id"] != provider_id:
        _refuse(
            EnvelopeRefusal.PROVIDER_MISMATCH,
            f"the envelope authorises {document['provider_id']!r} and this "
            f"request is for {provider_id!r}",
        )

    expires_at = document["expires_at"]
    if not isinstance(expires_at, str) or not isinstance(now, str) or not now:
        _refuse(EnvelopeRefusal.MALFORMED, "expiry and the current instant are RFC3339 strings")
    if expires_at <= now:
        # Lexicographic over RFC3339 UTC, which orders correctly by
        # construction. `<=` rather than `<`: an envelope expiring at exactly
        # this instant has expired, and the boundary belongs on the refusing
        # side of every check here.
        _refuse(
            EnvelopeRefusal.EXPIRED,
            f"the envelope expired at {expires_at} and it is now {now}",
        )

    generation = document["opt_in_generation"]
    if (type(generation) is not int
            or not 1 <= generation <= MAX_OPT_IN_GENERATION):
        _refuse(
            EnvelopeRefusal.MALFORMED,
            "opt_in_generation is a positive integer; an envelope minted with "
            "no remote opt-in in force authorises nothing",
        )

    nonce = document["nonce"]
    if not isinstance(nonce, str) or len(nonce) < 32:
        _refuse(
            EnvelopeRefusal.MALFORMED,
            "a nonce is at least 32 characters; a short one is a nonce an "
            "attacker can exhaust",
        )
    nonces.remember(nonce)

    return OpenedEnvelope(
        content_digest=digest,
        privacy_class=privacy_class,
        policy_version=str(document["policy_version"]),
        policy_revision=int(document["policy_revision"]),
        provider_id=provider_id,
        nonce=nonce,
        expires_at=expires_at,
        frame_bytes=frame_bytes,
        opt_in_generation=generation,
    )
