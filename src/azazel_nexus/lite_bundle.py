"""Reading the Knowledge Lite bundle Azazel-Knowledge publishes (#67, E1-F).

**Nexus invents no bundle format and no signature format.** Azazel-Knowledge
owns both, and this module is a read-only consumer of what that repository
actually emits: a gzip tar carrying `manifest.json`, a detached `manifest.sig`
over the raw manifest bytes, and the declared table members.

`contract/azazel-knowledge-lite/` holds the producer's own fixtures, pinned by
source revision and digest, and `PROVENANCE.md` there records where they came
from. Nexus CI runs this reader over all six of them -- valid,
corrupt-signature, corrupt-payload, corrupt-truncated, expired and absent --
so the reader is tested against what the producer emits rather than against a
forgery written here.

## The trust decisions are this node's, and they live in `anchors.toml`

`required_signer_role`, `minimum_security_epoch` and
`accepted_export_policy_digests` are read from the anchor, **never** from the
manifest. A bundle must not be able to state which role may sign it, which
epoch is acceptable, or which privacy policy this node tolerates; an attacker
holding any valid key could otherwise declare itself eligible. The manifest
may *claim* an epoch and *record* the policy digest it was built under, and
whether those are good enough is decided here.

`tomllib` reads the anchor. It is the canonical reader, it is standard library
from 3.11, and 3.11 is this product's floor for exactly that reason
(`docs/support-matrix.md` §3.3). There is no hand-written parser: shipping a
partial one to read the trust anchor of a signed artifact would trade a
dependency for an attack surface.

## Any exception is a refusal

Knowledge says so explicitly, and its `corrupt-truncated` fixture is the case:
the tar decoder raises before the verifier has an opinion, so that artifact
produces **no `BUNDLE_*` code at all**. A reader that caught only the
producer's own error type would let it through as an unhandled error. Every
refusal here carries a gate and, where the producer names one, its code --
The code names are the producer's own, so a refusal here and a refusal
there are the same word.

Measured rather than assumed: the producer's `negative.json` *description*
for the truncated fixture says it produces no `BUNDLE_*` code, while its
`expected_error_code` says `BUNDLE_ARCHIVE_UNREADABLE`. Running the
producer's verifier over that fixture shows the code is real -- the
description is the stale half. The defensive advice is kept anyway, because
catching a known type only is wrong whether or not the producer currently
wraps.

## Expiry is not a gate

An expired bundle **verifies**. Expiry has no manifest field and no filename
convention: it is per claim, evaluated against this node's own `query_as_of`
(ADR-0015 D4). So a bundle whose claims have all expired is a bundle that
passed every gate and serves nothing -- `stale`, which is a different fact
from `quarantined` and calls for a different action.

## Nothing here is extracted to disk

Members are read from the archive into memory, bounded, and digest-checked
before any of them is returned. There is no staging directory to promote and
therefore no staging directory to promote by mistake -- which is the failure
the producer's `corrupt-payload` fixture exists to catch, where the tampered
bytes are written to staging before the digest check fails.
"""

from __future__ import annotations

import hashlib
import io
import json
import posixpath
import tarfile
import tomllib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional, Sequence

__all__ = [
    "BundleAccepted",
    "Claims",
    "EXPIRY_FIELD",
    "read_claims",
    "BundleRefused",
    "Gate",
    "MANIFEST_MEMBER",
    "SIGNATURE_MEMBER",
    "SUPPORTED_FORMATS",
    "TrustAnchors",
    "read_anchors",
    "verify_bundle",
]

MANIFEST_MEMBER = "manifest.json"
SIGNATURE_MEMBER = "manifest.sig"

#: The bundle formats this reader can read, inclusive. Knowledge emits 1 and
#: reads 1..1; a consumer that read "whatever arrives" would have no way to
#: refuse a future incompatible artifact for being incompatible.
SUPPORTED_FORMATS = (1, 1)

#: The format a manifest carrying no `bundle_format_version` is taken to be,
#: matching the producer's `IMPLICIT_BUNDLE_FORMAT_VERSION`.
IMPLICIT_FORMAT = 1

#: Ceilings. Every one of them bounds work done on bytes an adversary chose.
MAX_BUNDLE_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_MEMBERS = 64
MAX_MEMBER_NAME = 200
MAX_MEMBER_DEPTH = 8
MAX_SIGNATURE_LINES = 32

#: Manifest fields that would let a bundle speak about its own trust. A
#: manifest carrying one is refused rather than having it ignored: something
#: that tried is worth reporting.
TRUST_SHADOWING_FIELDS = (
    "threshold",
    "keys",
    "revoked",
    "key_roles",
    "required_signer_role",
    "minimum_security_epoch",
    "accepted_export_policy_digests",
    "last_imported_version",
)


class Gate(str, Enum):
    """Where a bundle was refused. One word per distinct operator action."""

    ANCHORS = "anchors"
    ARCHIVE = "archive"
    MANIFEST = "manifest"
    FORMAT = "format"
    SIGNATURE = "signature"
    SIGNER_ROLE = "signer-role"
    SECURITY_EPOCH = "security-epoch"
    EXPORT_POLICY = "export-policy"
    ROLLBACK = "rollback"
    CONTENT = "content"


class BundleRefused(Exception):
    """The bundle was not accepted, and this says at which gate and why."""

    def __init__(self, gate: Gate, code: str, detail: str) -> None:
        super().__init__(f"[{gate.value}/{code}] {detail}")
        self.gate = gate
        self.code = code
        self.detail = detail

    def as_event(self) -> dict:
        return {
            "event_type": "lite.bundle.refused",
            "gate": self.gate.value,
            "code": self.code,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class TrustAnchors:
    """Everything trust-related, read from `anchors.toml` and nowhere else."""

    threshold: int
    keys: Mapping[str, bytes]
    revoked: frozenset[str] = frozenset()
    key_roles: Mapping[str, str] = field(default_factory=dict)
    required_signer_role: Optional[str] = None
    minimum_security_epoch: Optional[int] = None
    accepted_export_policy_digests: Optional[frozenset[str]] = None

    def __post_init__(self) -> None:
        if self.threshold < 1:
            raise BundleRefused(
                Gate.ANCHORS,
                "ANCHORS_INVALID",
                f"threshold is {self.threshold}; an anchor requiring no signature "
                "is an anchor that trusts anything",
            )
        if not self.keys:
            raise BundleRefused(
                Gate.ANCHORS, "ANCHORS_INVALID", "the anchor names no verification key"
            )
        if self.threshold > len(self.keys):
            raise BundleRefused(
                Gate.ANCHORS,
                "ANCHORS_INVALID",
                f"threshold {self.threshold} exceeds the {len(self.keys)} key(s) "
                "the anchor names; nothing could ever satisfy it",
            )


@dataclass(frozen=True)
class BundleAccepted:
    """A bundle that passed every gate, and what came out of it."""

    manifest: Mapping
    #: Member path to its verified bytes. Digest-checked before being put here.
    members: Mapping[str, bytes]
    signers: tuple[str, ...]
    bundle_digest: str

    @property
    def bundle_version(self) -> int:
        return int(self.manifest["bundle_version"])

    @property
    def export_policy_digest(self) -> Optional[str]:
        profile = self.manifest.get("profile")
        if not isinstance(profile, dict):
            return None
        inputs = profile.get("selection_inputs")
        if not isinstance(inputs, dict):
            return None
        value = inputs.get("export_policy_digest")
        return value if isinstance(value, str) and value else None

    def as_event(self) -> dict:
        """Provenance. Never the content of a claim."""

        return {
            "event_type": "lite.bundle.accepted",
            "bundle_digest": self.bundle_digest,
            "bundle_version": self.bundle_version,
            "bundle_format_version": self.manifest.get("bundle_format_version"),
            "kind": self.manifest.get("kind"),
            "signers": list(self.signers),
            "export_policy_digest": self.export_policy_digest,
            "members": sorted(self.members),
        }


# -- the trust anchor ------------------------------------------------------


def read_anchors(path: Path) -> TrustAnchors:
    """Read `anchors.toml` with `tomllib`, refusing anything malformed."""

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise BundleRefused(
            Gate.ANCHORS, "ANCHORS_UNREADABLE", f"the trust anchor could not be read: {exc}"
        ) from exc
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise BundleRefused(
            Gate.ANCHORS, "ANCHORS_INVALID", f"the trust anchor is not valid TOML: {exc}"
        ) from exc

    keys: dict[str, bytes] = {}
    for key_id, hex_key in dict(document.get("keys", {})).items():
        if not isinstance(hex_key, str):
            raise BundleRefused(
                Gate.ANCHORS, "ANCHORS_INVALID", f"key {key_id!r} is not hex text"
            )
        try:
            material = bytes.fromhex(hex_key)
        except ValueError as exc:
            raise BundleRefused(
                Gate.ANCHORS, "ANCHORS_INVALID", f"key {key_id!r} is not hex: {exc}"
            ) from exc
        if len(material) != 32:
            raise BundleRefused(
                Gate.ANCHORS,
                "ANCHORS_INVALID",
                f"key {key_id!r} is {len(material)} bytes; an ed25519 key is 32",
            )
        keys[str(key_id)] = material

    role = document.get("required_signer_role")
    if role is not None and (not isinstance(role, str) or not role):
        raise BundleRefused(
            Gate.ANCHORS,
            "ANCHORS_INVALID",
            "required_signer_role must be a non-empty string when present",
        )
    epoch = document.get("minimum_security_epoch")
    if epoch is not None and (not isinstance(epoch, int) or isinstance(epoch, bool)):
        raise BundleRefused(
            Gate.ANCHORS,
            "ANCHORS_INVALID",
            "minimum_security_epoch must be an integer when present",
        )
    policies = document.get("accepted_export_policy_digests")
    if policies is not None:
        if (
            not isinstance(policies, list)
            or not policies
            or not all(isinstance(digest, str) and digest for digest in policies)
        ):
            raise BundleRefused(
                Gate.ANCHORS,
                "ANCHORS_INVALID",
                "accepted_export_policy_digests must be a non-empty list of "
                "non-empty strings when present",
            )
        policies = frozenset(policies)

    threshold = document.get("threshold", 1)
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        raise BundleRefused(Gate.ANCHORS, "ANCHORS_INVALID", "threshold must be an integer")

    return TrustAnchors(
        threshold=threshold,
        keys=keys,
        revoked=frozenset(str(k) for k in document.get("revoked", [])),
        key_roles={str(k): str(v) for k, v in dict(document.get("key_roles", {})).items()},
        required_signer_role=role,
        minimum_security_epoch=epoch,
        accepted_export_policy_digests=policies,
    )


# -- the bundle ------------------------------------------------------------


def verify_bundle(
    raw: bytes,
    *,
    anchors: TrustAnchors,
    last_imported_version: int = 0,
) -> BundleAccepted:
    """Verify one bundle completely, or raise `BundleRefused`.

    `last_imported_version` is the anti-rollback watermark this node holds. It
    is passed in rather than read from the bundle for the obvious reason.

    Every refusal is a `BundleRefused` carrying its gate. Callers are expected
    to treat **any** exception as a refusal anyway -- the producer's truncated
    fixture raises from the tar decoder and carries no producer code -- and
    this function converts those itself so that the gate is still named.
    """

    if len(raw) > MAX_BUNDLE_BYTES:
        raise BundleRefused(
            Gate.ARCHIVE,
            "BUNDLE_TOO_LARGE",
            f"the bundle is {len(raw)} bytes and the ceiling is {MAX_BUNDLE_BYTES}",
        )
    bundle_digest = "sha256:" + hashlib.sha256(raw).hexdigest()

    members = _read_members(raw)
    manifest_bytes = members.get(MANIFEST_MEMBER)
    if manifest_bytes is None:
        raise BundleRefused(Gate.MANIFEST, "BUNDLE_MANIFEST_MISSING", "no manifest.json")
    signature_bytes = members.get(SIGNATURE_MEMBER)
    if signature_bytes is None:
        raise BundleRefused(Gate.SIGNATURE, "BUNDLE_SIGNATURE_MISSING", "no manifest.sig")
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise BundleRefused(
            Gate.MANIFEST,
            "BUNDLE_MANIFEST_TOO_LARGE",
            f"manifest.json is {len(manifest_bytes)} bytes",
        )

    try:
        manifest = json.loads(manifest_bytes)
    except ValueError as exc:
        raise BundleRefused(
            Gate.MANIFEST, "BUNDLE_MANIFEST_INVALID", f"manifest.json is not JSON: {exc}"
        ) from exc
    if not isinstance(manifest, dict):
        raise BundleRefused(
            Gate.MANIFEST, "BUNDLE_MANIFEST_INVALID", "manifest.json is not an object"
        )

    shadowed = sorted(name for name in TRUST_SHADOWING_FIELDS if name in manifest)
    if shadowed:
        raise BundleRefused(
            Gate.MANIFEST,
            "BUNDLE_SHADOWS_TRUST_ANCHOR",
            f"the manifest carries trust or state fields {shadowed}; a bundle "
            "does not get to say what this node will accept",
        )

    _check_format(manifest)
    signers = _check_signatures(manifest_bytes, signature_bytes, anchors)
    _check_signer_role(signers, anchors)
    _check_security_epoch(manifest, anchors)
    _check_export_policy(manifest, anchors)
    _check_rollback(manifest, last_imported_version)
    content = _check_content(manifest, members)

    return BundleAccepted(
        manifest=manifest,
        members=content,
        signers=tuple(sorted(signers)),
        bundle_digest=bundle_digest,
    )


def _read_members(raw: bytes) -> dict[str, bytes]:
    """Decode the archive into memory, bounded at every step.

    Nothing is written to disk. The producer's `corrupt-payload` fixture
    exists because a reader that stages before verifying can promote what it
    staged; a reader with no staging cannot.
    """

    found: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            for index, info in enumerate(archive):
                if index >= MAX_MEMBERS:
                    raise BundleRefused(
                        Gate.ARCHIVE,
                        "BUNDLE_TOO_MANY_MEMBERS",
                        f"more than {MAX_MEMBERS} members",
                    )
                _check_member_name(info.name)
                if not info.isreg():
                    raise BundleRefused(
                        Gate.ARCHIVE,
                        "BUNDLE_UNSAFE_MEMBER",
                        f"{info.name!r} is not a regular file; links, devices and "
                        "directories are refused rather than skipped",
                    )
                if info.name in found:
                    raise BundleRefused(
                        Gate.ARCHIVE,
                        "BUNDLE_DUPLICATE_MEMBER",
                        f"{info.name!r} appears twice; which one a reader gets "
                        "would depend on the reader",
                    )
                if info.size > MAX_MEMBER_BYTES:
                    raise BundleRefused(
                        Gate.ARCHIVE,
                        "BUNDLE_MEMBER_TOO_LARGE",
                        f"{info.name!r} declares {info.size} bytes",
                    )
                total += info.size
                if total > MAX_TOTAL_BYTES:
                    raise BundleRefused(
                        Gate.ARCHIVE,
                        "BUNDLE_DECOMPRESSION_BOMB",
                        f"the members total more than {MAX_TOTAL_BYTES} bytes",
                    )
                handle = archive.extractfile(info)
                if handle is None:
                    raise BundleRefused(
                        Gate.ARCHIVE, "BUNDLE_UNSAFE_MEMBER", f"{info.name!r} has no content"
                    )
                found[info.name] = handle.read(MAX_MEMBER_BYTES + 1)
                if len(found[info.name]) > MAX_MEMBER_BYTES:
                    raise BundleRefused(
                        Gate.ARCHIVE,
                        "BUNDLE_MEMBER_TOO_LARGE",
                        f"{info.name!r} is larger than it declared",
                    )
    except BundleRefused:
        raise
    except Exception as exc:  # noqa: BLE001 - any exception is a refusal
        raise BundleRefused(
            Gate.ARCHIVE,
            "BUNDLE_ARCHIVE_UNREADABLE",
            f"the archive could not be read ({type(exc).__name__}: {exc}). "
            "Caught as any exception rather than as a known type: the tar "
            "decoder raises before the verifier has an opinion, and a reader "
            "that caught only a known error type would let this through as an "
            "unhandled error",
        ) from exc
    return found


def _check_member_name(name: str) -> None:
    if len(name) > MAX_MEMBER_NAME:
        raise BundleRefused(
            Gate.ARCHIVE, "BUNDLE_MEMBER_NAME_TOO_LONG", f"{name[:60]!r}... is too long"
        )
    if name.startswith("/") or ".." in name.split("/") or posixpath.normpath(name) != name:
        raise BundleRefused(
            Gate.ARCHIVE,
            "BUNDLE_UNSAFE_MEMBER",
            f"{name!r} is not a plain relative path inside the bundle",
        )
    if name.count("/") > MAX_MEMBER_DEPTH:
        raise BundleRefused(
            Gate.ARCHIVE, "BUNDLE_MEMBER_PATH_TOO_DEEP", f"{name!r} is nested too deeply"
        )


def _check_format(manifest: Mapping) -> None:
    declared = manifest.get("bundle_format_version", IMPLICIT_FORMAT)
    if not isinstance(declared, int) or isinstance(declared, bool):
        raise BundleRefused(
            Gate.FORMAT,
            "BUNDLE_FORMAT_INVALID",
            f"bundle_format_version must be an integer, got {declared!r}",
        )
    low, high = SUPPORTED_FORMATS
    if not low <= declared <= high:
        raise BundleRefused(
            Gate.FORMAT,
            "BUNDLE_FORMAT_UNSUPPORTED",
            f"bundle format {declared} is outside {low}..{high} this reader "
            "supports; an incompatible artifact is refused for being "
            "incompatible rather than misread",
        )
    if manifest.get("kind") != "full":
        raise BundleRefused(
            Gate.FORMAT,
            "BUNDLE_KIND_UNSUPPORTED",
            f"kind is {manifest.get('kind')!r}; Lite is full-only (ADR-0017) and "
            "this reader applies no delta to anything",
        )


def _check_signatures(
    manifest_bytes: bytes, signature_bytes: bytes, anchors: TrustAnchors
) -> set[str]:
    from .signature import verify_detached

    try:
        text = signature_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BundleRefused(
            Gate.SIGNATURE, "BUNDLE_SIGNATURE_MALFORMED", f"manifest.sig is not text: {exc}"
        ) from exc
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) > MAX_SIGNATURE_LINES:
        raise BundleRefused(
            Gate.SIGNATURE,
            "BUNDLE_SIGNATURE_MALFORMED",
            f"{len(lines)} signature lines; the ceiling is {MAX_SIGNATURE_LINES}",
        )
    pairs: list[tuple[str, str]] = []
    for line in lines:
        if ":" not in line:
            raise BundleRefused(
                Gate.SIGNATURE, "BUNDLE_SIGNATURE_MALFORMED", f"malformed line: {line!r}"
            )
        key_id, _, hex_signature = line.partition(":")
        pairs.append((key_id.strip(), hex_signature.strip()))

    offered = {key_id for key_id, _ in pairs}
    revoked = offered & anchors.revoked
    if revoked:
        raise BundleRefused(
            Gate.SIGNATURE,
            "BUNDLE_REVOKED_SIGNER",
            f"signed by revoked key(s) {sorted(revoked)}",
        )

    verified: set[str] = set()
    for key_id, hex_signature in pairs:
        material = anchors.keys.get(key_id)
        if material is None:
            continue
        try:
            signature = bytes.fromhex(hex_signature)
        except ValueError:
            continue
        try:
            if verify_detached(
                public_key=material, message=manifest_bytes, signature=signature
            ):
                verified.add(key_id)
        except Exception:  # noqa: BLE001 - a bad key is not a valid signature
            continue
    if len(verified) < anchors.threshold:
        raise BundleRefused(
            Gate.SIGNATURE,
            "BUNDLE_SIGNATURE_THRESHOLD_NOT_MET",
            f"only {len(verified)} of the required {anchors.threshold} "
            "signature(s) verified",
        )
    return verified


def _check_signer_role(signers: set[str], anchors: TrustAnchors) -> None:
    """Which key signed, separately from whether the signature is valid."""

    required = anchors.required_signer_role
    if required is None:
        return
    holders = {key_id for key_id in signers if anchors.key_roles.get(key_id) == required}
    if not holders:
        raise BundleRefused(
            Gate.SIGNER_ROLE,
            "BUNDLE_SIGNER_ROLE_NOT_PERMITTED",
            f"this node requires a signature from role {required!r} and the "
            f"verified signer(s) {sorted(signers)} hold "
            f"{sorted({anchors.key_roles.get(k) for k in signers})}",
        )


def _check_security_epoch(manifest: Mapping, anchors: TrustAnchors) -> None:
    minimum = anchors.minimum_security_epoch
    if minimum is None:
        return
    declared = manifest.get("security_epoch")
    if declared is None:
        raise BundleRefused(
            Gate.SECURITY_EPOCH,
            "BUNDLE_SECURITY_EPOCH_MISSING",
            f"this node requires security_epoch >= {minimum} and the manifest "
            "declares none",
        )
    if not isinstance(declared, int) or isinstance(declared, bool):
        raise BundleRefused(
            Gate.SECURITY_EPOCH,
            "BUNDLE_SECURITY_EPOCH_INVALID",
            f"security_epoch must be an integer, got {declared!r}",
        )
    if declared < minimum:
        raise BundleRefused(
            Gate.SECURITY_EPOCH,
            "BUNDLE_SECURITY_EPOCH_TOO_LOW",
            f"the bundle declares security_epoch {declared} and this node "
            f"requires at least {minimum}; a correctly signed artifact from "
            "before a security event is still from before it",
        )


def _check_export_policy(manifest: Mapping, anchors: TrustAnchors) -> None:
    """Whether this node tolerates the privacy policy it was built under."""

    accepted = anchors.accepted_export_policy_digests
    if accepted is None:
        return
    declared: Optional[str] = None
    profile = manifest.get("profile")
    if isinstance(profile, dict):
        inputs = profile.get("selection_inputs")
        if isinstance(inputs, dict):
            value = inputs.get("export_policy_digest")
            if isinstance(value, str) and value:
                declared = value
    if declared is None:
        raise BundleRefused(
            Gate.EXPORT_POLICY,
            "BUNDLE_EXPORT_POLICY_MISSING",
            f"this node accepts only export policy digest(s) {sorted(accepted)} "
            "and the manifest records none",
        )
    if declared not in accepted:
        raise BundleRefused(
            Gate.EXPORT_POLICY,
            "BUNDLE_EXPORT_POLICY_NOT_ACCEPTED",
            f"the bundle was built under export policy digest {declared!r}, "
            f"which is not among the digest(s) this node accepts: {sorted(accepted)}",
        )


def _check_rollback(manifest: Mapping, last_imported_version: int) -> None:
    declared = manifest.get("bundle_version")
    if not isinstance(declared, int) or isinstance(declared, bool):
        raise BundleRefused(
            Gate.ROLLBACK,
            "BUNDLE_VERSION_INVALID",
            f"bundle_version must be an integer, got {declared!r}",
        )
    if declared <= last_imported_version:
        raise BundleRefused(
            Gate.ROLLBACK,
            "BUNDLE_VERSION_REGRESSION",
            f"bundle_version {declared} does not advance past the watermark "
            f"{last_imported_version}; a correctly signed older artifact is "
            "still an older artifact",
        )


def _check_content(manifest: Mapping, members: Mapping[str, bytes]) -> dict[str, bytes]:
    """Every declared member present and digest-matched; no undeclared member."""

    files = manifest.get("files")
    if not isinstance(files, dict):
        raise BundleRefused(
            Gate.MANIFEST, "BUNDLE_MANIFEST_INVALID", "the manifest declares no files map"
        )
    declared = set(files)
    present = set(members) - {MANIFEST_MEMBER, SIGNATURE_MEMBER}
    missing = sorted(declared - present)
    if missing:
        raise BundleRefused(
            Gate.CONTENT, "BUNDLE_FILE_MISSING", f"declared but absent: {missing}"
        )
    undeclared = sorted(present - declared)
    if undeclared:
        raise BundleRefused(
            Gate.CONTENT,
            "BUNDLE_UNDECLARED_MEMBER",
            f"present but not declared: {undeclared}; an unsigned member is not "
            "covered by the signature that covers the manifest",
        )
    verified: dict[str, bytes] = {}
    for path in sorted(declared):
        expected = files[path]
        if not isinstance(expected, str):
            raise BundleRefused(
                Gate.MANIFEST, "BUNDLE_MANIFEST_INVALID", f"{path!r} declares no digest"
            )
        actual = hashlib.sha256(members[path]).hexdigest()
        if actual != expected:
            raise BundleRefused(
                Gate.CONTENT,
                "BUNDLE_FILE_HASH_MISMATCH",
                f"{path!r} hashes to {actual} and the manifest declares "
                f"{expected}. Every trust gate passed and only this caught it",
            )
        verified[path] = members[path]
    return verified


# -- claims, and which of them may be served right now ---------------------
#
# Expiry is **not** a verification gate. An expired bundle passes every gate
# above. It is per claim, carried on the row, and evaluated against this
# node's own `query_as_of` -- never against a timestamp baked into the
# artifact, and never against a clock read here.


#: The row field carrying a claim's expiry, as Knowledge writes it.
EXPIRY_FIELD = "agg_next_expiry"


@dataclass(frozen=True)
class Claims:
    """What an accepted bundle offers, split by whether it may be served."""

    served: tuple[Mapping, ...]
    withheld: tuple[Mapping, ...]
    #: Rows carrying no expiry at all. Static reference material -- an ATT&CK
    #: technique does not expire on a clock -- so it is neither
    #: served-because-fresh nor withheld-because-expired. It is reported
    #: separately, and it never makes a bundle `available`: see
    #: `serves_a_dated_claim`.
    timeless: tuple[Mapping, ...]

    @property
    def serves_a_dated_claim(self) -> bool:
        """Whether any claim with an expiry may be served right now.

        **Timeless rows deliberately do not count.** The producer says of its
        expired fixture that a conforming reader "serves NO indicator from
        it", and that the static reference material is in that fixture *"so
        that withholding the expired indicators can be told apart from
        discarding the whole artifact"*.

        Counting reference material as something served would make a bundle
        whose every dated claim has expired report as serving -- which is the
        one thing that fixture exists to catch. It is the difference between
        `available` and `stale`, and an earlier draft of this property got it
        wrong by returning `served or timeless`.
        """

        return bool(self.served)


def read_claims(accepted: "BundleAccepted", *, query_as_of: str) -> Claims:
    """Split an accepted bundle's rows by expiry against `query_as_of`.

    A row with no `agg_next_expiry` is *timeless*, not fresh: Knowledge's own
    provenance says static reference material "does not expire on a clock",
    and calling it fresh would let a bundle whose every dated claim has
    expired still report as serving.

    A row whose expiry cannot be read is **withheld**, not served. An
    unparseable expiry is not a licence to serve.
    """

    served: list[Mapping] = []
    withheld: list[Mapping] = []
    timeless: list[Mapping] = []
    now = _instant(query_as_of, "query_as_of")
    for path in sorted(accepted.members):
        for row in _rows(accepted.members[path], path):
            expiry = row.get(EXPIRY_FIELD)
            if expiry is None:
                timeless.append(row)
                continue
            try:
                moment = _instant(expiry, f"{path} {EXPIRY_FIELD}")
            except BundleRefused:
                withheld.append(row)
                continue
            (served if now < moment else withheld).append(row)
    return Claims(tuple(served), tuple(withheld), tuple(timeless))


def _rows(raw: bytes, path: str) -> list[Mapping]:
    rows: list[Mapping] = []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BundleRefused(
            Gate.CONTENT, "BUNDLE_MEMBER_NOT_TEXT", f"{path!r} is not UTF-8: {exc}"
        ) from exc
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise BundleRefused(
                Gate.CONTENT,
                "BUNDLE_MEMBER_NOT_JSONL",
                f"{path!r} line {number} is not JSON: {exc}",
            ) from exc
        if not isinstance(row, dict):
            raise BundleRefused(
                Gate.CONTENT,
                "BUNDLE_MEMBER_NOT_JSONL",
                f"{path!r} line {number} is not an object",
            )
        rows.append(row)
    return rows


def _instant(text: object, what: str):
    """One RFC3339 UTC instant. Nothing here reads a clock."""

    from datetime import datetime, timezone

    raw = str(text)
    normalised = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        moment = datetime.fromisoformat(normalised)
    except ValueError as exc:
        raise BundleRefused(
            Gate.CONTENT, "BUNDLE_EXPIRY_INVALID", f"{what} is not RFC3339: {raw!r}"
        ) from exc
    if moment.tzinfo is None:
        raise BundleRefused(
            Gate.CONTENT,
            "BUNDLE_EXPIRY_INVALID",
            f"{what} carries no time zone: {raw!r}; an instant without one "
            "means something different on every host",
        )
    return moment.astimezone(timezone.utc)
