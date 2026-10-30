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
the tar stream ends part-way through a member, the tar decoder raises, and the
producer's verifier wraps that decoder error as `BundleVerifyError` with code
`BUNDLE_ARCHIVE_UNREADABLE`. A reader that caught only the producer's own error
type would be one decoder change away from letting such an artifact through as
an unhandled error, so this reader does not rely on the wrapping. Every
refusal here carries a gate and, where the producer names one, its code --
The code names are the producer's own, so a refusal here and a refusal
there are the same word.

Measured rather than assumed: running the producer's verifier over that
fixture produces `BUNDLE_ARCHIVE_UNREADABLE`, matching the
`expected_error_code` in `negative.json`. An earlier revision of the
producer's *description* said it produced no `BUNDLE_*` code; that stale text
was corrected in Azazel-Knowledge#109 (pinned here since then). The defensive
advice is kept anyway, because catching a known type only is wrong whether or
not the producer currently wraps.

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
import zlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional, Sequence

__all__ = [
    "BundleAccepted",
    "Claims",
    "MAX_LINE_BYTES",
    "iter_served",
    "iter_served_with_member",
    "Integrity",
    "KnowledgeReading",
    "StaticReference",
    "TimeBound",
    "absent_reading",
    "reading_for",
    "refused_reading",
    "EXPIRY_FIELD",
    "read_claims",
    "BundleRefused",
    "Gate",
    "MANIFEST_MEMBER",
    "SIGNATURE_MEMBER",
    "SUPPORTED_FORMATS",
    "TrustAnchors",
    "meetable_keys",
    "parse_anchors",
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
MAX_MEMBERS = 64
MAX_MEMBER_BYTES = 256 * 1024 * 1024
#: The largest Lite profile Knowledge builds (`knowledge-lite-32g`) carries at
#: most 512 MiB of content; the manifest and signature members come on top.
#: This was 1 GiB, twice anything a producer can emit.
MAX_TOTAL_BYTES = 512 * 1024 * 1024 + 2 * MAX_MANIFEST_BYTES
#: Content may decompress to at most this many times the bundle's own size,
#: the producer verifier's `DEFAULT_MAX_RATIO`. The size of the archive is the
#: one number an attacker cannot inflate, so this is what bounds the memory a
#: small hostile bundle can make this reader spend before any signature is
#: checked.
MAX_RATIO = 100
#: Tar framing allowed on top of the content: per member a header, a PAX
#: header and its record, and padding; then the end blocks and the record.
TAR_OVERHEAD_BYTES = (MAX_MEMBERS + 2) * 2048 + 20 * 512
#: How much is inflated per step before the ceiling is checked again.
INFLATE_STEP_BYTES = 1024 * 1024
MAX_MEMBER_NAME = 200
#: UTF-8 bytes per path component: the producer verifier's
#: `DEFAULT_MAX_MEMBER_COMPONENT_BYTES` (Azazel-Knowledge#110, K10), the
#: common POSIX NAME_MAX. `MAX_MEMBER_NAME` counts characters, so without this
#: a component of multi-byte characters could still pass it.
MAX_MEMBER_COMPONENT_BYTES = 255
MAX_MEMBER_DEPTH = 8
MAX_SIGNATURE_LINES = 32

#: Manifest fields that would let a bundle speak about its own trust or this
#: node's import state. A manifest carrying one is refused rather than having
#: it ignored: something that tried is worth reporting. The union of this
#: reader's list and the producer verifier's `_FORBIDDEN_MANIFEST_FIELDS`
#: (trust-anchor and rollback-state fields; Azazel-Knowledge#110, K11), so a
#: bundle one verifier refuses for this the other refuses too.
TRUST_SHADOWING_FIELDS = (
    "threshold",
    "keys",
    "revoked",
    "key_roles",
    "required_signer_role",
    "minimum_security_epoch",
    "accepted_export_policy_digests",
    "last_imported_version",
    "anchors",
    "trust",
    "last_import_at",
    "last_bundle_sha256",
    "needs_full_rebaseline",
)

#: The producer's local-tier tables (`LOCAL_TIER_TABLES` in its verifier): a
#: node's own records, which no bundle may carry. Nexus has no local tier and
#: serves only the tables it reads, so a bundle naming one cannot write here;
#: it is refused anyway because only a mis-built or forged bundle names one,
#: and the producer refuses it with this code.
LOCAL_TIER_TABLES = frozenset(
    {
        "reaction",
        "reaction_trust_event",
        "advisory_log",
        "observation",
        "observation_stats",
        "reputation",
        "edge_reported_ioc",
        "pattern",
        "pattern_index",
        "rule_draft",
        "bundle_state",
        "api_client",
        "feed_quarantine",
        "local_meta",
    }
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
    return parse_anchors(raw)


def parse_anchors(raw: bytes) -> TrustAnchors:
    """The bytes of an `anchors.toml`, read by exactly the rules of `read_anchors`."""

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
    fixture fails in the tar decoder, and only a wrapper turns that into
    `BUNDLE_ARCHIVE_UNREADABLE` -- and this function does that wrapping itself
    so that the gate is still named.
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
    # The producer's format puts manifest.json and manifest.sig first, in that
    # order, and its verifier refuses any other order with this code. This
    # reader holds every member before judging any, so the order is not what
    # keeps it safe; it is refused so that one format is accepted, not two.
    if list(members)[:2] != [MANIFEST_MEMBER, SIGNATURE_MEMBER]:
        raise BundleRefused(
            Gate.MANIFEST,
            "BUNDLE_MANIFEST_MISSING",
            "manifest.json and manifest.sig must be the first two members, in that order",
        )
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise BundleRefused(
            Gate.MANIFEST,
            "BUNDLE_MANIFEST_TOO_LARGE",
            f"manifest.json is {len(manifest_bytes)} bytes",
        )

    try:
        # Strict UTF-8 text with no byte-order mark. `json.loads(bytes)` would
        # also take UTF-16/32 and a UTF-8 BOM, none of which Knowledge emits.
        manifest = json.loads(manifest_bytes.decode("utf-8"))
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
    _check_local_tier(manifest)

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

    All of this runs before any signature is checked, so it is the part an
    unauthenticated sender reaches. The gzip stream is therefore inflated
    here, not by `tarfile`, and inflation stops as soon as it passes
    `MAX_RATIO` times the archive's size (or `MAX_TOTAL_BYTES`) plus room for
    the two metadata members and the tar framing: a megabyte of compressed
    zeros costs at most about a hundred megabytes,
    never the gigabyte its headers declare. The content rule after it is the
    producer's: declared member sizes, metadata members excluded, against
    `MAX_RATIO` times the archive's size.
    """

    content_cap = min(MAX_TOTAL_BYTES, MAX_RATIO * len(raw))
    found: dict[str, bytes] = {}
    total = content = 0
    try:
        # The two metadata members are bounded by their own ceiling, not by
        # the ratio, as in the producer: an oversized manifest is refused as
        # BUNDLE_MANIFEST_TOO_LARGE, not as a bomb.
        tar_bytes = _inflate(raw, content_cap + 2 * MAX_MANIFEST_BYTES + TAR_OVERHEAD_BYTES)
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
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
                if info.name not in (MANIFEST_MEMBER, SIGNATURE_MEMBER):
                    content += info.size
                if total > MAX_TOTAL_BYTES or content > MAX_RATIO * len(raw):
                    raise BundleRefused(
                        Gate.ARCHIVE,
                        "BUNDLE_DECOMPRESSION_BOMB",
                        f"the members declare {total} bytes from a {len(raw)}-byte "
                        f"archive; the ceilings are {MAX_TOTAL_BYTES} bytes and "
                        f"{MAX_RATIO}:1",
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
            "decoder raises its own error types, and a reader that caught "
            "only a known error type would let this through as an unhandled "
            "error",
        ) from exc
    return found


def _inflate(raw: bytes, limit: int) -> bytes:
    """The gzip stream's bytes, or a refusal once they would exceed `limit`.

    Concatenated gzip members and trailing zero padding are read as
    `gzip.GzipFile` reads them; anything else after the stream is refused as
    unreadable rather than ignored.
    """

    out = bytearray()
    data = raw
    while True:
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        pending = data
        # A step at a time, so a refusal costs `limit` and not one more step.
        while pending and not inflater.eof:
            out += inflater.decompress(pending, INFLATE_STEP_BYTES)
            pending = inflater.unconsumed_tail
            if len(out) > limit:
                raise BundleRefused(
                    Gate.ARCHIVE,
                    "BUNDLE_DECOMPRESSION_BOMB",
                    f"the archive inflates past {limit} bytes from {len(raw)}; the "
                    f"ceiling is {MAX_RATIO}:1 plus tar framing",
                )
        if not inflater.eof:
            raise EOFError("the gzip stream ended before its end marker")
        data = inflater.unused_data
        if not data.strip(b"\0"):
            return bytes(out)


def _table_of_member(name: object) -> Optional[str]:
    """The table a `tables/<t>.jsonl` or `deltas/<t>.jsonl` member names, as the producer reads it."""

    if not isinstance(name, str):
        return None
    for prefix in ("tables/", "deltas/"):
        if name.startswith(prefix) and name.endswith(".jsonl"):
            stem = name[len(prefix) : -len(".jsonl")]
            if stem and "/" not in stem:
                return stem
    return None


def _check_local_tier(manifest: Mapping) -> None:
    tables = manifest.get("tables", [])
    named = {t for t in tables if isinstance(t, str)} if isinstance(tables, list) else set()
    files = manifest.get("files")
    if isinstance(files, dict):
        named |= {t for t in map(_table_of_member, files) if t}
    touched = sorted(LOCAL_TIER_TABLES & named)
    if touched:
        raise BundleRefused(
            Gate.MANIFEST,
            "BUNDLE_TOUCHES_LOCAL_TIER",
            f"the bundle names local-tier table(s) {touched}; a node's own records "
            "are never shipped in a bundle",
        )


def _check_member_name(name: str) -> None:
    # Per component first, as the producer does, so a long component is
    # refused under the producer's code whatever the length of the whole name.
    for component in name.split("/"):
        size = len(component.encode("utf-8", "surrogateescape"))
        if size > MAX_MEMBER_COMPONENT_BYTES:
            raise BundleRefused(
                Gate.ARCHIVE,
                "BUNDLE_MEMBER_COMPONENT_TOO_LONG",
                f"{name[:60]!r}... has a {size}-byte path component; the cap is "
                f"{MAX_MEMBER_COMPONENT_BYTES}",
            )
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
    # Components, as the producer counts them: `a/b` is two deep. Counting
    # separators admitted one level more than Knowledge's verifier does.
    if name.count("/") + 1 > MAX_MEMBER_DEPTH:
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


def meetable_keys(anchors: TrustAnchors, pinned) -> int:
    """How many keys of `anchors` a bundle signature can count, under `pinned`.

    The same rules the verifier applies: the key's material must be pinned
    (`CommissionedTrust` intersects the anchor with the pin), its id not in
    `revoked`, and -- when the anchor names `required_signer_role` -- it must
    hold that role. An anchor whose `threshold` exceeds this can verify no
    bundle at all (ADR-0008, R390-01).
    """

    pinned = {bytes(key) for key in pinned}
    return sum(
        1 for key_id, material in anchors.keys.items()
        if material in pinned and key_id not in anchors.revoked
        and (anchors.required_signer_role is None
             or anchors.key_roles.get(key_id) == anchors.required_signer_role)
    )


def _check_signer_role(signers: set[str], anchors: TrustAnchors) -> None:
    """Which key signed, separately from whether the signature is valid.

    The threshold applies to the role holders, as in the producer's verifier:
    with `threshold = 2`, two verified signatures of which only one holds the
    required role are refused here. Counting any one holder would let a key
    provisioned for another purpose make up the threshold
    (`tools/knowledge_lite_differential.py`, `threshold2_one_holds_role`).
    """

    required = anchors.required_signer_role
    if required is None:
        return
    holders = {key_id for key_id in signers if anchors.key_roles.get(key_id) == required}
    if len(holders) < anchors.threshold:
        raise BundleRefused(
            Gate.SIGNER_ROLE,
            "BUNDLE_SIGNER_ROLE_NOT_PERMITTED",
            f"this node requires {anchors.threshold} signature(s) from role "
            f"{required!r} and the verified signer(s) {sorted(signers)} hold "
            f"{sorted({str(anchors.key_roles.get(k)) for k in signers})}",
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
    # The producer's rules (Azazel-Knowledge#110, K9): an integer >= 1, never
    # a bool or a string, and `base_version` null or such an integer. Lite is
    # full-only and never applies `base_version`, but a manifest the producer
    # refuses as malformed is not one this reader accepts.
    declared = manifest.get("bundle_version")
    if not isinstance(declared, int) or isinstance(declared, bool) or declared < 1:
        raise BundleRefused(
            Gate.ROLLBACK,
            "BUNDLE_VERSION_INVALID",
            f"bundle_version must be an integer >= 1, got {declared!r}",
        )
    base = manifest.get("base_version")
    if base is not None and (not isinstance(base, int) or isinstance(base, bool) or base < 1):
        raise BundleRefused(
            Gate.ROLLBACK,
            "BUNDLE_BASE_VERSION_INVALID",
            f"base_version must be null or an integer >= 1, got {base!r}",
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


class Integrity(str, Enum):
    """What happened to the artifact itself, before any claim was read."""

    #: Verified at every gate. Says nothing about what it can serve.
    ADMITTED = "admitted"
    #: Present and refused -- integrity, trust or policy. Isolated, not used.
    QUARANTINED = "quarantined"
    #: There is no artifact.
    UNAVAILABLE = "unavailable"


class TimeBound(str, Enum):
    """What the **time-bound** half of a bundle can do right now."""

    #: At least one dated claim has not expired at `query_as_of`.
    CURRENT = "current"
    #: Dated claims are present and every one of them has expired. They are
    #: history: readable by an operator asking about the past, never applied
    #: automatically.
    STALE = "stale"
    #: The bundle carries no dated claim at all.
    ABSENT = "absent"


class StaticReference(str, Enum):
    """What the **static reference** half can do. It does not expire."""

    AVAILABLE = "available"
    ABSENT = "absent"


@dataclass(frozen=True)
class Claims:
    """What an accepted bundle offers, on two axes that are not one axis.

    **Static reference material is usable Knowledge.** ATT&CK techniques do
    not expire on a clock, and a bundle whose dated indicators have all
    expired still carries base knowledge this node can serve. An earlier
    draft of this module collapsed the two and reported such a bundle as
    serving nothing -- which mislabels working reference material as
    unavailable and sends an operator to replace an artifact that is doing
    its job.

    The two are reported separately so that the operator's next action stays
    distinguishable: *refresh the indicator feed* and *there is no knowledge
    here at all* are different problems.
    """

    #: Counts, not rows. A summary that held every claim would be a summary
    #: whose memory is decided by the artifact -- and a status read happens
    #: far more often than an import does.
    served_count: int
    withheld_count: int
    timeless_count: int
    #: A bounded sample, for evidence rather than for serving. Serving goes
    #: through `iter_served`, which reads one row at a time.
    sample_served: tuple[Mapping, ...] = ()
    #: The earliest expiry among the served dated claims, as an RFC3339 UTC
    #: instant truncated to seconds (never later than the row's own), or
    #: None when nothing dated is served. A display fact, not a gate.
    next_expiry: Optional[str] = None

    @property
    def time_bound(self) -> TimeBound:
        if self.served_count:
            return TimeBound.CURRENT
        if self.withheld_count:
            return TimeBound.STALE
        return TimeBound.ABSENT

    @property
    def static_reference(self) -> StaticReference:
        return (
            StaticReference.AVAILABLE if self.timeless_count else StaticReference.ABSENT
        )

    @property
    def serves_anything(self) -> bool:
        """Whether this node can serve a claim of any kind right now.

        Current dated claims **or** static reference. Expired dated claims
        are not in it: they are history, and history is not applied
        automatically.
        """

        return bool(self.served_count) or bool(self.timeless_count)


#: The longest single JSONL line a member may carry. A row is a claim, and a
#: claim is small; a line longer than this is not one, and parsing it would
#: be work an artifact chose for us.
MAX_LINE_BYTES = 64 * 1024

#: The most rows kept for evidence. Counting is unbounded; keeping is not.
SAMPLE_LIMIT = 8


def read_claims(accepted: "BundleAccepted", *, query_as_of: str) -> Claims:
    """Count an accepted bundle's rows by expiry against `query_as_of`.

    **Counts and a bounded sample, never every row.** A status read happens
    far more often than an import does, and a summary that held every claim
    would be a summary whose memory the artifact decides. Serving goes
    through `iter_served`, one row at a time.

    A row with no `agg_next_expiry` is *timeless*, not fresh: Knowledge's own
    provenance says static reference material "does not expire on a clock",
    and it is reported on its own axis.

    A row whose expiry cannot be read is **withheld**, not served. An
    unparseable expiry is not a licence to serve.
    """

    served = withheld = timeless = 0
    sample: list[Mapping] = []
    nearest = None
    for _, row, verdict in _classify(accepted, query_as_of):
        if verdict == "timeless":
            timeless += 1
        elif verdict == "served":
            served += 1
            if len(sample) < SAMPLE_LIMIT:
                sample.append(row)
            moment = _instant(row[EXPIRY_FIELD], EXPIRY_FIELD)
            nearest = moment if nearest is None else min(nearest, moment)
        else:
            withheld += 1
    return Claims(
        served_count=served,
        withheld_count=withheld,
        timeless_count=timeless,
        sample_served=tuple(sample),
        next_expiry=None if nearest is None else nearest.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def iter_served(accepted: "BundleAccepted", *, query_as_of: str):
    """Yield the claims that may be served, one at a time.

    The serving path. It is a generator so that a caller reads what it needs
    and no more -- nothing here builds a list of every claim in the bundle.
    Static reference rows are served too: they are usable Knowledge and they
    do not expire.
    """

    for _, row in iter_served_with_member(accepted, query_as_of=query_as_of):
        yield row


def iter_served_with_member(accepted: "BundleAccepted", *, query_as_of: str):
    """`iter_served`, with each row's verified member path (for its dataset)."""

    for path, row, verdict in _classify(accepted, query_as_of):
        if verdict in ("served", "timeless"):
            yield path, row


def _classify(accepted: "BundleAccepted", query_as_of: str):
    now = _instant(query_as_of, "query_as_of")
    for path in sorted(accepted.members):
        for row in _rows(accepted.members[path], path):
            expiry = row.get(EXPIRY_FIELD)
            if expiry is None:
                yield path, row, "timeless"
                continue
            try:
                moment = _instant(expiry, f"{path} {EXPIRY_FIELD}")
            except BundleRefused:
                yield path, row, "withheld"
                continue
            yield path, row, ("served" if now < moment else "withheld")


def _rows(raw: bytes, path: str):
    """Yield one row at a time, with every line bounded before it is parsed."""

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BundleRefused(
            Gate.CONTENT, "BUNDLE_MEMBER_NOT_TEXT", f"{path!r} is not UTF-8: {exc}"
        ) from exc
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            raise BundleRefused(
                Gate.CONTENT,
                "BUNDLE_LINE_TOO_LONG",
                f"{path!r} line {number} is longer than {MAX_LINE_BYTES} bytes; "
                "a claim is small, and parsing this would be work the artifact "
                "chose for us",
            )
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
        yield row


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


# -- the overall word, derived from three axes that stay visible -----------


@dataclass(frozen=True)
class KnowledgeReading:
    """The four statements an operator plane shows, not one word for all four.

    | axis | values |
    | --- | --- |
    | `integrity` | `admitted` / `quarantined` / `unavailable` |
    | `time_bound` | `current` / `stale` / `absent` |
    | `static_reference` | `available` / `absent` |
    | `overall` | `available` / `stale` / `unavailable` / `quarantined` |

    The overall word exists because a status line needs one. It does **not**
    replace the three: a bundle whose indicators have all expired while its
    reference material is intact reads *available (static reference)* on the
    overall line and *stale* on the time-bound line, and those two facts have
    different next actions -- refresh the indicator feed, versus nothing.

    Collapsing them was the mistake this type exists to prevent. Reporting
    such a bundle as serving nothing sends an operator to replace an artifact
    that is working.
    """

    integrity: Integrity
    time_bound: TimeBound
    static_reference: StaticReference
    reason: str
    #: Why the overall word is what it is, in the operator's terms.
    qualifier: str = ""

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise BundleRefused(
                Gate.MANIFEST, "READING_UNEXPLAINED", "a reading with no reason"
            )
        if self.integrity is not Integrity.ADMITTED and (
            self.time_bound is not TimeBound.ABSENT
            or self.static_reference is not StaticReference.ABSENT
        ):
            raise BundleRefused(
                Gate.MANIFEST,
                "READING_INCONSISTENT",
                f"integrity is {self.integrity.value} and claims are still "
                "reported; nothing is read out of an artifact that was not "
                "admitted",
            )

    @property
    def overall(self) -> str:
        """One word, and the same four `LiteState` carries.

        * `quarantined` -- present and refused. Trust, not freshness.
        * `unavailable` -- no artifact, or an admitted one serving nothing.
        * `available` -- current dated claims **or** static reference.
        * `stale` -- admitted, and the only thing left is expired dated
          claims. Readable as history; never applied automatically.
        """

        if self.integrity is Integrity.QUARANTINED:
            return "quarantined"
        if self.integrity is Integrity.UNAVAILABLE:
            return "unavailable"
        if (
            self.time_bound is TimeBound.CURRENT
            or self.static_reference is StaticReference.AVAILABLE
        ):
            return "available"
        if self.time_bound is TimeBound.STALE:
            return "stale"
        return "unavailable"

    @property
    def serves_capability(self) -> bool:
        """Whether `knowledge_lite` is a capability this node currently has."""

        return self.overall == "available"

    def as_event(self) -> dict:
        return {
            "event_type": "lite.knowledge.reading",
            "integrity": self.integrity.value,
            "time_bound": self.time_bound.value,
            "static_reference": self.static_reference.value,
            "overall": self.overall,
            "qualifier": self.qualifier,
            "reason": self.reason,
        }


def reading_for(
    claims: "Claims", *, reason: str = "", query_as_of: str = ""
) -> KnowledgeReading:
    """The reading for an **admitted** bundle's claims."""

    time_bound = claims.time_bound
    static = claims.static_reference
    qualifier = ""
    if time_bound is not TimeBound.CURRENT and static is StaticReference.AVAILABLE:
        qualifier = "static reference"
    elif time_bound is TimeBound.CURRENT and static is StaticReference.AVAILABLE:
        qualifier = "current indicators and static reference"
    elif time_bound is TimeBound.CURRENT:
        qualifier = "current indicators"
    parts = [
        f"{claims.served_count} current claim(s)",
        f"{claims.withheld_count} expired and withheld",
        f"{claims.timeless_count} static reference row(s)",
    ]
    detail = reason or (
        f"admitted; at {query_as_of or 'the given instant'}: " + ", ".join(parts)
    )
    return KnowledgeReading(
        integrity=Integrity.ADMITTED,
        time_bound=time_bound,
        static_reference=static,
        reason=detail,
        qualifier=qualifier,
    )


def refused_reading(refusal: BundleRefused) -> KnowledgeReading:
    """The reading for a bundle that was present and refused."""

    return KnowledgeReading(
        integrity=Integrity.QUARANTINED,
        time_bound=TimeBound.ABSENT,
        static_reference=StaticReference.ABSENT,
        reason=(
            f"refused at the {refusal.gate.value} gate ({refusal.code}): "
            f"{refusal.detail}. Isolated rather than used; the deterministic "
            "path is untouched"
        ),
    )


def absent_reading(where: str) -> KnowledgeReading:
    """The reading for a node with no artifact at all.

    Not a fault. Absence of knowledge never blocks the deterministic path,
    and a node that has never been given a bundle is a node in its designed
    state.
    """

    return KnowledgeReading(
        integrity=Integrity.UNAVAILABLE,
        time_bound=TimeBound.ABSENT,
        static_reference=StaticReference.ABSENT,
        reason=(
            f"no Knowledge Lite bundle is present at {where}; absence of "
            "knowledge is not a fault and the deterministic path continues"
        ),
    )
