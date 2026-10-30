"""The first Knowledge Lite trust registration, as one checked request (S-14).

Before this module a fresh node reached a usable Lite trust root only by hand:
two `anchors.toml` writes, a root-run `TrustStore.pin`, a `chown`, and a repin
to add the revocation authority (`docs/knowledge-lite-consumer.md` §11 before
2026-10-30). Each step could be skipped or done differently, and none of them
checked the commissioning binding or the anchor threshold.

An **enrollment request** binds, in one closed JSON document, everything the
trust root holds:

* the bundle-signing keys (`keys`, by key id) and their optional `key_roles`;
* `threshold`, an explicit integer with ``1 <= threshold <= usable keys``
  (the keys holding `required_signer_role` when one is named): a threshold of
  zero, a negative one, a bool or a string, or one no key set can meet, is
  refused here rather than discovered by a bundle that never verifies;
* the optional `required_signer_role`, `minimum_security_epoch` and
  `accepted_export_policy_digests` the anchor carries;
* the revocation authority (`revocation_policy`: revocation-signing keys,
  threshold, generation), whose keys may not also sign bundles;
* `commissioning_digest`, the node's commissioning this trust is bound to. The
  caller passes the digest of the commissioning evidence it has just verified;
  a request naming another one is refused (`binding_mismatch`).

A published fixture key (`lab_keys`) is refused in either role off a marked lab
host, like every other registration path.

**One commit point.** `enroll` writes `trust/anchors.toml`, then
`revocation-policy.json`, then `trust.json`. Nothing reads the root as trusted
until `trust.json` exists, so an enrollment interrupted before it leaves only
residue that no reader trusts; running the same request again replaces exactly
that residue and completes. Any other file in the root (a repinned generation,
a revocation list) refuses the request: an enrolled or partly migrated root is
never overwritten. Every file is written to a temporary name, synced and
renamed, with mode ``0640`` (directories ``2750``) so the Lite reader's group
can read it.

This module checks and writes. It neither audits nor confirms: the runtime's
maintenance transaction (`azazel_nexus_runtime.lite_trust_ops`) records the
request before calling it and the outcome after, as the commissioning account.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import lab_host
from .lab_keys import holds_public_fixture_key
from .lite_bundle import BundleRefused, TrustAnchors, parse_anchors, read_anchors
from .revocation_policy import (
    POLICY_FILENAME,
    REVOCATION_SIGNING,
    RevocationPolicy,
    RevocationPolicyRefused,
    prepare_policy_record,
)
from .signature import SignatureRefused, parse_public_key

__all__ = [
    "AnchorSpec",
    "ENROLLMENT_FILENAME",
    "ENROLLMENT_REFUSAL_CODES",
    "ENROLLMENT_SCHEMA",
    "MAX_ENROLLMENT_BYTES",
    "EnrollmentOutcome",
    "EnrollmentRefused",
    "EnrollmentRequest",
    "EnrollmentUncertain",
    "decode_anchor_spec",
    "decode_enrollment",
    "enroll",
    "render_anchors",
]

ENROLLMENT_SCHEMA = "azazel-nexus/lite-enrollment/v1"
#: The fixed leaf in the commissioning directory root installs a request into.
ENROLLMENT_FILENAME = "lite-enrollment.json"
MAX_ENROLLMENT_BYTES = 64 * 1024
#: More bundle or revocation keys than this is a configuration nobody reviews.
MAX_KEYS = 16
MAX_EXPORT_POLICIES = 16

#: Every reason an enrollment is refused, as a fixed word (auditd's enum).
ENROLLMENT_REFUSAL_CODES = (
    "already_enrolled",
    "audit_unavailable",
    "binding_mismatch",
    "busy",
    "evidence_unavailable",
    "public_fixture_key",
    "request_changed",
    "request_invalid",
    "request_unreadable",
    "role_conflict",
    "threshold_invalid",
    "trust_root_not_empty",
    "write_failed",
)

_REQUIRED = {"schema", "commissioning_digest", "keys", "threshold", "revocation_policy"}
_OPTIONAL = {"key_roles", "required_signer_role", "minimum_security_epoch",
             "accepted_export_policy_digests"}
_POLICY_FIELDS = {"keys", "key_roles", "threshold", "generation"}
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
_ROLE = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_HEX_KEY = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ANCHORS = ("trust", "anchors.toml")
_TRUST = "trust.json"
_FILE_MODE = 0o640
_DIRECTORY_MODE = 0o2750
#: What an interrupted enrollment can leave without `trust.json`: the two
#: files it writes before the commit, the `trust/` directory, and temporaries.
_RESIDUE = {"trust", POLICY_FILENAME}
_TEMPORARY = re.compile(r"\.(?:trust|enroll|revocations)-[A-Za-z0-9_]+\Z", re.ASCII)


class EnrollmentRefused(Exception):
    """Refused with one fixed code (`ENROLLMENT_REFUSAL_CODES`), never input text."""

    def __init__(self, code: str) -> None:
        if code not in ENROLLMENT_REFUSAL_CODES:
            code = "request_invalid"
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class AnchorSpec:
    """The anchor fields of a request, checked; `render()` is its anchors.toml."""

    keys: Mapping[str, bytes]
    key_roles: Mapping[str, str]
    threshold: int
    required_signer_role: Optional[str]
    minimum_security_epoch: Optional[int]
    accepted_export_policy_digests: Optional[tuple[str, ...]]
    sealed: bool = False

    @property
    def usable_keys(self) -> int:
        """The keys a bundle signature can count towards the threshold."""
        if self.required_signer_role is None:
            return len(self.keys)
        return sum(1 for key_id in self.keys
                   if self.key_roles.get(key_id) == self.required_signer_role)

    def render(self) -> bytes:
        return render_anchors(self)


@dataclass(frozen=True)
class EnrollmentRequest:
    """A decoded, checked request. Key material is public keys only."""

    commissioning_digest: str
    keys: Mapping[str, bytes]
    key_roles: Mapping[str, str]
    threshold: int
    required_signer_role: Optional[str]
    minimum_security_epoch: Optional[int]
    accepted_export_policy_digests: Optional[tuple[str, ...]]
    revocation: RevocationPolicy
    #: SHA-256 of the exact request bytes, which the operator confirmed.
    digest: str
    # Enrollment's closed schema does not accept a seal. The common renderer
    # also handles repin's AnchorSpec, which can deliberately carry one.
    sealed: bool = False

    @property
    def usable_keys(self) -> int:
        """The keys a bundle signature can count towards the threshold."""
        if self.required_signer_role is None:
            return len(self.keys)
        return sum(1 for key_id in self.keys
                   if self.key_roles.get(key_id) == self.required_signer_role)


@dataclass(frozen=True)
class EnrollmentOutcome:
    """Counts and fingerprints only: what the audit record and the CLI show."""

    trust_fingerprint: str
    revocation_policy_fingerprint: str
    bundle_keys: int
    threshold: int
    revocation_keys: int
    #: `synced`, or `unsynced` when `trust.json` is in place (read back) but
    #: its rename was not confirmed durable: the enrollment is in force now
    #: and might not survive a power loss (R390-02).
    durability: str = "synced"


class EnrollmentUncertain(Exception):
    """The commit step failed and `trust.json` could not be read back as this
    enrollment's: it is unknown which trust, if any, is in force. Never a
    "nothing written" refusal (R390-02)."""


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EnrollmentRefused("request_invalid")
        result[key] = value
    return result


def _integer(value) -> bool:
    return type(value) is int and 0 <= value < 2**63


def _key_table(value) -> dict[str, bytes]:
    if type(value) is not dict or not 0 < len(value) <= MAX_KEYS:
        raise EnrollmentRefused("request_invalid")
    table = {}
    for key_id, text in value.items():
        if not _KEY_ID.fullmatch(key_id) or type(text) is not str or not _HEX_KEY.fullmatch(text):
            raise EnrollmentRefused("request_invalid")
        try:
            table[key_id] = parse_public_key(text)
        except SignatureRefused:
            raise EnrollmentRefused("request_invalid") from None
    if len(set(table.values())) != len(table):
        # One key under two ids would count twice towards a threshold.
        raise EnrollmentRefused("request_invalid")
    return table


_ANCHOR_REQUIRED = {"keys", "threshold"}
_ANCHOR_OPTIONAL = _OPTIONAL | {"sealed"}


def decode_anchor_spec(document) -> "AnchorSpec":
    """The anchor half of a request -- keys, roles, threshold, epoch, export
    policies -- checked and rendered once; shared by enrollment and by a
    repin that replaces the anchor with the keys (`TrustStore.repin`).

    This is a closed anchor document. Enrollment extracts its anchor fields
    after checking its own outer schema; repin supplies its nested document.
    Unsupported policy fields must never be silently discarded.
    """

    if (type(document) is not dict or not _ANCHOR_REQUIRED <= set(document)
            or not set(document) <= _ANCHOR_REQUIRED | _ANCHOR_OPTIONAL):
        raise EnrollmentRefused("request_invalid")
    sealed = document.get("sealed", False)
    if type(sealed) is not bool:
        raise EnrollmentRefused("request_invalid")
    keys = _key_table(document["keys"])
    roles = document.get("key_roles", {})
    if (type(roles) is not dict or not set(roles) <= set(keys)
            or any(type(role) is not str or not _ROLE.fullmatch(role)
                   or role == REVOCATION_SIGNING for role in roles.values())):
        # A bundle anchor never holds the revocation role: that authority is
        # the revocation policy's alone.
        raise EnrollmentRefused("role_conflict" if type(roles) is dict
                                and REVOCATION_SIGNING in roles.values() else "request_invalid")
    role = document.get("required_signer_role")
    if role is not None and (type(role) is not str or not _ROLE.fullmatch(role)):
        raise EnrollmentRefused("request_invalid")
    epoch = document.get("minimum_security_epoch")
    if epoch is not None and not _integer(epoch):
        raise EnrollmentRefused("request_invalid")
    policies = document.get("accepted_export_policy_digests")
    if policies is not None:
        if (type(policies) is not list or not 0 < len(policies) <= MAX_EXPORT_POLICIES
                or any(type(item) is not str or not _DIGEST.fullmatch(item) for item in policies)
                or len(set(policies)) != len(policies)):
            raise EnrollmentRefused("request_invalid")
        policies = tuple(sorted(policies))
    threshold = document["threshold"]
    if type(threshold) is not int:
        raise EnrollmentRefused("threshold_invalid")
    if not lab_host.is_lab_host() and holds_public_fixture_key(keys.values()):
        raise EnrollmentRefused("public_fixture_key")
    spec = AnchorSpec(keys=keys, key_roles=dict(roles), threshold=threshold,
                      required_signer_role=role, minimum_security_epoch=epoch,
                      accepted_export_policy_digests=policies, sealed=sealed)
    # The same rule Knowledge applies (`verify._load_anchors`, S-15): an
    # explicit positive threshold no larger than the keys that can meet it.
    if not 1 <= threshold <= spec.usable_keys:
        raise EnrollmentRefused("threshold_invalid")
    # The rendered anchor must read back as exactly this specification.
    anchors = _read_rendered(spec.render())
    if (anchors.threshold != threshold or dict(anchors.keys) != keys
            or dict(anchors.key_roles) != dict(roles)
            or anchors.required_signer_role != role
            or anchors.minimum_security_epoch != epoch
            or anchors.sealed != sealed
            or (anchors.accepted_export_policy_digests
                != (frozenset(policies) if policies is not None else None))):
        raise EnrollmentRefused("request_invalid")
    return spec


def decode_enrollment(raw: bytes) -> EnrollmentRequest:
    """Decode and check one request, or raise `EnrollmentRefused` with a code."""

    if type(raw) is not bytes or not 0 < len(raw) <= MAX_ENROLLMENT_BYTES:
        raise EnrollmentRefused("request_invalid")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except EnrollmentRefused:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise EnrollmentRefused("request_invalid") from None
    if (type(document) is not dict or not _REQUIRED <= set(document)
            or not set(document) <= _REQUIRED | _OPTIONAL
            or document["schema"] != ENROLLMENT_SCHEMA):
        raise EnrollmentRefused("request_invalid")
    digest_text = document["commissioning_digest"]
    if type(digest_text) is not str or not _DIGEST.fullmatch(digest_text):
        raise EnrollmentRefused("request_invalid")

    policy_document = document["revocation_policy"]
    if type(policy_document) is not dict or set(policy_document) != _POLICY_FIELDS:
        raise EnrollmentRefused("request_invalid")
    revocation_keys = _key_table(policy_document["keys"])
    revocation_roles = policy_document["key_roles"]
    if (type(revocation_roles) is not dict or set(revocation_roles) != set(revocation_keys)
            or any(value != REVOCATION_SIGNING for value in revocation_roles.values())):
        # Every key of the revocation authority signs revocations, and only that.
        raise EnrollmentRefused("role_conflict")
    if (type(policy_document["threshold"]) is not int
            or not 1 <= policy_document["threshold"] <= len(revocation_keys)):
        raise EnrollmentRefused("threshold_invalid")
    if type(policy_document["generation"]) is not int or policy_document["generation"] < 1:
        raise EnrollmentRefused("request_invalid")
    if not lab_host.is_lab_host() and holds_public_fixture_key(revocation_keys.values()):
        raise EnrollmentRefused("public_fixture_key")
    spec = decode_anchor_spec({name: value for name, value in document.items()
                               if name in _ANCHOR_REQUIRED | _OPTIONAL})
    if (set(revocation_keys.values()) & set(spec.keys.values())
            or set(revocation_keys) & set(spec.keys)):
        raise EnrollmentRefused("role_conflict")
    try:
        revocation = RevocationPolicy(
            keys=revocation_keys, key_roles=dict(revocation_roles),
            threshold=policy_document["threshold"], generation=policy_document["generation"])
    except RevocationPolicyRefused:
        raise EnrollmentRefused("request_invalid") from None
    return EnrollmentRequest(
        commissioning_digest=digest_text, keys=spec.keys, key_roles=spec.key_roles,
        threshold=spec.threshold, required_signer_role=spec.required_signer_role,
        minimum_security_epoch=spec.minimum_security_epoch,
        accepted_export_policy_digests=spec.accepted_export_policy_digests,
        revocation=revocation, digest="sha256:" + hashlib.sha256(raw).hexdigest(),
    )


def render_anchors(request) -> bytes:
    """`trust/anchors.toml` for `lite_bundle.read_anchors`, in one fixed form.

    Key ids and roles are restricted to characters that need no TOML escape,
    so the text is written, not built by a serializer this package lacks.
    """

    lines = [f"threshold = {request.threshold}"]
    if request.sealed:
        lines.append("sealed = true")
    if request.required_signer_role is not None:
        lines.append(f'required_signer_role = "{request.required_signer_role}"')
    if request.minimum_security_epoch is not None:
        lines.append(f"minimum_security_epoch = {request.minimum_security_epoch}")
    if request.accepted_export_policy_digests is not None:
        items = ", ".join(f'"{item}"' for item in request.accepted_export_policy_digests)
        lines.append(f"accepted_export_policy_digests = [{items}]")
    lines.append("")
    lines.append("[keys]")
    lines.extend(f'"{key_id}" = "{request.keys[key_id].hex()}"' for key_id in sorted(request.keys))
    if request.key_roles:
        lines.append("")
        lines.append("[key_roles]")
        lines.extend(f'"{key_id}" = "{request.key_roles[key_id]}"'
                     for key_id in sorted(request.key_roles))
    return ("\n".join(lines) + "\n").encode("ascii")


def _read_rendered(raw: bytes) -> TrustAnchors:
    try:
        return parse_anchors(raw)
    except BundleRefused:
        raise EnrollmentRefused("threshold_invalid") from None


def _trust_record(request: EnrollmentRequest, *, enrolled_at: str, actor: str) -> bytes:
    """The same record `TrustStore.pin` writes, so every reader reads it unchanged."""
    record = {
        "commissioning_digest": request.commissioning_digest,
        "pinned_at": enrolled_at,
        "actor": actor,
        "keys": sorted(key.hex() for key in request.keys.values()),
    }
    return (json.dumps(record, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _check_root(root: Path) -> None:
    """Refuse an enrolled root, or one holding anything but enrollment residue."""

    info = os.stat(root, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
        raise EnrollmentRefused("write_failed")
    with os.scandir(root) as entries:
        names = {entry.name for entry in entries}
    if _TRUST in names or "trust-current" in names:
        raise EnrollmentRefused("already_enrolled")
    unknown = {name for name in names if name not in _RESIDUE and not _TEMPORARY.fullmatch(name)}
    if unknown:
        raise EnrollmentRefused("trust_root_not_empty")
    anchors_dir = root / _ANCHORS[0]
    if anchors_dir.exists():
        if anchors_dir.is_symlink() or not anchors_dir.is_dir():
            raise EnrollmentRefused("trust_root_not_empty")
        with os.scandir(anchors_dir) as entries:
            inside = {entry.name for entry in entries}
        if {name for name in inside
                if name != _ANCHORS[1] and not _TEMPORARY.fullmatch(name)}:
            raise EnrollmentRefused("trust_root_not_empty")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write(path: Path, data: bytes) -> None:
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=".enroll-")
    try:
        with os.fdopen(handle, "wb") as stream:
            os.fchmod(stream.fileno(), _FILE_MODE)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _clear_residue(root: Path) -> None:
    """Remove what an interrupted enrollment left; `_check_root` named it all."""
    for name in os.listdir(root):
        if _TEMPORARY.fullmatch(name):
            (root / name).unlink()
    anchors_dir = root / _ANCHORS[0]
    if anchors_dir.is_dir():
        for name in os.listdir(anchors_dir):
            if _TEMPORARY.fullmatch(name):
                (anchors_dir / name).unlink()
    (root / POLICY_FILENAME).unlink(missing_ok=True)


def enroll(root: Path, request: EnrollmentRequest, *, commissioning_digest: Optional[str],
           enrolled_at: str, actor: str) -> EnrollmentOutcome:
    """Write the trust root for `request`, committing with `trust.json` last.

    `commissioning_digest` is the digest of the commissioning evidence the
    caller has just verified, or None when it could not verify any: then
    nothing is written (`evidence_unavailable`).
    """

    from .lite_trust import _fingerprint, _policy_fingerprint

    if commissioning_digest is None:
        raise EnrollmentRefused("evidence_unavailable")
    if (type(commissioning_digest) is not str
            or commissioning_digest != request.commissioning_digest):
        raise EnrollmentRefused("binding_mismatch")
    if type(enrolled_at) is not str or not enrolled_at or type(actor) is not str or not actor:
        raise EnrollmentRefused("request_invalid")
    _check_root(root)
    try:
        _clear_residue(root)
        anchors_dir = root / _ANCHORS[0]
        if not anchors_dir.is_dir():
            os.mkdir(anchors_dir, _DIRECTORY_MODE)
        os.chmod(anchors_dir, _DIRECTORY_MODE, follow_symlinks=False)
        _fsync_directory(root)
        _write(anchors_dir / _ANCHORS[1], render_anchors(request))
        anchors = read_anchors(anchors_dir / _ANCHORS[1])
        record = prepare_policy_record(
            root, request.revocation, commissioning_digest=request.commissioning_digest,
            anchors_key_roles=dict(anchors.key_roles), anchors_keys=dict(anchors.keys))
        _write(root / POLICY_FILENAME, json.dumps(record, sort_keys=True).encode("utf-8"))
        trust_bytes = _trust_record(request, enrolled_at=enrolled_at, actor=actor)
    except EnrollmentRefused:
        raise
    except (OSError, ValueError, TypeError, KeyError, BundleRefused, RevocationPolicyRefused):
        raise EnrollmentRefused("write_failed") from None
    # The commit point: until this rename no reader treats the root as trusted.
    # A failure here is read back, never assumed to have changed nothing.
    durability = "synced"
    try:
        _write(root / _TRUST, trust_bytes)
    except OSError:
        try:
            present = (root / _TRUST).read_bytes()
        except FileNotFoundError:
            raise EnrollmentRefused("write_failed") from None
        except OSError:
            raise EnrollmentUncertain("trust.json cannot be read back") from None
        if present != trust_bytes:
            raise EnrollmentUncertain("trust.json is not this enrollment's") from None
        durability = "unsynced"
    keys = tuple(sorted(key.hex() for key in request.keys.values()))
    return EnrollmentOutcome(
        trust_fingerprint=_fingerprint(keys),
        revocation_policy_fingerprint=_policy_fingerprint(record),
        bundle_keys=len(keys), threshold=request.threshold,
        revocation_keys=len(request.revocation.revocation_keys),
        durability=durability,
    )
