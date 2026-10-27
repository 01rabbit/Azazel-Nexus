"""Who issued the local Edge Core package, kept apart from whether it is intact.

`edge_package` re-derives the artifact digest and compares it with the
manifest. That is **integrity against accidental change**, and it is reported
here as `digest_verified`. It says nothing about who wrote the manifest: an
adversary who can rewrite the package rewrites the manifest's digest with it.

This module adds the second, separate fact, `issuer_authenticated`: a valid
detached Ed25519 signature over the canonical manifest, under the one issuer
public key the node's administrator configured. Neither fact implies the
other, and both are always reported:

| `digest_verified` | `issuer_authenticated` | meaning |
| --- | --- | --- |
| true | false | intact as far as accidental change goes; issuer unknown |
| false | true | the issuer signed this manifest, and the artifact is not the one it describes |
| true | true | the issuer's manifest, and the artifact it describes |

## The trust anchor, and what "not configured" means

`/etc/azazel/edge-issuer/issuer.json`, root-owned, not group or other
writable, read through no-follow descriptors from `/` like the operator trust
store. It holds a public key and the issuer's name -- nothing secret, so the
directory is world-readable and `azazel-nexus status` can read it as the
operator. **Nexus holds no signing key**: this module only verifies
(`signature.verify_detached`), and the key's creation and custody belong to the
issuer, outside this product.

## Exactly when anything changes

The anchor file is what makes this configured. Precisely:

* **No anchor file and no floor** (every node today): `not_configured`.
  `issuer_authenticated` is false with a fixed reason and the package checks
  accept and refuse **exactly** what they did before this module existed.
  A `revocations.signed` with no anchor carries no authority -- nothing can
  verify it -- and an `/etc/azazel/edge-issuer` (or a parent) that is group or
  other writable or not root-owned, with no anchor in it, changes nothing
  either; both are only reported, as the fixed notes `revocations_present_without_anchor` and
  `config_directory_unprotected`. Requiring issuer authentication for
  admission is an owner decision that has not been made, so no knob for it
  exists here.
* **Something other than a directory or a regular file where one belongs**
  -- the directory or a parent a symlink or a file, the anchor or floor a
  symlink, directory or FIFO -- is refused, for the anchor and the floor
  alike. Only a component that genuinely does not exist (`ENOENT`) is absent.
* **Anchor file present** and unsafe (a path component or the file group or
  other writable, not root-owned, linked) or malformed: refused, and the
  package with it, because the revocation state cannot be established.
* **The directory exists and this user cannot list it** (`EACCES`): whether
  an anchor is there is unknown, so the issuer is `trust_unreadable` and the
  digest check is `not-checked` for this user. Root, which the activation
  pass runs as, reads the real state; the documented mode is `0755`.
* **Floor present**, with or without an anchor: enforced, fail-closed.
  Removing the anchor does not remove the floor.

## Revocation and the rollback floor

Both only ever **narrow**: a revoked version or digest, a version below the
floor, or the floor's version with a different digest (an old signed manifest
replayed) fails a check that would otherwise pass. Nothing here turns a
refusal into a pass.

* The revocation list (`/etc/azazel/edge-issuer/revocations.signed`) is the
  Knowledge Lite transport -- 64 signature bytes, then the canonical JSON
  payload -- signed by the configured issuer key over its own domain. It names
  revoked versions and digests and carries a sequence number.
* The floor (`/var/lib/azazel/state/edge-issuer/floor.json`) is the highest
  version, with its digest, that a **successful, recorded activation of an
  issuer-authenticated package** has enabled, and the revocation sequence and
  payload digest in force then. Only the runtime's `edge_issuer_floor` writes
  it, raise-only; this module reads it. A revocation list older than the
  floor's sequence, missing once a sequence is held, or at the same sequence
  with other content, is a replayed list and refused. Before the first
  authenticated activation there is no floor, so replaying an older,
  validly signed list cannot be detected until then.

A floor or anchored configuration that exists and cannot be read as one is
refused, and the package with it: an unreadable revocation state is not
"nothing revoked". A file this user may not read (`EACCES`) is reported as not
established rather than as corrupt, and grants nothing either.

This is local trust. Root can replace every file here; the protection is
against a package directory rewritten by anyone else and against replaying an
older package or manifest, not against the node's own administrator.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .signature import (
    SIGNATURE_BYTES,
    SignatureRefused,
    parse_public_key,
    verify_detached,
)

__all__ = [
    "ANCHOR_FILENAME",
    "ANCHOR_SCHEMA",
    "CONFIG_DIR",
    "FLOOR_FILENAME",
    "FLOOR_SCHEMA",
    "MANIFEST_DOMAIN",
    "REVOCATION_DOMAIN",
    "REVOCATION_FILENAME",
    "REVOCATION_SCHEMA",
    "SIGNATURE_SUFFIX",
    "STATE_DIR",
    "EdgeFloor",
    "EdgeRevocations",
    "IssuerAnchor",
    "IssuerRefused",
    "IssuerTrust",
    "IssuerVerification",
    "ISSUER_REASONS",
    "NOT_CONFIGURED",
    "NOTE_CONFIG_UNPROTECTED",
    "NOTE_REVOCATIONS_WITHOUT_ANCHOR",
    "NOTE_STATE_UNPROTECTED",
    "canonical_json",
    "decode_floor",
    "encode_floor",
    "load_issuer_trust",
    "manifest_signature_target",
    "parse_version",
    "read_detached_signature",
    "verify_issuer",
]

#: Where the administrator places the issuer's public key and revocation list.
CONFIG_DIR = Path("/etc/azazel/edge-issuer")
_CONFIG_COMPONENTS = ("etc", "azazel", "edge-issuer")
ANCHOR_FILENAME = "issuer.json"
REVOCATION_FILENAME = "revocations.signed"
ANCHOR_SCHEMA = "azazel-nexus/edge-issuer-anchor/v1"
REVOCATION_SCHEMA = "azazel-nexus/edge-package-revocation/v1"

#: Where the runtime keeps the rollback floor. `/var/lib/azazel/state` is
#: traversal-only (`0711`), and the leaf and file are world-readable so that
#: `status` can show the floor; only root writes them.
STATE_DIR = Path("/var/lib/azazel/state/edge-issuer")
STATE_COMPONENTS = ("var", "lib", "azazel", "state", "edge-issuer")
FLOOR_FILENAME = "floor.json"
FLOOR_SCHEMA = "azazel-nexus/edge-issuer-floor/v1"

#: The detached signature sits beside the manifest as `<manifest>.sig`: exactly
#: 64 raw bytes, over `MANIFEST_DOMAIN + canonical_json(manifest)`.
SIGNATURE_SUFFIX = ".sig"
MANIFEST_DOMAIN = b"azazel-nexus/edge-package-manifest/v1\0"
REVOCATION_DOMAIN = b"azazel-nexus/edge-package-revocation/v1\0"

_MAX_BYTES = 64 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\Z")
_ISSUER = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC

#: The fixed reasons, by status label. A label is what the activation ledger
#: records; the text is what `status` prints. Neither carries a digest.
ISSUER_REASONS = {
    "not_configured": (
        "no Edge issuer trust anchor is configured on this node "
        f"({CONFIG_DIR / ANCHOR_FILENAME}), so the issuer is not authenticated. "
        "Package acceptance is unchanged by this"
    ),
    "trust_refused": (
        "an Edge issuer anchor file exists and was refused (unsafe ownership "
        "or mode on it or on a directory above it, or malformed), so the "
        "issuer is not authenticated and the revocation state is not established"
    ),
    "trust_unreadable": (
        "the Edge issuer configuration directory could not be read by this "
        "user, so whether an anchor is configured is unknown here; the issuer "
        "is not authenticated and the revocation state is not established"
    ),
    "not_inspected": (
        "no Edge package root is configured, so no manifest was authenticated"
    ),
    "package_refused": (
        "the package check did not pass, so no manifest was authenticated"
    ),
    "no_manifest": "there is no readable manifest to authenticate",
    "manifest_refused": (
        "the manifest could not be canonicalised (not JSON, a duplicate key, "
        "a non-integer number, or too large), so no signature can cover it"
    ),
    "no_signature": (
        "a trust anchor is configured and there is no detached issuer "
        "signature beside the manifest"
    ),
    "signature_unreadable": (
        "the detached issuer signature beside the manifest could not be read "
        "as one (not a regular file, linked, or not 64 bytes)"
    ),
    "signature_invalid": (
        "the detached signature does not verify over this manifest under the "
        "configured issuer key: the manifest was changed after signing, or it "
        "was signed by another key"
    ),
    "authenticated": (
        "the manifest carries a valid detached signature under the configured "
        "issuer key"
    ),
}


class IssuerRefused(Exception):
    """Issuer trust material, a revocation list or a floor was not accepted."""


# -- canonical form -------------------------------------------------------


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IssuerRefused("a duplicate JSON key is refused")
        result[key] = value
    return result


def _no_float(text):
    raise IssuerRefused(f"a non-integer number ({text}) has no single canonical form")


def canonical_json(raw: bytes) -> bytes:
    """One byte string for one JSON document, or `IssuerRefused`.

    Sorted keys, no insignificant whitespace, UTF-8 without escaping, and no
    floats, `NaN` or duplicate keys -- each of which would let two encodings of
    "the same" manifest carry two different signatures, or one signature cover
    two readings. The issuer signs exactly these bytes, after the domain.
    """

    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_BYTES:
        raise IssuerRefused("a signed document is between 1 byte and 64 KiB")
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_float=_no_float,
            parse_constant=_no_float,
        )
    except IssuerRefused:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise IssuerRefused("a signed document is UTF-8 JSON") from exc
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def manifest_signature_target(raw: bytes) -> bytes:
    """What the issuer signs for a manifest: the domain, then its canonical form."""

    return MANIFEST_DOMAIN + canonical_json(raw)


def parse_version(text) -> tuple[int, int, int]:
    """`MAJOR.MINOR.PATCH`, strictly, or `IssuerRefused`.

    Nothing looser: a floor compared against a version it had to guess at is a
    floor an adversary chooses the reading of.
    """

    match = _VERSION.match(text) if type(text) is str else None
    if match is None:
        raise IssuerRefused("a version is MAJOR.MINOR.PATCH without leading zeros")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


# -- the anchor, the revocation list and the floor -------------------------


@dataclass(frozen=True)
class IssuerAnchor:
    """The one key Edge package manifests and revocation lists must verify under."""

    issuer: str
    public_key: bytes


def _decode_anchor(raw: bytes) -> IssuerAnchor:
    try:
        document = json.loads(canonical_json(raw), object_pairs_hook=_no_duplicates)
    except IssuerRefused:
        raise
    if type(document) is not dict or set(document) != {"schema", "issuer", "public_key"}:
        raise IssuerRefused("the issuer anchor has exactly schema, issuer and public_key")
    if document["schema"] != ANCHOR_SCHEMA:
        raise IssuerRefused("the issuer anchor schema is not supported")
    if type(document["issuer"]) is not str or not _ISSUER.match(document["issuer"]):
        raise IssuerRefused("the issuer is named by a short lower-case identifier")
    try:
        key = parse_public_key(document["public_key"])
    except SignatureRefused as exc:
        raise IssuerRefused(f"the issuer public key is refused: {exc}") from exc
    return IssuerAnchor(issuer=document["issuer"], public_key=key)


@dataclass(frozen=True)
class EdgeRevocations:
    """Versions and digests of the Edge package that are no longer admitted."""

    sequence: int
    issued_at: str
    package: str
    revoked_versions: frozenset = frozenset()
    revoked_digests: frozenset = frozenset()

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or not 0 < self.sequence < 2**63:
            raise IssuerRefused("a revocation sequence is a positive integer")
        if type(self.issued_at) is not str or not self.issued_at.strip():
            raise IssuerRefused("a revocation list records when it was issued")
        if type(self.package) is not str or not self.package:
            raise IssuerRefused("a revocation list names its package")
        for version in self.revoked_versions:
            parse_version(version)
        for digest in self.revoked_digests:
            if type(digest) is not str or not _DIGEST.match(digest):
                raise IssuerRefused("a revoked digest is sha256:<64 lower-case hex>")

    def as_payload(self) -> bytes:
        return json.dumps({
            "schema": REVOCATION_SCHEMA,
            "package": self.package,
            "sequence": self.sequence,
            "issued_at": self.issued_at,
            "revoked_versions": sorted(self.revoked_versions),
            "revoked_digests": sorted(self.revoked_digests),
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def signature_target(self) -> bytes:
        return REVOCATION_DOMAIN + self.as_payload()

    @property
    def content_digest(self) -> str:
        """SHA-256 of the canonical payload: what the floor remembers of a list."""

        return "sha256:" + hashlib.sha256(self.as_payload()).hexdigest()


def _decode_revocations(blob: bytes, anchor: IssuerAnchor) -> EdgeRevocations:
    """Verify the transport (signature, then payload) and parse it, or refuse."""

    if type(blob) is not bytes or not SIGNATURE_BYTES < len(blob) <= _MAX_BYTES:
        raise IssuerRefused("a signed revocation list is 64 signature bytes and a payload")
    signature, payload = blob[:SIGNATURE_BYTES], blob[SIGNATURE_BYTES:]
    if canonical_json(payload) != payload:
        raise IssuerRefused("the revocation payload is not in canonical form")
    if not verify_detached(public_key=anchor.public_key,
                           message=REVOCATION_DOMAIN + payload, signature=signature):
        raise IssuerRefused("the revocation list is not signed by the configured issuer")
    document = json.loads(payload)
    expected = {"schema", "package", "sequence", "issued_at",
                "revoked_versions", "revoked_digests"}
    if type(document) is not dict or set(document) != expected:
        raise IssuerRefused("the revocation list fields are refused")
    if document["schema"] != REVOCATION_SCHEMA:
        raise IssuerRefused("the revocation list schema is not supported")
    for key in ("revoked_versions", "revoked_digests"):
        values = document[key]
        if (type(values) is not list or any(type(v) is not str for v in values)
                or values != sorted(set(values))):
            raise IssuerRefused(f"{key} is a sorted list of distinct strings")
    revocations = EdgeRevocations(
        sequence=document["sequence"], issued_at=document["issued_at"],
        package=document["package"],
        revoked_versions=frozenset(document["revoked_versions"]),
        revoked_digests=frozenset(document["revoked_digests"]),
    )
    if revocations.as_payload() != payload:
        raise IssuerRefused("the revocation payload is not in canonical form")
    return revocations


@dataclass(frozen=True)
class EdgeFloor:
    """The rollback floor: the highest enabled authenticated version and its digest."""

    version: str
    package_digest: str
    revocation_sequence: int = 0
    #: `EdgeRevocations.content_digest` of the list in force when the floor
    #: was raised; empty exactly when `revocation_sequence` is 0. A list at the
    #: same sequence with other content is a substituted list.
    revocation_digest: str = ""

    def __post_init__(self) -> None:
        parse_version(self.version)
        if type(self.package_digest) is not str or not _DIGEST.match(self.package_digest):
            raise IssuerRefused("the floor digest is sha256:<64 lower-case hex>")
        if type(self.revocation_sequence) is not int or not 0 <= self.revocation_sequence < 2**63:
            raise IssuerRefused("the floor revocation sequence is a bounded integer")
        if self.revocation_sequence == 0:
            if self.revocation_digest != "":
                raise IssuerRefused("a floor with no revocation sequence names no list")
        elif type(self.revocation_digest) is not str or not _DIGEST.match(self.revocation_digest):
            raise IssuerRefused("a floor with a revocation sequence names its list digest")

    def lower_than(self, other: "EdgeFloor") -> list[str]:
        """What in `self` would move `other` backwards, by field name."""

        lower = []
        mine, theirs = parse_version(self.version), parse_version(other.version)
        if mine < theirs:
            lower.append("version")
        elif mine == theirs and self.package_digest != other.package_digest:
            lower.append("package_digest")
        if self.revocation_sequence < other.revocation_sequence:
            lower.append("revocation_sequence")
        elif (self.revocation_sequence == other.revocation_sequence
              and self.revocation_digest != other.revocation_digest):
            lower.append("revocation_digest")
        return lower


def encode_floor(value: EdgeFloor) -> bytes:
    if type(value) is not EdgeFloor:
        raise IssuerRefused("a floor record is required")
    return json.dumps({
        "schema": FLOOR_SCHEMA, "version": value.version,
        "package_digest": value.package_digest,
        "revocation_sequence": value.revocation_sequence,
        "revocation_digest": value.revocation_digest,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def decode_floor(raw: bytes) -> EdgeFloor:
    """The floor, only from its exact canonical encoding; anything else refuses."""

    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 4096:
            raise IssuerRefused("floor size refused")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
        if (type(document) is not dict
                or set(document) != {"schema", "version", "package_digest",
                                     "revocation_sequence", "revocation_digest"}
                or document.pop("schema") != FLOOR_SCHEMA):
            raise IssuerRefused("floor fields refused")
        value = EdgeFloor(**document)
        if encode_floor(value) != raw:
            raise IssuerRefused("floor record is not canonical")
        return value
    except Exception:  # noqa: BLE001 - a floor that is not exactly one is refused
        raise IssuerRefused("the Edge rollback floor record is refused") from None


# -- protected reads ------------------------------------------------------


class _Unreadable(Exception):
    """This user may not read it. Not corrupt, and not absent."""


def _protected(fd: int, *, owner: int, directory: bool) -> os.stat_result:
    info = os.fstat(fd)
    kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not kind or info.st_uid != owner or info.st_mode & 0o022
            or (not directory and info.st_nlink != 1)):
        raise IssuerRefused("Edge issuer storage has unsafe type, ownership or mode")
    return info


def _is_protected(fd: int, *, owner: int, directory: bool) -> bool:
    try:
        _protected(fd, owner=owner, directory=directory)
    except IssuerRefused:
        return False
    return True


def _open_chain(components: tuple[str, ...], *, owner: int) -> tuple[Optional[int], bool]:
    """Open `/<components...>` with no symlink anywhere.

    `(None, True)` only when a component genuinely does not exist (`ENOENT`).
    A component that is a symlink (`ELOOP`) or not a directory (`ENOTDIR`)
    is `IssuerRefused`: something is there, and reading it as "absent" would
    let a link or a file in place of the directory hide an anchor or unbind
    the floor. Otherwise the descriptor and whether every directory on the
    way is root-owned and not group or other writable. `_Unreadable` on
    `EACCES`. Mode and ownership are *reported*, not enforced, here: whether
    they matter depends on what the directory turns out to hold.
    """

    fd = os.open("/", _DIR_FLAGS)
    safe = _is_protected(fd, owner=owner, directory=True)
    try:
        for component in components:
            child = os.open(component, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            safe = _is_protected(fd, owner=owner, directory=True) and safe
    except FileNotFoundError:
        os.close(fd)
        return None, True
    except PermissionError:
        os.close(fd)
        raise _Unreadable() from None
    except OSError:  # ELOOP (a link), ENOTDIR: present, and not a directory
        os.close(fd)
        raise IssuerRefused("an Edge issuer path component is a link or not a directory") from None
    except BaseException:
        os.close(fd)
        raise
    return fd, safe


def _open_leaf(directory: Path, *, owner: int) -> tuple[Optional[int], bool]:
    """The test seam: the same answer for one directory, checking only it."""

    try:
        fd = os.open(directory, _DIR_FLAGS)
    except FileNotFoundError:
        return None, True
    except PermissionError:
        raise _Unreadable() from None
    except OSError:
        raise IssuerRefused("an Edge issuer directory is a link or not a directory") from None
    return fd, _is_protected(fd, owner=owner, directory=True)


def _present(directory_fd: int, name: str) -> bool:
    """Whether a directory entry exists, without following or opening it."""

    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except PermissionError:
        raise _Unreadable() from None
    return True


def _read_file(directory_fd: int, name: str, *, owner: int) -> Optional[bytes]:
    """A bounded, unchanging read of one protected regular file; `None` if absent."""

    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except PermissionError:
        raise _Unreadable() from None
    try:
        before = _protected(fd, owner=owner, directory=False)
        if not 0 < before.st_size <= _MAX_BYTES:
            raise IssuerRefused("Edge issuer file size refused")
        chunks = bytearray()
        while len(chunks) <= _MAX_BYTES:
            part = os.read(fd, _MAX_BYTES + 1 - len(chunks))
            if not part:
                break
            chunks.extend(part)
        after = _protected(fd, owner=owner, directory=False)
        if ((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or len(chunks) != before.st_size):
            raise IssuerRefused("Edge issuer file changed while reading")
        return bytes(chunks)
    finally:
        os.close(fd)


# -- what the node trusts, read once per inspection ------------------------

#: Things worth an operator's attention that, by design, change nothing: with
#: no anchor file there is nothing they could be evidence for or against.
NOTE_REVOCATIONS_WITHOUT_ANCHOR = "revocations_present_without_anchor"
NOTE_CONFIG_UNPROTECTED = "config_directory_unprotected"
NOTE_STATE_UNPROTECTED = "state_directory_unprotected"


@dataclass(frozen=True)
class IssuerTrust:
    """The anchor, revocation list and floor as read, each with a fixed status.

    `config`: `not_configured` | `configured` | `refused` | `unreadable`.
    `floor_status`: `absent` | `present` | `refused` | `unreadable`.
    `revocation_status`: `not_configured` | `none` | `in_force` | `refused` |
    `unreadable` (the inspection adds `rolled_back` for a list older than, or
    substituted at, the floor's sequence).
    `notes`: fixed labels that are reported and change nothing.
    """

    config: str
    anchor: Optional[IssuerAnchor] = None
    revocations: Optional[EdgeRevocations] = None
    revocation_status: str = "not_configured"
    floor: Optional[EdgeFloor] = None
    floor_status: str = "absent"
    notes: tuple = ()


#: Nothing configured and no floor: what every node is until its administrator
#: places an anchor. Behaviour under it is exactly the behaviour before issuer
#: verification existed.
NOT_CONFIGURED = IssuerTrust(config="not_configured")


def _read_config(open_dir) -> tuple[str, Optional[IssuerAnchor], Optional[bytes], tuple]:
    """`(state, anchor, revocation bytes, notes)`. The anchor file decides.

    No anchor file: `not_configured`, whatever else is there -- a revocation
    list or an unprotected directory is noted and carries no authority. An
    anchor file: everything on the way and the file itself must be protected
    and well-formed, or the configuration is `refused`.
    """

    try:
        fd, safe = open_dir()
        if fd is None:
            return "not_configured", None, None, (() if safe else (NOTE_CONFIG_UNPROTECTED,))
        try:
            if not _present(fd, ANCHOR_FILENAME):
                notes = ()
                if _present(fd, REVOCATION_FILENAME):
                    notes += (NOTE_REVOCATIONS_WITHOUT_ANCHOR,)
                if not safe:
                    notes += (NOTE_CONFIG_UNPROTECTED,)
                return "not_configured", None, None, notes
            if not safe:
                return "refused", None, None, (NOTE_CONFIG_UNPROTECTED,)
            anchor_raw = _read_file(fd, ANCHOR_FILENAME, owner=_owner())
            revocation_raw = _read_file(fd, REVOCATION_FILENAME, owner=_owner())
        finally:
            os.close(fd)
        if anchor_raw is None:  # removed between the two looks
            return "refused", None, None, ()
        return "configured", _decode_anchor(anchor_raw), revocation_raw, ()
    except _Unreadable:
        return "unreadable", None, None, ()
    except Exception:  # noqa: BLE001 - an anchor that is not exactly one is refused
        return "refused", None, None, ()


def _read_floor(open_dir) -> tuple[str, Optional[EdgeFloor], tuple]:
    """`(status, floor, notes)`. A floor file, once there, is always enforced."""

    try:
        fd, safe = open_dir()
        if fd is None:
            return "absent", None, (() if safe else (NOTE_STATE_UNPROTECTED,))
        try:
            if not _present(fd, FLOOR_FILENAME):
                return "absent", None, (() if safe else (NOTE_STATE_UNPROTECTED,))
            if not safe:
                return "refused", None, (NOTE_STATE_UNPROTECTED,)
            raw = _read_file(fd, FLOOR_FILENAME, owner=_owner())
        finally:
            os.close(fd)
    except _Unreadable:
        return "unreadable", None, ()
    except Exception:  # noqa: BLE001 - a floor that cannot be read as one is refused
        return "refused", None, ()
    if raw is None:
        return "refused", None, ()
    try:
        return "present", decode_floor(raw), ()
    except IssuerRefused:
        return "refused", None, ()


#: The owner every component must have. Root in production; a private test
#: seam, never a parameter of a public function and never reached by a flag.
_OWNER = 0


def _owner() -> int:
    return _OWNER


def _assemble(config: tuple, floor: tuple) -> IssuerTrust:
    state, anchor, revocation_raw, config_notes = config
    floor_status, floor_value, floor_notes = floor
    revocations, revocation_status = None, "not_configured"
    if state == "configured":
        assert anchor is not None
        if revocation_raw is None:
            revocation_status = "none"
        else:
            try:
                revocations = _decode_revocations(revocation_raw, anchor)
                revocation_status = "in_force"
            except Exception:  # noqa: BLE001 - an unverifiable list is refused
                revocation_status = "refused"
    elif state in ("refused", "unreadable"):
        revocation_status = state
    return IssuerTrust(
        config=state, anchor=anchor, revocations=revocations,
        revocation_status=revocation_status, floor=floor_value,
        floor_status=floor_status, notes=tuple(config_notes) + tuple(floor_notes),
    )


def load_issuer_trust() -> IssuerTrust:
    """Read the fixed anchor, revocation list and floor. Never raises.

    Every path is fixed; nothing here takes a path from a caller, a flag or the
    environment. Each part reports its own status, so a refused floor does not
    hide a valid anchor and the reverse.
    """

    try:
        config = _read_config(lambda: _open_chain(_CONFIG_COMPONENTS, owner=_owner()))
    except Exception:  # noqa: BLE001
        config = ("refused", None, None, ())
    try:
        floor = _read_floor(lambda: _open_chain(STATE_COMPONENTS, owner=_owner()))
    except Exception:  # noqa: BLE001
        floor = ("refused", None, ())
    return _assemble(config, floor)


def _load_issuer_trust_at(config_dir: Path, state_dir: Path) -> IssuerTrust:
    """Tests only: the same reading from two directories, checking only their leaves."""

    return _assemble(
        _read_config(lambda: _open_leaf(config_dir, owner=_owner())),
        _read_floor(lambda: _open_leaf(state_dir, owner=_owner())),
    )


# -- the verification -----------------------------------------------------


@dataclass(frozen=True)
class IssuerVerification:
    """Two separate facts about one installed manifest, and what narrowed them.

    `digest_verified`: the artifact re-derived to the manifest's digest.
    `issuer_authenticated`: the manifest verified under the configured issuer.
    Neither is derived from the other, and `__post_init__` refuses any record
    in which the label and the boolean disagree.
    """

    digest_verified: bool
    issuer_authenticated: bool
    issuer_status: str
    issuer: Optional[str] = None
    revocation_status: str = "not_configured"
    revocation_sequence: Optional[int] = None
    #: `revoked_version` | `revoked_digest` | `none` | `not_evaluated`.
    revoked: str = "not_evaluated"
    #: `absent` | `held` | `below_floor` | `replayed` | `refused` |
    #: `unreadable` | `not_evaluated`.
    floor_status: str = "not_evaluated"
    floor_version: Optional[str] = None
    #: What was verified. Set only when the issuer is authenticated, because
    #: only then may the runtime raise the floor to it.
    version: Optional[str] = None
    package_digest: Optional[str] = None
    #: `EdgeRevocations.content_digest` of the list in force, for the floor.
    revocation_digest: Optional[str] = None
    #: Fixed labels that are reported and change nothing (`IssuerTrust.notes`).
    notes: tuple = ()

    def __post_init__(self) -> None:
        if type(self.digest_verified) is not bool or type(self.issuer_authenticated) is not bool:
            raise IssuerRefused("both facts are booleans")
        if self.issuer_status not in ISSUER_REASONS:
            raise IssuerRefused(f"unknown issuer status {self.issuer_status!r}")
        if self.issuer_authenticated != (self.issuer_status == "authenticated"):
            raise IssuerRefused("the issuer status and issuer_authenticated disagree")
        if self.issuer_authenticated and not self.issuer:
            raise IssuerRefused("an authenticated manifest names its issuer")
        if not self.issuer_authenticated and (self.version or self.package_digest):
            raise IssuerRefused("an unauthenticated manifest carries no floor candidate")

    @property
    def issuer_reason(self) -> str:
        return ISSUER_REASONS[self.issuer_status]

    def labels(self) -> dict:
        """Fixed labels and booleans only: no digest, version or key."""

        return {
            "digest_verified": self.digest_verified,
            "issuer_authenticated": self.issuer_authenticated,
            "issuer_status": self.issuer_status,
            "revocation_status": self.revocation_status,
            "revoked": self.revoked,
            "floor_status": self.floor_status,
            "notes": list(self.notes),
        }

    def as_event(self) -> dict:
        document = self.labels()
        document.update({
            "issuer": self.issuer,
            "issuer_reason": self.issuer_reason,
            "revocation_sequence": self.revocation_sequence,
            "floor_version": self.floor_version,
        })
        return document


def verify_issuer(
    manifest_raw: Optional[bytes], signature_raw: Optional[bytes], trust: IssuerTrust,
) -> tuple[str, Optional[str]]:
    """The issuer status label for one manifest, and the issuer when authenticated."""

    if trust.config == "not_configured":
        return "not_configured", None
    if trust.config == "unreadable":
        return "trust_unreadable", None
    if trust.config != "configured" or trust.anchor is None:
        return "trust_refused", None
    if manifest_raw is None:
        return "no_manifest", None
    try:
        target = manifest_signature_target(manifest_raw)
    except IssuerRefused:
        return "manifest_refused", None
    if signature_raw is None:
        return "no_signature", None
    if len(signature_raw) != SIGNATURE_BYTES:
        return "signature_unreadable", None
    try:
        valid = verify_detached(public_key=trust.anchor.public_key,
                                message=target, signature=signature_raw)
    except SignatureRefused:
        return "trust_refused", None
    if not valid:
        return "signature_invalid", None
    return "authenticated", trust.anchor.issuer


def read_detached_signature(manifest_path: Path) -> tuple[str, Optional[bytes]]:
    """`(state, bytes)` for `<manifest>.sig`: `absent`, `read` or `unreadable`.

    No-follow, a regular file, at most a few bytes more than a signature. The
    package directory is not trusted -- that is the point of the signature --
    so only its shape is checked, never its owner.
    """

    path = manifest_path.with_name(manifest_path.name + SIGNATURE_SUFFIX)
    try:
        fd = os.open(path, _FILE_FLAGS)
    except FileNotFoundError:
        return "absent", None
    except OSError:  # a link (ELOOP), a FIFO, or anything else unreadable
        return "unreadable", None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return "unreadable", None
        data = os.read(fd, SIGNATURE_BYTES + 1)
    except OSError:
        return "unreadable", None
    finally:
        os.close(fd)
    if len(data) != SIGNATURE_BYTES:
        return "unreadable", None
    return "read", data
