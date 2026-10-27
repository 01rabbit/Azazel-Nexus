"""Verify, extract and install an Azazel-Nexus offline install bundle.

The bundle is one gzip-compressed tar whose first member is ``MANIFEST.json``.
The manifest lists every other member -- source files, hash-pinned wheels, and
the optional Edge package, Debian package, model and Knowledge slots -- with
its sha256, size, kind and source. ``tools/build_offline_bundle.py`` writes it.

What this module establishes, and what it does not
==================================================

* **A strict format.** The bundle is POSIX ustar only: no pax records, no GNU
  long names or sparse members. This module parses the 512-byte headers itself
  (fixed fields, checksum verified, typeflag ``0`` only) and never hands the
  bundle to ``tarfile``, whose header processing can allocate in proportion to
  attacker data before a caller sees a member. The gzip layer is streamed with
  a cap on decompressed bytes.
* **Integrity against the manifest.** Extraction refuses absolute paths,
  ``..``, links of any kind, device files, FIFOs and directory members; a
  member count or byte total above the caps; a member that the manifest does
  not declare, or a declared one that is missing; and any size or sha256
  mismatch. It writes into a private staging directory beside the destination
  and renames it into place only after every check passed.
* **Not authenticity.** Nothing here is signed. The manifest can be rewritten
  together with the files it describes, so a bundle that passes every check
  above is exactly as trustworthy as the medium it arrived on.
  ``verify_bundle_signature`` is the integration point for the issuer/operator
  signature; until a verifier is wired in there, every report carries
  ``bundle_authenticated: false``.
* **Not admission.** Carrying an Edge package, a Debian package, a model or a
  Knowledge bundle on the medium admits none of them. Each has its own
  admission path (``edge_package`` checks, model import, Knowledge Lite trust),
  and nothing here substitutes for it.

Run the copy of this file from a reviewed checkout, not the one inside the
bundle: a verifier taken from the thing it verifies checks nothing.

This module uses only the standard library so that it runs with the target's
system interpreter before any virtual environment exists.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterable, Optional


SCHEMA = "azazel-nexus-offline-bundle@1"
MANIFEST_NAME = "MANIFEST.json"
#: The detached signature member the signing hook will read. Optional; when it
#: is present it is carried to ``verify_bundle_signature`` and nothing else.
SIGNATURE_NAME = "MANIFEST.sig"
SIGNATURE_MAX_BYTES = 64 << 10

#: Each kind lives under exactly one prefix, so a wheel cannot be smuggled in
#: as a source file or the other way round.
KIND_PREFIX = {
    "source": "source/",
    "wheel": "wheels/",
    "edge-package": "edge/",
    "deb": "deb/",
    "model": "assets/models/",
    "knowledge": "assets/knowledge/",
}
REQUIRED_KINDS = ("source", "wheel")
SLOT_KINDS = ("edge-package", "deb", "model", "knowledge")
SLOT_STATES = ("empty", "filled")
MODES = ("0644", "0755")

#: The only target this bundle format declares: the reference OS and
#: architecture of docs/support-matrix.md §3, with Debian 13's system CPython.
#: Defined here, never read from the manifest, so a bundle cannot name its own
#: target into acceptance.
TARGETS = {
    "debian-13-x86_64-cp313": {
        "os": "debian-13",
        "architecture": "x86_64",
        "deb_architectures": ("amd64", "all"),
        "python_tag": "cp313",
        "python_version": (3, 13),
        # Debian 13 ships glibc 2.41; a manylinux wheel needing more is refused.
        "glibc_max": (2, 41),
    },
}

# `%` because apt names an epoch `1%3a` in a .deb file name.
_COMPONENT = re.compile(r"[A-Za-z0-9_+~=%-][A-Za-z0-9._+~=%-]*\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_WHEEL = re.compile(
    r"(?P<name>[A-Za-z0-9_.]+)-(?P<version>[A-Za-z0-9_.!+]+)"
    r"(?:-(?P<build>\d[A-Za-z0-9_]*))?-(?P<py>[A-Za-z0-9_.]+)-(?P<abi>[A-Za-z0-9_.]+)"
    r"-(?P<plat>[A-Za-z0-9_.]+)\.whl\Z"
)
_REQUIREMENT = re.compile(r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[A-Za-z0-9.!+_-]+)\Z")
_MANYLINUX = re.compile(r"manylinux_(\d+)_(\d+)_(?P<arch>[a-z0-9_]+)\Z")
_LEGACY_MANYLINUX = {"manylinux1": (2, 5), "manylinux2010": (2, 12), "manylinux2014": (2, 17)}

#: The two distributions this repository builds; every bundle carries both.
OWN_DISTRIBUTIONS = ("azazel-nexus", "azazel-nexus-runtime")

#: The reviewed checkout this file is run from. Third-party wheels are admitted
#: only when their name, version and sha256 are in its lock; the two Nexus
#: wheels only when their versions equal its pyproject files.
REVIEWED_ROOT = Path(__file__).resolve().parents[1]
WHEEL_LOCK = Path("packaging/offline/requirements-x86_64-cp313.lock")


class BundleRefused(Exception):
    """The bundle, or one of its members, is refused. Nothing was promoted."""


@dataclass(frozen=True)
class Limits:
    """Extraction caps. A caller may lower them (``tighter``), never raise them."""

    max_members: int = 20_000
    max_total_bytes: int = 16 << 30
    max_member_bytes: int = 8 << 30
    max_manifest_bytes: int = 8 << 20
    max_depth: int = 16
    max_path_bytes: int = 240
    #: Declared uncompressed bytes per archive byte. Wheels, the Edge archive
    #: and models are already compressed; source text compresses ~4:1.
    max_ratio: int = 200

    def tighter(self, **overrides: int) -> "Limits":
        for key, value in overrides.items():
            current = getattr(self, key)
            if type(value) is not int or value < 1 or value > current:
                raise BundleRefused(
                    f"{key}={value!r} is refused: a cap can be lowered from {current}, "
                    "never raised"
                )
        return dataclasses.replace(self, **overrides)


DEFAULT_LIMITS = Limits()

#: Nesting depth of the manifest JSON; the real manifest needs 3.
MANIFEST_MAX_NESTING = 16
#: Free space kept beyond the declared total when extracting.
FREE_SPACE_MARGIN_BYTES = 64 << 20


# --------------------------------------------------------------------------
# A self-contained tar reader. ``tarfile``'s header processing (pax records,
# GNU long names, sparse maps) runs before any caller can look at a member and
# can allocate in proportion to attacker data, so untrusted archives are read
# here instead, with fixed-size fields and every extension refused or bounded
# before a byte of its body is read. ``tarfile`` is used only to *write*.
# --------------------------------------------------------------------------

BLOCK = 512
_USTAR_MAGIC = b"ustar\x0000"
_GNU_MAGIC = b"ustar  \x00"
#: Body of one nested pax extended header (Edge archive / .deb control only).
PAX_MAX_BYTES = 64 << 10
#: pax keys a nested archive may carry. Anything else -- ``size``,
#: ``GNU.sparse.*``, ``hdrcharset`` -- is refused, so a later ``tarfile`` read
#: of the same bytes cannot be driven into sparse-map or size processing.
NESTED_PAX_KEYS = frozenset({"path", "linkpath", "mtime", "atime", "ctime", "uid", "gid", "uname", "gname"})
_TYPE_NAMES = {
    b"1": "a hardlink", b"2": "a symlink", b"3": "a device file", b"4": "a device file",
    b"5": "a directory entry", b"6": "a FIFO", b"7": "a contiguous file",
    b"x": "a pax extended header", b"g": "a pax global header",
    b"L": "a GNU long-name header", b"K": "a GNU long-link header", b"S": "a GNU sparse member",
    b"X": "a Solaris extended header", b"V": "a GNU volume header", b"M": "a GNU multi-volume member",
    b"N": "a GNU long-name header", b"D": "a GNU dump directory", b"\0": "an old-style (pre-POSIX) member",
}


class _Gunzip:
    """A gzip stream read in bounded steps, with a hard cap on decompressed bytes."""

    def __init__(self, raw: BinaryIO, cap: int) -> None:
        self._raw = raw
        self.cap = cap
        self._produced = 0
        self._z = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self._buffer = bytearray()
        self._done = False

    def _fill(self, want: int) -> None:
        step = max(want, 1 << 16)
        if self._z.unconsumed_tail:
            chunk = self._z.decompress(self._z.unconsumed_tail, step)
        else:
            raw = self._raw.read(1 << 16)
            if not raw:
                if not self._z.eof:
                    raise BundleRefused("the gzip stream is truncated")
                self._done = True
                return
            if self._z.eof:
                raise BundleRefused("data follows the end of the gzip stream")
            chunk = self._z.decompress(raw, step)
        if self._z.eof and self._z.unused_data:
            raise BundleRefused("data follows the end of the gzip stream")
        self._produced += len(chunk)
        if self._produced > self.cap:
            raise BundleRefused(f"the archive decompresses beyond {self.cap} bytes")
        self._buffer += chunk

    def read(self, size: int) -> bytes:
        while len(self._buffer) < size and not self._done:
            self._fill(size - len(self._buffer))
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data

    def read_exact(self, size: int) -> bytes:
        data = self.read(size)
        if len(data) != size:
            raise BundleRefused("the archive ends inside a member")
        return data


class _Plain:
    """The same interface over bytes already in memory (a .deb control archive)."""

    def __init__(self, data: bytes) -> None:
        self._stream = io.BytesIO(data)

    def read(self, size: int) -> bytes:
        return self._stream.read(size)

    def read_exact(self, size: int) -> bytes:
        data = self._stream.read(size)
        if len(data) != size:
            raise BundleRefused("the archive ends inside a member")
        return data


@dataclass(frozen=True)
class TarHeader:
    name: str
    size: int
    typeflag: bytes
    linkname: str


def _octal(field: bytes, what: str) -> int:
    text = field.replace(b"\0", b" ").strip(b" ")
    if not text:
        return 0
    if not re.fullmatch(rb"[0-7]+", text):
        raise BundleRefused(f"tar header field {what} is not plain octal")
    return int(text, 8)


def _text(field: bytes) -> str:
    end = field.find(b"\0")
    raw = field if end < 0 else field[:end]
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise BundleRefused("a tar header name is not ASCII") from exc


def read_tar_header(stream, *, strict: bool) -> Optional[TarHeader]:
    """The next header, or None at the first all-zero block. Checksum always verified.

    ``strict`` accepts only POSIX ustar magic; otherwise the GNU magic of
    older writers (dpkg) is accepted too, without its extensions.
    """

    block = stream.read_exact(BLOCK)
    if block == bytes(BLOCK):
        return None
    stored = _octal(block[148:156], "checksum")
    if stored != sum(block[:148]) + 8 * 0x20 + sum(block[156:]):
        raise BundleRefused("a tar header checksum does not match")
    magic = block[257:265]
    if magic != _USTAR_MAGIC and (strict or magic != _GNU_MAGIC):
        raise BundleRefused("a tar header is not POSIX ustar")
    name = _text(block[0:100])
    prefix = _text(block[345:500]) if magic == _USTAR_MAGIC else ""
    return TarHeader(
        name=f"{prefix}/{name}" if prefix else name,
        size=_octal(block[124:136], "size"),
        typeflag=block[156:157],
        linkname=_text(block[157:257]),
    )


def type_refusal(header: TarHeader, allowed: tuple[bytes, ...]) -> Optional[str]:
    if header.typeflag in allowed:
        if header.linkname:
            return f"member {header.name!r} names a link target"
        return None
    kind = _TYPE_NAMES.get(header.typeflag, f"of type {header.typeflag!r}")
    target = f" (to {header.linkname!r})" if header.linkname else ""
    return f"member {header.name!r} is {kind}{target}; only regular files are carried"


class _Body:
    """Exactly ``size`` bytes of one member, then its block padding is consumed."""

    def __init__(self, stream, size: int) -> None:
        self._stream = stream
        self._left = size
        self._padding = -size % BLOCK

    def read(self, size: int = -1) -> bytes:
        want = self._left if size < 0 else min(size, self._left)
        data = self._stream.read_exact(want) if want else b""
        self._left -= len(data)
        if not self._left and self._padding:
            self._stream.read_exact(self._padding)
            self._padding = 0
        return data

    def skip(self) -> None:
        while self._left or self._padding:
            self.read(1 << 20)


def read_end_of_archive(stream) -> None:
    """After the first zero block: a second one, then only zero padding to EOF."""

    if stream.read_exact(BLOCK) != bytes(BLOCK):
        raise BundleRefused("the tar end marker is incomplete")
    while chunk := stream.read(1 << 16):
        if chunk.count(0) != len(chunk):
            raise BundleRefused("data follows the tar end marker")


def _pax_records(data: bytes) -> dict[str, str]:
    records: dict[str, str] = {}
    position = 0
    while position < len(data):
        space = data.find(b" ", position, position + 21)
        if space < 0 or not data[position:space].isdigit():
            raise BundleRefused("a pax record is malformed")
        length = int(data[position:space])
        record = data[space + 1:position + length]
        if length <= 0 or position + length > len(data) or not record.endswith(b"\n") or b"=" not in record:
            raise BundleRefused("a pax record is malformed")
        key, _, value = record[:-1].partition(b"=")
        try:
            key_text, value_text = key.decode("utf-8"), value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BundleRefused("a pax record is not UTF-8") from exc
        if key_text not in NESTED_PAX_KEYS:
            raise BundleRefused(f"pax key {key_text!r} is refused")
        records[key_text] = value_text
        position += length
    return records


def scan_nested_tar(stream, *, want: frozenset[str] = frozenset(), max_members: int = 4096,
                    max_wanted_bytes: int = 1 << 20) -> dict[str, bytes]:
    """Walk a nested archive (Edge package, .deb control) with every extension refused.

    Regular files, old-style regular files and directories are allowed; a pax
    ``x`` header is allowed only with ``NESTED_PAX_KEYS`` and only directly
    before the member it describes. Returns the bodies of ``want`` members.
    """

    found: dict[str, bytes] = {}
    pending: Optional[dict[str, str]] = None
    for _count in range(max_members + 1):
        header = read_tar_header(stream, strict=False)
        if header is None:
            if pending is not None:
                raise BundleRefused("a pax header describes no member")
            return found
        body = _Body(stream, header.size)
        if header.typeflag == b"x":
            if pending is not None:
                raise BundleRefused("chained pax extended headers are refused")
            if header.size > PAX_MAX_BYTES:
                raise BundleRefused(f"a pax header declares {header.size} bytes; the cap is {PAX_MAX_BYTES}")
            pending = _pax_records(body.read())
            continue
        refusal = type_refusal(header, (b"0", b"\0", b"5"))
        if refusal:
            raise BundleRefused(refusal)
        name = (pending or {}).get("path", header.name)
        pending = None
        normal = name[2:] if name.startswith("./") else name
        if header.typeflag != b"5" and normal in want:
            if header.size > max_wanted_bytes:
                raise BundleRefused(f"{normal} is larger than {max_wanted_bytes} bytes")
            found[normal] = body.read()
        else:
            body.skip()
    raise BundleRefused(f"the nested archive has more than {max_members} members")


# --------------------------------------------------------------------------
# The signing hook.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SignatureVerdict:
    authenticated: bool
    signature_present: bool
    reason: str


def verify_bundle_signature(manifest_bytes: bytes, signature: Optional[bytes]) -> SignatureVerdict:
    """Bundle signing hook: verify the issuer/operator signature over ``MANIFEST.json``.

    This is the one integration point for the bundle signature that the
    issuer/operator signing work defines. It receives the exact manifest bytes
    and the bytes of the optional ``MANIFEST.sig`` member. No verifier is
    integrated yet, so it authenticates nothing: an absent signature and a
    present one both yield ``authenticated=False``. A present signature is not
    checked and is never read as evidence of anything.

    Whatever replaces this body MUST NOT change the acceptance of an unsigned
    bundle as a side effect; that is a release-admission decision
    (docs/update-channel.md §3), not a property of the extractor.
    """

    del manifest_bytes  # bound by the future verifier; unused until then
    if signature is None:
        return SignatureVerdict(
            authenticated=False,
            signature_present=False,
            reason="unsigned: the bundle carries no MANIFEST.sig and no bundle signature is defined",
        )
    return SignatureVerdict(
        authenticated=False,
        signature_present=True,
        reason=(
            "MANIFEST.sig is present, but no issuer/operator bundle verifier is integrated; "
            "it was not checked and authenticates nothing"
        ),
    )


# --------------------------------------------------------------------------
# Paths, names and the manifest.
# --------------------------------------------------------------------------


def safe_member_path(name: object, limits: Limits = DEFAULT_LIMITS) -> str:
    """``name`` if it is a plain relative POSIX path inside the bundle, else refuse."""

    if type(name) is not str or not name:
        raise BundleRefused("a member path is empty or not a string")
    if "\0" in name or "\\" in name:
        raise BundleRefused(f"member path {name!r} contains a NUL or a backslash")
    if name.startswith("/"):
        raise BundleRefused(f"member path {name!r} is absolute")
    if len(name.encode("utf-8")) > limits.max_path_bytes:
        raise BundleRefused(f"member path {name!r} is longer than {limits.max_path_bytes} bytes")
    parts = name.split("/")
    if ".." in parts:
        raise BundleRefused(f"member path {name!r} contains '..'")
    if len(parts) > limits.max_depth:
        raise BundleRefused(f"member path {name!r} is deeper than {limits.max_depth}")
    for part in parts:
        if not _COMPONENT.match(part):
            raise BundleRefused(f"member path {name!r} has a refused component {part!r}")
    if PurePosixPath(name).as_posix() != name:
        raise BundleRefused(f"member path {name!r} is not in normal form")
    return name


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_wheel_name(filename: str) -> dict[str, str]:
    match = _WHEEL.match(filename)
    if not match:
        raise BundleRefused(f"{filename!r} is not a wheel file name")
    return match.groupdict()


def _glibc_of(tag: str, architecture: str) -> Optional[tuple[int, int]]:
    if tag == f"linux_{architecture}":
        return (0, 0)
    legacy, _, arch = tag.partition("_")
    if legacy in _LEGACY_MANYLINUX and arch == architecture:
        return _LEGACY_MANYLINUX[legacy]
    match = _MANYLINUX.match(tag)
    if match and match.group("arch") == architecture:
        return (int(match.group(1)), int(match.group(2)))
    return None


def wheel_fits_target(filename: str, target: dict) -> bool:
    """Whether a wheel's compatibility tags admit the declared target at all."""

    parts = parse_wheel_name(filename)
    pythons = set(parts["py"].split("."))
    abis = set(parts["abi"].split("."))
    platforms = parts["plat"].split(".")
    if not pythons & {"py3", target["python_tag"]}:
        return False
    if not abis & {"none", "abi3", target["python_tag"]}:
        return False
    if "abi3" in abis and not pythons & {"cp3" + str(m) for m in range(2, target["python_version"][1] + 1)}:
        return False
    if platforms == ["any"]:
        return True
    for platform in platforms:
        glibc = _glibc_of(platform, target["architecture"])
        if glibc is not None and glibc <= target["glibc_max"]:
            return True
    return False


def _exact_keys(document: dict, required: set[str], optional: set[str], what: str) -> None:
    keys = set(document)
    missing = required - keys
    extra = keys - required - optional
    if missing or extra:
        raise BundleRefused(f"{what}: missing {sorted(missing)}, unexpected {sorted(extra)}")


_ARTIFACT_KEYS = {"path", "kind", "sha256", "size", "mode", "source"}
_KIND_KEYS = {
    "source": set(),
    "wheel": {"requirement"},
    "edge-package": set(),
    "deb": {"package", "version", "architecture"},
    "model": set(),
    "knowledge": set(),
}


def validate_manifest(document: object, limits: Limits = DEFAULT_LIMITS) -> dict:
    """Return ``document`` if it is a well-formed bundle manifest, else refuse."""

    if type(document) is not dict:
        raise BundleRefused("the manifest is not a JSON object")
    _exact_keys(
        document,
        {"schema", "target", "repository_identity", "slots", "artifacts", "totals"},
        set(),
        "manifest",
    )
    if document["schema"] != SCHEMA:
        raise BundleRefused(f"manifest schema {document['schema']!r} is not {SCHEMA!r}")
    if document["target"] not in TARGETS:
        raise BundleRefused(f"manifest target {document['target']!r} is not a declared target")
    identity = document["repository_identity"]
    if type(identity) is not dict or not all(type(v) is str for v in identity.values()):
        raise BundleRefused("manifest repository_identity is not a string map")
    slots = document["slots"]
    if type(slots) is not dict or set(slots) != set(SLOT_KINDS):
        raise BundleRefused(f"manifest slots must be exactly {list(SLOT_KINDS)}")
    artifacts = document["artifacts"]
    if type(artifacts) is not list or not artifacts:
        raise BundleRefused("manifest lists no artifacts")
    if len(artifacts) > limits.max_members:
        raise BundleRefused(f"manifest lists {len(artifacts)} artifacts; the cap is {limits.max_members}")

    seen: set[str] = set()
    kinds_present: set[str] = set()
    total = 0
    reserved = {MANIFEST_NAME, SIGNATURE_NAME}
    for entry in artifacts:
        if type(entry) is not dict:
            raise BundleRefused("a manifest artifact is not an object")
        kind = entry.get("kind")
        if kind not in KIND_PREFIX:
            raise BundleRefused(f"artifact kind {kind!r} is not declared")
        _exact_keys(entry, _ARTIFACT_KEYS | _KIND_KEYS[kind], set(), f"artifact {entry.get('path')!r}")
        path = safe_member_path(entry["path"], limits)
        if path in reserved or path in seen:
            raise BundleRefused(f"artifact path {path!r} is reserved or duplicated")
        if not path.startswith(KIND_PREFIX[kind]):
            raise BundleRefused(f"{kind} artifact {path!r} is not under {KIND_PREFIX[kind]}")
        if type(entry["sha256"]) is not str or not _SHA256.match(entry["sha256"]):
            raise BundleRefused(f"artifact {path!r} has a malformed sha256")
        size = entry["size"]
        if type(size) is not int or size < 0 or size > limits.max_member_bytes:
            raise BundleRefused(f"artifact {path!r} declares a refused size {size!r}")
        if entry["mode"] not in MODES:
            raise BundleRefused(f"artifact {path!r} declares a refused mode {entry['mode']!r}")
        if type(entry["source"]) is not str or not entry["source"]:
            raise BundleRefused(f"artifact {path!r} names no source")
        if kind == "wheel":
            _validate_wheel_entry(entry, TARGETS[document["target"]])
        if kind == "deb":
            for key in ("package", "version", "architecture"):
                if type(entry[key]) is not str or not entry[key]:
                    raise BundleRefused(f"deb artifact {path!r} has no {key}")
            if entry["architecture"] not in TARGETS[document["target"]]["deb_architectures"]:
                raise BundleRefused(f"deb artifact {path!r} is for {entry['architecture']!r}")
        seen.add(path)
        kinds_present.add(kind)
        total += size
    if total > limits.max_total_bytes:
        raise BundleRefused(f"manifest declares {total} bytes; the cap is {limits.max_total_bytes}")
    folded: dict[str, str] = {}
    for path in seen:
        other = folded.setdefault(path.casefold(), path)
        if other != path:
            raise BundleRefused(f"artifact paths {other!r} and {path!r} differ only in case")
    for path in seen:
        parts = path.split("/")
        for depth in range(1, len(parts)):
            prefix = "/".join(parts[:depth])
            if prefix in seen or prefix.casefold() in folded:
                raise BundleRefused(
                    f"artifact {prefix!r} is a file and also the directory of {path!r}"
                )
    for kind in REQUIRED_KINDS:
        if kind not in kinds_present:
            raise BundleRefused(f"manifest carries no {kind} artifact")
    for kind in SLOT_KINDS:
        state = slots[kind]
        if state not in SLOT_STATES:
            raise BundleRefused(f"slot {kind} has a refused state {state!r}")
        if (state == "filled") != (kind in kinds_present):
            raise BundleRefused(f"slot {kind} is {state!r} but the artifacts say otherwise")
    if document["totals"] != {"count": len(artifacts), "bytes": total}:
        raise BundleRefused("manifest totals do not match its artifacts")
    if [entry["path"] for entry in artifacts] != sorted(seen):
        raise BundleRefused("manifest artifacts are not in path order")
    wheels = {canonical_name(e["requirement"].partition("==")[0]) for e in artifacts if e["kind"] == "wheel"}
    for own in OWN_DISTRIBUTIONS:
        if own not in wheels:
            raise BundleRefused(f"manifest carries no {own} wheel")
    return document


def _validate_wheel_entry(entry: dict, target: dict) -> None:
    filename = PurePosixPath(entry["path"]).name
    if entry["path"] != KIND_PREFIX["wheel"] + filename:
        raise BundleRefused(f"wheel {entry['path']!r} is not directly under wheels/")
    parts = parse_wheel_name(filename)
    requirement = entry["requirement"]
    match = _REQUIREMENT.match(requirement) if type(requirement) is str else None
    if not match:
        raise BundleRefused(f"wheel {filename!r} has a refused requirement {requirement!r}")
    if canonical_name(match.group("name")) != canonical_name(parts["name"]):
        raise BundleRefused(f"wheel {filename!r} does not carry {requirement!r}")
    if match.group("version") != parts["version"]:
        raise BundleRefused(f"wheel {filename!r} is not version {match.group('version')!r}")
    if not wheel_fits_target(filename, target):
        raise BundleRefused(f"wheel {filename!r} does not fit the declared target")


def manifest_bytes(document: dict) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _json_nesting(text: str) -> int:
    """The deepest bracket nesting outside strings, without recursing."""

    depth = deepest = 0
    in_string = escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif char in "]}":
            depth -= 1
    return deepest


def load_manifest(data: bytes, limits: Limits = DEFAULT_LIMITS) -> dict:
    if len(data) > limits.max_manifest_bytes:
        raise BundleRefused("the manifest is larger than its cap")
    try:
        text = data.decode("utf-8")
        if _json_nesting(text) > MANIFEST_MAX_NESTING:
            raise BundleRefused(f"the manifest nests deeper than {MANIFEST_MAX_NESTING}")
        document = json.loads(text)
    except BundleRefused:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise BundleRefused(f"the manifest is not JSON ({type(exc).__name__})") from exc
    return validate_manifest(document, limits)


def parse_lock(path: Path) -> dict[str, list[str]]:
    """``{"name==version": [sha256, ...]}`` from a pip ``--require-hashes`` file.

    Only ``name==version \\ --hash=sha256:...`` entries are accepted; any other
    requirement form is refused, so the lock cannot quietly widen into a range.
    """

    logical: list[str] = []
    buffer = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        line = stripped if stripped.startswith("--hash") else raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        logical.append(buffer + line)
        buffer = ""
    if buffer:
        raise ValueError(f"{path}: a continuation line has no end")
    pins: dict[str, list[str]] = {}
    for entry in logical:
        tokens = entry.split()
        requirement, hashes = tokens[0], tokens[1:]
        match = _REQUIREMENT.match(requirement)
        if not match or not hashes:
            raise ValueError(f"{path}: {entry!r} is not an exact pin with hashes")
        digests = []
        for token in hashes:
            prefix = "--hash=sha256:"
            if not token.startswith(prefix) or not _SHA256.match(token[len(prefix):]):
                raise ValueError(f"{path}: {token!r} is not a sha256 hash option")
            digests.append(token[len(prefix):])
        name = canonical_name(match.group("name"))
        if any(key.partition("==")[0] == name for key in pins):
            raise ValueError(f"{path}: {name} is pinned twice")
        pins[f"{name}=={match.group('version')}"] = digests
    return pins


def reviewed_pins(root: Path = REVIEWED_ROOT) -> tuple[dict[str, list[str]], dict[str, str]]:
    """The reviewed checkout's third-party lock and its own distributions' versions."""

    import tomllib  # noqa: PLC0415 - stdlib from 3.11, the declared floor

    try:
        lock = parse_lock(root / WHEEL_LOCK)
        versions = {}
        for path in (root / "pyproject.toml", root / "runtime" / "pyproject.toml"):
            project = tomllib.loads(path.read_text(encoding="utf-8"))["project"]
            versions[canonical_name(project["name"])] = project["version"]
    except (OSError, ValueError, KeyError) as exc:
        raise BundleRefused(
            f"the reviewed lock or pyproject could not be read from {root} ({exc}); run this "
            "verifier from a reviewed checkout"
        ) from exc
    return lock, versions


def check_wheels_against_lock(
    document: dict, pins: tuple[dict[str, list[str]], dict[str, str]]
) -> list[dict[str, str]]:
    """Refuse any bundled wheel the reviewed checkout does not pin.

    A third-party wheel must match a lock entry by name, version and sha256.
    The two Nexus wheels must carry the reviewed pyproject versions (an exact
    string compare, deliberately stricter than PEP 440 equivalence: the builder
    takes both from the same pyproject, so a differently spelled equivalent
    version is a different build and is refused); their
    content is built per bundle and is covered only by a future bundle
    signature, not by this check.
    """

    lock, versions = pins
    checked = []
    for entry in document["artifacts"]:
        if entry["kind"] != "wheel":
            continue
        name, _, version = entry["requirement"].partition("==")
        name = canonical_name(name)
        if name in OWN_DISTRIBUTIONS:
            if versions.get(name) != version:
                raise BundleRefused(
                    f"{entry['path']} is {name} {version}; the reviewed checkout builds "
                    f"{versions.get(name)!r}"
                )
            checked.append({"requirement": f"{name}=={version}", "pinned_by": "reviewed pyproject version only"})
            continue
        hashes = lock.get(f"{name}=={version}")
        if hashes is None:
            raise BundleRefused(f"{entry['path']} ({name}=={version}) is not in the reviewed lock")
        if entry["sha256"] not in hashes:
            raise BundleRefused(f"{entry['path']} does not have a sha256 the reviewed lock pins")
        checked.append({"requirement": f"{name}=={version}", "pinned_by": WHEEL_LOCK.as_posix()})
    return checked


def wheel_requirements(document: dict) -> str:
    """A ``--require-hashes`` requirements file naming exactly the bundled wheels."""

    lines = []
    for entry in document["artifacts"]:
        if entry["kind"] == "wheel":
            lines.append(f"{entry['requirement']} --hash=sha256:{entry['sha256']}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Safe extraction.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Extracted:
    root: Path
    manifest: dict
    manifest_bytes: bytes
    signature: Optional[bytes]


def _read_bounded(stream, size: int) -> bytes:
    data = stream.read(size + 1)
    if len(data) != size:
        raise BundleRefused("a member's data does not match its header size")
    return data


def _write_member(staging: Path, path: str, stream, entry: dict) -> None:
    destination = staging.joinpath(*path.split("/"))
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(destination, flags, 0o600)
    digest = hashlib.sha256()
    written = 0
    try:
        while True:
            chunk = stream.read(1 << 20)
            if not chunk:
                break
            written += len(chunk)
            if written > entry["size"]:
                raise BundleRefused(f"member {path!r} is larger than the manifest declares")
            digest.update(chunk)
            _write_all(fd, chunk)
        os.fsync(fd)
        os.fchmod(fd, int(entry["mode"], 8))
    finally:
        os.close(fd)
    if written != entry["size"]:
        raise BundleRefused(f"member {path!r} is {written} bytes; the manifest declares {entry['size']}")
    if digest.hexdigest() != entry["sha256"]:
        raise BundleRefused(f"member {path!r} does not match its manifest sha256")


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _fsync_tree(root: Path) -> None:
    for directory, _dirs, _files in os.walk(root):
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _owner_ok(uid: int) -> bool:
    """Root may trust only root-owned paths; another user, root's or its own."""

    euid = os.geteuid()
    return uid == 0 if euid == 0 else uid in (0, euid)


def _check_destination_parent(parent: Path) -> None:
    info = os.stat(parent)
    shared = info.st_mode & 0o022
    sticky = info.st_mode & stat.S_ISVTX
    if (shared and not sticky) or not _owner_ok(info.st_uid):
        raise BundleRefused(
            f"{parent} is writable by group/others without the sticky bit, or owned by another "
            "user; another account could replace the extracted tree"
        )


def refuse_self_vouching(*trees: Path) -> None:
    """Refuse when the verifier's own checkout is, or is inside, a tree it verifies.

    A bundle's copy of this file and its lock would otherwise vouch for the
    bundle that carried them.
    """

    reviewed = REVIEWED_ROOT.resolve()
    for tree in trees:
        resolved = Path(os.path.abspath(tree)).resolve()
        if reviewed == resolved or resolved in reviewed.parents:
            raise BundleRefused(f"the verifier's checkout {reviewed} is inside {resolved}")
    for ancestor in (reviewed, *reviewed.parents):
        if (ancestor / MANIFEST_NAME).is_file():
            raise BundleRefused(
                f"the verifier runs from inside an extracted bundle ({ancestor}); run it from a "
                "reviewed checkout"
            )


def extract_bundle(archive: Path, destination: Path, *, limits: Limits = DEFAULT_LIMITS) -> Extracted:
    """Extract ``archive`` into ``destination`` atomically, or refuse and leave nothing.

    ``destination`` must not exist. Members are written into a private staging
    directory beside it; the staging directory is renamed to ``destination``
    only after every member was declared, sized and hashed as the manifest
    says and no declared member is missing.
    """

    destination = Path(os.path.abspath(destination))
    if os.path.lexists(destination):
        raise BundleRefused(f"{destination} already exists; extraction never merges into a tree")
    parent = destination.parent
    if not parent.is_dir() or parent.is_symlink():
        raise BundleRefused(f"{parent} is not a directory")
    _check_destination_parent(parent)
    _remove_stale_staging(parent, destination.name)
    info = os.lstat(archive)
    if not stat.S_ISREG(info.st_mode):
        raise BundleRefused(f"{archive} is not a regular file")
    if info.st_size > limits.max_total_bytes + limits.max_manifest_bytes + (64 << 20):
        raise BundleRefused(f"{archive} is larger than the extraction cap")

    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.staging-{os.getpid()}-", dir=parent))
    try:
        result = _extract_into(archive, staging, limits)
        _fsync_tree(staging)
        if os.path.lexists(destination):
            raise BundleRefused(f"{destination} appeared during extraction")
        os.rename(staging, destination)
        fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return dataclasses.replace(result, root=destination)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _remove_stale_staging(parent: Path, name: str) -> None:
    """Remove staging directories a killed earlier run left beside the destination.

    A staging name records the pid of the run that made it
    (``.<name>.staging-<pid>-<random>``). Only real directories owned by this
    user whose recorded process no longer exists are removed, so a concurrent
    run's staging, a symlink, or another user's entry is left alone.
    """

    prefix = f".{name}.staging-"
    for entry in os.scandir(parent):
        if not entry.name.startswith(prefix):
            continue
        pid_text, sep, token = entry.name[len(prefix):].partition("-")
        if not sep or not token or not pid_text.isdigit():
            continue
        pid = int(pid_text)
        if pid == os.getpid() or _pid_alive(pid):
            continue
        info = entry.stat(follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid():
            shutil.rmtree(entry.path, ignore_errors=True)


def _check_capacity(archive: Path, staging: Path, document: dict, limits: Limits) -> None:
    declared = document["totals"]["bytes"]
    archive_size = max(os.stat(archive).st_size, 1)
    if declared > archive_size * limits.max_ratio:
        raise BundleRefused(
            f"the manifest declares {declared} bytes from a {archive_size}-byte archive; "
            f"the ratio cap is {limits.max_ratio}"
        )
    fs = os.statvfs(staging)
    free = fs.f_bavail * fs.f_frsize
    needed = declared + limits.max_manifest_bytes + FREE_SPACE_MARGIN_BYTES
    if free < needed:
        raise BundleRefused(f"{staging.parent} has {free} bytes free; extraction needs {needed}")


def _stream_cap(limits: Limits, members: int, payload: int) -> int:
    """Decompressed bytes a well-formed bundle can need: payload, headers, padding, end."""

    return payload + limits.max_manifest_bytes + SIGNATURE_MAX_BYTES + 2 * BLOCK * (members + 3) + 20 * BLOCK


def _extract_into(archive: Path, staging: Path, limits: Limits) -> Extracted:
    try:
        with open(archive, "rb") as raw:
            stream = _Gunzip(raw, _stream_cap(limits, limits.max_members, limits.max_total_bytes))
            first = read_tar_header(stream, strict=True)
            if first is None:
                raise BundleRefused(f"the first member is not {MANIFEST_NAME}")
            refusal = type_refusal(first, (b"0",))
            if refusal:
                raise BundleRefused(refusal)
            if first.name != MANIFEST_NAME:
                raise BundleRefused(f"the first member is not {MANIFEST_NAME}")
            if first.size > limits.max_manifest_bytes:
                raise BundleRefused("the manifest is larger than its cap")
            raw_manifest = _read_bounded(_Body(stream, first.size), first.size)
            document = load_manifest(raw_manifest, limits)
            _check_capacity(archive, staging, document, limits)
            stream.cap = _stream_cap(limits, document["totals"]["count"], document["totals"]["bytes"])
            declared = {entry["path"]: entry for entry in document["artifacts"]}
            seen: set[str] = set()
            signature: Optional[bytes] = None
            count = 1
            total = 0
            while True:
                header = read_tar_header(stream, strict=True)
                if header is None:
                    read_end_of_archive(stream)
                    break
                count += 1
                if count > limits.max_members + 2:
                    raise BundleRefused(f"the archive has more than {limits.max_members} members")
                refusal = type_refusal(header, (b"0",))
                if refusal:
                    raise BundleRefused(refusal)
                name = safe_member_path(header.name, limits)
                body = _Body(stream, header.size)
                if name == SIGNATURE_NAME:
                    if signature is not None or seen or header.size > SIGNATURE_MAX_BYTES:
                        raise BundleRefused(f"{SIGNATURE_NAME} is duplicated, misplaced or too large")
                    signature = _read_bounded(body, header.size)
                    continue
                if name not in declared:
                    raise BundleRefused(f"member {name!r} is not declared in the manifest")
                if name in seen:
                    raise BundleRefused(f"member {name!r} appears twice")
                entry = declared[name]
                if header.size != entry["size"]:
                    raise BundleRefused(
                        f"member {name!r} is {header.size} bytes; the manifest declares {entry['size']}"
                    )
                total += header.size
                if total > limits.max_total_bytes:
                    raise BundleRefused(f"the archive exceeds {limits.max_total_bytes} bytes")
                _write_member(staging, name, body, entry)
                body.skip()
                seen.add(name)
            missing = sorted(set(declared) - seen)
            if missing:
                raise BundleRefused(f"declared members are missing from the archive: {missing[:5]}")
    except BundleRefused:
        raise
    except (OSError, EOFError, ValueError, zlib.error, RecursionError, MemoryError) as exc:
        raise BundleRefused(f"the archive could not be read ({type(exc).__name__}: {exc})") from exc
    (staging / MANIFEST_NAME).write_bytes(raw_manifest)
    os.chmod(staging / MANIFEST_NAME, 0o644)
    return Extracted(root=staging, manifest=document, manifest_bytes=raw_manifest, signature=signature)


# --------------------------------------------------------------------------
# Slot verification.
# --------------------------------------------------------------------------


def _edge_package_module():
    """The reviewed ``azazel_nexus.edge_package`` beside this file (stdlib-only)."""

    source = str(Path(__file__).resolve().parents[1] / "src")
    if source not in sys.path:
        sys.path.insert(0, source)
    from azazel_nexus import edge_package  # noqa: PLC0415

    return edge_package


def verify_edge_slot(directory: Path) -> dict[str, Any]:
    """Run the existing Edge package checks over a carried Edge package.

    Requires ``package_present``, ``version_matches`` and ``digest_matches`` to
    pass and the manifest's bound-component digests to match the archive.
    Health and running are not observable from a medium and stay
    ``not-checked``; nothing here makes the package admitted or ready.
    """

    edge = _edge_package_module()
    names = sorted(p.name for p in directory.iterdir()) if directory.is_dir() else []
    expected = sorted((edge.PIN.manifest_name, edge.PIN.artifact_name))
    if names != expected:
        raise BundleRefused(f"the Edge slot holds {names}; it must hold exactly {expected}")
    inspection = edge.inspect(directory)
    findings = {f.check: f for f in inspection.findings}
    for check in ("package_present", "version_matches", "digest_matches"):
        finding = findings[check]
        if finding.evidence is not edge.Evidence.PASSED:
            raise BundleRefused(f"Edge {check} is {finding.evidence.value}: {finding.reason}")
    try:
        with open(directory / edge.PIN.artifact_name, "rb") as raw:
            # Refuses every tar extension before edge_package reads the same
            # bytes with tarfile, so its header processing sees plain members only.
            scan_nested_tar(_Gunzip(raw, EDGE_ARCHIVE_MAX_UNPACKED))
    except BundleRefused as exc:
        raise BundleRefused(f"the Edge archive is refused: {exc}") from exc
    except (OSError, EOFError, ValueError, zlib.error) as exc:
        raise BundleRefused(f"the Edge archive could not be read ({type(exc).__name__}: {exc})") from exc
    manifest = json.loads((directory / edge.PIN.manifest_name).read_text(encoding="utf-8"))
    try:
        declared = edge._manifest_components(manifest)
        archived = edge._archive_components((directory / edge.PIN.artifact_name).read_bytes())
    except edge.EdgePackageRefused as exc:
        raise BundleRefused(f"Edge components: {exc}") from exc
    if declared != archived:
        raise BundleRefused("the Edge archive's bound components do not match its manifest")
    return {
        "state": "verified-integrity",
        "checks": {check: findings[check].evidence.value for check in edge.CHECKS},
        "caveat": edge.UNSIGNED_CAVEAT,
        "admitted": False,
    }


EDGE_ARCHIVE_MAX_UNPACKED = 2 << 30
_AR_MAGIC = b"!<arch>\n"
_CONTROL_MAX_BYTES = 16 << 20


def deb_control_fields(path: Path) -> dict[str, str]:
    """Package/Version/Architecture from a .deb's control file, read with bounds."""

    with open(path, "rb") as stream:
        if stream.read(8) != _AR_MAGIC:
            raise BundleRefused(f"{path.name} is not an ar archive")
        index = 0
        control: Optional[tuple[str, bytes]] = None
        while control is None:
            header = stream.read(60)
            if len(header) != 60 or header[58:60] != b"`\n":
                raise BundleRefused(f"{path.name} has a malformed ar header")
            name = header[0:16].decode("ascii", "replace").strip().rstrip("/")
            try:
                size = int(header[48:58].decode("ascii").strip())
            except ValueError as exc:
                raise BundleRefused(f"{path.name} has a malformed ar member size") from exc
            if index == 0:
                if name != "debian-binary" or size > 64 or stream.read(size).strip() != b"2.0":
                    raise BundleRefused(f"{path.name} is not a format 2.0 Debian package")
            elif name.startswith("control.tar"):
                if size > _CONTROL_MAX_BYTES:
                    raise BundleRefused(f"{path.name} has an oversized control archive")
                control = (name, stream.read(size))
            elif index > 2:
                raise BundleRefused(f"{path.name} has no control archive")
            else:
                stream.seek(size, os.SEEK_CUR)
            if size % 2 and control is None:
                stream.seek(1, os.SEEK_CUR)
            index += 1
    name, data = control
    try:
        if name == "control.tar.gz":
            stream = _Gunzip(io.BytesIO(data), _CONTROL_MAX_BYTES)
        elif name == "control.tar.xz":
            decompressor = lzma.LZMADecompressor(memlimit=64 << 20)
            data = decompressor.decompress(data, max_length=_CONTROL_MAX_BYTES + 1)
            if len(data) > _CONTROL_MAX_BYTES:
                raise BundleRefused(f"{path.name} has an oversized control archive")
            stream = _Plain(data)
        elif name == "control.tar":
            stream = _Plain(data)
        else:
            raise BundleRefused(f"{path.name} uses {name}; this verifier cannot read it")
        found = scan_nested_tar(stream, want=frozenset({"control"}))
        text = found["control"].decode("utf-8") if "control" in found else None
    except BundleRefused:
        raise
    except (OSError, EOFError, ValueError, lzma.LZMAError, zlib.error, UnicodeDecodeError) as exc:
        raise BundleRefused(f"{path.name} control archive could not be read ({exc})") from exc
    if text is None:
        raise BundleRefused(f"{path.name} has no control file")
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if line[:1] in (" ", "\t") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        if key in ("Package", "Version", "Architecture"):
            fields[key.lower()] = value.strip()
    if set(fields) != {"package", "version", "architecture"}:
        raise BundleRefused(f"{path.name} control lacks Package/Version/Architecture")
    return fields


def verify_deb_slot(root: Path, document: dict) -> dict[str, Any]:
    packages = []
    for entry in document["artifacts"]:
        if entry["kind"] != "deb":
            continue
        fields = deb_control_fields(root.joinpath(*entry["path"].split("/")))
        declared = {key: entry[key] for key in ("package", "version", "architecture")}
        if fields != declared:
            raise BundleRefused(f"{entry['path']} control says {fields}; the manifest says {declared}")
        packages.append({**declared, "source": entry["source"]})
    return {
        "state": "verified-integrity",
        "packages": packages,
        "installed": False,
        "note": "carried and checked against the manifest only; the apt source is not authenticated here",
    }


def verify_extracted(
    extracted: Extracted,
    *,
    pins: Optional[tuple[dict[str, list[str]], dict[str, str]]] = None,
) -> dict[str, Any]:
    """Wheel-lock and slot checks over an extracted tree; the report the installer prints."""

    document = extracted.manifest
    root = extracted.root
    wheels = check_wheels_against_lock(document, reviewed_pins() if pins is None else pins)
    slots: dict[str, Any] = {}
    if document["slots"]["edge-package"] == "filled":
        slots["edge-package"] = verify_edge_slot(root / "edge")
    else:
        slots["edge-package"] = {"state": "empty"}
    if document["slots"]["deb"] == "filled":
        slots["deb"] = verify_deb_slot(root, document)
    else:
        slots["deb"] = {"state": "empty"}
    for kind in ("model", "knowledge"):
        carried = [e["path"] for e in document["artifacts"] if e["kind"] == kind]
        slots[kind] = (
            {"state": "carried", "files": carried, "admitted": False}
            if carried
            else {"state": "empty"}
        )
    verdict = verify_bundle_signature(extracted.manifest_bytes, extracted.signature)
    return {
        "schema": "azazel-nexus-offline-bundle-report@1",
        "target": document["target"],
        "manifest_sha256": hashlib.sha256(extracted.manifest_bytes).hexdigest(),
        "integrity": "every declared member matched its manifest size and sha256",
        "bundle_authenticated": verdict.authenticated,
        "signature": {"present": verdict.signature_present, "reason": verdict.reason},
        "counts": {kind: sum(1 for e in document["artifacts"] if e["kind"] == kind) for kind in KIND_PREFIX},
        "wheels": wheels,
        "own_wheels": OWN_WHEELS_NOTE,
        "slots": slots,
    }


OWN_WHEELS_NOTE = (
    "azazel-nexus and azazel-nexus-runtime are pinned by version only (exact string match "
    "against the reviewed pyproject files); their content is built per bundle and is "
    "unauthenticated until bundle signing exists"
)


def extract_and_verify(
    bundle: Path,
    into: Path,
    *,
    limits: Limits = DEFAULT_LIMITS,
    pins: Optional[tuple[dict[str, list[str]], dict[str, str]]] = None,
) -> tuple[Extracted, dict[str, Any]]:
    """Extract, then verify; a tree that fails verification is removed, not left."""

    refuse_self_vouching(into)
    extracted = extract_bundle(bundle, into, limits=limits)
    try:
        return extracted, verify_extracted(extracted, pins=pins)
    except BaseException:
        shutil.rmtree(extracted.root, ignore_errors=True)
        raise


def _check_owned_tree(root: Path, *, allow_links: bool) -> None:
    for directory, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames + [""]:
            path = os.path.join(directory, name) if name else directory
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode):
                if not allow_links:
                    raise BundleRefused(f"{path} is a link")
                if not _owner_ok(info.st_uid):
                    raise BundleRefused(f"{path} is owned by another user")
                continue
            if not _owner_ok(info.st_uid) or info.st_mode & 0o022:
                raise BundleRefused(f"{path} is owned by another user or writable by group/others")
            if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
                raise BundleRefused(f"{path} has {info.st_nlink} hard links")


def recheck_tree(
    root: Path,
    *,
    expected_manifest_sha256: str,
    limits: Limits = DEFAULT_LIMITS,
    pins: Optional[tuple[dict[str, list[str]], dict[str, str]]] = None,
) -> dict[str, Any]:
    """Re-verify an extracted tree immediately before the privileged step.

    ``expected_manifest_sha256`` is the value extraction reported; the
    in-tree ``MANIFEST.json`` is compared against it rather than trusted. The
    wheel lock check runs again, every file is re-hashed, and the tree may
    hold no link, no hard-linked file, nothing undeclared or missing, and
    nothing group/other-writable or owned by another user -- by anyone but
    root when run as root. Integrity against an unsigned manifest only.
    """

    root = Path(os.path.abspath(root))
    refuse_self_vouching(root)
    if type(expected_manifest_sha256) is not str or not _SHA256.match(expected_manifest_sha256):
        raise BundleRefused("--expect-manifest-sha256 must be the 64-hex value extraction reported")
    _check_owned_tree(root, allow_links=False)
    manifest_path = root / MANIFEST_NAME
    if os.lstat(manifest_path).st_size > limits.max_manifest_bytes:
        raise BundleRefused("the manifest is larger than its cap")
    raw = manifest_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_manifest_sha256:
        raise BundleRefused("MANIFEST.json is not the manifest extraction verified")
    document = load_manifest(raw, limits)
    check_wheels_against_lock(document, reviewed_pins() if pins is None else pins)
    declared = {entry["path"]: entry for entry in document["artifacts"]}
    found: set[str] = set()
    for directory, _dirnames, filenames in os.walk(root):
        for name in filenames:
            relative = os.path.relpath(os.path.join(directory, name), root).replace(os.sep, "/")
            if relative == MANIFEST_NAME:
                continue
            entry = declared.get(relative)
            if entry is None:
                raise BundleRefused(f"{relative} is not declared in the manifest")
            digest = hashlib.sha256()
            with open(os.path.join(directory, name), "rb") as stream:
                while chunk := stream.read(1 << 20):
                    digest.update(chunk)
            if digest.hexdigest() != entry["sha256"]:
                raise BundleRefused(f"{relative} no longer matches its manifest sha256")
            found.add(relative)
    missing = sorted(set(declared) - found)
    if missing:
        raise BundleRefused(f"declared files are missing from the tree: {missing[:5]}")
    return {
        "recheck": "pass",
        "files": len(found),
        "manifest_sha256": expected_manifest_sha256,
        "own_wheels": OWN_WHEELS_NOTE,
        "bundle_authenticated": False,
    }


# --------------------------------------------------------------------------
# Offline install of the two distributions.
# --------------------------------------------------------------------------


_FIXED_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
              "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INPUT": "1"}
#: The only installer options ``install --run-installer`` passes through.
INSTALLER_OPTIONS = ("--without-service-manager", "--without-accounts")


def _run(argv: list[str]) -> None:
    result = subprocess.run(argv, env=_FIXED_ENV, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise BundleRefused(
            f"{' '.join(argv[:4])} ... exited {result.returncode}: {result.stderr.strip()[-2000:]}"
        )


def pip_install_offline(python: Path, wheels: Path, requirements: Path) -> None:
    """``pip install`` with no index, only the given wheels, and every hash required."""

    _run([
        str(python), "-I", "-m", "pip", "install",
        "--no-index", "--find-links", str(wheels),
        "--require-hashes", "--only-binary=:all:", "--no-cache-dir",
        "--disable-pip-version-check", "-r", str(requirements),
    ])


def _require_root() -> None:
    if os.geteuid() != 0:
        raise BundleRefused(
            "install runs as root, so the extracted tree, the venv and everything install.sh "
            "later runs are root-owned and no unprivileged account can change them in between"
        )


def install(
    bundle: Path,
    into: Path,
    venv: Path,
    python: Path,
    *,
    limits: Limits = DEFAULT_LIMITS,
    pins: Optional[tuple[dict[str, list[str]], dict[str, str]]] = None,
    run_installer: bool = False,
    installer_options: tuple[str, ...] = (),
) -> dict:
    """Extract, verify and install offline as root; optionally run install.sh last.

    The sequence is: extract (root-owned staging, atomic rename) -> verify
    (lock, slots) -> fresh root-owned venv -> ``pip --no-index
    --require-hashes`` -> ``pip check`` and imports -> recheck of the tree
    against the manifest sha256 extraction reported, and of the venv's
    ownership -> ``install.sh`` (only with ``run_installer``). On any refusal
    before ``install.sh`` the extracted tree and the venv are removed.
    """

    _require_root()
    for option in installer_options:
        if option not in INSTALLER_OPTIONS:
            raise BundleRefused(f"installer option {option!r} is not one of {list(INSTALLER_OPTIONS)}")
    if os.path.lexists(venv):
        raise BundleRefused(f"{venv} already exists; the offline install creates a fresh venv")
    venv_parent = Path(os.path.abspath(venv)).parent
    if not venv_parent.is_dir():
        raise BundleRefused(f"{venv_parent} is not a directory")
    _check_destination_parent(venv_parent)
    extracted, report = extract_and_verify(bundle, into, limits=limits, pins=pins)
    try:
        _install_verified(extracted, report, into, venv, python)
        report["recheck"] = recheck_tree(
            into, expected_manifest_sha256=report["manifest_sha256"], limits=limits, pins=pins
        )
        _check_owned_tree(venv, allow_links=True)
    except BaseException:
        shutil.rmtree(venv, ignore_errors=True)
        shutil.rmtree(into, ignore_errors=True)
        raise
    venv_python = venv / "bin" / "python"
    installer = into / "source" / "packaging" / "install.sh"
    if not run_installer:
        report["install"]["next"] = [
            f"sudo python3 -I {Path(__file__).resolve()} recheck --tree {into} "
            f"--expect-manifest-sha256 {report['manifest_sha256']}",
            f"sudo env PYTHON={venv_python} sh {installer}",
        ]
        return report
    result = subprocess.run(
        ["/bin/sh", str(installer), *installer_options],
        env={**_FIXED_ENV, "PYTHON": str(venv_python)},
        cwd=str(into / "source"), capture_output=True, text=True, check=False,
    )
    report["installer"] = {
        "command": ["/bin/sh", str(installer), *installer_options],
        "exit": result.returncode,
        "stdout_tail": result.stdout.strip().splitlines()[-8:],
        "stderr_tail": result.stderr.strip().splitlines()[-8:],
    }
    if result.returncode != 0:
        raise BundleRefused(
            f"install.sh exited {result.returncode}; the host may be partly changed, and the "
            f"tree and venv are kept for inspection: {result.stderr.strip()[-1000:]}"
        )
    return report


def _install_verified(extracted: Extracted, report: dict, into: Path, venv: Path, python: Path) -> None:
    target = TARGETS[extracted.manifest["target"]]
    probe = subprocess.run(
        [str(python), "-I", "-c",
         "import platform, sys; print(platform.machine(), sys.implementation.name, *sys.version_info[:2])"],
        env=_FIXED_ENV, capture_output=True, text=True, check=False,
    )
    expected = f"{target['architecture']} cpython {target['python_version'][0]} {target['python_version'][1]}"
    if probe.returncode != 0 or probe.stdout.strip() != expected:
        raise BundleRefused(
            f"{python} reports {probe.stdout.strip()!r}; the bundle targets {expected!r}"
        )
    _run([str(python), "-I", "-m", "venv", str(venv)])
    venv_python = venv / "bin" / "python"
    with tempfile.TemporaryDirectory(prefix="azazel-offline-req-") as scratch:
        requirements = Path(scratch) / "wheels.requirements.txt"
        requirements.write_text(wheel_requirements(extracted.manifest), encoding="utf-8")
        pip_install_offline(venv_python, into / "wheels", requirements)
    _run([str(venv_python), "-I", "-m", "pip", "check", "--disable-pip-version-check"])
    _run([str(venv_python), "-I", "-c",
          "import azazel_nexus, azazel_nexus_runtime, azazel_nexus_runtime._bootstrap_deadline, "
          "yaml, dbus_next"])
    report["install"] = {
        "venv": str(venv),
        "distributions": sorted(
            e["requirement"] for e in extracted.manifest["artifacts"] if e["kind"] == "wheel"
        ),
        "pip": "--no-index --find-links --require-hashes --only-binary=:all:",
        "pip_check": "pass",
        "imports": "pass",
        "not_done": "accounts, units and activation are packaging/install.sh's and the operator's steps",
    }


# --------------------------------------------------------------------------
# CLI.
# --------------------------------------------------------------------------


def _limits_from(args: argparse.Namespace) -> Limits:
    overrides = {
        key: getattr(args, key)
        for key in ("max_members", "max_total_bytes")
        if getattr(args, key) is not None
    }
    return DEFAULT_LIMITS.tighter(**overrides) if overrides else DEFAULT_LIMITS


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    recheck = sub.add_parser("recheck", help="re-verify an extracted tree right before install.sh")
    recheck.add_argument("--tree", required=True, type=Path)
    recheck.add_argument("--expect-manifest-sha256", required=True,
                         help="the manifest_sha256 that extraction reported")
    for name in ("verify", "install"):
        command = sub.add_parser(name)
        command.add_argument("--bundle", required=True, type=Path)
        command.add_argument("--into", required=True, type=Path,
                             help="destination directory; must not exist")
        command.add_argument("--max-members", type=int)
        command.add_argument("--max-total-bytes", type=int)
        if name == "install":
            command.add_argument("--venv", required=True, type=Path)
            command.add_argument("--python", type=Path, default=Path("/usr/bin/python3"))
            command.add_argument("--run-installer", action="store_true",
                                 help="run packaging/install.sh after the final recheck")
            command.add_argument("--installer-option", action="append", default=[],
                                 choices=INSTALLER_OPTIONS)
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "recheck":
            report = recheck_tree(args.tree, expected_manifest_sha256=args.expect_manifest_sha256)
        else:
            limits = _limits_from(args)
            if args.command == "verify":
                report = extract_and_verify(args.bundle, args.into, limits=limits)[1]
            else:
                report = install(args.bundle, args.into, args.venv, args.python, limits=limits,
                                 run_installer=args.run_installer,
                                 installer_options=tuple(args.installer_option))
    except Exception as exc:  # noqa: BLE001 - every failure is a refusal, never a traceback
        reason = str(exc) if isinstance(exc, BundleRefused) else f"{type(exc).__name__}: {exc}"
        print(json.dumps({"refused": reason, "bundle_authenticated": False}), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
