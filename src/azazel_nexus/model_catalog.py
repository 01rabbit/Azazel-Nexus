"""What may be offered as a model, and what offering one does not mean (#94).

`docs/mio-route-policy.md` and [Nexus
#93](https://github.com/01rabbit/Azazel-Nexus/issues/93). This module fixes
the safety boundary the rest of the installer series stands on, so it comes
first: #95 imports against this contract, #96 acquires against it, #97 runs
against it, and #99 displays it.

It declares. **Nothing here fetches, unpacks, or runs anything.**

## Four states, and none of them is `available`

The distinction this module exists to keep is the one it would be easiest to
collapse:

| state | means |
| --- | --- |
| `ABSENT` | no catalog on this node. Nobody has said what may be offered |
| `EMPTY` | a valid, signed catalog that offers nothing |
| `DECLARED` | the catalog offers this model and **no artifact is present** |
| `PRESENT` | an artifact is present and verifies against its declaration |

`PRESENT` is **not** admitted, not running, and not usable. A model that is
on disk and verifies is a model that has passed the checks this module can
make — and every admission gate is still ahead of it, the resource gate among
them, which refuses while the Core reserve is unmeasured (`HG-05`).

"A catalog exists", "a model can be brought in", "it could be executed" and
"it is actually serving as a provider" are four different facts. One
`available` for all four would be the word an operator fills in from hope.

## Declared resource conditions are for display, never for admission

`declared_min_ram_mib` and `declared_min_disk_mib` come from whoever wrote the
catalog. They are useful for showing an operator which entries are plausible
and for refusing an obviously impossible one **before** a multi-gigabyte
import. They are **not evidence that a model fits**:

    an implementation MUST NOT treat the selected profile as evidence
    that a capability fits
    -- docs/capability-model.md §2

Whether a model fits is decided against a **measured** Core reserve
(`core_reserve.py`), which no node in this build has.

## An artifact is weights, not a program

`KNOWN_FORMATS` is an allowlist of weight formats. An artifact that begins
with the magic of an executable or an archive is **refused**, because an
archive is a thing that unpacks and an executable is a thing that runs, and
this module's whole contract is that a model artifact does neither.

Execution belongs to a separately distributed, fixed-allowlist runtime
(#97). Nothing in this file starts a process, and nothing in it names a
command.

## Three signing targets, three roles, never confused

The catalog, the artifact and the runtime binary are signed for different
purposes by different roles, so the **signing target carries a domain tag**
and the catalog's signer must hold the catalog role.

Without a tag, safety rests on two schemas never overlapping — and that is a
coincidence, not a design (the same finding recorded for the revocation list
in [#85](https://github.com/01rabbit/Azazel-Nexus/issues/85)). The tag is
fixed, versioned, canonical, and prefixed to the signed bytes.

## Symbolic IDs only

An operator picks a `model_id` **from a verified catalog**. No free-text
model name, no provider name, no URL, no path. A selector that accepted a
string would be a selector that could name anything the string could name.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .resource_profile import ResourceProfile
from .signature import SIGNATURE_BYTES, SignatureRefused, verify_detached

__all__ = [
    "CATALOG_DOMAIN",
    "CATALOG_FILENAME",
    "CATALOG_SCHEMA",
    "CatalogRefused",
    "CatalogState",
    "KNOWN_FORMATS",
    "KNOWN_RUNTIME_ABIS",
    "MAX_CATALOG_BYTES",
    "MAX_ENTRIES",
    "ModelEntry",
    "ModelReading",
    "ModelCatalog",
    "Refusal",
    "absent_reading",
    "artifact_filename",
    "catalog_payload",
    "read_catalog",
    "verify_artifact",
]

#: The bytes prefixed to a catalog's signing target. Fixed, versioned and
#: fixed-length, so the boundary between tag and payload cannot be argued
#: about -- and so a signature over a manifest, a revocation list or a runtime
#: binary can never be read as a signature over a catalog.
#:
#: **What this version number means.** The domain names two things and only
#: two: the *kind* of signing target -- a model catalog, as distinct from a
#: manifest, a revocation list or a runtime binary -- and the canonical
#: signing protocol by which a payload becomes signed bytes.
#:
#: It moves when, and only when, one of three things changes:
#:
#: 1. the kind of thing being signed,
#: 2. the canonicalisation (how a document becomes the bytes under the
#:    signature),
#: 3. what cross-protocol separation has to mean -- a new sibling protocol a
#:    catalog signature must not be confused with.
#:
#: It does **not** move because the payload grew a field. Adding `source_id`
#: (#96) changed the shape, not the kind and not the protocol, so
#: `CATALOG_SCHEMA` moved and this did not. Bumping the domain for every
#: shape change would make each one a new signing role, and roles are what
#: this tag exists to keep few and stable -- a store full of one-version
#: roles is a store where nothing is reused and every rotation is a
#: migration.
CATALOG_DOMAIN = b"azazel-nexus/model-catalog/v1\x00"

#: The signed file: 64 bytes of detached signature, then the payload exactly
#: as it was signed. One file, one atomic replace, and no canonicalisation
#: step the signer and the verifier could disagree about.
CATALOG_FILENAME = "catalog.signed"

#: The document shape, and nothing else. `/3` adds signed model role; `/2`
#: remains readable with its original generative semantics. Moved to `/2` when `source_id` was
#: added (#96): a required field changes what the document *is*, and a reader
#: that accepted a `/1` document under `/2` rules would be inferring a field
#: nobody wrote.
#:
#: The two version numbers are not the same number. See `CATALOG_DOMAIN` for
#: what that one means and when it moves.
#:
#: **Verification checks all three**, and a catalog is accepted only when
#: every one of them holds:
#:
#: | what | checked against | failing it means |
#: | --- | --- | --- |
#: | domain | `CATALOG_DOMAIN`, prefixed before verifying | a signature for another kind of thing, or another protocol |
#: | schema version | this constant, exactly | a shape this reader does not know |
#: | canonical bytes | the signature, over domain + payload as received | the bytes are not what was signed |
#:
#: An unknown schema is **refused**, never best-effort parsed. A reader that
#: guesses at a shape it does not know is a reader that accepts a document
#: nobody wrote for it.
CATALOG_SCHEMA = "azazel-nexus/model-catalog/3"
LEGACY_CATALOG_SCHEMA = "azazel-nexus/model-catalog/2"

#: A ceiling before parsing. A catalog is a list of declarations, not content.
MAX_CATALOG_BYTES = 1024 * 1024
MAX_ENTRIES = 64

#: Weight formats, allowlisted. Anything else is refused rather than guessed
#: at: a format nobody enumerated is a format nobody decided to support.
KNOWN_FORMATS = ("gguf", "safetensors")

#: Runtime ABIs this build knows how to talk about. Declaring one the node
#: does not know is refused -- #97 owns what can actually run.
KNOWN_RUNTIME_ABIS = ("llama.cpp/1", "onnxruntime/1")

#: Leading bytes that mean "this is a program or an archive". A model
#: artifact is neither, so an artifact beginning with one of these is refused
#: before its digest is even interesting.
_EXECUTABLE_OR_ARCHIVE_MAGIC = (
    (b"\x7fELF", "an ELF executable"),
    (b"MZ", "a PE executable"),
    (b"#!", "a script with an interpreter line"),
    (b"PK\x03\x04", "a zip archive"),
    (b"\x1f\x8b", "a gzip stream"),
    (b"ustar", "a tar archive"),
    (b"\xfd7zXZ\x00", "an xz stream"),
    (b"BZh", "a bzip2 archive"),
    (b"\x04\x22\x4d\x18", "an lz4 frame"),
    (b"\x28\xb5\x2f\xfd", "a zstd frame"),
)

#: A model id names an entry, never a location. Lower-case, no separators a
#: filesystem would read, and bounded.
_MODEL_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
#: A source symbol. No dot, no slash, no colon -- nothing a URL or a
#: path could be built from, so a symbol cannot be mistaken for a location.
_SOURCE_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")


class CatalogRefused(Exception):
    """A catalog or artifact that cannot be believed. Refused, never repaired."""


class Refusal(str, Enum):
    """Why something was refused. One named cause, never a flag."""

    CATALOG_ABSENT = "no catalog is present"
    CATALOG_UNSIGNED = "the catalog is not signed by a catalog-role key"
    CATALOG_INVALID = "the catalog cannot be read"
    UNKNOWN_MODEL = "no entry in the catalog names this model"
    UNKNOWN_FORMAT = "the entry declares a format this build does not know"
    UNKNOWN_RUNTIME_ABI = "the entry declares a runtime ABI this build does not know"
    UNDEFINED_PROFILE = "the entry declares a resource profile that does not exist"
    STALE_ROLLBACK_LINEAGE = "the entry's rollback lineage is older than what is installed"
    LICENSE_NOT_ACKNOWLEDGED = "the licence has not been acknowledged by an operator"
    ARTIFACT_ABSENT = "no artifact is present for this entry"
    SIZE_MISMATCH = "the artifact is not the size the catalog declares"
    DIGEST_MISMATCH = "the artifact is not the content the catalog declares"
    NOT_WEIGHTS = "the artifact is a program or an archive, not model weights"
    PATH_TRAVERSAL = "the entry names a location rather than a model"


class CatalogState(str, Enum):
    """What this node has, in four words that are not one word.

    **There is deliberately no `AVAILABLE`.** "A catalog exists", "a model can
    be brought in", "it could be executed" and "it is serving as a provider"
    are four facts, and a single word for them is one an operator fills in
    from hope.
    """

    ABSENT = "absent"
    EMPTY = "empty"
    DECLARED = "declared"
    PRESENT = "present"


@dataclass(frozen=True)
class ModelEntry:
    """One model the catalog offers. A declaration, never a measurement."""

    model_id: str
    format: str
    digest: str
    size_bytes: int
    provenance: str
    license_acknowledgement_required: bool
    runtime_abi: str
    purpose: str
    context_limit: int
    #: Declared by whoever wrote the catalog. For display and for refusing an
    #: obviously impossible entry before a multi-gigabyte import -- **never**
    #: evidence that the model fits (`capability-model.md` §2).
    declared_min_ram_mib: int
    declared_min_disk_mib: int
    #: The smallest profile the author says this runs on. Not a grant.
    declared_profile: ResourceProfile
    #: Generations this one may replace. An entry that cannot name its
    #: predecessors cannot be rolled back to safely.
    rollback_lineage: tuple[str, ...]
    #: Which acquisition source, **by symbol**, the catalog permits for this
    #: model -- or `None`, meaning no online source is permitted and the only
    #: route in is an operator's offline import.
    #:
    #: A symbol, never a location. If a catalog could carry the endpoint, a
    #: catalog signature would become a way to point a node at any host on
    #: the internet, and the signer would hold that power over every node
    #: their catalog reaches. The symbol resolves against a table fixed in
    #: the build, so the most a catalog can do is **choose among sources this
    #: build already knows** -- the discipline `remote_trust` holds for
    #: endpoints, applied one layer up.
    #:
    #: The field is required in the document and may be `null`. Required so
    #: that "no online source" is something a catalog author stated rather
    #: than forgot; nullable because most entries will honestly have none.
    #:
    #: **`null` means: this artifact has no source usable for online
    #: acquisition.** It is a terminal answer, not a gap to be filled:
    #:
    #: - it is **not** a slot for an endpoint to be supplied later, by an
    #:   operator, a configuration file, an argument or another document;
    #: - it is **not** an instruction to look for a fallback source, a
    #:   default source, or the source of some other entry.
    #:
    #: An offline import of such an artifact is permitted and ordinary. An
    #: online acquisition plan for it is refused as
    #: `model_acquisition.Refusal.SOURCE_UNAVAILABLE`, and no other source is
    #: consulted -- because a `null` that fell back to something would be a
    #: way to acquire from a source this entry never named.
    source_id: Optional[str] = None
    role: str = "generative"

    def __post_init__(self) -> None:
        if self.role not in ("embedding", "generative"):
            raise CatalogRefused("model role must be embedding or generative")
        if not _MODEL_ID.fullmatch(self.model_id):
            raise CatalogRefused(
                f"{self.model_id!r} is not a model id. An id names an entry, "
                "never a location, so separators a filesystem would read are "
                "refused rather than sanitised"
            )
        if self.format not in KNOWN_FORMATS:
            raise CatalogRefused(
                f"{self.model_id}: format {self.format!r} is not one of "
                f"{KNOWN_FORMATS}; a format nobody enumerated is a format "
                "nobody decided to support"
            )
        if self.runtime_abi not in KNOWN_RUNTIME_ABIS:
            raise CatalogRefused(
                f"{self.model_id}: runtime ABI {self.runtime_abi!r} is not one "
                f"of {KNOWN_RUNTIME_ABIS}"
            )
        if not _DIGEST.fullmatch(self.digest):
            raise CatalogRefused(f"{self.model_id}: {self.digest!r} is not a sha256 digest")
        for name, value in (
            ("size_bytes", self.size_bytes),
            ("context_limit", self.context_limit),
            ("declared_min_ram_mib", self.declared_min_ram_mib),
            ("declared_min_disk_mib", self.declared_min_disk_mib),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise CatalogRefused(f"{self.model_id}: {name} is a positive whole number")
        if self.source_id is not None and not _SOURCE_ID.fullmatch(self.source_id):
            raise CatalogRefused(
                f"{self.model_id}: {self.source_id!r} is not a source symbol. "
                "A source is named, never located: a catalog that could spell "
                "a host could point this node anywhere"
            )
        for name, value in (("provenance", self.provenance), ("purpose", self.purpose)):
            if not str(value).strip():
                raise CatalogRefused(
                    f"{self.model_id}: {name} is recorded. An entry that cannot "
                    "say where it came from or what it is for is one nobody can "
                    "decide about"
                )

    def as_document(self) -> Mapping[str, object]:
        return {
            "role": self.role,
            "model_id": self.model_id,
            "format": self.format,
            "digest": self.digest,
            "size_bytes": self.size_bytes,
            "provenance": self.provenance,
            "license_acknowledgement_required": self.license_acknowledgement_required,
            "runtime_abi": self.runtime_abi,
            "purpose": self.purpose,
            "context_limit": self.context_limit,
            "declared_min_ram_mib": self.declared_min_ram_mib,
            "declared_min_disk_mib": self.declared_min_disk_mib,
            "declared_profile": self.declared_profile.value,
            "source_id": self.source_id,
            "rollback_lineage": list(self.rollback_lineage),
        }


@dataclass(frozen=True)
class ModelCatalog:
    """A verified catalog: signed, versioned, and bound to a commissioning."""

    schema: str
    version: int
    #: The commissioning this catalog was pinned under. Keys do not carry
    #: across a re-commissioning, and neither does a catalog.
    commissioning_digest: str
    entries: tuple[ModelEntry, ...]
    #: Which key id verified it. Recorded so the audit says who offered this.
    signer: str

    def entry(self, model_id: str) -> Optional[ModelEntry]:
        for entry in self.entries:
            if entry.model_id == model_id:
                return entry
        return None

    @property
    def state(self) -> CatalogState:
        return CatalogState.EMPTY if not self.entries else CatalogState.DECLARED


@dataclass(frozen=True)
class ModelReading:
    """What is true about one model, on separate axes that do not collapse."""

    model_id: Optional[str]
    state: CatalogState
    #: Why it is not further along. `None` only when the artifact verified.
    refused_by: Optional[Refusal]
    reason: str
    #: Always `False` in this build. Kept as its own field so that "verified"
    #: is never read as "usable": the resource gate refuses while the Core
    #: reserve is unmeasured, and every other admission gate is still ahead.
    admitted: bool = False

    def __post_init__(self) -> None:
        if self.admitted:
            raise CatalogRefused(
                "this module does not admit anything. Admission is decided by "
                "the gates in cognition.py against a measured Core reserve, "
                "and a reading that claimed it would be claiming HG-05 is closed"
            )
        if not str(self.reason).strip():
            raise CatalogRefused("a reading carries a reason")

    def as_event(self) -> dict:
        """No prompt, no evidence, no secret, no licence text, no key material."""

        return {
            "event_type": "mio.model.reading",
            "model_id": self.model_id,
            "state": self.state.value,
            "refused_by": self.refused_by.name.lower() if self.refused_by else None,
            "reason": self.reason,
            "admitted": self.admitted,
        }


def artifact_filename(entry: ModelEntry) -> str:
    """Where an artifact lives, derived from its digest and never from a name.

    A filename built from `model_id` would be a filename an entry could steer.
    The digest is already constrained to 64 hex characters, so there is
    nothing in it a path could use.
    """

    return entry.digest.split(":", 1)[1] + "." + entry.format


def read_catalog(
    path: Path, *, trusted_keys: Mapping[str, bytes], commissioning_digest: str
) -> ModelCatalog:
    """Read and verify a catalog. Refuses rather than repairing.

    `trusted_keys` maps key id to key material and must contain **only keys
    holding the catalog-signing role**. This module does not read a trust
    store: which keys hold which role is a commissioning trust policy
    question, and deciding it here would put the role model in two places.
    """

    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise CatalogRefused(Refusal.CATALOG_ABSENT.value) from exc
    except OSError as exc:
        raise CatalogRefused(f"the catalog could not be read: {exc}") from exc

    return read_catalog_bytes(raw, trusted_keys=trusted_keys,
                              commissioning_digest=commissioning_digest)


def read_catalog_bytes(raw: bytes, *, trusted_keys: Mapping[str, bytes],
                       commissioning_digest: str) -> ModelCatalog:
    """Verify an already bounded, descriptor-read catalog snapshot."""
    if len(raw) > MAX_CATALOG_BYTES + SIGNATURE_BYTES:
        raise CatalogRefused(f"the catalog is larger than {MAX_CATALOG_BYTES} bytes")
    if len(raw) <= SIGNATURE_BYTES:
        raise CatalogRefused("the catalog is too short to carry a signature and a payload")

    signature, payload = raw[:SIGNATURE_BYTES], raw[SIGNATURE_BYTES:]
    signed = CATALOG_DOMAIN + payload
    signer = None
    for key_id, material in sorted(trusted_keys.items()):
        try:
            if verify_detached(public_key=material, message=signed, signature=signature):
                signer = key_id
                break
        except SignatureRefused:
            # A key that is unusable in the trust store is skipped, and only
            # after every other key has had its chance -- one bad key must not
            # make every catalog unverifiable, and the result must not depend
            # on ordering.
            continue
    if signer is None:
        raise CatalogRefused(
            f"{Refusal.CATALOG_UNSIGNED.value}. The signature is checked over "
            "the domain-tagged payload, so a signature made for a manifest, a "
            "revocation list or a runtime binary does not verify here"
        )

    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CatalogRefused(f"{Refusal.CATALOG_INVALID.value}: {exc}") from exc
    if not isinstance(document, dict):
        raise CatalogRefused(f"{Refusal.CATALOG_INVALID.value}: not an object")
    if document.get("schema") not in (CATALOG_SCHEMA, LEGACY_CATALOG_SCHEMA):
        raise CatalogRefused(
            f"the catalog names schema {document.get('schema')!r} and this "
            f"reader knows {CATALOG_SCHEMA!r}"
        )
    pinned = document.get("commissioning_digest")
    if pinned != commissioning_digest:
        raise CatalogRefused(
            f"this catalog was pinned under commissioning {pinned!r} and this "
            f"node is commissioned as {commissioning_digest!r}; a catalog does "
            "not carry across a re-commissioning"
        )
    version = document.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise CatalogRefused("the catalog version is a positive whole number")

    raw_entries = document.get("entries")
    if not isinstance(raw_entries, list):
        raise CatalogRefused(f"{Refusal.CATALOG_INVALID.value}: entries is not a list")
    if len(raw_entries) > MAX_ENTRIES:
        raise CatalogRefused(f"the catalog offers more than {MAX_ENTRIES} entries")

    entries = tuple(_entry_from(item, index, schema=document["schema"])
                    for index, item in enumerate(raw_entries))
    seen = [entry.model_id for entry in entries]
    duplicated = sorted({i for i in seen if seen.count(i) > 1})
    if duplicated:
        raise CatalogRefused(f"{duplicated} appear more than once; an id names one entry")
    return ModelCatalog(
        schema=document["schema"],
        version=version,
        commissioning_digest=commissioning_digest,
        entries=entries,
        signer=signer,
    )


_ENTRY_FIELDS = (
    "model_id",
    "format",
    "digest",
    "size_bytes",
    "provenance",
    "license_acknowledgement_required",
    "runtime_abi",
    "purpose",
    "context_limit",
    "declared_min_ram_mib",
    "declared_min_disk_mib",
    "declared_profile",
    "rollback_lineage",
    "source_id",
)


KNOWN_EMBEDDING_DIGESTS = frozenset({
    "sha256:950f4a8e5e19477a6d3c26d2f162233c20002c601f75e4b002e3239997821167",
})


def _entry_from(item: object, index: int, *, schema: str = CATALOG_SCHEMA) -> ModelEntry:
    if not isinstance(item, dict):
        raise CatalogRefused(f"entry {index} is not an object")
    fields = (*_ENTRY_FIELDS, "role") if schema == CATALOG_SCHEMA else _ENTRY_FIELDS
    extra = sorted(set(item) - set(fields))
    if extra:
        raise CatalogRefused(
            f"entry {index} carries {extra}, which a model entry does not "
            "declare. A field nobody decided on is a field nobody checks"
        )
    missing = [field for field in fields if field not in item]
    if missing:
        raise CatalogRefused(f"entry {index} is missing {missing}")
    try:
        profile = ResourceProfile(item["declared_profile"])
    except ValueError as exc:
        raise CatalogRefused(
            f"entry {index}: {Refusal.UNDEFINED_PROFILE.value} "
            f"({item['declared_profile']!r})"
        ) from exc
    lineage = item["rollback_lineage"]
    if not isinstance(lineage, list) or not all(isinstance(x, str) for x in lineage):
        raise CatalogRefused(f"entry {index}: rollback_lineage is a list of model ids")
    if not isinstance(item["license_acknowledgement_required"], bool):
        raise CatalogRefused(
            f"entry {index}: license_acknowledgement_required is a boolean"
        )
    if (schema != CATALOG_SCHEMA and item["digest"] in KNOWN_EMBEDDING_DIGESTS):
        raise CatalogRefused("legacy catalog cannot declare a known embedding digest")
    return ModelEntry(
        model_id=str(item["model_id"]),
        format=str(item["format"]),
        digest=str(item["digest"]),
        size_bytes=item["size_bytes"],
        provenance=str(item["provenance"]),
        license_acknowledgement_required=item["license_acknowledgement_required"],
        runtime_abi=str(item["runtime_abi"]),
        purpose=str(item["purpose"]),
        context_limit=item["context_limit"],
        declared_min_ram_mib=item["declared_min_ram_mib"],
        declared_min_disk_mib=item["declared_min_disk_mib"],
        declared_profile=profile,
        rollback_lineage=tuple(lineage),
        source_id=_source_id_from(item, index),
        role=item["role"] if schema == CATALOG_SCHEMA else "generative",
    )


def _source_id_from(item: Mapping, index: int) -> Optional[str]:
    """`null` or a symbol. Never absent, never anything else.

    A missing field would let "no online source" and "nobody thought about
    it" produce the same catalog, and only one of those is a decision. That
    refusal is `_entry_from`'s `missing` check, which runs first and covers
    every field; the subscript below cannot raise, and is written as a
    subscript rather than a `.get` so that a future reader sees the field is
    required rather than inferring a default that does not exist.
    """

    raw = item["source_id"]
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise CatalogRefused(
            f"entry {index}: source_id is a symbol or null, not {type(raw).__name__}"
        )
    return raw


def verify_artifact(
    entry: ModelEntry,
    *,
    artifact_root: Path,
    installed_lineage: Sequence[str] = (),
    license_acknowledged: bool = False,
    read_bytes: int = 8 * 1024 * 1024,
) -> ModelReading:
    """Check one artifact against its declaration. Admits nothing.

    Every refusal is named. The order runs cheap-and-absolute first: a licence
    that has not been acknowledged and a lineage that would go backwards are
    decided without touching the artifact, so a node does not hash gigabytes
    to discover it was never allowed to.
    """

    def refuse(cause: Refusal, detail: str = "") -> ModelReading:
        return ModelReading(
            model_id=entry.model_id,
            state=CatalogState.DECLARED,
            refused_by=cause,
            reason=cause.value + (f": {detail}" if detail else ""),
        )

    if entry.license_acknowledgement_required and not license_acknowledged:
        return refuse(Refusal.LICENSE_NOT_ACKNOWLEDGED)
    if installed_lineage and entry.model_id in installed_lineage:
        return refuse(
            Refusal.STALE_ROLLBACK_LINEAGE,
            f"{entry.model_id} is already in the installed lineage "
            f"{list(installed_lineage)}",
        )

    path = artifact_root / artifact_filename(entry)
    # The filename came from the digest, so this cannot escape -- checked
    # anyway, because a resolution that surprises is worth refusing rather
    # than discovering.
    try:
        resolved = path.resolve()
        resolved.relative_to(artifact_root.resolve())
    except (OSError, ValueError):
        return refuse(Refusal.PATH_TRAVERSAL, str(path))

    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return ModelReading(
            model_id=entry.model_id,
            state=CatalogState.DECLARED,
            refused_by=Refusal.ARTIFACT_ABSENT,
            reason=(
                f"{Refusal.ARTIFACT_ABSENT.value}. The catalog offers it; "
                "nothing has been brought in"
            ),
        )
    except OSError as exc:
        return refuse(Refusal.ARTIFACT_ABSENT, str(exc))

    if size != entry.size_bytes:
        return refuse(Refusal.SIZE_MISMATCH, f"{size} against {entry.size_bytes}")

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        head = handle.read(min(read_bytes, 512))
        for magic, description in _EXECUTABLE_OR_ARCHIVE_MAGIC:
            if head.startswith(magic) or (magic == b"ustar" and b"ustar" in head[:512]):
                return refuse(
                    Refusal.NOT_WEIGHTS,
                    f"it begins as {description}. A model artifact is weights; "
                    "an archive unpacks and an executable runs, and this "
                    "contract is that it does neither",
                )
        digest.update(head)
        while True:
            chunk = handle.read(read_bytes)
            if not chunk:
                break
            digest.update(chunk)
    observed = "sha256:" + digest.hexdigest()
    if observed != entry.digest:
        return refuse(Refusal.DIGEST_MISMATCH, f"{observed} against {entry.digest}")

    return ModelReading(
        model_id=entry.model_id,
        state=CatalogState.PRESENT,
        refused_by=None,
        reason=(
            "the artifact is present and matches its declaration. It is **not** "
            "admitted: every admission gate is still ahead of it, and the "
            "resource gate refuses while the Core reserve is unmeasured "
            "(docs/hardware-gates.md HG-05)"
        ),
    )


def absent_reading(reason: str = "") -> ModelReading:
    """The reading a node with no catalog produces."""

    return ModelReading(
        model_id=None,
        state=CatalogState.ABSENT,
        refused_by=Refusal.CATALOG_ABSENT,
        reason=reason
        or (
            "no catalog is present on this node, so nothing has been offered. "
            "This is not a fault: a node that has not been given a catalog has "
            "not been told what it may consider"
        ),
    )


def catalog_payload(
    *, version: int, commissioning_digest: str, entries: Sequence[ModelEntry]
) -> bytes:
    """The exact bytes a signer signs, minus the domain tag.

    Canonical: sorted keys, entries ordered by `model_id`, no insignificant
    whitespace, UTF-8. The signer and the verifier therefore cannot disagree
    about what was signed, which is the disagreement every canonicalisation
    step exists to prevent.

    Entries are sorted rather than kept in the caller's order because an id
    names exactly one entry -- `read_catalog` refuses duplicates -- so the
    order carries no meaning and would only be a way for two builders to
    disagree about the same set of models.
    """

    document = {
        "schema": CATALOG_SCHEMA,
        "version": version,
        "commissioning_digest": commissioning_digest,
        "entries": [
            entry.as_document()
            for entry in sorted(entries, key=lambda entry: entry.model_id)
        ],
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_artifact_fd(entry: ModelEntry, descriptor: int, *, license: str) -> ModelReading:
    """Full re-hash and data inspection of the held inode, never reopen a path."""
    import os
    import stat

    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o111
            or not 0 < info.st_size <= 64 * 1024 * 1024 * 1024
            or info.st_size != entry.size_bytes or info.st_nlink != 1
            or license != ("acknowledged" if entry.license_acknowledgement_required else "not-required")):
        raise CatalogRefused("ARTIFACT_REFUSED")
    head = os.pread(descriptor, min(512, entry.size_bytes), 0)
    for magic, _ in _EXECUTABLE_OR_ARCHIVE_MAGIC:
        if head.startswith(magic) or (magic == b"ustar" and magic in head):
            raise CatalogRefused("ARTIFACT_REFUSED")
    observed = hashlib.sha256()
    offset = 0
    while offset < entry.size_bytes:
        chunk = os.pread(descriptor, min(8 * 1024 * 1024, entry.size_bytes - offset), offset)
        if not chunk:
            raise CatalogRefused("ARTIFACT_REFUSED")
        observed.update(chunk)
        offset += len(chunk)
    after = os.fstat(descriptor)
    before_revision = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                       info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)
    after_revision = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                      after.st_ctime_ns, after.st_mode, after.st_uid, after.st_gid, after.st_nlink)
    if (before_revision != after_revision
            or "sha256:" + observed.hexdigest() != entry.digest):
        raise CatalogRefused("ARTIFACT_REFUSED")
    return ModelReading(entry.model_id, CatalogState.PRESENT, None, "held artifact verified")
