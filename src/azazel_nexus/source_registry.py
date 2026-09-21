"""Where a source symbol resolves, under a trust policy of its own (#105).

`model_catalog` says **which models** are offered and names a source by
symbol. This says **where that symbol points** and under what conditions. The
two are separate documents, separately signed, under separate commissioning
trust policies, and neither one is sufficient.

```
catalog (signer A)              registry (administrator B)
  model_id                        source_id
  digest / size                     -> host, port, path
  source_id --- symbol ------------> certificate pin
  (cannot spell a location)          client identity
                                     bandwidth ceiling
                                     allowed artifact classes
          \                        /
           +-- both, or no candidate --+
```

## Why the crossing, and not a containment

**The catalog signer cannot name an endpoint. The registry administrator
cannot introduce a model.**

- An attacker holding the catalog signing key cannot point this node at a
  host of their choosing: the symbol is resolved here, and a symbol this
  registry does not carry resolves to nothing.
- An attacker holding the registry cannot bring in a model: models are named
  by the catalog, and a `model_id` the catalog does not carry is not a
  candidate.

Only both together produce an arbitrary download, and **the breadth that
compromise requires is what this separation buys.** A design where one
document carried both would hand that breadth to whoever held it.

## Separate policies, checked rather than described

Two documents under one trust policy is one key that signs both, and the
crossing above collapses into a single point. So `CommissionedSources`
**refuses to exist** when a key id appears in both roles. That is the
separation: not a paragraph in a document, a constructor that will not build.

Domain separation carries the rest. A registry is signed under
`REGISTRY_DOMAIN`, a catalog under `CATALOG_DOMAIN`, so even the same key
material cannot produce a signature that reads as both.

## What a registry record decides, and what it does not

It decides where, how, and within what ceilings. It decides **nothing** about
whether a model may run: a resolved candidate is still unadmitted, still
unactivated, and still has to pass the same verification an offline import
goes through.

## No transport here

This module resolves and refuses. It opens nothing: no `socket`, no `ssl`,
no `http`, no `urllib`. The one module that may open a connection is named in
`docs/model-acquisition.md` and is the only exception
`tests/unit/test_runtime_boundary.py` allows.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .model_acquisition import KNOWN_SOURCES
from .model_catalog import CATALOG_DOMAIN, ModelEntry
from .signature import SIGNATURE_BYTES, SignatureRefused, verify_detached

__all__ = [
    "ArtifactClass",
    "CommissionedSources",
    "DownloadCandidate",
    "MAX_REGISTRY_BYTES",
    "MAX_SOURCES",
    "REGISTRY_DOMAIN",
    "REGISTRY_FILENAME",
    "REGISTRY_SCHEMA",
    "RegistryRefused",
    "Refusal",
    "SourceRecord",
    "SourceRegistry",
    "read_registry",
    "registry_payload",
    "resolve_candidate",
]

#: A different **kind** of signing target, so a different domain. A catalog
#: signature and a registry signature can never be read as each other even
#: under one key: the tag is part of what is signed.
#:
#: `v1` here is this document kind's own protocol version and moves by the
#: same rule `CATALOG_DOMAIN` states -- kind, canonicalisation, or what
#: cross-protocol separation must mean. Not for a field.
REGISTRY_DOMAIN = b"azazel-nexus/source-registry/v1\x00"

REGISTRY_FILENAME = "sources.signed"

#: The document shape.
REGISTRY_SCHEMA = "azazel-nexus/source-registry/1"

MAX_REGISTRY_BYTES = 256 * 1024
MAX_SOURCES = 16

#: A pin is over the certificate's public key, not the certificate: a server
#: that renews its certificate keeps its key, and a pin over the whole
#: certificate would turn every ordinary renewal into an outage that looks
#: like an attack.
_PIN = re.compile(r"^sha256:[0-9a-f]{64}$")
_SOURCE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
#: A hostname, and nothing that could carry a scheme, a port, a path, a query
#: or credentials. Those are separate fields or they do not exist.
_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
#: An address literal in the host field would let one document both name a
#: source and pick its address, skipping the commissioned address allowlist
#: that exists because a right name is not a right address.
_LOOKS_NUMERIC = re.compile(r"^[0-9.]+$")
#: A client identity is a **name** the node presents, resolved to material by
#: the commissioned key store. The registry never carries key material.
_IDENTITY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class ArtifactClass(str, Enum):
    """What a source is allowed to serve.

    A source approved for model weights is not thereby approved for anything
    else. Enumerated so that a new kind of artifact is a decision somebody
    makes here rather than something an existing source starts serving.
    """

    MODEL_WEIGHTS = "model-weights"


class Refusal(str, Enum):
    """Why a registry, a record or a candidate was refused."""

    REGISTRY_ABSENT = "registry_absent"
    REGISTRY_UNSIGNED = "registry_unsigned"
    REGISTRY_INVALID = "registry_invalid"
    SHARED_SIGNING_KEY = "shared_signing_key"
    UNKNOWN_SOURCE = "unknown_source"
    SOURCE_UNAVAILABLE = "source_unavailable"
    ARTIFACT_CLASS_NOT_ALLOWED = "artifact_class_not_allowed"


class RegistryRefused(Exception):
    """Refused, never repaired."""

    def __init__(self, cause: Refusal, detail: str = "") -> None:
        super().__init__(f"{cause.value}: {detail}" if detail else cause.value)
        self.cause = cause


@dataclass(frozen=True)
class SourceRecord:
    """One source: where it is, how to trust it, and within what ceilings."""

    source_id: str
    host: str
    port: int
    #: `{digest}` is the only substitution. A template with another hole is a
    #: template something can steer.
    path_template: str
    #: Over the server's public key. See `_PIN`.
    certificate_pin: str
    #: The **name** of the client identity this node presents. Never the key.
    client_identity: str
    #: A ceiling, so that an acquisition cannot starve everything else on a
    #: node whose whole job is to keep answering while it happens.
    bandwidth_bytes_per_second: int
    allowed_artifact_classes: tuple

    def __post_init__(self) -> None:
        if not _SOURCE_ID.match(self.source_id):
            raise RegistryRefused(
                Refusal.REGISTRY_INVALID,
                f"{self.source_id!r} is not a source symbol",
            )
        if not _HOST.match(self.host) or _LOOKS_NUMERIC.match(self.host):
            raise RegistryRefused(
                Refusal.REGISTRY_INVALID,
                f"{self.host!r} is not a hostname. A scheme, a port, a path, "
                "a query or credentials are separate fields or they do not "
                "exist -- a host field that accepted them would be a URL field "
                "wearing another name. An address literal is refused too: the "
                "registry **names** a source and the commissioned allowlist "
                "says which addresses that name may resolve to, so a literal "
                "here would be one document doing both jobs and skipping the "
                "allowlist entirely",
            )
        if not isinstance(self.port, int) or isinstance(self.port, bool):
            raise RegistryRefused(Refusal.REGISTRY_INVALID, "port is a whole number")
        if not 1 <= self.port <= 65535:
            raise RegistryRefused(Refusal.REGISTRY_INVALID, f"port {self.port} is not a port")
        holes = self.path_template.count("{")
        if holes != 1 or "{digest}" not in self.path_template:
            raise RegistryRefused(
                Refusal.REGISTRY_INVALID,
                f"{self.path_template!r} has holes other than {{digest}}",
            )
        if not self.path_template.startswith("/") or ".." in self.path_template:
            raise RegistryRefused(
                Refusal.REGISTRY_INVALID,
                f"{self.path_template!r} is not an absolute path without traversal",
            )
        if not _PIN.match(self.certificate_pin):
            raise RegistryRefused(
                Refusal.REGISTRY_INVALID,
                f"{self.certificate_pin!r} is not a sha256 public-key pin",
            )
        if not _IDENTITY.match(self.client_identity):
            raise RegistryRefused(
                Refusal.REGISTRY_INVALID,
                f"{self.client_identity!r} is not an identity name. The registry "
                "names an identity; the commissioned key store holds its material",
            )
        if (
            not isinstance(self.bandwidth_bytes_per_second, int)
            or isinstance(self.bandwidth_bytes_per_second, bool)
            or self.bandwidth_bytes_per_second < 1
        ):
            raise RegistryRefused(
                Refusal.REGISTRY_INVALID, "a bandwidth ceiling is a positive whole number"
            )
        if not self.allowed_artifact_classes:
            raise RegistryRefused(
                Refusal.REGISTRY_INVALID,
                f"{self.source_id} allows no artifact class. A source that may "
                "serve nothing is a source nobody decided about, not a source "
                "that serves everything",
            )

    def allows(self, artifact_class: ArtifactClass) -> bool:
        return artifact_class in self.allowed_artifact_classes

    def as_document(self) -> Mapping[str, object]:
        return {
            "source_id": self.source_id,
            "host": self.host,
            "port": self.port,
            "path_template": self.path_template,
            "certificate_pin": self.certificate_pin,
            "client_identity": self.client_identity,
            "bandwidth_bytes_per_second": self.bandwidth_bytes_per_second,
            "allowed_artifact_classes": [c.value for c in self.allowed_artifact_classes],
        }


@dataclass(frozen=True)
class SourceRegistry:
    """A verified registry. The signer is named so an audit can say which."""

    schema: str
    version: int
    commissioning_digest: str
    records: tuple
    signer: str

    def record(self, source_id: str) -> Optional[SourceRecord]:
        for record in self.records:
            if record.source_id == source_id:
                return record
        return None


@dataclass(frozen=True)
class DownloadCandidate:
    """What both documents agreed on. Not a permission to fetch.

    Produced only when the catalog names the model *and* the registry
    resolves its symbol *and* the class is allowed. It still carries no
    operator confirmation -- that is `model_acquisition`'s -- and admission is
    further away still.
    """

    model_id: str
    source_id: str
    digest: str
    size_bytes: int
    record: SourceRecord

    @property
    def path(self) -> str:
        return self.record.path_template.format(digest=self.digest)

    def as_event(self) -> dict:
        """The symbols and the sizes. Never the pin, never an identity's
        material, never a URL assembled for convenience."""

        return {
            "event_type": "mio.model.acquisition.candidate",
            "model_id": self.model_id,
            "source_id": self.source_id,
            "digest": self.digest,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class CommissionedSources:
    """The two trust policies, and the refusal that keeps them two.

    A key id that holds both the catalog-signing and the registry-signing role
    collapses the crossing this whole design rests on: one holder could then
    name a model *and* say where it comes from. So this refuses to be built.

    Not a documented expectation. A constructor that will not build.
    """

    catalog_keys: Mapping[str, bytes]
    registry_keys: Mapping[str, bytes]
    commissioning_digest: str

    def __post_init__(self) -> None:
        shared_ids = sorted(set(self.catalog_keys) & set(self.registry_keys))
        if shared_ids:
            raise RegistryRefused(
                Refusal.SHARED_SIGNING_KEY,
                f"{shared_ids} hold both the catalog and the registry role. "
                "One holder could then name a model and say where it comes "
                "from, which is the single point this separation exists to "
                "remove",
            )
        shared_material = sorted(
            key_id
            for key_id, material in self.catalog_keys.items()
            if material in set(self.registry_keys.values())
        )
        if shared_material:
            raise RegistryRefused(
                Refusal.SHARED_SIGNING_KEY,
                f"{shared_material} carry key material that also signs "
                "registries under another id. Two ids for one key is one key",
            )


def registry_payload(
    *, version: int, commissioning_digest: str, records: Sequence[SourceRecord]
) -> bytes:
    """The exact bytes a registry signer signs, minus the domain tag.

    Canonical on the same terms as a catalog payload, and records ordered by
    `source_id` for the same reason: an id names one record, so the order
    carries no meaning and could only be a way for two builders to disagree.
    """

    document = {
        "schema": REGISTRY_SCHEMA,
        "version": version,
        "commissioning_digest": commissioning_digest,
        "sources": [
            record.as_document()
            for record in sorted(records, key=lambda record: record.source_id)
        ],
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def read_registry(
    path: Path, *, commissioned: CommissionedSources
) -> SourceRegistry:
    """Read and verify a registry under the **registry** role only.

    `commissioned.catalog_keys` is not consulted here and could not help if it
    were: the domain tag differs, so a catalog signature does not verify as a
    registry signature even under the same key material.
    """

    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise RegistryRefused(Refusal.REGISTRY_ABSENT) from exc
    except OSError as exc:
        raise RegistryRefused(
            Refusal.REGISTRY_INVALID, f"the registry could not be read: {exc}"
        ) from exc

    if len(raw) > MAX_REGISTRY_BYTES + SIGNATURE_BYTES:
        raise RegistryRefused(
            Refusal.REGISTRY_INVALID, f"larger than {MAX_REGISTRY_BYTES} bytes"
        )
    if len(raw) <= SIGNATURE_BYTES:
        raise RegistryRefused(
            Refusal.REGISTRY_INVALID, "too short to carry a signature and a payload"
        )

    signature, payload = raw[:SIGNATURE_BYTES], raw[SIGNATURE_BYTES:]
    signed = REGISTRY_DOMAIN + payload
    signer = None
    for key_id, material in sorted(commissioned.registry_keys.items()):
        try:
            if verify_detached(public_key=material, message=signed, signature=signature):
                signer = key_id
                break
        except SignatureRefused:
            continue
    if signer is None:
        raise RegistryRefused(
            Refusal.REGISTRY_UNSIGNED,
            "no key holding the registry role signed these bytes under the "
            "registry domain. A catalog signature does not verify here, "
            "whatever key made it",
        )

    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RegistryRefused(Refusal.REGISTRY_INVALID, str(exc)) from exc
    if not isinstance(document, dict):
        raise RegistryRefused(Refusal.REGISTRY_INVALID, "not an object")
    if document.get("schema") != REGISTRY_SCHEMA:
        raise RegistryRefused(
            Refusal.REGISTRY_INVALID,
            f"the registry names schema {document.get('schema')!r} and this "
            f"reader knows {REGISTRY_SCHEMA!r}",
        )
    pinned = document.get("commissioning_digest")
    if pinned != commissioned.commissioning_digest:
        raise RegistryRefused(
            Refusal.REGISTRY_INVALID,
            f"pinned under commissioning {pinned!r} and this node is "
            f"{commissioned.commissioning_digest!r}",
        )
    version = document.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise RegistryRefused(
            Refusal.REGISTRY_INVALID, "the version is a positive whole number"
        )
    raw_sources = document.get("sources")
    if not isinstance(raw_sources, list):
        raise RegistryRefused(Refusal.REGISTRY_INVALID, "sources is not a list")
    if len(raw_sources) > MAX_SOURCES:
        raise RegistryRefused(
            Refusal.REGISTRY_INVALID, f"more than {MAX_SOURCES} sources"
        )
    records = tuple(_record_from(item, index) for index, item in enumerate(raw_sources))
    seen = [record.source_id for record in records]
    duplicated = sorted({s for s in seen if seen.count(s) > 1})
    if duplicated:
        raise RegistryRefused(
            Refusal.REGISTRY_INVALID,
            f"{duplicated} appear more than once; an id names one source",
        )
    return SourceRegistry(
        schema=REGISTRY_SCHEMA,
        version=version,
        commissioning_digest=commissioned.commissioning_digest,
        records=records,
        signer=signer,
    )


_RECORD_FIELDS = (
    "source_id",
    "host",
    "port",
    "path_template",
    "certificate_pin",
    "client_identity",
    "bandwidth_bytes_per_second",
    "allowed_artifact_classes",
)


def _record_from(item: object, index: int) -> SourceRecord:
    if not isinstance(item, dict):
        raise RegistryRefused(Refusal.REGISTRY_INVALID, f"source {index} is not an object")
    extra = sorted(set(item) - set(_RECORD_FIELDS))
    if extra:
        raise RegistryRefused(
            Refusal.REGISTRY_INVALID,
            f"source {index} carries {extra}, which a source record does not "
            "declare. A field nobody decided on is a field nobody checks",
        )
    missing = [field for field in _RECORD_FIELDS if field not in item]
    if missing:
        raise RegistryRefused(
            Refusal.REGISTRY_INVALID, f"source {index} is missing {missing}"
        )
    classes = item["allowed_artifact_classes"]
    if not isinstance(classes, list) or not all(isinstance(c, str) for c in classes):
        raise RegistryRefused(
            Refusal.REGISTRY_INVALID,
            f"source {index}: allowed_artifact_classes is a list of names",
        )
    try:
        parsed = tuple(ArtifactClass(c) for c in classes)
    except ValueError as exc:
        raise RegistryRefused(
            Refusal.REGISTRY_INVALID,
            f"source {index}: {exc}. A class nobody enumerated is a class "
            "nobody decided to allow",
        ) from exc
    return SourceRecord(
        source_id=str(item["source_id"]),
        host=str(item["host"]),
        port=item["port"],
        path_template=str(item["path_template"]),
        certificate_pin=str(item["certificate_pin"]),
        client_identity=str(item["client_identity"]),
        bandwidth_bytes_per_second=item["bandwidth_bytes_per_second"],
        allowed_artifact_classes=parsed,
    )


def resolve_candidate(
    entry: ModelEntry,
    registry: SourceRegistry,
    *,
    artifact_class: ArtifactClass = ArtifactClass.MODEL_WEIGHTS,
) -> DownloadCandidate:
    """Both documents, or no candidate.

    The catalog brought the model and the symbol; the registry brings the
    location and the conditions. Neither alone produces anything to fetch.
    """

    if entry.source_id is None:
        raise RegistryRefused(
            Refusal.SOURCE_UNAVAILABLE,
            f"{entry.model_id} has no source usable for online acquisition. "
            "The registry is not consulted, because there is no symbol to "
            "resolve -- and a registry that answered anyway would be "
            "supplying a source the catalog never named",
        )
    if entry.source_id not in KNOWN_SOURCES:
        raise RegistryRefused(
            Refusal.UNKNOWN_SOURCE,
            f"{entry.source_id!r} is not a symbol this build knows",
        )
    record = registry.record(entry.source_id)
    if record is None:
        raise RegistryRefused(
            Refusal.UNKNOWN_SOURCE,
            f"the registry carries no record for {entry.source_id!r}. The "
            "catalog may name a symbol this node's registry does not resolve, "
            "and that is a refusal rather than a lookup elsewhere",
        )
    if not record.allows(artifact_class):
        raise RegistryRefused(
            Refusal.ARTIFACT_CLASS_NOT_ALLOWED,
            f"{record.source_id} may serve "
            f"{[c.value for c in record.allowed_artifact_classes]}, not "
            f"{artifact_class.value}",
        )
    return DownloadCandidate(
        model_id=entry.model_id,
        source_id=entry.source_id,
        digest=entry.digest,
        size_bytes=entry.size_bytes,
        record=record,
    )
