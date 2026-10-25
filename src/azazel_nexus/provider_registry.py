"""Where a remote provider symbol resolves, under a third trust policy (#98).

Three registries now, and they are deliberately not one:

| registry | says | signed by |
| --- | --- | --- |
| model catalog | which models exist | the catalog role |
| Source Registry | where an **artifact** is fetched from | the registry role |
| **Provider Registry** | where an **inference request** is sent | the provider role |

A holder of the Source Registry role must not be able to name somewhere this
node sends what it has observed. Fetching weights and sending observations
are different acts with different blast radii: the first brings public bytes
in against a digest declared beforehand, the second carries what this node
saw to somebody else. Reusing one registry for both would make the account
that may pull a file also the account that may push a report.

So this is a separate document, a separate domain, a separate role and a
separate commissioned key set, read by a separate service under a separate
account. `docs/remote-inference.md` holds the table.

## What a record fixes, and what a caller may therefore not say

Everything about *where* and *how much*:

- host, port, path template, certificate pin, client identity
- the model, **as a symbol this record names** -- never a model string a
  caller passes through
- request and response ceilings, the deadline
- which privacy classes this provider may be sent at all

A caller names a `provider_id`. That is the whole of its influence over the
destination. There is no argument here, and no argument kind in
`protocol.py`, through which a URL, a header, a proxy, a certificate path or
a model name could arrive.

## It ships empty

`ProviderRegistry` is commissioned data, and none is commissioned. A node
with no provider record resolves no provider symbol, so the transport has
nowhere to send anything -- which is why the shipped state is not "remote is
switched off" but "there is no remote".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .sanitizer import NEVER_REMOTE, PrivacyClass
from .signature import SIGNATURE_BYTES, SignatureRefused, verify_detached

__all__ = [
    "MAX_PROVIDER_REGISTRY_BYTES",
    "PROVIDER_DOMAIN",
    "PROVIDER_SCHEMA",
    "ProviderRecord",
    "ProviderRefusal",
    "ProviderRefused",
    "ProviderRegistry",
    "ProviderTrust",
    "load_provider_registry",
    "provider_registry_payload",
    "resolve_provider",
]

#: The signing domain for this registry. A different **kind** of target from
#: a source registry: that one authorises where bytes are pulled from, this
#: one authorises where observations are pushed to. The same key holding both
#: roles is refused by `ProviderTrust`; the domain makes the separation hold
#: even if it did not.
PROVIDER_DOMAIN = b"azazel-nexus/provider-registry/v1\x00"

#: The payload shape, versioned independently of the domain.
PROVIDER_SCHEMA = "azazel-nexus/provider-registry/1"

#: A provider registry larger than this is refused before it is parsed.
MAX_PROVIDER_REGISTRY_BYTES = 64 * 1024

#: A provider id: a symbol, never a location. Same alphabet discipline as a
#: model id -- no separator a filesystem or a URL parser would read.
_PROVIDER_ID = re.compile(r"[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?\Z")

#: A hostname by grammar. Refuses a scheme, a port, a path, userinfo and a
#: query by having nowhere to put them.
_HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+\Z"
)

#: An address literal, refused: a pin and a hostname check are the two things
#: an address bypasses.
_ADDRESS_LITERAL = re.compile(r"^(\d{1,3}(\.\d{1,3}){3}|\[?[0-9a-f:]+\]?)$")

_PIN = re.compile(r"sha256:[0-9a-f]{64}\Z")

#: A client identity is a **name**, never key material. The name says which
#: commissioned identity to present; the key lives where only the transport's
#: account can read it, and never passes through this document.
_IDENTITY = re.compile(r"[A-Za-z0-9._@:+-]{1,64}\Z")


class ProviderRefusal(str, Enum):
    """Why no provider resolved. One value per condition, never merged."""

    REGISTRY_INVALID = "registry_invalid"
    REGISTRY_UNSIGNED = "registry_unsigned"
    SHARED_SIGNING_KEY = "shared_signing_key"
    UNKNOWN_PROVIDER = "unknown_provider"
    CLASS_NOT_PERMITTED = "class_not_permitted"
    NO_PROVIDER_COMMISSIONED = "no_provider_commissioned"


class ProviderRefused(Exception):
    """A provider that may not be resolved. Refused, never repaired."""

    def __init__(self, refusal: ProviderRefusal, reason: str) -> None:
        super().__init__(f"{refusal.value}: {reason}")
        self.refusal = refusal
        self.reason = reason


@dataclass(frozen=True)
class ProviderRecord:
    """One remote provider: where it is, how to trust it, and within what bounds.

    There is deliberately **no `model_name` a caller could set**. `model_id`
    is part of the signed record: which model this provider is asked for is a
    commissioning decision, not a request parameter. A caller that could name
    a model could name one the provider exposes and nobody reviewed.
    """

    provider_id: str
    host: str
    port: int
    #: `{model}` is the only substitution, filled from this record's own
    #: `model_id`. A template with another hole is a template something can
    #: steer.
    path_template: str
    #: Over the server's public key, like the artifact fetcher's.
    certificate_pin: str
    #: The **name** of the client identity this node presents. Never the key.
    client_identity: str
    #: The model this provider is asked for, as a symbol in this record.
    model_id: str
    max_request_bytes: int
    max_response_bytes: int
    deadline_seconds: int
    #: Which privacy classes may be sent to this provider at all. A record
    #: naming a never-remote class cannot be built.
    allowed_privacy_classes: tuple

    def __post_init__(self) -> None:
        if not _PROVIDER_ID.fullmatch(self.provider_id):
            raise ProviderRefused(
                ProviderRefusal.REGISTRY_INVALID,
                f"{self.provider_id!r} is not a provider symbol; a provider id "
                "names an entry, never a location",
            )
        if not _HOSTNAME.fullmatch(self.host) or _ADDRESS_LITERAL.match(self.host):
            raise ProviderRefused(
                ProviderRefusal.REGISTRY_INVALID,
                f"{self.host!r} is not a hostname. A scheme, a port, a path, a "
                "query, userinfo or an address literal are separate fields or "
                "they do not exist",
            )
        if not 1 <= self.port <= 65535:
            raise ProviderRefused(
                ProviderRefusal.REGISTRY_INVALID, f"{self.port} is not a port"
            )
        if not self.path_template.startswith("/"):
            raise ProviderRefused(
                ProviderRefusal.REGISTRY_INVALID,
                "a path template is absolute; a relative one is resolved "
                "against something this node did not choose",
            )
        holes = set(re.findall(r"\{([a-z_]*)\}", self.path_template))
        if holes - {"model"}:
            raise ProviderRefused(
                ProviderRefusal.REGISTRY_INVALID,
                f"the path template has {sorted(holes - {'model'})} in it; a "
                "template with a hole nobody fills is a template something else "
                "fills",
            )
        if not _PIN.fullmatch(self.certificate_pin):
            raise ProviderRefused(
                ProviderRefusal.REGISTRY_INVALID,
                "a certificate pin is sha256: and sixty-four hex digits",
            )
        if not _IDENTITY.fullmatch(self.client_identity):
            raise ProviderRefused(
                ProviderRefusal.REGISTRY_INVALID,
                "a client identity is a bounded name. Key material is not a "
                "name and does not belong in a document that is read aloud",
            )
        if not _PROVIDER_ID.fullmatch(self.model_id):
            raise ProviderRefused(
                ProviderRefusal.REGISTRY_INVALID,
                f"{self.model_id!r} is not a model symbol",
            )
        for label, value in (
            ("max_request_bytes", self.max_request_bytes),
            ("max_response_bytes", self.max_response_bytes),
            ("deadline_seconds", self.deadline_seconds),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ProviderRefused(
                    ProviderRefusal.REGISTRY_INVALID,
                    f"{label} is a positive quantity; a ceiling of zero is not "
                    "a ceiling and an absent one is not either",
                )
        if not self.allowed_privacy_classes:
            raise ProviderRefused(
                ProviderRefusal.REGISTRY_INVALID,
                f"{self.provider_id!r} permits no privacy class, so every "
                "request to it would be refused. A record nothing can use is a "
                "record that misstates its own purpose",
            )
        forbidden = sorted(
            c.value for c in self.allowed_privacy_classes if c in NEVER_REMOTE
        )
        if forbidden:
            raise ProviderRefused(
                ProviderRefusal.REGISTRY_INVALID,
                f"{self.provider_id!r} permits {forbidden}, which never leave "
                "this node. A registry that allows one contradicts the contract "
                "rather than configuring it",
            )

    def path_for(self) -> str:
        """The request path, from this record's own model symbol."""

        return self.path_template.format(model=self.model_id)


@dataclass(frozen=True)
class ProviderTrust:
    """The commissioned keys, and the roles they may not share.

    A key holding two of the three roles could name a model *and* say where
    the observations about it go, which is the single point all three
    registries exist to remove.
    """

    provider_keys: Mapping[str, bytes]
    #: The other two roles, so that sharing can be refused rather than
    #: assumed absent.
    catalog_keys: Mapping[str, bytes] = None  # type: ignore[assignment]
    registry_keys: Mapping[str, bytes] = None  # type: ignore[assignment]
    commissioning_digest: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "catalog_keys", dict(self.catalog_keys or {}))
        object.__setattr__(self, "registry_keys", dict(self.registry_keys or {}))
        others = {**self.catalog_keys, **self.registry_keys}
        shared_ids = sorted(set(self.provider_keys) & set(others))
        if shared_ids:
            raise ProviderRefused(
                ProviderRefusal.SHARED_SIGNING_KEY,
                f"{shared_ids} hold the provider role and another. One holder "
                "could then name a model and say where this node reports on it",
            )
        shared_material = sorted(
            key_id
            for key_id, material in self.provider_keys.items()
            if material in set(others.values())
        )
        if shared_material:
            raise ProviderRefused(
                ProviderRefusal.SHARED_SIGNING_KEY,
                f"{shared_material} carry key material that signs another role "
                "under a different id. Two ids for one key is one key",
            )


@dataclass(frozen=True)
class ProviderRegistry:
    """A verified provider registry. Holding one has contacted nothing."""

    version: int
    commissioning_digest: str
    records: Mapping[str, ProviderRecord]
    signer: str


def provider_registry_payload(
    *, version: int, commissioning_digest: str, records: Sequence[ProviderRecord]
) -> bytes:
    """The exact bytes a provider-registry signer signs."""

    document = {
        "schema": PROVIDER_SCHEMA,
        "version": version,
        "commissioning_digest": commissioning_digest,
        "providers": [
            {
                "provider_id": r.provider_id,
                "host": r.host,
                "port": r.port,
                "path_template": r.path_template,
                "certificate_pin": r.certificate_pin,
                "client_identity": r.client_identity,
                "model_id": r.model_id,
                "max_request_bytes": r.max_request_bytes,
                "max_response_bytes": r.max_response_bytes,
                "deadline_seconds": r.deadline_seconds,
                "allowed_privacy_classes": sorted(
                    c.value for c in r.allowed_privacy_classes
                ),
            }
            for r in sorted(records, key=lambda r: r.provider_id)
        ],
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_provider_registry(path: Path, *, trust: ProviderTrust) -> ProviderRegistry:
    """Read and verify a provider registry under the **provider** role only.

    `trust.catalog_keys` and `trust.registry_keys` are not consulted and could
    not help if they were: the domain tag differs, so a catalog or source
    signature does not verify here even under the same key material.
    """

    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise ProviderRefused(
            ProviderRefusal.NO_PROVIDER_COMMISSIONED,
            "no provider registry is commissioned on this node, so no provider "
            "symbol resolves and there is nowhere to send anything",
        ) from None
    except OSError as exc:
        raise ProviderRefused(
            ProviderRefusal.REGISTRY_INVALID, f"could not be read: {exc}"
        ) from exc

    if len(raw) > MAX_PROVIDER_REGISTRY_BYTES + SIGNATURE_BYTES:
        raise ProviderRefused(
            ProviderRefusal.REGISTRY_INVALID,
            f"larger than {MAX_PROVIDER_REGISTRY_BYTES} bytes",
        )
    if len(raw) <= SIGNATURE_BYTES:
        raise ProviderRefused(
            ProviderRefusal.REGISTRY_INVALID,
            "too short to carry a signature and a payload",
        )

    signature, payload = raw[:SIGNATURE_BYTES], raw[SIGNATURE_BYTES:]
    signed = PROVIDER_DOMAIN + payload
    signer = None
    for key_id, material in sorted(trust.provider_keys.items()):
        try:
            if verify_detached(public_key=material, message=signed, signature=signature):
                signer = key_id
                break
        except SignatureRefused:
            continue
    if signer is None:
        raise ProviderRefused(
            ProviderRefusal.REGISTRY_UNSIGNED,
            "no key holding the provider role signed these bytes under the "
            "provider domain. A catalog or source-registry signature does not "
            "verify here, whatever key made it",
        )

    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProviderRefused(ProviderRefusal.REGISTRY_INVALID, str(exc)) from exc
    if not isinstance(document, dict):
        raise ProviderRefused(ProviderRefusal.REGISTRY_INVALID, "not an object")
    if document.get("schema") != PROVIDER_SCHEMA:
        raise ProviderRefused(
            ProviderRefusal.REGISTRY_INVALID,
            f"the registry names schema {document.get('schema')!r} and this "
            f"reader knows {PROVIDER_SCHEMA!r}",
        )
    if document.get("commissioning_digest") != trust.commissioning_digest:
        raise ProviderRefused(
            ProviderRefusal.REGISTRY_INVALID,
            "the registry names a different commissioning than this node's; a "
            "document commissioned elsewhere is not commissioned here",
        )

    entries = document.get("providers")
    if not isinstance(entries, list):
        raise ProviderRefused(
            ProviderRefusal.REGISTRY_INVALID, "providers is a list"
        )

    records: dict = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ProviderRefused(
                ProviderRefusal.REGISTRY_INVALID, "a provider entry is an object"
            )
        try:
            classes = tuple(
                PrivacyClass(name) for name in entry["allowed_privacy_classes"]
            )
            record = ProviderRecord(
                provider_id=entry["provider_id"],
                host=entry["host"],
                port=entry["port"],
                path_template=entry["path_template"],
                certificate_pin=entry["certificate_pin"],
                client_identity=entry["client_identity"],
                model_id=entry["model_id"],
                max_request_bytes=entry["max_request_bytes"],
                max_response_bytes=entry["max_response_bytes"],
                deadline_seconds=entry["deadline_seconds"],
                allowed_privacy_classes=classes,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderRefused(
                ProviderRefusal.REGISTRY_INVALID, f"a provider entry is malformed: {exc}"
            ) from exc
        if record.provider_id in records:
            raise ProviderRefused(
                ProviderRefusal.REGISTRY_INVALID,
                f"{record.provider_id!r} appears twice; two records for one "
                "symbol means the destination depends on order",
            )
        records[record.provider_id] = record

    version = document.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ProviderRefused(
            ProviderRefusal.REGISTRY_INVALID, "version is a positive integer"
        )

    return ProviderRegistry(
        version=version,
        commissioning_digest=str(document["commissioning_digest"]),
        records=records,
        signer=signer,
    )


def resolve_provider(
    provider_id: str,
    registry: Optional[ProviderRegistry],
    *,
    privacy_class: PrivacyClass,
) -> ProviderRecord:
    """A symbol to the record that names it, or a refusal. Never a join.

    `provider_id` arrives as a string because it came off a socket. It is
    **looked up**, never formatted into a host, a path or a URL.
    """

    if registry is None:
        raise ProviderRefused(
            ProviderRefusal.NO_PROVIDER_COMMISSIONED,
            "no provider registry is commissioned on this node",
        )
    record = registry.records.get(provider_id)
    if record is None:
        raise ProviderRefused(
            ProviderRefusal.UNKNOWN_PROVIDER,
            f"{provider_id!r} resolves to no provider in this commissioning",
        )
    if privacy_class in NEVER_REMOTE:
        raise ProviderRefused(
            ProviderRefusal.CLASS_NOT_PERMITTED,
            f"{privacy_class.value} does not leave this node",
        )
    if privacy_class not in record.allowed_privacy_classes:
        raise ProviderRefused(
            ProviderRefusal.CLASS_NOT_PERMITTED,
            f"{provider_id!r} is not commissioned to receive "
            f"{privacy_class.value}",
        )
    return record
