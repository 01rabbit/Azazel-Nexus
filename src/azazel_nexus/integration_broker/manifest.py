"""Strict, commissioned adapter declarations, signed independently of other roles.

Wire format: 64-byte detached Ed25519 signature followed by exact JSON bytes.
Signatures cover ADAPTER_MANIFEST_DOMAIN + payload; digest covers the payload.
Compatibility is a bounded list of exact product/ABI identifiers (no ranges).
Nothing here installs an artifact, resolves a name, or retrieves a credential.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Collection, Mapping
from dataclasses import InitVar, dataclass
from enum import Enum

from ..sanitizer import PrivacyClass
from ..signature import SIGNATURE_BYTES, SignatureRefused, verify_detached

ADAPTER_MANIFEST_DOMAIN = b"azazel-nexus/adapter-manifest/v1\0"
ADAPTER_MANIFEST_SCHEMA = "azazel-nexus/adapter-manifest/1"
MAX_MANIFEST_BYTES = 32 * 1024
MAX_EGRESS_RULES = 64
MAX_COMPATIBILITY = 16
_SYMBOL = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_VERSION = re.compile(r"(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})"
                      r"(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?(?:\+[a-z0-9]+(?:[.-][a-z0-9]+)*)?")
_COMPATIBILITY = re.compile(r"[a-z][a-z0-9_.-]{0,47}/[0-9]{1,4}(?:\.[0-9]{1,4}){0,2}")
_FIELDS = frozenset({
    "schema", "commissioning_digest", "adapter_id", "kind", "version",
    "artifact_digest", "capability_set", "tenant", "privacy_class",
    "egress_allowlist", "mtls_identity", "credential_ref", "compatibility",
})
KeyRole = Mapping[str, bytes] | Collection[bytes]


class AdapterKind(str, Enum):
    EDR = "edr"
    FW = "fw"
    NDR = "ndr"
    SIEM = "siem"
    DNS = "dns"
    ASSET = "asset"
    VULNERABILITY = "vulnerability"


class Capability(str, Enum):
    TELEMETRY_READ = "telemetry_read"
    ADVISORY_READ = "advisory_read"
    EXPOSURE_CHANGE = "exposure_change"


class ManifestRefused(Exception):
    """A stable cause only; untrusted payloads are never echoed into audits."""

    def __init__(self, cause: str) -> None:
        self.cause = cause
        super().__init__(cause)


def is_safe_symbol(value: object) -> bool:
    """A reference/reason code, never a path, token, encoded key, or secret.

    Symbolic names cannot prove absence of an arbitrary human password; reject
    known credential prefixes and long opaque components as well as syntax.
    Commissioning resolves references; these names never carry their values.
    """
    if not isinstance(value, str) or not _SYMBOL.fullmatch(value):
        return False
    if value.startswith(("sk-", "sk_", "ghp_", "github_pat_", "xox", "akia", "bearer_")):
        return False
    return all(len(part) <= 24 for part in re.split(r"[_-]", value))


def _digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def validate_egress(address, port, *, wider_allowlist=(), management_prefixes=(),
                    enforce_prefix=True):
    """Apply the same commissioned address policy at admission and rendering.

    Wider exceptions are exact CIDR/port pairs; they never override forbidden
    address classes or overlap with the commissioned management plane.
    """
    if not isinstance(address, str) or len(address) > 49 or "%" in address:
        raise ManifestRefused("invalid_egress_address")
    try:
        network = ipaddress.ip_network(address, strict=True)
    except ValueError:
        raise ManifestRefused("invalid_egress_address") from None
    if network.prefixlen == 0:
        raise ManifestRefused("wildcard_egress")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ManifestRefused("invalid_egress_port")
    blocked = ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
               "240.0.0.0/4", "::/128", "::1/128", "fe80::/10", "ff00::/8",
               "::ffff:0:0/96")
    if any(network.version == (n := ipaddress.ip_network(cidr)).version
           and network.overlaps(n) for cidr in blocked) or any(
               ip.is_reserved for ip in (network.network_address, network.broadcast_address)):
        raise ManifestRefused("forbidden_egress")
    for cidr in management_prefixes:
        management = ipaddress.ip_network(cidr, strict=True)
        if network.version == management.version and network.overlaps(management):
            raise ManifestRefused("management_egress")
    if (enforce_prefix and network.prefixlen < (24 if network.version == 4 else 64)
            and (str(network), port) not in wider_allowlist):
        raise ManifestRefused("egress_prefix_too_wide")
    return network


@dataclass(frozen=True)
class EgressRule:
    """One literal address or canonical CIDR, and one TCP/UDP port number.

    No protocol is inferred here; confinement must enforce the port separately.
    Default routes, scoped IPv6, host bits, and wildcard notation are refused.
    """

    address: str
    port: int
    wider_allowlist: InitVar[tuple] = ()
    management_prefixes: InitVar[tuple] = ()

    def __post_init__(self, wider_allowlist, management_prefixes) -> None:
        validate_egress(self.address, self.port, wider_allowlist=wider_allowlist,
                        management_prefixes=management_prefixes)


@dataclass(frozen=True)
class AdapterManifest:
    schema: str
    commissioning_digest: str
    adapter_id: str
    kind: AdapterKind
    version: str
    artifact_digest: str
    capability_set: frozenset[Capability]
    tenant: str
    privacy_class: str
    egress_allowlist: tuple[EgressRule, ...]
    mtls_identity: str
    credential_ref: str
    compatibility: tuple[str, ...]
    signer: str
    manifest_digest: str

    def __post_init__(self) -> None:
        if self.schema != ADAPTER_MANIFEST_SCHEMA:
            raise ManifestRefused("unknown_schema")
        if not all(_digest(v) for v in (
            self.commissioning_digest, self.artifact_digest, self.manifest_digest,
        )):
            raise ManifestRefused("invalid_digest")
        for value in (self.adapter_id, self.tenant,
                      self.mtls_identity, self.credential_ref, self.signer):
            if not is_safe_symbol(value):
                raise ManifestRefused("invalid_symbol")
        if (not isinstance(self.privacy_class, str)
                or (self.privacy_class not in {c.value for c in PrivacyClass}
                    and not is_safe_symbol(self.privacy_class))):
            raise ManifestRefused("invalid_privacy_class")
        if not isinstance(self.kind, AdapterKind):
            raise ManifestRefused("unknown_kind")
        if (not isinstance(self.version, str) or len(self.version) > 64
                or not _VERSION.fullmatch(self.version)):
            raise ManifestRefused("invalid_version")
        if (not isinstance(self.capability_set, frozenset) or not self.capability_set
                or not all(isinstance(c, Capability) for c in self.capability_set)):
            raise ManifestRefused("invalid_capabilities")
        if Capability.EXPOSURE_CHANGE in self.capability_set and len(self.capability_set) != 1:
            raise ManifestRefused("mixed_read_change_capabilities")
        if (not isinstance(self.egress_allowlist, tuple)
                or len(self.egress_allowlist) > MAX_EGRESS_RULES
                or not all(isinstance(r, EgressRule) for r in self.egress_allowlist)):
            raise ManifestRefused("invalid_egress_allowlist")
        if len(set(self.egress_allowlist)) != len(self.egress_allowlist):
            raise ManifestRefused("duplicate_egress")
        if (not isinstance(self.compatibility, tuple)
                or not 1 <= len(self.compatibility) <= MAX_COMPATIBILITY
                or not all(isinstance(c, str) and _COMPATIBILITY.fullmatch(c)
                           for c in self.compatibility)):
            raise ManifestRefused("invalid_compatibility")
        if len(set(self.compatibility)) != len(self.compatibility):
            raise ManifestRefused("duplicate_compatibility")


def _object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestRefused("duplicate_field")
        result[key] = value
    return result


def _exact(value: object, fields: frozenset[str]) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ManifestRefused("invalid_fields")
    return value


def read_manifest(
    raw: bytes, *, trusted_keys: Mapping[str, bytes], commissioning_digest: str,
    catalog_keys: KeyRole | None = None,
    registry_keys: KeyRole | None = None,
    revocation_keys: KeyRole | None = None,
    bundle_keys: KeyRole | None = None,
    wider_egress_allowlist=(), management_prefixes=(),
) -> AdapterManifest:
    """Verify only adapter-role keys and bind the declaration to commissioning.

    Optional sibling-role maps refuse overlapping IDs *or* public material,
    including aliases. Collections of raw public keys are also supported for
    revocation/bundle policies without IDs. The whole adapter policy is disjoint.
    ``signer`` and ``manifest_digest`` are computed, never accepted on the wire.
    """
    if not isinstance(raw, bytes) or not SIGNATURE_BYTES < len(raw) <= (
        MAX_MANIFEST_BYTES + SIGNATURE_BYTES
    ):
        raise ManifestRefused("invalid_size")
    if not _digest(commissioning_digest):
        raise ManifestRefused("invalid_commissioning_digest")
    for role in (catalog_keys, registry_keys, revocation_keys, bundle_keys):
        if role is None:
            continue
        shared_ids = isinstance(role, Mapping) and bool(set(trusted_keys) & set(role))
        material = role.values() if isinstance(role, Mapping) else role
        if shared_ids or any(key in material for key in trusted_keys.values()):
            raise ManifestRefused("shared_signing_key")
    signer = None
    signature, payload = raw[:SIGNATURE_BYTES], raw[SIGNATURE_BYTES:]
    for key_id, material in sorted(trusted_keys.items()):
        if not is_safe_symbol(key_id) or not isinstance(material, bytes):
            raise ManifestRefused("invalid_trust_key")
        try:
            verified = verify_detached(
                public_key=material, message=ADAPTER_MANIFEST_DOMAIN + payload,
                signature=signature,
            )
        except SignatureRefused:
            raise ManifestRefused("invalid_trust_key") from None
        if verified:
            signer = key_id
            break
    if signer is None:
        raise ManifestRefused("untrusted_signature")
    try:
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=_object)
    except (UnicodeError, ValueError, RecursionError):
        raise ManifestRefused("invalid_json") from None
    document = _exact(document, _FIELDS)
    if document["commissioning_digest"] != commissioning_digest:
        raise ManifestRefused("commissioning_mismatch")
    capabilities = document["capability_set"]
    if (not isinstance(capabilities, list) or not 1 <= len(capabilities) <= len(Capability)
            or not all(isinstance(c, str) for c in capabilities)):
        raise ManifestRefused("invalid_capabilities")
    if len(set(capabilities)) != len(capabilities):
        raise ManifestRefused("duplicate_capability")
    try:
        kind = AdapterKind(document["kind"])
    except (ValueError, TypeError):
        raise ManifestRefused("unknown_kind") from None
    try:
        capability_set = frozenset(Capability(c) for c in capabilities)
    except ValueError:
        raise ManifestRefused("unknown_capability") from None
    egress = document["egress_allowlist"]
    if not isinstance(egress, list) or len(egress) > MAX_EGRESS_RULES:
        raise ManifestRefused("invalid_egress_allowlist")
    rules = tuple(EgressRule(**_exact(r, frozenset({"address", "port"})),
                             wider_allowlist=wider_egress_allowlist,
                             management_prefixes=management_prefixes) for r in egress)
    for rule in rules:
        validate_egress(rule.address, rule.port, wider_allowlist=wider_egress_allowlist,
                        management_prefixes=management_prefixes)
    compatibility = document["compatibility"]
    if not isinstance(compatibility, list):
        raise ManifestRefused("invalid_compatibility")
    return AdapterManifest(
        **{k: v for k, v in document.items() if k not in {
            "kind", "capability_set", "egress_allowlist", "compatibility",
        }},
        kind=kind, capability_set=capability_set, egress_allowlist=rules,
        compatibility=tuple(compatibility), signer=signer,
        manifest_digest="sha256:" + hashlib.sha256(payload).hexdigest(),
    )
