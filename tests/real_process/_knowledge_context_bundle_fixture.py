"""Synthetic Knowledge Context commissioning bundle builder (test use only).

Pure Python, no pytest. Produces the exact flat directory that
azazel_nexus_runtime.knowledge_context_config.load_commissioning() reads.
Keys, certificates and policies are caller-supplied synthetic material.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from nacl.signing import SigningKey

from azazel_nexus.knowledge_peer import REGISTRY_DOMAIN, SCHEMA, canonical

MANIFEST_SCHEMA = "azazel.knowledge-context.commissioning/1"
DEFAULT_POLICY = {
    "version": "synthetic-context-1",
    "remote_default": "deny",
    "classes": {"P0-public": {"remote": "allow", "fields": ["question"]}},
    "limits": {"max_bytes": 4096},
}
#: build_bundle(..., defect=NAME) values
DEFECTS = ("bad_signature", "expired_registry", "missing_value", "enabled_false",
           "enabled_string", "bad_ttl", "short_alias", "wrong_identity")


def _raw(value) -> bytes:
    return value.read_bytes() if isinstance(value, Path) else (
        Path(value).read_bytes() if isinstance(value, str) else bytes(value))


def registry_document(*, peer_id, peer_address, peer_public_key_hex, peer_host,
                      peer_port, certificate_pin, client_identity, commissioning_digest,
                      issued_at, expires_at, version=1):
    return {
        "schema": SCHEMA, "commissioning_digest": commissioning_digest,
        "issued_at": issued_at, "expires_at": expires_at, "version": version,
        "peers": [{
            "endpoint": {
                "provider_id": peer_id, "host": peer_host, "port": peer_port,
                "path_template": "/knowledge/v1", "model_id": "knowledge-v1",
                "certificate_pin": certificate_pin, "client_identity": client_identity,
                "max_request_bytes": 4096, "max_response_bytes": 65536,
                "deadline_seconds": 5, "allowed_privacy_classes": ["P0-public"],
            },
            "addresses": [peer_address], "public_key": peer_public_key_hex,
            "max_inflight": 1,
        }],
    }


def build_bundle(dest_dir: Path, *, peer_id: str, peer_address: str,
                 peer_host: str, peer_port: int, certificate_pin: str,
                 peer_signing_key: SigningKey, registry_signing_key: SigningKey,
                 ca, client_cert, client_key,
                 client_identity: str = "knowledge-context-client",
                 commissioning_digest: str = "synthetic-commissioning",
                 issued_at: str = "2026-01-01T00:00:00+00:00",
                 expires_at: str = "2099-01-01T00:00:00+00:00",
                 enabled: bool = True, max_ttl_seconds: int = 60,
                 mission: str = "synthetic-mission",
                 sanitizer_policy: dict | None = None,
                 alias_key: bytes = b"A" * 32,
                 defect: str | None = None,
                 mode: int = 0o644, secret_mode: int = 0o600,
                 owner: tuple[int, int] | None = None) -> Path:
    """Write the bundle into dest_dir (created 0755 if absent) and return it.

    ca / client_cert / client_key: PEM bytes or a path to a PEM file.
    defect: None or one of DEFECTS, applied on top of otherwise valid material.
    owner: optional (uid, gid) chown for every file and the directory (needs root).
    Files are 0644 and secrets 0600 by default, which the loader accepts when
    the owner matches its configured owner.
    """
    if defect is not None and defect not in DEFECTS:
        raise ValueError("unknown defect")
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(dest_dir, 0o755)
    if defect == "expired_registry":
        issued_at, expires_at = "2020-01-01T00:00:00+00:00", "2020-01-02T00:00:00+00:00"
    document = registry_document(
        peer_id=peer_id, peer_address=peer_address,
        peer_public_key_hex=bytes(peer_signing_key.verify_key).hex(),
        peer_host=peer_host, peer_port=peer_port, certificate_pin=certificate_pin,
        client_identity=("other-identity" if defect == "wrong_identity" else client_identity),
        commissioning_digest=commissioning_digest,
        issued_at=issued_at, expires_at=expires_at)
    registry = registry_signing_key.sign(
        REGISTRY_DOMAIN + canonical(document)).signature + canonical(document)
    if defect == "bad_signature":
        registry = bytes([registry[0] ^ 1]) + registry[1:]
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "enabled": "true" if defect == "enabled_string" else (
            False if defect == "enabled_false" else enabled),
        "peer_id": peer_id, "client_identity": client_identity,
        "commissioning_digest": commissioning_digest,
        "max_ttl_seconds": 0 if defect == "bad_ttl" else max_ttl_seconds,
        "mission": mission,
        "sanitizer_policy": sanitizer_policy or DEFAULT_POLICY,
    }
    if defect == "missing_value":
        del manifest["mission"]
    if defect == "short_alias":
        alias_key = alias_key[:31]
    files = {
        "manifest.json": (json.dumps(manifest, sort_keys=True).encode(), mode),
        "registry-keys.json": (json.dumps(
            {"knowledge-registry": bytes(registry_signing_key.verify_key).hex()}).encode(), mode),
        "registry.signed": (registry, mode),
        "ca.pem": (_raw(ca), mode),
        "client.pem": (_raw(client_cert), mode),
        "client.key": (_raw(client_key), secret_mode),
        "alias.key": (alias_key, secret_mode),
    }
    for name, (data, perm) in files.items():
        path = dest_dir / name
        path.write_bytes(data)
        os.chmod(path, perm)
        if owner is not None:
            os.chown(path, *owner)
    if owner is not None:
        os.chown(dest_dir, *owner)
    return dest_dir
