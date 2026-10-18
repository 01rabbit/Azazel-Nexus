"""Admission fails closed before any operational surface exists."""

import hashlib
import json
from dataclasses import FrozenInstanceError, replace

import pytest
from nacl.signing import SigningKey

from azazel_nexus.integration_broker.manifest import (
    ADAPTER_MANIFEST_DOMAIN,
    ADAPTER_MANIFEST_SCHEMA,
    MAX_MANIFEST_BYTES,
    AdapterKind,
    Capability,
    EgressRule,
    ManifestRefused,
    read_manifest,
)

PIN = "sha256:" + "a" * 64


@pytest.fixture
def document():
    return {
        "schema": ADAPTER_MANIFEST_SCHEMA,
        "commissioning_digest": PIN,
        "adapter_id": "sensor-one",
        "kind": "edr",
        "version": "1.2.3",
        "artifact_digest": "sha256:" + "b" * 64,
        "capability_set": ["telemetry_read", "advisory_read"],
        "tenant": "tenant-one",
        "privacy_class": "internal",
        "egress_allowlist": [{"address": "192.0.2.8", "port": 443}],
        "mtls_identity": "sensor-mtls",
        "credential_ref": "sensor-credential",
        "compatibility": ["azazel-nexus/1"],
    }


@pytest.fixture
def signing_key():
    return SigningKey.generate()


def encode(signing_key, document, *, domain=ADAPTER_MANIFEST_DOMAIN):
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return signing_key.sign(domain + payload).signature + payload


def admit(signing_key, document, **kwargs):
    return read_manifest(
        encode(signing_key, document), trusted_keys={"adapter-key": bytes(signing_key.verify_key)},
        commissioning_digest=PIN, **kwargs,
    )


def test_verified_frozen_manifest_and_payload_digest(signing_key, document):
    manifest = admit(signing_key, document)
    assert manifest.kind is AdapterKind.EDR
    assert manifest.capability_set == {Capability.TELEMETRY_READ, Capability.ADVISORY_READ}
    assert manifest.egress_allowlist == (EgressRule("192.0.2.8", 443),)
    assert manifest.signer == "adapter-key"
    assert manifest.manifest_digest == "sha256:" + hashlib.sha256(
        encode(signing_key, document)[64:]
    ).hexdigest()
    with pytest.raises(FrozenInstanceError):
        manifest.version = "9.9.9"
    with pytest.raises(ManifestRefused):
        replace(manifest, capability_set={Capability.TELEMETRY_READ})


@pytest.mark.parametrize("kind", list(AdapterKind))
def test_all_adapter_kinds(signing_key, document, kind):
    document["kind"] = kind.value
    assert admit(signing_key, document).kind is kind


@pytest.mark.parametrize("caps", [
    ["telemetry_read"], ["advisory_read"], ["telemetry_read", "advisory_read"],
    ["exposure_change"],
])
def test_separate_capability_sets(signing_key, document, caps):
    document["capability_set"] = caps
    assert {c.value for c in admit(signing_key, document).capability_set} == set(caps)


@pytest.mark.parametrize("field", [
    "schema", "commissioning_digest", "adapter_id", "kind", "version", "artifact_digest",
    "capability_set", "tenant", "privacy_class", "egress_allowlist", "mtls_identity",
    "credential_ref", "compatibility",
])
def test_every_field_required(signing_key, document, field):
    del document[field]
    with pytest.raises(ManifestRefused, match="invalid_fields"):
        admit(signing_key, document)


@pytest.mark.parametrize("extra", ["command", "installer", "secret", "signer", "manifest_digest"])
def test_extra_fields_refused(signing_key, document, extra):
    document[extra] = "never-executed"
    with pytest.raises(ManifestRefused, match="invalid_fields"):
        admit(signing_key, document)


@pytest.mark.parametrize(("field", "value"), [
    ("schema", "azazel-nexus/adapter-manifest/2"),
    ("commissioning_digest", "sha256:" + "c" * 64),
    ("artifact_digest", "b" * 64), ("artifact_digest", None),
    ("kind", "shell"), ("kind", []), ("kind", None),
    ("version", "latest"), ("version", "1.*"), ("version", ">=1.0.0"),
    ("version", "1.0"), ("version", 1), ("version", "01.0.0"),
    ("version", "1.0.0-" + "x" * 65),
    ("adapter_id", "../adapter"), ("adapter_id", "a" * 65), ("adapter_id", False),
    ("tenant", "https://tenant"), ("privacy_class", ""), ("mtls_identity", "key.pem"),
    ("credential_ref", "-----BEGIN PRIVATE KEY-----"),
    ("credential_ref", "/run/credentials/key"),
    ("credential_ref", "Bearer eyJhbGciOiJIUzI1NiJ9"),
    ("credential_ref", "eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig"),
    ("credential_ref", "sk-testsecret"), ("credential_ref", "ghp_testsecret"),
    ("credential_ref", "github_pat_test"), ("credential_ref", "xoxb-secret"),
    ("credential_ref", "akia-secret"), ("credential_ref", "bearer_secret"),
    ("credential_ref", "abcdef0123456789" * 4),
    ("credential_ref", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="),
    ("credential_ref", {"name": "key", "secret": "value"}),
    ("capability_set", []), ("capability_set", "telemetry_read"),
    ("capability_set", [True]), ("capability_set", ["execute"]),
    ("capability_set", ["telemetry_read", "telemetry_read"]),
    ("capability_set", ["telemetry_read", "exposure_change"]),
    ("capability_set", ["advisory_read", "exposure_change"]),
    ("capability_set", ["telemetry_read", "advisory_read", "exposure_change"]),
    ("egress_allowlist", "192.0.2.1"), ("egress_allowlist", [{}] * 65),
    ("egress_allowlist", [{"address": "192.0.2.1"}]),
    ("egress_allowlist", [{"address": "192.0.2.1", "port": 443, "command": "bad"}]),
    ("egress_allowlist", [None]),
    ("egress_allowlist", [{"address": "192.0.2.1", "port": 443}] * 2),
    ("compatibility", []), ("compatibility", "azazel-nexus/1"),
    ("compatibility", ["azazel-nexus/*"]), ("compatibility", [None]),
    ("compatibility", ["azazel-nexus/1"] * 2),
    ("compatibility", ["azazel-nexus/1"] * 17),
])
def test_invalid_field_refused_without_echoing_payload(signing_key, document, field, value):
    document[field] = value
    with pytest.raises(ManifestRefused) as result:
        admit(signing_key, document)
    assert str(result.value) == result.value.cause
    assert "secret" not in str(result.value)


@pytest.mark.parametrize("address", [
    "192.0.2.8", "192.0.2.0/24", "2001:db8::1", "2001:db8::/64",
])
def test_numeric_egress(signing_key, document, address):
    document["egress_allowlist"] = [{"address": address, "port": 65535}]
    assert admit(signing_key, document).egress_allowlist[0].address == address


def test_empty_egress_is_deny_all(signing_key, document):
    document["egress_allowlist"] = []
    assert admit(signing_key, document).egress_allowlist == ()


@pytest.mark.parametrize("address", [
    "example.org", "https://192.0.2.1", "*.example.org", "*", "0.0.0.0/0", "::/0",
    "192.0.2.1:443", "[2001:db8::1]", "fe80::1%en0", "192.0.2.1/24",
    "999.0.0.1", "", None, 123, "1" * 50,
])
def test_nonliteral_or_wildcard_egress_refused(signing_key, document, address):
    document["egress_allowlist"] = [{"address": address, "port": 443}]
    with pytest.raises(ManifestRefused):
        admit(signing_key, document)


@pytest.mark.parametrize("port", [0, 65536, -1, True, "443", 443.0, None, "*"])
def test_invalid_ports(signing_key, document, port):
    document["egress_allowlist"][0]["port"] = port
    with pytest.raises(ManifestRefused, match="invalid_egress_port"):
        admit(signing_key, document)


@pytest.mark.parametrize("role", ["catalog_keys", "registry_keys", "revocation_keys", "bundle_keys"])
@pytest.mark.parametrize("alias", [False, True])
def test_role_separation_by_id_and_material(signing_key, document, role, alias):
    other = bytes(SigningKey.generate().verify_key)
    role_keys = {"other-key": bytes(signing_key.verify_key)} if alias else {"adapter-key": other}
    with pytest.raises(ManifestRefused, match="shared_signing_key"):
        admit(signing_key, document, **{role: role_keys})


def test_disjoint_roles(signing_key, document):
    roles = {role: {role.replace("_", "-"): bytes(SigningKey.generate().verify_key)}
             for role in ["catalog_keys", "registry_keys", "revocation_keys", "bundle_keys"]}
    assert admit(signing_key, document, **roles).adapter_id == "sensor-one"


@pytest.mark.parametrize("role", ["catalog_keys", "registry_keys", "revocation_keys", "bundle_keys"])
def test_role_separation_accepts_raw_public_key_sets(signing_key, document, role):
    with pytest.raises(ManifestRefused, match="shared_signing_key"):
        admit(signing_key, document, **{role: frozenset({bytes(signing_key.verify_key)})})
    assert admit(signing_key, document, **{
        role: frozenset({bytes(SigningKey.generate().verify_key)}),
    }).signer == "adapter-key"


@pytest.mark.parametrize("domain", [b"", b"azazel-nexus/model-catalog/v1\0",
                                    b"azazel-nexus/source-registry/v1\0",
                                    b"azazel-nexus/revocation/v1\0"])
def test_other_signature_domains_refused(signing_key, document, domain):
    with pytest.raises(ManifestRefused, match="untrusted_signature"):
        read_manifest(encode(signing_key, document, domain=domain),
                      trusted_keys={"adapter-key": bytes(signing_key.verify_key)},
                      commissioning_digest=PIN)


@pytest.mark.parametrize("mode", ["unknown", "empty", "tampered", "bad-key", "bad-id"])
def test_trust_refusals(signing_key, document, mode):
    raw = encode(signing_key, document)
    keys = {"adapter-key": bytes(signing_key.verify_key)}
    if mode == "unknown":
        keys = {"adapter-key": bytes(SigningKey.generate().verify_key)}
    elif mode == "empty":
        keys = {}
    elif mode == "tampered":
        raw = raw[:-1] + b" "
    elif mode == "bad-key":
        keys = {"adapter-key": b"bad"}
    else:
        keys = {"../key": bytes(signing_key.verify_key)}
    with pytest.raises(ManifestRefused):
        read_manifest(raw, trusted_keys=keys, commissioning_digest=PIN)


@pytest.mark.parametrize("raw", [b"", b"x" * 64, b"x" * (MAX_MANIFEST_BYTES + 65), None])
def test_size_refusals(raw):
    with pytest.raises(ManifestRefused, match="invalid_size"):
        read_manifest(raw, trusted_keys={}, commissioning_digest=PIN)


@pytest.mark.parametrize("payload", [
    b"{", b"\xff", b"[]", b"null", b'{"schema":1,"schema":2}',
    b'{"egress_allowlist":[{"port":1,"port":2}]}', b"[" * 1100 + b"]" * 1100,
])
def test_malformed_signed_payload(signing_key, payload):
    raw = signing_key.sign(ADAPTER_MANIFEST_DOMAIN + payload).signature + payload
    with pytest.raises(ManifestRefused):
        read_manifest(raw, trusted_keys={"adapter-key": bytes(signing_key.verify_key)},
                      commissioning_digest=PIN)


def test_invalid_commissioning_pin(signing_key, document):
    with pytest.raises(ManifestRefused, match="invalid_commissioning_digest"):
        read_manifest(encode(signing_key, document), trusted_keys={}, commissioning_digest="bad")


@pytest.mark.parametrize("address", ["127.0.0.1", "0.0.0.0", "169.254.169.254",
    "224.0.0.1", "240.0.0.1", "::", "::1", "fe80::1", "ff02::1", "::ffff:192.0.2.8",
    "100::1", "192.0.0.0/16", "2001:db8::/32"])
def test_egress_special_and_wide_ranges_refused(signing_key, document, address):
    document["egress_allowlist"] = [{"address": address, "port": 443}]
    with pytest.raises(ManifestRefused):
        admit(signing_key, document)


def test_wide_exception_is_exact_and_cannot_override_management(signing_key, document):
    document["egress_allowlist"] = [{"address": "10.20.0.0/16", "port": 443}]
    exception = (("10.20.0.0/16", 443),)
    assert admit(signing_key, document, wider_egress_allowlist=exception)
    with pytest.raises(ManifestRefused):
        admit(signing_key, document, wider_egress_allowlist=(("10.20.0.0/16", 8443),))
    with pytest.raises(ManifestRefused, match="management_egress"):
        admit(signing_key, document, wider_egress_allowlist=exception,
              management_prefixes=("10.20.1.0/24",))
    document["egress_allowlist"] = [{"address": "169.254.0.0/16", "port": 443}]
    with pytest.raises(ManifestRefused):
        admit(signing_key, document, wider_egress_allowlist=(("169.254.0.0/16", 443),))
