"""Two documents, two authorities, and neither one sufficient (#105).

The property this file exists to defend: **the catalog signer cannot name an
endpoint, and the registry administrator cannot introduce a model.** Only
both together produce something to fetch, and the breadth that compromise
requires is what the separation buys.

Both signing oracles are fixed, test-only keys derived from literal strings.
They are shared with no production, commissioned or release key, exist only
for the run, and no key material reaches a file, a fixture, a log or an
assertion.
"""

from __future__ import annotations

import ast
import hashlib
import json
import pathlib

import pytest

from azazel_nexus import source_registry
from azazel_nexus.model_acquisition import KNOWN_SOURCES
from azazel_nexus.model_catalog import CATALOG_DOMAIN, ModelEntry
from azazel_nexus.resource_profile import ResourceProfile
from azazel_nexus.source_registry import (
    MAX_SOURCES,
    REGISTRY_DOMAIN,
    REGISTRY_FILENAME,
    REGISTRY_SCHEMA,
    ArtifactClass,
    CommissionedSources,
    Refusal,
    RegistryRefused,
    SourceRecord,
    read_registry,
    registry_payload,
    resolve_candidate,
)

nacl_signing = pytest.importorskip("nacl.signing", reason="PyNaCl is a dev dependency")

COMMISSIONING = "sha256:" + "c" * 64
WEIGHTS = b"weights, not a program"

#: Two separate, fixed, test-only keys. Two, because one would be the defect.
_CATALOG_SEED = hashlib.sha256(b"azazel-nexus/test-only/registry/catalog").digest()
_REGISTRY_SEED = hashlib.sha256(b"azazel-nexus/test-only/registry/registry").digest()


def _key(seed):
    return nacl_signing.SigningKey(seed)


def commissioned(**overrides) -> CommissionedSources:
    fields = {
        "catalog_keys": {"catalog-key": bytes(_key(_CATALOG_SEED).verify_key)},
        "registry_keys": {"registry-key": bytes(_key(_REGISTRY_SEED).verify_key)},
        "commissioning_digest": COMMISSIONING,
    }
    fields.update(overrides)
    return CommissionedSources(**fields)


def a_record(**overrides) -> SourceRecord:
    fields = {
        "source_id": "vendor-mirror",
        "host": "models-mirror.azazel.invalid",
        "port": 443,
        "path_template": "/artifacts/{digest}",
        "certificate_pin": "sha256:" + "a" * 64,
        "client_identity": "node-client",
        "bandwidth_bytes_per_second": 10 * 1024 * 1024,
        "allowed_artifact_classes": (ArtifactClass.MODEL_WEIGHTS,),
    }
    fields.update(overrides)
    return SourceRecord(**fields)


def an_entry(**overrides) -> ModelEntry:
    fields = {
        "model_id": "small-advisor",
        "format": "gguf",
        "digest": "sha256:" + hashlib.sha256(WEIGHTS).hexdigest(),
        "size_bytes": len(WEIGHTS),
        "provenance": "fixture",
        "license_acknowledgement_required": False,
        "runtime_abi": "llama.cpp/1",
        "purpose": "summarise a situation frame",
        "context_limit": 4096,
        "declared_min_ram_mib": 4096,
        "declared_min_disk_mib": 2048,
        "declared_profile": ResourceProfile.LITE,
        "rollback_lineage": (),
        "source_id": "vendor-mirror",
    }
    fields.update(overrides)
    return ModelEntry(**fields)


def write_registry(directory, records, *, seed=_REGISTRY_SEED, version=1,
                   commissioning=COMMISSIONING, domain=REGISTRY_DOMAIN, payload=None):
    body = payload if payload is not None else registry_payload(
        version=version, commissioning_digest=commissioning, records=list(records)
    )
    signature = bytes(_key(seed).sign(domain + body).signature)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / REGISTRY_FILENAME
    path.write_bytes(signature + body)
    return path


def a_registry(tmp_path, records=None):
    path = write_registry(tmp_path, records if records is not None else [a_record()])
    return read_registry(path, commissioned=commissioned())


# -- the crossing ----------------------------------------------------------


def test_the_catalog_signer_cannot_name_an_endpoint(tmp_path) -> None:
    """A catalog carries a symbol. The location comes from the other
    document, signed by the other authority.

    An attacker holding the catalog key can name any symbol they like; a
    symbol this node's registry does not carry resolves to nothing.
    """

    registry = a_registry(tmp_path)
    # Whatever the catalog says, the address comes from here.
    candidate = resolve_candidate(an_entry(), registry)
    assert candidate.record.host == "models-mirror.azazel.invalid"
    # And a symbol the registry does not carry is a refusal, not a lookup.
    with pytest.raises(RegistryRefused) as caught:
        resolve_candidate(an_entry(source_id="vendor-primary"), registry)
    assert caught.value.cause is Refusal.UNKNOWN_SOURCE
    assert "rather than a lookup elsewhere" in str(caught.value)


def test_the_registry_administrator_cannot_introduce_a_model(tmp_path) -> None:
    """A registry says where symbols point. It names no models at all.

    The record's document carries no `model_id`, no digest and no size, so
    there is nothing for a registry to add a model with.
    """

    document = a_record().as_document()
    assert "model_id" not in document
    assert "digest" not in document
    assert "size_bytes" not in document
    # A candidate takes its model, digest and size from the catalog entry.
    registry = a_registry(tmp_path)
    entry = an_entry()
    candidate = resolve_candidate(entry, registry)
    assert candidate.model_id == entry.model_id
    assert candidate.digest == entry.digest
    assert candidate.size_bytes == entry.size_bytes


def test_neither_document_alone_produces_a_candidate(tmp_path) -> None:
    """Both, or nothing to fetch."""

    empty = read_registry(write_registry(tmp_path / "a", []), commissioned=commissioned())
    with pytest.raises(RegistryRefused):
        resolve_candidate(an_entry(), empty)
    stocked = a_registry(tmp_path / "b")
    with pytest.raises(RegistryRefused) as caught:
        resolve_candidate(an_entry(source_id=None), stocked)
    assert caught.value.cause is Refusal.SOURCE_UNAVAILABLE
    assert "the registry is not consulted" in str(caught.value).lower()


# -- the two trust policies stay two --------------------------------------


def test_one_key_in_both_roles_refuses_to_commission() -> None:
    """Not a documented expectation. A constructor that will not build.

    Two documents under one trust policy is one key that signs both, and the
    crossing collapses into a single point.
    """

    material = bytes(_key(_CATALOG_SEED).verify_key)
    with pytest.raises(RegistryRefused) as caught:
        CommissionedSources(
            catalog_keys={"shared": material},
            registry_keys={"shared": material},
            commissioning_digest=COMMISSIONING,
        )
    assert caught.value.cause is Refusal.SHARED_SIGNING_KEY
    assert "name a model and say where it comes from" in str(caught.value)


def test_one_key_under_two_names_is_still_one_key() -> None:
    """Renaming is not separating."""

    material = bytes(_key(_CATALOG_SEED).verify_key)
    with pytest.raises(RegistryRefused) as caught:
        CommissionedSources(
            catalog_keys={"catalog-role": material},
            registry_keys={"registry-role": material},
            commissioning_digest=COMMISSIONING,
        )
    assert caught.value.cause is Refusal.SHARED_SIGNING_KEY
    assert "Two ids for one key is one key" in str(caught.value)


def test_the_two_domains_differ_so_one_signature_cannot_be_both() -> None:
    """Even under one key, the tag is part of what is signed."""

    assert REGISTRY_DOMAIN != CATALOG_DOMAIN
    assert b"source-registry" in REGISTRY_DOMAIN
    assert b"model-catalog" in CATALOG_DOMAIN


def test_a_catalog_signature_does_not_verify_as_a_registry(tmp_path) -> None:
    """The same payload, the right registry key, the catalog's domain."""

    path = write_registry(tmp_path, [a_record()], domain=CATALOG_DOMAIN)
    with pytest.raises(RegistryRefused) as caught:
        read_registry(path, commissioned=commissioned())
    assert caught.value.cause is Refusal.REGISTRY_UNSIGNED
    assert "whatever key made it" in str(caught.value)


def test_the_catalog_key_cannot_sign_a_registry(tmp_path) -> None:
    """Right domain, right shape, wrong role."""

    path = write_registry(tmp_path, [a_record()], seed=_CATALOG_SEED)
    with pytest.raises(RegistryRefused) as caught:
        read_registry(path, commissioned=commissioned())
    assert caught.value.cause is Refusal.REGISTRY_UNSIGNED


# -- the registry is signed, versioned, canonical and bound ---------------


def test_a_verified_registry_names_its_signer(tmp_path) -> None:
    registry = a_registry(tmp_path)
    assert registry.signer == "registry-key"
    assert registry.schema == REGISTRY_SCHEMA


def test_an_absent_registry_is_absent_not_empty(tmp_path) -> None:
    with pytest.raises(RegistryRefused) as caught:
        read_registry(tmp_path / REGISTRY_FILENAME, commissioned=commissioned())
    assert caught.value.cause is Refusal.REGISTRY_ABSENT
    # And an empty one is a different answer.
    empty = read_registry(write_registry(tmp_path / "e", []), commissioned=commissioned())
    assert empty.records == ()


def test_a_registry_naming_another_schema_is_refused(tmp_path) -> None:
    """Refused, not best-effort parsed. A reader that guesses at a shape it
    does not know accepts a document nobody wrote for it."""

    body = registry_payload(
        version=1, commissioning_digest=COMMISSIONING, records=[a_record()]
    )
    document = json.loads(body)
    document["schema"] = "azazel-nexus/source-registry/99"
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path = write_registry(tmp_path, [], payload=payload)
    with pytest.raises(RegistryRefused) as caught:
        read_registry(path, commissioned=commissioned())
    assert "source-registry/99" in str(caught.value)
    assert caught.value.cause is Refusal.REGISTRY_INVALID


def test_a_registry_pinned_under_another_commissioning_is_refused(tmp_path) -> None:
    path = write_registry(tmp_path, [a_record()], commissioning="sha256:" + "d" * 64)
    with pytest.raises(RegistryRefused) as caught:
        read_registry(path, commissioned=commissioned())
    assert "pinned under commissioning" in str(caught.value)


def test_the_payload_is_canonical_and_order_independent() -> None:
    records = [a_record(source_id="vendor-primary"), a_record()]
    once = registry_payload(version=1, commissioning_digest=COMMISSIONING, records=records)
    document = json.loads(once)
    assert once == json.dumps(
        document, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    assert [s["source_id"] for s in document["sources"]] == [
        "vendor-mirror", "vendor-primary"
    ]
    assert registry_payload(
        version=1, commissioning_digest=COMMISSIONING, records=list(reversed(records))
    ) == once


def test_a_duplicated_source_id_is_refused(tmp_path) -> None:
    path = write_registry(tmp_path, [a_record(), a_record()])
    with pytest.raises(RegistryRefused) as caught:
        read_registry(path, commissioned=commissioned())
    assert "an id names one source" in str(caught.value)


def test_a_registry_offering_too_many_sources_is_refused(tmp_path) -> None:
    records = [
        a_record(source_id=f"s{index:02d}") for index in range(MAX_SOURCES + 1)
    ]
    path = write_registry(tmp_path, records)
    with pytest.raises(RegistryRefused) as caught:
        read_registry(path, commissioned=commissioned())
    assert str(MAX_SOURCES) in str(caught.value)


def test_a_record_with_an_extra_field_is_refused(tmp_path) -> None:
    body = registry_payload(
        version=1, commissioning_digest=COMMISSIONING, records=[a_record()]
    )
    document = json.loads(body)
    document["sources"][0]["proxy"] = "http://somewhere.invalid"
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path = write_registry(tmp_path, [], payload=payload)
    with pytest.raises(RegistryRefused) as caught:
        read_registry(path, commissioned=commissioned())
    assert "A field nobody decided on is a field nobody checks" in str(caught.value)


# -- a host field is not a URL field wearing another name ------------------


@pytest.mark.parametrize(
    "host",
    [
        "https://models.invalid",
        "models.invalid:443",
        "models.invalid/artifacts",
        "user:pass@models.invalid",
        "models.invalid?a=b",
        "../models.invalid",
        "127.0.0.1",
        "",
    ],
)
def test_a_host_that_carries_more_than_a_host_is_refused(host) -> None:
    with pytest.raises(RegistryRefused) as caught:
        a_record(host=host)
    assert "is not a hostname" in str(caught.value)


@pytest.mark.parametrize(
    "template", ["/{name}/{digest}", "artifacts/{digest}", "/../{digest}", "/artifacts/x"]
)
def test_a_path_template_with_another_hole_or_traversal_is_refused(template) -> None:
    with pytest.raises(RegistryRefused):
        a_record(path_template=template)


@pytest.mark.parametrize("port", [0, -1, 65536, "443", True])
def test_a_port_that_is_not_one_is_refused(port) -> None:
    with pytest.raises(RegistryRefused):
        a_record(port=port)


@pytest.mark.parametrize("pin", ["", "sha1:" + "a" * 40, "a" * 64, "sha256:zz"])
def test_a_pin_that_is_not_a_sha256_pin_is_refused(pin) -> None:
    with pytest.raises(RegistryRefused):
        a_record(certificate_pin=pin)


def test_the_registry_names_an_identity_and_never_carries_its_material() -> None:
    """A registry that carried a private key would be a document that leaked
    one every time it was read."""

    document = a_record().as_document()
    assert document["client_identity"] == "node-client"
    flattened = json.dumps(document).lower()
    for forbidden in ("begin private", "-----", "private_key", "secret", "token"):
        assert forbidden not in flattened, forbidden
    with pytest.raises(RegistryRefused):
        a_record(client_identity="-----BEGIN PRIVATE KEY-----")


# -- ceilings and classes --------------------------------------------------


def test_a_source_must_allow_at_least_one_class() -> None:
    """A source that may serve nothing is a source nobody decided about, not
    a source that serves everything."""

    with pytest.raises(RegistryRefused) as caught:
        a_record(allowed_artifact_classes=())
    assert "not a source that serves everything" in str(caught.value)


def test_a_class_the_source_does_not_allow_is_refused(tmp_path) -> None:
    class Other(str):
        value = "something-else"

    registry = a_registry(tmp_path)
    with pytest.raises(RegistryRefused) as caught:
        resolve_candidate(an_entry(), registry, artifact_class=Other())
    assert caught.value.cause is Refusal.ARTIFACT_CLASS_NOT_ALLOWED


def test_an_unenumerated_class_is_refused_at_read(tmp_path) -> None:
    body = registry_payload(
        version=1, commissioning_digest=COMMISSIONING, records=[a_record()]
    )
    document = json.loads(body)
    document["sources"][0]["allowed_artifact_classes"] = ["anything-at-all"]
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path = write_registry(tmp_path, [], payload=payload)
    with pytest.raises(RegistryRefused) as caught:
        read_registry(path, commissioned=commissioned())
    assert "nobody decided to allow" in str(caught.value)


@pytest.mark.parametrize("bandwidth", [0, -1, "fast", True])
def test_a_bandwidth_ceiling_that_is_not_one_is_refused(bandwidth) -> None:
    with pytest.raises(RegistryRefused):
        a_record(bandwidth_bytes_per_second=bandwidth)


# -- the candidate is not a permission -------------------------------------


def test_a_candidate_carries_no_permission_and_no_admission(tmp_path) -> None:
    candidate = resolve_candidate(an_entry(), a_registry(tmp_path))
    assert not hasattr(candidate, "admitted")
    assert not hasattr(candidate, "confirmed")
    assert not hasattr(candidate, "permitted")
    # The path is built from the digest, and from nothing a caller chose.
    assert candidate.digest.split(":")[1] in candidate.path


def test_a_candidate_event_leaks_no_location_pin_or_identity(tmp_path) -> None:
    event = resolve_candidate(an_entry(), a_registry(tmp_path)).as_event()
    flattened = repr(event).lower()
    for forbidden in ("invalid", "http", "://", "pin", "identity", "port", "path"):
        assert forbidden not in flattened, forbidden


def test_the_registry_module_opens_nothing() -> None:
    """It resolves and refuses. The one module that may connect is named in
    `test_runtime_boundary.py`, and this is not it."""

    tree = ast.parse(
        pathlib.Path(source_registry.__file__).read_text(encoding="utf-8")
    )
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {
        "socket", "ssl", "http", "urllib", "requests", "httpx", "subprocess"
    } == set(), sorted(imported)


def test_every_symbol_the_build_knows_can_be_carried(tmp_path) -> None:
    """The registry and the build's symbol set are about the same symbols."""

    records = [a_record(source_id=symbol) for symbol in KNOWN_SOURCES]
    registry = a_registry(tmp_path, records)
    assert {r.source_id for r in registry.records} == set(KNOWN_SOURCES)


def test_no_registry_is_committed_to_the_repository() -> None:
    repository = pathlib.Path(__file__).resolve().parents[2]
    found = [
        str(path.relative_to(repository))
        for path in repository.rglob(REGISTRY_FILENAME)
        if ".git" not in path.parts and ".venv" not in path.parts
    ]
    assert found == [], f"{found} ship a source registry"


#: A trailing line ending, blank or NUL after a valid value. `$` matches before
#: a final `\n`, so a grammar closed with `$` and used with `match` admitted
#: the first of these (Azazel-Fabric#65). Each must be refused.
TRAILING = ("\n", "\r\n", " ", "\x00")


@pytest.mark.parametrize(
    "field, valid",
    [
        ("source_id", "vendor-mirror"),
        ("host", "models-mirror.azazel.invalid"),
        ("certificate_pin", "sha256:" + "a" * 64),
        ("client_identity", "node-client"),
    ],
)
@pytest.mark.parametrize("suffix", TRAILING)
def test_a_source_field_with_a_trailing_line_ending_is_refused(
    field: str, valid: str, suffix: str
) -> None:
    a_record(**{field: valid})
    with pytest.raises(RegistryRefused) as caught:
        a_record(**{field: valid + suffix})
    assert caught.value.cause is Refusal.REGISTRY_INVALID
