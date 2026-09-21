"""The third registry, and the reason it is not the second one (#98).

A holder of the Source Registry role must not be able to name somewhere this
node sends what it has observed. Pulling a file and pushing a report are
different acts, so they are different documents, different domains, different
roles and different commissioned key sets.

The signing key here is a fixed package-owned test seed. No provider is
commissioned, no endpoint is real, and nothing is contacted.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from nacl import signing as nacl_signing

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "runtime" / "src"))

from azazel_nexus.model_catalog import CATALOG_DOMAIN  # noqa: E402
from azazel_nexus.provider_registry import (  # noqa: E402
    MAX_PROVIDER_REGISTRY_BYTES,
    PROVIDER_DOMAIN,
    PROVIDER_SCHEMA,
    ProviderRecord,
    ProviderRefusal,
    ProviderRefused,
    ProviderTrust,
    load_provider_registry,
    provider_registry_payload,
    resolve_provider,
)
from azazel_nexus.sanitizer import NEVER_REMOTE, PrivacyClass  # noqa: E402
from azazel_nexus.source_registry import REGISTRY_DOMAIN  # noqa: E402

_SEED = b"\x51" * 32
_OTHER = b"\x52" * 32
DIGEST = "sha256:" + "0" * 64


def _key(seed=_SEED):
    return nacl_signing.SigningKey(seed)


def _public(seed=_SEED) -> bytes:
    return bytes(_key(seed).verify_key)


def _record(**overrides) -> ProviderRecord:
    fields = dict(
        provider_id="vendor-advisory",
        host="advisory.example.test",
        port=443,
        path_template="/v1/{model}/advise",
        certificate_pin=DIGEST,
        client_identity="node-advisory-client",
        model_id="advisor",
        max_request_bytes=4096,
        max_response_bytes=8192,
        deadline_seconds=10,
        allowed_privacy_classes=(PrivacyClass.P1_SANITIZED,),
    )
    fields.update(overrides)
    return ProviderRecord(**fields)


def _signed(tmp_path, *, records=None, seed=_SEED, domain=PROVIDER_DOMAIN,
            commissioning=DIGEST, version=1) -> Path:
    payload = provider_registry_payload(
        version=version,
        commissioning_digest=commissioning,
        records=records if records is not None else [_record()],
    )
    path = tmp_path / "providers.signed"
    path.write_bytes(bytes(_key(seed).sign(domain + payload).signature) + payload)
    return path


def _trust(**overrides) -> ProviderTrust:
    fields = dict(
        provider_keys={"provider-1": _public()},
        commissioning_digest=DIGEST,
    )
    fields.update(overrides)
    return ProviderTrust(**fields)


# -- it loads, and only under its own role --------------------------------


def test_a_signed_registry_loads(tmp_path):
    registry = load_provider_registry(_signed(tmp_path), trust=_trust())
    assert registry.signer == "provider-1"
    assert set(registry.records) == {"vendor-advisory"}


def test_no_registry_commissioned_is_not_an_error_it_is_the_shipped_state(tmp_path):
    with pytest.raises(ProviderRefused) as caught:
        load_provider_registry(tmp_path / "absent", trust=_trust())
    assert caught.value.refusal is ProviderRefusal.NO_PROVIDER_COMMISSIONED


@pytest.mark.parametrize(
    "domain", [CATALOG_DOMAIN, REGISTRY_DOMAIN, b""],
    ids=["catalog", "source-registry", "no-domain"],
)
def test_another_roles_signature_does_not_verify_here(tmp_path, domain):
    """**The separation.** Even under the same key material: the domain tag
    differs, so a source-registry signature does not authorise a provider."""

    with pytest.raises(ProviderRefused) as caught:
        load_provider_registry(_signed(tmp_path, domain=domain), trust=_trust())
    assert caught.value.refusal is ProviderRefusal.REGISTRY_UNSIGNED


def test_an_unknown_key_cannot_commission_a_provider(tmp_path):
    with pytest.raises(ProviderRefused) as caught:
        load_provider_registry(_signed(tmp_path, seed=_OTHER), trust=_trust())
    assert caught.value.refusal is ProviderRefusal.REGISTRY_UNSIGNED


def test_one_key_may_not_hold_the_provider_role_and_another():
    """One holder could then name a model **and** say where this node reports
    on it, which is the single point the three registries exist to remove."""

    with pytest.raises(ProviderRefused) as caught:
        ProviderTrust(
            provider_keys={"shared": _public()},
            catalog_keys={"shared": _public()},
            commissioning_digest=DIGEST,
        )
    assert caught.value.refusal is ProviderRefusal.SHARED_SIGNING_KEY

    with pytest.raises(ProviderRefused) as caught:
        ProviderTrust(
            provider_keys={"provider-1": _public()},
            registry_keys={"registry-1": _public()},
            commissioning_digest=DIGEST,
        )
    assert caught.value.refusal is ProviderRefusal.SHARED_SIGNING_KEY, (
        "two ids for one key is one key"
    )


def test_a_registry_commissioned_elsewhere_is_not_commissioned_here(tmp_path):
    path = _signed(tmp_path, commissioning="sha256:" + "1" * 64)
    with pytest.raises(ProviderRefused) as caught:
        load_provider_registry(path, trust=_trust())
    assert caught.value.refusal is ProviderRefusal.REGISTRY_INVALID


def test_an_oversized_registry_is_refused_before_it_is_parsed(tmp_path):
    path = tmp_path / "providers.signed"
    path.write_bytes(b"\x00" * (MAX_PROVIDER_REGISTRY_BYTES + 128))
    with pytest.raises(ProviderRefused) as caught:
        load_provider_registry(path, trust=_trust())
    assert caught.value.refusal is ProviderRefusal.REGISTRY_INVALID


# -- a record cannot express a location a caller chose --------------------


@pytest.mark.parametrize(
    "host",
    ["https://advisory.example.test", "1.2.3.4", "[::1]", "advisory.example.test:443",
     "advisory.example.test/collect", "user@advisory.example.test"],
    ids=["scheme", "v4-literal", "v6-literal", "port", "path", "userinfo"],
)
def test_a_host_that_is_not_a_hostname_cannot_be_declared(host):
    with pytest.raises(ProviderRefused):
        _record(host=host)


@pytest.mark.parametrize(
    "template", ["/v1/{model}/{extra}", "v1/{model}", "/v1/{}/x", "/v1/{host}/x"],
    ids=["second-hole", "relative", "empty-hole", "host-hole"],
)
def test_a_path_template_with_a_hole_nobody_fills_is_refused(template):
    with pytest.raises(ProviderRefused):
        _record(path_template=template)


def test_the_only_substitution_is_the_records_own_model():
    """A caller cannot name a model. Which model this provider is asked for
    is a commissioning decision, not a request parameter."""

    assert _record().path_for() == "/v1/advisor/advise"


def test_a_client_identity_is_a_name_never_key_material():
    with pytest.raises(ProviderRefused):
        _record(client_identity="-----BEGIN PRIVATE KEY-----")


@pytest.mark.parametrize("never", sorted(NEVER_REMOTE, key=lambda c: c.value))
def test_a_record_permitting_a_never_remote_class_cannot_be_built(never):
    """A registry that allows one contradicts the contract rather than
    configuring it."""

    with pytest.raises(ProviderRefused):
        _record(allowed_privacy_classes=(PrivacyClass.P0_PUBLIC, never))


def test_a_record_permitting_nothing_cannot_be_built():
    with pytest.raises(ProviderRefused):
        _record(allowed_privacy_classes=())


@pytest.mark.parametrize(
    "field", ["max_request_bytes", "max_response_bytes", "deadline_seconds"]
)
def test_a_ceiling_of_zero_is_not_a_ceiling(field):
    with pytest.raises(ProviderRefused):
        _record(**{field: 0})


def test_two_records_for_one_symbol_are_refused(tmp_path):
    path = _signed(tmp_path, records=[_record(), _record()])
    with pytest.raises(ProviderRefused) as caught:
        load_provider_registry(path, trust=_trust())
    assert caught.value.refusal is ProviderRefusal.REGISTRY_INVALID


# -- resolving is a lookup, never a join ---------------------------------


def test_an_unknown_symbol_resolves_to_nothing(tmp_path):
    registry = load_provider_registry(_signed(tmp_path), trust=_trust())
    with pytest.raises(ProviderRefused) as caught:
        resolve_provider(
            "somebody-else", registry, privacy_class=PrivacyClass.P1_SANITIZED
        )
    assert caught.value.refusal is ProviderRefusal.UNKNOWN_PROVIDER


def test_no_registry_resolves_nothing():
    with pytest.raises(ProviderRefused) as caught:
        resolve_provider("x", None, privacy_class=PrivacyClass.P0_PUBLIC)
    assert caught.value.refusal is ProviderRefusal.NO_PROVIDER_COMMISSIONED


@pytest.mark.parametrize("never", sorted(NEVER_REMOTE, key=lambda c: c.value))
def test_resolving_refuses_a_never_remote_class(tmp_path, never):
    registry = load_provider_registry(_signed(tmp_path), trust=_trust())
    with pytest.raises(ProviderRefused) as caught:
        resolve_provider("vendor-advisory", registry, privacy_class=never)
    assert caught.value.refusal is ProviderRefusal.CLASS_NOT_PERMITTED


def test_a_class_the_provider_is_not_commissioned_for_is_refused(tmp_path):
    registry = load_provider_registry(_signed(tmp_path), trust=_trust())
    with pytest.raises(ProviderRefused) as caught:
        resolve_provider(
            "vendor-advisory", registry, privacy_class=PrivacyClass.P0_PUBLIC
        )
    assert caught.value.refusal is ProviderRefusal.CLASS_NOT_PERMITTED


# -- the document ---------------------------------------------------------


def test_the_payload_is_canonical_and_ordered(tmp_path):
    """Two runs produce the same bytes, so a signature is reproducible."""

    a = provider_registry_payload(
        version=1, commissioning_digest=DIGEST,
        records=[_record(provider_id="b-vendor"), _record(provider_id="a-vendor")],
    )
    b = provider_registry_payload(
        version=1, commissioning_digest=DIGEST,
        records=[_record(provider_id="a-vendor"), _record(provider_id="b-vendor")],
    )
    assert a == b
    document = json.loads(a)
    assert [p["provider_id"] for p in document["providers"]] == [
        "a-vendor", "b-vendor"
    ]
    assert document["schema"] == PROVIDER_SCHEMA


def test_the_document_carries_no_key_material(tmp_path):
    payload = provider_registry_payload(
        version=1, commissioning_digest=DIGEST, records=[_record()]
    )
    text = payload.decode()
    for forbidden in ("PRIVATE KEY", "BEGIN ", "token", "password", "secret"):
        assert forbidden not in text


def test_the_module_reaches_nothing():
    import ast

    import azazel_nexus.provider_registry as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {"ssl", "socket", "subprocess", "http", "urllib"} == set()
