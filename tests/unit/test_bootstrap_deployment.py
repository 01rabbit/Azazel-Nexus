"""Portable bootstrap declarations bind independently measured policy state."""

from dataclasses import FrozenInstanceError, replace
import hashlib
import json

import pytest

from azazel_nexus.bootstrap_approval import BootstrapContext
from azazel_nexus.bootstrap_deployment import (
    BootstrapDeployment,
    bind_bootstrap_deployment,
    decode_bootstrap_deployment,
    declared_node_digest,
    encode_bootstrap_deployment,
)
from azazel_nexus.operator_trust import ApprovalRefused

DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
OPERATOR = "operator-a"
NODE_ID = "nexus-edge-01"
NODE_DIGEST = declared_node_digest(NODE_ID)


@pytest.fixture
def context():
    return BootstrapContext(
        approval_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        node_digest=NODE_DIGEST,
        boot_id="11111111-1111-1111-1111-111111111111",
        generation=1,
        generation_digest=DIGEST,
        package_digest=DIGEST,
        unit_closure_digest=DIGEST,
        policy_digest=DIGEST,
        approval_policy_digest=DIGEST,
        security_epoch=7,
        revocation_digest=DIGEST,
    )


@pytest.fixture
def deployment():
    return BootstrapDeployment(NODE_DIGEST, 7, DIGEST, DIGEST, DIGEST, OPERATOR)


def test_declared_node_digest_uses_canonical_domain_separated_document():
    node_id = "nexus-edge-01"
    document = {"schema": "azazel-nexus/declared-node/v1", "node_id": node_id}
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected = "sha256:" + hashlib.sha256(raw).hexdigest()

    assert declared_node_digest(node_id) == expected
    assert declared_node_digest(node_id) == declared_node_digest("nexus-edge-01")
    assert expected != "sha256:" + hashlib.sha256(node_id.encode()).hexdigest()


@pytest.mark.parametrize("node_id", ["", "has space", "é", True, None])
def test_declared_node_digest_requires_explicit_safe_ascii_label(node_id):
    with pytest.raises(ApprovalRefused):
        declared_node_digest(node_id)


def test_record_roundtrips_as_exact_canonical_schema(deployment):
    raw = encode_bootstrap_deployment(deployment)
    assert raw == (
        b'{"approval_policy_digest":"' + DIGEST.encode() + b'","node_digest":"'
        + NODE_DIGEST.encode() + b'","operator":"operator-a","policy_digest":"'
        + DIGEST.encode() + b'","revocation_digest":"' + DIGEST.encode()
        + b'","schema":"azazel-nexus/bootstrap-deployment/v1",'
        b'"security_epoch":7}'
    )
    assert decode_bootstrap_deployment(raw) == deployment
    with pytest.raises(FrozenInstanceError):
        deployment.security_epoch = 8


@pytest.mark.parametrize("field,value", [
    ("node_digest", "sha256:" + "A" * 64),
    ("revocation_digest", "bad"),
    ("policy_digest", None),
    ("approval_policy_digest", 1),
    ("security_epoch", True),
    ("security_epoch", -1),
    ("security_epoch", 2**64),
    ("operator", "Operator-A"),
    ("operator", "../operator"),
])
def test_deployment_constructor_refuses_invalid_field_values(deployment, field, value):
    fields = deployment.__dict__ | {field: value}
    with pytest.raises(ApprovalRefused):
        BootstrapDeployment(**fields)


@pytest.mark.parametrize("raw", [
    b"{}",
    b'{"schema":"azazel-nexus/bootstrap-deployment/v2"}',
    b'{"schema":"azazel-nexus/bootstrap-deployment/v1","node_digest":"x",'
    b'"node_digest":"y"}',
    b'{"schema":"azazel-nexus/bootstrap-deployment/v1","architecture":"x"}',
    b'{"schema":"azazel-nexus/bootstrap-deployment/v1","boot_id":"x"}',
    b"null",
    b"[]",
    b"{",
    b" " * 4097,
    b"{}\n",
])
def test_decoder_refuses_malformed_noncanonical_or_unbounded_records(raw):
    with pytest.raises(ApprovalRefused):
        decode_bootstrap_deployment(raw)


@pytest.mark.parametrize("field,value", [
    ("architecture", "x86_64"),
    ("vm_id", "vm-1"),
    ("ip_address", "192.0.2.1"),
    ("password", "secret"),
    ("boot_id", "11111111-1111-1111-1111-111111111111"),
])
def test_decoder_refuses_forbidden_declaration_fields(deployment, field, value):
    document = json.loads(encode_bootstrap_deployment(deployment))
    document[field] = value
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ApprovalRefused):
        decode_bootstrap_deployment(raw)


@pytest.mark.parametrize("mutation", ["version", "missing", "duplicate", "newline", "bool"])
def test_decoder_rejects_single_defect_in_otherwise_valid_record(deployment, mutation):
    raw = encode_bootstrap_deployment(deployment)
    document = json.loads(raw)
    if mutation == "version":
        document["schema"] = "azazel-nexus/bootstrap-deployment/v2"
    elif mutation == "missing":
        del document["operator"]
    elif mutation == "bool":
        document["security_epoch"] = True
    elif mutation == "duplicate":
        raw = raw[:-1] + b',"security_epoch":7}'
    else:
        raw += b"\n"
    if mutation in {"version", "missing", "bool"}:
        raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ApprovalRefused):
        decode_bootstrap_deployment(raw)


@pytest.mark.parametrize("field,value", [
    ("node_digest", OTHER),
    ("security_epoch", 8),
    ("revocation_digest", OTHER),
    ("policy_digest", OTHER),
    ("approval_policy_digest", OTHER),
])
def test_binding_refuses_each_declaration_context_mismatch(deployment, context, field, value):
    with pytest.raises(ApprovalRefused):
        bind_bootstrap_deployment(
            deployment, context=replace(context, **{field: value}),
            node_id=NODE_ID, operator=OPERATOR,
        )


@pytest.mark.parametrize(("node_id", "operator"), [
    ("different-node", OPERATOR),
    (NODE_ID, "operator-b"),
])
def test_binding_refuses_separately_declared_node_or_operator_mismatch(
    deployment, context, node_id, operator,
):
    with pytest.raises(ApprovalRefused):
        bind_bootstrap_deployment(
            deployment, context=context, node_id=node_id, operator=operator,
        )


def test_binding_allows_same_contract_context_on_a_different_boot(deployment, context):
    current_boot = replace(context, boot_id="22222222-2222-2222-2222-222222222222")
    assert bind_bootstrap_deployment(
        deployment, context=current_boot, node_id=NODE_ID, operator=OPERATOR,
    ) is None
