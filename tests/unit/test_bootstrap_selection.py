"""Canonical per-boot bootstrap selection intent; no approval/admission."""

from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import json

import pytest

from azazel_nexus.bootstrap_deployment import (
    BootstrapDeployment,
    encode_bootstrap_deployment,
)
from azazel_nexus.bootstrap_selection import (
    BootstrapSelection,
    bind_bootstrap_selection,
    decode_bootstrap_selection,
    encode_bootstrap_selection,
)
from azazel_nexus.operator_trust import ApprovalRefused

BOOT = "11111111-1111-4111-8111-111111111111"
OTHER_BOOT = "22222222-2222-4222-8222-222222222222"
APPROVAL = "33333333-3333-4333-8333-333333333333"
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


@pytest.fixture
def deployment():
    return BootstrapDeployment(DIGEST, 4, OTHER_DIGEST, DIGEST, OTHER_DIGEST, "operator-a")


@pytest.fixture
def selection(deployment):
    return BootstrapSelection(
        _deployment_digest(deployment),
        BOOT, APPROVAL, 7, DIGEST,
    )


def _canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def _deployment_digest(deployment):
    return "sha256:" + sha256(encode_bootstrap_deployment(deployment)).hexdigest()


def test_selection_exact_canonical_roundtrip_and_frozen(selection):
    raw = encode_bootstrap_selection(selection)
    assert raw == _canonical({
        "schema": "azazel-nexus/bootstrap-selection/v1",
        "deployment_digest": selection.deployment_digest,
        "boot_id": BOOT,
        "approval_id": APPROVAL,
        "generation": 7,
        "generation_digest": DIGEST,
    })
    assert decode_bootstrap_selection(raw) == selection
    with pytest.raises(FrozenInstanceError):
        selection.generation = 8


@pytest.mark.parametrize("raw", [
    b"", b"{}", b"null", b"[]", b"{", b" " * 4097,
    b'{"schema":"azazel-nexus/bootstrap-selection/v2"}',
    b'{"schema":"azazel-nexus/bootstrap-selection/v1","boot_id":"x",'
    b'"boot_id":"y"}',
    b'{"schema":"azazel-nexus/bootstrap-selection/v1","unknown":1}',
])
def test_decoder_rejects_malformed_duplicate_unknown_wrong_version_and_unbounded(raw):
    with pytest.raises(ApprovalRefused):
        decode_bootstrap_selection(raw)


@pytest.mark.parametrize("field,value", [
    ("deployment_digest", "a" * 64),
    ("deployment_digest", "sha256:" + "A" * 64),
    ("generation_digest", "bad"),
    ("boot_id", "not-a-uuid"),
    ("approval_id", "NOT-A-UUID"),
    ("generation", True),
    ("generation", 0),
    ("generation", 2**63),
])
def test_selection_rejects_invalid_exact_field_types_and_values(selection, field, value):
    with pytest.raises(ApprovalRefused):
        replace(selection, **{field: value})


@pytest.mark.parametrize("mutation", ["missing", "extra", "wrong-type", "noncanonical"])
def test_decoder_rejects_schema_field_and_canonical_mutations(selection, mutation):
    document = json.loads(encode_bootstrap_selection(selection))
    if mutation == "missing":
        del document["approval_id"]
    elif mutation == "extra":
        document["architecture"] = "x86_64"
    elif mutation == "wrong-type":
        document["generation"] = True
    raw = _canonical(document)
    if mutation == "noncanonical":
        raw += b"\n"
    with pytest.raises(ApprovalRefused):
        decode_bootstrap_selection(raw)


def test_binding_requires_exact_deployment_digest_and_current_boot(deployment, selection):
    assert bind_bootstrap_selection(selection, deployment=deployment, boot_id=BOOT) is None

    with pytest.raises(ApprovalRefused):
        bind_bootstrap_selection(selection, deployment=deployment, boot_id=OTHER_BOOT)
    with pytest.raises(ApprovalRefused):
        bind_bootstrap_selection(
            selection, deployment=replace(deployment, security_epoch=5), boot_id=BOOT,
        )
    with pytest.raises(ApprovalRefused):
        bind_bootstrap_selection(
            replace(selection, deployment_digest=OTHER_DIGEST),
            deployment=deployment, boot_id=BOOT,
        )


@pytest.mark.parametrize("bad", [None, True, "bad"])
def test_binding_requires_exact_input_types(deployment, selection, bad):
    with pytest.raises(ApprovalRefused):
        bind_bootstrap_selection(selection, deployment=deployment, boot_id=bad)
    with pytest.raises(ApprovalRefused):
        bind_bootstrap_selection(selection, deployment=bad, boot_id=BOOT)


def test_encoder_requires_exact_selection_type(selection):
    with pytest.raises(ApprovalRefused):
        encode_bootstrap_selection(object())
