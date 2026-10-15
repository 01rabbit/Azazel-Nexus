"""Schema v5 first-install genesis policy: encoding, closed decoding, node binding."""

from dataclasses import replace
from hashlib import sha256
import json

import pytest

from azazel_nexus.audit import GENESIS_HASH
from azazel_nexus.bootstrap_prestart_policy import (
    FirstInstallGenesis, decode_pinned_prestart_policy,
    decode_prestart_policy, encode_prestart_policy,
)
from azazel_nexus.operator_trust import ApprovalRefused
from test_bootstrap_prestart_policy import canonical, expected_for, policy

NODE = "sha256:" + "1" * 64  # matches test context node_digest
PID = "3333333a-3333-4333-b333-33333333333c"
LOADED = "sha256:" + "b" * 64


def genesis(**changes):
    values = {"audit_sequence": 0, "audit_head": GENESIS_HASH, "loaded_policy_digest": LOADED,
              "first_install_genesis": FirstInstallGenesis(NODE, PID)}
    values.update(changes)
    return policy(**values)


def doc(value=None):
    return json.loads(encode_prestart_policy(value or genesis()))


def pinned(document):
    raw = canonical(document)
    return decode_pinned_prestart_policy(raw, expected_digest="sha256:" + sha256(raw).hexdigest())


def test_v5_roundtrip_canonical_bytes_and_accessors():
    value = genesis()
    raw = encode_prestart_policy(value)
    document = json.loads(raw)
    assert document["schema"] == "azazel-nexus/bootstrap-prestart-policy/v5"
    assert document["audit_mode"] == "first-install-genesis"
    assert document["audit_genesis"] == {
        "head": GENESIS_HASH, "node_digest": NODE, "provisioning_id": PID, "sequence": 0}
    assert "audit_sequence" not in document and "audit_head" not in document
    assert raw == canonical(document)
    assert decode_prestart_policy(raw, expected=expected_for(raw)) == value
    assert value.audit_mode == "first-install-genesis"
    assert value.expected_audit_head == (0, GENESIS_HASH)
    assert policy().audit_mode == "existing-history"
    assert policy().expected_audit_head == (8, "e" * 64)


def test_v3_v4_bytes_unchanged_and_modes():
    for loaded, version in ((None, "v3"), (LOADED, "v4")):
        document = json.loads(encode_prestart_policy(policy(loaded_policy_digest=loaded)))
        assert document["schema"].endswith("/" + version)
        assert document["audit_mode"] == "existing-history"
        assert "audit_genesis" not in document and "first_install_genesis" not in document
        assert document["audit_sequence"] == 8


def test_v5_requires_loaded_policy_digest():
    with pytest.raises(ApprovalRefused):
        encode_prestart_policy(genesis(loaded_policy_digest=None))
    document = doc()
    del document["loaded_policy_digest"]
    with pytest.raises(ApprovalRefused):
        pinned(document)
    document["loaded_policy_digest"] = None
    with pytest.raises(ApprovalRefused):
        pinned(document)


@pytest.mark.parametrize("changes", [
    {"audit_sequence": 1}, {"audit_head": "a" * 64}, {"audit_sequence": True},
])
def test_genesis_policy_requires_exact_zero_genesis(changes):
    with pytest.raises(ApprovalRefused):
        genesis(**changes)


def test_non_genesis_policy_still_rejects_zero_sequence_and_genesis_head():
    with pytest.raises(ApprovalRefused):
        policy(audit_sequence=0)
    with pytest.raises(ApprovalRefused):
        policy(audit_head=GENESIS_HASH, audit_sequence=0)


def test_v5_rejects_top_level_sequence_and_head():
    for key, value in (("audit_sequence", 0), ("audit_head", GENESIS_HASH)):
        document = doc()
        document[key] = value
        with pytest.raises(ApprovalRefused):
            pinned(document)


def test_v5_wrong_audit_mode():
    for mode in ("existing-history", "genesis", None, 1):
        document = doc()
        document["audit_mode"] = mode
        with pytest.raises(ApprovalRefused):
            pinned(document)


@pytest.mark.parametrize("mutate", [
    lambda g: g.update(head="a" * 64),
    lambda g: g.update(sequence=1),
    lambda g: g.update(sequence=True),
    lambda g: g.update(sequence=0.0),
    lambda g: g.update(extra=1),
    lambda g: g.pop("head"),
    lambda g: g.pop("provisioning_id"),
    lambda g: g.update(node_digest="sha256:" + "A" * 64),
    lambda g: g.update(node_digest="1" * 64),
    lambda g: g.update(provisioning_id=PID.upper()),
    lambda g: g.update(provisioning_id="not-a-uuid"),
    lambda g: g.update(provisioning_id=7),
])
def test_v5_bad_genesis_object_refused(mutate):
    document = doc()
    mutate(document["audit_genesis"])
    with pytest.raises(ApprovalRefused):
        pinned(document)


@pytest.mark.parametrize("bad", [None, [], "x", 0])
def test_v5_genesis_object_must_be_object(bad):
    document = doc()
    document["audit_genesis"] = bad
    with pytest.raises(ApprovalRefused):
        pinned(document)


def test_v5_missing_genesis_object_refused():
    document = doc()
    del document["audit_genesis"]
    with pytest.raises(ApprovalRefused):
        pinned(document)


def test_v5_duplicate_key_refused():
    raw = encode_prestart_policy(genesis()).decode()
    raw = raw.replace('"sequence":0', '"sequence":0,"sequence":0', 1).encode()
    with pytest.raises(ApprovalRefused):
        decode_pinned_prestart_policy(raw, expected_digest="sha256:" + sha256(raw).hexdigest())


def test_v5_internal_field_name_refused():
    document = doc()
    document["first_install_genesis"] = {"node_digest": NODE, "provisioning_id": PID}
    with pytest.raises(ApprovalRefused):
        pinned(document)


@pytest.mark.parametrize("loaded", [None, LOADED])
def test_v3_v4_cannot_carry_genesis_or_mode(loaded):
    base = json.loads(encode_prestart_policy(policy(loaded_policy_digest=loaded)))
    for key, value in (
        ("audit_genesis", {"head": GENESIS_HASH, "node_digest": NODE,
                           "provisioning_id": PID, "sequence": 0}),
        ("audit_mode", "first-install-genesis"),
        ("audit_mode", "genesis"),
    ):
        document = dict(base)
        document[key] = value
        with pytest.raises(ApprovalRefused):
            pinned(document)


@pytest.mark.parametrize("loaded", [None, LOADED])
def test_v3_v4_zero_sequence_and_genesis_mode_stay_refused(loaded):
    document = json.loads(encode_prestart_policy(policy(loaded_policy_digest=loaded)))
    document["audit_sequence"] = 0
    with pytest.raises(ApprovalRefused):
        pinned(document)


def test_node_binding_to_expected_context():
    raw = encode_prestart_policy(genesis())
    assert decode_prestart_policy(raw, expected=expected_for(raw)).first_install_genesis
    other = genesis(first_install_genesis=FirstInstallGenesis("sha256:" + "9" * 64, PID))
    raw = encode_prestart_policy(other)
    with pytest.raises(ApprovalRefused):
        decode_prestart_policy(raw, expected=expected_for(raw))


def test_context_digest_and_scope_still_enforced():
    raw = encode_prestart_policy(genesis())
    context = expected_for(raw)
    for changed in (replace(context, policy_digest="sha256:" + "0" * 64),
                    replace(context, package_digest="sha256:" + "7" * 64),
                    replace(context, unit_closure_digest="sha256:" + "7" * 64)):
        with pytest.raises(ApprovalRefused):
            decode_prestart_policy(raw, expected=changed)


def test_genesis_record_type_is_exact():
    with pytest.raises(ApprovalRefused):
        FirstInstallGenesis("x", PID)
    with pytest.raises(ApprovalRefused):
        genesis(first_install_genesis={"node_digest": NODE, "provisioning_id": PID})
