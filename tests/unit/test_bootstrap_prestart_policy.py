"""Canonical bootstrap pre-start policy parsing and independent bindings."""

from dataclasses import replace
from hashlib import sha256
import json

import pytest

from azazel_nexus.bootstrap_prestart_policy import (
    BootstrapPrestartPolicy,
    decode_prestart_policy,
    encode_prestart_policy,
)
from azazel_nexus.operator_trust import ApprovalRefused
from test_bootstrap_generation import _context


def policy(**changes):
    values = {
        "package_digest": "sha256:" + "c" * 64,
        "unit_closure_digest": "sha256:" + "d" * 64,
        "systemd_profile_digest": "sha256:" + "a" * 64,
        "min_usable_memory_mib": 4096,
        "min_online_logical_cpus": 4,
        "min_mission_available_mib": 2048,
        "bootstrap_bytes": 100_000,
        "bootstrap_inodes": 100,
        "audit_bytes": 200_000,
        "audit_inodes": 200,
        "audit_sequence": 8,
        "audit_head": "e" * 64,
        "max_audit_bytes": 1_000_000,
        "max_audit_segments": 16,
        "max_anchor_lifetime_ns": 60_000_000_000,
        "max_uncertainty_ns": 2_000_000_000,
        "drift_ppb": 1000,
    }
    values.update(changes)
    return BootstrapPrestartPolicy(**values)


def expected_for(raw, **changes):
    context = _context(**changes)
    return replace(context, policy_digest="sha256:" + sha256(raw).hexdigest())


def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def test_policy_has_canonical_roundtrip_and_context_bound_full_hash():
    value = policy()
    raw = encode_prestart_policy(value)
    expected = expected_for(raw)

    assert decode_prestart_policy(raw, expected=expected) == value
    assert encode_prestart_policy(decode_prestart_policy(raw, expected=expected)) == raw
    assert expected.policy_digest == "sha256:" + sha256(raw).hexdigest()


def test_v3_canonical_encoding_is_unchanged_and_omits_new_field():
    value = policy()
    raw = encode_prestart_policy(value)

    # Independently enumerate the pre-v4 wire fields, rather than deriving
    # this compatibility assertion from the current dataclass/encoder.
    legacy = {
        "schema": "azazel-nexus/bootstrap-prestart-policy/v3",
        "units": ["azazel-auditd.service", "azazel-commissiond.service"],
        "audit_assurance": "LOCAL_CONTINUITY_ONLY", "audit_mode": "existing-history",
        "package_digest": "sha256:" + "c" * 64,
        "unit_closure_digest": "sha256:" + "d" * 64,
        "systemd_profile_digest": "sha256:" + "a" * 64,
        "min_usable_memory_mib": 4096, "min_online_logical_cpus": 4,
        "min_mission_available_mib": 2048, "bootstrap_bytes": 100_000,
        "bootstrap_inodes": 100, "audit_bytes": 200_000, "audit_inodes": 200,
        "audit_sequence": 8, "audit_head": "e" * 64,
        "max_audit_bytes": 1_000_000, "max_audit_segments": 16,
        "max_anchor_lifetime_ns": 60_000_000_000,
        "max_uncertainty_ns": 2_000_000_000, "drift_ppb": 1000,
    }
    assert raw == canonical(legacy)

    assert json.loads(raw)["schema"] == "azazel-nexus/bootstrap-prestart-policy/v3"
    assert "loaded_policy_digest" not in json.loads(raw)
    assert decode_prestart_policy(raw, expected=expected_for(raw)) == value


def test_v4_roundtrip_binds_loaded_policy_digest():
    value = policy(loaded_policy_digest="sha256:" + "b" * 64)
    raw = encode_prestart_policy(value)

    assert json.loads(raw)["schema"] == "azazel-nexus/bootstrap-prestart-policy/v4"
    assert decode_prestart_policy(raw, expected=expected_for(raw)) == value
    assert encode_prestart_policy(decode_prestart_policy(raw, expected=expected_for(raw))) == raw


def test_v4_full_digest_mismatch_refuses():
    raw = encode_prestart_policy(policy(loaded_policy_digest="sha256:" + "b" * 64))
    wrong = replace(_context(), policy_digest="sha256:" + "0" * 64)

    with pytest.raises(ApprovalRefused):
        decode_prestart_policy(raw, expected=wrong)


def test_policy_hash_mismatch_refuses():
    raw = encode_prestart_policy(policy())
    wrong = replace(_context(), policy_digest="sha256:" + "0" * 64)

    with pytest.raises(ApprovalRefused):
        decode_prestart_policy(raw, expected=wrong)


@pytest.mark.parametrize("field,value", [
    ("package_digest", "sha256:" + "9" * 64),
    ("unit_closure_digest", "sha256:" + "8" * 64),
])
def test_policy_package_and_closure_bindings_are_checked_independently(field, value):
    raw = encode_prestart_policy(policy())
    expected = expected_for(raw, **{field: value})

    with pytest.raises(ApprovalRefused):
        decode_prestart_policy(raw, expected=expected)


@pytest.mark.parametrize("field,value", [
    ("min_usable_memory_mib", True),
    ("min_online_logical_cpus", 1.5),
    ("min_mission_available_mib", "2048"),
    ("bootstrap_bytes", 0),
    ("bootstrap_inodes", -1),
    ("audit_bytes", 2**63),
    ("audit_inodes", None),
    ("audit_sequence", False),
    ("max_audit_bytes", "large"),
    ("max_audit_segments", 0),
    ("package_digest", "SHA256:" + "c" * 64),
    ("unit_closure_digest", "bad"),
    ("systemd_profile_digest", "sha256:" + "A" * 64),
    ("systemd_profile_digest", "sha256:" + "a" * 63),
    ("systemd_profile_digest", "a" * 64),
    ("audit_head", "f" * 63),
    ("loaded_policy_digest", "sha256:" + "B" * 64),
    ("loaded_policy_digest", "sha256:" + "a" * 63),
    ("loaded_policy_digest", "a" * 64),
])
def test_policy_constructor_rejects_malformed_exact_types_and_bounds(field, value):
    current = policy()
    values = current.__dict__ | {field: value}
    with pytest.raises(ApprovalRefused):
        BootstrapPrestartPolicy(**values)


@pytest.mark.parametrize("mutation", [
    "duplicate", "unknown", "version", "v2", "units", "audit_mode", "assurance",
])
def test_decoder_refuses_mutated_schema_and_semantics_with_matching_outer_hash(mutation):
    raw = encode_prestart_policy(policy())
    document = json.loads(raw)
    if mutation == "duplicate":
        raw = raw[:-1] + b',"audit_sequence":8}'
    else:
        if mutation == "unknown":
            document["unexpected"] = "value"
        elif mutation == "version":
            document["schema"] = "azazel-nexus/bootstrap-prestart-policy/v1"
        elif mutation == "v2":
            document["schema"] = "azazel-nexus/bootstrap-prestart-policy/v2"
        elif mutation == "units":
            document["units"] = ["azazel-commissiond.service"]
        elif mutation == "audit_mode":
            document["audit_mode"] = "genesis"
        elif mutation == "assurance":
            document["audit_assurance"] = "ROLLBACK_ANCHORED"
        raw = canonical(document)
    expected = expected_for(raw)

    with pytest.raises(ApprovalRefused):
        decode_prestart_policy(raw, expected=expected)


@pytest.mark.parametrize("mutation", ["v3_field", "v4_missing", "v4_null", "v4_extra"])
def test_decoder_enforces_v3_v4_field_presence_and_schema(mutation):
    value = policy()
    document = json.loads(encode_prestart_policy(value))
    if mutation == "v3_field":
        document["loaded_policy_digest"] = "sha256:" + "b" * 64
    else:
        document["schema"] = "azazel-nexus/bootstrap-prestart-policy/v4"
        if mutation == "v4_null":
            document["loaded_policy_digest"] = None
        elif mutation == "v4_extra":
            document["loaded_policy_digest"] = "sha256:" + "b" * 64
            document["unexpected"] = True
    raw = canonical(document)

    with pytest.raises(ApprovalRefused):
        decode_prestart_policy(raw, expected=expected_for(raw))


@pytest.mark.parametrize("missing", [
    "systemd_profile_digest", "max_anchor_lifetime_ns", "max_uncertainty_ns", "drift_ppb",
])
def test_clock_policy_values_never_default_when_missing(missing):
    document = json.loads(encode_prestart_policy(policy()))
    del document[missing]
    raw = canonical(document)
    with pytest.raises(ApprovalRefused):
        decode_prestart_policy(raw, expected=expected_for(raw))


@pytest.mark.parametrize("field,value", [
    ("min_usable_memory_mib", True),
    ("audit_sequence", 0),
    ("audit_bytes", "many"),
])
def test_decoder_refuses_malformed_integer_fields_even_when_hash_matches(field, value):
    document = json.loads(encode_prestart_policy(policy()))
    document[field] = value
    raw = canonical(document)

    with pytest.raises(ApprovalRefused):
        decode_prestart_policy(raw, expected=expected_for(raw))


@pytest.mark.parametrize("raw", [b"", b"{}\n", b"null", b"[]", b"{" + b" " * 8192])
def test_decoder_refuses_empty_noncanonical_nonobject_and_oversized_input(raw):
    with pytest.raises(ApprovalRefused):
        decode_prestart_policy(raw, expected=expected_for(raw))
