"""Activation approval v3, decoder and verifier only, not wired (#196 G6 prep).

`docs/deception-exposure-grant.md` §5 C1 condition 1 and §9. Keys are
generated in memory for each test; nothing is read from the host or kept.
"""

import ast
import hashlib
import json
from itertools import combinations
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from azazel_nexus import activation_approval_v2, activation_approval_v3
from azazel_nexus.activation import (
    CORE_UNITS,
    DECEPTION_EXPOSURE_UNITS,
    ActivationLease,
    UnitTier,
)
from azazel_nexus.activation_approval_v2 import (
    ActivationApprovalPolicy,
    ObserveBaselineApproval,
    ObserveBaselineContext,
    observe_baseline_payload,
    verify_observe_baseline_approval,
)
from azazel_nexus.activation_approval_v3 import (
    SCHEMA_V3,
    ActivationApprovalV3,
    activation_approval_v3_payload,
    decode_activation_approval_v3,
    verify_activation_approval_v3,
)
from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST
from azazel_nexus.decoy_scope import MAX_INGRESS, MAX_PREFIXES
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
    approval_message,
)

REPO = Path(__file__).resolve().parents[2]
DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
BINDING = "hmac-sha256:" + "c" * 64
START = "2026-10-20T00:00:00Z"
END = "2026-10-21T00:00:00Z"
LOOP = ("azazel-edge-intaked.service", "azazel-incident-explaind.service",
        "azazel-edge-probed.service", "azazel-mio-entryd.service",
        "azazel-knowledge-lited.service")
EXPOSURE = tuple(DECEPTION_EXPOSURE_UNITS)
POLICY = ActivationApprovalPolicy(
    authorized_operators=frozenset({"operator-a"}), max_lease_seconds=72 * 3600,
    unit_scope=frozenset(LOOP),
)
CONTEXT = ObserveBaselineContext(
    node_digest=DIGEST, generation=3, generation_digest=DIGEST,
    commissioning_digest=DIGEST, commissioning_evidence_binding=BINDING,
    policy_digest=DIGEST, security_epoch=2,
)
FIELDS = dict(approval_id="approval-1", operator="operator-a", approval_seq=5,
              units=LOOP, granted_at=START, expires_at=END)
SCOPE = "sha256:" + "e" * 64
#: v3's own fields (wiring §5.1, V2): what the operator reads, shape only.
EXPOSURE_FIELDS = dict(exposure_scope_digest=SCOPE, exposure_prefix_count=2,
                       exposure_ingress_count=1)
V3_FIELDS = FIELDS | EXPOSURE_FIELDS
#: Every proper, nonempty part of the exposure tier.
PARTIAL = [part for size in (1, 2) for part in combinations(EXPOSURE, size)]


def _sign(key, payload, purpose=ApprovalPurpose.ACTIVATION_EXPOSURE):
    return key.sign(approval_message(purpose, payload)).signature


def _encode(document) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


@pytest.fixture
def approved():
    key = SigningKey.generate()
    payload = activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS)
    args = dict(trust=OperatorTrust({"operator-a": bytes(key.verify_key)}), expected=CONTEXT,
                policy=POLICY, payload=payload, signature=_sign(key, payload), now=START,
                security_epoch_floor=2, approval_seq_floor=5)
    return key, args


def _resigned(key, args, payload):
    return args | dict(payload=payload, signature=_sign(key, payload))


# -- the document --------------------------------------------------------------


def test_v3_carries_the_v2_fields_under_its_own_schema_name():
    v2 = json.loads(observe_baseline_payload(context=CONTEXT, **FIELDS))
    v3 = json.loads(activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS))
    assert SCHEMA_V3 == "azazel-nexus/activation-approval/v3"
    assert v3["schema"] == SCHEMA_V3 and v2["schema"] == "azazel-nexus/activation-approval/v2"
    assert set(v3) == set(v2) | set(EXPOSURE_FIELDS)
    assert {k: v for k, v in v3.items() if k != "schema" and k not in EXPOSURE_FIELDS} == {
        k: v for k, v in v2.items() if k != "schema"}
    assert {k: v3[k] for k in EXPOSURE_FIELDS} == EXPOSURE_FIELDS
    assert v3["units"] == sorted(LOOP)


def test_v2_bytes_are_unchanged():
    """The v2 encoding is pinned byte for byte; v3 did not touch it."""
    payload = observe_baseline_payload(context=CONTEXT, **FIELDS)
    assert hashlib.sha256(payload).hexdigest() == (
        "9430a725b9127f0547fecefa8448873e665fc058c9c5b417bc151df8dbd6a8ab")


@pytest.mark.parametrize("units,digest", [
    (LOOP, "0224bd68f6bc218f729afa925b7090b04d29d41db274a489204bd7b4c6d74be6"),
    (LOOP + EXPOSURE, "871327a5de926ff665390f23e7223a3b3f9caa575f6767bb0698f57dab6d151f"),
])
def test_v3_bytes_are_pinned(units, digest):
    payload = activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS | dict(units=units))
    assert hashlib.sha256(payload).hexdigest() == digest


#: The fields both schemas carry, written out (v3 keeps its own copy).
DOCUMENTED_FIELDS = frozenset({
    "schema", "approval_id", "operator", "node_digest", "generation",
    "generation_digest", "commissioning_digest", "commissioning_evidence_binding",
    "policy_digest", "security_epoch", "approval_seq", "units", "granted_at",
    "expires_at",
})


def test_the_field_sets_are_pinned():
    assert activation_approval_v3._FIELDS == DOCUMENTED_FIELDS | {
        "exposure_scope_digest", "exposure_prefix_count", "exposure_ingress_count"}
    assert activation_approval_v2._FIELDS == DOCUMENTED_FIELDS
    assert activation_approval_v3._FIELDS is not activation_approval_v2._FIELDS


def test_the_v3_unit_set_is_pinned_and_excludes_enforcement():
    supporting = {
        "azazel-auditd.service", "azazel-commissiond.service",
        "azazel-edge-intaked.service", "azazel-edge-probed.service",
        "azazel-incident-explaind.service", "azazel-knowledge-lited.service",
        "azazel-mio-entryd.service", "azazel-mio-locald.service",
        "azazel-mio-remoted.service", "azazel-model-fetchd.service",
        "azazel-watchdog.service", "azazel-mio-referenced.service",
        # The integrated loop's audit writer (ADR 0008, 2026-10-30).
        "azazel-auditd-loop.service",
    }
    v2 = supporting | {"azazel-edge-core.service"}
    assert activation_approval_v2._V2_UNITS == v2
    assert activation_approval_v3._V3_UNITS == v2 | set(EXPOSURE)
    tiers = {d.name: d.tier for d in CORE_UNITS}
    assert UnitTier.ENFORCEMENT not in {tiers[name] for name in activation_approval_v3._V3_UNITS}
    enforcement = {d.name for d in CORE_UNITS if d.tier is UnitTier.ENFORCEMENT}
    assert not enforcement & activation_approval_v3._V3_UNITS


def test_v3_does_not_borrow_v2_private_names():
    imported = set()
    for node in ast.walk(ast.parse(Path(activation_approval_v3.__file__).read_text())):
        if isinstance(node, ast.ImportFrom) and node.module == "activation_approval_v2":
            imported.update(alias.name for alias in node.names)
    assert imported == {"ActivationApprovalPolicy", "ObserveBaselineContext"}


def test_the_whole_exposure_tier_can_be_named_and_decodes():
    units = LOOP + EXPOSURE
    payload = activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS | dict(units=units))
    decoded = decode_activation_approval_v3(payload)
    assert decoded.units == frozenset(units)
    assert decoded.context == CONTEXT
    assert (decoded.approval_id, decoded.operator, decoded.approval_seq) == (
        "approval-1", "operator-a", 5)
    assert (decoded.granted_at, decoded.expires_at) == (START, END)
    assert (decoded.exposure_scope_digest, decoded.exposure_prefix_count,
            decoded.exposure_ingress_count) == (SCOPE, 2, 1)
    assert BINDING not in repr(decoded)


def test_the_exposure_tier_alone_can_be_named():
    payload = activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS | dict(units=EXPOSURE))
    assert decode_activation_approval_v3(payload).units == frozenset(EXPOSURE)


def test_without_the_tier_v3_decodes_like_v2():
    payload = activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS)
    assert decode_activation_approval_v3(payload).units == frozenset(LOOP)


@pytest.mark.parametrize("part", PARTIAL)
def test_part_of_the_exposure_tier_cannot_be_encoded(part):
    with pytest.raises(ApprovalRefused, match="together or not at all"):
        activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS | dict(units=LOOP + part))
    with pytest.raises(ApprovalRefused, match="together or not at all"):
        activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS | dict(units=part))


@pytest.mark.parametrize("part", PARTIAL)
def test_part_of_the_exposure_tier_cannot_be_decoded(part):
    document = json.loads(activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS))
    document["units"] = sorted(LOOP + part)
    with pytest.raises(ApprovalRefused, match="together or not at all"):
        decode_activation_approval_v3(_encode(document))


@pytest.mark.parametrize("units", [
    [], "azazel-decoyd.service", ["azazel-decoyd.service"] * 3,
    sorted(["azazel-unknown.service"] + list(EXPOSURE)),
    ["azazel-unknown.service"], [1], None,
])
def test_invalid_unit_lists_are_refused(units):
    document = json.loads(activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS))
    document["units"] = units
    with pytest.raises(ApprovalRefused):
        decode_activation_approval_v3(_encode(document))


@pytest.mark.parametrize("kind", [
    "unsorted_units", "spaces", "extra_field", "missing_field", "bool_seq",
    "bool_generation", "float_epoch", "not_utf8", "empty", "too_large", "array",
    "unsorted_keys", "v2_schema", "v1_like", "bad_time", "expiry_before_grant",
])
def test_noncanonical_or_malformed_bytes_are_refused(kind):
    payload = activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS)
    document = json.loads(payload)
    mutated = {
        "unsorted_units": lambda: payload.replace(
            b'"azazel-edge-intaked.service","azazel-edge-probed.service"',
            b'"azazel-edge-probed.service","azazel-edge-intaked.service"'),
        "spaces": lambda: payload.replace(b",", b", ", 1),
        "extra_field": lambda: _encode(document | {"boot_id": "x"}),
        "missing_field": lambda: _encode({k: v for k, v in document.items()
                                          if k != "policy_digest"}),
        "bool_seq": lambda: _encode(document | {"approval_seq": True}),
        "bool_generation": lambda: _encode(document | {"generation": True}),
        "float_epoch": lambda: _encode(document | {"security_epoch": 2.0}),
        "not_utf8": lambda: payload + b"\xff",
        "empty": lambda: b"",
        "too_large": lambda: payload + b" " * 70000,
        "array": lambda: b"[]",
        "unsorted_keys": lambda: json.dumps(dict(reversed(document.items())),
                                             separators=(",", ":")).encode(),
        "v2_schema": lambda: _encode(document | {"schema": "azazel-nexus/activation-approval/v2"}),
        "v1_like": lambda: _encode(document | {"schema": "azazel-nexus/activation-approval/v1"}),
        "bad_time": lambda: _encode(document | {"granted_at": "2026-10-20 00:00:00"}),
        "expiry_before_grant": lambda: _encode(document | {"expires_at": START}),
    }[kind]()
    assert mutated != payload
    with pytest.raises(ApprovalRefused):
        decode_activation_approval_v3(mutated)


@pytest.mark.parametrize("duplicate", ["schema", "units", "operator"])
def test_duplicate_keys_are_refused(duplicate):
    payload = activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS)
    value = json.dumps(json.loads(payload)[duplicate], separators=(",", ":")).encode()
    doubled = payload[:-1] + b',"' + duplicate.encode() + b'":' + value + b"}"
    with pytest.raises(ApprovalRefused):
        decode_activation_approval_v3(doubled)


def test_v2_bytes_are_not_v3_and_v3_bytes_are_not_v2(approved):
    key, args = approved
    with pytest.raises(ApprovalRefused):
        decode_activation_approval_v3(observe_baseline_payload(context=CONTEXT, **FIELDS))
    v2 = observe_baseline_payload(context=CONTEXT, **FIELDS)
    with pytest.raises(ApprovalRefused):
        verify_activation_approval_v3(**_resigned(key, args, v2))


# -- the exposure fields (wiring §5.1, V2: shape only) ---------------------------


def test_the_exposure_field_rules_are_the_generations_and_the_scopes():
    """The digest form is the generation section's `scope_digest`; the bounds
    are the rendered scope file's (`decoy_scope`), not new ones."""
    from azazel_nexus_runtime import exposure_generation

    assert activation_approval_v3._SCOPE_DIGEST.pattern == exposure_generation._DIGEST.pattern
    assert activation_approval_v3.MAX_PREFIXES is MAX_PREFIXES
    assert activation_approval_v3.MAX_INGRESS is MAX_INGRESS


@pytest.mark.parametrize("prefixes,ingresses", [
    (1, 1), (MAX_PREFIXES, MAX_INGRESS), (1, MAX_INGRESS), (MAX_PREFIXES, 1)])
def test_the_exposure_counts_within_bounds_decode(prefixes, ingresses):
    payload = activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS | dict(
        exposure_prefix_count=prefixes, exposure_ingress_count=ingresses))
    decoded = decode_activation_approval_v3(payload)
    assert (decoded.exposure_prefix_count, decoded.exposure_ingress_count) == (
        prefixes, ingresses)


_BAD_DIGESTS = [
    None, 1, True, b"sha256:" + b"e" * 64, "", "sha256:", "e" * 64,
    "sha256:" + "E" * 64, "SHA256:" + "e" * 64, "sha256:" + "e" * 63,
    "sha256:" + "e" * 65, "sha256:" + "g" * 64, "sha256:" + "e" * 64 + "\n",
    " sha256:" + "e" * 64, "sha512:" + "e" * 64, "hmac-sha256:" + "e" * 64, "none",
]
_BAD_PREFIXES = [None, "2", 2.0, True, False, 0, -1, MAX_PREFIXES + 1]
_BAD_INGRESSES = [None, "1", 1.0, True, False, 0, -1, MAX_INGRESS + 1]
#: Every refused value of each field, with that field's code.
SHAPES = (
    [("exposure_scope_digest", v, "approval_v3_exposure_scope_digest_invalid")
     for v in _BAD_DIGESTS]
    + [("exposure_prefix_count", v, "approval_v3_exposure_prefix_count_invalid")
       for v in _BAD_PREFIXES]
    + [("exposure_ingress_count", v, "approval_v3_exposure_ingress_count_invalid")
       for v in _BAD_INGRESSES]
)


@pytest.mark.parametrize("name,value,code", SHAPES)
def test_an_exposure_field_of_another_shape_cannot_be_encoded(name, value, code):
    with pytest.raises(ApprovalRefused, match=f"^{code}: "):
        activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS | {name: value})


@pytest.mark.parametrize("name,value,code", SHAPES)
def test_an_exposure_field_of_another_shape_cannot_be_decoded(name, value, code):
    if type(value) is bytes:
        pytest.skip("bytes are not JSON")
    document = json.loads(activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS))
    with pytest.raises(ApprovalRefused, match=f"^{code}: "):
        decode_activation_approval_v3(_encode(document | {name: value}))


@pytest.mark.parametrize("name,value,code", SHAPES)
def test_a_validly_signed_exposure_field_of_another_shape_is_refused(approved, name, value,
                                                                      code):
    if type(value) is bytes:
        pytest.skip("bytes are not JSON")
    key, args = approved
    document = json.loads(args["payload"]) | {name: value}
    with pytest.raises(ApprovalRefused, match=f"^{code}: "):
        verify_activation_approval_v3(**_resigned(key, args, _encode(document)))


@pytest.mark.parametrize("name", sorted(EXPOSURE_FIELDS))
def test_each_exposure_field_is_required(approved, name):
    key, args = approved
    document = {k: v for k, v in json.loads(args["payload"]).items() if k != name}
    with pytest.raises(ApprovalRefused, match="^approval_v3_fields_invalid: "):
        decode_activation_approval_v3(_encode(document))
    with pytest.raises(ApprovalRefused, match="^approval_v3_fields_invalid: "):
        verify_activation_approval_v3(**_resigned(key, args, _encode(document)))
    with pytest.raises(TypeError):
        activation_approval_v3_payload(
            context=CONTEXT, **{k: v for k, v in V3_FIELDS.items() if k != name})


def test_the_exposure_fields_are_shape_only_here(approved):
    """Any well-formed value verifies: comparing them with the generation's
    section and this boot's rendering is the pass's (P10), not v3's."""
    key, args = approved
    payload = activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS | dict(
        exposure_scope_digest="sha256:" + "0" * 64, exposure_prefix_count=MAX_PREFIXES,
        exposure_ingress_count=MAX_INGRESS))
    result = verify_activation_approval_v3(**_resigned(key, args, payload))
    assert (result.exposure_scope_digest, result.exposure_prefix_count,
            result.exposure_ingress_count) == ("sha256:" + "0" * 64, MAX_PREFIXES, MAX_INGRESS)


def test_a_count_written_noncanonically_is_refused():
    payload = activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS)
    for old, new in ((b'"exposure_prefix_count":2', b'"exposure_prefix_count":2.0'),
                     (b'"exposure_prefix_count":2', b'"exposure_prefix_count":02'),
                     (b'"exposure_ingress_count":1', b'"exposure_ingress_count":1e0')):
        assert old in payload
        with pytest.raises(ApprovalRefused):
            decode_activation_approval_v3(payload.replace(old, new))


# -- the verifier --------------------------------------------------------------


def test_a_v3_approval_within_the_v2_tiers_produces_the_bound_lease(approved):
    _, args = approved
    result = verify_activation_approval_v3(**args)
    assert type(result) is ActivationApprovalV3
    assert type(result) is not ObserveBaselineApproval
    assert result.lease == ActivationLease(
        granted_by="operator-a", granted_at=START, expires_at=END,
        generation_digest=DIGEST, generation_number=3, commissioning_digest=DIGEST,
        commissioning_evidence_binding=BINDING, units=frozenset(LOOP))
    assert (result.approval_id, result.approval_seq, result.security_epoch) == (
        "approval-1", 5, 2)
    assert (result.exposure_scope_digest, result.exposure_prefix_count,
            result.exposure_ingress_count) == (SCOPE, 2, 1)


def test_a_validly_signed_exposure_approval_is_refused_by_the_policy_scope(approved):
    """Every check before the scope passes; the scope, which cannot name the
    tier until G6, is what refuses it."""
    key, args = approved
    payload = activation_approval_v3_payload(
        context=CONTEXT, **V3_FIELDS | dict(units=LOOP + EXPOSURE))
    with pytest.raises(ApprovalRefused, match="outside the policy scope"):
        verify_activation_approval_v3(**_resigned(key, args, payload))


@pytest.mark.parametrize("part", PARTIAL)
def test_a_validly_signed_partial_exposure_approval_is_refused(approved, part):
    key, args = approved
    document = json.loads(args["payload"])
    document["units"] = sorted(LOOP + part)
    with pytest.raises(ApprovalRefused, match="together or not at all"):
        verify_activation_approval_v3(**_resigned(key, args, _encode(document)))


def test_the_policy_cannot_scope_the_exposure_tier():
    for units in (EXPOSURE, LOOP + EXPOSURE):
        with pytest.raises(ApprovalRefused):
            ActivationApprovalPolicy(
                authorized_operators=frozenset({"operator-a"}),
                max_lease_seconds=3600, unit_scope=frozenset(units))


@pytest.mark.parametrize("name,value", [
    ("node_digest", OTHER), ("generation", 4), ("generation_digest", OTHER),
    ("commissioning_digest", OTHER), ("commissioning_evidence_binding",
                                      "hmac-sha256:" + "d" * 64),
    ("policy_digest", OTHER), ("security_epoch", 3),
])
def test_a_validly_signed_approval_for_another_context_is_refused(approved, name, value):
    key, args = approved
    document = json.loads(args["payload"]) | {name: value}
    with pytest.raises(ApprovalRefused, match="expected context"):
        verify_activation_approval_v3(**_resigned(key, args, _encode(document)))


def test_every_byte_is_covered_by_the_signature(approved):
    _, args = approved
    tampered = args["payload"].replace(b'"approval_seq":5', b'"approval_seq":6')
    with pytest.raises(ApprovalRefused):
        verify_activation_approval_v3(**args | dict(payload=tampered))


def test_wrong_purpose_signature_is_refused(approved):
    key, args = approved
    for purpose in ApprovalPurpose:
        if purpose is not ApprovalPurpose.ACTIVATION_EXPOSURE:
            with pytest.raises(ApprovalRefused, match="approval_v3_signature_refused"):
                verify_activation_approval_v3(
                    **args | dict(signature=_sign(key, args["payload"], purpose)))


@pytest.mark.parametrize("units", [LOOP, LOOP + EXPOSURE])
def test_a_v3_signed_under_the_v2_purpose_is_refused(approved, units):
    """Owner decision Q-C (wiring §5.1): v3 verifies only under
    `ACTIVATION_EXPOSURE`. A v3 signed for an ordinary activation is refused
    whatever it names, before the policy is consulted."""
    key, args = approved
    assert ApprovalPurpose.ACTIVATION_EXPOSURE.value == "activation-exposure"
    payload = activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS | dict(units=units))
    with pytest.raises(ApprovalRefused, match="approval_v3_signature_refused"):
        verify_activation_approval_v3(**args | dict(
            payload=payload, signature=_sign(key, payload, ApprovalPurpose.ACTIVATION)))


def test_v2_under_the_exposure_purpose_is_refused_by_both_verifiers(approved):
    key, args = approved
    v2 = observe_baseline_payload(context=CONTEXT, **FIELDS)
    signature = _sign(key, v2, ApprovalPurpose.ACTIVATION_EXPOSURE)
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**args | dict(payload=v2, signature=signature))
    with pytest.raises(ApprovalRefused):
        verify_activation_approval_v3(**args | dict(payload=v2, signature=signature))


def test_another_key_or_an_unauthorized_operator_is_refused(approved):
    _, args = approved
    with pytest.raises(ApprovalRefused):
        verify_activation_approval_v3(
            **args | dict(signature=_sign(SigningKey.generate(), args["payload"])))
    other = ActivationApprovalPolicy(
        authorized_operators=frozenset({"operator-b"}), max_lease_seconds=72 * 3600,
        unit_scope=frozenset(LOOP))
    with pytest.raises(ApprovalRefused, match="not authorized"):
        verify_activation_approval_v3(**args | dict(policy=other))


def test_floors_and_time_are_the_callers(approved):
    _, args = approved
    with pytest.raises(ApprovalRefused, match="epoch below"):
        verify_activation_approval_v3(**args | dict(security_epoch_floor=3))
    with pytest.raises(ApprovalRefused, match="sequence below"):
        verify_activation_approval_v3(**args | dict(approval_seq_floor=6))
    for now in (END, "2026-10-19T23:59:59Z"):
        with pytest.raises(ApprovalRefused, match="time policy"):
            verify_activation_approval_v3(**args | dict(now=now))
    short = ActivationApprovalPolicy(
        authorized_operators=frozenset({"operator-a"}), max_lease_seconds=3600,
        unit_scope=frozenset(LOOP))
    with pytest.raises(ApprovalRefused, match="time policy"):
        verify_activation_approval_v3(**args | dict(policy=short))
    for floor in (True, -1, "2"):
        with pytest.raises(ApprovalRefused):
            verify_activation_approval_v3(**args | dict(approval_seq_floor=floor))


def test_typed_trust_context_and_policy_are_required(approved):
    _, args = approved

    class Lookalike:
        def verify(self, **kwargs):
            return None

    for trust in (Lookalike(), None):
        with pytest.raises(ApprovalRefused, match="operator trust required"):
            verify_activation_approval_v3(**args | dict(trust=trust))
    with pytest.raises(ApprovalRefused):
        verify_activation_approval_v3(**args | dict(expected=None))
    with pytest.raises(ApprovalRefused):
        verify_activation_approval_v3(**args | dict(policy=None))


# -- not wired -----------------------------------------------------------------
#
# That nothing outside the tests imports or names v3, statically or through
# importlib, `__import__` or runpy, is `test_g6_unwired.py` (#196 L1): one
# table for every G6 part. What stays here is v3's own: the verifier the pass
# uses and the signing tool refuse it, and no scope was widened.


@pytest.mark.parametrize("units", [LOOP, LOOP + EXPOSURE])
def test_the_v2_verifier_the_pass_uses_refuses_v3(approved, units):
    key, args = approved
    payload = activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS | dict(units=units))
    for purpose in (ApprovalPurpose.ACTIVATION_EXPOSURE, ApprovalPurpose.ACTIVATION):
        with pytest.raises(ApprovalRefused):
            verify_observe_baseline_approval(**args | dict(
                payload=payload, signature=_sign(key, payload, purpose)))


def test_the_signing_tool_refuses_v3():
    import sys

    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from tools import operator_sign

    for units in (LOOP, LOOP + EXPOSURE):
        payload = activation_approval_v3_payload(context=CONTEXT, **V3_FIELDS | dict(units=units))
        with pytest.raises(operator_sign.SignRefused):
            operator_sign.activation_summary(payload)
    # Nor does it offer v3's purpose (Q-C): not before G6.
    assert "activation-exposure" not in operator_sign.PURPOSES
    assert ApprovalPurpose.ACTIVATION_EXPOSURE not in operator_sign.PURPOSES.values()


def test_no_scope_was_widened():
    from azazel_nexus_runtime import activation_markers
    from azazel_nexus_runtime.activation_pass import POLICY_UNIT_SCOPE

    edge = "azazel-edge-core.service"
    # The two additions are the model-free reference service (§6.2, proposed
    # 2026-10-28) and the loop's audit writer (§6, 2026-10-30, ADR 0008). No
    # model host, enforcement, commissioning or exposure unit is added.
    reference = "azazel-mio-referenced.service"
    audit = "azazel-auditd-loop.service"
    assert set(ACTIVATION_UNIT_ALLOWLIST) == set(LOOP) | {edge, reference, audit}
    assert POLICY_UNIT_SCOPE == frozenset(LOOP) | {edge, reference, audit}
    # The exposure units are grantable only so #253 checks their files; no
    # policy names them and the library withholds their tier (unchanged).
    assert activation_markers.GRANTABLE_UNITS == (
        frozenset(LOOP + EXPOSURE) | {edge, reference, audit})
    assert activation_markers.EXPOSURE_UNITS == set(EXPOSURE)
