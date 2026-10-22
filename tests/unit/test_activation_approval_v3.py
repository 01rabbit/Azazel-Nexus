"""Activation approval v3, decoder and verifier only, not wired (#196 G6 prep).

`docs/deception-exposure-grant.md` §5 C1 condition 1 and §9. Keys are
generated in memory for each test; nothing is read from the host or kept.
"""

import ast
import hashlib
import json
import subprocess
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
#: Every proper, nonempty part of the exposure tier.
PARTIAL = [part for size in (1, 2) for part in combinations(EXPOSURE, size)]


def _sign(key, payload, purpose=ApprovalPurpose.ACTIVATION):
    return key.sign(approval_message(purpose, payload)).signature


def _encode(document) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


@pytest.fixture
def approved():
    key = SigningKey.generate()
    payload = activation_approval_v3_payload(context=CONTEXT, **FIELDS)
    args = dict(trust=OperatorTrust({"operator-a": bytes(key.verify_key)}), expected=CONTEXT,
                policy=POLICY, payload=payload, signature=_sign(key, payload), now=START,
                security_epoch_floor=2, approval_seq_floor=5)
    return key, args


def _resigned(key, args, payload):
    return args | dict(payload=payload, signature=_sign(key, payload))


# -- the document --------------------------------------------------------------


def test_v3_carries_the_v2_fields_under_its_own_schema_name():
    v2 = json.loads(observe_baseline_payload(context=CONTEXT, **FIELDS))
    v3 = json.loads(activation_approval_v3_payload(context=CONTEXT, **FIELDS))
    assert SCHEMA_V3 == "azazel-nexus/activation-approval/v3"
    assert v3["schema"] == SCHEMA_V3 and v2["schema"] == "azazel-nexus/activation-approval/v2"
    assert set(v3) == set(v2)
    assert {k: v for k, v in v3.items() if k != "schema"} == {
        k: v for k, v in v2.items() if k != "schema"}
    assert v3["units"] == sorted(LOOP)


def test_v2_bytes_are_unchanged():
    """The v2 encoding is pinned byte for byte; v3 did not touch it."""
    payload = observe_baseline_payload(context=CONTEXT, **FIELDS)
    assert hashlib.sha256(payload).hexdigest() == (
        "9430a725b9127f0547fecefa8448873e665fc058c9c5b417bc151df8dbd6a8ab")


@pytest.mark.parametrize("units,digest", [
    (LOOP, "1b312b4c67430db7b42668967e66a88934d7cae203e3e7ce69acf9927e159cad"),
    (LOOP + EXPOSURE, "f96f7f240d741e60773a52cc5c8f6a85ccf6ca85079ad2e150e666e5570c15f9"),
])
def test_v3_bytes_are_pinned(units, digest):
    payload = activation_approval_v3_payload(context=CONTEXT, **FIELDS | dict(units=units))
    assert hashlib.sha256(payload).hexdigest() == digest


#: The fields both schemas carry, written out (v3 keeps its own copy).
DOCUMENTED_FIELDS = frozenset({
    "schema", "approval_id", "operator", "node_digest", "generation",
    "generation_digest", "commissioning_digest", "commissioning_evidence_binding",
    "policy_digest", "security_epoch", "approval_seq", "units", "granted_at",
    "expires_at",
})


def test_the_field_sets_are_pinned():
    assert activation_approval_v3._FIELDS == DOCUMENTED_FIELDS
    assert activation_approval_v2._FIELDS == DOCUMENTED_FIELDS
    assert activation_approval_v3._FIELDS is not activation_approval_v2._FIELDS


def test_the_v3_unit_set_is_pinned_and_excludes_enforcement():
    supporting = {
        "azazel-auditd.service", "azazel-commissiond.service",
        "azazel-edge-intaked.service", "azazel-edge-probed.service",
        "azazel-incident-explaind.service", "azazel-knowledge-lited.service",
        "azazel-mio-entryd.service", "azazel-mio-locald.service",
        "azazel-mio-remoted.service", "azazel-model-fetchd.service",
        "azazel-watchdog.service",
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
    payload = activation_approval_v3_payload(context=CONTEXT, **FIELDS | dict(units=units))
    decoded = decode_activation_approval_v3(payload)
    assert decoded.units == frozenset(units)
    assert decoded.context == CONTEXT
    assert (decoded.approval_id, decoded.operator, decoded.approval_seq) == (
        "approval-1", "operator-a", 5)
    assert (decoded.granted_at, decoded.expires_at) == (START, END)
    assert BINDING not in repr(decoded)


def test_the_exposure_tier_alone_can_be_named():
    payload = activation_approval_v3_payload(context=CONTEXT, **FIELDS | dict(units=EXPOSURE))
    assert decode_activation_approval_v3(payload).units == frozenset(EXPOSURE)


def test_without_the_tier_v3_decodes_like_v2():
    payload = activation_approval_v3_payload(context=CONTEXT, **FIELDS)
    assert decode_activation_approval_v3(payload).units == frozenset(LOOP)


@pytest.mark.parametrize("part", PARTIAL)
def test_part_of_the_exposure_tier_cannot_be_encoded(part):
    with pytest.raises(ApprovalRefused, match="together or not at all"):
        activation_approval_v3_payload(context=CONTEXT, **FIELDS | dict(units=LOOP + part))
    with pytest.raises(ApprovalRefused, match="together or not at all"):
        activation_approval_v3_payload(context=CONTEXT, **FIELDS | dict(units=part))


@pytest.mark.parametrize("part", PARTIAL)
def test_part_of_the_exposure_tier_cannot_be_decoded(part):
    document = json.loads(activation_approval_v3_payload(context=CONTEXT, **FIELDS))
    document["units"] = sorted(LOOP + part)
    with pytest.raises(ApprovalRefused, match="together or not at all"):
        decode_activation_approval_v3(_encode(document))


@pytest.mark.parametrize("units", [
    [], "azazel-decoyd.service", ["azazel-decoyd.service"] * 3,
    sorted(["azazel-unknown.service"] + list(EXPOSURE)),
    ["azazel-unknown.service"], [1], None,
])
def test_invalid_unit_lists_are_refused(units):
    document = json.loads(activation_approval_v3_payload(context=CONTEXT, **FIELDS))
    document["units"] = units
    with pytest.raises(ApprovalRefused):
        decode_activation_approval_v3(_encode(document))


@pytest.mark.parametrize("kind", [
    "unsorted_units", "spaces", "extra_field", "missing_field", "bool_seq",
    "bool_generation", "float_epoch", "not_utf8", "empty", "too_large", "array",
    "unsorted_keys", "v2_schema", "v1_like", "bad_time", "expiry_before_grant",
])
def test_noncanonical_or_malformed_bytes_are_refused(kind):
    payload = activation_approval_v3_payload(context=CONTEXT, **FIELDS)
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
    payload = activation_approval_v3_payload(context=CONTEXT, **FIELDS)
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


def test_a_validly_signed_exposure_approval_is_refused_by_the_policy_scope(approved):
    """Every check before the scope passes; the scope, which cannot name the
    tier until G6, is what refuses it."""
    key, args = approved
    payload = activation_approval_v3_payload(
        context=CONTEXT, **FIELDS | dict(units=LOOP + EXPOSURE))
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
        if purpose is not ApprovalPurpose.ACTIVATION:
            with pytest.raises(ApprovalRefused):
                verify_activation_approval_v3(
                    **args | dict(signature=_sign(key, args["payload"], purpose)))


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


@pytest.mark.parametrize("units", [LOOP, LOOP + EXPOSURE])
def test_the_v2_verifier_the_pass_uses_refuses_v3(approved, units):
    key, args = approved
    payload = activation_approval_v3_payload(context=CONTEXT, **FIELDS | dict(units=units))
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**_resigned(key, args, payload))


def test_the_signing_tool_refuses_v3():
    import sys

    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from tools import operator_sign

    for units in (LOOP, LOOP + EXPOSURE):
        payload = activation_approval_v3_payload(context=CONTEXT, **FIELDS | dict(units=units))
        with pytest.raises(operator_sign.SignRefused):
            operator_sign.activation_summary(payload)


def _imports(path: Path) -> set[str]:
    imported = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            imported.add(("." * node.level) + (node.module or ""))
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    return imported


MODULE = REPO / "src/azazel_nexus/activation_approval_v3.py"


def _tracked_outside_tests_and_docs() -> list[Path]:
    """Every tracked file except tests/ and docs/. Without a checkout this
    fails rather than skips: the property is not established without it."""
    listed = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"],
                            capture_output=True, check=True).stdout
    names = [name for name in listed.decode("utf-8").split("\0") if name]
    assert names, "git ls-files listed nothing"
    files = [REPO / name for name in names if not name.startswith(("tests/", "docs/"))]
    for root in ("src", "runtime", "tools", "bench"):
        assert any(path.is_relative_to(REPO / root) for path in files), root
    assert MODULE in files
    return files


def test_nothing_outside_the_tests_imports_or_names_v3():
    for path in _tracked_outside_tests_and_docs():
        if path == MODULE or not path.is_file():
            continue
        raw = path.read_bytes()
        for needle in (b"activation_approval_v3", b"activation-approval/v3", b"ApprovalV3"):
            assert needle not in raw, (path, needle)
        if path.suffix == ".py":
            assert not {"activation_approval_v3", ".activation_approval_v3"} & _imports(path), path


_DYNAMIC = {"import_module", "__import__", "find_spec", "spec_from_file_location",
            "module_from_spec", "reload", "run_module", "run_path"}


def _dynamic_import_strings(path: Path) -> list[str]:
    """Every string constant inside an importlib, `__import__` or runpy call."""
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name in _DYNAMIC:
            found.extend(sub.value for sub in ast.walk(node)
                         if isinstance(sub, ast.Constant) and isinstance(sub.value, str))
    return found


def test_no_dynamic_import_reaches_an_activation_approval_module():
    sources = [path for path in _tracked_outside_tests_and_docs()
               if path.suffix == ".py" and path.is_file()]
    for path in sources:
        text = path.read_text(encoding="utf-8")
        for value in _dynamic_import_strings(path):
            assert "activation_approval" not in value and "approval_v" not in value, (
                path, value)
        # A name assembled from pieces would escape the scan above, so a file
        # that imports dynamically may not mention the family at all.
        if path != MODULE and any(f"{name}(" in text for name in _DYNAMIC):
            assert "activation_approval" not in text, path


def test_no_scope_was_widened():
    from azazel_nexus_runtime import activation_markers
    from azazel_nexus_runtime.activation_pass import POLICY_UNIT_SCOPE

    edge = "azazel-edge-core.service"
    assert set(ACTIVATION_UNIT_ALLOWLIST) == set(LOOP) | {edge}
    assert POLICY_UNIT_SCOPE == frozenset(LOOP) | {edge}
    # The exposure units are grantable only so #253 checks their files; no
    # policy names them and the library withholds their tier (unchanged).
    assert activation_markers.GRANTABLE_UNITS == frozenset(LOOP + EXPOSURE) | {edge}
    assert activation_markers.EXPOSURE_UNITS == set(EXPOSURE)
