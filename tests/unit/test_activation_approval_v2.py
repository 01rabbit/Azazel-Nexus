"""Boot-free v2 approval with ephemeral in-memory keys; no host input or persisted key."""

import json
from dataclasses import replace

import pytest
from nacl.signing import SigningKey

from azazel_nexus.activation import (
    CORE_UNITS,
    ActivationController,
    ActivationLease,
    ActivationRefused,
    RecordingUnitController,
    UnitState,
)
from azazel_nexus.activation_approval import (
    ActivationContext,
    approval_payload,
    verify_activation_approval,
)
from azazel_nexus.activation_approval_v2 import (
    MAX_LEASE_CEILING_SECONDS,
    ActivationApprovalPolicy,
    ObserveBaselineContext,
    observe_baseline_payload,
    verify_observe_baseline_approval,
)
from azazel_nexus.audit import AuditLedger
from azazel_nexus.generation import GenerationStore
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
    approval_message,
)

DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
BINDING = "hmac-sha256:" + "c" * 64
START = "2026-10-20T00:00:00Z"
END = "2026-10-21T00:00:00Z"
LOOP = ("azazel-edge-intaked.service", "azazel-incident-explaind.service",
        "azazel-edge-probed.service", "azazel-mio-entryd.service",
        "azazel-knowledge-lited.service")
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


def _sign(key, payload, purpose=ApprovalPurpose.ACTIVATION):
    return key.sign(approval_message(purpose, payload)).signature


@pytest.fixture
def approved():
    key = SigningKey.generate()
    payload = observe_baseline_payload(context=CONTEXT, **FIELDS)
    args = dict(trust=OperatorTrust({"operator-a": bytes(key.verify_key)}), expected=CONTEXT,
                policy=POLICY, payload=payload, signature=_sign(key, payload), now=START,
                security_epoch_floor=2, approval_seq_floor=5)
    return key, args


def _resigned(key, args, document):
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return args | dict(payload=payload, signature=_sign(key, payload))


def test_payload_has_exactly_the_documented_fields_and_sorted_units():
    document = json.loads(observe_baseline_payload(context=CONTEXT, **FIELDS))
    assert set(document) == {
        "schema", "approval_id", "operator", "node_digest", "generation",
        "generation_digest", "commissioning_digest", "commissioning_evidence_binding",
        "policy_digest", "security_epoch", "approval_seq", "units", "granted_at",
        "expires_at",
    }
    assert document["schema"] == "azazel-nexus/activation-approval/v2"
    assert document["units"] == sorted(LOOP)
    assert "boot_id" not in document and "renderer_digest" not in document


def test_approval_produces_only_the_bound_scoped_lease(approved):
    _, args = approved
    result = verify_observe_baseline_approval(**args)
    lease = result.lease
    assert lease.units == frozenset(LOOP)
    assert (lease.granted_by, lease.generation_digest, lease.generation_number,
            lease.commissioning_digest, lease.commissioning_evidence_binding) == (
        "operator-a", DIGEST, 3, DIGEST, BINDING)
    assert (result.approval_id, result.approval_seq, result.security_epoch) == ("approval-1", 5, 2)
    assert lease.valid_at(START) and not lease.valid_at(END)


@pytest.mark.parametrize("name,value", [
    ("node_digest", OTHER), ("generation", 4), ("generation_digest", OTHER),
    ("commissioning_digest", OTHER), ("commissioning_evidence_binding", "hmac-sha256:" + "d" * 64),
    ("policy_digest", OTHER), ("security_epoch", 3),
])
def test_approval_cannot_follow_changed_expected_context(approved, name, value):
    _, args = approved
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**(args | {"expected": replace(CONTEXT, **{name: value})}))


@pytest.mark.parametrize("name,value", [
    ("approval_id", "approval-2"), ("operator", "operator-b"), ("approval_seq", 6),
    ("units", sorted(LOOP[:4])), ("granted_at", "2026-10-19T23:59:59Z"),
    ("expires_at", "2026-10-21T00:00:01Z"), ("node_digest", OTHER), ("generation", 4),
    ("generation_digest", OTHER), ("commissioning_digest", OTHER),
    ("commissioning_evidence_binding", "hmac-sha256:" + "d" * 64),
    ("policy_digest", OTHER), ("security_epoch", 3),
])
def test_every_signed_field_is_covered_by_the_signature(approved, name, value):
    _, args = approved
    document = json.loads(args["payload"])
    document[name] = value
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**(args | {"payload": payload}))


@pytest.mark.parametrize("name,value", [
    ("node_digest", OTHER), ("generation", 4), ("generation_digest", OTHER),
    ("commissioning_digest", OTHER), ("commissioning_evidence_binding", "hmac-sha256:" + "d" * 64),
    ("policy_digest", OTHER), ("security_epoch", 3),
])
def test_a_validly_signed_approval_for_another_context_is_refused(approved, name, value):
    key, args = approved
    document = json.loads(args["payload"])
    document[name] = value
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**_resigned(key, args, document))


def test_wrong_purpose_signature_is_refused(approved):
    key, args = approved
    for purpose in ApprovalPurpose:
        if purpose is ApprovalPurpose.ACTIVATION:
            continue
        with pytest.raises(ApprovalRefused):
            verify_observe_baseline_approval(**(args | {"signature": _sign(key, args["payload"], purpose)}))


def test_revoked_operator_is_refused(approved):
    key, args = approved
    trust = OperatorTrust({"operator-a": bytes(key.verify_key)}, frozenset({"operator-a"}))
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**(args | {"trust": trust}))


def test_another_key_is_refused(approved):
    _, args = approved
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**(args | {"signature": _sign(SigningKey.generate(), args["payload"])}))


def test_enrolled_but_unauthorized_operator_is_refused(approved):
    key, args = approved
    other = SigningKey.generate()
    trust = OperatorTrust({"operator-a": bytes(key.verify_key), "operator-b": bytes(other.verify_key)})
    payload = observe_baseline_payload(context=CONTEXT, **(FIELDS | {"operator": "operator-b"}))
    with pytest.raises(ApprovalRefused, match="not authorized"):
        verify_observe_baseline_approval(**(args | dict(trust=trust, payload=payload,
                                                        signature=_sign(other, payload))))
    policy = replace(POLICY, authorized_operators=frozenset())
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**(args | {"policy": policy}))


@pytest.mark.parametrize("now", [
    "2026-10-19T23:59:59Z", END, "2026-10-22T00:00:00Z",
    "2026-10-20T00:00:00+00:00", "2026-02-30T00:00:00Z", None,
])
def test_expiry_and_time_form_are_checked_against_the_supplied_time(approved, now):
    _, args = approved
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**(args | {"now": now}))


def test_lease_longer_than_policy_is_refused(approved):
    _, args = approved
    policy = replace(POLICY, max_lease_seconds=24 * 3600 - 1)
    with pytest.raises(ApprovalRefused, match="time policy"):
        verify_observe_baseline_approval(**(args | {"policy": policy}))
    assert verify_observe_baseline_approval(**(args | {"policy": replace(POLICY, max_lease_seconds=24 * 3600)}))


def test_lease_longer_than_the_owner_ceiling_cannot_be_permitted(approved):
    key, args = approved
    with pytest.raises(ApprovalRefused):
        replace(POLICY, max_lease_seconds=MAX_LEASE_CEILING_SECONDS + 1)
    payload = observe_baseline_payload(
        context=CONTEXT, **(FIELDS | {"expires_at": "2026-10-23T00:00:01Z"}))
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**(args | dict(payload=payload, signature=_sign(key, payload))))


def test_sequence_below_floor_is_refused(approved):
    _, args = approved
    with pytest.raises(ApprovalRefused, match="sequence below"):
        verify_observe_baseline_approval(**(args | {"approval_seq_floor": 6}))
    assert verify_observe_baseline_approval(**(args | {"approval_seq_floor": 0}))


def test_epoch_mismatch_and_below_floor_are_refused(approved):
    _, args = approved
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**(args | {"expected": replace(CONTEXT, security_epoch=1)}))
    with pytest.raises(ApprovalRefused, match="epoch below"):
        verify_observe_baseline_approval(**(args | {"security_epoch_floor": 3}))


@pytest.mark.parametrize("floor", [-1, True, None, "5"])
def test_floors_must_be_supplied_as_plain_integers(approved, floor):
    _, args = approved
    for name in ("security_epoch_floor", "approval_seq_floor"):
        with pytest.raises(ApprovalRefused):
            verify_observe_baseline_approval(**(args | {name: floor}))


def test_units_outside_policy_scope_are_refused(approved):
    _, args = approved
    policy = replace(POLICY, unit_scope=frozenset(LOOP[:4]))
    with pytest.raises(ApprovalRefused, match="outside the policy scope"):
        verify_observe_baseline_approval(**(args | {"policy": policy}))


def test_a_subset_of_policy_scope_is_accepted(approved):
    key, args = approved
    payload = observe_baseline_payload(context=CONTEXT, **(FIELDS | {"units": LOOP[:2]}))
    result = verify_observe_baseline_approval(**(args | dict(payload=payload, signature=_sign(key, payload))))
    assert result.lease.units == frozenset(LOOP[:2])


@pytest.mark.parametrize("units", [
    [], ["azazel-not-a-unit.service"], [LOOP[0], LOOP[0]], "azazel-edge-intaked.service", [1],
])
def test_invalid_unit_lists_are_refused(approved, units):
    key, args = approved
    with pytest.raises(ApprovalRefused):
        observe_baseline_payload(context=CONTEXT, **(FIELDS | {"units": units}))
    document = json.loads(args["payload"]) | {"units": units}
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**_resigned(key, args, document))


@pytest.mark.parametrize("kind", [
    "whitespace", "unsorted_keys", "unsorted_units", "extra", "missing", "boolean_seq",
    "boolean_generation", "float_epoch", "schema", "ascii_escape", "not_json", "array",
])
def test_signed_noncanonical_or_malformed_bytes_are_refused(approved, kind):
    key, args = approved
    document = json.loads(args["payload"])
    payload = None
    if kind == "whitespace":
        payload = args["payload"] + b"\n"
    elif kind == "unsorted_keys":
        payload = json.dumps(document, separators=(",", ":")).encode()
        payload = b'{"units":' + json.dumps(document["units"], separators=(",", ":")).encode() + b"," + \
            json.dumps({k: v for k, v in document.items() if k != "units"},
                       sort_keys=True, separators=(",", ":")).encode()[1:]
    elif kind == "unsorted_units":
        document["units"] = list(reversed(document["units"]))
    elif kind == "extra":
        document["healthy"] = True
    elif kind == "missing":
        del document["approval_id"]
    elif kind == "boolean_seq":
        document["approval_seq"] = True
    elif kind == "boolean_generation":
        document["generation"] = True
    elif kind == "float_epoch":
        document["security_epoch"] = 2.0
    elif kind == "schema":
        document["schema"] = "azazel-nexus/activation-approval/v3"
    elif kind == "ascii_escape":
        payload = args["payload"].replace(b"operator-a", b"operator\\u002da")
    elif kind == "not_json":
        payload = b"\xff\xfe"
    elif kind == "array":
        payload = b"[]"
    if payload is None:
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    assert payload != args["payload"]
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**(args | dict(payload=payload, signature=_sign(key, payload))))


@pytest.mark.parametrize("duplicate", ['"operator":"operator-b",', '"approval_seq":9,', '"units":[],'])
def test_duplicate_keys_are_refused_even_when_signed(approved, duplicate):
    key, args = approved
    payload = b"{" + duplicate.encode() + args["payload"][1:]
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**(args | dict(payload=payload, signature=_sign(key, payload))))


def test_v1_approval_is_not_accepted_as_v2_and_v2_not_as_v1(approved):
    key, args = approved
    v1_context = ActivationContext(DIGEST, "11111111-1111-1111-1111-111111111111", 3,
                                   DIGEST, DIGEST, DIGEST, DIGEST, DIGEST, 2,
                                   commissioning_evidence_binding=BINDING)
    v1 = approval_payload(context=v1_context, operator="operator-a", granted_at=START,
                          expires_at="2026-10-20T00:10:00Z")
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**(args | dict(payload=v1, signature=_sign(key, v1))))
    # The v1 verifier still accepts its own document, unchanged.
    v1_args = dict(trust=args["trust"], expected=v1_context, operator="operator-a",
                   payload=v1, signature=_sign(key, v1), now=START, max_lease_seconds=600)
    assert verify_activation_approval(**v1_args).units is None
    with pytest.raises(ApprovalRefused):
        verify_activation_approval(**(v1_args | dict(payload=args["payload"],
                                                     signature=args["signature"],
                                                     max_lease_seconds=MAX_LEASE_CEILING_SECONDS)))


@pytest.mark.parametrize("changes", [
    {"generation": True}, {"generation": 0}, {"security_epoch": -1},
    {"node_digest": "not-a-digest"}, {"commissioning_evidence_binding": None},
    {"commissioning_evidence_binding": "sha256:" + "c" * 64},
])
def test_invalid_expected_context_refuses(changes):
    with pytest.raises(ApprovalRefused):
        replace(CONTEXT, **changes)


@pytest.mark.parametrize("changes", [
    {"authorized_operators": {"operator-a"}}, {"authorized_operators": frozenset({"Bad"})},
    {"max_lease_seconds": 0}, {"max_lease_seconds": True}, {"unit_scope": set(LOOP)},
    {"unit_scope": frozenset()}, {"unit_scope": frozenset({"azazel-not-a-unit.service"})},
])
def test_invalid_policy_refuses(changes):
    with pytest.raises(ApprovalRefused):
        replace(POLICY, **changes)


def test_verifier_requires_typed_context_and_policy(approved):
    _, args = approved
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**(args | {"expected": object()}))
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(**(args | {"policy": object()}))


# -- lease.units in the controller (narrowing only) ---------------------------

def _controller(tmp_path):
    store = GenerationStore(tmp_path / "generations")
    generation = store.create({"config": b"synthetic"}, created_at=START, commissioning_digest=DIGEST)
    units = RecordingUnitController(d.name for d in CORE_UNITS)
    controller = ActivationController(units=units, generations=store,
                                      ledger=AuditLedger(tmp_path / "audit.jsonl"))
    return controller, units, generation


def _lease(generation, units):
    return ActivationLease(granted_by="operator-a", granted_at=START, expires_at=END,
                           generation_digest=generation.digest, units=units)


def test_unscoped_lease_keeps_previous_behaviour(tmp_path):
    controller, _, generation = _controller(tmp_path)
    granted = set(controller.activate(now=START, actor="t", lease=_lease(generation, None)).granted)
    # Without scope, every unwired SUPPORTING unit passes the lease gate as before.
    assert set(LOOP) <= granted
    assert "azazel-commissiond.service" in granted


def test_scoped_lease_only_removes_units(tmp_path):
    controller, units, generation = _controller(tmp_path)
    unscoped = set(controller.activate(now=START, actor="t", lease=_lease(generation, None)).granted)
    controller, units, generation = _controller(tmp_path / "scoped")
    outcome = controller.activate(now=START, actor="t", lease=_lease(generation, frozenset(LOOP)))
    assert set(outcome.granted) == set(LOOP) & unscoped
    assert "azazel-commissiond.service" in unscoped - set(outcome.granted)
    for verdict in outcome.verdicts:
        if verdict.unit not in LOOP:
            assert not verdict.granted
            assert units.state(verdict.unit) is UnitState.MASKED
            if verdict.unit in unscoped:
                assert verdict.reason.startswith("outside_lease_scope")


def test_scope_cannot_widen_past_other_gates(tmp_path):
    controller, _, generation = _controller(tmp_path)
    everything = frozenset(d.name for d in CORE_UNITS)
    outcome = controller.activate(now=START, actor="t", lease=_lease(generation, everything),
                                  healthy=False)
    assert outcome.granted == ()
    outcome = controller.activate(now=START, actor="t", lease=_lease(generation, everything))
    # Wiring and Edge gates still withhold units named by the scope.
    assert "azazel-model-fetchd.service" not in outcome.granted
    assert "azazel-edge-core.service" not in outcome.granted


def test_empty_scope_grants_nothing(tmp_path):
    controller, _, generation = _controller(tmp_path)
    outcome = controller.activate(now=START, actor="t", lease=_lease(generation, frozenset()))
    assert outcome.granted == ()


@pytest.mark.parametrize("units", [set(LOOP), list(LOOP), frozenset({""}), frozenset({1})])
def test_lease_scope_must_be_a_frozenset_of_names(units):
    with pytest.raises(ActivationRefused):
        ActivationLease(granted_by="operator-a", granted_at=START, expires_at=END,
                        generation_digest=DIGEST, units=units)
