"""Synthetic signed proposals; no host admission or persistent keys."""

from dataclasses import replace
import json

import pytest
from nacl.signing import SigningKey

from azazel_nexus.activation import (
    ActivationController, ActivationLease, ActivationRefused, CORE_UNITS,
    RecordingUnitController, UnitState,
)
from azazel_nexus.audit import AuditLedger
from azazel_nexus.generation import GenerationStore
from azazel_nexus.activation_approval import (
    ActivationContext, approval_payload, verify_activation_approval,
)
from azazel_nexus.operator_trust import (
    ApprovalPurpose, ApprovalRefused, OperatorTrust, approval_message,
)

DIGEST = "sha256:" + "a" * 64
START = "2026-10-13T00:00:00Z"
END = "2026-10-13T00:10:00Z"


@pytest.fixture
def approved():
    key = SigningKey.generate()
    context = ActivationContext(
        DIGEST, "11111111-1111-1111-1111-111111111111", 1,
        DIGEST, DIGEST, DIGEST, DIGEST, DIGEST, 0,
    )
    payload = approval_payload(context=context, operator="operator-a", granted_at=START, expires_at=END)
    signature = key.sign(approval_message(ApprovalPurpose.ACTIVATION, payload)).signature
    args = dict(trust=OperatorTrust({"operator-a": bytes(key.verify_key)}), expected=context,
                operator="operator-a", payload=payload, signature=signature,
                now=START, max_lease_seconds=600)
    return key, args


def test_approval_produces_only_the_bound_lease(approved):
    _, args = approved
    lease = verify_activation_approval(**args)
    assert lease.generation_digest == DIGEST
    assert lease.granted_by == "operator-a"
    assert lease.generation_number == 1
    assert lease.commissioning_digest == DIGEST
    assert lease.valid_at(START)
    assert not lease.valid_at(END)


@pytest.mark.parametrize("name,value", [
    ("node_digest", "sha256:" + "b" * 64),
    ("boot_id", "22222222-2222-2222-2222-222222222222"),
    ("generation", 2), ("generation_digest", "sha256:" + "b" * 64),
    ("commissioning_digest", "sha256:" + "b" * 64),
    ("inventory_digest", "sha256:" + "b" * 64),
    ("policy_digest", "sha256:" + "b" * 64),
    ("renderer_digest", "sha256:" + "b" * 64), ("security_epoch", 1),
])
def test_approval_cannot_follow_changed_expected_context(approved, name, value):
    _, args = approved
    with pytest.raises(ApprovalRefused):
        verify_activation_approval(**(args | {"expected": replace(args["expected"], **{name: value})}))


@pytest.mark.parametrize("changes", [
    {"now": "2026-10-12T23:59:59Z"}, {"now": END},
    {"now": "2026-10-13T00:00:00+00:00"}, {"now": "2026-02-30T00:00:00Z"},
    {"max_lease_seconds": 599}, {"max_lease_seconds": True}, {"max_lease_seconds": 0},
])
def test_time_policy_is_not_selected_by_signer(approved, changes):
    _, args = approved
    with pytest.raises(ApprovalRefused):
        verify_activation_approval(**(args | changes))


@pytest.mark.parametrize("kind", ["operator", "extra", "whitespace", "duplicate", "boolean", "schema"])
def test_even_valid_signatures_cannot_authorize_noncanonical_or_mismatched_documents(approved, kind):
    key, args = approved
    document = json.loads(args["payload"])
    if kind == "operator":
        document["operator"] = "someone-else"
    elif kind == "extra":
        document["healthy"] = True
    elif kind == "boolean":
        document["context"]["generation"] = True
    elif kind == "schema":
        document["schema"] = "other/v1"
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if kind == "whitespace":
        payload += b"\n"
    elif kind == "duplicate":
        payload = b'{"operator":"operator-a",' + payload[1:]
    signature = key.sign(approval_message(ApprovalPurpose.ACTIVATION, payload)).signature
    with pytest.raises(ApprovalRefused):
        verify_activation_approval(**(args | dict(payload=payload, signature=signature)))


def test_commissioning_signature_cannot_be_used_as_activation(approved):
    key, args = approved
    signature = key.sign(approval_message(ApprovalPurpose.COMMISSIONING, args["payload"])).signature
    with pytest.raises(ApprovalRefused):
        verify_activation_approval(**(args | {"signature": signature}))


@pytest.mark.parametrize("changes", [{"generation": True}, {"security_epoch": -1},
                                     {"node_digest": "not-a-digest"}, {"boot_id": ""}])
def test_invalid_expected_context_refuses(approved, changes):
    _, args = approved
    with pytest.raises(ApprovalRefused):
        replace(args["expected"], **changes)


@pytest.mark.parametrize("change", ["number_same_tree", "commissioning_same_number"])
def test_verified_approval_cannot_authorize_a_generation_changed_before_controller_pass(
    approved, tmp_path, change,
):
    key, args = approved
    store = GenerationStore(tmp_path / "generations")
    generation = store.create({"config": b"same bytes"}, created_at=START, commissioning_digest=DIGEST)
    context = replace(args["expected"], generation_digest=generation.digest)
    payload = approval_payload(context=context, operator="operator-a", granted_at=START, expires_at=END)
    signature = key.sign(approval_message(ApprovalPurpose.ACTIVATION, payload)).signature
    lease = verify_activation_approval(**(args | dict(expected=context, payload=payload, signature=signature)))
    units = RecordingUnitController(d.name for d in CORE_UNITS)
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    controller = ActivationController(units=units, generations=store, ledger=ledger)
    assert controller.activate(now=START, actor="operator-a", lease=lease).granted
    if change == "number_same_tree":
        store.create({"config": b"same bytes"}, created_at=START, commissioning_digest=DIGEST)
    else:
        # Simulate altered metadata using the store's actual on-disk layout.
        metadata = store.root / "1" / "generation.json"
        document = json.loads(metadata.read_text())
        document["commissioning_digest"] = "sha256:" + "b" * 64
        metadata.write_text(json.dumps(document))
    units.calls.clear()
    event_count = len(list(ledger))
    outcome = controller.activate(now=START, actor="operator-a", lease=lease)
    assert outcome.granted == ()
    assert all(v.reason.startswith("lease_generation_binding_mismatch") for v in outcome.verdicts)
    assert all(units.state(d.name) is UnitState.MASKED for d in CORE_UNITS)
    assert all(operation == "mask" for operation, _ in units.calls)
    assert not any(e.event["event_type"] == "activation.unit_granted" for e in list(ledger)[event_count:])
    refusal = next(e.event for e in list(ledger)[event_count:]
                   if e.event["event_type"] == "activation.refused")
    assert refusal["generation"] == store.current().number
    assert refusal["reason"].startswith("lease_generation_binding_mismatch")


@pytest.mark.parametrize("binding", [
    {"generation_number": 1}, {"commissioning_digest": DIGEST},
    {"generation_number": True, "commissioning_digest": DIGEST},
    {"generation_number": 0, "commissioning_digest": DIGEST},
    {"generation_number": 1, "commissioning_digest": ""},
])
def test_incomplete_or_invalid_lease_binding_is_rejected(binding):
    with pytest.raises(ActivationRefused):
        ActivationLease(granted_by="operator-a", granted_at=START, expires_at=END,
                        generation_digest=DIGEST, **binding)


@pytest.mark.parametrize("now", ["2026-10-13T00:01:00+00:00", "2026-10-13T00:01:00.1Z",
                                 "2026-10-13T00:01:00z", "2026-02-30T00:01:00Z", None])
def test_controller_time_check_does_not_reinterpret_a_verified_lease(approved, now):
    _, args = approved
    lease = verify_activation_approval(**args)
    assert not lease.valid_at(now)


@pytest.mark.parametrize("field,value", [
    ("granted_at", "2026-10-13T00:00:00+00:00"),
    ("expires_at", "2026-10-13T00:10:00.5Z"),
    ("granted_at", "2026-02-30T00:00:00Z"),
])
def test_bound_lease_construction_requires_canonical_calendar_times(approved, field, value):
    _, args = approved
    lease = verify_activation_approval(**args)
    with pytest.raises(ActivationRefused):
        replace(lease, **{field: value})
