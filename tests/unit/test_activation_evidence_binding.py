"""Activation's commissioning evidence is an added gate, not admission."""

from dataclasses import replace
import json

import pytest
from nacl.signing import SigningKey

pytest.importorskip("azazel_fabric")

from azazel_fabric.provisioning_contracts import (  # noqa: E402
    HardwareInventory,
    ResourceProfile,
    TopologyProfile,
)
from azazel_fabric.testing.provisioning import (  # noqa: E402
    golden_hardware_inventory,
    golden_resource_profile,
    golden_topology_profile,
)

from azazel_nexus.activation import (  # noqa: E402
    ActivationController,
    ActivationLease,
    ActivationRefused,
    EdgeBaselineState,
    RecordingUnitController,
    UnitDefinition,
    UnitTier,
)
from azazel_nexus.activation_approval import (  # noqa: E402
    ActivationContext,
    approval_payload,
    verify_activation_approval,
)
from azazel_nexus.audit import AuditLedger  # noqa: E402
from azazel_nexus.commissioning import CommissioningRecord, ConfirmedRole  # noqa: E402
from azazel_nexus.commissioning_approval import (  # noqa: E402
    commissioning_proposal_payload,
)
from azazel_nexus.commissioning_evidence import (  # noqa: E402
    CommissioningEvidence,
    verify_commissioning_evidence,
)
from azazel_nexus.generation import GenerationStore  # noqa: E402
from azazel_nexus.inventory import IDENTITY_FIELDS  # noqa: E402
from azazel_nexus.operator_trust import (  # noqa: E402
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
    approval_message,
)

NOW = "2026-10-13T00:00:00Z"
END = "2026-10-13T00:10:00Z"
ACTOR = "operator-a"
DIGEST = "sha256:" + "a" * 64
BINDING = "hmac-sha256:" + "b" * 64
OTHER_BINDING = "hmac-sha256:" + "c" * 64
CONFIG = {"node.yaml": b"role: observation\n"}
ENFORCING = UnitDefinition(
    "azazel-enforced.service", UnitTier.ENFORCEMENT, "azenforce", "evidence-gated"
)


def _signed_proposal():
    inputs = {
        "inventory": HardwareInventory.model_validate(golden_hardware_inventory()),
        "resource_profile": ResourceProfile.model_validate(golden_resource_profile()),
        "topology_profile": TopologyProfile.model_validate(golden_topology_profile()),
        "record_id": "record-synthetic",
        "operator": ACTOR,
        "confirmed_at": NOW,
    }
    payload = commissioning_proposal_payload(**inputs)
    key = SigningKey.generate()
    signature = key.sign(
        approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL, payload)
    ).signature
    trust = OperatorTrust({ACTOR: bytes(key.verify_key)})
    evidence = verify_commissioning_evidence(
        trust=trust,
        expected_payload=payload,
        payload=payload,
        signature=signature,
        node_id=inputs["inventory"].node_id,
        current_inventory=inputs["inventory"],
        protection_key=b"p" * 32,
    )
    # Build the legacy record's identity from the same Fabric inventory fields
    # that the signed topology assignment selected. Neither side uses kernel
    # enumeration names as identity.
    roles = []
    for assignment in inputs["topology_profile"].commissioned_assignments:
        interface = next(
            item
            for item in inputs["inventory"].interfaces
            if all(
                getattr(assignment.selector, name) is None
                or getattr(item, name) == getattr(assignment.selector, name)
                for name in IDENTITY_FIELDS
            )
        )
        composite = tuple((name, getattr(interface, name)) for name in IDENTITY_FIELDS)
        confirmation = assignment.confirmation.model_dump(mode="json")
        roles.append(
            ConfirmedRole(
                composite,
                assignment.role,
                confirmation["operator_ref"],
                confirmation["confirmed_at"],
            )
        )
    record = CommissioningRecord(
        roles=tuple(roles),
        profiles_present=("hardware", "resource", "topology"),
        created_at=NOW,
    )
    return evidence, record


def _controller(tmp_path, *, binding=BINDING, commissioning_digest=None):
    record_digest = commissioning_digest or _signed_proposal()[1].digest()
    store = GenerationStore(tmp_path / "generations")
    generation = store.create(
        CONFIG,
        created_at=NOW,
        commissioning_digest=record_digest,
        commissioning_evidence_binding=binding,
    )
    units = RecordingUnitController([ENFORCING.name])
    ledger = AuditLedger(tmp_path / "ledger.jsonl")
    controller = ActivationController(
        units=units,
        generations=store,
        ledger=ledger,
        definitions=(ENFORCING,),
    )
    return controller, units, ledger, generation


def _lease(generation, *, binding=BINDING, commissioning_digest=None):
    return ActivationLease(
        granted_by=ACTOR,
        granted_at="2026-10-12T23:59:00Z",
        expires_at=END,
        generation_digest=generation.digest,
        generation_number=generation.number,
        commissioning_digest=commissioning_digest or _signed_proposal()[1].digest(),
        commissioning_evidence_binding=binding,
    )


def _activate(controller, lease, *, evidence=None, record=None, **kwargs):
    return controller.activate(
        now=NOW,
        actor=ACTOR,
        lease=lease,
        record=record,
        commissioning_evidence=evidence,
        require_commissioning_evidence=True,
        **kwargs,
    )


def test_fake_constructor_evidence_is_only_a_test_seam_and_cannot_bind_an_unrelated_record(
    tmp_path,
):
    """Shape-valid bytes do not authenticate or bind a legacy role record."""
    record = _signed_proposal()[1]
    controller, _, _, generation = _controller(
        tmp_path, commissioning_digest=record.digest()
    )
    unrelated = replace(
        record,
        roles=(
            replace(
                record.roles[0],
                composite=(
                    ("bus_path", "pci-0000:ff:00.0"),
                    ("permanent_mac", "02:ff:00:00:00:01"),
                ),
            ),
        ),
    )
    # Direct construction intentionally exercises only the decision seam. It
    # is not evidence that a signature or provenance check was performed.
    fake = CommissioningEvidence(b"{}", b"s" * 64, b"{}", BINDING)

    outcome = _activate(
        controller,
        _lease(generation, commissioning_digest=record.digest()),
        evidence=fake,
        record=unrelated,
    )

    assert outcome.granted == ()
    assert outcome.verdicts[0].reason.startswith("commissioning_evidence")


@pytest.mark.parametrize("evidence", [None, object()])
def test_missing_or_wrong_type_evidence_withholds_enforcement(tmp_path, evidence):
    record = _signed_proposal()[1]
    controller, _, _, generation = _controller(
        tmp_path, commissioning_digest=record.digest()
    )

    outcome = _activate(
        controller,
        _lease(generation, commissioning_digest=record.digest()),
        evidence=evidence,
        record=record,
    )

    assert outcome.granted == ()
    assert outcome.verdicts[0].reason.startswith("commissioning_evidence_absent")


def test_bound_policy_refuses_a_generation_without_an_evidence_binding(tmp_path):
    evidence, record = _signed_proposal()
    controller, _, _, generation = _controller(
        tmp_path, binding=None, commissioning_digest=record.digest()
    )

    outcome = _activate(
        controller,
        _lease(generation, binding=None, commissioning_digest=record.digest()),
        evidence=evidence,
        record=record,
    )

    assert outcome.granted == ()
    assert "binding" in outcome.verdicts[0].reason


def test_enforcement_refuses_when_evidence_binding_differs_from_generation(tmp_path):
    evidence, record = _signed_proposal()
    controller, _, _, generation = _controller(
        tmp_path, binding=BINDING, commissioning_digest=record.digest()
    )

    outcome = _activate(
        controller,
        _lease(
            generation,
            binding=evidence.binding,
            commissioning_digest=record.digest(),
        ),
        evidence=evidence,
        record=record,
    )

    assert outcome.granted == ()
    assert outcome.verdicts[0].reason.startswith(
        "commissioning_evidence_binding_mismatch"
    )


@pytest.mark.parametrize(
    ("record", "healthy", "with_lease", "reason"),
    [
        (None, True, True, "commissioning_absent"),
        ("incomplete", True, True, "commissioning_evidence_record_mismatch"),
        ("complete", False, True, "health_not_established"),
        ("complete", True, False, "lease_absent"),
    ],
)
def test_valid_evidence_does_not_replace_legacy_record_health_or_lease_gates(
    tmp_path, record, healthy, with_lease, reason
):
    evidence, complete = _signed_proposal()
    controller, _, _, generation = _controller(
        tmp_path, binding=evidence.binding, commissioning_digest=complete.digest()
    )
    selected_record = (
        None
        if record is None
        else replace(complete, profiles_present=("hardware", "resource"))
        if record == "incomplete"
        else complete
    )

    outcome = _activate(
        controller,
        _lease(
            generation,
            binding=evidence.binding,
            commissioning_digest=complete.digest(),
        )
        if with_lease
        else None,
        evidence=evidence,
        record=selected_record,
        healthy=healthy,
    )

    assert outcome.granted == ()
    assert outcome.verdicts[0].reason.startswith(reason)


@pytest.mark.injected
def test_valid_canonical_evidence_and_matching_legacy_record_can_pass_injected_decision(
    tmp_path,
):
    """This is injected decision coverage, not production activation proof."""
    evidence, record = _signed_proposal()
    controller, _, _, generation = _controller(
        tmp_path, binding=evidence.binding, commissioning_digest=record.digest()
    )

    outcome = _activate(
        controller,
        _lease(
            generation,
            binding=evidence.binding,
            commissioning_digest=record.digest(),
        ),
        evidence=evidence,
        record=record,
    )

    signed_document = json.loads(evidence.payload)
    assert len(record.roles) == len(
        signed_document["topology"]["commissioned_assignments"]
    )
    assert outcome.granted == (ENFORCING.name,)


@pytest.mark.parametrize(
    ("field", "value"),
    [("role", "management"), ("confirmed_by", "operator-impersonator")],
)
def test_real_evidence_rejects_a_mutated_role_or_provenance(tmp_path, field, value):
    evidence, record = _signed_proposal()
    changed_role = replace(record.roles[0], **{field: value})
    changed_record = replace(record, roles=(changed_role, *record.roles[1:]))
    controller, _, _, generation = _controller(
        tmp_path, binding=evidence.binding, commissioning_digest=record.digest()
    )

    outcome = _activate(
        controller,
        _lease(
            generation,
            binding=evidence.binding,
            commissioning_digest=record.digest(),
        ),
        evidence=evidence,
        record=changed_record,
    )

    assert outcome.granted == ()
    assert outcome.verdicts[0].reason.startswith(
        "commissioning_evidence_record_mismatch"
    )


def test_legacy_activation_without_evidence_keeps_existing_admission(tmp_path):
    record = _signed_proposal()[1]
    controller, _, _, generation = _controller(
        tmp_path, binding=None, commissioning_digest=record.digest()
    )
    lease = ActivationLease(
        ACTOR,
        "2026-10-12T23:59:00Z",
        END,
        generation.digest,
    )

    outcome = controller.activate(now=NOW, actor=ACTOR, lease=lease, record=record)

    assert outcome.granted == (ENFORCING.name,)


def test_lease_only_evidence_binding_refuses_enforcement_without_evidence(tmp_path):
    """A bound approval cannot bypass the evidence gate on a legacy generation."""
    record = _signed_proposal()[1]
    controller, _, _, generation = _controller(
        tmp_path, binding=None, commissioning_digest=record.digest()
    )
    lease = _lease(
        generation,
        binding=BINDING,
        commissioning_digest=record.digest(),
    )

    outcome = controller.activate(
        now=NOW,
        actor=ACTOR,
        lease=lease,
        record=record,
        healthy=True,
    )

    assert generation.commissioning_evidence_binding is None
    assert lease.commissioning_evidence_binding == BINDING
    assert outcome.granted == ()
    assert outcome.verdicts[0].reason.startswith("commissioning_evidence_absent")


def test_supporting_tier_does_not_gain_the_enforcement_evidence_gate(tmp_path):
    supporting = UnitDefinition(
        "azazel-auditd.service", UnitTier.SUPPORTING, "azaudit", "base"
    )
    record = _signed_proposal()[1]
    store = GenerationStore(tmp_path / "generations")
    generation = store.create(
        CONFIG, created_at=NOW, commissioning_digest=record.digest()
    )
    controller = ActivationController(
        units=RecordingUnitController([supporting.name]),
        generations=store,
        ledger=AuditLedger(tmp_path / "ledger.jsonl"),
        definitions=(supporting,),
    )

    outcome = controller.activate(
        now=NOW,
        actor=ACTOR,
        lease=ActivationLease(ACTOR, "2026-10-12T23:59:00Z", END, generation.digest),
        require_commissioning_evidence=True,
    )

    assert outcome.granted == (supporting.name,)


@pytest.mark.parametrize(
    ("tier", "name", "account", "edge"),
    [
        (UnitTier.SUPPORTING, "azazel-auditd.service", "azaudit", None),
        (
            UnitTier.EDGE_BASELINE,
            "azazel-edge-core.service",
            "root",
            EdgeBaselineState(True, True, True, True, True),
        ),
    ],
)
def test_lower_tiers_ignore_new_evidence_binding_mismatch(
    tmp_path, tier, name, account, edge
):
    evidence, record = _signed_proposal()
    definition = UnitDefinition(name, tier, account, "baseline eligibility")
    store = GenerationStore(tmp_path / "generations")
    generation = store.create(
        CONFIG,
        created_at=NOW,
        commissioning_digest=record.digest(),
        commissioning_evidence_binding=BINDING,
    )
    controller = ActivationController(
        units=RecordingUnitController([name]),
        generations=store,
        ledger=AuditLedger(tmp_path / "ledger.jsonl"),
        definitions=(definition,),
    )
    lease = _lease(
        generation,
        binding=evidence.binding,
        commissioning_digest=record.digest(),
    )

    outcome = controller.activate(
        now=NOW,
        actor=ACTOR,
        lease=lease,
        edge=edge,
        record=record,
        healthy=True,
        commissioning_evidence=evidence,
        require_commissioning_evidence=True,
    )

    assert (
        generation.commissioning_evidence_binding
        != lease.commissioning_evidence_binding
    )
    assert outcome.granted == (name,)


@pytest.mark.parametrize(
    ("tier", "name", "account", "edge"),
    [
        (UnitTier.SUPPORTING, "azazel-auditd.service", "azaudit", None),
        (
            UnitTier.EDGE_BASELINE,
            "azazel-edge-core.service",
            "root",
            EdgeBaselineState(True, True, True, True, True),
        ),
    ],
)
def test_lease_only_evidence_binding_does_not_block_lower_tiers(
    tmp_path, tier, name, account, edge
):
    record = _signed_proposal()[1]
    definition = UnitDefinition(name, tier, account, "lease-only-binding")
    store = GenerationStore(tmp_path / "generations")
    generation = store.create(
        CONFIG,
        created_at=NOW,
        commissioning_digest=record.digest(),
    )
    controller = ActivationController(
        units=RecordingUnitController([name]),
        generations=store,
        ledger=AuditLedger(tmp_path / "ledger.jsonl"),
        definitions=(definition,),
    )
    lease = _lease(
        generation,
        binding=BINDING,
        commissioning_digest=record.digest(),
    )

    outcome = controller.activate(
        now=NOW,
        actor=ACTOR,
        lease=lease,
        edge=edge,
        healthy=True,
    )

    assert generation.commissioning_evidence_binding is None
    assert lease.commissioning_evidence_binding == BINDING
    assert outcome.granted == (name,)


def test_matching_evidence_does_not_override_the_distribution_wiring_gate(tmp_path):
    evidence, record = _signed_proposal()
    wired_enforcement = UnitDefinition(
        ENFORCING.name,
        UnitTier.ENFORCEMENT,
        "azenforce",
        "wiring-gated",
        "fabric.runtime",
    )
    store = GenerationStore(tmp_path / "generations")
    generation = store.create(
        CONFIG,
        created_at=NOW,
        commissioning_digest=record.digest(),
        commissioning_evidence_binding=evidence.binding,
    )
    controller = ActivationController(
        units=RecordingUnitController([wired_enforcement.name]),
        generations=store,
        ledger=AuditLedger(tmp_path / "ledger.jsonl"),
        definitions=(wired_enforcement,),
    )

    outcome = controller.activate(
        now=NOW,
        actor=ACTOR,
        lease=_lease(
            generation,
            binding=evidence.binding,
            commissioning_digest=record.digest(),
        ),
        record=record,
        commissioning_evidence=evidence,
        require_commissioning_evidence=True,
        wired=(),
    )

    assert outcome.granted == ()
    assert outcome.verdicts[0].reason.startswith("wiring_absent")


def _activation_context(*, binding=None):
    return ActivationContext(
        DIGEST,
        "11111111-1111-1111-1111-111111111111",
        1,
        DIGEST,
        DIGEST,
        DIGEST,
        DIGEST,
        DIGEST,
        0,
        binding,
    )


def test_legacy_approval_encoding_omits_the_new_optional_field():
    payload = approval_payload(
        context=_activation_context(),
        operator=ACTOR,
        granted_at=NOW,
        expires_at=END,
    )
    context_document = json.loads(payload)["context"]

    assert "commissioning_evidence_binding" not in context_document


@pytest.mark.parametrize("replacement", ["omit", "null"])
def test_bound_expected_context_rejects_omitted_or_null_binding_even_when_resigned(
    replacement,
):
    context = _activation_context(binding=BINDING)
    payload_document = json.loads(
        approval_payload(
            context=context, operator=ACTOR, granted_at=NOW, expires_at=END
        )
    )
    if replacement == "omit":
        payload_document["context"].pop("commissioning_evidence_binding")
    else:
        payload_document["context"]["commissioning_evidence_binding"] = None
    payload = json.dumps(
        payload_document, sort_keys=True, separators=(",", ":")
    ).encode()
    key = SigningKey.generate()
    signature = key.sign(
        approval_message(ApprovalPurpose.ACTIVATION, payload)
    ).signature

    with pytest.raises(ApprovalRefused):
        verify_activation_approval(
            trust=OperatorTrust({ACTOR: bytes(key.verify_key)}),
            expected=context,
            operator=ACTOR,
            payload=payload,
            signature=signature,
            now=NOW,
            max_lease_seconds=600,
        )


def test_validly_signed_context_with_different_generation_binding_is_refused(tmp_path):
    record = _signed_proposal()[1]
    controller, _, _, generation = _controller(
        tmp_path, binding=BINDING, commissioning_digest=record.digest()
    )
    context = replace(
        _activation_context(binding=OTHER_BINDING),
        generation_digest=generation.digest,
        commissioning_digest=record.digest(),
    )
    key = SigningKey.generate()
    payload = approval_payload(
        context=context, operator=ACTOR, granted_at=NOW, expires_at=END
    )
    signature = key.sign(
        approval_message(ApprovalPurpose.ACTIVATION, payload)
    ).signature
    lease = verify_activation_approval(
        trust=OperatorTrust({ACTOR: bytes(key.verify_key)}),
        expected=context,
        operator=ACTOR,
        payload=payload,
        signature=signature,
        now=NOW,
        max_lease_seconds=600,
    )

    assert lease.commissioning_evidence_binding == OTHER_BINDING
    outcome = _activate(
        controller,
        lease,
        evidence=CommissioningEvidence(b"{}", b"s" * 64, b"{}", OTHER_BINDING),
        record=record,
    )

    assert outcome.granted == ()
    assert outcome.verdicts[0].reason.startswith(
        "commissioning_evidence_binding_mismatch"
    )


@pytest.mark.parametrize(
    "binding",
    [
        1,
        True,
        b"hmac-sha256:" + b"b" * 64,
        "hmac-sha256:" + "B" * 64,
        "hmac-sha256:" + "b" * 63,
        "sha256:" + "b" * 64,
        "hmac-sha256:" + "b" * 64 + "x",
    ],
)
def test_invalid_activation_context_and_lease_binding_types_or_formats_refuse(binding):
    with pytest.raises(ApprovalRefused, match="binding"):
        _activation_context(binding=binding)
    with pytest.raises(ActivationRefused, match="binding"):
        ActivationLease(
            ACTOR,
            "2026-10-12T23:59:00Z",
            END,
            DIGEST,
            generation_number=1,
            commissioning_digest=DIGEST,
            commissioning_evidence_binding=binding,
        )
    with pytest.raises(ApprovalRefused, match="commissioning evidence shape"):
        CommissioningEvidence(b"x", b"s" * 64, b"x", binding)
