"""A new operator signature over full linked commissioning inputs, not a grant."""

import json
import re

from .fabric_boundary import (
    CommissioningRecordUnavailable, build_commissioning_record, restore_commissioning_inputs,
)
from .operator_trust import ApprovalPurpose, ApprovalRefused, MAX_APPROVAL_BYTES, OperatorTrust


def commissioning_proposal_payload(*, inventory, resource_profile, topology_profile,
                                   record_id: str, operator: str, confirmed_at: str) -> bytes:
    """Canonical unsigned bytes for external review/signing in protected storage."""
    if type(operator) is not str or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", operator):
        raise ApprovalRefused("invalid commissioning operator")
    document = build_commissioning_record(inventory=inventory, resource_profile=resource_profile,
        topology_profile=topology_profile, record_id=record_id,
        operator_ref=operator, confirmed_at=confirmed_at)
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > MAX_APPROVAL_BYTES:
        raise ApprovalRefused("full commissioning proposal exceeds approval size bound")
    return payload


def verify_commissioning_proposal(*, trust: OperatorTrust, payload: bytes, signature: bytes,
                                  inventory, resource_profile, topology_profile,
                                  record_id: str, operator: str, confirmed_at: str) -> None:
    """Verify against independent expected snapshots, never inputs learned from payload.

    Rebuild all cross-record bindings, then demand exact canonical signed bytes.
    Returns no authorization/activation token. Storage, freshness, clock trust,
    high-water state, health and product admission are separate prerequisites.
    """
    trust.verify(operator=operator, purpose=ApprovalPurpose.COMMISSIONING_PROPOSAL,
                 payload=payload, signature=signature)
    expected = commissioning_proposal_payload(inventory=inventory, resource_profile=resource_profile,
        topology_profile=topology_profile, record_id=record_id, operator=operator, confirmed_at=confirmed_at)
    if payload != expected:
        raise ApprovalRefused("commissioning proposal does not match expected snapshots")


def verify_retained_commissioning_proposal(*, trust: OperatorTrust, payload: bytes,
                                          signature: bytes, expected_payload: bytes,
                                          operator: str, node_id: str) -> None:
    """Check a detached signature against separately retained local expectations.

    expected_payload must come from protected local creation state, never from
    the externally returned candidate. Storage ownership/provenance is the
    caller's responsibility. This is historical approval, not freshness or
    current-hardware/activation validation; no authorization token is returned.
    """
    from .lab_host import refuse_lab_host

    refuse_lab_host(ApprovalRefused)
    try:
        if (type(expected_payload) is not bytes
                or not 0 < len(expected_payload) <= MAX_APPROVAL_BYTES):
            raise ValueError
        context = restore_commissioning_inputs(json.loads(expected_payload))
        if (type(node_id) is not str or context["inventory"].node_id != node_id
                or context["operator"] != operator
                or commissioning_proposal_payload(**context) != expected_payload):
            raise ValueError
        verify_commissioning_proposal(trust=trust, payload=payload, signature=signature, **context)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError,
            CommissioningRecordUnavailable):
        raise ApprovalRefused("retained commissioning expectations refused") from None
