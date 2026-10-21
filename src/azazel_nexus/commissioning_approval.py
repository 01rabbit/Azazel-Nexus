"""A new operator signature over full linked commissioning inputs, not a grant."""

import json
import re

from .decoy_scope import DecoyScopeRefused, decode_deception_scope, render_deception_scope
from .fabric_boundary import (
    CommissioningRecordUnavailable, IdentityUnavailable, build_commissioning_record,
    deception_scope_assignments, restore_commissioning_inputs,
)
from .operator_trust import ApprovalPurpose, ApprovalRefused, MAX_APPROVAL_BYTES, OperatorTrust


def commissioning_proposal_payload(*, inventory, resource_profile, topology_profile,
                                   record_id: str, operator: str, confirmed_at: str,
                                   mio_profile: str | None = None,
                                   deception_scope: dict | None = None) -> bytes:
    """Canonical unsigned bytes for external review/signing in protected storage.

    `deception_scope` makes the wrapper `commissioning-proposal/v3`: v2 plus
    the operator's Deception Lite exposure scope (#196 G1a,
    `docs/deception-exposure-grant.md` §4.1). v3 carries everything v2 does,
    so it needs `mio_profile` too, and the section is decoded whole by
    `decoy_scope.decode_deception_scope` against this proposal's own roles.
    It grants nothing: no pass or helper reads v3 in this build.
    """
    if type(operator) is not str or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", operator):
        raise ApprovalRefused("invalid commissioning operator")
    document = build_commissioning_record(inventory=inventory, resource_profile=resource_profile,
        topology_profile=topology_profile, record_id=record_id,
        operator_ref=operator, confirmed_at=confirmed_at)
    if mio_profile is not None:
        if type(mio_profile) is not str or mio_profile not in {"CORE", "LITE", "FULL"}:
            raise ApprovalRefused("unknown M.I.O. commissioning profile")
        # Extend the Nexus wrapper, not Fabric's descriptive record or authority.
        # The existing full-proposal signature covers this selection as well.
        document["schema"] = "azazel-nexus/commissioning-proposal/v2"
        document["mio_profile"] = mio_profile
    if deception_scope is not None:
        if mio_profile is None:
            raise ApprovalRefused("a deception scope extends a v2 commissioning proposal")
        try:
            scope = decode_deception_scope(deception_scope, assignments=deception_scope_assignments(
                inventory, topology_profile))
        except (DecoyScopeRefused, IdentityUnavailable, ValueError, TypeError, AttributeError):
            raise ApprovalRefused("deception scope refused") from None
        # Same signature, same purpose: the scope is inside the signed bytes
        # and so inside the commissioning digest. Required in v3, as
        # `mio_profile` is in v2; never a separately signed document.
        document["schema"] = "azazel-nexus/commissioning-proposal/v3"
        document["deception_scope"] = render_deception_scope(scope)
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > MAX_APPROVAL_BYTES:
        raise ApprovalRefused("full commissioning proposal exceeds approval size bound")
    return payload


def verify_commissioning_proposal(*, trust: OperatorTrust, payload: bytes, signature: bytes,
                                  inventory, resource_profile, topology_profile,
                                  record_id: str, operator: str, confirmed_at: str,
                                  mio_profile: str | None = None,
                                  deception_scope: dict | None = None) -> None:
    """Verify against independent expected snapshots, never inputs learned from payload.

    Rebuild all cross-record bindings, then demand exact canonical signed bytes.
    Returns no authorization/activation token. Storage, freshness, clock trust,
    high-water state, health and product admission are separate prerequisites.
    """
    trust.verify(operator=operator, purpose=ApprovalPurpose.COMMISSIONING_PROPOSAL,
                 payload=payload, signature=signature)
    expected = commissioning_proposal_payload(inventory=inventory, resource_profile=resource_profile,
        topology_profile=topology_profile, record_id=record_id, operator=operator, confirmed_at=confirmed_at,
        mio_profile=mio_profile, deception_scope=deception_scope)
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
