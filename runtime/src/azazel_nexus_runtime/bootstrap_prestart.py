"""Policy-pinned real capacity checks, not complete bootstrap admission."""

from azazel_nexus.bootstrap_prestart_store import load_bootstrap_prestart_policy
from azazel_nexus.operator_trust import ApprovalRefused

from .bootstrap_resources import BootstrapResourceThresholds, require_bootstrap_resources
from .bootstrap_state_capacity import BootstrapStateFloors, require_bootstrap_state_capacity
from .bootstrap_audit import AuditObservation, inspect_existing_audit, inspect_audit_extension
from .units import UnitKey


def _require_helpers_stopped(manager):
    for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND):
        if manager.is_masked(unit) is not True or manager.is_inactive(unit) is not True:
            raise ApprovalRefused("bootstrap helpers must be masked and inactive")


def check_bootstrap_capacity(*, expected) -> None:
    """Use independent expected context, never candidate-supplied expectations.

    Only capacity prerequisites are checked. Actual installed closure, audit
    continuity/writer state, trusted time and lifetime fencing remain required.
    This function is not a complete `ProtectedBootstrapGenerationAdmission.admit`.
    """
    try:
        policy = load_bootstrap_prestart_policy(expected=expected)
        require_bootstrap_resources(BootstrapResourceThresholds(
            policy.min_usable_memory_mib, policy.min_online_logical_cpus,
            policy.min_mission_available_mib,
        ))
        require_bootstrap_state_capacity(BootstrapStateFloors(
            policy.bootstrap_bytes, policy.bootstrap_inodes, policy.audit_bytes, policy.audit_inodes,
        ))
        if load_bootstrap_prestart_policy(expected=expected) != policy:
            raise ApprovalRefused("policy changed during resource checks")
    except Exception:
        raise ApprovalRefused("policy-bound bootstrap capacity refused") from None


def check_bootstrap_existing_audit(*, expected, manager) -> AuditObservation:
    """Inspect policy-pinned existing history between read-only helper checks.

    Manager belongs to trusted runtime composition, not request payloads.
    Before/after inactive observations are not a continuous writer lock or a
    defense against hostile root. The controller's lifetime transaction and
    independently reviewed service graph remain prerequisites. No service is
    stopped, masked, started or enabled here. No missing-history genesis.
    """
    try:
        policy = load_bootstrap_prestart_policy(expected=expected)
        _require_helpers_stopped(manager)
        observed = inspect_existing_audit(
            expected_head=(policy.audit_sequence, policy.audit_head),
            max_total_bytes=policy.max_audit_bytes, max_segments=policy.max_audit_segments,
        )
        if (type(observed) is not AuditObservation
                or (observed.sequence, observed.digest) != (policy.audit_sequence, policy.audit_head)):
            raise ApprovalRefused("audit observation differs from policy")
        _require_helpers_stopped(manager)
        if load_bootstrap_prestart_policy(expected=expected) != policy:
            raise ApprovalRefused("policy changed during audit observation")
        return observed
    except Exception:
        raise ApprovalRefused("policy-bound bootstrap audit refused") from None


def inspect_bootstrap_prestart(*, expected, manager) -> AuditObservation:
    """Compose capacity plus existing-history checks, not full semantic admission.

    Installed closure, trusted time, storage trust and lifecycle fencing are
    intentionally not replaced by these checks or this returned observation.
    """
    try:
        policy = load_bootstrap_prestart_policy(expected=expected)
        _require_helpers_stopped(manager)
        check_bootstrap_capacity(expected=expected)
        observed = check_bootstrap_existing_audit(expected=expected, manager=manager)
        _require_helpers_stopped(manager)
        if load_bootstrap_prestart_policy(expected=expected) != policy:
            raise ApprovalRefused("policy changed across prestart checks")
        return observed
    except Exception:
        raise ApprovalRefused("bootstrap prestart prerequisites refused") from None


def check_bootstrap_audit_extension(*, expected, previous: AuditObservation) -> AuditObservation:
    """Policy-bounded continuation; previous must be the controller's verified head."""
    try:
        if type(previous) is not AuditObservation:
            raise ApprovalRefused("previous verified audit observation required")
        policy = load_bootstrap_prestart_policy(expected=expected)
        if (previous.sequence < policy.audit_sequence
                or (previous.sequence == policy.audit_sequence and previous.digest != policy.audit_head)):
            raise ApprovalRefused("previous audit observation precedes policy")
        observed = inspect_audit_extension(
            expected_head=(previous.sequence, previous.digest),
            max_total_bytes=policy.max_audit_bytes, max_segments=policy.max_audit_segments,
        )
        if load_bootstrap_prestart_policy(expected=expected) != policy:
            raise ApprovalRefused("policy changed during audit continuation")
        return observed
    except Exception:
        raise ApprovalRefused("policy-bound bootstrap audit continuation refused") from None
