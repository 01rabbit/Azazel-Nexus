"""Fresh resource floor checks, not complete health or bootstrap admission.

Thresholds must come from independently admitted deployment policy. They are
not inferred from candidate generation bytes or from the machine being tested.
Memory here is kernel MemTotal, NOT free memory or a cgroup allocation.
"""

from dataclasses import dataclass

from azazel_nexus.operator_trust import ApprovalRefused

from .resource_assessment import assess_resources


@dataclass(frozen=True)
class BootstrapResourceThresholds:
    min_usable_memory_mib: int
    min_online_logical_cpus: int
    min_mission_available_mib: int

    def __post_init__(self):
        for value in (self.min_usable_memory_mib, self.min_online_logical_cpus,
                      self.min_mission_available_mib):
            if type(value) is not int or not 0 < value < 2**63:
                raise ApprovalRefused("explicit positive resource floors required")


def require_bootstrap_resources(thresholds: BootstrapResourceThresholds) -> None:
    """Check fresh aggregate floors only; never turn observation into start grant.

    No default thresholds, architecture allowlist, policy reader or cached
    success. Encryption, cgroups, free RAM, audit, closure, time and lifecycle
    checks remain required separately. The observation timestamp is not trusted
    time. Production semantic composition must bind these floors to its policy.
    """
    try:
        if type(thresholds) is not BootstrapResourceThresholds:
            raise ApprovalRefused("admitted resource thresholds required")
        observation = assess_resources()
        if (type(observation) is not dict
                or observation.get("schema") != "azazel-nexus/resource-observation/v1"
                or observation.get("admission") != "not-evaluated"
                or observation.get("unavailable") != []):
            raise ApprovalRefused("resource observations incomplete")
        values = observation.get("measurements")
        required = {
            "usable_memory_mib": thresholds.min_usable_memory_mib,
            "online_logical_cpus": thresholds.min_online_logical_cpus,
            "mission_available_mib": thresholds.min_mission_available_mib,
        }
        if type(values) is not dict or set(values) != set(required):
            raise ApprovalRefused("resource measurements malformed")
        for field, floor in required.items():
            if type(values[field]) is not int or not floor <= values[field] < 2**63:
                raise ApprovalRefused("resource floor not met")
    except Exception:
        raise ApprovalRefused("bootstrap capacity prerequisite refused") from None
