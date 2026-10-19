"""Read-only M.I.O. capability evidence; never admission or Edge authority."""

from dataclasses import dataclass
from enum import Enum

from azazel_nexus.capability import CapabilityState
from azazel_nexus.edge_package import Evidence
from azazel_nexus.mio_profile import MioProfile


class ResourceReason(str, Enum):
    CORE_RESERVE_UNMEASURED = "core_reserve_unmeasured"


class TopologyReason(str, Enum):
    NO_VERIFIED_EGRESS = "no_verified_egress"


class HealthReason(str, Enum):
    UNAVAILABLE = "unavailable"
    NOT_ADMITTED = "not_admitted"
    NO_ADMISSION_EVIDENCE = "no_admission_evidence"
    INVALID_OBSERVATION = "invalid_observation"


@dataclass(frozen=True)
class CapabilityReading:
    state: CapabilityState
    ceiling: CapabilityState
    local_health: HealthReason
    remote_health: HealthReason

    def as_dict(self) -> dict:
        return {
            "state": self.state.value,
            "reasons": {
                "profile": self.ceiling.value,
                "resource": ResourceReason.CORE_RESERVE_UNMEASURED.value,
                "trust": Evidence.NOT_CHECKED.value,
                "health": {"local": self.local_health.value,
                           "remote": self.remote_health.value},
                "topology": TopologyReason.NO_VERIFIED_EGRESS.value,
            },
        }


def read_capability(profile, local, remote) -> CapabilityReading:
    """Evaluate every dimension, even when another already requires CORE.

    These are the evidence sources entryd actually has today: HG-05 has no
    measured reserve, trust is unchecked, and no verified egress is supplied.
    Socket availability cannot replace any of them. Consequently no current
    input can justify LITE/FULL; the commissioned ceiling remains independent.
    Unknown profiles and malformed observations are conservative, fixed codes.
    """
    ceiling = {
        MioProfile.CORE: CapabilityState.CORE,
        MioProfile.LOCAL_ONLY: CapabilityState.LITE,
        MioProfile.FASTEST_PERMITTED: CapabilityState.FULL,
    }.get(profile, CapabilityState.CORE) if isinstance(profile, MioProfile) else CapabilityState.CORE

    def health(value, prefix):
        return {f"{prefix}_{reason.value}": reason for reason in (
            HealthReason.UNAVAILABLE, HealthReason.NOT_ADMITTED,
            HealthReason.NO_ADMISSION_EVIDENCE,
        )}.get(value, HealthReason.INVALID_OBSERVATION) if type(value) is str else HealthReason.INVALID_OBSERVATION

    return CapabilityReading(CapabilityState.CORE, ceiling,
                             health(local, "local"), health(remote, "remote"))
