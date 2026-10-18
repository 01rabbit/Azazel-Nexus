"""Local adapter admission and assurance; no adapter transport or execution."""

from .broker import Broker, BrokerRefused
from .confinement import (
    AdapterCommissioning,
    ConfinementRefused,
    CredentialRef,
    render_adapter_unit,
    rotate_credential,
)
from .manifest import (
    ADAPTER_MANIFEST_DOMAIN,
    AdapterKind,
    AdapterManifest,
    Capability,
    EgressRule,
    ManifestRefused,
    read_manifest,
)
from .routing import (
    DataRecord,
    DispatchIntent,
    EdgeLease,
    ExposureChangeProposal,
    GateRefusal,
    ManagementFailsafe,
    deliver,
    gate_exposure_proposal,
    route_advisory,
    route_telemetry,
)
from .states import (
    AdapterRecord,
    Approval,
    BrokerState,
    Transition,
    TransitionRefused,
    transition,
)

__all__ = [
    "ADAPTER_MANIFEST_DOMAIN", "AdapterCommissioning", "AdapterKind", "AdapterManifest",
    "AdapterRecord", "Approval", "Broker", "BrokerRefused", "BrokerState", "Capability",
    "ConfinementRefused", "CredentialRef", "DataRecord", "DispatchIntent", "EdgeLease",
    "EgressRule", "ExposureChangeProposal", "GateRefusal", "ManagementFailsafe", "ManifestRefused",
    "Transition", "TransitionRefused", "deliver", "gate_exposure_proposal", "read_manifest",
    "render_adapter_unit", "rotate_credential", "route_advisory", "route_telemetry", "transition",
]
