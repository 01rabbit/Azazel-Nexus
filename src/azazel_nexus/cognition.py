"""Local-first M.I.O. routing, and the provider gates before it (#5, E2).

`docs/mio-runtime.md` is the contract. This module implements the parts of it
that can be implemented from evidence this repository holds, and **refuses the
parts that would need a measurement it does not have**.

## The one sentence that does not move

M.I.O. is advisory. Nothing here authorizes or executes an Edge action, in any
state, under any resource profile. `CognitionState` names what the node can
currently *say*, never what it may decide.

## Local-first, and remote off

    deterministic no-model handoff   always available, never removed
            -> local M.I.O.          when a local provider is admitted and healthy
            -> remote assistance     optional; never required, never blocking

Remote assistance is **disabled by default and has no code path here**. It is
not "configured off"; there is no client, no socket, no URL and no egress
function in this module, and `tests/unit/test_cognition.py` scans for their
absence. Enabling it needs three things this repository does not have: an
enumerated privacy-class admission, a deterministic sanitizer, and explicit
operator permission. Until all three exist, `remote` reads `disabled`, which
is a decision, not a failure -- and `disabled` and `unavailable` are therefore
different words here, as they are everywhere else in this product.

## The Core reserve is unmeasured, so the resource gate refuses

`docs/capability-model.md` §2 and `docs/IMPLEMENTATION_SPEC.md` §2.1 both say
it plainly: whether a hardware class can carry a given workload is *"subject to
the measured Core reserve, which for Nexus is still **unmeasured**"*, and an
implementation *"MUST NOT treat the selected profile as evidence that a
capability fits"*.

A headroom check needs that number. Choosing one here would be inventing a
measurement, so the resource gate refuses every local model provider and names
why. The consequence is honest and is the required behaviour rather than a
defect: the node sits at `CORE ONLY` for a *resource* reason, the other
dimensions report independently, and the deterministic path continues
untouched. `docs/hardware-gates.md` `HG-05` tracks the measurement.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Sequence

from .compatibility import HostFacts, TestedTupleSet
from .core_reserve import CoreReserve
from .resource_profile import ResourceProfile

__all__ = [
    "AdmissionGate",
    "CognitionReading",
    "CognitionState",
    "LocalModelProvider",
    "ProviderAdmission",
    "RemoteState",
    "ResourceEvidence",
    "admit_local_model",
    "read_cognition",
]


class CognitionState(str, Enum):
    """What the node can currently say. Never what it may decide."""

    #: Deterministic explanations only. Always available, never removed.
    CORE_ONLY = "CORE ONLY"
    #: A local model is admitted and healthy.
    LOCAL = "LOCAL"
    #: Local plus admitted remote assistance. Unreachable in this build.
    HYBRID = "HYBRID"


class RemoteState(str, Enum):
    """Why remote assistance is not in use. The two are not the same fact."""

    #: A decision: it is not enabled, and no egress path exists to enable.
    DISABLED = "disabled"
    #: Enabled and not reachable or not healthy. Unreachable in this build.
    UNAVAILABLE = "unavailable"


class AdmissionGate(str, Enum):
    """`docs/contract-ownership.md` §4, in order. Every gate can reject."""

    AUTHENTICITY = "authenticity"
    COMPATIBILITY = "tested compatibility tuple"
    CONTENT_POLICY = "semantic content policy"
    RESOURCE_TOPOLOGY = "resource/topology admission"
    APPROVAL = "operator or policy-authority approval"
    STAGED_ACTIVATION = "staged activation"


#: The order gates run in. A later gate never runs when an earlier one
#: rejected, so the gate a refusal names is the first one that rejected --
#: which is the one an operator acts on.
#:
#: `APPROVAL` and `STAGED_ACTIVATION` are in the vocabulary and are **not
#: reached on any node this build runs on**: the resource gate before them
#: refuses without a measured Core reserve, and no node has one
#: (`core_reserve.py`, `docs/hardware-gates.md` HG-05).
#:
#: They are not *unreachable*, and the difference matters. Supply a measured
#: reserve that a provider fits under and `APPROVAL` is reached -- where it
#: refuses for having no implementation, not for being past the end of the
#: road. A gate that refuses only by being unreachable is a gate that starts
#: passing the day something upstream stops refusing, silently and without a
#: line of code changing. `tests/unit/test_cognition.py` drives both: no node
#: today gets past the resource gate, and a node with a reserve gets exactly
#: one gate further and stops.
GATE_ORDER = (
    AdmissionGate.AUTHENTICITY,
    AdmissionGate.COMPATIBILITY,
    AdmissionGate.CONTENT_POLICY,
    AdmissionGate.RESOURCE_TOPOLOGY,
    AdmissionGate.APPROVAL,
    AdmissionGate.STAGED_ACTIVATION,
)


@dataclass(frozen=True)
class ResourceEvidence:
    """What the resource gate needs to decide, both halves or neither (#68).

    The gate compares a declared memory need against the node's envelope
    **after the Core reserve**, so it needs two measured quantities: the
    reserve (`core_reserve.py`) and the envelope the node actually has. They
    are one argument because either alone is worse than neither -- an envelope
    without a reserve is the invented-threshold case `HG-05` exists to
    prevent, and a reserve without an envelope has nothing to subtract from.

    `envelope_mib` is what the node measured, not a class floor.
    `resource_profile.PROFILE_ORDER` names hardware classes, and
    `docs/capability-model.md` §2 is explicit that a class is never evidence
    that a capability fits.

    **No node this build runs on supplies one.** `core_reserve.load_reserve()`
    returns `None` everywhere, because no measurement has been taken and none
    ships -- see `docs/core-reserve-measurement.md`.
    """

    reserve: CoreReserve
    envelope_mib: int

    def __post_init__(self) -> None:
        if self.envelope_mib < 1:
            raise ValueError(
                "the envelope is not a positive quantity; a node that cannot "
                "say how much memory it has has not measured one"
            )


@dataclass(frozen=True)
class LocalModelProvider:
    """A declared local model runtime. Declaring is not being admitted."""

    name: str
    component_digest: str
    #: Declared, never discovered. `docs/mio-runtime.md` §3 requires the
    #: format, tokenizer format, runtime version, quantization, context size
    #: and memory need to be declared before admission can consider them.
    declared_format: str
    tokenizer_format: str
    runtime_version: str
    quantization: str
    context_size: int
    memory_need_mib: int
    #: Whether the asset's signature verified. Supplied by the caller because
    #: this module does not own asset verification; `False` and `None` are
    #: different -- the second means nobody checked.
    signature_verified: Optional[bool] = None
    #: Whether the content policy passed. Same three-valued rule.
    content_policy_passed: Optional[bool] = None

    role: str = "generative"

    # There is deliberately no `approved` or `staged` field. The resource gate
    # always rejects while the Core reserve is unmeasured, so the approval and
    # staged-activation gates are never reached -- and a field nothing reads is
    # a claim the code does not support. They arrive with HG-05, together with
    # the gates that would consult them.


@dataclass(frozen=True)
class ProviderAdmission:
    """The outcome, and the first gate that rejected."""

    provider: str
    admitted: bool
    failed_gate: Optional[AdmissionGate]
    reason: str

    def as_event(self) -> dict:
        return {
            "event_type": "cognition.provider.admission",
            "provider": self.provider,
            "admitted": self.admitted,
            "failed_gate": self.failed_gate.value if self.failed_gate else None,
            "reason": self.reason,
        }


def admit_local_model(
    provider: LocalModelProvider,
    *,
    host: Optional[HostFacts],
    tested: TestedTupleSet,
    resources: Optional[ResourceEvidence] = None,
) -> ProviderAdmission:
    """Run §4's gates in order. The first rejection is the answer.

    Admission is never inferred from availability: a present file is not an
    admitted provider, so every gate's evidence must be supplied explicitly
    and `None` -- nobody checked -- rejects exactly as `False` does, with a
    different reason.
    """

    def refuse(gate: AdmissionGate, reason: str) -> ProviderAdmission:
        return ProviderAdmission(
            provider=provider.name, admitted=False, failed_gate=gate, reason=reason
        )

    if provider.signature_verified is None:
        return refuse(
            AdmissionGate.AUTHENTICITY,
            "no asset verification result was supplied; an unchecked asset is "
            "not an admitted one, and absence of a check is not a pass",
        )
    if not provider.signature_verified:
        return refuse(AdmissionGate.AUTHENTICITY, "the asset signature did not verify")

    if host is None:
        return refuse(
            AdmissionGate.COMPATIBILITY,
            "no host facts have been established, so no tested tuple can be "
            "matched against this node; admission needs what the node is, and "
            "inventing it would make the tuple match something nobody tested",
        )
    matched, reason = tested.admits(provider.component_digest, host, model_role=provider.role)
    if matched is None:
        return refuse(AdmissionGate.COMPATIBILITY, reason)

    for label, value in (
        ("declared_format", provider.declared_format),
        ("tokenizer_format", provider.tokenizer_format),
        ("runtime_version", provider.runtime_version),
        ("quantization", provider.quantization),
    ):
        if not str(value).strip():
            return refuse(
                AdmissionGate.CONTENT_POLICY,
                f"{label} is not declared; admission considers what a provider "
                "declares, and an undeclared field is not a permissive one",
            )
    if provider.context_size < 1 or provider.memory_need_mib < 1:
        return refuse(
            AdmissionGate.CONTENT_POLICY,
            "context size and memory need are declared as positive quantities",
        )
    if provider.content_policy_passed is None:
        return refuse(
            AdmissionGate.CONTENT_POLICY,
            "no content-policy result was supplied; nobody checked is not a pass",
        )
    if not provider.content_policy_passed:
        return refuse(AdmissionGate.CONTENT_POLICY, "the content policy rejected the asset")

    # The resource gate. With no measured reserve it refuses, which is the
    # answer on every node this build runs on.
    if resources is None:
        return refuse(
            AdmissionGate.RESOURCE_TOPOLOGY,
            "the Core reserve is unmeasured for Nexus, so whether "
            f"{provider.memory_need_mib} MiB fits in the {host.profile.value!r} "
            "envelope cannot be decided here. docs/capability-model.md §2: an "
            "implementation must not treat the selected profile as evidence that a "
            "capability fits. Choosing a reserve would be inventing a measurement; "
            "docs/hardware-gates.md HG-05 tracks taking it",
        )
    # A reserve is per memory class. `HG-05` is explicit that it does not
    # scale as one number, so one class's reserve is not another's -- and a
    # reserve carried across classes is an invented measurement again, this
    # time wearing a real one's clothes.
    if resources.reserve.profile is not host.profile:
        return refuse(
            AdmissionGate.RESOURCE_TOPOLOGY,
            f"the reserve was measured on the {resources.reserve.profile.value!r} "
            f"class and this node is {host.profile.value!r}; the Core reserve "
            "scales with retention and concurrency (IMPLEMENTATION_SPEC.md "
            "§2.1), so it is not one number across classes",
        )
    if not resources.reserve.fits(
        memory_need_mib=provider.memory_need_mib, envelope_mib=resources.envelope_mib
    ):
        return refuse(
            AdmissionGate.RESOURCE_TOPOLOGY,
            f"{provider.memory_need_mib} MiB does not fit the measured envelope "
            f"of {resources.envelope_mib} MiB after a Core reserve of "
            f"{resources.reserve.reserve_mib} MiB",
        )

    # Past the resource gate, and into the two that are named by the contract
    # and not implemented. This is reachable only with a measured reserve, so
    # no node this build runs on reaches it -- but it refuses by having no
    # implementation rather than by being unreachable, because an unreachable
    # gate that becomes reachable is a gate that silently starts passing.
    return refuse(
        AdmissionGate.APPROVAL,
        "operator or policy-authority approval is not implemented; the gate "
        "became reachable with a measured Core reserve and has no evidence to "
        "consider, and absence of a check is not a pass "
        "(docs/mio-runtime.md §3, Nexus#68)",
    )


@dataclass(frozen=True)
class CognitionReading:
    """The published state, with an independent reason per dimension.

    `docs/mio-runtime.md` §8: a single summary state without reasons is not
    sufficient, because it hides which dimension failed. So the reasons are
    separate fields and each is set from its own evidence.
    """

    state: CognitionState
    remote: RemoteState
    resource_reason: str
    topology_reason: str
    asset_reason: str
    trust_health_reason: str
    admissions: tuple[ProviderAdmission, ...] = ()

    def blocks_deterministic_path(self) -> bool:
        """Always False, in every state, and asserted as such by the tests."""

        return False

    @property
    def sources_local_cognition(self) -> bool:
        return self.state is not CognitionState.CORE_ONLY

    def as_event(self) -> dict:
        return {
            "event_type": "cognition.state",
            "state": self.state.value,
            "remote": self.remote.value,
            "resource_reason": self.resource_reason,
            "topology_reason": self.topology_reason,
            "asset_reason": self.asset_reason,
            "trust_health_reason": self.trust_health_reason,
            "providers": [admission.as_event() for admission in self.admissions],
        }


#: Why remote assistance is off, stated once so every caller says it the same
#: way. All three conditions are outstanding; none is a failure of this node.
REMOTE_DISABLED_REASON = (
    "remote assistance is disabled by default and has no egress path in this "
    "build; enabling it requires an enumerated privacy-class admission, a "
    "deterministic sanitizer, and explicit operator permission, and none of the "
    "three exists yet"
)


def read_cognition(
    providers: Sequence[LocalModelProvider],
    *,
    profile: ResourceProfile,
    tested: TestedTupleSet,
    host: Optional[HostFacts] = None,
    resources: Optional[ResourceEvidence] = None,
) -> CognitionReading:
    """What the cognition plane is right now.

    A fresh call with no admitted provider is `CORE ONLY`, which is also what
    a restart produces: this function holds no state between calls, so there
    is no way for a provider to be carried across one. `docs/mio-runtime.md`
    §7: restart of any cognition service resumes at `CORE ONLY` and re-admits
    before rising.

    **`profile` and `host` are separate arguments on purpose.** The resource
    reason needs only the measured envelope, which a node always has; matching
    a tested tuple needs the full `HostFacts`, which a node that has not been
    commissioned does not. Taking one argument would force a caller with the
    first and not the second to invent the rest -- and an invented `os_abi`
    makes a tuple match something nobody tested. So `host=None` is a fact
    ("nothing has established what this node is") and it refuses admission at
    the compatibility gate rather than being filled in.
    """

    admissions = tuple(
        admit_local_model(provider, host=host, tested=tested, resources=resources)
        for provider in providers
    )
    admitted = [outcome for outcome in admissions if outcome.admitted]

    if admitted:
        state = CognitionState.LOCAL
        asset_reason = (
            f"{len(admitted)} local provider(s) admitted: "
            + ", ".join(outcome.provider for outcome in admitted)
        )
    else:
        state = CognitionState.CORE_ONLY
        asset_reason = _no_provider_reason(admissions)

    return CognitionReading(
        state=state,
        remote=RemoteState.DISABLED,
        resource_reason=_resource_reason(profile, resources),
        topology_reason=(
            "no commissioned egress path is required, because no remote provider "
            "is enabled; topology neither permits nor blocks anything here"
        ),
        asset_reason=asset_reason,
        trust_health_reason=(
            "no provider is running, so there is no health window to report; an "
            "absent provider is not an unhealthy one"
        ),
        admissions=admissions,
    )


def _no_provider_reason(admissions: Sequence[ProviderAdmission]) -> str:
    if not admissions:
        return (
            "no local model provider is declared; deterministic explanations "
            "continue unchanged"
        )
    gates = sorted(
        {outcome.failed_gate.value for outcome in admissions if outcome.failed_gate}
    )
    return (
        f"{len(admissions)} declared provider(s), none admitted; first gate to "
        f"reject, per provider: {', '.join(gates)}"
    )


def _resource_reason(profile: ResourceProfile, resources: Optional[ResourceEvidence]) -> str:
    if resources is None:
        return (
            f"envelope {profile.value!r}; headroom undecidable because the Core "
            "reserve is unmeasured for Nexus (docs/hardware-gates.md HG-05). The "
            "envelope is a hardware class and never evidence that a capability fits"
        )
    return (
        f"envelope {profile.value!r}, measured at {resources.envelope_mib} MiB; "
        f"Core reserve {resources.reserve.reserve_mib} MiB from "
        f"{resources.reserve.sample_count} samples over "
        f"{resources.reserve.duration_seconds}s by "
        f"{resources.reserve.harness_version}. Headroom is decidable and the "
        "envelope is still a hardware class, never evidence that a capability fits"
    )
