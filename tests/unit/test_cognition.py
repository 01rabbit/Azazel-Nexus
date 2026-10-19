"""Local-first M.I.O. routing and provider admission (#5, E2).

Three things are under test, and the third is the one that is easy to get
wrong by being helpful.

*Gates run in order, and the first rejection is the answer.* A provider that
fails two gates must report the earlier one, because that is the one an
operator acts on.

*Absence of a check is not a pass.* Every gate's evidence is three-valued:
passed, failed, and nobody looked. The third rejects, with its own reason.

*The resource gate cannot pass here, and this build does not pretend it can.*
The Core reserve is unmeasured for Nexus. Choosing a number would be inventing
a measurement, so the gate refuses and the node stays at `CORE ONLY` for a
resource reason -- with the other three dimensions reporting independently,
which is exactly what `docs/mio-runtime.md` §8 requires.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from azazel_nexus import cognition
from azazel_nexus.cognition import (
    GATE_ORDER,
    AdmissionGate,
    CognitionState,
    LocalModelProvider,
    RemoteState,
    ResourceEvidence,
    admit_local_model,
    read_cognition,
)
from azazel_nexus.compatibility import (
    ADMITTED_ARCHITECTURE,
    HostFacts,
    TestedTuple,
    TestedTupleSet,
)
from azazel_nexus.core_reserve import CoreReserve
from azazel_nexus.resource_profile import ResourceProfile

COMPONENT = "sha256:" + "1" * 64
DIGEST = "sha256:" + "2" * 64


def a_host(**overrides) -> HostFacts:
    fields = {
        "os_abi": "debian-13/linux-6.12",
        "architecture": ADMITTED_ARCHITECTURE,
        "cpu_features": frozenset({"avx2"}),
        "fabric_version": "v0.9.0rc5",
        "fabric_features": frozenset(),
        "schema_features": frozenset(),
        "profile": ResourceProfile.LITE,
        "overlay_schema": "3",
        "security_epoch": 4,
    }
    fields.update(overrides)
    return HostFacts(**fields)


def a_catalogue(**overrides) -> TestedTupleSet:
    fields = {
        "component_digest": COMPONENT,
        "adapter_digest": DIGEST,
        "renderer_digest": DIGEST,
        "toolchain_digest": DIGEST,
        "os_abi": "debian-13/linux-6.12",
        "architecture": ADMITTED_ARCHITECTURE,
        "fabric_version": "v0.9.0rc5",
        "profile": ResourceProfile.LITE,
        "overlay_schema": "3",
        "security_epoch": 4,
        "max_rollback_version": "0.9.0",
        "model_role": "embedding",
    }
    fields.update(overrides)
    return TestedTupleSet.of([TestedTuple(**fields)])


def a_provider(**overrides) -> LocalModelProvider:
    fields = {
        "name": "local-model",
        "component_digest": COMPONENT,
        "declared_format": "gguf",
        "tokenizer_format": "sentencepiece",
        "runtime_version": "1.4.0",
        "quantization": "q4_k_m",
        "context_size": 2048,
        "memory_need_mib": 3000,
        "role": "embedding",
    }
    fields.update(overrides)
    from admission_helpers import evidence

    fields["evidence"] = evidence(component=fields["component_digest"], model_id=fields["name"],
                                  need=max(1, fields["memory_need_mib"]),
                                  version=fields["runtime_version"].strip() or "1.4.0",
                                  format=fields["declared_format"].strip() or "gguf")
    if "evidence" in overrides:
        fields["evidence"] = overrides["evidence"]
    return LocalModelProvider(**fields)


# -- gates run in order ----------------------------------------------------


def test_the_gate_order_is_the_contract_s_order() -> None:
    assert [gate.value for gate in GATE_ORDER] == [
        "authenticity",
        "tested compatibility tuple",
        "semantic content policy",
        "resource/topology admission",
        "operator or policy-authority approval",
        "staged activation",
    ]


def test_the_first_gate_to_reject_is_the_one_reported() -> None:
    """The provider fails authenticity *and* compatibility. Only the first counts."""

    outcome = admit_local_model(
        a_provider(evidence=None, component_digest="sha256:" + "9" * 64),
        host=a_host(),
        tested=a_catalogue(),
    )
    assert outcome.failed_gate is AdmissionGate.AUTHENTICITY
    assert GATE_ORDER.index(outcome.failed_gate) < GATE_ORDER.index(
        AdmissionGate.COMPATIBILITY
    )


def test_a_later_gate_is_reached_only_when_the_earlier_ones_pass() -> None:
    """Each gate, reached by satisfying everything before it."""

    cases = [
        (a_provider(evidence=None), AdmissionGate.AUTHENTICITY),
        (a_provider(component_digest="sha256:" + "9" * 64), AdmissionGate.COMPATIBILITY),
        (a_provider(declared_format=""), AdmissionGate.CONTENT_POLICY),
        (a_provider(), AdmissionGate.RESOURCE_TOPOLOGY),
    ]
    for provider, expected in cases:
        outcome = admit_local_model(provider, host=a_host(), tested=a_catalogue())
        assert outcome.failed_gate is expected, outcome.reason
        assert outcome.admitted is False


# -- absence of a check is not a pass --------------------------------------


@pytest.mark.parametrize("value", [None, False, True, object()])
def test_unminted_evidence_refuses(value):
    result = admit_local_model(a_provider(evidence=value), host=a_host(), tested=a_catalogue())
    assert result.failed_gate is AdmissionGate.AUTHENTICITY
    assert "not a pass" in result.reason


def test_admission_is_never_inferred_from_availability() -> None:
    """A fully declared provider with no evidence at all is still refused."""

    outcome = admit_local_model(
        LocalModelProvider(
            name="present-on-disk",
            component_digest=COMPONENT,
            declared_format="gguf",
            tokenizer_format="sentencepiece",
            runtime_version="1.4.0",
            quantization="q4_k_m",
            context_size=4096,
            memory_need_mib=6000,
        ),
        host=a_host(),
        tested=a_catalogue(),
    )
    assert outcome.admitted is False
    assert outcome.failed_gate is AdmissionGate.AUTHENTICITY


@pytest.mark.parametrize(
    "field", ["declared_format", "tokenizer_format", "runtime_version", "quantization"]
)
def test_an_undeclared_field_is_not_a_permissive_one(field: str) -> None:
    outcome = admit_local_model(
        a_provider(**{field: "  "}), host=a_host(), tested=a_catalogue()
    )
    assert outcome.failed_gate is AdmissionGate.CONTENT_POLICY
    assert field in outcome.reason


@pytest.mark.parametrize("field", ["context_size", "memory_need_mib"])
def test_a_non_positive_declared_quantity_is_refused(field: str) -> None:
    outcome = admit_local_model(
        a_provider(**{field: 0}), host=a_host(), tested=a_catalogue()
    )
    assert outcome.failed_gate is AdmissionGate.CONTENT_POLICY


# -- the gate that cannot pass ---------------------------------------------


def test_a_fully_evidenced_provider_is_still_refused_at_the_resource_gate() -> None:
    """The honest consequence of an unmeasured Core reserve."""

    outcome = admit_local_model(a_provider(), host=a_host(), tested=a_catalogue())
    assert outcome.admitted is False
    assert outcome.failed_gate is AdmissionGate.RESOURCE_TOPOLOGY
    assert "Core reserve is unmeasured" in outcome.reason
    assert "HG-05" in outcome.reason


@pytest.mark.parametrize(
    "profile", [ResourceProfile.CORE, ResourceProfile.LITE, ResourceProfile.STANDARD]
)
def test_no_envelope_makes_the_resource_gate_pass(profile: ResourceProfile) -> None:
    """Including `standard`. A bigger machine is not a measurement."""

    outcome = admit_local_model(
        a_provider(memory_need_mib=1),
        host=a_host(profile=profile),
        tested=a_catalogue(profile=profile),
    )
    assert outcome.failed_gate is AdmissionGate.RESOURCE_TOPOLOGY


def a_reserve(**overrides) -> CoreReserve:
    """A validated reserve, as `core_reserve.reserve_from` would return one.

    Constructed directly rather than parsed from a record, because what these
    tests drive is the **comparison** the gate makes, not the validation that
    produces a reserve -- `test_core_reserve.py` owns that. The numbers here
    are a test's numbers and are not a measurement of anything; no node in
    this build has one (`test_no_measurement_is_committed_anywhere`).
    """

    fields = {
        "profile": ResourceProfile.LITE,
        "reserve_mib": 2000,
        "host_digest": "sha256:" + "1" * 64,
        "harness_version": "core-reserve-probe/1",
        "sample_count": 60,
        "duration_seconds": 600,
    }
    fields.update(overrides)
    return CoreReserve(**fields)


def test_no_node_in_this_build_gets_past_the_resource_gate() -> None:
    """The reserve is unmeasured, so the gate refuses -- whatever is declared."""

    outcome = admit_local_model(
        a_provider(memory_need_mib=1),
        host=a_host(),
        tested=a_catalogue(),
    )
    assert outcome.failed_gate is AdmissionGate.RESOURCE_TOPOLOGY
    assert "unmeasured" in outcome.reason


def test_a_measured_reserve_reaches_approval_and_stops_there() -> None:
    """The gates past the resource gate refuse by having no implementation.

    This is the distinction the old version of this test could not make. It
    scanned `admit_local_model` for the gate names and asserted the last two
    were absent -- which was true, and which would have stayed true right up
    until the resource gate stopped refusing, at which point the two gates
    would have been skipped rather than reached. A gate that refuses only by
    being unreachable starts passing the day something upstream changes.

    So: supply a reserve a provider fits under, and exactly one more gate is
    reached. It refuses for having nothing to consider, and absence of a check
    is not a pass.
    """

    outcome = admit_local_model(
        a_provider(memory_need_mib=1000),
        host=a_host(profile=ResourceProfile.LITE),
        tested=a_catalogue(profile=ResourceProfile.LITE),
        resources=ResourceEvidence(reserve=a_reserve(reserve_mib=2000), envelope_mib=15000),
    )
    assert outcome.admitted is False
    assert outcome.failed_gate is AdmissionGate.APPROVAL
    assert "not implemented" in outcome.reason


@pytest.mark.parametrize("descriptors", [None, object()])
def test_staged_activation_requires_held_verified_descriptors(descriptors):
    from admission_helpers import H, evidence

    from azazel_nexus.model_admission import canonical, digest

    matched, _ = a_catalogue().admits(COMPONENT, a_host(), model_role="embedding")
    proof = evidence(component=COMPONENT, need=1000, descriptors=descriptors,
                     tuple_digest=digest(canonical(matched.as_record())))
    provider = a_provider(memory_need_mib=1000, evidence=proof)
    result = admit_local_model(provider, host=a_host(), tested=a_catalogue(), approval=proof,
                              resources=ResourceEvidence(a_reserve(host_digest=H), 15000,
                                                         proof.context.bindings["reserve"]["campaign_record_digest"]))
    assert result.failed_gate is AdmissionGate.STAGED_ACTIVATION


def test_a_reserve_from_another_memory_class_is_refused() -> None:
    """`HG-05`: the reserve is not one number across classes."""

    outcome = admit_local_model(
        a_provider(memory_need_mib=1),
        host=a_host(profile=ResourceProfile.LITE),
        tested=a_catalogue(profile=ResourceProfile.LITE),
        resources=ResourceEvidence(
            reserve=a_reserve(profile=ResourceProfile.STANDARD), envelope_mib=15000
        ),
    )
    assert outcome.failed_gate is AdmissionGate.RESOURCE_TOPOLOGY
    assert "standard" in outcome.reason and "lite" in outcome.reason


def test_a_provider_that_does_not_fit_after_the_reserve_is_refused_for_that() -> None:
    """The subtraction is the whole point: it is the envelope *after* the reserve."""

    resources = ResourceEvidence(reserve=a_reserve(reserve_mib=2000), envelope_mib=5000)
    # 3000 fits exactly; 3001 does not. The boundary is checked on both
    # sides so that an off-by-one in either direction fails here.
    fits = admit_local_model(
        a_provider(memory_need_mib=3000), host=a_host(), tested=a_catalogue(), resources=resources
    )
    assert fits.failed_gate is AdmissionGate.APPROVAL
    does_not = admit_local_model(
        a_provider(memory_need_mib=3001), host=a_host(), tested=a_catalogue(), resources=resources
    )
    assert does_not.failed_gate is AdmissionGate.RESOURCE_TOPOLOGY
    assert "3001" in does_not.reason and "2000" in does_not.reason


def test_an_envelope_with_no_reserve_cannot_be_supplied_at_all() -> None:
    """Both halves of the resource evidence or neither.

    An envelope without a reserve is the invented-threshold case `HG-05`
    exists to prevent, so there is no argument shape that expresses it.
    """

    with pytest.raises(TypeError):
        ResourceEvidence(envelope_mib=15000)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        ResourceEvidence(reserve=a_reserve(), envelope_mib=0)


# -- profile and host are separate facts -----------------------------------


def test_a_node_with_no_host_facts_still_reports_its_envelope() -> None:
    """The measured envelope is a fact a node always has.

    Commissioning is what establishes the rest. A reading that needed all of
    it would leave an uncommissioned node unable to say what it measured.
    """

    reading = read([], host=None)
    assert reading.state is CognitionState.CORE_ONLY
    assert "lite" in reading.resource_reason


def test_a_provider_declared_without_host_facts_is_refused_at_compatibility() -> None:
    """Not filled in. Inventing an os_abi matches a tuple nobody tested."""

    outcome = admit_local_model(a_provider(), host=None, tested=a_catalogue())
    assert outcome.failed_gate is AdmissionGate.COMPATIBILITY
    assert "no host facts have been established" in outcome.reason
    assert "inventing it" in outcome.reason


def test_the_missing_host_refusal_is_reached_only_after_authenticity() -> None:
    """Order is preserved: an unverified asset still fails first."""

    outcome = admit_local_model(
        a_provider(evidence=None), host=None, tested=a_catalogue()
    )
    assert outcome.failed_gate is AdmissionGate.AUTHENTICITY


def test_the_resource_reason_comes_from_the_profile_and_not_from_the_host() -> None:
    """The two are given different values, so only one can be the source.

    Without this, `_resource_reason(profile)` and `_resource_reason(
    host.profile)` are indistinguishable -- every other test supplies a host
    whose profile matches.
    """

    reading = read(
        [], profile=ResourceProfile.CORE, host=a_host(profile=ResourceProfile.STANDARD)
    )
    assert "core" in reading.resource_reason
    assert "standard" not in reading.resource_reason


def test_a_reading_without_host_facts_still_reports_every_dimension() -> None:
    reading = read([a_provider()], host=None)
    assert set(reading.as_event()) == {
        "event_type",
        "state",
        "remote",
        "resource_reason",
        "topology_reason",
        "asset_reason",
        "trust_health_reason",
        "providers",
    }
    assert "tested compatibility tuple" in reading.asset_reason


# -- the published state ---------------------------------------------------


def read(providers, **overrides):
    call = {"profile": ResourceProfile.LITE, "tested": a_catalogue(), "host": a_host()}
    call.update(overrides)
    return read_cognition(providers, **call)


def test_a_node_with_no_declared_provider_is_core_only() -> None:
    reading = read([])
    assert reading.state is CognitionState.CORE_ONLY
    assert "deterministic explanations continue unchanged" in reading.asset_reason
    assert reading.admissions == ()


def test_a_declared_but_unadmitted_provider_is_still_core_only() -> None:
    reading = read([a_provider()])
    assert reading.state is CognitionState.CORE_ONLY
    assert "none admitted" in reading.asset_reason
    assert "resource/topology admission" in reading.asset_reason


def test_remote_is_disabled_and_that_is_not_unavailable() -> None:
    """A decision and a failure are different facts with different words."""

    reading = read([])
    assert reading.remote is RemoteState.DISABLED
    assert reading.remote is not RemoteState.UNAVAILABLE
    assert RemoteState.DISABLED.value != RemoteState.UNAVAILABLE.value


def test_hybrid_is_unreachable_while_remote_is_disabled() -> None:
    reading = read([a_provider()])
    assert reading.state is not CognitionState.HYBRID


def test_the_four_reasons_are_independent_and_none_is_empty() -> None:
    """§8: a summary state without reasons hides which dimension failed."""

    reading = read([a_provider()])
    reasons = [
        reading.resource_reason,
        reading.topology_reason,
        reading.asset_reason,
        reading.trust_health_reason,
    ]
    assert all(reason.strip() for reason in reasons)
    assert len(set(reasons)) == 4, "two dimensions sharing a reason are one dimension"


def test_the_resource_reason_never_claims_the_envelope_is_evidence() -> None:
    for profile in ResourceProfile:
        reading = read([], profile=profile, host=a_host(profile=profile))
        assert profile.value in reading.resource_reason
        assert "never evidence that a capability fits" in reading.resource_reason


def test_an_absent_provider_is_not_an_unhealthy_one() -> None:
    reading = read([])
    assert "not an unhealthy one" in reading.trust_health_reason


def test_a_restart_resumes_at_core_only() -> None:
    """Held by the function holding no state, which is checked directly."""

    first = read([a_provider()])
    second = read([])
    assert first.state is CognitionState.CORE_ONLY
    assert second.state is CognitionState.CORE_ONLY

    tree = ast.parse(pathlib.Path(cognition.__file__).read_text(encoding="utf-8"))
    module_bindings = {
        target.id
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    mutable = {
        name
        for name in module_bindings
        if not name.startswith("__")
        and isinstance(getattr(cognition, name, None), (list, dict, set))
    }
    assert mutable == set(), f"module-level mutable state would survive a restart: {mutable}"


# -- nothing here can act --------------------------------------------------


def test_no_state_blocks_the_deterministic_path() -> None:
    for providers in ([], [a_provider()], [a_provider(evidence=None)]):
        reading = read(providers)
        assert reading.blocks_deterministic_path() is False


def test_the_module_contains_no_egress_path() -> None:
    """Remote is not "configured off". There is nothing here to configure.

    Scanned as imports rather than as text, so a mention in a docstring --
    and this module's docstring does mention sockets -- is not mistaken for a
    capability.
    """

    tree = ast.parse(pathlib.Path(cognition.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    forbidden = imported & {
        "socket",
        "ssl",
        "http",
        "urllib",
        "urllib2",
        "requests",
        "httpx",
        "asyncio",
        "subprocess",
    }
    assert forbidden == set(), f"the cognition plane reached for {forbidden}"


def test_the_module_defines_no_verb_that_could_execute() -> None:
    """Advisory means advisory. There is no run, exec, apply or enforce here."""

    tree = ast.parse(pathlib.Path(cognition.__file__).read_text(encoding="utf-8"))
    names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    acting = {
        name
        for name in names
        if name.lstrip("_").split("_")[0]
        in {"run", "exec", "execute", "apply", "enforce", "invoke", "launch", "send"}
    }
    assert acting == set(), f"the cognition plane defines {acting}"


def test_the_admission_event_names_the_gate_and_carries_no_asset_content() -> None:
    outcome = admit_local_model(a_provider(), host=a_host(), tested=a_catalogue())
    event = outcome.as_event()
    assert event["event_type"] == "cognition.provider.admission"
    assert event["failed_gate"] == "resource/topology admission"
    assert event["admitted"] is False
    assert "q4_k_m" not in repr(event), "an audit event records the decision, not the asset"


def test_the_state_event_carries_every_dimension() -> None:
    event = read([a_provider()]).as_event()
    assert set(event) == {
        "event_type",
        "state",
        "remote",
        "resource_reason",
        "topology_reason",
        "asset_reason",
        "trust_health_reason",
        "providers",
    }
    assert event["state"] == "CORE ONLY"
    assert event["remote"] == "disabled"
    assert len(event["providers"]) == 1
