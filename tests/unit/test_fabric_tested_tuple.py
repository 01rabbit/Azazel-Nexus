"""Nexus's tested tuple against Fabric's `TestedCompatibilityTuple` (ADR-0006).

Run against the pinned Fabric itself, so the comparison is with the released
model and its own golden fixture, not with a Nexus copy of either. Every test
here needs the extra; the `fabric-extra` CI job refuses a run where they skip.
The Fabric-absent behaviour is tested in `test_compatibility.py`, which runs
on CORE.
"""

from __future__ import annotations

import dataclasses
import typing

import pytest

from azazel_nexus import platform_profile as pp
from azazel_nexus.compatibility import (
    ADMITTED_ARCHITECTURE,
    FABRIC_ONLY_FIELDS,
    FABRIC_SHARED_FIELDS,
    NEXUS_ONLY_FIELDS,
    HostFacts,
    TestedTuple,
    TestedTupleSet,
)
from azazel_nexus.fabric_boundary import (
    FABRIC_PIN,
    check_tested_tuple,
    project_tested_tuple,
)
from azazel_nexus.resource_profile import ResourceProfile

fabric = pytest.importorskip(
    "azazel_fabric",
    reason="the Fabric extra is optional; CORE must work without it",
)
contracts = pytest.importorskip("azazel_fabric.provisioning_contracts")
models = pytest.importorskip("azazel_fabric.provisioning_contracts.models")
golden = pytest.importorskip("azazel_fabric.testing.provisioning")

COMPONENT = "sha256:" + "1" * 64
ADAPTER = "sha256:" + "4" * 64
RENDERER = "sha256:" + "3" * 64
TOOLCHAIN = "sha256:" + "5" * 64


def a_tuple(**overrides) -> TestedTuple:
    """A Nexus tuple describing what Fabric's golden `tt-golden-1` describes."""

    fields = {
        "component_digest": COMPONENT,
        "adapter_digest": ADAPTER,
        "renderer_digest": RENDERER,
        "toolchain_digest": TOOLCHAIN,
        "os_abi": "linux-gnu-x86_64",
        "architecture": ADMITTED_ARCHITECTURE,
        "fabric_version": "v0.9.0",
        "profile": ResourceProfile.LITE,
        "overlay_schema": "0.1",
        "security_epoch": 4,
        "max_rollback_version": "0.9.0",
        "cpu_features": frozenset({"sse4_2", "avx2"}),
        "fabric_features": frozenset({"mio_contracts"}),
        "schema_features": frozenset({"provisioning-contracts/v0.1", "mio-contracts/v0.1"}),
    }
    fields.update(overrides)
    return TestedTuple(**fields)


def a_lab_tuple(**overrides) -> TestedTuple:
    fields = {"architecture": "aarch64", "os_abi": "linux-gnu-aarch64",
              "cpu_features": frozenset({"asimd"}),
              "purpose": pp.PURPOSE_LAB_SOFTWARE_VERIFICATION}
    fields.update(overrides)
    return a_tuple(**fields)


def golden_tuple() -> dict:
    (only,) = golden.golden_compatibility_manifest()["tested_tuples"]
    return only


def projected(tested: TestedTuple, **claim) -> object:
    claim.setdefault("tuple_id", "tt-nexus-1")
    claim.setdefault("product_version", "0.1.0")
    projection = project_tested_tuple(tested, **claim)
    assert projection.available, projection.reason
    return projection.view


# -- the vocabulary -------------------------------------------------------


def test_every_fabric_architecture_names_one_reviewed_profile_and_only_amd64_is_the_baseline():
    """Fabric's `Architecture` literal, read from the pin: each value has a
    reviewed profile, and the purpose comes from that table, not the record."""

    values = typing.get_args(models.Architecture)
    purposes = {value: pp.purpose_for_architecture(pp.from_boundary("fabric", value))
                for value in values}
    assert purposes == {"amd64": pp.PURPOSE_DEPLOYMENT_BASELINE,
                        "arm64": pp.PURPOSE_LAB_SOFTWARE_VERIFICATION}
    assert pp.kernel_name(pp.from_boundary("fabric", "amd64")) == ADMITTED_ARCHITECTURE


def test_the_field_tables_cover_both_models_exactly():
    """A field Fabric adds at a new pin, or one Nexus adds, fails here rather
    than being silently dropped from the comparison."""

    fabric_fields = set(contracts.TestedCompatibilityTuple.model_fields)
    shared_fabric = {theirs for _, theirs in FABRIC_SHARED_FIELDS}
    assert fabric_fields == shared_fabric | set(FABRIC_ONLY_FIELDS)
    assert not shared_fabric & set(FABRIC_ONLY_FIELDS)

    nexus_fields = {f.name for f in dataclasses.fields(TestedTuple)}
    shared_nexus = {ours for ours, _ in FABRIC_SHARED_FIELDS}
    assert nexus_fields == shared_nexus | set(NEXUS_ONLY_FIELDS)
    assert not shared_nexus & set(NEXUS_ONLY_FIELDS)


# -- Fabric's own golden fixture -----------------------------------------


def test_fabrics_golden_tuple_conforms_to_the_nexus_tuple_that_describes_it():
    result = check_tested_tuple(a_tuple(), golden_tuple())
    assert result.conforms, result.reason
    assert result.reason == ""
    assert result.purpose == pp.PURPOSE_DEPLOYMENT_BASELINE
    assert result.fabric_version == FABRIC_PIN.lstrip("v")


def test_the_golden_tuple_as_a_fabric_model_conforms_too():
    claim = contracts.TestedCompatibilityTuple.model_validate(golden_tuple())
    assert check_tested_tuple(a_tuple(), claim).conforms


@pytest.mark.parametrize(
    "nexus_field, value",
    [
        ("component_digest", "sha256:" + "9" * 64),
        ("adapter_digest", "sha256:" + "9" * 64),
        ("fabric_version", "v0.10.0"),
        ("os_abi", "debian-13/linux-6.12"),
        ("cpu_features", frozenset({"sse4_2"})),
        ("cpu_features", frozenset({"sse4_2", "avx2", "aes"})),
        ("schema_features", frozenset({"provisioning-contracts/v0.1"})),
        ("overlay_schema", "0.2"),
    ],
)
def test_each_shared_field_that_differs_is_named(nexus_field, value):
    result = check_tested_tuple(a_tuple(**{nexus_field: value}), golden_tuple())
    assert not result.conforms
    assert result.reason.startswith(f"{nexus_field} differs")


def test_a_claim_for_arm64_does_not_conform_to_the_baseline_tuple_and_reads_as_lab():
    claim = {**golden_tuple(), "architecture": "arm64"}
    result = check_tested_tuple(a_tuple(), claim)
    assert not result.conforms
    assert result.reason.startswith("architecture differs")
    assert result.purpose == pp.PURPOSE_LAB_SOFTWARE_VERIFICATION


def test_a_claim_without_an_overlay_schema_does_not_conform():
    claim = {**golden_tuple(), "overlay_schema_version": None}
    result = check_tested_tuple(a_tuple(), claim)
    assert not result.conforms and result.reason.startswith("overlay_schema differs")


@pytest.mark.parametrize("name", ["cpu_features", "schema_features"])
def test_a_claim_that_repeats_a_feature_is_refused_not_folded(name):
    values = list(golden_tuple()[name])
    claim = {**golden_tuple(), name: values + values[:1]}
    result = check_tested_tuple(a_tuple(), claim)
    assert not result.conforms and "repeats an entry" in result.reason


def test_a_claim_about_another_product_does_not_conform():
    result = check_tested_tuple(a_tuple(), {**golden_tuple(), "product": "azazel-edge"})
    assert not result.conforms and "azazel-edge" in result.reason


@pytest.mark.parametrize(
    "claim",
    [
        {**golden_tuple(), "admitted": True},
        {**golden_tuple(), "architecture": "x86_64"},
        {**golden_tuple(), "architecture": "aarch64"},
        {**golden_tuple(), "artifact_digest": "sha256:" + "A" * 64},
        "not a mapping",
        None,
    ],
)
def test_fabric_refuses_what_it_does_not_define(claim):
    """Unknown fields, kernel spellings and malformed digests are Fabric's
    refusals; the adapter reports them and does not repair them."""

    result = check_tested_tuple(a_tuple(), claim)
    assert not result.conforms and result.reason
    assert result.purpose is None


def test_a_drifted_fabric_is_not_compared(monkeypatch):
    monkeypatch.setattr(fabric, "__version__", "0.9.0rc4")
    result = check_tested_tuple(a_tuple(), golden_tuple())
    assert not result.conforms and result.reason == "pinned Fabric is required"
    assert not project_tested_tuple(a_tuple(), tuple_id="t", product_version="0").available


# -- the projection -------------------------------------------------------


def test_the_projection_is_a_fabric_model_that_round_trips_and_conforms():
    view = projected(a_tuple(), evidence_ref="lab:run:1")
    assert type(view) is contracts.TestedCompatibilityTuple
    assert view.architecture == "amd64"
    assert view.fabric_version == "0.9.0"
    assert view.product == "azazel-nexus"
    dumped = view.model_dump(mode="json")
    assert check_tested_tuple(a_tuple(), dumped).conforms
    assert dumped["schema_version"] == "tested-compatibility-tuple/v0.1"


def test_the_projection_carries_no_nexus_only_field():
    dumped = projected(a_tuple(model_role="embedding")).model_dump(mode="json")
    for name in NEXUS_ONLY_FIELDS:
        assert name not in dumped
    assert dumped["deployment_profile"] is None
    assert dumped["cpu_features"] == ["avx2", "sse4_2"]


def test_the_projection_is_the_same_bytes_for_the_same_tuple():
    first = projected(a_tuple()).model_dump_json()
    assert projected(a_tuple(cpu_features=frozenset({"avx2", "sse4_2"}))).model_dump_json() == first


@pytest.mark.parametrize("tag", ["0.9.0", "vv0.9.0", "v"])
def test_a_fabric_version_that_is_not_a_tag_is_not_projected(tag):
    projection = project_tested_tuple(a_tuple(fabric_version=tag), tuple_id="t",
                                      product_version="0")
    assert not projection.available and "release tag" in projection.reason


def test_fabric_refusing_the_claim_identity_is_reported():
    projection = project_tested_tuple(a_tuple(), tuple_id="", product_version="0")
    assert not projection.available and projection.view is None


# -- Arm: describable, never admissible -----------------------------------


def lab_host(**overrides) -> HostFacts:
    fields = {"os_abi": "linux-gnu-aarch64", "architecture": "aarch64",
              "cpu_features": frozenset({"asimd"}), "fabric_version": "v0.9.0",
              "fabric_features": frozenset({"mio_contracts"}),
              "schema_features": frozenset({"provisioning-contracts/v0.1", "mio-contracts/v0.1"}),
              "profile": ResourceProfile.LITE, "overlay_schema": "0.1", "security_epoch": 4}
    fields.update(overrides)
    return HostFacts(**fields)


def test_an_arm64_lab_tuple_projects_and_conforms_and_is_still_refused_for_admission():
    """The whole path: Fabric's arm64 claim and the Nexus lab tuple agree,
    and the commissioned set still admits nothing on a host that matches
    every field."""

    lab = a_lab_tuple()
    view = projected(lab)
    assert view.architecture == "arm64"
    result = check_tested_tuple(lab, view.model_dump(mode="json"))
    assert result.conforms, result.reason
    assert result.purpose == pp.PURPOSE_LAB_SOFTWARE_VERIFICATION

    matched, reason = TestedTupleSet.of([lab]).admits(COMPONENT, lab_host())
    assert matched is None
    assert "lab-software-verification" in reason and "production admission" in reason
    assert lab.refusal_for(lab_host()) is not None


def test_a_conforming_arm64_claim_does_not_make_the_baseline_tuple_admit_an_arm_host():
    matched, reason = TestedTupleSet.of([a_tuple()]).admits(COMPONENT, lab_host())
    assert matched is None and "architecture" in reason


def test_an_unvalidated_fabric_instance_is_validated_again_and_refused():
    """`model_construct` skips Fabric's validators; the adapter does not."""

    fields = {k: v for k, v in golden_tuple().items() if k != "adapter_digest"}
    forged = contracts.TestedCompatibilityTuple.model_construct(**fields)
    result = check_tested_tuple(a_tuple(), forged)
    assert not result.conforms and result.reason == "Fabric refused the tested tuple claim"
    bad_digest = contracts.TestedCompatibilityTuple.model_construct(
        **{**golden_tuple(), "artifact_digest": "not-a-digest"})
    assert not check_tested_tuple(a_tuple(), bad_digest).conforms


def test_a_lab_projection_names_the_lab_profile_in_the_fabric_record():
    view = projected(a_lab_tuple())
    assert view.deployment_profile == pp.ARM64_LAB.profile_id
    assert view.deployment_profile.endswith("-lab")
    assert projected(a_lab_tuple(), deployment_profile=pp.ARM64_LAB.profile_id
                     ).deployment_profile == pp.ARM64_LAB.profile_id
    refused = project_tested_tuple(a_lab_tuple(), tuple_id="t", product_version="0",
                                   deployment_profile="nexus-embedded-lite")
    assert not refused.available and "-lab" in refused.reason
    assert projected(a_tuple()).deployment_profile is None
