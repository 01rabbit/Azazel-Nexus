"""Tested compatibility tuples (#5, E2).

`docs/contract-ownership.md` §4.1. The tests that matter here are the ones
about *direction*: a feature requirement checked the wrong way round, or an
epoch comparison inverted, admits exactly what the check exists to exclude,
and both mistakes pass a test that only ever supplies matching values.
"""

from __future__ import annotations

import builtins

import pytest

from azazel_nexus import compatibility
from azazel_nexus import platform_profile as pp
from azazel_nexus.compatibility import (
    ADMITTED_ARCHITECTURE,
    CompatibilityRefused,
    HostFacts,
    TestedTuple,
    TestedTupleSet,
    fabric_release_version,
    fabric_shared_fields,
    tuple_purpose,
)
from azazel_nexus.resource_profile import ResourceProfile

COMPONENT = "sha256:" + "1" * 64
ADAPTER = "sha256:" + "2" * 64
RENDERER = "sha256:" + "3" * 64
TOOLCHAIN = "sha256:" + "4" * 64
OTHER_COMPONENT = "sha256:" + "5" * 64


def a_tuple(**overrides) -> TestedTuple:
    fields = {
        "component_digest": COMPONENT,
        "adapter_digest": ADAPTER,
        "renderer_digest": RENDERER,
        "toolchain_digest": TOOLCHAIN,
        "os_abi": "debian-13/linux-6.12",
        "architecture": ADMITTED_ARCHITECTURE,
        "fabric_version": "v0.9.0rc5",
        "profile": ResourceProfile.LITE,
        "overlay_schema": "3",
        "security_epoch": 4,
        "max_rollback_version": "0.9.0",
        "cpu_features": frozenset({"avx2"}),
        "fabric_features": frozenset({"mio_contracts"}),
        "schema_features": frozenset({"advisory_v2"}),
    }
    fields.update(overrides)
    return TestedTuple(**fields)


def a_host(**overrides) -> HostFacts:
    fields = {
        "os_abi": "debian-13/linux-6.12",
        "architecture": ADMITTED_ARCHITECTURE,
        "cpu_features": frozenset({"avx2", "aes"}),
        "fabric_version": "v0.9.0rc5",
        "fabric_features": frozenset({"mio_contracts", "extra"}),
        "schema_features": frozenset({"advisory_v2"}),
        "profile": ResourceProfile.LITE,
        "overlay_schema": "3",
        "security_epoch": 4,
    }
    fields.update(overrides)
    return HostFacts(**fields)


# -- the baseline ----------------------------------------------------------


def test_a_matching_host_is_admitted_and_the_tuple_is_named() -> None:
    """An admission that cannot say which tuple admitted it is unauditable."""

    matched, reason = TestedTupleSet.of([a_tuple()]).admits(COMPONENT, a_host())
    assert matched is not None
    assert matched.component_digest == COMPONENT
    assert "matches a tested tuple" in reason


def test_an_empty_set_admits_nothing_and_says_that_is_correct() -> None:
    matched, reason = TestedTupleSet().admits(COMPONENT, a_host())
    assert matched is None
    assert "correct answer and not an error" in reason


def test_an_unnamed_component_is_rejected() -> None:
    """A correctly signed artifact matching no tested tuple is rejected."""

    matched, reason = TestedTupleSet.of([a_tuple()]).admits(OTHER_COMPONENT, a_host())
    assert matched is None
    assert "matches no tested tuple is rejected" in reason


# -- direction: requirements are a subset of what the host offers ----------


@pytest.mark.parametrize(
    "field, required, offered",
    [
        ("cpu_features", frozenset({"avx2", "avx512"}), frozenset({"avx2"})),
        ("fabric_features", frozenset({"mio_contracts", "unreleased"}), frozenset({"mio_contracts"})),
        ("schema_features", frozenset({"advisory_v2", "advisory_v3"}), frozenset({"advisory_v2"})),
    ],
)
def test_a_host_missing_a_required_feature_is_rejected(
    field: str, required: frozenset, offered: frozenset
) -> None:
    matched, reason = TestedTupleSet.of([a_tuple(**{field: required})]).admits(
        COMPONENT, a_host(**{field: offered})
    )
    assert matched is None
    assert f"required {field}" in reason


@pytest.mark.parametrize("field", ["cpu_features", "fabric_features", "schema_features"])
def test_a_host_offering_more_than_the_tuple_requires_is_admitted(field: str) -> None:
    """The other direction, which must **not** reject.

    Written because a subset check with its arguments swapped passes every
    test that only ever supplies equal sets, and fails only here.
    """

    tested = a_tuple(**{field: frozenset({"one"})})
    host = a_host(**{field: frozenset({"one", "two", "three"})})
    matched, reason = TestedTupleSet.of([tested]).admits(COMPONENT, host)
    assert matched is not None, reason


@pytest.mark.parametrize("field", ["cpu_features", "fabric_features", "schema_features"])
def test_a_tuple_requiring_nothing_is_satisfied_by_any_host(field: str) -> None:
    tested = a_tuple(**{field: frozenset()})
    host = a_host(**{field: frozenset()})
    assert TestedTupleSet.of([tested]).admits(COMPONENT, host)[0] is not None


# -- direction: the security epoch is a floor ------------------------------


def test_a_host_below_the_minimum_security_epoch_is_rejected() -> None:
    matched, reason = TestedTupleSet.of([a_tuple(security_epoch=5)]).admits(
        COMPONENT, a_host(security_epoch=4)
    )
    assert matched is None
    assert "below the tuple's minimum" in reason


def test_a_host_above_the_minimum_security_epoch_is_admitted() -> None:
    """Inverting the comparison admits exactly what the epoch excludes."""

    matched, _ = TestedTupleSet.of([a_tuple(security_epoch=4)]).admits(
        COMPONENT, a_host(security_epoch=9)
    )
    assert matched is not None


def test_a_host_at_the_minimum_security_epoch_is_admitted() -> None:
    matched, _ = TestedTupleSet.of([a_tuple(security_epoch=4)]).admits(
        COMPONENT, a_host(security_epoch=4)
    )
    assert matched is not None


# -- the profile is matched exactly, not as a floor ------------------------


@pytest.mark.parametrize(
    "tested_profile, host_profile",
    [
        (ResourceProfile.CORE, ResourceProfile.LITE),
        (ResourceProfile.LITE, ResourceProfile.CORE),
        (ResourceProfile.LITE, ResourceProfile.STANDARD),
    ],
)
def test_an_envelope_the_tuple_was_not_tested_in_is_rejected(
    tested_profile: ResourceProfile, host_profile: ResourceProfile
) -> None:
    """Including the *larger* host, which a floor comparison would admit.

    A component tested only in `core` and run in `lite` is running somewhere
    nobody tested it. Two envelopes need two tuples.
    """

    matched, reason = TestedTupleSet.of([a_tuple(profile=tested_profile)]).admits(
        COMPONENT, a_host(profile=host_profile)
    )
    assert matched is None
    assert "nobody tested it" in reason


def test_two_tuples_cover_two_envelopes() -> None:
    catalogue = TestedTupleSet.of(
        [a_tuple(profile=ResourceProfile.CORE), a_tuple(profile=ResourceProfile.LITE)]
    )
    for profile in (ResourceProfile.CORE, ResourceProfile.LITE):
        matched, reason = catalogue.admits(COMPONENT, a_host(profile=profile))
        assert matched is not None, reason
        assert matched.profile is profile


def test_a_rejection_names_every_candidate_tuple_that_did_not_cover_the_host() -> None:
    catalogue = TestedTupleSet.of(
        [a_tuple(profile=ResourceProfile.CORE), a_tuple(security_epoch=99)]
    )
    matched, reason = catalogue.admits(COMPONENT, a_host())
    assert matched is None
    assert "2 tested tuple(s)" in reason
    assert "nobody tested it" in reason and "below the tuple's minimum" in reason


# -- exactness -------------------------------------------------------------


@pytest.mark.parametrize(
    "field, value",
    [
        ("os_abi", "debian-13/linux-6.13"),
        ("fabric_version", "v0.9.0rc3"),
        ("overlay_schema", "4"),
    ],
)
def test_a_near_miss_on_an_exact_field_is_rejected(field: str, value: str) -> None:
    matched, reason = TestedTupleSet.of([a_tuple()]).admits(
        COMPONENT, a_host(**{field: value})
    )
    assert matched is None
    assert field in reason


@pytest.mark.parametrize(
    "field, value",
    [
        ("fabric_version", ">=0.9.0"),
        ("fabric_version", "0.9.*"),
        ("fabric_version", "^0.9.0"),
        ("fabric_version", "0.9.0 - 1.0.0"),
        ("fabric_version", "0.9.0 || 1.0.0"),
        ("os_abi", "debian-13,debian-14"),
        ("overlay_schema", "~3"),
        ("max_rollback_version", "<1.0.0"),
    ],
)
def test_a_version_range_is_refused_when_the_tuple_is_built(field: str, value: str) -> None:
    """Not tolerated at match time -- refused at construction.

    A range is a claim about compatibility. Admission needs a statement about
    what was tested.
    """

    with pytest.raises(CompatibilityRefused) as caught:
        a_tuple(**{field: value})
    assert "must not authorize activation" in str(caught.value)


@pytest.mark.parametrize("field", ["os_abi", "fabric_version", "overlay_schema", "max_rollback_version"])
def test_an_empty_versioned_field_is_refused(field: str) -> None:
    with pytest.raises(CompatibilityRefused) as caught:
        a_tuple(**{field: "  "})
    assert "names one tested version" in str(caught.value)


@pytest.mark.parametrize(
    "field", ["component_digest", "adapter_digest", "renderer_digest", "toolchain_digest"]
)
@pytest.mark.parametrize("value", ["", "1" * 64, "sha256:" + "1" * 63, "sha512:" + "1" * 64, "sha256:" + "Z" * 64])
def test_a_field_that_is_not_an_immutable_digest_is_refused(field: str, value: str) -> None:
    with pytest.raises(CompatibilityRefused) as caught:
        a_tuple(**{field: value})
    assert "immutable digest" in str(caught.value)


@pytest.mark.parametrize("architecture", ["aarch64", "armv7l", "X86_64", ""])
def test_only_x86_64_is_admitted(architecture: str) -> None:
    with pytest.raises(CompatibilityRefused) as caught:
        a_tuple(architecture=architecture)
    assert ADMITTED_ARCHITECTURE in str(caught.value)


def test_a_negative_security_epoch_is_refused() -> None:
    with pytest.raises(CompatibilityRefused):
        a_tuple(security_epoch=-1)


def test_a_host_on_another_architecture_is_rejected_at_match_time_too() -> None:
    """The tuple cannot hold a non-x86_64 value, but a host can report one."""

    matched, reason = TestedTupleSet.of([a_tuple()]).admits(
        COMPONENT, a_host(architecture="aarch64")
    )
    assert matched is None
    assert "architecture" in reason


# -- the audit record ------------------------------------------------------


def test_the_record_is_sorted_so_it_replays_identically() -> None:
    record = a_tuple(cpu_features=frozenset({"sse4", "avx2", "aes"})).as_record()
    assert record["cpu_features"] == ["aes", "avx2", "sse4"]
    assert record["profile"] == "lite"


def test_the_record_carries_every_field_the_contract_names() -> None:
    """§4.1's table, so a field added there is not silently dropped here."""

    assert set(a_tuple().as_record()) == {
        "component_digest",
        "adapter_digest",
        "renderer_digest",
        "toolchain_digest",
        "os_abi",
        "architecture",
        "cpu_features",
        "fabric_version",
        "fabric_features",
        "schema_features",
        "profile",
        "overlay_schema",
        "security_epoch",
        "max_rollback_version",
    }


#: A trailing line ending, blank or NUL after a valid value. `$` matches before
#: a final `\n`, so a grammar closed with `$` and used with `match` admitted
#: the first of these (Azazel-Fabric#65). Each must be refused.
TRAILING = ("\n", "\r\n", " ", "\x00")


@pytest.mark.parametrize(
    "field", ["component_digest", "adapter_digest", "renderer_digest", "toolchain_digest"]
)
@pytest.mark.parametrize("suffix", TRAILING)
def test_a_digest_with_a_trailing_line_ending_is_refused(field: str, suffix: str) -> None:
    with pytest.raises(CompatibilityRefused) as caught:
        a_tuple(**{field: COMPONENT + suffix})
    assert "immutable digest" in str(caught.value)


# -- the admitted CPU and lab tuples (ADR-0006) ----------------------------

LAB = pp.PURPOSE_LAB_SOFTWARE_VERIFICATION


def a_lab_tuple(**overrides) -> TestedTuple:
    return a_tuple(**{"architecture": "aarch64", "purpose": LAB, **overrides})


def test_the_admitted_cpu_is_the_deployment_baseline_profiles():
    """Read from `REVIEWED_PROFILES`, not restated: the kernel spelling of the
    one deployment-baseline profile's CPU, which is still x86_64."""

    baseline = pp.deployment_baseline_profile()
    assert baseline.purpose == pp.PURPOSE_DEPLOYMENT_BASELINE
    assert ADMITTED_ARCHITECTURE == pp.kernel_name(baseline.architecture) == "x86_64"
    assert tuple_purpose(ADMITTED_ARCHITECTURE) == pp.PURPOSE_DEPLOYMENT_BASELINE


def test_a_tuple_defaults_to_the_baseline_and_its_record_is_unchanged():
    tested = a_tuple()
    assert tested.purpose == pp.PURPOSE_DEPLOYMENT_BASELINE
    assert "purpose" not in tested.as_record()


def test_an_aarch64_tuple_is_recorded_only_as_lab():
    tested = a_lab_tuple()
    assert tuple_purpose("aarch64") == LAB
    assert tested.as_record()["purpose"] == LAB
    assert tested.as_record()["architecture"] == "aarch64"


@pytest.mark.parametrize("architecture", ["x86_64", "arm64", "amd64", "armv7l", "AARCH64", ""])
def test_a_lab_tuple_must_name_the_lab_profiles_cpu(architecture):
    with pytest.raises(CompatibilityRefused):
        a_lab_tuple(architecture=architecture)


@pytest.mark.parametrize("purpose", ["", "production", "lab", None, 1, "Deployment-Baseline"])
def test_an_unknown_purpose_is_refused(purpose):
    with pytest.raises(CompatibilityRefused) as caught:
        a_tuple(purpose=purpose)
    assert "purpose" in str(caught.value)


@pytest.mark.parametrize("host_architecture", ["aarch64", ADMITTED_ARCHITECTURE])
def test_a_lab_tuple_admits_no_host_even_one_that_matches_every_field(host_architecture):
    lab = a_lab_tuple()
    host = a_host(architecture=host_architecture)
    matched, reason = TestedTupleSet.of([lab]).admits(COMPONENT, host)
    assert matched is None
    assert "lab-software-verification" in reason and "production admission" in reason
    assert lab.refusal_for(host) is not None
    for role in ("embedding", "generative"):
        assert TestedTupleSet.of([a_lab_tuple(model_role=role)]).admits(
            COMPONENT, host, model_role=role)[0] is None


def test_a_lab_tuple_beside_a_baseline_tuple_does_not_change_what_is_admitted():
    catalogue = TestedTupleSet.of([a_lab_tuple(), a_tuple()])
    assert catalogue.admits(COMPONENT, a_host())[0] == a_tuple()
    assert catalogue.admits(COMPONENT, a_host(architecture="aarch64"))[0] is None


# -- the Fabric vocabulary, without Fabric ---------------------------------


def test_fabric_shared_fields_speak_fabrics_vocabulary():
    shared = fabric_shared_fields(a_tuple(cpu_features=frozenset({"sse4", "avx2"})))
    assert shared["architecture"] == "amd64"
    assert shared["artifact_digest"] == COMPONENT
    assert shared["fabric_version"] == "0.9.0rc5"
    assert shared["cpu_features"] == ("avx2", "sse4")
    assert shared["overlay_schema_version"] == "3"
    assert set(shared) == {theirs for _, theirs in compatibility.FABRIC_SHARED_FIELDS}
    assert fabric_shared_fields(a_lab_tuple())["architecture"] == "arm64"


@pytest.mark.parametrize("tag, version", [("v0.9.0rc5", "0.9.0rc5"), ("v0.9.0", "0.9.0")])
def test_a_fabric_tag_maps_to_its_version(tag, version):
    assert fabric_release_version(tag) == version


@pytest.mark.parametrize("tag", ["0.9.0rc5", "vv0.9.0", "v", "", None, "V0.9.0"])
def test_a_fabric_version_that_is_not_a_tag_is_refused(tag):
    with pytest.raises(CompatibilityRefused):
        fabric_release_version(tag)


def test_without_fabric_the_adapter_is_unavailable_and_says_why(monkeypatch):
    """CORE: the boundary still imports and answers with Fabric gone."""

    from azazel_nexus import fabric_boundary

    real = builtins.__import__

    def no_fabric(name, *args, **kwargs):
        if name == "azazel_fabric" or name.startswith("azazel_fabric."):
            raise ImportError("simulated absence of the Fabric extra")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_fabric)
    projection = fabric_boundary.project_tested_tuple(
        a_tuple(), tuple_id="t", product_version="0")
    assert not projection.available and "not installed" in projection.reason
    result = fabric_boundary.check_tested_tuple(a_tuple(), {})
    assert not result.conforms and "not installed" in result.reason
    assert result.purpose is None
