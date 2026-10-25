"""Tested compatibility tuples (#5, E2).

`docs/contract-ownership.md` §4.1. The tests that matter here are the ones
about *direction*: a feature requirement checked the wrong way round, or an
epoch comparison inverted, admits exactly what the check exists to exclude,
and both mistakes pass a test that only ever supplies matching values.
"""

from __future__ import annotations

import pytest

from azazel_nexus.compatibility import (
    ADMITTED_ARCHITECTURE,
    CompatibilityRefused,
    HostFacts,
    TestedTuple,
    TestedTupleSet,
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
