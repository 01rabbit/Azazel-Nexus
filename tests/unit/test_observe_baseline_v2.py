"""The observe-baseline generation with the exposure section (#196 G6, wiring §5.2).

v1 is the generation without the Deception Lite exposure tier and refuses
the three exposure units; v2 is v1's document plus `exposure`, required
exactly when the policy scope names the three. The body (`units`,
`unit_files`) lists the observe scope only, so a changed exposure unit file
is the pass's stage P9's and never refuses the generation. The section's
shape is checked here; its content is compared by `exposure_generation`.
"""

from __future__ import annotations

import json

import pytest

from azazel_nexus.activation import DECEPTION_EXPOSURE_UNITS
from azazel_nexus.generation import Generation, GenerationRefused, tree_digest
from azazel_nexus.observe_baseline import (
    EXPOSURE_SECTION_APPARMOR_PROFILES,
    EXPOSURE_SECTION_KEYS,
    EXPOSURE_SECTION_WATCH_UNITS,
    OBSERVE_BASELINE_FILE,
    OBSERVE_BASELINE_SCHEMA,
    OBSERVE_BASELINE_SCHEMA_V2,
    build_observe_baseline,
    decode_observe_baseline,
    exposure_section_of,
    verify_observe_baseline,
)

EXPOSURE = tuple(sorted(DECEPTION_EXPOSURE_UNITS))
LOOP = ("azazel-edge-intaked.service", "azazel-mio-entryd.service")
FILES = {unit: f"[Unit]\nDescription={unit}\n".encode() for unit in LOOP}
D = "sha256:" + "d" * 64


def _section(**changes):
    section = {
        "apparmor_policy_hashes": {name: "a" * 64 for name in EXPOSURE_SECTION_APPARMOR_PROFILES},
        "apparmor_profiles": {name: D for name in EXPOSURE_SECTION_APPARMOR_PROFILES},
        "scope_digest": D,
        "unit_files": {unit: D for unit in EXPOSURE},
        "watch_unit_files": {unit: D for unit in EXPOSURE_SECTION_WATCH_UNITS},
    }
    section.update(changes)
    return section


def _generation(tree):
    return Generation(number=1, digest=tree_digest(tree), created_at="2026-10-20T00:00:00Z",
                      commissioning_digest=D, commissioning_evidence_binding="hmac-sha256:"
                      + "c" * 64)


def test_the_restated_names_are_the_runtimes():
    from azazel_nexus_runtime.activation_unit_files import WATCH_UNITS
    from azazel_nexus_runtime.decoy_apparmor import REQUIRED_ENFORCED_PROFILES
    from azazel_nexus_runtime.exposure_generation import EXPOSURE_SECTION_KEYS as RUNTIME_KEYS

    assert set(EXPOSURE_SECTION_WATCH_UNITS) == set(WATCH_UNITS)
    assert set(EXPOSURE_SECTION_APPARMOR_PROFILES) == set(REQUIRED_ENFORCED_PROFILES)
    assert EXPOSURE_SECTION_KEYS == RUNTIME_KEYS


def test_v1_refuses_the_exposure_units_in_its_body():
    for unit in EXPOSURE:
        with pytest.raises(GenerationRefused):
            build_observe_baseline(units=sorted(LOOP + (unit,)),
                                   unit_files={**FILES, unit: b"x"})
    tree = build_observe_baseline(units=list(LOOP), unit_files=FILES)
    assert decode_observe_baseline(tree[OBSERVE_BASELINE_FILE])["schema"] == (
        OBSERVE_BASELINE_SCHEMA)


def test_v2_requires_the_section_exactly_with_the_tier_and_its_body_never_names_it():
    units = sorted(LOOP + EXPOSURE)
    with pytest.raises(GenerationRefused):
        build_observe_baseline(units=units, unit_files=FILES)
    with pytest.raises(GenerationRefused):
        build_observe_baseline(units=list(LOOP), unit_files=FILES, exposure=_section())
    with pytest.raises(GenerationRefused):  # the body never measures them
        build_observe_baseline(units=units, unit_files={**FILES, EXPOSURE[0]: b"x"},
                               exposure=_section())
    for part in (EXPOSURE[:1], EXPOSURE[:2]):
        with pytest.raises(GenerationRefused):
            build_observe_baseline(units=sorted(LOOP + part), unit_files=FILES,
                                   exposure=_section())
    tree = build_observe_baseline(units=units, unit_files=FILES, exposure=_section())
    document = decode_observe_baseline(tree[OBSERVE_BASELINE_FILE])
    assert document["schema"] == OBSERVE_BASELINE_SCHEMA_V2
    assert document["units"] == list(LOOP) and set(document["unit_files"]) == set(LOOP)
    assert exposure_section_of(tree[OBSERVE_BASELINE_FILE]) == _section()


@pytest.mark.parametrize("changes", [
    {"scope_digest": "none"},
    {"unit_files": {unit: D for unit in EXPOSURE[:2]}},
    {"watch_unit_files": {unit: D for unit in EXPOSURE}},
    {"apparmor_profiles": {name: "d" * 64 for name in EXPOSURE_SECTION_APPARMOR_PROFILES}},
    {"apparmor_policy_hashes": {name: D for name in EXPOSURE_SECTION_APPARMOR_PROFILES}},
    {"apparmor_policy_hashes": {name: "A" * 64 for name in EXPOSURE_SECTION_APPARMOR_PROFILES}},
    {"extra": 1},
])
def test_a_section_out_of_its_closed_shape_is_refused(changes):
    with pytest.raises(GenerationRefused):
        build_observe_baseline(units=sorted(LOOP + EXPOSURE), unit_files=FILES,
                               exposure=_section(**changes))


def test_verify_takes_the_recorded_section_and_measures_the_observe_scope_only():
    units = sorted(LOOP + EXPOSURE)
    tree = build_observe_baseline(units=units, unit_files=FILES, exposure=_section())
    generation = _generation(tree)
    verified = verify_observe_baseline(generation=generation, files=tree, units=units,
                                       unit_files=FILES)
    assert verified.units == LOOP
    # The same tree under a policy without the tier, or v1 under one with it.
    with pytest.raises(GenerationRefused):
        verify_observe_baseline(generation=generation, files=tree, units=list(LOOP),
                                unit_files=FILES)
    v1 = build_observe_baseline(units=list(LOOP), unit_files=FILES)
    with pytest.raises(GenerationRefused):
        verify_observe_baseline(generation=_generation(v1), files=v1, units=units,
                                unit_files=FILES)
    # A section edited in the tree changes its digest: refused.
    raw = json.loads(tree[OBSERVE_BASELINE_FILE])
    raw["exposure"]["scope_digest"] = "sha256:" + "e" * 64
    edited = {OBSERVE_BASELINE_FILE: json.dumps(raw, sort_keys=True,
                                                separators=(",", ":")).encode()}
    with pytest.raises(GenerationRefused):
        verify_observe_baseline(generation=generation, files=edited, units=units,
                                unit_files=FILES)


def test_scoped_measurement_refuses_an_exposure_unit():
    from azazel_nexus_runtime.activation_unit_files import (
        UnitFilesRefused,
        measure_scoped_unit_files,
    )

    for unit in EXPOSURE:
        with pytest.raises(UnitFilesRefused, match="unit scope refused"):
            measure_scoped_unit_files([unit])
