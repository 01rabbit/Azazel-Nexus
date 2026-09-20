"""A hardware class, measured. Not a permission (#26, `IMPLEMENTATION_SPEC` §2.1).

Three things are pinned here, and the second is the one that produced this
file's most interesting test.

1. **The boundaries.** Four classes, three floors, checked on both sides.
2. **The input is not reduced again.** The floors already carry the
   firmware-reservation allowance; subtracting it a second time from the
   reading selects one tier low, and there are real inputs where it does.
3. **A profile enables nothing.** It is the answer to "how big is this
   machine", and the module is structurally incapable of answering anything
   else.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from azazel_nexus.resource_profile import (
    PROFILE_ORDER,
    ResourceProfile,
    ResourceReading,
    UsableMemoryUnavailable,
    read_usable_mib,
    reduce_for_non_memory_resources,
    select_profile,
    take_reading,
)

MODULE = (
    Path(__file__).resolve().parents[2] / "src" / "azazel_nexus" / "resource_profile.py"
)

#: The specification's table, as a table.
#:
#: Written out rather than derived from the module's own `_FLOORS`, because a
#: test that enumerates from the thing under test agrees with it by
#: construction and would pass on every boundary moved together.
BOUNDARIES = [
    (1, ResourceProfile.DIAGNOSTIC),
    (7167, ResourceProfile.DIAGNOSTIC),
    (7168, ResourceProfile.CORE),
    (15359, ResourceProfile.CORE),
    (15360, ResourceProfile.LITE),
    (31743, ResourceProfile.LITE),
    (31744, ResourceProfile.STANDARD),
    (131072, ResourceProfile.STANDARD),
]


@pytest.mark.parametrize("usable_mib,expected", BOUNDARIES)
def test_the_four_classes_are_selected_at_their_stated_boundaries(usable_mib, expected):
    assert select_profile(usable_mib) is expected


def test_every_floor_is_checked_from_both_sides():
    """A one-sided boundary test passes on an off-by-one in one direction.

    Derived from the table above so that adding a class without adding its
    pair of neighbours fails here rather than going unchecked.
    """

    selected = {mib: select_profile(mib) for mib, _ in BOUNDARIES}
    transitions = {
        (low, high)
        for low, high in zip(sorted(selected), sorted(selected)[1:])
        if selected[low] is not selected[high]
    }
    assert len(transitions) == len(ResourceProfile) - 1, (
        f"expected one transition per boundary, saw {sorted(transitions)}"
    )
    for low, high in transitions:
        assert high - low == 1, (
            f"the boundary between {selected[low].value} and "
            f"{selected[high].value} is not checked on both sides: "
            f"{low} and {high} are not adjacent"
        )


# ---------------------------------------------------------------------------
# The allowance is applied once
# ---------------------------------------------------------------------------

#: Readings where removing 1024 MiB a second time changes the answer.
#:
#: Each floor's own value, plus the host the specification actually measured.
#: A reading in the middle of a band absorbs a second subtraction silently, so
#: a test built on one would pass while the defect was present.
DOUBLE_SUBTRACTION_CHANGES_THE_ANSWER = [
    (7168, ResourceProfile.CORE, ResourceProfile.DIAGNOSTIC),
    (15360, ResourceProfile.LITE, ResourceProfile.CORE),
    (31744, ResourceProfile.STANDARD, ResourceProfile.LITE),
    (16095, ResourceProfile.LITE, ResourceProfile.CORE),
]


@pytest.mark.parametrize(
    "usable_mib,correct,if_subtracted_twice", DOUBLE_SUBTRACTION_CHANGES_THE_ANSWER
)
def test_the_firmware_allowance_is_not_applied_to_the_reading_as_well(
    usable_mib, correct, if_subtracted_twice
):
    """The floors carry the allowance. The input must not carry it too.

    `7168` is `8192 − 1024`; `15360` is `16384 − 1024`; `31744` is
    `32768 − 1024`. Subtracting 1024 from the reading as well applies the
    allowance twice and lands one tier low. The third argument is what the
    defect would produce, so this test states the wrong answer as well as the
    right one -- it fails loudly rather than merely stopping agreeing.
    """

    assert select_profile(usable_mib) is correct
    assert select_profile(usable_mib - 1024) is if_subtracted_twice
    assert correct is not if_subtracted_twice


def test_the_measured_host_in_the_specification_keeps_its_nominal_tier():
    """16,095 MiB on a nominal 16 GB host, and why 1024 is the allowance.

    `MemTotal: 16481980 kB` = 16,095 MiB, 289 MiB short of 16384. A floor set
    at the nominal 16384 would put that machine in `core`. The allowance
    exists to keep it in the tier its size deserves, and this is the reading
    that shows the allowance doing its job.
    """

    assert select_profile(16095) is ResourceProfile.LITE
    assert select_profile(16384 - 289) is ResourceProfile.LITE
    # What a nominal-sized floor would have done.
    assert 16095 < 16384


# ---------------------------------------------------------------------------
# A failed reading is a refusal
# ---------------------------------------------------------------------------


def test_an_unreadable_meminfo_refuses_rather_than_defaulting(tmp_path):
    with pytest.raises(UsableMemoryUnavailable):
        read_usable_mib(tmp_path / "does-not-exist")


def test_a_meminfo_without_memtotal_refuses(tmp_path):
    """Not "zero MiB", which would select `diagnostic` from a failed read."""

    meminfo = tmp_path / "meminfo"
    meminfo.write_text("MemFree:  1024 kB\n", encoding="utf-8")
    with pytest.raises(UsableMemoryUnavailable):
        read_usable_mib(meminfo)


@pytest.mark.parametrize("bad", [0, -1, None, "16384", 16384.0, True])
def test_a_reading_that_is_not_a_positive_integer_is_refused(bad):
    with pytest.raises(UsableMemoryUnavailable):
        select_profile(bad)


def test_memtotal_is_read_as_reported(tmp_path):
    meminfo = tmp_path / "meminfo"
    meminfo.write_text(
        "MemTotal:       16481980 kB\nMemFree:         8000000 kB\n", encoding="utf-8"
    )
    assert read_usable_mib(meminfo) == 16095
    assert take_reading(meminfo).profile is ResourceProfile.LITE


# ---------------------------------------------------------------------------
# The profile is not a capability
# ---------------------------------------------------------------------------


def test_the_selector_module_cannot_answer_a_capability_question():
    """Structural, not conventional (`IMPLEMENTATION_SPEC` §2.2).

    "The resource profile is not a capability" is a sentence in the
    specification. What keeps it true is that this module has no way to
    express one: it does not import the capability vocabulary, so no function
    here can return a capability set however it is later edited.
    """

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    } | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }

    offenders = sorted(name for name in imported if "capability" in name)
    assert offenders == [], (
        f"{offenders} is imported by the resource profile selector. A profile "
        "records measured capacity and enables nothing; a module that can "
        "name capabilities is a module that can be edited into granting one."
    )


def test_no_function_here_maps_a_profile_to_something_it_may_do():
    """The vocabulary a capability answer would have to use.

    Checked against the module's own text because the previous test only
    refuses an import. A hand-rolled set of strings needs no import at all,
    and that is the shape this catches.
    """

    text = MODULE.read_text(encoding="utf-8").lower()
    for word in ("enforce", "capture", "nic role", "egress", "permit"):
        assert f"def {word}" not in text and f"return {word}" not in text, (
            f"the selector appears to answer a {word!r} question; a resource "
            "profile is an upper bound on capacity and authorizes nothing"
        )


# ---------------------------------------------------------------------------
# Non-memory resources reduce, never raise
# ---------------------------------------------------------------------------


def test_a_non_memory_resource_may_lower_the_class():
    reading = ResourceReading(usable_mib=32768, profile=ResourceProfile.STANDARD)
    assert (
        reduce_for_non_memory_resources(reading, to=ResourceProfile.CORE)
        is ResourceProfile.CORE
    )


@pytest.mark.parametrize(
    "usable_mib,attempt",
    [
        (7168, ResourceProfile.LITE),
        (7168, ResourceProfile.STANDARD),
        (15360, ResourceProfile.STANDARD),
        (1024, ResourceProfile.CORE),
    ],
)
def test_a_non_memory_resource_can_never_raise_the_class(usable_mib, attempt):
    """Refused rather than clamped.

    A `min()` would make the attempt a silent no-op, and a caller that
    believed a fast CPU earned a wider envelope would never find out it did
    not. The error is the answer.
    """

    reading = ResourceReading(
        usable_mib=usable_mib, profile=select_profile(usable_mib)
    )
    with pytest.raises(ValueError, match="cannot raise"):
        reduce_for_non_memory_resources(reading, to=attempt)


def test_the_order_is_weakest_to_strongest_and_covers_every_class():
    assert set(PROFILE_ORDER) == set(ResourceProfile)
    assert PROFILE_ORDER[0] is ResourceProfile.DIAGNOSTIC
    assert PROFILE_ORDER[-1] is ResourceProfile.STANDARD


def test_a_reading_cannot_carry_a_class_its_measurement_does_not_select():
    """Otherwise the two fields drift and the record says both things."""

    with pytest.raises(ValueError, match="must agree"):
        ResourceReading(usable_mib=1024, profile=ResourceProfile.STANDARD)


def test_the_reading_records_non_memory_resources_without_folding_them_in():
    """Kept beside the class, so a reader can see which input caused what."""

    reading = ResourceReading(
        usable_mib=32768,
        profile=ResourceProfile.STANDARD,
        cpu_cores=2,
        storage_gib=16,
    )
    assert reading.profile is ResourceProfile.STANDARD
    assert (reading.cpu_cores, reading.storage_gib) == (2, 16)
