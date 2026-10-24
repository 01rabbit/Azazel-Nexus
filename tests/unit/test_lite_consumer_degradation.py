"""Nexus#15: missing, corrupt, or expired knowledge never blocks Edge Core.

Each acceptance criterion in the issue gets its own group, driven against the
**real** artifacts Knowledge emits rather than against anything forged here.

Where a verdict is needed, it comes from Knowledge's own `negative.json` -- the
file in which Knowledge states what its verifier does with each artifact. Nexus
does not own the verifier and does not reimplement it; what Nexus owns, and
what is under test here, is everything that happens around the verdict.
"""

from __future__ import annotations

import tarfile

import pytest

from azazel_nexus.capability import (
    CORE_CAPABILITIES,
    CapabilityState,
    OptionalComponent,
    degrade,
    state_for,
)
from azazel_nexus.lite_cache import (
    DEGRADED_CAPABILITY,
    Admission,
    Freshness,
    StagedReader,
    Verdict,
    classify_freshness,
    refuse_everything,
)

AS_OF = "2026-09-19T00:00:00Z"
FULL_SET = frozenset(
    CORE_CAPABILITIES
    | {
        "extended_knowledge",
        "knowledge_lite",
        "full_host_redirect",
        "deception_lite",
        "local_cognition",
        "remote_cognition",
    }
)


def verifier_from_index(case: dict):
    """Build a verifier that answers exactly what Knowledge says it answers."""

    def _verify(artifact):
        if case["verifies"]:
            return Verdict(admitted=True, reason=f"{case['name']} verifies")
        return Verdict(
            admitted=False,
            reason=case["description"],
            error_code=case["expected_error_code"],
        )

    return _verify


def real_extract(artifact, staging):
    """Extract for real, so a truncated archive really does raise here."""

    staging.mkdir(parents=True, exist_ok=True)
    with tarfile.open(artifact, "r:gz") as archive:
        for member in archive:
            if not member.isreg():
                continue
            data = archive.extractfile(member)
            if data is None:
                continue
            target = staging / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data.read())


# -- criterion 1: absent artifact, Core starts and functions ----------------


def test_an_absent_artifact_is_not_an_error(cache_root, fixture_root, negative_cases):
    reader = StagedReader(root=cache_root, verifier=refuse_everything)
    decision = reader.admit(fixture_root / negative_cases["absent"]["path"])

    assert decision.admission is Admission.ABSENT
    assert decision.capability == DEGRADED_CAPABILITY
    assert decision.blocks_core() is False
    assert decision.staging_written is False
    assert decision.promoted is False


def test_core_capabilities_survive_losing_knowledge_lite_entirely():
    remaining = degrade(FULL_SET, OptionalComponent.KNOWLEDGE_LITE)

    assert CORE_CAPABILITIES <= remaining
    assert "knowledge_lite" not in remaining
    assert state_for(remaining) is CapabilityState.LITE  # Deception Lite remains


def test_core_survives_losing_every_optional_component_at_once():
    """The doctrine sentence, as a test: Nexus is useful as CORE with nothing
    external at all."""
    remaining = degrade(FULL_SET, frozenset(OptionalComponent))

    assert remaining == CORE_CAPABILITIES
    assert state_for(remaining) is CapabilityState.CORE


# -- criterion 2: corrupt artifact, Core functions, degradation is visible --


@pytest.mark.parametrize("name", ["corrupt-signature", "corrupt-payload"])
def test_a_corrupt_artifact_is_refused_and_core_continues(
    name, cache_root, fixture_root, negative_cases
):
    case = negative_cases[name]
    reader = StagedReader(root=cache_root, verifier=verifier_from_index(case))
    decision = reader.admit(fixture_root / case["path"], extract=real_extract)

    assert decision.admission is Admission.REFUSED
    assert decision.capability == DEGRADED_CAPABILITY
    assert decision.blocks_core() is False
    assert decision.promoted is False
    assert decision.degradation_visible is True
    # The operator plane and the audit record get Knowledge's own code.
    assert decision.error_code == case["expected_error_code"]


def test_a_truncated_archive_is_a_refusal_even_though_no_code_is_produced(
    cache_root, fixture_root, negative_cases
):
    """Knowledge's index warns about exactly this.

    "a reader that catches only the verifier's own exception type is one
    decoder change away from letting a truncated artifact through as an
    unhandled error, so treat ANY exception from verification as a refusal."
    Knowledge's verifier wraps this one as BUNDLE_ARCHIVE_UNREADABLE, but here
    the tar decoder raises during extraction, before the verifier is reached,
    so no verifier code exists and nothing here can be keyed on an error code.
    """

    case = negative_cases["corrupt-truncated"]

    def _should_not_be_reached(artifact):
        raise AssertionError(
            "verification was reached; the archive should have failed to extract first"
        )

    reader = StagedReader(root=cache_root, verifier=_should_not_be_reached)
    decision = reader.admit(fixture_root / case["path"], extract=real_extract)

    assert decision.admission is Admission.UNVERIFIABLE
    assert decision.capability == DEGRADED_CAPABILITY
    assert decision.error_code is None
    assert decision.promoted is False
    assert decision.blocks_core() is False

    # Distinguish the two ways this test could pass. Without these it would
    # also pass if extraction had succeeded and the sentinel verifier had
    # raised -- which is a different code path and proves nothing about the
    # archive. The reason must name extraction, and bytes must have reached
    # staging before the decoder gave up, which is what Knowledge describes:
    # "a reader can be holding fully verified content and must still promote
    # none of it".
    assert "extraction failed" in decision.reason
    assert decision.staging_written is True
    assert case["staging_written"] is True


def test_a_verifier_that_raises_is_a_refusal_not_a_crash(cache_root, fixture_root):
    def _explodes(artifact):
        raise RuntimeError("verifier is from a newer Knowledge and tightened")

    reader = StagedReader(root=cache_root, verifier=_explodes)
    decision = reader.admit(fixture_root / "lite.tar.gz")

    assert decision.admission is Admission.UNVERIFIABLE
    assert decision.promoted is False
    assert decision.blocks_core() is False


# -- criterion 3: expired artifact, Core functions, freshness is not lost ---


def test_the_expired_fixture_verifies_and_is_admitted(
    cache_root, fixture_root, negative_cases
):
    """Expiry is not a verification failure. It is a serving decision."""
    case = negative_cases["expired"]
    assert case["verifies"] is True

    reader = StagedReader(root=cache_root, verifier=verifier_from_index(case))
    decision = reader.admit(fixture_root / case["path"], extract=real_extract)

    assert decision.admission is Admission.ADMITTED
    assert decision.promoted is True


def test_an_expired_claim_is_unavailable_not_merely_labelled(
    cache_root, fixture_root, negative_cases
):
    case = negative_cases["expired"]
    reader = StagedReader(root=cache_root)
    claims = [
        {"id": "expired-indicator", "expiry": case["indicator_expiry"]},
        {"id": "live-indicator", "expiry": case["valid_indicator_expiry"]},
        {"id": "static-reference", "expiry": None},
    ]

    served, withheld = reader.serve(claims, as_of=AS_OF)

    assert [claim["id"] for claim in withheld] == ["expired-indicator"]
    assert withheld[0]["freshness"] == Freshness.EXPIRED.value
    # The artifact is not discarded wholesale: what is still good is still served.
    assert {claim["id"] for claim in served} == {"live-indicator", "static-reference"}


def test_the_freshness_label_survives_on_everything_served(cache_root):
    reader = StagedReader(root=cache_root)
    served, _ = reader.serve([{"id": "a", "expiry": None}], as_of=AS_OF)

    assert served[0]["freshness"] == Freshness.NOT_CLOCK_BOUND.value


def test_an_unparseable_expiry_is_withheld_rather_than_assumed_current():
    assert classify_freshness("not-a-date", as_of=AS_OF) is Freshness.UNKNOWN
    assert classify_freshness("2026-09-19T00:00:00", as_of=AS_OF) is Freshness.UNKNOWN


# -- criterion 4: a failed artifact never reaches the read-only cache -------


@pytest.mark.parametrize("name", ["corrupt-signature", "corrupt-payload", "corrupt-truncated"])
def test_no_refused_artifact_leaves_anything_in_the_live_cache(
    name, cache_root, fixture_root, negative_cases
):
    case = negative_cases[name]
    verifier = (
        verifier_from_index(case)
        if name != "corrupt-truncated"
        else (lambda artifact: Verdict(False, "unreached"))
    )
    reader = StagedReader(root=cache_root, verifier=verifier)
    reader.admit(fixture_root / case["path"], extract=real_extract)

    assert not reader.live.exists(), f"{name} left content in the live cache"
    assert not any(reader.staging.rglob("*")), f"{name} left content in staging"


def test_staging_written_is_reported_as_knowledge_says_it_happens(
    cache_root, fixture_root, negative_cases
):
    """Knowledge states, per fixture, whether bytes reach staging before the
    failure. An audit record that said "nothing was written" when something was
    would be wrong, so the reader reports the fact rather than assuming it."""
    case = negative_cases["corrupt-payload"]
    assert case["staging_written"] is True

    reader = StagedReader(root=cache_root, verifier=verifier_from_index(case))
    decision = reader.admit(fixture_root / case["path"], extract=real_extract)

    assert decision.staging_written is True
    assert decision.promoted is False


def test_the_default_verifier_admits_nothing(cache_root, fixture_root):
    """A caller that forgets to inject a verifier gets CORE, not unverified data."""
    reader = StagedReader(root=cache_root)
    decision = reader.admit(fixture_root / "lite.tar.gz", extract=real_extract)

    assert decision.admission is Admission.REFUSED
    assert decision.promoted is False
    assert not reader.live.exists()


# -- criterion 5: capability degrades; authority never moves ----------------


@pytest.mark.parametrize(
    "name", ["absent", "corrupt-signature", "corrupt-payload", "corrupt-truncated"]
)
def test_every_failure_lands_on_core_and_moves_no_authority(
    name, cache_root, fixture_root, negative_cases
):
    case = negative_cases[name]
    verifier = (
        refuse_everything if case["sha256"] is None else verifier_from_index(case)
    )
    reader = StagedReader(root=cache_root, verifier=verifier)
    decision = reader.admit(fixture_root / case["path"], extract=real_extract)

    assert decision.capability == DEGRADED_CAPABILITY == "CORE"
    assert decision.blocks_core() is False
    assert decision.promoted is False


def test_no_capability_function_can_return_an_authority():
    """There is no authority in the capability module to return.

    Stated as a test because the invariant is an absence, and an absence is
    what a later change quietly fills in.
    """

    import azazel_nexus.capability as module

    offenders = [
        name
        for name in dir(module)
        if not name.startswith("_")
        and any(word in name.lower() for word in ("authority", "authorize", "enforce", "approve"))
    ]
    assert offenders == [], f"an authority concept appeared in the capability module: {offenders}"


def test_losing_a_component_never_adds_a_capability():
    for component in OptionalComponent:
        remaining = degrade(FULL_SET, component)
        assert remaining <= FULL_SET, f"losing {component} added a capability"


def test_a_missing_core_capability_is_not_a_degradation():
    """Core is never sourced from an optional component, so its absence is a
    broken node rather than a lower state -- and must not be reported as one."""
    with pytest.raises(ValueError, match="broken node"):
        state_for(frozenset({"knowledge_lite"}))


# -- criterion 6: the swap exposes no partial state -------------------------


def test_a_swap_replaces_the_live_cache_atomically(cache_root, fixture_root, negative_cases):
    good = lambda artifact: Verdict(True, "ok")  # noqa: E731
    reader = StagedReader(root=cache_root, verifier=good)

    reader.admit(fixture_root / "lite.tar.gz", extract=real_extract)
    first = sorted(p.name for p in reader.live.rglob("*") if p.is_file())
    assert first, "the first admission produced an empty live cache"

    reader.admit(fixture_root / negative_cases["expired"]["path"], extract=real_extract)
    second = sorted(p.name for p in reader.live.rglob("*") if p.is_file())
    assert second, "the swap produced an empty live cache"
    assert not (cache_root / "retired").exists()


def test_a_failed_admission_leaves_the_previous_live_cache_intact(
    cache_root, fixture_root, negative_cases
):
    """The case that matters most: a bad update must not cost the good cache
    that was already there."""
    reader = StagedReader(root=cache_root, verifier=lambda a: Verdict(True, "ok"))
    reader.admit(fixture_root / "lite.tar.gz", extract=real_extract)
    before = {
        str(p.relative_to(reader.live)): p.read_bytes()
        for p in reader.live.rglob("*")
        if p.is_file()
    }
    assert before

    case = negative_cases["corrupt-payload"]
    reader.verifier = verifier_from_index(case)
    decision = reader.admit(fixture_root / case["path"], extract=real_extract)

    assert decision.admission is Admission.REFUSED
    after = {
        str(p.relative_to(reader.live)): p.read_bytes()
        for p in reader.live.rglob("*")
        if p.is_file()
    }
    assert after == before, "a refused artifact disturbed the previously live cache"
