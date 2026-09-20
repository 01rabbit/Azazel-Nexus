"""7 conditions x 5 failure modes, and the one thing none of them may do (#30).

SO-06's acceptance condition is inherited verbatim: *100% continuation means
zero divergence on the deterministic path, not nearly the same.* So the
central test here is a sweep over the whole matrix asserting a negative, and
everything else establishes that the sweep is meaningful.

**No test in this file waits.** A `HANGING` component is modelled with an
injected clock that a test advances past a budget; nothing sleeps, and
`test_no_test_here_can_hang` enforces that against the source. A suite that
proved its timeout handling by actually hanging would be a suite that gets
skipped in CI and then deleted.
"""

from __future__ import annotations

import ast
import itertools
import re
import time
from pathlib import Path

import pytest

from azazel_nexus.capability import (
    CORE_CAPABILITIES,
    CapabilityState,
    OptionalComponent,
)
from azazel_nexus.degradation import (
    CONDITIONS,
    DISPOSITIONS,
    MATRIX,
    DeadlineExceeded,
    DegradationReason,
    Disposition,
    FailureMode,
    Outcome,
    RETENTION_ORDER,
    UNDROPPABLE,
    assess,
    call_with_deadline,
    retain_under_pressure,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

#: A node with everything, so that every loss is visible as a loss.
EVERYTHING = frozenset(CORE_CAPABILITIES) | {
    "extended_knowledge",
    "knowledge_lite",
    "full_host_redirect",
    "deception_lite",
    "local_cognition",
    "remote_cognition",
}


# -- the sweep ----------------------------------------------------------


def test_the_matrix_covers_every_condition_against_every_mode():
    assert len(MATRIX) == len(CONDITIONS) * len(FailureMode) == 40


def test_the_matrix_covers_every_optional_component():
    """Every component `capability.py` sources a capability from has a row.

    This is the test that found the gap: issue #30 lists the *external* AZ-06
    node and not the embedded Deception Lite runtime, so `deception_lite`
    survived a run in which every declared condition failed at once. A matrix
    missing a component is a component whose failure nothing tests, and it
    reads as though that component were out of scope.
    """

    covered = {c.component for c in CONDITIONS if c.component is not None}
    assert covered == set(OptionalComponent), (
        f"no row covers {sorted(c.value for c in set(OptionalComponent) - covered)}"
    )


@pytest.mark.parametrize(
    "condition,mode",
    [(c.key, m) for c in CONDITIONS for m in FailureMode],
    ids=lambda v: v.value if isinstance(v, FailureMode) else v,
)
def test_no_condition_in_any_mode_subtracts_a_core_capability(condition, mode):
    """The whole point, asserted 35 times.

    `Outcome` refuses to be built with a core capability missing, so a
    regression fails at construction rather than at a comparison someone might
    later relax.
    """

    outcome = assess(EVERYTHING, {condition: mode})
    assert outcome.deterministic_path_intact
    assert CORE_CAPABILITIES <= set(outcome.retained)


#: Issue #30's third column, pinned literally.
#:
#: Added after a mutation survived: emptying a row's `also_continues` broke
#: nothing, because every other test read the promise out of the same field it
#: was meant to be checking. A declaration that only ever compares against
#: itself is a declaration, not a check -- so the issue's table is written out
#: here and a row that quietly stops promising something goes red.
PROMISED_BEYOND_CORE = {
    "local_model_absent": (),
    "remote_path_unreachable": ("local_cognition",),
    "knowledge_node_absent": (),
    "deception_node_absent": (),
    "knowledge_lite_absent": (),
    "knowledge_lite_expired": (),
    "deception_lite_absent": (),
    "audit_pressure": (),
}


def test_every_row_promises_what_the_issue_says_it_promises():
    declared = {c.key: c.also_continues for c in CONDITIONS}
    assert declared == PROMISED_BEYOND_CORE


def test_every_condition_keeps_what_its_row_promises():
    """The table's third column, not only its second.

    A degradation that quietly took a neighbouring capability with it would
    pass the core-capability sweep and still be wrong.
    """

    for condition in CONDITIONS:
        outcome = assess(EVERYTHING, {condition.key: FailureMode.ABSENT})
        kept = set(outcome.retained)
        promised = frozenset(CORE_CAPABILITIES) | frozenset(
            PROMISED_BEYOND_CORE[condition.key]
        )
        assert promised <= kept, (
            f"{condition.key} lost {sorted(promised - kept)}, "
            "which its row says continues"
        )
        assert condition.must_continue == promised


def test_no_core_capability_is_sourced_from_an_optional_component():
    """What makes `degrade`'s core-capability clause defensive rather than dead.

    A mutation deleting that clause survived, and correctly so: nothing in
    `_CAPABILITY_SOURCE` names a core capability, so subtracting one is
    already impossible. That is the invariant, and it was being relied on
    without ever being stated. If a core capability were ever given a source,
    this fails here rather than silently making an optional component
    load-bearing for the deterministic path.
    """

    from azazel_nexus.capability import _CAPABILITY_SOURCE

    overlap = sorted(set(_CAPABILITY_SOURCE) & CORE_CAPABILITIES)
    assert overlap == [], (
        f"{overlap} would be removed when their component is lost. A core "
        "capability sourced from an optional component is the failure the "
        "whole capability model exists to make impossible"
    )


def test_every_simultaneous_pair_still_keeps_the_deterministic_path():
    """One failure is the easy case. Two at once is where a subtraction hides."""

    keys = [c.key for c in CONDITIONS]
    for first, second in itertools.combinations(keys, 2):
        outcome = assess(
            EVERYTHING, {first: FailureMode.CORRUPT, second: FailureMode.HANGING}
        )
        assert outcome.deterministic_path_intact, f"{first} + {second}"


def test_losing_every_optional_component_at_once_is_still_core():
    outcome = assess(
        EVERYTHING, {c.key: FailureMode.ABSENT for c in CONDITIONS}
    )
    assert outcome.state is CapabilityState.CORE
    assert set(outcome.retained) == CORE_CAPABILITIES
    assert outcome.deterministic_path_intact


def test_an_outcome_missing_a_core_capability_cannot_be_constructed():
    with pytest.raises(AssertionError):
        Outcome(
            state=CapabilityState.CORE,
            retained=tuple(sorted(CORE_CAPABILITIES - {"audit"})),
            lost=("audit",),
            reasons=(),
        )


# -- absent is not corrupt ----------------------------------------------


def test_each_failure_mode_has_its_own_disposition():
    """Injective, and asserted as such.

    A mapping in which `ABSENT` and `CORRUPT` landed on one disposition would
    satisfy every other check in this file while destroying the distinction
    issue #30 names first.
    """

    assert len(set(DISPOSITIONS.values())) == len(FailureMode)
    assert set(DISPOSITIONS) == set(FailureMode)


def test_a_reason_cannot_claim_a_disposition_that_is_not_its_modes():
    with pytest.raises(ValueError):
        DegradationReason(
            condition="knowledge_lite_absent",
            mode=FailureMode.CORRUPT,
            disposition=Disposition.NOT_CONFIGURED,
            detail="the node has no cache",
        )


def test_absent_and_corrupt_produce_different_results(tmp_path):
    absent = assess(EVERYTHING, {"knowledge_lite_absent": FailureMode.ABSENT})
    corrupt = assess(EVERYTHING, {"knowledge_lite_absent": FailureMode.CORRUPT})

    assert absent.reasons[0].disposition is Disposition.NOT_CONFIGURED
    assert corrupt.reasons[0].disposition is Disposition.QUARANTINED
    assert absent.reasons[0].detail != corrupt.reasons[0].detail


def test_a_failure_the_matrix_does_not_declare_is_refused():
    with pytest.raises(ValueError):
        assess(EVERYTHING, {"something_nobody_modelled": FailureMode.ABSENT})


# -- reasons stay independent -------------------------------------------


def test_two_failures_produce_two_reasons():
    """A single "degraded" line is a node that knows more than it says.

    And the second failure is the one nobody investigates.
    """

    outcome = assess(
        EVERYTHING,
        {
            "remote_path_unreachable": FailureMode.HANGING,
            "knowledge_lite_expired": FailureMode.EXPIRED,
        },
    )
    assert len(outcome.reasons) == 2
    assert {r.condition for r in outcome.reasons} == {
        "remote_path_unreachable",
        "knowledge_lite_expired",
    }


def test_two_conditions_losing_one_component_still_report_separately():
    """Both Knowledge Lite rows subtract the same capability.

    They owe the operator different sentences: one says there is no cache, the
    other says there is one and it has lapsed. A table that merged them would
    make a node serving stale intelligence look like a node serving none.
    """

    outcome = assess(
        EVERYTHING,
        {
            "knowledge_lite_absent": FailureMode.ABSENT,
            "knowledge_lite_expired": FailureMode.EXPIRED,
        },
    )
    assert len(outcome.reasons) == 2
    assert outcome.stale_sources == ("knowledge_lite_expired",)


def test_the_reason_order_does_not_depend_on_how_the_failures_were_collected():
    forwards = assess(
        EVERYTHING,
        {"audit_pressure": FailureMode.REFUSING, "local_model_absent": FailureMode.ABSENT},
    )
    backwards = assess(
        EVERYTHING,
        {"local_model_absent": FailureMode.ABSENT, "audit_pressure": FailureMode.REFUSING},
    )
    assert [r.condition for r in forwards.reasons] == [
        r.condition for r in backwards.reasons
    ]


# -- expired is not absent ----------------------------------------------


def test_expired_is_reported_as_stale_and_absent_is_not():
    expired = assess(EVERYTHING, {"knowledge_lite_expired": FailureMode.EXPIRED})
    absent = assess(EVERYTHING, {"knowledge_lite_absent": FailureMode.ABSENT})

    assert expired.stale_sources == ("knowledge_lite_expired",)
    assert absent.stale_sources == ()
    assert expired.reasons[0].stale
    assert not absent.reasons[0].stale


def test_stale_is_named_per_source_rather_than_as_a_flag():
    """Which cache is stale, not merely that something is.

    An operator holding "stale: yes" and two caches has to go and find out
    which, and the node already knew.
    """

    outcome = assess(
        EVERYTHING,
        {
            "knowledge_lite_expired": FailureMode.EXPIRED,
            "knowledge_node_absent": FailureMode.EXPIRED,
        },
    )
    assert set(outcome.stale_sources) == {
        "knowledge_lite_expired",
        "knowledge_node_absent",
    }


# -- a hanging component, finitely ---------------------------------------


def test_a_component_that_overruns_its_budget_is_refused_without_waiting():
    """The whole `HANGING` model. Nothing sleeps.

    The clock is injected, so "it never answered" is expressed as a counter
    that moved past the budget. A test that reproduced hanging by hanging
    would be a test nobody can run in CI.
    """

    ticks = iter([0, 10_000])
    started = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        call_with_deadline(lambda: "advice", budget_ms=250, clock=lambda: next(ticks))
    assert time.monotonic() - started < 0.5, (
        "the deadline test spent real time; a hanging component must be "
        "modelled, not reproduced"
    )


def test_a_component_that_answers_inside_its_budget_is_used():
    ticks = iter([0, 100])
    assert (
        call_with_deadline(lambda: "advice", budget_ms=250, clock=lambda: next(ticks))
        == "advice"
    )


def test_a_budget_exactly_met_is_not_an_overrun():
    """Off-by-one on a deadline refuses answers that arrived in time."""

    ticks = iter([0, 250])
    assert (
        call_with_deadline(lambda: "advice", budget_ms=250, clock=lambda: next(ticks))
        == "advice"
    )


def test_a_budget_of_zero_is_refused_rather_than_silently_admitting_nothing():
    with pytest.raises(ValueError):
        call_with_deadline(lambda: "advice", budget_ms=0, clock=lambda: 0)


def test_no_test_here_can_hang():
    """Enforced against the source of this file and of the module.

    Parsed rather than searched as text. The first version of this guard was a
    regular expression, and it matched its own pattern literal -- a guard that
    failed on itself and on nothing else.
    """

    sleeps = []
    for relative in (
        "tests/unit/test_degradation_matrix.py",
        "src/azazel_nexus/degradation.py",
    ):
        tree = ast.parse((REPO_ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = node.func
            name = (
                target.attr
                if isinstance(target, ast.Attribute)
                else getattr(target, "id", "")
            )
            if name == "sleep":
                sleeps.append(f"{relative}:{node.lineno}")
    assert sleeps == [], (
        f"{sleeps} sleep. A hanging component is reproduced with a deadline "
        "and an injected clock, never by waiting"
    )


# -- audit pressure ------------------------------------------------------


def test_retention_pressure_releases_the_longest_retention_first():
    kept, released = retain_under_pressure(
        ["audit_chain", *RETENTION_ORDER], release=2
    )
    assert released == RETENTION_ORDER[:2]
    assert "audit_chain" in kept


def test_retention_pressure_never_releases_the_audit_chain():
    """The chain does not stop under pressure.

    A node that freed space by dropping links would have a ledger that reports
    itself intact while missing entries -- which is worse than no ledger,
    because it is believed.
    """

    with pytest.raises(AssertionError) as refusal:
        retain_under_pressure(["audit_chain", "capture_spool"], release=2)
    assert "audit_chain" in str(refusal.value)
    assert UNDROPPABLE == ("audit_chain",)


def test_audit_pressure_is_a_condition_whose_row_keeps_audit():
    condition = next(c for c in CONDITIONS if c.key == "audit_pressure")
    assert "audit" in condition.must_continue
    for mode in FailureMode:
        outcome = assess(EVERYTHING, {"audit_pressure": mode})
        assert "audit" in outcome.retained


def test_releasing_nothing_releases_nothing():
    kept, released = retain_under_pressure(["audit_chain", "capture_spool"], release=0)
    assert released == ()
    assert set(kept) == {"audit_chain", "capture_spool"}


# -- what continues is reported -----------------------------------------


def test_a_degraded_outcome_reports_what_continues():
    outcome = assess(EVERYTHING, {"remote_path_unreachable": FailureMode.HANGING})
    assert outcome.retained, "a degraded node must say what still works"
    assert "remote_cognition" in outcome.lost
    assert "local_cognition" in outcome.retained, (
        "the row says local advice continues when the remote path is unreachable"
    )


def test_degradation_is_a_capability_state_and_not_an_authority():
    """`FULL -> LITE -> CORE` are capability states.

    The deterministic arbiter holds the same authority in all three, and
    nothing in this module returns one to be changed.
    """

    from azazel_nexus import degradation

    assert not any(
        "authority" in name.lower() for name in dir(degradation) if not name.startswith("_")
    )
    outcome = assess(EVERYTHING, {"knowledge_lite_absent": FailureMode.ABSENT})
    assert isinstance(outcome.state, CapabilityState)


# -- the document and the table -----------------------------------------


def test_the_document_matches_the_table_it_describes():
    """The matrix document is generated from `MATRIX` and checked against it.

    A second statement of a table is a second thing to keep current, and prose
    has no way to notice when it stops matching the code. This is what makes
    `docs/degradation-matrix.md` a rendering rather than a claim.
    """

    text = (REPO_ROOT / "docs" / "degradation-matrix.md").read_text(encoding="utf-8")
    rows = re.findall(
        r"^\| `([a-z_]+)` \| `([a-z_]+)` \| `([a-z_]+)` \| (yes|\*\*NO\*\*) \|$",
        text,
        re.M,
    )
    assert len(rows) == len(MATRIX), (
        f"the document renders {len(rows)} cells and the table has {len(MATRIX)}"
    )
    documented = {(key, mode, disposition) for key, mode, disposition, _ in rows}
    actual = {
        (key, mode.value, disposition.value) for key, mode, disposition, _ in MATRIX
    }
    assert documented == actual

    assert all(intact == "yes" for *_, intact in rows), (
        "the document renders a cell where the deterministic path is not "
        "intact; SO-06 admits no such cell"
    )


def test_every_condition_appears_in_the_document():
    text = (REPO_ROOT / "docs" / "degradation-matrix.md").read_text(encoding="utf-8")
    for condition in CONDITIONS:
        assert f"`{condition.key}`" in text
