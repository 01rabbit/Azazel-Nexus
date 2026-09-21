"""The mutation harness, whose whole job is to be trustworthy (Nexus#81).

A "killed" count is a claim about evidence. Three times in one session this
repository produced one that was not: the working tree was stashed and
checked out while a run was copying it, and a mutation that only introduced
a `SyntaxError` was counted as killed when no test body had run.

The fix is structural, so what is tested here is the structure:

*`INVALID` is a third value.* Not a warning and not a survivor. One of them
fails the whole run, because a kill count containing an outcome that
established nothing is not evidence.

*The live working tree cannot reach a result.* Proven by running the harness
with the working tree deliberately broken.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from tools.mutate import (  # noqa: E402
    Mutation,
    MutationOutcome,
    MutationResult,
    MutationRun,
    RunRefused,
    classify,
    run_suite,
)

REPOSITORY = pathlib.Path(__file__).resolve().parents[2]
SHA = "1" * 40
OTHER_SHA = "2" * 40


def a_result(outcome: MutationOutcome, identifier: str = "m") -> MutationResult:
    return MutationResult(
        identifier=identifier,
        outcome=outcome,
        target_sha=SHA,
        observed_sha=SHA,
        suite="tests/unit",
        exit_status=1,
        detail="fixture",
    )


# -- the third value -------------------------------------------------------


def test_a_syntax_error_is_not_a_kill() -> None:
    """The failure mode that produced a false kill twice in one session.

    A mutation that does not compile has tested nothing, whatever pytest's
    exit status says.
    """

    for marker in ("SyntaxError", "IndentationError", "ERROR collecting"):
        outcome, detail = classify(
            exit_status=1,
            output=f"E   {marker}: something",
            target_sha=SHA,
            observed_sha=SHA,
        )
        assert outcome is MutationOutcome.INVALID
        assert "not a kill" in detail


def test_a_run_against_another_revision_is_invalid() -> None:
    """The failure mode stashing the tree produced."""

    outcome, detail = classify(
        exit_status=1, output="1 failed, 9 passed", target_sha=SHA, observed_sha=OTHER_SHA
    )
    assert outcome is MutationOutcome.INVALID
    assert OTHER_SHA in detail and SHA in detail


def test_a_suite_that_did_not_finish_is_invalid() -> None:
    outcome, _ = classify(
        exit_status=None, output="", target_sha=SHA, observed_sha=SHA
    )
    assert outcome is MutationOutcome.INVALID


def test_a_run_with_no_result_line_is_invalid() -> None:
    """Exiting non-zero is not the same as having tested something."""

    outcome, _ = classify(
        exit_status=1, output="bash: pytest: not found", target_sha=SHA, observed_sha=SHA
    )
    assert outcome is MutationOutcome.INVALID


def test_a_real_failure_is_a_kill_and_a_pass_is_a_survivor() -> None:
    """Otherwise every test above would pass by nothing ever being valid."""

    killed, _ = classify(
        exit_status=1, output="1 failed, 99 passed", target_sha=SHA, observed_sha=SHA
    )
    survived, _ = classify(
        exit_status=0, output="100 passed", target_sha=SHA, observed_sha=SHA
    )
    assert killed is MutationOutcome.KILLED
    assert survived is MutationOutcome.SURVIVED


def test_invalid_is_neither_of_the_other_two() -> None:
    assert len({o.value for o in MutationOutcome}) == 3
    assert MutationOutcome.INVALID not in (MutationOutcome.KILLED, MutationOutcome.SURVIVED)


# -- one invalid fails the whole run --------------------------------------


def test_a_run_containing_an_invalid_may_not_be_cited() -> None:
    """Not a warning. Part of the kill count would not be evidence."""

    run = MutationRun(
        target_sha=SHA,
        suite="tests/unit",
        results=(
            a_result(MutationOutcome.KILLED, "a"),
            a_result(MutationOutcome.KILLED, "b"),
            a_result(MutationOutcome.INVALID, "c"),
        ),
    )
    assert run.killed and run.invalid
    assert run.trustworthy is False


def test_a_run_of_only_valid_outcomes_may_be_cited() -> None:
    run = MutationRun(
        target_sha=SHA,
        suite="tests/unit",
        results=(a_result(MutationOutcome.KILLED, "a"), a_result(MutationOutcome.SURVIVED, "b")),
    )
    assert run.trustworthy is True


def test_an_empty_run_establishes_nothing() -> None:
    assert MutationRun(target_sha=SHA, suite="tests/unit").trustworthy is False


def test_the_report_carries_the_revision_every_result_is_against() -> None:
    """A result with no revision is a result nobody can reproduce."""

    run = MutationRun(
        target_sha=SHA, suite="tests/unit", results=(a_result(MutationOutcome.KILLED),)
    )
    document = run.as_document()
    assert document["target_sha"] == SHA
    assert document["suite"] == "tests/unit"
    assert document["results"][0]["target_sha"] == SHA
    assert document["results"][0]["observed_sha"] == SHA


# -- a run that could not establish anything is refused up front ----------


def test_a_mutation_that_changes_nothing_is_refused() -> None:
    """It would report a kill for an edit that never happened."""

    with pytest.raises(RunRefused) as caught:
        Mutation(identifier="m", path="p", old="same", new="same")
    assert "never happened" in str(caught.value)


def test_a_run_with_no_mutations_is_refused() -> None:
    with pytest.raises(RunRefused):
        run_suite([], repository=REPOSITORY)


def test_duplicate_identifiers_are_refused() -> None:
    """Two results under one name cannot both be read."""

    twice = [
        Mutation(identifier="same", path="p", old="a", new="b"),
        Mutation(identifier="same", path="p", old="c", new="d"),
    ]
    with pytest.raises(RunRefused) as caught:
        run_suite(twice, repository=REPOSITORY)
    assert "more than once" in str(caught.value)


# -- the working tree cannot reach a result -------------------------------


def test_the_live_working_tree_cannot_change_a_result(tmp_path) -> None:
    """The structural guarantee, exercised rather than asserted.

    The harness resolves `HEAD` once and runs every mutation in a git
    worktree detached at that revision. So a working tree that does not even
    parse must not affect the outcome -- which is exactly the situation a
    mid-run `git stash` created.

    A mutation whose text is absent at the target revision is used, because
    it is decided without running a suite and so keeps this test fast while
    still going through the worktree machinery.
    """

    import subprocess

    broken = REPOSITORY / "src" / "azazel_nexus" / "route_evidence.py"
    original = broken.read_text(encoding="utf-8")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=str(REPOSITORY), capture_output=True, text=True
    ).stdout.strip()
    try:
        broken.write_text(original + "\ndef not_python(:\n", encoding="utf-8")
        run = run_suite(
            [
                Mutation(
                    identifier="absent-at-target",
                    path="src/azazel_nexus/route_evidence.py",
                    old="def not_python(:",
                    new="pass",
                )
            ],
            repository=REPOSITORY,
            suite="tests/unit/test_mutate.py",
        )
    finally:
        broken.write_text(original, encoding="utf-8")

    # The text exists only in the *working tree*, never in the commit. If the
    # harness had read the working tree it would have applied the mutation;
    # reading the revision, it correctly reports that there was nothing to
    # mutate.
    assert run.target_sha == head
    assert run.results[0].outcome is MutationOutcome.INVALID
    assert "not present at this revision" in run.results[0].detail
    assert run.trustworthy is False
