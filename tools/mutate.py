"""Run a mutation suite so that its result can be trusted (Nexus#81).

A mutation is killed when the test suite fails because of it. That claim is
only worth anything if the suite really ran, really ran against the intended
code, and really failed for the mutation rather than for something the
mutation broke on its way in.

**Three times in one session a run produced a number that was not that.** The
working tree was `git stash`-ed and `git checkout`-ed while a run was
copying it, so later mutations landed on different code than the recorded
target; and a mutation that introduced a `SyntaxError` was counted as killed
when nothing had been tested at all. Both produced plausible output.

So the trust boundary is moved out of the operator's attention and into this
tool. It is not a convenience wrapper.

## What makes a run trustworthy

| guarantee | how |
| --- | --- |
| the target is recorded | `git rev-parse HEAD` once, before anything else, into `MutationRun.target_sha` |
| each mutation runs against that target | every mutation gets its own `git worktree` **detached at the target SHA** -- not a copy of the live tree |
| it still ran against it at the end | the worktree's `HEAD` is re-read after the suite and compared |
| the live tree cannot corrupt a run | nothing reads the working tree after the SHA is resolved. `stash`, `checkout` and branch moves in the main tree are now irrelevant by construction, not by care |
| a syntax error is not a kill | a run whose failure is only a collection error is `INVALID` |
| an unfinished run is not a kill | a mutation that did not produce a parseable suite result is `INVALID` |
| one invalid fails everything | `MutationRun.trustworthy` is `False` if any outcome is `INVALID`, whatever the kill count |

**`INVALID` is not `SURVIVED` and not `KILLED`.** It means the run says
nothing, and a suite that says nothing must not be reported as evidence --
the same three-valued discipline `edge_package.Evidence` holds to for checks.

## What it does not do

It does not choose mutations. A mutation that nobody thought of is not
caught by running the ones that were, and this tool makes no claim about
coverage -- only about whether the outcomes it reports happened.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional, Sequence

__all__ = [
    "Mutation",
    "MutationOutcome",
    "MutationResult",
    "MutationRun",
    "RunRefused",
    "classify",
    "run_suite",
]


class RunRefused(Exception):
    """The run cannot be trusted and is refused rather than reported."""


class MutationOutcome(str, Enum):
    """Three values. `INVALID` is neither of the other two."""

    #: The suite failed because of the mutation. Evidence.
    KILLED = "killed"
    #: The suite passed with the mutation applied. A gap in the tests.
    SURVIVED = "survived"
    #: The run says nothing: wrong revision, no result, or a syntax error.
    INVALID = "invalid"


@dataclass(frozen=True)
class Mutation:
    """One edit to try. `identifier` is what a result is reported against."""

    identifier: str
    path: str
    old: str
    new: str

    def __post_init__(self) -> None:
        for name in ("identifier", "path", "old"):
            if not str(getattr(self, name)).strip():
                raise RunRefused(f"a mutation declares {name}")
        if self.old == self.new:
            raise RunRefused(
                f"{self.identifier}: the replacement is identical to the "
                "original, so nothing would be mutated and the run would "
                "report a kill for an edit that never happened"
            )


@dataclass(frozen=True)
class MutationResult:
    """What happened to one mutation, and against exactly which revision."""

    identifier: str
    outcome: MutationOutcome
    target_sha: str
    #: The revision the worktree was actually at when the suite finished.
    observed_sha: str
    suite: str
    exit_status: Optional[int]
    detail: str

    def as_document(self) -> Mapping[str, object]:
        return {
            "identifier": self.identifier,
            "outcome": self.outcome.value,
            "target_sha": self.target_sha,
            "observed_sha": self.observed_sha,
            "suite": self.suite,
            "exit_status": self.exit_status,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class MutationRun:
    """Every result, and whether the run as a whole may be cited."""

    target_sha: str
    suite: str
    results: tuple[MutationResult, ...] = field(default_factory=tuple)

    @property
    def invalid(self) -> tuple[MutationResult, ...]:
        return tuple(r for r in self.results if r.outcome is MutationOutcome.INVALID)

    @property
    def survived(self) -> tuple[MutationResult, ...]:
        return tuple(r for r in self.results if r.outcome is MutationOutcome.SURVIVED)

    @property
    def killed(self) -> tuple[MutationResult, ...]:
        return tuple(r for r in self.results if r.outcome is MutationOutcome.KILLED)

    @property
    def trustworthy(self) -> bool:
        """One invalid result fails the whole run.

        Not a warning. A run containing an outcome that says nothing cannot
        be summarised as "N killed" -- the reader would take N as evidence,
        and part of it is not.
        """

        return bool(self.results) and not self.invalid

    def as_document(self) -> Mapping[str, object]:
        return {
            "target_sha": self.target_sha,
            "suite": self.suite,
            "trustworthy": self.trustworthy,
            "killed": len(self.killed),
            "survived": len(self.survived),
            "invalid": len(self.invalid),
            "results": [r.as_document() for r in self.results],
        }


#: Markers that mean the suite never ran the bodies it was meant to. A
#: mutation that produces one of these has tested nothing, whatever its exit
#: status says.
_COLLECTION_FAILURE = (
    "SyntaxError",
    "IndentationError",
    "errors during collection",
    "ERROR collecting",
    "ImportError while loading conftest",
)

_SUMMARY = re.compile(r"(\d+) (?:failed|passed)")


def classify(
    *,
    exit_status: Optional[int],
    output: str,
    target_sha: str,
    observed_sha: str,
) -> tuple[MutationOutcome, str]:
    """Decide what one run established. Pure, so it is testable on its own."""

    if observed_sha != target_sha:
        return (
            MutationOutcome.INVALID,
            f"the worktree was at {observed_sha} and the run targeted "
            f"{target_sha}; this says nothing about the target",
        )
    if exit_status is None:
        return MutationOutcome.INVALID, "the suite did not finish"
    for marker in _COLLECTION_FAILURE:
        if marker in output:
            return (
                MutationOutcome.INVALID,
                f"the suite reported {marker!r}: the mutation did not compile, "
                "so no test body ran and nothing was established. This is not "
                "a kill",
            )
    if not _SUMMARY.search(output):
        return MutationOutcome.INVALID, "the suite produced no result line"
    if exit_status == 0:
        return MutationOutcome.SURVIVED, "the suite passed with the mutation applied"
    return MutationOutcome.KILLED, "the suite failed because of the mutation"


def _git(*args: str, cwd: Path) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True
    )
    if completed.returncode != 0:
        raise RunRefused(
            f"git {' '.join(args)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def run_suite(
    mutations: Sequence[Mutation],
    *,
    repository: Path,
    suite: str = "tests/unit",
    python: Optional[str] = None,
    timeout_seconds: int = 900,
) -> MutationRun:
    """Run every mutation against one recorded revision.

    The revision is resolved **once**, before any mutation, and every
    worktree is detached at it. Nothing reads the working tree afterwards,
    so the main tree may be stashed, checked out or moved during the run
    without reaching the results.
    """

    if not mutations:
        raise RunRefused("a run with no mutations establishes nothing")
    identifiers = [m.identifier for m in mutations]
    duplicated = sorted({i for i in identifiers if identifiers.count(i) > 1})
    if duplicated:
        raise RunRefused(
            f"{duplicated} appear more than once; two results under one "
            "identifier cannot both be read"
        )

    target_sha = _git("rev-parse", "HEAD", cwd=repository)
    interpreter = python or sys.executable
    results: list[MutationResult] = []
    scratch = Path(tempfile.mkdtemp(prefix="azazel-mutate-"))
    try:
        for mutation in mutations:
            worktree = scratch / mutation.identifier.replace("/", "_").replace(" ", "_")
            _git("worktree", "add", "--detach", str(worktree), target_sha, cwd=repository)
            try:
                results.append(
                    _run_one(
                        mutation,
                        worktree=worktree,
                        repository=repository,
                        target_sha=target_sha,
                        suite=suite,
                        interpreter=interpreter,
                        timeout_seconds=timeout_seconds,
                    )
                )
            finally:
                _git("worktree", "remove", "--force", str(worktree), cwd=repository)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return MutationRun(target_sha=target_sha, suite=suite, results=tuple(results))


def _run_one(
    mutation: Mutation,
    *,
    worktree: Path,
    repository: Path,
    target_sha: str,
    suite: str,
    interpreter: str,
    timeout_seconds: int,
) -> MutationResult:
    target = worktree / mutation.path
    try:
        text = target.read_text(encoding="utf-8")
    except OSError as exc:
        return MutationResult(
            identifier=mutation.identifier,
            outcome=MutationOutcome.INVALID,
            target_sha=target_sha,
            observed_sha=target_sha,
            suite=suite,
            exit_status=None,
            detail=f"{mutation.path} could not be read at {target_sha}: {exc}",
        )
    if mutation.old not in text:
        return MutationResult(
            identifier=mutation.identifier,
            outcome=MutationOutcome.INVALID,
            target_sha=target_sha,
            observed_sha=target_sha,
            suite=suite,
            exit_status=None,
            detail=(
                "the text to replace is not present at this revision, so no "
                "mutation was applied and the suite would have tested the "
                "unmutated code"
            ),
        )
    target.write_text(text.replace(mutation.old, mutation.new, 1), encoding="utf-8")

    environment = dict(__import__("os").environ)
    environment["PYTHONPATH"] = (
        f"{worktree / 'src'}:{worktree / 'runtime' / 'src'}"
    )
    exit_status: Optional[int]
    try:
        completed = subprocess.run(
            [interpreter, "-m", "pytest", suite, "-q", "-x", "--no-header",
             "-p", "no:cacheprovider"],
            cwd=str(worktree),
            capture_output=True,
            text=True,
            env=environment,
            timeout=timeout_seconds,
        )
        output = completed.stdout + completed.stderr
        exit_status = completed.returncode
    except subprocess.TimeoutExpired:
        output = ""
        exit_status = None

    # Re-read the revision *after* the suite. The mutation edited a file in
    # this worktree, so the tree is dirty -- what is checked is that it is
    # still the intended commit, which is what the result is reported against.
    observed_sha = _git("rev-parse", "HEAD", cwd=worktree)
    outcome, detail = classify(
        exit_status=exit_status,
        output=output,
        target_sha=target_sha,
        observed_sha=observed_sha,
    )
    return MutationResult(
        identifier=mutation.identifier,
        outcome=outcome,
        target_sha=target_sha,
        observed_sha=observed_sha,
        suite=suite,
        exit_status=exit_status,
        detail=detail,
    )


def load_spec(path: Path) -> tuple[Mutation, ...]:
    """Read a mutation spec: a JSON list of {identifier, path, old, new}."""

    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise RunRefused("a mutation spec is a list")
    return tuple(
        Mutation(
            identifier=str(entry["identifier"]),
            path=str(entry["path"]),
            old=str(entry["old"]),
            new=str(entry["new"]),
        )
        for entry in document
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mutate",
        description=(
            "Run a mutation suite against one recorded revision. Any invalid "
            "outcome fails the whole run."
        ),
    )
    parser.add_argument("spec", type=Path, help="JSON mutation spec")
    parser.add_argument("--suite", default="tests/unit")
    parser.add_argument("--report", type=Path, default=None)
    arguments = parser.parse_args(argv)

    repository = Path(__file__).resolve().parents[1]
    run = run_suite(
        load_spec(arguments.spec), repository=repository, suite=arguments.suite
    )
    for result in run.results:
        print(f"{result.outcome.value.upper():9} {result.identifier} -- {result.detail}")
    print(
        f"\ntarget {run.target_sha} · suite {run.suite} · "
        f"killed {len(run.killed)}, survived {len(run.survived)}, "
        f"invalid {len(run.invalid)}"
    )
    if arguments.report:
        arguments.report.write_text(
            json.dumps(run.as_document(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if not run.trustworthy:
        print(
            "\nthis run may not be cited: an outcome established nothing, so "
            "the kill count is not evidence",
            file=sys.stderr,
        )
        return 2
    return 0 if not run.survived else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
