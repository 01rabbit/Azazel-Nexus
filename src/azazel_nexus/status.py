"""Status claims that carry their own evidence, or say they have none (#23).

Nexus makes statements about the world: which Fabric tag it pins, whether that
Fabric is installed, where the series as a whole stands. Some of those are
facts this repository holds. Most are not, and the ones that are not have gone
stale repeatedly -- a support-matrix table restating four other products'
pins, a section asserting for months that two Fabric modules did not exist
after they did, and a module comment ranking one Fabric
candidate against the rest of them, which a later Fabric release quietly
falsified.

The pattern in all three is the same. A claim about another repository was
written in the grammar of a fact, and nothing here could tell the difference
afterwards. This module makes the difference structural instead:

``VERIFIED``
    Derived, now, from something in this repository: its manifest, or a
    distribution installed in this environment. Never available to a claim
    about another repository, because there is nothing here to derive it from.

``OBSERVED``
    Somebody looked, once. Requires the tag or revision looked at, where they
    looked, and when. An observation missing any of those is not a weaker
    observation; it is a standing claim about a moving repository.

``UNKNOWN`` / ``UNAVAILABLE``
    Nothing was established. Both carry a reason, because "no evidence" must
    reach a reader as an answer about the evidence and not as a quiet absence
    they will read as agreement.

Nothing here reaches the network. A status check that needed to is a check
that reports differently on a disconnected node, which is the node Nexus is
built for (ADR-0001).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple

__all__ = [
    "EvidenceKind",
    "LOCALLY_DERIVABLE_EVIDENCE",
    "StatusClaim",
    "SubjectScope",
    "VerificationState",
    "collect_status",
    "describe_fabric_pin",
    "describe_installed_fabric",
    "describe_series_compatibility",
]

_ROOT = Path(__file__).resolve().parents[2]

#: Where the series-wide compatibility record lives.
#:
#: Cited, never copied. A second statement of somebody else's table is a second
#: thing to keep current, and this repository has no way to notice when it
#: stops matching the first.
SERIES_MATRIX_REF = "https://github.com/01rabbit/Azazel-Fabric/blob/main/docs/release-compatibility.md"


class VerificationState(str, Enum):
    VERIFIED = "verified"
    OBSERVED = "observed"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"


class EvidenceKind(str, Enum):
    #: This repository's own `pyproject.toml`, read now.
    LOCAL_MANIFEST = "local_manifest"
    #: A distribution installed in this environment, interrogated now.
    INSTALLED_DISTRIBUTION = "installed_distribution"
    #: Somebody looked at another repository at a named revision.
    OPERATOR_OBSERVATION = "operator_observation"
    #: Nothing was consulted.
    NONE = "none"


class SubjectScope(str, Enum):
    THIS_REPOSITORY = "this_repository"
    ANOTHER_REPOSITORY = "another_repository"


#: The evidence a `VERIFIED` claim may rest on.
#:
#: Both are re-derivable here and now. An observation is not, however carefully
#: it was made: the repository it described has moved since, or has not, and
#: this one cannot tell which.
LOCALLY_DERIVABLE_EVIDENCE = frozenset(
    {EvidenceKind.LOCAL_MANIFEST, EvidenceKind.INSTALLED_DISTRIBUTION}
)


@dataclass(frozen=True)
class StatusClaim:
    """One statement, with what backs it. Refuses to be built ill-formed.

    The refusals are in `__post_init__` rather than in a checker that runs
    over finished claims. A malformed claim that exists until something
    validates it is a malformed claim that gets rendered, logged and read in
    between.
    """

    subject: str
    subject_scope: SubjectScope
    statement: str
    verification_state: VerificationState
    evidence_kind: EvidenceKind
    source_ref: Optional[str] = None
    observed_at: Optional[str] = None
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.subject.strip():
            raise ValueError("a status claim must name its subject")
        if not self.statement.strip():
            raise ValueError("a status claim must say something")

        if self.verification_state is VerificationState.VERIFIED:
            if self.subject_scope is not SubjectScope.THIS_REPOSITORY:
                raise ValueError(
                    f"{self.subject!r} is in another repository and cannot be "
                    "verified from here; the strongest available state is "
                    "observed, and it must name the revision looked at"
                )
            if self.evidence_kind not in LOCALLY_DERIVABLE_EVIDENCE:
                raise ValueError(
                    f"a verified claim cannot rest on {self.evidence_kind.value!r}; "
                    "it must be re-derivable in this repository now"
                )
            if not self.source_ref:
                raise ValueError("a verified claim must name what it was derived from")

        elif self.verification_state is VerificationState.OBSERVED:
            if not self.source_ref:
                raise ValueError("an observation must name where it looked")
            if not self.observed_at:
                raise ValueError(
                    "an observation must name when it looked; an undated "
                    "observation is a standing claim about a moving repository"
                )
            if not _names_a_revision(self.source_ref):
                raise ValueError(
                    f"the observation source {self.source_ref!r} names no tag, "
                    "revision or digest. An observation of 'the repository' is "
                    "an observation of whatever it has since become"
                )

        else:
            if not self.reason:
                raise ValueError(
                    f"a {self.verification_state.value!r} claim must say why "
                    "nothing was established; an unexplained absence reads as "
                    "agreement"
                )


#: What counts as naming a point in another repository's history.
#:
#: A tag, a commit-ish of at least seven hex digits, or a content digest. A
#: branch name is deliberately not enough: `main` is not a revision, it is a
#: subscription to one.
_REVISION = re.compile(
    r"v\d+\.\d+\.\d+[\w.+-]*|\b[0-9a-f]{7,40}\b|sha256:[0-9a-f]{16,64}", re.I
)


def _names_a_revision(source_ref: str) -> bool:
    return _REVISION.search(source_ref) is not None


def _pyproject_text(root: Path) -> Optional[str]:
    manifest = root / "pyproject.toml"
    try:
        return manifest.read_text(encoding="utf-8")
    except OSError:
        return None


_PIN = re.compile(r"azazel-fabric\s*@\s*git\+[^\s\"']+@(?P<tag>[\w.+-]+)")


def describe_fabric_pin(root: Optional[Path] = None) -> StatusClaim:
    """Which Fabric tag this repository pins. A fact Nexus holds."""

    root = root or _ROOT
    text = _pyproject_text(root)
    if text is None:
        return StatusClaim(
            subject="azazel-nexus fabric pin",
            subject_scope=SubjectScope.THIS_REPOSITORY,
            statement="the dependency manifest could not be read",
            verification_state=VerificationState.UNAVAILABLE,
            evidence_kind=EvidenceKind.NONE,
            reason="pyproject.toml is missing or unreadable",
        )
    match = _PIN.search(text)
    if match is None:
        return StatusClaim(
            subject="azazel-nexus fabric pin",
            subject_scope=SubjectScope.THIS_REPOSITORY,
            statement="this repository declares no Azazel-Fabric pin",
            verification_state=VerificationState.VERIFIED,
            evidence_kind=EvidenceKind.LOCAL_MANIFEST,
            source_ref="pyproject.toml",
        )
    return StatusClaim(
        subject="azazel-nexus fabric pin",
        subject_scope=SubjectScope.THIS_REPOSITORY,
        statement=f"this repository pins Azazel-Fabric at {match.group('tag')}",
        verification_state=VerificationState.VERIFIED,
        evidence_kind=EvidenceKind.LOCAL_MANIFEST,
        source_ref="pyproject.toml",
    )


def describe_installed_fabric(root: Optional[Path] = None) -> StatusClaim:
    """Whether the pinned Fabric is installed here, and whether it agrees.

    A version that disagrees with the pin is reported as `UNKNOWN`, not as a
    failure and not as the pin. The environment and the manifest are each
    telling the truth about themselves; what is unknown is which one describes
    the code that will run, and that is a question for whoever installed it.
    """

    subject = "azazel-fabric installation"
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:  # pragma: no cover - stdlib since 3.8
        return StatusClaim(
            subject=subject,
            subject_scope=SubjectScope.THIS_REPOSITORY,
            statement="installed distributions could not be interrogated",
            verification_state=VerificationState.UNAVAILABLE,
            evidence_kind=EvidenceKind.NONE,
            reason="importlib.metadata is unavailable",
        )

    try:
        installed = version("azazel-fabric")
    except PackageNotFoundError:
        return StatusClaim(
            subject=subject,
            subject_scope=SubjectScope.THIS_REPOSITORY,
            statement="Azazel-Fabric is not installed in this environment",
            verification_state=VerificationState.UNAVAILABLE,
            evidence_kind=EvidenceKind.NONE,
            reason=(
                "the fabric extra is optional; CORE runs without it, so its "
                "absence is a configuration and not a fault"
            ),
        )

    pin = describe_fabric_pin(root)
    pinned_tag = _REVISION.search(pin.statement)
    if pinned_tag is None:
        return StatusClaim(
            subject=subject,
            subject_scope=SubjectScope.THIS_REPOSITORY,
            statement=f"Azazel-Fabric {installed} is installed; no pin to compare it with",
            verification_state=VerificationState.UNKNOWN,
            evidence_kind=EvidenceKind.NONE,
            reason="the manifest declares no Fabric pin to compare against",
        )

    wanted = pinned_tag.group(0).lstrip("v")
    if installed == wanted:
        return StatusClaim(
            subject=subject,
            subject_scope=SubjectScope.THIS_REPOSITORY,
            statement=f"the installed Azazel-Fabric {installed} matches the pin",
            verification_state=VerificationState.VERIFIED,
            evidence_kind=EvidenceKind.INSTALLED_DISTRIBUTION,
            source_ref="importlib.metadata:azazel-fabric",
        )
    return StatusClaim(
        subject=subject,
        subject_scope=SubjectScope.THIS_REPOSITORY,
        statement=(
            f"the installed Azazel-Fabric {installed} does not match the pinned {wanted}"
        ),
        verification_state=VerificationState.UNKNOWN,
        evidence_kind=EvidenceKind.NONE,
        reason=(
            "the manifest and the environment disagree, so which code will run "
            "is not established here"
        ),
    )


def describe_series_compatibility() -> StatusClaim:
    """Where the series as a whole stands: not something Nexus can say.

    Returned as a claim rather than omitted. A status report that simply has no
    row for the series lets a reader supply their own, and the row they supply
    is the stale table this function replaced.
    """

    return StatusClaim(
        subject="azazel series compatibility",
        subject_scope=SubjectScope.ANOTHER_REPOSITORY,
        statement=(
            "which Fabric tag each other product pins is not established here"
        ),
        verification_state=VerificationState.UNKNOWN,
        evidence_kind=EvidenceKind.NONE,
        reason=(
            "Nexus consumes no other product and cannot read their manifests; "
            f"the series record is held at {SERIES_MATRIX_REF}"
        ),
    )


def collect_status(root: Optional[Path] = None) -> Tuple[StatusClaim, ...]:
    """Every claim Nexus makes, each carrying what backs it.

    Reads this repository's manifest and this environment's installed
    distributions. Nothing else, and in particular nothing over a network:
    a check that answered differently on a disconnected node would be a check
    the node Nexus is built for cannot run.
    """

    return (
        describe_fabric_pin(root),
        describe_installed_fabric(root),
        describe_series_compatibility(),
    )
