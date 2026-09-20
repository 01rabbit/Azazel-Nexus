"""A claim can only be as strong as what backs it (#23).

Three stale claims produced this file, and they failed the same way: a
statement about another repository was written in the grammar of a fact, and
afterwards nothing here could tell it from one. The support matrix restated
four other products' pins. `contract-ownership.md` §2 asserted for months that
two Fabric modules did not exist, after they did. And `fabric_boundary.py`
called `v0.9.0rc2` "the newest published candidate" until Fabric published
`v0.9.0rc3` and nothing here noticed.

So the tests below are mostly about refusals. What is checked is not that the
right answer comes out but that the wrong shape of answer cannot be built.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from azazel_nexus.status import (
    LOCALLY_DERIVABLE_EVIDENCE,
    EvidenceKind,
    StatusClaim,
    SubjectScope,
    VerificationState,
    collect_status,
    describe_fabric_pin,
    describe_installed_fabric,
    describe_series_compatibility,
)

ROOT = Path(__file__).resolve().parents[2]


def _claim(**overrides) -> StatusClaim:
    fields = dict(
        subject="azazel-nexus fabric pin",
        subject_scope=SubjectScope.THIS_REPOSITORY,
        statement="this repository pins Azazel-Fabric at v0.9.0rc2",
        verification_state=VerificationState.VERIFIED,
        evidence_kind=EvidenceKind.LOCAL_MANIFEST,
        source_ref="pyproject.toml",
    )
    fields.update(overrides)
    return StatusClaim(**fields)


# ---------------------------------------------------------------------------
# The rule the issue exists for
# ---------------------------------------------------------------------------


def test_a_claim_about_another_repository_can_never_be_verified():
    """The one that would have caught all three stale claims.

    Not "should not be" -- cannot be. A rule enforced at the point of
    rendering leaves the claim existing, and therefore loggable and readable,
    in the meantime.
    """

    with pytest.raises(ValueError, match="another repository"):
        _claim(
            subject="azazel-fabric published tags",
            subject_scope=SubjectScope.ANOTHER_REPOSITORY,
            statement="v0.9.0rc2 is the newest published candidate",
        )


def test_an_observation_is_the_strongest_a_foreign_claim_can_reach():
    """And it costs a revision and a date to say it."""

    claim = _claim(
        subject="azazel-fabric published tags",
        subject_scope=SubjectScope.ANOTHER_REPOSITORY,
        statement="v0.9.0rc3 was the newest published candidate",
        verification_state=VerificationState.OBSERVED,
        evidence_kind=EvidenceKind.OPERATOR_OBSERVATION,
        source_ref="01rabbit/Azazel-Fabric@v0.9.0rc3",
        observed_at="2026-09-20",
    )
    assert claim.verification_state is VerificationState.OBSERVED


def test_verified_evidence_must_be_re_derivable_here_and_now():
    with pytest.raises(ValueError, match="re-derivable"):
        _claim(evidence_kind=EvidenceKind.OPERATOR_OBSERVATION)
    with pytest.raises(ValueError, match="re-derivable"):
        _claim(evidence_kind=EvidenceKind.NONE)


def test_the_two_locally_derivable_kinds_both_actually_work():
    """A refusal that refused everything would pass the test above."""

    for kind in sorted(LOCALLY_DERIVABLE_EVIDENCE, key=lambda k: k.value):
        assert _claim(evidence_kind=kind).evidence_kind is kind


def test_a_verified_claim_must_name_what_it_was_derived_from():
    with pytest.raises(ValueError, match="derived from"):
        _claim(source_ref=None)


# ---------------------------------------------------------------------------
# An observation is dated and sourced, or it is not an observation
# ---------------------------------------------------------------------------


def _observation(**overrides) -> StatusClaim:
    fields = dict(
        subject="azazel-fabric published tags",
        subject_scope=SubjectScope.ANOTHER_REPOSITORY,
        statement="v0.9.0rc3 was the newest published candidate",
        verification_state=VerificationState.OBSERVED,
        evidence_kind=EvidenceKind.OPERATOR_OBSERVATION,
        source_ref="01rabbit/Azazel-Fabric@v0.9.0rc3",
        observed_at="2026-09-20",
    )
    fields.update(overrides)
    return StatusClaim(**fields)


def test_an_undated_observation_is_refused():
    with pytest.raises(ValueError, match="when it looked"):
        _observation(observed_at=None)


def test_an_unsourced_observation_is_refused():
    with pytest.raises(ValueError, match="where it looked"):
        _observation(source_ref=None)


@pytest.mark.parametrize(
    "source_ref",
    [
        "01rabbit/Azazel-Fabric",
        "01rabbit/Azazel-Fabric@main",
        "the Fabric repository",
        "https://github.com/01rabbit/Azazel-Fabric",
    ],
)
def test_an_observation_of_a_moving_target_is_refused(source_ref):
    """`main` is not a revision. It is a subscription to one.

    An observation sourced to a branch describes whatever that branch has
    since become, which is the failure mode this whole file is about, dressed
    as a citation.
    """

    with pytest.raises(ValueError, match="no tag, revision or digest"):
        _observation(source_ref=source_ref)


@pytest.mark.parametrize(
    "source_ref",
    [
        "01rabbit/Azazel-Fabric@v0.9.0rc3",
        "01rabbit/Azazel-Fabric@3a9543a",
        "release/v0.9.0rc3.digest.json sha256:0210f96783248aa6",
    ],
)
def test_a_tag_a_commit_or_a_digest_all_count_as_a_revision(source_ref):
    assert _observation(source_ref=source_ref).source_ref == source_ref


# ---------------------------------------------------------------------------
# Absence is an answer, and has to be given as one
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "state", [VerificationState.UNKNOWN, VerificationState.UNAVAILABLE]
)
def test_an_unestablished_claim_must_say_why(state):
    """An unexplained absence reads as agreement.

    A reader who sees a row with nothing in it supplies the reason themselves,
    and the reason they supply is usually "nothing to report".
    """

    with pytest.raises(ValueError, match="why"):
        _claim(
            verification_state=state,
            evidence_kind=EvidenceKind.NONE,
            source_ref=None,
            reason=None,
        )


def test_the_series_row_exists_rather_than_being_left_out():
    """Omitting it would let the reader write the stale table back in."""

    claim = describe_series_compatibility()
    assert claim.verification_state is VerificationState.UNKNOWN
    assert claim.subject_scope is SubjectScope.ANOTHER_REPOSITORY
    assert claim.reason
    assert "release-compatibility" in claim.reason, (
        "the series row must point at the record that holds the answer, not "
        "merely decline to answer"
    )


def test_the_series_row_cites_the_record_instead_of_copying_it():
    """A version literal here would be a second copy of somebody else's table."""

    claim = describe_series_compatibility()
    import re

    assert not re.search(r"v\d+\.\d+\.\d+", claim.statement), (
        "the series row states a version; cite Fabric's table instead"
    )


# ---------------------------------------------------------------------------
# The local facts
# ---------------------------------------------------------------------------


def test_the_pin_is_read_from_the_manifest_rather_than_written_here():
    claim = describe_fabric_pin()
    assert claim.verification_state is VerificationState.VERIFIED
    assert claim.evidence_kind is EvidenceKind.LOCAL_MANIFEST
    manifest = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    tag = claim.statement.rsplit(" ", 1)[-1]
    assert f"@{tag}" in manifest, (
        f"the reported pin {tag!r} does not appear in pyproject.toml; the "
        "claim was written rather than derived"
    )


def test_a_missing_manifest_is_unavailable_and_not_no_pin(tmp_path):
    """"We could not read it" and "it declares nothing" are different answers."""

    claim = describe_fabric_pin(tmp_path)
    assert claim.verification_state is VerificationState.UNAVAILABLE
    assert claim.reason


def test_an_environment_without_fabric_is_unavailable_and_not_a_fault(tmp_path):
    """CORE runs with nothing installed (ADR-0001)."""

    claim = describe_installed_fabric()
    assert claim.verification_state in {
        VerificationState.VERIFIED,
        VerificationState.UNAVAILABLE,
        VerificationState.UNKNOWN,
    }
    if claim.verification_state is VerificationState.UNAVAILABLE:
        assert "optional" in (claim.reason or "")


# ---------------------------------------------------------------------------
# Offline
# ---------------------------------------------------------------------------


def test_the_whole_status_check_runs_with_the_network_removed(monkeypatch):
    """ADR-0001: CORE is useful with no cloud connectivity.

    A status check that reached out would answer differently on the node Nexus
    is built for, and would answer *worse* there -- the disconnected operator
    is the one who most needs to know what their node is running.

    Sockets are broken rather than merely watched. A test that asserted "no
    request was made" would pass on a check that made one and fell back.
    """

    class NetworkTouched(BaseException):
        """Derived from `BaseException`, and that is the whole point.

        The first version of this raised `AssertionError`. A check that
        reached out and wrapped the attempt in `except Exception` -- the
        ordinary shape of an optional lookup with a fallback -- swallowed it
        and this test stayed green over exactly the behaviour it forbids. An
        exception the code under test is able to catch is not a tripwire.
        """

    def refuse(*args, **kwargs):
        raise NetworkTouched("the status check opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)

    claims = collect_status()
    assert claims
    for claim in claims:
        assert isinstance(claim, StatusClaim)


def test_every_claim_carries_the_four_fields_the_schema_promises():
    for claim in collect_status():
        assert claim.verification_state in set(VerificationState)
        assert claim.evidence_kind in set(EvidenceKind)
        # Exactly one of "backed by something" or "says why not".
        backed = claim.source_ref is not None
        excused = claim.reason is not None
        assert backed != excused, (
            f"{claim.subject}: a claim either names its evidence or says why it "
            f"has none, never both and never neither (source_ref="
            f"{claim.source_ref!r}, reason={claim.reason!r})"
        )


# ---------------------------------------------------------------------------
# The phrasings that carried the stale claims, kept out of the package
# ---------------------------------------------------------------------------

#: How a claim about another repository's releases gets written as a fact.
#:
#: Each of these was in this repository, in the grammar of something Nexus
#: knew, and each went stale without a sound. They are listed here -- in the
#: one file that may name them -- rather than in a comment beside the code
#: they were removed from, because a scan cannot tell a claim from its own
#: retraction and the retraction would have to go.
#:
#: The substance is not banned. Where a Fabric tag stands among Fabric's
#: releases is a real question; it is answered by
#: `describe_series_compatibility`, which returns `unknown` and cites the
#: record, or by an `OBSERVED` claim carrying the revision someone looked at.
#: What is banned is asserting it here as though this repository could tell.
RETIRED_RANKING_PHRASES = (
    "newest published",
    "latest published",
    "most recent published",
    "newest candidate",
    "latest candidate",
)

#: Where a reader would act on such a claim.
SCANNED_PATHS = (
    "src/azazel_nexus",
    "README.md",
    "docs/IMPLEMENTATION_SPEC.md",
    "docs/architecture.md",
    "docs/contract-ownership.md",
    "docs/inheritance-ledger.md",
    "docs/support-matrix.md",
    "docs/roadmap.md",
)


def _scanned_files():
    for relative in SCANNED_PATHS:
        target = ROOT / relative
        if target.is_dir():
            yield from sorted(target.rglob("*.py"))
        elif target.is_file():
            yield target


@pytest.mark.parametrize("phrase", RETIRED_RANKING_PHRASES)
def test_nothing_ranks_another_repositorys_releases_as_a_fact(phrase):
    """Comments included, on purpose.

    The claim this replaced lived in a `#:` comment, which no AST walk sees.
    A scan restricted to string values would have been green over the exact
    defect it was written for -- and would have looked thorough doing it.
    """

    offenders = [
        str(path.relative_to(ROOT))
        for path in _scanned_files()
        if phrase in path.read_text(encoding="utf-8").lower()
    ]
    assert offenders == [], (
        f"{offenders} rank another repository's releases with {phrase!r}. "
        "Nexus cannot read another repository, so such a statement is true "
        "only until the repository moves and cannot be checked here either "
        "way. Report it through azazel_nexus.status as unknown, or make it an "
        "OBSERVED claim naming the revision that was looked at."
    )


def test_the_scan_covers_the_file_the_defect_was_actually_in():
    """A list of paths is only a guard while it contains the path that failed."""

    scanned = {str(path.relative_to(ROOT)) for path in _scanned_files()}
    assert "src/azazel_nexus/fabric_boundary.py" in scanned
    assert "src/azazel_nexus/status.py" in scanned


def test_the_banned_phrases_are_ones_that_would_have_fired():
    """Otherwise the list above could be eight phrases nobody would write.

    `fabric_boundary.py` carried "the newest published candidate". Reinstating
    it must turn the scan red, and this checks that against the real file
    rather than against a fabricated string.
    """

    target = ROOT / "src" / "azazel_nexus" / "fabric_boundary.py"
    reinstated = target.read_text(encoding="utf-8") + (
        '\n#: `v0.9.0rc2` is the newest published candidate.\n'
    )
    assert any(
        phrase in reinstated.lower() for phrase in RETIRED_RANKING_PHRASES
    ), "the retired phrasing would no longer be caught if it came back"


# ---------------------------------------------------------------------------
# A claim Nexus *could* have checked, and did not
# ---------------------------------------------------------------------------

#: Ways the documents said a Fabric module does not exist.
#:
#: Six documents said `provisioning_contracts` and `mio_contracts` were "not
#: released" while the Fabric tag this repository pins shipped both, from
#: `v0.9.0rc1` onwards. That is the sharpest form of the failure #23 is about:
#: not an unverifiable claim about a distant repository, but a claim about the
#: *pinned* one, installed right here and never asked.
#:
#: They were: `docs/IMPLEMENTATION_SPEC.md` (a table row and the §6.3 owner
#: line), `docs/architecture.md` (two table rows), `docs/inheritance-ledger.md`
#: (two table rows) and `docs/contract-ownership.md` §3.4 -- whose header
#: called the module unreleased directly above a row describing a record as
#: consumed from it. Meanwhile `docs/support-matrix.md` §4 had said "released,
#: unadopted" correctly the whole time. One place being right is what a
#: document-by-document correction produces, and it is why this is a test.
#:
#: This file may name the phrasing because it is the file that refuses it. A
#: scan cannot tell a claim from its own retraction, so the retraction cannot
#: live where the scan runs.
_DENIALS = (
    "not released",
    "not yet released",
    "unreleased",
    "does not exist",
    "do not exist",
    "does not ship",
)


def _denial_sentences(text: str, module: str):
    """Sentences that name the module and deny it, in the same breath.

    Sentence-scoped rather than document-scoped. A document may legitimately
    name a module in one place and say something else is unreleased in
    another, and a whole-document check would call that a contradiction.
    """

    import re

    for sentence in re.split(r"(?<=[.!?|])\s+|\n", text):
        lowered = sentence.lower()
        if module in lowered and any(denial in lowered for denial in _DENIALS):
            yield sentence.strip()


def _fabric_contract_modules():
    """Enumerated from the installed Fabric, not from a list kept here.

    A list here would cover exactly the families that were wrong the day it
    was written. Reading Fabric's own package means a family published later
    is covered the moment the pin moves to it.
    """

    import pkgutil

    import azazel_fabric

    return sorted(
        name
        for _, name, _ in pkgutil.iter_modules(azazel_fabric.__path__)
        if name.endswith("_contracts")
    )


def test_no_document_calls_a_pinned_fabric_module_unreleased():
    """The claim was checkable here the whole time.

    Skips without the optional extra, which is right for a contributor with no
    network and useless as a gate; CI installs it (`.[dev,fabric]`).
    """

    pytest.importorskip(
        "azazel_fabric",
        reason="the Fabric extra is optional; CORE must work without it",
    )

    shipped = _fabric_contract_modules()
    assert shipped, "the installed Fabric exposes no *_contracts module at all"

    offenders = []
    for path in _scanned_files():
        text = path.read_text(encoding="utf-8")
        for module in shipped:
            for sentence in _denial_sentences(text, module):
                offenders.append(f"{path.relative_to(ROOT)}: {sentence[:110]}")

    assert offenders == [], (
        "these say a Fabric module is unreleased, and the Fabric tag this "
        f"repository pins ships it:\n  " + "\n  ".join(offenders) + "\n"
        "Nexus pins that tag, so this is not an unverifiable claim about a "
        "distant repository -- it is installed here and could have been asked."
    )
