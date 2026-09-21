"""What must hold before a remote route is a candidate (#84).

`docs/mio-route-policy.md` §3. The load-bearing claims:

*Nobody has looked is not a failure and not a pass.* Every node in this build
reports all four signals `NOT_CHECKED`, so remote is not permitted — and that
is the correct state.

*The privacy class is a third independent refusal.* `P2`/`P3` stay out with
every trust signal passing, the profile widest and consent given.

*There is no client.* This module judges; it does not communicate.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from azazel_nexus import remote_trust
from azazel_nexus.edge_package import Evidence
from azazel_nexus.mio_profile import (
    NO_OPT_IN,
    PREREQUISITES,
    MioProfile,
    RemoteOptIn,
    Withdrawal,
)
from azazel_nexus.remote_trust import (
    ENDPOINT_ALLOWLIST,
    Exclusion,
    RemoteTrustReading,
    TrustSignal,
    remote_admission,
    unchecked_reading,
)
from azazel_nexus.sanitizer import NEVER_REMOTE, PrivacyClass


def consent() -> RemoteOptIn:
    return RemoteOptIn(
        granted=frozenset(PREREQUISITES), operator="operator-1", at="2026-09-21T00:00:00Z"
    )


def established() -> RemoteTrustReading:
    """Every signal passed. Reachable only in a test; no node produces it."""

    return RemoteTrustReading(
        signals={signal: Evidence.PASSED for signal in TrustSignal},
        reasons={signal: "established by a test fixture" for signal in TrustSignal},
    )


def admit(**overrides):
    fields = {
        "profile": MioProfile.FASTEST_PERMITTED,
        "opt_in": consent(),
        "trust": established(),
        "privacy_class": PrivacyClass.P0_PUBLIC,
        "sanitised": True,
    }
    fields.update(overrides)
    return remote_admission(**fields)


# -- the node this build produces -----------------------------------------


def test_every_signal_is_unchecked_on_this_node() -> None:
    reading = unchecked_reading()
    assert reading.established is False
    assert {e for e in reading.signals.values()} == {Evidence.NOT_CHECKED}
    assert len(reading.withheld()) == len(TrustSignal)


def test_unchecked_is_neither_failed_nor_passed() -> None:
    """Reporting it as failed sends an operator to fix a provider that is fine."""

    reading = unchecked_reading()
    for _signal, evidence, reason in reading.withheld():
        assert evidence is Evidence.NOT_CHECKED
        assert evidence is not Evidence.FAILED
        assert "Nobody looked is not a failure" in reason


def test_remote_is_not_permitted_on_this_node() -> None:
    outcome = admit(trust=unchecked_reading())
    assert outcome.permitted is False
    assert outcome.excluded_by is Exclusion.TRUST
    assert "not-checked" in outcome.reason


def test_the_endpoint_allowlist_is_empty_and_is_a_constant() -> None:
    """An allowlist taken from runtime input is one the input can widen."""

    assert ENDPOINT_ALLOWLIST == ()
    tree = ast.parse(pathlib.Path(remote_trust.__file__).read_text(encoding="utf-8"))
    assigned = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "ENDPOINT_ALLOWLIST"
    ]
    assert len(assigned) == 1, "the allowlist is assigned in exactly one place"
    assert isinstance(assigned[0].value, ast.Tuple)


def test_an_established_reading_would_still_find_no_endpoint() -> None:
    """The last refusal, and the one that is not vacuous to check.

    With every signal passed, consent given and the widest profile, the route
    is still excluded -- because there is nowhere for it to go.
    """

    outcome = admit()
    assert outcome.permitted is False
    assert outcome.excluded_by is Exclusion.NO_ENDPOINT


# -- each condition excludes independently --------------------------------


@pytest.mark.parametrize(
    "profile", [MioProfile.CORE, MioProfile.LOCAL_ONLY, MioProfile.REMOTE_DISABLED]
)
def test_a_profile_that_does_not_permit_remote_excludes_it(profile) -> None:
    outcome = admit(profile=profile)
    assert outcome.excluded_by is Exclusion.PROFILE
    assert profile.value in outcome.reason


def test_no_consent_excludes_remote() -> None:
    outcome = admit(opt_in=NO_OPT_IN)
    assert outcome.excluded_by is Exclusion.CONSENT


def test_withdrawn_consent_excludes_remote() -> None:
    withdrawn = RemoteOptIn(
        granted=frozenset(PREREQUISITES),
        operator="operator-1",
        at="2026-09-21T00:00:00Z",
        withdrawn=Withdrawal(operator="operator-1", at="t", reason="policy change"),
    )
    outcome = admit(opt_in=withdrawn)
    assert outcome.excluded_by is Exclusion.CONSENT
    assert "withdrawn" in outcome.reason


@pytest.mark.parametrize("signal", list(TrustSignal))
def test_each_trust_signal_independently_withholds_remote(signal) -> None:
    """One established signal must not stand in for three that were not."""

    for evidence in (Evidence.FAILED, Evidence.NOT_CHECKED):
        reading = RemoteTrustReading(
            signals={
                s: (evidence if s is signal else Evidence.PASSED) for s in TrustSignal
            },
            reasons={s: "fixture" for s in TrustSignal},
        )
        outcome = admit(trust=reading)
        assert outcome.excluded_by is Exclusion.TRUST
        assert signal.value in outcome.reason
        assert evidence.value in outcome.reason


def test_an_unsanitised_p1_is_excluded() -> None:
    outcome = admit(privacy_class=PrivacyClass.P1_SANITIZED, sanitised=False)
    assert outcome.excluded_by is Exclusion.UNSANITISED


def test_a_sanitised_p1_passes_the_class_check() -> None:
    """Otherwise the test above would pass because P1 is refused outright."""

    outcome = admit(privacy_class=PrivacyClass.P1_SANITIZED, sanitised=True)
    assert outcome.excluded_by is not Exclusion.UNSANITISED
    assert outcome.excluded_by is not Exclusion.PRIVACY_CLASS


# -- the privacy class is a third, independent refusal --------------------


@pytest.mark.parametrize("privacy_class", sorted(NEVER_REMOTE, key=lambda c: c.value))
def test_a_never_remote_class_survives_everything_else_passing(privacy_class) -> None:
    """The widest profile, consent given, every trust signal established.

    Speed cannot reach this module, and neither can commissioning: no
    combination of the other conditions admits a class that may not leave.
    """

    outcome = admit(privacy_class=privacy_class, sanitised=True)
    assert outcome.permitted is False
    assert outcome.excluded_by is Exclusion.PRIVACY_CLASS
    assert "never remote" in outcome.reason


def test_the_class_refusal_is_not_reported_as_something_to_fix() -> None:
    """An operator must not be told to finish commissioning; nothing would help."""

    outcome = admit(privacy_class=PrivacyClass.P3_RESTRICTED, opt_in=NO_OPT_IN)
    assert outcome.excluded_by is Exclusion.PRIVACY_CLASS


def test_this_module_agrees_with_the_sanitizer_about_which_classes_never_leave() -> None:
    """Three refusals, one list. Two lists would drift into two policies."""

    assert NEVER_REMOTE == {PrivacyClass.P2_MISSION, PrivacyClass.P3_RESTRICTED}
    for privacy_class in PrivacyClass:
        excluded = admit(privacy_class=privacy_class).excluded_by is Exclusion.PRIVACY_CLASS
        assert excluded is (privacy_class in NEVER_REMOTE)


# -- shape --------------------------------------------------------------


def test_a_reading_that_omits_a_signal_is_refused() -> None:
    with pytest.raises(ValueError) as caught:
        RemoteTrustReading(
            signals={TrustSignal.MUTUAL_TLS: Evidence.PASSED},
            reasons={TrustSignal.MUTUAL_TLS: "fixture"},
        )
    assert "mutual TLS" not in str(caught.value)  # the *absent* ones are named
    assert "provider identity" in str(caught.value)


def test_a_signal_with_no_reason_is_refused() -> None:
    with pytest.raises(ValueError):
        RemoteTrustReading(
            signals={s: Evidence.FAILED for s in TrustSignal},
            reasons={s: "  " for s in TrustSignal},
        )


def test_an_exclusion_always_names_its_cause() -> None:
    for privacy_class in PrivacyClass:
        for profile in MioProfile:
            for opt_in in (NO_OPT_IN, consent()):
                outcome = remote_admission(
                    profile=profile,
                    opt_in=opt_in,
                    trust=unchecked_reading(),
                    privacy_class=privacy_class,
                    sanitised=False,
                )
                assert outcome.permitted is False
                assert outcome.excluded_by is not None
                assert outcome.reason.strip()


# -- no client ----------------------------------------------------------


def test_this_module_cannot_communicate() -> None:
    """It judges; it does not talk. The judgement must run where talking cannot."""

    tree = ast.parse(pathlib.Path(remote_trust.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {
        "socket", "ssl", "http", "urllib", "requests", "httpx", "asyncio", "subprocess"
    } == set()


def test_the_cognition_plane_still_has_no_egress_path() -> None:
    """#84 must not open what #5 closed. Re-asserted from this side too."""

    from azazel_nexus import cognition

    tree = ast.parse(pathlib.Path(cognition.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {"socket", "ssl", "http", "urllib", "requests", "httpx"} == set()


def test_nothing_here_takes_a_latency_or_a_deadline() -> None:
    """Speed cannot argue with the permit stage, so it cannot be passed in."""

    tree = ast.parse(pathlib.Path(remote_trust.__file__).read_text(encoding="utf-8"))
    parameters = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            args = node.args
            for arg in list(args.args) + list(args.kwonlyargs):
                parameters.add(arg.arg)
    assert not parameters & {
        "latency", "p95", "deadline", "predicted", "speed", "elapsed"
    }, sorted(parameters)


# -- no authority -------------------------------------------------------


def test_no_admission_outcome_moves_the_edge_answer() -> None:
    from azazel_nexus.edge_package import inspect as inspect_edge

    root = pathlib.Path("/nonexistent-edge-core-for-remote-trust")

    def edge_answer():
        answer = inspect_edge(root)
        return (answer.ready, answer.presence.value, answer.state().ready)

    baseline = edge_answer()
    assert baseline == (False, "absent", False)
    for privacy_class in PrivacyClass:
        for profile in MioProfile:
            for trust in (unchecked_reading(), established()):
                remote_admission(
                    profile=profile,
                    opt_in=consent(),
                    trust=trust,
                    privacy_class=privacy_class,
                    sanitised=True,
                )
                assert edge_answer() == baseline


def test_an_admission_cannot_be_constructed_without_a_named_cause() -> None:
    """The constructor guard, made reachable so it is not merely present.

    `remote_admission` always names a cause, so removing this guard changed
    no outcome the function produces and a mutation removing it survived the
    whole suite. It exists for a caller that builds one directly -- and an
    exclusion an operator cannot act on is an exclusion they will route
    around, which is the one thing this type is for.
    """

    from azazel_nexus.remote_trust import RemoteAdmission

    with pytest.raises(ValueError) as caught:
        RemoteAdmission(permitted=False, excluded_by=None, reason="no reason given")
    assert "named cause" in str(caught.value)

    with pytest.raises(ValueError):
        RemoteAdmission(
            permitted=True, excluded_by=Exclusion.TRUST, reason="both at once"
        )

    # And a well-formed one is still constructible, so the assertions above
    # are not satisfied by the type refusing everything.
    assert RemoteAdmission(
        permitted=False, excluded_by=Exclusion.TRUST, reason="a reason"
    ).excluded_by is Exclusion.TRUST
