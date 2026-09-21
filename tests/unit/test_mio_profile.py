"""The cognition ceiling an operator sets, and what it does not grant (#82).

`docs/mio-route-policy.md` §2. Three things are under test and the third is
the one that would be easy to lose:

*The path an operator takes* -- `CORE` until commissioned, and
`FASTEST_PERMITTED` recommended once all four prerequisites are explicitly
set.

*Withdrawal removes rather than fails* -- immediately, and never completing a
request by the route just withdrawn.

*A profile grants nothing.* No value of it, and no state of consent, moves
Edge readiness, action authority, an activation lease, or enforcement.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from azazel_nexus import mio_profile
REPOSITORY = pathlib.Path(__file__).resolve().parents[2]

from azazel_nexus.mio_profile import (
    NO_OPT_IN,
    OFFERED,
    PREREQUISITES,
    InFlightDisposition,
    MioProfile,
    ProfileRefused,
    RemoteOptIn,
    RemotePrerequisite,
    Withdrawal,
    admits_any_provider,
    disposition_on_withdrawal,
    profile_in_force,
    profile_rows,
    recommend_profile,
    remote_reachable,
)


def an_opt_in(*, granted=None, withdrawn=None) -> RemoteOptIn:
    return RemoteOptIn(
        granted=frozenset(PREREQUISITES if granted is None else granted),
        operator="operator-1",
        at="2026-09-21T00:00:00Z",
        withdrawn=withdrawn,
    )


def a_withdrawal() -> Withdrawal:
    return Withdrawal(
        operator="operator-1", at="2026-09-21T01:00:00Z", reason="policy change"
    )


# -- the path an operator takes -------------------------------------------


def test_an_uncommissioned_node_is_core_whatever_is_written_down() -> None:
    """"It is in the config" is not a grant.

    The same rule the decoy runtime holds to: a selection no commissioning
    confirmed is a selection nobody approved.
    """

    for selected in MioProfile:
        assert profile_in_force(commissioned=False, selected=selected) is MioProfile.CORE
    assert profile_in_force(commissioned=False, selected=None) is MioProfile.CORE


def test_a_commissioned_node_with_no_selection_is_core() -> None:
    assert profile_in_force(commissioned=True, selected=None) is MioProfile.CORE


def test_a_commissioned_node_operates_under_what_it_selected() -> None:
    """Otherwise the test above would pass by everything being CORE."""

    for selected in MioProfile:
        assert profile_in_force(commissioned=True, selected=selected) is selected


def test_all_four_prerequisites_recommend_fastest_permitted() -> None:
    """The standard path for a normal deployment, not an advanced option."""

    recommendation = recommend_profile(opt_in=an_opt_in(), reserve_measured=True)
    assert recommendation.profile is MioProfile.FASTEST_PERMITTED
    assert recommendation.blocked_by == ()


@pytest.mark.parametrize("withheld", PREREQUISITES)
def test_each_missing_prerequisite_independently_withholds_remote(withheld) -> None:
    """Each of the four, on its own. Three set is not "partially enabled"."""

    opt_in = an_opt_in(granted=[p for p in PREREQUISITES if p is not withheld])
    recommendation = recommend_profile(opt_in=opt_in, reserve_measured=True)
    assert recommendation.profile is MioProfile.LOCAL_ONLY
    assert withheld.value in recommendation.blocked_by
    assert withheld.value in recommendation.reason


def test_an_unmeasured_reserve_recommends_core_not_local_only() -> None:
    """`HG-05` first: no provider of any kind can be admitted.

    Proposing `LOCAL_ONLY` here would send an operator to configure a model
    that nothing on this node would accept.
    """

    for opt_in in (NO_OPT_IN, an_opt_in()):
        recommendation = recommend_profile(opt_in=opt_in, reserve_measured=False)
        assert recommendation.profile is MioProfile.CORE
        assert "HG-05" in recommendation.reason
        assert any("HG-05" in blocker for blocker in recommendation.blocked_by)


def test_the_recommendation_always_says_what_would_widen_it() -> None:
    """A dead end an operator cannot act on is worse than a refusal."""

    for reserve in (True, False):
        for opt_in in (NO_OPT_IN, an_opt_in(granted=[]), an_opt_in()):
            recommendation = recommend_profile(opt_in=opt_in, reserve_measured=reserve)
            if recommendation.profile is not MioProfile.FASTEST_PERMITTED:
                assert recommendation.blocked_by, recommendation


# -- absence is never consent ---------------------------------------------


def test_a_prerequisite_never_set_is_missing_and_not_permissive() -> None:
    opt_in = an_opt_in(granted=[RemotePrerequisite.REMOTE_USE])
    assert opt_in.complete is False
    assert opt_in.active() is False
    assert set(opt_in.missing) == set(PREREQUISITES) - {RemotePrerequisite.REMOTE_USE}


def test_the_missing_ones_are_named_not_counted() -> None:
    """An operator with "3 of 4 set" has nothing to act on."""

    opt_in = an_opt_in(granted=[RemotePrerequisite.REMOTE_USE])
    reason = opt_in.reason()
    for prerequisite in opt_in.missing:
        assert prerequisite.value in reason


def test_an_unknown_prerequisite_is_refused() -> None:
    with pytest.raises(ProfileRefused):
        RemoteOptIn(granted=frozenset({"invented"}), operator="o", at="t")  # type: ignore[arg-type]


# -- withdrawal -----------------------------------------------------------


def test_withdrawal_stops_permitting_immediately() -> None:
    """Not at the next restart and not at the next commissioning."""

    withdrawn = an_opt_in(withdrawn=a_withdrawal())
    assert withdrawn.complete is True  # the prerequisites really were set
    assert withdrawn.active() is False  # and it no longer permits
    assert recommend_profile(opt_in=withdrawn, reserve_measured=True).profile is (
        MioProfile.LOCAL_ONLY
    )


def test_a_withdrawn_opt_in_keeps_its_record() -> None:
    """Erasing it would lose the fact an audit reader needs."""

    withdrawn = an_opt_in(withdrawn=a_withdrawal())
    event = withdrawn.as_event()
    assert sorted(event["granted"]) == sorted(p.value for p in PREREQUISITES)
    assert event["withdrawn"]["operator"] == "operator-1"
    assert event["withdrawn"]["reason"] == "policy change"


def test_withdrawn_and_never_given_are_different_words() -> None:
    """The operator's next action differs, and so does what the audit says."""

    withdrawn = profile_rows(
        profile=MioProfile.LOCAL_ONLY,
        opt_in=an_opt_in(withdrawn=a_withdrawal()),
        reserve_measured=True,
    )
    never = profile_rows(
        profile=MioProfile.LOCAL_ONLY, opt_in=NO_OPT_IN, reserve_measured=True
    )
    consent = {row["axis"]: row["value"] for row in withdrawn}["mio_remote_consent"]
    absent = {row["axis"]: row["value"] for row in never}["mio_remote_consent"]
    assert consent == "withdrawn"
    assert absent == "not-given"
    assert consent != absent


@pytest.mark.parametrize(
    "local_available, expected",
    [(True, InFlightDisposition.LOCAL_FALLBACK), (False, InFlightDisposition.REFUSED)],
)
def test_an_in_flight_request_falls_back_or_is_refused(local_available, expected) -> None:
    assert disposition_on_withdrawal(local_available=local_available) is expected


def test_there_is_no_disposition_that_completes_remotely() -> None:
    """The one outcome withdrawal exists to prevent is absent from the vocabulary.

    Absent rather than forbidden by a check: a check can be edited, and a
    member that does not exist cannot be returned by anything.
    """

    assert {d.value for d in InFlightDisposition} == {"local fallback", "refused"}
    source = pathlib.Path(mio_profile.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    members = {
        node.targets[0].id
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in {"LOCAL_FALLBACK", "REFUSED", "COMPLETED"}
    }
    assert "COMPLETED" not in members


def test_an_unexplained_withdrawal_is_refused() -> None:
    for blank in ("", "   "):
        with pytest.raises(ProfileRefused):
            Withdrawal(operator="o", at="t", reason=blank)
        with pytest.raises(ProfileRefused):
            Withdrawal(operator=blank, at="t", reason="why")


# -- a profile is a ceiling, not a grant ----------------------------------


def test_only_fastest_permitted_can_even_consider_remote() -> None:
    assert remote_reachable(MioProfile.FASTEST_PERMITTED) is True
    for profile in (MioProfile.CORE, MioProfile.LOCAL_ONLY, MioProfile.REMOTE_DISABLED):
        assert remote_reachable(profile) is False


def test_local_only_and_remote_disabled_stay_different_words() -> None:
    """Both refuse remote; an operator's next action differs."""

    assert MioProfile.LOCAL_ONLY.value != MioProfile.REMOTE_DISABLED.value
    rows = {
        profile: {row["axis"]: row["value"] for row in profile_rows(
            profile=profile, opt_in=NO_OPT_IN, reserve_measured=True
        )}["mio_profile"]
        for profile in (MioProfile.LOCAL_ONLY, MioProfile.REMOTE_DISABLED)
    }
    assert rows[MioProfile.LOCAL_ONLY] != rows[MioProfile.REMOTE_DISABLED]


def test_the_widest_profile_admits_nothing_by_itself() -> None:
    """`admits_any_provider` is a ceiling. The gates still run afterwards."""

    assert admits_any_provider(MioProfile.FASTEST_PERMITTED) is True
    assert admits_any_provider(MioProfile.CORE) is False
    # And on this build the reserve is unmeasured, so the row says refused
    # even under the widest profile with consent given.
    rows = {
        row["axis"]: row["value"]
        for row in profile_rows(
            profile=MioProfile.FASTEST_PERMITTED,
            opt_in=an_opt_in(),
            reserve_measured=False,
        )
    }
    assert rows["mio_profile"] == "fastest-permitted"
    assert rows["mio_remote_consent"] == "permitted"
    assert rows["mio_provider_admission"] == "refused"


def test_the_three_status_facts_do_not_collapse_into_one() -> None:
    """A single summary word would send an operator after the wrong thing."""

    rows = profile_rows(
        profile=MioProfile.FASTEST_PERMITTED,
        opt_in=an_opt_in(),
        reserve_measured=False,
    )
    assert len({row["axis"] for row in rows}) == 3
    assert all(str(row["reason"]).strip() for row in rows)


# -- nothing here grants authority ----------------------------------------


def test_no_profile_or_consent_state_moves_the_edge_answer() -> None:
    """Driven over every profile and both consent states, not asserted.

    M.I.O. is an advisory plane; the Azazel-Edge arbiter is the sole decider.
    A ceiling on what cognition may be consulted is not a share of that.
    """

    from azazel_nexus.edge_package import inspect as inspect_edge

    def edge_answer(root):
        answer = inspect_edge(root)
        return (answer.ready, answer.presence.value, answer.state().ready)

    root = pathlib.Path("/nonexistent-edge-core-for-mio-profile")
    baseline = edge_answer(root)
    assert baseline == (False, "absent", False), baseline

    for profile in MioProfile:
        for opt_in in (NO_OPT_IN, an_opt_in(), an_opt_in(withdrawn=a_withdrawal())):
            for reserve in (True, False):
                profile_in_force(commissioned=True, selected=profile)
                recommend_profile(opt_in=opt_in, reserve_measured=reserve)
                profile_rows(
                    profile=profile, opt_in=opt_in, reserve_measured=reserve
                )
                assert edge_answer(root) == baseline, (profile, opt_in, reserve)


def test_the_module_defines_no_verb_that_could_execute_or_egress() -> None:
    """Advisory means advisory. A ceiling module starts nothing and reaches nowhere."""

    tree = ast.parse(pathlib.Path(mio_profile.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {
        "socket", "ssl", "http", "urllib", "requests", "httpx", "asyncio", "subprocess"
    } == set()
    names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert not any(
        name.startswith(("run", "exec", "apply", "enforce", "launch", "start"))
        for name in names
    ), sorted(names)


# -- commissioning is where a profile is first offered --------------------


def a_commissioning(answer="core", confirmed=True, opt_in=None, reserve_measured=False):
    from azazel_nexus.mio_profile import commission_profile

    seen = {}

    def ask(prompt, choices):
        seen["prompt"] = prompt
        seen["choices"] = choices
        return answer

    record = commission_profile(
        ask=ask,
        confirm=lambda _summary: confirmed,
        opt_in=opt_in if opt_in is not None else NO_OPT_IN,
        reserve_measured=reserve_measured,
        operator="operator-1",
        at="2026-09-21T00:00:00Z",
    )
    return record, seen


def test_installation_offers_nothing_and_leaves_core() -> None:
    """A profile is first presented at commissioning, never by the installer.

    Checked against the installer itself rather than asserted: a script that
    wrote a profile would make the node something other than `CORE` before
    anybody was asked.
    """

    installer = (REPOSITORY / "packaging" / "install.sh").read_text(encoding="utf-8")
    for profile in MioProfile:
        if profile is MioProfile.CORE:
            continue
        assert profile.value not in installer, (
            f"the installer mentions {profile.value}; installation leaves CORE "
            "in force and asks nothing"
        )


def test_all_four_profiles_are_offered() -> None:
    """Offering only the recommended one would make the recommendation a decision."""

    _record, seen = a_commissioning()
    assert seen["choices"] == tuple(p.value for p in OFFERED)
    assert set(seen["choices"]) == {p.value for p in MioProfile}


def test_the_narrowest_is_offered_first() -> None:
    """A list that opens with the widest option recommends it by placement."""

    _record, seen = a_commissioning()
    assert seen["choices"][0] == MioProfile.CORE.value
    assert seen["choices"][-1] == MioProfile.FASTEST_PERMITTED.value


def test_the_recommendation_and_its_reason_travel_with_the_question() -> None:
    _record, seen = a_commissioning()
    assert "Recommended: core" in seen["prompt"]
    assert "HG-05" in seen["prompt"]


def test_fastest_permitted_is_recommended_once_everything_is_set() -> None:
    """The standard path, and it needs the reserve as well as the consent."""

    record, seen = a_commissioning(
        answer="fastest-permitted", opt_in=an_opt_in(), reserve_measured=True
    )
    assert record.recommended is MioProfile.FASTEST_PERMITTED
    assert record.chosen is MioProfile.FASTEST_PERMITTED
    assert record.overrode_recommendation is False
    assert "Recommended: fastest-permitted" in seen["prompt"]


def test_an_override_that_widens_is_recorded_as_such() -> None:
    """Narrowing is unremarkable; widening is what an audit reader looks for."""

    record, _seen = a_commissioning(answer="fastest-permitted", reserve_measured=False)
    assert record.recommended is MioProfile.CORE
    assert record.overrode_recommendation is True
    assert record.widened is True
    assert record.as_event()["widened"] is True


def test_an_override_that_narrows_is_not_reported_as_widening() -> None:
    record, _seen = a_commissioning(
        answer="core", opt_in=an_opt_in(), reserve_measured=True
    )
    assert record.recommended is MioProfile.FASTEST_PERMITTED
    assert record.overrode_recommendation is True
    assert record.widened is False


def test_the_record_keeps_both_the_choice_and_the_recommendation() -> None:
    """An operator who took the advice and one who overrode it differ."""

    record, _seen = a_commissioning(answer="fastest-permitted")
    event = record.as_event()
    assert event["chosen"] == "fastest-permitted"
    assert event["recommended"] == "core"
    assert event["recommendation_reason"]
    assert event["operator"] == "operator-1"


def test_an_unconfirmed_commissioning_writes_nothing() -> None:
    with pytest.raises(ProfileRefused) as caught:
        a_commissioning(confirmed=False)
    assert "remains CORE" in str(caught.value)


def test_an_answer_outside_the_offer_is_refused_rather_than_taken() -> None:
    """A profile commissioned by a typo is a ceiling nobody decided on."""

    with pytest.raises(ProfileRefused) as caught:
        a_commissioning(answer="fastest")  # a plausible mistyping
    assert "not a choice" in str(caught.value)


def test_a_commissioning_still_admits_nothing() -> None:
    """Even the widest choice. Every admission gate runs afterwards."""

    record, _seen = a_commissioning(
        answer="fastest-permitted", opt_in=an_opt_in(), reserve_measured=False
    )
    rows = {
        row["axis"]: row["value"]
        for row in profile_rows(
            profile=record.chosen, opt_in=an_opt_in(), reserve_measured=False
        )
    }
    assert rows["mio_profile"] == "fastest-permitted"
    assert rows["mio_provider_admission"] == "refused"
