"""Which permitted candidate answers, and what happens when it does not (#81).

The fourteen acceptance cases, each its own test: P2/P3 absolute refusal, P1
with the sanitizer not established, a withdrawn remote opt-in, unchecked
trust, an empty allowlist, `HG-05` unmet, too few samples, expired
observations, a prediction that misses the deadline, remote faster, local
faster, a tie, a withdrawal after the route was chosen, and exactly one
fallback after a timeout.

Over all of them, the Edge answer does not move. M.I.O. is an advisory plane.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from azazel_nexus import route_selection
from azazel_nexus.edge_package import Evidence
from azazel_nexus.mio_profile import (
    NO_OPT_IN,
    PREREQUISITES,
    MioProfile,
    RemoteOptIn,
    Withdrawal,
)
from azazel_nexus.remote_trust import (
    Exclusion,
    RemoteTrustReading,
    TrustSignal,
    remote_admission,
    unchecked_reading,
)
from azazel_nexus.route_evidence import MIN_SAMPLES, Observation, Outcome, SizeClass, predict
from azazel_nexus.route_selection import (
    MAX_FALLBACKS,
    NEVER_ANSWERED,
    Disposition,
    RequestOutcome,
    Selection,
    SelectionRefused,
    TerminalEvent,
    fallback_once,
    outcome_for,
    select,
)
from azazel_nexus.routing import ROUTE_ORDER, Route
from azazel_nexus.sanitizer import NEVER_REMOTE, PrivacyClass

NOW = "2026-09-21T12:00:00Z"
HG05 = "the Core reserve is unmeasured (HG-05), so no local provider is admitted"


def consent() -> RemoteOptIn:
    return RemoteOptIn(granted=frozenset(PREREQUISITES), operator="op", at="t")


def all_passed() -> RemoteTrustReading:
    return RemoteTrustReading(
        signals={s: Evidence.PASSED for s in TrustSignal},
        reasons={s: "fixture" for s in TrustSignal},
    )


def samples(*, candidate: str, elapsed: int, count: int = MIN_SAMPLES, at: str = "2026-09-21T11:59:00Z"):
    return [
        Observation(
            candidate=candidate,
            at=at,
            elapsed_ms=elapsed,
            outcome=Outcome.ANSWERED,
            request_size=SizeClass.SMALL,
            response_size=SizeClass.SMALL,
            queue_depth=0,
            cold_start=False,
        )
        for _ in range(count)
    ]


def predictions_for(**by_route):
    """`{"local": (elapsed, count)}` -> the prediction map `select` takes."""

    built = {}
    for name, spec in by_route.items():
        route = Route.LOCAL if name == "local" else Route.REMOTE
        if spec is None:
            continue
        elapsed, count, at = spec
        built[route] = predict(
            samples(candidate=name, elapsed=elapsed, count=count, at=at),
            candidate=name,
            as_of=NOW,
        )
    return built


def a_selection(
    *,
    force_remote_permitted=False,
    local_admitted=True,
    privacy_class=PrivacyClass.P0_PUBLIC,
    predictions=None,
    deadline_ms=1000,
    profile=MioProfile.FASTEST_PERMITTED,
    sanitised=True,
    opt_in=None,
    trust=None,
):
    """Build one decision from honest inputs.

    **The profile is not touched to make remote go away.** An earlier version
    of this helper set `LOCAL_ONLY` whenever a caller wanted remote excluded,
    which meant every such test read back "the profile does not permit it" --
    whatever condition the test was actually about. Three tests passed while
    checking nothing they named.

    `force_remote_permitted` is the one deliberate fiction, for the cases that
    are about *ordering* rather than permission: the endpoint allowlist is
    empty in this build, so no real input yields a permitted remote.
    """

    admission = remote_admission(
        profile=profile,
        opt_in=opt_in if opt_in is not None else consent(),
        trust=trust if trust is not None else all_passed(),
        privacy_class=privacy_class,
        sanitised=sanitised,
    )
    if force_remote_permitted:
        from azazel_nexus.remote_trust import RemoteAdmission

        assert admission.excluded_by is Exclusion.NO_ENDPOINT, (
            "the fixture may only paper over the empty allowlist; this "
            f"decision was excluded by {admission.excluded_by}"
        )
        admission = RemoteAdmission(
            permitted=True, excluded_by=None, reason="permitted by a test fixture"
        )
    return select(
        profile=profile,
        privacy_class=privacy_class,
        remote=admission,
        local_admitted=local_admitted,
        local_refusal=HG05,
        predictions=predictions or {},
        deadline_ms=deadline_ms,
    )


# -- 1-6: permission, checked before speed --------------------------------


@pytest.mark.parametrize("privacy_class", sorted(NEVER_REMOTE, key=lambda c: c.value))
def test_p2_and_p3_are_refused_absolutely(privacy_class) -> None:
    """Case 1. Remote is excluded with every other condition met and it faster."""

    selection = a_selection(
        privacy_class=privacy_class,
        predictions=predictions_for(local=(900, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
                                    remote=(1, MIN_SAMPLES, "2026-09-21T11:59:00Z")),
    )
    remote = selection.reading_for(Route.REMOTE)
    assert remote.disposition is Disposition.EXCLUDED
    assert "never remote" in remote.reason
    assert selection.route is Route.LOCAL


def test_an_unsanitised_p1_excludes_remote() -> None:
    """Case 2."""

    selection = a_selection(
        privacy_class=PrivacyClass.P1_SANITIZED,
        sanitised=False,
        predictions=predictions_for(local=(500, MIN_SAMPLES, "2026-09-21T11:59:00Z")),
    )
    assert selection.reading_for(Route.REMOTE).disposition is Disposition.EXCLUDED
    assert selection.route is Route.LOCAL


def test_a_withdrawn_opt_in_excludes_remote() -> None:
    """Case 3."""

    withdrawn = RemoteOptIn(
        granted=frozenset(PREREQUISITES),
        operator="op",
        at="t",
        withdrawn=Withdrawal(operator="op", at="t2", reason="policy change"),
    )
    selection = a_selection(
        opt_in=withdrawn,
        predictions=predictions_for(local=(500, MIN_SAMPLES, "2026-09-21T11:59:00Z")),
    )
    assert selection.reading_for(Route.REMOTE).disposition is Disposition.EXCLUDED


def test_unchecked_trust_excludes_remote() -> None:
    """Case 4. Nobody looked, so remote is not a candidate."""

    selection = a_selection(
        trust=unchecked_reading(),
        predictions=predictions_for(local=(500, MIN_SAMPLES, "2026-09-21T11:59:00Z")),
    )
    reading = selection.reading_for(Route.REMOTE)
    assert reading.disposition is Disposition.EXCLUDED
    assert "not-checked" in reading.reason


def test_an_empty_allowlist_excludes_remote() -> None:
    """Case 5. Every signal established, and nowhere for the route to go."""

    admission = remote_admission(
        profile=MioProfile.FASTEST_PERMITTED,
        opt_in=consent(),
        trust=all_passed(),
        privacy_class=PrivacyClass.P0_PUBLIC,
        sanitised=True,
    )
    assert admission.permitted is False  # the allowlist is empty in this build
    selection = select(
        profile=MioProfile.FASTEST_PERMITTED,
        privacy_class=PrivacyClass.P0_PUBLIC,
        remote=admission,
        local_admitted=True,
        local_refusal=HG05,
        predictions=predictions_for(local=(500, MIN_SAMPLES, "2026-09-21T11:59:00Z")),
        deadline_ms=1000,
    )
    reading = selection.reading_for(Route.REMOTE)
    assert reading.disposition is Disposition.EXCLUDED
    assert "allowlist" in reading.reason


def test_hg05_unmet_excludes_local() -> None:
    """Case 6. The state of every node in this build."""

    selection = a_selection(local_admitted=False, opt_in=NO_OPT_IN)
    assert selection.route is Route.DETERMINISTIC_HANDOFF
    local = selection.reading_for(Route.LOCAL)
    assert local.disposition is Disposition.EXCLUDED
    assert "HG-05" in local.reason
    assert selection.permitted == (Route.DETERMINISTIC_HANDOFF,)


# -- 7-9: evidence --------------------------------------------------------


def test_too_few_samples_is_unpredictable_not_excluded() -> None:
    """Case 7. A permission an operator can grant, versus evidence nobody has."""

    selection = a_selection(
        predictions=predictions_for(local=(10, MIN_SAMPLES - 1, "2026-09-21T11:59:00Z")),
    )
    local = selection.reading_for(Route.LOCAL)
    assert local.disposition is Disposition.UNPREDICTABLE
    assert local.disposition is not Disposition.EXCLUDED
    assert selection.route is Route.DETERMINISTIC_HANDOFF


def test_expired_observations_make_a_candidate_unpredictable() -> None:
    """Case 8. A stale answer is a permanent setting, so it is not kept."""

    selection = a_selection(
        predictions=predictions_for(local=(10, MIN_SAMPLES * 2, "2026-09-21T09:00:00Z")),
    )
    assert selection.reading_for(Route.LOCAL).disposition is Disposition.UNPREDICTABLE
    assert selection.route is Route.DETERMINISTIC_HANDOFF


def test_a_prediction_that_misses_the_deadline_is_not_chosen() -> None:
    """Case 9. And it is a different word from unpredictable."""

    selection = a_selection(
        deadline_ms=100,
        predictions=predictions_for(local=(5000, MIN_SAMPLES, "2026-09-21T11:59:00Z")),
    )
    local = selection.reading_for(Route.LOCAL)
    assert local.disposition is Disposition.MISSES_DEADLINE
    assert local.predicted_ms == 5000
    assert selection.route is Route.DETERMINISTIC_HANDOFF


def test_nothing_predictable_claims_nothing_is_fastest() -> None:
    """The degradation reason, rather than a guess."""

    selection = a_selection(local_admitted=True, opt_in=NO_OPT_IN)
    assert selection.route is Route.DETERMINISTIC_HANDOFF
    assert "not gathered" in selection.reading_for(Route.DETERMINISTIC_HANDOFF).reason
    assert "fastest" not in selection.reason.lower() or "Nothing" in selection.reason


# -- 10-12: the comparison ------------------------------------------------


def test_remote_is_chosen_when_remote_is_sooner() -> None:
    """Case 10. What the operator asked for: use the faster permitted route."""

    selection = a_selection(
        force_remote_permitted=True,
        predictions=predictions_for(
            local=(800, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
            remote=(200, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
        )
    )
    assert selection.route is Route.REMOTE
    assert selection.reading_for(Route.LOCAL).disposition is Disposition.NOT_SOONEST


def test_local_is_chosen_when_local_is_sooner() -> None:
    """Case 11. `fastest-permitted` is not "prefer remote"."""

    selection = a_selection(
        force_remote_permitted=True,
        predictions=predictions_for(
            local=(200, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
            remote=(800, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
        )
    )
    assert selection.route is Route.LOCAL
    assert selection.reading_for(Route.REMOTE).disposition is Disposition.NOT_SOONEST


def test_a_tie_resolves_to_the_narrower_route() -> None:
    """Case 12. Stated, deterministic, and replayable."""

    selection = a_selection(
        force_remote_permitted=True,
        predictions=predictions_for(
            local=(300, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
            remote=(300, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
        )
    )
    assert selection.route is Route.LOCAL
    assert ROUTE_ORDER.index(Route.LOCAL) < ROUTE_ORDER.index(Route.REMOTE)
    assert "narrower" in selection.reading_for(Route.LOCAL).reason


def test_the_same_readings_give_the_same_route() -> None:
    """A decision that does not replay cannot be audited."""

    def once():
        return a_selection(
            force_remote_permitted=True,
            predictions=predictions_for(
                local=(300, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
                remote=(300, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
            )
        )

    assert once().as_event() == once().as_event()


# -- 13-14: after the decision --------------------------------------------


def test_a_withdrawal_after_selection_removes_the_route() -> None:
    """Case 13. Never served by the route the operator just withdrew."""

    selection = a_selection(
        force_remote_permitted=True,
        predictions=predictions_for(
            local=(800, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
            remote=(200, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
        ),
    )
    assert selection.route is Route.REMOTE
    decision = fallback_once(
        selection=selection,
        failed=Route.REMOTE,
        already_spent=False,
        still_permitted=(Route.DETERMINISTIC_HANDOFF, Route.LOCAL),
    )
    assert decision.route is Route.LOCAL
    assert decision.route is not Route.REMOTE


def test_exactly_one_fallback_after_a_timeout() -> None:
    """Case 14. The second failure is evidence, not a third chance."""

    selection = a_selection(
        force_remote_permitted=True,
        predictions=predictions_for(
            local=(800, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
            remote=(200, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
        ),
    )
    first = fallback_once(selection=selection, failed=Route.REMOTE, already_spent=False)
    assert first.route is Route.LOCAL and first.spent is True
    second = fallback_once(selection=selection, failed=Route.LOCAL, already_spent=True)
    assert second.route is Route.DETERMINISTIC_HANDOFF
    assert MAX_FALLBACKS == 1


def test_a_fallback_never_returns_to_the_route_that_failed() -> None:
    """A retry to the same provider is the same attempt again."""

    selection = a_selection(
        force_remote_permitted=True,
        predictions=predictions_for(
            local=(200, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
            remote=(800, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
        ),
    )
    for failed in (Route.LOCAL, Route.REMOTE):
        decision = fallback_once(selection=selection, failed=failed, already_spent=False)
        assert decision.route is not failed


def test_a_fallback_never_leaves_the_permitted_set() -> None:
    """Widening on failure is the direction that must be impossible."""

    selection = a_selection(
        predictions=predictions_for(local=(200, MIN_SAMPLES, "2026-09-21T11:59:00Z")),
    )
    assert Route.REMOTE not in selection.permitted
    decision = fallback_once(selection=selection, failed=Route.LOCAL, already_spent=False)
    assert decision.route is Route.DETERMINISTIC_HANDOFF
    assert decision.route in selection.permitted


# -- the word that must not exist -----------------------------------------


def test_there_is_no_completed_outcome() -> None:
    """Absent from the vocabulary, not forbidden by a check that could be edited."""

    assert "COMPLETED" not in {o.name for o in RequestOutcome}
    source = pathlib.Path(route_selection.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    enum_members = {
        node.targets[0].id
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id.isupper()
    }
    assert "COMPLETED" not in enum_members


@pytest.mark.parametrize("event", list(NEVER_ANSWERED))
def test_no_ending_but_answering_reports_the_route_as_having_answered(event) -> None:
    """Cancellation, failure, timeout, withdrawal and a policy change."""

    for fallback_available in (True, False):
        outcome = outcome_for(event, fallback_available=fallback_available)
        assert outcome is not RequestOutcome.ANSWERED


def test_answering_is_the_one_ending_that_answers() -> None:
    """Otherwise the test above passes by nothing ever answering."""

    assert outcome_for(TerminalEvent.ANSWERED, fallback_available=False) is (
        RequestOutcome.ANSWERED
    )


def test_every_terminal_event_is_accounted_for() -> None:
    assert set(NEVER_ANSWERED) == set(TerminalEvent) - {TerminalEvent.ANSWERED}


def test_a_sanitisation_that_did_not_hold_does_not_fall_back_to_another_remote() -> None:
    """Found by mutation: the branch was written and never driven (#98).

    A failed route can fall back when a fallback is left, because another
    might work. This sanitizer refusal did not fail a route: this
    node decided the thing must not leave. Trying a different remote with it
    is the same disclosure to a different party.
    """

    assert outcome_for(
        TerminalEvent.SANITIZER_FAILED, fallback_available=True
    ) is RequestOutcome.REFUSED
    assert outcome_for(
        TerminalEvent.SANITIZER_FAILED, fallback_available=False
    ) is RequestOutcome.REFUSED

    # And it really is the exception: a transport failure with a fallback
    # available does fall back, so the assertion above is not true of
    # everything.
    assert outcome_for(
        TerminalEvent.TLS_FAILED, fallback_available=True
    ) is RequestOutcome.FELL_BACK


def test_a_tls_failure_and_a_refusal_to_send_are_different_endings() -> None:
    """A provider up and answering with the wrong key is not a provider that
    is down, and neither is this node declining to send. Folding them into
    `FAILED` sends an operator to check whether a service is running -- which
    it is."""

    assert TerminalEvent.TLS_FAILED is not TerminalEvent.FAILED
    assert TerminalEvent.SANITIZER_FAILED is not TerminalEvent.FAILED
    assert TerminalEvent.NOT_ADVICE is not TerminalEvent.FAILED
    values = [event.value for event in TerminalEvent]
    assert len(values) == len(set(values)), "two endings share a word"


# -- the record ------------------------------------------------------------


def test_every_candidate_appears_with_a_reason() -> None:
    """An operator who cannot see why a candidate was not used cannot act on it."""

    selection = a_selection(
        force_remote_permitted=True,
        predictions=predictions_for(
            local=(200, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
            remote=(800, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
        ),
    )
    assert {r.candidate for r in selection.candidates} == {
        Route.LOCAL,
        Route.REMOTE,
        Route.DETERMINISTIC_HANDOFF,
    } - {Route.DETERMINISTIC_HANDOFF} | {selection.route}
    for reading in selection.candidates:
        assert reading.reason.strip()


def test_the_record_is_bounded_and_carries_no_request() -> None:
    selection = a_selection(
        force_remote_permitted=True,
        predictions=predictions_for(
            local=(200, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
            remote=(800, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
        ),
    )
    event = selection.as_event()
    assert len(event["candidates"]) <= len(Route)
    flattened = repr(event).lower()
    for forbidden in ("prompt", "body", "endpoint", "identifier", "evidence", "token", "secret"):
        assert forbidden not in flattened, forbidden


def test_a_decision_naming_a_route_it_did_not_consider_is_refused() -> None:
    with pytest.raises(SelectionRefused):
        Selection(
            route=Route.REMOTE,
            reason="r",
            candidates=(),
            profile=MioProfile.CORE,
            privacy_class=PrivacyClass.P0_PUBLIC,
            permitted=(),
        )


def test_a_candidate_with_no_reason_is_refused() -> None:
    from azazel_nexus.route_selection import CandidateReading

    with pytest.raises(SelectionRefused):
        CandidateReading(
            candidate=Route.LOCAL, disposition=Disposition.EXCLUDED, reason="  "
        )


# -- pure decision layer ---------------------------------------------------


def test_this_module_executes_nothing_and_reaches_nowhere() -> None:
    """No client, no socket, no HTTP, no TLS, no provider execution."""

    tree = ast.parse(pathlib.Path(route_selection.__file__).read_text(encoding="utf-8"))
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
        name.startswith(("run", "exec", "send", "launch", "start", "enforce"))
        for name in names
    ), sorted(names)


def test_no_decision_moves_the_edge_answer() -> None:
    """Over every acceptance case. M.I.O. is an advisory plane."""

    from azazel_nexus.edge_package import inspect as inspect_edge

    root = pathlib.Path("/nonexistent-edge-core-for-route-selection")

    def edge_answer():
        answer = inspect_edge(root)
        return (answer.ready, answer.presence.value, answer.state().ready)

    baseline = edge_answer()
    assert baseline == (False, "absent", False)
    for privacy_class in PrivacyClass:
        for profile in MioProfile:
            for local_admitted in (True, False):
                for opt_in in (consent(), NO_OPT_IN):
                    selection = a_selection(
                        profile=profile,
                        privacy_class=privacy_class,
                        local_admitted=local_admitted,
                        opt_in=opt_in,
                        predictions=predictions_for(
                            local=(200, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
                            remote=(200, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
                        ),
                    )
                    fallback_once(
                        selection=selection,
                        failed=selection.route,
                        already_spent=False,
                    )
                    for event in TerminalEvent:
                        outcome_for(event, fallback_available=True)
                    assert edge_answer() == baseline


def test_a_caller_cannot_widen_the_fallback_by_supplying_a_wider_set() -> None:
    """`still_permitted` may only narrow. A mutation showed it was not checked.

    `test_a_fallback_never_leaves_the_permitted_set` passed with the
    membership check removed, because with no `still_permitted` the narrowed
    set *is* the permitted set and the two conditions are redundant. The case
    that reaches the check is a caller passing a route the decision never
    permitted -- which is how a failure would become a reason to widen.
    """

    selection = a_selection(
        opt_in=NO_OPT_IN,  # remote was never permitted for this request
        predictions=predictions_for(local=(200, MIN_SAMPLES, "2026-09-21T11:59:00Z")),
    )
    assert Route.REMOTE not in selection.permitted

    decision = fallback_once(
        selection=selection,
        failed=Route.LOCAL,
        already_spent=False,
        # A caller offering remote anyway. It was not permitted when the
        # route was chosen, so it must not be reachable now.
        still_permitted=(Route.DETERMINISTIC_HANDOFF, Route.LOCAL, Route.REMOTE),
    )
    assert decision.route is not Route.REMOTE
    assert decision.route is Route.DETERMINISTIC_HANDOFF


def test_a_route_withdrawn_between_the_decision_and_the_failure_is_not_used() -> None:
    """The narrowing half, with a route that was permitted and no longer is.

    The earlier withdrawal test could not tell: the withdrawn route was also
    the one that failed, so excluding it twice looked the same as excluding
    it once. Here `local` fails and `remote` is the one withdrawn, so the
    only thing keeping the request off remote is the narrowing.
    """

    selection = a_selection(
        force_remote_permitted=True,
        predictions=predictions_for(
            local=(200, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
            remote=(800, MIN_SAMPLES, "2026-09-21T11:59:00Z"),
        ),
    )
    assert selection.route is Route.LOCAL
    assert Route.REMOTE in selection.permitted

    # Without narrowing, remote is a perfectly good fallback target here.
    unnarrowed = fallback_once(
        selection=selection, failed=Route.LOCAL, already_spent=False
    )
    assert unnarrowed.route is Route.REMOTE

    # With the opt-in withdrawn, it is not.
    withdrawn = fallback_once(
        selection=selection,
        failed=Route.LOCAL,
        already_spent=False,
        still_permitted=(Route.DETERMINISTIC_HANDOFF, Route.LOCAL),
    )
    assert withdrawn.route is not Route.REMOTE
    assert withdrawn.route is Route.DETERMINISTIC_HANDOFF


@pytest.mark.parametrize("fallback_available", [False, True])
def test_no_answer_is_not_a_failure_and_never_falls_back(fallback_available) -> None:
    assert TerminalEvent.NO_ANSWER is not TerminalEvent.FAILED
    assert outcome_for(
        TerminalEvent.NO_ANSWER, fallback_available=fallback_available
    ) is RequestOutcome.REFUSED
