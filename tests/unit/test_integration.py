"""The six axes an operator reads (#55, E4).

Three claims, each with a way of passing for the wrong reason.

*The axes are independent.* A test that builds one view and reads six values
proves nothing about independence. Each input here is varied on its own and
the other five axes are asserted unchanged.

*Five words stay five words.* `disabled` / `unavailable` / `stale` /
`quarantined` / `missing` call for five different operator actions. A test
that checked only that each word appears somewhere would pass for a renderer
that prints two of them for one condition.

*Nothing claims what it has not got.* `enforcement_capable` and
`baseline_ready` are asserted `False` over **every combination** of the other
five axes, not over the convenient one -- and no row claims Edge decisions
continue on a node whose Edge is absent.
"""

from __future__ import annotations

import itertools
import json

import pytest

from azazel_nexus.capability import CapabilityState
from azazel_nexus.cognition import (
    AdmissionGate,
    CognitionReading,
    CognitionState,
    ProviderAdmission,
    RemoteState,
)
from azazel_nexus.decoy import DecoyState, DecoyStatus
from azazel_nexus.integration import (
    AXES,
    MISSING,
    NEXUS_ALWAYS,
    Axis,
    EdgePresence,
    IntegrationRefused,
    Supplier,
    build_view,
)
from azazel_nexus.lite_service import LiteReading, LiteState

REFUSED = ProviderAdmission(
    provider="local-model",
    admitted=False,
    failed_gate=AdmissionGate.RESOURCE_TOPOLOGY,
    reason="the Core reserve is unmeasured",
)


def a_cognition(**overrides) -> CognitionReading:
    fields = {
        "state": CognitionState.CORE_ONLY,
        "remote": RemoteState.DISABLED,
        "resource_reason": "envelope 'lite'; headroom undecidable",
        "topology_reason": "no commissioned egress path is required",
        "asset_reason": "1 declared provider, none admitted",
        "trust_health_reason": "no provider is running",
        "admissions": (REFUSED,),
    }
    fields.update(overrides)
    return CognitionReading(**fields)


def a_knowledge(state: LiteState = LiteState.UNAVAILABLE) -> LiteReading:
    return LiteReading(state=state, reason=f"knowledge is {state.value}", generation=1)


def a_decoy(state: DecoyState = DecoyState.DISABLED) -> DecoyStatus:
    return DecoyStatus(decoy="decoy-a", state=state, reason=f"decoy is {state.value}")


def a_view(**overrides):
    call = {
        "capability": CapabilityState.CORE,
        "knowledge": a_knowledge(),
        "cognition": a_cognition(),
        "decoy": a_decoy(),
        "edge": EdgePresence.ABSENT,
        "knowledge_peer": False,
        "deception_peer": False,
    }
    call.update(overrides)
    return build_view(**call)


def _values(view) -> dict[tuple[str, str], str]:
    return {(row.axis, row.subject): row.value for row in view.rows}


# -- six axes, all present -------------------------------------------------


def test_every_axis_is_reported() -> None:
    reported = {row.axis for row in a_view().rows}
    assert reported == set(AXES)
    assert len(AXES) == 6


def test_a_view_missing_an_axis_is_refused() -> None:
    """An axis nobody reports is a dimension nobody can act on."""

    from azazel_nexus.integration import IntegrationView

    rows = tuple(row for row in a_view().rows if row.axis != "edge")
    with pytest.raises(IntegrationRefused) as caught:
        IntegrationView(rows=rows, edge=EdgePresence.ABSENT)
    assert "edge" in str(caught.value)


def test_both_embedded_features_get_their_own_freshness_row() -> None:
    subjects = {row.subject for row in a_view().rows if row.axis == "freshness"}
    assert subjects == {"knowledge_lite", "deception_lite"}


# -- the axes are independent ----------------------------------------------


@pytest.mark.parametrize(
    "override, moved",
    [
        ({"capability": CapabilityState.LITE}, {("capability", "")}),
        ({"edge": EdgePresence.UNKNOWN}, {("edge", "edge_core")}),
        ({"knowledge": a_knowledge(LiteState.QUARANTINED)}, {("freshness", "knowledge_lite")}),
        ({"decoy": a_decoy(DecoyState.QUARANTINED)}, {("freshness", "deception_lite")}),
        ({"knowledge_peer": True}, {("knowledge_supplier", "knowledge")}),
        ({"deception_peer": True}, {("deception_supplier", "deception")}),
        (
            {"cognition": a_cognition(remote=RemoteState.UNAVAILABLE)},
            {("cognition_route", "mio")},
        ),
    ],
)
def test_one_input_moves_one_axis(override: dict, moved: set) -> None:
    """Independence, as a difference rather than as a description."""

    before = _values(a_view())
    after = _values(a_view(**override))
    changed = {key for key in before if before[key] != after[key]}
    assert changed == moved, f"expected {moved} to move, got {changed}"


def test_an_available_knowledge_cache_moves_both_its_freshness_and_its_supplier() -> None:
    """Two axes move because two facts changed, and the test says which.

    Deliberately not folded into the table above: `available` is the one
    knowledge state that also makes Knowledge Lite a supplier, and a reader
    should see that stated rather than discover it as an exception.
    """

    before = _values(a_view())
    after = _values(a_view(knowledge=a_knowledge(LiteState.AVAILABLE)))
    changed = {key for key in before if before[key] != after[key]}
    assert changed == {("freshness", "knowledge_lite"), ("knowledge_supplier", "knowledge")}


def test_an_exposed_decoy_moves_both_its_freshness_and_its_supplier() -> None:
    before = _values(a_view())
    after = _values(a_view(decoy=a_decoy(DecoyState.EXPOSED)))
    changed = {key for key in before if before[key] != after[key]}
    assert changed == {("freshness", "deception_lite"), ("deception_supplier", "deception")}


# -- five words stay five words --------------------------------------------


def test_the_five_state_words_are_five_distinct_words() -> None:
    words = {
        RemoteState.DISABLED.value,
        LiteState.UNAVAILABLE.value,
        LiteState.STALE.value,
        LiteState.QUARANTINED.value,
        MISSING,
    }
    assert len(words) == 5, words


@pytest.mark.parametrize(
    "state, expected",
    [
        (LiteState.AVAILABLE, "available"),
        (LiteState.STALE, "stale"),
        (LiteState.UNAVAILABLE, "unavailable"),
        (LiteState.QUARANTINED, "quarantined"),
    ],
)
def test_each_knowledge_state_renders_as_its_own_word(state, expected: str) -> None:
    view = a_view(knowledge=a_knowledge(state))
    assert view.row("freshness", "knowledge_lite").value == expected


def test_a_quarantined_decoy_keeps_its_own_word() -> None:
    """"We had it and it is not trustworthy" is what the vocabulary is for."""

    view = a_view(decoy=a_decoy(DecoyState.QUARANTINED))
    assert view.row("freshness", "deception_lite").value == "quarantined"
    assert view.row("freshness", "deception_lite").value != "unavailable"


@pytest.mark.parametrize("state", [DecoyState.DISABLED, DecoyState.ELIGIBLE])
def test_a_decoy_that_is_not_listening_is_unavailable_and_says_which(state) -> None:
    """Both mean nothing is listening; the decoy's own reason distinguishes."""

    row = a_view(decoy=a_decoy(state)).row("freshness", "deception_lite")
    assert row.value == "unavailable"
    assert state.value in row.reason


def test_remote_disabled_and_remote_unavailable_render_differently() -> None:
    disabled = a_view().row("cognition_route", "mio").value
    unavailable = a_view(cognition=a_cognition(remote=RemoteState.UNAVAILABLE)).row(
        "cognition_route", "mio"
    ).value
    assert "disabled" in disabled and "unavailable" in unavailable
    assert disabled != unavailable


# -- an absent peer and an absent embedded feature are not the same fact ---


def test_an_absent_embedded_feature_is_missing_and_a_defect() -> None:
    view = a_view(knowledge=None)
    row = view.row("freshness", "knowledge_lite")
    assert row.value == MISSING
    assert row.defect is True
    assert "defect" in row.reason
    assert view.defects == (row,)


def test_an_absent_peer_is_unavailable_and_not_a_defect() -> None:
    """A node with no peers is the designed node, not a degraded one."""

    view = a_view()
    row = view.row("knowledge_supplier", "knowledge")
    assert row.defect is False
    assert "unavailable, not a defect" in row.reason
    assert view.defects == ()


def test_the_two_absences_never_render_as_one_word() -> None:
    absent_peer = a_view().row("knowledge_supplier", "knowledge").value
    absent_feature = a_view(knowledge=None).row("freshness", "knowledge_lite").value
    assert absent_peer != absent_feature
    assert absent_feature == MISSING
    assert absent_peer == Supplier.NONE.value


def test_both_embedded_features_can_be_missing_independently() -> None:
    assert len(a_view(knowledge=None).defects) == 1
    assert len(a_view(decoy=None).defects) == 1
    assert len(a_view(knowledge=None, decoy=None).defects) == 2


# -- what continues is not optional ----------------------------------------


def test_every_row_says_what_continues() -> None:
    for row in a_view().rows:
        assert row.continues, row.axis


def test_a_row_with_nothing_continuing_is_refused() -> None:
    with pytest.raises(IntegrationRefused) as caught:
        Axis(axis="edge", subject="x", value="v", reason="r", continues=())
    assert "it is doing its job" in str(caught.value)


@pytest.mark.parametrize("axis", list(AXES))
def test_a_row_without_a_reason_is_refused(axis: str) -> None:
    with pytest.raises(IntegrationRefused) as caught:
        Axis(axis=axis, subject="x", value="v", reason="  ", continues=("audit",))
    assert "reads as agreement" in str(caught.value)


def test_a_row_on_an_unknown_axis_is_refused() -> None:
    with pytest.raises(IntegrationRefused):
        Axis(axis="vibes", subject="", value="v", reason="r", continues=("audit",))


def test_the_view_gathers_what_continues_across_every_axis() -> None:
    assert set(NEXUS_ALWAYS) <= set(a_view().continues)


def test_an_available_cache_adds_its_own_continuation() -> None:
    assert "Knowledge Lite advice" in a_view(knowledge=a_knowledge(LiteState.AVAILABLE)).continues
    assert "Knowledge Lite advice" not in a_view().continues


def test_an_exposed_decoy_adds_its_own_continuation() -> None:
    assert "decoy observation" in a_view(decoy=a_decoy(DecoyState.EXPOSED)).continues
    assert "decoy observation" not in a_view().continues


def test_a_local_provider_adds_its_own_continuation() -> None:
    local = a_view(cognition=a_cognition(state=CognitionState.LOCAL))
    assert "local M.I.O. explanations" in local.continues
    assert "local M.I.O. explanations" not in a_view().continues


# -- nothing claims what it has not got ------------------------------------

_COMBINATIONS = list(
    itertools.product(
        [CapabilityState.CORE, CapabilityState.LITE, CapabilityState.FULL],
        [None, a_knowledge(LiteState.AVAILABLE), a_knowledge(LiteState.QUARANTINED)],
        [None, a_decoy(DecoyState.EXPOSED), a_decoy(DecoyState.QUARANTINED)],
        [True, False],
    )
)


@pytest.mark.parametrize("capability, knowledge, decoy, peers", _COMBINATIONS)
@pytest.mark.parametrize("edge", [EdgePresence.ABSENT, EdgePresence.UNKNOWN])
def test_nothing_is_enforcement_capable_or_baseline_ready_without_edge(
    capability, knowledge, decoy, peers, edge
) -> None:
    """Every combination of the other five axes. Not the convenient one."""

    view = a_view(
        capability=capability,
        knowledge=knowledge,
        decoy=decoy,
        edge=edge,
        knowledge_peer=peers,
        deception_peer=peers,
    )
    assert view.enforcement_capable is False
    assert view.baseline_ready is False
    assert view.as_event()["enforcement_capable"] is False
    assert view.as_event()["baseline_ready"] is False


@pytest.mark.parametrize("edge", [EdgePresence.ABSENT, EdgePresence.UNKNOWN])
def test_no_row_claims_edge_decisions_continue_while_edge_is_not_ready(edge) -> None:
    """The reassurance an operator most wants, and least may be given falsely."""

    view = a_view(edge=edge)
    assert "Edge deterministic decisions" not in view.continues
    for row in view.rows:
        assert "Edge deterministic decisions" not in row.continues


def test_a_verified_ready_edge_is_the_only_thing_that_grants() -> None:
    """So the tests above are about the evidence and not about never granting.

    Nothing in this product produces `verified-ready` -- #44 -- so this is the
    only place it appears, and it appears to prove the check is a check.
    """

    view = a_view(edge=EdgePresence.VERIFIED_READY)
    assert view.enforcement_capable is True
    assert view.baseline_ready is True
    assert "Edge deterministic decisions" in view.continues


def test_the_edge_reason_names_what_is_not_claimed() -> None:
    for edge in (EdgePresence.ABSENT, EdgePresence.UNKNOWN):
        reason = a_view(edge=edge).row("edge").reason
        assert "not claimed" in reason
    assert "never grants" in a_view(edge=EdgePresence.UNKNOWN).row("edge").reason


# -- the audit event -------------------------------------------------------


def test_the_view_event_carries_every_axis_and_both_claims() -> None:
    event = a_view().as_event()
    assert event["event_type"] == "nexus.integration.view"
    assert {row["axis"] for row in event["rows"]} == set(AXES)
    assert event["enforcement_capable"] is False
    assert event["baseline_ready"] is False
    assert event["edge"] == "absent"
    assert set(NEXUS_ALWAYS) <= set(event["continues"])


def test_the_view_event_is_serialisable() -> None:
    json.dumps(a_view(knowledge=None, decoy=None).as_event())


def test_the_event_marks_a_defect_row_as_one() -> None:
    event = a_view(knowledge=None).as_event()
    defects = [row for row in event["rows"] if row["defect"]]
    assert len(defects) == 1
    assert defects[0]["value"] == MISSING
