"""CORE + Lite, as nine configurations rather than as one happy path (#56, E5).

The individual features have their own tests, and each is correct on its own.
This file is about what they are like **together**, and in particular about
what happens when one of them is not there -- because a node running all three
is the configuration this product is least likely to be deployed in.

Three things are established here and nowhere else:

*Nine configurations, each with a stated expectation.* Not "it works", but
which state each feature reports and what continues under it.

*The privilege boundary survives composition.* Each feature is advisory on its
own; the question is whether chaining them produces a path to enforcement that
none of them has alone.

*A failure propagates no further than the feature that had it.* Losing any one
never narrows the deterministic path, and degradation only ever narrows.

What this file **does not** establish: anything about real hardware. It is
software integration, and `docs/hardware-gates.md` holds what is still owed.
"""

from __future__ import annotations

import ast
import json
import pathlib

import pytest

from azazel_nexus import cognition as cognition_module
from azazel_nexus import decoy as decoy_module
from azazel_nexus import integration as integration_module
from azazel_nexus import lite_service as lite_service_module
from azazel_nexus import routing as routing_module
from azazel_nexus import sanitizer as sanitizer_module
from azazel_nexus.capability import CapabilityState
from azazel_nexus.cognition import CognitionState, RemoteState, read_cognition
from azazel_nexus.compatibility import TestedTupleSet
from azazel_nexus.decoy import DecoyState, DecoyStatus, IsolationCheck, evaluate
from azazel_nexus.functional_readiness import (
    CONTROL_PLANE_ONLY,
    READINESS,
    Readiness,
)
from azazel_nexus.integration import MISSING, EdgePresence, build_view
from azazel_nexus.lite_service import LiteReading, LiteState
from azazel_nexus.resource_profile import ResourceProfile
from azazel_nexus.routing import (
    ROUTE_ORDER,
    Budgets,
    FallbackTrigger,
    RequestEnvelope,
    Route,
    fallback_for,
    select_route,
)
from azazel_nexus.sanitizer import PrivacyClass

#: The four modules a Lite node is composed of. Scanned together, because a
#: boundary that holds in each and not across them is not a boundary.
LITE_MODULES = (
    lite_service_module,
    cognition_module,
    decoy_module,
    sanitizer_module,
    routing_module,
    integration_module,
)


def knowledge(state: LiteState) -> LiteReading:
    return LiteReading(state=state, reason=f"knowledge is {state.value}", generation=1)


def decoy_at(state: DecoyState) -> DecoyStatus:
    return DecoyStatus(decoy="decoy-a", state=state, reason=f"decoy is {state.value}")


def absent_decoy() -> DecoyStatus:
    return evaluate(
        "decoy-a",
        catalogue=None,
        commissioning=None,
        isolation=IsolationCheck(passed=None),
    )


def cognition(**overrides):
    call = {"profile": ResourceProfile.LITE, "tested": TestedTupleSet(), "host": None}
    call.update(overrides)
    return read_cognition([], **call)


@pytest.fixture()
def functional(monkeypatch):
    """Declare the embedded features functional for one test.

    The nine configurations describe what each feature reports **when it can
    report anything**. Today all three are `control-plane-only`, which would
    collapse the table to one value and stop it testing the composition at
    all. The `control-plane-only` behaviour itself is asserted separately,
    against the real declarations.
    """

    for feature in READINESS:
        monkeypatch.setitem(
            READINESS,
            feature,
            Readiness(feature=feature, functional=True, missing="", issue=""),
        )


def view(*, knowledge_reading, decoy_status, capability=CapabilityState.CORE, **kwargs):
    return build_view(
        capability=capability,
        knowledge=knowledge_reading,
        cognition=kwargs.pop("cognition_reading", cognition()),
        decoy=decoy_status,
        edge=kwargs.pop("edge", EdgePresence.ABSENT),
        **kwargs,
    )


# -- the nine configurations ------------------------------------------------
#
# Each row is (name, knowledge reading, decoy status, expected knowledge word,
# expected deception word). The expectations are written out rather than
# derived, so that a change in the mapping is a change to this table.

CONFIGURATIONS = [
    ("knowledge only", knowledge(LiteState.AVAILABLE), absent_decoy(), "available", "unavailable"),
    ("mio only", None, absent_decoy(), MISSING, "unavailable"),
    ("deception only", None, decoy_at(DecoyState.EXPOSED), MISSING, "available"),
    (
        "all three running",
        knowledge(LiteState.AVAILABLE),
        decoy_at(DecoyState.EXPOSED),
        "available",
        "available",
    ),
    ("none present", knowledge(LiteState.UNAVAILABLE), absent_decoy(), "unavailable", "unavailable"),
    ("knowledge stale", knowledge(LiteState.STALE), absent_decoy(), "stale", "unavailable"),
    (
        "knowledge quarantined",
        knowledge(LiteState.QUARANTINED),
        absent_decoy(),
        "quarantined",
        "unavailable",
    ),
    (
        "decoy quarantined",
        knowledge(LiteState.AVAILABLE),
        decoy_at(DecoyState.QUARANTINED),
        "available",
        "quarantined",
    ),
    (
        "remote not permitted",
        knowledge(LiteState.AVAILABLE),
        absent_decoy(),
        "available",
        "unavailable",
    ),
]


@pytest.mark.parametrize(
    "name, knowledge_reading, decoy_status, knowledge_word, deception_word",
    CONFIGURATIONS,
)
def test_each_configuration_reports_the_state_it_is_in(
    name, knowledge_reading, decoy_status, knowledge_word, deception_word, functional
) -> None:
    built = view(knowledge_reading=knowledge_reading, decoy_status=decoy_status)
    assert built.row("freshness", "knowledge_lite").value == knowledge_word, name
    assert built.row("freshness", "deception_lite").value == deception_word, name


@pytest.mark.parametrize(
    "name, knowledge_reading, decoy_status, _k, _d", CONFIGURATIONS
)
def test_every_configuration_keeps_the_deterministic_path(
    name, knowledge_reading, decoy_status, _k, _d
) -> None:
    """The one invariant that holds across all nine."""

    built = view(knowledge_reading=knowledge_reading, decoy_status=decoy_status)
    assert set(built.continues) >= {"audit", "operator plane", "deterministic explanations"}, name
    for row in built.rows:
        assert row.continues, f"{name}: {row.axis} lists nothing continuing"


@pytest.mark.parametrize(
    "name, knowledge_reading, decoy_status, _k, _d", CONFIGURATIONS
)
def test_no_configuration_claims_enforcement_or_baseline_readiness(
    name, knowledge_reading, decoy_status, _k, _d
) -> None:
    built = view(knowledge_reading=knowledge_reading, decoy_status=decoy_status)
    assert built.enforcement_capable is False, name
    assert built.baseline_ready is False, name


# -- what each configuration specifically must not do ----------------------


def test_a_node_with_none_of_the_three_is_the_designed_node_not_a_defect(functional) -> None:
    """The configuration this product is most likely to ship in.

    Both embedded features are present as code and hold nothing. That is
    `unavailable`, and a screen of defects would tell an operator to fix an
    installation that is correct.
    """

    built = view(
        knowledge_reading=knowledge(LiteState.UNAVAILABLE), decoy_status=absent_decoy()
    )
    assert built.defects == ()
    assert built.row("freshness", "knowledge_lite").value == "unavailable"
    assert built.row("freshness", "deception_lite").value == "unavailable"
    assert built.row("capability").value == "CORE"


def test_a_stale_cache_is_visible_as_stale_and_not_served_as_current(functional) -> None:
    built = view(knowledge_reading=knowledge(LiteState.STALE), decoy_status=absent_decoy())
    assert built.row("freshness", "knowledge_lite").value == "stale"
    # `stale` sources no capability, so nothing downstream can treat it as
    # content that may be used.
    assert built.row("knowledge_supplier", "knowledge").value == "none"


def test_a_quarantined_cache_supplies_nothing(functional) -> None:
    built = view(
        knowledge_reading=knowledge(LiteState.QUARANTINED), decoy_status=absent_decoy()
    )
    assert built.row("freshness", "knowledge_lite").value == "quarantined"
    assert built.row("knowledge_supplier", "knowledge").value == "none"


def test_a_quarantined_decoy_leaves_the_rest_of_the_node_working(functional) -> None:
    """The failure is the decoy's. It stays the decoy's."""

    built = view(
        knowledge_reading=knowledge(LiteState.AVAILABLE),
        decoy_status=decoy_at(DecoyState.QUARANTINED),
    )
    assert built.row("freshness", "deception_lite").value == "quarantined"
    assert built.row("freshness", "knowledge_lite").value == "available"
    assert built.row("knowledge_supplier", "knowledge").value == "Knowledge Lite"
    assert "Knowledge Lite advice" in built.continues


def test_remote_is_disabled_rather_than_attempted_in_every_configuration() -> None:
    for name, knowledge_reading, decoy_status, _k, _d in CONFIGURATIONS:
        built = view(knowledge_reading=knowledge_reading, decoy_status=decoy_status)
        assert "remote M.I.O. disabled" in built.row("cognition_route", "mio").value, name


def test_a_node_with_no_provider_never_routes_a_request_off_the_node() -> None:
    decision = select_route(
        envelope=RequestEnvelope(
            correlation_id="c",
            privacy_class=PrivacyClass.P1_SANITIZED,
            deadline="2099-01-01T00:00:00Z",
            expiry="2099-01-01T00:00:00Z",
        ),
        admissions=[],
        remote_enabled=False,
        now="2026-09-21T00:00:00Z",
        budgets=Budgets(
            max_request_bytes=1,
            max_response_bytes=1,
            requests_per_hour=1,
            deadline_seconds=1,
            max_concurrency=1,
        ),
    )
    assert decision.route is Route.DETERMINISTIC_HANDOFF
    assert decision.blocks_deterministic_path() is False


# -- the privilege boundary survives composition ---------------------------


def test_no_lite_module_reaches_the_privileged_runtime() -> None:
    """The one-way dependency, checked across all six together.

    A boundary that holds in each module and not across them is not a
    boundary: the composition is where a path appears that none of the parts
    has alone.
    """

    for module in LITE_MODULES:
        tree = ast.parse(pathlib.Path(module.__file__).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                assert not name.startswith("azazel_nexus_runtime"), (
                    f"{module.__name__} imports {name}"
                )


def test_no_lite_module_can_open_a_socket_or_start_a_process() -> None:
    forbidden = {
        "socket", "ssl", "http", "urllib", "requests", "httpx",
        "subprocess", "multiprocessing", "ctypes", "signal", "pty",
    }
    for module in LITE_MODULES:
        tree = ast.parse(pathlib.Path(module.__file__).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imported.add(node.module.split(".")[0])
        assert imported & forbidden == set(), f"{module.__name__}: {imported & forbidden}"


def test_no_lite_module_defines_a_verb_that_acts() -> None:
    acting = {
        "run", "exec", "execute", "apply", "enforce", "invoke", "launch",
        "send", "dispatch", "start", "bind", "listen", "spawn", "redirect",
    }
    offenders: list[str] = []
    for module in LITE_MODULES:
        tree = ast.parse(pathlib.Path(module.__file__).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if any(
                isinstance(d, ast.Name) and d.id == "property" for d in node.decorator_list
            ):
                continue
            if node.name.lstrip("_").split("_")[0] in acting:
                offenders.append(f"{module.__name__}.{node.name}")
    assert offenders == [], offenders


def test_the_composed_output_is_data_and_carries_no_callable() -> None:
    """Chained end to end, the result is JSON. There is nothing to invoke.

    This is the composition check the static scans cannot make: the three
    features feed one view, and what comes out is a document.
    """

    built = view(
        knowledge_reading=knowledge(LiteState.AVAILABLE),
        decoy_status=decoy_at(DecoyState.EXPOSED),
        capability=CapabilityState.LITE,
    )
    event = built.as_event()
    text = json.dumps(event)
    assert json.loads(text) == event


def test_the_capability_state_grants_nothing_in_any_of_the_three_values() -> None:
    """`FULL -> LITE -> CORE` is a capability state, never an authority."""

    for capability in (CapabilityState.CORE, CapabilityState.LITE, CapabilityState.FULL):
        built = view(
            knowledge_reading=knowledge(LiteState.AVAILABLE),
            decoy_status=decoy_at(DecoyState.EXPOSED),
            capability=capability,
        )
        assert built.enforcement_capable is False
        assert built.baseline_ready is False
        assert "Edge deterministic decisions" not in built.continues


def test_an_exposed_decoy_is_an_observation_surface_in_every_configuration() -> None:
    for capability in (CapabilityState.CORE, CapabilityState.LITE, CapabilityState.FULL):
        status = decoy_at(DecoyState.EXPOSED)
        assert status.redirect_eligible is False
        built = view(
            knowledge_reading=knowledge(LiteState.AVAILABLE),
            decoy_status=status,
            capability=capability,
        )
        assert built.as_event()["enforcement_capable"] is False


# -- a failure propagates no further than the feature that had it ----------


@pytest.mark.parametrize(
    "failing",
    [
        {"knowledge_reading": knowledge(LiteState.QUARANTINED), "decoy_status": absent_decoy()},
        {"knowledge_reading": knowledge(LiteState.AVAILABLE), "decoy_status": decoy_at(DecoyState.QUARANTINED)},
        {"knowledge_reading": None, "decoy_status": absent_decoy()},
        {"knowledge_reading": None, "decoy_status": None},
    ],
)
def test_any_feature_failing_leaves_the_deterministic_path_intact(failing: dict) -> None:
    built = view(**failing)
    assert set(built.continues) >= {"audit", "operator plane", "deterministic explanations"}
    for row in built.rows:
        assert row.continues


def test_a_failure_in_one_feature_does_not_change_another_feature_s_row() -> None:
    """Isolation, as a difference rather than as a description."""

    healthy = view(
        knowledge_reading=knowledge(LiteState.AVAILABLE),
        decoy_status=decoy_at(DecoyState.EXPOSED),
    )
    decoy_broken = view(
        knowledge_reading=knowledge(LiteState.AVAILABLE),
        decoy_status=decoy_at(DecoyState.QUARANTINED),
    )
    assert healthy.row("freshness", "knowledge_lite").value == decoy_broken.row(
        "freshness", "knowledge_lite"
    ).value
    assert healthy.row("cognition_route", "mio").value == decoy_broken.row(
        "cognition_route", "mio"
    ).value


@pytest.mark.parametrize("trigger", list(FallbackTrigger))
@pytest.mark.parametrize("from_route", list(Route))
def test_degradation_only_ever_narrows(trigger: FallbackTrigger, from_route: Route) -> None:
    """Restated here because it is a property of the composition too.

    A failure in any feature may reduce what the node can do. It may never
    widen it, and a widening is the one direction that would turn a fault into
    a reason to disclose more.
    """

    landed = fallback_for(trigger, from_route=from_route)
    assert ROUTE_ORDER.index(landed.ceiling) <= ROUTE_ORDER.index(from_route)


def test_losing_everything_at_once_still_reports_six_axes() -> None:
    """The worst case is still a readable screen, not an exception."""

    built = view(knowledge_reading=None, decoy_status=None)
    assert len(built.defects) == 2
    assert {row.axis for row in built.rows} == set(integration_module.AXES)
    assert built.continues


# -- what this file does not establish -------------------------------------


def test_this_file_makes_no_claim_about_hardware() -> None:
    """Stated as a test so it is read.

    Every assertion above runs in this process against in-memory state. None
    of it establishes that a unit was masked, that a bridge refused to
    forward, that a model fits in the memory a host actually has, or that a
    real Edge Core package verifies on a real host -- `HG-01` through `HG-07`.
    """

    gates = pathlib.Path(integration_module.__file__).parents[2] / "docs" / "hardware-gates.md"
    text = gates.read_text(encoding="utf-8")
    for gate in ("HG-01", "HG-02", "HG-03", "HG-04", "HG-05", "HG-06", "HG-07"):
        assert gate in text, f"{gate} is not registered"
    assert "hardware-unverified" in text
    assert "unmeasured" in text


# -- what every configuration reports today --------------------------------


@pytest.mark.parametrize(
    "name, knowledge_reading, decoy_status, _k, _d", CONFIGURATIONS
)
def test_today_every_configuration_reports_control_plane_only(
    name, knowledge_reading, decoy_status, _k, _d
) -> None:
    """Run against the real declarations, not the fixture.

    Nine configurations of *what is there*, and on every node this repository
    can build the answer is the same: the control plane is implemented and the
    functional layer is not. The table above describes what each one will
    report once that changes; this is what they report now.
    """

    built = view(knowledge_reading=knowledge_reading, decoy_status=decoy_status)
    if knowledge_reading is not None:
        assert built.row("freshness", "knowledge_lite").value == CONTROL_PLANE_ONLY, name
    if decoy_status is not None:
        assert built.row("freshness", "deception_lite").value == CONTROL_PLANE_ONLY, name
    assert built.row("knowledge_supplier", "knowledge").value == "none", name
    assert built.row("deception_supplier", "deception").value == "none", name


@pytest.mark.parametrize(
    "name, knowledge_reading, decoy_status, _k, _d", CONFIGURATIONS
)
def test_no_configuration_supplies_a_capability_it_cannot_provide(
    name, knowledge_reading, decoy_status, _k, _d
) -> None:
    """The reason the override exists.

    A cache holding a verified artifact still cannot answer a query, because
    nothing can read the artifact. Reporting it as a supplier would be a claim
    about a capability the node does not have.
    """

    built = view(knowledge_reading=knowledge_reading, decoy_status=decoy_status)
    assert "Knowledge Lite advice" not in built.continues, name
    assert "decoy observation" not in built.continues, name
