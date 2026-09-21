"""Route selection and the fallback table (#5, E2).

The two invariants are checked over **every** trigger and **every** route
pairing, not over a representative one. A fallback that widened the route
would turn a failure into a reason to disclose more, and the only way to know
that cannot happen is to try all of them.
"""

from __future__ import annotations

import ast
import itertools
import json
import pathlib

import pytest

from azazel_nexus import routing as routing_module
from azazel_nexus.cognition import AdmissionGate, ProviderAdmission
from azazel_nexus.degradation import RETENTION_ORDER, UNDROPPABLE
from azazel_nexus.routing import (
    FALLBACKS,
    PROTECTED_FROM_SHEDDING,
    ROUTE_ORDER,
    SHEDDING_ORDER,
    Budgets,
    FallbackTrigger,
    RequestEnvelope,
    Route,
    fallback_for,
    select_route,
)
from azazel_nexus.sanitizer import NEVER_REMOTE, PrivacyClass

NOW = "2026-09-21T00:00:00Z"
LATER = "2026-09-21T01:00:00Z"

BUDGETS = Budgets(
    max_request_bytes=16384,
    max_response_bytes=65536,
    requests_per_hour=20,
    deadline_seconds=20,
    max_concurrency=1,
)

ADMITTED = ProviderAdmission(
    provider="local-model", admitted=True, failed_gate=None, reason="hypothetical"
)
REFUSED = ProviderAdmission(
    provider="local-model",
    admitted=False,
    failed_gate=AdmissionGate.RESOURCE_TOPOLOGY,
    reason="the Core reserve is unmeasured",
)


def an_envelope(**overrides) -> RequestEnvelope:
    fields = {
        "correlation_id": "corr-1",
        "privacy_class": PrivacyClass.P1_SANITIZED,
        "deadline": LATER,
        "expiry": LATER,
    }
    fields.update(overrides)
    return RequestEnvelope(**fields)


def route(**overrides):
    call = {
        "envelope": an_envelope(),
        "admissions": [REFUSED],
        "remote_enabled": False,
        "now": NOW,
        "budgets": BUDGETS,
        "counters": {},
    }
    call.update(overrides)
    return select_route(**call)


# -- the product path today ------------------------------------------------


def test_with_no_admitted_provider_the_deterministic_handoff_answers() -> None:
    decision = route()
    assert decision.route is Route.DETERMINISTIC_HANDOFF
    assert "never removed" in decision.reason


def test_the_refused_provider_does_not_count_as_admitted() -> None:
    """The gate that cannot pass is not a gate that quietly passes."""

    assert route(admissions=[REFUSED, REFUSED]).route is Route.DETERMINISTIC_HANDOFF
    assert route(admissions=[REFUSED]).inputs["admitted_providers"] == []


# -- the ladder, reached with a hypothetical admitted provider -------------


def test_an_admitted_provider_with_remote_off_routes_local() -> None:
    decision = route(admissions=[ADMITTED], remote_enabled=False)
    assert decision.route is Route.LOCAL
    assert "nothing leaves" in decision.reason


@pytest.mark.parametrize("privacy_class", sorted(NEVER_REMOTE, key=lambda c: c.value))
def test_a_never_remote_class_stays_local_even_with_remote_enabled(privacy_class) -> None:
    """Two independent refusals: here, and again at the egress boundary."""

    decision = route(
        admissions=[ADMITTED],
        remote_enabled=True,
        envelope=an_envelope(privacy_class=privacy_class),
    )
    assert decision.route is Route.LOCAL
    assert privacy_class.value in decision.reason


@pytest.mark.parametrize(
    "privacy_class", [PrivacyClass.P0_PUBLIC, PrivacyClass.P1_SANITIZED]
)
def test_an_eligible_class_with_remote_enabled_routes_remote(privacy_class) -> None:
    """So the tests above are about eligibility and not about remote never firing."""

    decision = route(
        admissions=[ADMITTED],
        remote_enabled=True,
        envelope=an_envelope(privacy_class=privacy_class),
    )
    assert decision.route is Route.REMOTE
    assert "additive" in decision.reason


# -- expiry ----------------------------------------------------------------


def test_an_expired_request_is_not_routed_anywhere() -> None:
    decision = route(
        admissions=[ADMITTED],
        remote_enabled=True,
        envelope=an_envelope(expiry="2020-01-01T00:00:00Z"),
    )
    assert decision.route is Route.DETERMINISTIC_HANDOFF
    assert "expired" in decision.reason


def test_an_unreadable_expiry_counts_as_expired() -> None:
    decision = route(
        admissions=[ADMITTED], remote_enabled=True, envelope=an_envelope(expiry="soon")
    )
    assert decision.route is Route.DETERMINISTIC_HANDOFF


def test_expiry_is_compared_against_the_supplied_instant_not_a_clock() -> None:
    """The same envelope, two `now` values, two answers."""

    envelope = an_envelope(expiry="2026-09-21T00:30:00Z")
    before = route(envelope=envelope, admissions=[ADMITTED], now="2026-09-21T00:00:00Z")
    after = route(envelope=envelope, admissions=[ADMITTED], now="2026-09-21T01:00:00Z")
    assert before.route is Route.LOCAL
    assert after.route is Route.DETERMINISTIC_HANDOFF


@pytest.mark.parametrize("field", ["correlation_id", "deadline", "expiry"])
def test_an_envelope_missing_a_field_is_refused(field: str) -> None:
    with pytest.raises(ValueError) as caught:
        an_envelope(**{field: "  "})
    assert field in str(caught.value)


# -- budgets are declared, not discovered ----------------------------------


@pytest.mark.parametrize(
    "counters, expected",
    [
        ({"request_bytes": 16385}, "request_bytes"),
        ({"response_bytes": 65537}, "response_bytes"),
        ({"requests_this_hour": 21}, "requests_this_hour"),
        ({"in_flight": 2}, "in_flight"),
    ],
)
def test_an_exhausted_budget_narrows_to_the_deterministic_handoff(
    counters: dict, expected: str
) -> None:
    decision = route(admissions=[ADMITTED], remote_enabled=True, counters=counters)
    assert decision.route is Route.DETERMINISTIC_HANDOFF
    assert expected in decision.reason
    assert "not widened" in decision.reason


@pytest.mark.parametrize(
    "counters",
    [{"request_bytes": 16384}, {"requests_this_hour": 20}, {"in_flight": 1}, {}],
)
def test_a_budget_at_its_limit_is_not_exceeded(counters: dict) -> None:
    """The boundary, in the direction that must still work."""

    assert BUDGETS.exceeded(counters) is None


@pytest.mark.parametrize("counters", [{"in_flight": -1}, {"in_flight": True}, {"in_flight": "one"}])
def test_a_counter_that_is_not_a_count_is_refused(counters: dict) -> None:
    assert "is not a count" in (BUDGETS.exceeded(counters) or "")


def test_the_module_holds_no_counters() -> None:
    """A check that owned its counter could pass by forgetting to increment."""

    tree = ast.parse(pathlib.Path(routing_module.__file__).read_text(encoding="utf-8"))
    mutable = {
        target.id
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
        and not target.id.startswith("__")
        and isinstance(getattr(routing_module, target.id, None), (list, dict, set))
    }
    assert mutable == set(), f"module-level mutable state: {mutable}"


@pytest.mark.parametrize(
    "field",
    ["max_request_bytes", "max_response_bytes", "requests_per_hour", "deadline_seconds", "max_concurrency"],
)
@pytest.mark.parametrize("value", [0, -1, True])
def test_a_budget_that_is_not_a_positive_whole_number_is_refused(field, value) -> None:
    fields = {
        "max_request_bytes": 1,
        "max_response_bytes": 1,
        "requests_per_hour": 1,
        "deadline_seconds": 1,
        "max_concurrency": 1,
    }
    fields[field] = value
    with pytest.raises(ValueError) as caught:
        Budgets(**fields)
    assert field in str(caught.value)


# -- a fallback never escalates --------------------------------------------


def test_every_trigger_has_a_fallback() -> None:
    """A trigger with no row is a failure mode with no defined outcome."""

    assert set(FALLBACKS) == set(FallbackTrigger)
    assert len(FALLBACKS) == 8


@pytest.mark.parametrize(
    "trigger, from_route", list(itertools.product(FallbackTrigger, Route))
)
def test_no_fallback_from_any_route_ever_widens(
    trigger: FallbackTrigger, from_route: Route
) -> None:
    """All 8 x 3 pairings. The invariant is over the whole table or nowhere."""

    result = fallback_for(trigger, from_route=from_route)
    assert ROUTE_ORDER.index(result.ceiling) <= ROUTE_ORDER.index(from_route), (
        f"{trigger.value} from {from_route.value} widened to {result.ceiling.value}"
    )


@pytest.mark.parametrize("trigger", list(FallbackTrigger))
def test_the_deterministic_handoff_survives_every_trigger(trigger: FallbackTrigger) -> None:
    """The floor of the ladder. There is nowhere below it to fall."""

    result = fallback_for(trigger, from_route=Route.DETERMINISTIC_HANDOFF)
    assert result.ceiling is Route.DETERMINISTIC_HANDOFF


@pytest.mark.parametrize("trigger", list(FallbackTrigger))
def test_every_fallback_states_what_it_must_never_do(trigger: FallbackTrigger) -> None:
    fallback = FALLBACKS[trigger]
    assert fallback.result.strip()
    assert fallback.never.strip()
    assert fallback.result != fallback.never


def test_the_eight_results_are_eight_distinct_statements() -> None:
    """Two triggers with one result are one trigger with two names."""

    assert len({fallback.result for fallback in FALLBACKS.values()}) == 8
    assert len({fallback.never for fallback in FALLBACKS.values()}) == 8


@pytest.mark.parametrize(
    "trigger, expected",
    [
        (FallbackTrigger.PROVIDER_TIMEOUT, Route.LOCAL),
        (FallbackTrigger.AUTHENTICATION_FAILURE, Route.LOCAL),
        (FallbackTrigger.STALE_OR_REPLAYED, Route.LOCAL),
        (FallbackTrigger.UNPARSEABLE_OR_OVERSIZE, Route.LOCAL),
        (FallbackTrigger.PRIVACY_DENIAL, Route.LOCAL),
        (FallbackTrigger.ASSET_VERIFICATION_FAILURE, Route.DETERMINISTIC_HANDOFF),
        (FallbackTrigger.RESOURCE_PRESSURE, Route.DETERMINISTIC_HANDOFF),
        (FallbackTrigger.COGNITION_RESTART, Route.DETERMINISTIC_HANDOFF),
    ],
)
def test_each_trigger_lands_where_the_contract_says(
    trigger: FallbackTrigger, expected: Route
) -> None:
    """Pinned per row, so "never widens" is not satisfied by collapsing them all."""

    assert fallback_for(trigger, from_route=Route.REMOTE).ceiling is expected


def test_a_fallback_from_a_narrower_route_stays_narrow() -> None:
    result = fallback_for(FallbackTrigger.PROVIDER_TIMEOUT, from_route=Route.DETERMINISTIC_HANDOFF)
    assert result.ceiling is Route.DETERMINISTIC_HANDOFF
    assert "not widened" in result.result


def test_a_deadline_expiry_never_queues_for_later() -> None:
    assert "never queues data for later" in FALLBACKS[FallbackTrigger.PROVIDER_TIMEOUT].never


def test_an_authentication_failure_never_retries_with_relaxed_trust() -> None:
    assert "relaxed trust" in FALLBACKS[FallbackTrigger.AUTHENTICATION_FAILURE].never


# -- shedding --------------------------------------------------------------


def test_shedding_goes_widest_first() -> None:
    assert SHEDDING_ORDER == ("remote work", "optional model work", "the local model")


@pytest.mark.parametrize("protected", sorted(PROTECTED_FROM_SHEDDING))
def test_the_protected_work_is_absent_from_the_shedding_order(protected: str) -> None:
    """Absent, not last. Being last is still being in the queue."""

    assert protected not in SHEDDING_ORDER
    assert all(protected not in step for step in SHEDDING_ORDER)


def test_the_protected_set_is_the_contract_s_four_things() -> None:
    """The contract's four, in this package's vocabulary.

    `docs/mio-runtime.md` §7 writes "capture, evidence, audit, lease expiry".
    The bare word `capture` is a retired role word here and
    `test_no_retired_role_word_survives_as_a_value` refuses it as a string
    value, so these are `degradation.py`'s names for the same four.
    """

    assert PROTECTED_FROM_SHEDDING == {
        "capture_spool",
        "evidence_objects",
        "audit_chain",
        "lease_expiry",
    }
    assert RETENTION_ORDER[0] in PROTECTED_FROM_SHEDDING
    assert UNDROPPABLE[0] in PROTECTED_FROM_SHEDDING


# -- nothing here acts, and nothing here reads a clock ---------------------


@pytest.mark.parametrize("remote_enabled", [True, False])
def test_no_decision_blocks_the_deterministic_path(remote_enabled: bool) -> None:
    for admissions in ([REFUSED], [ADMITTED], []):
        decision = route(admissions=admissions, remote_enabled=remote_enabled)
        assert decision.blocks_deterministic_path() is False


def test_the_module_reads_no_clock_and_has_no_egress_path() -> None:
    tree = ast.parse(pathlib.Path(routing_module.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {
        "socket", "ssl", "http", "urllib", "requests", "httpx", "subprocess",
        "time", "random", "secrets", "uuid", "os",
    } == set()

    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "now" not in calls and "utcnow" not in calls


def test_the_module_defines_no_verb_that_could_execute() -> None:
    tree = ast.parse(pathlib.Path(routing_module.__file__).read_text(encoding="utf-8"))
    names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    acting = {
        name
        for name in names
        if name.lstrip("_").split("_")[0]
        in {"run", "exec", "execute", "apply", "enforce", "invoke", "launch", "send", "dispatch"}
    }
    assert acting == set(), f"the routing plane defines {acting}"


# -- the audit events ------------------------------------------------------


def test_the_route_event_carries_the_inputs_that_produced_it() -> None:
    """§9: the decision *and the inputs*. A decision alone cannot be checked."""

    event = route(admissions=[ADMITTED], remote_enabled=True).as_event()
    assert event["event_type"] == "mio.route.selected"
    assert event["route"] == "remote"
    assert event["inputs"]["correlation_id"] == "corr-1"
    assert event["inputs"]["now"] == NOW
    assert event["inputs"]["admitted_providers"] == ["local-model"]
    assert event["inputs"]["remote_enabled"] is True


def test_the_route_event_is_the_same_for_the_same_inputs() -> None:
    first = route(admissions=[ADMITTED]).as_event()
    second = route(admissions=[ADMITTED]).as_event()
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_the_fallback_event_names_the_trigger_and_the_ceiling() -> None:
    event = fallback_for(FallbackTrigger.RESOURCE_PRESSURE, from_route=Route.REMOTE).as_event()
    assert event["trigger"] == "resource pressure"
    assert event["ceiling"] == "deterministic handoff"
    assert "never shed" in event["never"]
