"""Observed evidence, and the claims it does and does not support (#83).

`docs/mio-route-policy.md` §4. The load-bearing claims:

*No measurement is invented.* The distribution ships no observation, and the
first test says so.

*No samples, no prediction.* A candidate nobody measured is not offered as
fast; it is not offered. "Not yet measured" and "measured and slow" are
different words.

*Observations expire.* A stale one is not evidence of current latency, and a
candidate whose samples have all expired goes back to not-predictable rather
than keeping its last answer.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from azazel_nexus.lite_cache import classify_freshness
from azazel_nexus.route_evidence import (
    EVIDENCE_MAX_BYTES,
    EVIDENCE_SCHEMA,
    MIN_SAMPLES,
    OBSERVATION_FIELDS,
    OBSERVATION_TTL_SECONDS,
    SUCCESS_FLOOR_PERCENT,
    EvidenceRefused,
    Observation,
    Outcome,
    SizeClass,
    fresh,
    load_observations,
    observations_as_document,
    parse_observations,
    predict,
)

REPOSITORY = pathlib.Path(__file__).resolve().parents[2]
NOW = "2026-09-21T12:00:00Z"


def an_observation(**overrides) -> Observation:
    fields = {
        "candidate": "local",
        "at": "2026-09-21T11:59:00Z",
        "elapsed_ms": 100,
        "outcome": Outcome.ANSWERED,
        "request_size": SizeClass.SMALL,
        "response_size": SizeClass.SMALL,
        "queue_depth": 0,
        "cold_start": False,
    }
    fields.update(overrides)
    return Observation(**fields)


def enough(*, elapsed=100, outcome=Outcome.ANSWERED, cold_start=False, count=None):
    count = MIN_SAMPLES if count is None else count
    return [
        an_observation(elapsed_ms=elapsed, outcome=outcome, cold_start=cold_start)
        for _ in range(count)
    ]


# -- nothing on disk is a measurement -------------------------------------


def test_no_observation_is_committed_anywhere() -> None:
    """The load-bearing test.

    A committed observation would be a permanent setting wearing a
    measurement's clothes -- and it would let `fastest-permitted` call a route
    fastest on evidence nobody gathered.
    """

    found = []
    for path in sorted(REPOSITORY.rglob("*.json")):
        if any(p in {".git", ".venv", "node_modules", "__pycache__"} for p in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            if parse_observations(text):
                found.append(str(path.relative_to(REPOSITORY)))
        except EvidenceRefused:
            continue
    assert found == [], f"{found} carry observations"


def test_the_scan_above_would_find_one() -> None:
    """Otherwise it passes because the reader rejects everything."""

    document = observations_as_document([an_observation()])
    assert len(parse_observations(json.dumps(document))) == 1


def test_a_node_that_has_observed_nothing_reads_as_nothing(tmp_path) -> None:
    assert load_observations(tmp_path / "absent.json") == ()


def test_a_record_that_exists_and_cannot_be_read_raises(tmp_path) -> None:
    path = tmp_path / "evidence.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(EvidenceRefused):
        load_observations(path)


# -- no samples, no prediction --------------------------------------------


def test_nothing_observed_is_not_predictable() -> None:
    prediction = predict([], candidate="local", as_of=NOW)
    assert prediction.predictable is False
    assert prediction.p95_ms is None
    assert prediction.meets(deadline_ms=10**9) is False


def test_an_unmeasured_candidate_is_not_called_slow() -> None:
    """"Not yet measured" and "measured and slow" are different words."""

    unmeasured = predict([], candidate="local", as_of=NOW)
    assert "unmeasured one" in unmeasured.reason
    measured_slow = predict(
        enough(elapsed=900_000), candidate="local", as_of=NOW
    )
    assert measured_slow.predictable is True
    assert measured_slow.meets(deadline_ms=1000) is False
    assert "unmeasured" not in measured_slow.reason


@pytest.mark.parametrize("count", [0, 1, MIN_SAMPLES - 1])
def test_fewer_than_the_floor_is_not_predictable(count) -> None:
    prediction = predict(enough(count=count), candidate="local", as_of=NOW)
    assert prediction.predictable is False
    assert str(MIN_SAMPLES) in prediction.reason


def test_exactly_the_floor_is_predictable() -> None:
    """Otherwise the tests above would pass by nothing ever being predictable."""

    prediction = predict(enough(count=MIN_SAMPLES), candidate="local", as_of=NOW)
    assert prediction.predictable is True
    assert prediction.p95_ms == 100


def test_another_candidates_samples_are_not_borrowed() -> None:
    other = [an_observation(candidate="remote") for _ in range(MIN_SAMPLES * 2)]
    assert predict(other, candidate="local", as_of=NOW).predictable is False


# -- observations expire ---------------------------------------------------


def test_an_expired_observation_is_not_used() -> None:
    stale = [
        an_observation(at="2026-09-21T10:00:00Z") for _ in range(MIN_SAMPLES * 2)
    ]
    assert fresh(stale, as_of=NOW) == ()
    assert predict(stale, candidate="local", as_of=NOW).predictable is False


def test_the_expiry_boundary_is_the_declared_ttl() -> None:
    """Checked on both sides, so an off-by-one in either direction fails."""

    inside = an_observation(at="2026-09-21T11:01:00Z")  # 59 minutes old
    outside = an_observation(at="2026-09-21T10:59:00Z")  # 61 minutes old
    assert OBSERVATION_TTL_SECONDS == 3600
    assert fresh([inside], as_of=NOW) == (inside,)
    assert fresh([outside], as_of=NOW) == ()


def test_a_candidate_whose_samples_expired_stops_being_predictable() -> None:
    """It does not keep its last answer. A stale answer is a permanent setting."""

    samples = enough()
    assert predict(samples, candidate="local", as_of=NOW).predictable is True
    later = "2026-09-21T23:00:00Z"
    assert predict(samples, candidate="local", as_of=later).predictable is False


def test_an_undatable_observation_is_dropped_not_treated_as_current() -> None:
    assert fresh([an_observation(at="not-an-instant")], as_of=NOW) == ()


def test_an_undatable_as_of_is_refused_rather_than_guessed() -> None:
    with pytest.raises(EvidenceRefused):
        fresh([an_observation()], as_of="whenever")


def test_this_module_and_lite_cache_agree_about_instants() -> None:
    """One parser, checked rather than asserted.

    `route_evidence` imports `lite_cache._parse_instant` so there is a single
    notion of when something happened. If the two ever disagreed, an
    observation could be fresh to one and expired to the other.
    """

    boundary = "2026-09-21T11:00:01Z"
    assert classify_freshness(boundary, as_of=NOW).value == "expired"
    assert fresh([an_observation(at=boundary)], as_of=NOW) != ()


# -- the statistic is stated ----------------------------------------------


def test_p95_is_the_tail_and_not_the_mean() -> None:
    """Driven by a set where the two differ by an order of magnitude."""

    samples = [an_observation(elapsed_ms=10) for _ in range(MIN_SAMPLES * 5)]
    samples += [an_observation(elapsed_ms=5000) for _ in range(MIN_SAMPLES)]
    prediction = predict(samples, candidate="local", as_of=NOW)
    assert prediction.p95_ms == 5000
    mean = sum(o.elapsed_ms for o in samples) // len(samples)
    assert prediction.p95_ms != mean


def test_p95_is_deterministic_over_ordering() -> None:
    samples = [an_observation(elapsed_ms=ms) for ms in range(MIN_SAMPLES * 2)]
    forward = predict(samples, candidate="local", as_of=NOW).p95_ms
    backward = predict(list(reversed(samples)), candidate="local", as_of=NOW).p95_ms
    assert forward == backward


# -- cold start is kept separate ------------------------------------------


def test_cold_and_warm_samples_are_not_averaged() -> None:
    samples = enough(elapsed=100, cold_start=False) + enough(
        elapsed=9000, cold_start=True
    )
    warm = predict(samples, candidate="local", as_of=NOW, expect_cold_start=False)
    cold = predict(samples, candidate="local", as_of=NOW, expect_cold_start=True)
    assert warm.p95_ms == 100
    assert cold.p95_ms == 9000
    assert warm.cold_start_assumed is False and cold.cold_start_assumed is True


def test_asking_for_a_case_with_no_samples_is_not_predictable() -> None:
    warm_only = enough(cold_start=False)
    assert predict(
        warm_only, candidate="local", as_of=NOW, expect_cold_start=True
    ).predictable is False


# -- success rate ----------------------------------------------------------


def test_a_fast_but_failing_candidate_does_not_meet_a_deadline() -> None:
    """A route that is quick and usually fails is not quick."""

    samples = enough(elapsed=1, outcome=Outcome.FAILED)
    prediction = predict(samples, candidate="local", as_of=NOW)
    assert prediction.predictable is True
    assert prediction.p95_ms == 1
    assert prediction.success_percent == 0
    assert prediction.meets(deadline_ms=10**9) is False


def test_the_success_floor_is_where_it_is_declared() -> None:
    """Checked on both sides of the floor."""

    total = 100
    for answered, expected in ((SUCCESS_FLOOR_PERCENT, True), (SUCCESS_FLOOR_PERCENT - 1, False)):
        samples = [
            an_observation(
                elapsed_ms=1,
                outcome=Outcome.ANSWERED if i < answered else Outcome.FAILED,
            )
            for i in range(total)
        ]
        prediction = predict(samples, candidate="local", as_of=NOW)
        assert prediction.success_percent == answered
        assert prediction.meets(deadline_ms=10**9) is expected


def test_a_deadline_miss_is_its_own_outcome() -> None:
    """Three outcomes, not a boolean: missing a deadline is not failing."""

    assert {o.value for o in Outcome} == {"answered", "failed", "deadline missed"}


# -- the record carries no request ----------------------------------------


def test_an_observation_records_exactly_these_fields() -> None:
    """A timing record that grew a request field would be a request log."""

    assert OBSERVATION_FIELDS == (
        "candidate",
        "at",
        "elapsed_ms",
        "outcome",
        "request_size",
        "response_size",
        "queue_depth",
        "cold_start",
    )
    document = observations_as_document([an_observation()])
    assert set(document["observations"][0]) == set(OBSERVATION_FIELDS)


def test_a_record_carrying_an_extra_field_is_refused() -> None:
    """Including the ones somebody would most plausibly add."""

    for extra in ("correlation_id", "body", "prompt", "source_ip", "evidence"):
        document = observations_as_document([an_observation()])
        document["observations"][0][extra] = "x"
        with pytest.raises(EvidenceRefused) as caught:
            parse_observations(json.dumps(document))
        assert extra in str(caught.value)


def test_sizes_are_classes_and_not_byte_counts() -> None:
    assert {s.value for s in SizeClass} == {"small", "medium", "large"}
    document = observations_as_document([an_observation()])
    assert document["observations"][0]["request_size"] in {"small", "medium", "large"}


# -- the reader refuses rather than repairing ------------------------------


def test_a_record_larger_than_the_ceiling_is_refused() -> None:
    with pytest.raises(EvidenceRefused):
        parse_observations("x" * (EVIDENCE_MAX_BYTES + 1))


@pytest.mark.parametrize(
    "mutation, expected",
    [
        ({"schema": "azazel-nexus/route-evidence/2"}, "knows"),
        ({"observations": "not-a-list"}, "not a list"),
    ],
)
def test_a_malformed_record_is_refused(mutation, expected) -> None:
    document = dict(observations_as_document([an_observation()]))
    document.update(mutation)
    with pytest.raises(EvidenceRefused) as caught:
        parse_observations(json.dumps(document))
    assert expected in str(caught.value)


@pytest.mark.parametrize("value", [True, 1.5, "100", None])
def test_a_non_integer_elapsed_is_refused(value) -> None:
    document = observations_as_document([an_observation()])
    document["observations"][0]["elapsed_ms"] = value
    with pytest.raises(EvidenceRefused):
        parse_observations(json.dumps(document))


def test_a_record_round_trips() -> None:
    original = (an_observation(), an_observation(candidate="remote", elapsed_ms=7))
    assert parse_observations(json.dumps(observations_as_document(original))) == original


def test_a_negative_elapsed_is_refused() -> None:
    with pytest.raises(EvidenceRefused):
        an_observation(elapsed_ms=-1)


def test_p95_is_distinguishable_from_the_max_the_median_and_the_mean() -> None:
    """A set where all four differ, because a set where two coincide proves nothing.

    The first version of this file checked p95 against the mean using 100
    samples at 10ms and 20 at 5000ms -- where p95 and the **max** are both
    5000. A mutation replacing the rank with `len(ordered)` survived the whole
    suite: the test could not tell the tail from the last value.

    With 1..100 the four statistics are 95, 100, 51 and 50.
    """

    samples = [an_observation(elapsed_ms=ms) for ms in range(1, 101)]
    prediction = predict(samples, candidate="local", as_of=NOW)
    elapsed = sorted(o.elapsed_ms for o in samples)
    assert prediction.p95_ms == 95
    assert prediction.p95_ms != max(elapsed)
    assert prediction.p95_ms != elapsed[len(elapsed) // 2]
    assert prediction.p95_ms != sum(elapsed) // len(elapsed)


def test_an_unpredictable_candidate_with_some_samples_still_meets_nothing() -> None:
    """The guard in `meets`, made reachable.

    With zero samples `success_percent` is `None` and the later check refuses
    anyway, so removing the predictability guard changed nothing and a mutation
    removing it survived. Below the floor but **not empty** is the case that
    reaches it: a candidate with a few fast, all-successful samples must still
    not be offered, because a handful of samples is not evidence of a tail.
    """

    few = enough(elapsed=1, outcome=Outcome.ANSWERED, count=MIN_SAMPLES - 1)
    prediction = predict(few, candidate="local", as_of=NOW)
    assert prediction.predictable is False
    assert prediction.sample_count == MIN_SAMPLES - 1
    assert prediction.success_percent == 100  # every one of them answered
    assert prediction.p95_ms is None
    assert prediction.meets(deadline_ms=10**9) is False
