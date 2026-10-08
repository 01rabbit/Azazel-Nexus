"""Observed evidence about how fast a route actually answers (#83).

`docs/mio-route-policy.md` §4. `fastest-permitted` may call a candidate the
fastest only on the strength of what was **observed**, so this module holds
the record, the freshness rule and the derivation.

## It invents no measurements

The same discipline as `core_reserve.py` and `HG-05`. There is no default
latency here, no seed value, no "about this much to begin with". A number put
here to get the code running would be a permanent setting wearing a
measurement's clothes -- and a permanent setting is the exact thing this
module exists to replace.

`tests/unit/test_route_evidence.py::test_no_observation_is_committed_anywhere`
offers every JSON file in the distribution to the reader and fails if one is
accepted as an observation record.

## No samples, no prediction

A candidate with fewer than `MIN_SAMPLES` fresh observations is **not
predictable**, and a candidate that is not predictable cannot be called
fastest. That is the correct state, not a defect: on every node in this build
nothing has been observed, so nothing is predictable, and the deterministic
handoff answers.

**"Not yet measured" and "measured and slow" are different words.**
`Prediction.predictable` is `False` for the first and `True` for the second,
and the reason says which.

## Observations expire

Latency observed an hour ago is not evidence of latency now. An observation
older than `OBSERVATION_TTL_SECONDS` is **not used**, and a candidate whose
samples have all expired goes back to not-predictable rather than keeping its
last answer. A stale observation presented as current is a permanent setting
again, just a slower one to notice.

## p95, by nearest rank

The statistic is stated so it is argued with rather than discovered. **p95,
not the mean**: an operator experiences each request individually, and a mean
hides the tail that a deadline is missed in. Nearest-rank on the sorted
samples -- integer arithmetic, no interpolation, no floats -- so the same
samples give the same answer on every machine.

## Cold start is kept separate, not averaged in

A first request to a local model pays for loading it; later ones do not.
Averaging the two produces a number that describes neither. Observations
record which they were, and `predict` is asked which case to answer for.

## The record carries no request

An observation holds the candidate, the time, the elapsed milliseconds, the
outcome, coarse **size classes**, the queue depth and whether a cold start was
paid. It holds no body, no identifier, no correlation id and no evidence.
`test_route_evidence.py` asserts the field set exactly, so a field added later
has to be argued for here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence

# `_parse_instant` is private and is imported anyway, deliberately. The
# alternative is a second RFC3339 parser in this module, and two parsers
# for one timestamp format drift into two notions of when something
# happened. `test_route_evidence.py` checks the two agree on the boundary
# rather than leaving the coupling asserted.
from .lite_cache import _parse_instant

__all__ = [
    "EVIDENCE_MAX_BYTES",
    "EVIDENCE_SCHEMA",
    "MIN_SAMPLES",
    "OBSERVATION_TTL_SECONDS",
    "Observation",
    "Outcome",
    "Prediction",
    "SizeClass",
    "SUCCESS_FLOOR_PERCENT",
    "EvidenceRefused",
    "fresh",
    "parse_observations",
    "predict",
]

#: The record schema this reader accepts. A record naming another is refused
#: rather than read leniently.
EVIDENCE_SCHEMA = "azazel-nexus/route-evidence/1"

#: A ceiling before parsing, like every other reader here.
EVIDENCE_MAX_BYTES = 1024 * 1024

#: Below this many fresh samples a candidate is not predictable. One
#: observation is an anecdote, and a "fastest" derived from it is a claim with
#: no evidence of its spread.
MIN_SAMPLES = 20

#: An observation older than this is not evidence of current latency.
OBSERVATION_TTL_SECONDS = 3600

#: A candidate that answers less often than this is not offered as fastest
#: however quickly it answers when it does. **Declared policy, not a
#: measurement**: a route that is quick and usually fails is not quick.
SUCCESS_FLOOR_PERCENT = 90


class EvidenceRefused(Exception):
    """A record that cannot be read as one. Refused, never repaired."""


class Outcome(str, Enum):
    """What happened to one request. Three, and they are not one flag."""

    ANSWERED = "answered"
    FAILED = "failed"
    DEADLINE_MISSED = "deadline missed"


class SizeClass(str, Enum):
    """Coarse buckets. Exact sizes describe the request, which is not recorded."""

    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"


#: Exactly the fields an observation carries. Asserted by a test, so a field
#: added later has to be argued for rather than appearing.
OBSERVATION_FIELDS = (
    "candidate",
    "at",
    "elapsed_ms",
    "outcome",
    "request_size",
    "response_size",
    "queue_depth",
    "cold_start",
)


@dataclass(frozen=True)
class Observation:
    """One request, as far as timing is concerned. Nothing about its content."""

    #: Which candidate answered. A short opaque name supplied by the caller;
    #: this module owns no route vocabulary, so that `routing` can own one
    #: without the two importing each other.
    candidate: str
    #: RFC3339, when the request completed.
    at: str
    elapsed_ms: int
    outcome: Outcome
    request_size: SizeClass
    response_size: SizeClass
    #: How many requests were already in flight for this candidate.
    queue_depth: int
    #: Whether this request paid to start the provider.
    cold_start: bool

    def __post_init__(self) -> None:
        if not str(self.candidate).strip():
            raise EvidenceRefused("an observation names the candidate it is about")
        if not str(self.at).strip():
            raise EvidenceRefused("an observation records when it happened")
        for field in ("elapsed_ms", "queue_depth"):
            value = getattr(self, field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise EvidenceRefused(f"{field} is a non-negative whole number")


def fresh(
    observations: Iterable[Observation], *, as_of: str
) -> tuple[Observation, ...]:
    """The observations still usable at `as_of`.

    `as_of` is supplied, never read from a clock. A prediction whose inputs
    included the wall clock is a prediction nobody can check later, and §8
    requires the evidence behind a route choice to be auditable.
    """

    try:
        now = _parse_instant(as_of)
    except ValueError as exc:
        raise EvidenceRefused(
            f"{as_of!r} is not an instant this reader can compare against; a "
            "prediction dated by nothing is a prediction nobody can check"
        ) from exc

    kept = []
    for observation in observations:
        try:
            observed = _parse_instant(observation.at)
        except ValueError:
            # An observation nobody can date is not evidence of when anything
            # happened, so it is dropped rather than treated as current.
            continue
        age_seconds = (now - observed).total_seconds()
        # A timestamp in the future is not fresh evidence. Accepting a
        # negative age here would let clock skew or a forged record extend
        # its useful lifetime without bound.
        if 0 <= age_seconds < OBSERVATION_TTL_SECONDS:
            kept.append(observation)
    return tuple(kept)


@dataclass(frozen=True)
class Prediction:
    """What the evidence supports about one candidate. Never more than that."""

    candidate: str
    #: Whether there is enough fresh evidence to say anything at all.
    predictable: bool
    #: The p95 of the matching samples, or `None` when not predictable.
    p95_ms: Optional[int]
    #: Counts rather than a float, so the ratio is exact and replays.
    answered: int
    sample_count: int
    #: Whether a cold start was assumed when deriving `p95_ms`.
    cold_start_assumed: bool
    reason: str

    @property
    def success_percent(self) -> Optional[int]:
        if not self.sample_count:
            return None
        return self.answered * 100 // self.sample_count

    def meets(self, *, deadline_ms: int) -> bool:
        """Whether this candidate is predicted to answer inside the deadline.

        `False` when not predictable. **A candidate nobody has measured is not
        offered as fast**; it is not offered at all.
        """

        if not self.predictable or self.p95_ms is None:
            return False
        percent = self.success_percent
        if percent is None or percent < SUCCESS_FLOOR_PERCENT:
            return False
        return self.p95_ms <= deadline_ms

    def as_event(self) -> dict:
        return {
            "candidate": self.candidate,
            "predictable": self.predictable,
            "p95_ms": self.p95_ms,
            "sample_count": self.sample_count,
            "success_percent": self.success_percent,
            "cold_start_assumed": self.cold_start_assumed,
            "reason": self.reason,
        }


def _p95(values: Sequence[int]) -> int:
    """Nearest rank, on integers. No interpolation and no floats.

    `ceil(0.95 * n)` expressed as integer arithmetic so that the same samples
    give the same answer everywhere.
    """

    ordered = sorted(values)
    rank = -(-95 * len(ordered) // 100)  # ceil(0.95 * n)
    return ordered[max(rank, 1) - 1]


def predict(
    observations: Iterable[Observation],
    *,
    candidate: str,
    as_of: str,
    expect_cold_start: bool = False,
) -> Prediction:
    """What can be said about `candidate` from the evidence, and nothing more.

    Cold-start and warm samples are answered separately rather than averaged:
    a mean of the two describes neither case, and the caller knows which one
    it is about to incur.
    """

    usable = [
        observation
        for observation in fresh(observations, as_of=as_of)
        if observation.candidate == candidate
        and observation.cold_start is expect_cold_start
    ]
    if len(usable) < MIN_SAMPLES:
        return Prediction(
            candidate=candidate,
            predictable=False,
            p95_ms=None,
            answered=sum(1 for o in usable if o.outcome is Outcome.ANSWERED),
            sample_count=len(usable),
            cold_start_assumed=expect_cold_start,
            reason=(
                f"{len(usable)} fresh "
                + ("cold-start" if expect_cold_start else "warm")
                + f" sample(s), fewer than {MIN_SAMPLES}; nothing has been "
                "observed often enough to predict from. This is not a slow "
                "candidate -- it is an unmeasured one"
            ),
        )
    answered = sum(1 for o in usable if o.outcome is Outcome.ANSWERED)
    return Prediction(
        candidate=candidate,
        predictable=True,
        p95_ms=_p95([o.elapsed_ms for o in usable]),
        answered=answered,
        sample_count=len(usable),
        cold_start_assumed=expect_cold_start,
        reason=(
            f"p95 over {len(usable)} fresh "
            + ("cold-start" if expect_cold_start else "warm")
            + f" sample(s); {answered} answered"
        ),
    )


def parse_observations(text: str) -> tuple[Observation, ...]:
    """Read a record of observations. Refuses rather than repairing."""

    if len(text.encode("utf-8")) > EVIDENCE_MAX_BYTES:
        raise EvidenceRefused(f"the record is larger than {EVIDENCE_MAX_BYTES} bytes")
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise EvidenceRefused(f"the record is not JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise EvidenceRefused("the record is JSON that is not an object")
    if document.get("schema") != EVIDENCE_SCHEMA:
        raise EvidenceRefused(
            f"the record names schema {document.get('schema')!r} and this reader "
            f"knows {EVIDENCE_SCHEMA!r}"
        )
    raw = document.get("observations")
    if not isinstance(raw, list):
        raise EvidenceRefused("observations is not a list")
    parsed: list[Observation] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise EvidenceRefused(f"observation {index} is not an object")
        extra = sorted(set(entry) - set(OBSERVATION_FIELDS))
        if extra:
            raise EvidenceRefused(
                f"observation {index} carries {extra}, which an observation does "
                "not record. A timing record that grew a request field is a "
                "request log"
            )
        missing = [f for f in OBSERVATION_FIELDS if f not in entry]
        if missing:
            raise EvidenceRefused(f"observation {index} is missing {missing}")
        try:
            outcome = Outcome(entry["outcome"])
            request_size = SizeClass(entry["request_size"])
            response_size = SizeClass(entry["response_size"])
        except ValueError as exc:
            raise EvidenceRefused(f"observation {index}: {exc}") from exc
        if not isinstance(entry["cold_start"], bool):
            raise EvidenceRefused(f"observation {index} has a non-boolean cold_start")
        for field in ("elapsed_ms", "queue_depth"):
            value = entry[field]
            if not isinstance(value, int) or isinstance(value, bool):
                raise EvidenceRefused(f"observation {index} has a non-integer {field}")
        parsed.append(
            Observation(
                candidate=str(entry["candidate"]),
                at=str(entry["at"]),
                elapsed_ms=entry["elapsed_ms"],
                outcome=outcome,
                request_size=request_size,
                response_size=response_size,
                queue_depth=entry["queue_depth"],
                cold_start=entry["cold_start"],
            )
        )
    return tuple(parsed)


def observations_as_document(
    observations: Sequence[Observation],
) -> Mapping[str, object]:
    """The inverse of `parse_observations`."""

    return {
        "schema": EVIDENCE_SCHEMA,
        "observations": [
            {
                "candidate": o.candidate,
                "at": o.at,
                "elapsed_ms": o.elapsed_ms,
                "outcome": o.outcome.value,
                "request_size": o.request_size.value,
                "response_size": o.response_size.value,
                "queue_depth": o.queue_depth,
                "cold_start": o.cold_start,
            }
            for o in observations
        ],
    }


def load_observations(path: Path) -> tuple[Observation, ...]:
    """Read the node's observations, or none when it has never recorded any.

    An empty tuple for an absent file -- a node that has observed nothing is
    not a node with a broken record, and it is what every node in this build
    returns. A file that exists and cannot be read raises.
    """

    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ()
    except OSError as exc:
        raise EvidenceRefused(f"the record could not be read: {exc}") from exc
    return parse_observations(text)
