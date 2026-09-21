"""The Core reserve: the path around a number that does not exist (#68).

`HG-05` is open because nobody has measured the Core reserve on target
hardware. What this file tests is everything else: the record a measurement
takes, what makes one admissible, how a reserve is derived from it, and the
one path by which it reaches the admission gates.

**The first test is the important one.** Every other test here builds records,
and a fixture that leaked onto disk would look exactly like the measurement
that has not been taken. So the distribution is scanned for one.
"""

from __future__ import annotations

import ast
import json
import pathlib

import pytest

from azazel_nexus.core_reserve import (
    MIN_DURATION_SECONDS,
    MIN_SAMPLES,
    REQUIRED_SUBSYSTEMS,
    RESERVE_MAX_BYTES,
    RESERVE_RECORD_PATH,
    RESERVE_SCHEMA,
    CoreReserve,
    Provenance,
    ReserveRefused,
    Sample,
    Validation,
    build_record,
    load_reserve,
    parse_record,
    record_as_document,
    reserve_from,
    validate,
)
from azazel_nexus.resource_profile import ResourceProfile

REPOSITORY = pathlib.Path(__file__).resolve().parents[2]


def a_record(**overrides):
    """An otherwise-admissible record. `provenance` must be overridden to use it."""

    fields = {
        "provenance": Provenance.FIXTURE,
        "profile": ResourceProfile.LITE,
        "host_digest": "sha256:" + "a" * 64,
        "harness_version": "core-reserve-probe/1",
        "subsystems_active": REQUIRED_SUBSYSTEMS,
        "samples": tuple(
            Sample(offset_seconds=i * 10, resident_mib=1000 + i) for i in range(MIN_SAMPLES + 1)
        ),
    }
    fields.update(overrides)
    return build_record(**fields)


# -- nothing on disk claims to be a measurement -----------------------------


def test_no_measurement_is_committed_anywhere() -> None:
    """The load-bearing test of this file.

    A record marked `measured` in the repository would be an invented
    measurement wearing a real one's clothes, and because it gates whether a
    provider is admitted, an optimistic one would admit a model onto a host
    that then sheds the work the reserve exists to protect.

    Every JSON file in the distribution is offered to the reader. Anything the
    reader accepts as a record must be a fixture.
    """

    found = []
    for path in sorted(REPOSITORY.rglob("*.json")):
        if any(part in {".git", ".venv", "node_modules", "__pycache__"} for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            record = parse_record(text)
        except ReserveRefused:
            continue
        if record.provenance is Provenance.MEASURED:
            found.append(str(path.relative_to(REPOSITORY)))
    assert found == [], f"{found} declare themselves measurements"


def test_the_scan_above_would_find_one(tmp_path) -> None:
    """Otherwise it passes because the reader rejects everything it is given."""

    document = record_as_document(a_record(provenance=Provenance.MEASURED))
    parsed = parse_record(json.dumps(document))
    assert parsed.provenance is Provenance.MEASURED


def test_every_node_in_this_build_has_no_reserve(tmp_path) -> None:
    """`load_reserve` returns `None`, which is the answer everywhere today."""

    assert load_reserve(tmp_path / "absent.json") is None
    # And the production path is a runtime location, not a packaged file.
    assert not RESERVE_RECORD_PATH.exists() or RESERVE_RECORD_PATH.is_absolute()
    assert str(RESERVE_RECORD_PATH).startswith("/var/lib/azazel")


def test_a_record_that_exists_and_cannot_be_parsed_raises(tmp_path) -> None:
    """Silence would hide the one case where a reserve is produced wrongly."""

    path = tmp_path / "core-reserve.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ReserveRefused):
        load_reserve(path)


def test_a_record_that_exists_and_cannot_be_opened_raises(tmp_path) -> None:
    """The other half, and the half a mutation showed was untested.

    A parse failure and an `OSError` are different events and only the first
    was driven. With the `OSError` branch returning `None`, a node whose
    reserve file cannot be opened -- wrong mode, wrong owner, a directory
    where the file should be -- would read exactly like a node that has never
    measured one. That is the case `load_reserve`'s docstring says it will not
    hide, so it is checked rather than asserted.
    """

    path = tmp_path / "core-reserve.json"
    path.mkdir()
    with pytest.raises(ReserveRefused) as caught:
        load_reserve(path)
    assert "could not be read" in str(caught.value)


# -- the reader refuses rather than repairing -------------------------------


def test_a_record_larger_than_the_ceiling_is_refused() -> None:
    with pytest.raises(ReserveRefused) as caught:
        parse_record("x" * (RESERVE_MAX_BYTES + 1))
    assert str(RESERVE_MAX_BYTES) in str(caught.value)


@pytest.mark.parametrize(
    "mutation, expected",
    [
        ({"schema": "azazel-nexus/core-reserve/2"}, "knows"),
        ({"provenance": "guessed"}, "unknown provenance"),
        ({"profile": "enormous"}, "unknown profile"),
        ({"host_digest": "  "}, "host_digest"),
        ({"harness_version": ""}, "harness_version"),
        ({"subsystems_active": "audit"}, "not a list"),
        ({"samples": {"offset_seconds": 0}}, "not a list"),
    ],
)
def test_a_malformed_record_is_refused(mutation, expected) -> None:
    document = dict(record_as_document(a_record()))
    document.update(mutation)
    with pytest.raises(ReserveRefused) as caught:
        parse_record(json.dumps(document))
    assert expected in str(caught.value)


def test_a_missing_field_names_itself() -> None:
    document = dict(record_as_document(a_record()))
    del document["samples"]
    with pytest.raises(ReserveRefused) as caught:
        parse_record(json.dumps(document))
    assert "samples" in str(caught.value)


@pytest.mark.parametrize("value", [True, False, 1.5, "1024", None])
def test_a_sample_that_is_not_an_integer_is_refused(value) -> None:
    """`True` is the one that would slip through: a bool is an int in Python.

    A record whose sample reads `true` is a broken writer, not a sample of one
    MiB, and averaging it into a threshold is how a broken writer becomes a
    number somebody trusts.
    """

    document = dict(record_as_document(a_record()))
    document["samples"] = [{"offset_seconds": 0, "resident_mib": value}]
    with pytest.raises(ReserveRefused) as caught:
        parse_record(json.dumps(document))
    assert "non-integer" in str(caught.value)


def test_a_record_survives_a_round_trip() -> None:
    """What the harness writes is what the reader reads."""

    original = a_record()
    assert parse_record(json.dumps(record_as_document(original))) == original


# -- validation reports every reason, not the first -------------------------


def test_an_admissible_record_is_admissible() -> None:
    """So the refusals below are about specific defects, not about everything."""

    assert validate(a_record(provenance=Provenance.MEASURED)).admissible


def test_a_fixture_is_refused_for_being_one() -> None:
    result = validate(a_record(provenance=Provenance.FIXTURE))
    assert not result.admissible
    assert any("fixture" in reason for reason in result.refusals)


def test_a_missing_subsystem_names_itself() -> None:
    result = validate(
        a_record(
            provenance=Provenance.MEASURED,
            subsystems_active=tuple(s for s in REQUIRED_SUBSYSTEMS if s != "audit"),
        )
    )
    assert not result.admissible
    assert any("audit" in reason for reason in result.refusals)


def test_too_few_samples_is_refused() -> None:
    result = validate(
        a_record(
            provenance=Provenance.MEASURED,
            samples=tuple(
                Sample(offset_seconds=i * 100, resident_mib=1000)
                for i in range(MIN_SAMPLES - 1)
            ),
        )
    )
    assert not result.admissible
    assert any(str(MIN_SAMPLES) in reason for reason in result.refusals)


def test_a_burst_of_samples_is_refused_however_many() -> None:
    """Enough samples in one second observe one moment of the node's life."""

    result = validate(
        a_record(
            provenance=Provenance.MEASURED,
            samples=tuple(
                Sample(offset_seconds=0, resident_mib=1000) for _ in range(MIN_SAMPLES * 10)
            ),
        )
    )
    assert not result.admissible
    assert any(str(MIN_DURATION_SECONDS) in reason for reason in result.refusals)


def test_a_non_positive_sample_is_refused() -> None:
    samples = list(a_record().samples)
    samples[3] = Sample(offset_seconds=30, resident_mib=0)
    result = validate(a_record(provenance=Provenance.MEASURED, samples=tuple(samples)))
    assert not result.admissible
    assert any("positive" in reason for reason in result.refusals)


def test_every_refusal_is_reported_not_just_the_first() -> None:
    """An operator who fixes one and is then told the next has gone round twice."""

    result = validate(
        a_record(
            provenance=Provenance.FIXTURE,
            subsystems_active=(),
            samples=(Sample(offset_seconds=0, resident_mib=1),),
        )
    )
    assert not result.admissible
    assert len(result.refusals) >= 4


def test_a_validation_cannot_be_both_or_neither() -> None:
    with pytest.raises(ValueError):
        Validation(admissible=True, refusals=("something",))
    with pytest.raises(ValueError):
        Validation(admissible=False, refusals=())


# -- the reserve is the maximum, by stated policy ---------------------------


def test_the_reserve_is_the_maximum_and_not_a_central_statistic() -> None:
    """Driven by a set where maximum, mean and median all differ.

    A percentile admits a provider on the strength of the samples below the
    tail, and the tail is exactly the load under which the node sheds the work
    the reserve exists to protect.
    """

    samples = tuple(
        Sample(offset_seconds=i * 10, resident_mib=(9000 if i == 40 else 1000))
        for i in range(MIN_SAMPLES + 20)
    )
    reserve = reserve_from(a_record(provenance=Provenance.MEASURED, samples=samples))
    assert reserve is not None
    assert reserve.reserve_mib == 9000
    mean = sum(s.resident_mib for s in samples) / len(samples)
    assert reserve.reserve_mib != round(mean)
    assert reserve.reserve_mib != 1000  # the median and the 99th percentile


def test_a_record_that_does_not_validate_yields_no_reserve() -> None:
    assert reserve_from(a_record(provenance=Provenance.FIXTURE)) is None


def test_the_reserve_carries_the_evidence_it_came_from() -> None:
    """A reserve with no provenance is a number somebody would have to trust."""

    reserve = reserve_from(a_record(provenance=Provenance.MEASURED))
    assert reserve is not None
    assert reserve.sample_count == MIN_SAMPLES + 1
    assert reserve.harness_version == "core-reserve-probe/1"
    assert reserve.profile is ResourceProfile.LITE
    assert reserve.duration_seconds >= MIN_DURATION_SECONDS


def test_fits_subtracts_the_reserve_from_the_envelope() -> None:
    reserve = CoreReserve(
        profile=ResourceProfile.LITE,
        reserve_mib=2000,
        host_digest="sha256:" + "b" * 64,
        harness_version="core-reserve-probe/1",
        sample_count=60,
        duration_seconds=600,
    )
    assert reserve.fits(memory_need_mib=13000, envelope_mib=15000)
    assert not reserve.fits(memory_need_mib=13001, envelope_mib=15000)
    # And the envelope alone is never the answer.
    assert not reserve.fits(memory_need_mib=15000, envelope_mib=15000)


# -- the schema is named, so a changed one is a changed name ----------------


def test_the_schema_version_is_in_the_record_the_harness_writes() -> None:
    assert record_as_document(a_record())["schema"] == RESERVE_SCHEMA
    assert RESERVE_SCHEMA.endswith("/1")


def test_the_module_imports_nothing_outside_the_standard_library() -> None:
    """It is on the CORE path: a node with nothing installed reads its reserve."""

    from azazel_nexus import core_reserve

    tree = ast.parse(pathlib.Path(core_reserve.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    import sys

    assert imported <= set(sys.stdlib_module_names), sorted(
        imported - set(sys.stdlib_module_names)
    )


# -- the recorded synthetic artifact (#115) --------------------------------


PROCEDURE = pathlib.Path(__file__).resolve().parents[2] / "docs" / "core-reserve-measurement.md"


def _procedure() -> str:
    """Whitespace-normalised: these sentences are wrapped in the source."""

    return " ".join(PROCEDURE.read_text(encoding="utf-8").split())


@pytest.mark.parametrize(
    "statement",
    [
        "it is **not** in `main`, in any release, in any signed artifact, or in any HIL evidence",
        "**no claim is made that the external hosting has erased it**",
        "**invalid as HIL evidence** and **must not be cited**",
        "It writes only to a dedicated directory outside version control",
        "CI verifies that the guard refuses **before the first write**",
    ],
)
def test_the_record_keeps_every_statement_it_was_written_to_make(statement):
    """Five statements, each of which a later edit could soften into
    something easier to read and less true. The second is the one most
    likely to go: a rewritten branch reads as a deletion, and claiming the
    forge forgot is a claim nobody here can check."""

    assert statement in _procedure(), f"the record lost: {statement}"


def test_the_record_reproduces_nothing_from_the_artifact():
    """Describing it by quoting it would be the same mistake with a better
    excuse. Any long run of hex is a digest; a `provenance` field would be
    the record body itself."""

    text = PROCEDURE.read_text(encoding="utf-8")
    import re  # noqa: PLC0415 - one use, in one test

    assert re.findall(r"\b[0-9a-f]{16,}\b", text) == [], "a digest-shaped value"
    assert '"provenance"' not in text, "the record body is reproduced"
    assert "sha256:" not in text, "a digest is reproduced"


def test_the_record_does_not_call_it_a_disclosure():
    """It was not one, and a record that overstates what happened is one
    nobody trusts the next time."""

    text = _procedure()
    assert "not a disclosure one" in text
    assert "nothing about it involved real data, a credential or a secret" in text
