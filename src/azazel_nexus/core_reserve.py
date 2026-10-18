"""The Core reserve: how a measurement is recorded, validated and consulted (#68).

`docs/mio-runtime.md` §3 requires a local model provider to pass a *"resource
envelope sufficient for the declared memory need, **after the Core reserve**"*
gate. Deciding that needs a number, and Nexus does not have one
([`HG-05`](../../docs/hardware-gates.md)). This module is **everything around
that number except the number**: the shape a measurement has to take, what
makes one admissible, and the single path by which an admissible one reaches
the admission gates.

## This module ships no measurement, and a test says so

`RESERVE_RECORD_PATH` is a runtime path, not a packaged file.
`tests/unit/test_core_reserve.py` scans the distribution for any record that
declares itself `measured` and fails if one is found. A number committed here
would be an invented measurement wearing a threshold's clothes -- and because
it gates whether a provider is admitted, an optimistic one would admit a model
onto a host that then sheds the work the reserve exists to protect.

So `load_reserve()` returns `None` on every node this build runs on, the
resource gate refuses exactly as it did before this module existed, and
`tests/unit/test_cognition.py` still asserts that refusal. **The input path is
built; nothing is on it.**

## Fixture and measurement are different words

Every record declares its `Provenance`. A `FIXTURE` record exercises the
reader, the validator and the gate wiring, and `validate` **refuses it for
admission** with that as the reason. Without the distinction, the tests that
prove this path works would be indistinguishable from the measurement that has
not been taken -- and the first person to grep for a reserve would find one.

## What makes a record admissible

A measurement is not a number someone wrote down. `HG-05` says what would
settle it: the node running on the target hardware -- a generic rugged
x86_64 Linux PC at the class being measured -- **under load, with audit,
evidence capture and the lease journal active**, sampled across the memory
classes, because the reserve scales with retention and concurrency
(`IMPLEMENTATION_SPEC.md` §2.1). Each of those is a refusal here when absent:

| refusal | why it is not a detail |
| --- | --- |
| a subsystem in `REQUIRED_SUBSYSTEMS` was not active | the reserve is what the node needs *before* optional work; measuring it with the node's own work switched off measures something else |
| fewer than `MIN_SAMPLES` samples | one observation is an anecdote, and a reserve derived from it is a threshold with no evidence of its spread |
| the samples span less than `MIN_DURATION_SECONDS` | a burst of samples in a second sees one moment of the node's life |
| no host facts, or a profile the record does not name | a reserve measured on one memory class is not the reserve of another, and `HG-05` is explicit that it does not scale as one number |
| a sample that is not a positive quantity | a zero or negative resident set is a broken reader, and a reader that reports one must not be averaged into a threshold |
| provenance is not `MEASURED` | above |

## The reserve is the **maximum** observed, not a percentile

A declared policy, stated here so that it is argued with rather than
discovered. The reserve is a floor the node must always have. A percentile
admits a provider on the strength of the samples below the tail -- and the
tail is exactly the load under which the node sheds the work the reserve
exists to protect. Taking the maximum can only refuse a provider that would
have fit; taking a percentile can admit one that does not.

This is a policy, and a later measurement campaign may argue it should be a
maximum plus a margin. It is not a measurement, and changing it changes no
number this build has.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .resource_profile import ResourceProfile

__all__ = [
    "CoreReserve",
    "MIN_DURATION_SECONDS",
    "MIN_SAMPLES",
    "Provenance",
    "REQUIRED_SUBSYSTEMS",
    "RESERVE_MAX_BYTES",
    "RESERVE_RECORD_PATH",
    "RESERVE_SCHEMA",
    "RESERVE_SCHEMA_V2",
    "ReserveRecord",
    "ReserveRefused",
    "Sample",
    "Validation",
    "load_reserve",
    "parse_record",
    "validate",
]

#: The record schema this reader accepts. A record naming another schema is
#: refused rather than read leniently: a reader that guesses at an unknown
#: version is a reader that will one day interpret a field it does not have.
RESERVE_SCHEMA = "azazel-nexus/core-reserve/1"
RESERVE_SCHEMA_V2 = "azazel-nexus/core-reserve/2"

#: Where a measurement would live on a node. Runtime state, never packaged.
RESERVE_RECORD_PATH = Path("/var/lib/azazel/run/core-reserve.json")

#: A ceiling before parsing, for the same reason every other reader here has
#: one: a reader with no ceiling has its memory decided by whatever wrote the
#: file.
RESERVE_MAX_BYTES = 256 * 1024

#: What must have been running for the samples to be the Core reserve rather
#: than the reserve of a quieter node. `HG-05`: "the node running on the
#: target hardware under load with audit, evidence capture and the lease
#: journal active".
REQUIRED_SUBSYSTEMS = (
    "arbiter",
    "audit",
    "evidence_capture",
    "lease_journal",
    "operator_plane",
)

#: Below this many samples the spread is not observed, only asserted.
MIN_SAMPLES = 30

#: And below this span they are all the same moment.
MIN_DURATION_SECONDS = 300


class Provenance(str, Enum):
    """Where a record came from. The two are never interchangeable."""

    #: Produced by the harness on a real node. Only these are admissible.
    MEASURED = "measured"
    #: Hand-built to exercise the reader, the validator or the gate wiring.
    #: Refused for admission, by name, in `validate`.
    FIXTURE = "fixture"


class ReserveRefused(Exception):
    """A record that cannot be read as a record. Refused, never repaired."""


@dataclass(frozen=True)
class Sample:
    """One observation of the node's own resident set."""

    #: Seconds since the run began. Not a wall clock: the reserve is about a
    #: span of load, and a record that travels between hosts should not carry
    #: one host's clock into another's comparison.
    offset_seconds: int
    resident_mib: int


@dataclass(frozen=True)
class ReserveRecord:
    """A measurement run, or a fixture standing in for one."""

    schema: str
    provenance: Provenance
    #: Which memory class this was measured on. A reserve is per class.
    profile: ResourceProfile
    #: Identifies the node without describing it. The harness supplies it; this
    #: module never derives host facts, because a record that could invent its
    #: own host could claim to be from a host it was not run on.
    host_digest: str
    #: The harness that produced it, so a record from a harness whose sampling
    #: changed is identifiable rather than silently comparable.
    harness_version: str
    #: The subsystems observed to be active for the whole run.
    subsystems_active: tuple[str, ...]
    samples: tuple[Sample, ...]
    boot_fingerprint: str | None = None
    run_sequence: int | None = None
    build_commit: str | None = None
    kernel_release: str | None = None

    @property
    def duration_seconds(self) -> int:
        if not self.samples:
            return 0
        return max(s.offset_seconds for s in self.samples) - min(
            s.offset_seconds for s in self.samples
        )

    @property
    def observed_maximum_mib(self) -> Optional[int]:
        """The statistic the reserve is taken from. `None` with no samples."""

        return max((s.resident_mib for s in self.samples), default=None)


@dataclass(frozen=True)
class Validation:
    """Whether a record may be used as the Core reserve, and why not."""

    admissible: bool
    #: Every reason it is not, not just the first. An operator who fixes one
    #: refusal and is then told about the next has been sent round twice.
    refusals: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.admissible and self.refusals:
            raise ValueError(
                "a record cannot be admissible and refused; one of the two is "
                "describing a different record"
            )
        if not self.admissible and not self.refusals:
            raise ValueError(
                "a record was refused with no reason; a refusal an operator "
                "cannot act on is a refusal that will be worked around"
            )


@dataclass(frozen=True)
class CoreReserve:
    """A validated reserve, and the record it came from."""

    profile: ResourceProfile
    reserve_mib: int
    host_digest: str
    harness_version: str
    sample_count: int
    duration_seconds: int

    def fits(self, *, memory_need_mib: int, envelope_mib: int) -> bool:
        """Whether a declared need fits the envelope after this reserve."""

        return memory_need_mib <= envelope_mib - self.reserve_mib


def parse_record(text: str) -> ReserveRecord:
    """Read one record. Refuses rather than repairing, like every reader here."""

    if len(text.encode("utf-8")) > RESERVE_MAX_BYTES:
        raise ReserveRefused(
            f"the reserve record is larger than {RESERVE_MAX_BYTES} bytes"
        )
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise ReserveRefused(f"the reserve record is not JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ReserveRefused("the reserve record is JSON that is not an object")
    missing = [
        key
        for key in (
            "schema",
            "provenance",
            "profile",
            "host_digest",
            "harness_version",
            "subsystems_active",
            "samples",
        )
        if key not in document
    ]
    if missing:
        raise ReserveRefused(f"the reserve record is missing {missing}")
    if document["schema"] not in (RESERVE_SCHEMA, RESERVE_SCHEMA_V2):
        raise ReserveRefused(
            f"the reserve record names schema {document['schema']!r} and this "
            f"reader knows {RESERVE_SCHEMA!r} and {RESERVE_SCHEMA_V2!r}; a reader that guesses at an "
            "unknown version will one day interpret a field it does not have"
        )
    try:
        provenance = Provenance(document["provenance"])
    except ValueError as exc:
        raise ReserveRefused(
            f"the reserve record names an unknown provenance: {exc}"
        ) from exc
    try:
        profile = ResourceProfile(document["profile"])
    except ValueError as exc:
        raise ReserveRefused(
            f"the reserve record names an unknown profile: {exc}"
        ) from exc
    subsystems = document["subsystems_active"]
    if not isinstance(subsystems, list) or not all(isinstance(s, str) for s in subsystems):
        raise ReserveRefused("subsystems_active is not a list of names")
    raw_samples = document["samples"]
    if not isinstance(raw_samples, list):
        raise ReserveRefused("samples is not a list")
    samples = []
    for index, entry in enumerate(raw_samples):
        if not isinstance(entry, dict):
            raise ReserveRefused(f"sample {index} is not an object")
        if "offset_seconds" not in entry or "resident_mib" not in entry:
            raise ReserveRefused(f"sample {index} is missing a field")
        for field in ("offset_seconds", "resident_mib"):
            value = entry[field]
            # `bool` is an `int` in Python, and a record whose sample reads
            # `true` is a broken writer, not a sample of one MiB.
            if not isinstance(value, int) or isinstance(value, bool):
                raise ReserveRefused(f"sample {index} has a non-integer {field}")
        samples.append(
            Sample(
                offset_seconds=entry["offset_seconds"],
                resident_mib=entry["resident_mib"],
            )
        )
    for field in ("host_digest", "harness_version"):
        if not isinstance(document[field], str) or not document[field].strip():
            raise ReserveRefused(f"{field} is not a non-empty string")
    metadata = {}
    if document["schema"] == RESERVE_SCHEMA_V2:
        metadata = {name: document.get(name) for name in (
            "boot_fingerprint", "run_sequence", "build_commit", "kernel_release"
        )}
        _validate_v2_metadata(document)
    return ReserveRecord(
        **metadata,
        schema=document["schema"],
        provenance=provenance,
        profile=profile,
        host_digest=document["host_digest"],
        harness_version=document["harness_version"],
        subsystems_active=tuple(subsystems),
        samples=tuple(samples),
    )


def validate(record: ReserveRecord) -> Validation:
    """Every reason this record may not be used as the Core reserve."""

    refusals: list[str] = []
    if record.schema not in (RESERVE_SCHEMA, RESERVE_SCHEMA_V2):
        refusals.append("unknown reserve schema")
    if record.schema == RESERVE_SCHEMA_V2:
        try:
            _validate_v2_metadata(vars(record))
        except ReserveRefused as exc:
            refusals.append(str(exc))
    if record.provenance is not Provenance.MEASURED:
        refusals.append(
            f"the record declares itself {record.provenance.value!r}; only a "
            "measurement taken by the harness on a real node is admissible, and "
            "a fixture is how the path around the number is tested"
        )
    absent = [s for s in REQUIRED_SUBSYSTEMS if s not in record.subsystems_active]
    if absent:
        refusals.append(
            f"{absent} were not active for the run; the Core reserve is what "
            "the node needs before any optional workload, so measuring it with "
            "the node's own work switched off measures a different node"
        )
    if len(record.samples) < MIN_SAMPLES:
        refusals.append(
            f"{len(record.samples)} samples is fewer than {MIN_SAMPLES}; a "
            "reserve derived from that is a threshold with no evidence of its "
            "spread"
        )
    if record.duration_seconds < MIN_DURATION_SECONDS:
        refusals.append(
            f"the samples span {record.duration_seconds}s, less than "
            f"{MIN_DURATION_SECONDS}s; samples taken in one burst observe one "
            "moment of the node's life"
        )
    if any(s.resident_mib < 1 for s in record.samples):
        refusals.append(
            "a sample reports a resident set that is not a positive quantity; "
            "that is a broken reader, and a broken reader must not be averaged "
            "into a threshold"
        )
    if any(s.offset_seconds < 0 for s in record.samples):
        refusals.append("a sample reports a negative offset")
    if refusals:
        return Validation(admissible=False, refusals=tuple(refusals))
    return Validation(admissible=True, refusals=())


def reserve_from(record: ReserveRecord) -> Optional[CoreReserve]:
    """The reserve this record supports, or `None` when it supports none."""

    if not validate(record).admissible:
        return None
    maximum = record.observed_maximum_mib
    if maximum is None:  # pragma: no cover - MIN_SAMPLES rejects an empty run
        return None
    return CoreReserve(
        profile=record.profile,
        # The maximum observed, by the policy this module's docstring states.
        reserve_mib=maximum,
        host_digest=record.host_digest,
        harness_version=record.harness_version,
        sample_count=len(record.samples),
        duration_seconds=record.duration_seconds,
    )


def load_reserve(path: Path = RESERVE_RECORD_PATH) -> Optional[CoreReserve]:
    """The node's measured Core reserve, or `None` when it has none.

    `None` for an absent file, because a node that has never been measured is
    not a node with a broken measurement -- and `None` is what every node this
    build runs on returns. A file that exists and cannot be read raises:
    something wrote it, and ignoring that would hide the one case where a
    reserve is being produced wrongly.
    """

    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ReserveRefused(f"the reserve record could not be read: {exc}") from exc
    return reserve_from(parse_record(text))


def record_as_document(record: ReserveRecord) -> Mapping[str, object]:
    """The record as the harness writes it. The inverse of `parse_record`."""

    metadata = {}
    if record.schema == RESERVE_SCHEMA_V2:
        metadata = {name: getattr(record, name) for name in (
            "boot_fingerprint", "run_sequence", "build_commit", "kernel_release"
        )}
    return {
        **metadata,
        "schema": record.schema,
        "provenance": record.provenance.value,
        "profile": record.profile.value,
        "host_digest": record.host_digest,
        "harness_version": record.harness_version,
        "subsystems_active": list(record.subsystems_active),
        "samples": [
            {"offset_seconds": s.offset_seconds, "resident_mib": s.resident_mib}
            for s in record.samples
        ],
    }


def build_record(
    *,
    provenance: Provenance,
    profile: ResourceProfile,
    host_digest: str,
    harness_version: str,
    subsystems_active: Sequence[str],
    samples: Sequence[Sample],
    boot_fingerprint: str | None = None,
    run_sequence: int | None = None,
    build_commit: str | None = None,
    kernel_release: str | None = None,
) -> ReserveRecord:
    """Assemble v2 with campaign metadata, or v1 for legacy callers."""

    return ReserveRecord(
        schema=(RESERVE_SCHEMA_V2 if any(value is not None for value in (
            boot_fingerprint, run_sequence, build_commit, kernel_release
        )) else RESERVE_SCHEMA),
        boot_fingerprint=boot_fingerprint,
        run_sequence=run_sequence,
        build_commit=build_commit,
        kernel_release=kernel_release,
        provenance=provenance,
        profile=profile,
        host_digest=host_digest,
        harness_version=harness_version,
        subsystems_active=tuple(subsystems_active),
        samples=tuple(samples),
    )


def _validate_v2_metadata(document: Mapping[str, object]) -> None:
    """V2 metadata must be complete; a v1 record retains its original rules."""

    prefix = "hmac-sha256:"
    for field in ("boot_fingerprint", "host_digest"):
        fingerprint = document.get(field)
        if (not isinstance(fingerprint, str) or not fingerprint.startswith(prefix)
                or len(fingerprint.removeprefix(prefix)) != 64
                or any(c not in "0123456789abcdef" for c in fingerprint.removeprefix(prefix))):
            raise ReserveRefused(f"{field} is not a full HMAC fingerprint")
    sequence = document.get("run_sequence")
    if type(sequence) is not int or sequence < 1:
        raise ReserveRefused("run_sequence is not a positive integer")
    commit = document.get("build_commit")
    if (not isinstance(commit, str) or len(commit) not in (40, 64)
            or any(c not in "0123456789abcdef" for c in commit)):
        raise ReserveRefused("build_commit is not a full commit identifier")
    kernel = document.get("kernel_release")
    if not isinstance(kernel, str) or not kernel.strip() or len(kernel) > 256:
        raise ReserveRefused("kernel_release is not a non-empty bounded string")
