"""`az-core-reserve-probe`: the harness that would measure the Core reserve (#68).

**No measurement has been taken, and this produces none here.** What this
module is, is the mechanism: the sampling, the preconditions it refuses
without, the record it writes, and the single path by which that record
reaches `azazel_nexus.core_reserve`. Running it on a real node under load is
what closes [`HG-05`](../../../docs/hardware-gates.md), and that needs target
hardware this repository has never had. `docs/core-reserve-measurement.md` is
the procedure.

## What it refuses to measure

A number produced by the wrong run is worse than no number, because it looks
like the one that was missing. So the run refuses -- it does not warn and
continue -- when:

- any of `core_reserve.REQUIRED_SUBSYSTEMS` is not active for the **whole**
  run. Checked before the first sample and again after the last: a subsystem
  that stopped in the middle makes every sample after it a sample of a
  different node, and there is no way to tell which ones
- the memory class cannot be read, or changes during the run
- a sample cannot be read, or reads as a non-positive quantity

A refusal writes nothing. There is no partial record, because a record with
some of the samples is a measurement of a shorter run that does not say so.

## It measures the node, not itself

The reserve is what the node needs before any optional workload: the arbiter,
audit, the lease journal, evidence capture, the operator plane, and the
kernel's own working set under load. The sample is the **cgroup** the Azazel
units live in, read from `memory.current`, plus the kernel's own reclaimable
state from `/proc/meminfo` -- not this process's resident set, which would
measure the harness.

`CGROUP_CURRENT` and `MEMINFO` are module constants. `main` takes no path, no
unit, no interval and no sample count, exactly as `edge_probed.main` takes
none: a harness that accepted a cgroup path would be a harness that could be
pointed at any cgroup on the host and report the answer as the Core reserve.

## It runs nothing and reaches nothing

Unlike `edge_probed`, this executes no subprocess at all. Subsystem liveness
is read over D-Bus through an injected `call(method, unit)` with the same
read-only allowlist, and everything else is a file read under `/sys` and
`/proc`. `tests/unit/test_runtime_activated.py` scans this distribution for
anything that can execute, and this module is not an exception to it -- it
has nothing to exempt.

## The record it writes is a `MEASURED` one, and that is the only place one
   comes from

`core_reserve.Provenance.FIXTURE` exists so that the reader, the validator and
the admission wiring can be tested without a measurement. This is the one
writer of `MEASURED`, and `tests/unit/test_core_reserve.py` asserts that no
`MEASURED` record is committed anywhere in the distribution.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

from azazel_nexus.core_reserve import (
    MIN_DURATION_SECONDS,
    MIN_SAMPLES,
    REQUIRED_SUBSYSTEMS,
    RESERVE_RECORD_PATH,
    Provenance,
    Sample,
    build_record,
    record_as_document,
    validate,
)
from azazel_nexus.resource_profile import read_usable_mib, select_profile

__all__ = [
    "CGROUP_CURRENT",
    "HARNESS_VERSION",
    "MEMINFO",
    "READ_ONLY_METHODS",
    "SAMPLE_COUNT",
    "SAMPLE_INTERVAL_SECONDS",
    "SUBSYSTEM_UNITS",
    "MeasurementRefused",
    "main",
    "measure",
    "write_record",
]

#: Identifies this sampler in every record it writes. A record from a harness
#: whose sampling changed must be identifiable rather than silently comparable
#: with one from another.
HARNESS_VERSION = "core-reserve-probe/2"

#: The cgroup the Azazel units live in, and the kernel's own accounting. Both
#: fixed in code; neither can be supplied.
CGROUP_CURRENT = Path("/sys/fs/cgroup/azazel.slice/memory.current")
MEMINFO = Path("/proc/meminfo")

#: The systemd methods this may invoke. Both read, same allowlist rule as
#: `edge_probed`: the write methods are absent from the table, which is the
#: only way in.
READ_ONLY_METHODS = ("GetUnit", "GetUnitProperties")

#: Which unit stands for each required subsystem. A subsystem with no unit
#: cannot be observed, and `measure` refuses rather than assuming it is up.
SUBSYSTEM_UNITS = {
    "arbiter": "azazel-arbiter.service",
    "audit": "azazel-auditd.service",
    "evidence_capture": "azazel-evidence.service",
    "lease_journal": "azazel-leasejournal.service",
    "operator_plane": "azazel-operator.service",
}

#: Twice the validator's floor, so that a run losing a few samples to a
#: transient read still produces an admissible record rather than a near miss.
SAMPLE_COUNT = MIN_SAMPLES * 2

#: Chosen so that `SAMPLE_COUNT` samples span comfortably more than
#: `MIN_DURATION_SECONDS`. The reserve is about a span of load, not a burst.
SAMPLE_INTERVAL_SECONDS = 10


class MeasurementRefused(Exception):
    """A run that must not become a record. Nothing is written."""


@dataclass(frozen=True)
class Readers:
    """Everything the run reads, injected so the tests are not the host.

    A default is supplied for each, so `main` constructs none of them and the
    production path is the same code the tests drive.
    """

    #: `(method, unit) -> mapping of properties`. Read-only by allowlist.
    call: Optional[Callable[[str, str], dict]] = None
    cgroup_current: Callable[[], int] = lambda: int(
        CGROUP_CURRENT.read_text(encoding="utf-8").strip()
    )
    usable_mib: Callable[[], int] = lambda: read_usable_mib(MEMINFO)
    sleep: Callable[[float], None] = time.sleep
    identity: Callable[[], dict] = lambda: _identity()
    run_sequence: Callable[[], int] = lambda: next_sequence()


def _active(readers: Readers, unit: str) -> bool:
    if readers.call is None:
        raise MeasurementRefused(
            "no connection to the service manager, so no subsystem can be "
            "observed to be active. A reserve measured without knowing what "
            "was running is a measurement of an unknown node"
        )
    properties = readers.call("GetUnitProperties", unit)
    return properties.get("ActiveState") == "active" and properties.get("SubState") == "running"


def _require_subsystems(readers: Readers, *, when: str) -> None:
    inactive = []
    for subsystem in REQUIRED_SUBSYSTEMS:
        unit = SUBSYSTEM_UNITS.get(subsystem)
        if unit is None:
            raise MeasurementRefused(
                f"{subsystem!r} has no unit in SUBSYSTEM_UNITS, so it cannot be "
                "observed; an unobservable subsystem is not an active one"
            )
        if not _active(readers, unit):
            inactive.append(subsystem)
    if inactive:
        raise MeasurementRefused(
            f"{inactive} were not active {when}; the Core reserve is what the "
            "node needs before any optional workload, so a run with the node's "
            "own work switched off measures a different node"
        )


def measure(readers: Optional[Readers] = None) -> object:
    """One complete run, or a refusal. Never a partial record.

    The subsystems are checked before the first sample and again after the
    last. A run that passed the first check and failed the second produced
    samples of two different nodes, and there is no way to tell which sample
    was the last of the first node -- so the whole run is refused.
    """

    readers = readers or Readers()
    _require_subsystems(readers, when="when the run began")

    try:
        usable_before = readers.usable_mib()
    except Exception as exc:  # noqa: BLE001 - any read failure is a refusal
        raise MeasurementRefused(f"the memory class could not be read: {exc}") from exc
    profile = select_profile(usable_before)
    try:
        identity = readers.identity()
        sequence = readers.run_sequence()
    except Exception as exc:
        raise MeasurementRefused("run identity/key/build metadata unavailable") from exc

    samples: list[Sample] = []
    for index in range(SAMPLE_COUNT):
        if index:
            readers.sleep(SAMPLE_INTERVAL_SECONDS)
        try:
            current_bytes = readers.cgroup_current()
        except Exception as exc:  # noqa: BLE001
            raise MeasurementRefused(
                f"sample {index} could not be read: {exc}; a run with a hole in "
                "it is a shorter run that does not say so"
            ) from exc
        resident_mib = int(current_bytes) // (1024 * 1024)
        if resident_mib < 1:
            raise MeasurementRefused(
                f"sample {index} read {current_bytes} bytes, which is not a "
                "positive resident set; that is a broken reader, and a broken "
                "reader must not be averaged into a threshold"
            )
        samples.append(
            Sample(
                offset_seconds=index * SAMPLE_INTERVAL_SECONDS,
                resident_mib=resident_mib,
            )
        )

    _require_subsystems(readers, when="when the run ended")
    usable_after = readers.usable_mib()
    if select_profile(usable_after) is not profile:
        raise MeasurementRefused(
            "the memory class changed during the run, so the samples are not "
            "all of one class; the reserve is per class"
        )

    if readers.identity() != identity:
        raise MeasurementRefused("boot or build identity changed during the run")

    record = build_record(
        provenance=Provenance.MEASURED,
        profile=profile,
        **identity,
        run_sequence=sequence,
        harness_version=HARNESS_VERSION,
        subsystems_active=REQUIRED_SUBSYSTEMS,
        samples=samples,
    )
    result = validate(record)
    if not result.admissible:
        # The harness produced a record its own validator refuses. That is a
        # defect in this module, not a property of the node, so it is raised
        # rather than written: a record that fails validation on disk is a
        # record somebody will eventually relax the validator for.
        raise MeasurementRefused(
            "the completed run does not validate: " + "; ".join(result.refusals)
        )
    return record


def _identity() -> dict:
    from .hil_readiness import run_identity

    return run_identity()


def next_sequence(directory: Path = RESERVE_RECORD_PATH.parent) -> int:
    """Read the immutable run archive; publication refuses a concurrent collision."""

    sequences = [0]
    for path in directory.glob("core-reserve-run-*.json"):
        sequence = path.stem.removeprefix("core-reserve-run-")
        if sequence.isdigit():
            sequences.append(int(sequence))
    return max(sequences) + 1


def write_record(record, path: Path = RESERVE_RECORD_PATH) -> Path:
    """Publish an immutable run; never overwrite a previous measurement.

    The legacy admission path is deliberately not promoted by this sampler.
    Campaign validation/attestation must precede operator promotion there.
    """

    if record.run_sequence is not None:
        path = path.parent / f"core-reserve-run-{record.run_sequence:08d}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(record_as_document(record), indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    from azazel_nexus.hil_records.confidentiality import lint_text

    lint_text(payload)
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=".core-reserve.")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.link(temporary, path)
        os.unlink(temporary)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return path


def main(argv: Optional[Sequence[str]] = None) -> int:
    """One run, then exit. Takes nothing that could redirect it.

    No `--cgroup`, no `--unit`, no `--samples`, no `--interval`, no `--output`.
    Every one of those would be a way to point the harness at something other
    than this node's own units and record the answer as the Core reserve.
    """

    parser = argparse.ArgumentParser(
        prog="az-core-reserve-probe",
        description=(
            "Measure this node's Core reserve under load and write the record. "
            "Refuses unless every required subsystem is active for the whole run."
        ),
    )
    parser.parse_args(argv)
    try:
        from .hil_readiness import ReadOnlySystemd

        with ReadOnlySystemd() as manager:
            record = measure(Readers(call=manager))
        path = write_record(record)
    except Exception:  # noqa: BLE001 - no host details in terminal diagnostics
        print("refused: subsystem observation, run identity, sampling or publication failed", file=sys.stderr)
        return 2
    print(
        f"recorded {len(record.samples)} samples over {record.duration_seconds}s "
        f"on the {record.profile.value!r} class to {path}"
    )
    return 0
