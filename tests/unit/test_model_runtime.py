"""The containment fixed before anything can need it loosened (#97).

The point of #97 is not to run a model. It is that a containment written
*after* the thing it contains is a containment shaped by what that thing
turned out to need -- so every guarantee here is checked on a build that
starts nothing, which is the only moment nobody is arguing for an exception.

Three refusals keep a model from starting, in three places, for three
reasons, and each covers a case the others do not:

| refusal | where | defeated by |
| --- | --- | --- |
| the pinned runtime is absent or unverified | `model_runtime.RUNTIMES` | wiring a runtime |
| the unit is not granted | `activation.UnitDefinition.wiring` | wiring a runtime |
| the Core reserve is unmeasured | `readiness` | measuring it (`HG-05`) |

Wire a runtime and the reserve still refuses. Measure the reserve and the
allowlist still refuses. That is not redundancy; each is the answer to a
different question, and a test that drove only one of them would report a
node as contained when one change would uncontain it.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "runtime" / "src"))

from azazel_nexus.core_reserve import CoreReserve  # noqa: E402
from azazel_nexus.model_runtime import (  # noqa: E402
    CPU_QUOTA_PERCENT,
    Containment,
    DEADLINE_SECONDS,
    FILE_SIZE_MAX_BYTES,
    MAX_MODEL_ARTIFACT_BYTES,
    RUNTIMES,
    ActivationReadiness,
    ArtifactDisposition,
    RuntimeBinary,
    RuntimeRefused,
    TASKS_MAX,
    archive_signatures,
    containment_for,
    inspect_artifact,
    readiness,
    resolve_runtime,
)
from azazel_nexus.resource_profile import ResourceProfile  # noqa: E402


def _reserve(reserve_mib: int = 512) -> CoreReserve:
    """A reserve, for driving the paths a measured node would take.

    Constructed here rather than read from a record on purpose: this is the
    *shape* of a measurement, and `core_reserve.validate` is what refuses a
    hand-built record for admission. No test here claims a measurement.
    """

    return CoreReserve(
        profile=ResourceProfile.STANDARD,
        reserve_mib=reserve_mib,
        host_digest="sha256:" + "0" * 64,
        harness_version="fixture",
        sample_count=64,
        duration_seconds=3600,
    )


# -- 1. the allowlist is the only way to a binary -------------------------


def test_this_build_pins_exactly_one_runtime():
    """The shipped answer, and the first of the three refusals."""

    assert set(RUNTIMES) == {"llama-cpp-b11716"}


def test_an_unknown_runtime_id_resolves_to_nothing():
    with pytest.raises(RuntimeRefused) as caught:
        resolve_runtime("llama-cpp")
    assert "not a runtime this build contains" in str(caught.value)


@pytest.mark.parametrize(
    "hostile",
    [
        "../../../usr/bin/sh",
        "/usr/bin/sh",
        "",
        "runtime; sh",
        None,
        42,
    ],
)
def test_nothing_a_caller_can_spell_resolves(hostile):
    """The table is a lookup. There is no join, no format and no fallback,
    so a hostile symbol is refused by being absent rather than by a filter
    somebody has to keep correct."""

    with pytest.raises(RuntimeRefused):
        resolve_runtime(hostile)


def test_a_runtime_outside_the_package_cannot_be_declared():
    with pytest.raises(RuntimeRefused) as caught:
        RuntimeBinary(
            runtime_id="borrowed",
            executable="/usr/bin/python3",
            version="1",
            digest="sha256:" + "0" * 64,
            argv=("/usr/bin/python3",),
        )
    assert "package's own directory" in str(caught.value)


def test_an_argv_with_a_hole_cannot_be_declared():
    """A template is a place a caller's value goes."""

    for hole in ("--model={model}", "--opt=%i"):
        with pytest.raises(RuntimeRefused):
            RuntimeBinary(
                runtime_id="templated",
                executable="/usr/libexec/azazel/az-runtime",
                version="1",
                digest="sha256:" + "0" * 64,
                argv=("/usr/libexec/azazel/az-runtime", hole),
            )


def test_an_argv_that_starts_something_else_cannot_be_declared():
    with pytest.raises(RuntimeRefused):
        RuntimeBinary(
            runtime_id="mismatched",
            executable="/usr/libexec/azazel/az-runtime",
            version="1",
            digest="sha256:" + "0" * 64,
            argv=("/usr/libexec/azazel/az-other",),
        )


def test_a_well_formed_runtime_can_be_declared():
    """So the refusals above are refusals, not a constructor that never works."""

    binary = RuntimeBinary(
        runtime_id="fixture",
        executable="/usr/libexec/azazel/az-runtime",
        version="1",
        digest="sha256:" + "0" * 64,
        argv=("/usr/libexec/azazel/az-runtime", "--inert"),
    )
    assert binary.argv[0] == binary.executable


# -- 2. the model is data -------------------------------------------------


def test_a_plain_file_of_weights_is_data(tmp_path):
    artifact = tmp_path / "m.model"
    artifact.write_bytes(b"\x00" * 4096)
    assert inspect_artifact(artifact).disposition is ArtifactDisposition.DATA


def test_an_executable_artifact_is_refused_rather_than_stripped(tmp_path):
    """Clearing the bit would be deciding that a file which arrived
    executable was meant not to be. The interesting question is who set it."""

    artifact = tmp_path / "m.model"
    artifact.write_bytes(b"\x00" * 4096)
    artifact.chmod(0o755)

    found = inspect_artifact(artifact)
    assert found.disposition is ArtifactDisposition.EXECUTABLE
    assert os.stat(artifact).st_mode & stat.S_IXUSR, "the file was modified"


@pytest.mark.parametrize("bit", [stat.S_IXUSR, stat.S_IXGRP, stat.S_IXOTH])
def test_any_executable_bit_refuses(tmp_path, bit):
    """Not just the owner's. A group or other bit is executable by somebody."""

    artifact = tmp_path / "m.model"
    artifact.write_bytes(b"\x00" * 4096)
    artifact.chmod(0o644 | bit)
    assert inspect_artifact(artifact).disposition is ArtifactDisposition.EXECUTABLE


def test_a_symlink_is_judged_as_a_symlink(tmp_path):
    """`lstat`, so it is never judged as whatever it currently points at --
    and what it points at can change after the check."""

    target = tmp_path / "real"
    target.write_bytes(b"\x00" * 4096)
    link = tmp_path / "m.model"
    link.symlink_to(target)
    assert inspect_artifact(link).disposition is ArtifactDisposition.NOT_A_REGULAR_FILE


def test_a_directory_is_not_a_model(tmp_path):
    (tmp_path / "m.model").mkdir()
    assert (
        inspect_artifact(tmp_path / "m.model").disposition
        is ArtifactDisposition.NOT_A_REGULAR_FILE
    )


@pytest.mark.parametrize(
    "magic,label",
    [(m, label) for m, label in archive_signatures() if m != b"ustar"],
    ids=[label for m, label in archive_signatures() if m != b"ustar"],
)
def test_anything_that_begins_as_a_container_is_refused(tmp_path, magic, label):
    """By content. An extension is a claim by whoever wrote the filename."""

    artifact = tmp_path / "m.model"
    artifact.write_bytes(magic + b"\x00" * 4096)
    assert inspect_artifact(artifact).disposition is ArtifactDisposition.ARCHIVE


def test_a_tar_is_refused_by_its_magic_at_its_own_offset(tmp_path):
    artifact = tmp_path / "m.model"
    artifact.write_bytes(b"\x00" * 257 + b"ustar" + b"\x00" * 1024)
    assert inspect_artifact(artifact).disposition is ArtifactDisposition.ARCHIVE


def test_a_gguf_is_not_mistaken_for_an_archive(tmp_path):
    """The scan must admit the thing it exists to admit."""

    artifact = tmp_path / "m.model"
    artifact.write_bytes(b"GGUF" + b"\x00" * 4096)
    assert inspect_artifact(artifact).disposition is ArtifactDisposition.DATA


def test_an_absent_artifact_is_absent_not_refused(tmp_path):
    """Two different facts. A node that has not fetched a model has not been
    handed a hostile one."""

    assert (
        inspect_artifact(tmp_path / "nothing").disposition
        is ArtifactDisposition.ABSENT
    )


def test_an_empty_or_oversized_artifact_is_out_of_range(tmp_path):
    empty = tmp_path / "e.model"
    empty.write_bytes(b"")
    assert inspect_artifact(empty).disposition is ArtifactDisposition.OUT_OF_RANGE
    assert MAX_MODEL_ARTIFACT_BYTES == 64 * 1024 * 1024 * 1024


def test_every_refusal_says_why(tmp_path):
    """A disposition an operator cannot act on is one they will work around."""

    artifact = tmp_path / "m.model"
    artifact.write_bytes(b"PK\x03\x04" + b"\x00" * 4096)
    found = inspect_artifact(artifact)
    assert not found.is_data
    assert found.reason.strip()


# -- 3. containment needs the measurement, and refuses without it ---------


def test_no_containment_without_a_measured_reserve():
    """Choosing a number here would be inventing the measurement HG-05 takes,
    and a cgroup set from an invented number looks like protection."""

    with pytest.raises(RuntimeRefused) as caught:
        containment_for(memory_need_mib=1024, reserve=None, envelope_mib=8192)
    assert "HG-05" in str(caught.value)


def test_a_provider_is_contained_at_its_declared_need_not_the_spare():
    """Given everything the node can spare, a provider uses everything the
    node can spare, and the reserve then holds only because nothing asked."""

    contained = containment_for(
        memory_need_mib=1024, reserve=_reserve(512), envelope_mib=8192
    )
    assert contained.memory_max_mib == 1024


def test_a_need_that_would_eat_the_reserve_is_refused():
    with pytest.raises(RuntimeRefused) as caught:
        containment_for(memory_need_mib=7800, reserve=_reserve(512), envelope_mib=8192)
    assert "inside the reserve" in str(caught.value)


def test_the_deterministic_path_keeps_the_majority_of_the_cpu():
    """A provider that can take most of the CPU decides how fast the arbiter
    runs, which is the one thing this product will not let it decide."""

    assert CPU_QUOTA_PERCENT < 50
    contained = containment_for(
        memory_need_mib=1024, reserve=_reserve(), envelope_mib=8192
    )
    assert contained.cpu_quota_percent == CPU_QUOTA_PERCENT


def test_every_bound_is_present_and_positive():
    contained = containment_for(
        memory_need_mib=1024, reserve=_reserve(), envelope_mib=8192
    )
    assert contained.tasks_max == TASKS_MAX >= 1
    assert contained.file_size_max_bytes == FILE_SIZE_MAX_BYTES >= 1
    assert contained.deadline_seconds == DEADLINE_SECONDS >= 1


def test_a_containment_that_permits_the_network_cannot_be_built():
    """A model that can open a connection is a model that can carry what it
    was shown. It is a field rather than a sentence, so removing it is a diff."""

    for loopback, outbound in ((False, True), (True, False), (False, False)):
        with pytest.raises(RuntimeRefused):
            Containment(
                memory_max_mib=1024,
                cpu_quota_percent=40,
                tasks_max=8,
                file_size_max_bytes=1024,
                deadline_seconds=30,
                loopback_only=loopback,
                outbound_denied=outbound,
            )


@pytest.mark.parametrize(
    "field,value",
    [
        ("memory_max_mib", 0),
        ("cpu_quota_percent", 0),
        ("cpu_quota_percent", 101),
        ("tasks_max", 0),
        ("file_size_max_bytes", 0),
        ("deadline_seconds", 0),
    ],
)
def test_a_bound_that_bounds_nothing_cannot_be_built(field, value):
    fields = dict(
        memory_max_mib=1024,
        cpu_quota_percent=40,
        tasks_max=8,
        file_size_max_bytes=1024,
        deadline_seconds=30,
        loopback_only=True,
        outbound_denied=True,
    )
    fields[field] = value
    with pytest.raises(RuntimeRefused):
        Containment(**fields)


def test_the_bounds_render_as_the_settings_that_enforce_them():
    contained = containment_for(
        memory_need_mib=1024, reserve=_reserve(), envelope_mib=8192
    )
    settings = dict(contained.as_unit_settings())
    assert settings["MemoryMax"] == "1024M"
    assert settings["CPUQuota"] == f"{CPU_QUOTA_PERCENT}%"
    assert settings["IPAddressDeny"] == "any"
    assert settings["PrivateNetwork"] == "yes"


# -- 4. HG-05 refuses even when everything else is sound ------------------


def test_an_unmeasured_reserve_refuses_a_node_that_is_sound_in_every_other_way(
    tmp_path,
):
    """**The requirement of this issue.** Catalog, artifact and runtime all
    valid, admission granted -- and still no activation.

    'Verified' and 'may be used' are not the same word.
    """

    artifact = tmp_path / "m.model"
    artifact.write_bytes(b"GGUF" + b"\x00" * 4096)

    verdict = readiness(
        admitted=True,
        runtime_id="fixture",
        artifact=inspect_artifact(artifact),
        reserve=None,
    )
    assert verdict.readiness is ActivationReadiness.REFUSED
    assert "HG-05" in verdict.reason


def test_the_reserve_is_checked_before_anything_a_node_could_go_and_fix():
    """Both hold; only one is something an operator can act on today.

    Reporting the fixable one first sends them to do work that will not help,
    and tells them the real answer afterwards.
    """

    verdict = readiness(
        admitted=False, runtime_id=None, artifact=None, reserve=None
    )
    assert "HG-05" in verdict.reason


def test_an_unadmitted_provider_is_not_activated_on_a_measured_node():
    """Admission and readiness answer different questions, and this is not a
    second place to take the admission decision."""

    verdict = readiness(
        admitted=False, runtime_id="fixture", artifact=None, reserve=_reserve()
    )
    assert verdict.readiness is ActivationReadiness.REFUSED
    assert "no provider is admitted" in verdict.reason


def test_an_unresolvable_runtime_refuses_on_a_measured_admitted_node():
    """The second of the three refusals, driven with the first satisfied."""

    verdict = readiness(
        admitted=True, runtime_id="llama-cpp", artifact=None, reserve=_reserve()
    )
    assert verdict.readiness is ActivationReadiness.REFUSED
    assert "not a runtime this build contains" in verdict.reason


def test_nobody_checked_is_not_a_pass():
    """`NOT_ASSESSED` is a third value, and it is not `REFUSED`: one is a
    decision and the other is the absence of one."""

    verdict = readiness(
        admitted=True, runtime_id=None, artifact=None, reserve=_reserve()
    )
    assert verdict.readiness is ActivationReadiness.NOT_ASSESSED
    assert verdict.readiness is not ActivationReadiness.REFUSED


def test_a_hostile_artifact_refuses_with_everything_else_satisfied(
    tmp_path, monkeypatch
):
    """Measured, admitted, runtime resolved -- and the artifact executes.

    Driven with a **package-owned fixture** runtime: a table entry made here,
    never a real provider, and nothing in this test claims an inference.
    """

    import azazel_nexus.model_runtime as module

    fixture = RuntimeBinary(
        runtime_id="fixture",
        executable="/usr/libexec/azazel/az-runtime",
        version="1",
        digest="sha256:" + "0" * 64,
        argv=("/usr/libexec/azazel/az-runtime", "--inert"),
    )
    monkeypatch.setattr(module, "RUNTIMES", {"fixture": fixture})

    artifact = tmp_path / "m.model"
    artifact.write_bytes(b"\x7fELF" + b"\x00" * 4096)
    verdict = readiness(
        admitted=True,
        runtime_id="fixture",
        artifact=module.inspect_artifact(artifact),
        reserve=_reserve(),
    )
    assert verdict.readiness is ActivationReadiness.REFUSED
    assert "unpacking" in verdict.reason or "executes" in verdict.reason


def test_everything_satisfied_reaches_ready_and_stops_there(tmp_path, monkeypatch):
    """The gate must be reachable, or it is a gate that refuses only by
    being unreachable -- and one that starts passing the day something
    upstream stops refusing, silently.

    Reaching `READY` is **not** an inference, an admitted provider or a
    started process. It is this module saying nothing further stands in the
    way, on a node built from fixtures.
    """

    import azazel_nexus.model_runtime as module

    monkeypatch.setattr(
        module,
        "RUNTIMES",
        {
            "fixture": RuntimeBinary(
                runtime_id="fixture",
                executable="/usr/libexec/azazel/az-runtime",
                version="1",
                digest="sha256:" + "0" * 64,
                argv=("/usr/libexec/azazel/az-runtime",),
            )
        },
    )
    artifact = tmp_path / "m.model"
    artifact.write_bytes(b"GGUF" + b"\x00" * 4096)

    verdict = readiness(
        admitted=True,
        runtime_id="fixture",
        artifact=module.inspect_artifact(artifact),
        reserve=_reserve(),
    )
    assert verdict.readiness is ActivationReadiness.READY
    assert verdict.reason == ""
