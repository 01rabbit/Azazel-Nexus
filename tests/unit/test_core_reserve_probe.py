"""The harness that would measure the Core reserve (#68).

It has never been run on target hardware, so what is tested here is what it
**refuses** and what shape its output takes -- driven through injected
readers, so the tests are not the host.

The refusals are the substance. A number produced by the wrong run is worse
than no number, because it looks like the one that was missing.
"""

from __future__ import annotations

import ast
import json
import pathlib
from dataclasses import replace

import pytest
from azazel_nexus_runtime import core_reserve_probe as probe
from azazel_nexus_runtime.core_reserve_probe import (
    HARNESS_VERSION,
    SAMPLE_COUNT,
    SAMPLE_INTERVAL_SECONDS,
    SUBSYSTEM_UNITS,
    MeasurementRefused,
    Readers,
    measure,
    write_record,
)

from azazel_nexus_runtime.platform_observation import HostObservation

from azazel_nexus.activation import CORE_UNITS
from azazel_nexus.core_reserve import (
    MIN_DURATION_SECONDS,
    MIN_SAMPLES,
    REQUIRED_SUBSYSTEMS,
    Provenance,
    parse_record,
    validate,
)
from azazel_nexus.resource_profile import ResourceProfile
from azazel_nexus.virtualization import SENSORS

#: Enough usable memory to classify as `lite`, so `select_profile` has a real
#: input rather than a profile handed to it.
LITE_MIB = 16000

REPOSITORY = pathlib.Path(__file__).resolve().parents[2]

#: What the deployment baseline reports, and what the arm64 lab VM reports.
#: Injected: no host was observed.
BASELINE_HOST = HostObservation(
    sysname="Linux", release="6.12.0-test", machine="x86_64", os_id="debian",
    os_version_id="13", soabi="cpython-313-x86_64-linux-gnu", lp64=True,
    byteorder="little", dpkg_architecture="amd64")
ARM64_LAB_HOST = replace(BASELINE_HOST, machine="aarch64",
                         soabi="cpython-313-aarch64-linux-gnu", dpkg_architecture="arm64")


def a_caller(inactive=(), inactive_after=()):
    """A D-Bus stand-in. `inactive_after` starts reporting after the samples."""

    state = {"calls": 0, "sampled": False}

    def call(method, unit):
        assert method in probe.READ_ONLY_METHODS, method
        state["calls"] += 1
        subsystem = next(s for s, u in SUBSYSTEM_UNITS.items() if u == unit)
        if subsystem in inactive:
            return {"ActiveState": "inactive", "SubState": "dead"}
        if state["sampled"] and subsystem in inactive_after:
            return {"ActiveState": "failed", "SubState": "failed"}
        return {"ActiveState": "active", "SubState": "running"}

    return call, state


def readers(*, inactive=(), inactive_after=(), residents=None, usable=LITE_MIB, usable_after=None,
            platform=lambda: BASELINE_HOST):
    call, state = a_caller(inactive=inactive, inactive_after=inactive_after)
    produced = {"n": 0}

    def cgroup_current():
        index = produced["n"]
        produced["n"] += 1
        if produced["n"] >= SAMPLE_COUNT:
            state["sampled"] = True
        if residents is None:
            return (1000 + index) * 1024 * 1024
        value = residents[index] if index < len(residents) else residents[-1]
        if isinstance(value, Exception):
            raise value
        return value

    usable_values = {"n": 0}

    def usable_mib():
        usable_values["n"] += 1
        if usable_values["n"] > 1 and usable_after is not None:
            return usable_after
        return usable

    return Readers(
        identity=lambda: {
            "host_digest": "hmac-sha256:" + "a" * 64,
            "boot_fingerprint": "hmac-sha256:" + "b" * 64,
            "build_commit": "c" * 40,
            "kernel_release": "test-kernel",
        },
        run_sequence=lambda: 1,
        virtualization=lambda: dict.fromkeys(SENSORS, "clear"),
        call=call,
        cgroup_current=cgroup_current,
        usable_mib=usable_mib,
        sleep=lambda _seconds: None,
        platform=platform,
    )


# -- a complete run -------------------------------------------------------


def test_a_complete_run_produces_a_record_its_own_validator_admits() -> None:
    """A harness whose output its validator refuses is a harness nobody can use."""

    record = measure(readers())
    assert record.provenance is Provenance.MEASURED
    assert record.harness_version == HARNESS_VERSION
    assert record.profile is ResourceProfile.LITE
    assert len(record.samples) == SAMPLE_COUNT
    assert validate(record).admissible


def test_the_harness_constants_clear_the_validator_s_floors() -> None:
    """Checked as arithmetic, not by running: the two must not drift apart.

    `SAMPLE_COUNT` and `SAMPLE_INTERVAL_SECONDS` live in the harness and
    `MIN_SAMPLES` and `MIN_DURATION_SECONDS` live in the validator. Lowering
    either of the first pair without noticing would make every real run a near
    miss, discovered on the hardware and not here.
    """

    assert SAMPLE_COUNT >= MIN_SAMPLES
    assert (SAMPLE_COUNT - 1) * SAMPLE_INTERVAL_SECONDS >= MIN_DURATION_SECONDS


def test_the_record_round_trips_through_the_file_it_writes(tmp_path) -> None:
    record = replace(measure(readers()), provenance=Provenance.FIXTURE)
    path = write_record(record, tmp_path / "core-reserve.json")
    assert parse_record(path.read_text(encoding="utf-8")) == record


def test_the_host_digest_carries_no_inventory() -> None:
    """Enough to tell two hosts apart, and no more.

    A record that carried a host's inventory would be a record that leaks one
    when it is pasted into a ticket.
    """

    record = measure(readers())
    assert record.host_digest.startswith("hmac-sha256:")
    assert len(record.host_digest) == len("hmac-sha256:") + 64
    assert record.boot_fingerprint.startswith("hmac-sha256:")
    assert record.run_sequence == 1
    assert record.build_commit == "c" * 40
    assert record.kernel_release == "test-kernel"


# -- what it refuses ------------------------------------------------------


def test_no_service_manager_is_a_refusal_not_an_assumption() -> None:
    """A reserve measured without knowing what was running is of an unknown node."""

    with pytest.raises(MeasurementRefused) as caught:
        measure(Readers(call=None, platform=lambda: BASELINE_HOST))
    assert "service manager" in str(caught.value)


def test_a_subsystem_that_was_never_up_is_named() -> None:
    with pytest.raises(MeasurementRefused) as caught:
        measure(readers(inactive=("audit",)))
    assert "audit" in str(caught.value) and "began" in str(caught.value)


def test_a_subsystem_that_stopped_during_the_run_refuses_the_whole_run() -> None:
    """The two-check property, and the reason it is two.

    A run that passed the first check and failed the second produced samples
    of two different nodes, and there is no way to tell which sample was the
    last of the first node. Keeping the samples up to the failure would be
    recording a shorter run that does not say so.
    """

    with pytest.raises(MeasurementRefused) as caught:
        measure(readers(inactive_after=("lease_journal",)))
    assert "lease_journal" in str(caught.value) and "ended" in str(caught.value)


def test_every_required_subsystem_is_actually_checked() -> None:
    """Otherwise the two tests above pass on the one subsystem they name."""

    for subsystem in REQUIRED_SUBSYSTEMS:
        with pytest.raises(MeasurementRefused) as caught:
            measure(readers(inactive=(subsystem,)))
        assert subsystem in str(caught.value)


def test_every_required_subsystem_has_a_unit_to_observe_it() -> None:
    """A subsystem with no unit cannot be observed, and unobserved is not active."""

    assert set(SUBSYSTEM_UNITS) == set(REQUIRED_SUBSYSTEMS)


def test_a_sample_that_cannot_be_read_refuses_the_run() -> None:
    with pytest.raises(MeasurementRefused) as caught:
        measure(readers(residents=[1000 * 1024 * 1024, OSError("no such file")]))
    assert "hole in it" in str(caught.value)


def test_a_non_positive_sample_refuses_the_run_at_the_sample() -> None:
    """Asserted on the sampler's own wording, and a mutation showed why.

    The first version of this test asserted `"positive" in` the message. The
    sampler's guard and the validator's both use that word, so removing the
    sampler's guard left the test passing -- the run completed, the validator
    caught the zero at the end, and the message still said "positive". It was
    green for the wrong reason: a refusal that names the sample had become a
    refusal that names the run.

    The distinction matters. The sampler refuses at sample 0 of 60; the
    validator refuses after the node has been held under load for ten minutes.
    """

    with pytest.raises(MeasurementRefused) as caught:
        measure(readers(residents=[0]))
    message = str(caught.value)
    assert "sample 0 read 0 bytes" in message
    assert "does not validate" not in message


def test_a_memory_class_that_changed_during_the_run_refuses_it() -> None:
    """The reserve is per class, so samples spanning two classes are of neither."""

    with pytest.raises(MeasurementRefused) as caught:
        measure(readers(usable=LITE_MIB, usable_after=8000))
    assert "class changed" in str(caught.value)


def test_a_refusal_writes_nothing(tmp_path) -> None:
    """There is no partial record, because a partial one does not say it is."""

    path = tmp_path / "core-reserve.json"
    with pytest.raises(MeasurementRefused):
        record = measure(readers(inactive=("arbiter",)))
        write_record(record, path)
    assert not path.exists()


# -- nothing can redirect it ----------------------------------------------


def test_main_accepts_no_argument_that_changes_what_is_measured() -> None:
    """A harness that took a cgroup could report any cgroup as the Core reserve."""

    tree = ast.parse(pathlib.Path(probe.__file__).read_text(encoding="utf-8"))
    main = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    added = [
        node
        for node in ast.walk(main)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_argument"
    ]
    assert added == [], "main declares an argument"


def test_main_refuses_on_a_host_with_no_service_manager(capsys) -> None:
    """Which is every host this test suite runs on."""

    assert probe.main([]) == 2
    assert "refused" in capsys.readouterr().err


def test_the_paths_it_reads_are_constants_not_arguments() -> None:
    assert str(probe.CGROUP_CURRENT).startswith("/sys/fs/cgroup/")
    assert str(probe.MEMINFO) == "/proc/meminfo"


def test_the_harness_executes_nothing() -> None:
    """Unlike `edge_probed`, it has nothing to exempt from the runtime scan."""

    tree = ast.parse(pathlib.Path(probe.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert {"subprocess", "shlex", "pty"} & imported == set()


def test_the_write_methods_are_absent_from_the_allowlist() -> None:
    assert set(probe.READ_ONLY_METHODS) == {"GetUnit", "GetUnitProperties"}
    for method in ("StartUnit", "StopUnit", "RestartUnit", "EnableUnitFiles"):
        assert method not in probe.READ_ONLY_METHODS


def test_the_harness_is_a_console_script_and_not_a_unit_the_node_runs() -> None:
    """Operator-invoked on target hardware, not something a node does.

    `az-edge-probed` is a unit because every node probes its Edge package.
    A measurement campaign happens once per hardware class, so a masked unit
    for it would sit on every node describing work no node performs -- and
    `CORE_UNITS` is the list of what this node runs.

    An operator on the target host runs `az-core-reserve-probe` directly;
    `docs/core-reserve-measurement.md` is the procedure.
    """

    manifest = (REPOSITORY / "runtime" / "pyproject.toml").read_text(encoding="utf-8")
    assert "az-core-reserve-probe = " in manifest
    assert all("core-reserve" not in unit.name for unit in CORE_UNITS)
    assert list((REPOSITORY / "packaging" / "systemd").glob("*core-reserve*")) == []


def test_the_harness_refuses_a_run_its_own_validator_would_reject(monkeypatch) -> None:
    """The last guard in `measure`, made reachable so it is not merely present.

    Nothing in the sampling loop can currently produce a record the validator
    refuses, so this guard is unreachable in the shipped configuration -- and
    a mutation removing it survived the whole suite. It exists for exactly one
    scenario: somebody lowers `SAMPLE_COUNT` or `SAMPLE_INTERVAL_SECONDS` and
    the harness starts producing records that are refused on arrival.

    So that scenario is what is driven. Without the guard the run would write
    a record its own validator rejects, and a record that fails validation on
    disk is a record somebody will eventually relax the validator for.
    """

    monkeypatch.setattr(probe, "SAMPLE_COUNT", 3)
    with pytest.raises(MeasurementRefused) as caught:
        measure(readers())
    message = str(caught.value)
    assert "does not validate" in message
    assert str(MIN_SAMPLES) in message


def test_runs_never_overwrite_and_sequence_survives_restart(tmp_path):
    record = replace(measure(readers()), provenance=Provenance.FIXTURE)
    first = write_record(record, tmp_path / "core-reserve.json")
    payload = first.read_bytes()
    with pytest.raises(FileExistsError):
        write_record(record, tmp_path / "core-reserve.json")
    assert first.read_bytes() == payload
    assert probe.next_sequence(tmp_path) == 2
    second = write_record(replace(record, run_sequence=2), tmp_path / "core-reserve.json")
    assert first != second
    assert not (tmp_path / "core-reserve.json").exists()


def test_identity_failure_refuses_before_sampling():
    supplied = readers()
    def refused():
        raise ValueError("private detail")
    with pytest.raises(MeasurementRefused, match="metadata unavailable"):
        measure(replace(supplied, identity=refused))


def test_boot_change_refuses_entire_run():
    supplied = readers()
    identity = supplied.identity()
    count = iter([identity, dict(identity, boot_fingerprint="hmac-sha256:" + "d" * 64)])
    with pytest.raises(MeasurementRefused, match="identity changed"):
        measure(replace(supplied, identity=lambda: next(count)))


@pytest.mark.parametrize("failure,expected", [
    (probe.MeasurementRefused("required subsystems inactive"), "required subsystems inactive"),
    (FileExistsError("private path"), "concurrent run"),
    (RuntimeError("private details"), "sampling or publication failed"),
])
def test_main_reports_safe_refusal_reasons(monkeypatch, capsys, failure, expected):
    from azazel_nexus_runtime import hil_readiness

    class Manager:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

    def fail(*_):
        raise failure

    monkeypatch.setattr(hil_readiness, "ReadOnlySystemd", Manager)
    monkeypatch.setattr(probe, "measure", fail)
    assert probe.main([]) == 2
    output = capsys.readouterr()
    assert expected in output.err
    assert "private" not in output.err


# -- the CPU the run was measured on (core-reserve/4, ADR-0003 R2) ---------


def test_a_run_records_the_observed_cpu_and_profile() -> None:
    record = measure(readers())
    assert record.schema == "azazel-nexus/core-reserve/4"
    assert (record.architecture, record.platform_profile_id) == ("amd64", "debian-13-amd64-cp313")
    assert parse_record(json.dumps(probe.record_as_document(record))) == record


@pytest.mark.parametrize(("host", "reason"), [
    (ARM64_LAB_HOST, "LAB_PROFILE_NOT_FOR_PRODUCTION"),
    (replace(BASELINE_HOST, machine="riscv64"), "UNKNOWN_ARCHITECTURE"),
    (replace(BASELINE_HOST, soabi="cpython-312-x86_64-linux-gnu"), "UNREVIEWED_PYTHON_ABI"),
    (replace(BASELINE_HOST, dpkg_architecture="i386"), "DPKG_ARCHITECTURE_MISMATCH"),
    (replace(BASELINE_HOST, os_version_id="12"), "UNREVIEWED_OS"),
])
def test_a_host_that_is_not_the_baseline_is_refused_before_sampling(host, reason) -> None:
    sampled = []
    run = replace(readers(platform=lambda: host),
                  cgroup_current=lambda: sampled.append(1) or 1 << 30)
    with pytest.raises(MeasurementRefused, match=reason):
        measure(run)
    assert sampled == []


def test_an_unreadable_platform_is_refused() -> None:
    def broken():
        raise OSError("no uname")

    with pytest.raises(MeasurementRefused, match="could not be observed"):
        measure(readers(platform=broken))


def test_a_platform_that_changes_during_the_run_refuses_it() -> None:
    hosts = iter([BASELINE_HOST, replace(BASELINE_HOST, release="6.12.1-test")])
    with pytest.raises(MeasurementRefused, match="platform observation changed"):
        measure(readers(platform=lambda: next(hosts)))
