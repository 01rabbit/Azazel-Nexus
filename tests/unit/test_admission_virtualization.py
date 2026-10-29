"""Virtualization is a negative file observation, never hardware attestation."""
from dataclasses import replace

import pytest
from azazel_nexus_runtime import virtualization_observation as observation

from azazel_nexus.virtualization import SENSORS, virtualization_not_observed


@pytest.mark.parametrize("sensor", SENSORS)
@pytest.mark.parametrize("state", ["observed", "unknown"])
def test_any_observed_or_unknown_sensor_refuses(sensor, state):
    values = dict.fromkeys(SENSORS, "clear")
    values[sensor] = state
    assert not virtualization_not_observed(values)


def test_file_observer_catches_container_hypervisor_and_dmi(tmp_path, monkeypatch):
    files = {}
    for name in SENSORS:
        path = tmp_path / name
        if name not in ("dockerenv", "systemd_container", "hypervisor_type"):
            path.write_text("normal bare-metal observation")
        files[name] = str(path)
    (tmp_path / "cpu_hypervisor").write_text("flags\t\t: fpu vme sse2\n")
    monkeypatch.setattr(observation, "_FILES", files)
    assert virtualization_not_observed(observation.observe_virtualization())
    (tmp_path / "dockerenv").touch()
    assert observation.observe_virtualization()["dockerenv"] == "observed"
    (tmp_path / "dockerenv").unlink()
    (tmp_path / "cpu_hypervisor").write_text("flags: hypervisor avx2")
    assert observation.observe_virtualization()["cpu_hypervisor"] == "observed"
    (tmp_path / "dmi_vendor").write_text("QEMU")
    assert observation.observe_virtualization()["dmi_vendor"] == "observed"
    # Apple's Virtualization.framework guest DMI, observed in the container
    # rehearsal; "Virtual Machine" alone did not match it.
    (tmp_path / "dmi_product").write_text("Apple Virtualization Generic Platform\n")
    assert observation.observe_virtualization()["dmi_product"] == "observed"


def test_probe_refuses_virtualized_and_unknown_observations_before_samples():
    from azazel_nexus_runtime.core_reserve_probe import MeasurementRefused, measure
    from test_core_reserve_probe import readers

    supplied = replace(readers(), virtualization=lambda: dict.fromkeys(SENSORS, "observed"),
                       cgroup_current=lambda: pytest.fail("virtualized probe sampled"))
    with pytest.raises(MeasurementRefused, match="RESERVE_VIRTUALIZATION_OBSERVED"):
        measure(supplied)


def test_hil_manifest_cannot_begin_with_approval_domain_prefix():
    from nacl.signing import SigningKey

    from azazel_nexus.hil_records.evidence import RecordRefused, verified_manifest_bytes

    key = SigningKey.generate()
    with pytest.raises(RecordRefused):
        verified_manifest_bytes({"manifest.json": b"azazel-nexus/operator-approval/v1\0{}"},
                                public_key=bytes(key.verify_key))


# -- ADR-0003 R1 / owner-decisions H4: the x86 flag on a CPU without it --

X86_CPUINFO = "processor\t: 0\nvendor_id\t: GenuineIntel\nflags\t\t: fpu vme sse2 avx2\n"
X86_GUEST_CPUINFO = "processor\t: 0\nflags\t\t: fpu vme sse2 hypervisor\n"
#: aarch64 publishes `Features`, never an x86 `flags` line.
ARM_CPUINFO = "processor\t: 0\nFeatures\t: fp asimd evtstrm aes\nCPU implementer\t: 0x61\n"


def _files(tmp_path, monkeypatch, *, cpuinfo, dmi=("Generic Vendor", "Generic Board")):
    """The real observer over files; ``dmi=None`` is a board without DMI."""
    files = {name: str(tmp_path / name) for name in SENSORS}
    (tmp_path / "cpu_hypervisor").write_text(cpuinfo)
    (tmp_path / "init_cgroup").write_text("0::/init.scope\n")
    if dmi is not None:
        (tmp_path / "dmi_vendor").write_text(dmi[0])
        (tmp_path / "dmi_product").write_text(dmi[1])
    monkeypatch.setattr(observation, "_FILES", files)
    return observation.observe_virtualization()


@pytest.mark.parametrize(("cpuinfo", "reading"), [
    (X86_CPUINFO, "clear"), (X86_GUEST_CPUINFO, "observed"),
    (ARM_CPUINFO, "unobservable"), ("", "unknown"),
    # A `flags` word elsewhere is not the x86 flags line.
    ("Features\t: fp asimd\nflagsx: y\n", "unobservable"),
])
def test_the_cpu_flag_sensor_is_unobservable_without_an_x86_flags_line(
        cpuinfo, reading, tmp_path, monkeypatch):
    assert _files(tmp_path, monkeypatch, cpuinfo=cpuinfo)["cpu_hypervisor"] == reading


@pytest.mark.parametrize(("architecture", "cpu", "admitted"), [
    (None, "clear", True), ("amd64", "clear", True), ("x86_64", "clear", True),
    (None, "unobservable", False), ("amd64", "unobservable", False),
    ("arm64", "unobservable", True), ("aarch64", "unobservable", True),
    # The reading observers wrote before 2026-10-30 for a flag that is not there.
    ("arm64", "clear", False), ("aarch64", "clear", False),
    ("arm64", "observed", False), ("arm64", "absent", False), ("arm64", "unknown", False),
    ("riscv64", "clear", False), ("riscv64", "unobservable", False),
    ("", "clear", False), (1, "clear", False),
])
def test_the_filter_reads_the_cpu_flag_for_the_observed_cpu(architecture, cpu, admitted):
    values = dict(dict.fromkeys(SENSORS, "clear"), cpu_hypervisor=cpu)
    assert virtualization_not_observed(values, architecture) is admitted


@pytest.mark.parametrize("sensor", [s for s in SENSORS if s != "cpu_hypervisor"])
def test_unobservable_is_never_a_negative_finding_for_another_sensor(sensor):
    values = dict(dict.fromkeys(SENSORS, "clear"), cpu_hypervisor="unobservable")
    values[sensor] = "unobservable"
    assert not virtualization_not_observed(values, "arm64")


@pytest.mark.parametrize("sensor", ["dmi_vendor", "dmi_product", "init_cgroup"])
@pytest.mark.parametrize("state", ["absent", "unknown", "observed"])
def test_arm64_needs_the_generic_sensors_read_and_clear(sensor, state):
    """With the x86 flag unobservable, nothing else may be unobserved either."""
    values = dict(dict.fromkeys(SENSORS, "clear"), cpu_hypervisor="unobservable")
    values[sensor] = state
    assert not virtualization_not_observed(values, "arm64")


def test_arm64_with_every_sensor_unobserved_is_refused():
    values = dict(dict.fromkeys(SENSORS, "absent"), cpu_hypervisor="unobservable")
    assert not virtualization_not_observed(values, "arm64")


@pytest.mark.parametrize(("cpuinfo", "dmi", "architecture", "admitted"), [
    (X86_CPUINFO, ("Generic Vendor", "Generic Board"), "x86_64", True),
    (X86_GUEST_CPUINFO, ("Generic Vendor", "Generic Board"), "x86_64", False),
    (X86_CPUINFO, ("QEMU", "Standard PC"), "x86_64", False),
    (X86_CPUINFO, None, "x86_64", False),
    # Arm, DMI read and clear: decided on the generic sensors alone.
    (ARM_CPUINFO, ("Generic Vendor", "Generic Board"), "aarch64", True),
    # ... and only when read for aarch64.
    (ARM_CPUINFO, ("Generic Vendor", "Generic Board"), None, False),
    (ARM_CPUINFO, ("Generic Vendor", "Generic Board"), "x86_64", False),
    # The VMware Fusion Arm guest of V3 (DMI names VMware).
    (ARM_CPUINFO, ("VMware, Inc.", "VMware20,1"), "aarch64", False),
    # An Arm board without DMI: nothing read is not "not virtualized".
    (ARM_CPUINFO, None, "aarch64", False),
])
def test_cpu_and_dmi_combinations_through_the_real_observer(
        cpuinfo, dmi, architecture, admitted, tmp_path, monkeypatch):
    values = _files(tmp_path, monkeypatch, cpuinfo=cpuinfo, dmi=dmi)
    assert virtualization_not_observed(values, architecture) is admitted

