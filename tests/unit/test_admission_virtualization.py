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
