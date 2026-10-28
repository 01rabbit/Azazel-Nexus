"""Injected observations only: these tests neither acquire nor write evidence."""

import json
import os
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import hil_capture as capture
from azazel_nexus_runtime import hil_readiness as readiness


class Manager:
    def unit_files(self):
        return {unit: "enabled" for unit in readiness.CAPTURE_UNITS}

    def version(self):
        return "test-systemd"

    def __call__(self, method, unit):
        assert method == "GetUnitProperties"
        assert unit in readiness.CAPTURE_UNITS
        return {"ActiveState": "active", "SubState": "running", "LoadState": "loaded"}


def test_readiness_reports_each_missing_edge_core_prerequisite():
    report = readiness.readiness(key_reader=lambda: b"test", memory_reader=lambda: 8000)
    assert not report["ready"]
    assert report["edge_core_prerequisites_missing_or_unobserved"] == list(readiness.REQUIRED_UNITS)
    assert "Edge Core" in report["prerequisite"]
    assert all(state["present"] is None for state in report["units"].values())


def test_readiness_requires_units_key_and_target_class():
    def unavailable():
        raise OSError("private detail")
    report = readiness.readiness(Manager(), key_reader=lambda: b"test", memory_reader=lambda: 8000)
    assert report["ready"]
    assert not readiness.readiness(Manager(), key_reader=unavailable,
                                   memory_reader=lambda: 8000)["ready"]
    assert not readiness.readiness(Manager(), key_reader=lambda: b"test",
                                   memory_reader=lambda: 16000)["ready"]
    class Missing(Manager):
        def unit_files(self):
            return {}
    assert not readiness.readiness(Missing(), key_reader=lambda: b"test",
                                   memory_reader=lambda: 8000)["ready"]


def test_hg01_captures_all_governed_units():
    report = capture.capture_hg01(Manager())
    assert report["systemd_version"] == "test-systemd"
    assert set(report["unit_files"]) == set(readiness.CAPTURE_UNITS)
    assert set(report["units"]) == set(readiness.CAPTURE_UNITS)
    assert "synthetic" not in report


def test_hg04_never_emits_raw_names_or_addresses():
    from nacl.utils import random

    key = random(32)
    links = [SimpleNamespace(index=1, name="test-private-name", permanent_mac="02:00:00:00:00:01"),
             SimpleNamespace(index=2, name="test-missing-address", permanent_mac=None,
                             reason="the driver reports no permanent address for this interface")]
    report = capture.capture_hg04(links_reader=lambda: links, key_reader=lambda: key)
    text = json.dumps(report)
    assert links[0].name not in text
    assert links[0].permanent_mac not in text
    assert report["interfaces"][0]["ifla_perm_address_present"]
    assert not report["interfaces"][1]["ifla_perm_address_present"]
    assert report["interfaces"][1]["permanent_address_fingerprint"] is None
    other = capture.capture_hg04(links_reader=lambda: links, key_reader=lambda: random(32))
    assert report != other


def test_capture_refusal_does_not_print_exception_identity(monkeypatch, capsys):
    def refused():
        raise ValueError("private-identifier")
    from azazel_nexus.virtualization import SENSORS

    monkeypatch.setattr(capture, "observe_virtualization", lambda: dict.fromkeys(SENSORS, "clear"))
    monkeypatch.setattr(capture, "run_identity", refused)
    assert capture.main(["hg-04"]) == 2
    output = capsys.readouterr()
    assert not output.out
    assert "private-identifier" not in output.err


def test_key_reader_refuses_symlinks_wrong_owner_mode_and_size(tmp_path, monkeypatch, private_os):
    private_os(readiness)
    from nacl.utils import random

    directory = tmp_path / "secrets"
    directory.mkdir(mode=0o700)
    path = directory / "commissioning.key"
    path.write_bytes(random(32))
    path.chmod(0o600)
    # Mac runner is not root. Fake only the owner in fstat/lstat to drive all
    # remaining production guards with ephemeral test key material.
    real_fstat, real_lstat = os.fstat, readiness.Path.lstat
    def root_info(info):
        values = list(info)
        values[4] = 0
        return os.stat_result(values)
    monkeypatch.setattr(readiness.os, "fstat", lambda fd: root_info(real_fstat(fd)))
    monkeypatch.setattr(readiness.Path, "lstat", lambda p: root_info(real_lstat(p)))
    assert len(readiness.protection_key(path)) == 32
    path.chmod(0o644)
    with pytest.raises(ValueError):
        readiness.protection_key(path)
    path.chmod(0o600)
    path.write_bytes(b"test")
    with pytest.raises(ValueError):
        readiness.protection_key(path)
    link = directory / "alias"
    link.symlink_to(path)
    with pytest.raises(OSError):
        readiness.protection_key(link)
    directory.chmod(0o755)
    with pytest.raises(ValueError):
        readiness.protection_key(path)


def test_read_only_bus_rejects_mutating_methods_and_arbitrary_units():
    manager = readiness.ReadOnlySystemd()
    for method in ("StartUnit", "StopUnit", "LoadUnit", "UnmaskUnitFiles", "EnableUnitFiles"):
        with pytest.raises(ValueError, match="read-only"):
            manager._read(method)
    with pytest.raises(ValueError, match="allowlist"):
        manager("GetUnitProperties", "unrelated.service")


def test_read_only_unit_file_list_omits_paths_and_unrelated_units():
    manager = readiness.ReadOnlySystemd()
    manager._read = lambda *a, **kw: SimpleNamespace(signature="a(ss)", body=[[
        ["/etc/systemd/system/azazel.slice", "enabled"],
        ["/private/host-identity.service", "enabled"],
    ]])
    assert manager.unit_files() == {"azazel.slice": "enabled"}


def test_boot_and_host_identity_are_domain_separated_and_never_rendered(tmp_path, monkeypatch):
    from nacl.utils import random

    key = random(32)
    monkeypatch.setattr(readiness, "protection_key", lambda: key)
    for name, value in [("BOOT_ID", "00000000-0000-4000-8000-000000000001"),
                        ("MACHINE_ID", "test-private-machine"), ("BUILD_COMMIT", "a" * 40)]:
        path = tmp_path / name
        path.write_text(value)
        monkeypatch.setattr(readiness, name, path)
    identity = readiness.run_identity()
    text = json.dumps(identity)
    assert "test-private-machine" not in text
    assert readiness.BOOT_ID.read_text() not in text
    assert identity["boot_fingerprint"] != identity["host_digest"]
    readiness.BUILD_COMMIT.write_text("unknown")
    with pytest.raises(ValueError, match="build identity"):
        readiness.run_identity()


def test_missing_proc_memory_is_blocked_not_an_exception():
    from azazel_nexus.resource_profile import UsableMemoryUnavailable

    def missing():
        raise UsableMemoryUnavailable("private path")
    report = readiness.readiness(memory_reader=missing)
    assert not report["ready"]
    assert not report["target_class_present"]
    assert "private path" not in json.dumps(report)


def test_hg04_attribute_presence_does_not_claim_usable_address():
    links = [SimpleNamespace(index=1, name="test", permanent_mac=None,
                             reason="the permanent address is all zeroes, which is what a driver reports")]
    report = capture.capture_hg04(links_reader=lambda: links, key_reader=lambda: b"test")
    interface = report["interfaces"][0]
    assert interface["ifla_perm_address_present"]
    assert not interface["permanent_address_usable"]
    assert interface["permanent_address_fingerprint"] is None
