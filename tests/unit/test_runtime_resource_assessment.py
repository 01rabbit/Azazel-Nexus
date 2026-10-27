"""Synthetic aggregate readings; no device, mount or network operations."""

import json
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime import commission_cli, resource_assessment as resources


@pytest.mark.parametrize("text, count", [("0", 1), ("0-3\n", 4), ("0-2,4,7-8", 6)])
def test_online_logical_cpu_count(monkeypatch, text, count):
    monkeypatch.setattr(resources.Path, "read_text", lambda *a, **k: text)
    assert resources._online_cores() == count


@pytest.mark.parametrize("text", ["", "0-1,1", "4-2", "65536", "0-99999999", "0,,2", "private-data"])
def test_malformed_cpu_sets_refused(monkeypatch, text):
    monkeypatch.setattr(resources.Path, "read_text", lambda *a, **k: text)
    with pytest.raises(ValueError):
        resources._online_cores()


@pytest.fixture
def space(monkeypatch, private_os):
    private_os(resources)
    opened, closed = [], []
    def open_directory(path, flags):
        opened.append((path, flags))
        return 123
    monkeypatch.setattr(resources.os, "open", open_directory)
    monkeypatch.setattr(resources.os, "close", closed.append)
    monkeypatch.setattr(resources.os, "fstat", lambda fd: SimpleNamespace(st_dev=2))
    monkeypatch.setattr(resources.os, "stat", lambda path: SimpleNamespace(st_dev=1))
    monkeypatch.setattr(resources.os, "fstatvfs", lambda fd: SimpleNamespace(
        f_frsize=4096, f_bavail=512, f_bfree=768, f_blocks=1024, f_flag=0))
    return opened, closed


def test_storage_measures_available_not_total_and_closes_descriptor(space):
    assert resources._mission_space() == 2
    opened, closed = space
    assert opened[0][0] == "/data"
    assert opened[0][1] & resources.os.O_NOFOLLOW
    assert opened[0][1] & resources.os.O_DIRECTORY
    assert closed == [123]


def test_root_backed_mission_directory_has_no_fallback(space, monkeypatch):
    monkeypatch.setattr(resources.os, "fstat", lambda fd: SimpleNamespace(st_dev=1))
    monkeypatch.setattr(resources.os, "fstatvfs", lambda fd: pytest.fail("root fallback"))
    with pytest.raises(ValueError):
        resources._mission_space()
    assert space[1] == [123]


@pytest.mark.parametrize("changes", [{"f_bavail": -1}, {"f_bavail": 900},
                                    {"f_frsize": 0}])
def test_invalid_or_readonly_storage_refused(space, monkeypatch, changes):
    stats = dict(f_frsize=4096, f_bavail=512, f_bfree=768, f_blocks=1024, f_flag=0)
    monkeypatch.setattr(resources.os, "fstatvfs", lambda fd: SimpleNamespace(**(stats | changes)))
    with pytest.raises(ValueError):
        resources._mission_space()
    assert space[1] == [123]


@pytest.mark.parametrize("architecture", ["aarch64", "x86_64"])
def test_assessment_reports_measurements_without_admission(monkeypatch, architecture):
    monkeypatch.setattr(resources, "read_usable_mib", lambda: 7500)
    monkeypatch.setattr(resources, "_online_cores", lambda: 4)
    monkeypatch.setattr(resources, "_mission_space", lambda: 0)
    monkeypatch.setattr(resources.platform, "machine", lambda: architecture)
    result = resources.assess_resources()
    assert result["measurements"] == dict(usable_memory_mib=7500, online_logical_cpus=4, mission_available_mib=0)
    assert result["unavailable"] == []
    assert result["admission"] == "not-evaluated"
    assert "gpu-unmeasured" in result["limitations"]


def test_failed_measurements_are_null_and_do_not_leak_details(monkeypatch):
    def fail():
        raise OSError("private-identity")
    for name in ("read_usable_mib", "_online_cores", "_mission_space"):
        monkeypatch.setattr(resources, name, fail)
    result = resources.assess_resources()
    assert set(result["measurements"]) <= set(result["unavailable"])
    assert all(value is None for value in result["measurements"].values())
    assert "private-identity" not in json.dumps(result)


def test_unknown_architecture_remains_unavailable(monkeypatch):
    monkeypatch.setattr(resources.platform, "machine", lambda: "unknown-architecture")
    monkeypatch.setattr(resources, "read_usable_mib", lambda: 7500)
    monkeypatch.setattr(resources, "_online_cores", lambda: 4)
    monkeypatch.setattr(resources, "_mission_space", lambda: 10)
    result = resources.assess_resources()
    assert result["architecture"] is None
    assert result["unavailable"] == ["architecture"]


@pytest.mark.parametrize("missing, expected", [([], 0), (["mission_available_mib"], 1)])
def test_cli_resources_uses_real_assessor_without_inventory_or_activation(monkeypatch, capsys, missing, expected):
    monkeypatch.setattr(commission_cli, "assess_resources", lambda: {"unavailable": missing})
    monkeypatch.setattr(commission_cli, "library_main", lambda *a, **k: pytest.fail("library invoked"))
    assert commission_cli.main(["resources"]) == expected
    assert json.loads(capsys.readouterr().out) == {"unavailable": missing}
