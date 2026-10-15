"""Local identity reader tests with synthetic procfs bytes; no service access."""

from pathlib import Path

import pytest

from azazel_nexus_runtime import bootstrap_controller_identity as module
from azazel_nexus_runtime.units import UnitOperationFailed

_RAW = b"0::/system.slice/azazel-activated.service\n"
_INVOCATION = "a1" * 16


@pytest.fixture
def identity_inputs(monkeypatch):
    monkeypatch.setattr(module, "ROOT", Path("/"))
    monkeypatch.setattr(module.os, "getpid", lambda: 1234)
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setenv("INVOCATION_ID", _INVOCATION)
    monkeypatch.setattr(module, "_namespaces", lambda: (1, 2))
    calls = []

    def read(path, limit):
        calls.append((path, limit))
        return _RAW

    monkeypatch.setattr(module, "_read_proc", read)
    return calls


def test_fixed_identity_is_read_twice_without_dbus(identity_inputs):
    observed = module.current_bootstrap_controller_identity()
    assert observed.pid == 1234
    assert observed.invocation_id == bytes.fromhex(_INVOCATION)
    assert observed.control_group == "/system.slice/azazel-activated.service"
    assert identity_inputs == [("/proc/1234/cgroup", 4096)] * 2


@pytest.mark.parametrize("case", ["nonroot", "relocated", "missing", "zero", "invalid"])
def test_missing_context_refuses_before_proc_read(identity_inputs, monkeypatch, case):
    if case == "nonroot":
        monkeypatch.setattr(module.os, "geteuid", lambda: 1000)
    elif case == "relocated":
        monkeypatch.setattr(module, "ROOT", Path("/relocated"))
    elif case == "missing":
        monkeypatch.delenv("INVOCATION_ID")
    else:
        monkeypatch.setenv("INVOCATION_ID", "00" * 16 if case == "zero" else "unknown")
    with pytest.raises(UnitOperationFailed):
        module.current_bootstrap_controller_identity()
    assert not identity_inputs


@pytest.mark.parametrize("raw", [
    b"0::/\n", b"0::/system.slice/other.service\n", _RAW + _RAW,
    _RAW + b"2:cpu:/other\n", b"", b"\xff",
])
def test_wrong_or_ambiguous_cgroup_refuses(identity_inputs, monkeypatch, raw):
    monkeypatch.setattr(module, "_read_proc", lambda *_: raw)
    with pytest.raises(UnitOperationFailed):
        module.current_bootstrap_controller_identity()


@pytest.mark.parametrize("change", ["proc", "pid", "invocation", "uid", "namespace"])
def test_identity_changes_during_read_refuse(identity_inputs, monkeypatch, change):
    calls = []

    def read(*_):
        calls.append(True)
        if len(calls) == 2:
            if change == "proc":
                return b"0::/other\n"
            if change == "pid":
                monkeypatch.setattr(module.os, "getpid", lambda: 1235)
            elif change == "uid":
                monkeypatch.setattr(module.os, "geteuid", lambda: 1000)
            elif change == "namespace":
                monkeypatch.setattr(module, "_namespaces", lambda: (1, 3))
            else:
                monkeypatch.setenv("INVOCATION_ID", "b2" * 16)
        return _RAW

    monkeypatch.setattr(module, "_read_proc", read)
    with pytest.raises(UnitOperationFailed):
        module.current_bootstrap_controller_identity()
