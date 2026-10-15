"""Loaded launch constraints; fake D-Bus only, no programs or units start."""

import asyncio

import pytest

from azazel_nexus_runtime.launch_environment import BOOTSTRAP_UNSET_ENVIRONMENT
from azazel_nexus_runtime.units import UnitKey, UnitOperationFailed
from azazel_nexus.bootstrap_grant_transaction import advance_transaction
from test_runtime_bootstrap_controller import FakeBus as ControllerBus, _inspector as controller
from test_runtime_bootstrap_loaded import (
    FakeBus as HelperBus, SERVICE_INTERFACE, Variant, _inspector as helper, _dependencies,
)
import test_runtime_bootstrap_manager_publication as publication


def test_compiled_unset_names_are_fixed_not_patterns_or_assignments():
    names = BOOTSTRAP_UNSET_ENVIRONMENT
    assert len(names) == 31
    assert names == tuple(sorted(set(names)))
    assert {"LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "GLIBC_TUNABLES",
            "GCONV_PATH", "__PYVENV_LAUNCHER__"} <= set(names)
    assert not {"NOTIFY_SOCKET", "INVOCATION_ID", "WATCHDOG_USEC", "WATCHDOG_PID"} & set(names)
    assert all("=" not in name and "*" not in name for name in names)


FAULTS = (
    ("Environment", "as", ["LD_PRELOAD=synthetic.so"]),
    ("EnvironmentFiles", "a(sb)", [["/synthetic/environment", False]]),
    ("PassEnvironment", "as", ["LD_PRELOAD"]),
    ("UnsetEnvironment", "as", []),
    ("UnsetEnvironment", "as", ["LD_PRELOAD=synthetic.so"]),
    ("UnsetEnvironment", "s", "LD_PRELOAD"),
    ("SetLoginEnvironment", "b", True),
    ("PAMName", "s", "synthetic-pam"),
)


@pytest.mark.parametrize("unit", [UnitKey.AUDITD, UnitKey.COMMISSIOND])
@pytest.mark.parametrize("key,signature,value", FAULTS)
def test_helpers_refuse_changed_launch_environment(unit, key, signature, value):
    reached = []

    def mutate(_snapshot, interface, props):
        if interface == SERVICE_INTERFACE:
            props[key] = Variant(signature, value)
            reached.append(True)
        return props

    bus = HelperBus(unit, mutate=mutate)
    with pytest.raises(UnitOperationFailed):
        asyncio.run(helper(bus).inspect(unit, expected_dependencies=_dependencies(unit)))
    assert reached
    assert not any(call.member == "StartUnit" for call in bus.calls)


@pytest.mark.parametrize("phase", ["pre-ready", "ready"])
@pytest.mark.parametrize("key,signature,value", FAULTS)
def test_controller_refuses_changed_launch_environment(phase, key, signature, value):
    reached = []

    def mutate(interface, _count, props):
        if interface == SERVICE_INTERFACE:
            props[key] = Variant(signature, value)
            reached.append(True)
        return props

    bus = ControllerBus(phase=phase, mutate=mutate)
    with pytest.raises(UnitOperationFailed):
        asyncio.run(controller(bus, phase=phase).inspect())
    assert reached


@pytest.mark.parametrize("drift", ["missing-unset", "pam-hook"])
def test_retained_bound_audit_refuses_controller_launch_drift_before_start(
    tmp_path, monkeypatch, drift,
):
    with publication._environment(tmp_path) as env:
        manager, sessions, bus, approval, *_ = publication._manager_fixture(env, monkeypatch)
        grant = publication._transaction(approval)
        published, _ = manager._publish_and_inspect_pair(
            grant, approval=approval, check_publish=lambda: None,
        )
        manager._controller_ready_confirmed = True
        bus.controller.phase = "ready"
        assert manager._check_retained_publication() is None
        transaction = advance_transaction(
            advance_transaction(grant, "pair_grant_opened"), "auditd_start_intent",
        )
        reached = []

        def mutate(interface, _count, props):
            if interface == SERVICE_INTERFACE:
                if drift == "missing-unset":
                    names = list(BOOTSTRAP_UNSET_ENVIRONMENT)
                    names.remove("LD_PRELOAD")
                    props["UnsetEnvironment"] = Variant("as", names)
                else:
                    props["PAMName"] = Variant("s", "synthetic-pam")
                reached.append(True)
            return props

        bus.controller.mutate = mutate
        with pytest.raises(UnitOperationFailed) as error:
            manager._start_bound_audit(transaction, check_start=lambda: None)
        assert reached, str(error.value)
        assert not any(call.member == "StartUnit" for call in bus.calls)
        assert bus.reload_count == 1
        assert env["store"].load() == published
        assert bus.disconnected and all(session.closed for session in sessions)
